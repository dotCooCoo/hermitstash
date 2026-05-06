"use strict";
/**
 * pqc-gate — TCP-level enforcement of post-quantum key exchange.
 *
 * Inspects the TLS ClientHello before letting the connection reach the
 * HTTPS server. Connections that don't offer a PQC hybrid group in
 * supported_groups are rejected with a TLS handshake_failure alert.
 *
 * Architecture:
 *
 *   net.Server (public 443) → parse ClientHello → pipe to internal HTTPS server
 *
 * The HTTPS server binds to a private loopback port and never directly
 * sees the internet. Operators set Node's TLS group preference at the
 * HTTPS server level (so accepted connections still negotiate PQC) and
 * use this gate as the outermost rejection point. Both layers must be
 * configured PQC-only — gate without HTTPS-side enforcement leaves a
 * connection that downgrades to a non-PQ group at handshake time.
 *
 *   var server = b.pqcGate.create({
 *     internalPort: 8443,
 *     internalHost: "127.0.0.1",
 *     bypass:       ["127.0.0.1", "::1", "::ffff:127.0.0.1"],
 *     clientHelloTimeoutMs: 5000,
 *     maxClientHelloBytes:  16384,
 *     log:          logInstance,
 *   });
 *   server.listen(443, "0.0.0.0");
 *
 * Bypass: localhost connections skip the gate so health probes and
 * sidecars (which often do plain TCP or use older TLS configurations)
 * still work without weakening the public-facing posture.
 *
 * Test seam: opts._connect / _server / _setTimeout / _clearTimeout
 * default to net.createConnection / net.createServer / setTimeout /
 * clearTimeout. The unit tests use fakes to drive the parser and
 * connection lifecycle deterministically.
 */
var net = require("node:net");
var C = require("./constants");
var { PQC_GROUPS } = require("./constants");
var nb = require("./numeric-bounds");
var validateOpts = require("./validate-opts");
var { boot } = require("./log");

var DEFAULT_LOG = boot("pqc-gate");
var DEFAULT_BYPASS = Object.freeze(["127.0.0.1", "::1", "::ffff:127.0.0.1"]);
var DEFAULT_CLIENTHELLO_TIMEOUT_MS = C.TIME.seconds(5);
var DEFAULT_MAX_CLIENTHELLO_BYTES = C.BYTES.kib(16);

// TLS handshake_failure alert (fatal). Sent before destroying a socket
// so a strict TLS client logs a precise reason rather than a vague
// connection-reset.
var TLS_ALERT_HANDSHAKE_FAILURE = Buffer.from([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]);

// Set built once from the framework's PQC_GROUPS constant. New PQC
// groups added there flow into the gate without code changes.
var PQC_GROUP_IDS = new Set(Object.values(PQC_GROUPS));

// clientHelloHasPQC — return true iff the parsed ClientHello buffer
// includes any group listed in PQC_GROUP_IDS in its supported_groups
// extension. Returns false on malformed input or when no PQC group is
// present.
function clientHelloHasPQC(buf) {
  if (!buf || buf.length < 44) return false;

  // TLS record header: type(1) version(2) length(2)
  if (buf[0] !== 0x16) return false; // not a handshake record

  var recordLen = buf.readUInt16BE(3);
  var recordEnd = Math.min(5 + recordLen, buf.length);

  // Handshake header: type(1) length(3)
  if (buf.length < 10) return false;
  if (buf[5] !== 0x01) return false; // not ClientHello

  // Body: version(2) + random(32) = 34 bytes after handshake header
  var offset = 9 + 2 + C.BYTES.bytes(32);
  if (offset + 1 > recordEnd) return false;

  // Session ID: length(1) + data
  var sessionIdLen = buf[offset];
  offset += 1 + sessionIdLen;
  if (offset + 2 > recordEnd) return false;

  // Cipher suites: length(2) + data
  var cipherSuitesLen = buf.readUInt16BE(offset);
  offset += 2 + cipherSuitesLen;
  if (offset + 1 > recordEnd) return false;

  // Compression methods: length(1) + data
  var compLen = buf[offset];
  offset += 1 + compLen;
  if (offset + 2 > recordEnd) return false;

  // Extensions: total_length(2)
  var extensionsLen = buf.readUInt16BE(offset);
  offset += 2;
  var extensionsEnd = Math.min(offset + extensionsLen, recordEnd);

  while (offset + 4 <= extensionsEnd) {
    var extType = buf.readUInt16BE(offset);
    var extLen  = buf.readUInt16BE(offset + 2);
    offset += 4;

    if (extType === 0x000A && extLen >= 2 && offset + extLen <= extensionsEnd) {
      // supported_groups: list_length(2) + group_ids(2 each)
      var listLen = buf.readUInt16BE(offset);
      var groupsOffset = offset + 2;
      var groupsEnd = Math.min(groupsOffset + listLen, offset + extLen);
      while (groupsOffset + 2 <= groupsEnd) {
        var groupId = buf.readUInt16BE(groupsOffset);
        if (PQC_GROUP_IDS.has(groupId)) return true;
        groupsOffset += 2;
      }
      return false;
    }
    offset += extLen;
  }
  return false;
}

function _isBypassed(remoteAddr, bypass) {
  if (!remoteAddr) return false;
  for (var i = 0; i < bypass.length; i++) {
    if (bypass[i] === remoteAddr) return true;
  }
  return false;
}

function _logVia(log, level, msg, fields) {
  if (log && typeof log[level] === "function") {
    try { log[level](msg, fields); } catch (_e) { /* logger best-effort */ }
    return;
  }
  // Fallback to the framework's per-module console channel
  var line = msg + (fields ? " " + JSON.stringify(fields) : "");
  if (level === "error" || level === "fatal" || level === "warn") {
    DEFAULT_LOG.warn(line);
  } else {
    DEFAULT_LOG(line);
  }
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "internalPort", "internalHost", "bypass",
    "clientHelloTimeoutMs", "maxClientHelloBytes", "log",
    "_connect", "_server", "_setTimeout", "_clearTimeout",
  ], "b.pqcGate");
  var internalPort = opts.internalPort;
  if (typeof internalPort !== "number" || internalPort < 1 || internalPort > 65535) {
    throw new Error("pqc-gate: opts.internalPort must be a port number (1-65535)");
  }
  var internalHost = typeof opts.internalHost === "string" ? opts.internalHost : "127.0.0.1";
  var bypass       = Array.isArray(opts.bypass) ? opts.bypass.slice() : DEFAULT_BYPASS.slice();
  if (opts.clientHelloTimeoutMs !== undefined && !nb.isPositiveFiniteInt(opts.clientHelloTimeoutMs)) {
    throw new Error("pqc-gate: clientHelloTimeoutMs must be a positive finite integer; got " +
      nb.shape(opts.clientHelloTimeoutMs));
  }
  var clientHelloTimeoutMs = opts.clientHelloTimeoutMs || DEFAULT_CLIENTHELLO_TIMEOUT_MS;
  if (opts.maxClientHelloBytes !== undefined && !nb.isPositiveFiniteInt(opts.maxClientHelloBytes)) {
    throw new Error("pqc-gate: maxClientHelloBytes must be a positive finite integer; got " +
      nb.shape(opts.maxClientHelloBytes));
  }
  var maxClientHelloBytes  = opts.maxClientHelloBytes || DEFAULT_MAX_CLIENTHELLO_BYTES;
  var log = opts.log || null;

  // Test seams
  var connectFn = opts._connect || function (cOpts, cb) { return net.createConnection(cOpts, cb); };
  var serverFn  = opts._server  || function (sOpts, cb) { return net.createServer(sOpts, cb); };
  var setTimeoutFn  = opts._setTimeout  || setTimeout;
  var clearTimeoutFn = opts._clearTimeout || clearTimeout;

  function pipeToInternal(socket, prependData) {
    var internal = connectFn({ port: internalPort, host: internalHost }, function () {
      if (prependData) internal.write(prependData);
      socket.pipe(internal);
      internal.pipe(socket);
      socket.resume();
    });
    internal.on("error", function () { socket.destroy(); });
    socket.on("error",   function () { internal.destroy(); });
    internal.on("close", function () { socket.destroy(); });
    socket.on("close",   function () { internal.destroy(); });
  }

  function _onConnection(socket) {
    var clientIp = socket.remoteAddress || "";

    if (_isBypassed(clientIp, bypass)) {
      pipeToInternal(socket);
      return;
    }

    var chunks = [];
    var totalLen = 0;
    var resolved = false;

    var timeout = setTimeoutFn(function () {
      if (resolved) return;
      resolved = true;
      _logVia(log, "warn", "ClientHello timeout", { ip: clientIp });
      try { socket.destroy(); } catch (_e) { /* socket may already be torn down */ }
    }, clientHelloTimeoutMs);

    socket.on("data", function onData(chunk) {
      if (resolved) return;
      chunks.push(chunk);
      totalLen += chunk.length;

      if (totalLen > maxClientHelloBytes) {
        resolved = true;
        try { clearTimeoutFn(timeout); } catch (_e) { /* timer may already have fired */ }
        _logVia(log, "warn", "ClientHello too large", { ip: clientIp, size: totalLen });
        try { socket.destroy(); } catch (_e) { /* socket may already be torn down */ }
        return;
      }

      // Reject non-handshake first byte immediately
      if (totalLen >= 1 && chunks[0][0] !== 0x16) {
        resolved = true;
        try { clearTimeoutFn(timeout); } catch (_e) { /* timer may already have fired */ }
        try { socket.destroy(); } catch (_e) { /* socket may already be torn down */ }
        return;
      }

      if (totalLen < 5) return; // need at least the record header

      // TLS ClientHello parser needs streaming peek (re-concat on
      // each chunk to read the record-length prefix) before deciding
      // whether more data is needed. boundedChunkCollector is append-
      // only with no peek, doesn't fit.
      // allow:handrolled-buffer-collect — see comment above
      var buf = Buffer.concat(chunks);
      var recordLen = buf.readUInt16BE(3);
      var neededLen = 5 + recordLen;

      if (buf.length < Math.min(neededLen, maxClientHelloBytes)) return;

      resolved = true;
      try { clearTimeoutFn(timeout); } catch (_e) { /* timer may already have fired */ }
      socket.removeListener("data", onData);
      socket.pause();

      if (clientHelloHasPQC(buf)) {
        pipeToInternal(socket, buf);
      } else {
        _logVia(log, "warn",
          "connection rejected — no PQC group in ClientHello", { ip: clientIp });
        try {
          socket.write(TLS_ALERT_HANDSHAKE_FAILURE, function () {
            try { socket.destroy(); } catch (_e) { /* socket may already be torn down */ }
          });
        } catch (_e) {
          try { socket.destroy(); } catch (_e2) { /* socket may already be torn down */ }
        }
      }
    });

    socket.on("error", function () {
      resolved = true;
      try { clearTimeoutFn(timeout); } catch (_e) { /* timer may already have fired */ }
    });

    socket.resume();
  }

  return serverFn({ pauseOnConnect: true }, _onConnection);
}

module.exports = {
  create:                       create,
  clientHelloHasPQC:            clientHelloHasPQC,
  PQC_GROUP_IDS:                PQC_GROUP_IDS,
  TLS_ALERT_HANDSHAKE_FAILURE:  TLS_ALERT_HANDSHAKE_FAILURE,
  DEFAULT_BYPASS:               DEFAULT_BYPASS,
};
