// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.pqcGate
 * @nav    Crypto
 * @title  PQC Gate
 * @slug   pqc-gate
 *
 * @intro
 *   A TCP front door that reads the TLS ClientHello and lets a connection
 *   through only when the client offered a post-quantum key-exchange
 *   group. A client that offered none is answered with a TLS
 *   handshake-failure alert and disconnected, so nothing behind the gate
 *   ever negotiates a classical-only key exchange.
 *
 *   The point is harvest-now-decrypt-later. A session whose key exchange
 *   is classical can be recorded today and opened once a quantum computer
 *   can solve the discrete log behind it, whatever the cipher protecting
 *   the bytes. Refusing at the front means a deployment can state that no
 *   session it served is in that recording.
 *
 *   It reads the ClientHello and nothing else: it does not terminate TLS,
 *   so it holds no key and sees no plaintext, and hands the bytes it read
 *   on to the real listener unchanged. The read is bounded in time and in
 *   size, so a client that opens a connection and says nothing, or says
 *   too much, is dropped rather than held.
 *
 *   Loopback bypasses by default, because a health check and a local
 *   probe should not have to speak post-quantum to reach the service.
 *
 * @card
 *   Refuse a TLS connection whose ClientHello offers no post-quantum key
 *   exchange, before it reaches the listener. Reads the ClientHello only,
 *   terminates nothing, and bypasses loopback.
 */

var net = require("node:net");
var C = require("./constants");
var { PQC_GROUPS } = require("./constants");
var numericBounds = require("./numeric-bounds");
var validateOpts = require("./validate-opts");
var { boot } = require("./log");

var DEFAULT_LOG = boot("pqc-gate");
var DEFAULT_BYPASS = Object.freeze(["127.0.0.1", "::1", "::ffff:127.0.0.1"]);
var DEFAULT_CLIENTHELLO_TIMEOUT_MS = C.TIME.seconds(5);
var DEFAULT_MAX_CLIENTHELLO_BYTES = C.BYTES.kib(16);

var TLS_ALERT_HANDSHAKE_FAILURE = Buffer.from([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]);

var PQC_GROUP_IDS = new Set(Object.values(PQC_GROUPS));

/**
 * @primitive b.pqcGate.clientHelloHasPQC
 * @signature b.pqcGate.clientHelloHasPQC(buf)
 * @since     0.1.77
 * @status    stable
 * @compliance soc2
 * @related   b.pqcGate.create
 *
 * Does this buffer hold a TLS ClientHello whose supported-groups extension
 * names a post-quantum group? Answers a boolean, and answers false for
 * anything it cannot read as a ClientHello, including a record that is
 * truncated, one that is not a handshake record and one whose length
 * fields point past the bytes present.
 *
 * The groups it counts are `b.constants.PQC_GROUPS`.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.pqcGate.clientHelloHasPQC(Buffer.alloc(0));   // → false
 */
function clientHelloHasPQC(buf) {
  if (!buf || buf.length < 44) return false;

  if (buf[0] !== 0x16) return false;

  var recordLen = buf.readUInt16BE(3);
  var recordEnd = Math.min(5 + recordLen, buf.length);

  if (buf.length < 10) return false;
  if (buf[5] !== 0x01) return false;

  var offset = 9 + 2 + C.BYTES.bytes(32);
  if (offset + 1 > recordEnd) return false;

  var sessionIdLen = buf[offset];
  offset += 1 + sessionIdLen;
  if (offset + 2 > recordEnd) return false;

  var cipherSuitesLen = buf.readUInt16BE(offset);
  offset += 2 + cipherSuitesLen;
  if (offset + 1 > recordEnd) return false;

  var compLen = buf[offset];
  offset += 1 + compLen;
  if (offset + 2 > recordEnd) return false;

  var extensionsLen = buf.readUInt16BE(offset);
  offset += 2;
  var extensionsEnd = Math.min(offset + extensionsLen, recordEnd);

  while (offset + 4 <= extensionsEnd) {
    var extType = buf.readUInt16BE(offset);
    var extLen  = buf.readUInt16BE(offset + 2);
    offset += 4;

    if (extType === 0x000A && extLen >= 2 && offset + extLen <= extensionsEnd) {
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
  var line = msg + (fields ? " " + JSON.stringify(fields) : "");
  if (level === "error" || level === "fatal" || level === "warn") {
    DEFAULT_LOG.warn(line);
  } else {
    DEFAULT_LOG(line);
  }
}

/**
 * @primitive b.pqcGate.create
 * @signature b.pqcGate.create(opts)
 * @since     0.1.77
 * @status    stable
 * @compliance soc2
 * @related   b.pqcGate.clientHelloHasPQC, b.network.tls.outboundPosture
 *
 * Build the gate as a `node:net` server. It is not listening yet: the
 * caller calls `listen` on it, on the port the world reaches, and points
 * `internalPort` at the TLS listener behind it.
 *
 * A connection whose ClientHello names a post-quantum group is piped to
 * the internal listener with the bytes already read written first, so the
 * listener sees the whole handshake. One that names none is written a TLS
 * handshake-failure alert and destroyed, which is what a TLS client
 * expects rather than a bare close.
 *
 * A peer address in `bypass` is piped through without the check, and the
 * default list is the loopback addresses. A connection that sends nothing
 * within `clientHelloTimeoutMs`, or more than `maxClientHelloBytes` before
 * a complete ClientHello, is dropped.
 *
 * @opts
 *   internalPort:         number,    // the TLS listener's port; required, 1-65535
 *   internalHost:         string,    // its host; default "127.0.0.1"
 *   bypass:               string[],  // peers exempt from the check; default loopback
 *   clientHelloTimeoutMs: number,    // wait for the ClientHello; default 5000
 *   maxClientHelloBytes:  number,    // ceiling on what is read; default 16384
 *   log:                  object,    // logger for refusals
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var gate = b.pqcGate.create({ internalPort: 8443 });
 *   gate.listen(443);
 */
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
  if (opts.clientHelloTimeoutMs !== undefined && !numericBounds.isPositiveFiniteInt(opts.clientHelloTimeoutMs)) {
    throw new Error("pqc-gate: clientHelloTimeoutMs must be a positive finite integer; got " +
      numericBounds.shape(opts.clientHelloTimeoutMs));
  }
  var clientHelloTimeoutMs = opts.clientHelloTimeoutMs || DEFAULT_CLIENTHELLO_TIMEOUT_MS;
  if (opts.maxClientHelloBytes !== undefined && !numericBounds.isPositiveFiniteInt(opts.maxClientHelloBytes)) {
    throw new Error("pqc-gate: maxClientHelloBytes must be a positive finite integer; got " +
      numericBounds.shape(opts.maxClientHelloBytes));
  }
  var maxClientHelloBytes  = opts.maxClientHelloBytes || DEFAULT_MAX_CLIENTHELLO_BYTES;
  var log = opts.log || null;

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

      if (totalLen >= 1 && chunks[0][0] !== 0x16) {
        resolved = true;
        try { clearTimeoutFn(timeout); } catch (_e) { /* timer may already have fired */ }
        try { socket.destroy(); } catch (_e) { /* socket may already be torn down */ }
        return;
      }

      if (totalLen < 5) return;

      // allow:handrolled-buffer-collect-bounded-framing — see comment above
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
