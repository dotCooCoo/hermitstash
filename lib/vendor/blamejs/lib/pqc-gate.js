// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
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
