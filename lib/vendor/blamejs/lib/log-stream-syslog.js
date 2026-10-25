// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var dgram = require("node:dgram");
var net   = require("node:net");
var os    = require("node:os");
var nodeTls   = require("node:tls");
var C = require("./constants");
var { boot } = require("./log");
var safeAsync = require("./safe-async");
var safeBuffer = require("./safe-buffer");
var safeUrl = require("./safe-url");
var ipUtils = require("./ip-utils");
var { LogStreamError } = require("./framework-error");
var lazyRequire = require("./lazy-require");
// Lazy — audit a cert-validation-disabled syslog/TLS session at honor time.
var networkTls = lazyRequire(function () { return require("./network-tls"); });
// Lazy: only the UDP sink resolves its host, through the network-dns UDP target resolver.
var networkDns = lazyRequire(function () { return require("./network-dns"); });

var _err = LogStreamError.factory;
var log  = boot("log-stream-syslog");

var DEFAULT_FACILITY    = 0x10;
var DEFAULT_APP_NAME    = "blamejs";
var DEFAULT_PROC_ID     = String(process.pid);
var DEFAULT_MSG_ID      = "-";
var DEFAULT_STRUCT_DATA = "-";
var TCP_DEFAULT_PORT    = 514;
var TLS_DEFAULT_PORT    = 6514;
var UDP_DEFAULT_PORT    = 514;
var DEFAULT_TIMEOUT_MS  = C.TIME.seconds(10);
var DEFAULT_RECONNECT_BASE_MS = 250;
var DEFAULT_RECONNECT_MAX_MS  = C.TIME.seconds(30);
var DEFAULT_BUFFER_LIMIT = C.BYTES.bytes(10000);

var LEVEL_TO_SEVERITY = {
  debug: 7,
  info:  6,
  warn:  4,
  error: 3,
};

function _toRfc3339(tsMs) {
  return new Date(tsMs).toISOString();
}

function _formatRfc5424(record, cfg) {
  var severity = LEVEL_TO_SEVERITY[record.level] != null
    ? LEVEL_TO_SEVERITY[record.level] : 6;
  var pri = (cfg.facility << 3) + severity;
  var ts  = _toRfc3339(record.ts || Date.now());
  var body = record.message || "";
  if (record.meta && Object.keys(record.meta).length > 0) {
    try { body += " " + JSON.stringify(record.meta); }
    catch (_e) { /* best-effort */ }
  }
  body = safeBuffer.stripCrlf(String(body), "␤");
  return "<" + pri + ">1 " + ts + " " + cfg.hostname + " " +
         cfg.appName + " " + cfg.procId + " " + cfg.msgId + " " +
         (cfg.structuredData || "-") + " " + body;
}

function create(config) {
  if (!config) throw _err("log-stream-syslog/bad-opt", "log-stream syslog requires { url } (e.g. udp://host:514, tcp://host:514, tls://host:6514)");
  var url = config.url;
  if (typeof url !== "string" || url.length === 0) {
    throw _err("log-stream-syslog/bad-opt", "log-stream syslog requires { url } (string)");
  }
  var parsed;
  try {
    parsed = safeUrl.parse(url, {
      allowedProtocols: ["udp:", "tcp:", "tls:"],
      errorClass:       LogStreamError,
    });
  } catch (e) {
    throw _err("log-stream-syslog/bad-url", "log-stream syslog: bad url '" + url + "': " +
      ((e && e.message) || String(e)));
  }
  var transport = parsed.protocol.replace(/:$/, "").toLowerCase();
  var defaultPort = transport === "tls" ? TLS_DEFAULT_PORT
                  : transport === "tcp" ? TCP_DEFAULT_PORT
                  : UDP_DEFAULT_PORT;
  var host = ipUtils.dialHost(parsed.hostname);
  var port = parsed.port ? parseInt(parsed.port, 10) : defaultPort;
  var tlsIdentity = networkTls().identityFor(host, config.servername, {
    label: "log-stream syslog: servername", errorClass: LogStreamError, code: "log-stream-syslog/bad-opt",
  });
  networkTls()._assertCaNotCompromised(config.ca, {
    errorClass: LogStreamError, code: "log-stream-syslog/compromised-key", label: "log-stream syslog: ca",
  });

  var cfg = {
    transport:        transport,
    host:             host,
    port:             port,
    facility:         (typeof config.facility === "number" && config.facility >= 0 && config.facility <= 23)
                        ? Math.floor(config.facility) : DEFAULT_FACILITY,
    appName:          config.appName || DEFAULT_APP_NAME,
    procId:           config.procId  || DEFAULT_PROC_ID,
    msgId:            config.msgId   || DEFAULT_MSG_ID,
    hostname:         config.hostname || os.hostname(),
    structuredData:   config.structuredData || DEFAULT_STRUCT_DATA,
    timeoutMs:        config.timeoutMs || DEFAULT_TIMEOUT_MS,
    bufferLimit:      config.bufferLimit || DEFAULT_BUFFER_LIMIT,
    reconnectBaseMs:  config.reconnectBaseMs || DEFAULT_RECONNECT_BASE_MS,
    reconnectMaxMs:   config.reconnectMaxMs  || DEFAULT_RECONNECT_MAX_MS,
    ca:               config.ca || null,
    rejectUnauthorized: config.rejectUnauthorized !== false,
    tlsIdentity:      tlsIdentity,
  };
  if (parsed.username || parsed.password) {
    throw _err("log-stream-syslog/bad-url",
      "log-stream syslog: url must not contain userinfo");
  }
  var onDrop = typeof config.onDrop === "function" ? config.onDrop : null;
  var _emitDrop = safeAsync.makeDropCallback(onDrop,
    function (e) { log.warn("onDrop-callback-failed: " + e.message); });

  if (transport === "udp") {
    var udpSock = null;
    var udpFamily = 0;
    var udpClosed = false;
    var _udpSocketFor = function (family) {
      if (udpSock && udpFamily === family) return udpSock;
      if (udpSock) {
        try { udpSock.close(); }
        catch (e) { log.warn("udp-close-failed: " + e.message); }
      }
      udpSock = dgram.createSocket(family === 6 ? "udp6" : "udp4");
      udpSock.unref && udpSock.unref();
      udpSock.on("error", function () { /* non-fatal: datagrams race */ });
      udpFamily = family;
      return udpSock;
    };
    var _closedResult = function (record) {
      _emitDrop("sink-closed", [record], null);
      return { accepted: false, reason: "closed" };
    };

    return {
      protocol: "syslog-udp",
      emit: function (record) {
        if (udpClosed) return Promise.resolve(_closedResult(record));
        var msg = _formatRfc5424(record, cfg);
        var buf = Buffer.from(msg, "utf8");
        return networkDns()._resolveUdpTarget(cfg.host).then(function (target) {
          if (udpClosed) return _closedResult(record);
          var s = _udpSocketFor(target.family);
          return new Promise(function (resolve) {
            s.send(buf, 0, buf.length, cfg.port, target.address, function (err) {
              if (err) _emitDrop("udp-send-error", [record], err);
              resolve({ accepted: !err, queued: 0 });
            });
          });
        }, function (err) {
          _emitDrop("udp-resolve-error", [record], err);
          return { accepted: false, reason: "resolve-error" };
        });
      },
      close: function () {
        udpClosed = true;
        if (udpSock) {
          try { udpSock.close(); }
          catch (e) { log.warn("udp-close-failed: " + e.message); }
          udpSock = null;
        }
        return Promise.resolve();
      },
    };
  }

  var sock = null;
  var sockReady = false;
  var connecting = false;
  var queue = [];
  var closed = false;
  var reconnectAttempt = 0;

  function _writeFramed(record) {
    var msg = _formatRfc5424(record, cfg);
    var msgBuf = Buffer.from(msg, "utf8");
    var prefix = Buffer.from(msgBuf.length + " ", "utf8");
    sock.write(Buffer.concat([prefix, msgBuf]));
  }

  function _connect() {
    if (closed || connecting) return;
    connecting = true;
    sockReady = false;
    var connectOpts = { host: cfg.host, port: cfg.port };
    var onConnect = function () {
      connecting = false;
      sockReady = true;
      reconnectAttempt = 0;
      while (queue.length > 0 && sockReady) {
        try { _writeFramed(queue.shift()); }
        catch (e) { _emitDrop("write-error", [], e); break; }
      }
    };
    if (transport === "tls") {
      var tlsOpts = Object.assign({}, connectOpts, {
        rejectUnauthorized: cfg.rejectUnauthorized,
      }, networkTls().outboundPosture());
      var anchors = networkTls()._clientTrustAnchors(cfg.ca || undefined);
      if (anchors !== undefined) tlsOpts.ca = anchors;
      Object.assign(tlsOpts, cfg.tlsIdentity);
      tlsOpts.checkServerIdentity = networkTls()._withCompromisedChainCheck(undefined, cfg.ca || undefined);
      if (cfg.rejectUnauthorized === false) {
        networkTls().auditInsecureTls({ host: cfg.host, port: cfg.port, source: "log-stream.syslog" });
      }
      sock = nodeTls.connect(tlsOpts, onConnect);
    } else {
      sock = net.connect(connectOpts, onConnect);
    }
    var thisSock = sock;
    thisSock.unref && thisSock.unref();
    thisSock.on("error", function () { /* reconnect handled in the close listener */ });
    thisSock.on("close", function () {
      sockReady = false;
      connecting = false;
      try { thisSock.destroy(); }
      catch (e) { log.warn("sock-destroy-failed: " + e.message); }
      if (sock === thisSock) sock = null;
      if (closed) return;
      reconnectAttempt += 1;
      var delay = Math.min(cfg.reconnectMaxMs,
        cfg.reconnectBaseMs * Math.pow(2, reconnectAttempt - 1));
      var t = setTimeout(_connect, delay);
      t.unref && t.unref();
    });
  }
  _connect();

  return {
    protocol: "syslog-" + transport,
    emit: function (record) {
      if (closed) {
        _emitDrop("sink-closed", [record], null);
        return Promise.resolve({ accepted: false, reason: "closed" });
      }
      if (sockReady) {
        try { _writeFramed(record); }
        catch (e) {
          _emitDrop("write-error", [record], e);
          return Promise.resolve({ accepted: false, reason: "write-error" });
        }
        return Promise.resolve({ accepted: true, queued: 0 });
      }
      if (queue.length >= cfg.bufferLimit) {
        var dropped = queue.shift();
        _emitDrop("overflow", [dropped], null);
      }
      queue.push(record);
      return Promise.resolve({ accepted: true, queued: queue.length });
    },
    close: function () {
      var DRAIN_TIMEOUT_MS = C.TIME.seconds(3);
      var started = Date.now();
      return new Promise(function (resolve) {
        function _finish() {
          closed = true;
          var pending = queue.splice(0, queue.length);
          if (pending.length > 0) _emitDrop("sink-closed", pending, null);
          try { if (sock) sock.end(); }
          catch (e) { log.warn("sock-end-failed: " + e.message); }
          try { if (sock) sock.destroy(); }
          catch (e) { log.warn("sock-destroy-failed: " + e.message); }
          sock = null;
          resolve();
        }
        function _tick() {
          if (queue.length === 0 || Date.now() - started > DRAIN_TIMEOUT_MS) {
            return _finish();
          }
          setTimeout(_tick, 25);
        }
        _tick();
      });
    },
    _queueSizeForTest: function () { return queue.length; },
    _formatRfc5424ForTest: function (rec) { return _formatRfc5424(rec, cfg); },
  };
}

module.exports = { create: create };
