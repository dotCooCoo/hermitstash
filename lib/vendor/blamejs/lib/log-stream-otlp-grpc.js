// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var http2 = require("node:http2");
var C = require("./constants");
var { boot } = require("./log");
var pb = require("./protobuf-encoder");
var safeAsync = require("./safe-async");
var safeUrl = require("./safe-url");
var { tearDownH2Session } = require("./http2-teardown");
var { LogStreamError } = require("./framework-error");
var lazyRequire = require("./lazy-require");
// Lazy to break the observability <-> log-stream require cycle. Used only to
// scrub attribute values through the telemetry redactor before they cross the
// OTLP egress boundary (CWE-532).
var observability = lazyRequire(function () { return require("./observability"); });
// Lazy to match the observability cycle-break above. Scrubs secrets embedded in
// the free-text log body for a directly-wired sink (defense in depth — emit()
// already redacts, but a sink can be driven without it, same as meta/redactAttrs).
var redact = lazyRequire(function () { return require("./redact"); });
// Lazy — network-tls is widely required; audit an insecure (cert-validation-
// disabled) outbound TLS session at honor time, same surface as connectWithEch.
var networkTls = lazyRequire(function () { return require("./network-tls"); });

var _err = LogStreamError.factory;
var _log = boot("log-stream-otlp-grpc");

var DEFAULTS = {
  scopeName:     "blamejs",
  batchSize:     100,
  maxBatchAgeMs: C.TIME.seconds(5),
  timeoutMs:     C.TIME.seconds(30),
  bufferLimit:   C.BYTES.bytes(10000),
};

var SEVERITY = {
  debug: { number: 5,  text: "DEBUG" },
  info:  { number: 9,  text: "INFO"  },
  warn:  { number: 13, text: "WARN"  },
  error: { number: 17, text: "ERROR" },
};

function _encodeAnyValue(v) {
  if (v == null)             return pb.string(1, "");
  if (typeof v === "string") return pb.string(1, v);
  if (typeof v === "boolean")return pb.bool(2, v);
  if (typeof v === "number") {
    if (Number.isInteger(v) && v >= 0) return pb.uint64(3, v);
    return pb.double(4, v);
  }
  if (Buffer.isBuffer(v))    return pb.bytes(7, v);
  try { return pb.string(1, JSON.stringify(v)); }
  catch (_e) { return pb.string(1, String(v)); }
}

function _encodeKeyValue(key, value) {
  return Buffer.concat([
    pb.string(1, key),
    pb.embeddedMessage(2, _encodeAnyValue(value)),
  ]);
}

function _encodeAttributes(obj) {
  if (!obj) return [];
  var out = [];
  var keys = Object.keys(obj);
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    var v = obj[k];
    if (v === undefined) continue;
    out.push(_encodeKeyValue(k, v));
  }
  return out;
}

function _encodeResource(attrs) {
  var kvs = _encodeAttributes(attrs);
  if (kvs.length === 0) return Buffer.alloc(0);
  var pieces = kvs.map(function (kvBody) { return pb.embeddedMessage(1, kvBody); });
  return Buffer.concat(pieces);
}

function _encodeScope(name, version) {
  return Buffer.concat([
    pb.string(1, name || DEFAULTS.scopeName),
    pb.string(2, version || ""),
  ]);
}

function _encodeLogRecord(record) {
  var sev = SEVERITY[record.level] || SEVERITY.info;
  var tsMs = record.ts || Date.now();
  var tsNs = BigInt(tsMs) * 1000000n;
  var attrPieces = _encodeAttributes(observability().redactAttrs(record.meta)).map(function (kvBody) {
    return pb.embeddedMessage(6, kvBody);
  });
  var msg = (record.message != null ? redact().redactText(String(record.message)) : "");
  return Buffer.concat([
    pb.fixed64(1, tsNs),
    pb.uint32(2, sev.number),
    pb.string(3, sev.text),
    pb.embeddedMessage(5, pb.string(1, msg)),
    Buffer.concat(attrPieces),
    pb.fixed64(11, tsNs),
  ]);
}

function _encodeScopeLogs(records, scopeName, scopeVersion) {
  var recordPieces = records.map(function (rec) {
    return pb.embeddedMessage(2, _encodeLogRecord(rec));
  });
  return Buffer.concat([
    pb.embeddedMessage(1, _encodeScope(scopeName, scopeVersion)),
    Buffer.concat(recordPieces),
  ]);
}

function _encodeResourceLogs(records, cfg) {
  var resourceBody = _encodeResource(observability().redactAttrs(_resourceAttrs(cfg)));
  var scopeLogsBody = _encodeScopeLogs(records, cfg.scopeName, cfg.scopeVersion);
  return Buffer.concat([
    pb.embeddedMessage(1, resourceBody),
    pb.embeddedMessage(2, scopeLogsBody),
  ]);
}

function _encodeExportRequest(records, cfg) {
  return pb.embeddedMessage(1, _encodeResourceLogs(records, cfg));
}

function _resourceAttrs(cfg) {
  var attrs = Object.assign({}, cfg.resourceAttributes || {});
  if (cfg.serviceName)    attrs["service.name"]    = cfg.serviceName;
  if (cfg.serviceVersion) attrs["service.version"] = cfg.serviceVersion;
  return attrs;
}

function _frame(messageBuf) {
  var hdr = Buffer.alloc(5);
  hdr[0] = 0;
  hdr.writeUInt32BE(messageBuf.length, 1);
  return Buffer.concat([hdr, messageBuf]);
}

function _makeClient(cfg) {
  var url = safeUrl.parse(cfg.url, {
    allowedProtocols: cfg.allowedProtocols || safeUrl.ALLOW_HTTP_TLS,
    errorClass:       LogStreamError,
  });
  var authority = url.protocol + "//" + url.host;
  var sessionOpts = url.protocol === "https:"
    ? networkTls().outboundPosture()
    : {};
  if (cfg.ca) sessionOpts.ca = cfg.ca;
  if (cfg.servername) sessionOpts.servername = cfg.servername;
  if (cfg.allowInsecure && url.protocol === "https:") {
    sessionOpts.rejectUnauthorized = !cfg.allowInsecure;
    networkTls().auditInsecureTls({ host: authority, source: "log-stream.otlp-grpc" });
  }
  var session = http2.connect(authority, sessionOpts);
  session.on("error", function () { /* surfaced through request err */ });
  if (typeof session.unref === "function") session.unref();
  return session;
}

function _doExport(session, cfg, records) {
  return new Promise(function (resolve, reject) {
    var body = _encodeExportRequest(records, cfg);
    var framed = _frame(body);

    var headers = Object.assign({
      ":method":             "POST",
      ":path":               "/opentelemetry.proto.collector.logs.v1.LogsService/Export",
      "content-type":        "application/grpc+proto",
      "te":                  "trailers",
      "grpc-encoding":       "identity",
      "grpc-accept-encoding": "identity",
    }, cfg.headers || {});

    var req = session.request(headers);
    var resStatus = null;
    var trailers = null;
    var errored = false;

    var timer = setTimeout(function () {
      errored = true;
      try { req.close(http2.constants.NGHTTP2_CANCEL); }
      catch (e) { _log.debug("otlp-grpc-timer-cancel: " + (e && e.message || e)); }
      reject(_err("ETIMEDOUT",
        "otlp-grpc: request timed out after " + cfg.timeoutMs + "ms"));
    }, cfg.timeoutMs);

    req.on("response", function (h) {
      resStatus = h[":status"];
    });
    req.on("trailers", function (t) { trailers = t; });
    req.on("error", function (e) {
      if (errored) return;
      errored = true;
      clearTimeout(timer);
      reject(_err("log-stream-otlp-grpc/http2-error", "otlp-grpc: " + (e && e.message || String(e))));
    });
    req.on("close", function () {
      if (errored) return;
      clearTimeout(timer);
      if (resStatus !== 200) {
        return reject(_err("log-stream-otlp-grpc/http-error",
          "otlp-grpc: HTTP/2 status " + resStatus));
      }
      var grpcStatus = trailers && trailers["grpc-status"];
      var grpcMessage = trailers && trailers["grpc-message"];
      if (grpcStatus === undefined) {
        return reject(_err("log-stream-otlp-grpc/http-error",
          "otlp-grpc: response missing grpc-status trailer"));
      }
      if (String(grpcStatus) !== "0") {
        return reject(_err("log-stream-otlp-grpc/http-error",
          "otlp-grpc: grpc-status " + grpcStatus +
          (grpcMessage ? " — " + grpcMessage : "")));
      }
      resolve();
    });

    req.end(framed);
  });
}

function create(config) {
  if (!config || !config.url) {
    throw _err("log-stream-otlp-grpc/bad-opt", "log-stream otlp-grpc: { url } is required");
  }
  var allowedProtocols = config.allowedProtocols || safeUrl.ALLOW_HTTP_TLS;
  safeUrl.parse(config.url, {
    allowedProtocols: allowedProtocols,
    errorClass:       LogStreamError,
  });

  var cfg = Object.assign({}, DEFAULTS, config);
  cfg.batchSize     = Number(cfg.batchSize)     || DEFAULTS.batchSize;
  cfg.maxBatchAgeMs = Number(cfg.maxBatchAgeMs) || DEFAULTS.maxBatchAgeMs;
  cfg.timeoutMs     = Number(cfg.timeoutMs)     || DEFAULTS.timeoutMs;
  cfg.bufferLimit   = Number(cfg.bufferLimit)   || DEFAULTS.bufferLimit;

  var onDrop = typeof config.onDrop === "function" ? config.onDrop : null;
  var _emitDrop = safeAsync.makeDropCallback(onDrop,
    function (e) { _log.debug("otlp-grpc-onDrop-threw: " + (e && e.message || e)); });

  var buffer = [];
  var inFlight = false;
  var closed = false;
  var session = null;
  var inflightPromise = null;
  var flushScheduler = safeAsync.makeScheduledFlush(cfg.maxBatchAgeMs, function () { return _flush(); });

  function _ensureSession() {
    if (session && !session.destroyed) return session;
    session = _makeClient(cfg);
    return session;
  }

  async function _flush() {
    if (inFlight || buffer.length === 0) return;
    inFlight = true;
    try {
      while (buffer.length > 0 && !closed) {
        var batch = buffer.splice(0, cfg.batchSize);
        try {
          var s = _ensureSession();
          inflightPromise = _doExport(s, cfg, batch);
          await inflightPromise;
        } catch (e) {
          _emitDrop("send-failed", batch, e);
        } finally {
          inflightPromise = null;
        }
      }
    } finally {
      inFlight = false;
    }
  }

  var _enqueue = safeAsync.makeBufferedEnqueue(buffer, {
    batchSize:   cfg.batchSize,
    bufferLimit: cfg.bufferLimit,
    flush:       _flush,
    schedule:    flushScheduler.schedule,
    onOverflow:  function (dropped) { _emitDrop("overflow", [dropped], null); },
  });

  function emit(record) {
    if (closed) {
      _emitDrop("sink-closed", [record], null);
      return Promise.resolve({ accepted: false, reason: "closed" });
    }
    return _enqueue(record);
  }

  async function close() {
    closed = true;
    flushScheduler.cancel();
    if (inflightPromise) {
      try { await inflightPromise; }
      catch (e) { _log.debug("otlp-grpc-close-drain: " + (e && e.message || e)); }
    }
    var pending = buffer.splice(0, buffer.length);
    if (pending.length > 0) {
      try {
        var s = _ensureSession();
        await _doExport(s, cfg, pending);
      } catch (e) {
        _emitDrop("send-failed", pending, e);
      }
    }
    tearDownH2Session(session);
    session = null;
  }

  return {
    protocol: "otlp-grpc",
    emit:     emit,
    close:    close,
    _encodeForTest:    function (records) { return _encodeExportRequest(records, cfg); },
    _frameForTest:     _frame,
  };
}

module.exports = {
  create:                create,
  _makeClient:           _makeClient,
  _encodeAnyValue:       _encodeAnyValue,
  _encodeKeyValue:       _encodeKeyValue,
  _encodeLogRecord:      _encodeLogRecord,
  _encodeExportRequest:  _encodeExportRequest,
  _frame:                _frame,
};
