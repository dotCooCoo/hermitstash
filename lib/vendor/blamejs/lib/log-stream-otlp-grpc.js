"use strict";
/**
 * OTLP gRPC log sink — OpenTelemetry Protocol logs over gRPC.
 *
 * Companion to lib/log-stream-otlp.js (HTTP/JSON). The OTel collector
 * accepts both transports; gRPC is the higher-throughput path with
 * less per-batch overhead and is preferred for production deployments
 * pushing >100K logs/s.
 *
 * Wire format:
 *   - HTTP/2 (node:http2) POST to
 *     /opentelemetry.proto.collector.logs.v1.LogsService/Export
 *   - content-type: application/grpc+proto
 *   - te: trailers
 *   - Body: 1-byte compression flag (0 = none) + 4-byte big-endian
 *           length + protobuf-encoded ExportLogsServiceRequest
 *   - Response status: HTTP/2 trailer `grpc-status` (0 = OK)
 *
 * The protobuf body is encoded by hand via lib/protobuf-encoder.js —
 * no schema parser ships in the bundle, consistent with the framework's
 * vendoring stance. The OTel logs schema is small and stable
 * (https://github.com/open-telemetry/opentelemetry-proto/blob/main/
 *  opentelemetry/proto/logs/v1/logs.proto).
 *
 * Severity mapping follows the OTel spec: debug=5 / info=9 / warn=13 /
 * error=17.
 */
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
  // Ring-buffer cap (event count, not bytes); routed through C.BYTES
  // identity passthrough so the file's literal arithmetic has a single
  // source of truth.
  bufferLimit:   C.BYTES.bytes(10000),
};

var SEVERITY = {
  debug: { number: 5,  text: "DEBUG" },
  info:  { number: 9,  text: "INFO"  },
  warn:  { number: 13, text: "WARN"  },
  error: { number: 17, text: "ERROR" },
};

// ---- Protobuf message shapes (OTel logs.proto) ----
//
// Field numbers match
// https://github.com/open-telemetry/opentelemetry-proto/blob/main/
//   opentelemetry/proto/{common,resource,logs}/v1/*.proto
//
// AnyValue (common.proto) — proto3 oneof; we emit one of:
//   string_value = 1, bool_value = 2, int_value = 3 (int64 varint),
//   double_value = 4, bytes_value = 7
function _encodeAnyValue(v) {
  if (v == null)             return pb.string(1, "");                   // string_value=""
  if (typeof v === "string") return pb.string(1, v);
  if (typeof v === "boolean")return pb.bool(2, v);
  if (typeof v === "number") {
    if (Number.isInteger(v) && v >= 0) return pb.uint64(3, v);          // int_value (proto3 int64 varint)
    return pb.double(4, v);                                              // double_value
  }
  if (Buffer.isBuffer(v))    return pb.bytes(7, v);
  // Fallback — JSON-stringify objects/arrays into string_value rather
  // than implementing the full ArrayValue / KeyValueList branches.
  // Operators wanting structured nested attributes shape their record
  // up-front into top-level scalars or stringified JSON.
  try { return pb.string(1, JSON.stringify(v)); }
  catch (_e) { return pb.string(1, String(v)); }
}

// KeyValue (common.proto): key=1 (string), value=2 (AnyValue)
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

// Resource (resource.proto): attributes=1 (repeated KeyValue),
// dropped_attributes_count=2
function _encodeResource(attrs) {
  var kvs = _encodeAttributes(attrs);
  if (kvs.length === 0) return Buffer.alloc(0);
  var pieces = kvs.map(function (kvBody) { return pb.embeddedMessage(1, kvBody); });
  return Buffer.concat(pieces);
}

// InstrumentationScope (common.proto): name=1, version=2
function _encodeScope(name, version) {
  return Buffer.concat([
    pb.string(1, name || DEFAULTS.scopeName),
    pb.string(2, version || ""),
  ]);
}

// LogRecord (logs.proto):
//   time_unix_nano = 1 (fixed64)
//   severity_number = 2 (enum / varint)
//   severity_text = 3 (string)
//   body = 5 (AnyValue)
//   attributes = 6 (repeated KeyValue)
//   observed_time_unix_nano = 11 (fixed64)
function _encodeLogRecord(record) {
  var sev = SEVERITY[record.level] || SEVERITY.info;
  var tsMs = record.ts || Date.now();
  // Convert ms to ns. Use BigInt to avoid 53-bit precision loss on
  // operators emitting > year-2255 timestamps. For ms-resolution
  // records the LSB nanos are 0; we still send fixed64.
  var tsNs = BigInt(tsMs) * 1000000n;
  // Scrub meta values through the telemetry redactor before the wire (CWE-532),
  // matching the span/metric exporters' egress contract.
  var attrPieces = _encodeAttributes(observability().redactAttrs(record.meta)).map(function (kvBody) {
    return pb.embeddedMessage(6, kvBody);
  });
  var msg = (record.message != null ? String(record.message) : "");
  return Buffer.concat([
    pb.fixed64(1, tsNs),
    pb.uint32(2, sev.number),
    pb.string(3, sev.text),
    pb.embeddedMessage(5, pb.string(1, msg)),   // body.string_value
    Buffer.concat(attrPieces),
    pb.fixed64(11, tsNs),
  ]);
}

// ScopeLogs (logs.proto): scope=1 (InstrumentationScope),
// log_records=2 (repeated LogRecord), schema_url=3
function _encodeScopeLogs(records, scopeName, scopeVersion) {
  var recordPieces = records.map(function (rec) {
    return pb.embeddedMessage(2, _encodeLogRecord(rec));
  });
  return Buffer.concat([
    pb.embeddedMessage(1, _encodeScope(scopeName, scopeVersion)),
    Buffer.concat(recordPieces),
  ]);
}

// ResourceLogs (logs.proto): resource=1 (Resource),
// scope_logs=2 (repeated ScopeLogs), schema_url=3
function _encodeResourceLogs(records, cfg) {
  var resourceBody = _encodeResource(observability().redactAttrs(_resourceAttrs(cfg)));
  var scopeLogsBody = _encodeScopeLogs(records, cfg.scopeName, cfg.scopeVersion);
  return Buffer.concat([
    pb.embeddedMessage(1, resourceBody),
    pb.embeddedMessage(2, scopeLogsBody),
  ]);
}

// ExportLogsServiceRequest (collector logs.proto):
//   resource_logs = 1 (repeated ResourceLogs)
function _encodeExportRequest(records, cfg) {
  return pb.embeddedMessage(1, _encodeResourceLogs(records, cfg));
}

function _resourceAttrs(cfg) {
  var attrs = Object.assign({}, cfg.resourceAttributes || {});
  if (cfg.serviceName)    attrs["service.name"]    = cfg.serviceName;
  if (cfg.serviceVersion) attrs["service.version"] = cfg.serviceVersion;
  return attrs;
}

// ---- gRPC framing ----

function _frame(messageBuf) {
  // 1 byte (compression flag, 0 = uncompressed) + 4 bytes (length, BE)
  // + message bytes.
  var hdr = Buffer.alloc(5);
  hdr[0] = 0;
  hdr.writeUInt32BE(messageBuf.length, 1);
  return Buffer.concat([hdr, messageBuf]);
}

// ---- HTTP/2 client ----
//
// One client per sink instance. The OTLP gRPC server keeps the
// connection alive across many Export calls; we re-create on
// disconnect.
function _makeClient(cfg) {
  var url = safeUrl.parse(cfg.url, {
    allowedProtocols: cfg.allowedProtocols || safeUrl.ALLOW_HTTP_TLS,
    errorClass:       LogStreamError,
  });
  var authority = url.protocol + "//" + url.host;
  var sessionOpts = {};
  if (cfg.ca) sessionOpts.ca = cfg.ca;
  if (cfg.servername) sessionOpts.servername = cfg.servername;
  if (cfg.allowInsecure && url.protocol === "https:") {
    // allowInsecure only has meaning on a TLS session. For an h2c endpoint
    // (http://, cleartext HTTP/2) there is no certificate to validate and
    // nothing to skip, so neither rejectUnauthorized nor the insecure-TLS
    // audit applies — emitting it there would be a false security event.
    // Operator-governed (not a hardcoded literal): cfg.allowInsecure is true in
    // this branch, so this resolves to false — but derived from the operator's
    // own flag, audited, and never a framework default.
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
      // Best-effort cancel of the in-flight HTTP/2 request — close()
      // can throw on an already-torn-down stream; the timeout error
      // below is the authoritative signal so we swallow + log only.
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
      reject(_err("HTTP2_ERROR", "otlp-grpc: " + (e && e.message || String(e))));
    });
    req.on("close", function () {
      if (errored) return;
      clearTimeout(timer);
      if (resStatus !== 200) {
        return reject(_err("HTTP_ERROR",
          "otlp-grpc: HTTP/2 status " + resStatus));
      }
      // Trailers MUST carry grpc-status. The OTel collector returns
      // grpc-status: 0 on success.
      var grpcStatus = trailers && trailers["grpc-status"];
      var grpcMessage = trailers && trailers["grpc-message"];
      if (grpcStatus === undefined) {
        return reject(_err("HTTP_ERROR",
          "otlp-grpc: response missing grpc-status trailer"));
      }
      if (String(grpcStatus) !== "0") {
        return reject(_err("HTTP_ERROR",
          "otlp-grpc: grpc-status " + grpcStatus +
          (grpcMessage ? " — " + grpcMessage : "")));
      }
      resolve();
    });

    req.end(framed);
  });
}

// ---- Public sink factory ----

function create(config) {
  if (!config || !config.url) {
    throw _err("BAD_OPT", "log-stream otlp-grpc: { url } is required");
  }
  // Reject http:// without explicit allowInsecure — gRPC endpoints
  // are virtually always TLS in real deployments.
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

  // Fire-and-forget enqueue: full batch drains immediately (not awaited —
  // emit is hot-path), partial batch coalesces via the scheduler. Errors
  // surface through onDrop. No dropCount here — gRPC drop accounting is the
  // export stream's concern, not the buffer's.
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
    // Drain the in-flight Export before tearing down the HTTP/2 session.
    // The promise rejection (if any) was already routed through onDrop
    // by _flush — we only await here to avoid racing the teardown.
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
    // Tear down the HTTP/2 session via the shared close+destroy helper.
    // By this point we've already awaited inflightPromise and run a
    // final _doExport for any buffered records, so there's nothing left
    // to drain. See lib/http2-teardown.js for the rationale on why
    // close() alone leaves the underlying socket connected on Linux.
    tearDownH2Session(session);
    session = null;
  }

  return {
    protocol: "otlp-grpc",
    emit:     emit,
    close:    close,
    // Test hooks — encode without sending.
    _encodeForTest:    function (records) { return _encodeExportRequest(records, cfg); },
    _frameForTest:     _frame,
  };
}

module.exports = {
  create:                create,
  // Exposed for layer-0 tests that verify the wire encoding without
  // standing up an HTTP/2 server.
  _makeClient:           _makeClient,
  _encodeAnyValue:       _encodeAnyValue,
  _encodeKeyValue:       _encodeKeyValue,
  _encodeLogRecord:      _encodeLogRecord,
  _encodeExportRequest:  _encodeExportRequest,
  _frame:                _frame,
};
