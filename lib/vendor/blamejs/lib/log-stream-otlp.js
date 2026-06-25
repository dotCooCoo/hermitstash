"use strict";
/**
 * OTLP/HTTP-JSON log sink — OpenTelemetry Protocol logs over HTTP/JSON.
 *
 * Per the OTLP spec (v1.3+, Logs Data Model), log records are wrapped in
 * a ResourceLogs envelope and POSTed to the operator's collector
 * endpoint. Marshalling is OTel-native: timeUnixNano (string), severity
 * mapping per OTel spec, attribute typing.
 *
 * Operator config:
 *
 *   {
 *     url:                 "https://otel-collector.example.com:4318/v1/logs"
 *                          // OR the collector root — "/v1/logs" auto-appended
 *     headers:             { ... }   // additional headers (api keys, tenant ids)
 *     auth:                'none' | 'bearer' | 'basic' | 'header'
 *     token / username+password
 *     serviceName:         "my-service"   // emitted as resource service.name
 *     serviceVersion:      "1.2.3"        // resource service.version
 *     resourceAttributes:  { env: "prod", region: "us-east-1" }
 *                          // additional resource attributes
 *     scopeName:           "blamejs"      // instrumentation scope name
 *     batchSize:           100
 *     maxBatchAgeMs:       C.TIME.seconds(5)
 *     timeoutMs:           C.TIME.seconds(30)
 *     retry:               { maxAttempts, baseDelayMs, ... }
 *     bufferLimit:         10000   // ring-buffer cap; drops oldest on overflow
 *     onDrop:              function ({ reason, batch, error }) { ... }
 *   }
 *
 * Severity mapping (per OTel Logs Data Model):
 *   debug → 5 (DEBUG)
 *   info  → 9 (INFO)
 *   warn  → 13 (WARN)
 *   error → 17 (ERROR)
 *
 * Endpoint convention: most OTel collectors expose:
 *   <base>:4318/v1/logs   — HTTP/JSON path (per OTLP HTTP §4.5)
 *   <base>:4317           — gRPC path (NOT supported here)
 *
 * If `url` ends in `/v1/logs` it's used as-is. If not, `/v1/logs` is
 * appended (collector root → logs endpoint). Operators with a custom
 * routing prefix pass the full URL.
 *
 * Why JSON not protobuf: protobuf needs a schema parser (vendored dep
 * or hand-rolled). The OTLP/HTTP spec accepts both Content-Type:
 * application/json and application/x-protobuf; the JSON variant is the
 * "no extra deps" path consistent with the framework's vendoring stance.
 * Operators benchmarking >100K logs/s ship the OTel Collector locally
 * (collector → upstream gRPC) — this sink hands JSON to the local
 * collector which forwards.
 */
var C = require("./constants");
var pkg = require("../package.json");
var retryHelper = require("./retry");
var { LogStreamError } = require("./framework-error");
var httpClient = require("./http-client");
var safeAsync = require("./safe-async");
var safeUrl = require("./safe-url");
var authHeader = require("./auth-header");
var lazyRequire = require("./lazy-require");
// Lazy to break the observability <-> log-stream require cycle (observability's
// log path can reach a log-stream sink). Used only to scrub attribute values
// through the telemetry redactor before they cross the OTLP egress boundary.
var observability = lazyRequire(function () { return require("./observability"); });

var MAX_RESPONSE_BYTES = C.BYTES.mib(1);
var FRAMEWORK_VERSION = (pkg && pkg.version) || "unknown";

// OTel Logs Data Model severity numbers.
// https://opentelemetry.io/docs/specs/otel/logs/data-model/#field-severitynumber
var SEVERITY = {
  debug: { number: 5,  text: "DEBUG" },
  info:  { number: 9,  text: "INFO"  },
  warn:  { number: 13, text: "WARN"  },
  error: { number: 17, text: "ERROR" },
};

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

var _err = LogStreamError.factory;

function _resolveUrl(url) {
  // If the URL already ends in "/v1/logs" (with or without trailing slash),
  // use as-is. Otherwise treat as the collector root and append.
  var trimmed = url.replace(/\/+$/, "");
  if (/\/v1\/logs$/.test(trimmed)) return trimmed;
  return trimmed + "/v1/logs";
}

function _authHeaders(config) {
  if (config.auth === "header") return Object.assign({}, config.headers || {});
  return authHeader.fromConfig(config);
}

// OTel attribute encoding — JSON form per OTLP spec. Each attribute is
// { key: <name>, value: { <type>Value: <v> } } where the type field
// matches the JS type at the boundary.
function _encodeAttrValue(v) {
  if (v === null || v === undefined) return null;
  var t = typeof v;
  if (t === "string")  return { stringValue: v };
  if (t === "boolean") return { boolValue: v };
  if (t === "number") {
    if (Number.isInteger(v)) return { intValue: String(v) };       // OTLP int is string-encoded
    return { doubleValue: v };
  }
  if (Array.isArray(v)) {
    return { arrayValue: { values: v.map(function (e) { return _encodeAttrValue(e); }).filter(Boolean) } };
  }
  if (t === "object") {
    return { kvlistValue: { values: _encodeAttrs(v) } };
  }
  return { stringValue: String(v) };
}

function _encodeAttrs(obj) {
  if (!obj || typeof obj !== "object") return [];
  return Object.keys(obj).map(function (k) {
    var encoded = _encodeAttrValue(obj[k]);
    if (!encoded) return null;
    return { key: k, value: encoded };
  }).filter(Boolean);
}

function _resourceAttrs(cfg) {
  var attrs = {};
  if (cfg.serviceName)    attrs["service.name"]    = cfg.serviceName;
  if (cfg.serviceVersion) attrs["service.version"] = cfg.serviceVersion;
  if (cfg.resourceAttributes && typeof cfg.resourceAttributes === "object") {
    Object.assign(attrs, cfg.resourceAttributes);
  }
  return attrs;
}

function _toLogRecord(record) {
  var sev = SEVERITY[record.level] || SEVERITY.info;
  // OTel timeUnixNano is a string (JSON can't safely represent 64-bit ints).
  var nanos = String(BigInt(record.ts) * 1000000n);
  // Telemetry is a first-class EGRESS sink: scrub every meta value through the
  // redactor before it reaches the collector wire (CWE-532), the same contract
  // the span/metric exporters hold.
  var attrs = record.meta ? _encodeAttrs(observability().redactAttrs(record.meta)) : [];
  return {
    timeUnixNano:     nanos,
    observedTimeUnixNano: nanos,
    severityNumber:   sev.number,
    severityText:     sev.text,
    body:             { stringValue: record.message == null ? "" : String(record.message) },
    attributes:       attrs,
  };
}

function _serializeBatch(records, cfg, scopeVersion) {
  var resourceAttrs = _resourceAttrs(cfg);
  return Buffer.from(JSON.stringify({
    resourceLogs: [
      {
        resource: {
          attributes: _encodeAttrs(observability().redactAttrs(resourceAttrs)),
        },
        scopeLogs: [
          {
            scope: {
              name:    cfg.scopeName,
              version: scopeVersion,
            },
            logRecords: records.map(_toLogRecord),
          },
        ],
      },
    ],
  }), "utf8");
}

function _post(url, body, headers, timeoutMs, allowedProtocols, allowInternal) {
  return httpClient.request({
    method:           "POST",
    url:              url,
    headers:          headers,
    body:             body,
    timeoutMs:        timeoutMs,
    idleTimeoutMs:    timeoutMs,
    maxResponseBytes: MAX_RESPONSE_BYTES,
    errorClass:       LogStreamError,
    allowedProtocols: allowedProtocols,
    allowInternal:    allowInternal,
  });
}

function create(config) {
  if (!config || !config.url) throw _err("BAD_OPT", "log-stream otlp requires { url }");
  var cfg = Object.assign({}, DEFAULTS, config);
  var resolvedUrl = _resolveUrl(cfg.url);
  // Validate URL shape + scheme at create time. Default HTTPS-only;
  // operators with an internal cleartext OTel collector pass
  // cfg.allowedProtocols (safeUrl.ALLOW_HTTP_ALL).
  safeUrl.parse(resolvedUrl, {
    allowedProtocols: cfg.allowedProtocols || safeUrl.ALLOW_HTTP_TLS,
    errorClass:       LogStreamError,
  });
  var scopeVersion = cfg.scopeVersion || FRAMEWORK_VERSION;
  var headers = Object.assign({
    "Content-Type": "application/json",
    "Accept":       "application/json",
  }, _authHeaders(cfg));
  var sink = safeAsync.makeBatchingSink({
    batchSize:     cfg.batchSize,
    bufferLimit:   cfg.bufferLimit,
    maxBatchAgeMs: cfg.maxBatchAgeMs,
    onDrop:        cfg.onDrop,
    sendBatch:     function (batch) {
      var body = _serializeBatch(batch, cfg, scopeVersion);
      return retryHelper.withRetry(function () {
        return _post(resolvedUrl, body, headers, cfg.timeoutMs, cfg.allowedProtocols, cfg.allowInternal);
      }, cfg.retry);
    },
  });

  return {
    protocol: "otlp",
    emit:     sink.emit,
    close:    sink.close,
    stats:    function () { return sink.stats({ url: resolvedUrl }); },
    flush:    sink.flush,
  };
}

module.exports = {
  create:         create,
  // Exposed for tests + advanced operator wiring.
  _resolveUrl:    _resolveUrl,
  _encodeAttrs:   _encodeAttrs,
  _toLogRecord:   _toLogRecord,
  _serializeBatch: _serializeBatch,
  SEVERITY:       SEVERITY,
};
