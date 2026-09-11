// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var C = require("./constants");
var codepointClass = require("./codepoint-class");
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
// Lazy to match the observability cycle-break above. Scrubs secrets embedded in
// the free-text log body for a directly-wired sink (defense in depth — emit()
// already redacts, but a sink can be driven without it, same as meta/redactAttrs).
var redact = lazyRequire(function () { return require("./redact"); });

var MAX_RESPONSE_BYTES = C.BYTES.mib(1);
var FRAMEWORK_VERSION = (pkg && pkg.version) || "unknown";

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
  bufferLimit:   C.BYTES.bytes(10000),
};

var _err = LogStreamError.factory;

function _resolveUrl(url) {
  var trimmed = codepointClass.trimTrailingChars(url, "/");
  if (/\/v1\/logs$/.test(trimmed)) return trimmed;
  return trimmed + "/v1/logs";
}

function _authHeaders(config) {
  if (config.auth === "header") return Object.assign({}, config.headers || {});
  return authHeader.fromConfig(config);
}

function _encodeAttrValue(v) {
  if (v === null || v === undefined) return null;
  var t = typeof v;
  if (t === "string")  return { stringValue: v };
  if (t === "boolean") return { boolValue: v };
  if (t === "number") {
    if (Number.isInteger(v)) return { intValue: String(v) };
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
  var nanos = String(BigInt(record.ts) * 1000000n);
  var attrs = record.meta ? _encodeAttrs(observability().redactAttrs(record.meta)) : [];
  return {
    timeUnixNano:     nanos,
    observedTimeUnixNano: nanos,
    severityNumber:   sev.number,
    severityText:     sev.text,
    body:             { stringValue: record.message == null ? "" : redact().redactText(String(record.message)) },
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
  if (!config || !config.url) throw _err("log-stream-otlp/bad-opt", "log-stream otlp requires { url }");
  var cfg = Object.assign({}, DEFAULTS, config);
  var resolvedUrl = _resolveUrl(cfg.url);
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
  _resolveUrl:    _resolveUrl,
  _encodeAttrs:   _encodeAttrs,
  _toLogRecord:   _toLogRecord,
  _serializeBatch: _serializeBatch,
  SEVERITY:       SEVERITY,
};
