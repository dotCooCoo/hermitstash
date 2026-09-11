// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var C = require("./constants");
var retryHelper = require("./retry");
var { LogStreamError } = require("./framework-error");
var httpClient = require("./http-client");
var safeAsync = require("./safe-async");
var safeUrl = require("./safe-url");
var authHeader = require("./auth-header");

var MAX_RESPONSE_BYTES = C.BYTES.mib(1);

var DEFAULTS = {
  batchSize:     100,
  maxBatchAgeMs: C.TIME.seconds(5),
  contentType:   "application/json",
  bodyShape:     "array",
  timeoutMs:     C.TIME.seconds(30),
  bufferLimit:   C.BYTES.bytes(10000),
};

function _authHeaders(config) {
  if (config.auth === "header") return Object.assign({}, config.headers || {});
  return authHeader.fromConfig(config);
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

function _serializeBatch(records, shape) {
  if (shape === "ndjson") {
    return Buffer.from(records.map(function (r) { return JSON.stringify(r); }).join("\n") + "\n", "utf8");
  }
  if (shape === "singleEnvelope") {
    return Buffer.from(JSON.stringify({ events: records }), "utf8");
  }
  return Buffer.from(JSON.stringify(records), "utf8");
}

function create(config) {
  if (!config || !config.url) throw new Error("log-stream webhook requires { url }");
  var cfg = Object.assign({}, DEFAULTS, config);
  safeUrl.parse(cfg.url, {
    allowedProtocols: cfg.allowedProtocols || safeUrl.ALLOW_HTTP_TLS,
    errorClass:       LogStreamError,
  });
  var headers = Object.assign({ "Content-Type": cfg.contentType }, _authHeaders(cfg));
  var sink = safeAsync.makeBatchingSink({
    batchSize:     cfg.batchSize,
    bufferLimit:   cfg.bufferLimit,
    maxBatchAgeMs: cfg.maxBatchAgeMs,
    onDrop:        cfg.onDrop,
    sendBatch:     function (batch) {
      var body = _serializeBatch(batch, cfg.bodyShape);
      return retryHelper.withRetry(function () {
        return _post(cfg.url, body, headers, cfg.timeoutMs, cfg.allowedProtocols, cfg.allowInternal);
      }, cfg.retry);
    },
  });

  return {
    protocol:  "webhook",
    emit:      sink.emit,
    close:     sink.close,
    stats:     sink.stats,
    flush:     sink.flush,
  };
}

module.exports = { create: create };
