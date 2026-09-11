// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var C = require("./constants");
var boundedMap = require("./bounded-map");
var canonicalJson = require("./canonical-json");
var httpClient = require("./http-client");
var observability = require("./observability");
var safeAsync = require("./safe-async");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var OtelExportError = defineClass("OtelExportError", { alwaysPermanent: false });

var DEFAULT_INTERVAL_MS = C.TIME.seconds(15);

var MAX_RESPONSE_BYTES = C.BYTES.mib(1);

var TEMPORALITY_DELTA = 1;

function _attrsToOtlp(attrs) {
  attrs = observability.redactAttrs(attrs);
  var out = [];
  if (!attrs || typeof attrs !== "object") return out;
  var keys = Object.keys(attrs);
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    var v = attrs[k];
    var kv;
    if (typeof v === "string")  kv = { stringValue: v };
    else if (typeof v === "number") {
      kv = Number.isInteger(v) ? { intValue: String(v) } : { doubleValue: v };
    }
    else if (typeof v === "boolean") kv = { boolValue: v };
    else if (v == null) continue;
    else kv = { stringValue: String(v) };
    out.push({ key: k, value: kv });
  }
  return out;
}

function _bucketKey(name, attrs) {
  if (!attrs) return name + "|";
  var coerced = {};
  var rawKeys = Object.keys(attrs);
  for (var i = 0; i < rawKeys.length; i++) {
    coerced[rawKeys[i]] = String(attrs[rawKeys[i]]);
  }
  return name + "|" + canonicalJson.stringify(coerced);
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "endpoint", "headers", "serviceName", "intervalMs",
    "httpClient", "resourceAttributes", "scope",
  ], "otelExport.create");
  validateOpts.requireNonEmptyString(opts.endpoint, "create: endpoint", OtelExportError, "otel-export/bad-endpoint");
  validateOpts.requireNonEmptyString(opts.serviceName, "create: serviceName", OtelExportError, "otel-export/bad-service-name");
  var endpoint = opts.endpoint;
  var serviceName = opts.serviceName;
  var headers = opts.headers || {};
  var intervalMs = opts.intervalMs != null ? opts.intervalMs : DEFAULT_INTERVAL_MS;
  if (typeof intervalMs !== "number" || !isFinite(intervalMs) || intervalMs < 0) {
    throw new OtelExportError("otel-export/bad-interval",
      "create: intervalMs must be a non-negative finite number");
  }
  var effectiveHttpClient = opts.httpClient || httpClient;
  var scopeName = (opts.scope && opts.scope.name) || "blamejs";
  var scopeVersion = (opts.scope && opts.scope.version) || "0.5.x";
  var resourceAttrs = Object.assign({ "service.name": serviceName },
    opts.resourceAttributes || {});

  var counters = new Map();
  var observations = new Map();
  var startUnixNano = String(Date.now() * 1e6);
  var loop = null;
  var closed = false;

  function recordCounter(name, value, attrs) {
    if (closed) return;
    if (typeof name !== "string" || name.length === 0) return;
    var v = typeof value === "number" && isFinite(value) ? value : 1;
    var key = _bucketKey(name, attrs);
    var b = boundedMap.getOrInsert(counters, key, function () {
      return { name: name, attrs: attrs || {}, value: 0, startUnixNano: startUnixNano };
    });
    b.value += v;
  }

  function recordObservation(name, value, attrs) {
    if (closed) return;
    if (typeof name !== "string" || name.length === 0) return;
    if (typeof value !== "number" || !isFinite(value)) return;
    var key = _bucketKey(name, attrs);
    var b = boundedMap.getOrInsert(observations, key, function () {
      return { name: name, attrs: attrs || {}, sum: 0, count: 0, min: value, max: value, startUnixNano: startUnixNano };
    });
    b.sum   += value;
    b.count += 1;
    if (value < b.min) b.min = value;
    if (value > b.max) b.max = value;
  }

  function tapHandler(name, value, labels) {
    recordCounter(name, value, labels);
  }

  function _drainAndEncode() {
    var nowUnixNano = String(Date.now() * 1e6);
    var metrics = [];
    var c, o;

    counters.forEach(function (entry) {
      metrics.push({
        name: entry.name,
        sum: {
          dataPoints: [{
            attributes:        _attrsToOtlp(entry.attrs),
            startTimeUnixNano: entry.startUnixNano,
            timeUnixNano:      nowUnixNano,
            asDouble:          entry.value,
          }],
          aggregationTemporality: TEMPORALITY_DELTA,
          isMonotonic:            true,
        },
      });
    });
    void c;
    observations.forEach(function (entry) {
      metrics.push({
        name: entry.name,
        summary: {
          dataPoints: [{
            attributes:        _attrsToOtlp(entry.attrs),
            startTimeUnixNano: entry.startUnixNano,
            timeUnixNano:      nowUnixNano,
            count:             String(entry.count),
            sum:               entry.sum,
            quantileValues: [
              { quantile: 0,   value: entry.min },
              { quantile: 1,   value: entry.max },
            ],
          }],
        },
      });
    });
    void o;

    counters.clear();
    observations.clear();
    startUnixNano = nowUnixNano;
    if (metrics.length === 0) return null;
    return {
      resourceMetrics: [{
        resource: { attributes: _attrsToOtlp(resourceAttrs) },
        scopeMetrics: [{
          scope:   { name: scopeName, version: scopeVersion },
          metrics: metrics,
        }],
      }],
    };
  }

  async function flush() {
    var payload = _drainAndEncode();
    if (!payload) return { sent: false, reason: "no-data" };
    var body = JSON.stringify(payload);
    try {
      var res = await effectiveHttpClient.request({
        method:           "POST",
        url:              endpoint,
        headers:          Object.assign({ "Content-Type": "application/json" }, headers),
        body:             body,
        maxResponseBytes: MAX_RESPONSE_BYTES,
        errorClass:       OtelExportError,
      });
      if (res.statusCode < 200 || res.statusCode >= 300) {
        throw new OtelExportError("otel-export/upstream-rejected",
          "OTLP endpoint returned " + res.statusCode);
      }
      return { sent: true, statusCode: res.statusCode, bodyLength: body.length };
    } catch (e) {
      if (e && e.isOtelExportError) throw e;
      throw new OtelExportError("otel-export/send-failed",
        "OTLP send failed: " + ((e && e.message) || String(e)));
    }
  }

  if (intervalMs > 0) {
    loop = safeAsync.flushLoop(flush, intervalMs, { name: "otel-flush" });
  }

  function close() {
    if (closed) return;
    closed = true;
    if (loop) { loop.stop(); loop = null; }
    return flush().catch(function (_e) { /* close path swallows final-flush errors */ });
  }

  return {
    recordCounter:     recordCounter,
    recordObservation: recordObservation,
    tapHandler:        tapHandler,
    flush:             flush,
    close:             close,
    get bufferedCounters()     { return counters.size; },
    get bufferedObservations() { return observations.size; },
  };
}

module.exports = {
  create:           create,
  OtelExportError:  OtelExportError,
  _attrsToOtlpForTest: _attrsToOtlp,
  _bucketKeyForTest:   _bucketKey,
};
