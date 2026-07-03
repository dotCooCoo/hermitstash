// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * otel-export — OTLP/HTTP-JSON exporter for `b.observability` events.
 *
 * Bridges the framework's `observability.event(name, value, attrs)`
 * surface to any OTel-compatible backend (Honeycomb, Datadog, Jaeger
 * Collector, AWS Distro, Grafana, NewRelic — anything that speaks
 * OTLP/HTTP). Spec: opentelemetry.io/docs/specs/otlp.
 *
 *   var otel = b.otelExport.create({
 *     endpoint:     "https://otel.honeycomb.io/v1/metrics",
 *     headers:      { "X-Honeycomb-Team": env("HONEYCOMB_API_KEY") },
 *     serviceName:  "wiki",
 *     intervalMs:   b.constants.TIME.seconds(15),  // auto-flush cadence
 *     httpClient:   b.httpClient,                  // for testing
 *   });
 *
 *   // Counter — accumulates per (name, attrs) tuple, flushed in batches.
 *   otel.recordCounter("http.requests", 1, { method: "GET", status: 200 });
 *
 *   // Histogram — operator-bucketed observation. Less common; operators
 *   // wanting full histogram support build on top.
 *   otel.recordObservation("http.duration_ms", 142, { route: "/api/x" });
 *
 *   await otel.flush();   // manual flush
 *   otel.close();         // cancels interval, final flush
 *
 * Wiring with `b.observability`:
 *
 *   // Option A: install as an external tap on b.observability
 *   b.observability.setTap(otel.tapHandler);
 *
 *   // Option B: alongside b.metrics — operators write their own
 *   // multi-tap fan-out (or pick one or the other for v1).
 *
 * Endpoint must accept OTLP/HTTP with Content-Type: application/json
 * (the JSON variant of the OTLP protobuf — every modern collector
 * supports it). The framework refuses to ship the binary protobuf
 * encoding because it requires either a vendored proto runtime or
 * hand-rolled wire format with no compelling benefit at this scope.
 */
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

// OTLP collector response is `Empty` (zero protobuf bytes) on success
// or a short ExportPartialSuccess message on partial accept. A response
// past this cap is a hostile / misbehaving collector; refusing the
// body keeps the exporter from buffering megabytes per flush (CVE-2026-
// 40891 / CVE-2026-40182 OTLP class).
var MAX_RESPONSE_BYTES = C.BYTES.mib(1);

// OTLP aggregation temporality:
//   1 = DELTA      — counters report deltas since last export
//   2 = CUMULATIVE — counters report running totals
// DELTA is what most exporters do for short-lived processes; the
// receiving backend handles the running sum.
var TEMPORALITY_DELTA = 1;

// ---- attribute encoding ----
// OTLP attributes are KeyValue with typed `value` fields:
//   { key, value: { stringValue | intValue | doubleValue | boolValue } }
// Telemetry is a first-class EGRESS sink — an attribute value holding a user
// email, bearer token, or vault-sealed ciphertext would otherwise be serialized
// verbatim onto the OTLP wire (CWE-532). observability.redactAttrs scrubs every
// value through the active redactor (operator overrides via setRedactor take
// effect without re-creating the exporter) and drops any key whose redactor
// throws — failing toward dropping, never leaking, on the export hot path.
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

// Stable key per (name, attrs) so tap calls aggregate. Routes the
// sort through canonical-json so the framework has one canonical-sort
// source of truth for hash-input-shaped keys (the OTLP attribute
// encoding _attrsToOtlp emits the wire-format separately).
function _bucketKey(name, attrs) {
  if (!attrs) return name + "|";
  // Coerce to strings so canonical-json doesn't reject odd value types.
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

  // Buckets: counters and observations keyed by (name, sorted-attrs).
  var counters = new Map();          // bucketKey → { name, attrs, value, startUnixNano }
  var observations = new Map();      // bucketKey → { name, attrs, sum, count, min, max, startUnixNano }
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

  // Operators wire this as the observability tap. event(name, value, labels)
  // → recordCounter for value=1 fire-and-forget shapes.
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

    // Reset buckets (DELTA temporality — each export is the delta).
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
  // Test-only encoders for unit-testing the OTLP shape without an HTTP client.
  _attrsToOtlpForTest: _attrsToOtlp,
  _bucketKeyForTest:   _bucketKey,
};
