// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.otelExport
 * @nav    Observability
 * @title  OTLP Export
 * @slug   otel-export
 *
 * @intro
 *   Send the counters and measurements the framework records to an
 *   OpenTelemetry collector, as OTLP over HTTP.
 *
 *   It aggregates in this process and sends on an interval rather than
 *   sending per event, because a request-per-metric would make the
 *   collector's load a copy of the application's. Counters go out with
 *   delta temporality, so each send carries what happened since the last
 *   one and a collector restart cannot double-count.
 *
 *   Attributes pass through <code>b.observability</code>'s redactor before
 *   they leave, so a label that picked up a token or an address is
 *   scrubbed on the way out rather than at the collector, which is a
 *   different trust boundary and often a different company.
 *
 *   The response is read under a size cap, so a collector answering with
 *   something large does not become this process's memory.
 *
 * @card
 *   Export the framework's counters and measurements to an OpenTelemetry
 *   collector over OTLP/HTTP, aggregated in process and sent on an
 *   interval, with attributes redacted before they leave.
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

/**
 * @primitive b.otelExport.create
 * @signature b.otelExport.create(opts)
 * @since     0.5.16
 * @status    stable
 * @compliance soc2
 * @related   b.observability.tap, b.observability.setRedactor
 *
 * Open an exporter and answer the handle to feed it. The handle carries
 * `recordCounter(name, value, attrs?)` for something that only goes up,
 * `recordObservation(name, value, attrs?)` for a measured value,
 * `tapHandler`, which is the shape `b.observability.setTap` takes so the
 * framework's own events are exported without a per-call-site change,
 * `flush()` to send now, `close()` to stop the interval and send what is
 * held, and the `bufferedCounters` and `bufferedObservations` properties,
 * which read how much is waiting.
 *
 * `endpoint` and `serviceName` are required and refused when empty.
 * `headers` carries whatever the collector authenticates with.
 * `resourceAttributes` and `scope` label everything sent. `httpClient`
 * replaces the transport, which is what a test drives instead of a socket.
 *
 * @opts
 *   endpoint:           string,   // OTLP/HTTP collector URL; required
 *   serviceName:        string,   // service.name on everything sent; required
 *   headers:            object,   // sent with each request, for collector auth
 *   intervalMs:         number,   // send interval; default 15000
 *   resourceAttributes: object,   // resource-level attributes
 *   scope:              object,   // instrumentation scope
 *   httpClient:         object,   // replaces b.httpClient as the transport
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var otel = b.otelExport.create({
 *     endpoint:    "https://collector.example/v1/metrics",
 *     serviceName: "orders-api",
 *     headers:     { authorization: "Bearer " + token },
 *   });
 *   b.observability.setTap(otel.tapHandler);
 *   otel.recordCounter("orders.placed", 1, { region: "eu" });
 *   await otel.close();
 */
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
