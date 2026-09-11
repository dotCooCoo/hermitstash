// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.metrics
 * @nav    Observability
 * @title  Metrics
 *
 * @intro
 *   Counter / gauge / histogram primitives in Prometheus 0.0.4 text
 *   format with OTLP-friendly labels, plus framework auto-instrumentation
 *   wired into audit / vault / queue hot paths.
 *
 *   `b.metrics.create()` returns a registry — call `counter(name)` /
 *   `gauge(name)` / `histogram(name)` to register typed metrics, then
 *   `requestMiddleware()` for per-request counter+latency, and
 *   `expositionHandler()` for the `/metrics` scrape route. Every metric
 *   carries a per-instance `labelCardinalityCap` (default 10,000) — when
 *   the next label combination would push past the cap the increment
 *   drops and a single warning logs, so a runaway label (request-id,
 *   raw URL with query string, per-user dimension) can't OOM the
 *   process.
 *
 *   Framework modules call `metrics.tap("audit.record", value, labels)`
 *   at hot paths. Until a registry is active the call is a zero-cost
 *   no-op; once `create()` runs, taps flow into pre-registered
 *   counters / gauges (`framework_audit_events_total`,
 *   `framework_vault_seal_total`, `framework_queue_depth`,
 *   `framework_jobs_inflight`, `framework_errors_total`,
 *   `framework_http_requests_total`,
 *   `framework_http_request_duration_seconds`).
 *
 *   Best-practice route labels are the route TEMPLATE
 *   (`/users/:id`), not the actual path — `requestMiddleware` reads
 *   `req.routePattern` when the matcher set one and falls back to the
 *   query-stripped URL otherwise.
 *
 * @card
 *   Counter / gauge / histogram primitives in Prometheus 0.0.4 text format with OTLP-friendly labels, plus framework auto-instrumentation wired into audit / vault / queue hot paths.
 */

var C = require("./constants");
var time = require("./time");
var canonicalJson = require("./canonical-json");
var atomicFile = require("./atomic-file");
var safeJson = require("./safe-json");
var { defineClass } = require("./framework-error");
var { boot } = require("./log");
var numericBounds = require("./numeric-bounds");
var requestHelpers = require("./request-helpers");
var { resolveRoute, captureResponseStatus, HTTP_STATUS } = requestHelpers;
var validateOpts = require("./validate-opts");
var boundedMap = require("./bounded-map");

var MetricsError = defineClass("MetricsError", { alwaysPermanent: true });
var log = boot("metrics");

var DEFAULT_HTTP_BUCKETS = Object.freeze([
  0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
]);

var DEFAULT_CARDINALITY_CAP = C.BYTES.bytes(10000);
var MAX_METRIC_NAME_LEN = 200;
var METRIC_NAME_RE = /^[a-zA-Z_:][a-zA-Z0-9_:]*$/;
var LABEL_NAME_RE  = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

// Drop-silent by design: the wrapping try/catch is intentional. tap is
// tap() is the drop-silent boundary.

var _activeTap = null;

/**
 * @primitive b.metrics.tap
 * @signature b.metrics.tap(name, value, labels)
 * @since     0.4.0
 * @related   b.metrics.create, b.observability.event
 *
 * Framework hot-path tap. Modules call `tap("audit.record", 1,
 * { action, outcome })` without importing a registry. Until
 * `b.metrics.create()` runs the call is a zero-cost no-op; afterwards
 * the active registry routes the tap into pre-registered counters and
 * gauges. Drop-silent on internal throws so a misconfigured metric
 * cannot crash the request that triggered the tap.
 *
 * @example
 *   // Module-level — no registry yet, no-op:
 *   b.metrics.tap("audit.record", 1, { action: "auth.login", outcome: "success" });
 *
 *   // After registry creation, the same tap call increments
 *   // framework_audit_events_total{action="auth.login", outcome="success"}.
 *   var registry = b.metrics.create({ namespace: "myapp" });
 *   b.metrics.tap("audit.record", 1, { action: "auth.login", outcome: "success" });
 */
function tap(name, value, labels) {
  if (_activeTap === null) return;
  try { _activeTap(name, value, labels); }
  catch (_e) { /* tap path errors must not break callers */ }
}

function _validateMetricName(name) {
  if (typeof name !== "string" || name.length > MAX_METRIC_NAME_LEN ||
      !METRIC_NAME_RE.test(name)) {
    throw new MetricsError("metrics/bad-name",
      "metric name '" + name + "' must match " + METRIC_NAME_RE +
      " (max " + MAX_METRIC_NAME_LEN + " chars)");
  }
}
function _validateLabelName(name) {
  if (typeof name !== "string" || name.length > MAX_METRIC_NAME_LEN ||
      !LABEL_NAME_RE.test(name)) {
    throw new MetricsError("metrics/bad-label",
      "label name '" + name + "' must match " + LABEL_NAME_RE +
      " (max " + MAX_METRIC_NAME_LEN + " chars)");
  }
}
function _normalizeLabelArg(callLabels, value, defaultValue) {
  if (typeof callLabels === "number") {
    return { labels: null, value: callLabels };
  }
  return {
    labels: callLabels,
    value:  typeof value === "number" ? value : defaultValue,
  };
}

var _CRED_PREFIX_RE = /^(?:Bearer|Basic|Negotiate|Token|Digest)\s+\S/i;
var _CRED_ISSUER_RE = /^(?:sk-|pk-|rk-|ghp_|ghs_|gho_|github_pat_|xoxb-|xoxa-|xoxp-|xoxr-|xapp-)/;
var _CRED_JWT_RE    = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/;
var _CRED_ENTROPY_RE = /^[A-Za-z0-9_+/=-]{40,}$/;

var CRED_MAX_SCAN = 256;

function _looksLikeCredential(str) {
  if (typeof str !== "string") return false;
  if (str.length < 8) return false;
  var clamped = str.length > CRED_MAX_SCAN ? str.slice(0, CRED_MAX_SCAN) : str;
  var CRED_MIN_LEN = 8;
  if (clamped.length >= CRED_MIN_LEN && _CRED_PREFIX_RE.test(clamped)) return true;
  if (clamped.length >= CRED_MIN_LEN && _CRED_ISSUER_RE.test(clamped)) return true;
  if (clamped.length >= CRED_MIN_LEN && _CRED_JWT_RE.test(clamped)) return true;
  if (clamped.length >= CRED_MIN_LEN && _CRED_ENTROPY_RE.test(clamped)) return true;
  return false;
}

function _validateLabelValue(value) {
  if (value === null || value === undefined) return "";
  var coerced = String(value);
  if (_looksLikeCredential(coerced)) return "[REDACTED-CREDENTIAL]";
  return coerced;
}

function _redactLabelMap(labelObj) {
  var out = {};
  if (!labelObj || typeof labelObj !== "object") return out;
  var keys = Object.keys(labelObj);
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    if (k.length > MAX_METRIC_NAME_LEN || !LABEL_NAME_RE.test(k)) continue;
    out[k] = _validateLabelValue(labelObj[k]);
  }
  return out;
}

function _numericExemplarField(value, fallback) {
  var n = typeof value === "number" ? value : Number(value);
  return isFinite(n) ? n : fallback;
}

function _labelsKey(labels) {
  if (!labels) return "";
  var coerced = {};
  var keys = Object.keys(labels);
  for (var i = 0; i < keys.length; i++) {
    coerced[keys[i]] = _validateLabelValue(labels[keys[i]]);
  }
  return canonicalJson.stringify(coerced);
}

function _escapeLabelValue(v) {
  return String(v).replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, "\\\"");
}

function _renderLabels(labelObj) {
  if (!labelObj) return "";
  var sortedKeys = _sortedLabelKeys(labelObj);
  if (sortedKeys.length === 0) return "";
  var parts = [];
  for (var k = 0; k < sortedKeys.length; k++) {
    parts.push(sortedKeys[k] + '="' + _escapeLabelValue(labelObj[sortedKeys[k]]) + '"');
  }
  return "{" + parts.join(",") + "}";
}

function _sortedLabelKeys(labelObj) {
  var keys = Object.keys(labelObj);
  keys.sort();
  return keys;
}

function _renderFamilyLines(family, openMetrics, lines) {
  var exposedName = family.name;
  if (openMetrics && family.type === "counter" && !/_total$/.test(family.name)) {                    // allow:regex-no-length-cap — name-suffix check
    exposedName = family.name + "_total";
  }
  if (family.help) lines.push("# HELP " + exposedName + " " + family.help);
  lines.push("# TYPE " + exposedName + " " + family.type);
  if (openMetrics && family.unit) lines.push("# UNIT " + exposedName + " " + family.unit);
  var entries = family.entries;
  if (family.type === "histogram") {
    for (var k = 0; k < entries.length; k++) {
      var entry = entries[k];
      for (var bi = 0; bi < family.buckets.length; bi++) {
        var bLabels = Object.assign(Object.create(null), entry.labels, { le: String(family.buckets[bi]) });
        var bucketLine = family.name + "_bucket" + _renderLabels(bLabels) + " " + entry.counts[bi];
        if (openMetrics && entry.exemplars && entry.exemplars[bi]) {
          var ex = entry.exemplars[bi];
          bucketLine += " # " + _renderLabels(ex.labels || {}) + " " + ex.value;
          if (typeof ex.timestamp === "number") bucketLine += " " + ex.timestamp;
        }
        lines.push(bucketLine);
      }
      var infLabels = Object.assign(Object.create(null), entry.labels, { le: "+Inf" });
      lines.push(family.name + "_bucket" + _renderLabels(infLabels) + " " + entry.counts[family.buckets.length]);
      lines.push(family.name + "_sum"   + _renderLabels(entry.labels) + " " + entry.sum);
      lines.push(family.name + "_count" + _renderLabels(entry.labels) + " " + entry.count);
    }
  } else {
    for (var v = 0; v < entries.length; v++) {
      lines.push(exposedName + _renderLabels(entries[v].labels) + " " + entries[v].value);
    }
  }
}

function _familySamples(family) {
  var out = Object.create(null);
  for (var i = 0; i < family.entries.length; i++) {
    var entry = family.entries[i];
    if (family.type === "histogram") {
      for (var bi = 0; bi < family.buckets.length; bi++) {
        var bLabels = Object.assign(Object.create(null), entry.labels, { le: String(family.buckets[bi]) });
        out[family.name + "_bucket" + _renderLabels(bLabels)] = entry.counts[bi];
      }
      var infLabels = Object.assign(Object.create(null), entry.labels, { le: "+Inf" });
      out[family.name + "_bucket" + _renderLabels(infLabels)] = entry.counts[family.buckets.length];
      out[family.name + "_sum" + _renderLabels(entry.labels)] = entry.sum;
      out[family.name + "_count" + _renderLabels(entry.labels)] = entry.count;
    } else {
      out[family.name + _renderLabels(entry.labels)] = entry.value;
    }
  }
  return out;
}

function _resolveLabels(defaultLabels, declaredNames, callLabels) {
  var out = {};
  if (defaultLabels) {
    var dk = Object.keys(defaultLabels);
    for (var i = 0; i < dk.length; i++) out[dk[i]] = defaultLabels[dk[i]];
  }
  if (callLabels) {
    var ck = Object.keys(callLabels);
    for (var j = 0; j < ck.length; j++) {
      var k = ck[j];
      if (declaredNames.indexOf(k) === -1 && !(defaultLabels && Object.prototype.hasOwnProperty.call(defaultLabels, k))) {
        throw new MetricsError("metrics/undeclared-label",
          "label '" + k + "' not declared in labelNames " + JSON.stringify(declaredNames));
      }
      out[k] = callLabels[k];
    }
  }
  for (var n = 0; n < declaredNames.length; n++) {
    if (!Object.prototype.hasOwnProperty.call(out, declaredNames[n])) {
      throw new MetricsError("metrics/missing-label",
        "label '" + declaredNames[n] + "' is required (declared in labelNames)");
    }
  }
  var redacted = {};
  var ok = Object.keys(out);
  for (var r = 0; r < ok.length; r++) redacted[ok[r]] = _validateLabelValue(out[ok[r]]);
  return redacted;
}

/**
 * @primitive b.metrics.create
 * @signature b.metrics.create(opts)
 * @since     0.4.0
 * @status    stable
 * @related   b.metrics.tap, b.observability.event, b.tracing.create
 *
 * Build a Prometheus-format metrics registry. The returned registry
 * exposes `counter` / `gauge` / `histogram` factories,
 * `requestMiddleware()` for per-route auto-instrumentation,
 * `expositionHandler()` for the `/metrics` scrape route, and
 * `exposition()` for direct rendering. Activates the framework
 * auto-tap so audit / vault / queue / error events feed
 * pre-registered framework counters.
 *
 * @opts
 *   namespace:           string,  // prepended to every metric name
 *   defaultLabels:       object,  // attached to every sample
 *   labelCardinalityCap: number,  // per-metric distinct-label-set cap; default 10000
 *
 * @example
 *   var m = b.metrics.create({
 *     namespace:     "myapp",
 *     defaultLabels: { service: "api", version: "1.2.3" },
 *   });
 *
 *   var requests = m.counter("http_requests_total", {
 *     help:       "Total HTTP requests",
 *     labelNames: ["method", "route", "status"],
 *   });
 *   requests.inc({ method: "GET", route: "/users", status: "200" });
 *
 *   var latency = m.histogram("http_request_duration_seconds", {
 *     help:       "HTTP request latency",
 *     labelNames: ["method", "route"],
 *     buckets:    [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
 *   });
 *   latency.observe({ method: "GET", route: "/users" }, 0.123);
 *
 *   var depth = m.gauge("queue_depth", { labelNames: ["queueName"] });
 *   depth.set({ queueName: "default" }, 42);
 *
 *   // Wire into an HTTP server.
 *   router.use(m.requestMiddleware());
 *   router.get("/metrics", m.expositionHandler());
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "namespace", "defaultLabels", "labelCardinalityCap",
  ], "b.metrics");
  var namespace     = opts.namespace || "";
  var defaultLabels = opts.defaultLabels || {};
  numericBounds.requirePositiveFiniteIntIfPresent(opts.labelCardinalityCap,
    "labelCardinalityCap", MetricsError, "metrics/bad-opt");
  var cardinalityCap = opts.labelCardinalityCap || DEFAULT_CARDINALITY_CAP;

  var dlk = Object.keys(defaultLabels);
  for (var i = 0; i < dlk.length; i++) _validateLabelName(dlk[i]);

  var metrics = new Map();

  function _qualifyName(name) {
    return namespace ? namespace + "_" + name : name;
  }

  function _registerMetric(metric) {
    boundedMap.requireAbsent(metrics, metric.name, function () {
      throw new MetricsError("metrics/duplicate",
        "metric '" + metric.name + "' already registered");
    });
    metrics.set(metric.name, metric);
    return metric;
  }

  function counter(name, copts) {
    copts = copts || {};
    var fullName = _qualifyName(name);
    _validateMetricName(fullName);
    var labelNames = (copts.labelNames || []).slice();
    for (var i = 0; i < labelNames.length; i++) _validateLabelName(labelNames[i]);
    var help = copts.help || "";
    var values = new Map();
    var capWarned = false;

    var instance = {
      type:       "counter",
      name:       fullName,
      help:       help,
      unit:       copts.unit || null,
      labelNames: labelNames,
      values:     values,
      inc: function (callLabels, n) {
        var arg = _normalizeLabelArg(callLabels, n, 1);
        if (typeof arg.value !== "number" || !isFinite(arg.value)) {
          throw new MetricsError("metrics/counter-bad-value",
            "counter.inc value must be a finite number");
        }
        if (arg.value < 0) {
          throw new MetricsError("metrics/counter-decrement",
            "counter.inc value must be >= 0 (got " + arg.value + ") — counters never decrease");
        }
        var resolved = _resolveLabels(defaultLabels, labelNames, arg.labels);
        var key = _labelsKey(resolved);
        var entry = boundedMap.getOrInsert(values, key, function () {
          return { labels: resolved, value: 0 };
        }, {
          maxSize: cardinalityCap,
          onFull: function () {
            if (!capWarned) {
              log("metric '" + fullName + "' hit labelCardinalityCap (" + cardinalityCap +
                  ") — dropping new label combinations. Reduce label cardinality or raise the cap.");
              capWarned = true;
            }
            return null;
          },
        });
        if (!entry) return;
        entry.value += arg.value;
      },
      reset: function () { values.clear(); capWarned = false; },
      get: function (callLabels) {
        var resolved = _resolveLabels(defaultLabels, labelNames, callLabels);
        var entry = values.get(_labelsKey(resolved));
        return entry ? entry.value : 0;
      },
    };
    return _registerMetric(instance);
  }

  function gauge(name, copts) {
    copts = copts || {};
    var fullName = _qualifyName(name);
    _validateMetricName(fullName);
    var labelNames = (copts.labelNames || []).slice();
    for (var i = 0; i < labelNames.length; i++) _validateLabelName(labelNames[i]);
    var help = copts.help || "";
    var values = new Map();
    var capWarned = false;

    function _ensure(callLabels) {
      var resolved = _resolveLabels(defaultLabels, labelNames, callLabels);
      var key = _labelsKey(resolved);
      return boundedMap.getOrInsert(values, key, function () {
        return { labels: resolved, value: 0 };
      }, {
        maxSize: cardinalityCap,
        onFull: function () {
          if (!capWarned) {
            log("metric '" + fullName + "' hit labelCardinalityCap (" + cardinalityCap + ")");
            capWarned = true;
          }
          return null;
        },
      });
    }

    var instance = {
      type:       "gauge",
      name:       fullName,
      help:       help,
      unit:       copts.unit || null,
      labelNames: labelNames,
      values:     values,
      set: function (callLabels, v) {
        var arg = _normalizeLabelArg(callLabels, v, NaN);
        if (typeof arg.value !== "number" || !isFinite(arg.value)) {
          throw new MetricsError("metrics/gauge-bad-value",
            "gauge.set value must be a finite number");
        }
        var entry = _ensure(arg.labels);
        if (entry) entry.value = arg.value;
      },
      inc: function (callLabels, n) {
        var arg = _normalizeLabelArg(callLabels, n, 1);
        var entry = _ensure(arg.labels);
        if (entry) entry.value += arg.value;
      },
      dec: function (callLabels, n) {
        var arg = _normalizeLabelArg(callLabels, n, 1);
        var entry = _ensure(arg.labels);
        if (entry) entry.value -= arg.value;
      },
      reset: function () { values.clear(); capWarned = false; },
      get: function (callLabels) {
        var resolved = _resolveLabels(defaultLabels, labelNames, callLabels);
        var entry = values.get(_labelsKey(resolved));
        return entry ? entry.value : 0;
      },
    };
    return _registerMetric(instance);
  }

  function histogram(name, copts) {
    copts = copts || {};
    var fullName = _qualifyName(name);
    _validateMetricName(fullName);
    var labelNames = (copts.labelNames || []).slice();
    for (var i = 0; i < labelNames.length; i++) _validateLabelName(labelNames[i]);
    var help = copts.help || "";
    var rawBuckets = copts.buckets || DEFAULT_HTTP_BUCKETS;
    if (!Array.isArray(rawBuckets) || rawBuckets.length === 0) {
      throw new MetricsError("metrics/bad-buckets",
        "histogram buckets must be a non-empty array of ascending numbers");
    }
    for (var b = 0; b < rawBuckets.length; b++) {
      if (typeof rawBuckets[b] !== "number" || isNaN(rawBuckets[b])) {
        throw new MetricsError("metrics/bad-buckets",
          "histogram bucket boundary " + b + " is not a number");
      }
      if (b > 0 && rawBuckets[b] <= rawBuckets[b - 1]) {
        throw new MetricsError("metrics/bad-buckets",
          "histogram buckets must be strictly ascending");
      }
    }
    var buckets = rawBuckets.slice();
    var values = new Map();
    var capWarned = false;

    var instance = {
      type:       "histogram",
      name:       fullName,
      help:       help,
      unit:       copts.unit || null,
      labelNames: labelNames,
      buckets:    buckets,
      values:     values,
      observe: function (callLabels, v, exemplar) {
        var arg = _normalizeLabelArg(callLabels, v, NaN);
        if (typeof arg.value !== "number" || !isFinite(arg.value)) {
          throw new MetricsError("metrics/histogram-bad-value",
            "histogram.observe value must be a finite number");
        }
        var resolved = _resolveLabels(defaultLabels, labelNames, arg.labels);
        var key = _labelsKey(resolved);
        var entry = boundedMap.getOrInsert(values, key, function () {
          return {
            labels:    resolved,
            counts:    new Array(buckets.length + 1).fill(0),
            sum:       0,
            count:     0,
            exemplars: new Array(buckets.length + 1).fill(null),
          };
        }, {
          maxSize: cardinalityCap,
          onFull: function () {
            if (!capWarned) {
              log("metric '" + fullName + "' hit labelCardinalityCap (" + cardinalityCap + ")");
              capWarned = true;
            }
            return null;
          },
        });
        if (!entry) return;
        for (var i = 0; i < buckets.length; i++) {
          if (arg.value <= buckets[i]) {
            entry.counts[i]++;
            if (exemplar && typeof exemplar === "object") {
              entry.exemplars[i] = {
                labels:    _redactLabelMap(exemplar.labels),
                value:     _numericExemplarField(exemplar.value, arg.value),
                timestamp: _numericExemplarField(exemplar.timestamp, null),
              };
            }
          }
        }
        entry.counts[buckets.length]++;
        entry.sum   += arg.value;
        entry.count += 1;
      },
      reset: function () { values.clear(); capWarned = false; },
    };
    return _registerMetric(instance);
  }

  function exposition(opts) {
    opts = opts || {};
    var openMetrics = opts.format === "openmetrics";
    var lines = [];
    var sortedNames = Array.from(metrics.keys()).sort();
    for (var i = 0; i < sortedNames.length; i++) {
      var m = metrics.get(sortedNames[i]);
      var keys = Array.from(m.values.keys()).sort();
      var entries = [];
      for (var k = 0; k < keys.length; k++) entries.push(m.values.get(keys[k]));
      _renderFamilyLines({
        name:    m.name,
        type:    m.type,
        help:    m.help,
        unit:    m.unit,
        buckets: m.buckets,
        entries: entries,
      }, openMetrics, lines);
      lines.push("");
    }
    if (openMetrics) lines.push("# EOF");
    return lines.join("\n") + (lines.length ? "" : "\n");
  }

  function expositionHandler() {
    return function metricsHandler(req, res) {
      var acceptHeader = req && req.headers ? String(req.headers.accept || "") : "";
      var entries = requestHelpers.parseQualityList(acceptHeader);
      var openMetricsQ = 0;
      var prometheusQ = 0;
      var sawAccept = entries.length > 0;
      for (var i = 0; i < entries.length; i += 1) {
        var v = entries[i].value;
        var q = entries[i].q;
        if (v === "application/openmetrics-text" || v === "*/*" || v === "application/*") {
          if (q > openMetricsQ) openMetricsQ = q;
        }
        if (v === "text/plain" || v === "*/*" || v === "text/*") {
          if (q > prometheusQ) prometheusQ = q;
        }
      }
      var wantOpenMetrics = sawAccept && openMetricsQ > prometheusQ && openMetricsQ > 0;
      var body = exposition(wantOpenMetrics ? { format: "openmetrics" } : undefined);
      var contentType = wantOpenMetrics
        ? "application/openmetrics-text; version=1.0.0; charset=utf-8"
        : "text/plain; version=0.0.4; charset=utf-8";
      res.writeHead(HTTP_STATUS.OK, {
        "Content-Type":   contentType,
        "Content-Length": Buffer.byteLength(body),
        "Cache-Control":  "no-store",
      });
      res.end(body);
    };
  }

  var requestsTotal = null;
  var requestDuration = null;
  function _ensureRequestMetrics() {
    if (requestsTotal && requestDuration) return;
    requestsTotal = counter("framework_http_requests_total", {
      help:       "Total HTTP requests handled by the framework",
      labelNames: ["method", "route", "status"],
    });
    requestDuration = histogram("framework_http_request_duration_seconds", {
      help:       "HTTP request latency in seconds",
      labelNames: ["method", "route"],
      buckets:    DEFAULT_HTTP_BUCKETS,
    });
  }

  function requestMiddleware() {
    _ensureRequestMetrics();
    return function metricsRequest(req, res, next) {
      var sw = time.stopwatch();
      captureResponseStatus(res, function (status) {
        var elapsedSec = sw.ms() / C.TIME.seconds(1);
        var route = resolveRoute(req);
        var labels = { method: req.method || "GET", route: route, status: String(status) };
        var durLabels = { method: labels.method, route: route };
        try { requestsTotal.inc(labels); }
        catch (e) { log.warn("metrics/request-counter-failed: " + e.message); }
        var exemplar = null;
        if (req.span && req.span.traceId && req.span.spanId && req.span.sampled !== false) {
          exemplar = {
            labels:    { trace_id: req.span.traceId, span_id: req.span.spanId },
            value:     elapsedSec,
            timestamp: Date.now() / 1000,
          };
        } else if (req.trace && req.trace.sampled && req.trace.traceId && req.trace.spanId) {
          exemplar = {
            labels:    { trace_id: req.trace.traceId, span_id: req.trace.spanId },
            value:     elapsedSec,
            timestamp: Date.now() / 1000,
          };
        }
        try { requestDuration.observe(durLabels, elapsedSec, exemplar); }
        catch (e) { log.warn("metrics/request-duration-failed: " + e.message); }
      });
      return next();
    };
  }

  var auditEventsTotal = counter("framework_audit_events_total", {
    help:       "Audit events recorded by the framework",
    labelNames: ["action", "outcome"],
  });
  var vaultSealTotal = counter("framework_vault_seal_total", {
    help:       "Vault seal calls",
  });
  var vaultUnsealTotal = counter("framework_vault_unseal_total", {
    help:       "Vault unseal calls",
  });
  var queueEnqueueTotal = counter("framework_queue_enqueue_total", {
    help:       "Queue enqueue operations",
    labelNames: ["queueName"],
  });
  var queueCompleteTotal = counter("framework_queue_complete_total", {
    help:       "Queue job completions",
    labelNames: ["queueName"],
  });
  var queueFailTotal = counter("framework_queue_fail_total", {
    help:       "Queue job failures",
    labelNames: ["queueName"],
  });
  var queueDepthGauge = gauge("framework_queue_depth", {
    help:       "Queue depth — pending + inflight jobs",
    labelNames: ["queueName"],
  });
  var jobsInflightGauge = gauge("framework_jobs_inflight", {
    help:       "Jobs currently leased to a consumer",
    labelNames: ["queueName"],
  });
  var errorsTotal = counter("framework_errors_total", {
    help:       "Framework-error class constructions",
    labelNames: ["class"],
  });

  function _tapHandler(name, value, labels) {
    var qn = (labels && labels.queueName) || "default";
    if (name === "audit.record") {
      auditEventsTotal.inc({
        action:  (labels && labels.action)  || "unknown",
        outcome: (labels && labels.outcome) || "unknown",
      }, value || 1);
    } else if (name === "vault.seal")    { vaultSealTotal.inc(value || 1); }
    else if (name === "vault.unseal")    { vaultUnsealTotal.inc(value || 1); }
    else if (name === "queue.enqueue") {
      queueEnqueueTotal.inc({ queueName: qn }, value || 1);
      queueDepthGauge.inc({ queueName: qn }, value || 1);
    }
    else if (name === "queue.lease") {
      jobsInflightGauge.inc({ queueName: qn }, value || 1);
    }
    else if (name === "queue.complete") {
      queueCompleteTotal.inc({ queueName: qn }, value || 1);
      queueDepthGauge.dec({ queueName: qn }, value || 1);
      jobsInflightGauge.dec({ queueName: qn }, value || 1);
    }
    else if (name === "queue.fail") {
      queueFailTotal.inc({ queueName: qn }, value || 1);
      jobsInflightGauge.dec({ queueName: qn }, value || 1);
      if (labels && labels.willRetry === false) {
        queueDepthGauge.dec({ queueName: qn }, value || 1);
      }
    }
    else if (name === "error.construct") {
      errorsTotal.inc({ class: (labels && labels.class) || "unknown" }, value || 1);
    }
  }
  _activeTap = _tapHandler;

  var registry = {
    counter:           counter,
    gauge:             gauge,
    histogram:         histogram,
    requestMiddleware: requestMiddleware,
    expositionHandler: expositionHandler,
    exposition:        exposition,
    metrics:           metrics,
    namespace:         namespace,
    defaultLabels:     defaultLabels,
    cardinalityCap:    cardinalityCap,
    deactivate: function () {
      if (_activeTap === _tapHandler) _activeTap = null;
    },
  };
  return registry;
}

function _resetForTest() {
  _activeTap = null;
}

/**
 * @primitive b.metrics.snapshot.startWriter
 * @signature b.metrics.snapshot.startWriter(opts)
 * @since     0.9.13
 * @status    stable
 * @related   b.metrics.snapshot.read, b.metrics.snapshot.render
 *
 * Start a periodic writer that calls `opts.fields()` every
 * `opts.intervalMs` and writes the returned object as JSON to
 * `opts.path` atomically. Returns a `stop()` function that clears
 * the timer + performs one final flush before resolving.
 *
 * @opts
 *   path:        string,    // absolute path to write the snapshot
 *   intervalMs:  number,    // milliseconds between flushes (>=100)
 *   fields:      Function,  // returns an object — written as JSON
 *   registry:    object,    // optional `b.metrics.create()` handle — adds a
 *                           //   structured `metrics` field carrying every
 *                           //   registered counter / gauge / histogram (incl.
 *                           //   bucket counts) so sidecar readers compose
 *                           //   histogram_quantile() against the snapshot
 *   fileMode:    number,    // POSIX mode (default 0o640 — owner rw, group r)
 *
 * @example
 *   var registry = b.metrics.create();
 *   var latency  = registry.histogram("op_latency_seconds", { buckets: [0.01, 0.1, 1] });
 *   var stop = b.metrics.snapshot.startWriter({
 *     path:       "/run/blamejs/metrics.json",
 *     intervalMs: 5000,
 *     registry:   registry,
 *     fields:     function () { return { uptimeMs: process.uptime() * 1000 }; },
 *   });
 *   // Snapshot file: { writtenAt, fields, metrics: { op_latency_seconds: { type, buckets, observations: [{ labels, counts, sum, count }] } } }
 *   stop();
 */
function _serializeRegistry(registry) {
  var out = {};
  var names = registry.metrics instanceof Map
    ? Array.from(registry.metrics.keys()).sort()
    : Object.keys(registry.metrics).sort();
  for (var i = 0; i < names.length; i += 1) {
    var name = names[i];
    var m = registry.metrics instanceof Map ? registry.metrics.get(name) : registry.metrics[name];
    if (!m) continue;
    var entry = { type: m.type, help: m.help || "", labelNames: m.labelNames || [] };
    if (m.type === "histogram") {
      entry.buckets = m.buckets.slice();
      entry.observations = [];
      var hKeys = m.values instanceof Map ? Array.from(m.values.keys()).sort() : Object.keys(m.values).sort();
      for (var hi = 0; hi < hKeys.length; hi += 1) {
        var hv = m.values instanceof Map ? m.values.get(hKeys[hi]) : m.values[hKeys[hi]];
        entry.observations.push({
          labels: hv.labels,
          counts: hv.counts.slice(),
          sum:    hv.sum,
          count:  hv.count,
        });
      }
    } else {
      entry.observations = [];
      var vKeys = m.values instanceof Map ? Array.from(m.values.keys()).sort() : Object.keys(m.values).sort();
      for (var vi = 0; vi < vKeys.length; vi += 1) {
        var vv = m.values instanceof Map ? m.values.get(vKeys[vi]) : m.values[vKeys[vi]];
        entry.observations.push({ labels: vv.labels, value: vv.value });
      }
    }
    out[name] = entry;
  }
  return out;
}

function snapshotStartWriter(opts) {
  opts = opts || {};
  validateOpts.requireNonEmptyString(opts.path,
    "metrics.snapshot.startWriter: opts.path",
    MetricsError, "metrics-snapshot/bad-path");
  if (typeof opts.intervalMs !== "number" || !isFinite(opts.intervalMs) || opts.intervalMs < 100) {
    throw new MetricsError("metrics-snapshot/bad-interval",
      "metrics.snapshot.startWriter: opts.intervalMs must be a finite number >= 100, got " + opts.intervalMs);
  }
  if (typeof opts.fields !== "function") {
    throw new MetricsError("metrics-snapshot/bad-fields",
      "metrics.snapshot.startWriter: opts.fields must be a function returning the snapshot object");
  }
  if (opts.registry !== undefined && opts.registry !== null &&
      (typeof opts.registry !== "object" || typeof opts.registry.metrics !== "object")) {
    throw new MetricsError("metrics-snapshot/bad-registry",
      "metrics.snapshot.startWriter: opts.registry must be a metrics registry " +
      "(from b.metrics.create()) or omitted");
  }
  var p          = opts.path;
  var fieldsFn   = opts.fields;
  var registry   = opts.registry || null;
  var intervalMs = opts.intervalMs;
  var fileMode = opts.fileMode !== undefined ? opts.fileMode : 0o640;
  if (typeof fileMode !== "number" || !isFinite(fileMode) ||
      fileMode < 0 || fileMode > 0o777 || Math.floor(fileMode) !== fileMode) {
    throw new MetricsError("metrics-snapshot/bad-file-mode",
      "metrics.snapshot.startWriter: opts.fileMode must be a POSIX file-mode integer in [0, 0o777], got " +
      fileMode);
  }

  var doFlush = function () {
    var snap;
    try {
      snap = fieldsFn();
    } catch (e) {
      log("snapshot.fields() threw: " + (e && e.message ? e.message : String(e)));
      return;
    }
    if (!snap || typeof snap !== "object") {
      log("snapshot.fields() returned non-object; skipping flush");
      return;
    }
    var payload = {
      writtenAt: new Date().toISOString(),
      fields:    snap,
    };
    if (registry) {
      try { payload.metrics = _serializeRegistry(registry); }
      catch (e2) { log("snapshot.metrics serialize failed: " + ((e2 && e2.message) || String(e2))); }
    }
    try {
      atomicFile.writeSync(p, JSON.stringify(payload) + "\n", { fileMode: fileMode });
    } catch (e) {
      log("snapshot.writeSync failed: " + (e && e.message ? e.message : String(e)));
    }
  };

  doFlush();
  var timer = setInterval(doFlush, intervalMs);
  if (typeof timer.unref === "function") timer.unref();

  return function stop() {
    clearInterval(timer);
    doFlush();
  };
}

/**
 * @primitive b.metrics.snapshot.read
 * @signature b.metrics.snapshot.read(path)
 * @since     0.9.13
 * @status    stable
 * @related   b.metrics.snapshot.startWriter, b.metrics.snapshot.render
 *
 * Read + parse a snapshot file written by `startWriter`. Returns
 * `{ writtenAt, fields }`. Throws `MetricsError` with code
 * `metrics-snapshot/...` on missing file, parse failure, or
 * shape mismatch.
 *
 * @example
 *   var snap = b.metrics.snapshot.read("/run/blamejs/metrics.json");
 *   console.log("uptime:", snap.fields.uptimeMs);
 *   console.log("written at:", snap.writtenAt);
 */
function snapshotRead(p) {
  validateOpts.requireNonEmptyString(p,
    "metrics.snapshot.read: path",
    MetricsError, "metrics-snapshot/bad-path");
  var raw;
  try {
    raw = atomicFile.fdSafeReadSync(p, {
      maxBytes: C.BYTES.mib(4), encoding: "utf8", refuseSymlink: true,
      errorFor: function (kind, detail) {
        if (kind === "enoent") return new MetricsError("metrics-snapshot/not-found", "metrics.snapshot.read: " + p + " — not found");
        if (kind === "too-large") return new MetricsError("metrics-snapshot/too-large", "metrics.snapshot.read: " + p + " exceeds " + detail.max + " bytes");
        if (kind === "symlink") return new MetricsError("metrics-snapshot/symlink-refused", "metrics.snapshot.read: " + p + " is a symlink (refused)");
        return undefined;
      },
    });
  } catch (e) {
    if (e instanceof MetricsError) throw e;
    throw new MetricsError("metrics-snapshot/not-found",
      "metrics.snapshot.read: " + p + " — " + (e && e.message ? e.message : String(e)));
  }
  var parsed;
  try {
    parsed = safeJson.parse(raw, { maxBytes: C.BYTES.mib(4) });
  } catch (e) {
    throw new MetricsError("metrics-snapshot/bad-json",
      "metrics.snapshot.read: " + p + " contains invalid JSON: " + (e && e.message ? e.message : String(e)));
  }
  if (!parsed || typeof parsed !== "object" ||
      typeof parsed.writtenAt !== "string" || !parsed.fields ||
      typeof parsed.fields !== "object") {
    throw new MetricsError("metrics-snapshot/bad-shape",
      "metrics.snapshot.read: " + p + " is not a startWriter-produced snapshot (missing writtenAt or fields)");
  }
  return parsed;
}

/**
 * @primitive b.metrics.snapshot.render
 * @signature b.metrics.snapshot.render(snap, opts)
 * @since     0.9.13
 * @status    stable
 * @related   b.metrics.snapshot.read
 *
 * Format a snapshot object for human or machine consumption.
 *
 *   format: "text"       — operator-readable lines, one field per row (default)
 *   format: "prometheus" — Prometheus 0.0.4 text format
 *
 * ## Type detection (`prometheus` format only)
 *
 * Per Prometheus naming convention + OpenMetrics 1.0.0 §6.2, counter
 * metric families MUST carry the `_total` suffix; every other numeric
 * field renders as a gauge. The renderer auto-detects by suffix:
 *
 *   - field name ends in `_total` → `# TYPE <name> counter`
 *   - everything else             → `# TYPE <name> gauge`
 *
 * Operators with metrics that don't fit the convention (e.g. a counter
 * named `bytes_sent` without the `_total` suffix, or a gauge that
 * happens to end in `_total`) opt the right type via `opts.fieldTypes`:
 *
 *   render(snap, { format: "prometheus", fieldTypes: {
 *     bytes_sent: "counter",     // override default gauge
 *     ratio_total: "gauge",       // override default counter
 *   }});
 *
 * Pre-v0.9.47 every field rendered as gauge regardless of name, which
 * broke `rate()` queries against counter-shaped series. Operators
 * scraping a long-running deployment will see `rate(*_total[5m])`
 * queries start returning the right answer once the new types reach
 * the scrape target.
 *
 * ## Labeled registry series
 *
 * A snapshot written with `startWriter`'s `registry` option carries the
 * registry's counters / gauges / histograms — label sets and histogram
 * bucket counts — in a structured `metrics` field. Both formats render
 * them: `prometheus` emits the same labeled / bucketed sample lines the
 * live `exposition()` endpoint serves, family names verbatim (NOT
 * `prefix`-qualified) so dashboards see one series name regardless of
 * scrape source; `text` lists each labeled sample as a
 * `name{label="value"}` row. A malformed family, metric / label name,
 * or non-numeric sample in a hand-edited snapshot file is dropped,
 * never rendered.
 *
 * @opts
 *   format:      "text" | "prometheus",   // default: "text"
 *   prefix:      string,                   // prometheus-only; default: "blamejs"
 *   fieldTypes:  Object,                   // prometheus-only; per-field type override
 *                                          // map. Values: "counter" | "gauge".
 *
 * @example
 *   var snap = b.metrics.snapshot.read("/run/blamejs/metrics.json");
 *   process.stdout.write(b.metrics.snapshot.render(snap));
 *   // or for Prometheus scraping (auto-detects http_requests_total
 *   // as a counter via the _total suffix):
 *   res.setHeader("Content-Type", "text/plain; version=0.0.4");
 *   res.end(b.metrics.snapshot.render(snap, { format: "prometheus", prefix: "myapp" }));
 */
var ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;                                // allow:duplicate-regex — ISO-8601 instant shape ships in three primitives (ai-model-manifest, metrics text-render, content-credentials); none of the three imports safe-schema, whose DATETIME_RE also admits a numeric offset, so sharing it would pull a validation module into a hot-path sink for a 50-byte literal

function _formatTextValue(v) {
  if (typeof v === "number") return String(v);
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "string") {
    if (ISO_DATE_RE.test(v) && isFinite(Date.parse(v))) return v;                                    // allow:regex-no-length-cap — ISO-date shape, length-bounded by the anchored pattern
    return v;
  }
  return JSON.stringify(v);
}

function _renderText(fields, snap, opts) {
  var lines = ["snapshot written-at: " + snap.writtenAt];
  if (opts.groups && typeof opts.groups === "object" && !Array.isArray(opts.groups)) {
    var groupNames = Object.keys(opts.groups);
    var named = Object.create(null);
    for (var gi = 0; gi < groupNames.length; gi += 1) {
      var gName = groupNames[gi];
      var fieldNames = opts.groups[gName];
      if (!Array.isArray(fieldNames)) continue;
      lines.push("");
      lines.push("== " + gName + " ==");
      for (var fi = 0; fi < fieldNames.length; fi += 1) {
        var fn = fieldNames[fi];
        named[fn] = true;
        if (Object.prototype.hasOwnProperty.call(fields, fn)) {
          lines.push("  " + fn + ": " + _formatTextValue(fields[fn]));
        }
      }
    }
    // allow:bare-canonicalize-walk — operator-facing display ordering
    var remainder = Object.keys(fields).sort().filter(function (k) { return !named[k]; });
    if (remainder.length > 0) {
      lines.push("");
      lines.push("== Other ==");
      for (var ri = 0; ri < remainder.length; ri += 1) {
        lines.push("  " + remainder[ri] + ": " + _formatTextValue(fields[remainder[ri]]));
      }
    }
    return lines.join("\n") + "\n";
  }
  // allow:bare-canonicalize-walk — operator-facing display ordering
  var keys = Object.keys(fields).sort();
  for (var i = 0; i < keys.length; i += 1) {
    var k = keys[i];
    lines.push("  " + k + ": " + _formatTextValue(fields[k]));
  }
  return lines.join("\n") + "\n";
}

function _normalizeSnapshotFamily(name, fam) {
  if (!fam || typeof fam !== "object" || Array.isArray(fam)) return null;
  if (name.length > 1024 || !METRIC_NAME_RE.test(name)) return null;
  var type = fam.type;
  if (type !== "counter" && type !== "gauge" && type !== "histogram") return null;
  var buckets = null;
  if (type === "histogram") {
    if (!Array.isArray(fam.buckets)) return null;
    buckets = [];
    for (var bi = 0; bi < fam.buckets.length; bi += 1) {
      if (typeof fam.buckets[bi] !== "number" || !isFinite(fam.buckets[bi])) return null;
      buckets.push(fam.buckets[bi]);
    }
  }
  var observations = Array.isArray(fam.observations) ? fam.observations : [];
  var entries = [];
  for (var i = 0; i < observations.length; i += 1) {
    var obs = observations[i];
    if (!obs || typeof obs !== "object") continue;
    var labels = Object.create(null);
    var rawLabels = obs.labels && typeof obs.labels === "object" ? obs.labels : {};
    var lnames = Object.keys(rawLabels);
    for (var li = 0; li < lnames.length; li += 1) {
      if (lnames[li].length > 1024 || !LABEL_NAME_RE.test(lnames[li])) continue;
      labels[lnames[li]] = String(rawLabels[lnames[li]]);
    }
    if (type === "histogram") {
      if (!Array.isArray(obs.counts) || obs.counts.length !== buckets.length + 1) continue;
      var countsOk = true;
      for (var ci = 0; ci < obs.counts.length; ci += 1) {
        if (typeof obs.counts[ci] !== "number" || !isFinite(obs.counts[ci])) { countsOk = false; break; }
      }
      if (!countsOk) continue;
      if (typeof obs.sum !== "number" || !isFinite(obs.sum)) continue;
      if (typeof obs.count !== "number" || !isFinite(obs.count)) continue;
      entries.push({ labels: labels, counts: obs.counts, sum: obs.sum, count: obs.count });
    } else {
      if (typeof obs.value !== "number" || !isFinite(obs.value)) continue;
      entries.push({ labels: labels, value: obs.value });
    }
  }
  var help = typeof fam.help === "string"
    ? fam.help.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/\r/g, "")                       // allow:regex-no-length-cap — fixed-char-set escape // allow:duplicate-regex — Prometheus help-text escape shape
    : "";
  return { name: name, type: type, help: help, buckets: buckets, entries: entries };
}

function _normalizeSnapshotFamilies(metricsObj) {
  if (!metricsObj || typeof metricsObj !== "object" || Array.isArray(metricsObj)) return [];
  var families = [];
  // allow:bare-canonicalize-walk — stable exposition output ordering
  var names = Object.keys(metricsObj).sort();
  for (var i = 0; i < names.length; i += 1) {
    var family = _normalizeSnapshotFamily(names[i], metricsObj[names[i]]);
    if (family) families.push(family);
  }
  return families;
}

function snapshotRender(snap, opts) {
  opts = opts || {};
  var format = opts.format || "text";
  if (!snap || typeof snap !== "object" || !snap.fields) {
    throw new MetricsError("metrics-snapshot/bad-snap",
      "metrics.snapshot.render: snap must be a startWriter-produced object (got " + typeof snap + ")");
  }
  var fields = snap.fields;
  var families = _normalizeSnapshotFamilies(snap.metrics);
  if (format === "text") {
    var textFields = fields;
    if (families.length > 0) {
      var synth = Object.create(null);
      for (var tf = 0; tf < families.length; tf += 1) {
        Object.assign(synth, _familySamples(families[tf]));
      }
      textFields = Object.assign(synth, fields);
    }
    return _renderText(textFields, snap, opts);
  }
  if (format === "prometheus") {
    var prefix = opts.prefix || "blamejs";
    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(prefix)) {
      throw new MetricsError("metrics-snapshot/bad-prefix",
        "metrics.snapshot.render: prometheus prefix must match [a-zA-Z_][a-zA-Z0-9_]*, got '" + prefix + "'");
    }
    var fieldTypes = opts.fieldTypes || {};
    if (typeof fieldTypes !== "object" || fieldTypes === null || Array.isArray(fieldTypes)) {
      throw new MetricsError("metrics-snapshot/bad-field-types",
        "metrics.snapshot.render: opts.fieldTypes must be an object mapping field-name → 'counter' | 'gauge'");
    }
    var out = [];
    // allow:bare-canonicalize-walk — sort is for stable Prometheus
    var keys2 = Object.keys(fields).sort();
    for (var j = 0; j < keys2.length; j++) {
      var k2 = keys2[j];
      var v2 = fields[k2];
      if (typeof v2 !== "number" || !isFinite(v2)) continue;
      if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(k2)) continue;
      var metric = prefix + "_" + k2;
      var declared = fieldTypes[k2];
      var fieldType;
      if (declared !== undefined) {
        if (declared !== "counter" && declared !== "gauge") {
          throw new MetricsError("metrics-snapshot/bad-field-type",
            "metrics.snapshot.render: opts.fieldTypes." + k2 + " must be 'counter' or 'gauge', got '" + declared + "'");
        }
        fieldType = declared;
      } else {
        fieldType = /_total$/.test(k2) ? "counter" : "gauge";
      }
      out.push("# TYPE " + metric + " " + fieldType);
      out.push(metric + " " + v2);
    }
    for (var jd = 0; jd < keys2.length; jd += 1) {
      var kd = keys2[jd];
      var vd = fields[kd];
      if (typeof vd !== "string") continue;
      if (vd.length > 64) continue;
      if (!ISO_DATE_RE.test(vd)) continue;                                                           // allow:regex-no-length-cap — length-bounded immediately above
      if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(kd)) continue;                                            // allow:regex-no-length-cap — field-name shape, length-bounded by snap field naming
      var ms = Date.parse(vd);
      if (!isFinite(ms)) continue;
      var emName = prefix + "_" + kd + "_epoch_ms";
      out.push("# TYPE " + emName + " gauge");
      out.push(emName + " " + ms);
    }
    for (var fj = 0; fj < families.length; fj += 1) {
      if (out.length > 0) out.push("");
      _renderFamilyLines(families[fj], false, out);
    }
    return out.join("\n") + "\n";
  }
  throw new MetricsError("metrics-snapshot/bad-format",
    "metrics.snapshot.render: format must be 'text' or 'prometheus', got '" + format + "'");
}

/**
 * @primitive b.metrics.snapshot.shadowRegistry
 * @signature b.metrics.snapshot.shadowRegistry(opts)
 * @since     0.10.9
 * @status    stable
 * @related   b.metrics.snapshot.render, b.metrics.create
 *
 * Build a namespaced shadow metrics registry that mirrors a subset of
 * a primary registry's counters / gauges / info for export to systems
 * needing isolated views (sidecar / per-tenant scrape endpoint /
 * compliance-tagged subset). Cardinality cap closes the
 * [client_golang CVE-2022-21698](https://nvd.nist.gov/vuln/detail/CVE-2022-21698)
 * unbounded-cardinality DoS class. Returns
 * `{ inc, set, setInfo, snapshot, render, reset }`.
 *
 * @opts
 *   namespace:              string,           // identifier prefix; required
 *   counters:               string[],         // counter names to mirror
 *   gauges:                 string[],         // gauge names to mirror
 *   info:                   string[],         // info names to mirror
 *   cardinalityCap:         number,           // default 10000 per metric name
 *   onCardinalityExceeded:  "drop" | "audit-only" | "refuse",  // default "drop"
 *
 * @example
 *   var shadow = b.metrics.snapshot.shadowRegistry({
 *     namespace: "tenant_a",
 *     counters:  ["requests_total", "errors_total"],
 *     gauges:    ["queue_depth"],
 *   });
 *   shadow.inc("requests_total");
 *   shadow.set("queue_depth", 42);
 *   shadow.snapshot();
 */
var SHADOW_DEFAULT_CARDINALITY = 10000;
function shadowRegistry(opts) {
  if (!opts || typeof opts !== "object") {
    throw new MetricsError("metrics-shadow/bad-opts",
      "shadowRegistry: opts object required");
  }
  validateOpts.requireNonEmptyString(opts.namespace,
    "shadowRegistry: opts.namespace", MetricsError, "metrics-shadow/bad-namespace");
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(opts.namespace)) {                                            // allow:regex-no-length-cap — OpenMetrics name-shape, length-bounded by namespace
    throw new MetricsError("metrics-shadow/bad-namespace",
      "shadowRegistry: namespace must match [a-zA-Z_][a-zA-Z0-9_]*");
  }
  var counterSet = _shadowSetOf(opts.counters, "counters");
  var gaugeSet   = _shadowSetOf(opts.gauges,   "gauges");
  var infoSet    = _shadowSetOf(opts.info,     "info");
  var cap = opts.cardinalityCap === undefined ? SHADOW_DEFAULT_CARDINALITY : opts.cardinalityCap;
  if (!numericBounds.isPositiveFiniteInt(cap)) {
    throw new MetricsError("metrics-shadow/bad-cap",
      "shadowRegistry: cardinalityCap must be a positive integer");
  }
  var policy = opts.onCardinalityExceeded || "drop";
  if (policy !== "drop" && policy !== "audit-only" && policy !== "refuse") {
    throw new MetricsError("metrics-shadow/bad-policy",
      "shadowRegistry: onCardinalityExceeded must be 'drop', 'audit-only', or 'refuse'");
  }
  var counters = Object.create(null);
  var gauges   = Object.create(null);
  var info     = Object.create(null);
  var labelSets = Object.create(null);
  var lastCardinalityAuditMs = 0;

  function _cardinalityHit(metric) {
    var now = Date.now();
    if (now - lastCardinalityAuditMs >= C.TIME.seconds(1)) {
      lastCardinalityAuditMs = now;
      try {
        require("./audit").safeEmit({
          action:   "metrics.shadow.cardinality_dropped",
          outcome:  policy === "refuse" ? "denied" : "denied",
          metadata: { namespace: opts.namespace, metric: metric, cap: cap, policy: policy },
        });
      } catch (_e) { /* drop-silent */ }
    }
    if (policy === "refuse") {
      throw new MetricsError("metrics-shadow/cardinality-exceeded",
        "shadowRegistry.inc/set: '" + metric + "' cardinality exceeds cap=" + cap);
    }
  }

  function _coerceLabels(labels) {
    if (!labels || typeof labels !== "object") return { key: "", set: null };
    var keys = Object.keys(labels);
    if (keys.length === 0) return { key: "", set: null };
    var coerced = Object.create(null);
    for (var i = 0; i < keys.length; i += 1) coerced[keys[i]] = String(labels[keys[i]]);
    return { key: canonicalJson.stringify(coerced), set: coerced };
  }

  function inc(name, labels) {
    if (!counterSet[name]) return;
    var ck = _coerceLabels(labels);
    var lk = ck.key;
    if (!counters[name]) counters[name] = Object.create(null);
    var current = counters[name][lk];
    if (current === undefined) {
      if (Object.keys(counters[name]).length >= cap) {
        _cardinalityHit(name);
        return;
      }
      counters[name][lk] = 1;
      if (ck.set) labelSets[lk] = ck.set;
    } else {
      counters[name][lk] = current + 1;
    }
  }

  function set(name, value, labels) {
    if (!gaugeSet[name]) return;
    if (typeof value !== "number" || !isFinite(value)) {
      throw new MetricsError("metrics-shadow/bad-gauge-value",
        "shadowRegistry.set: '" + name + "' value must be a finite number");
    }
    var ck = _coerceLabels(labels);
    var lk = ck.key;
    if (!gauges[name]) gauges[name] = Object.create(null);
    if (gauges[name][lk] === undefined && Object.keys(gauges[name]).length >= cap) {
      _cardinalityHit(name);
      return;
    }
    gauges[name][lk] = value;
    if (ck.set) labelSets[lk] = ck.set;
  }

  function setInfo(name, value) {
    if (!infoSet[name]) return;
    info[name] = value;
  }

  function snapshotShadow() {
    return Object.freeze({
      namespace: opts.namespace,
      counters:  _shallowClone(counters),
      gauges:    _shallowClone(gauges),
      info:      Object.assign({}, info),
    });
  }

  function renderShadow(renderOpts) {
    renderOpts = renderOpts || {};
    var format = renderOpts.format || "text";
    if (format === "prometheus" || format === "openmetrics") {
      var out = [];
      var prefix = opts.namespace;
      function _emitLabeled(name, labelMap, kind) {
        var metric = prefix + "_" + name;
        if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(metric)) return;                                        // allow:regex-no-length-cap — Prometheus name-shape; metric length bounded by namespace + name caps
        var entries = [];
        var lks = Object.keys(labelMap);
        for (var li = 0; li < lks.length; li += 1) {
          var lk = lks[li];
          var labelObj = lk === "" ? null : labelSets[lk];
          var labels = Object.create(null);
          if (labelObj && typeof labelObj === "object") {
            var lnames = Object.keys(labelObj);
            for (var pi = 0; pi < lnames.length; pi += 1) {
              if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(lnames[pi])) continue;                            // allow:regex-no-length-cap — Prometheus label-name shape
              labels[lnames[pi]] = labelObj[lnames[pi]];
            }
          }
          entries.push({ labels: labels, value: labelMap[lk] });
        }
        _renderFamilyLines({ name: metric, type: kind, help: "", entries: entries }, false, out);
      }
      var cn2 = Object.keys(counters);
      for (var ci = 0; ci < cn2.length; ci += 1) {
        _emitLabeled(cn2[ci], counters[cn2[ci]], /_total$/.test(cn2[ci]) ? "counter" : "gauge");      // allow:regex-no-length-cap — name-suffix check
      }
      var gn2 = Object.keys(gauges);
      for (var ggi = 0; ggi < gn2.length; ggi += 1) {
        _emitLabeled(gn2[ggi], gauges[gn2[ggi]], "gauge");
      }
      return out.join("\n") + (out.length ? "\n" : "");
    }
    var snap = { writtenAt: new Date().toISOString(), fields: {} };
    var cn = Object.keys(counters);
    for (var i = 0; i < cn.length; i += 1) {
      var labels = counters[cn[i]];
      var labelKeys = Object.keys(labels);
      if (labelKeys.length === 1 && labelKeys[0] === "") {
        snap.fields[cn[i]] = labels[""];
      } else {
        for (var j = 0; j < labelKeys.length; j += 1) {
          var key = labelKeys[j] === "" ? cn[i] : cn[i] + "{" + labelKeys[j] + "}";
          snap.fields[key] = labels[labelKeys[j]];
        }
      }
    }
    var gn = Object.keys(gauges);
    for (var gi = 0; gi < gn.length; gi += 1) {
      var glabels = gauges[gn[gi]];
      var glk = Object.keys(glabels);
      if (glk.length === 1 && glk[0] === "") {
        snap.fields[gn[gi]] = glabels[""];
      } else {
        for (var gj = 0; gj < glk.length; gj += 1) {
          var gkey = glk[gj] === "" ? gn[gi] : gn[gi] + "{" + glk[gj] + "}";
          snap.fields[gkey] = glabels[glk[gj]];
        }
      }
    }
    var inames = Object.keys(info);
    for (var ii = 0; ii < inames.length; ii += 1) snap.fields[inames[ii]] = info[inames[ii]];
    return snapshotRender(snap, Object.assign({ prefix: opts.namespace }, renderOpts));
  }

  function reset() {
    counters  = Object.create(null);
    gauges    = Object.create(null);
    info      = Object.create(null);
    labelSets = Object.create(null);
    lastCardinalityAuditMs = 0;
  }

  return {
    inc:      inc,
    set:      set,
    setInfo:  setInfo,
    snapshot: snapshotShadow,
    render:   renderShadow,
    reset:    reset,
  };
}

function _shadowSetOf(arr, label) {
  if (arr === undefined) return Object.create(null);
  if (!Array.isArray(arr)) {
    throw new MetricsError("metrics-shadow/bad-" + label,
      "shadowRegistry: opts." + label + " must be an array of metric names");
  }
  var set = Object.create(null);
  for (var i = 0; i < arr.length; i += 1) {
    if (typeof arr[i] !== "string" || arr[i].length === 0) {
      throw new MetricsError("metrics-shadow/bad-" + label,
        "shadowRegistry: opts." + label + "[" + i + "] must be a non-empty string");
    }
    set[arr[i]] = true;
  }
  return set;
}

function _shallowClone(obj) {
  var out = Object.create(null);
  var keys = Object.keys(obj);
  for (var i = 0; i < keys.length; i += 1) {
    out[keys[i]] = Object.assign(Object.create(null), obj[keys[i]]);
  }
  return out;
}

var snapshot = {
  startWriter:     snapshotStartWriter,
  read:            snapshotRead,
  render:          snapshotRender,
  shadowRegistry:  shadowRegistry,
};

module.exports = {
  create:                    create,
  tap:                       tap,
  snapshot:                  snapshot,
  MetricsError:              MetricsError,
  DEFAULT_HTTP_BUCKETS:      DEFAULT_HTTP_BUCKETS,
  DEFAULT_CARDINALITY_CAP:   DEFAULT_CARDINALITY_CAP,
  _resetForTest:             _resetForTest,
  _labelsKey:                _labelsKey,
  _renderLabels:             _renderLabels,
  _escapeLabelValue:         _escapeLabelValue,
};
