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
var canonicalJson = require("./canonical-json");
var nodeFs   = require("node:fs");
var atomicFile = require("./atomic-file");
var safeJson = require("./safe-json");
var { defineClass } = require("./framework-error");
var { boot } = require("./log");
var numericBounds = require("./numeric-bounds");
var { resolveRoute, captureResponseStatus, HTTP_STATUS } = require("./request-helpers");
var validateOpts = require("./validate-opts");

var MetricsError = defineClass("MetricsError", { alwaysPermanent: true });
var log = boot("metrics");

// Default histogram buckets for HTTP latency in seconds.
var DEFAULT_HTTP_BUCKETS = Object.freeze([
  0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
]);

var DEFAULT_CARDINALITY_CAP = C.BYTES.bytes(10000);
// Bound metric / label names before regex test — DoS shape if an
// operator passed a multi-megabyte string. Prometheus exposition
// recommends short ascii names; 200 is a generous ceiling.
var MAX_METRIC_NAME_LEN = 200;
var METRIC_NAME_RE = /^[a-zA-Z_:][a-zA-Z0-9_:]*$/;
var LABEL_NAME_RE  = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

// ---- tap (global no-op stub for framework module taps) ----
//
// Framework modules call metrics.tap("name", value, labels) at hot
// paths. Until a registry is active, calls are no-ops (zero cost).
// metrics.create() replaces _activeTap with the registry-driven path,
// flowing taps into pre-registered counters / gauges / histograms.
//
// Drop-silent by design: the wrapping try/catch is intentional. tap is
// called from request hot paths where throwing on a misnamed metric
// (or a label whose value coerced unexpectedly) would crash the
// request that triggered it. The metric-registration path (counter /
// gauge / histogram) DOES throw on bad name/label-name regex — that's
// a config-time call where operators want fast failure; the runtime
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

// ---- helpers ----

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
// Counter / gauge / histogram methods all accept (callLabels, value) but
// degrade to (value) when no labels are passed. Centralized here so we
// don't repeat the swap-and-coerce dance four times.
//
//   _normalizeLabelArg(arg1, arg2, defaultValue) → { labels, value }
function _normalizeLabelArg(callLabels, value, defaultValue) {
  if (typeof callLabels === "number") {
    return { labels: null, value: callLabels };
  }
  return {
    labels: callLabels,
    value:  typeof value === "number" ? value : defaultValue,
  };
}

function _validateLabelValue(value) {
  // Prometheus exposition: label values are quoted strings; backslash,
  // newline, double-quote get escaped at serialize time. Coerce here so
  // counters indexed by various input types still work.
  if (value === null || value === undefined) return "";
  return String(value);
}

// Serialize a labels object to a canonical Map key. Routed through
// canonical-json so the framework has one canonical-sort source of
// truth for sorted-keys serialization (avoiding the silent-data-loss
// class on Date / Buffer / Map / Set / BigInt values).
function _labelsKey(labels) {
  if (!labels) return "";
  // Coerce values to strings first so canonical-json's primitive
  // serialization matches the Prometheus wire format.
  var coerced = {};
  var keys = Object.keys(labels);
  for (var i = 0; i < keys.length; i++) {
    coerced[keys[i]] = _validateLabelValue(labels[keys[i]]);
  }
  return canonicalJson.stringify(coerced);
}

// Escape a label value per the Prometheus exposition format.
function _escapeLabelValue(v) {
  return String(v).replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, "\\\"");
}

// Wire-format renderer for Prometheus exposition. Determinism is
// shared with _labelsKey: both walk keys in lexicographic order via
// the same _sortedLabelKeys helper, so the canonical-sort source of
// truth is one helper instead of two duplicated walks.
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

// Single canonical-sort source of truth for label keys. Both
// _labelsKey (Map key) and _renderLabels (Prometheus exposition)
// route through here so the framework has one walk shape.
function _sortedLabelKeys(labelObj) {
  var keys = Object.keys(labelObj);
  keys.sort();
  return keys;
}

// Combine default + per-call labels, validating against the metric's
// declared labelNames. Throws if a label name isn't declared.
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
  // Verify all declared labels are present.
  for (var n = 0; n < declaredNames.length; n++) {
    if (!Object.prototype.hasOwnProperty.call(out, declaredNames[n])) {
      throw new MetricsError("metrics/missing-label",
        "label '" + declaredNames[n] + "' is required (declared in labelNames)");
    }
  }
  return out;
}

// ---- registry factory ----

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

  // Validate defaultLabels names.
  var dlk = Object.keys(defaultLabels);
  for (var i = 0; i < dlk.length; i++) _validateLabelName(dlk[i]);

  var metrics = new Map();   // fullName → metric instance

  function _qualifyName(name) {
    return namespace ? namespace + "_" + name : name;
  }

  function _registerMetric(metric) {
    if (metrics.has(metric.name)) {
      throw new MetricsError("metrics/duplicate",
        "metric '" + metric.name + "' already registered");
    }
    metrics.set(metric.name, metric);
    return metric;
  }

  // ---- counter ----

  function counter(name, copts) {
    copts = copts || {};
    var fullName = _qualifyName(name);
    _validateMetricName(fullName);
    var labelNames = (copts.labelNames || []).slice();
    for (var i = 0; i < labelNames.length; i++) _validateLabelName(labelNames[i]);
    var help = copts.help || "";
    var values = new Map();   // labelsKey → { labels, value }
    var capWarned = false;

    var instance = {
      type:       "counter",
      name:       fullName,
      help:       help,
      labelNames: labelNames,
      values:     values,
      inc: function (callLabels, n) {
        var arg = _normalizeLabelArg(callLabels, n, 1);
        if (arg.value < 0) {
          throw new MetricsError("metrics/counter-decrement",
            "counter.inc value must be >= 0 (got " + arg.value + ") — counters never decrease");
        }
        var resolved = _resolveLabels(defaultLabels, labelNames, arg.labels);
        var key = _labelsKey(resolved);
        var entry = values.get(key);
        if (!entry) {
          if (values.size >= cardinalityCap) {
            if (!capWarned) {
              log("metric '" + fullName + "' hit labelCardinalityCap (" + cardinalityCap +
                  ") — dropping new label combinations. Reduce label cardinality or raise the cap.");
              capWarned = true;
            }
            return;
          }
          entry = { labels: resolved, value: 0 };
          values.set(key, entry);
        }
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

  // ---- gauge ----

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
      var entry = values.get(key);
      if (!entry) {
        if (values.size >= cardinalityCap) {
          if (!capWarned) {
            log("metric '" + fullName + "' hit labelCardinalityCap (" + cardinalityCap + ")");
            capWarned = true;
          }
          return null;
        }
        entry = { labels: resolved, value: 0 };
        values.set(key, entry);
      }
      return entry;
    }

    var instance = {
      type:       "gauge",
      name:       fullName,
      help:       help,
      labelNames: labelNames,
      values:     values,
      set: function (callLabels, v) {
        var arg = _normalizeLabelArg(callLabels, v, NaN);
        if (typeof arg.value !== "number" || isNaN(arg.value)) {
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

  // ---- histogram ----

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
    // Verify ascending + numeric.
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
      labelNames: labelNames,
      buckets:    buckets,
      values:     values,
      observe: function (callLabels, v) {
        var arg = _normalizeLabelArg(callLabels, v, NaN);
        if (typeof arg.value !== "number" || isNaN(arg.value)) {
          throw new MetricsError("metrics/histogram-bad-value",
            "histogram.observe value must be a finite number");
        }
        var resolved = _resolveLabels(defaultLabels, labelNames, arg.labels);
        var key = _labelsKey(resolved);
        var entry = values.get(key);
        if (!entry) {
          if (values.size >= cardinalityCap) {
            if (!capWarned) {
              log("metric '" + fullName + "' hit labelCardinalityCap (" + cardinalityCap + ")");
              capWarned = true;
            }
            return;
          }
          // counts[i] is the count for the [<=buckets[i]] bucket; counts[buckets.length] is +Inf.
          entry = {
            labels: resolved,
            counts: new Array(buckets.length + 1).fill(0),
            sum:    0,
            count:  0,
          };
          values.set(key, entry);
        }
        for (var i = 0; i < buckets.length; i++) {
          if (arg.value <= buckets[i]) entry.counts[i]++;
        }
        entry.counts[buckets.length]++;   // +Inf bucket is everything
        entry.sum   += arg.value;
        entry.count += 1;
      },
      reset: function () { values.clear(); capWarned = false; },
    };
    return _registerMetric(instance);
  }

  // ---- exposition ----

  function exposition() {
    var lines = [];
    var sortedNames = Array.from(metrics.keys()).sort();
    for (var i = 0; i < sortedNames.length; i++) {
      var m = metrics.get(sortedNames[i]);
      if (m.help) lines.push("# HELP " + m.name + " " + m.help);
      lines.push("# TYPE " + m.name + " " + m.type);
      var keys = Array.from(m.values.keys()).sort();
      if (m.type === "histogram") {
        for (var k = 0; k < keys.length; k++) {
          var entry = m.values.get(keys[k]);
          for (var bi = 0; bi < m.buckets.length; bi++) {
            var bLabels = Object.assign({}, entry.labels, { le: String(m.buckets[bi]) });
            lines.push(m.name + "_bucket" + _renderLabels(bLabels) + " " + entry.counts[bi]);
          }
          var infLabels = Object.assign({}, entry.labels, { le: "+Inf" });
          lines.push(m.name + "_bucket" + _renderLabels(infLabels) + " " + entry.counts[m.buckets.length]);
          lines.push(m.name + "_sum"   + _renderLabels(entry.labels) + " " + entry.sum);
          lines.push(m.name + "_count" + _renderLabels(entry.labels) + " " + entry.count);
        }
      } else {
        for (var v = 0; v < keys.length; v++) {
          var ent = m.values.get(keys[v]);
          lines.push(m.name + _renderLabels(ent.labels) + " " + ent.value);
        }
      }
      lines.push("");
    }
    return lines.join("\n") + (lines.length ? "" : "\n");
  }

  function expositionHandler() {
    return function metricsHandler(req, res) {
      var body = exposition();
      res.writeHead(HTTP_STATUS.OK, {
        "Content-Type":   "text/plain; version=0.0.4; charset=utf-8",
        "Content-Length": Buffer.byteLength(body),
        "Cache-Control":  "no-store",
      });
      res.end(body);
    };
  }

  // ---- request middleware (auto-time + auto-count) ----

  // Built-in metrics created on first requestMiddleware call so apps
  // that don't use the middleware don't pay the registration cost.
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
      var start = process.hrtime.bigint();
      captureResponseStatus(res, function (status) {
        var elapsedSec = Number(process.hrtime.bigint() - start) / 1e9;
        var route = resolveRoute(req);
        var labels = { method: req.method || "GET", route: route, status: String(status) };
        var durLabels = { method: labels.method, route: route };
        // Best-effort tap path — a label coercion or registry race
        // must not crash the request that triggered it. Log so
        // the operator sees the failure in the same channel as
        // the rest of the framework's diagnostics.
        try { requestsTotal.inc(labels); }
        catch (e) { log.warn("metrics/request-counter-failed: " + e.message); }
        try { requestDuration.observe(durLabels, elapsedSec); }
        catch (e) { log.warn("metrics/request-duration-failed: " + e.message); }
      });
      return next();
    };
  }

  // ---- framework auto-instrumentation taps ----
  //
  // tap() calls in audit / vault / queue route through here when this
  // registry is active. Pre-register the counters so we don't create
  // them lazily inside the tap path (which would bind allocator cost
  // to per-event hot paths).

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
      // Depth = pending + inflight. Retry transitions inflight→pending
      // (depth unchanged); terminal failure exits both buckets.
      if (labels && labels.willRetry === false) {
        queueDepthGauge.dec({ queueName: qn }, value || 1);
      }
    }
    else if (name === "error.construct") {
      errorsTotal.inc({ class: (labels && labels.class) || "unknown" }, value || 1);
    }
  }
  _activeTap = _tapHandler;

  // ---- registry surface ----

  var registry = {
    counter:           counter,
    gauge:             gauge,
    histogram:         histogram,
    requestMiddleware: requestMiddleware,
    expositionHandler: expositionHandler,
    exposition:        exposition,
    metrics:           metrics,           // diagnostic; operators rarely need it
    namespace:         namespace,
    defaultLabels:     defaultLabels,
    cardinalityCap:    cardinalityCap,
    deactivate: function () {
      // Release the global tap handler. Operator-driven test reset.
      if (_activeTap === _tapHandler) _activeTap = null;
    },
  };
  return registry;
}

function _resetForTest() {
  _activeTap = null;
}

// ---- Snapshot writer/reader ----
//
// Out-of-process metrics export pattern for long-running daemons:
// the daemon writes a JSON snapshot atomically every N seconds; a
// separate CLI process reads + renders. Bypasses the HTTP-port +
// Unix-socket coupling that the regular Prometheus exposition
// handler requires. Useful for systemd daemons that don't want to
// bind a stats port at all (operator runs `daemon stats` and the
// CLI just reads the file).
//
// The writer is atomic — every write goes through atomic-file's
// writeSync (temp-file + rename + fsync) so a reader that lands
// between rename and fsync sees the previous complete snapshot
// rather than a partially-written one.
//
// Surface:
//
//   var stop = b.metrics.snapshot.startWriter({
//     path:       "/run/blamejs-daemon/metrics.json",
//     intervalMs: 5000,
//     fields:     function () { return { uptimeMs: ..., counters: {...} }; },
//   });
//   // ...later:
//   stop();   // clears timer; runs one final fields() flush before returning
//
//   var snap = b.metrics.snapshot.read("/run/blamejs-daemon/metrics.json");
//   process.stdout.write(b.metrics.snapshot.render(snap, { format: "text" }));

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
 *
 * @example
 *   var stop = b.metrics.snapshot.startWriter({
 *     path:       "/run/blamejs/metrics.json",
 *     intervalMs: 5000,
 *     fields:     function () {
 *       return {
 *         uptimeMs:    process.uptime() * 1000,
 *         queueDepth:  myQueue.size,
 *         lastSyncAt:  lastSyncAt,
 *       };
 *     },
 *   });
 *   // ... on SIGTERM:
 *   stop();
 */
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
  var p          = opts.path;
  var fieldsFn   = opts.fields;
  var intervalMs = opts.intervalMs;

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
    try {
      atomicFile.writeSync(p, JSON.stringify(payload) + "\n", { fileMode: 0o644 });
    } catch (e) {
      log("snapshot.writeSync failed: " + (e && e.message ? e.message : String(e)));
    }
  };

  // First flush is synchronous so the file exists by the time
  // startWriter returns. Subsequent flushes run on the interval.
  doFlush();
  var timer = setInterval(doFlush, intervalMs);
  if (typeof timer.unref === "function") timer.unref();

  return function stop() {
    clearInterval(timer);
    doFlush();   // final flush captures last state before the daemon exits
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
    raw = nodeFs.readFileSync(p, "utf8");
  } catch (e) {
    throw new MetricsError("metrics-snapshot/not-found",
      "metrics.snapshot.read: " + p + " — " + (e && e.message ? e.message : String(e)));
  }
  var parsed;
  // safeJson.parse with bounded maxBytes — the snapshot file is read
  // by a separate CLI / sidecar process from where it's written, and a
  // hostile actor with write access to the snapshot path could replace
  // it with a multi-GB file that would OOM the reader. 4 MiB ceiling
  // is well above the framework's expected snapshot size (~5-50 KiB)
  // and the safeJson absolute cap stays within reach.
  try {
    parsed = safeJson.parse(raw, { maxBytes: 4 * 1024 * 1024 });   // allow:raw-byte-literal — 4 MiB snapshot-file ceiling
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
 *   format: "prometheus" — Prometheus 0.0.4 text format, gauge metrics
 *                          named with a configurable prefix; only top-level
 *                          numeric fields under `snap.fields` are emitted
 *
 * @opts
 *   format:  "text" | "prometheus",   // default: "text"
 *   prefix:  string,                   // prometheus-only; default: "blamejs"
 *
 * @example
 *   var snap = b.metrics.snapshot.read("/run/blamejs/metrics.json");
 *   process.stdout.write(b.metrics.snapshot.render(snap));
 *   // or for Prometheus scraping:
 *   res.setHeader("Content-Type", "text/plain; version=0.0.4");
 *   res.end(b.metrics.snapshot.render(snap, { format: "prometheus", prefix: "myapp" }));
 */
function snapshotRender(snap, opts) {
  opts = opts || {};
  var format = opts.format || "text";
  if (!snap || typeof snap !== "object" || !snap.fields) {
    throw new MetricsError("metrics-snapshot/bad-snap",
      "metrics.snapshot.render: snap must be a startWriter-produced object (got " + typeof snap + ")");
  }
  var fields = snap.fields;
  if (format === "text") {
    var lines = ["snapshot written-at: " + snap.writtenAt];
    // allow:bare-canonicalize-walk — sort is for stable human-readable
    // output ordering, not canonicalize-for-hashing
    var keys = Object.keys(fields).sort();
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i];
      var v = fields[k];
      var s;
      if (typeof v === "number") s = String(v);
      else if (typeof v === "string") s = v;
      else if (typeof v === "boolean") s = v ? "true" : "false";
      else s = JSON.stringify(v);
      lines.push("  " + k + ": " + s);
    }
    return lines.join("\n") + "\n";
  }
  if (format === "prometheus") {
    var prefix = opts.prefix || "blamejs";
    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(prefix)) {
      throw new MetricsError("metrics-snapshot/bad-prefix",
        "metrics.snapshot.render: prometheus prefix must match [a-zA-Z_][a-zA-Z0-9_]*, got '" + prefix + "'");
    }
    var out = [];
    // allow:bare-canonicalize-walk — sort is for stable Prometheus
    // exposition output ordering, not canonicalize-for-hashing
    var keys2 = Object.keys(fields).sort();
    for (var j = 0; j < keys2.length; j++) {
      var k2 = keys2[j];
      var v2 = fields[k2];
      if (typeof v2 !== "number" || !isFinite(v2)) continue;   // only numeric scalars
      if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(k2)) continue;       // skip prom-incompatible names
      var metric = prefix + "_" + k2;
      out.push("# TYPE " + metric + " gauge");
      out.push(metric + " " + v2);
    }
    return out.join("\n") + "\n";
  }
  throw new MetricsError("metrics-snapshot/bad-format",
    "metrics.snapshot.render: format must be 'text' or 'prometheus', got '" + format + "'");
}

var snapshot = {
  startWriter: snapshotStartWriter,
  read:        snapshotRead,
  render:      snapshotRender,
};

module.exports = {
  create:                    create,
  tap:                       tap,
  snapshot:                  snapshot,
  MetricsError:              MetricsError,
  DEFAULT_HTTP_BUCKETS:      DEFAULT_HTTP_BUCKETS,
  DEFAULT_CARDINALITY_CAP:   DEFAULT_CARDINALITY_CAP,
  _resetForTest:             _resetForTest,
  // Internal helpers for tests
  _labelsKey:                _labelsKey,
  _renderLabels:             _renderLabels,
  _escapeLabelValue:         _escapeLabelValue,
};
