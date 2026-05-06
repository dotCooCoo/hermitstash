"use strict";
/**
 * metrics — Prometheus-format counters, gauges, and histograms.
 *
 * Production deployments need numbers. Without a metrics layer ops
 * teams are half-blind on every incident: "Was that p99 spike real?
 * What's the queue depth? How fast are audit emits going?". This
 * module ships the standard Prometheus types with framework
 * auto-instrumentation already wired into audit / vault / queue
 * hot paths so operators get the framework's vital signs for free.
 *
 * Public API:
 *
 *   var m = b.metrics.create({
 *     namespace:     "myapp",                  // prepended to every metric name
 *     defaultLabels: { service: "api", version: "1.2.3" },
 *     labelCardinalityCap: 10000,              // per-metric ceiling
 *   });
 *
 *   var requests = m.counter("http_requests_total", {
 *     help: "Total HTTP requests",
 *     labelNames: ["method", "route", "status"],
 *   });
 *   requests.inc({ method: "GET", route: "/users", status: "200" });
 *   requests.inc({ method: "GET", route: "/users", status: "200" }, 5);
 *
 *   var latency = m.histogram("http_request_duration_seconds", {
 *     help:       "HTTP request latency",
 *     labelNames: ["method", "route"],
 *     buckets:    [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
 *   });
 *   latency.observe({ method: "GET", route: "/users" }, 0.123);
 *
 *   var queueDepth = m.gauge("queue_depth", { labelNames: ["queueName"] });
 *   queueDepth.set({ queueName: "default" }, 42);
 *   queueDepth.inc({ queueName: "default" });
 *   queueDepth.dec({ queueName: "default" });
 *
 *   router.use(m.requestMiddleware());           // auto-times every request
 *   router.get("/metrics", m.expositionHandler());
 *
 * Framework auto-instrumentation:
 *   When metrics.create() runs, framework hot paths (audit.record,
 *   vault.seal, vault.unseal, queue ops) call metrics.tap() — a
 *   global no-op stub that the active registry replaces with real
 *   counters. Modules don't import the registry directly; the tap
 *   pattern keeps them decoupled and lets operators with no metrics
 *   pay zero cost.
 *
 *   Built-in metrics surfaced:
 *     framework_audit_events_total{action, outcome}   counter
 *     framework_vault_seal_total                      counter
 *     framework_vault_unseal_total                    counter
 *     framework_queue_enqueue_total{queueName}        counter
 *     framework_queue_complete_total{queueName}       counter
 *     framework_queue_fail_total{queueName}           counter
 *     framework_queue_depth{queueName}                gauge
 *     framework_jobs_inflight{queueName}              gauge
 *     framework_errors_total{class}                   counter
 *     framework_http_requests_total{method,route,status}  counter
 *     framework_http_request_duration_seconds{method,route}  histogram
 *
 * Cardinality control:
 *   Every metric has a per-instance ceiling on distinct label
 *   combinations (default 10,000). When a request's label set would
 *   create the 10,001st unique combination, the increment is dropped
 *   and a warning is logged ONCE per metric. The bound is high enough
 *   that legitimate apps don't hit it; low enough that runaway
 *   labels (a label per request id, per user id, per full URL with
 *   query string) can't OOM the process. Operators size up via
 *   labelCardinalityCap when they have a legitimate need.
 *
 *   Best practice: route labels are the route TEMPLATE (`/users/:id`),
 *   not the actual path (`/users/123`). The framework's
 *   requestMiddleware uses req.routePattern when set; otherwise falls
 *   back to req.url stripped of query string.
 *
 * Exposition format:
 *   The text/plain exposition follows the Prometheus 0.0.4 text format:
 *   `# HELP <name> <description>` and `# TYPE <name> <counter|gauge|
 *   histogram>` headers, one sample per line with serialized labels
 *   in `{key="value",key2="value2"}` form. Buckets and _sum / _count
 *   for histograms.
 *
 * Out of scope (with structural reasons):
 *   - Summary type (client-side quantiles): generally inferior to
 *     histogram for aggregation across instances. Prometheus team
 *     recommends histogram. Add later if a real demand emerges.
 *   - Push gateway: pull-only monitoring is the simpler architecture.
 *     Operators with batch jobs that want push wire it themselves.
 *   - Native histogram (Prometheus 2.40+): not yet broadly supported
 *     by tooling; classic histogram is universal.
 *   - Per-process labels at scrape time (instance, hostname): operators
 *     pass via defaultLabels. The framework doesn't auto-inject —
 *     deploy environments differ on what to use (k8s pod name,
 *     hostname, container id) and the operator knows best.
 */

var C = require("./constants");
var canonicalJson = require("./canonical-json");
var { defineClass } = require("./framework-error");
var { boot } = require("./log");
var nb = require("./numeric-bounds");
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

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "namespace", "defaultLabels", "labelCardinalityCap",
  ], "b.metrics");
  var namespace     = opts.namespace || "";
  var defaultLabels = opts.defaultLabels || {};
  nb.requirePositiveFiniteIntIfPresent(opts.labelCardinalityCap,
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

module.exports = {
  create:                    create,
  tap:                       tap,
  MetricsError:              MetricsError,
  DEFAULT_HTTP_BUCKETS:      DEFAULT_HTTP_BUCKETS,
  DEFAULT_CARDINALITY_CAP:   DEFAULT_CARDINALITY_CAP,
  _resetForTest:             _resetForTest,
  // Internal helpers for tests
  _labelsKey:                _labelsKey,
  _renderLabels:             _renderLabels,
  _escapeLabelValue:         _escapeLabelValue,
};
