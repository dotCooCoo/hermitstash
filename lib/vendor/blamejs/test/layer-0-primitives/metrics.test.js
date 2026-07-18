// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.metrics — error-path + adversarial-input coverage for the core
 * registry (counter / gauge / histogram / exposition / requestMiddleware
 * / tap dispatch) and the snapshot + shadow-registry surfaces.
 *
 * The happy path is exercised by the smoke + integration suites; this
 * file drives the validation refusals, resource-limit rejections,
 * wrong-state / unknown-command branches, and typed-error paths those
 * suites never reach. Every assertion drives the public API
 * (`b.metrics.*`) — never a private internal.
 *
 * Run standalone: `node test/layer-0-primitives/metrics.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var path    = require("node:path");
var fs      = require("node:fs");

var BACKSLASH = String.fromCharCode(92);
var NEWLINE   = String.fromCharCode(10);

// Snapshot fixture — a real writable file under an isolated temp dir
// (b.testing.tempDir, the sanctioned helper). Returns the file path plus
// the dir cleanup so every test tears its scratch state down in finally.
function _snapFixture(label) {
  var d = b.testing.tempDir("metrics-" + label);
  return { file: path.join(d.path, "snap.json"), cleanup: d.cleanup };
}

// Shared throw-capture helpers — one shape, reused across every refusal
// assertion (audit-existing: mirrors the expectThrow shape the sibling
// metrics-snapshot / metrics-shadow-registry tests already use).
function expectCode(label, fn, codeMatch) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, !!(threw && (threw.code || "").indexOf(codeMatch) !== -1));
}
function expectThrowMsg(label, fn, re) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, !!(threw && re.test(threw.message || "")));
}

// ---- create() opt validation (entry-point / throw tier) ----

function testCreateRejectsUnknownOpt() {
  expectThrowMsg("create: unknown opt rejected",
    function () { b.metrics.create({ bogus: 1 }); },
    /unknown option/);
}

function testCreateRejectsBadCardinalityCap() {
  expectCode("create: cardinalityCap 0 rejected",
    function () { b.metrics.create({ labelCardinalityCap: 0 }); }, "metrics/bad-opt");
  expectCode("create: cardinalityCap negative rejected",
    function () { b.metrics.create({ labelCardinalityCap: -1 }); }, "metrics/bad-opt");
  expectCode("create: cardinalityCap non-integer rejected",
    function () { b.metrics.create({ labelCardinalityCap: 1.5 }); }, "metrics/bad-opt");
  expectCode("create: cardinalityCap Infinity rejected",
    function () { b.metrics.create({ labelCardinalityCap: Infinity }); }, "metrics/bad-opt");
}

function testCreateRejectsBadDefaultLabelName() {
  expectCode("create: invalid defaultLabels name rejected",
    function () { b.metrics.create({ defaultLabels: { "bad-name": "x" } }); }, "metrics/bad-label");
}

// ---- metric-name / label-name validation ----

function testMetricNameValidation() {
  var m = b.metrics.create();
  expectCode("counter: hyphen in name rejected",
    function () { m.counter("bad-name!", {}); }, "metrics/bad-name");
  expectCode("counter: empty name rejected",
    function () { m.counter("", {}); }, "metrics/bad-name");
  expectCode("counter: non-string name rejected",
    function () { m.counter(123, {}); }, "metrics/bad-name");
  expectCode("counter: over-long name rejected",
    function () { m.counter(new Array(250).join("x"), {}); }, "metrics/bad-name");
  expectCode("gauge: bad labelName rejected",
    function () { m.gauge("okg", { labelNames: ["bad-name"] }); }, "metrics/bad-label");
  expectCode("histogram: bad labelName rejected",
    function () { m.histogram("okh", { labelNames: ["also bad"] }); }, "metrics/bad-label");
}

function testDuplicateRegistration() {
  var m = b.metrics.create();
  m.counter("dup_total", {});
  expectCode("counter: duplicate name rejected",
    function () { m.counter("dup_total", {}); }, "metrics/duplicate");
  // A gauge re-using a counter's fully-qualified name also collides.
  expectCode("gauge: collides with existing counter name",
    function () { m.gauge("dup_total", {}); }, "metrics/duplicate");
}

// ---- counter error branches ----

function testCounterDecrementRefused() {
  var m = b.metrics.create();
  var c = m.counter("reqs_total", {});
  expectCode("counter.inc: negative value refused",
    function () { c.inc(-1); }, "metrics/counter-decrement");
  expectCode("counter.inc: negative with labels refused",
    function () { m.counter("reqs2_total", { labelNames: ["a"] }).inc({ a: "x" }, -5); },
    "metrics/counter-decrement");
}

function testLabelResolution() {
  var m = b.metrics.create();
  var c = m.counter("http_total", { labelNames: ["method"] });
  expectCode("inc: undeclared label rejected",
    function () { c.inc({ method: "GET", route: "/x" }); }, "metrics/undeclared-label");
  expectCode("inc: missing required label rejected",
    function () { c.inc({}); }, "metrics/missing-label");
  // Declared + present → succeeds; get reflects the increment.
  c.inc({ method: "GET" }, 3);
  check("inc: declared label increments", c.get({ method: "GET" }) === 3);
  check("get: unknown labelset defaults to 0", c.get({ method: "POST" }) === 0);
}

function testCardinalityCapDropsSilently() {
  var m = b.metrics.create({ namespace: "cap", labelCardinalityCap: 2 });
  var c = m.counter("k_total", { labelNames: ["id"] });
  c.inc({ id: "a" });
  c.inc({ id: "b" });
  c.inc({ id: "c" });   // third distinct label set — over cap, dropped
  check("cap: first labelset kept",  c.get({ id: "a" }) === 1);
  check("cap: second labelset kept", c.get({ id: "b" }) === 1);
  check("cap: over-cap labelset dropped (stays 0)", c.get({ id: "c" }) === 0);
  // An already-seen labelset still increments after the cap is hit.
  c.inc({ id: "a" });
  check("cap: existing labelset still increments post-cap", c.get({ id: "a" }) === 2);
  // Exposition renders only the retained series (no third series line).
  var out = m.exposition();
  check("cap: over-cap series absent from exposition",
    out.indexOf('cap_k_total{id="c"}') === -1);
}

// ---- gauge error branches ----

function testGaugeBadValueRefused() {
  var m = b.metrics.create();
  var g = m.gauge("temp", {});
  expectCode("gauge.set: NaN refused",
    function () { g.set(NaN); }, "metrics/gauge-bad-value");
  expectCode("gauge.set: missing value (undefined) refused",
    function () { g.set({}); }, "metrics/gauge-bad-value");
  expectCode("gauge.set: string value refused",
    function () { g.set("hot"); }, "metrics/gauge-bad-value");
  // inc / dec adjust an existing series; get returns the running value.
  g.set(10);
  g.inc(5);
  g.dec(3);
  check("gauge.set/inc/dec compose", g.get() === 12);
}

// ---- histogram error branches ----

function testHistogramBadBuckets() {
  var m = b.metrics.create();
  expectCode("histogram: empty buckets refused",
    function () { m.histogram("h1", { buckets: [] }); }, "metrics/bad-buckets");
  expectCode("histogram: non-array buckets refused",
    function () { m.histogram("h2", { buckets: "nope" }); }, "metrics/bad-buckets");
  expectCode("histogram: non-numeric bucket boundary refused",
    function () { m.histogram("h3", { buckets: [1, "x", 3] }); }, "metrics/bad-buckets");
  expectCode("histogram: NaN bucket boundary refused",
    function () { m.histogram("h4", { buckets: [1, NaN] }); }, "metrics/bad-buckets");
  expectCode("histogram: non-ascending buckets refused (equal)",
    function () { m.histogram("h5", { buckets: [1, 1] }); }, "metrics/bad-buckets");
  expectCode("histogram: non-ascending buckets refused (descending)",
    function () { m.histogram("h6", { buckets: [2, 1] }); }, "metrics/bad-buckets");
}

function testHistogramObserveBadValue() {
  var m = b.metrics.create();
  var h = m.histogram("lat", { buckets: [0.5, 1] });
  expectCode("histogram.observe: NaN refused",
    function () { h.observe(NaN); }, "metrics/histogram-bad-value");
  expectCode("histogram.observe: string refused",
    function () { h.observe("slow"); }, "metrics/histogram-bad-value");
  // A valid observation lands in the right bucket + the +Inf bucket.
  h.observe(0.1);
  var out = m.exposition();
  check("histogram: le bucket rendered", out.indexOf('lat_bucket{le="0.5"} 1') !== -1);
  check("histogram: +Inf bucket rendered", out.indexOf('lat_bucket{le="+Inf"} 1') !== -1);
  check("histogram: count rendered", out.indexOf("lat_count 1") !== -1);
}

// ---- exposition wire-format escaping + content negotiation ----

function testLabelValueEscaping() {
  var m = b.metrics.create({ namespace: "esc" });
  var c = m.counter("k_total", { labelNames: ["p"] });
  c.inc({ p: 'x"y' + NEWLINE + "z" });   // short, non-credential value
  var out = m.exposition();
  var line = out.split(NEWLINE).filter(function (l) { return l.indexOf("esc_k_total{") === 0; })[0] || "";
  check("escape: no raw newline leaks into the exposition line", line.indexOf(NEWLINE) === -1);
  check("escape: double-quote escaped", line.indexOf(BACKSLASH + '"') !== -1);
  check("escape: newline escaped to backslash-n", line.indexOf(BACKSLASH + "n") !== -1);
}

function testExpositionHandlerNegotiation() {
  var m = b.metrics.create();
  m.counter("hits_total", {}).inc();
  var handler = m.expositionHandler();

  function run(accept) {
    var req = b.testing.mockReq({ headers: accept ? { accept: accept } : {} });
    var res = b.testing.mockRes();
    handler(req, res);
    return res._captured();
  }

  var noAccept = run(null);
  check("negotiate: no Accept defaults to Prometheus 0.0.4",
    (noAccept.headers["content-type"] || "").indexOf("version=0.0.4") !== -1);
  check("negotiate: exposition status is 200", noAccept.status === 200);
  check("negotiate: Cache-Control no-store set", noAccept.headers["cache-control"] === "no-store");
  check("negotiate: Content-Length is a byte count", typeof noAccept.headers["content-length"] === "number");

  var om = run("application/openmetrics-text; version=1.0.0");
  check("negotiate: OpenMetrics Accept selects OpenMetrics 1.0.0",
    (om.headers["content-type"] || "").indexOf("openmetrics-text") !== -1);
  check("negotiate: OpenMetrics body carries the # EOF terminator",
    om.body.indexOf("# EOF") !== -1);

  // RFC 9110 weighted negotiation: text/plain q=1 beats openmetrics q=0.
  var weighted = run("text/plain;q=1.0, application/openmetrics-text;q=0");
  check("negotiate: q=0 OpenMetrics loses to q=1 text/plain (Prometheus wins)",
    (weighted.headers["content-type"] || "").indexOf("version=0.0.4") !== -1);
}

// ---- requestMiddleware auto-instrumentation ----

function testRequestMiddlewareCountsAndTimes() {
  var m = b.metrics.create();
  var mw = m.requestMiddleware();
  var req = b.testing.mockReq({ method: "GET", url: "/users?q=1" });
  req.routePattern = "/users/:id";   // matcher-set route template
  var res = b.testing.mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  res.writeHead(200);
  res.end("body");
  check("middleware: next() invoked", nextCalled === true);
  var reqs = m.metrics.get("framework_http_requests_total");
  check("middleware: counts by route TEMPLATE not raw path",
    reqs.get({ method: "GET", route: "/users/:id", status: "200" }) === 1);
  var dur = m.metrics.get("framework_http_request_duration_seconds");
  check("middleware: latency histogram observed",
    dur.values.size === 1);
}

// ---- tap dispatch (global no-op stub + registry-driven handler) ----

function testTapDispatch() {
  b.metrics._resetForTest();
  // Before any registry is active, tap is a zero-cost no-op — never throws.
  var noThrow = true;
  try { b.metrics.tap("audit.record", 1, { action: "x", outcome: "ok" }); }
  catch (_e) { noThrow = false; }
  check("tap: no-op (no throw) before a registry is active", noThrow);

  var m = b.metrics.create();
  b.metrics.tap("audit.record", 2, { action: "login", outcome: "success" });
  check("tap: audit.record routes into framework_audit_events_total",
    m.metrics.get("framework_audit_events_total").get({ action: "login", outcome: "success" }) === 2);

  b.metrics.tap("queue.enqueue", 3, { queueName: "q" });
  check("tap: queue.enqueue raises queue depth gauge",
    m.metrics.get("framework_queue_depth").get({ queueName: "q" }) === 3);
  b.metrics.tap("queue.complete", 1, { queueName: "q" });
  check("tap: queue.complete lowers queue depth gauge",
    m.metrics.get("framework_queue_depth").get({ queueName: "q" }) === 2);

  // Unknown / unsupported tap name falls through the dispatch with no
  // effect — no throw, no metric mutated.
  var before = m.metrics.get("framework_errors_total").values.size;
  var unknownOk = true;
  try { b.metrics.tap("nonexistent.event", 1, {}); } catch (_e) { unknownOk = false; }
  check("tap: unknown command is a silent no-op", unknownOk &&
    m.metrics.get("framework_errors_total").values.size === before);

  // deactivate() releases the global handler → tap is a no-op again.
  m.deactivate();
  var seal = m.metrics.get("framework_vault_seal_total").get();
  b.metrics.tap("vault.seal", 1, {});
  check("tap: no-op after deactivate()",
    m.metrics.get("framework_vault_seal_total").get() === seal);

  b.metrics._resetForTest();
}

// ---- snapshot.startWriter validation (uncovered opt branches) ----

function testSnapshotStartWriterValidation() {
  function baseOpts(extra) {
    var o = { path: "/tmp/metrics-cov.json", intervalMs: 1000, fields: function () { return {}; } };
    var k = Object.keys(extra);
    for (var i = 0; i < k.length; i++) o[k[i]] = extra[k[i]];
    return o;
  }
  expectCode("startWriter: non-registry registry object rejected",
    function () { b.metrics.snapshot.startWriter(baseOpts({ registry: 5 })); },
    "metrics-snapshot/bad-registry");
  expectCode("startWriter: registry without .metrics rejected",
    function () { b.metrics.snapshot.startWriter(baseOpts({ registry: { nope: 1 } })); },
    "metrics-snapshot/bad-registry");
  expectCode("startWriter: negative fileMode rejected",
    function () { b.metrics.snapshot.startWriter(baseOpts({ fileMode: -1 })); },
    "metrics-snapshot/bad-file-mode");
  expectCode("startWriter: fileMode above 0o777 rejected",
    function () { b.metrics.snapshot.startWriter(baseOpts({ fileMode: 0o1000 })); },
    "metrics-snapshot/bad-file-mode");
  expectCode("startWriter: non-integer fileMode rejected",
    function () { b.metrics.snapshot.startWriter(baseOpts({ fileMode: 1.5 })); },
    "metrics-snapshot/bad-file-mode");
}

// ---- shadowRegistry error branches (uncovered) ----

function testShadowRegistryValidation() {
  expectCode("shadow: bad onCardinalityExceeded policy rejected",
    function () { b.metrics.snapshot.shadowRegistry({ namespace: "ns", onCardinalityExceeded: "explode" }); },
    "metrics-shadow/bad-policy");
  expectCode("shadow: negative cardinalityCap rejected",
    function () { b.metrics.snapshot.shadowRegistry({ namespace: "ns", cardinalityCap: -1 }); },
    "metrics-shadow/bad-cap");
  expectCode("shadow: non-integer cardinalityCap rejected",
    function () { b.metrics.snapshot.shadowRegistry({ namespace: "ns", cardinalityCap: 1.5 }); },
    "metrics-shadow/bad-cap");
  expectCode("shadow: empty-string info name rejected",
    function () { b.metrics.snapshot.shadowRegistry({ namespace: "ns", info: [""] }); },
    "metrics-shadow/bad-info");
  expectCode("shadow: non-string counter name rejected",
    function () { b.metrics.snapshot.shadowRegistry({ namespace: "ns", counters: [123] }); },
    "metrics-shadow/bad-counters");
}

function testShadowRegistryGaugeValueRefusal() {
  var sh = b.metrics.snapshot.shadowRegistry({ namespace: "ns", gauges: ["gd"] });
  expectCode("shadow.set: NaN gauge value refused",
    function () { sh.set("gd", NaN); }, "metrics-shadow/bad-gauge-value");
  expectCode("shadow.set: Infinity gauge value refused",
    function () { sh.set("gd", Infinity); }, "metrics-shadow/bad-gauge-value");
  expectCode("shadow.set: string gauge value refused",
    function () { sh.set("gd", "x"); }, "metrics-shadow/bad-gauge-value");
}

function testShadowRegistryDropPolicyAndReset() {
  // Default "drop" policy: over-cap label sets silently dropped, no throw.
  var sh = b.metrics.snapshot.shadowRegistry({
    namespace: "ns", counters: ["hits_total"], cardinalityCap: 2,
  });
  var noThrow = true;
  try {
    sh.inc("hits_total", { id: "a" });
    sh.inc("hits_total", { id: "b" });
    sh.inc("hits_total", { id: "c" });   // over cap — dropped, not thrown
  } catch (_e) { noThrow = false; }
  check("shadow drop-policy: over-cap inc does not throw", noThrow);
  var snap = sh.snapshot();
  check("shadow drop-policy: over-cap series absent",
    snap.counters.hits_total['{"id":"c"}'] === undefined);
  // Non-mirrored names are ignored (setInfo only stores declared names).
  sh.setInfo("not_declared", "x");
  check("shadow: setInfo ignores non-mirrored name",
    sh.snapshot().info.not_declared === undefined);
  // reset() clears all accumulated state.
  sh.reset();
  check("shadow reset: counters cleared",
    Object.keys(sh.snapshot().counters).length === 0);
}

// ---- counter non-finite value + defaultLabels merge ----

function testCounterNonFiniteValueRefused() {
  var m = b.metrics.create();
  var c = m.counter("ctr_total", { labelNames: ["a"] });
  expectCode("counter.inc: NaN value refused",
    function () { c.inc(NaN); }, "metrics/counter-bad-value");
  expectCode("counter.inc: Infinity value refused",
    function () { c.inc({ a: "x" }, Infinity); }, "metrics/counter-bad-value");
}

function testDefaultLabelsMergedIntoSeries() {
  // Non-empty defaultLabels drive the label-copy loop in _resolveLabels
  // and attach to every rendered sample.
  var m = b.metrics.create({ namespace: "dl", defaultLabels: { service: "api", version: "1" } });
  var c = m.counter("hits_total", { labelNames: ["route"] });
  c.inc({ route: "/x" }, 4);
  check("defaultLabels: series carries the increment", c.get({ route: "/x" }) === 4);
  var out = m.exposition();
  check("defaultLabels: service attached to the sample line",
    out.indexOf('service="api"') !== -1);
  check("defaultLabels: version attached to the sample line",
    out.indexOf('version="1"') !== -1);
}

// ---- gauge / histogram cardinality-cap onFull (drop-silent) ----

function testGaugeCardinalityCap() {
  var m = b.metrics.create({ namespace: "gcap", labelCardinalityCap: 1 });
  var g = m.gauge("depth", { labelNames: ["q"] });
  g.set({ q: "a" }, 5);
  g.set({ q: "b" }, 9);   // second distinct set — over cap, dropped
  check("gauge cap: first set kept", g.get({ q: "a" }) === 5);
  check("gauge cap: over-cap set dropped (stays 0)", g.get({ q: "b" }) === 0);
  // inc/dec on an over-cap (never-created) series are also no-ops.
  g.inc({ q: "b" }, 3);
  g.dec({ q: "b" }, 1);
  check("gauge cap: inc/dec on dropped series stay 0", g.get({ q: "b" }) === 0);
}

function testHistogramCardinalityCap() {
  var m = b.metrics.create({ namespace: "hcap", labelCardinalityCap: 1 });
  var h = m.histogram("lat", { labelNames: ["op"], buckets: [0.5, 1] });
  h.observe({ op: "a" }, 0.1);
  h.observe({ op: "b" }, 0.2);   // over cap — dropped
  var out = m.exposition();
  check("histogram cap: first series present",
    out.indexOf('hcap_lat_count{op="a"} 1') !== -1);
  check("histogram cap: over-cap series absent",
    out.indexOf('op="b"') === -1);
}

// ---- credential-shape label redaction (adversarial input) ----

function testCredentialRedaction() {
  var m = b.metrics.create({ namespace: "cred" });
  var c = m.counter("k_total", { labelNames: ["tok"] });
  var bearerBody = "abcdefghijklmnop";
  var issuerTok  = "sk-abcdefghijklmnop";
  var jwtTok     = "aaaaaaaa.bbbbbbbb.cccccccc";
  var entropyTok = "abcdef0123456789abcdef0123456789abcdef01";   // 40 hex chars
  var longBearer = "Bearer " + new Array(301).join("x");         // > CRED_MAX_SCAN, clamped
  var plainLong  = "hello_world_xyz";                            // >= 8, not a credential
  c.inc({ tok: "Bearer " + bearerBody });
  c.inc({ tok: issuerTok });
  c.inc({ tok: jwtTok });
  c.inc({ tok: entropyTok });
  c.inc({ tok: longBearer });
  c.inc({ tok: plainLong });
  var out = m.exposition();
  check("redact: credential values replaced with the marker",
    out.indexOf("[REDACTED-CREDENTIAL]") !== -1);
  check("redact: raw bearer token body never reaches the scrape stream",
    out.indexOf(bearerBody) === -1);
  check("redact: raw issuer token absent", out.indexOf(issuerTok) === -1);
  check("redact: raw JWT absent", out.indexOf(jwtTok) === -1);
  check("redact: raw high-entropy token absent", out.indexOf(entropyTok) === -1);
  check("redact: non-credential long value passes through verbatim",
    out.indexOf(plainLong) !== -1);
}

// ---- OpenMetrics exposition (_total suffix, UNIT line, exemplars) ----

function testExpositionOpenMetricsCounterSuffixAndUnit() {
  var m = b.metrics.create();
  // Counter name WITHOUT the _total suffix + a declared unit: OpenMetrics
  // forces the `_total` sample-line suffix and emits a `# UNIT` line.
  var c = m.counter("bytes_processed", { help: "bytes", unit: "bytes" });
  c.inc(7);
  var out = m.exposition({ format: "openmetrics" });
  check("openmetrics: counter gains _total suffix on the sample line",
    out.indexOf("bytes_processed_total 7") !== -1);
  check("openmetrics: TYPE line uses the suffixed name",
    out.indexOf("# TYPE bytes_processed_total counter") !== -1);
  check("openmetrics: UNIT line emitted for a metric with a unit",
    out.indexOf("# UNIT bytes_processed_total bytes") !== -1);
  check("openmetrics: EOF terminator present", out.indexOf("# EOF") !== -1);
}

function testHistogramExemplarsRendered() {
  var m = b.metrics.create();
  var h = m.histogram("op_seconds", { labelNames: ["op"], buckets: [0.5, 1] });
  // Full exemplar (labels + explicit value + timestamp).
  h.observe({ op: "a" }, 0.1, { labels: { trace_id: "T1", span_id: "S1" }, value: 0.1, timestamp: 1717000000 });
  // Minimal exemplar object ({}): value falls back to the observed value,
  // timestamp falls back to null — drives the false side of both ternaries.
  h.observe({ op: "b" }, 0.2, {});
  var out = m.exposition({ format: "openmetrics" });
  check("exemplar: full exemplar renders trace_id + timestamp",
    out.indexOf('# {span_id="S1",trace_id="T1"} 0.1 1717000000') !== -1);
  check("exemplar: minimal exemplar renders value, empty labels, no timestamp",
    out.indexOf('op_seconds_bucket{le="0.5",op="b"} 1 #  0.2\n') !== -1);
}

// Exemplar labels reach the OpenMetrics scrape stream verbatim, the same
// egress surface regular labels do — so a credential-shaped value an operator
// attaches to an exemplar (e.g. tapping a raw header alongside trace context)
// must be scrubbed the same way _resolveLabels scrubs regular labels. Redacting
// only the regular labels left the exemplar-label path raw (CWE-532). RED before
// the fix: the raw bearer / issuer / JWT / high-entropy tokens appear in the
// exposition; GREEN after: the marker replaces them and the trace context
// survives.
function testHistogramExemplarLabelsRedacted() {
  var m = b.metrics.create({ namespace: "exred" });
  var h = m.histogram("op_seconds", { labelNames: ["op"], buckets: [0.5, 1] });
  var bearerBody = "abcdefghijklmnop";                            // "Bearer <body>"
  var issuerTok  = "sk-abcdefghijklmnop";                         // issuer-prefixed
  var jwtTok     = "aaaaaaaa.bbbbbbbb.cccccccc";                  // JWT shape
  var entropyTok = "abcdef0123456789abcdef0123456789abcdef01";   // 40 hex chars
  h.observe({ op: "a" }, 0.1, {
    labels: {
      trace_id: "trace-keepme",
      authorization: "Bearer " + bearerBody,
      api_key: issuerTok,
      jwt: jwtTok,
      opaque: entropyTok,
    },
    value: 0.1,
  });
  var out = m.exposition({ format: "openmetrics" });
  check("exemplar-redact: bearer body never reaches the scrape stream",
    out.indexOf(bearerBody) === -1);
  check("exemplar-redact: issuer token absent", out.indexOf(issuerTok) === -1);
  check("exemplar-redact: JWT absent", out.indexOf(jwtTok) === -1);
  check("exemplar-redact: high-entropy token absent", out.indexOf(entropyTok) === -1);
  check("exemplar-redact: credential marker present on the exemplar line",
    out.indexOf("[REDACTED-CREDENTIAL]") !== -1);
  check("exemplar-redact: non-credential trace_id survives verbatim",
    out.indexOf('trace_id="trace-keepme"') !== -1);
}

// Exemplar VALUE and TIMESTAMP are appended to the exposition line RAW — unlike
// labels, which _escapeLabelValue quotes — so a non-numeric operator-supplied
// value ("0.1\n# forged 999") would inject a forged metric line into every
// scrape (the same root as the exemplar-label leak, on the two numeric fields
// the label redactor doesn't cover). Both are coerced to a finite number
// (value falls back to the observation, timestamp to none) so only a bare
// number ever reaches the wire. RED before the fix: the forged line appears;
// GREEN after: it is gone and the observed value renders.
function testHistogramExemplarValueTimestampNotInjectable() {
  var m = b.metrics.create({ namespace: "exinj" });
  var h = m.histogram("op_seconds", { labelNames: ["op"], buckets: [0.5, 1] });
  h.observe({ op: "a" }, 0.1, {
    labels: { trace_id: "T1" },
    value: '0.1\n# forged_bucket{le="9"} 999',
    timestamp: "1717000000\n# ts_forged 1",
  });
  var out = m.exposition({ format: "openmetrics" });
  check("exemplar-inject: a forged bucket line in exemplar.value never renders",
    out.indexOf("forged_bucket") === -1);
  check("exemplar-inject: a forged line in exemplar.timestamp never renders",
    out.indexOf("ts_forged") === -1);
  check("exemplar-inject: exemplar renders the observed numeric value (fallback), no timestamp",
    out.indexOf('# {trace_id="T1"} 0.1\n') !== -1);
  // A clean numeric string still coerces to a number (OpenMetrics values are
  // numeric) — the guard rejects only non-finite input, it doesn't require a
  // native number.
  var m2 = b.metrics.create({ namespace: "exinj2" });
  var h2 = m2.histogram("op_seconds", { labelNames: ["op"], buckets: [0.5, 1] });
  h2.observe({ op: "a" }, 0.9, { labels: { trace_id: "T2" }, value: "0.5", timestamp: "1717000000" });
  var out2 = m2.exposition({ format: "openmetrics" });
  check("exemplar-inject: a clean numeric-string value coerces and renders",
    out2.indexOf('# {trace_id="T2"} 0.5 1717000000') !== -1);
  // A valid zero (Unix-epoch) timestamp must survive: present-vs-missing is a
  // numeric check, not truthiness, so 0 renders rather than being dropped as
  // falsy (the regression the coercion would otherwise introduce).
  var m3 = b.metrics.create({ namespace: "exts0" });
  var h3 = m3.histogram("op_seconds", { labelNames: ["op"], buckets: [0.5, 1] });
  h3.observe({ op: "a" }, 0.9, { labels: { trace_id: "T3" }, value: 0.9, timestamp: "0" });
  var out3 = m3.exposition({ format: "openmetrics" });
  check("exemplar-inject: a valid zero (epoch) timestamp is preserved, not dropped as falsy",
    out3.indexOf('# {trace_id="T3"} 0.9 0\n') !== -1);
}

// Exemplar label KEYS reach the OpenMetrics exposition through the same
// verbatim renderer (_renderLabels) as regular labels — and, unlike a label
// VALUE, a label NAME cannot be quoted or escaped in the Prometheus wire
// format. Regular label keys are gated (LABEL_NAME_RE at registration +
// _resolveLabels' undeclared-label refusal), but the exemplar path stored the
// operator-supplied key verbatim, so a key carrying a newline forged a whole
// metric line into every scrape (CWE-93 / OpenMetrics line-injection — the
// exemplar-KEY sibling of the exemplar-VALUE injection above). RED before the
// fix: a `forged_metric` line appears in the exposition; GREEN after: the
// invalid key is dropped and the valid trace_id survives.
function testHistogramExemplarLabelKeyNotInjectable() {
  var m = b.metrics.create({ namespace: "exkey" });
  var h = m.histogram("op_seconds", { labelNames: ["op"], buckets: [0.5, 1] });
  // Hostile exemplar label name: closes the exemplar brace, injects a newline,
  // and opens a forged metric family. Built from char codes so the lib source
  // stays pure-ASCII-literal-free of the attack bytes. A valid trace_id rides
  // alongside it in the SAME exemplar so the assertion proves selective
  // key-dropping (invalid name gone, valid name kept) rather than a blanket
  // exemplar drop.
  var forgedKey = 'x"} 0.1' + NEWLINE + 'forged_metric{a="b';
  var lbl = {};
  lbl.trace_id = "keepme";
  lbl[forgedKey] = "v";
  h.observe({ op: "a" }, 0.1, { labels: lbl, value: 0.1 });
  var out = m.exposition({ format: "openmetrics" });
  check("exemplar-key: a forged metric line via a hostile exemplar label name never renders",
    out.indexOf(NEWLINE + "forged_metric") === -1);
  check("exemplar-key: the raw attack newline never reaches the exposition",
    out.indexOf(forgedKey) === -1);
  check("exemplar-key: a valid exemplar label name survives verbatim",
    out.indexOf('trace_id="keepme"') !== -1);
  // Every exemplar comment segment (the ` # {...} value` tail) must stay on
  // one physical line — no injected key can split it across the newline the
  // scraper uses as its record separator.
  var lines = out.split(NEWLINE);
  var okShape = true;
  for (var i = 0; i < lines.length; i++) {
    var hashIdx = lines[i].indexOf(" # {");
    if (hashIdx === -1) continue;
    // The exemplar tail must contain a closing `}` on the SAME line.
    if (lines[i].indexOf("}", hashIdx) === -1) okShape = false;
  }
  check("exemplar-key: every exemplar comment stays on one exposition line", okShape);
}

// ---- requestMiddleware exemplar wiring + method fallback ----

function testRequestMiddlewareExemplarFromSpan() {
  var m = b.metrics.create();
  var mw = m.requestMiddleware();
  var req = b.testing.mockReq({ method: "GET", url: "/a" });
  req.span = { traceId: "trace-abc", spanId: "span-xyz", sampled: true };
  var res = b.testing.mockRes();
  mw(req, res, function () {});
  res.writeHead(200); res.end("ok");
  var dur = m.metrics.get("framework_http_request_duration_seconds");
  var entry = Array.from(dur.values.values())[0];
  check("middleware exemplar: server span trace_id stored on a bucket",
    entry.exemplars.some(function (ex) { return ex && ex.labels && ex.labels.trace_id === "trace-abc"; }));
}

function testRequestMiddlewareExemplarFromTraceFallback() {
  var m = b.metrics.create();
  var mw = m.requestMiddleware();
  var req = b.testing.mockReq({ method: "POST", url: "/b" });
  // No req.span — the traceparent-only fallback surfaces on req.trace.
  req.trace = { sampled: true, traceId: "tp-1", spanId: "tp-span-1" };
  var res = b.testing.mockRes();
  mw(req, res, function () {});
  res.writeHead(500); res.end("err");
  var dur = m.metrics.get("framework_http_request_duration_seconds");
  var entry = Array.from(dur.values.values())[0];
  check("middleware exemplar: req.trace fallback trace_id stored",
    entry.exemplars.some(function (ex) { return ex && ex.labels && ex.labels.trace_id === "tp-1"; }));
}

function testRequestMiddlewareMethodFallback() {
  var m = b.metrics.create();
  var mw = m.requestMiddleware();
  var req = b.testing.mockReq({ url: "/c" });
  delete req.method;   // absent method → counter labels default to "GET"
  var res = b.testing.mockRes();
  mw(req, res, function () {});
  res.writeHead(200); res.end("");
  var reqs = m.metrics.get("framework_http_requests_total");
  check("middleware: absent method defaults to GET",
    reqs.get({ method: "GET", route: "/c", status: "200" }) === 1);
}

// ---- tap dispatch: every framework hot-path branch ----

function testTapAllFrameworkBranches() {
  b.metrics._resetForTest();
  var m = b.metrics.create();

  // audit.record with NO labels → action/outcome default to "unknown".
  b.metrics.tap("audit.record", 1);
  check("tap: audit.record defaults missing action/outcome to unknown",
    m.metrics.get("framework_audit_events_total").get({ action: "unknown", outcome: "unknown" }) === 1);

  b.metrics.tap("vault.seal", 2, {});
  b.metrics.tap("vault.unseal", 3, {});
  check("tap: vault.seal counted while registry active",
    m.metrics.get("framework_vault_seal_total").get() === 2);
  check("tap: vault.unseal counted while registry active",
    m.metrics.get("framework_vault_unseal_total").get() === 3);

  // queue.lease raises the inflight gauge.
  b.metrics.tap("queue.lease", 2, { queueName: "q" });
  check("tap: queue.lease raises inflight gauge",
    m.metrics.get("framework_jobs_inflight").get({ queueName: "q" }) === 2);

  // queue.fail with willRetry !== false: inflight drops, depth unchanged.
  b.metrics.tap("queue.enqueue", 5, { queueName: "q" });
  var depthBefore = m.metrics.get("framework_queue_depth").get({ queueName: "q" });
  b.metrics.tap("queue.fail", 1, { queueName: "q", willRetry: true });
  check("tap: queue.fail retry lowers inflight",
    m.metrics.get("framework_jobs_inflight").get({ queueName: "q" }) === 1);
  check("tap: queue.fail retry leaves depth unchanged",
    m.metrics.get("framework_queue_depth").get({ queueName: "q" }) === depthBefore);
  // queue.fail with willRetry === false: terminal — depth also drops.
  b.metrics.tap("queue.fail", 1, { queueName: "q", willRetry: false });
  check("tap: terminal queue.fail lowers depth",
    m.metrics.get("framework_queue_depth").get({ queueName: "q" }) === depthBefore - 1);

  // error.construct with no class → "unknown"; default queueName when omitted.
  b.metrics.tap("error.construct", 1, {});
  check("tap: error.construct defaults class to unknown",
    m.metrics.get("framework_errors_total").get({ class: "unknown" }) === 1);
  b.metrics.tap("queue.enqueue", 1);   // no labels → queueName "default"
  check("tap: queue.enqueue with no labels lands under 'default'",
    m.metrics.get("framework_queue_depth").get({ queueName: "default" }) === 1);

  b.metrics._resetForTest();
}

function testTapDefaultsFromPartialLabelsAndFalsyValue() {
  b.metrics._resetForTest();
  var m = b.metrics.create();
  // Partial labels (object present, keyed prop absent) + falsy value (0):
  // value coerces to 1, and each missing label falls to its default.
  b.metrics.tap("audit.record", 0, { outcome: "ok" });   // action absent → "unknown"
  check("tap: falsy value coerces to 1; missing action defaults to unknown",
    m.metrics.get("framework_audit_events_total").get({ action: "unknown", outcome: "ok" }) === 1);
  b.metrics.tap("queue.enqueue", 0, {});   // queueName absent → "default"; value → 1
  check("tap: enqueue with empty labels defaults queueName + value",
    m.metrics.get("framework_queue_depth").get({ queueName: "default" }) === 1);
  b.metrics.tap("queue.lease", 0, {});     // inflight default queue, value → 1
  b.metrics.tap("queue.fail", 0, {});      // willRetry absent (not false) → depth unchanged
  check("tap: lease then fail(no-retry) nets inflight back to zero",
    m.metrics.get("framework_jobs_inflight").get({ queueName: "default" }) === 0);
  b.metrics.tap("vault.unseal", 0, {});    // value → 1
  check("tap: vault.unseal falsy value coerces to 1",
    m.metrics.get("framework_vault_unseal_total").get() === 1);
  b.metrics.tap("error.construct", 0, {}); // class absent → "unknown"; value → 1
  check("tap: error.construct with empty labels defaults class",
    m.metrics.get("framework_errors_total").get({ class: "unknown" }) === 1);
  b.metrics._resetForTest();
}

// ---- snapshot writer → reader round-trip (registry serialize) ----

function testSnapshotWriterReaderRegistry() {
  var fx = _snapFixture("rw");
  try {
    var registry = b.metrics.create({ namespace: "snap" });
    var c = registry.counter("reqs_total", { help: "r", labelNames: ["code"] });
    c.inc({ code: "200" }, 3);
    var g = registry.gauge("depth", { help: "d", labelNames: ["q"] });
    g.set({ q: "main" }, 7);
    var h = registry.histogram("lat_seconds", { help: "l", labelNames: ["op"], buckets: [0.01, 0.1] });
    h.observe({ op: "read" }, 0.05);

    var stop = b.metrics.snapshot.startWriter({
      path:       fx.file,
      intervalMs: 100000,     // large — only the sync first + stop() flushes run
      registry:   registry,
      fields:     function () { return { uptimeMs: 42 }; },
    });
    check("startWriter: file exists after synchronous first flush", fs.existsSync(fx.file));
    stop();

    var snap = b.metrics.snapshot.read(fx.file);
    check("read: writtenAt is a string", typeof snap.writtenAt === "string");
    check("read: flat field carried through", snap.fields.uptimeMs === 42);
    check("read: registry counter serialized",
      snap.metrics.snap_reqs_total.observations[0].value === 3);
    check("read: registry gauge serialized",
      snap.metrics.snap_depth.observations[0].value === 7);
    check("read: histogram buckets + counts serialized",
      Array.isArray(snap.metrics.snap_lat_seconds.buckets) &&
      snap.metrics.snap_lat_seconds.observations[0].count === 1);
  } finally {
    fx.cleanup();
  }
}

function testSnapshotWriterFlushErrorHandling() {
  var fx = _snapFixture("flush");
  try {
    // fields() that throws: first flush swallows the error, writes nothing,
    // and startWriter still returns a stop() handle.
    var threwOut = false;
    var stop1;
    try {
      stop1 = b.metrics.snapshot.startWriter({
        path:       fx.file,
        intervalMs: 100000,
        fields:     function () { throw new Error("fields boom"); },
      });
    } catch (_e) { threwOut = true; }
    check("startWriter: a throwing fields() does not escape startWriter", !threwOut);
    check("startWriter: no file written when the first flush threw", !fs.existsSync(fx.file));
    if (stop1) stop1();

    // fields() returning a non-object is skipped (no file, no throw).
    var stop2 = b.metrics.snapshot.startWriter({
      path:       fx.file,
      intervalMs: 100000,
      fields:     function () { return 42; },
    });
    check("startWriter: non-object fields() result skips the flush", !fs.existsSync(fx.file));
    stop2();
  } finally {
    fx.cleanup();
  }
}

// ---- snapshot.read error branches ----

function testSnapshotReadErrors() {
  expectCode("read: missing file rejected",
    function () { b.metrics.snapshot.read(path.join(b.testing.tempDir("metrics-none").path, "absent.json")); },
    "metrics-snapshot/not-found");
  var fx = _snapFixture("readbad");
  try {
    fs.writeFileSync(fx.file, "}{ not json");
    expectCode("read: malformed JSON rejected",
      function () { b.metrics.snapshot.read(fx.file); }, "metrics-snapshot/bad-json");
    fs.writeFileSync(fx.file, JSON.stringify({ writtenAt: "x" }));   // missing fields
    expectCode("read: snapshot missing fields rejected",
      function () { b.metrics.snapshot.read(fx.file); }, "metrics-snapshot/bad-shape");
  } finally {
    fx.cleanup();
  }
}

// ---- snapshot.render text (grouped, flat, ISO-date value) ----

function testSnapshotRenderTextGrouped() {
  var snap = {
    writtenAt: "2026-05-13T00:00:00.000Z",
    fields:    { count: 7, uptimeMs: 1000, at: "2026-05-13T12:00:00.000Z", extra: 3 },
  };
  var grouped = b.metrics.snapshot.render(snap, {
    format: "text",
    groups: { "Core": ["count", "uptimeMs"], "Bad": "not-an-array" },
  });
  check("render text: group header emitted", grouped.indexOf("== Core ==") !== -1);
  check("render text: grouped field listed under its group",
    grouped.indexOf("count: 7") !== -1);
  check("render text: ungrouped remainder falls under Other",
    grouped.indexOf("== Other ==") !== -1 && grouped.indexOf("extra: 3") !== -1);
  check("render text: non-array group value skipped (no == Bad == header)",
    grouped.indexOf("== Bad ==") === -1);
  check("render text: ISO-date field rendered verbatim",
    grouped.indexOf("at: 2026-05-13T12:00:00.000Z") !== -1);
}

// ---- snapshot.render prometheus (ISO epoch_ms + registry families) ----

function testSnapshotRenderPrometheusEpochAndFamilies() {
  var snap = {
    writtenAt: "2026-05-13T00:00:00.000Z",
    fields:    { hits_total: 5, depth: 2, at: "2026-05-13T00:00:00.000Z" },
    metrics:   {
      served_total: {
        type: "counter", help: "served things", labelNames: ["route"],
        observations: [{ labels: { route: "/x" }, value: 9 }],
      },
    },
  };
  var out = b.metrics.snapshot.render(snap, { format: "prometheus", prefix: "app" });
  check("render prom: _total field typed counter", out.indexOf("# TYPE app_hits_total counter") !== -1);
  check("render prom: non-suffixed field typed gauge", out.indexOf("# TYPE app_depth gauge") !== -1);
  check("render prom: ISO-date field emits parallel epoch_ms gauge",
    out.indexOf("# TYPE app_at_epoch_ms gauge") !== -1 &&
    out.indexOf("app_at_epoch_ms " + Date.parse("2026-05-13T00:00:00.000Z")) !== -1);
  check("render prom: registry family rendered with its verbatim name (no prefix)",
    out.indexOf('served_total{route="/x"} 9') !== -1 &&
    out.indexOf("# HELP served_total served things") !== -1);
}

function testSnapshotRenderErrors() {
  expectCode("render: non-object snap rejected",
    function () { b.metrics.snapshot.render(null); }, "metrics-snapshot/bad-snap");
  expectCode("render: unknown format rejected",
    function () { b.metrics.snapshot.render({ writtenAt: "x", fields: {} }, { format: "yaml" }); },
    "metrics-snapshot/bad-format");
  expectCode("render: bad prometheus prefix rejected",
    function () { b.metrics.snapshot.render({ writtenAt: "x", fields: {} }, { format: "prometheus", prefix: "1bad" }); },
    "metrics-snapshot/bad-prefix");
  expectCode("render: non-object fieldTypes rejected",
    function () { b.metrics.snapshot.render({ writtenAt: "x", fields: { n: 1 } }, { format: "prometheus", fieldTypes: [] }); },
    "metrics-snapshot/bad-field-types");
  expectCode("render: fieldTypes value must be counter|gauge",
    function () { b.metrics.snapshot.render({ writtenAt: "x", fields: { n: 1 } }, { format: "prometheus", fieldTypes: { n: "histogram" } }); },
    "metrics-snapshot/bad-field-type");
}

// ---- snapshot family defensive drops (forged / hand-edited snapshot) ----

function testSnapshotFamilyDefensiveDrops() {
  var snap = {
    writtenAt: "2026-05-13T00:00:00.000Z",
    fields:    {},
    metrics:   {
      // Whole-family drops → null, never rendered.
      "not_object":          "string-not-object",
      "bad name\nforged 1":  { type: "gauge", observations: [{ labels: {}, value: 1 }] },
      "bad_type":            { type: "summary", observations: [] },
      "hist_no_buckets":     { type: "histogram", observations: [] },
      "hist_bad_bucket":     { type: "histogram", buckets: ["x"], observations: [] },
      // Valid families whose individual observations are dropped.
      "ctr":  { type: "counter", help: "c\nx", labelNames: ["ok"], observations: [
        "not-an-object",
        { labels: { ok: "1", "bad name\n": "z" }, value: 4 },   // forged label dropped, sample kept
        { labels: {}, value: "not-a-number" },                  // non-numeric value dropped
      ] },
      "hist_ok": { type: "histogram", buckets: [0.5, 1], observations: [
        { labels: {}, counts: [1, 2], sum: 3, count: 3 },               // wrong counts length dropped
        { labels: {}, counts: [1, 2, "x"], sum: 3, count: 3 },          // non-numeric count dropped
        { labels: {}, counts: [1, 2, 3], sum: "nope", count: 6 },       // bad sum dropped
        { labels: {}, counts: [1, 2, 3], sum: 6, count: "x" },          // bad count dropped
        { counts: [1, 2, 3], sum: 6, count: 6 },                        // no labels key → {} labels
      ] },
      // observations not an array at all → treated as empty, family renders
      // metadata only (no samples).
      "obs_not_array": { type: "gauge", help: "", observations: "not-an-array" },
    },
  };
  var out = b.metrics.snapshot.render(snap, { format: "prometheus", prefix: "app" });
  check("family drop: non-object family skipped", out.indexOf("not_object") === -1);
  check("family drop: forged metric name skipped", out.indexOf("forged") === -1);
  check("family drop: unknown type skipped", out.indexOf("bad_type") === -1);
  check("family drop: bucket-less histogram skipped", out.indexOf("hist_no_buckets") === -1);
  check("family drop: non-numeric bucket boundary skips family", out.indexOf("hist_bad_bucket") === -1);
  check("family drop: forged label name dropped, valid sample kept",
    out.indexOf('ctr{ok="1"} 4') !== -1 && out.indexOf("bad name") === -1);
  check("family drop: help text newline escaped, not raw",
    out.indexOf("# HELP ctr c" + BACKSLASH + "nx") !== -1);
  check("family drop: only the well-formed histogram observation renders",
    out.indexOf("hist_ok_count 6") !== -1 && out.indexOf("hist_ok_count 3") === -1);
  check("family drop: non-array observations render metadata only",
    out.indexOf("# TYPE obs_not_array gauge") !== -1);
}

// ---- shadow registry render (prometheus / openmetrics / text) ----

function testShadowRenderPrometheus() {
  var sh = b.metrics.snapshot.shadowRegistry({
    namespace: "tenant", counters: ["requests_total"], gauges: ["queue_depth"],
  });
  sh.inc("requests_total", { route: "/x" });
  sh.inc("requests_total");                    // no-label series
  sh.set("queue_depth", 12, { queue: "main" });
  var prom = sh.render({ format: "prometheus" });
  check("shadow prom: labeled counter emitted with namespace prefix",
    prom.indexOf('tenant_requests_total{route="/x"} 1') !== -1);
  check("shadow prom: no-label counter series emitted",
    prom.indexOf("tenant_requests_total 1") !== -1);
  check("shadow prom: counter TYPE line is counter",
    prom.indexOf("# TYPE tenant_requests_total counter") !== -1);
  check("shadow prom: labeled gauge emitted",
    prom.indexOf('tenant_queue_depth{queue="main"} 12') !== -1);
  // openmetrics format takes the same labeled path.
  var om = sh.render({ format: "openmetrics" });
  check("shadow openmetrics: labeled gauge present",
    om.indexOf('tenant_queue_depth{queue="main"} 12') !== -1);
}

function testShadowRenderText() {
  var sh = b.metrics.snapshot.shadowRegistry({
    namespace: "t", counters: ["hits_total"], gauges: ["depth"], info: ["build"],
  });
  sh.inc("hits_total");                         // flat (no-label) counter
  sh.set("depth", 3, { q: "a" });               // labeled gauge → synthetic row
  sh.setInfo("build", "v1");
  var text = sh.render({ format: "text" });
  check("shadow text: flat counter row present", text.indexOf("hits_total: 1") !== -1);
  check("shadow text: info field present", text.indexOf("build: v1") !== -1);
}

// ---- shadow registry: remaining validation + cardinality policies ----

function testShadowMoreValidation() {
  expectCode("shadow: missing opts object rejected",
    function () { b.metrics.snapshot.shadowRegistry(); }, "metrics-shadow/bad-opts");
  expectCode("shadow: non-object opts rejected",
    function () { b.metrics.snapshot.shadowRegistry("nope"); }, "metrics-shadow/bad-opts");
  expectCode("shadow: namespace failing the name shape rejected",
    function () { b.metrics.snapshot.shadowRegistry({ namespace: "1bad" }); },
    "metrics-shadow/bad-namespace");
  expectCode("shadow: non-array counters rejected",
    function () { b.metrics.snapshot.shadowRegistry({ namespace: "ns", counters: "nope" }); },
    "metrics-shadow/bad-counters");
  expectCode("shadow: non-array gauges rejected",
    function () { b.metrics.snapshot.shadowRegistry({ namespace: "ns", gauges: 5 }); },
    "metrics-shadow/bad-gauges");
}

function testShadowCardinalityPolicies() {
  // refuse: the over-cap store THROWS (and emits a rate-limited audit).
  var refuse = b.metrics.snapshot.shadowRegistry({
    namespace: "r", counters: ["c_total"], cardinalityCap: 1, onCardinalityExceeded: "refuse",
  });
  refuse.inc("c_total", { id: "a" });
  expectCode("shadow refuse: over-cap inc throws",
    function () { refuse.inc("c_total", { id: "b" }); }, "metrics-shadow/cardinality-exceeded");

  // audit-only: over-cap is dropped without throwing.
  var auditOnly = b.metrics.snapshot.shadowRegistry({
    namespace: "a", gauges: ["g"], cardinalityCap: 1, onCardinalityExceeded: "audit-only",
  });
  auditOnly.set("g", 1, { id: "a" });
  var noThrow = true;
  try { auditOnly.set("g", 2, { id: "b" }); } catch (_e) { noThrow = false; }
  check("shadow audit-only: over-cap gauge set does not throw", noThrow);
  check("shadow audit-only: over-cap gauge value absent",
    auditOnly.snapshot().gauges.g['{"id":"b"}'] === undefined);

  // Re-incrementing an existing label set bumps the stored value.
  var counter = b.metrics.snapshot.shadowRegistry({ namespace: "i", counters: ["n_total"] });
  counter.inc("n_total", { id: "a" });
  counter.inc("n_total", { id: "a" });
  check("shadow: repeat inc on the same label set accumulates",
    counter.snapshot().counters.n_total['{"id":"a"}'] === 2);
}

function testNullLabelValueCoercedToEmpty() {
  var m = b.metrics.create({ namespace: "nl" });
  var c = m.counter("k_total", { labelNames: ["p"] });
  c.inc({ p: null });        // null label value coerces to ""
  c.inc({ p: undefined });   // undefined coerces to "" (same series)
  check("null label: coerces to empty-string series",
    c.get({ p: null }) === 2);
  var out = m.exposition();
  check("null label: rendered as empty-string label value",
    out.indexOf('nl_k_total{p=""} 2') !== -1);
}

function testSnapshotStartWriterMoreValidation() {
  var goodFields = function () { return {}; };
  expectCode("startWriter: missing path rejected",
    function () { b.metrics.snapshot.startWriter({ intervalMs: 1000, fields: goodFields }); },
    "metrics-snapshot/bad-path");
  expectCode("startWriter: interval below floor rejected",
    function () { b.metrics.snapshot.startWriter({ path: "/tmp/x.json", intervalMs: 50, fields: goodFields }); },
    "metrics-snapshot/bad-interval");
  expectCode("startWriter: non-finite interval rejected",
    function () { b.metrics.snapshot.startWriter({ path: "/tmp/x.json", intervalMs: Infinity, fields: goodFields }); },
    "metrics-snapshot/bad-interval");
  expectCode("startWriter: non-function fields rejected",
    function () { b.metrics.snapshot.startWriter({ path: "/tmp/x.json", intervalMs: 1000, fields: "nope" }); },
    "metrics-snapshot/bad-fields");
}

function testSnapshotRenderTextWithFamiliesAndValueShapes() {
  var snap = {
    writtenAt: "2026-05-13T00:00:00.000Z",
    fields:    {
      flag:  true,                     // boolean → "true"
      obj:   { nested: 1 },            // object → JSON.stringify branch
      plain: "just a string",          // non-ISO string → verbatim
    },
    metrics:   {
      served_total: { type: "counter", help: "s", labelNames: ["r"],
        observations: [{ labels: { r: "/x" }, value: 4 }] },
      depth: { type: "gauge", help: "d", labelNames: ["q"],
        observations: [{ labels: { q: "main" }, value: 8 }] },
      lat_seconds: { type: "histogram", help: "l", labelNames: ["op"], buckets: [0.5, 1],
        observations: [{ labels: { op: "read" }, counts: [1, 1, 1], sum: 0.3, count: 1 }] },
    },
  };
  var text = b.metrics.snapshot.render(snap, { format: "text" });
  check("text families: labeled counter row rendered",
    text.indexOf('served_total{r="/x"}: 4') !== -1);
  check("text families: labeled gauge row rendered",
    text.indexOf('depth{q="main"}: 8') !== -1);
  check("text families: histogram bucket + count rows rendered",
    text.indexOf('lat_seconds_bucket{le="0.5",op="read"}: 1') !== -1 &&
    text.indexOf('lat_seconds_count{op="read"}: 1') !== -1);
  check("text value: boolean field rendered as true", text.indexOf("flag: true") !== -1);
  check("text value: object field JSON-stringified",
    text.indexOf('obj: {"nested":1}') !== -1);
  check("text value: plain string rendered verbatim", text.indexOf("plain: just a string") !== -1);
}

function testSnapshotRenderPrometheusFieldTypeOverrideAndSkips() {
  var longStr = new Array(70).join("a");   // > 64 chars — ISO-epoch loop skips it
  var snap = {
    writtenAt: "2026-05-13T00:00:00.000Z",
    fields:    {
      ratio_total: 1,                       // _total but overridden to gauge
      served:      3,                        // no suffix, overridden to counter
      "1bad":      9,                        // invalid prom name — skipped
      note:        "not-a-timestamp",        // non-ISO string — epoch loop skips
      big:         longStr,                  // > 64 chars — epoch loop length-skips
      "1ts":       "2026-05-13T00:00:00.000Z", // ISO value but invalid prom field name
    },
  };
  var out = b.metrics.snapshot.render(snap, {
    format: "prometheus", prefix: "app",
    fieldTypes: { ratio_total: "gauge", served: "counter" },
  });
  check("fieldTypes: _total field overridden to gauge",
    out.indexOf("# TYPE app_ratio_total gauge") !== -1);
  check("fieldTypes: no-suffix field overridden to counter",
    out.indexOf("# TYPE app_served counter") !== -1);
  check("prom: invalid-name field skipped", out.indexOf("app_1bad") === -1);
  check("prom: non-ISO string field produces no epoch gauge",
    out.indexOf("app_note") === -1);
  check("prom: over-long string field produces no epoch gauge",
    out.indexOf("app_big") === -1);
  check("prom: ISO value under an invalid field name emits no epoch gauge",
    out.indexOf("1ts") === -1);
}

function testShadowTextLabeledCounterAndFlatGauge() {
  var sh = b.metrics.snapshot.shadowRegistry({
    namespace: "st", counters: ["hits_total"], gauges: ["depth"],
  });
  sh.inc("hits_total", { route: "/x" });   // labeled counter → synthetic row
  sh.set("depth", 5);                        // flat (no-label) gauge
  var text = sh.render({ format: "text" });
  check("shadow text: labeled counter synthetic row present",
    text.indexOf("hits_total{") !== -1);
  check("shadow text: flat gauge row present", text.indexOf("depth: 5") !== -1);
}

function testMetricResetClearsSeries() {
  var m = b.metrics.create({ namespace: "rst" });
  var c = m.counter("c_total", { labelNames: ["a"] });
  c.inc({ a: "x" }, 4);
  c.reset();
  check("counter.reset: series cleared", c.get({ a: "x" }) === 0);
  var g = m.gauge("g");
  g.set(5);
  g.reset();
  check("gauge.reset: value cleared", g.get() === 0);
  var h = m.histogram("h", { buckets: [1] });
  h.observe(0.5);
  h.reset();
  check("histogram.reset: observations cleared", h.values.size === 0);
}

function testShadowIgnoresUndeclaredAndEmptyLabels() {
  var sh = b.metrics.snapshot.shadowRegistry({
    namespace: "u", counters: ["events"], gauges: ["g"],
  });
  // inc / set on a name not in the mirrored set are silent no-ops.
  sh.inc("undeclared_total", { a: "1" });
  sh.set("undeclared_gauge", 5, { a: "1" });
  check("shadow: inc on unmirrored counter is a no-op",
    Object.keys(sh.snapshot().counters).length === 0);
  check("shadow: set on unmirrored gauge is a no-op",
    Object.keys(sh.snapshot().gauges).length === 0);
  // Empty labels object → the no-label series (key "").
  sh.inc("events", {});
  // A mirrored counter whose name lacks the _total suffix renders as a gauge.
  var prom = sh.render({ format: "prometheus" });
  check("shadow prom: empty-labels inc lands on the no-label series",
    prom.indexOf("u_events 1") !== -1);
  check("shadow prom: non-_total counter name typed as gauge",
    prom.indexOf("# TYPE u_events gauge") !== -1);
}

function testMetricFactoryDefaultsAndHeaderlessScrape() {
  var m = b.metrics.create();
  // Factories called with no options object → copts defaults to {} and the
  // histogram falls back to DEFAULT_HTTP_BUCKETS.
  m.counter("a_total").inc();
  m.gauge("g").set(3);
  var h = m.histogram("h");
  h.observe(0.02);
  check("factory defaults: histogram uses DEFAULT_HTTP_BUCKETS",
    h.buckets.length === b.metrics.DEFAULT_HTTP_BUCKETS.length);
  // Scrape handler with a request carrying no headers → defaults to
  // Prometheus 0.0.4 without dereferencing a missing headers object.
  var handler = m.expositionHandler();
  var res = b.testing.mockRes();
  handler({}, res);
  var cap = res._captured();
  check("headerless scrape: defaults to Prometheus 0.0.4",
    (cap.headers["content-type"] || "").indexOf("version=0.0.4") !== -1 && cap.status === 200);
}

function run() {
  testCreateRejectsUnknownOpt();
  testCreateRejectsBadCardinalityCap();
  testCreateRejectsBadDefaultLabelName();
  testMetricNameValidation();
  testDuplicateRegistration();
  testCounterDecrementRefused();
  testLabelResolution();
  testCardinalityCapDropsSilently();
  testGaugeBadValueRefused();
  testHistogramBadBuckets();
  testHistogramObserveBadValue();
  testLabelValueEscaping();
  testExpositionHandlerNegotiation();
  testRequestMiddlewareCountsAndTimes();
  testTapDispatch();
  testSnapshotStartWriterValidation();
  testShadowRegistryValidation();
  testShadowRegistryGaugeValueRefusal();
  testShadowRegistryDropPolicyAndReset();
  testCounterNonFiniteValueRefused();
  testDefaultLabelsMergedIntoSeries();
  testGaugeCardinalityCap();
  testHistogramCardinalityCap();
  testCredentialRedaction();
  testExpositionOpenMetricsCounterSuffixAndUnit();
  testHistogramExemplarsRendered();
  testHistogramExemplarLabelsRedacted();
  testHistogramExemplarValueTimestampNotInjectable();
  testHistogramExemplarLabelKeyNotInjectable();
  testRequestMiddlewareExemplarFromSpan();
  testRequestMiddlewareExemplarFromTraceFallback();
  testRequestMiddlewareMethodFallback();
  testTapAllFrameworkBranches();
  testTapDefaultsFromPartialLabelsAndFalsyValue();
  testSnapshotWriterReaderRegistry();
  testSnapshotWriterFlushErrorHandling();
  testSnapshotReadErrors();
  testSnapshotRenderTextGrouped();
  testSnapshotRenderPrometheusEpochAndFamilies();
  testSnapshotRenderErrors();
  testSnapshotFamilyDefensiveDrops();
  testShadowRenderPrometheus();
  testShadowRenderText();
  testShadowMoreValidation();
  testShadowCardinalityPolicies();
  testNullLabelValueCoercedToEmpty();
  testSnapshotStartWriterMoreValidation();
  testSnapshotRenderTextWithFamiliesAndValueShapes();
  testSnapshotRenderPrometheusFieldTypeOverrideAndSkips();
  testShadowTextLabeledCounterAndFlatGauge();
  testMetricResetClearsSeries();
  testShadowIgnoresUndeclaredAndEmptyLabels();
  testMetricFactoryDefaultsAndHeaderlessScrape();
}

if (require.main === module) run();
module.exports = { run: run };
