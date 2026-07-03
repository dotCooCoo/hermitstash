// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.otelExport — OTLP/HTTP-JSON exporter for b.observability events.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  // ---- Surface ----
  check("b.otelExport namespace present",  typeof b.otelExport === "object");
  check("b.otelExport.create is fn",       typeof b.otelExport.create === "function");
  check("b.otelExport.OtelExportError fn", typeof b.otelExport.OtelExportError === "function");
  check("test-only _attrsToOtlpForTest fn", typeof b.otelExport._attrsToOtlpForTest === "function");
  check("test-only _bucketKeyForTest fn",   typeof b.otelExport._bucketKeyForTest === "function");

  // ---- _attrsToOtlp encoding ----
  var enc = b.otelExport._attrsToOtlpForTest({
    s: "hello",
    i: 42,
    f: 1.5,
    b: true,
    n: null,
  });
  // Order is iteration order — keys are: s, i, f, b, n (n filtered)
  check("attrs: 4 entries (null filtered)", enc.length === 4);
  function _find(key) {
    for (var i = 0; i < enc.length; i++) if (enc[i].key === key) return enc[i];
    return null;
  }
  check("attrs: string encoded as stringValue",  _find("s").value.stringValue === "hello");
  check("attrs: integer encoded as intValue",    _find("i").value.intValue === "42");
  check("attrs: float encoded as doubleValue",   _find("f").value.doubleValue === 1.5);
  check("attrs: boolean encoded as boolValue",   _find("b").value.boolValue === true);

  check("attrs: missing input → empty array",   b.otelExport._attrsToOtlpForTest(null).length === 0);
  check("attrs: non-object input → empty array", b.otelExport._attrsToOtlpForTest(42).length === 0);

  // ---- _bucketKey: stable across attr key ordering ----
  var k1 = b.otelExport._bucketKeyForTest("http.requests", { method: "GET", status: 200 });
  var k2 = b.otelExport._bucketKeyForTest("http.requests", { status: 200, method: "GET" });
  check("bucketKey: stable across attr ordering", k1 === k2);
  var k3 = b.otelExport._bucketKeyForTest("http.requests", { method: "POST", status: 200 });
  check("bucketKey: distinct on attr value diff", k1 !== k3);
  var kNoAttrs = b.otelExport._bucketKeyForTest("x");
  check("bucketKey: no attrs returns name|",   kNoAttrs === "x|");

  // ---- recordCounter accumulation ----
  var hc = b.testing.fakeHttpClient(function () {
    return { statusCode: 200, headers: {}, body: Buffer.from("") };
  });
  var ex = b.otelExport.create({
    endpoint:    "https://otel.example/v1/metrics",
    serviceName: "wiki",
    intervalMs:  0,           // disable auto-flush in tests
    httpClient:  hc,
  });
  ex.recordCounter("http.requests", 1, { method: "GET" });
  ex.recordCounter("http.requests", 2, { method: "GET" });
  ex.recordCounter("http.requests", 1, { method: "POST" });
  check("recordCounter: 2 buckets (per-attr)",  ex.bufferedCounters === 2);

  // ---- recordObservation min/max/sum/count ----
  ex.recordObservation("http.duration_ms", 100, { route: "/a" });
  ex.recordObservation("http.duration_ms", 250, { route: "/a" });
  ex.recordObservation("http.duration_ms",  50, { route: "/a" });
  check("recordObservation: 1 bucket",          ex.bufferedObservations === 1);

  // ---- tapHandler routes to recordCounter ----
  ex.tapHandler("page.view", 1, { path: "/x" });
  check("tapHandler: counter bucket added",     ex.bufferedCounters === 3);

  // ---- flush sends OTLP-shaped JSON ----
  var res = await ex.flush();
  check("flush: sent=true",                     res.sent === true);
  check("flush: status 200",                    res.statusCode === 200);
  check("flush: drains counters",               ex.bufferedCounters === 0);
  check("flush: drains observations",           ex.bufferedObservations === 0);
  check("flush: 1 http call",                   hc.calls.length === 1);

  var sent = hc.calls[0];
  check("flush: POST",                          sent.method === "POST");
  check("flush: correct endpoint",              sent.url === "https://otel.example/v1/metrics");
  check("flush: JSON content-type",             sent.headers["Content-Type"] === "application/json");
  var body = JSON.parse(sent.body);
  check("flush body: resourceMetrics present",  Array.isArray(body.resourceMetrics) && body.resourceMetrics.length === 1);
  var rm = body.resourceMetrics[0];
  check("flush body: service.name in resource", rm.resource.attributes.some(function (a) {
    return a.key === "service.name" && a.value.stringValue === "wiki";
  }));
  check("flush body: scopeMetrics present",     Array.isArray(rm.scopeMetrics) && rm.scopeMetrics.length === 1);
  var sm = rm.scopeMetrics[0];
  check("flush body: scope name=blamejs",       sm.scope.name === "blamejs");
  // 3 counter buckets + 1 observation bucket = 4 metric entries
  check("flush body: 4 metrics",                sm.metrics.length === 4);

  // Find the http.requests sum metric for method=GET — value should be 3.
  var getReq = sm.metrics.filter(function (m) { return m.name === "http.requests" && m.sum; })
    .find(function (m) {
      return m.sum.dataPoints[0].attributes.some(function (a) {
        return a.key === "method" && a.value.stringValue === "GET";
      });
    });
  check("flush body: GET counter sum is 3",     getReq && getReq.sum.dataPoints[0].asDouble === 3);
  check("flush body: monotonic counter",        getReq.sum.isMonotonic === true);
  check("flush body: DELTA temporality",        getReq.sum.aggregationTemporality === 1);

  // Find the duration summary metric — count=3, sum=400, min=50, max=250.
  var durSummary = sm.metrics.find(function (m) { return m.name === "http.duration_ms" && m.summary; });
  check("flush body: summary count=3",          durSummary.summary.dataPoints[0].count === "3");
  check("flush body: summary sum=400",          durSummary.summary.dataPoints[0].sum === 400);
  var qv = durSummary.summary.dataPoints[0].quantileValues;
  check("flush body: summary min q=0",          qv[0].quantile === 0 && qv[0].value === 50);
  check("flush body: summary max q=1",          qv[1].quantile === 1 && qv[1].value === 250);

  // ---- flush with no buffered data → no http call ----
  var emptyRes = await ex.flush();
  check("flush: no-data path",                  emptyRes.sent === false && emptyRes.reason === "no-data");
  check("flush: no extra http call",            hc.calls.length === 1);

  // ---- close cancels timer + drains via final flush ----
  ex.recordCounter("late.event", 1);
  await ex.close();
  check("close: final flush sent",              hc.calls.length === 2);
  // Subsequent record* calls after close are dropped.
  ex.recordCounter("after.close", 5);
  check("close: no record after close",         ex.bufferedCounters === 0);

  // ---- Custom resource attributes + scope ----
  var hc2 = b.testing.fakeHttpClient(function () {
    return { statusCode: 200, headers: {}, body: Buffer.from("") };
  });
  var ex2 = b.otelExport.create({
    endpoint:           "https://otel.example/v1/metrics",
    serviceName:        "api",
    intervalMs:         0,
    httpClient:         hc2,
    resourceAttributes: { "deployment.environment": "production", "host.name": "ip-10-0-0-1" },
    scope:              { name: "wiki-app", version: "1.2.3" },
    headers:            { "X-Honeycomb-Team": "secret" },
  });
  ex2.recordCounter("x", 1);
  await ex2.flush();
  var sent2 = hc2.calls[0];
  check("custom: honeycomb header forwarded",   sent2.headers["X-Honeycomb-Team"] === "secret");
  var body2 = JSON.parse(sent2.body);
  var resAttrs = body2.resourceMetrics[0].resource.attributes;
  check("custom: deployment.environment present", resAttrs.some(function (a) {
    return a.key === "deployment.environment" && a.value.stringValue === "production";
  }));
  check("custom: host.name present",            resAttrs.some(function (a) {
    return a.key === "host.name" && a.value.stringValue === "ip-10-0-0-1";
  }));
  check("custom: scope name overridden",        body2.resourceMetrics[0].scopeMetrics[0].scope.name === "wiki-app");
  check("custom: scope version overridden",     body2.resourceMetrics[0].scopeMetrics[0].scope.version === "1.2.3");
  await ex2.close();

  // ---- Upstream error wraps as OtelExportError ----
  var hcBad = b.testing.fakeHttpClient(function () {
    return { statusCode: 500, headers: {}, body: Buffer.from("upstream-down") };
  });
  var exBad = b.otelExport.create({
    endpoint:    "https://otel.example/v1/metrics",
    serviceName: "x",
    intervalMs:  0,
    httpClient:  hcBad,
  });
  exBad.recordCounter("x", 1);
  var threw = null;
  try { await exBad.flush(); } catch (e) { threw = e; }
  check("upstream 500: throws OtelExportError",  threw && threw.isOtelExportError === true);
  check("upstream 500: code names rejection",    threw && /upstream-rejected/.test(threw.code || ""));
  await exBad.close().catch(function () { /* drop */ });

  // ---- Transport failure wraps as send-failed ----
  var hcThrow = {
    calls: [],
    request: function () { return Promise.reject(new Error("ECONNREFUSED")); },
  };
  var exConn = b.otelExport.create({
    endpoint:    "https://otel.example/v1/metrics",
    serviceName: "x",
    intervalMs:  0,
    httpClient:  hcThrow,
  });
  exConn.recordCounter("x", 1);
  var threw2 = null;
  try { await exConn.flush(); } catch (e) { threw2 = e; }
  check("transport fail: OtelExportError",       threw2 && threw2.isOtelExportError === true);
  check("transport fail: send-failed code",      threw2 && /send-failed/.test(threw2.code || ""));
  await exConn.close().catch(function () { /* drop */ });

  // ---- create() reject paths ----
  function rejects(label, fn, codeRe) {
    var t = null;
    try { fn(); } catch (e) { t = e; }
    check("create rejects: " + label,   t && codeRe.test(t.code || ""));
  }
  rejects("missing endpoint",
    function () { b.otelExport.create({ serviceName: "x" }); },
    /otel-export\/bad-endpoint/);
  rejects("empty endpoint",
    function () { b.otelExport.create({ endpoint: "", serviceName: "x" }); },
    /otel-export\/bad-endpoint/);
  rejects("missing serviceName",
    function () { b.otelExport.create({ endpoint: "https://x" }); },
    /otel-export\/bad-service-name/);
  rejects("non-string serviceName",
    function () { b.otelExport.create({ endpoint: "https://x", serviceName: 42 }); },
    /otel-export\/bad-service-name/);
  rejects("negative intervalMs",
    function () { b.otelExport.create({ endpoint: "https://x", serviceName: "x", intervalMs: -1 }); },
    /otel-export\/bad-interval/);
  rejects("non-finite intervalMs",
    function () { b.otelExport.create({ endpoint: "https://x", serviceName: "x", intervalMs: NaN }); },
    /otel-export\/bad-interval/);

  // Unknown opts key — validate-opts throws plain Error with no code.
  var threwUnknown = null;
  try {
    b.otelExport.create({
      endpoint:    "https://x",
      serviceName: "x",
      bogusKey:    1,
    });
  } catch (e) { threwUnknown = e; }
  check("create rejects: unknown opt key",
    threwUnknown && /unknown option 'bogusKey'/.test(threwUnknown.message || ""));

  // ---- recordCounter / recordObservation are tolerant of bad input (drop-silent) ----
  var hc3 = b.testing.fakeHttpClient(function () {
    return { statusCode: 200, headers: {}, body: Buffer.from("") };
  });
  var ex3 = b.otelExport.create({
    endpoint:    "https://x",
    serviceName: "x",
    intervalMs:  0,
    httpClient:  hc3,
  });
  ex3.recordCounter("", 1);                     // empty name → drop
  ex3.recordCounter(42, 1);                     // bad name type → drop
  ex3.recordObservation("x", "not-a-number");   // non-finite → drop
  ex3.recordObservation("x", NaN);              // NaN → drop
  check("record: bad name dropped",             ex3.bufferedCounters === 0);
  check("record: bad value dropped",            ex3.bufferedObservations === 0);
  await ex3.close();

  // ---- Telemetry-attribute redaction (CWE-532) ----
  // Span/metric attribute VALUES are a first-class egress sink — a secret
  // in an attribute must not reach the OTLP collector verbatim. Redaction
  // is ON by default (composes b.redact via b.observability.getRedactor);
  // benign attributes pass through unchanged.
  await _testRedaction();

  // setRedactor surface validation
  check("setRedactor rejects non-function/non-null", (function () {
    var t = null;
    try { b.observability.setRedactor(42); } catch (e) { t = e; }
    return t instanceof TypeError && /must be a function or null/.test(t.message);
  })());
  check("getRedactor returns a function", typeof b.observability.getRedactor() === "function");
}

function _findAttr(list, key) {
  for (var i = 0; i < list.length; i++) if (list[i].key === key) return list[i];
  return null;
}

async function _testRedaction() {
  // Always restore the default redactor so this block can't pollute the
  // shared b.observability singleton used by sibling tests.
  try {
    // Default-on: secret-shaped attrs scrubbed, benign attrs untouched —
    // asserted on the real OTLP payload captured by the test exporter.
    var captured = null;
    var hc = b.testing.fakeHttpClient(function (req) {
      captured = JSON.parse(req.body);
      return { statusCode: 200, headers: {}, body: Buffer.from("") };
    });
    var ex = b.otelExport.create({
      endpoint:    "https://otel.example/v1/metrics",
      serviceName: "wiki",
      intervalMs:  0,
      httpClient:  hc,
    });
    ex.recordCounter("http.requests", 1, {
      "http.route":   "/checkout",                          // benign — passes through
      "authorization": "Bearer eyJabc.eyJdef.sigsigsig",    // sensitive field name
      "card":          "4111 1111 1111 1111",               // credit-card value-shape
      "status":        200,                                  // benign number
    });
    await ex.flush();

    var dp = captured.resourceMetrics[0].scopeMetrics[0].metrics
      .find(function (m) { return m.name === "http.requests" && m.sum; })
      .sum.dataPoints[0];
    var attrs = dp.attributes;
    check("redact: benign route attr passes through",
      _findAttr(attrs, "http.route").value.stringValue === "/checkout");
    check("redact: benign number attr passes through",
      _findAttr(attrs, "status").value.intValue === "200");
    check("redact: sensitive field-name attr redacted",
      _findAttr(attrs, "authorization").value.stringValue === b.redact.MARKER);
    check("redact: credit-card value-shape attr redacted",
      _findAttr(attrs, "card").value.stringValue === "[REDACTED-CC]");
    await ex.close();

    // Resource attributes also flow through the redactor — a secret in a
    // resource attribute (operator misconfiguration) is scrubbed too.
    var capturedRes = null;
    var hcRes = b.testing.fakeHttpClient(function (req) {
      capturedRes = JSON.parse(req.body);
      return { statusCode: 200, headers: {}, body: Buffer.from("") };
    });
    var exRes = b.otelExport.create({
      endpoint:           "https://otel.example/v1/metrics",
      serviceName:        "wiki",
      intervalMs:         0,
      httpClient:         hcRes,
      resourceAttributes: { "deployment.environment": "production", "api_key": "AKIAABCDEFGHIJKLMNOP" },
    });
    exRes.recordCounter("x", 1);
    await exRes.flush();
    var resAttrs = capturedRes.resourceMetrics[0].resource.attributes;
    check("redact: benign resource attr passes through",
      _findAttr(resAttrs, "deployment.environment").value.stringValue === "production");
    check("redact: sensitive resource attr redacted",
      _findAttr(resAttrs, "api_key").value.stringValue === b.redact.MARKER);
    await exRes.close();

    // Operator override via setRedactor — a stricter scrubber is honored
    // without re-creating the exporter.
    b.observability.setRedactor(function (value, key) {
      if (key === "enduser.id") return "[CUSTOM]";
      return b.redact.redact(value, { parentKey: key });
    });
    var enc = b.otelExport._attrsToOtlpForTest({ "enduser.id": "u-42", "http.route": "/p" });
    check("redact: custom redactor applied",
      _findAttr(enc, "enduser.id").value.stringValue === "[CUSTOM]");
    check("redact: custom redactor leaves benign attr",
      _findAttr(enc, "http.route").value.stringValue === "/p");

    // A throwing redactor must DROP the attribute (fail toward dropping,
    // not leaking) and must NOT crash the export.
    b.observability.setRedactor(function () { throw new Error("redactor-boom"); });
    var threw = null;
    var encThrow;
    try { encThrow = b.otelExport._attrsToOtlpForTest({ secret_token: "shhh", keep: "x" }); }
    catch (e) { threw = e; }
    check("redact: throwing redactor does not crash export", threw === null);
    check("redact: throwing redactor drops all attrs (no leak)", encThrow.length === 0);

    // A throwing redactor through the full flush path still ships an
    // empty-attribute datapoint rather than the raw secret.
    var capturedThrow = null;
    var hcThrow = b.testing.fakeHttpClient(function (req) {
      capturedThrow = JSON.parse(req.body);
      return { statusCode: 200, headers: {}, body: Buffer.from("") };
    });
    var exThrow = b.otelExport.create({
      endpoint:    "https://otel.example/v1/metrics",
      serviceName: "wiki",
      intervalMs:  0,
      httpClient:  hcThrow,
    });
    exThrow.recordCounter("http.requests", 1, { secret_token: "shhh" });
    await exThrow.flush();
    var dpThrow = capturedThrow.resourceMetrics[0].scopeMetrics[0].metrics
      .find(function (m) { return m.name === "http.requests" && m.sum; })
      .sum.dataPoints[0];
    check("redact: flush with throwing redactor drops the secret attr",
      (dpThrow.attributes || []).length === 0);
    var bodyStr = JSON.stringify(capturedThrow);
    check("redact: secret never appears in exported payload",
      bodyStr.indexOf("shhh") === -1);
    await exThrow.close();
  } finally {
    b.observability.setRedactor(null);   // restore default for sibling tests
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
