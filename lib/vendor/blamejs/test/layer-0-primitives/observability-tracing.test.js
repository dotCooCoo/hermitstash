"use strict";
/**
 * Tests for the W3C distributed tracing suite shipped in v0.7.103:
 *
 *   - b.observability.traceContext.parseTracestate / buildTracestate
 *   - b.observability.baggage.parse / build
 *   - b.observability.tracer.create / span lifecycle
 *   - b.observability.otlpExporter — span batching + OTLP/JSON shape
 *   - b.middleware.tracePropagate (extended with tracestate + baggage)
 *   - b.middleware.spanHttpServer
 */

var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

// ---- Tracestate ----

function testTracestateParse() {
  var tc = b.observability.traceContext;
  var rows = tc.parseTracestate("rojo=00f067aa0ba902b7,congo=t61rcWkgMzE");
  check("parseTracestate: 2 entries", Array.isArray(rows) && rows.length === 2);
  check("parseTracestate: first key", rows[0].key === "rojo");
  check("parseTracestate: first value", rows[0].value === "00f067aa0ba902b7");
  check("parseTracestate: second key", rows[1].key === "congo");

  // Vendor@tenant form
  var tenant = tc.parseTracestate("acme@tracing=op-id-123");
  check("parseTracestate: tenant@vendor accepted",
        tenant && tenant.length === 1 && tenant[0].key === "acme@tracing");

  // Empty + bogus
  check("parseTracestate: empty → null", tc.parseTracestate("") === null);
  check("parseTracestate: missing-eq → null", tc.parseTracestate("notavalidpair") === null);
  check("parseTracestate: comma-comma → empty entry skipped",
        tc.parseTracestate("a=1,,b=2").length === 2);
  check("parseTracestate: bad key (uppercase) → null",
        tc.parseTracestate("BAD=1") === null);
  check("parseTracestate: bad value (with comma in middle) → null",
        tc.parseTracestate("ok=val,bad=v=v") === null);

  // Cap: > 32 entries
  var manyEntries = [];
  for (var i = 0; i < 40; i++) manyEntries.push("k" + i + "=v");
  check("parseTracestate: > 32 entries → null",
        tc.parseTracestate(manyEntries.join(",")) === null);

  // Cap: > 512 chars
  var bigVal = "k1=" + "x".repeat(600);
  check("parseTracestate: > 512 chars → null",
        tc.parseTracestate(bigVal) === null);

  // Duplicate keys: keep first
  var dup = tc.parseTracestate("a=1,a=2,b=3");
  check("parseTracestate: dup key keeps first", dup && dup.length === 2 && dup[0].value === "1");
}

function testTracestateBuild() {
  var tc = b.observability.traceContext;
  var s = tc.buildTracestate([
    { key: "rojo", value: "00f067aa0ba902b7" },
    { key: "congo", value: "t61rcWkgMzE" },
  ]);
  check("buildTracestate: comma-joined", s === "rojo=00f067aa0ba902b7,congo=t61rcWkgMzE");

  // Round-trip
  var parsed = tc.parseTracestate(s);
  check("buildTracestate→parse round-trip", parsed && parsed.length === 2);

  // Bad input throws
  var threwBadKey = false;
  try { tc.buildTracestate([{ key: "BAD", value: "x" }]); }
  catch (_e) { threwBadKey = true; }
  check("buildTracestate: bad key throws", threwBadKey);

  var threwTooMany = false;
  try {
    var entries = [];
    for (var i = 0; i < 35; i++) entries.push({ key: "k" + i, value: "v" });
    tc.buildTracestate(entries);
  } catch (_e) { threwTooMany = true; }
  check("buildTracestate: > 32 entries throws", threwTooMany);
}

// ---- Baggage ----

function testBaggageParse() {
  var bg = b.observability.baggage;
  var rows = bg.parse("userId=alice,tenant=acme;public=1");
  check("baggage.parse: 2 entries", Array.isArray(rows) && rows.length === 2);
  check("baggage.parse: first key", rows[0].key === "userId");
  check("baggage.parse: first value", rows[0].value === "alice");
  check("baggage.parse: second key", rows[1].key === "tenant");
  check("baggage.parse: properties parsed",
        rows[1].properties.length === 1 && rows[1].properties[0].key === "public" &&
        rows[1].properties[0].value === "1");

  // Percent-encoded value
  var enc = bg.parse("name=Alice%20Smith");
  check("baggage.parse: percent-decoded value",
        enc && enc[0].value === "Alice Smith");

  // Bare-property (no value)
  var bare = bg.parse("k=v;readonly");
  check("baggage.parse: bare property",
        bare && bare[0].properties[0].key === "readonly" &&
        bare[0].properties[0].value === null);

  // Bogus input
  check("baggage.parse: empty → null", bg.parse("") === null);
  check("baggage.parse: missing-eq → null", bg.parse("notapair") === null);

  // Cap: > 64 entries
  var manyEntries = [];
  for (var i = 0; i < 80; i++) manyEntries.push("k" + i + "=v");
  check("baggage.parse: > 64 entries → null",
        bg.parse(manyEntries.join(",")) === null);
}

function testBaggageBuild() {
  var bg = b.observability.baggage;
  var s = bg.build([
    { key: "userId", value: "alice", properties: [] },
    { key: "tenant", value: "acme",  properties: [{ key: "public", value: "1" }] },
  ]);
  check("baggage.build: comma+semicolon shape",
        s === "userId=alice,tenant=acme;public=1");

  // Percent-encode special chars
  var enc = bg.build([{ key: "name", value: "Alice Smith", properties: [] }]);
  check("baggage.build: percent-encoded space",
        enc === "name=Alice%20Smith");

  // Round-trip
  var parsed = bg.parse(enc);
  check("baggage.build→parse round-trip",
        parsed && parsed[0].value === "Alice Smith");

  // Bad input throws
  var threwBadKey = false;
  try { bg.build([{ key: "bad key with space", value: "x" }]); }
  catch (_e) { threwBadKey = true; }
  check("baggage.build: bad key throws", threwBadKey);
}

// ---- Tracer + span lifecycle ----

function testTracerStartEnd() {
  var tracer = b.observability.tracer.create({ service: "test-svc" });
  var captured = null;
  var span = tracer.start("op", {
    attributes: { foo: "bar", "http.request.method": "GET" },
  });
  check("tracer: span has traceId", typeof span.traceId === "string" && span.traceId.length === 32);
  check("tracer: span has spanId", typeof span.spanId === "string" && span.spanId.length === 16);
  check("tracer: span recording", span.isRecording() === true);
  span.setAttribute("count", 42);
  span.addEvent("started");
  span.setStatus("ok");
  span.end();
  check("tracer: span no longer recording", span.isRecording() === false);
  var json = span.toJSON();
  check("tracer: toJSON has attributes", json.attributes.foo === "bar" && json.attributes.count === 42);
  check("tracer: toJSON has events", json.events.length === 1 && json.events[0].name === "started");
  check("tracer: toJSON has status", json.status.code === "ok");
  check("tracer: toJSON has duration", typeof json.durationMs === "number" && json.durationMs >= 0);
  check("tracer: toJSON has resource",
        json.resource["service.name"] === "test-svc");
  void captured;
}

function testTracerOnEnd() {
  var seen = [];
  var tracer = b.observability.tracer.create({
    service: "test",
    onEnd: function (s) { seen.push(s); },
  });
  var span = tracer.start("op");
  span.end();
  check("tracer.onEnd: fired once", seen.length === 1);
  check("tracer.onEnd: receives JSON span", seen[0] && seen[0].name === "op");
}

function testTracerChildSpan() {
  var tracer = b.observability.tracer.create({ service: "test" });
  var parent = tracer.start("parent");
  var child = tracer.startChildOf(parent, "child");
  check("tracer.startChildOf: shares traceId", child.traceId === parent.traceId);
  check("tracer.startChildOf: parentSpanId set", child.parentSpanId === parent.spanId);
  child.end();
  parent.end();
}

function testTracerRecordException() {
  var tracer = b.observability.tracer.create({ service: "test" });
  var span = tracer.start("op");
  var err = new TypeError("bad arg");
  span.recordException(err);
  span.setStatus("error", err.message);
  span.end();
  var json = span.toJSON();
  check("tracer.recordException: emits exception event",
        json.events.length === 1 && json.events[0].name === "exception");
  check("tracer.recordException: captures type",
        json.events[0].attributes["exception.type"] === "TypeError");
  check("tracer.recordException: captures message",
        json.events[0].attributes["exception.message"] === "bad arg");
  check("tracer: error status",
        json.status.code === "error" && json.status.message === "bad arg");
}

function testTracerAttributeCaps() {
  var tracer = b.observability.tracer.create({
    service: "test",
    maxAttributes: 4,
    maxEvents: 2,
  });
  var span = tracer.start("op");
  for (var i = 0; i < 10; i++) span.setAttribute("key" + i, i);
  for (var j = 0; j < 5; j++) span.addEvent("e" + j);
  span.end();
  var json = span.toJSON();
  check("tracer: attribute cap enforced",
        Object.keys(json.attributes).length === 4);
  check("tracer: dropped attributes counted",
        json.droppedAttributesCount === 6);
  check("tracer: event cap enforced", json.events.length === 2);
  check("tracer: dropped events counted", json.droppedEventsCount === 3);
}

function testTracerSpanToTraceparent() {
  var tracer = b.observability.tracer.create({ service: "test" });
  var span = tracer.start("op", { sampled: true });
  var hdr = b.observability.tracer.spanToTraceparent(span);
  check("spanToTraceparent: starts 00-",
        hdr.indexOf("00-") === 0);
  check("spanToTraceparent: contains traceId",
        hdr.indexOf(span.traceId) !== -1);
  check("spanToTraceparent: contains spanId",
        hdr.indexOf(span.spanId) !== -1);
  check("spanToTraceparent: ends 01 (sampled)",
        hdr.endsWith("-01"));
  span.end();
}

// ---- OTLP exporter ----

function testOtlpBundleShape() {
  var ex = require("../../lib/observability-otlp-exporter");
  var tracer = b.observability.tracer.create({ service: "checkout-api" });
  var span = tracer.start("op");
  span.setAttribute("foo", "bar");
  span.end();
  var bundle = ex._bundleSpans([span.toJSON()]);
  check("otlp.bundle: resourceSpans", Array.isArray(bundle.resourceSpans));
  check("otlp.bundle: 1 resource",     bundle.resourceSpans.length === 1);
  check("otlp.bundle: scopeSpans wraps spans",
        bundle.resourceSpans[0].scopeSpans[0].spans.length === 1);
  var s = bundle.resourceSpans[0].scopeSpans[0].spans[0];
  check("otlp.bundle: span.name",  s.name === "op");
  check("otlp.bundle: span.kind",  s.kind === 1);   // SPAN_KIND_INTERNAL
  check("otlp.bundle: span.attributes is array",
        Array.isArray(s.attributes) && s.attributes[0].key === "foo");
  check("otlp.bundle: attribute value as stringValue",
        s.attributes[0].value.stringValue === "bar");
}

async function testOtlpExporterQueueAndFlush() {
  // Minimal in-memory fetch impl; collects requests + returns 200.
  var posts = [];
  var fetchImpl = function (url, opts) {
    posts.push({ url: url, body: opts.body });
    return Promise.resolve({ ok: true, status: 200 });
  };
  var exporter = b.observability.otlpExporter.create({
    endpoint:         "http://localhost:4318/v1/traces",
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    fetchImpl:        fetchImpl,
    batchSize:        2,
    flushIntervalMs:  0,    // disable automatic ticker
  });
  var tracer = b.observability.tracer.create({
    service: "test",
    onEnd:   exporter.queue,
  });
  var s1 = tracer.start("a"); s1.end();
  var s2 = tracer.start("b"); s2.end();
  // Queue at batchSize triggers an async flush; poll until the post
  // lands at the mock endpoint.
  await helpers.waitUntil(function () { return posts.length >= 1; }, {
    label: "otlp.exporter: batch-size flush reached mock endpoint",
  });
  check("otlp.exporter: posted at batchSize", posts.length === 1);
  var body = posts[0] && JSON.parse(posts[0].body);
  check("otlp.exporter: body shape", body && Array.isArray(body.resourceSpans));
  await exporter.shutdown();
}

function testOtlpExporterValidation() {
  var threwBadEndpoint = false;
  try {
    b.observability.otlpExporter.create({
      endpoint:  "not-a-url",
      fetchImpl: function () {},
    });
  } catch (_e) { threwBadEndpoint = true; }
  check("otlp.exporter: bad endpoint throws", threwBadEndpoint);
}

// ---- tracePropagate middleware ----

function testTracePropagateExtractsTracestate() {
  var mw = b.middleware.tracePropagate({
    generateIfMissing: true,
  });
  var req = {
    headers: {
      traceparent: "00-12345678901234567890123456789012-1234567890123456-01",
      tracestate:  "rojo=abc,congo=def",
    },
    url: "/foo",
  };
  var res = { setHeader: function () {}, headersSent: false };
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("tracePropagate: parsed tracestate",
        req.trace.tracestate.length === 2 &&
        req.trace.tracestate[0].key === "rojo");
  check("tracePropagate: hadUpstream true", req.trace.hadUpstream === true);
  check("tracePropagate: next called", nextCalled);
}

function testTracePropagateGeneratesWhenMissing() {
  var mw = b.middleware.tracePropagate({ generateIfMissing: true });
  var req = { headers: {}, url: "/" };
  var res = { setHeader: function () {}, headersSent: false };
  mw(req, res, function () {});
  check("tracePropagate: generated traceId", typeof req.trace.traceId === "string" && req.trace.traceId.length === 32);
  check("tracePropagate: hadUpstream false", req.trace.hadUpstream === false);
  check("tracePropagate: tracestate empty array", Array.isArray(req.trace.tracestate));
}

// ---- spanHttpServer middleware ----

function testSpanHttpServer() {
  var ended = [];
  var tracer = b.observability.tracer.create({
    service: "test",
    onEnd:   function (s) { ended.push(s); },
  });
  var mw = b.middleware.spanHttpServer({
    tracer: tracer,
  });
  var req = {
    method:  "GET",
    url:     "/foo?bar=1",
    headers: { host: "example.com", "user-agent": "test/1.0" },
    socket:  { encrypted: false },
    trace:   { traceId: "abcdef0123456789abcdef0123456789", parentId: "abcdef0123456789", sampled: true },
  };
  var listeners = {};
  var res = {
    headersSent: false,
    statusCode:  200,
    on:          function (ev, cb) { listeners[ev] = cb; },
    getHeader:   function () { return undefined; },
  };
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("spanHttpServer: req.span attached", typeof req.span === "object");
  check("spanHttpServer: span name has method+path",
        req.span.name === "GET /foo");
  check("spanHttpServer: next called", nextCalled);
  // Simulate response finish
  listeners["finish"]();
  check("spanHttpServer: span ended on finish",
        ended.length === 1 && ended[0].status.code === "ok");
  check("spanHttpServer: status code attribute set",
        ended[0].attributes["http.response.status_code"] === 200);
  check("spanHttpServer: method attribute set",
        ended[0].attributes["http.request.method"] === "GET");
}

function testSpanHttpServerIgnorePaths() {
  var ended = [];
  var tracer = b.observability.tracer.create({
    service: "test",
    onEnd:   function (s) { ended.push(s); },
  });
  var mw = b.middleware.spanHttpServer({
    tracer:      tracer,
    ignorePaths: ["/healthz", /^\/static/],
  });
  var req1 = { method: "GET", url: "/healthz", headers: {}, socket: {} };
  var req2 = { method: "GET", url: "/static/a.css", headers: {}, socket: {} };
  var req3 = { method: "GET", url: "/api/x", headers: {}, socket: {} };
  var res = {
    headersSent: false, statusCode: 200,
    on:          function () {},
    getHeader:   function () {},
  };
  var n1 = false, n2 = false, n3 = false;
  mw(req1, res, function () { n1 = true; });
  mw(req2, res, function () { n2 = true; });
  mw(req3, res, function () { n3 = true; });
  check("spanHttpServer: skips healthz", req1.span === undefined && n1);
  check("spanHttpServer: skips /static", req2.span === undefined && n2);
  check("spanHttpServer: instruments /api/x", typeof req3.span === "object" && n3);
}

// ---- traceLogCorrelation middleware ----

function testTraceLogCorrelation() {
  var captured = [];
  var fakeLogger = {
    info:  function (msg, meta) { captured.push({ level: "info",  msg: msg, meta: meta }); },
    warn:  function (msg, meta) { captured.push({ level: "warn",  msg: msg, meta: meta }); },
    error: function (msg, meta) { captured.push({ level: "error", msg: msg, meta: meta }); },
  };
  var mw = b.middleware.traceLogCorrelation({ logger: fakeLogger });
  var req = {
    trace: { traceId: "abcdef0123456789abcdef0123456789", parentId: "abcdef0123456789", sampled: true },
  };
  var nextCalled = false;
  mw(req, {}, function () { nextCalled = true; });
  check("traceLogCorrelation: next called", nextCalled);
  check("traceLogCorrelation: req.log attached", typeof req.log === "object");
  req.log.info("hello", { foo: "bar" });
  check("traceLogCorrelation: forwarded to logger",
        captured.length === 1 && captured[0].level === "info");
  check("traceLogCorrelation: trace_id injected",
        captured[0].meta.trace_id === "abcdef0123456789abcdef0123456789");
  check("traceLogCorrelation: span_id injected",
        captured[0].meta.span_id === "abcdef0123456789");
  check("traceLogCorrelation: original meta preserved",
        captured[0].meta.foo === "bar");
}

function testTraceLogCorrelationWithSpan() {
  var captured = [];
  var fakeLogger = {
    info: function (msg, meta) { captured.push({ msg: msg, meta: meta }); },
  };
  var mw = b.middleware.traceLogCorrelation({ logger: fakeLogger });
  var req = {
    trace: { traceId: "11112222333344445555666677778888", parentId: "1111111111111111", sampled: true },
    span:  { spanId:  "abcdef0123456789", traceId: "11112222333344445555666677778888" },
  };
  mw(req, {}, function () {});
  req.log.info("with span");
  check("traceLogCorrelation: prefers req.span.spanId over parentId",
        captured[0].meta.span_id === "abcdef0123456789");
}

function testTraceLogCorrelationNoTrace() {
  var captured = [];
  var fakeLogger = {
    info: function (msg, meta) { captured.push({ msg: msg, meta: meta }); },
  };
  var mw = b.middleware.traceLogCorrelation({ logger: fakeLogger });
  var req = {};   // no trace context
  mw(req, {}, function () {});
  req.log.info("no-trace");
  check("traceLogCorrelation: no-trace req still logs",
        captured.length === 1);
  check("traceLogCorrelation: no trace_id when missing",
        captured[0].meta.trace_id === undefined);
}

// ---- spanToTraceparent edge cases ----

function testSpanToTraceparentValidation() {
  var threwBadSpan = false;
  try { b.observability.tracer.spanToTraceparent({}); }
  catch (_e) { threwBadSpan = true; }
  check("spanToTraceparent: bad span throws", threwBadSpan);

  var threwNullSpan = false;
  try { b.observability.tracer.spanToTraceparent(null); }
  catch (_e) { threwNullSpan = true; }
  check("spanToTraceparent: null span throws", threwNullSpan);
}

// ---- Tracer attribute validation ----

function testTracerInvalidAttributeKey() {
  var tracer = b.observability.tracer.create({ service: "test" });
  var span = tracer.start("op");
  span.setAttribute("", "value");           // empty key — should drop
  span.setAttribute(null, "value");         // null key — should drop
  span.setAttribute("good_key", "ok");
  span.end();
  var json = span.toJSON();
  check("tracer.setAttribute: empty/null keys dropped",
        Object.keys(json.attributes).length === 1 &&
        json.attributes.good_key === "ok");
  check("tracer.setAttribute: dropped count incremented",
        json.droppedAttributesCount >= 2);
}

function testTracerArrayAttribute() {
  var tracer = b.observability.tracer.create({ service: "test" });
  var span = tracer.start("op");
  span.setAttribute("tags", ["a", "b", "c"]);
  span.setAttribute("scores", [1.5, 2.5, 3.5]);
  span.setAttribute("flags",  [true, false]);
  span.setAttribute("mixed",  ["a", 1, true]);
  span.end();
  var json = span.toJSON();
  check("tracer.setAttribute: string array preserved",
        Array.isArray(json.attributes.tags) && json.attributes.tags.length === 3);
  check("tracer.setAttribute: number array preserved",
        Array.isArray(json.attributes.scores) && json.attributes.scores.length === 3);
  check("tracer.setAttribute: boolean array preserved",
        Array.isArray(json.attributes.flags) && json.attributes.flags.length === 2);
}

function testTracerStatusCodeValidation() {
  var tracer = b.observability.tracer.create({ service: "test" });
  var span = tracer.start("op");
  var threw = false;
  try { span.setStatus("invalid"); }
  catch (_e) { threw = true; }
  check("tracer.setStatus: rejects invalid code", threw);
  span.end();
}

async function testOtlpExporterRetryOn5xx() {
  var attempts = 0;
  var fetchImpl = function () {
    attempts += 1;
    if (attempts === 1) return Promise.resolve({ ok: false, status: 503 });
    return Promise.resolve({ ok: true, status: 200 });
  };
  var exporter = b.observability.otlpExporter.create({
    endpoint:         "http://localhost:4318/v1/traces",
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    fetchImpl:        fetchImpl,
    batchSize:        1,
    flushIntervalMs:  0,
    backoffInitialMs: 1,    // fast backoff for tests
  });
  var tracer = b.observability.tracer.create({
    service: "test",
    onEnd:   exporter.queue,
  });
  var s = tracer.start("retry"); s.end();
  // Poll until the exporter's retry attempt lands.
  await helpers.waitUntil(function () { return attempts >= 2; }, {
    label: "otlp.exporter: retried on 5xx",
  });
  check("otlp.exporter: retried on 5xx", attempts === 2);
  await exporter.shutdown();
}

function testTracerToJSONIsImmutable() {
  var tracer = b.observability.tracer.create({ service: "test" });
  var span = tracer.start("op");
  span.setAttribute("foo", "bar");
  span.end();
  var json1 = span.toJSON();
  json1.attributes.foo = "MUTATED";
  var json2 = span.toJSON();
  check("tracer.toJSON: snapshot independent of caller mutation",
        json2.attributes.foo === "bar");
}

// ---- Run all ----

(async function run() {
  testTracestateParse();
  testTracestateBuild();
  testBaggageParse();
  testBaggageBuild();
  testTracerStartEnd();
  testTracerOnEnd();
  testTracerChildSpan();
  testTracerRecordException();
  testTracerAttributeCaps();
  testTracerSpanToTraceparent();
  testOtlpBundleShape();
  await testOtlpExporterQueueAndFlush();
  testOtlpExporterValidation();
  testTracePropagateExtractsTracestate();
  testTracePropagateGeneratesWhenMissing();
  testSpanHttpServer();
  testSpanHttpServerIgnorePaths();
  testTraceLogCorrelation();
  testTraceLogCorrelationWithSpan();
  testTraceLogCorrelationNoTrace();
  testSpanToTraceparentValidation();
  testTracerInvalidAttributeKey();
  testTracerArrayAttribute();
  testTracerStatusCodeValidation();
  await testOtlpExporterRetryOn5xx();
  testTracerToJSONIsImmutable();
})().catch(function (e) { console.error(e); process.exit(1); });
