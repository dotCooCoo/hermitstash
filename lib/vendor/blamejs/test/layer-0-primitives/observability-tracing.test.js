// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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

var otlpEx = require("../../lib/observability-otlp-exporter");

// Minimal pre-OTLP span object (the shape b.observability.tracer's
// span.toJSON() produces). Overrides let each edge-case test perturb
// exactly one field without re-declaring the whole record.
function _mkSpan(overrides) {
  var s = {
    traceId:           "0123456789abcdef0123456789abcdef",
    spanId:            "0123456789abcdef",
    parentSpanId:      "",
    name:              "op",
    kind:              "internal",
    startTimeUnixNano: "100",
    endTimeUnixNano:   "200",
    attributes:        {},
    events:            [],
    status:            { code: "ok", message: "" },
    droppedAttributesCount: 0,
    droppedEventsCount:     0,
  };
  if (overrides) { for (var k in overrides) { s[k] = overrides[k]; } }
  return s;
}

// Walk the top-level fields of a protobuf message, returning
// [ [fieldNumber, wireType], ... ] in emission order. Skips each
// field's payload by its wire type so the walk stays aligned. Used to
// assert the Span message emits dropped_links_count at field 14 and
// Status (a length-delimited message) at field 15 — never a bare varint
// on the Status field number.
function _scanTopLevelProtoFields(buf) {
  var fields = [];
  var i = 0;
  function readVarint() {
    var shift = 0, result = 0;
    while (i < buf.length) {
      var byte = buf[i++];
      result += (byte & 0x7f) * Math.pow(2, shift);
      if ((byte & 0x80) === 0) break;
      shift += 7;
    }
    return result;
  }
  while (i < buf.length) {
    var tag = readVarint();
    var field = Math.floor(tag / 8);
    var wire = tag & 7;
    fields.push([field, wire]);
    if (wire === 0) { readVarint(); }
    else if (wire === 1) { i += 8; }
    else if (wire === 2) { var len = readVarint(); i += len; }
    else if (wire === 5) { i += 4; }
    else break;
  }
  return fields;
}

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

async function testOtlpExporterProtobufNegativeAnyValue() {
  // Regression for the v0.12.6 Codex P1 finding: a negative integer
  // AnyValue (e.g. retry-after offset, signed metric delta) under the
  // protobuf encoding path was emitted with wire-type 2 (length-
  // delimited) instead of int64's wire-type 0 varint, AND truncated via
  // `v >>> 0`. Collectors reject the whole batch on such a payload.
  //
  // OTLP AnyValue (opentelemetry-proto trace.proto, common.proto):
  //   message AnyValue { oneof value { ... int64 int_value = 3; ... } }
  // int64 field 3 with the varint tag = (3 << 3) | 0 = 0x18.
  // -1 reinterprets as 64-bit two's-complement, encoded as 10 bytes
  // (all 0xff with continuation bits, final byte 0x01).
  var posts = [];
  var fetchImpl = function (url, opts) {
    posts.push({ url: url, body: opts.body });
    return Promise.resolve({ ok: true, status: 200 });
  };
  var exporter = b.observability.otlpExporter.create({
    endpoint:         "http://localhost:4318/v1/traces",
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    fetchImpl:        fetchImpl,
    batchSize:        1,
    flushIntervalMs:  0,
    encoding:         "protobuf",
  });
  var tracer = b.observability.tracer.create({
    service: "test",
    onEnd:   exporter.queue,
  });
  var s = tracer.start("neg-attr");
  s.setAttribute("retry.delta", -1);
  s.end();
  await helpers.waitUntil(function () { return posts.length >= 1; }, {
    label: "otlp.exporter: protobuf batch flushed with negative AnyValue",
  });
  var body = posts[0] && posts[0].body;
  check("otlp.exporter: protobuf body is a Buffer", Buffer.isBuffer(body));
  // The marker bytes for int64 field 3 = -1 with the wrapping AnyValue
  // embedded-message tag (field 2 in KeyValue, wire-type 2): "12 0b 18
  // ff ff ff ff ff ff ff ff ff 01" — KeyValue.value is field 2 length-
  // delimited (0x12), inner AnyValue is 11 bytes (0x0b), int_value tag
  // 0x18 (field 3 wire 0), then 10 varint bytes for -1.
  var marker = Buffer.from("120b18ffffffffffffffffff01", "hex");
  check("otlp.exporter: negative int64 AnyValue encoded as varint (wire-type 0)",
        body.indexOf(marker) !== -1);
  // The OLD broken path produced "1a 05 18 ff ff ff 0f" (field 5
  // arrayValue mis-tag + truncated 4-byte uint), so the OLD shape
  // must NOT be present.
  var oldBrokenMarker = Buffer.from("18ffffff0f", "hex");
  check("otlp.exporter: pre-fix truncated-uint shape absent",
        body.indexOf(oldBrokenMarker) === -1);
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

function testSpanHttpServerRejectsReDoSIgnorePath() {
  // ignorePaths RegExps are matched per-request against the attacker-
  // controlled request path, so a catastrophic-backtracking (ReDoS) shape
  // is screened at config time and refused. The wrapped nested quantifier
  // `((a)+)+$` is the canonical ReDoS class; the matched input stays
  // harmless so the test never actually backtracks.
  var tracer = b.observability.tracer.create({ service: "test" });
  var threw = false;
  var code = null;
  try {
    b.middleware.spanHttpServer({
      tracer:      tracer,
      ignorePaths: [/((a)+)+$/],
    });
  } catch (e) { threw = true; code = e.code; }
  check("spanHttpServer: ReDoS ignorePaths RegExp refused", threw);
  check("spanHttpServer: ReDoS refusal code", code === "span-http/unsafe-pattern");
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

function testTraceLogCorrelationRejectsAuditOpt() {
  // The `audit` opt was an accepted-but-unread no-op (the middleware
  // only wraps a logger — no audit-worthy event). De-advertised: it is
  // no longer in the allowlist, so passing it throws at config time.
  var threw = false;
  try {
    b.middleware.traceLogCorrelation({ logger: { info: function () {} }, audit: true });
  } catch (_e) { threw = true; }
  check("traceLogCorrelation: unknown 'audit' opt rejected", threw);
  // Default surface still constructs without the key.
  var mw = b.middleware.traceLogCorrelation({ logger: { info: function () {} } });
  check("traceLogCorrelation: constructs without audit opt", typeof mw === "function");
}

function testTracerRejectsAuditOpt() {
  // `audit` was accepted by tracer.create but never read (the tracer is
  // a pure observability primitive — span lifecycle goes to observability
  // counters, not the audit log). De-advertised.
  var threw = false;
  try { b.observability.tracer.create({ service: "test", audit: true }); }
  catch (_e) { threw = true; }
  check("tracer.create: unknown 'audit' opt rejected", threw);
  var tracer = b.observability.tracer.create({ service: "test" });
  check("tracer.create: constructs without audit opt", typeof tracer.start === "function");
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

// ---- OTLP builder: attribute type coercion (JSON path) ----

function testOtlpAttrValueCoercion() {
  b.observability.setRedactor(null);   // default redactor — non-sensitive keys pass through
  var out = otlpEx._attrToOtlp({
    s:   "x",
    i:   42,
    d:   1.5,
    bt:  true,
    bf:  false,
    arr: [1, "two", true],
    obj: { a: 1 },
  });
  var by = {};
  for (var j = 0; j < out.length; j++) { by[out[j].key] = out[j].value; }
  check("otlp.attr: string → stringValue",  by.s && by.s.stringValue === "x");
  check("otlp.attr: integer → intValue string", by.i && by.i.intValue === "42");
  check("otlp.attr: float → doubleValue",   by.d && by.d.doubleValue === 1.5);
  check("otlp.attr: true → boolValue",      by.bt && by.bt.boolValue === true);
  check("otlp.attr: false → boolValue",     by.bf && by.bf.boolValue === false);
  check("otlp.attr: array → arrayValue.values length",
        by.arr && by.arr.arrayValue && by.arr.arrayValue.values.length === 3);
  check("otlp.attr: array element types preserved",
        by.arr.arrayValue.values[0].intValue === "1" &&
        by.arr.arrayValue.values[1].stringValue === "two" &&
        by.arr.arrayValue.values[2].boolValue === true);
  check("otlp.attr: plain object → String() coercion",
        by.obj && by.obj.stringValue === "[object Object]");
}

function testOtlpAttrNonObjectInputs() {
  // _attrToOtlp tolerates a non-object attribute bag (a malformed span
  // that carries a scalar / null where a map is expected) → empty array,
  // never a throw.
  check("otlp.attr: null attrs → []",      otlpEx._attrToOtlp(null).length === 0);
  check("otlp.attr: undefined attrs → []", otlpEx._attrToOtlp(undefined).length === 0);
  check("otlp.attr: string attrs → []",    otlpEx._attrToOtlp("nope").length === 0);
  check("otlp.attr: number attrs → []",    otlpEx._attrToOtlp(42).length === 0);
}

// ---- OTLP builder: span defaulting / fallbacks (JSON path) ----

function testOtlpSpanToOtlpDefaults() {
  // Unknown kind → SPAN_KIND_INTERNAL (1); missing endTime → startTime;
  // missing status → { code: 0, message: "" }; undefined events → [].
  var s = otlpEx._spanToOtlp({
    traceId:           "aa",
    spanId:            "bb",
    name:              "op",
    kind:              "bogus-kind",
    startTimeUnixNano: "500",
    // endTimeUnixNano, status, events, parentSpanId, attributes omitted
  });
  check("otlp.span: unknown kind falls back to internal(1)", s.kind === 1);
  check("otlp.span: missing endTime falls back to startTime",
        s.endTimeUnixNano === "500");
  check("otlp.span: missing status → code 0",   s.status.code === 0);
  check("otlp.span: missing status → empty msg", s.status.message === "");
  check("otlp.span: missing parentSpanId → ''",  s.parentSpanId === "");
  check("otlp.span: undefined events → []",      Array.isArray(s.events) && s.events.length === 0);
  check("otlp.span: undefined attributes → []",  Array.isArray(s.attributes) && s.attributes.length === 0);

  // Named kind maps through, status code maps through, events map through.
  var s2 = otlpEx._spanToOtlp(_mkSpan({
    kind:   "server",
    status: { code: "error", message: "boom" },
    events: [{ name: "ev", timeUnixNano: "5", attributes: { k: "v" } }],
    droppedEventsCount: 3,
  }));
  check("otlp.span: server kind → 2", s2.kind === 2);
  check("otlp.span: error status → 2", s2.status.code === 2);
  check("otlp.span: status message preserved", s2.status.message === "boom");
  check("otlp.span: event mapped with name + attrs",
        s2.events.length === 1 && s2.events[0].name === "ev" &&
        s2.events[0].attributes[0].key === "k");
  check("otlp.span: droppedEventsCount preserved", s2.droppedEventsCount === 3);
}

// ---- OTLP builder: resource bundling / batching edges ----

function testOtlpBundleEmptyAndGrouping() {
  check("otlp.bundle: empty batch → empty resourceSpans",
        otlpEx._bundleSpans([]).resourceSpans.length === 0);

  // Two spans, distinct resource attrs → two resourceSpans entries.
  var multi = otlpEx._bundleSpans([
    _mkSpan({ resource: { "service.name": "alpha" } }),
    _mkSpan({ resource: { "service.name": "beta" } }),
  ]);
  check("otlp.bundle: distinct resources split into 2 envelopes",
        multi.resourceSpans.length === 2);
  check("otlp.bundle: resource attributes emitted as KeyValue array",
        Array.isArray(multi.resourceSpans[0].resource.attributes) &&
        multi.resourceSpans[0].resource.attributes[0].key === "service.name");

  // Two spans, SAME resource → one envelope holding both spans.
  var grouped = otlpEx._bundleSpans([
    _mkSpan({ resource: { "service.name": "same" }, name: "a" }),
    _mkSpan({ resource: { "service.name": "same" }, name: "b" }),
  ]);
  check("otlp.bundle: shared resource groups into 1 envelope",
        grouped.resourceSpans.length === 1);
  check("otlp.bundle: grouped envelope holds both spans",
        grouped.resourceSpans[0].scopeSpans[0].spans.length === 2);

  // Missing scope → default blamejs scope name, empty version string.
  var noScope = otlpEx._bundleSpans([_mkSpan({})]);
  var scope = noScope.resourceSpans[0].scopeSpans[0].scope;
  check("otlp.bundle: default scope name", scope.name === "blamejs");
  check("otlp.bundle: default scope version → ''", scope.version === "");
}

// ---- OTLP builder: protobuf wire-format edges ----

function testOtlpProtobufSpanFieldLayout() {
  // Span-message top-level field layout regression guard. Status is proto
  // field 15 (a length-delimited message); dropped_attributes_count is 10,
  // dropped_events_count is 12, dropped_links_count is 14. The encoder must
  // never place a bare varint on the Status field number 15 — that would
  // corrupt the Status message for a strict OTLP protobuf collector. (The
  // hardcoded dropped_links_count is 0 and proto3 omits it from the wire, so
  // both field 14 and a stray field-15 varint are absent today; this asserts
  // the invariant so a future non-zero placeholder can't regress onto 15.)
  var buf = otlpEx._spanToProto(_mkSpan({
    droppedAttributesCount: 3,   // → field 10 emits (non-zero)
    droppedEventsCount:     2,   // → field 12 emits (non-zero)
  }));
  check("otlp.proto: span encodes to a non-empty Buffer",
        Buffer.isBuffer(buf) && buf.length > 0);
  var fields = _scanTopLevelProtoFields(buf);
  function has(field, wire) {
    return fields.some(function (f) { return f[0] === field && f[1] === wire; });
  }
  check("otlp.proto: dropped_attributes_count at field 10 (varint)", has(10, 0));
  check("otlp.proto: dropped_events_count at field 12 (varint)",     has(12, 0));
  check("otlp.proto: no bare varint on Status field 15", !has(15, 0));
  check("otlp.proto: Status at field 15 as length-delimited message", has(15, 2));
}

function testOtlpProtobufMalformedHexIds() {
  // Malformed inbound trace/span ids (odd length, non-hex chars, empty)
  // must not crash the encoder — _hexToBytes drops to empty bytes.
  var buf = otlpEx._spanToProto(_mkSpan({
    traceId:      "abc",              // odd length → empty
    spanId:       "zzzzzzzzzzzzzzzz", // non-hex → empty
    parentSpanId: "",                 // empty → empty
  }));
  check("otlp.proto: malformed ids encode without throwing",
        Buffer.isBuffer(buf) && buf.length > 0);
}

function testOtlpProtobufAnyValueDepthCap() {
  // A deeply nested array attribute must not blow the stack / recurse
  // past MAX_ANYVALUE_DEPTH — the encoder caps descent and emits empty.
  var deep = 0;
  for (var d = 0; d < 130; d++) { deep = [deep]; }
  var buf = otlpEx._spanToProto(_mkSpan({ attributes: { nested: deep } }));
  check("otlp.proto: deep-nested array attribute encodes without crashing",
        Buffer.isBuffer(buf) && buf.length > 0);
}

// ---- OTLP exporter: create() option validation ----

function testOtlpCreateEncodingValidation() {
  function code(fn) { try { fn(); } catch (e) { return e.code; } return null; }
  check("otlp.create: bogus encoding rejected",
        code(function () {
          otlpEx.create({ endpoint: "https://c.invalid/v1/traces", encoding: "xml", fetchImpl: function () {} });
        }) === "otlp/bad-encoding");
  // http/protobuf is a documented alias for protobuf — constructs fine.
  var ex = otlpEx.create({
    endpoint: "https://c.invalid/v1/traces",
    encoding: "http/protobuf",
    fetchImpl: function () {},
    flushIntervalMs: 0,
  });
  check("otlp.create: http/protobuf alias constructs", typeof ex.flush === "function");
}

function testOtlpCreateFetchImplValidation() {
  var threw = false, codeVal = null;
  try {
    otlpEx.create({ endpoint: "https://c.invalid/v1/traces", fetchImpl: 42 });
  } catch (e) { threw = true; codeVal = e.code; }
  check("otlp.create: non-function fetchImpl rejected", threw && codeVal === "otlp/no-fetch");
}

function testOtlpCreateNumericOptValidation() {
  function code(fn) { try { fn(); } catch (e) { return e.code; } return null; }
  var base = { endpoint: "https://c.invalid/v1/traces", fetchImpl: function () {}, flushIntervalMs: 0 };
  check("otlp.create: negative batchSize rejected",
        code(function () { otlpEx.create(Object.assign({}, base, { batchSize: -5 })); }) === "otlp/bad-opts");
  check("otlp.create: non-numeric batchSize rejected",
        code(function () { otlpEx.create(Object.assign({}, base, { batchSize: "big" })); }) === "otlp/bad-opts");
  check("otlp.create: zero maxAttempts rejected",
        code(function () { otlpEx.create(Object.assign({}, base, { maxAttempts: 0 })); }) === "otlp/bad-opts");
  check("otlp.create: infinite maxQueueSize rejected",
        code(function () { otlpEx.create(Object.assign({}, base, { maxQueueSize: Infinity })); }) === "otlp/bad-opts");
}

// ---- OTLP exporter: queue / flush / retry behaviour (injected transport) ----

function _mkExporter(fetchImpl, extra) {
  return otlpEx.create(Object.assign({
    endpoint:         "http://localhost:4318/v1/traces",
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    fetchImpl:        fetchImpl,
    batchSize:        100,   // large → queue() never auto-flushes; we flush explicitly
    flushIntervalMs:  0,     // no ticker
  }, extra || {}));
}

async function testOtlpFlushEmptyQueue() {
  var ex = _mkExporter(function () { throw new Error("must not post on empty queue"); });
  var r = await ex.flush();
  check("otlp.flush: empty queue → sent 0", r.sent === 0);
  await ex.shutdown();
}

async function testOtlpPostPermanent4xx() {
  var attempts = 0;
  var ex = _mkExporter(function () {
    attempts += 1;
    return Promise.resolve({ ok: false, status: 400 });   // permanent, non-retryable
  }, { backoffInitialMs: 1 });
  ex.queue(_mkSpan({}));
  var r = await ex.flush();
  check("otlp.post: 400 not retried (single attempt)", attempts === 1);
  check("otlp.post: 400 batch dropped", r.dropped === 1 && r.sent === 0);
  check("otlp.stats: droppedExportFailed incremented", ex.stats().droppedExportFailed === 1);
  await ex.shutdown();
}

async function testOtlpPostRetryable429() {
  var attempts = 0;
  var ex = _mkExporter(function () {
    attempts += 1;
    if (attempts === 1) return Promise.resolve({ ok: false, status: 429 });   // retryable
    return Promise.resolve({ ok: true, status: 200 });
  }, { backoffInitialMs: 1 });
  ex.queue(_mkSpan({}));
  var r = await ex.flush();
  check("otlp.post: 429 retried then succeeded", attempts === 2 && r.sent === 1);
  await ex.shutdown();
}

async function testOtlpPostNetworkErrorExhausts() {
  var attempts = 0;
  var ex = _mkExporter(function () {
    attempts += 1;
    return Promise.reject(new Error("ECONNREFUSED"));
  }, { backoffInitialMs: 1, maxAttempts: 2 });
  ex.queue(_mkSpan({}));
  var r = await ex.flush();
  check("otlp.post: network error retried to maxAttempts", attempts === 2);
  check("otlp.post: exhausted network error drops batch", r.dropped === 1 && r.sent === 0);
  check("otlp.stats: network drop counted", ex.stats().droppedExportFailed === 1);
  await ex.shutdown();
}

function testOtlpQueueOverflowDropsOldest() {
  var ex = _mkExporter(function () { return Promise.resolve({ ok: true, status: 200 }); },
    { maxQueueSize: 2 });
  ex.queue(_mkSpan({ name: "one" }));
  ex.queue(_mkSpan({ name: "two" }));
  ex.queue(_mkSpan({ name: "three" }));   // overflow → drop oldest
  var st = ex.stats();
  check("otlp.queue: overflow capped at maxQueueSize", st.queueLength === 2);
  check("otlp.queue: overflow drop counted", st.droppedQueueOverflow === 1);
}

function testOtlpQueueGarbageAndStopping() {
  var ex = _mkExporter(function () { return Promise.resolve({ ok: true, status: 200 }); });
  ex.queue(null);
  ex.queue(42);
  ex.queue("not-a-span");
  check("otlp.queue: non-object spans ignored", ex.stats().queueLength === 0);
}

async function testOtlpQueueAfterShutdown() {
  var ex = _mkExporter(function () { return Promise.resolve({ ok: true, status: 200 }); });
  await ex.shutdown();                    // sets stopping
  ex.queue(_mkSpan({}));                  // must be dropped, not queued
  var st = ex.stats();
  check("otlp.queue: post-shutdown span not queued", st.queueLength === 0);
  check("otlp.queue: post-shutdown span counted as export-failed drop",
        st.droppedExportFailed >= 1);
}

async function testOtlpFlushProtobufBodyIsBuffer() {
  var bodies = [];
  var ex = _mkExporter(function (url, init) {
    bodies.push(init.body);
    return Promise.resolve({ ok: true, status: 200 });
  }, { encoding: "protobuf" });
  ex.queue(_mkSpan({ attributes: { retry: -7 } }));   // negative int64 through proto path
  var r = await ex.flush();
  check("otlp.flush: protobuf batch sent", r.sent === 1);
  check("otlp.flush: protobuf body is a Buffer", Buffer.isBuffer(bodies[0]) && bodies[0].length > 0);
  await ex.shutdown();
}

// ---- Run all ----

async function run() {
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
  await testOtlpExporterProtobufNegativeAnyValue();
  testOtlpExporterValidation();
  testTracePropagateExtractsTracestate();
  testTracePropagateGeneratesWhenMissing();
  testSpanHttpServer();
  testSpanHttpServerIgnorePaths();
  testSpanHttpServerRejectsReDoSIgnorePath();
  testTraceLogCorrelation();
  testTraceLogCorrelationWithSpan();
  testTraceLogCorrelationNoTrace();
  testSpanToTraceparentValidation();
  testTracerInvalidAttributeKey();
  testTracerArrayAttribute();
  testTracerStatusCodeValidation();
  await testOtlpExporterRetryOn5xx();
  testTracerToJSONIsImmutable();
  testTraceLogCorrelationRejectsAuditOpt();
  testTracerRejectsAuditOpt();
  // OTLP wire-format builder edges
  testOtlpAttrValueCoercion();
  testOtlpAttrNonObjectInputs();
  testOtlpSpanToOtlpDefaults();
  testOtlpBundleEmptyAndGrouping();
  testOtlpProtobufSpanFieldLayout();
  testOtlpProtobufMalformedHexIds();
  testOtlpProtobufAnyValueDepthCap();
  testOtlpCreateEncodingValidation();
  testOtlpCreateFetchImplValidation();
  testOtlpCreateNumericOptValidation();
  await testOtlpFlushEmptyQueue();
  await testOtlpPostPermanent4xx();
  await testOtlpPostRetryable429();
  await testOtlpPostNetworkErrorExhausts();
  testOtlpQueueOverflowDropsOldest();
  testOtlpQueueGarbageAndStopping();
  await testOtlpQueueAfterShutdown();
  await testOtlpFlushProtobufBodyIsBuffer();
}

module.exports = { run: run };

if (require.main === module) {
  run().catch(function (e) { console.error(e); process.exit(1); });
}
