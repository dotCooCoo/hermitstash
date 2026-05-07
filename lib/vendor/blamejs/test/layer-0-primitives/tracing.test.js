"use strict";
/**
 * tracing — OpenTelemetry seam.
 *
 * Run standalone: `node test/layer-0-primitives/tracing.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b                = helpers.b;
var check            = helpers.check;
var _bodyRes         = helpers._bodyRes;
var _makeFakeOtelApi = helpers.makeFakeOtelApi;

function testTracingSurface() {
  check("b.tracing namespace present",      typeof b.tracing === "object");
  check("b.tracing.create is a function",   typeof b.tracing.create === "function");
  check("b.tracing.tap is a function",      typeof b.tracing.tap === "function");
  check("TracingError class",               typeof b.tracing.TracingError === "function");
  check("TRACEPARENT_RE exposed",           b.tracing.TRACEPARENT_RE instanceof RegExp);
}

function testTracingTraceparentParse() {
  var t = b.tracing;
  var ok = t._parseTraceparent("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01");
  check("traceparent: parses valid",        ok && ok.traceId === "0af7651916cd43dd8448eb211c80319c");
  check("traceparent: extracts spanId",     ok.spanId === "b7ad6b7169203331");
  check("traceparent: rejects bad format",  t._parseTraceparent("malformed") === null);
  check("traceparent: rejects all-zero traceId",
        t._parseTraceparent("00-" + "0".repeat(32) + "-b7ad6b7169203331-01") === null);
  check("traceparent: rejects all-zero spanId",
        t._parseTraceparent("00-0af7651916cd43dd8448eb211c80319c-" + "0".repeat(16) + "-01") === null);
  check("traceparent: rejects future version (01)",
        t._parseTraceparent("01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01") === null);
}

function testTracingTraceparentFormat() {
  var t = b.tracing;
  var s = t._formatTraceparent("a".repeat(32), "b".repeat(16), "01");
  check("traceparent: format with explicit flags",
        s === "00-" + "a".repeat(32) + "-" + "b".repeat(16) + "-01");
  var d = t._formatTraceparent("a".repeat(32), "b".repeat(16));
  check("traceparent: default flags = 01",  d.endsWith("-01"));
}

function testTracingNewIds() {
  var t = b.tracing;
  var traceId = t._newTraceId();
  var spanId = t._newSpanId();
  check("newTraceId: 32 hex chars",         /^[0-9a-f]{32}$/.test(traceId));
  check("newSpanId: 16 hex chars",          /^[0-9a-f]{16}$/.test(spanId));
  var seen = new Set();
  for (var i = 0; i < 50; i++) seen.add(t._newTraceId());
  check("newTraceId: 50 calls produce 50 distinct ids", seen.size === 50);
}

async function testTracingPassthroughSpan() {
  b.tracing._resetForTest();
  b.tracing._setOtelForTest(null);
  var t = b.tracing.create();
  var ranWith = null;
  var result = await t.span("test-op", function (span) {
    ranWith = span;
    span.setAttribute("k", "v");
    span.addEvent("hello");
    return 42;
  });
  check("passthrough: span body executes",         result === 42);
  check("passthrough: span passed to fn",          ranWith && ranWith._isPassthrough === true);
  t.deactivate();
}

async function testTracingPassthroughSpanAsync() {
  b.tracing._resetForTest();
  b.tracing._setOtelForTest(null);
  var t = b.tracing.create();
  var result = await t.span("async-op", async function () {
    await new Promise(function (r) { setImmediate(r); });
    return "done";
  });
  check("passthrough: async span returns value",   result === "done");
  t.deactivate();
}

async function testTracingPassthroughSpanThrows() {
  b.tracing._resetForTest();
  b.tracing._setOtelForTest(null);
  var t = b.tracing.create();
  var threw = null;
  try {
    await t.span("err-op", async function () { throw new Error("boom"); });
  } catch (e) { threw = e; }
  check("passthrough: throw propagates",            threw && threw.message === "boom");
  t.deactivate();
}

async function testTracingRealSpan() {
  b.tracing._resetForTest();
  var fake = _makeFakeOtelApi();
  b.tracing._setOtelForTest(fake);
  var t = b.tracing.create();
  check("isReal: detects OTel installed",          t.isReal() === true);
  var result = await t.span("real-op", function (span) {
    span.setAttribute("user_id", "u1");
    span.addEvent("checkpoint-1");
    return 7;
  }, { attributes: { route: "/x" } });
  check("real span: returns fn value",             result === 7);
  check("real span: tracer received span name",    fake._spans[0]._name === "real-op");
  check("real span: attributes set during fn",     fake._spans[0]._attrs.user_id === "u1");
  check("real span: events captured",              fake._spans[0]._events.indexOf("checkpoint-1") !== -1);
  check("real span: ended after fn",               fake._spans[0]._ended === true);
  t.deactivate();
}

async function testTracingRealSpanThrowRecordsException() {
  b.tracing._resetForTest();
  var fake = _makeFakeOtelApi();
  b.tracing._setOtelForTest(fake);
  var t = b.tracing.create();
  var threw = null;
  try {
    await t.span("err-op", async function () { throw new Error("kaboom"); });
  } catch (e) { threw = e; }
  check("real span: throw propagates",                  threw && threw.message === "kaboom");
  check("real span: exception recorded",                fake._spans[0]._exceptions.length === 1);
  check("real span: status code 2 (ERROR)",             fake._spans[0]._status.code === 2);
  check("real span: still ended after throw",           fake._spans[0]._ended === true);
  t.deactivate();
}

async function testTracingCurrentSpanInsideFn() {
  b.tracing._resetForTest();
  b.tracing._setOtelForTest(null);
  var t = b.tracing.create();
  var seen = null;
  await t.span("outer", function () {
    seen = t.currentSpan();
  });
  check("currentSpan: returns active passthrough span inside fn",
        seen && seen._isPassthrough === true);
  check("currentSpan: null after span ended",  t.currentSpan() === null);
  t.deactivate();
}

async function testTracingContextHeaders() {
  b.tracing._resetForTest();
  b.tracing._setOtelForTest(null);
  var t = b.tracing.create();
  check("contextHeaders: empty when no active span", Object.keys(t.contextHeaders()).length === 0);
  var headers = null;
  await t.span("op", function () { headers = t.contextHeaders(); });
  check("contextHeaders: traceparent set inside span",
        typeof headers.traceparent === "string" &&
        b.tracing.TRACEPARENT_RE.test(headers.traceparent));
  t.deactivate();
}

function testTracingExtractContext() {
  b.tracing._resetForTest();
  b.tracing._setOtelForTest(null);
  var t = b.tracing.create();
  var headers = { traceparent: "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01" };
  var ctx = t.extractContext(headers);
  check("extractContext: parses incoming traceparent",
        ctx && ctx.traceId === "0af7651916cd43dd8448eb211c80319c");
  check("extractContext: returns null on missing header",
        t.extractContext({}) === null);
  check("extractContext: returns null on malformed",
        t.extractContext({ traceparent: "garbage" }) === null);
  t.deactivate();
}

async function testTracingRequestMiddleware() {
  b.tracing._resetForTest();
  var fake = _makeFakeOtelApi();
  b.tracing._setOtelForTest(fake);
  var t = b.tracing.create();
  var mw = t.requestMiddleware();

  var EE = require("node:events").EventEmitter;
  var req = new EE();
  req.method = "GET";
  req.url = "/users/123";
  req.routePattern = "/users/:id";
  req.headers = {
    traceparent: "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
  };
  var res = _bodyRes();
  await new Promise(function (resolve) {
    res.on("finish", resolve);
    mw(req, res, function () {
      res.writeHead(200);
      res.end();
    });
  });
  check("requestMiddleware: span name = HTTP method route",
        fake._spans[0]._name === "HTTP GET /users/:id");
  check("requestMiddleware: http.method attribute set",
        fake._spans[0]._attrs["http.method"] === "GET");
  check("requestMiddleware: http.route attribute set",
        fake._spans[0]._attrs["http.route"] === "/users/:id");
  check("requestMiddleware: parent traceparent attribute set",
        fake._spans[0]._attrs["traceparent.parent"] === "0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331");
  check("requestMiddleware: http.status_code captured",
        fake._spans[0]._attrs["http.status_code"] === 200);
  check("requestMiddleware: span ended",            fake._spans[0]._ended === true);
  check("requestMiddleware: req.span exposed",      req.span !== undefined);
  t.deactivate();
}

async function testTracingTapRoutes() {
  b.tracing._resetForTest();
  var fake = _makeFakeOtelApi();
  b.tracing._setOtelForTest(fake);
  var t = b.tracing.create();
  var ran = false;
  await b.tracing.tap("framework.audit.record", { action: "auth.login" }, function () {
    ran = true;
  });
  check("tap: fn ran",                             ran === true);
  check("tap: span created with given name",       fake._spans[0]._name === "framework.audit.record");
  check("tap: attributes propagated",              fake._spans[0]._attrs.action === "auth.login");
  t.deactivate();
}

async function testTracingTapNoOpWhenNoRegistry() {
  b.tracing._resetForTest();
  var ran = false;
  var result = await b.tracing.tap("nothing", function () { ran = true; return 99; });
  check("tap: fn still runs without registry",     ran === true);
  check("tap: return value preserved",             result === 99);
}

async function testTracingPassthroughTap() {
  b.tracing._resetForTest();
  b.tracing._setOtelForTest(null);
  var t = b.tracing.create();
  var captured = null;
  await b.tracing.tap("passthru-tap", function (s) { captured = s; });
  check("passthrough tap: span passed to fn",      captured && captured._isPassthrough === true);
  t.deactivate();
}

function testTracingIsReal() {
  b.tracing._resetForTest();
  b.tracing._setOtelForTest(null);
  var t = b.tracing.create();
  check("isReal: false when no OTel",              t.isReal() === false);
  t.deactivate();
}

async function run() {
  testTracingSurface();
  testTracingTraceparentParse();
  testTracingTraceparentFormat();
  testTracingNewIds();
  await testTracingPassthroughSpan();
  await testTracingPassthroughSpanAsync();
  await testTracingPassthroughSpanThrows();
  await testTracingRealSpan();
  await testTracingRealSpanThrowRecordsException();
  await testTracingCurrentSpanInsideFn();
  await testTracingContextHeaders();
  testTracingExtractContext();
  await testTracingRequestMiddleware();
  await testTracingTapRoutes();
  await testTracingTapNoOpWhenNoRegistry();
  await testTracingPassthroughTap();
  testTracingIsReal();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
