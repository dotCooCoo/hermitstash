"use strict";
/**
 * b.testing — operator-facing test helpers.
 *
 * Verifies b.testing composes existing primitives (b.safeAsync.sleep,
 * .withTimeout; b.observability.tap contract; b.audit.safeEmit drop-
 * silent; b.requestHelpers.extractActorContext compatibility) instead
 * of re-implementing timer races / polling loops / actor extraction.
 *
 * Run standalone: `node test/layer-0-primitives/testing.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var nodeHttp = require("node:http");
var helpers = require("../helpers");
var b      = helpers.b;
var fs     = helpers.fs;
var check  = helpers.check;
var t      = b.testing;

// ---- Surface ----

function testSurface() {
  check("b.testing namespace present",        typeof b.testing === "object");
  check("b.testing.mockReq fn",               typeof t.mockReq === "function");
  check("b.testing.mockRes fn",               typeof t.mockRes === "function");
  check("b.testing.bodyReq fn",               typeof t.bodyReq === "function");
  check("b.testing.bodyRes fn",               typeof t.bodyRes === "function");
  check("b.testing.streamingRes fn",          typeof t.streamingRes === "function");
  check("b.testing.fakeClock fn",             typeof t.fakeClock === "function");
  check("b.testing.fakeHttpClient fn",        typeof t.fakeHttpClient === "function");
  check("b.testing.captureAudit fn",          typeof t.captureAudit === "function");
  check("b.testing.captureObservability fn",  typeof t.captureObservability === "function");
  check("b.testing.captureMetricsTap fn",     typeof t.captureMetricsTap === "function");
  check("b.testing.runMiddleware fn",         typeof t.runMiddleware === "function");
  check("b.testing.waitFor fn",               typeof t.waitFor === "function");
  check("b.testing.tempDir fn",               typeof t.tempDir === "function");
  check("b.testing.makeFakeOtelApi fn",       typeof t.makeFakeOtelApi === "function");
  check("b.testing.listenOnRandomPort fn",    typeof t.listenOnRandomPort === "function");
  check("b.testing.TestingError class",       typeof t.TestingError === "function");
  check("b.testing.DEFAULTS frozen",          Object.isFrozen(t.DEFAULTS));
  check("DEFAULTS.waitForTimeoutMs positive", t.DEFAULTS.waitForTimeoutMs > 0);
  check("DEFAULTS.runMiddlewareTimeoutMs positive",
        t.DEFAULTS.runMiddlewareTimeoutMs > 0);
}

// ---- mockReq / mockRes ----

function testMockReq() {
  var req = t.mockReq();
  check("mockReq default method GET",         req.method === "GET");
  check("mockReq default url /",              req.url === "/");
  check("mockReq default pathname /",         req.pathname === "/");
  check("mockReq default socket remoteAddress",
        req.socket.remoteAddress === "127.0.0.1");
  check("mockReq default headers empty",      Object.keys(req.headers).length === 0);

  var req2 = t.mockReq({
    method: "POST", url: "/users/42",
    headers: { "x-foo": "bar" },
  });
  check("mockReq override method",            req2.method === "POST");
  check("mockReq pathname split from url",    req2.pathname === "/users/42");
  check("mockReq override headers",           req2.headers["x-foo"] === "bar");

  // Headers cloned — mutating returned doesn't affect opts
  var origHeaders = { "x-foo": "bar" };
  var req3 = t.mockReq({ headers: origHeaders });
  req3.headers["x-foo"] = "mutated";
  check("mockReq headers cloned (no opt mutation)",
        origHeaders["x-foo"] === "bar");
}

function testMockReqExtractActorContextCompatibility() {
  // Verify mockReq populates fields that b.requestHelpers.extractActorContext
  // consumes — the helper IS used by the framework's audit chain
  // emission across api-key / cache / permissions / seeders / notify /
  // webhook / etc.
  var req = t.mockReq({
    ip:        "10.0.0.5",
    userAgent: "tester/1.0",
    requestId: "req-42",
    method:    "POST",
    url:       "/admin/cache/clear",
  });
  var actor = b.requestHelpers.extractActorContext(req);
  check("extractActorContext picks up ip from socket.remoteAddress",
        actor.ip === "10.0.0.5");
  check("extractActorContext picks up userAgent",
        actor.userAgent === "tester/1.0");
  check("extractActorContext picks up requestId from header",
        actor.requestId === "req-42");
  check("extractActorContext picks up method",
        actor.method === "POST");
  check("extractActorContext picks up route from url",
        actor.route === "/admin/cache/clear");
}

function testMockRes() {
  var res = t.mockRes();
  res.setHeader("X-Foo", "bar");
  res.writeHead(200, { "X-Bar": "baz" });
  res.end("hello");
  var captured = res._captured();
  check("mockRes captures status",            captured.status === 200);
  check("mockRes captures setHeader",         captured.headers["x-foo"] === "bar");
  check("mockRes captures writeHead headers", captured.headers["x-bar"] === "baz");
  check("mockRes captures body",              captured.body === "hello");
  check("mockRes ended flag",                 captured.ended === true);
  check("mockRes writableEnded set",          res.writableEnded === true);
}

function testBodyReqRes() {
  return new Promise(function (resolve) {
    var req = t.bodyReq("POST", { "content-type": "text/plain" }, "hello body");
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      check("bodyReq method preserved",        req.method === "POST");
      check("bodyReq headers preserved",       req.headers["content-type"] === "text/plain");
      check("bodyReq replays body via data",   Buffer.concat(chunks).toString() === "hello body");

      // bodyRes
      var res = t.bodyRes();
      var finished = false;
      res.on("finish", function () { finished = true; });
      res.writeHead(201, { "X-Foo": "bar" });
      res.end("response body");
      check("bodyRes captures status",          res.statusCode === 201);
      check("bodyRes captures body",            res._captured === "response body");
      check("bodyRes emits finish on end()",    finished === true);

      resolve();
    });
  });
}

function testStreamingRes() {
  var res = t.streamingRes();
  res.setHeader("X-Foo", "bar");
  check("streamingRes setHeader+getHeader round-trip",
        res.getHeader("x-foo") === "bar");
  check("streamingRes case-insensitive lookup",
        res.getHeader("X-Foo") === "bar");
  res.removeHeader("X-Foo");
  check("streamingRes removeHeader",
        res.getHeader("x-foo") === undefined);
  res.write("chunk1");
  res.write("chunk2");
  res.end();
  check("streamingRes captures concatenated chunks",
        res._captured().toString() === "chunk1chunk2");
}

// ---- fakeClock ----

function testFakeClock() {
  var clk = t.fakeClock(1000);
  check("fakeClock initial now()",            clk.now() === 1000);
  check("fakeClock ms getter",                clk.ms === 1000);
  clk.advance(500);
  check("fakeClock advance",                  clk.now() === 1500);
  clk.set(2000);
  check("fakeClock set jumps absolute",       clk.now() === 2000);
  // Bound — operator can pass clk.now without losing this
  var now = clk.now;
  check("fakeClock now is bound",             now() === 2000);

  var clk2 = t.fakeClock();
  check("fakeClock default initial is finite", typeof clk2.now() === "number" && isFinite(clk2.now()));

  var threwBad = false;
  try { t.fakeClock(NaN); } catch (_e) { threwBad = true; }
  check("fakeClock(NaN) throws TestingError", threwBad);

  var threwBadAdvance = false;
  try { clk.advance("string"); } catch (_e) { threwBadAdvance = true; }
  check("fakeClock.advance(non-number) throws", threwBadAdvance);
}

function testFakeClockIntegrationCache() {
  // Round-trip: pass clk.now to b.cache.create as the clock opt and
  // verify TTL math sees the controllable clock.
  var clk = t.fakeClock(1_000_000);
  var cache = b.cache.create({
    namespace: "test-clk",
    ttlMs:     100,
    clock:     clk.now,
  });
  return (async function () {
    await cache.set("k", "v");
    check("cache set+get under fakeClock",      (await cache.get("k")) === "v");
    clk.advance(150);
    check("cache miss after fakeClock advance past ttl",
          (await cache.get("k")) === undefined);
    await cache.close();
  })();
}

// ---- fakeHttpClient ----

async function testFakeHttpClient() {
  var hc = t.fakeHttpClient(function (req) {
    if (req.url === "/ok")     return { statusCode: 200, body: Buffer.from("ok") };
    if (req.url === "/notfound") return { statusCode: 404, body: Buffer.from("nope") };
    return { statusCode: 500 };
  });
  var r1 = await hc.request({ method: "GET", url: "/ok" });
  check("fakeHttpClient returns canned response", r1.statusCode === 200);
  var r2 = await hc.request({ method: "GET", url: "/notfound" });
  check("fakeHttpClient routes per request",      r2.statusCode === 404);
  check("fakeHttpClient.calls captures requests", hc.calls.length === 2);
  check("fakeHttpClient.calls preserves request shape",
        hc.calls[0].url === "/ok" && hc.calls[1].url === "/notfound");

  // Async responder
  var hcAsync = t.fakeHttpClient(async function () {
    return { statusCode: 200, body: Buffer.from("async") };
  });
  var r3 = await hcAsync.request({ method: "GET", url: "/" });
  check("fakeHttpClient awaits async responder", r3.statusCode === 200);

  var threwBad = false;
  try { t.fakeHttpClient("not-a-fn"); } catch (_e) { threwBad = true; }
  check("fakeHttpClient(non-fn) throws TestingError", threwBad);
}

// ---- captureAudit ----

function testCaptureAudit() {
  var audit = t.captureAudit();
  audit.safeEmit({ action: "foo.created", outcome: "success" });
  audit.safeEmit({ action: "foo.deleted", outcome: "failure" });
  audit.safeEmit({ action: "foo.created", outcome: "success" });
  check("captureAudit captures all events",   audit.captured.length === 3);
  check("captureAudit byAction filters",      audit.byAction("foo.created").length === 2);
  check("captureAudit byAction empty for missing",
        audit.byAction("bar.x").length === 0);
  audit.clear();
  check("captureAudit clear() empties",       audit.captured.length === 0);
}

function testCaptureAuditDropSilent() {
  var audit = t.captureAudit();
  // Mirror b.audit.safeEmit drop-silent: caller-side bug shouldn't crash test
  audit.safeEmit({ action: "x" });
  check("captureAudit safeEmit doesn't throw on normal input",
        audit.captured.length === 1);
}

// ---- captureObservability ----

async function testCaptureObservability() {
  var obs = t.captureObservability();
  obs.event("foo.bar", 1, { x: "y" });
  check("captureObservability captures events",
        obs.captured.length === 1 && obs.captured[0].kind === "event");

  // tap with sync fn
  var ret = obs.tap("foo.tap", { ns: "x" }, function () { return 42; });
  check("captureObservability.tap returns sync fn return value", ret === 42);
  check("captureObservability.tap captures begin + end events",
        obs.captured.filter(function (e) { return e.kind === "tap" || e.kind === "tap.end"; }).length === 2);

  // tap with async fn
  var asyncRet = await obs.tap("foo.async", function () {
    return Promise.resolve(99);
  });
  check("captureObservability.tap returns async fn return value", asyncRet === 99);

  // tap with throwing fn
  var threw = false;
  try { obs.tap("foo.err", function () { throw new Error("boom"); }); }
  catch (_e) { threw = true; }
  check("captureObservability.tap propagates throws", threw);
  check("captureObservability captured tap.error",
        obs.captured.some(function (e) { return e.kind === "tap.error" && e.name === "foo.err"; }));

  // byName filters
  check("captureObservability.byName filters",
        obs.byName("foo.tap").length === 2);    // tap + tap.end

  // event drop-silent on bad name
  var initialCount = obs.captured.length;
  obs.event("", 1);
  obs.event(null, 1);
  check("captureObservability.event drop-silent on empty name",
        obs.captured.length === initialCount);

  obs.clear();
  check("captureObservability clear() empties",  obs.captured.length === 0);
}

// ---- captureMetricsTap ----

function testCaptureMetricsTap() {
  var cap = t.captureMetricsTap();
  try {
    b.metrics.tap("test.metric", 1, { foo: "bar" });
    check("captureMetricsTap captures via b.metrics.tap",
          cap.captured.length === 1);
    check("captureMetricsTap byName filters",
          cap.byName("test.metric").length === 1);
    check("captureMetricsTap captures labels",
          cap.captured[0].labels.foo === "bar");
  } finally {
    cap.restore();
  }
  // After restore, b.metrics.tap should not push to our array
  var beforeLen = cap.captured.length;
  b.metrics.tap("test.after-restore", 1);
  check("captureMetricsTap restore reverts the swap",
        cap.captured.length === beforeLen);
}

// ---- runMiddleware ----

async function testRunMiddlewareNext() {
  var r = await t.runMiddleware(function (req, res, next) {
    next();
  });
  check("runMiddleware: next() called",       r.nextCalled === true);
  check("runMiddleware: nextError null",      r.nextError === null);
  check("runMiddleware: ended false",         r.ended === false);
}

async function testRunMiddlewareNextErr() {
  var r = await t.runMiddleware(function (req, res, next) {
    next(new Error("forbidden"));
  });
  check("runMiddleware: next(err) captured",  r.nextError && r.nextError.message === "forbidden");
}

async function testRunMiddlewareThrow() {
  var r = await t.runMiddleware(function () { throw new Error("sync boom"); });
  check("runMiddleware: sync throw captured",
        r.nextError && r.nextError.message === "sync boom");
}

async function testRunMiddlewareAsyncReject() {
  var r = await t.runMiddleware(async function () {
    throw new Error("async boom");
  });
  check("runMiddleware: async reject captured",
        r.nextError && r.nextError.message === "async boom");
}

async function testRunMiddlewareEndsResponse() {
  var r = await t.runMiddleware(function (req, res) {
    res.end("done");
  });
  check("runMiddleware: ended detected",      r.ended === true);
  check("runMiddleware: nextCalled false",    r.nextCalled === false);
  check("runMiddleware: response.end invoked", r.res._captured().body === "done");
}

async function testRunMiddlewareTimeoutFromSafeAsync() {
  // Middleware that never settles → withTimeout from b.safeAsync rejects
  var threw = false;
  try {
    await t.runMiddleware(function () {
      // never call next, never end res
    }, undefined, undefined, { timeoutMs: 30 });
  } catch (e) {
    threw = e && e.code === "async/timeout";
  }
  check("runMiddleware: hung middleware rejected via safeAsync.withTimeout",
        threw);
}

async function testRunMiddlewareBadInput() {
  var threw = false;
  try { await t.runMiddleware("not-a-fn"); } catch (_e) { threw = true; }
  check("runMiddleware(non-fn) throws TestingError", threw);
}

// ---- waitFor ----

async function testWaitForResolves() {
  var counter = 0;
  var startedAt = Date.now();
  var v = await t.waitFor(function () {
    counter++;
    return counter >= 3 ? "done" : false;
  }, { timeoutMs: 200, intervalMs: 5 });
  check("waitFor resolves with predicate value", v === "done");
  check("waitFor invoked predicate at least 3 times",  counter >= 3);
  check("waitFor finished within timeout",      Date.now() - startedAt < 2000);
}

async function testWaitForTimeoutFromSafeAsync() {
  var threw = false;
  try {
    await t.waitFor(function () { return false; }, { timeoutMs: 30, intervalMs: 5 });
  } catch (e) {
    threw = e && /TIMEOUT/.test(e.code || "");
  }
  check("waitFor timeout maps async/timeout → TestingError TIMEOUT",
        threw);
}

async function testWaitForAsyncPredicate() {
  var counter = 0;
  var v = await t.waitFor(async function () {
    counter++;
    return counter >= 2 ? 42 : null;
  }, { timeoutMs: 200, intervalMs: 5 });
  check("waitFor awaits async predicate",     v === 42);
}

async function testWaitForBadInput() {
  var threwPred = false;
  try { await t.waitFor("not-a-fn"); } catch (_e) { threwPred = true; }
  check("waitFor(non-fn) throws", threwPred);

  var threwInterval = false;
  try {
    await t.waitFor(function () { return true; }, { intervalMs: 0 });
  } catch (_e) { threwInterval = true; }
  check("waitFor with bad intervalMs throws", threwInterval);
}

// ---- tempDir ----

function testTempDir() {
  var dir = t.tempDir();
  check("tempDir returns absolute path",      fs.existsSync(dir.path));

  // Write a file inside
  var helpersPath = require("node:path").join(dir.path, "fixture.txt");
  fs.writeFileSync(helpersPath, "data");
  check("tempDir is writable",                fs.readFileSync(helpersPath, "utf8") === "data");

  // Cleanup
  dir.cleanup();
  check("tempDir cleanup() removes",          !fs.existsSync(dir.path));

  // Idempotent
  dir.cleanup();
  check("tempDir cleanup() idempotent (no throw)", true);
}

function testTempDirRejectsTraversal() {
  var attacks = ["../escape", "/abs", "\\abs", "with/slash", "null\0byte", ".."];
  for (var i = 0; i < attacks.length; i++) {
    var threw = false;
    try { t.tempDir(attacks[i]); } catch (_e) { threw = true; }
    check("tempDir rejects path-traversal prefix " + JSON.stringify(attacks[i]),
          threw);
  }
}

// ---- listenOnRandomPort ----

async function testListenOnRandomPort() {
  var server = nodeHttp.createServer(function (req, res) {
    res.writeHead(204); res.end();
  });
  var port = await t.listenOnRandomPort(server);
  check("listenOnRandomPort returns a positive port",
        typeof port === "number" && port > 0);
  await new Promise(function (resolve) { server.close(resolve); });
}

// ---- makeFakeOtelApi ----

function testMakeFakeOtelApi() {
  var fake = t.makeFakeOtelApi();
  check("fakeOtelApi has trace + context",
        typeof fake.trace === "object" && typeof fake.context === "object");
  var tracer = fake.trace.getTracer();
  var span = tracer.startSpan("test.span", { attributes: { foo: "bar" } });
  span.setAttribute("baz", "qux");
  check("fakeOtelApi span attributes captured",
        span._attrs.foo === "bar" && span._attrs.baz === "qux");
  check("fakeOtelApi _spans captures",         fake._spans.length === 1);
  check("fakeOtelApi getActiveSpan reflects",  fake._activeSpan() === span);
  span.end();
  check("fakeOtelApi span end clears active",  fake._activeSpan() === null);
}

// ---- run ----

async function run() {
  testSurface();
  testMockReq();
  testMockReqExtractActorContextCompatibility();
  testMockRes();
  await testBodyReqRes();
  testStreamingRes();
  testFakeClock();
  await testFakeClockIntegrationCache();
  await testFakeHttpClient();
  testCaptureAudit();
  testCaptureAuditDropSilent();
  await testCaptureObservability();
  testCaptureMetricsTap();
  await testRunMiddlewareNext();
  await testRunMiddlewareNextErr();
  await testRunMiddlewareThrow();
  await testRunMiddlewareAsyncReject();
  await testRunMiddlewareEndsResponse();
  await testRunMiddlewareTimeoutFromSafeAsync();
  await testRunMiddlewareBadInput();
  await testWaitForResolves();
  await testWaitForTimeoutFromSafeAsync();
  await testWaitForAsyncPredicate();
  await testWaitForBadInput();
  testTempDir();
  testTempDirRejectsTraversal();
  await testListenOnRandomPort();
  testMakeFakeOtelApi();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
