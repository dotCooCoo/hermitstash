// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.router — coverage for the registration, dispatch, introspection, and
 * static-file surfaces not exercised by the focused router test files
 * (router-use-path-scope / router-cross-origin-redirect / router-body-
 * validation / router-tls0rtt).
 *
 * Drives the public API only — b.router.create(...), the route-registration
 * verbs, r.handle(req, res) with in-memory request/response fakes, and a
 * real in-process listen(0) server for the response-helper wiring
 * (res.json / res.status / res.redirect / errorHandler / 0-RTT gate) that
 * is only attached inside listen(). No external network / DB backend.
 *
 * Validates:
 *   - compilePattern registration-time refusals (empty / non-string /
 *     over-length pattern, empty parameter name)
 *   - _registerRoute CVE-2026-4923 asterisk-flood refusal
 *   - route-spec validation (unknown key, non-schema body/query/params/
 *     response, malformed tags)
 *   - dispatch: method-mismatch → 404, default vs custom notFound, param
 *     capture + req.routePattern, trailing-slash no-match, multi-handler
 *     fall-through, middleware next() semantics, req.query population,
 *     the HashDoS query-key cap
 *   - schema validator query/params paths + response-validation throw mode
 *   - inspectRoutes / openapi / getReservedSlugs introspection
 *   - ws() registration validation + activeWebSockets / closeWebSockets
 *   - serveStatic next() bypass branches + a real served file
 *   - listen() response helpers end-to-end on a live localhost server
 */

var http    = require("node:http");
var fs       = require("node:fs");
var os       = require("node:os");
var nodePath = require("node:path");

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var s       = b.safeSchema;

function _req(method, url, headers) {
  return { method: method, url: url, headers: Object.assign({ host: "localhost" }, headers || {}) };
}

function _res() {
  var res = {
    statusCode:    0,
    headersSent:   false,
    writableEnded: false,
    _body:         "",
    _headers:      null,
    writeHead: function (status, headers) {
      res.statusCode = status;
      res._headers = headers || {};
      res.headersSent = true;
    },
    end: function (chunk) {
      if (chunk !== undefined) res._body += chunk;
      res.writableEnded = true;
    },
  };
  return res;
}

function _throwMsg(fn) {
  try { fn(); return null; }
  catch (e) { return (e && e.message) || "threw"; }
}

// ---- compilePattern registration-time refusals ----

function testPatternValidation() {
  check("get('') refuses empty pattern",
    /non-empty string/.test(_throwMsg(function () { b.router.create().get("", function () {}); })));
  check("get(123) refuses non-string pattern",
    /non-empty string/.test(_throwMsg(function () { b.router.create().get(123, function () {}); })));
  var long = "/" + "a".repeat(1030);
  check("get(<1031-char pattern>) refuses over-length pattern",
    /exceeds 1024 chars/.test(_throwMsg(function () { b.router.create().get(long, function () {}); })));
  check("get('/users/:') refuses empty parameter name",
    /empty parameter name/.test(_throwMsg(function () { b.router.create().get("/users/:", function () {}); })));
}

function testAsteriskFloodRefused() {
  check("get('/a/****/b') refused (CVE-2026-4923, 4 asterisks)",
    /CVE-2026-4923/.test(_throwMsg(function () { b.router.create().get("/a/****/b", function () {}); })));
  check("get('/a/***/b') allowed (3 asterisks under the cap)",
    _throwMsg(function () { b.router.create().get("/a/***/b", function () {}); }) === null);
}

function testRouteSpecValidation() {
  check("spec with unknown key refused",
    /unknown spec key 'bogus'/.test(_throwMsg(function () {
      b.router.create().get("/x", { bogus: 1 }, function () {});
    })));
  check("spec.body not a schema refused",
    /spec\.body must be a b\.safeSchema/.test(_throwMsg(function () {
      b.router.create().get("/x", { body: {} }, function () {});
    })));
  check("spec.query not a schema refused",
    /spec\.query must be a b\.safeSchema/.test(_throwMsg(function () {
      b.router.create().get("/x", { query: { safeParse: 1 } }, function () {});
    })));
  check("spec.response not a schema refused",
    /spec\.response must be a b\.safeSchema/.test(_throwMsg(function () {
      b.router.create().get("/x", { response: 5 }, function () {});
    })));
  check("spec.tags not an array refused",
    /spec\.tags must be an array of strings/.test(_throwMsg(function () {
      b.router.create().get("/x", { tags: "nope" }, function () {});
    })));
  check("spec.tags with non-string entries refused",
    /spec\.tags must be an array of strings/.test(_throwMsg(function () {
      b.router.create().get("/x", { tags: [1, 2] }, function () {});
    })));
}

// ---- dispatch ----

async function testMethodMismatchFallsToNotFound() {
  var r = b.router.create();
  var ran = false;
  r.get("/x", function (req, res) { ran = true; res.writeHead(200); res.end("get"); });
  var res = _res();
  await r.handle(_req("POST", "/x"), res);
  check("POST to a GET-only path → 404 (method not matched, no 405)",
    res.statusCode === 404 && ran === false);
}

async function testDefaultNotFoundBody() {
  var r = b.router.create();
  var res = _res();
  await r.handle(_req("GET", "/nope"), res);
  check("default notFound → 404 with the framework HTML body",
    res.statusCode === 404 && res._body === "<h1>404 Not Found</h1>");
}

async function testCustomNotFound() {
  var r = b.router.create();
  var sawReq = false;
  r.onNotFound(function (req, res) { sawReq = !!req; res.writeHead(404); res.end("custom-nf"); });
  var res = _res();
  await r.handle(_req("GET", "/nope"), res);
  check("onNotFound handler runs on no-match",
    res.statusCode === 404 && res._body === "custom-nf" && sawReq === true);
}

async function testParamCaptureAndRoutePattern() {
  var r = b.router.create();
  var seen = null, pattern = null;
  r.get("/users/:id/posts/:pid", function (req, res) {
    seen = req.params; pattern = req.routePattern;
    res.writeHead(200); res.end("ok");
  });
  var res = _res();
  await r.handle(_req("GET", "/users/42/posts/99"), res);
  check("named params captured onto req.params",
    seen && seen.id === "42" && seen.pid === "99");
  check("req.routePattern exposes the route template (not the concrete URL)",
    pattern === "/users/:id/posts/:pid");
}

async function testTrailingSlashParamNoMatch() {
  var r = b.router.create();
  var ran = false;
  r.get("/users/:id", function (req, res) { ran = true; res.writeHead(200); res.end("u"); });
  var res = _res();
  await r.handle(_req("GET", "/users/"), res);
  check("'/users/' does NOT match '/users/:id' (empty param segment) → 404",
    res.statusCode === 404 && ran === false);
}

async function testMultiHandlerFallThrough() {
  var r = b.router.create();
  var order = [];
  r.get("/m",
    function (req, res) { order.push("h1"); },
    function (req, res) { order.push("h2"); res.writeHead(200); res.end("done"); });
  var res = _res();
  await r.handle(_req("GET", "/m"), res);
  check("two terminal handlers on one route both run in order",
    order.join(",") === "h1,h2" && res.statusCode === 200);
}

async function testInRouteMiddlewareNextSemantics() {
  var r = b.router.create();
  var terminalRan = false;
  r.get("/g",
    function gate(req, res, next) { /* no next() — refuse */ res.writeHead(403); res.end("deny"); },
    function terminal(req, res) { terminalRan = true; res.writeHead(200); res.end("ok"); });
  var res = _res();
  await r.handle(_req("GET", "/g"), res);
  check("in-route middleware that omits next() halts the chain",
    res.statusCode === 403 && terminalRan === false);

  var r2 = b.router.create();
  var order = [];
  r2.get("/g2",
    function gate(req, res, next) { order.push("gate"); next(); },
    function terminal(req, res) { order.push("terminal"); res.writeHead(200); res.end("ok"); });
  var res2 = _res();
  await r2.handle(_req("GET", "/g2"), res2);
  check("in-route middleware that calls next() proceeds to the terminal handler",
    order.join(",") === "gate,terminal" && res2.statusCode === 200);
}

async function testGlobalMwEndsResponseWithNextStopsDispatch() {
  var r = b.router.create();
  var routeRan = false;
  r.use(function (req, res, next) { res.writeHead(200); res.end("mw"); next(); });
  r.get("/f", function (req, res) { routeRan = true; res.writeHead(200); res.end("route"); });
  var res = _res();
  await r.handle(_req("GET", "/f"), res);
  check("a global middleware that ends the response short-circuits dispatch even if it calls next()",
    routeRan === false && res._body === "mw");
}

async function testQueryPopulated() {
  var r = b.router.create();
  var seen = null;
  r.get("/search", function (req, res) { seen = req.query; res.writeHead(200); res.end("ok"); });
  var res = _res();
  await r.handle(_req("GET", "/search?q=hello&limit=5"), res);
  check("req.query is populated from the URL search string",
    seen && seen.q === "hello" && seen.limit === "5");
}

async function testQueryKeyCap() {
  var r = b.router.create();
  var ran = false;
  r.get("/q", function (req, res) { ran = true; res.writeHead(200); res.end("ok"); });
  var parts = [];
  for (var i = 0; i < 1001; i++) parts.push("k" + i + "=v");
  var res = _res();
  await r.handle(_req("GET", "/q?" + parts.join("&")), res);
  check("HashDoS query-key cap: 1001 distinct keys → 400 before dispatch",
    res.statusCode === 400 && ran === false && /too many query keys/.test(res._body));
}

// ---- schema + response validators ----

async function testQuerySchemaValidation() {
  var r = b.router.create();
  var handlerRan = false;
  r.get("/search", { query: s.object({ q: s.string() }) }, function (req, res) {
    handlerRan = true; res.writeHead(200); res.end("ok");
  });

  var ok = _res();
  await r.handle(_req("GET", "/search?q=abc"), ok);
  check("valid query → 200", ok.statusCode === 200 && handlerRan === true);

  var bad = _res();
  handlerRan = false;
  await r.handle(_req("GET", "/search"), bad);   // q omitted
  check("missing required query field → 400 with where:query",
    bad.statusCode === 400 && /"where":"query"/.test(bad._body) && handlerRan === false);
}

async function testParamsSchemaValidation() {
  var r = b.router.create();
  var seen = null;
  r.get("/n/:count", { params: s.object({ count: s.string() }) }, function (req, res) {
    seen = req.params; res.writeHead(200); res.end("ok");
  });
  var res = _res();
  await r.handle(_req("GET", "/n/7"), res);
  check("params schema runs and the handler sees the parsed params",
    res.statusCode === 200 && seen && seen.count === "7");
}

async function testResponseValidatorThrowMode() {
  var r = b.router.create();
  r.get("/rv", { response: s.object({ ok: s.boolean() }), validateResponse: "throw" },
    function (req, res) { res.json({ ok: "not-a-boolean" }); });
  var res = _res();
  res.json = function (v) { res.writeHead(200); res.end(JSON.stringify(v)); };
  var threw = null;
  try { await r.handle(_req("GET", "/rv"), res); } catch (e) { threw = e; }
  check("response-validation throw mode surfaces a drift error out of res.json",
    threw && /response-validation failed/.test(threw.message));
}

// ---- introspection ----

function testInspectRoutes() {
  var r = b.router.create();
  r.get("/u/:id", { description: "desc", tags: ["t"], summary: "sum" }, function () {});
  r.post("/plain", function () {});
  var rows = r.inspectRoutes();
  check("inspectRoutes returns one row per registered route", rows.length === 2);
  var specRow = rows[0];
  check("inspectRoutes surfaces method + pattern + description",
    specRow.method === "GET" && specRow.pattern === "/u/:id" && specRow.description === "desc");
  check("inspectRoutes surfaces the spec tags + summary",
    specRow.spec && specRow.spec.tags.join(",") === "t" && specRow.spec.summary === "sum");
  check("inspectRoutes reports a plain route's spec as null",
    rows[1].spec === null && rows[1].method === "POST");
}

function testOpenapi() {
  var r = b.router.create();
  r.get("/users/:id", {
    summary: "Get user", tags: ["users"], description: "d",
    queryJsonSchema: { properties: { q: { type: "string" } }, required: ["q"] },
    responseJsonSchema: { type: "object" },
  }, function () {});
  r.post("/users/:id", { bodyJsonSchema: { type: "object" } }, function () {});
  r.get("/safe", { body: s.object({ a: s.string() }) }, function () {});
  r.put("/plain", function () {});

  var docDefault = b.router.create().openapi();
  check("openapi() defaults info to the framework placeholder",
    docDefault.openapi === "3.0.3" &&
    docDefault.info.title === "blamejs app" && docDefault.info.version === "0.0.0");

  var doc = r.openapi({ info: { title: "T", version: "1.0" } });
  check("openapi() passes custom info through", doc.info.title === "T" && doc.info.version === "1.0");
  check("openapi() converts ':id' path params to '{id}' and merges methods on one path",
    doc.paths["/users/{id}"] &&
    !!doc.paths["/users/{id}"].get && !!doc.paths["/users/{id}"].post);

  var getOp = doc.paths["/users/{id}"].get;
  var pathParam = getOp.parameters.filter(function (p) { return p.in === "path"; })[0];
  var queryParam = getOp.parameters.filter(function (p) { return p.in === "query"; })[0];
  check("openapi() emits a required path parameter",
    pathParam && pathParam.name === "id" && pathParam.required === true);
  check("openapi() emits the query parameter from queryJsonSchema (required)",
    queryParam && queryParam.name === "q" && queryParam.required === true);
  check("openapi() emits responses from responseJsonSchema",
    getOp.responses && getOp.responses["200"]);
  check("openapi() emits requestBody from bodyJsonSchema",
    doc.paths["/users/{id}"].post.requestBody &&
    doc.paths["/users/{id}"].post.requestBody.required === true);
  check("openapi() annotates a safeSchema-only body with x-blamejs-body-validation",
    doc.paths["/safe"].get["x-blamejs-body-validation"] === "safe-schema (json schema not provided)");
  check("openapi() summarizes a spec-less route from method + pattern",
    doc.paths["/plain"].put.summary === "PUT /plain");
}

function testReservedSlugs() {
  var r = b.router.create();
  r.get("/admin/panel", function () {});
  r.get("/api", function () {});
  r.get("/API/v2", function () {});      // dedupes case-insensitively with /api
  r.get("/:id", function () {});          // param-first: not a reserved slug
  r.get("/", function () {});             // root: no slug
  var slugs = r.getReservedSlugs();
  check("getReservedSlugs collects first literal segments, lowercased + deduped",
    slugs.has("admin") && slugs.has("api") && slugs.size === 2);
  check("getReservedSlugs excludes parameter-first and root patterns",
    !slugs.has(":id") && !slugs.has(""));
}

// ---- ws() registration + lifecycle ----

function testWsValidation() {
  check("ws('') refuses empty path",
    /path must be a non-empty string/.test(_throwMsg(function () { b.router.create().ws("", function () {}); })));
  check("ws(path, non-fn) refuses non-function handler",
    /handler must be a function/.test(_throwMsg(function () { b.router.create().ws("/ws", "x"); })));
  check("ws(path, fn, {transport:'h3'}) refuses unknown transport",
    /transport must be/.test(_throwMsg(function () { b.router.create().ws("/ws", function () {}, { transport: "h3" }); })));
  check("ws(path, fn, {origins:'*'}) registers without throwing",
    _throwMsg(function () { b.router.create().ws("/ws", function () {}, { origins: "*" }); }) === null);
}

async function testWebSocketLifecycleCounters() {
  var r = b.router.create();
  check("activeWebSockets() is 0 on a fresh router", r.activeWebSockets() === 0);
  var closed = await r.closeWebSockets();
  check("closeWebSockets() with no open connections resolves to 0", closed === 0);
}

// ---- serveStatic ----

async function _runStaticMw(mw, req) {
  var res = _res();
  var nexted = false;
  mw(req, res, function () { nexted = true; });
  // Settle when the middleware finishes — it either called next() (sync or
  // async) or wrote a response. A pass-through that does neither settles as
  // not-nexted once the poll window elapses (waitUntil throws on timeout).
  try {
    await helpers.waitUntil(function () {
      return nexted || res.headersSent || res.writableEnded;
    }, { timeoutMs: 2000, label: "router static mw: next() or response written" });
  } catch (_e) { /* mw neither nexted nor responded — settle as-is */ }
  return { nexted: nexted, res: res };
}

async function testServeStaticBypassBranches() {
  var mw = b.router.serveStatic(os.tmpdir());
  var nonGet = await _runStaticMw(mw, { method: "POST", url: "/x", pathname: "/x", headers: {} });
  check("serveStatic passes non-GET requests through (next)", nonGet.nexted === true);

  var nul = await _runStaticMw(mw, { method: "GET", url: "/x", pathname: "/x y", headers: {} });
  check("serveStatic passes NUL-byte pathnames through (next)", nul.nexted === true);

  var traversal = await _runStaticMw(mw, { method: "GET", url: "/x", pathname: "/../../etc/passwd", headers: {} });
  check("serveStatic passes a '..' escape outside root through (next)", traversal.nexted === true);

  var missing = await _runStaticMw(mw, {
    method: "GET", url: "/x", pathname: "/no-such-file-" + Date.now() + ".html", headers: {},
  });
  check("serveStatic passes a missing file through (next)", missing.nexted === true);
}

async function testServeStaticServesFile() {
  var dir = fs.mkdtempSync(nodePath.join(os.tmpdir(), "router-cov-"));
  try {
    fs.writeFileSync(nodePath.join(dir, "hello.html"), "<b>hi</b>");
    fs.writeFileSync(nodePath.join(dir, "blob.xyz"), "rawbytes");

    var r = b.router.create();
    r.use(b.router.serveStatic(dir));
    var server = r.listen(0);
    await _listening(server);
    var port = server.address().port;
    try {
      var html = await _get(port, "/hello.html");
      check("serveStatic serves a known file with mapped MIME + 1h cache",
        html.status === 200 && html.body === "<b>hi</b>" &&
        html.headers["content-type"] === "text/html" &&
        html.headers["cache-control"] === "public, max-age=3600");

      var versioned = await _get(port, "/hello.html?v=abc");
      check("serveStatic marks ?v=-versioned URLs immutable for a year",
        versioned.headers["cache-control"] === "public, max-age=31536000, immutable");

      var blob = await _get(port, "/blob.xyz");
      check("serveStatic falls back to application/octet-stream for unknown extensions",
        blob.status === 200 && blob.headers["content-type"] === "application/octet-stream");

      var post = await _get(port, "/hello.html", {}, "POST");
      check("serveStatic + no POST route → 404 (non-GET bypass reaches the notFound)",
        post.status === 404);

      var missing = await _get(port, "/absent.html");
      check("serveStatic + missing file → 404 (bypass reaches the notFound)",
        missing.status === 404);
    } finally {
      await _close(server);
    }
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

// ---- live listen() response-helper wiring ----

function _listening(server) {
  return new Promise(function (resolve) {
    if (server.listening) { resolve(); return; }
    server.once("listening", resolve);
  });
}
function _close(server) { return new Promise(function (resolve) { server.close(resolve); }); }
function _get(port, path, headers, method) {
  return new Promise(function (resolve, reject) {
    var req = http.request({ host: "127.0.0.1", port: port, path: path, method: method || "GET", headers: headers || {} },
      function (r) {
        var body = "";
        r.on("data", function (c) { body += c; });
        r.on("end", function () { resolve({ status: r.statusCode, headers: r.headers, body: body }); });
      });
    req.on("error", reject);
    req.end();
  });
}

async function testListenResponseHelpers() {
  var r = b.router.create({ allowedRedirectOrigins: ["https://idp.example.com"] });
  r.get("/json",    function (req, res) { res.json({ hello: "world" }); });
  r.get("/created", function (req, res) { res.status(201).json({ id: 1 }); });
  r.get("/same",    function (req, res) { res.redirect("/dashboard"); });
  r.get("/xo",      function (req, res) { res.redirect("https://idp.example.com/authorize?x=1"); });
  r.get("/xo-bad",  function (req, res) { try { res.redirect("https://evil.example.com/x"); } catch (e) { res.writeHead(400); res.end("refused:" + e.code); } });
  r.get("/crlf",    function (req, res) { try { res.redirect("/a\nEvil:1"); } catch (e) { res.writeHead(400); res.end("refused:" + e.code); } });
  r.get("/boom",    function (req, res) { throw new Error("kaboom"); });
  r.onError(function (err, req, res) { res.writeHead(500, { "Content-Type": "text/plain" }); res.end("custom-500:" + err.message); });

  var server = r.listen(0);
  await _listening(server);
  var port = server.address().port;
  try {
    var j = await _get(port, "/json");
    check("res.json ships 200 + application/json + serialized body",
      j.status === 200 && /application\/json/.test(j.headers["content-type"]) &&
      j.body === '{"hello":"world"}');

    var created = await _get(port, "/created");
    check("res.status(201).json chains the status through", created.status === 201);

    var same = await _get(port, "/same");
    check("res.redirect same-origin path → 302 Location", same.status === 302 && same.headers.location === "/dashboard");

    var xo = await _get(port, "/xo");
    check("res.redirect to an allowlisted cross-origin → 302 Location",
      xo.status === 302 && xo.headers.location === "https://idp.example.com/authorize?x=1");

    var xoBad = await _get(port, "/xo-bad");
    check("res.redirect to an off-allowlist origin throws RouterError (handler-observable)",
      xoBad.status === 400 && xoBad.body === "refused:router/redirect-cross-origin-refused");

    var crlf = await _get(port, "/crlf");
    check("res.redirect refuses a LF in the target (header-injection guard)",
      crlf.status === 400 && crlf.body === "refused:router/redirect-target-has-control-chars");

    var boom = await _get(port, "/boom");
    check("a throwing handler routes through onError to a custom 500",
      boom.status === 500 && boom.body === "custom-500:kaboom");

    var nf = await _get(port, "/missing");
    check("unmatched path on the live server → 404", nf.status === 404);
  } finally {
    await _close(server);
  }
}

async function testListenDefault500NoErrorHandler() {
  var r = b.router.create();
  r.get("/boom", function () { throw new Error("nope"); });
  var server = r.listen(0);
  await _listening(server);
  var port = server.address().port;
  try {
    var boom = await _get(port, "/boom");
    check("a throwing handler with no onError → default 500 Internal Server Error",
      boom.status === 500 && /Internal Server Error/.test(boom.body));
  } finally {
    await _close(server);
  }
}

async function testListenEarlyDataGate() {
  var r = b.router.create({ tls0Rtt: "refuse" });
  r.get("/e", function (req, res) { res.json({ ok: 1 }); });
  var server = r.listen(0);
  await _listening(server);
  var port = server.address().port;
  try {
    var early = await _get(port, "/e", { "early-data": "1" });
    check("refuse posture: an Early-Data:1 request is gated with 425 at listen()",
      early.status === 425 && early.body === "early-data-refused");
    var normal = await _get(port, "/e");
    check("refuse posture: a normal (non-early-data) request proceeds",
      normal.status === 200);
  } finally {
    await _close(server);
  }
}

async function run() {
  testPatternValidation();
  testAsteriskFloodRefused();
  testRouteSpecValidation();
  await testMethodMismatchFallsToNotFound();
  await testDefaultNotFoundBody();
  await testCustomNotFound();
  await testParamCaptureAndRoutePattern();
  await testTrailingSlashParamNoMatch();
  await testMultiHandlerFallThrough();
  await testInRouteMiddlewareNextSemantics();
  await testGlobalMwEndsResponseWithNextStopsDispatch();
  await testQueryPopulated();
  await testQueryKeyCap();
  await testQuerySchemaValidation();
  await testParamsSchemaValidation();
  await testResponseValidatorThrowMode();
  testInspectRoutes();
  testOpenapi();
  testReservedSlugs();
  testWsValidation();
  await testWebSocketLifecycleCounters();
  await testServeStaticBypassBranches();
  await testServeStaticServesFile();
  await testListenResponseHelpers();
  await testListenDefault500NoErrorHandler();
  await testListenEarlyDataGate();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK router-coverage — " + helpers.getChecks() + " checks"); process.exit(0); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
