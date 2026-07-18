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

var http     = require("node:http");
var net      = require("node:net");
var crypto   = require("node:crypto");
var fs       = require("node:fs");
var os       = require("node:os");
var nodePath = require("node:path");

var http2      = require("node:http2");
var C          = require("../../lib/constants");
var mtlsEngine = require("../../lib/mtls-engine-default");
var compliance = require("../../lib/compliance");
var pki        = require("../../lib/vendor/pki.cjs");

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

  // A pathname that resolves to a directory (not a file) is passed through.
  var subdir = fs.mkdtempSync(nodePath.join(os.tmpdir(), "router-dir-"));
  try {
    var dirMw = b.router.serveStatic(os.tmpdir());
    var dirReq = { method: "GET", url: "/x", pathname: "/" + nodePath.basename(subdir), headers: {} };
    var dir = await _runStaticMw(dirMw, dirReq);
    check("serveStatic passes a directory pathname through (next, not a file body)", dir.nexted === true);
  } finally {
    try { fs.rmSync(subdir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
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

// ---- constructor option validation (create opts) ----

function testConstructorOptionValidation() {
  check("create({ tls0Rtt: 'bogus' }) throws TypeError naming the valid postures",
    /tls0Rtt must be one of/.test(_throwMsg(function () { b.router.create({ tls0Rtt: "bogus" }); })));
  check("create({ tls0Rtt: 42 }) (non-string) throws TypeError",
    /tls0Rtt must be one of/.test(_throwMsg(function () { b.router.create({ tls0Rtt: 42 }); })));

  check("create({ allowedRedirectOrigins: 'x' }) (non-array) refuses",
    /allowedRedirectOrigins must be an array/.test(_throwMsg(function () {
      b.router.create({ allowedRedirectOrigins: "https://x.example.com" });
    })));
  check("allowedRedirectOrigins with a non-string entry refuses (index-pointing)",
    /allowedRedirectOrigins\[0\] must be a non-empty string/.test(_throwMsg(function () {
      b.router.create({ allowedRedirectOrigins: [123] });
    })));
  check("allowedRedirectOrigins with an empty-string entry refuses",
    /allowedRedirectOrigins\[0\] must be a non-empty string/.test(_throwMsg(function () {
      b.router.create({ allowedRedirectOrigins: [""] });
    })));
  check("allowedRedirectOrigins with a non-HTTPS origin refuses",
    /is not a valid HTTPS origin/.test(_throwMsg(function () {
      b.router.create({ allowedRedirectOrigins: ["http://plain.example.com"] });
    })));
  check("allowedRedirectOrigins carrying a path refuses (origin form only)",
    /must be an origin/.test(_throwMsg(function () {
      b.router.create({ allowedRedirectOrigins: ["https://idp.example.com/authorize"] });
    })));
  check("allowedRedirectOrigins carrying a query string refuses (origin form only)",
    /must be an origin/.test(_throwMsg(function () {
      b.router.create({ allowedRedirectOrigins: ["https://idp.example.com?next=/x"] });
    })));
  check("allowedRedirectOrigins carrying userinfo refuses (credential-leak guard)",
    /is not a valid HTTPS origin/.test(_throwMsg(function () {
      b.router.create({ allowedRedirectOrigins: ["https://user:pass@idp.example.com"] });
    })));

  var r = b.router.create({ allowedRedirectOrigins: ["https://idp.example.com"] });
  var copy = r.allowedRedirectOrigins();
  check("allowedRedirectOrigins() reads back the normalized origin",
    copy.length === 1 && copy[0] === "https://idp.example.com");
  copy.push("https://mutated.example.com");
  check("allowedRedirectOrigins() returns a defensive copy (caller mutation does not leak)",
    r.allowedRedirectOrigins().length === 1);
}

// ---- patch / delete verbs ----

async function testPatchAndDeleteVerbs() {
  var r = b.router.create();
  var hit = [];
  r.patch("/thing/:id", function (req, res) { hit.push("PATCH:" + req.params.id); res.writeHead(200); res.end("p"); });
  r.delete("/thing/:id", function (req, res) { hit.push("DELETE:" + req.params.id); res.writeHead(200); res.end("d"); });

  var pres = _res();
  await r.handle(_req("PATCH", "/thing/7"), pres);
  check("router.patch registers + dispatches (PATCH verb)", pres.statusCode === 200 && hit[0] === "PATCH:7");

  var dres = _res();
  await r.handle(_req("DELETE", "/thing/9"), dres);
  check("router.delete registers + dispatches (DELETE verb)", dres.statusCode === 200 && hit[1] === "DELETE:9");
}

// ---- handle(): adversarial path canonicalization ----

async function testHandleEncodedSeparatorRefusals() {
  var r = b.router.create();
  r.get("/a/b", function (req, res) { res.writeHead(200); res.end("ok"); });

  var enc = _res();
  await r.handle(_req("GET", "/a%2Fb"), enc);
  check("encoded '/' (%2F) in the path → 400 (guard/consumer decoding agreement)",
    enc.statusCode === 400 && /encoded path separator/.test(enc._body));

  var back = _res();
  await r.handle(_req("GET", "/a%5Cb"), back);
  check("encoded '\\' (%5C) in the path → 400", back.statusCode === 400 && /encoded path separator/.test(back._body));

  var nul = _res();
  await r.handle(_req("GET", "/a%00b"), nul);
  check("encoded NUL (%00) in the path → 400", nul.statusCode === 400 && /null byte/.test(nul._body));

  var mal = _res();
  await r.handle(_req("GET", "/a/%zz"), mal);
  check("malformed percent-encoding (%zz) → 400 malformed (decode throws, caught)",
    mal.statusCode === 400 && /malformed percent-encoding/.test(mal._body));

  var segMismatch = _res();
  await r.handle(_req("GET", "/a/b/c"), segMismatch);
  check("a longer path than the pattern is a no-match (segment-count mismatch) → 404",
    segMismatch.statusCode === 404);

  // A request with no Host header falls back to the "localhost" base for URL parsing.
  var noHost = _res();
  await r.handle({ method: "GET", url: "/a/b", headers: {} }, noHost);
  check("a request with no Host header resolves against the localhost base (still routes)",
    noHost.statusCode === 200);
}

// ---- path-scoped middleware (use(prefix, mw)) ----

async function testPathScopedMiddleware() {
  var r = b.router.create();
  var ran = [];
  r.use("/admin", function adminGate(req, res, next) { ran.push("gate"); next(); });
  r.use(["/api", "/v2"], function apiTag(req, res, next) { ran.push("apitag"); next(); });
  r.get("/admin/panel", function (req, res) { res.writeHead(200); res.end("admin"); });
  r.get("/api/thing", function (req, res) { res.writeHead(200); res.end("api"); });
  r.get("/public", function (req, res) { res.writeHead(200); res.end("public"); });

  ran = [];
  var a = _res();
  await r.handle(_req("GET", "/admin/panel"), a);
  check("scoped mw under '/admin' runs on '/admin/panel'", a.statusCode === 200 && ran.indexOf("gate") !== -1);

  ran = [];
  var api = _res();
  await r.handle(_req("GET", "/api/thing"), api);
  check("array-prefix mw ['/api','/v2'] runs when the path matches one prefix",
    api.statusCode === 200 && ran.indexOf("apitag") !== -1);

  ran = [];
  var pub = _res();
  await r.handle(_req("GET", "/public"), pub);
  check("scoped mw is SKIPPED off-prefix but does NOT short-circuit dispatch",
    pub.statusCode === 200 && pub._body === "public" && ran.length === 0);

  ran = [];
  var sib = _res();
  r.use("/adm", function () {});   // ensure a substring-prefix does not leak
  await r.handle(_req("GET", "/administrator"), sib);
  check("a scoped prefix matches on segment boundaries, not textual prefix ('/adm' ⊄ '/administrator')",
    ran.length === 0);

  // A trailing-slash prefix normalizes to the same mount as its slashless form.
  var r2 = b.router.create();
  var teamRan = false;
  r2.use("/team/", function (req, res, next) { teamRan = true; next(); });
  r2.get("/team/roster", function (req, res) { res.writeHead(200); res.end("roster"); });
  var team = _res();
  await r2.handle(_req("GET", "/team/roster"), team);
  check("a trailing-slash mount prefix ('/team/') matches '/team/roster' (normalized)",
    team.statusCode === 200 && teamRan === true);
}

function testUseValidationErrors() {
  check("use() with no args refuses",
    /requires at least one middleware/.test(_throwMsg(function () { b.router.create().use(); })));
  check("use(number) (bad first arg) refuses",
    /first argument must be a middleware/.test(_throwMsg(function () { b.router.create().use(42); })));
  check("use(null) (bad first arg) refuses naming the type",
    /got null/.test(_throwMsg(function () { b.router.create().use(null); })));
  check("use([]) (empty prefix array) refuses",
    /at least one prefix string/.test(_throwMsg(function () { b.router.create().use([], function () {}); })));
  check("use([123], mw) (non-string prefix entry) refuses",
    _throwMsg(function () { b.router.create().use([123], function () {}); }) !== null);
  check("use('admin', mw) (prefix not absolute) refuses",
    /must begin with '\/'/.test(_throwMsg(function () { b.router.create().use("admin", function () {}); })));
  check("use(<over-length prefix>, mw) refuses",
    /exceeds 1024 chars/.test(_throwMsg(function () { b.router.create().use("/" + "a".repeat(1030), function () {}); })));
  check("use('/admin') with no middleware after the prefix refuses",
    /requires at least one middleware/.test(_throwMsg(function () { b.router.create().use("/admin"); })));
  check("use('/admin', notFn) (scoped middleware not a function) refuses (position-pointing)",
    /middleware at position 0 must be a function/.test(_throwMsg(function () { b.router.create().use("/admin", "nope"); })));
  check("use(fn, notFn) (global middleware not a function) refuses",
    /middleware at position 1 must be a function/.test(_throwMsg(function () { b.router.create().use(function () {}, 5); })));
}

// ---- middleware error propagation + mid-chain short-circuit ----

async function testMiddlewareErrorRethrows() {
  var r = b.router.create();
  r.use(function boom(req, res, next) { throw new Error("mw-explode"); });
  r.get("/x", function (req, res) { res.writeHead(200); res.end("ok"); });
  var res = _res();
  var threw = null;
  try { await r.handle(_req("GET", "/x"), res); } catch (e) { threw = e; }
  check("a throwing global middleware rejects handle() (error surfaces, not swallowed)",
    threw && /mw-explode/.test(threw.message));
}

async function testWritableEndedBetweenHandlers() {
  var r = b.router.create();
  var ran = [];
  r.get("/two",
    function first(req, res) { ran.push("first"); res.writeHead(200); res.end("first-ends"); },
    function second(req, res) { ran.push("second"); res.writeHead(200); res.end("second"); });
  var res = _res();
  await r.handle(_req("GET", "/two"), res);
  check("once a terminal handler ends the response, the next handler is skipped (writableEnded guard)",
    ran.join(",") === "first" && res._body === "first-ends");
}

// ---- body schema validation + validation-error body sealing ----

async function testBodySchemaValidation() {
  var r = b.router.create();
  var handlerRan = false;
  r.post("/create", { body: s.object({ name: s.string() }) }, function (req, res) {
    handlerRan = true; res.writeHead(201); res.end("made:" + req.body.name);
  });

  var bad = _res();
  await r.handle(_req("POST", "/create"), bad);   // no req.body → required body missing
  check("a required body schema with no parsed body → 400 where:body",
    bad.statusCode === 400 && /"where":"body"/.test(bad._body) && handlerRan === false);

  var okReq = _req("POST", "/create");
  okReq.body = { name: "alice" };                 // simulate an upstream body parser
  var ok = _res();
  await r.handle(okReq, ok);
  check("a valid parsed body passes the schema and the handler sees the coerced value",
    ok.statusCode === 201 && ok._body === "made:alice" && handlerRan === true);
}

async function testValidationErrorSealedBody() {
  var r = b.router.create();
  r.post("/sealed", { body: s.object({ name: s.string() }) }, function (req, res) { res.writeHead(201); res.end("ok"); });

  var sealReq = _req("POST", "/sealed");
  sealReq.apiEncryptEncode = function (payload) { return { sealed: true, where: payload.where }; };
  var sealed = _res();
  await r.handle(sealReq, sealed);
  check("validation error body is sealed through req.apiEncryptEncode when an encrypted session is active",
    sealed.statusCode === 400 && sealed._body === '{"sealed":true,"where":"body"}');

  var throwReq = _req("POST", "/sealed");
  throwReq.apiEncryptEncode = function () { throw new Error("encoder-down"); };
  var fallback = _res();
  await r.handle(throwReq, fallback);
  check("an encoder that throws falls back to the plaintext validation body (no crash)",
    fallback.statusCode === 400 && /"where":"body"/.test(fallback._body));
}

// ---- response validation: warn mode, raw res.end path, non-JSON skip ----

async function testResponseValidatorWarnAndRawEnd() {
  // warn mode via res.json — drift is logged, response ships as-is (200).
  var r1 = b.router.create();
  r1.get("/warn", { response: s.object({ ok: s.boolean() }), validateResponse: "warn" },
    function (req, res) { res.json({ ok: "not-a-boolean" }); });
  var w = _res();
  w.json = function (v) { w.writeHead(200); w.end(JSON.stringify(v)); };
  await r1.handle(_req("GET", "/warn"), w);
  check("response-validation warn mode ships the drifting body as-is (200, no throw)",
    w.statusCode === 200 && /not-a-boolean/.test(w._body));

  // raw res.end(JSON.stringify(...)) path — the res.end wrapper parses the
  // JSON-shaped buffer and validates it even without res.json.
  var r2 = b.router.create();
  r2.get("/raw", { response: s.object({ ok: s.boolean() }), validateResponse: "warn" },
    function (req, res2) { res2.writeHead(200); res2.end(JSON.stringify({ ok: "drift" })); });
  var raw = _res();
  await r2.handle(_req("GET", "/raw"), raw);
  check("a raw res.end(JSON) body is validated by the res.end wrapper (warn, ships)",
    raw.statusCode === 200 && /drift/.test(raw._body));

  // non-JSON body is skipped by _bodyLooksLikeJson (leading '<').
  var r3 = b.router.create();
  r3.get("/html", { response: s.object({ ok: s.boolean() }), validateResponse: "warn" },
    function (req, res3) { res3.writeHead(200); res3.end("<h1>not json</h1>"); });
  var htmlRes = _res();
  await r3.handle(_req("GET", "/html"), htmlRes);
  check("a non-JSON (HTML) response body is skipped by the response validator (no parse attempt)",
    htmlRes.statusCode === 200 && htmlRes._body === "<h1>not json</h1>");

  // whitespace-leading JSON is still recognized + validated (warn, ships).
  var r4 = b.router.create();
  r4.get("/ws", { response: s.object({ ok: s.boolean() }), validateResponse: "warn" },
    function (req, res4) { res4.writeHead(200); res4.end("   {\"ok\":\"drift\"}"); });
  var wsRes = _res();
  await r4.handle(_req("GET", "/ws"), wsRes);
  check("a whitespace-leading JSON body is recognized + validated by the res.end wrapper",
    wsRes.statusCode === 200 && /drift/.test(wsRes._body));

  // a Buffer body that looks like JSON is decoded + validated by the wrapper.
  var r4b = b.router.create();
  r4b.get("/buf", { response: s.object({ ok: s.boolean() }), validateResponse: "warn" },
    function (req, res4b) { res4b.writeHead(200); res4b.end(Buffer.from("{\"ok\":\"drift\"}")); });
  var bufRes = _res();
  await r4b.handle(_req("GET", "/buf"), bufRes);
  check("a Buffer response body that looks like JSON is decoded + validated (warn, ships)",
    bufRes.statusCode === 200 && /drift/.test(bufRes._body));

  // a JSON-shaped-but-unparseable body is skipped (parse throws, caught).
  var r4c = b.router.create();
  r4c.get("/broken", { response: s.object({ ok: s.boolean() }), validateResponse: "throw" },
    function (req, res4c) { res4c.writeHead(200); res4c.end("{not valid json"); });
  var brokenRes = _res();
  var brokenThrew = null;
  try { await r4c.handle(_req("GET", "/broken"), brokenRes); } catch (e) { brokenThrew = e; }
  check("a JSON-shaped but unparseable body is skipped by the validator (no crash, ships)",
    brokenThrew === null && brokenRes.statusCode === 200 && brokenRes._body === "{not valid json");

  // an all-whitespace body is not treated as JSON (loop completes, returns false).
  var r4d = b.router.create();
  r4d.get("/blank", { response: s.object({ ok: s.boolean() }), validateResponse: "throw" },
    function (req, res4d) { res4d.writeHead(200); res4d.end("   "); });
  var blankRes = _res();
  var blankThrew = null;
  try { await r4d.handle(_req("GET", "/blank"), blankRes); } catch (e) { blankThrew = e; }
  check("an all-whitespace response body is not mistaken for JSON (no validation attempt)",
    blankThrew === null && blankRes.statusCode === 200);

  // throw mode, but headers already sent on a raw res.end — degrades to a
  // logged error (cannot un-send), still ships.
  var r5 = b.router.create();
  r5.get("/late", { response: s.object({ ok: s.boolean() }), validateResponse: "throw" },
    function (req, res5) { res5.writeHead(200); res5.end(JSON.stringify({ ok: "drift" })); });
  var late = _res();
  var threw = null;
  try { await r5.handle(_req("GET", "/late"), late); } catch (e) { threw = e; }
  check("throw mode after headers already sent degrades to a logged error (no mid-flush throw)",
    threw === null && late.statusCode === 200 && /drift/.test(late._body));

  // validateResponse truthy-but-not-throw/warn → validator installed but
  // passthrough (no active mode).
  var r6 = b.router.create();
  var ranPass = false;
  r6.get("/pass", { response: s.object({ ok: s.boolean() }), validateResponse: true },
    function (req, res6) { ranPass = true; res6.writeHead(200); res6.end(JSON.stringify({ ok: "anything" })); });
  var pass = _res();
  await r6.handle(_req("GET", "/pass"), pass);
  check("validateResponse truthy-but-not-'throw'/'warn' installs a passthrough (no validation)",
    ranPass === true && pass.statusCode === 200);
}

// ---- TLS 1.3 0-RTT anti-replay (direct _check0RttReplay drive) ----

function test0RttReplayCacheDirect() {
  var refuse = b.router.create({ tls0Rtt: "refuse" });
  check("refuse posture: a non-early-data request is allowed through (null verdict)",
    refuse._check0RttReplay(helpers._mockReq({ method: "GET", url: "/x" })) === null);
  var refuseVerdict = refuse._check0RttReplay(helpers._mockReq({ method: "POST", url: "/charge", headers: { "early-data": "1" } }));
  check("refuse posture: an Early-Data:1 request is refused 425",
    refuseVerdict && refuseVerdict.status === 425 && refuseVerdict.reason === "early-data-refused");

  var replay = b.router.create({ tls0Rtt: "replay-cache" });
  var hdrs = { "early-data": "1", host: "api.example.com", authorization: "Bearer t", date: "Fri, 01 Jan 2027 00:00:00 GMT" };
  var first = replay._check0RttReplay(helpers._mockReq({ method: "POST", url: "/charge", headers: hdrs }));
  check("replay-cache: the first Early-Data:1 request is admitted (cached)", first === null);
  var second = replay._check0RttReplay(helpers._mockReq({ method: "POST", url: "/charge", headers: Object.assign({}, hdrs) }));
  check("replay-cache: an identical Early-Data:1 replay is refused 425 (cache hit)",
    second && second.status === 425 && second.reason === "early-data-replay");
  var distinct = replay._check0RttReplay(helpers._mockReq({ method: "POST", url: "/charge",
    headers: Object.assign({}, hdrs, { "idempotency-key": "k-2" }) }));
  check("replay-cache: a distinct (idempotency-keyed) request is admitted",
    distinct === null);
  // Early-Data header present but not "1" (RFC 8470: only "1" is early data).
  check("replay-cache: Early-Data header != '1' is treated as a normal request",
    replay._check0RttReplay(helpers._mockReq({ method: "GET", url: "/x", headers: { "early-data": "0" } })) === null);
}

function test0RttReplayCacheEviction() {
  var replay = b.router.create({ tls0Rtt: "replay-cache" });
  // Insert past the bounded entry cap (4096) with distinct early-data
  // requests so the oldest entries are evicted to make room.
  var cap = 4096;
  for (var i = 0; i < cap + 32; i += 1) {
    var v = replay._check0RttReplay(helpers._mockReq({
      method: "POST", url: "/charge",
      headers: { "early-data": "1", "idempotency-key": "evict-" + i },
    }));
    if (v !== null) { check("replay-cache eviction: every distinct request is admitted", false); return; }
  }
  check("replay-cache eviction: distinct-request insertions past the 4096 cap all admit", true);
  check("replay-cache eviction: the cache stays bounded at the entry cap",
    replay._tls0RttReplayCache.size === cap);
}

function test0RttFailClosedUnderPci() {
  var prior = null;
  try { prior = compliance.current ? compliance.current() : null; } catch (_e) { /* not set */ }
  if (prior) {
    // Posture already pinned in this process — reset so the assertion is deterministic.
    try { compliance._resetForTest(); } catch (_e) { /* best-effort */ }
  }
  try {
    compliance.set("pci-dss");
    var r = b.router.create({ tls0Rtt: "replay-cache" });
    check("replay-cache fail-closes to 'refuse' under the pci-dss posture (RFC 8446 §8 / PCI 6.4.3)",
      r._effective0RttPosture() === "refuse");
  } finally {
    try { compliance._resetForTest(); } catch (_e) { /* best-effort */ }
  }
}

// ---- listen(): TLS server setup path (config branches, no handshake) ----

async function _makeServerCert() {
  var ca = await mtlsEngine.generateCa({ name: "routertestca" });
  var leaf = await mtlsEngine.signClientCert({
    cn: "localhost", usage: "server", caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem,
  });
  return { key: leaf.key, cert: leaf.cert };
}

async function testTlsListenSetup() {
  var cert = await _makeServerCert();

  // Variant 1 — bare {key, cert} + operator SNICallback. Exercises the
  // SNICallback wrapper install, the TLS 1.3 minVersion default, and the
  // posture-driven allowEarlyData default.
  var r1 = b.router.create({ tls0Rtt: "refuse" });
  r1.get("/e", function (req, res) { res.json({ ok: 1 }); });
  var s1 = r1.listen(0, function () {}, {
    key: cert.key, cert: cert.cert,
    // Present so the framework wraps it (CVE-2026-21637); the body only
    // runs on a handshake, which testTlsH2Handshake drives.
    SNICallback: function (servername, cb) { cb(null, null); },
  });
  try {
    await _listening(s1);
    check("listen() with tlsOptions boots an HTTP/2-capable TLS server (ALPN h2 + http/1.1)",
      s1.listening === true && typeof s1.address().port === "number");
    check("TLS server pins the Slowloris header/keepalive timeouts",
      s1.headersTimeout === 60000 && s1.keepAliveTimeout === 5000);
  } finally {
    await _close(s1);
  }

  // Variant 2 — operator-supplied minVersion + allowEarlyData + no
  // SNICallback, under the replay-cache posture. Exercises the
  // "already-set, skip the default" branches.
  var r2 = b.router.create({ tls0Rtt: "replay-cache" });
  r2.get("/e", function (req, res) { res.json({ ok: 1 }); });
  var s2 = r2.listen(0, function () {}, {
    key: cert.key, cert: cert.cert, minVersion: "TLSv1.3", allowEarlyData: false,
  });
  try {
    await _listening(s2);
    check("listen() honors operator-supplied minVersion + allowEarlyData (no default override)",
      s2.listening === true);
  } finally {
    await _close(s2);
  }
}

// A classical (ECDSA P-256) self-signed leaf so a real TLS 1.3 h2
// handshake completes in-process — the mtls engine issues ML-DSA certs,
// which node:tls cannot yet negotiate, so the vendored x509 generator is
// driven directly here for a handshake-capable server cert.
async function _makeClassicalServerCert() {
  var x509 = pki.x509;
  var webcrypto = pki.crypto;
  var keys = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  var cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name:         "CN=localhost",
    notBefore:    new Date(Date.now() - C.TIME.hours(1)),
    notAfter:     new Date(Date.now() + C.TIME.hours(1)),
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    keys:         keys,
    extensions:   [new x509.SubjectAlternativeNameExtension([{ type: "dns", value: "localhost" }])],
  });
  var pkcs8 = await webcrypto.subtle.exportKey("pkcs8", keys.privateKey);
  var keyPem = "-----BEGIN PRIVATE KEY-----\n" +
    Buffer.from(pkcs8).toString("base64").replace(/(.{64})/g, "$1\n") +
    "\n-----END PRIVATE KEY-----\n";
  return { key: keyPem, cert: cert.toString("pem") };
}

async function testTlsH2Handshake() {
  var cert = await _makeClassicalServerCert();
  var r = b.router.create({ tls0Rtt: "refuse" });
  r.get("/e", function (req, res) { res.json({ ok: 1 }); });
  var sniSeen = false;
  var capturedSession = null;
  var server = r.listen(0, function () {}, {
    key: cert.key, cert: cert.cert,
    SNICallback: function (servername, cb) { sniSeen = true; cb(null, null); },
  });
  server.on("session", function (sess) { if (!capturedSession) capturedSession = sess; });
  await _listening(server);
  var port = server.address().port;
  var client = null;
  try {
    client = http2.connect("https://localhost:" + port, { ca: cert.cert, servername: "localhost" });
    var got = await new Promise(function (resolve) {
      client.on("error", function (e) { resolve({ err: e.message }); });
      var creq = client.request({ ":path": "/e" });
      var body = "", st = null;
      creq.on("response", function (h) { st = h[":status"]; });
      creq.on("data", function (d) { body += d; });
      creq.on("end", function () { resolve({ status: st, body: body }); });
      creq.on("error", function (e) { resolve({ err: e.message }); });
      creq.end();
    });
    check("a real TLS 1.3 h2 handshake + GET returns the handler's JSON (200)",
      got.status === 200 && got.body === '{"ok":1}');
    check("the operator SNICallback is invoked (framework wraps it against synchronous throws)",
      sniSeen === true);
    check("the framework registers a per-session GOAWAY guard (CVE-2026-21714)",
      capturedSession !== null && capturedSession._blamejsGoawaySent === false);

    // Drive the framework's wrapped goaway() so the guard flips the
    // session's GOAWAY flag (defense-in-depth WINDOW_UPDATE-after-GOAWAY).
    if (capturedSession && typeof capturedSession.goaway === "function") {
      capturedSession.goaway();
      await helpers.waitUntil(function () { return capturedSession._blamejsGoawaySent === true; },
        { timeoutMs: 2000, label: "h2: framework goaway wrapper flips the guard flag" });
      check("the wrapped goaway() marks the session so post-GOAWAY frames are refused",
        capturedSession._blamejsGoawaySent === true);
    }
  } finally {
    try { if (client) client.close(); } catch (_e) { /* best-effort */ }
    await _close(server);
  }
}

async function testTlsSniCallbackThrows() {
  var cert = await _makeClassicalServerCert();
  var r = b.router.create();
  r.get("/e", function (req, res) { res.json({ ok: 1 }); });
  var operatorSniInvoked = false;
  // CVE-2026-21637 — a synchronous throw from the operator SNICallback must
  // not crash the TLS listener; the framework wraps it into a clean
  // (err, null) callback and aborts just that handshake.
  var server = r.listen(0, function () {}, {
    key: cert.key, cert: cert.cert,
    SNICallback: function (servername, cb) { operatorSniInvoked = true; throw new Error("sni-boom"); },
  });
  await _listening(server);
  var port = server.address().port;
  var client = null;
  try {
    var clientOutcome = null;   // "error" | "connect"
    client = http2.connect("https://localhost:" + port, { ca: cert.cert, servername: "localhost" });
    client.on("error", function () { if (clientOutcome === null) clientOutcome = "error"; });
    client.on("connect", function () { if (clientOutcome === null) clientOutcome = "connect"; });
    await helpers.waitUntil(function () { return operatorSniInvoked && clientOutcome !== null; },
      { timeoutMs: 4000, label: "tls: SNICallback invoked + handshake resolved" });
    check("a throwing operator SNICallback is caught by the framework (listener survives, handshake aborts)",
      operatorSniInvoked === true && clientOutcome === "error");
    // The server is still up and can be closed cleanly (no listener crash).
    check("the TLS listener remains healthy after the SNICallback throw", server.listening === true);
  } finally {
    try { if (client) client.destroy(); } catch (_e) { /* best-effort */ }
    await _close(server);
  }
}

// ---- listen(): h1 WebSocket upgrade routing ----

async function _rawUpgrade(port, path, extraHeaders) {
  var buf = "";
  var closed = false;
  var sock = net.connect(port, "127.0.0.1", function () {
    var key = crypto.randomBytes(16).toString("base64");
    var lines = [
      "GET " + path + " HTTP/1.1", "Host: localhost:" + port,
      "Upgrade: websocket", "Connection: Upgrade",
      "Sec-WebSocket-Key: " + key, "Sec-WebSocket-Version: 13",
    ].concat(extraHeaders || []);
    sock.write(lines.join("\r\n") + "\r\n\r\n");
  });
  sock.on("data", function (d) { buf += d.toString("latin1"); });
  sock.on("close", function () { closed = true; });
  sock.on("error", function () { closed = true; });
  // A refuse path destroys the socket (close fires); an accepted 101 keeps
  // the socket open, so settle once the response headers are fully framed.
  try {
    await helpers.waitUntil(function () { return closed || /\r\n\r\n/.test(buf); },
      { timeoutMs: 4000, label: "router ws h1 upgrade: response framed or socket closed (" + path + ")" });
  } catch (_e) { /* settle as-is */ }
  return { buf: buf, sock: sock, closed: closed };
}

async function testWsListenH1Upgrade() {
  var r = b.router.create();
  var handlerConn = null;
  r.ws("/ws", function (conn) { handlerConn = conn; }, { origins: "*" });
  r.ws("/h2only", function () {}, { origins: "*", transport: "h2-only" });
  // A route registered WITHOUT origins to drive the startup warn branch.
  r.ws("/noorigins", function () {}, {});

  var server = r.listen(0);
  await _listening(server);
  var port = server.address().port;
  var okSock = null;
  try {
    var unknown = await _rawUpgrade(port, "/not-registered");
    check("h1 upgrade to an unregistered ws path → socket destroyed (no response)",
      unknown.closed === true && unknown.buf === "");

    var h2only = await _rawUpgrade(port, "/h2only");
    check("h1 upgrade to an h2-only ws path → 426 Upgrade Required + 'Upgrade: h2c'",
      /426 Upgrade Required/.test(h2only.buf) && /Upgrade: h2c/.test(h2only.buf));

    var okUp = await _rawUpgrade(port, "/ws");
    okSock = okUp.sock;
    check("a valid h1 ws handshake → 101 Switching Protocols and the handler is invoked",
      /101 Switching Protocols/.test(okUp.buf) && handlerConn !== null);
    await helpers.waitUntil(function () { return r.activeWebSockets() === 1; },
      { timeoutMs: 3000, label: "router ws: upgraded connection tracked" });
    check("activeWebSockets() reflects the open upgraded connection",
      r.activeWebSockets() === 1);

    var closedN = await r.closeWebSockets({ timeoutMs: 200 });
    check("closeWebSockets() closes the live connection and returns the count",
      closedN === 1);
  } finally {
    try { if (okSock) okSock.destroy(); } catch (_e) { /* best-effort */ }
    await _close(server);
  }
}

// ---- listen(): redirect + errorHandler edge branches ----

async function testRedirectAndErrorBranches() {
  var r = b.router.create();   // no allowedRedirectOrigins → empty allowlist
  r.get("/r-nonstring", function (req, res) {
    try { res.redirect(123); } catch (e) { res.writeHead(400); res.end("code:" + e.code); }
  });
  r.get("/r-parsefail", function (req, res) {
    try { res.redirect("http://plain.example.com/x"); } catch (e) { res.writeHead(400); res.end("code:" + e.code); }
  });
  r.get("/r-noallowlist", function (req, res) {
    try { res.redirect("https://valid.example.com/x"); } catch (e) { res.writeHead(400); res.end("code:" + e.code); }
  });
  r.get("/boom", function () { throw new Error("handler-down"); });
  // An error handler that itself throws → the default 500 fallback must still fire.
  r.onError(function () { throw new Error("errorHandler-down"); });

  var server = r.listen(0);
  await _listening(server);
  var port = server.address().port;
  try {
    var nonStr = await _get(port, "/r-nonstring");
    check("res.redirect(non-string) throws router/redirect-target-not-string",
      nonStr.status === 400 && nonStr.body === "code:router/redirect-target-not-string");

    var parseFail = await _get(port, "/r-parsefail");
    check("res.redirect to a non-HTTPS cross-origin target is refused (parse rejects http)",
      parseFail.status === 400 && parseFail.body === "code:router/redirect-cross-origin-refused");

    var noAllow = await _get(port, "/r-noallowlist");
    check("res.redirect cross-origin with an empty allowlist is refused",
      noAllow.status === 400 && noAllow.body === "code:router/redirect-cross-origin-refused");

    var boom = await _get(port, "/boom");
    check("an error handler that itself throws still yields the default 500",
      boom.status === 500 && /Internal Server Error/.test(boom.body));
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
  testConstructorOptionValidation();
  await testPatchAndDeleteVerbs();
  await testHandleEncodedSeparatorRefusals();
  await testPathScopedMiddleware();
  testUseValidationErrors();
  await testMiddlewareErrorRethrows();
  await testWritableEndedBetweenHandlers();
  await testBodySchemaValidation();
  await testValidationErrorSealedBody();
  await testResponseValidatorWarnAndRawEnd();
  test0RttReplayCacheDirect();
  test0RttReplayCacheEviction();
  test0RttFailClosedUnderPci();
  await testTlsListenSetup();
  await testTlsH2Handshake();
  await testTlsSniCallbackThrows();
  await testWsListenH1Upgrade();
  await testRedirectAndErrorBranches();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK router — " + helpers.getChecks() + " checks"); process.exit(0); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
