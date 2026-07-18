// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.router — the Host header must NOT steer route dispatch.
 *
 * router.handle() derives req.pathname (the value the route matcher AND
 * every path-scoped middleware compare against) from the request target.
 * The Host header is client-controlled: a value like "trusted/admin"
 * bleeds a path segment into WHATWG-URL's pathname parsing, so a request
 * whose request-line is `/x` would dispatch as `/admin/x` while req.url
 * stays `/x`. That desyncs req.pathname from req.url and lets a front
 * proxy that ACLs on the visible request path be bypassed (the proxy sees
 * `/x`, the origin routes `/admin/x`).
 *
 * Validates, driving the public router.handle dispatch path AND a real
 * in-process listen(0) server with a raw-socket request that carries a
 * crafted Host header:
 *   - req.pathname is a pure function of req.url (Host ignored)
 *   - a "/public" request with Host "x/admin" does NOT reach an
 *     "/admin/public" route
 *   - a path-scoped gate is not triggered by a host-injected prefix
 *   - a request with no Host header still routes (localhost-base parity)
 */

var net     = require("node:net");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _req(url, host) {
  var headers = {};
  if (host !== null) headers.host = host === undefined ? "localhost" : host;
  return { method: "GET", url: url, headers: headers };
}

function _res() {
  var res = {
    statusCode:    0,
    headersSent:   false,
    writableEnded: false,
    _body:         "",
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

// The request-line path is `/secret`; the Host header names `x/admin`.
// The router must route `/secret` (or 404 it), never the `/admin/secret`
// route — the Host header is not part of the request target.
async function testHostHeaderDoesNotSteerRoute() {
  var r = b.router.create();
  var adminReached = false;
  var publicReached = false;
  r.get("/admin/secret", function (req, res) {
    adminReached = true;
    res.writeHead(200); res.end("ADMIN");
  });
  r.get("/secret", function (req, res) {
    publicReached = true;
    res.writeHead(200); res.end("public");
  });

  var req = _req("/secret", "localhost/admin");
  var res = _res();
  await r.handle(req, res);

  check("Host header does not bleed into req.pathname (pathname === req.url path)",
    req.pathname === "/secret");
  check("the '/admin/secret' handler is NOT reached by a '/secret' request",
    adminReached === false);
  check("the '/secret' handler IS reached and served",
    publicReached === true && res._body === "public");
}

// A path-scoped gate mounted on "/admin" must not fire for a "/public"
// request merely because the Host header carries "/admin".
async function testHostHeaderDoesNotSteerScopedGate() {
  var r = b.router.create();
  var gateRan = false;
  r.use("/admin", function (req, res, next) {
    gateRan = true;
    res.writeHead(403); res.end("denied");
  });
  r.get("/public", function (req, res) {
    res.writeHead(200); res.end("ok");
  });

  var req = _req("/public", "evil.example/admin");
  var res = _res();
  await r.handle(req, res);

  check("path-scoped '/admin' gate does NOT run on a '/public' request with a host-injected prefix",
    gateRan === false);
  check("the '/public' route is served (200) despite the crafted Host",
    res.statusCode === 200 && res._body === "ok");
}

// A Host header with a leading-dot / traversal shape must likewise not
// reach a route above the request target.
async function testHostTraversalShapeIgnored() {
  var r = b.router.create();
  var hit = null;
  r.get("/a", function (req, res) { hit = "/a"; res.writeHead(200); res.end("a"); });
  r.get("/admin/a", function (req, res) { hit = "/admin/a"; res.writeHead(200); res.end("adm"); });

  var req = _req("/a", "host/../admin");
  var res = _res();
  await r.handle(req, res);
  check("Host 'host/../admin' does not route '/a' as '/admin/a'", hit === "/a" && req.pathname === "/a");
}

// No Host header at all still routes (the fixed internal base gives the
// same result the previous "localhost" fallback did).
async function testNoHostStillRoutes() {
  var r = b.router.create();
  r.get("/a/b", function (req, res) { res.writeHead(200); res.end("ok"); });
  var res = _res();
  await r.handle({ method: "GET", url: "/a/b", headers: {} }, res);
  check("a request with no Host header still routes", res.statusCode === 200 && res._body === "ok");
}

// End-to-end proof through a real in-process HTTP server: a raw socket
// sends `GET /secret` with `Host: localhost/admin`. The `/admin/secret`
// route must NOT be dispatched.
async function testEndToEndRawSocketHostInjection() {
  var r = b.router.create();
  var adminReached = false;
  r.get("/admin/secret", function (req, res) {
    adminReached = true;
    res.writeHead(200, { "content-type": "text/plain" }); res.end("ADMIN-REACHED");
  });
  r.onNotFound(function (req, res) { res.writeHead(404); res.end("nf"); });

  var server = r.listen(0);
  await helpers.waitUntil(function () {
    return server.address() && typeof server.address().port === "number";
  }, { timeoutMs: 5000, label: "router-host-injection: server listening" });
  var port = server.address().port;

  var responseText = await new Promise(function (resolve, reject) {
    var sock = net.connect(port, "127.0.0.1", function () {
      sock.write("GET /secret HTTP/1.1\r\nHost: localhost/admin\r\nConnection: close\r\n\r\n");
    });
    var chunks = [];
    sock.on("data", function (c) { chunks.push(c); });
    sock.on("close", function () { resolve(Buffer.concat(chunks).toString("utf8")); });
    sock.on("error", reject);
  });

  await new Promise(function (resolve) { server.close(resolve); });

  check("e2e: real server does NOT dispatch '/admin/secret' for a '/secret' request line",
    adminReached === false);
  check("e2e: response did not carry the admin handler body",
    responseText.indexOf("ADMIN-REACHED") === -1);
}

// A request target that is not origin-form (a single leading "/") must be
// rejected with 400, never coerced into a routable path. Prefixing a bare or
// absolute-form target with "/" would let it match a param/catch-all route
// ("foo" -> "/foo" matches "/:seg"; "http://evil/admin" -> "/http://evil/admin")
// — the opposite of failing closed.
async function testNonOriginFormTargetRejected() {
  var r = b.router.create();
  var reachedSeg = null;
  var seenReqUrl = null;
  r.get("/:seg", function (req, res) { reachedSeg = req.params.seg; seenReqUrl = req.url; res.writeHead(200); res.end("SEG:" + req.params.seg); });

  // Bare relative target (no leading slash) — pre-fix this was prefixed to
  // "/foo" and matched the /:seg route.
  var res1 = _res();
  await r.handle(_req("foo", "localhost"), res1);
  check("a bare (non-slash) request target is rejected 400, not coerced to /foo",
    res1.statusCode === 400 && reachedSeg === null);

  // Absolute-form (the reviewer's example).
  var res2 = _res();
  await r.handle(_req("http://evil.example/admin", "localhost"), res2);
  check("an absolute-form request target is rejected 400", res2.statusCode === 400);

  // A "/"-leading target with a redundant leading slash (//seg) is a valid
  // absolute-path (empty first segment), NOT rejected. But left intact it stays
  // a network-path reference, so a downstream `new URL(req.url, base)` reader
  // would parse the first segment as an AUTHORITY (Host bleed). The router
  // collapses the leading slash run to a single "/" and writes it back to
  // req.url, so it routes as an ordinary path and every req.url reader sees a
  // pure path — never a host.
  var res3 = _res();
  await r.handle(_req("//evil.example", "localhost"), res3);
  check("a //-leading target is accepted (not 400) and normalized to a single leading slash",
    res3.statusCode !== 400 && reachedSeg === "evil.example" && seenReqUrl === "/evil.example");
  reachedSeg = null; seenReqUrl = null;

  // Asterisk-form (OPTIONS *).
  var res4 = _res();
  await r.handle({ method: "OPTIONS", url: "*", headers: { host: "localhost" } }, res4);
  check("an asterisk-form target (OPTIONS *) is rejected 400", res4.statusCode === 400);

  // Sanity: a normal origin-form target still routes.
  var res5 = _res();
  await r.handle(_req("/hello", "localhost"), res5);
  check("a normal origin-form target still routes to /:seg",
    reachedSeg === "hello" && res5._body === "SEG:hello");
}

async function run() {
  await testHostHeaderDoesNotSteerRoute();
  await testHostHeaderDoesNotSteerScopedGate();
  await testHostTraversalShapeIgnored();
  await testNoHostStillRoutes();
  await testNonOriginFormTargetRejected();
  await testEndToEndRawSocketHostInjection();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("router host-path-injection tests passed — " + helpers.getChecks() + " checks"); process.exit(0); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
