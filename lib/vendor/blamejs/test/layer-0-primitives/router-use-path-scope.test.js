// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.router — path-scoped middleware: `use(prefix, mw)`.
 *
 * The router supports both `use(mw)` (global, runs on every request)
 * and `use(prefix, mw)` (runs only when the request path is at or
 * beneath `prefix`, matched on segment boundaries). The path-scoped
 * form is the documented mounting shape for the framework's access-
 * refusal middleware (`csrf`, `bearerAuth`, `requireAal`,
 * `requireStepUp`, `requireMtls`, …): an operator writes
 * `router.use("/admin", stepUpGate)` to gate everything under /admin.
 *
 * Validates, driving requests end-to-end through router.handle:
 *   - a path-scoped gate runs for a matching path and NOT for a
 *     non-matching one (no silent security-control bypass, no 500)
 *   - segment-boundary matching: "/admin" does not match "/administrator"
 *   - registration order: a gate registered before a route runs first
 *   - global `use(mw)` still runs on every request (back-compat)
 *   - multi-middleware scoped mounts preserve order
 *   - array-of-prefixes scopes a gate to several path roots
 *   - trailing-slash normalization ("/admin" == "/admin/")
 *   - config-time throws on a bad prefix / missing or non-function
 *     middleware (entry-point validation tier)
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _req(url) {
  // router.handle parses req.url against the Host header to derive
  // req.pathname; a minimal request shape is enough to drive dispatch.
  return { method: "GET", url: url, headers: { host: "localhost" } };
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

async function testScopedGateRunsOnlyUnderPrefix() {
  var r = b.router.create();
  var gateRanFor = [];
  r.use("/admin", function gate(req, res, next) {
    gateRanFor.push(req.pathname);
    next();
  });
  r.get("/admin/secret", function (req, res) { res.statusCode = 200; res.end("admin"); });
  r.get("/public",       function (req, res) { res.statusCode = 200; res.end("public"); });

  var resPublic = _res();
  await r.handle(_req("/public"), resPublic);
  check("use('/admin', gate): gate does NOT run for /public",
        gateRanFor.length === 0 && resPublic.statusCode === 200 &&
        resPublic._body === "public");

  var resAdmin = _res();
  await r.handle(_req("/admin/secret"), resAdmin);
  check("use('/admin', gate): gate runs for /admin/secret",
        gateRanFor.length === 1 && gateRanFor[0] === "/admin/secret" &&
        resAdmin.statusCode === 200 && resAdmin._body === "admin");
}

async function testGateCanRefuseUnderPrefix() {
  // A scoped gate that does NOT call next() halts the chain (a refusal)
  // — and only for the scoped path. The route handler under the prefix
  // never runs; an unrelated path is untouched.
  var r = b.router.create();
  r.use("/admin", function deny(req, res /*, next */) {
    res.writeHead(403, { "Content-Type": "text/plain" });
    res.end("forbidden");
    // no next() — chain stops
  });
  var adminHandlerRan = false;
  r.get("/admin/secret", function (req, res) { adminHandlerRan = true; res.statusCode = 200; res.end("admin"); });
  r.get("/public",       function (req, res) { res.statusCode = 200; res.end("public"); });

  var resAdmin = _res();
  await r.handle(_req("/admin/secret"), resAdmin);
  check("use('/admin', deny): refusal halts the chain under /admin",
        resAdmin.statusCode === 403 && resAdmin._body === "forbidden" &&
        adminHandlerRan === false);

  var resPublic = _res();
  await r.handle(_req("/public"), resPublic);
  check("use('/admin', deny): /public unaffected by the /admin refusal",
        resPublic.statusCode === 200 && resPublic._body === "public");
}

async function testSegmentBoundaryNotPrefixSubstring() {
  var r = b.router.create();
  var gateRan = false;
  r.use("/admin", function (req, res, next) { gateRan = true; next(); });
  r.get("/administrator", function (req, res) { res.statusCode = 200; res.end("ator"); });

  var res1 = _res();
  await r.handle(_req("/administrator"), res1);
  check("use('/admin', gate): '/admin' does NOT match '/administrator' (segment boundary)",
        gateRan === false && res1.statusCode === 200 && res1._body === "ator");
}

async function testExactPrefixMatch() {
  var r = b.router.create();
  var gateRan = false;
  r.use("/admin", function (req, res, next) { gateRan = true; next(); });
  r.get("/admin", function (req, res) { res.statusCode = 200; res.end("exact"); });

  var res1 = _res();
  await r.handle(_req("/admin"), res1);
  check("use('/admin', gate): gate runs for the exact path '/admin'",
        gateRan === true && res1.statusCode === 200 && res1._body === "exact");
}

async function testRegistrationOrderPreserved() {
  // A gate registered before a route must run before the route handler;
  // a global middleware registered after the scoped gate runs after it.
  var r = b.router.create();
  var order = [];
  r.use(function global1(req, res, next) { order.push("global1"); next(); });
  r.use("/admin", function adminGate(req, res, next) { order.push("adminGate"); next(); });
  r.use(function global2(req, res, next) { order.push("global2"); next(); });
  r.get("/admin/x", function (req, res) { order.push("route"); res.statusCode = 200; res.end("x"); });

  var res1 = _res();
  await r.handle(_req("/admin/x"), res1);
  check("registration order: global1 → adminGate → global2 → route",
        order.join(",") === "global1,adminGate,global2,route");
}

async function testGlobalUseStillRunsEverywhere() {
  var r = b.router.create();
  var seen = [];
  r.use(function (req, res, next) { seen.push(req.pathname); next(); });
  r.get("/a", function (req, res) { res.statusCode = 200; res.end("a"); });
  r.get("/b", function (req, res) { res.statusCode = 200; res.end("b"); });

  await r.handle(_req("/a"), _res());
  await r.handle(_req("/b"), _res());
  check("global use(mw) runs on every request (back-compat)",
        seen.length === 2 && seen[0] === "/a" && seen[1] === "/b");
}

async function testMultiMiddlewareScopedOrder() {
  var r = b.router.create();
  var order = [];
  r.use("/api",
    function (req, res, next) { order.push("first"); next(); },
    function (req, res, next) { order.push("second"); next(); });
  r.get("/api/users", function (req, res) { order.push("route"); res.statusCode = 200; res.end("u"); });

  var res1 = _res();
  await r.handle(_req("/api/users"), res1);
  check("use(prefix, mw1, mw2): both run in order before the route",
        order.join(",") === "first,second,route");

  // And they do NOT run off-prefix.
  var offOrder = order.length;
  r.get("/other", function (req, res) { res.statusCode = 200; res.end("o"); });
  await r.handle(_req("/other"), _res());
  check("use(prefix, mw1, mw2): neither runs off-prefix",
        order.length === offOrder);
}

async function testArrayOfPrefixes() {
  var r = b.router.create();
  var hits = [];
  r.use(["/caldav", "/carddav"], function (req, res, next) { hits.push(req.pathname); next(); });
  r.get("/caldav/cal",   function (req, res) { res.statusCode = 200; res.end("cal"); });
  r.get("/carddav/card", function (req, res) { res.statusCode = 200; res.end("card"); });
  r.get("/jmap",         function (req, res) { res.statusCode = 200; res.end("jmap"); });

  await r.handle(_req("/caldav/cal"), _res());
  await r.handle(_req("/carddav/card"), _res());
  await r.handle(_req("/jmap"), _res());
  check("use([prefixA, prefixB], mw): runs under either prefix, not elsewhere",
        hits.length === 2 &&
        hits.indexOf("/caldav/cal") !== -1 &&
        hits.indexOf("/carddav/card") !== -1);
}

async function testTrailingSlashNormalized() {
  var r = b.router.create();
  var gateRan = [];
  r.use("/admin/", function (req, res, next) { gateRan.push(req.pathname); next(); });
  r.get("/admin",   function (req, res) { res.statusCode = 200; res.end("a"); });
  r.get("/admin/x", function (req, res) { res.statusCode = 200; res.end("x"); });

  await r.handle(_req("/admin"), _res());
  await r.handle(_req("/admin/x"), _res());
  check("use('/admin/', gate): trailing slash normalized — matches /admin and /admin/x",
        gateRan.length === 2 &&
        gateRan.indexOf("/admin") !== -1 &&
        gateRan.indexOf("/admin/x") !== -1);
}

async function testEncodedPathDoesNotBypassScopedGate() {
  // A path-scoped security gate must fire for every request a downstream
  // consumer (b.staticServe / router.serveStatic) would treat as being under
  // the prefix. Those consumers percent-decode the path before resolving the
  // resource; if the gate matched the still-encoded pathname, an attacker
  // could encode a character in the guarded segment ("/%61dmin/secret") or
  // hide a separator ("/admin%2fsecret") to slip past the gate while the
  // consumer still reached the protected resource — an authn/authz/CSRF/mTLS
  // bypass. The router now refuses an encoded separator / NUL and decodes the
  // path once, so the gate and every consumer share one canonical path.
  var r = b.router.create();
  var gateRanFor = [];
  r.use("/admin", function deny(req, res /*, next*/) {
    gateRanFor.push(req.pathname);
    res.writeHead(403, { "Content-Type": "text/plain" });
    res.end("forbidden");
  });
  r.get("/admin/secret", function (req, res) { res.statusCode = 200; res.end("admin"); });

  // Control — the plain path is gated.
  var ctl = _res();
  await r.handle(_req("/admin/secret"), ctl);
  check("encoded-path: plain /admin/secret is gated (403)", ctl.statusCode === 403);

  // An encoded character in the guarded segment must still match the gate
  // (it decodes to /admin/secret before matching).
  var enc = _res();
  await r.handle(_req("/%61dmin/secret"), enc);
  check("encoded-path: /%61dmin/secret cannot bypass the /admin gate",
        enc.statusCode === 403 && gateRanFor.indexOf("/admin/secret") !== -1);

  // An encoded path separator / backslash / NUL is refused outright — these
  // have no legitimate routing use and would let a consumer rejoin segments
  // the gate split on.
  var sep = _res();
  await r.handle(_req("/admin%2fsecret"), sep);
  check("encoded-path: /admin%2fsecret refused 400 (encoded separator)", sep.statusCode === 400);
  var bsl = _res();
  await r.handle(_req("/admin%5csecret"), bsl);
  check("encoded-path: /admin%5csecret refused 400 (encoded backslash)", bsl.statusCode === 400);
  var nul = _res();
  await r.handle(_req("/admin/se%00cret"), nul);
  check("encoded-path: %00 in path refused 400", nul.statusCode === 400);

  // A legitimate percent-escape (space) decodes rather than being refused,
  // and the gate still fires.
  var spc = _res();
  await r.handle(_req("/admin/a%20b"), spc);
  check("encoded-path: legit %20 decoded and still gated (403, not 400)", spc.statusCode === 403);

  // Malformed percent-encoding is refused, not passed through raw.
  var bad = _res();
  await r.handle(_req("/admin/%zz"), bad);
  check("encoded-path: malformed %zz refused 400", bad.statusCode === 400);
}

function _throwCode(fn) {
  try { fn(); return null; }
  catch (e) { return (e && e.code) || (e && e.constructor && e.constructor.name) || "threw"; }
}

function testConfigTimeThrows() {
  var r = b.router.create();
  check("use(123, mw) throws (non-string prefix)",
        _throwCode(function () { r.use(123, function () {}); }) === "router/use-bad-first-arg");
  check("use('/x', 'notafn') throws (non-function middleware)",
        _throwCode(function () { r.use("/x", "notafn"); }) === "router/use-middleware-not-function");
  check("use('noslash', mw) throws (prefix must begin with '/')",
        _throwCode(function () { r.use("noslash", function () {}); }) === "router/use-prefix-not-absolute");
  check("use() throws (no arguments)",
        _throwCode(function () { r.use(); }) === "router/use-no-args");
  check("use('/x') throws (no middleware after prefix)",
        _throwCode(function () { r.use("/x"); }) === "router/use-no-middleware");
  check("use([], mw) throws (empty prefix array)",
        _throwCode(function () { r.use([], function () {}); }) === "router/use-empty-prefix-array");
  check("use(['/x', 123], mw) throws (non-string entry in prefix array)",
        _throwCode(function () { r.use(["/x", 123], function () {}); }) === "router/use-prefix-not-string");
  check("use(null, mw) throws (null first arg)",
        _throwCode(function () { r.use(null, function () {}); }) === "router/use-bad-first-arg");
}

async function run() {
  await testScopedGateRunsOnlyUnderPrefix();
  await testGateCanRefuseUnderPrefix();
  await testSegmentBoundaryNotPrefixSubstring();
  await testExactPrefixMatch();
  await testRegistrationOrderPreserved();
  await testGlobalUseStillRunsEverywhere();
  await testMultiMiddlewareScopedOrder();
  await testArrayOfPrefixes();
  await testTrailingSlashNormalized();
  await testEncodedPathDoesNotBypassScopedGate();
  testConfigTimeThrows();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("router path-scoped use tests passed"); process.exit(0); },
    function (e) { console.error(e); process.exit(1); }
  );
}
