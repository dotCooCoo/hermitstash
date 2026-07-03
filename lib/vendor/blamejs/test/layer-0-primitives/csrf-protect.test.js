// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.middleware.csrfProtect — cookie-header parsing prototype-pollution
 * defense (CWE-915 / CWE-1321) + double-submit success path.
 *
 * The Cookie request header is attacker-controlled. The internal cookie
 * parser builds its map from [name, value] pairs through
 * Object.fromEntries onto a null-prototype object — never a computed-
 * write (`out[name] = value`) sink. These tests drive the middleware
 * end-to-end (no internal mocks) to verify:
 *   - a Cookie header carrying `__proto__` / `constructor` / `prototype`
 *     names does NOT pollute Object.prototype;
 *   - a legitimate CSRF cookie alongside those hostile names still
 *     resolves and the double-submit check passes (header token matches);
 *   - first-occurrence-wins is preserved for duplicate cookie names.
 *
 * Run standalone: `node test/layer-0-primitives/csrf-protect.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b        = helpers.b;
var check    = helpers.check;
var _mockReq = helpers._mockReq;
var _mockRes = helpers._mockRes;

// Drive one request through the csrf middleware; resolve to an outcome
// object describing whether next() was called or the request was denied.
function _runCsrf(mwOpts, req) {
  var res = _mockRes();
  return new Promise(function (resolve) {
    var calledNext = false;
    var mw = b.middleware.csrfProtect(mwOpts);
    // denyResponse writes to res + ends it; next() is the success signal.
    // mockRes captures the status via writeHead → res._captured().status.
    var origEnd = res.end;
    res.end = function () {
      var r = origEnd.apply(res, arguments);
      var cap = res._captured();
      resolve({ outcome: "denied", status: cap.status, body: cap.body, req: req, res: res, calledNext: calledNext });
      return r;
    };
    mw(req, res, function () {
      calledNext = true;
      resolve({ outcome: "next", req: req, res: res, calledNext: true });
    });
  });
}

async function testSuccessPathDoubleSubmit() {
  // Valid 64-hex cookie + matching X-CSRF-Token header on a POST → next().
  var token = b.forms.generateCsrfToken();
  var req = _mockReq({
    method: "POST",
    url: "/submit",
    headers: {
      host:         "example.com",
      cookie:       "csrf=" + token,
      "x-csrf-token": token,
    },
  });
  var r = await _runCsrf({ cookie: true }, req);
  check("csrf: valid double-submit passes (next called)", r.outcome === "next");
}

async function testMismatchDenied() {
  var token = b.forms.generateCsrfToken();
  var req = _mockReq({
    method: "POST",
    url: "/submit",
    headers: {
      host:           "example.com",
      cookie:         "csrf=" + token,
      "x-csrf-token": b.forms.generateCsrfToken(),    // different token
    },
  });
  var r = await _runCsrf({ cookie: true }, req);
  check("csrf: token mismatch denied (403)", r.outcome === "denied" && r.status === 403);
}

async function testPoisonedCookieNamesDoNotPollute() {
  // A Cookie header carrying __proto__ / constructor / prototype names
  // alongside the real csrf cookie must not pollute Object.prototype, and
  // the legitimate cookie must still resolve so the double-submit passes.
  var token = b.forms.generateCsrfToken();
  var req = _mockReq({
    method: "POST",
    url: "/submit",
    headers: {
      host:   "example.com",
      cookie: "__proto__=polluted; constructor=evil; prototype=evil2; csrf=" + token + "; other=ok",
      "x-csrf-token": token,
    },
  });
  var r = await _runCsrf({ cookie: true }, req);
  check("csrf: hostile cookie names did not pollute Object.prototype",
        ({}).polluted === undefined &&
        Object.prototype.polluted === undefined &&
        ({}).evil === undefined &&
        ({}).evil2 === undefined);
  check("csrf: legitimate cookie still resolved (double-submit passed)",
        r.outcome === "next");
}

async function testFirstOccurrenceWinsForDuplicateCookie() {
  // RFC 6265 §5.2 — duplicate cookie names resolve to the FIRST occurrence
  // (most-specific path). A later forged `csrf=` must not override the
  // first; the double-submit must validate against the first value.
  var first  = b.forms.generateCsrfToken();
  var second = b.forms.generateCsrfToken();
  var req = _mockReq({
    method: "POST",
    url: "/submit",
    headers: {
      host:           "example.com",
      cookie:         "csrf=" + first + "; csrf=" + second,
      "x-csrf-token": first,                       // matches FIRST occurrence
    },
  });
  var r = await _runCsrf({ cookie: true }, req);
  check("csrf: duplicate cookie resolves to first occurrence (next on first-token submit)",
        r.outcome === "next");

  // Submitting the SECOND value must be rejected — proves first-wins, not
  // last-wins.
  var req2 = _mockReq({
    method: "POST",
    url: "/submit",
    headers: {
      host:           "example.com",
      cookie:         "csrf=" + first + "; csrf=" + second,
      "x-csrf-token": second,
    },
  });
  var r2 = await _runCsrf({ cookie: true }, req2);
  check("csrf: submitting the second (shadowed) cookie value is denied",
        r2.outcome === "denied" && r2.status === 403);
}

function testMethodsEmptyThrows() {
  // An empty methods array would silently disable the primary CSRF method-gate
  // for all state-changing requests — refuse it at config time.
  var threw = null;
  try { b.middleware.csrfProtect({ cookie: true, methods: [] }); } catch (e) { threw = e; }
  check("csrfProtect({ methods: [] }) refused at config time (no silent CSRF disable)",
        threw && /non-empty array/.test(threw.message || ""));
}

// Two distinct csrf instances on the same response (createApp wires csrf
// globally AND an operator re-mounts it at the route level) must issue a
// SINGLE Set-Cookie for the same cookie name — cookie issuance is a
// response-level resource, deduped by name. Enforcement stays per instance
// (the next test).
async function testRedundantMountIssuesSingleCookie() {
  var req = _mockReq({ method: "GET", url: "/", headers: { host: "example.com" } });
  var res = _mockRes();
  var mw1 = b.middleware.csrfProtect({ cookie: true });
  var mw2 = b.middleware.csrfProtect({ cookie: true });
  await new Promise(function (r) { mw1(req, res, r); });
  await new Promise(function (r) { mw2(req, res, r); });
  var sc = res.getHeader("set-cookie");
  var arr = Array.isArray(sc) ? sc : (sc ? [sc] : []);
  var csrfCookies = arr.filter(function (c) { return /^csrf=/.test(c); });
  check("csrf: redundant same-name mount issues a single Set-Cookie",
        csrfCookies.length === 1);
  check("csrf: both instances expose the same req.csrfToken",
        typeof req.csrfToken === "string" && req.csrfToken.length === 64);
}

// The cookie-issuance dedup must NOT disable per-instance enforcement: two
// distinct instances each validate the double-submit token on a POST. A bad
// token reaches a deny regardless of which instance runs first — a shared
// "already handled" flag (the bug the per-instance gate fixed) would let the
// first instance mark the request handled and skip the second's check.
async function testDistinctInstancesBothEnforce() {
  var good = b.forms.generateCsrfToken();
  var req = _mockReq({
    method: "POST", url: "/submit",
    headers: { host: "example.com", cookie: "csrf=" + good, "x-csrf-token": "deadbeef" },
  });
  var res = _mockRes();
  var denied = false;
  var origEnd = res.end;
  res.end = function () { denied = true; return origEnd.apply(res, arguments); };
  var mw = b.middleware.csrfProtect({ cookie: true });
  var nextCalled = false;
  await new Promise(function (r) { mw(req, res, function () { nextCalled = true; r(); }); if (denied) r(); });
  // The instance denies the mismatched token (cookie != header), proving
  // enforcement runs per instance and the cookie-dedup did not mark the
  // request "already handled".
  check("csrf: distinct instance enforces double-submit (bad token denied)",
        denied === true && nextCalled === false);
}

// The Origin/Referer cross-check must canonicalize host case the same way on
// both sides. The candidate Origin is canonicalized via new URL(...).origin
// (lowercases host, strips default port), but the same-origin baseline was
// built by raw `proto + Host` concatenation and the allowedOrigins were
// compared verbatim — so a legitimate same-origin POST whose Host header is
// mixed-case (or carries an explicit default port) was wrongly refused.
async function testOriginCheckCanonicalizesHost() {
  var tok = b.forms.generateCsrfToken();
  var req = _mockReq({
    method: "POST", url: "/submit",
    headers: {
      host:           "App.Example.com",            // mixed-case Host
      origin:         "http://app.example.com",      // lowercased same origin
      cookie:         "csrf=" + tok,
      "x-csrf-token": tok,
    },
  });
  var r = await _runCsrf({ cookie: true, checkOrigin: true }, req);
  check("csrf: same-origin POST with a mixed-case Host is allowed (not cross-origin-refused)",
        r.outcome === "next");

  // A mixed-case allowedOrigins entry must admit the lowercased candidate too.
  var tok2 = b.forms.generateCsrfToken();
  var req2 = _mockReq({
    method: "POST", url: "/submit",
    headers: {
      host:           "app.example.com",
      origin:         "http://cdn.example.com",
      cookie:         "csrf=" + tok2,
      "x-csrf-token": tok2,
    },
  });
  var r2 = await _runCsrf({ cookie: true, checkOrigin: true, allowedOrigins: ["http://CDN.Example.com"] }, req2);
  check("csrf: a mixed-case allowedOrigins entry admits the lowercased Origin",
        r2.outcome === "next");
}

async function run() {
  await testSuccessPathDoubleSubmit();
  await testMismatchDenied();
  await testPoisonedCookieNamesDoNotPollute();
  await testFirstOccurrenceWinsForDuplicateCookie();
  await testRedundantMountIssuesSingleCookie();
  await testDistinctInstancesBothEnforce();
  testMethodsEmptyThrows();
  await testOriginCheckCanonicalizesHost();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    // Re-throw rather than logging e.message: the failure message can
    // echo request-derived cookie names/values fed into the middleware,
    // and writing that to the log unescaped would be log injection
    // (CWE-117). The non-zero exit + thrown stack still surface the
    // failure to the runner.
    function (e) { process.exitCode = 1; throw e; }
  );
}
