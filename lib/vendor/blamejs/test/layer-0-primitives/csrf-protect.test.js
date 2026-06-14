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

async function run() {
  await testSuccessPathDoubleSubmit();
  await testMismatchDenied();
  await testPoisonedCookieNamesDoNotPollute();
  await testFirstOccurrenceWinsForDuplicateCookie();
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
