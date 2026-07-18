// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.middleware.hostAllowlist — DNS-rebinding defense.
 *
 * Drives the Host-header allowlist: exact + wildcard-single-label
 * matching, port-agnostic entries, refusal of an off-allowlist or
 * missing Host with HTTP 421, the onDeny hook, and create-time
 * validation.
 *
 * Run standalone: `node test/layer-0-primitives/middleware-host-allowlist.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers   = require("../helpers");
var b         = helpers.b;
var check     = helpers.check;
var _mockReq  = helpers._mockReq;
var _mockRes  = helpers._mockRes;

function _drive(mw, host) {
  var headers = (host === null || host === undefined) ? {} : { host: host };
  var req = _mockReq({ method: "GET", url: "/", headers: headers });
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  var cap = res._captured();
  cap.nextCalled = nextCalled;
  // The problem+json path sets res.statusCode directly (not via
  // writeHead), so surface that property alongside the writeHead status.
  cap.statusCode = res.statusCode;
  return cap;
}

function testExactHostAllowed() {
  var mw = b.middleware.hostAllowlist({ hosts: ["app.example.com"] });
  var cap = _drive(mw, "app.example.com");
  check("hostAllowlist: exact Host match passes through", cap.nextCalled === true);
  check("hostAllowlist: allowed request writes no refusal", cap.status === null);
}

function testCaseInsensitiveMatch() {
  var mw = b.middleware.hostAllowlist({ hosts: ["app.example.com"] });
  var cap = _drive(mw, "APP.Example.COM");
  check("hostAllowlist: Host match is case-insensitive (RFC 7230 §5.4)",
    cap.nextCalled === true);
}

function testWrongHostRefused() {
  var mw = b.middleware.hostAllowlist({ hosts: ["app.example.com"] });
  var cap = _drive(mw, "attacker.evil.com");
  check("hostAllowlist: off-allowlist Host refused with 421", cap.status === 421);
  check("hostAllowlist: refusal does not delegate", cap.nextCalled === false);
  check("hostAllowlist: default refusal body is Misdirected Request",
    cap.body === "Misdirected Request");
}

function testMissingHostRefused() {
  var mw = b.middleware.hostAllowlist({ hosts: ["app.example.com"] });
  var cap = _drive(mw, null);
  check("hostAllowlist: missing Host header refused with 421", cap.status === 421);
  check("hostAllowlist: missing Host does not delegate", cap.nextCalled === false);
}

function testWildcardSingleLabel() {
  var mw = b.middleware.hostAllowlist({ hosts: ["*.example.com"] });
  var single = _drive(mw, "app.example.com");
  check("hostAllowlist: wildcard matches a single label", single.nextCalled === true);
  var multi = _drive(mw, "deep.app.example.com");
  check("hostAllowlist: wildcard does NOT match multiple labels", multi.status === 421);
  var apex = _drive(mw, "example.com");
  check("hostAllowlist: wildcard does NOT match the bare apex", apex.status === 421);
}

function testPortAgnosticEntry() {
  var mw = b.middleware.hostAllowlist({ hosts: ["app.example.com"] });
  var cap = _drive(mw, "app.example.com:8443");
  check("hostAllowlist: entry without a port matches any port", cap.nextCalled === true);
}

function testCustomDenyStatusAndBody() {
  var mw = b.middleware.hostAllowlist({
    hosts:      ["app.example.com"],
    denyStatus: 403,
    denyBody:   "Nope",
  });
  var cap = _drive(mw, "evil.com");
  check("hostAllowlist: custom denyStatus honored", cap.status === 403);
  check("hostAllowlist: custom denyBody honored", cap.body === "Nope");
}

function testOnDenyHookOwnsRefusal() {
  var seen = null;
  var mw = b.middleware.hostAllowlist({
    hosts:  ["app.example.com"],
    onDeny: function (req, res, info) {
      seen = info;
      res.writeHead(499, { "Content-Type": "text/plain" });
      res.end("blocked-by-hook");
    },
  });
  var cap = _drive(mw, "evil.com");
  check("hostAllowlist: onDeny hook owns the refusal response",
    cap.status === 499 && cap.body === "blocked-by-hook");
  check("hostAllowlist: onDeny info carries the reason + host",
    seen && seen.reason === "host-not-in-allowlist" && seen.host === "evil.com");
}

function testProblemDetailsMode() {
  var mw = b.middleware.hostAllowlist({
    hosts:          ["app.example.com"],
    problemDetails: true,
  });
  var cap = _drive(mw, "evil.com");
  check("hostAllowlist: problemDetails emits application/problem+json",
    /application\/problem\+json/.test(cap.headers["content-type"] || ""));
  check("hostAllowlist: problem document carries the 421 status",
    cap.statusCode === 421);
}

function testCreateValidationThrows() {
  function code(fn) {
    try { fn(); return null; } catch (e) { return e.code || e.message; }
  }
  check("hostAllowlist: non-object opts throws",
    code(function () { b.middleware.hostAllowlist(null); }) !== null);
  check("hostAllowlist: empty hosts array throws",
    /no-hosts/.test(code(function () { b.middleware.hostAllowlist({ hosts: [] }); })));
  check("hostAllowlist: non-string host entry throws",
    /bad-host/.test(code(function () { b.middleware.hostAllowlist({ hosts: [42] }); })));
}

function run() {
  testExactHostAllowed();
  testCaseInsensitiveMatch();
  testWrongHostRefused();
  testMissingHostRefused();
  testWildcardSingleLabel();
  testPortAgnosticEntry();
  testCustomDenyStatusAndBody();
  testOnDenyHookOwnsRefusal();
  testProblemDetailsMode();
  testCreateValidationThrows();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.message); process.exit(1); }
  );
}
