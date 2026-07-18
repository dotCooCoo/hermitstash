// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.middleware.cookies — inbound Cookie-header threat detection.
 *
 * Drives the request-lifecycle wrapper around b.cookies.parseSafe:
 * populates req.cookieJar, refuses on a HIGH-severity issue in enforce
 * mode, passes through (but still parses) in audit-only mode, and is
 * idempotent when a jar is already present.
 *
 * Run standalone: `node test/layer-0-primitives/middleware-cookies.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers   = require("../helpers");
var b         = helpers.b;
var check     = helpers.check;
var _mockReq  = helpers._mockReq;
var _mockRes  = helpers._mockRes;

function testCleanCookiePopulatesJar() {
  var mw = b.middleware.cookies({ mode: "enforce" });
  var req = _mockReq({ headers: { cookie: "sid=abc; theme=dark" } });
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("cookies: clean header delegates via next()", nextCalled === true);
  check("cookies: req.cookieJar populated with parsed pairs",
    req.cookieJar.sid === "abc" && req.cookieJar.theme === "dark");
}

function testEnforceRefusesDuplicateName() {
  // Cookie-tossing: a duplicate name is a HIGH issue; enforce mode
  // refuses with HTTP 400 + JSON body and does NOT call next().
  var mw = b.middleware.cookies({ mode: "enforce" });
  var req = _mockReq({ headers: { cookie: "session=abc; session=evil" } });
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("cookies: enforce refuses HIGH-severity issue with 400", res.statusCode === 400);
  check("cookies: refusal does not delegate to the handler", nextCalled === false);
  var body = JSON.parse(res._captured().body);
  check("cookies: refusal body names the threat",
    body.error === "cookie-threat-detected" &&
    body.issues.some(function (i) { return i.kind === "duplicate-name" && i.severity === "high"; }));
}

function testAuditOnlyPassesThroughButParses() {
  var mw = b.middleware.cookies({ mode: "audit-only" });
  var req = _mockReq({ headers: { cookie: "session=abc; session=evil" } });
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("cookies: audit-only passes the request through", nextCalled === true);
  check("cookies: audit-only still populates the jar (last-write-wins)",
    req.cookieJar.session === "evil");
  check("cookies: audit-only writes no refusal status", res.statusCode === null);
}

function testAuditSinkReceivesThreat() {
  var audit = b.testing.captureAudit();
  var mw = b.middleware.cookies({ mode: "enforce", audit: audit });
  var req = _mockReq({ headers: { cookie: "session=abc; session=evil" } });
  mw(req, _mockRes(), function () {});
  check("cookies: threat routed to the audit sink",
    audit.captured.some(function (e) { return e.action === "middleware.cookies.threat-detected"; }));
}

function testIdempotentWhenJarPresent() {
  var mw = b.middleware.cookies({ mode: "enforce" });
  var req = _mockReq({ headers: { cookie: "session=abc; session=evil" } });
  // A prior cookies middleware already parsed the jar this request.
  req.cookieJar = { session: "trusted" };
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("cookies: idempotent — pre-existing jar is not re-parsed or refused",
    nextCalled === true && req.cookieJar.session === "trusted" && res.statusCode === null);
}

function testControlByteRefused() {
  var mw = b.middleware.cookies({ mode: "enforce" });
  var req = _mockReq({ headers: { cookie: "a=1\r\nSet-Cookie: evil=1" } });
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("cookies: CR/LF control-byte header refused with 400",
    res.statusCode === 400 && nextCalled === false);
}

function run() {
  testCleanCookiePopulatesJar();
  testEnforceRefusesDuplicateName();
  testAuditOnlyPassesThroughButParses();
  testAuditSinkReceivesThreat();
  testIdempotentWhenJarPresent();
  testControlByteRefused();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.message); process.exit(1); }
  );
}
