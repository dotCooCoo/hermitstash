// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.middleware.assetlinks — Digital Asset Links at
 * `/.well-known/assetlinks.json`.
 *
 * Drives the served-path, non-matching-path pass-through, method gate,
 * and create-time validation of the advertised middleware.
 *
 * Run standalone: `node test/layer-0-primitives/middleware-assetlinks.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers   = require("../helpers");
var b         = helpers.b;
var check     = helpers.check;
var _mockReq  = helpers._mockReq;
var _mockRes  = helpers._mockRes;

var STATEMENTS = [{
  relation: ["delegate_permission/common.handle_all_urls"],
  target: {
    namespace:                "android_app",
    package_name:             "com.example.app",
    sha256_cert_fingerprints: ["AB:CD:EF:01:23:45:67:89"],
  },
}];

function _drive(mw, req) {
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  var cap = res._captured();
  cap.nextCalled = nextCalled;
  return cap;
}

function testServesWellKnownPath() {
  var mw = b.middleware.assetlinks({ statements: STATEMENTS });
  var cap = _drive(mw, _mockReq({ method: "GET", url: "/.well-known/assetlinks.json" }));
  check("assetlinks: served with HTTP 200", cap.status === 200);
  check("assetlinks: Content-Type is application/json",
    /application\/json/.test(cap.headers["content-type"]));
  check("assetlinks: nosniff header present",
    cap.headers["x-content-type-options"] === "nosniff");
  var parsed = JSON.parse(cap.body);
  check("assetlinks: body is the statements array",
    Array.isArray(parsed) && parsed[0].target.package_name === "com.example.app");
  check("assetlinks: did not delegate via next()", cap.nextCalled === false);
}

function testQueryStringIgnoredOnMatch() {
  var mw = b.middleware.assetlinks({ statements: STATEMENTS });
  var cap = _drive(mw, _mockReq({ method: "GET", url: "/.well-known/assetlinks.json?v=2" }));
  check("assetlinks: query string does not defeat the path match", cap.status === 200);
}

function testNonMatchingPathPassesThrough() {
  var mw = b.middleware.assetlinks({ statements: STATEMENTS });
  var cap = _drive(mw, _mockReq({ method: "GET", url: "/some/other/path" }));
  check("assetlinks: non-matching path delegates via next()", cap.nextCalled === true);
  check("assetlinks: non-matching path writes no response", cap.status === null);
}

function testHeadServesNoBody() {
  var mw = b.middleware.assetlinks({ statements: STATEMENTS });
  var cap = _drive(mw, _mockReq({ method: "HEAD", url: "/.well-known/assetlinks.json" }));
  check("assetlinks: HEAD returns 200 with no body", cap.status === 200 && cap.body === "");
}

function testMethodGate() {
  var mw = b.middleware.assetlinks({ statements: STATEMENTS });
  var cap = _drive(mw, _mockReq({ method: "POST", url: "/.well-known/assetlinks.json" }));
  check("assetlinks: POST refused with 405", cap.status === 405);
  check("assetlinks: 405 advertises Allow: GET, HEAD", cap.headers["allow"] === "GET, HEAD");
}

function testCreateValidationThrows() {
  function code(fn) {
    try { fn(); return null; } catch (e) { return e.code || e.message; }
  }
  check("assetlinks: non-object opts throws",
    code(function () { b.middleware.assetlinks(null); }) !== null);
  check("assetlinks: empty statements array throws",
    /no-statements/.test(code(function () { b.middleware.assetlinks({ statements: [] }); })));
  check("assetlinks: statement missing relation throws",
    /bad-statement/.test(code(function () {
      b.middleware.assetlinks({ statements: [{ target: { namespace: "android_app" } }] });
    })));
  check("assetlinks: statement missing target throws",
    /bad-statement/.test(code(function () {
      b.middleware.assetlinks({ statements: [{ relation: ["x"] }] });
    })));
}

function run() {
  testServesWellKnownPath();
  testQueryStringIgnoredOnMatch();
  testNonMatchingPathPassesThrough();
  testHeadServesNoBody();
  testMethodGate();
  testCreateValidationThrows();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.message); process.exit(1); }
  );
}
