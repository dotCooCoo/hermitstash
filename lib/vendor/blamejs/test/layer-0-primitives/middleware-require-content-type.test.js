// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.middleware.requireContentType — MIME-confusion refusal.
 *
 * Drives the RFC 9110 §15.5.16 415 gate: body-bearing verbs whose
 * Content-Type is off the allowlist are refused with an Accept header;
 * idempotent verbs bypass; parameters (charset) are ignored on the
 * bare type; the methods override + onDeny hook + create-time
 * validation are exercised.
 *
 * Run standalone: `node test/layer-0-primitives/middleware-require-content-type.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _drive(mw, method, contentType) {
  var headers = contentType ? { "content-type": contentType } : {};
  var req = { method: method, url: "/api/echo", headers: headers };
  var res = b.testing.mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  var cap = res._captured();
  cap.nextCalled = nextCalled;
  return cap;
}

function testAllowedTypePasses() {
  var mw = b.middleware.requireContentType(["application/json"]);
  var cap = _drive(mw, "POST", "application/json");
  check("requireContentType: allowed Content-Type passes through", cap.nextCalled === true);
  check("requireContentType: allowed request writes no refusal", cap.status === null);
}

function testCharsetParameterIgnored() {
  var mw = b.middleware.requireContentType(["application/json"]);
  var cap = _drive(mw, "POST", "application/json; charset=utf-8");
  check("requireContentType: charset parameter ignored on the bare type",
    cap.nextCalled === true);
}

function testWrongTypeRefused() {
  var mw = b.middleware.requireContentType(["application/json"]);
  var cap = _drive(mw, "POST", "application/x-www-form-urlencoded");
  check("requireContentType: off-allowlist type refused with 415", cap.status === 415);
  check("requireContentType: refusal does not delegate", cap.nextCalled === false);
  check("requireContentType: 415 advertises the accepted types via Accept",
    cap.headers["accept"] === "application/json");
}

function testAbsentTypeRefused() {
  var mw = b.middleware.requireContentType(["application/json"]);
  var cap = _drive(mw, "PUT", null);
  check("requireContentType: absent Content-Type on a body verb refused with 415",
    cap.status === 415 && cap.nextCalled === false);
}

function testIdempotentVerbsBypass() {
  var mw = b.middleware.requireContentType(["application/json"]);
  var get = _drive(mw, "GET", null);
  check("requireContentType: GET bypasses the check", get.nextCalled === true);
  var del = _drive(mw, "DELETE", "text/plain");
  check("requireContentType: DELETE bypasses by default (no body verb)",
    del.nextCalled === true);
}

function testMethodsOverride() {
  // Operators enforcing content-type on a rare DELETE-with-body shape.
  var mw = b.middleware.requireContentType(["application/json"], { methods: ["DELETE"] });
  var refused = _drive(mw, "DELETE", "text/plain");
  check("requireContentType: methods override enforces on DELETE", refused.status === 415);
  var passed = _drive(mw, "POST", "text/plain");
  check("requireContentType: methods override removes the default POST enforcement",
    passed.nextCalled === true);
}

function testOnDenyHookOwnsRefusal() {
  var seen = null;
  var mw = b.middleware.requireContentType(["application/json"], {
    onDeny: function (req, res, info) {
      seen = info;
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end("bad-type");
    },
  });
  var cap = _drive(mw, "POST", "text/xml");
  check("requireContentType: onDeny hook owns the refusal",
    cap.status === 400 && cap.body === "bad-type");
  check("requireContentType: onDeny info carries the offending + accepted types",
    seen && seen.contentType === "text/xml" && seen.accepted.indexOf("application/json") !== -1);
}

function testCreateValidationThrows() {
  function code(fn) {
    try { fn(); return null; } catch (e) { return e.code || e.message; }
  }
  check("requireContentType: empty allowlist throws",
    /no-allowlist/.test(code(function () { b.middleware.requireContentType([]); })));
  check("requireContentType: non-array allowlist throws",
    /no-allowlist/.test(code(function () { b.middleware.requireContentType("application/json"); })));
  check("requireContentType: non-string entry throws",
    /no-allowlist/.test(code(function () { b.middleware.requireContentType([42]); })));
}

function run() {
  testAllowedTypePasses();
  testCharsetParameterIgnored();
  testWrongTypeRefused();
  testAbsentTypeRefused();
  testIdempotentVerbsBypass();
  testMethodsOverride();
  testOnDenyHookOwnsRefusal();
  testCreateValidationThrows();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.message); process.exit(1); }
  );
}
