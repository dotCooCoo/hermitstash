// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.middleware.webAppManifest — W3C Web App Manifest server.
 *
 * Drives the served-path, the optional /manifest.json alias, the
 * method gate, and the create-time validation of the W3C-required
 * fields (name / start_url / icons) plus the field allowlist.
 *
 * Run standalone: `node test/layer-0-primitives/middleware-web-app-manifest.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers   = require("../helpers");
var b         = helpers.b;
var check     = helpers.check;
var _mockReq  = helpers._mockReq;
var _mockRes  = helpers._mockRes;

var BASE = {
  name:      "Example App",
  start_url: "/",
  display:   "standalone",
  icons: [
    { src: "/icons/192.png", sizes: "192x192", type: "image/png" },
    { src: "/icons/512.png", sizes: "512x512", type: "image/png" },
  ],
};

function _drive(mw, method, url) {
  var res = _mockRes();
  var nextCalled = false;
  mw(_mockReq({ method: method, url: url }), res, function () { nextCalled = true; });
  var cap = res._captured();
  cap.nextCalled = nextCalled;
  return cap;
}

function testServesWebmanifest() {
  var mw = b.middleware.webAppManifest(BASE);
  var cap = _drive(mw, "GET", "/manifest.webmanifest");
  check("webAppManifest: served with HTTP 200", cap.status === 200);
  check("webAppManifest: Content-Type is application/manifest+json",
    cap.headers["content-type"] === "application/manifest+json");
  check("webAppManifest: nosniff header present",
    cap.headers["x-content-type-options"] === "nosniff");
  var parsed = JSON.parse(cap.body);
  check("webAppManifest: body carries the manifest fields",
    parsed.name === "Example App" && parsed.start_url === "/" && parsed.icons.length === 2);
  check("webAppManifest: internal opts (audit) are not leaked into the body",
    parsed.audit === undefined && parsed.alsoAtJsonPath === undefined);
}

function testJsonAliasOptIn() {
  var without = b.middleware.webAppManifest(BASE);
  var capOff = _drive(without, "GET", "/manifest.json");
  check("webAppManifest: /manifest.json NOT served by default", capOff.nextCalled === true);

  var withAlias = b.middleware.webAppManifest(Object.assign({ alsoAtJsonPath: true }, BASE));
  var capOn = _drive(withAlias, "GET", "/manifest.json");
  check("webAppManifest: /manifest.json served when alsoAtJsonPath:true", capOn.status === 200);
  // The canonical path still serves regardless.
  var capCanonical = _drive(withAlias, "GET", "/manifest.webmanifest");
  check("webAppManifest: canonical path still served alongside the alias",
    capCanonical.status === 200);
}

function testNonMatchingPathPassesThrough() {
  var mw = b.middleware.webAppManifest(BASE);
  var cap = _drive(mw, "GET", "/index.html");
  check("webAppManifest: unrelated path delegates via next()", cap.nextCalled === true);
}

function testHeadServesNoBody() {
  var mw = b.middleware.webAppManifest(BASE);
  var cap = _drive(mw, "HEAD", "/manifest.webmanifest");
  check("webAppManifest: HEAD returns 200 with no body",
    cap.status === 200 && cap.body === "");
}

function testMethodGate() {
  var mw = b.middleware.webAppManifest(BASE);
  var cap = _drive(mw, "POST", "/manifest.webmanifest");
  check("webAppManifest: POST refused with 405", cap.status === 405);
  check("webAppManifest: 405 advertises Allow: GET, HEAD",
    cap.headers["allow"] === "GET, HEAD");
}

function testCreateValidationThrows() {
  function code(fn) {
    try { fn(); return null; } catch (e) { return e.code || e.message; }
  }
  check("webAppManifest: missing name throws",
    /no-name/.test(code(function () {
      b.middleware.webAppManifest({ start_url: "/", icons: BASE.icons });
    })));
  check("webAppManifest: missing start_url throws",
    /no-start-url/.test(code(function () {
      b.middleware.webAppManifest({ name: "X", icons: BASE.icons });
    })));
  check("webAppManifest: missing icons throws",
    /no-icons/.test(code(function () {
      b.middleware.webAppManifest({ name: "X", start_url: "/" });
    })));
  check("webAppManifest: empty icons array throws",
    /no-icons/.test(code(function () {
      b.middleware.webAppManifest({ name: "X", start_url: "/", icons: [] });
    })));
  check("webAppManifest: field outside the W3C allowlist throws (typo surfacing)",
    code(function () {
      b.middleware.webAppManifest(Object.assign({ nam: "typo" }, BASE));
    }) !== null);
}

function run() {
  testServesWebmanifest();
  testJsonAliasOptIn();
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
