// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.middleware.clearSiteData — RFC 9527 Clear-Site-Data middleware.
 *
 * Layer 0 primitive coverage:
 *   - default token set on logout-style routes
 *   - operator-supplied subset
 *   - unknown-token refusal (config-time throw)
 *   - empty-array refusal
 *   - non-array refusal
 *   - wildcard token support
 *   - constants surface (KNOWN_TYPES + DEFAULT_TYPES)
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

function _mkRes() {
  var hdrs = {};
  return {
    _hdrs: hdrs,
    setHeader: function (k, v) { hdrs[k] = v; },
  };
}

function testDefaultTypes() {
  var mw = b.middleware.clearSiteData();
  var res = _mkRes();
  mw({}, res, function () {});
  check("clearSiteData: default emits cookies + storage + cache + executionContexts",
    res._hdrs["Clear-Site-Data"] === '"cookies", "storage", "cache", "executionContexts"');
}

function testOperatorSubset() {
  var mw = b.middleware.clearSiteData({ types: ["cache"] });
  var res = _mkRes();
  mw({}, res, function () {});
  check("clearSiteData: subset of types honored",
    res._hdrs["Clear-Site-Data"] === '"cache"');
}

function testWildcard() {
  var mw = b.middleware.clearSiteData({ types: ["*"] });
  var res = _mkRes();
  mw({}, res, function () {});
  check("clearSiteData: wildcard '*' allowed",
    res._hdrs["Clear-Site-Data"] === '"*"');
}

function testClientHints() {
  var mw = b.middleware.clearSiteData({ types: ["clientHints"] });
  var res = _mkRes();
  mw({}, res, function () {});
  check("clearSiteData: clientHints (2024 RFC 9527 revision) accepted",
    res._hdrs["Clear-Site-Data"] === '"clientHints"');
}

function testUnknownTokenRefused() {
  var threw = false;
  try { b.middleware.clearSiteData({ types: ["bogus"] }); }
  catch (e) { threw = e instanceof TypeError && /unknown type/.test(e.message); }
  check("clearSiteData: unknown token refused at config-time", threw);

  // B13: an Object.prototype member name must NOT pass the allowlist. A bracket
  // lookup on the plain-object KNOWN_TYPES resolved inherited functions to
  // truthy, so "toString" / "constructor" / "hasOwnProperty" slipped through and
  // were emitted as bogus directives (prototype shadowing).
  var csd = b.middleware._modules.clearSiteData;
  ["toString", "constructor", "hasOwnProperty", "__proto__", "valueOf"].forEach(function (proto) {
    var t2 = false;
    try { csd.headerValue([proto]); }
    catch (e) { t2 = e instanceof TypeError && /unknown type/.test(e.message); }
    check("clearSiteData: prototype member '" + proto + "' refused (no proto-shadow)", t2);
  });
}

function testEmptyArrayRefused() {
  var threw = false;
  try { b.middleware.clearSiteData({ types: [] }); }
  catch (e) { threw = e instanceof TypeError && /non-empty array/.test(e.message); }
  check("clearSiteData: empty types[] refused at config-time", threw);
}

function testNonArrayRefused() {
  var threw = false;
  try { b.middleware.clearSiteData({ types: "cache" }); }
  catch (e) { threw = e instanceof TypeError; }
  check("clearSiteData: non-array types refused at config-time", threw);
}

function testConstantsSurface() {
  var m = b.middleware._modules.clearSiteData;
  check("clearSiteData: KNOWN_TYPES exposed as array", Array.isArray(m.KNOWN_TYPES));
  check("clearSiteData: KNOWN_TYPES includes cookies", m.KNOWN_TYPES.indexOf("cookies") !== -1);
  check("clearSiteData: KNOWN_TYPES includes wildcard", m.KNOWN_TYPES.indexOf("*") !== -1);
  check("clearSiteData: DEFAULT_TYPES is the canonical 4",
    Array.isArray(m.DEFAULT_TYPES) && m.DEFAULT_TYPES.length === 4);
}

async function run() {
  testDefaultTypes();
  testOperatorSubset();
  testWildcard();
  testClientHints();
  testUnknownTokenRefused();
  testEmptyArrayRefused();
  testNonArrayRefused();
  testConstantsSurface();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
