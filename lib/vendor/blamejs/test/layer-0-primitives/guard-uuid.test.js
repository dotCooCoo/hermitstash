// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-uuid — RFC 9562 UUID identifier-safety primitive (b.guardUuid).
 *
 * Covers the normalize-or-throw sanitize contract: sanitize strips the
 * `urn:uuid:` prefix and Microsoft GUID braces and lower-cases to the
 * canonical hyphenated form, and throws GuardUuidError on a critical /
 * high finding (nil / max sentinel under reject).
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var CANON = "550e8400-e29b-41d4-a716-446655440000";
function _code(fn) { try { fn(); return null; } catch (e) { return e && e.code; } }

function testGuardUuidSurface() {
  check("guardUuid is an object",           typeof b.guardUuid === "object");
  check("guardUuid.NAME === 'uuid'",        b.guardUuid.NAME === "uuid");
  check("guardUuid.sanitize is a function", typeof b.guardUuid.sanitize === "function");
  check("guardUuid registered in guardAll",
    b.guardAll.allGuards().some(function (g) { return (g.name || g.NAME) === "uuid"; }));
  check("frameworkError.GuardUuidError exposed",
    typeof b.frameworkError.GuardUuidError === "function");
}

function testSanitizeCanonicalPassthrough() {
  var out = b.guardUuid.sanitize(CANON, { profile: "strict" });
  check("already-canonical UUID passes through", out === CANON);
}

function testSanitizeNormalizesUrnPrefix() {
  // urn:uuid: prefix stripped + upper-case lowered → canonical form.
  var out = b.guardUuid.sanitize("urn:uuid:550E8400-E29B-41D4-A716-446655440000",
    { profile: "balanced" });
  check("urn:uuid: prefix normalized to canonical", out === CANON);
}

function testSanitizeNormalizesBraces() {
  // Microsoft GUID braces stripped → canonical form.
  var out = b.guardUuid.sanitize("{550E8400-E29B-41D4-A716-446655440000}",
    { profile: "balanced" });
  check("GUID braces normalized to canonical", out === CANON);
}

function testSanitizeRefusesMaxSentinelStrict() {
  check("max UUID sentinel refused under strict",
    _code(function () {
      b.guardUuid.sanitize("ffffffff-ffff-ffff-ffff-ffffffffffff", { profile: "strict" });
    }) === "uuid.max-uuid");
}

function testSanitizeRefusesNilSentinelStrict() {
  check("nil UUID sentinel refused under strict",
    _code(function () {
      b.guardUuid.sanitize("00000000-0000-0000-0000-000000000000", { profile: "strict" });
    }) === "uuid.nil-uuid");
}

function testSanitizeThrowsGuardUuidError() {
  var caught = null;
  try { b.guardUuid.sanitize("not-a-uuid", { profile: "strict" }); }
  catch (e) { caught = e; }
  check("malformed UUID sanitize throws a GuardUuidError instance",
    caught instanceof b.frameworkError.GuardUuidError);
}

function run() {
  testGuardUuidSurface();
  testSanitizeCanonicalPassthrough();
  testSanitizeNormalizesUrnPrefix();
  testSanitizeNormalizesBraces();
  testSanitizeRefusesMaxSentinelStrict();
  testSanitizeRefusesNilSentinelStrict();
  testSanitizeThrowsGuardUuidError();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[guard-uuid] OK — " + helpers.getChecks() + " checks passed"); }
  catch (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
}
