"use strict";
/**
 * b.compliance — top-level compliance-posture coordinator.
 *
 * Covers: surface; set + current + assert + clear; unknown-posture
 * throws; runtime-switch refusal; guard primitive picks up the global
 * posture as fallback.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _resetState() {
  // Tests share global posture state — clear before each.
  b.compliance._resetForTest();
}

function testSurface() {
  check("compliance.set is a function",      typeof b.compliance.set === "function");
  check("compliance.current is a function",  typeof b.compliance.current === "function");
  check("compliance.assert is a function",   typeof b.compliance.assert === "function");
  check("compliance.clear is a function",    typeof b.compliance.clear === "function");
  check("KNOWN_POSTURES exposed",
        Array.isArray(b.compliance.KNOWN_POSTURES) &&
        Object.isFrozen(b.compliance.KNOWN_POSTURES));
  check("frameworkError.ComplianceError exposed",
        typeof b.frameworkError.ComplianceError === "function");
}

function testSetThenCurrent() {
  _resetState();
  check("current() before set → null", b.compliance.current() === null);
  b.compliance.set("hipaa");
  check("set('hipaa') then current() → 'hipaa'",
        b.compliance.current() === "hipaa");
}

function testAssert() {
  _resetState();
  b.compliance.set("pci-dss");
  b.compliance.assert("pci-dss");
  var threw = null;
  try { b.compliance.assert("hipaa"); } catch (e) { threw = e; }
  check("assert(other-posture) throws assertion-failed",
        threw && /assertion-failed/.test(threw.code || ""));
}

function testUnknownPosture() {
  _resetState();
  var threw = null;
  try { b.compliance.set("not-real"); } catch (e) { threw = e; }
  check("set('not-real') throws unknown-posture",
        threw && /unknown-posture/.test(threw.code || ""));
}

function testRuntimeSwitchRefused() {
  _resetState();
  b.compliance.set("hipaa");
  var threw = null;
  try { b.compliance.set("dora"); } catch (e) { threw = e; }
  check("changing posture after set → already-set",
        threw && /already-set/.test(threw.code || ""));
  // Same-value re-set is idempotent (boot scripts that set posture
  // multiple times don't fight each other when they agree).
  var threw2 = null;
  try { b.compliance.set("hipaa"); } catch (e) { threw2 = e; }
  check("re-setting same posture → idempotent (no throw)",
        threw2 === null && b.compliance.current() === "hipaa");
}

function testGuardPrimitivePicksUpGlobalPosture() {
  _resetState();
  b.compliance.set("hipaa");
  // b.guardCsv.gate({}) without an explicit compliancePosture should
  // pick up the global "hipaa" overlay from compliance.current().
  // We verify by inspecting the resolved opts — guardCsv exposes the
  // resolution via its compliancePosture function indirectly.
  var hipaaOverlay = b.guardCsv.compliancePosture("hipaa");
  // Build a gate without explicit posture; verify the gate's resolved
  // opts contain the hipaa-overlay's forensicSnippetBytes (256 per the
  // hipaa overlay).
  var resolved = b.gateContract.resolveProfileAndPosture({}, {
    profiles:           b.guardCsv.PROFILES,
    compliancePostures: b.guardCsv.COMPLIANCE_POSTURES,
    defaults:           b.guardCsv.DEFAULTS,
    errorClass:         b.frameworkError.GuardCsvError,
    errCodePrefix:      "csv",
  });
  check("guard primitive picks up global hipaa posture",
        resolved.forensicSnippetBytes === hipaaOverlay.forensicSnippetBytes);
}

function testClearResetsState() {
  _resetState();
  b.compliance.set("hipaa");
  b.compliance.clear();
  check("clear() sets current to null",
        b.compliance.current() === null);
  // After clear, set() works again with a different posture.
  b.compliance.set("dora");
  check("after clear, set('dora') succeeds",
        b.compliance.current() === "dora");
}

async function run() {
  testSurface();
  testSetThenCurrent();
  testAssert();
  testUnknownPosture();
  testRuntimeSwitchRefused();
  testGuardPrimitivePicksUpGlobalPosture();
  testClearResetsState();
  // Reset at end so other tests don't see leaked posture.
  _resetState();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
