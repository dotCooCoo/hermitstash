// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
  check("compliance.set is a function",                  typeof b.compliance.set === "function");
  check("compliance.current is a function",              typeof b.compliance.current === "function");
  check("compliance.assert is a function",               typeof b.compliance.assert === "function");
  check("compliance.clear is a function",                typeof b.compliance.clear === "function");
  check("compliance.fipsMode is a function",             typeof b.compliance.fipsMode === "function");
  check("compliance.artifactStandards is a function",    typeof b.compliance.artifactStandards === "function");
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

function testV0870NewPostures() {
  var ps = b.compliance.list().map(function (p) { return p.posture; });
  check("compliance: modpa registered",                              ps.indexOf("modpa") !== -1);
  check("compliance: nydfs-500 registered",                          ps.indexOf("nydfs-500") !== -1);
  check("compliance: hipaa-2026 registered",                         ps.indexOf("hipaa-2026") !== -1);
  check("compliance: quebec-25 registered",                          ps.indexOf("quebec-25") !== -1);
  check("compliance: fapi-2.0-message-signing registered",           ps.indexOf("fapi-2.0-message-signing") !== -1);

  check("describe(modpa): jurisdiction US-MD",                       b.compliance.describe("modpa").jurisdiction === "US-MD");
  check("describe(nydfs-500): jurisdiction US-NY",                   b.compliance.describe("nydfs-500").jurisdiction === "US-NY");
  check("describe(quebec-25): jurisdiction CA-QC",                   b.compliance.describe("quebec-25").jurisdiction === "CA-QC");
  check("describe(hipaa-2026): domain health",                       b.compliance.describe("hipaa-2026").domain === "health");
}

function testV0881NewPostures() {
  var ps = b.compliance.KNOWN_POSTURES;
  // ---- AI governance ----
  check("compliance: co-ai registered",       ps.indexOf("co-ai") !== -1);
  check("compliance: il-hb3773 registered",   ps.indexOf("il-hb3773") !== -1);
  check("compliance: tx-traiga registered",   ps.indexOf("tx-traiga") !== -1);
  check("compliance: ut-aipa registered",     ps.indexOf("ut-aipa") !== -1);
  check("compliance: nyc-ll144 registered",   ps.indexOf("nyc-ll144") !== -1);
  check("compliance: ca-tfaia registered",    ps.indexOf("ca-tfaia") !== -1);
  check("compliance: kr-ai-basic registered", ps.indexOf("kr-ai-basic") !== -1);
  check("compliance: cn-ai-label registered", ps.indexOf("cn-ai-label") !== -1);
  check("compliance: iso-42001 registered",   ps.indexOf("iso-42001") !== -1);
  check("compliance: iso-23894 registered",   ps.indexOf("iso-23894") !== -1);
  // ---- content-credentials ----
  check("compliance: ca-sb942 registered",    ps.indexOf("ca-sb942") !== -1);
  check("compliance: ca-ab853 registered",    ps.indexOf("ca-ab853") !== -1);
  // ---- substrate cleanup ----
  check("compliance: eaa registered",         ps.indexOf("eaa") !== -1);
  check("compliance: wcag-2-2 registered",    ps.indexOf("wcag-2-2") !== -1);
  check("compliance: eu-data-act registered", ps.indexOf("eu-data-act") !== -1);
  check("compliance: hitech registered",      ps.indexOf("hitech") !== -1);
  check("compliance: ferpa registered",       ps.indexOf("ferpa") !== -1);
  // ---- privacy ----
  check("compliance: fl-fdbr registered",     ps.indexOf("fl-fdbr") !== -1);
  // D1 drift fix — dpdp was in POSTURE_DEFAULTS but missing from KNOWN_POSTURES
  check("compliance: dpdp registered (D1 drift fix)", ps.indexOf("dpdp") !== -1);

  // REGIME_MAP fields
  check("describe(co-ai): domain ai-governance",        b.compliance.describe("co-ai").domain === "ai-governance");
  check("describe(nyc-ll144): jurisdiction US-NY-NYC",  b.compliance.describe("nyc-ll144").jurisdiction === "US-NY-NYC");
  check("describe(iso-42001): jurisdiction international", b.compliance.describe("iso-42001").jurisdiction === "international");
  check("describe(ca-sb942): domain content-credentials", b.compliance.describe("ca-sb942").domain === "content-credentials");
  check("describe(eaa): domain accessibility",          b.compliance.describe("eaa").domain === "accessibility");
  check("describe(ferpa): domain student-records",      b.compliance.describe("ferpa").domain === "student-records");
  check("describe(eu-data-act): domain data-sharing",   b.compliance.describe("eu-data-act").domain === "data-sharing");
  check("describe(fl-fdbr): jurisdiction US-FL",        b.compliance.describe("fl-fdbr").jurisdiction === "US-FL");
  check("describe(hitech): domain health",              b.compliance.describe("hitech").domain === "health");

  // D2 drift — citation dates corrected from 2026 → 2025
  check("describe(modpa) citation reflects 2025-10-01 effective date",
        /2025-10-01/.test(b.compliance.describe("modpa").citation));
  check("describe(nh-nhpa) citation reflects 2025-01-01 effective date",
        /2025-01-01/.test(b.compliance.describe("nh-nhpa").citation));
  check("describe(nj-njdpa) citation reflects 2025-01-15 effective date",
        /2025-01-15/.test(b.compliance.describe("nj-njdpa").citation));
  check("describe(mn-mncdpa) citation reflects 2025-07-31 effective date",
        /2025-07-31/.test(b.compliance.describe("mn-mncdpa").citation));

  // posture-default cascade for AI-governance tier
  check("postureDefault(co-ai, auditChainSignedRequired) === true",
        b.compliance.postureDefault("co-ai", "auditChainSignedRequired") === true);
  check("postureDefault(iso-42001, requireVacuumAfterErase) === true",
        b.compliance.postureDefault("iso-42001", "requireVacuumAfterErase") === true);
  check("postureDefault(ca-tfaia, backupEncryptionRequired) === true",
        b.compliance.postureDefault("ca-tfaia", "backupEncryptionRequired") === true);

  // posturesByDomain(ai-governance) returns all the new AI postures
  var aiGov = b.compliance.posturesByDomain("ai-governance");
  check("posturesByDomain(ai-governance) includes co-ai",
        aiGov.indexOf("co-ai") !== -1 && aiGov.indexOf("iso-42001") !== -1);

  // posturesByJurisdiction for new state codes
  var caP = b.compliance.posturesByJurisdiction("US-CA");
  check("posturesByJurisdiction(US-CA) includes ca-tfaia + ca-sb942",
        caP.indexOf("ca-tfaia") !== -1 && caP.indexOf("ca-sb942") !== -1);
}

function testV0882NewPostures() {
  var ps = b.compliance.KNOWN_POSTURES;
  // US federal
  check("compliance: coppa registered",          ps.indexOf("coppa") !== -1);
  check("compliance: coppa-2025 registered",     ps.indexOf("coppa-2025") !== -1);
  check("compliance: glba-safeguards registered", ps.indexOf("glba-safeguards") !== -1);
  check("compliance: gina registered",            ps.indexOf("gina") !== -1);
  check("compliance: vppa registered",            ps.indexOf("vppa") !== -1);
  check("compliance: can-spam registered",        ps.indexOf("can-spam") !== -1);
  check("compliance: il-gipa registered",         ps.indexOf("il-gipa") !== -1);
  check("compliance: hhs-repro-24 registered",    ps.indexOf("hhs-repro-24") !== -1);
  check("compliance: nist-pf-1.1 registered",     ps.indexOf("nist-pf-1.1") !== -1);
  // UK
  check("compliance: uk-duaa registered",         ps.indexOf("uk-duaa") !== -1);
  // LATAM
  check("compliance: cl-pdpa registered",         ps.indexOf("cl-pdpa") !== -1);
  check("compliance: mx-lfpdppp registered",      ps.indexOf("mx-lfpdppp") !== -1);
  check("compliance: ar-pdpa registered",         ps.indexOf("ar-pdpa") !== -1);
  // APAC
  check("compliance: pipa-kr registered",         ps.indexOf("pipa-kr") !== -1);
  check("compliance: au-privacy registered",      ps.indexOf("au-privacy") !== -1);
  check("compliance: th-pdpa registered",         ps.indexOf("th-pdpa") !== -1);
  check("compliance: vn-pdp registered",          ps.indexOf("vn-pdp") !== -1);
  check("compliance: id-pdp registered",          ps.indexOf("id-pdp") !== -1);
  check("compliance: my-pdpa registered",         ps.indexOf("my-pdpa") !== -1);
  // US state child privacy
  check("compliance: ny-safe-kids registered",    ps.indexOf("ny-safe-kids") !== -1);
  check("compliance: ny-saffe registered",        ps.indexOf("ny-saffe") !== -1);
  check("compliance: md-kids-code registered",    ps.indexOf("md-kids-code") !== -1);
  check("compliance: vt-aadc registered",         ps.indexOf("vt-aadc") !== -1);
  // EU adjacent
  check("compliance: dsa registered",             ps.indexOf("dsa") !== -1);
  check("compliance: dga registered",             ps.indexOf("dga") !== -1);
  check("compliance: eu-cer registered",          ps.indexOf("eu-cer") !== -1);
  check("compliance: eu-cyber-sol registered",    ps.indexOf("eu-cyber-sol") !== -1);
  check("compliance: eidas-2 registered",         ps.indexOf("eidas-2") !== -1);

  // Spot-check REGIME_MAP entries
  check("describe(coppa-2025): domain child-privacy", b.compliance.describe("coppa-2025").domain === "child-privacy");
  check("describe(uk-duaa): jurisdiction UK",         b.compliance.describe("uk-duaa").jurisdiction === "UK");
  check("describe(cl-pdpa): jurisdiction CL",         b.compliance.describe("cl-pdpa").jurisdiction === "CL");
  check("describe(pipa-kr): jurisdiction KR",         b.compliance.describe("pipa-kr").jurisdiction === "KR");
  check("describe(au-privacy): jurisdiction AU",      b.compliance.describe("au-privacy").jurisdiction === "AU");
  check("describe(dsa): domain platform-governance",  b.compliance.describe("dsa").domain === "platform-governance");
  check("describe(eu-cer): domain cybersecurity",     b.compliance.describe("eu-cer").domain === "cybersecurity");
  check("describe(gina): domain genetic-privacy",     b.compliance.describe("gina").domain === "genetic-privacy");
  check("describe(eidas-2): domain identity",         b.compliance.describe("eidas-2").domain === "identity");

  // POSTURE_DEFAULTS cascade
  check("postureDefault(uk-duaa, requireVacuumAfterErase) === true",
        b.compliance.postureDefault("uk-duaa", "requireVacuumAfterErase") === true);
  check("postureDefault(glba-safeguards, backupEncryptionRequired) === true",
        b.compliance.postureDefault("glba-safeguards", "backupEncryptionRequired") === true);
  check("postureDefault(coppa-2025, backupEncryptionRequired) === true",
        b.compliance.postureDefault("coppa-2025", "backupEncryptionRequired") === true);
  check("postureDefault(pipa-kr, requireVacuumAfterErase) === true",
        b.compliance.postureDefault("pipa-kr", "requireVacuumAfterErase") === true);

  // posturesByDomain
  var childPriv = b.compliance.posturesByDomain("child-privacy");
  check("posturesByDomain(child-privacy) includes coppa + ny-safe-kids",
        childPriv.indexOf("coppa") !== -1 && childPriv.indexOf("ny-safe-kids") !== -1);

  // posturesByJurisdiction
  var euP = b.compliance.posturesByJurisdiction("EU");
  check("posturesByJurisdiction(EU) includes dsa + dga + eu-cer",
        euP.indexOf("dsa") !== -1 && euP.indexOf("dga") !== -1 && euP.indexOf("eu-cer") !== -1);
}

// ---- Seal-envelope floor (POSTURE_DEFAULTS data + registerTable gate) ----

function testSealEnvelopeFloorData() {
  check("postureDefault(hipaa, sealEnvelopeFloor) === 'aad'",
        b.compliance.postureDefault("hipaa", "sealEnvelopeFloor") === "aad");
  check("postureDefault(pci-dss, sealEnvelopeFloor) === 'aad'",
        b.compliance.postureDefault("pci-dss", "sealEnvelopeFloor") === "aad");
  // Absent on non-regulated / unfloored postures → null (back-compat).
  check("postureDefault(gdpr, sealEnvelopeFloor) === null",
        b.compliance.postureDefault("gdpr", "sealEnvelopeFloor") === null);
  check("postureDefault(soc2, sealEnvelopeFloor) === null",
        b.compliance.postureDefault("soc2", "sealEnvelopeFloor") === null);
  check("postureDefault(dora, sealEnvelopeFloor) === null",
        b.compliance.postureDefault("dora", "sealEnvelopeFloor") === null);
}

function testRegisterTableFloorBackCompatUnpinned() {
  // No posture pinned: a plain sealed table registers exactly as before.
  _resetState();
  b.cryptoField.clearForTest();
  var threw = null;
  try {
    b.cryptoField.registerTable("ct_floor_unpinned", { sealedFields: ["x"] });
  } catch (e) { threw = e; }
  check("plain sealed table registers under no posture (back-compat)",
        threw === null);
  b.cryptoField.clearForTest();
}

function testRegisterTableFloorThrowsUnderHipaa() {
  _resetState();
  b.cryptoField.clearForTest();
  b.compliance.set("hipaa");
  var threw = null;
  try {
    b.cryptoField.registerTable("ct_floor_hipaa_plain", { sealedFields: ["ssn"] });
  } catch (e) { threw = e; }
  check("plain sealed table under hipaa throws seal-envelope-below-floor",
        threw && threw.code === "crypto-field/seal-envelope-below-floor");
  b.cryptoField.clearForTest();
  _resetState();
}

function testRegisterTableFloorAadSatisfiesHipaa() {
  _resetState();
  b.cryptoField.clearForTest();
  b.compliance.set("hipaa");
  var threw = null;
  try {
    b.cryptoField.registerTable("ct_floor_hipaa_aad",
      { sealedFields: ["ssn"], aad: true, rowIdField: "id" });
  } catch (e) { threw = e; }
  check("aad-bound sealed table satisfies hipaa floor (no throw)",
        threw === null);
  b.cryptoField.clearForTest();
  _resetState();
}

function testRegisterTableFloorNoSealedFieldsPasses() {
  _resetState();
  b.cryptoField.clearForTest();
  b.compliance.set("pci-dss");
  var threw = null;
  try {
    // No sealed columns → no envelope to gate.
    b.cryptoField.registerTable("ct_floor_pci_nosealed", { sealedFields: [] });
  } catch (e) { threw = e; }
  check("table with no sealed fields passes under pci-dss floor",
        threw === null);
  b.cryptoField.clearForTest();
  _resetState();
}

function testRegisterTableFloorPerRowKeySatisfies() {
  _resetState();
  b.cryptoField.clearForTest();
  b.compliance.set("hipaa");
  // declarePerRowKey before registerTable: the table's declared envelope
  // is per-row-key, which is ABOVE the aad floor.
  b.cryptoField.declarePerRowKey("ct_floor_hipaa_prk", { keySize: 32 });
  var threw = null;
  try {
    b.cryptoField.registerTable("ct_floor_hipaa_prk", { sealedFields: ["ssn"] });
  } catch (e) { threw = e; }
  check("per-row-key table satisfies hipaa floor (no throw)",
        threw === null);
  b.cryptoField.clearForTest();
  _resetState();
}

function testRegisterTableFloorUnflooredPosturePasses() {
  // gdpr is regulated but declares no sealEnvelopeFloor → plain passes.
  _resetState();
  b.cryptoField.clearForTest();
  b.compliance.set("gdpr");
  var threw = null;
  try {
    b.cryptoField.registerTable("ct_floor_gdpr_plain", { sealedFields: ["email"] });
  } catch (e) { threw = e; }
  check("plain sealed table under gdpr (no floor) passes (back-compat)",
        threw === null);
  b.cryptoField.clearForTest();
  _resetState();
}

// ---- Region-tag normalization + compatibility helpers (additive) ----

function testNormalizeRegionTag() {
  check("normalizeRegionTag('EU') === normalizeRegionTag('eu')",
        b.compliance.normalizeRegionTag("EU") === b.compliance.normalizeRegionTag("eu"));
  check("normalizeRegionTag(' eu ') trims + lowercases",
        b.compliance.normalizeRegionTag(" eu ") === "eu");
  check("normalizeRegionTag('global') folds to 'unrestricted'",
        b.compliance.normalizeRegionTag("global") === "unrestricted");
  check("normalizeRegionTag('unrestricted') === 'unrestricted'",
        b.compliance.normalizeRegionTag("unrestricted") === "unrestricted");
  check("normalizeRegionTag(null) === null",
        b.compliance.normalizeRegionTag(null) === null);
  check("normalizeRegionTag('') === null",
        b.compliance.normalizeRegionTag("") === null);
}

function testIsRegionCompatible() {
  check("isRegionCompatible('EU','eu') === true (case-insensitive)",
        b.compliance.isRegionCompatible("EU", "eu") === true);
  check("isRegionCompatible('eu','global') === true (wildcard)",
        b.compliance.isRegionCompatible("eu", "global") === true);
  check("isRegionCompatible('unrestricted','us') === true (wildcard)",
        b.compliance.isRegionCompatible("unrestricted", "us") === true);
  check("isRegionCompatible('eu','us') === false (distinct regions)",
        b.compliance.isRegionCompatible("eu", "us") === false);
  check("isRegionCompatible('EU',null) === true (no constraint)",
        b.compliance.isRegionCompatible("EU", null) === true);
}

// ---- Bug C1: gate-contract unmapped-posture warning ----

function _gcCfg() {
  return {
    profiles:           { strict: { a: 1 } },
    compliancePostures: { hipaa: { piiPolicy: "redact" }, "pci-dss": { piiPolicy: "refuse" } },
    defaults:           { piiPolicy: "serve" },
    errCodePrefix:      "ct_c1",
  };
}

function testGateContractUnmappedPostureWarns() {
  _resetState();
  b.gateContract._resetForTest();
  // fedramp-rev5-moderate is a real posture with no overlay in _gcCfg.
  b.compliance.set("fedramp-rev5-moderate");
  var captured = [];
  var origAudit = b.audit.safeEmit;
  b.audit.safeEmit = function (e) { captured.push(e); };
  var resolved;
  try {
    resolved = b.gateContract.resolveProfileAndPosture({}, _gcCfg());
    // Second call same posture+guard must NOT re-warn (dedupe).
    b.gateContract.resolveProfileAndPosture({}, _gcCfg());
  } finally {
    b.audit.safeEmit = origAudit;
  }
  var warns = captured.filter(function (e) {
    return e.action === "gateContract.posture.unmapped";
  });
  check("unmapped global posture emits exactly one warning (deduped)",
        warns.length === 1 && warns[0].metadata.posture === "fedramp-rev5-moderate");
  check("unmapped posture keeps the safe (unposture-d) default",
        resolved.piiPolicy === "serve");
  b.gateContract._resetForTest();
  _resetState();
}

function testGateContractMappedPostureNoWarn() {
  _resetState();
  b.gateContract._resetForTest();
  b.compliance.set("hipaa");
  var captured = [];
  var origAudit = b.audit.safeEmit;
  b.audit.safeEmit = function (e) { captured.push(e); };
  var resolved;
  try {
    resolved = b.gateContract.resolveProfileAndPosture({}, _gcCfg());
  } finally {
    b.audit.safeEmit = origAudit;
  }
  var warns = captured.filter(function (e) {
    return e.action === "gateContract.posture.unmapped";
  });
  check("mapped global posture does not warn", warns.length === 0);
  check("mapped global posture applies overlay", resolved.piiPolicy === "redact");
  b.gateContract._resetForTest();
  _resetState();
}

function testGateContractUnpinnedNoWarn() {
  _resetState();
  b.gateContract._resetForTest();
  var captured = [];
  var origAudit = b.audit.safeEmit;
  b.audit.safeEmit = function (e) { captured.push(e); };
  var resolved;
  try {
    resolved = b.gateContract.resolveProfileAndPosture({}, _gcCfg());
  } finally {
    b.audit.safeEmit = origAudit;
  }
  var warns = captured.filter(function (e) {
    return e.action === "gateContract.posture.unmapped";
  });
  check("unpinned deployment does not warn", warns.length === 0);
  check("unpinned deployment keeps default", resolved.piiPolicy === "serve");
  b.gateContract._resetForTest();
}

async function run() {
  testSurface();
  testSetThenCurrent();
  testAssert();
  testUnknownPosture();
  testRuntimeSwitchRefused();
  testGuardPrimitivePicksUpGlobalPosture();
  testClearResetsState();
  testV0870NewPostures();
  testV0881NewPostures();
  testV0882NewPostures();
  testSealEnvelopeFloorData();
  testRegisterTableFloorBackCompatUnpinned();
  testRegisterTableFloorThrowsUnderHipaa();
  testRegisterTableFloorAadSatisfiesHipaa();
  testRegisterTableFloorNoSealedFieldsPasses();
  testRegisterTableFloorPerRowKeySatisfies();
  testRegisterTableFloorUnflooredPosturePasses();
  testNormalizeRegionTag();
  testIsRegionCompatible();
  testGateContractUnmappedPostureWarns();
  testGateContractMappedPostureNoWarn();
  testGateContractUnpinnedNoWarn();
  // Reset at end so other tests don't see leaked posture.
  b.cryptoField.clearForTest();
  b.gateContract._resetForTest();
  _resetState();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
