// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.retention.complianceFloor — operator-audit accessor for the
 * regulatory minimum-retention windows. Verifies the documented
 * floors match PCI-DSS / HIPAA / SOX / SOC 2 / DORA expectations.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("retention.complianceFloor is a function",
        typeof b.retention.complianceFloor === "function");
  check("retention.COMPLIANCE_RETENTION_FLOOR_MS is exposed",
        typeof b.retention.COMPLIANCE_RETENTION_FLOOR_MS === "object");
}

function testKnownPostures() {
  var pci   = b.retention.complianceFloor("pci-dss");
  var hipaa = b.retention.complianceFloor("hipaa");
  var sox   = b.retention.complianceFloor("sox");
  var soc2  = b.retention.complianceFloor("soc2");
  var dora  = b.retention.complianceFloor("dora");
  check("pci-dss floor = 365 days",   pci   === b.constants.TIME.days(365));
  check("hipaa floor = 6 years",      hipaa === b.constants.TIME.days(365 * 6));
  check("sox floor = 7 years",        sox   === b.constants.TIME.days(365 * 7));
  check("soc2 floor = 1 year",        soc2  === b.constants.TIME.days(365));
  check("dora floor = 5 years",       dora  === b.constants.TIME.days(365 * 5));
}

function testCandidateGreaterThanFloor() {
  // Operator candidate is longer than the floor — keep the candidate.
  var rv = b.retention.complianceFloor("pci-dss", b.constants.TIME.days(400));
  check("candidate > floor → candidate wins",
        rv === b.constants.TIME.days(400));
}

function testCandidateShorterThanFloor() {
  // Operator candidate is shorter than the floor — floor takes over.
  var rv = b.retention.complianceFloor("hipaa", b.constants.TIME.days(30));
  check("candidate < floor → floor wins",
        rv === b.constants.TIME.days(365 * 6));
}

function testUnknownPostureThrows() {
  var threw = null;
  try { b.retention.complianceFloor("not-a-real-posture"); }
  catch (e) { threw = e; }
  check("unknown posture → throws unknown-posture",
        threw && /unknown-posture/.test(threw.code || threw.message || ""));
}

function testOptionalPostureInheritance() {
  // #121 — applyPosture(posture) records an active posture that
  // complianceFloor() callers without an explicit posture inherit (the
  // advertised cascade behavior). complianceFloor hard-required a string and
  // never read STATE.activePosture, so the inheritance was unimplemented dead
  // state; applyPosture(null) now also clears it (was a no-op).
  var r = b.retention;
  var prior = r.activePosture();
  try {
    r.applyPosture(null);
    check("#121 applyPosture(null) clears the active posture",
          r.activePosture() === null);
    var threwNoActive = null;
    try { r.complianceFloor(b.constants.TIME.days(30)); } catch (e) { threwNoActive = e; }
    check("#121 no active posture + omitted posture → throws clearly",
          threwNoActive !== null);

    r.applyPosture("hipaa");
    check("#121 activePosture reflects the set value", r.activePosture() === "hipaa");
    check("#121 complianceFloor(ttl) inherits the active posture (single numeric arg)",
          r.complianceFloor(b.constants.TIME.days(30)) === b.constants.TIME.days(365 * 6));
    check("#121 complianceFloor(undefined, ttl) inherits the active posture",
          r.complianceFloor(undefined, b.constants.TIME.days(30)) === b.constants.TIME.days(365 * 6));
    check("#121 a candidate longer than the inherited floor still wins",
          r.complianceFloor(b.constants.TIME.days(365 * 10)) === b.constants.TIME.days(365 * 10));
    check("#121 an explicit posture still overrides the active one",
          r.complianceFloor("pci-dss", 0) === b.constants.TIME.days(365));
  } finally {
    if (typeof prior === "string") r.applyPosture(prior); else r.applyPosture(null);
  }
}

function testComplianceClearCascadesToRetention() {
  // b.compliance.set cascades the posture into retention (via applyPosture), so
  // b.compliance.clear must cascade the clear too — otherwise complianceFloor
  // keeps inheriting the stale posture after the global posture was cleared.
  if (!b.compliance || typeof b.compliance.set !== "function") return;
  var r = b.retention;
  try {
    if (b.compliance.current()) b.compliance.clear();
    r.applyPosture(null);
    b.compliance.set("hipaa");
    check("compliance.set cascades the posture into retention",
          r.activePosture() === "hipaa");
    b.compliance.clear();
    check("compliance.clear cascades the clear into retention (no stale inheritance)",
          r.activePosture() === null);
    var threw = null;
    try { r.complianceFloor(b.constants.TIME.days(30)); } catch (e) { threw = e; }
    check("after clear, complianceFloor with no explicit posture throws (not the stale floor)",
          threw !== null);
  } finally {
    try { if (b.compliance.current()) b.compliance.clear(); } catch (_e) { /* best-effort restore */ }
    try { r.applyPosture(null); } catch (_e) { /* best-effort restore */ }
  }
}

async function run() {
  testSurface();
  testKnownPostures();
  testCandidateGreaterThanFloor();
  testCandidateShorterThanFloor();
  testUnknownPostureThrows();
  testOptionalPostureInheritance();
  testComplianceClearCascadesToRetention();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
