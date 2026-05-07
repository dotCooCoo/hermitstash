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

async function run() {
  testSurface();
  testKnownPostures();
  testCandidateGreaterThanFloor();
  testCandidateShorterThanFloor();
  testUnknownPostureThrows();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
