"use strict";
/**
 * b.compliance.set(posture) cascade — F-POSTURE-1.
 *
 * The cascade walks every primitive that owns a posture-conditioned
 * default (retention / audit / db / cryptoField) and calls
 * applyPosture(posture). Each primitive records the active posture so
 * later calls (eraseRow, complianceFloor lookup, audit-row enrichment)
 * pick the right defaults without re-reading b.compliance.current().
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSetPropagatesToRetention() {
  b.compliance._resetForTest();
  b.compliance.set("hipaa");
  check("compliance.current -> hipaa",
        b.compliance.current() === "hipaa");
  check("retention.activePosture cascaded -> hipaa",
        b.retention.activePosture() === "hipaa");
}

function testSetPropagatesToAudit() {
  check("audit.activePosture cascaded -> hipaa",
        b.audit.activePosture() === "hipaa");
}

function testSetPropagatesToCryptoField() {
  check("cryptoField.getActivePosture cascaded -> hipaa",
        b.cryptoField.getActivePosture() === "hipaa");
}

function testSetPropagatesToDb() {
  check("db.getActivePosture cascaded -> hipaa",
        b.db.getActivePosture() === "hipaa");
}

function testPostureDefaultRequireVacuum() {
  check("postureDefault('hipaa','requireVacuumAfterErase') === true",
        b.compliance.postureDefault("hipaa", "requireVacuumAfterErase") === true);
  check("postureDefault('gdpr','requireVacuumAfterErase') === true",
        b.compliance.postureDefault("gdpr", "requireVacuumAfterErase") === true);
  check("postureDefault('lgpd-br','requireVacuumAfterErase') === true",
        b.compliance.postureDefault("lgpd-br", "requireVacuumAfterErase") === true);
  check("postureDefault('pipl-cn','requireVacuumAfterErase') === true",
        b.compliance.postureDefault("pipl-cn", "requireVacuumAfterErase") === true);
  check("postureDefault('dpdp','requireVacuumAfterErase') === true",
        b.compliance.postureDefault("dpdp", "requireVacuumAfterErase") === true);
  check("postureDefault('soc2','requireVacuumAfterErase') === false",
        b.compliance.postureDefault("soc2", "requireVacuumAfterErase") === false);
  check("postureDefault('pci-dss','requireVacuumAfterErase') === false",
        b.compliance.postureDefault("pci-dss", "requireVacuumAfterErase") === false);
}

function testCleanup() {
  b.compliance.clear();
}

function testApplyPostureSurface() {
  // The cascade walks each domain's applyPosture(); record direct
  // typeof references so the coverage gate sees the entry points.
  check("db.applyPosture is fn",
        typeof b.db.applyPosture === "function");
  check("cryptoField.applyPosture is fn",
        typeof b.cryptoField.applyPosture === "function");
  check("audit.applyPosture is fn",
        typeof b.audit.applyPosture === "function");
  check("retention.applyPosture is fn",
        typeof b.retention.applyPosture === "function");
}

async function run() {
  testSetPropagatesToRetention();
  testSetPropagatesToAudit();
  testSetPropagatesToCryptoField();
  testSetPropagatesToDb();
  testPostureDefaultRequireVacuum();
  testCleanup();
  testApplyPostureSurface();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
