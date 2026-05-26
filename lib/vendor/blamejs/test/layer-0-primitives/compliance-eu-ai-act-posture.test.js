"use strict";
/**
 * Layer 0 — eu-ai-act + ca-ab-853 + cac-genai-label posture
 * defaults wired into POSTURE_DEFAULTS + bundleAdapterStorage
 * encryption-required refusal.
 */

var os = require("node:os");
var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

async function testEuAiActPostureDefaults() {
  check("eu-ai-act: backupEncryptionRequired: true",
    b.compliance.postureDefault("eu-ai-act", "backupEncryptionRequired") === true);
  check("eu-ai-act: auditChainSignedRequired: true",
    b.compliance.postureDefault("eu-ai-act", "auditChainSignedRequired") === true);
  check("eu-ai-act: tlsMinVersion: TLSv1.3",
    b.compliance.postureDefault("eu-ai-act", "tlsMinVersion") === "TLSv1.3");
  check("eu-ai-act: requireVacuumAfterErase: true",
    b.compliance.postureDefault("eu-ai-act", "requireVacuumAfterErase") === true);
}

async function testCaAb853PostureDefaults() {
  check("ca-ab-853: backupEncryptionRequired: true",
    b.compliance.postureDefault("ca-ab-853", "backupEncryptionRequired") === true);
  check("ca-ab-853: requireVacuumAfterErase: true",
    b.compliance.postureDefault("ca-ab-853", "requireVacuumAfterErase") === true);
}

async function testCacGenaiLabelPostureDefaults() {
  check("cac-genai-label: backupEncryptionRequired: true",
    b.compliance.postureDefault("cac-genai-label", "backupEncryptionRequired") === true);
  check("cac-genai-label: auditChainSignedRequired: true",
    b.compliance.postureDefault("cac-genai-label", "auditChainSignedRequired") === true);
}

async function testLegacyAiActAliasGetsSameCascade() {
  // Codex P1 on v0.12.26 PR #177 — the legacy `ai-act` short
  // name was in KNOWN_POSTURES but the POSTURE_DEFAULTS row was
  // missing. Deployments pinned to the legacy alias would get
  // null from postureDefault() and bypass the encryption gate.
  check("legacy ai-act: backupEncryptionRequired same as eu-ai-act",
    b.compliance.postureDefault("ai-act", "backupEncryptionRequired") === true);
  check("legacy ai-act: tlsMinVersion same as eu-ai-act",
    b.compliance.postureDefault("ai-act", "tlsMinVersion") === "TLSv1.3");
  check("legacy ai-act: requireVacuumAfterErase same as eu-ai-act",
    b.compliance.postureDefault("ai-act", "requireVacuumAfterErase") === true);
  // Verify backup encryption gate covers the legacy alias too.
  var refused = null;
  try {
    b.backup.bundleAdapterStorage({
      adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: os.tmpdir() }),
      posture:        "ai-act",
      cryptoStrategy: "none",
    });
  } catch (e) { refused = e; }
  check("legacy ai-act: backup posture-gate refuses cryptoStrategy: none",
    refused && /posture-requires-encryption/.test(refused.code || refused.message));
}

async function testBackupRefusesPlaintextUnderAiPostures() {
  var postures = ["eu-ai-act", "ca-ab-853", "cac-genai-label"];
  for (var i = 0; i < postures.length; i += 1) {
    var refused = null;
    try {
      b.backup.bundleAdapterStorage({
        adapter:        b.backup.bundleAdapterStorage.fsAdapter({ root: os.tmpdir() }),
        posture:        postures[i],
        cryptoStrategy: "none",
      });
    } catch (e) { refused = e; }
    check("backup: " + postures[i] + " posture refuses cryptoStrategy: none",
      refused && /posture-requires-encryption/.test(refused.code || refused.message));
  }
}

async function run() {
  await testEuAiActPostureDefaults();
  await testCaAb853PostureDefaults();
  await testCacGenaiLabelPostureDefaults();
  await testLegacyAiActAliasGetsSameCascade();
  await testBackupRefusesPlaintextUnderAiPostures();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[compliance-eu-ai-act-posture] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
