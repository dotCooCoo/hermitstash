"use strict";
/**
 * Full-framework setup/teardown for tests that need a working DB +
 * vault + audit chain.
 *
 * Tests run with the same secure modes operators use in production —
 * wrapped vault (Argon2id-derived AEAD wrap), encrypted at-rest db
 * (tmpfs working copy, sealed db.enc on durable disk), wrapped audit-
 * signing key. The earlier "plain mode for test speed" pattern hid
 * the same class of bug as feedback_test_to_security_not_security_to_test.md
 * warns about; the production path is what should be exercised.
 *
 * The test passphrase is hard-coded — these tests are local-only and
 * the surface that matters is wrap/unwrap behaviour, not passphrase
 * secrecy. Real deployments source it from BLAMEJS_VAULT_PASSPHRASE.
 */

var fs = require("fs");
var os = require("os");
var path = require("path");
var b = require("../../index.js");

var TEST_PASSPHRASE = "blamejs-test-passphrase-not-secret";

function _setTestEnv() {
  process.env.BLAMEJS_VAULT_PASSPHRASE         = TEST_PASSPHRASE;
  process.env.BLAMEJS_AUDIT_SIGNING_PASSPHRASE = TEST_PASSPHRASE;
  delete process.env.BLAMEJS_AUDIT_SIGNING_MODE;
}

async function setupTestDb(tmpDir, schemaOverrides) {
  process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
  _setTestEnv();
  b.cluster._resetForTest();
  b.audit._resetForTest();
  b.vault._resetForTest();
  b.db._resetForTest();
  await b.vault.init({ dataDir: tmpDir });
  await b.db.init({
    dataDir: tmpDir,
    tmpDir:  path.join(tmpDir, "tmpfs"),
    schema:  schemaOverrides || [
      {
        name: "users",
        columns: {
          _id:       "TEXT PRIMARY KEY",
          email:     "TEXT",
          emailHash: "TEXT",
          name:      "TEXT",
          status:    "TEXT DEFAULT 'active'",
          createdAt: "TEXT",
        },
        indexes: ["emailHash", "status"],
        sealedFields:  ["email", "name"],
        derivedHashes: { emailHash: { from: "email", normalize: function (v) { return String(v).toLowerCase(); } } },
      },
    ],
  });
}

async function teardownTestDb(tmpDir) {
  // Drain audit handler buffered emissions BEFORE close so pending
  // rows land in audit_log rather than leaking into the next test's DB.
  try { await b.audit.flush(); } catch (_e) {}
  try { b.db.close(); } catch (_e) {}
  b.audit._resetForTest();
  b.db._resetForTest();
  b.vault._resetForTest();
  b.cluster._resetForTest();
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
}

// Lightweight middleware-fixture setup: db boots with no app schema.
// For tests that don't need any app-level tables.
async function setupTestDbForMW() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mw-"));
  process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
  _setTestEnv();
  b.vault._resetForTest();
  b.db._resetForTest();
  await b.vault.init({ dataDir: tmpDir });
  await b.db.init({
    dataDir: tmpDir,
    tmpDir:  path.join(tmpDir, "tmpfs"),
    schema:  [],
  });
  global._mwTmpDir = tmpDir;
}

function teardownMW() {
  try { b.db.close(); } catch (_e) {}
  b.db._resetForTest();
  b.vault._resetForTest();
  if (global._mwTmpDir) {
    try { fs.rmSync(global._mwTmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

module.exports = {
  setupTestDb:      setupTestDb,
  teardownTestDb:   teardownTestDb,
  setupTestDbForMW: setupTestDbForMW,
  teardownMW:       teardownMW,
  // Exported so tests that close + re-open the vault (persistence,
  // schema-evolution) can re-supply the passphrase. The framework's
  // passphrase source strips env after reading (security feature),
  // so each fresh vault.init needs a fresh env set.
  setTestPassphraseEnv: _setTestEnv,
  TEST_PASSPHRASE:      TEST_PASSPHRASE,
};
