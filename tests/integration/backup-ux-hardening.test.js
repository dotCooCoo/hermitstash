/**
 * Backup-UX hardening — regression tests for the silent-passphrase-loss
 * class + the operator-visible diagnostic surfaces.
 *
 * The load-bearing case is "passphrase preservation across schedule
 * edit": a form edit that doesn't re-type the passphrase must NOT
 * clobber the stored value.
 */
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var fs = require("fs");
var crypto = require("crypto");
var b = require("../../lib/vendor/blamejs");

var testId = b.crypto.generateToken(4);
var harnessDir = path.join(__dirname, "..", "..", "data", "backup-hardening-test-" + testId);
process.env.HERMITSTASH_DATA_DIR = harnessDir;
process.env.HERMITSTASH_DB_PATH = path.join(harnessDir, "h.db");
fs.mkdirSync(harnessDir, { recursive: true });

Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

var vault = require("../../lib/vault");
var config = require("../../lib/config");
var backup = require("../../lib/backup");
var adminValidator = require("../../app/http/validators/admin.validator");

before(async function () {
  await vault.init();
});

after(function () {
  try { fs.rmSync(harnessDir, { recursive: true, force: true }); } catch {}
});

describe("passphrase preservation across schedule edit", function () {

  it("getSettings() now returns mask(backupPassphrase) when one is set", function () {
    config.updateSettings({ backupPassphrase: "secret-passphrase-12345" });
    var settings = config.getSettings();
    assert.ok("backupPassphrase" in settings, "backupPassphrase MUST appear in getSettings response");
    assert.match(settings.backupPassphrase, /^•+$/, "should be masked bullets");
  });

  it("getSettings() returns empty string when no passphrase set", function () {
    config.updateSettings({ backupPassphrase: "" });
    var settings = config.getSettings();
    assert.strictEqual(settings.backupPassphrase, "");
  });

  it("REGRESSION: round-trip preserves passphrase across schedule edit", function () {
    // Step 1: Operator sets a passphrase
    config.updateSettings({ backupPassphrase: "original-passphrase-xyz" });
    var snap1 = config.getSettings();
    assert.match(snap1.backupPassphrase, /^•+$/);
    var savedPassphrase = config.backup.passphrase;
    assert.ok(savedPassphrase && savedPassphrase.length > 0, "passphrase should be saved");

    // Step 2: Operator edits schedule. Form submits all backup fields,
    // including the masked passphrase value pulled from getSettings().
    // The defect class this regresses: form submits the masked-bullet
    // value as plaintext, validator accepts it, storage clobbers the
    // real passphrase. Defense: validator skips bullet-only values.
    var formSubmission = {
      backupSchedule: 43200000,
      backupTimezone: "America/Los_Angeles",
      backupPassphrase: snap1.backupPassphrase, // the masked value
    };

    var validated = adminValidator.validateSettingsInput(formSubmission);
    assert.ok(!validated.error, "validation should accept the masked re-submission");
    config.updateSettings(validated.settings);

    // Step 3: Verify passphrase is still saved (NOT clobbered)
    assert.strictEqual(config.backup.passphrase, savedPassphrase,
      "passphrase MUST survive a settings save that included only the masked value");
  });

  it("validator refuses backupEnabled=true save without any passphrase ever set", function () {
    // First reset: make sure no passphrase is configured
    config.updateSettings({ backupPassphrase: "" });
    config.backup.passphraseHash = "";

    var formSubmission = { backupEnabled: true, backupPassphrase: "" };
    var result = adminValidator.validateSettingsInput(formSubmission);
    assert.ok(result.error, "should refuse backupEnabled=true without passphrase");
    assert.match(result.error, /no passphrase has been set/);
  });

  it("validator allows backupEnabled=true save when a passphrase is being entered", function () {
    config.backup.passphraseHash = "";
    var formSubmission = { backupEnabled: true, backupPassphrase: "freshly-typed-pw" };
    var result = adminValidator.validateSettingsInput(formSubmission);
    assert.ok(!result.error, "should accept; got: " + result.error);
  });
});

describe("diagnostic surfaces", function () {

  it("getBackupStatus reports blocked + reason when enabled but no passphrase", function () {
    config.updateSettings({ backupPassphrase: "" });
    config.backup.enabled = true;
    config.backup.s3.bucket = "test-bucket";
    config.backup.s3.accessKey = "AK";
    config.backup.s3.secretKey = "SK";
    var status = backup.getBackupStatus();
    assert.strictEqual(status.enabled, true);
    assert.strictEqual(status.configured, false);
    assert.strictEqual(status.blocked, true);
    assert.match(status.blockedReason, /BACKUP_PASSPHRASE/);
  });

  it("getBackupStatus reports configured when all fields present", function () {
    config.updateSettings({ backupPassphrase: "good-pw" });
    config.backup.enabled = true;
    config.backup.s3.bucket = "test-bucket";
    config.backup.s3.accessKey = "AK";
    config.backup.s3.secretKey = "SK";
    var status = backup.getBackupStatus();
    assert.strictEqual(status.configured, true);
    assert.strictEqual(status.blocked, false);
    assert.strictEqual(status.blockedReason, null);
  });

  it("setLastBackupAttempt + getLastBackupAttempt round-trip via settings table", function () {
    var attempt = {
      timestamp: "2026-04-22T03:00:00.000Z",
      status: "skipped",
      reason: "no passphrase",
    };
    backup.setLastBackupAttempt(attempt);
    var loaded = backup.getLastBackupAttempt();
    assert.deepStrictEqual(loaded, attempt);
  });

  it("audit ACTIONS includes BACKUP_SKIPPED constant", function () {
    var audit = require("../../lib/audit");
    assert.strictEqual(audit.ACTIONS.BACKUP_SKIPPED, "backup_skipped");
  });
});
