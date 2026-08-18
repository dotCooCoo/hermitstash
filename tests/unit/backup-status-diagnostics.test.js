"use strict";

/**
 * The answer the admin page gives to "why are my backups not running?".
 *
 * getBackupStatus exists because scheduled backups used to no-op every twelve
 * hours in silence: enabled in the settings, unable to run, and nothing anywhere
 * saying so. It derives that answer from configuration, and none of its reason
 * branches had a test — so the diagnostic that closes a silent-failure gap could
 * itself have gone quiet, and the symptom would be identical to the bug it was
 * written to explain.
 *
 * The reasons name environment variables, which operators paste into a search or
 * a config file. A wrong or reworded name sends someone to the wrong setting, so
 * they are pinned exactly.
 *
 * Nothing here reaches S3: the status is a pure reading of configuration plus
 * the last attempt recorded in the settings table.
 */

require("../helpers/isolate-db"); // must precede every HermitStash require
var { describe, it, before, beforeEach, after } = require("node:test");
var assert = require("node:assert");

var config = require("../../lib/config");
var vault = require("../../lib/vault");
var db = require("../../lib/db");
var backup = require("../../lib/backup");

before(async function () { await vault.init(); });

var saved;
before(function () { saved = JSON.stringify(config.backup || {}); });
after(function () { config.backup = JSON.parse(saved); });

// A fully working configuration, which each case then breaks in one place.
function configured() {
  config.backup = {
    enabled: true,
    passphrase: "correct horse battery staple",
    passphraseHash: config.backup && config.backup.passphraseHash,
    s3: { bucket: "hs-backups", accessKey: "AKIA", secretKey: "shhh" },
  };
}

beforeEach(function () {
  configured();
  db.settings.find({ key: "SCHEDULED_BACKUP_LAST_ATTEMPT" }).forEach(function (r) {
    db.settings.remove({ _id: r._id });
  });
});

describe("a complete configuration reports itself ready", function () {
  it("is enabled, configured, and not blocked", function () {
    var s = backup.getBackupStatus();
    assert.strictEqual(s.enabled, true);
    assert.strictEqual(s.configured, true);
    assert.strictEqual(s.blocked, false);
    assert.strictEqual(s.blockedReason, null);
  });
});

describe("each missing piece is named", function () {
  it("no bucket", function () {
    config.backup.s3.bucket = "";
    var s = backup.getBackupStatus();
    assert.strictEqual(s.configured, false);
    assert.strictEqual(s.blocked, true);
    assert.strictEqual(s.blockedReason, "BACKUP_S3_BUCKET is not set");
  });

  it("no credentials — either half missing counts", function () {
    config.backup.s3.accessKey = "";
    assert.strictEqual(backup.getBackupStatus().blockedReason,
      "BACKUP_S3_ACCESS_KEY / BACKUP_S3_SECRET_KEY are not set");

    configured();
    config.backup.s3.secretKey = "";
    assert.strictEqual(backup.getBackupStatus().blockedReason,
      "BACKUP_S3_ACCESS_KEY / BACKUP_S3_SECRET_KEY are not set");
  });

  it("no passphrase", function () {
    config.backup.passphrase = "";
    assert.strictEqual(backup.getBackupStatus().blockedReason, "BACKUP_PASSPHRASE is not set");
  });

  it("several at once are all listed, in a fixed order", function () {
    config.backup.s3 = {};
    config.backup.passphrase = "";
    assert.strictEqual(backup.getBackupStatus().blockedReason,
      "BACKUP_S3_BUCKET is not set; "
      + "BACKUP_S3_ACCESS_KEY / BACKUP_S3_SECRET_KEY are not set; "
      + "BACKUP_PASSPHRASE is not set");
  });

  it("an absent s3 section is the same as an empty one", function () {
    delete config.backup.s3;
    var s = backup.getBackupStatus();
    assert.strictEqual(s.blocked, true);
    assert.match(s.blockedReason, /BACKUP_S3_BUCKET is not set/);
  });
});

describe("a feature the operator turned off is not a problem to report", function () {
  it("disabled and unconfigured is not blocked", function () {
    // "Blocked" means "you asked for this and it cannot run". Reporting a
    // problem for a feature nobody enabled would train operators to ignore it.
    config.backup.enabled = false;
    config.backup.s3 = {};
    config.backup.passphrase = "";
    var s = backup.getBackupStatus();
    assert.strictEqual(s.enabled, false);
    assert.strictEqual(s.configured, false);
    assert.strictEqual(s.blocked, false);
    assert.strictEqual(s.blockedReason, null);
  });

  it("disabled but fully configured is also not blocked", function () {
    config.backup.enabled = false;
    var s = backup.getBackupStatus();
    assert.strictEqual(s.configured, false, "configured means it can run now");
    assert.strictEqual(s.blocked, false);
  });
});

describe("the last attempt survives a round trip and is replaced, not duplicated", function () {
  it("reports nothing before any attempt", function () {
    assert.strictEqual(backup.getLastBackupAttempt(), null);
    assert.strictEqual(backup.getBackupStatus().lastAttempt, null);
  });

  it("stores and returns an attempt", function () {
    var attempt = { at: "2026-08-17T00:00:00.000Z", outcome: "skipped", reason: "no passphrase" };
    backup.setLastBackupAttempt(attempt);
    assert.deepStrictEqual(backup.getLastBackupAttempt(), attempt);
    assert.deepStrictEqual(backup.getBackupStatus().lastAttempt, attempt);
  });

  it("a second attempt replaces the first rather than adding a row", function () {
    // Every scheduled tick writes one. Inserting instead of updating would grow
    // the settings table without bound and leave the read returning whichever
    // row happened to be found.
    backup.setLastBackupAttempt({ at: "2026-08-17T00:00:00.000Z", outcome: "failed" });
    backup.setLastBackupAttempt({ at: "2026-08-17T12:00:00.000Z", outcome: "completed" });

    var rows = db.settings.find({ key: "SCHEDULED_BACKUP_LAST_ATTEMPT" });
    assert.strictEqual(rows.length, 1, "one key, one row");
    assert.strictEqual(backup.getLastBackupAttempt().outcome, "completed");
  });

  it("an unreadable stored value reports nothing rather than throwing", function () {
    // The admin page asks for this on every load; a corrupt value must not take
    // the page down with it.
    backup.setLastBackupAttempt({ outcome: "completed" });
    db.settings.update({ key: "SCHEDULED_BACKUP_LAST_ATTEMPT" }, { $set: { value: "{not json" } });
    assert.strictEqual(backup.getLastBackupAttempt(), null);
    assert.doesNotThrow(function () { backup.getBackupStatus(); });
  });
});

describe("the restore passphrase", function () {
  it("is refused outright when none was ever set", async function () {
    // Restore overwrites the live database, so "no passphrase configured" must
    // deny rather than admit anything. Awaited because the function is async
    // even on the branch that answers immediately — comparing the promise itself
    // to false would pass whatever the answer was.
    config.backup.passphraseHash = "";
    assert.strictEqual(await backup.verifyPassphrase("anything"), false);
  });

  it("accepts the right one and refuses a wrong one", async function () {
    var b = require("../../lib/vendor/blamejs");
    config.backup.passphraseHash = await b.auth.password.hash("correct horse battery staple");
    assert.strictEqual(await backup.verifyPassphrase("correct horse battery staple"), true);
    assert.strictEqual(await backup.verifyPassphrase("wrong"), false);
    assert.strictEqual(await backup.verifyPassphrase(""), false);
  });
});
