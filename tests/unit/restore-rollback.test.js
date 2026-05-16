/**
 * Unit tests for lib/restore-rollback.js — the pre-restore snapshot +
 * rollback helpers used by restore-worker to preserve live server state
 * when a restore operation fails mid-flow.
 */
var { describe, it, beforeEach, afterEach } = require("node:test");
var assert = require("node:assert");
var fs = require("fs");
var os = require("os");
var path = require("path");
var rollback = require("../../lib/restore-rollback");

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hs-rollback-test-"));
}

function cleanup(d) {
  try { fs.rmSync(d, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
}

function writeFile(dir, name, content) {
  fs.writeFileSync(path.join(dir, name), content, { mode: 0o600 });
}

function readFile(dir, name) {
  return fs.readFileSync(path.join(dir, name));
}

function exists(dir, name) {
  return fs.existsSync(path.join(dir, name));
}

describe("restore-rollback createSnapshots", function () {
  var dir;
  beforeEach(function () { dir = tmpDir(); });
  afterEach(function () { cleanup(dir); });

  it("returns empty array when no tracked files exist", function () {
    var created = rollback.createSnapshots(dir);
    assert.deepStrictEqual(created, []);
  });

  it("snapshots every tracked file that exists", function () {
    writeFile(dir, "vault.key", "plaintext-vault-key");
    writeFile(dir, "db.key.enc", "db-key-blob");
    writeFile(dir, "hermitstash.db.enc", "db-content");
    // vault.key.sealed intentionally omitted — only plaintext mode
    var created = rollback.createSnapshots(dir);
    assert.deepStrictEqual(created.sort(), ["db.key.enc", "hermitstash.db.enc", "vault.key"]);
    assert.ok(exists(dir, "vault.key.pre-restore"));
    assert.ok(exists(dir, "db.key.enc.pre-restore"));
    assert.ok(exists(dir, "hermitstash.db.enc.pre-restore"));
    assert.ok(!exists(dir, "vault.key.sealed.pre-restore"));
  });

  it("snapshots both vault.key and vault.key.sealed when present (unusual state, but we handle it)", function () {
    writeFile(dir, "vault.key", "plaintext");
    writeFile(dir, "vault.key.sealed", "sealed-bytes");
    var created = rollback.createSnapshots(dir);
    assert.ok(created.includes("vault.key"));
    assert.ok(created.includes("vault.key.sealed"));
  });

  it("snapshot content is byte-exact", function () {
    var content = Buffer.concat([Buffer.from([0, 1, 2]), Buffer.alloc(1024, 0x42), Buffer.from([0xff])]);
    fs.writeFileSync(path.join(dir, "vault.key.sealed"), content);
    rollback.createSnapshots(dir);
    var snap = readFile(dir, "vault.key.sealed.pre-restore");
    assert.strictEqual(Buffer.compare(snap, content), 0);
  });
});

describe("restore-rollback rollbackFromSnapshots", function () {
  var dir;
  beforeEach(function () { dir = tmpDir(); });
  afterEach(function () { cleanup(dir); });

  it("restores byte-exact content after live file is overwritten", function () {
    writeFile(dir, "vault.key", "original");
    var created = rollback.createSnapshots(dir);

    // Simulate mid-restore overwrite that corrupts the live file
    writeFile(dir, "vault.key", "NEW-CORRUPTED-CONTENT");
    assert.strictEqual(readFile(dir, "vault.key").toString(), "NEW-CORRUPTED-CONTENT");

    // Rollback
    var errors = rollback.rollbackFromSnapshots(dir, created);
    assert.deepStrictEqual(errors, []);
    assert.strictEqual(readFile(dir, "vault.key").toString(), "original");
  });

  it("restores multiple files correctly", function () {
    writeFile(dir, "vault.key", "v-orig");
    writeFile(dir, "db.key.enc", "d-orig");
    writeFile(dir, "hermitstash.db.enc", "h-orig");
    var created = rollback.createSnapshots(dir);
    writeFile(dir, "vault.key", "v-mod");
    writeFile(dir, "db.key.enc", "d-mod");
    writeFile(dir, "hermitstash.db.enc", "h-mod");
    rollback.rollbackFromSnapshots(dir, created);
    assert.strictEqual(readFile(dir, "vault.key").toString(), "v-orig");
    assert.strictEqual(readFile(dir, "db.key.enc").toString(), "d-orig");
    assert.strictEqual(readFile(dir, "hermitstash.db.enc").toString(), "h-orig");
  });

  it("preserves .pre-restore files by default (for operator inspection)", function () {
    writeFile(dir, "vault.key", "original");
    var created = rollback.createSnapshots(dir);
    writeFile(dir, "vault.key", "corrupted");
    rollback.rollbackFromSnapshots(dir, created);
    assert.ok(exists(dir, "vault.key.pre-restore"), "snapshot should still exist after rollback");
  });

  it("removes .pre-restore files when preserveSnapshots:false", function () {
    writeFile(dir, "vault.key", "original");
    var created = rollback.createSnapshots(dir);
    writeFile(dir, "vault.key", "corrupted");
    rollback.rollbackFromSnapshots(dir, created, { preserveSnapshots: false });
    assert.ok(!exists(dir, "vault.key.pre-restore"), "snapshot should be removed");
  });

  it("cleans up leftover .tmp files from incomplete atomic renames", function () {
    writeFile(dir, "vault.key.tmp", "incomplete");
    writeFile(dir, "vault.key.sealed.tmp", "also-incomplete");
    writeFile(dir, "db.key.enc.tmp", "yet-another");
    rollback.rollbackFromSnapshots(dir, []);
    assert.ok(!exists(dir, "vault.key.tmp"), ".tmp should be cleaned");
    assert.ok(!exists(dir, "vault.key.sealed.tmp"), ".tmp should be cleaned");
    assert.ok(!exists(dir, "db.key.enc.tmp"), ".tmp should be cleaned");
  });

  it("never throws — returns error list for individual failures", function () {
    // Create snapshot then delete the .pre-restore file (forcing rollback to not find it)
    writeFile(dir, "vault.key", "orig");
    var created = rollback.createSnapshots(dir);
    fs.unlinkSync(path.join(dir, "vault.key.pre-restore"));
    // Rollback — should NOT throw, but should succeed silently on missing snapshot
    var errors = rollback.rollbackFromSnapshots(dir, created);
    // Missing .pre-restore is a no-op (not listed as error)
    assert.deepStrictEqual(errors, []);
  });

  it("is no-op for empty snapshotsCreated", function () {
    writeFile(dir, "vault.key", "present");
    rollback.rollbackFromSnapshots(dir, []);
    // File unaffected
    assert.strictEqual(readFile(dir, "vault.key").toString(), "present");
  });
});

describe("restore-rollback clearSnapshots", function () {
  var dir;
  beforeEach(function () { dir = tmpDir(); });
  afterEach(function () { cleanup(dir); });

  it("removes .pre-restore files", function () {
    writeFile(dir, "vault.key", "x");
    writeFile(dir, "db.key.enc", "y");
    var created = rollback.createSnapshots(dir);
    rollback.clearSnapshots(dir, created);
    assert.ok(!exists(dir, "vault.key.pre-restore"));
    assert.ok(!exists(dir, "db.key.enc.pre-restore"));
  });

  it("silently tolerates missing snapshots", function () {
    // clearSnapshots called with names whose snapshots don't exist — should not throw
    rollback.clearSnapshots(dir, ["vault.key", "db.key.enc"]);
  });
});

describe("restore-rollback full scenario: simulated mid-flow failure", function () {
  var dir;
  beforeEach(function () { dir = tmpDir(); });
  afterEach(function () { cleanup(dir); });

  it("server state is fully preserved after mid-restore failure", function () {
    // Set up a pre-restore state representing a running wrapped-mode server
    writeFile(dir, "vault.key.sealed", "sealed-bytes-v1");
    writeFile(dir, "db.key.enc", "live-db-key-v1");
    writeFile(dir, "hermitstash.db.enc", "live-db-content-v1");

    // Step 1: restore snapshots everything
    var created = rollback.createSnapshots(dir);
    assert.strictEqual(created.length, 3);

    // Step 2: restore overwrites db.key.enc successfully
    writeFile(dir, "db.key.enc", "restored-db-key");
    // Step 3: restore starts overwriting hermitstash.db.enc via .tmp + rename
    writeFile(dir, "hermitstash.db.enc.tmp", "partial-restore-content");
    // Step 4: RESTORE FAILS before rename (e.g., checksum mismatch)
    //         — vault.key.sealed is NOT yet touched

    // Rollback should:
    //   - Restore db.key.enc content to v1
    //   - Clean up hermitstash.db.enc.tmp
    //   - Leave vault.key.sealed untouched (but still restore from snapshot defensively)
    //   - Leave hermitstash.db.enc unchanged (wasn't overwritten)
    var errors = rollback.rollbackFromSnapshots(dir, created);
    assert.deepStrictEqual(errors, []);

    // Verify state is pre-restore
    assert.strictEqual(readFile(dir, "vault.key.sealed").toString(), "sealed-bytes-v1");
    assert.strictEqual(readFile(dir, "db.key.enc").toString(), "live-db-key-v1");
    assert.strictEqual(readFile(dir, "hermitstash.db.enc").toString(), "live-db-content-v1");
    assert.ok(!exists(dir, "hermitstash.db.enc.tmp"), "stale .tmp cleaned");
    // Snapshots preserved for operator inspection
    assert.ok(exists(dir, "vault.key.sealed.pre-restore"));
    assert.ok(exists(dir, "db.key.enc.pre-restore"));
    assert.ok(exists(dir, "hermitstash.db.enc.pre-restore"));
  });
});
