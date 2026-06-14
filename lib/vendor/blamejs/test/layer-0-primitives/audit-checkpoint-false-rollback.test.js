"use strict";

// SMOKE_RUN_SOLO — the smoke runner (test/smoke.js) runs this file ALONE
// with the whole machine instead of inside the parallel layer-0 pool.
// The test drives the encrypted-at-rest durability path end to end:
// db.enc re-encryption (flushToDisk), the atomicFile.writeSync tip
// sidecar, an in-place crash corruption of the tmpfs working file, and a
// decrypt-from-db.enc reboot — every step a blocking fsync on the real
// data dir. Under SMOKE_PARALLEL=64 on a virtualized filesystem (the
// Dropbox-backed working tree, Docker-Desktop FS-virt) 64 sibling forks
// contend for fsync on the same volume and these synchronous writes
// overrun the per-file watchdog. There is no single async event to poll
// past — the contention is whole-process I/O, so the file runs solo and
// finishes in its normal time. Passes alone and at SMOKE_PARALLEL=16.

/**
 * audit.checkpoint() durability vs the boot-time rollback check.
 *
 * In encrypted-at-rest mode the live SQLite copy is a tmpfs working file;
 * durability comes from re-encrypting it into db.enc (flushToDisk /
 * periodic encrypt / process-exit handler / orderly close). The boot-time
 * rollback detector compares MAX(monotonicCounter) in the restored DB
 * against the audit.tip sidecar and REFUSES boot when the DB is below the
 * tip (the snapshot was rolled back to an older state, or rows were
 * deleted).
 *
 * checkpoint() writes the audit.tip sidecar with atomicFile.writeSync — a
 * durable write to a real disk path in dataDir — immediately after
 * inserting the checkpoint row, but WITHOUT first re-encrypting the
 * audit_log rows it anchors into db.enc. So the tip's durability outruns
 * the rows' durability: if the process dies between checkpoint() and the
 * next encrypt, the durable db.enc is BEHIND the durable tip.
 *
 * On reboot the tmpfs working copy is gone / discarded as corrupt (the
 * unclean-shutdown case decryptToTmp falls back from), so the DB is
 * restored from db.enc — below the tip. The rollback detector then refuses
 * boot with db/audit-rollback-detected even though the chain is perfectly
 * intact (it was a normal crash, not a rollback attack or a deletion).
 *
 * This test reproduces that crash window and asserts the CORRECT behavior:
 * a clean reopen with the chain readable, no false rollback refusal. If
 * checkpoint() left the tip ahead of the durable rows (issue #62), the
 * reopen throws db/audit-rollback-detected and this test FAILS.
 *
 * Scratch dir lives under the repo-local .test-output (not os.tmpdir):
 * the crash simulation corrupts the working file in place, which static
 * analysis (CodeQL js/insecure-temporary-file) flags as an insecure
 * OS-temp-dir write. A gitignored per-test dir outside the shared OS temp
 * dir sidesteps that false positive and keeps test isolation clean.
 */

var helpers = require("../helpers");
var b                    = helpers.b;
var check                = helpers.check;
var fs                   = helpers.fs;
var path                 = helpers.path;
var setupTestDb          = helpers.setupTestDb;
var teardownTestDb       = helpers.teardownTestDb;
var setTestPassphraseEnv = helpers.setTestPassphraseEnv;

var SCHEMA = [{ name: "ckpt_t", columns: { _id: "TEXT PRIMARY KEY", v: "TEXT" } }];

function currentMaxCounter() {
  var row = b.db.prepare("SELECT MAX(monotonicCounter) AS m FROM audit_log").get();
  return row && row.m ? Number(row.m) : 0;
}

function readTipCounter(tmpDir) {
  var tipPath = path.join(tmpDir, "audit.tip");
  var tip = JSON.parse(fs.readFileSync(tipPath, "utf8"));
  return Number(tip.atMonotonicCounter);
}

// Simulate an unclean crash: close the SQLite handle WITHOUT re-encrypting
// (so db.enc keeps the last flushed snapshot), then corrupt the tmpfs
// working copy + stamp it newer than db.enc so the next boot's
// decryptToTmp discards it and restores the durable db.enc. This is the
// exact shape produced by an unclean shutdown / full tmpfs — the carrier
// of the post-checkpoint rows is lost, db.enc is the only durable state.
function simulateCrashDiscardingTmpfs(tmpDir) {
  b.db._resetForTest(); // drops the handle; leaves the working file on disk
  var workingDir = path.join(tmpDir, "tmpfs");
  var workingFile = fs.readdirSync(workingDir).filter(function (f) {
    return /\.db$/.test(f);
  })[0];
  var workingPath = path.join(workingDir, workingFile);
  var corruptFd = fs.openSync(workingPath, "r+");
  try {
    fs.writeSync(corruptFd,
      Buffer.from("not a sqlite database -- crash\n".repeat(8)), 0, undefined, 0);
  } finally {
    fs.closeSync(corruptFd);
  }
  var future = new Date(Date.now() + 60000);
  fs.utimesSync(workingPath, future, future);
}

async function reinitDbOnly(tmpDir) {
  // Re-wire audit-sign from the same passphrase; do NOT reset the vault so
  // the existing db.enc key still decrypts. Mirrors setupTestDb's pre-init
  // reset minus the vault reset (the boot-recovery path).
  setTestPassphraseEnv();
  b.audit._resetForTest();
  // Same disk-residency posture as setupTestDb: the fixture's scratch dir is
  // the repo-local .test-output (not a real tmpfs mount), so the v0.15.0
  // non-tmpfs tmpDir gate must be opted past explicitly here too — otherwise
  // db.init refuses with db/tmpdir-not-tmpfs on Linux (the gate is
  // platform-specific, so this only surfaces off Windows).
  await b.db.init({
    dataDir:             tmpDir,
    tmpDir:              path.join(tmpDir, "tmpfs"),
    schema:              SCHEMA,
    allowNonTmpfsTmpDir: true,
  });
}

async function run() {
  var scratchBase = path.join(__dirname, "..", ".test-output");
  fs.mkdirSync(scratchBase, { recursive: true });
  var tmpDir = fs.mkdtempSync(path.join(scratchBase, "audit-ckpt-rollback-"));
  try {
    await setupTestDb(tmpDir, SCHEMA);
    check("test runs in encrypted at-rest mode", b.db.getMode() === "encrypted");
    // Register an app namespace so safeEmit rows land in the chain (the
    // async handler drops events under unregistered namespaces).
    b.audit.registerNamespace("orders");

    // ---- Baseline: a clean checkpoint that IS flushed to durable disk ----
    b.audit.safeEmit({ action: "orders.baseline.one", outcome: "success" });
    b.audit.safeEmit({ action: "orders.baseline.two", outcome: "success" });
    await b.audit.flush();
    var baselineCkpt = await b.audit.checkpoint();
    check("baseline checkpoint anchored", baselineCkpt && baselineCkpt.atMonotonicCounter > 0);
    await b.db.flushToDisk(); // db.enc + tip now agree at the baseline counter
    var baselineCounter = currentMaxCounter();
    check("baseline tip agrees with durable rows",
          readTipCounter(tmpDir) === baselineCounter);

    // ---- More audit activity, then a checkpoint that is NOT flushed ----
    // These rows + the new checkpoint row live only in the tmpfs working
    // copy; db.enc is unchanged. checkpoint() advances the durable tip.
    b.audit.safeEmit({ action: "orders.post.one", outcome: "success" });
    b.audit.safeEmit({ action: "orders.post.two", outcome: "success" });
    b.audit.safeEmit({ action: "orders.post.three", outcome: "success" });
    await b.audit.flush();
    var advancedCounter = currentMaxCounter();
    check("new audit activity advanced the in-memory counter past baseline",
          advancedCounter > baselineCounter);

    var postCkpt = await b.audit.checkpoint();
    check("post-batch checkpoint anchored at the advanced counter",
          postCkpt && postCkpt.atMonotonicCounter === advancedCounter);

    // The tip is now durable and points at the advanced counter — but the
    // rows it anchors were never re-encrypted into db.enc.
    check("durable tip advanced to the post-checkpoint counter",
          readTipCounter(tmpDir) === advancedCounter);

    // ---- Crash: lose the tmpfs carrier; db.enc stays at the baseline ----
    simulateCrashDiscardingTmpfs(tmpDir);

    // ---- Reboot: must NOT falsely refuse with a rollback error ----
    // The chain is intact — db.enc holds a valid prefix of the same chain,
    // every row hashes correctly, no row was deleted. A normal crash that
    // lost unflushed rows is not a rollback attack. checkpoint() should
    // have flushed the rows durably before (or with) the tip so the tip
    // never references a counter that isn't on durable disk.
    var rollbackError = null;
    try {
      await reinitDbOnly(tmpDir);
    } catch (e) {
      rollbackError = e;
    }

    check("reopen after crash does NOT falsely refuse with a rollback error" +
          (rollbackError ? " (got: " + rollbackError.code + " — " + rollbackError.message + ")" : ""),
          rollbackError === null);

    // If the reopen succeeded, the recovered chain must be readable and the
    // app table intact — a real clean recovery, not a degraded boot.
    if (rollbackError === null) {
      var rows = await b.audit.query({ action: "orders.baseline.one" });
      check("recovered audit chain is readable (baseline row present)", rows.length === 1);
      var ckptVerify = await b.audit.verifyCheckpoints();
      check("recovered checkpoints verify clean", ckptVerify.ok === true);
    }
  } finally {
    try { b.db._resetForTest(); } catch (_e) { /* best effort */ }
    await teardownTestDb(tmpDir);
  }

  console.log("OK — audit checkpoint false-rollback tests");
}

module.exports = { run: run };
if (require.main === module) {
  // Rethrow on failure so Node exits non-zero, instead of logging the
  // caught error object — a taint analyzer traces a logged error back to
  // the test passphrase fixture (a non-secret constant) and raises a
  // false clear-text-logging alert.
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
