// F-1 regression: retention cleanup and encrypted archival both move the tamper
// chain's purge anchor and delete audit rows. If a retention delete raises the
// anchor to Y while an archival is mid-await, the archival's later _pruneArchived
// must NOT lower the anchor back below Y — doing so leaves the live floor at Y+1
// with the anchor claiming a lower counter, a permanent, self-perpetuating
// verifyChain "prevHash mismatch". The fix serializes both paths behind one mutex
// AND makes every anchor write monotonic (never-lower). This test models the
// archival prune landing AFTER a retention delete and asserts the chain stays ok.
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var os = require("os");
var path = require("path");
var fs = require("fs");

var dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "hs-audit-race-"));
process.env.HERMITSTASH_DATA_DIR = dataDir;
process.env.HERMITSTASH_DB_PATH = path.join(dataDir, "hermitstash.db");
// Also the directory lib/db sweeps at load, deleting every other
// hermitstash-*.db in it. Redirecting only the data directory leaves that on
// /dev/shm wherever it exists — which is CI — so concurrent test processes
// delete each other's databases there.
process.env.HERMITSTASH_TMPDIR = dataDir;

Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

var b = require("../../lib/vendor/blamejs");
var vault = require("../../lib/vault");
var db = require("../../lib/db");
var config = require("../../lib/config");
var audit = require("../../lib/audit");
var auditArchive = require("../../lib/audit-archive");

before(async function () {
  await vault.init();
  config.auditChainEnabled = true;
});
after(function () {
  config.auditChainEnabled = false;
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch {}
});

function liveChainRows() {
  return db.rawQuery("SELECT _id, monotonicCounter, rowHash FROM audit_log WHERE monotonicCounter IS NOT NULL ORDER BY monotonicCounter ASC");
}
function readAnchor() {
  return db.rawGet("SELECT lastPurgedCounter, lastPurgedRowHash FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'");
}
function verifyChain() {
  return b.auditChain.verifyChain(audit.chainQueryAll, "audit_log", {});
}

describe("audit purge-anchor race (F-1)", function () {
  it("a stale archival prune cannot lower the anchor below a newer retention floor", async function () {
    // Build a chain of 12 rows.
    for (var i = 0; i < 12; i++) {
      audit.log(audit.ACTIONS.LOGIN_SUCCESS, { performedBy: "race-" + i, details: "row " + i });
    }
    await audit.drainChain();

    var rows = liveChainRows();
    assert.ok(rows.length >= 12, "need at least 12 chained rows, got " + rows.length);

    // (1) An archival captures the OLDEST 4 rows and builds its manifest — its
    //     lastCounter is the 4th row's counter. This is the pre-await snapshot.
    var lowSlice = rows.slice(0, 4);
    var lowManifest = {
      chainEnabled: true,
      lastCounter: Number(lowSlice[3].monotonicCounter),
      lastRowHash: lowSlice[3].rowHash,
      id: "race-archive-low",
    };

    // (2) Retention fires mid-await: it advances the anchor to a HIGHER row (index 7)
    //     and deletes everything at/below it. Live floor is now row[8].
    var hi = rows[7];
    auditArchive.upsertPurgeAnchorNeverLower(Number(hi.monotonicCounter), hi.rowHash, "race-retention");
    db.rawExec("DELETE FROM audit_log WHERE monotonicCounter <= ?", Number(hi.monotonicCounter));

    var afterRetention = await verifyChain();
    assert.strictEqual(afterRetention.ok, true, "chain must verify after the retention delete: " + afterRetention.reason);

    // (3) The archival resumes and prunes its (now-stale) low slice. Under the fix
    //     this must NOT drag the anchor back down to the low slice's lastCounter.
    auditArchive._pruneArchived(lowSlice, lowManifest);

    var anchor = readAnchor();
    assert.strictEqual(Number(anchor.lastPurgedCounter), Number(hi.monotonicCounter),
      "anchor must stay at the higher retention floor, not drop to the stale archival slice");

    var afterPrune = await verifyChain();
    assert.strictEqual(afterPrune.ok, true,
      "chain must still verify after the late archival prune (no false tamper alarm): " + afterPrune.reason);
  });

  it("runExclusivePurge serializes overlapping mutating regions", async function () {
    // Two regions enter the serializer; the second must not begin until the first
    // releases, so their critical sections cannot interleave.
    var events = [];
    var slowResolve;
    var slow = new Promise(function (r) { slowResolve = r; });

    var p1 = auditArchive.runExclusivePurge(async function () {
      events.push("A-start");
      await slow;
      events.push("A-end");
    });
    var p2 = auditArchive.runExclusivePurge(async function () {
      events.push("B-start");
      events.push("B-end");
    });

    // Yield to the event loop once (flushes all pending microtasks) so A reaches
    // its awaited barrier. B must still be queued behind A — it cannot start while
    // A holds the lock, no matter how long we wait, since A is parked on `slow`.
    await new Promise(function (r) { setImmediate(r); });
    assert.deepStrictEqual(events, ["A-start"], "B must not start while A holds the lock");

    slowResolve();
    await Promise.all([p1, p2]);
    assert.deepStrictEqual(events, ["A-start", "A-end", "B-start", "B-end"],
      "regions must run to completion one at a time, in arrival order");
  });
});
