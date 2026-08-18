// F-6 regression: the row-hash chain is keyless, so a DB-write adversary who can
// edit every row can recompute a self-consistent chain and defeat verifyChain. A
// periodic PQC-signed checkpoint anchors the chain tip with the server's audit
// signing key; a later verify catches a full-chain rewrite the private key can't
// forge, and the linked checkpoint sequence catches truncation / reorder.
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var os = require("os");
var path = require("path");
var fs = require("fs");

var dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "hs-audit-ckpt-"));
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

async function writeRows(n, tag) {
  for (var i = 0; i < n; i++) {
    audit.log(audit.ACTIONS.LOGIN_SUCCESS, { performedBy: tag + "-" + i, details: "row " + i });
  }
  await audit.drainChain();
}

describe("audit chain PQC checkpoints (F-6)", function () {
  it("signs the current chain tip and the anchor verifies", async function () {
    await writeRows(5, "c1");
    var res = await auditArchive.checkpointNow();
    assert.strictEqual(res.ok, true, "checkpoint should be written");
    assert.ok(res.counter > 0 && typeof res.tipHash === "string");

    // The persisted anchor is a self-verifying PQC signature.
    var doc = JSON.parse(fs.readFileSync(path.join(dataDir, "audit-chain-checkpoints.json"), "utf8"));
    assert.strictEqual(doc.anchors.length, 1);
    // checkpointNow() already initialized the audit signing key via _ensureSigning().
    var one = b.auditSign.verifyAnchor(doc.anchors[doc.anchors.length - 1]);
    assert.strictEqual(one.ok, true, "the stored anchor's PQC signature must verify");

    var v = await auditArchive.verifyCheckpoints();
    assert.strictEqual(v.ok, true, "checkpoints must verify against the live tip: " + v.reason);
  });

  it("skips a checkpoint when the tip has not advanced", async function () {
    var res = await auditArchive.checkpointNow();
    assert.strictEqual(res.skipped, true, "a same-counter checkpoint must be skipped");
    assert.ok(/not advanced/.test(res.reason || ""));
  });

  it("chains a second checkpoint after the tip advances", async function () {
    await writeRows(3, "c2");
    var res = await auditArchive.checkpointNow();
    assert.strictEqual(res.ok, true);
    var v = await auditArchive.verifyCheckpoints();
    assert.strictEqual(v.ok, true, "the linked checkpoint sequence must verify: " + v.reason);
    assert.strictEqual(v.checkpoints, 2, "two checkpoints now recorded");
  });

  it("a rewritten chain tip fails checkpoint verification", async function () {
    var v0 = await auditArchive.verifyCheckpoints();
    assert.strictEqual(v0.ok, true);
    var counter = v0.counter;
    var signedTip = v0.tipHash;

    // Rewrite the live row at the checkpointed counter — the shape of a full-chain
    // recompute. The signed checkpoint pins the original tip hash.
    db.rawExec("UPDATE audit_log SET rowHash = ? WHERE monotonicCounter = ?", "f".repeat(128), counter);

    var v1 = await auditArchive.verifyCheckpoints();
    assert.strictEqual(v1.ok, false, "a rewritten tip must fail checkpoint verification");
    assert.ok(/rewritten|does not match|match/.test(v1.reason || ""), "reason should flag the tip mismatch: " + v1.reason);

    // Restoring the genuine hash makes it verify again — proving the checkpoint,
    // not some unrelated state, is what caught the rewrite.
    db.rawExec("UPDATE audit_log SET rowHash = ? WHERE monotonicCounter = ?", signedTip, counter);
    var v2 = await auditArchive.verifyCheckpoints();
    assert.strictEqual(v2.ok, true, "restoring the real tip hash verifies again: " + v2.reason);
  });

  it("a checkpointed row deleted without being archived fails as a truncation", async function () {
    // Deleting the tail is the other half of a chain rewrite: rather than
    // changing a row's hash, remove it. The purge anchor is what separates this
    // from a legitimate archival, so a row that is simply gone — with the anchor
    // still below it — has to be reported rather than passed over.
    await writeRows(2, "trunc");
    var res = await auditArchive.checkpointNow();
    assert.strictEqual(res.ok, true, "a fresh checkpoint is needed to delete under it");

    db.rawExec("DELETE FROM audit_log WHERE monotonicCounter = ?", res.counter);

    var v = await auditArchive.verifyCheckpoints();
    assert.strictEqual(v.ok, false, "a deleted checkpointed row must not verify");
    assert.strictEqual(Number(v.counter), Number(res.counter));
    assert.ok(/truncat|deleted without being archived/i.test(v.reason || ""),
      "reason should name the truncation: " + v.reason);
  });

  it("the same deletion verifies once the purge anchor records the archival", async function () {
    // Same missing row, legitimate cause. Archival advances the anchor to the
    // counter it purged, and verification has to accept that — otherwise every
    // deployment that ever archived would report its own audit chain as
    // tampered with.
    var v0 = await auditArchive.verifyCheckpoints();
    assert.strictEqual(v0.ok, false, "still the truncation from the previous case");

    auditArchive.upsertPurgeAnchorNeverLower(v0.counter, "a".repeat(128), "test-bundle");

    var v1 = await auditArchive.verifyCheckpoints();
    assert.strictEqual(v1.ok, true,
      "a row removed by a recorded archival is not a truncation: " + v1.reason);
  });

  it("an edited checkpoint file fails the linked-anchor check", async function () {
    // The anchors are linked and individually signed, so editing one on disk
    // breaks the sequence regardless of what the live rows say. Without this the
    // stored evidence could be pruned or reordered after the fact.
    var file = path.join(dataDir, "audit-chain-checkpoints.json");
    var original = fs.readFileSync(file, "utf8");
    var doc = JSON.parse(original);
    assert.ok(doc.anchors.length >= 2, "need at least two anchors to break a link");

    doc.anchors[0].tipHash = "0".repeat(128);
    fs.writeFileSync(file, JSON.stringify(doc));
    try {
      var v = await auditArchive.verifyCheckpoints();
      assert.strictEqual(v.ok, false, "an edited anchor must fail the chain check");
      assert.ok(v.breakAt !== undefined, "and should say where the chain broke: " + JSON.stringify(v));
    } finally {
      fs.writeFileSync(file, original);
    }

    var restored = await auditArchive.verifyCheckpoints();
    assert.strictEqual(restored.ok, true, "restoring the file verifies again: " + restored.reason);
  });
});
