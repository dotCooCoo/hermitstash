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
});
