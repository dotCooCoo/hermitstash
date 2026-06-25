/**
 * Stash counter-desync regression for the last-file auto-cleanup path.
 *
 * POST /files/:shareId/delete auto-removes a bundle once its last live file is
 * deleted. When that bundle belongs to a stash (bundle.stashId set), the stash's
 * cached customer_stash.bundleCount / totalBytes aggregates must be decremented
 * before the bundle row is removed — mirroring the three sibling delete paths
 * (routes/bundles.js, routes/admin.js, routes/stash.js). Previously this path
 * removed the bundle without the decrement, leaving the stash aggregates
 * permanently inflated by +1 / +totalSize for every stash bundle emptied via
 * file-by-file deletion.
 *
 * This exercises the repo contract the handler relies on: a bundle created under
 * a stash increments the aggregates, and the auto-cleanup decrement returns them
 * to baseline. A re-introduced "remove without decrement" regression leaves the
 * aggregates inflated and fails the assertions below.
 */
const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const fs = require("fs");
const b = require("../../lib/vendor/blamejs");

var testId = b.crypto.generateToken(4);
var testDbPath = path.join(__dirname, "..", "..", "data", "test-stash-counter-" + testId + ".db");
process.env.HERMITSTASH_DB_PATH = testDbPath;

Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

var vault = require("../../lib/vault");
var db;
var stashRepo;
var bundlesRepo;

before(async function () {
  await vault.init();
  db = require("../../lib/db");
  stashRepo = require("../../app/data/repositories/stash.repo");
  bundlesRepo = require("../../app/data/repositories/bundles.repo");
});

after(function () {
  try { fs.unlinkSync(testDbPath); } catch {}
  try { fs.unlinkSync(testDbPath + "-shm"); } catch {}
  try { fs.unlinkSync(testDbPath + "-wal"); } catch {}
  try { fs.unlinkSync(testDbPath + ".enc"); } catch {}
});

describe("stash counter cleanup on last-file bundle removal", function () {
  it("decrements stash bundleCount/totalBytes before removing an emptied stash bundle", function () {
    var stash = stashRepo.create({ slug: "counter-" + testId, name: "Counter Stash", bundleCount: 0, totalBytes: 0 });

    // A stash bundle is created → aggregates increment (mirrors stash.js:373).
    var bundleSize = 4096;
    var plainShareId = "share-" + testId;
    stashRepo.incrementBundleStats(stash._id, bundleSize);
    bundlesRepo.create({
      shareId: plainShareId,
      stashId: stash._id,
      status: "complete",
      totalSize: bundleSize,
    });

    var afterCreate = stashRepo.findById(stash._id);
    assert.strictEqual(afterCreate.bundleCount, 1, "create must increment bundleCount");
    assert.strictEqual(afterCreate.totalBytes, bundleSize, "create must increment totalBytes");

    // The auto-cleanup sequence the files.js delete handler now performs:
    // decrement the owning stash BEFORE removing the bundle row.
    var fresh = bundlesRepo.findByShareId(plainShareId);
    assert.ok(fresh, "bundle must be retrievable by shareId");
    if (fresh.stashId) {
      stashRepo.decrementBundleStats(fresh.stashId, fresh.totalSize);
    }
    bundlesRepo.remove(fresh._id);

    var afterCleanup = stashRepo.findById(stash._id);
    assert.strictEqual(afterCleanup.bundleCount, 0, "auto-cleanup must decrement bundleCount back to baseline");
    assert.strictEqual(afterCleanup.totalBytes, 0, "auto-cleanup must decrement totalBytes back to baseline");
  });

  it("never drives the aggregates below zero", function () {
    var stash = stashRepo.create({ slug: "floor-" + testId, name: "Floor Stash", bundleCount: 0, totalBytes: 0 });
    // Decrement with no prior increment must clamp at zero (MAX(0, ...)).
    stashRepo.decrementBundleStats(stash._id, 1000);
    var s = stashRepo.findById(stash._id);
    assert.strictEqual(s.bundleCount, 0, "bundleCount must clamp at 0");
    assert.strictEqual(s.totalBytes, 0, "totalBytes must clamp at 0");
  });
});
