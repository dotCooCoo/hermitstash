/**
 * files.repo tombstone-exclusion regression.
 *
 * Sync-bundle deletes (handleSyncFileDelete) leave the row with status
 * "complete" and a deletedAt timestamp, clearing only storagePath /
 * encryptionKey. Content-serving lookups must treat such a row as gone so the
 * single-file download path 404s cleanly and the ZIP/folder handlers don't feed
 * a tombstone to storage.getFileStream (which would leak the deleted name into
 * the user-visible _MISSING_FILES.txt manifest).
 */
const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const fs = require("fs");
const b = require("../../lib/vendor/blamejs");

var testId = b.crypto.generateToken(4);
var testDbPath = path.join(__dirname, "..", "..", "data", "test-files-repo-tomb-" + testId + ".db");
process.env.HERMITSTASH_DB_PATH = testDbPath;

Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

var vault = require("../../lib/vault");
var db;
var filesRepo;

before(async function () {
  await vault.init();
  db = require("../../lib/db");
  filesRepo = require("../../app/data/repositories/files.repo");
});

after(function () {
  try { fs.unlinkSync(testDbPath); } catch {}
  try { fs.unlinkSync(testDbPath + "-shm"); } catch {}
  try { fs.unlinkSync(testDbPath + "-wal"); } catch {}
  try { fs.unlinkSync(testDbPath + ".enc"); } catch {}
});

// Returns { doc, shareId } — db.files.insert returns the SEALED row (shareId
// comes back as a vault.aad: ciphertext), so callers must keep the plaintext
// shareId they passed in to look the row up afterward.
function seedFile(over) {
  var now = new Date().toISOString();
  var shareId = b.crypto.generateToken(16);
  var doc = db.files.insert(Object.assign({
    shareId: shareId,
    bundleShareId: "bundle-share",
    originalName: "doc.pdf",
    relativePath: "doc.pdf",
    storagePath: "bundles/x/doc.pdf",
    mimeType: "application/pdf",
    size: 10,
    downloads: 0,
    status: "complete",
    createdAt: now,
    updatedAt: now,
  }, over || {}));
  return { doc: doc, shareId: shareId };
}

describe("files.repo tombstone exclusion", function () {
  it("findCompleteByShareId returns a live complete file", function () {
    var f = seedFile();
    var found = filesRepo.findCompleteByShareId(f.shareId);
    assert.ok(found, "live complete file should be found");
    assert.strictEqual(found.shareId, f.shareId);
    db.files.remove({ _id: f.doc._id });
  });

  it("findCompleteByShareId returns null for a deletedAt tombstone (status still complete)", function () {
    var f = seedFile({ deletedAt: new Date().toISOString(), storagePath: null, encryptionKey: null });
    var found = filesRepo.findCompleteByShareId(f.shareId);
    assert.strictEqual(found, null, "tombstone must not be served on the download path");
    db.files.remove({ _id: f.doc._id });
  });

  it("findCompleteByShareId still returns null for an incomplete (chunking) upload", function () {
    var f = seedFile({ status: "uploading" });
    var found = filesRepo.findCompleteByShareId(f.shareId);
    assert.strictEqual(found, null, "in-flight upload must not be served");
    db.files.remove({ _id: f.doc._id });
  });

  it("findLiveByBundleShareId excludes tombstones but keeps live files", function () {
    var share = "bundle-live-" + b.crypto.generateToken(4);
    var live = seedFile({ bundleShareId: share, originalName: "live.pdf", relativePath: "live.pdf" });
    var dead = seedFile({ bundleShareId: share, originalName: "secret-deleted.pdf", relativePath: "secret-deleted.pdf", deletedAt: new Date().toISOString(), storagePath: null, encryptionKey: null });

    var liveSet = filesRepo.findLiveByBundleShareId(share);
    var names = liveSet.map(function (f) { return f.originalName; });
    assert.ok(names.indexOf("live.pdf") !== -1, "live file should be present");
    assert.strictEqual(names.indexOf("secret-deleted.pdf"), -1, "deleted file name must not leak into the ZIP set");

    // The unfiltered variant still returns the whole row set (used by delete /
    // last-file auto-cleanup paths that act on every row).
    var allSet = filesRepo.findByBundleShareId(share);
    assert.strictEqual(allSet.length, 2, "findByBundleShareId keeps tombstones for row-set callers");

    db.files.remove({ _id: live.doc._id });
    db.files.remove({ _id: dead.doc._id });
  });
});
