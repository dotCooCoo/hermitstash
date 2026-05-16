var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var fs = require("fs");
var crypto = require("crypto");
var b = require("../../lib/vendor/blamejs");

// Use an isolated test database
var testId = b.crypto.generateToken(4);
var testDbPath = path.join(__dirname, "..", "..", "data", "test-expiry-" + testId + ".db");
process.env.HERMITSTASH_DB_PATH = testDbPath;

// Clear require cache so all lib modules load fresh against the test DB
Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

var db = require("../../lib/db");
var storage = require("../../lib/storage");
// Expiry logic moved from lib/expiry to app/jobs/expiry-cleanup.job.js during
// the DDD refactor. Shim the old API shape so these tests still exercise the
// behavior without being rewritten end-to-end.
var expiryJob = require("../../app/jobs/expiry-cleanup.job");
var expiry = {
  cleanupExpired: async function () { return await expiryJob.cleanupExpiredFiles(); },
};

// Create a temp upload dir for file operations
var tempUploadDir = path.join(__dirname, "..", "..", "data", "test-expiry-uploads-" + testId);
if (!fs.existsSync(tempUploadDir)) fs.mkdirSync(tempUploadDir, { recursive: true });

after(function () {
  // Clean up temp files and DB
  try { fs.rmSync(tempUploadDir, { recursive: true, force: true }); } catch {}
  try { fs.unlinkSync(testDbPath); } catch {}
  try { fs.unlinkSync(testDbPath + "-shm"); } catch {}
  try { fs.unlinkSync(testDbPath + "-wal"); } catch {}
  try { fs.unlinkSync(testDbPath + ".enc"); } catch {}
});

// Helper: insert a file record with expiry date and optionally create a storage file
function insertTestFile(opts) {
  var fileId = opts.id || b.crypto.generateToken(6);
  var storagePath = opts.storagePath || null;

  // Create the actual file on disk if storagePath is provided
  if (storagePath) {
    var fullPath = path.join(storage.uploadDir, storagePath);
    var dir = path.dirname(fullPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(fullPath, "test-data-" + fileId);
  }

  var doc = db.files.insert({
    _id: fileId,
    shareId: "expiry-" + fileId,
    originalName: opts.name || "test.txt",
    storagePath: storagePath,
    status: "complete",
    size: 100,
    expiresAt: opts.expiresAt || null,
    createdAt: new Date().toISOString()
  });

  return doc;
}

describe("expiry", function () {

  describe("cleanupExpired", function () {
    it("exports cleanupExpired function", function () {
      assert.strictEqual(typeof expiry.cleanupExpired, "function");
    });

    it("removes expired files from the database", async function () {
      // Insert an expired file (yesterday)
      var yesterday = new Date(Date.now() - 86400000).toISOString();
      insertTestFile({
        id: "expired-db-1",
        expiresAt: yesterday,
        name: "expired.txt"
      });

      var countBefore = db.files.count();
      await expiry.cleanupExpired();
      var countAfter = db.files.count();

      assert.ok(countAfter < countBefore, "expired file should be removed from DB");
      assert.strictEqual(db.files.findOne({ _id: "expired-db-1" }), null, "expired file record should be gone");
    });

    it("removes expired files from disk", async function () {
      var yesterday = new Date(Date.now() - 86400000).toISOString();
      var storagePath = "expiry-test/" + testId + "/disk-remove.txt";
      insertTestFile({
        id: "expired-disk-1",
        expiresAt: yesterday,
        storagePath: storagePath,
        name: "disk-remove.txt"
      });

      var fullPath = path.join(storage.uploadDir, storagePath);
      assert.ok(fs.existsSync(fullPath), "test file should exist before cleanup");

      await expiry.cleanupExpired();

      assert.ok(!fs.existsSync(fullPath), "expired file should be removed from disk");
      assert.strictEqual(db.files.findOne({ _id: "expired-disk-1" }), null, "DB record should be removed");
    });

    it("preserves non-expired files", async function () {
      // Insert a file expiring tomorrow
      var tomorrow = new Date(Date.now() + 86400000).toISOString();
      insertTestFile({
        id: "notexpired-1",
        expiresAt: tomorrow,
        name: "future.txt"
      });

      await expiry.cleanupExpired();

      var found = db.files.findOne({ _id: "notexpired-1" });
      assert.ok(found, "non-expired file should be preserved");
      assert.strictEqual(found.originalName, "future.txt");

      // cleanup
      db.files.remove({ _id: "notexpired-1" });
    });

    it("preserves files with no expiresAt", async function () {
      insertTestFile({
        id: "noexpiry-1",
        expiresAt: null,
        name: "permanent.txt"
      });

      await expiry.cleanupExpired();

      var found = db.files.findOne({ _id: "noexpiry-1" });
      assert.ok(found, "file with no expiresAt should be preserved");

      db.files.remove({ _id: "noexpiry-1" });
    });

    it("handles multiple expired files at once", async function () {
      var pastDate = new Date(Date.now() - 3600000).toISOString();
      insertTestFile({ id: "multi-exp-1", expiresAt: pastDate });
      insertTestFile({ id: "multi-exp-2", expiresAt: pastDate });
      insertTestFile({ id: "multi-exp-3", expiresAt: pastDate });

      await expiry.cleanupExpired();

      assert.strictEqual(db.files.findOne({ _id: "multi-exp-1" }), null, "first expired file should be removed");
      assert.strictEqual(db.files.findOne({ _id: "multi-exp-2" }), null, "second expired file should be removed");
      assert.strictEqual(db.files.findOne({ _id: "multi-exp-3" }), null, "third expired file should be removed");
    });

    it("removes only expired files in a mixed set", async function () {
      var pastDate = new Date(Date.now() - 86400000).toISOString();
      var futureDate = new Date(Date.now() + 86400000).toISOString();

      insertTestFile({ id: "mixed-exp", expiresAt: pastDate });
      insertTestFile({ id: "mixed-future", expiresAt: futureDate });
      insertTestFile({ id: "mixed-none", expiresAt: null });

      await expiry.cleanupExpired();

      assert.strictEqual(db.files.findOne({ _id: "mixed-exp" }), null, "expired file should be removed");
      assert.ok(db.files.findOne({ _id: "mixed-future" }), "future file should be preserved");
      assert.ok(db.files.findOne({ _id: "mixed-none" }), "no-expiry file should be preserved");

      db.files.remove({ _id: "mixed-future" });
      db.files.remove({ _id: "mixed-none" });
    });

    it("handles file with null storagePath", async function () {
      var pastDate = new Date(Date.now() - 86400000).toISOString();
      insertTestFile({
        id: "nullpath-1",
        expiresAt: pastDate,
        storagePath: null
      });

      // Should not reject even with null storagePath
      await assert.doesNotReject(async function () {
        await expiry.cleanupExpired();
      });

      assert.strictEqual(db.files.findOne({ _id: "nullpath-1" }), null, "DB record should still be removed");
    });

    it("continues cleanup when individual file deletion fails", async function () {
      var pastDate = new Date(Date.now() - 86400000).toISOString();

      // Insert a file with a nonexistent storage path — deleteFile won't crash
      // because storage.deleteFile checks existsSync first
      insertTestFile({
        id: "fail-del-1",
        expiresAt: pastDate,
        storagePath: "nonexistent/path/file.txt"
      });
      insertTestFile({
        id: "fail-del-2",
        expiresAt: pastDate,
      });

      // Should not reject — errors are caught internally
      await assert.doesNotReject(async function () {
        await expiry.cleanupExpired();
      });

      // Both DB records should be removed regardless
      assert.strictEqual(db.files.findOne({ _id: "fail-del-1" }), null);
      assert.strictEqual(db.files.findOne({ _id: "fail-del-2" }), null);
    });

    it("does nothing when no files are expired", async function () {
      var futureDate = new Date(Date.now() + 86400000).toISOString();
      insertTestFile({ id: "safe-1", expiresAt: futureDate });
      insertTestFile({ id: "safe-2", expiresAt: null });

      var countBefore = db.files.count();
      await expiry.cleanupExpired();
      var countAfter = db.files.count();

      assert.strictEqual(countAfter, countBefore, "no files should be removed");

      db.files.remove({ _id: "safe-1" });
      db.files.remove({ _id: "safe-2" });
    });

    it("handles empty files table", async function () {
      // Remove all files first
      var allFiles = db.files.find({});
      for (var i = 0; i < allFiles.length; i++) {
        db.files.remove({ _id: allFiles[i]._id });
      }

      await assert.doesNotReject(async function () {
        await expiry.cleanupExpired();
      }, "should not reject on empty files table");
    });

    it("handles file expired at exactly current time boundary", async function () {
      // A file expiring 1 second ago should be treated as expired
      var justExpired = new Date(Date.now() - 1000).toISOString();
      insertTestFile({ id: "boundary-1", expiresAt: justExpired });

      await expiry.cleanupExpired();

      assert.strictEqual(db.files.findOne({ _id: "boundary-1" }), null, "just-expired file should be removed");
    });
  });
});
