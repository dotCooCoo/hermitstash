const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const b = require("../../lib/vendor/blamejs");

// Use an isolated test database
var testId = b.crypto.generateToken(4);
var testDbPath = path.join(__dirname, "..", "..", "data", "test-db-unit-" + testId + ".db");
process.env.HERMITSTASH_DB_PATH = testDbPath;

// Clear module cache so db.js loads fresh
Object.keys(require.cache).forEach(function (k) {
  if (k.includes("lib/db") || k.includes("lib\\db")) delete require.cache[k];
});

var db = require("../../lib/db");

after(function () {
  try { fs.unlinkSync(testDbPath); } catch {}
  try { fs.unlinkSync(testDbPath + "-shm"); } catch {}
  try { fs.unlinkSync(testDbPath + "-wal"); } catch {}
  try { fs.unlinkSync(testDbPath + ".enc"); } catch {}
  try { fs.unlinkSync(testDbPath.replace(".db", "") + ".db.enc"); } catch {}
});

describe("db.Collection", function () {
  describe("insert", function () {
    it("generates _id if not provided", function () {
      var doc = db.users.insert({ email: "test@test.com", displayName: "Test" });
      assert.ok(doc._id, "should have _id");
      // insert returns the sealed doc; read via findOne auto-unseals
      var found = db.users.findOne({ _id: doc._id });
      assert.strictEqual(found.email, "test@test.com");
      db.users.remove({ _id: doc._id });
    });

    it("uses provided _id", function () {
      var doc = db.users.insert({ _id: "custom123", email: "c@c.com" });
      assert.strictEqual(doc._id, "custom123");
      db.users.remove({ _id: "custom123" });
    });

    it("returns a copy, not a reference", function () {
      var doc = db.users.insert({ email: "ref@test.com" });
      doc.email = "mutated";
      var found = db.users.findOne({ _id: doc._id });
      assert.strictEqual(found.email, "ref@test.com", "mutation should not affect DB");
      db.users.remove({ _id: doc._id });
    });
  });

  describe("findOne", function () {
    it("finds by indexed column", function () {
      var doc = db.files.insert({ shareId: "abc123", originalName: "test.pdf", status: "complete" });
      var found = db.files.findOne({ shareId: "abc123" });
      assert.ok(found);
      assert.strictEqual(found.originalName, "test.pdf");
      db.files.remove({ _id: doc._id });
    });

    it("returns null for no match", function () {
      var found = db.files.findOne({ shareId: "nonexistent" });
      assert.strictEqual(found, null);
    });

    it("supports multi-field query", function () {
      var doc = db.files.insert({ shareId: "multi1", status: "complete", uploadedBy: "user1" });
      var found = db.files.findOne({ shareId: "multi1", status: "complete" });
      assert.ok(found);
      var notFound = db.files.findOne({ shareId: "multi1", status: "uploading" });
      assert.strictEqual(notFound, null);
      db.files.remove({ _id: doc._id });
    });
  });

  describe("find", function () {
    it("returns all with empty query", function () {
      var before = db.bundles.find({}).length;
      db.bundles.insert({ shareId: "b1", status: "complete" });
      db.bundles.insert({ shareId: "b2", status: "complete" });
      var all = db.bundles.find({});
      assert.strictEqual(all.length, before + 2, "should have exactly 2 more bundles");
      db.bundles.remove({ shareId: "b1" });
      db.bundles.remove({ shareId: "b2" });
    });

    it("returns copies not references", function () {
      var doc = db.files.insert({ shareId: "reftest", status: "complete" });
      var results = db.files.find({ shareId: "reftest" });
      results[0].shareId = "mutated";
      var fresh = db.files.findOne({ _id: doc._id });
      assert.strictEqual(fresh.shareId, "reftest");
      db.files.remove({ _id: doc._id });
    });
  });

  describe("$ne operator", function () {
    it("excludes matching records", function () {
      db.users.insert({ _id: "ne1", role: "admin", email: "ne1@t.com" });
      db.users.insert({ _id: "ne2", role: "user", email: "ne2@t.com" });
      var nonAdmins = db.users.find({ role: { $ne: "admin" } });
      var hasAdmin = nonAdmins.some(function (u) { return u._id === "ne1"; });
      assert.strictEqual(hasAdmin, false, "should not include admin");
      var hasUser = nonAdmins.some(function (u) { return u._id === "ne2"; });
      assert.strictEqual(hasUser, true, "should include non-admin");
      db.users.remove({ _id: "ne1" });
      db.users.remove({ _id: "ne2" });
    });
  });

  describe("update", function () {
    it("$set updates fields", function () {
      var doc = db.users.insert({ email: "up@test.com", role: "user" });
      db.users.update({ _id: doc._id }, { $set: { role: "admin", lastLogin: "now" } });
      var updated = db.users.findOne({ _id: doc._id });
      assert.strictEqual(updated.role, "admin");
      assert.strictEqual(updated.lastLogin, "now");
      db.users.remove({ _id: doc._id });
    });

    it("$push appends to array", function () {
      var doc = db.bundles.insert({ shareId: "push1", skippedFiles: [] });
      db.bundles.update({ _id: doc._id }, { $push: { skippedFiles: { path: "a.exe", reason: "blocked" } } });
      var updated = db.bundles.findOne({ _id: doc._id });
      assert.strictEqual(updated.skippedFiles.length, 1);
      assert.strictEqual(updated.skippedFiles[0].path, "a.exe");
      db.bundles.remove({ _id: doc._id });
    });

    it("$push creates array if not exists", function () {
      var doc = db.bundles.insert({ shareId: "push2" });
      db.bundles.update({ _id: doc._id }, { $push: { skippedFiles: { path: "b.exe" } } });
      var updated = db.bundles.findOne({ _id: doc._id });
      assert.ok(Array.isArray(updated.skippedFiles));
      assert.strictEqual(updated.skippedFiles.length, 1);
      db.bundles.remove({ _id: doc._id });
    });

    it("returns count of updated records", function () {
      db.files.insert({ _id: "uc1", shareId: "uc", status: "uploading" });
      db.files.insert({ _id: "uc2", shareId: "uc", status: "uploading" });
      var count = db.files.update({ shareId: "uc" }, { $set: { status: "complete" } });
      assert.strictEqual(count, 2);
      db.files.remove({ _id: "uc1" });
      db.files.remove({ _id: "uc2" });
    });
  });

  describe("remove", function () {
    it("removes matching records", function () {
      db.files.insert({ _id: "rm1", shareId: "rmtest" });
      db.files.insert({ _id: "rm2", shareId: "rmtest" });
      var count = db.files.remove({ shareId: "rmtest" });
      assert.strictEqual(count, 2);
      assert.strictEqual(db.files.findOne({ _id: "rm1" }), null);
    });

    it("returns 0 for no match", function () {
      var count = db.files.remove({ _id: "nonexistent" });
      assert.strictEqual(count, 0);
    });
  });

  describe("count", function () {
    it("counts all with empty query", function () {
      var before = db.files.count();
      db.files.insert({ shareId: "cnt1" });
      assert.strictEqual(db.files.count(), before + 1);
      db.files.remove({ shareId: "cnt1" });
    });

    it("counts matching query", function () {
      db.files.insert({ _id: "ct1", status: "complete" });
      db.files.insert({ _id: "ct2", status: "uploading" });
      var c = db.files.count({ status: "complete" });
      assert.ok(c >= 1);
      db.files.remove({ _id: "ct1" });
      db.files.remove({ _id: "ct2" });
    });
  });

  describe("extra fields (JSON overflow)", function () {
    it("stores and retrieves non-column fields", function () {
      var doc = db.files.insert({ shareId: "extra1", customField: "hello", nested: { a: 1 } });
      var found = db.files.findOne({ _id: doc._id });
      assert.strictEqual(found.customField, "hello");
      assert.deepStrictEqual(found.nested, { a: 1 });
      db.files.remove({ _id: doc._id });
    });
  });

  describe("new tables and columns", function () {
    it("verification_tokens table exists", function () {
      var doc = db.verificationTokens.insert({ userId: "u1", token: "tok", type: "email", expiresAt: new Date().toISOString() });
      assert.ok(doc._id);
      var found = db.verificationTokens.findOne({ token: "tok" });
      assert.ok(found);
      assert.strictEqual(found.userId, "u1");
      db.verificationTokens.remove({ _id: doc._id });
    });

    it("credentials table exists", function () {
      var doc = db.credentials.insert({ userId: "u1", credentialId: "cid", publicKey: "pk", counter: 0 });
      assert.ok(doc._id);
      var found = db.credentials.findOne({ userId: "u1" });
      assert.ok(found);
      assert.strictEqual(found.credentialId, "cid");
      db.credentials.remove({ _id: doc._id });
    });

    it("emailHash column exists on users", function () {
      // Auto-seal computes emailHash from the email field automatically
      var doc = db.users.insert({ email: "eh@test.com" });
      // Query by plaintext email — auto-translated to emailHash lookup
      var found = db.users.findOne({ email: "eh@test.com" });
      assert.ok(found, "should find user by email (auto-translated to emailHash)");
      assert.strictEqual(found.email, "eh@test.com");
      // Verify the raw emailHash was computed
      var raw = db.users.raw().findOne({ _id: doc._id });
      assert.ok(raw.emailHash, "emailHash should be auto-computed");
      assert.ok(raw.emailHash.length > 50, "emailHash should be a SHA3 hash");
      db.users.remove({ _id: doc._id });
    });

    it("emailHash column exists on files", function () {
      var doc = db.files.insert({ shareId: "ehf1", emailHash: "filehash1" });
      var found = db.files.findOne({ emailHash: "filehash1" });
      assert.ok(found);
      db.files.remove({ _id: doc._id });
    });

    it("emailHash column exists on bundles", function () {
      var doc = db.bundles.insert({ shareId: "ehb1", emailHash: "bundlehash1" });
      var found = db.bundles.findOne({ emailHash: "bundlehash1" });
      assert.ok(found);
      db.bundles.remove({ _id: doc._id });
    });
  });

  describe("findPaginated", function () {
    it("returns paginated results with total", function () {
      for (var i = 0; i < 5; i++) db.files.insert({ shareId: "pg" + i, status: "complete", createdAt: new Date().toISOString() });
      var result = db.files.findPaginated({ status: "complete" }, { limit: 2, offset: 0 });
      assert.strictEqual(result.data.length, 2, "page should contain exactly 2 items");
      assert.strictEqual(result.total, 5, "total should be exactly 5");
      assert.strictEqual(result.limit, 2);
      for (var j = 0; j < 5; j++) db.files.remove({ shareId: "pg" + j });
    });
  });

  describe("searchPaginated", function () {
    it("searches across fields with LIKE on non-sealed fields", function () {
      // originalName is sealed in DB so SQL LIKE won't match sealed values.
      // Search on a non-sealed field (status) instead.
      db.files.insert({ shareId: "srch1", originalName: "report.pdf", status: "complete", createdAt: new Date().toISOString() });
      var result = db.files.searchPaginated(["status"], "complete", {}, { limit: 10 });
      assert.ok(result.total >= 1, "should find at least one result searching non-sealed field");
      db.files.remove({ shareId: "srch1" });
    });
  });
});
