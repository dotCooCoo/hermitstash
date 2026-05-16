var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var fs = require("fs");
var crypto = require("crypto");
var b = require("../../lib/vendor/blamejs");

// Use an isolated test database so field-crypto + vault load cleanly
var testId = b.crypto.generateToken(4);
var testDbPath = path.join(__dirname, "..", "..", "data", "test-field-crypto-" + testId + ".db");
process.env.HERMITSTASH_DB_PATH = testDbPath;

// Clear require cache so all lib modules load fresh against the test DB
Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

var fieldCrypto = require("../../lib/field-crypto");
var vault = require("../../lib/vault");
var { sha3Hash } = require("../../lib/crypto");

// Cleanup after all tests
after(function () {
  try { fs.unlinkSync(testDbPath); } catch {}
  try { fs.unlinkSync(testDbPath + "-shm"); } catch {}
  try { fs.unlinkSync(testDbPath + "-wal"); } catch {}
  try { fs.unlinkSync(testDbPath + ".enc"); } catch {}
});

describe("field-crypto", function () {

  // ---- FIELD_SCHEMA ----

  describe("FIELD_SCHEMA", function () {
    it("exports FIELD_SCHEMA object", function () {
      assert.ok(fieldCrypto.FIELD_SCHEMA, "FIELD_SCHEMA should be exported");
      assert.strictEqual(typeof fieldCrypto.FIELD_SCHEMA, "object");
    });

    it("has schemas for all expected tables", function () {
      var expected = [
        "users", "files", "bundles", "audit_log", "blocked_ips",
        "api_keys", "webhooks", "credentials", "email_sends", "teams", "settings"
      ];
      for (var i = 0; i < expected.length; i++) {
        assert.ok(fieldCrypto.FIELD_SCHEMA[expected[i]], "missing schema for: " + expected[i]);
      }
    });

    it("users schema seals email and displayName", function () {
      var schema = fieldCrypto.FIELD_SCHEMA.users;
      assert.ok(schema.seal.includes("email"), "users should seal email");
      assert.ok(schema.seal.includes("displayName"), "users should seal displayName");
      assert.ok(schema.seal.includes("avatar"), "users should seal avatar");
      assert.ok(schema.seal.includes("googleId"), "users should seal googleId");
    });

    it("files schema has derived shareIdHash and emailHash", function () {
      var schema = fieldCrypto.FIELD_SCHEMA.files;
      assert.ok(schema.derived.shareIdHash, "files should have shareIdHash derived field");
      assert.ok(schema.derived.emailHash, "files should have emailHash derived field");
      assert.strictEqual(schema.derived.shareIdHash.from, "shareId");
      assert.strictEqual(schema.derived.emailHash.from, "uploaderEmail");
    });

    it("audit_log schema seals ip and action", function () {
      var schema = fieldCrypto.FIELD_SCHEMA.audit_log;
      assert.ok(schema.seal.includes("ip"), "audit_log should seal ip");
      assert.ok(schema.seal.includes("action"), "audit_log should seal action");
      assert.ok(schema.seal.includes("details"), "audit_log should seal details");
    });

    it("blocked_ips uses hash type for ip", function () {
      var schema = fieldCrypto.FIELD_SCHEMA.blocked_ips;
      assert.ok(schema.hash.includes("ip"), "blocked_ips should hash ip");
      assert.ok(schema.seal.includes("reason"), "blocked_ips should seal reason");
    });
  });

  // ---- sealDoc ----

  describe("sealDoc", function () {
    it("seals specified fields with vault prefix", function () {
      var doc = { email: "user@example.com", displayName: "Test User", role: "user" };
      var sealed = fieldCrypto.sealDoc("users", doc);
      assert.ok(String(sealed.email).startsWith("vault:"), "email should be vault-sealed");
      assert.ok(String(sealed.displayName).startsWith("vault:"), "displayName should be vault-sealed");
    });

    it("does not modify raw fields", function () {
      var doc = { email: "user@example.com", role: "admin", status: "active", _id: "abc123" };
      var sealed = fieldCrypto.sealDoc("users", doc);
      assert.strictEqual(sealed.role, "admin", "role should remain plaintext");
      assert.strictEqual(sealed.status, "active", "status should remain plaintext");
      assert.strictEqual(sealed._id, "abc123", "_id should remain plaintext");
    });

    it("computes derived emailHash for users", function () {
      var doc = { email: "Derived@Test.COM" };
      var sealed = fieldCrypto.sealDoc("users", doc);
      assert.ok(sealed.emailHash, "emailHash should be computed");
      var expected = sha3Hash("hs-email:derived@test.com");
      assert.strictEqual(sealed.emailHash, expected, "emailHash should match SHA3 of lowercased email with prefix");
    });

    it("computes derived shareIdHash for files", function () {
      var doc = { shareId: "share-abc-123", originalName: "test.pdf" };
      var sealed = fieldCrypto.sealDoc("files", doc);
      assert.ok(sealed.shareIdHash, "shareIdHash should be computed");
      var expected = sha3Hash("hs-share:share-abc-123");
      assert.strictEqual(sealed.shareIdHash, expected);
    });

    it("computes derived emailHash for bundles from uploaderEmail", function () {
      var doc = { uploaderEmail: "bundle@test.com", shareId: "bun1" };
      var sealed = fieldCrypto.sealDoc("bundles", doc);
      assert.ok(sealed.emailHash, "emailHash derived from uploaderEmail");
      var expected = sha3Hash("hs-email:bundle@test.com");
      assert.strictEqual(sealed.emailHash, expected);
    });

    it("computes bundleShareIdHash for files", function () {
      var doc = { bundleShareId: "bsid-999" };
      var sealed = fieldCrypto.sealDoc("files", doc);
      assert.ok(sealed.bundleShareIdHash, "bundleShareIdHash should be computed");
      var expected = sha3Hash("hs-share:bsid-999");
      assert.strictEqual(sealed.bundleShareIdHash, expected);
    });

    it("does not double-seal already sealed values", function () {
      var original = "sensitive data";
      var alreadySealed = vault.seal(original);
      var doc = { email: alreadySealed, displayName: "Plain Name" };
      var sealed = fieldCrypto.sealDoc("users", doc);
      // The sealed email should still unseal to the original value
      var unsealed = vault.unseal(sealed.email);
      assert.strictEqual(unsealed, original, "already-sealed value should not be double-sealed");
    });

    it("handles null fields gracefully", function () {
      var doc = { email: null, displayName: null, role: "user" };
      var sealed = fieldCrypto.sealDoc("users", doc);
      assert.strictEqual(sealed.email, null, "null email should remain null");
      assert.strictEqual(sealed.displayName, null, "null displayName should remain null");
    });

    it("handles undefined fields gracefully", function () {
      var doc = { role: "user" };
      var sealed = fieldCrypto.sealDoc("users", doc);
      assert.strictEqual(sealed.email, undefined, "missing email should remain undefined");
    });

    it("derived fields are null when source is null", function () {
      var doc = { email: null };
      var sealed = fieldCrypto.sealDoc("users", doc);
      assert.strictEqual(sealed.emailHash, undefined, "emailHash should not be computed from null source");
    });

    it("returns doc as-is for unknown table", function () {
      var doc = { foo: "bar", baz: 123 };
      var result = fieldCrypto.sealDoc("nonexistent_table", doc);
      assert.deepStrictEqual(result, doc, "unknown table should pass through unchanged");
    });

    it("does not mutate the original document", function () {
      var doc = { email: "original@test.com", displayName: "Original" };
      var originalEmail = doc.email;
      fieldCrypto.sealDoc("users", doc);
      assert.strictEqual(doc.email, originalEmail, "original doc should not be mutated");
    });

    it("hashes ip field for blocked_ips table", function () {
      var doc = { ip: "192.168.1.1", reason: "spam" };
      var sealed = fieldCrypto.sealDoc("blocked_ips", doc);
      // ip should be hashed (not vault-sealed)
      assert.ok(!String(sealed.ip).startsWith("vault:"), "ip should be hashed, not vault-sealed");
      assert.ok(sealed.ip.length > 50, "ip hash should be substantial");
      // reason should be vault-sealed
      assert.ok(String(sealed.reason).startsWith("vault:"), "reason should be vault-sealed");
    });

    it("hashed ip is deterministic", function () {
      var doc1 = { ip: "10.0.0.1" };
      var doc2 = { ip: "10.0.0.1" };
      var sealed1 = fieldCrypto.sealDoc("blocked_ips", doc1);
      var sealed2 = fieldCrypto.sealDoc("blocked_ips", doc2);
      assert.strictEqual(sealed1.ip, sealed2.ip, "same IP should produce same hash");
    });

    it("seals all audit_log fields", function () {
      var doc = {
        action: "login_success",
        targetId: "user-1",
        targetEmail: "t@t.com",
        performedBy: "admin-1",
        performedByEmail: "admin@t.com",
        details: "Logged in from Chrome",
        ip: "1.2.3.4"
      };
      var sealed = fieldCrypto.sealDoc("audit_log", doc);
      assert.ok(String(sealed.action).startsWith("vault:"), "action should be sealed");
      assert.ok(String(sealed.targetId).startsWith("vault:"), "targetId should be sealed");
      assert.ok(String(sealed.targetEmail).startsWith("vault:"), "targetEmail should be sealed");
      assert.ok(String(sealed.performedBy).startsWith("vault:"), "performedBy should be sealed");
      assert.ok(String(sealed.performedByEmail).startsWith("vault:"), "performedByEmail should be sealed");
      assert.ok(String(sealed.details).startsWith("vault:"), "details should be sealed");
      assert.ok(String(sealed.ip).startsWith("vault:"), "ip should be sealed");
    });

    it("derives correct hash when source is already sealed", function () {
      var email = "presealed@test.com";
      var sealedEmail = vault.seal(email);
      var doc = { email: sealedEmail };
      var sealed = fieldCrypto.sealDoc("users", doc);
      // emailHash should still be computed from the plaintext email
      var expected = sha3Hash("hs-email:presealed@test.com");
      assert.strictEqual(sealed.emailHash, expected, "derived hash should unseal source before hashing");
    });
  });

  // ---- unsealDoc ----

  describe("unsealDoc", function () {
    it("unseals vault-sealed fields back to plaintext", function () {
      var doc = { email: "test@unseal.com", displayName: "Unseal Me" };
      var sealed = fieldCrypto.sealDoc("users", doc);
      var unsealed = fieldCrypto.unsealDoc("users", sealed);
      assert.strictEqual(unsealed.email, "test@unseal.com");
      assert.strictEqual(unsealed.displayName, "Unseal Me");
    });

    it("preserves raw fields unchanged", function () {
      var doc = { email: "raw@test.com", role: "admin", status: "active", _id: "xyz" };
      var sealed = fieldCrypto.sealDoc("users", doc);
      var unsealed = fieldCrypto.unsealDoc("users", sealed);
      assert.strictEqual(unsealed.role, "admin");
      assert.strictEqual(unsealed.status, "active");
      assert.strictEqual(unsealed._id, "xyz");
    });

    it("returns null/falsy doc as-is", function () {
      assert.strictEqual(fieldCrypto.unsealDoc("users", null), null);
      assert.strictEqual(fieldCrypto.unsealDoc("users", undefined), undefined);
    });

    it("returns doc as-is for unknown table", function () {
      var doc = { foo: "bar" };
      var result = fieldCrypto.unsealDoc("nonexistent_table", doc);
      assert.deepStrictEqual(result, doc);
    });

    it("returns doc as-is for table with no seal fields", function () {
      // team_members has no schema entry at all
      var doc = { teamId: "t1", userId: "u1" };
      var result = fieldCrypto.unsealDoc("team_members", doc);
      assert.deepStrictEqual(result, doc);
    });

    it("handles null sealed fields without error", function () {
      var doc = { email: null, displayName: null, role: "user" };
      var result = fieldCrypto.unsealDoc("users", doc);
      // null fields should remain null (no attempt to unseal)
      assert.strictEqual(result.role, "user");
    });

    it("leaves non-sealed string values as-is", function () {
      // If a seal field has a plaintext value (not vault: prefixed), unseal returns it as-is
      var doc = { email: "plaintext@test.com", displayName: "Name" };
      var result = fieldCrypto.unsealDoc("users", doc);
      assert.strictEqual(result.email, "plaintext@test.com");
      assert.strictEqual(result.displayName, "Name");
    });

    it("does not mutate the original sealed document", function () {
      var doc = { email: "mutate@test.com" };
      var sealed = fieldCrypto.sealDoc("users", doc);
      var sealedEmailBefore = sealed.email;
      fieldCrypto.unsealDoc("users", sealed);
      assert.strictEqual(sealed.email, sealedEmailBefore, "original sealed doc should not be mutated");
    });

    it("roundtrips all files seal fields correctly", function () {
      var doc = {
        shareId: "roundtrip-share",
        originalName: "document.pdf",
        relativePath: "uploads/document.pdf",
        storagePath: "/data/uploads/abc123",
        mimeType: "application/pdf",
        uploaderEmail: "uploader@example.com",
        encryptionKey: "base64keydata==",
        bundleShareId: "bundle-rt-1"
      };
      var sealed = fieldCrypto.sealDoc("files", doc);
      var unsealed = fieldCrypto.unsealDoc("files", sealed);
      assert.strictEqual(unsealed.shareId, "roundtrip-share");
      assert.strictEqual(unsealed.originalName, "document.pdf");
      assert.strictEqual(unsealed.relativePath, "uploads/document.pdf");
      assert.strictEqual(unsealed.storagePath, "/data/uploads/abc123");
      assert.strictEqual(unsealed.mimeType, "application/pdf");
      assert.strictEqual(unsealed.uploaderEmail, "uploader@example.com");
      assert.strictEqual(unsealed.encryptionKey, "base64keydata==");
      assert.strictEqual(unsealed.bundleShareId, "bundle-rt-1");
    });
  });

  // ---- lookupHash ----

  describe("lookupHash", function () {
    it("returns emailHash lookup for users.email", function () {
      var result = fieldCrypto.lookupHash("users", "email", "lookup@test.com");
      assert.ok(result, "should return a lookup object");
      assert.strictEqual(result.key, "emailHash");
      var expected = sha3Hash("hs-email:lookup@test.com");
      assert.strictEqual(result.value, expected);
    });

    it("returns shareIdHash lookup for files.shareId", function () {
      var result = fieldCrypto.lookupHash("files", "shareId", "share-xyz");
      assert.ok(result);
      assert.strictEqual(result.key, "shareIdHash");
      assert.strictEqual(result.value, sha3Hash("hs-share:share-xyz"));
    });

    it("returns emailHash lookup for files.uploaderEmail", function () {
      var result = fieldCrypto.lookupHash("files", "uploaderEmail", "file@test.com");
      assert.ok(result);
      assert.strictEqual(result.key, "emailHash");
    });

    it("returns emailHash lookup for bundles.uploaderEmail", function () {
      var result = fieldCrypto.lookupHash("bundles", "uploaderEmail", "bundle@test.com");
      assert.ok(result);
      assert.strictEqual(result.key, "emailHash");
    });

    it("returns shareIdHash lookup for bundles.shareId", function () {
      var result = fieldCrypto.lookupHash("bundles", "shareId", "bun-share");
      assert.ok(result);
      assert.strictEqual(result.key, "shareIdHash");
    });

    it("returns bundleShareIdHash lookup for files.bundleShareId", function () {
      var result = fieldCrypto.lookupHash("files", "bundleShareId", "bsid-abc");
      assert.ok(result);
      assert.strictEqual(result.key, "bundleShareIdHash");
    });

    it("returns null for blocked_ips.ip (no derived schema — hash-only table)", function () {
      // blocked_ips has hash fields but no derived fields, so lookupHash
      // short-circuits at the !schema.derived check before reaching HASH_FNS.
      // The ip hashing for blocked_ips is applied via sealDoc, not lookupHash.
      var result = fieldCrypto.lookupHash("blocked_ips", "ip", "192.168.0.1");
      assert.strictEqual(result, null, "blocked_ips has no derived schema so lookupHash returns null");
    });

    it("returns null for non-derived field", function () {
      var result = fieldCrypto.lookupHash("users", "role", "admin");
      assert.strictEqual(result, null);
    });

    it("returns null for unknown table", function () {
      var result = fieldCrypto.lookupHash("nonexistent", "email", "x@x.com");
      assert.strictEqual(result, null);
    });

    it("email lookup is case-insensitive", function () {
      var r1 = fieldCrypto.lookupHash("users", "email", "UPPER@CASE.COM");
      var r2 = fieldCrypto.lookupHash("users", "email", "upper@case.com");
      assert.strictEqual(r1.value, r2.value, "email lookups should be case-insensitive");
    });
  });

  // ---- getSealedFields ----

  describe("getSealedFields", function () {
    it("returns seal fields for users", function () {
      var fields = fieldCrypto.getSealedFields("users");
      assert.ok(Array.isArray(fields));
      assert.ok(fields.includes("email"));
      assert.ok(fields.includes("displayName"));
    });

    it("returns seal fields for audit_log", function () {
      var fields = fieldCrypto.getSealedFields("audit_log");
      assert.ok(fields.includes("action"));
      assert.ok(fields.includes("ip"));
      assert.ok(fields.includes("details"));
    });

    it("returns empty array for unknown table", function () {
      var fields = fieldCrypto.getSealedFields("nonexistent_table");
      assert.ok(Array.isArray(fields));
      assert.strictEqual(fields.length, 0);
    });

    it("returns empty array for table with explicitly empty seal list", function () {
      // verification_tokens is in FIELD_SCHEMA with seal: [] — all fields are
      // raw/derived/hash, nothing to encrypt.
      var fields = fieldCrypto.getSealedFields("verification_tokens");
      assert.ok(Array.isArray(fields));
      assert.strictEqual(fields.length, 0);
    });
  });
});
