var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var fs = require("fs");
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

// AAD-sealed values carry this prefix. Sealing now binds each value's AEAD tag
// to (table, _id, column, schemaVersion); b.vault.aad.isAadSealed recognizes it.
var AAD_PREFIX = "vault.aad:";

// New, distinct _id per doc so cross-row tests have non-colliding AAD identities.
function rid() { return b.crypto.generateToken(8); }

// Vault must be initialized before any seal/unseal (b.vault.aad has no sync
// fallback). registerWithBlamejs() runs from lib/db.js at module load; requiring
// it here guarantees the cryptoField tables are registered (an unregistered
// table makes b.cryptoField sealing a plaintext no-op).
before(async function () {
  await vault.init();
  require("../../lib/db");
  fieldCrypto.registerWithBlamejs();
});

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
    it("seals specified fields with the AAD vault prefix", function () {
      var id = rid();
      var doc = { _id: id, email: "user@example.com", displayName: "Test User", role: "user" };
      var sealed = fieldCrypto.sealDoc("users", doc, id);
      assert.ok(String(sealed.email).startsWith(AAD_PREFIX), "email should be AAD-sealed");
      assert.ok(String(sealed.displayName).startsWith(AAD_PREFIX), "displayName should be AAD-sealed");
      assert.ok(b.vault.aad.isAadSealed(sealed.email), "isAadSealed should recognize the sealed email");
      assert.notStrictEqual(sealed.email, "user@example.com", "sealed email must not equal plaintext");
      assert.notStrictEqual(sealed.displayName, "Test User", "sealed displayName must not equal plaintext");
    });

    it("does not modify raw fields", function () {
      var doc = { email: "user@example.com", role: "admin", status: "active", _id: "abc123" };
      var sealed = fieldCrypto.sealDoc("users", doc, doc._id);
      assert.strictEqual(sealed.role, "admin", "role should remain plaintext");
      assert.strictEqual(sealed.status, "active", "status should remain plaintext");
      assert.strictEqual(sealed._id, "abc123", "_id should remain plaintext");
    });

    it("computes derived emailHash for users", function () {
      var id = rid();
      var doc = { _id: id, email: "Derived@Test.COM" };
      var sealed = fieldCrypto.sealDoc("users", doc, id);
      assert.ok(sealed.emailHash, "emailHash should be computed");
      var expected = fieldCrypto.derivedKeyed("hs-email", "derived@test.com", false);
      assert.strictEqual(sealed.emailHash, expected, "emailHash should be the keyed MAC of the lowercased email");
      assert.notStrictEqual(sealed.emailHash, sha3Hash("hs-email:derived@test.com"), "emailHash must not be the legacy plaintext-recomputable digest");
    });

    it("computes derived shareIdHash for files", function () {
      var id = rid();
      var doc = { _id: id, shareId: "share-abc-123", originalName: "test.pdf" };
      var sealed = fieldCrypto.sealDoc("files", doc, id);
      assert.ok(sealed.shareIdHash, "shareIdHash should be computed");
      var expected = fieldCrypto.derivedKeyed("hs-share", "share-abc-123", false);
      assert.strictEqual(sealed.shareIdHash, expected);
    });

    it("computes derived emailHash for bundles from uploaderEmail", function () {
      var id = rid();
      var doc = { _id: id, uploaderEmail: "bundle@test.com", shareId: "bun1" };
      var sealed = fieldCrypto.sealDoc("bundles", doc, id);
      assert.ok(sealed.emailHash, "emailHash derived from uploaderEmail");
      var expected = fieldCrypto.derivedKeyed("hs-email", "bundle@test.com", false);
      assert.strictEqual(sealed.emailHash, expected);
    });

    it("computes bundleShareIdHash for files", function () {
      var id = rid();
      var doc = { _id: id, bundleShareId: "bsid-999" };
      var sealed = fieldCrypto.sealDoc("files", doc, id);
      assert.ok(sealed.bundleShareIdHash, "bundleShareIdHash should be computed");
      var expected = fieldCrypto.derivedKeyed("hs-share", "bsid-999", false);
      assert.strictEqual(sealed.bundleShareIdHash, expected);
    });

    it("does not double-seal an already AAD-sealed value", function () {
      var id = rid();
      var original = "sensitive data";
      var firstSeal = fieldCrypto.sealDoc("users", { _id: id, email: original }, id);
      // Feed the already-sealed doc back through sealDoc — it must pass the
      // sealed value through verbatim (no nested seal), so it still unseals.
      var secondSeal = fieldCrypto.sealDoc("users", { _id: id, email: firstSeal.email }, id);
      assert.strictEqual(secondSeal.email, firstSeal.email, "already-sealed value should not be re-sealed");
      var unsealed = fieldCrypto.unsealDoc("users", secondSeal, id);
      assert.strictEqual(unsealed.email, original, "already-sealed value should still unseal to the original");
    });

    it("handles null fields gracefully", function () {
      var id = rid();
      var doc = { _id: id, email: null, displayName: null, role: "user" };
      var sealed = fieldCrypto.sealDoc("users", doc, id);
      assert.strictEqual(sealed.email, null, "null email should remain null");
      assert.strictEqual(sealed.displayName, null, "null displayName should remain null");
    });

    it("handles undefined fields gracefully", function () {
      var id = rid();
      var doc = { _id: id, role: "user" };
      var sealed = fieldCrypto.sealDoc("users", doc, id);
      assert.strictEqual(sealed.email, undefined, "missing email should remain undefined");
    });

    it("derived fields are null when source is null", function () {
      var id = rid();
      var doc = { _id: id, email: null };
      var sealed = fieldCrypto.sealDoc("users", doc, id);
      assert.strictEqual(sealed.emailHash, undefined, "emailHash should not be computed from null source");
    });

    it("returns doc as-is for unknown table", function () {
      var doc = { foo: "bar", baz: 123 };
      var result = fieldCrypto.sealDoc("nonexistent_table", doc, "id");
      assert.deepStrictEqual(result, doc, "unknown table should pass through unchanged");
    });

    it("does not mutate the original document", function () {
      var id = rid();
      var doc = { _id: id, email: "original@test.com", displayName: "Original" };
      var originalEmail = doc.email;
      fieldCrypto.sealDoc("users", doc, id);
      assert.strictEqual(doc.email, originalEmail, "original doc should not be mutated");
    });

    it("hashes ip field for blocked_ips table", function () {
      var id = rid();
      var doc = { _id: id, ip: "192.168.1.1", reason: "spam" };
      var sealed = fieldCrypto.sealDoc("blocked_ips", doc, id);
      // ip should be hashed (not vault-sealed)
      assert.ok(!String(sealed.ip).startsWith("vault:"), "ip should be hashed, not vault-sealed");
      assert.ok(!b.vault.aad.isAadSealed(sealed.ip), "ip should be hashed, not AAD-sealed");
      assert.ok(sealed.ip.length > 50, "ip hash should be substantial");
      // reason should be AAD-sealed
      assert.ok(String(sealed.reason).startsWith(AAD_PREFIX), "reason should be AAD-sealed");
    });

    it("hashed ip is deterministic", function () {
      var doc1 = { _id: rid(), ip: "10.0.0.1" };
      var doc2 = { _id: rid(), ip: "10.0.0.1" };
      var sealed1 = fieldCrypto.sealDoc("blocked_ips", doc1, doc1._id);
      var sealed2 = fieldCrypto.sealDoc("blocked_ips", doc2, doc2._id);
      assert.strictEqual(sealed1.ip, sealed2.ip, "same IP should produce same hash");
    });

    it("seals all audit_log fields", function () {
      var id = rid();
      var doc = {
        _id: id,
        action: "login_success",
        targetId: "user-1",
        targetEmail: "t@t.com",
        performedBy: "admin-1",
        performedByEmail: "admin@t.com",
        details: "Logged in from Chrome",
        ip: "1.2.3.4"
      };
      var sealed = fieldCrypto.sealDoc("audit_log", doc, id);
      assert.ok(String(sealed.action).startsWith(AAD_PREFIX), "action should be sealed");
      assert.ok(String(sealed.targetId).startsWith(AAD_PREFIX), "targetId should be sealed");
      assert.ok(String(sealed.targetEmail).startsWith(AAD_PREFIX), "targetEmail should be sealed");
      assert.ok(String(sealed.performedBy).startsWith(AAD_PREFIX), "performedBy should be sealed");
      assert.ok(String(sealed.performedByEmail).startsWith(AAD_PREFIX), "performedByEmail should be sealed");
      assert.ok(String(sealed.details).startsWith(AAD_PREFIX), "details should be sealed");
      assert.ok(String(sealed.ip).startsWith(AAD_PREFIX), "ip should be sealed");
    });

    it("derives correct hash when source is already sealed", function () {
      var id = rid();
      var email = "presealed@test.com";
      var sealedEmail = fieldCrypto.sealDoc("users", { _id: id, email: email }, id).email;
      var doc = { _id: id, email: sealedEmail };
      var sealed = fieldCrypto.sealDoc("users", doc, id);
      // emailHash should still be computed from the plaintext email
      var expected = fieldCrypto.derivedKeyed("hs-email", "presealed@test.com", false);
      assert.strictEqual(sealed.emailHash, expected, "derived hash should unseal source before keyed hashing");
    });
  });

  // ---- AAD security properties (the point of the row-binding change) ----

  describe("AAD row binding", function () {
    it("cross-row swap fails closed (sealed value read under a different _id → null)", function () {
      var idA = rid();
      var idB = rid();
      var plaintext = "cross-row-secret@example.com";
      var sealed = fieldCrypto.sealDoc("users", { _id: idA, email: plaintext }, idA);

      // Same ciphertext, but presented as belonging to a different row.
      var swapped = { _id: idB, email: sealed.email };
      var unsealed = fieldCrypto.unsealDoc("users", swapped, idB);
      assert.strictEqual(unsealed.email, null,
        "value sealed for one row must not unseal under another row's _id");
      assert.notStrictEqual(unsealed.email, plaintext, "must not leak the plaintext");
      assert.notStrictEqual(unsealed.email, sealed.email, "must not echo the ciphertext");
    });

    it("cross-column swap fails closed (sealed value read under a different column → null)", function () {
      var id = rid();
      var plaintext = "cross-col-secret@example.com";
      var sealed = fieldCrypto.sealDoc("users", { _id: id, email: plaintext }, id);

      // Put the email's ciphertext into the displayName slot, same row.
      var swapped = { _id: id, displayName: sealed.email };
      var unsealed = fieldCrypto.unsealDoc("users", swapped, id);
      assert.strictEqual(unsealed.displayName, null,
        "value sealed for column 'email' must not unseal under column 'displayName'");
      assert.notStrictEqual(unsealed.displayName, plaintext, "must not leak the plaintext");
    });

    it("correct row + column round-trips (sanity counterpart to the fail-closed cases)", function () {
      var id = rid();
      var doc = { _id: id, email: "bound@example.com", displayName: "Bound User" };
      var sealed = fieldCrypto.sealDoc("users", doc, id);
      var unsealed = fieldCrypto.unsealDoc("users", sealed, id);
      assert.strictEqual(unsealed.email, "bound@example.com");
      assert.strictEqual(unsealed.displayName, "Bound User");
    });
  });

  // ---- falsy passthrough ----

  describe("falsy passthrough", function () {
    it("empty-string sealed field stays raw and round-trips to empty string", function () {
      var id = rid();
      var sealed = fieldCrypto.sealDoc("users", { _id: id, email: "" }, id);
      assert.strictEqual(sealed.email, "", "empty string should be stored raw");
      assert.ok(!b.vault.aad.isAadSealed(sealed.email), "empty string must not be AAD-sealed");
      assert.ok(!String(sealed.email).startsWith(AAD_PREFIX), "empty string must not carry the AAD prefix");
      var unsealed = fieldCrypto.unsealDoc("users", sealed, id);
      assert.strictEqual(unsealed.email, "", "empty string round-trips to empty string");
    });

    it("false-valued sealed boolean (vaultEnabled) stays false, not AAD-sealed", function () {
      var id = rid();
      // vaultEnabled is a sealed field in the users schema but a boolean in practice.
      var sealed = fieldCrypto.sealDoc("users", { _id: id, vaultEnabled: false }, id);
      assert.strictEqual(sealed.vaultEnabled, false, "false should be stored raw, not coerced to \"false\"");
      assert.ok(!b.vault.aad.isAadSealed(sealed.vaultEnabled), "false must not be AAD-sealed");
      var unsealed = fieldCrypto.unsealDoc("users", sealed, id);
      assert.strictEqual(unsealed.vaultEnabled, false, "false round-trips to false");
    });
  });

  // ---- legacy dual-read ----

  describe("legacy dual-read", function () {
    it("a legacy 'vault:'-sealed value still unseals through unsealDoc", function () {
      var id = rid();
      var plaintext = "legacy-secret-value";
      // Legacy path: vault.seal produces the old non-AAD "vault:" prefix — the
      // shape pre-AAD rows carry on disk.
      var legacySealed = vault.seal(plaintext);
      assert.ok(String(legacySealed).startsWith("vault:"), "fixture should be a legacy vault: value");
      assert.ok(!b.vault.aad.isAadSealed(legacySealed), "legacy value is not AAD-sealed");

      var doc = { _id: id, email: legacySealed };
      var unsealed = fieldCrypto.unsealDoc("users", doc, id);
      assert.strictEqual(unsealed.email, plaintext,
        "legacy vault:-sealed value must still decrypt (backward compat)");
    });
  });

  // ---- derived-hash compatibility under AAD sealing ----

  describe("derived-hash compatibility", function () {
    it("sealDoc emailHash matches lookupHash for the same email", function () {
      var id = rid();
      var sealed = fieldCrypto.sealDoc("users", { _id: id, email: "x@y.com" }, id);
      assert.ok(sealed.emailHash, "emailHash should be set");
      var lookup = fieldCrypto.lookupHash("users", "email", "x@y.com");
      assert.ok(lookup, "lookupHash should resolve for users.email");
      assert.strictEqual(sealed.emailHash, lookup.value,
        "the derived emailHash written at seal time must equal the lookup hash used in queries");
    });
  });

  // ---- unsealDoc ----

  describe("unsealDoc", function () {
    it("unseals AAD-sealed fields back to plaintext", function () {
      var id = rid();
      var doc = { _id: id, email: "test@unseal.com", displayName: "Unseal Me" };
      var sealed = fieldCrypto.sealDoc("users", doc, id);
      var unsealed = fieldCrypto.unsealDoc("users", sealed, id);
      assert.strictEqual(unsealed.email, "test@unseal.com");
      assert.strictEqual(unsealed.displayName, "Unseal Me");
    });

    it("preserves raw fields unchanged", function () {
      var doc = { email: "raw@test.com", role: "admin", status: "active", _id: "xyz" };
      var sealed = fieldCrypto.sealDoc("users", doc, doc._id);
      var unsealed = fieldCrypto.unsealDoc("users", sealed, doc._id);
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
      // verification_tokens has seal: [] — nothing to unseal.
      var doc = { _id: "vt1", token: "abc", type: "email" };
      var result = fieldCrypto.unsealDoc("verification_tokens", doc);
      assert.deepStrictEqual(result, doc);
    });

    it("handles null sealed fields without error", function () {
      var id = rid();
      var doc = { _id: id, email: null, displayName: null, role: "user" };
      var result = fieldCrypto.unsealDoc("users", doc, id);
      // null fields should remain null (no attempt to unseal)
      assert.strictEqual(result.role, "user");
    });

    it("leaves non-sealed string values as-is", function () {
      // A seal field holding plaintext (no vault prefix) is returned verbatim.
      var id = rid();
      var doc = { _id: id, email: "plaintext@test.com", displayName: "Name" };
      var result = fieldCrypto.unsealDoc("users", doc, id);
      assert.strictEqual(result.email, "plaintext@test.com");
      assert.strictEqual(result.displayName, "Name");
    });

    it("does not mutate the original sealed document", function () {
      var id = rid();
      var doc = { _id: id, email: "mutate@test.com" };
      var sealed = fieldCrypto.sealDoc("users", doc, id);
      var sealedEmailBefore = sealed.email;
      fieldCrypto.unsealDoc("users", sealed, id);
      assert.strictEqual(sealed.email, sealedEmailBefore, "original sealed doc should not be mutated");
    });

    it("roundtrips all files seal fields correctly", function () {
      var id = rid();
      var doc = {
        _id: id,
        shareId: "roundtrip-share",
        originalName: "document.pdf",
        relativePath: "uploads/document.pdf",
        storagePath: "/data/uploads/abc123",
        mimeType: "application/pdf",
        uploaderEmail: "uploader@example.com",
        encryptionKey: "base64keydata==",
        bundleShareId: "bundle-rt-1"
      };
      var sealed = fieldCrypto.sealDoc("files", doc, id);
      var unsealed = fieldCrypto.unsealDoc("files", sealed, id);
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
      var expected = fieldCrypto.derivedKeyed("hs-email", "lookup@test.com", false);
      assert.strictEqual(result.value, expected);
      // dual-read: candidates carry both the active keyed MAC and the legacy digest
      assert.ok(Array.isArray(result.candidates) && result.candidates.indexOf(expected) !== -1, "candidates include the keyed digest");
      assert.ok(result.candidates.indexOf(sha3Hash("hs-email:lookup@test.com")) !== -1, "candidates include the legacy digest");
    });

    it("returns shareIdHash lookup for files.shareId", function () {
      var result = fieldCrypto.lookupHash("files", "shareId", "share-xyz");
      assert.ok(result);
      assert.strictEqual(result.key, "shareIdHash");
      var expectedKeyed = fieldCrypto.derivedKeyed("hs-share", "share-xyz", false);
      assert.strictEqual(result.value, expectedKeyed);
      assert.ok(result.candidates.indexOf(sha3Hash("hs-share:share-xyz")) !== -1, "dual-read candidates include the legacy digest");
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

    it("translates blocked_ips.ip to its one-way hash so the blocklist matches", function () {
      // blocked_ips.ip is a one-way "hash" field: it is hashed on write, so a
      // findOne({ ip }) must translate the raw IP to the same digest or the
      // blocklist never matches (it short-circuited before HASH_FNS pre-fix).
      var result = fieldCrypto.lookupHash("blocked_ips", "ip", "192.168.0.1");
      assert.ok(result, "blocked_ips.ip should translate to its stored hash");
      assert.strictEqual(result.key, "ip");
      assert.strictEqual(result.value, b.crypto.namespaceHash("hs-blockedip", "192.168.0.1"));
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
