const { describe, it } = require("node:test");
const assert = require("node:assert");
var b = require("../../lib/vendor/blamejs");
// Argon2id moved to b.auth.password.* during the v1.9.x migration.
// Local wrappers preserve the test's call shape.
var hashPassword   = function (p) { return b.auth.password.hash(String(p)); };
var verifyPassword = function (p, h) { return b.auth.password.verify(h, String(p)); };
const {
  sha3Hash, hashEmail, generateEncryptionKeyPair, encrypt, decrypt,
} = require("../../lib/crypto");

describe("crypto module", function () {
  describe("SHA3-512 hashing", function () {
    it("sha3Hash returns 128 hex chars", function () {
      var hash = sha3Hash("hello");
      assert.strictEqual(hash.length, 128, "SHA3-512 should produce 128 hex chars");
      assert.ok(/^[0-9a-f]+$/.test(hash), "should be hex");
    });

    it("sha3Hash is deterministic", function () {
      assert.strictEqual(sha3Hash("test"), sha3Hash("test"));
    });

    it("sha3Hash differs for different inputs", function () {
      assert.notStrictEqual(sha3Hash("a"), sha3Hash("b"));
    });

  });

  describe("hashEmail", function () {
    it("returns consistent hash for same email", function () {
      assert.strictEqual(hashEmail("user@example.com"), hashEmail("user@example.com"));
    });

    it("normalizes to lowercase", function () {
      assert.strictEqual(hashEmail("USER@EXAMPLE.COM"), hashEmail("user@example.com"));
    });

    it("different emails produce different hashes", function () {
      assert.notStrictEqual(hashEmail("a@b.com"), hashEmail("c@d.com"));
    });

    it("returns null for null/empty", function () {
      assert.strictEqual(hashEmail(null), null);
      assert.strictEqual(hashEmail(""), null);
    });

    it("includes prefix to prevent collisions", function () {
      // hashEmail("x") should differ from sha3Hash("x") due to "hs-email:" prefix
      assert.notStrictEqual(hashEmail("x"), sha3Hash("x"));
    });
  });

  describe("ML-KEM-768 + AES-256-GCM", function () {
    it("generateEncryptionKeyPair returns PEM keys", function () {
      var pair = generateEncryptionKeyPair();
      assert.ok(pair.publicKey.startsWith("-----BEGIN PUBLIC KEY-----"));
      assert.ok(pair.privateKey.startsWith("-----BEGIN PRIVATE KEY-----"));
    });

    it("encrypt/decrypt roundtrip", function () {
      var pair = generateEncryptionKeyPair();
      var plaintext = "Hello post-quantum world!";
      var encrypted = encrypt(plaintext, pair.publicKey);
      assert.ok(encrypted.length > 100, "ciphertext should be substantial");
      assert.notStrictEqual(encrypted, plaintext);
      var decrypted = decrypt(encrypted, pair.privateKey);
      assert.strictEqual(decrypted, plaintext);
    });

    it("different encryptions produce different ciphertext", function () {
      var pair = generateEncryptionKeyPair();
      var e1 = encrypt("same", pair.publicKey);
      var e2 = encrypt("same", pair.publicKey);
      assert.notStrictEqual(e1, e2, "each encryption uses new KEM encapsulation");
    });

    it("wrong key fails decryption", function () {
      var pair1 = generateEncryptionKeyPair();
      var pair2 = generateEncryptionKeyPair();
      var encrypted = encrypt("secret", pair1.publicKey);
      assert.throws(function () {
        decrypt(encrypted, pair2.privateKey);
      }, "decrypting with wrong key should throw");
    });

    it("tampered ciphertext fails decryption", function () {
      var pair = generateEncryptionKeyPair();
      var encrypted = encrypt("data", pair.publicKey);
      var tampered = encrypted.substring(0, encrypted.length - 5) + "AAAAA";
      assert.throws(function () {
        decrypt(tampered, pair.privateKey);
      }, "tampered ciphertext should throw");
    });

    it("handles unicode and long strings", function () {
      var pair = generateEncryptionKeyPair();
      var unicode = "Hello world! Emoji test. Multi-line\nstring.";
      var decrypted = decrypt(encrypt(unicode, pair.publicKey), pair.privateKey);
      assert.strictEqual(decrypted, unicode);
    });
  });
});
