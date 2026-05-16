const { describe, it } = require("node:test");
const assert = require("node:assert");

var totp = require("../../lib/totp");

describe("totp", function () {
  describe("generateSecret()", function () {
    it("returns a base32 string of reasonable length", function () {
      var secret = totp.generateSecret();
      assert.ok(typeof secret === "string");
      // 128-byte secret (HMAC-SHA-512 block size). 128 bytes
      // base32-encoded → 205 chars (no padding) — Math.ceil(128 * 8 / 5).
      assert.ok(secret.length >= 200 && secret.length <= 210, "expected 200-210 chars, got " + secret.length);
      assert.ok(/^[A-Z2-7]+$/.test(secret), "should be valid base32 characters");
    });

    it("generates unique secrets each time", function () {
      var s1 = totp.generateSecret();
      var s2 = totp.generateSecret();
      assert.notStrictEqual(s1, s2, "secrets should differ");
    });
  });

  describe("verify()", function () {
    it("returns false for a wrong code", function () {
      // Use a fixed secret so the code "999999" is extremely unlikely to match
      var secret = "JBSWY3DPEHPK3PXP"; // base32 for "Hello!"
      var result = totp.verify(secret, "999999");
      assert.strictEqual(result, false, "wrong code should not verify");
    });

    it("returns false for empty code", function () {
      var secret = totp.generateSecret();
      assert.strictEqual(totp.verify(secret, ""), false);
    });

    it("returns false for non-numeric code", function () {
      var secret = totp.generateSecret();
      assert.strictEqual(totp.verify(secret, "abcdef"), false);
    });
  });

  describe("getUri()", function () {
    it("returns a string starting with otpauth://totp/", function () {
      var secret = totp.generateSecret();
      var uri = totp.getUri(secret, "user@example.com", "HermitStash");
      assert.ok(uri.startsWith("otpauth://totp/"), "should start with otpauth://totp/");
    });

    it("includes the secret parameter", function () {
      var secret = totp.generateSecret();
      var uri = totp.getUri(secret, "user@example.com", "HermitStash");
      assert.ok(uri.includes("secret=" + secret), "should include secret parameter");
    });

    it("includes the issuer", function () {
      var secret = totp.generateSecret();
      var uri = totp.getUri(secret, "user@example.com", "TestIssuer");
      assert.ok(uri.includes("issuer=TestIssuer"), "should include issuer");
    });

    it("uses HermitStash as default issuer", function () {
      var secret = totp.generateSecret();
      var uri = totp.getUri(secret, "user@example.com");
      assert.ok(uri.includes("issuer=HermitStash"), "should default to HermitStash");
    });

    it("includes algorithm and period", function () {
      var secret = totp.generateSecret();
      var uri = totp.getUri(secret, "user@example.com");
      // HMAC-SHA-512 + 8-digit codes; period 30s per RFC 6238.
      assert.ok(uri.includes("algorithm=SHA512"), "should include SHA512 algorithm");
      assert.ok(uri.includes("period=30"), "should include period");
      assert.ok(uri.includes("digits=8"), "should include 8 digits");
    });
  });

  describe("generateBackupCodes()", function () {
    it("returns 10 codes", function () {
      var codes = totp.generateBackupCodes();
      assert.strictEqual(codes.length, 10);
    });

    it("each code is 8 hex characters", function () {
      var codes = totp.generateBackupCodes();
      for (var i = 0; i < codes.length; i++) {
        assert.strictEqual(codes[i].length, 8, "code " + i + " should be 8 chars");
        assert.ok(/^[0-9a-f]{8}$/.test(codes[i]), "code " + i + " should be hex");
      }
    });

    it("codes are unique", function () {
      var codes = totp.generateBackupCodes();
      var unique = new Set(codes);
      assert.strictEqual(unique.size, 10, "all 10 codes should be unique");
    });
  });
});
