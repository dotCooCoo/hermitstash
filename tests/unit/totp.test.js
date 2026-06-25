const { describe, it } = require("node:test");
const assert = require("node:assert");
const nodeCrypto = require("node:crypto");

var totp = require("../../lib/totp");

// Reconstruct the 6-digit RFC 4226 SHA-1 HOTP code an authenticator app would
// emit for a base32 secret + counter, so the legacy verify path can be exercised
// against a code computed independently of lib/totp.
var BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function legacySha1Code(secret, timeStep) {
  var bits = "";
  for (var i = 0; i < secret.length; i++) {
    var idx = BASE32.indexOf(secret[i].toUpperCase());
    if (idx === -1) continue;
    bits += idx.toString(2).padStart(5, "0");
  }
  var bytes = [];
  for (var j = 0; j + 8 <= bits.length; j += 8) bytes.push(parseInt(bits.substring(j, j + 8), 2));
  var key = Buffer.from(bytes);
  var time = Buffer.alloc(8);
  time.writeUInt32BE(0, 0);
  time.writeUInt32BE(timeStep, 4);
  var hmac = nodeCrypto.createHmac("sha1", key).update(time).digest();
  var offset = hmac[hmac.length - 1] & 0x0f;
  var code = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
  return String(code % 1000000).padStart(6, "0");
}

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

    it("verifies a legacy 6-digit SHA-1 code and returns the matched step", function () {
      // Pre-v1.9.11 enrollments used a 20-byte base32 secret + 6-digit SHA-1
      // codes; that path must still complete one final login through the
      // verify-only SHA-1 branch.
      var secret = "JBSWY3DPEHPK3PXP";
      var step = Math.floor(Date.now() / 30000);
      var code = legacySha1Code(secret, step);
      var result = totp.verify(secret, code, 0, "SHA1");
      assert.strictEqual(result, step, "valid SHA-1 code should return the matched step");
    });

    it("rejects a wrong SHA-1 code", function () {
      assert.strictEqual(totp.verify("JBSWY3DPEHPK3PXP", "000000", 0, "SHA1"), false);
    });

    it("rejects a replayed SHA-1 step (step <= lastUsedStep)", function () {
      var secret = "JBSWY3DPEHPK3PXP";
      var step = Math.floor(Date.now() / 30000);
      var code = legacySha1Code(secret, step);
      assert.strictEqual(totp.verify(secret, code, step, "SHA1"), false, "a replayed step must not verify");
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
