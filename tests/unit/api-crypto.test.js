const { describe, it } = require("node:test");
const assert = require("node:assert");
var { encryptPayload, decryptPayload, generateApiKey } = require("../../lib/api-crypto");

describe("api-crypto (AES-256-GCM payload encryption)", function () {
  it("generateApiKey returns 32-byte base64url key", function () {
    var key = generateApiKey();
    assert.ok(key.length > 30, "key should be substantial");
    assert.ok(/^[A-Za-z0-9_-]+$/.test(key), "should be base64url");
    var buf = Buffer.from(key, "base64url");
    assert.strictEqual(buf.length, 32, "should decode to 32 bytes");
  });

  it("different keys each time", function () {
    var k1 = generateApiKey();
    var k2 = generateApiKey();
    assert.notStrictEqual(k1, k2);
  });

  it("encrypt/decrypt roundtrip", function () {
    var key = generateApiKey();
    var data = { email: "test@example.com", password: "secret123" };
    var encrypted = encryptPayload(data, key);
    assert.ok(typeof encrypted === "string");
    assert.ok(encrypted.length > 20);
    var decrypted = decryptPayload(encrypted, key);
    assert.deepStrictEqual(decrypted, data);
  });

  it("different encryptions produce different ciphertext", function () {
    var key = generateApiKey();
    var data = { same: true };
    var e1 = encryptPayload(data, key);
    var e2 = encryptPayload(data, key);
    assert.notStrictEqual(e1, e2, "random IV should produce different output");
  });

  it("wrong key fails decryption", function () {
    var key1 = generateApiKey();
    var key2 = generateApiKey();
    var encrypted = encryptPayload({ data: "test" }, key1);
    assert.throws(function () {
      decryptPayload(encrypted, key2);
    }, "wrong key should throw");
  });

  it("tampered payload fails decryption", function () {
    var key = generateApiKey();
    var encrypted = encryptPayload({ x: 1 }, key);
    var tampered = encrypted.substring(0, 10) + "AAAA" + encrypted.substring(14);
    assert.throws(function () {
      decryptPayload(tampered, key);
    }, "tampered data should throw");
  });

  it("handles complex nested objects", function () {
    var key = generateApiKey();
    var data = { users: [{ id: 1, name: "Alice" }], meta: { total: 1, page: 1 } };
    var decrypted = decryptPayload(encryptPayload(data, key), key);
    assert.deepStrictEqual(decrypted, data);
  });

  it("handles empty object", function () {
    var key = generateApiKey();
    var decrypted = decryptPayload(encryptPayload({}, key), key);
    assert.deepStrictEqual(decrypted, {});
  });

  it("rejects too-short payload", function () {
    var key = generateApiKey();
    var result = decryptPayload("abc", key);
    assert.strictEqual(result, null, "too-short payload should return null");
  });
});
