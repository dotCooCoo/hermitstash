const { describe, it } = require("node:test");
const assert = require("node:assert");
var vault = require("../../lib/vault");

describe("vault (ML-KEM-768)", function () {
  it("seal returns vault: prefixed string", function () {
    var sealed = vault.seal("secret data");
    assert.ok(sealed.startsWith("vault:"), "should start with vault: prefix");
    assert.ok(sealed.length > 100, "sealed data should be substantial (ML-KEM ciphertext)");
  });

  it("seal/unseal roundtrip", function () {
    var original = "sensitive value 12345";
    var sealed = vault.seal(original);
    var unsealed = vault.unseal(sealed);
    assert.strictEqual(unsealed, original);
  });

  it("different seals produce different ciphertext", function () {
    var s1 = vault.seal("same");
    var s2 = vault.seal("same");
    assert.notStrictEqual(s1, s2, "each seal uses new KEM encapsulation");
  });

  it("seal does not double-seal", function () {
    var sealed = vault.seal("test");
    var doubleSeal = vault.seal(sealed);
    assert.strictEqual(sealed, doubleSeal, "already-sealed values should pass through");
  });

  it("unseal returns non-sealed values as-is", function () {
    assert.strictEqual(vault.unseal("plaintext"), "plaintext");
    assert.strictEqual(vault.unseal(""), "");
    assert.strictEqual(vault.unseal(null), null);
  });

  it("tampered sealed data throws on unseal", function () {
    var sealed = vault.seal("data");
    var tampered = sealed.substring(0, sealed.length - 5) + "ZZZZZ";
    assert.throws(function () {
      vault.unseal(tampered);
    }, "tampered vault data should throw");
  });

  it("handles various data types via string coercion", function () {
    var tests = ["hello", "12345", "true", '{"key":"value"}', "a".repeat(1000)];
    for (var i = 0; i < tests.length; i++) {
      var unsealed = vault.unseal(vault.seal(tests[i]));
      assert.strictEqual(unsealed, tests[i], "roundtrip failed for: " + tests[i].substring(0, 20));
    }
  });

  it("seal returns null/empty for null/empty input", function () {
    assert.strictEqual(vault.seal(null), null);
    assert.strictEqual(vault.seal(""), "");
  });
});
