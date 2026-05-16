const { describe, it } = require("node:test");
const assert = require("node:assert");
var b = require("../../lib/vendor/blamejs");
var hashPassword = function (p) { return b.auth.password.hash(String(p)); };
var verifyPassword = function (p, h) { return b.auth.password.verify(h, String(p)); };

describe("password (Argon2id)", function () {
  it("hashPassword returns Argon2id format", async function () {
    var hash = await hashPassword("test123");
    assert.ok(hash.startsWith("$argon2id$"), "should start with $argon2id$ prefix, got: " + hash.substring(0, 20));
    assert.ok(hash.length > 50, "hash should be substantial length");
  });

  it("different hashes for same password (random salt)", async function () {
    var h1 = await hashPassword("same");
    var h2 = await hashPassword("same");
    assert.notStrictEqual(h1, h2, "Argon2id should use random salt each time");
  });

  it("verifyPassword accepts correct password", async function () {
    var hash = await hashPassword("correct");
    var result = await verifyPassword("correct", hash);
    assert.strictEqual(result, true);
  });

  it("verifyPassword rejects wrong password", async function () {
    var hash = await hashPassword("correct");
    var result = await verifyPassword("wrong", hash);
    assert.strictEqual(result, false);
  });

  it("rejects empty password (b.auth.password security default)", async function () {
    await assert.rejects(
      function () { return hashPassword(""); },
      function (err) { return err.code === "auth-password/invalid-plain"; },
    );
  });

  it("handles numeric and special char passwords", async function () {
    var hash = await hashPassword("p@$$w0rd!#%&*()");
    assert.ok(hash.startsWith("$argon2id$"));
    var result = await verifyPassword("p@$$w0rd!#%&*()", hash);
    assert.strictEqual(result, true);
  });

  it("coerces non-string input to string", async function () {
    var hash = await hashPassword(12345);
    var result = await verifyPassword(12345, hash);
    assert.strictEqual(result, true);
  });
});
