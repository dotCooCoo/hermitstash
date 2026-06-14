// Regression coverage for the single-use replay claim that backs the 2FA
// single-use guarantee (TOTP step + backup code) and the cookie-ECIES
// in-window replay defense. The defense is only real if a repeat claim of the
// same value is actually refused.
const { describe, it } = require("node:test");
const assert = require("node:assert");
var b = require("../../lib/vendor/blamejs");
var replayNonce = require("../../lib/replay-nonce");

describe("replay-nonce single-use claim", function () {
  it("claims a key once; an immediate repeat of the same key is refused", async function () {
    var key = "k-" + b.crypto.generateToken(6);
    assert.strictEqual(await replayNonce.claimOnce(key, 60000), true, "first claim succeeds");
    assert.strictEqual(await replayNonce.claimOnce(key, 60000), false, "a concurrent/repeat claim is refused");
  });

  it("a distinct key is independent of another", async function () {
    var a = "k-" + b.crypto.generateToken(6);
    var c = "k-" + b.crypto.generateToken(6);
    assert.strictEqual(await replayNonce.claimOnce(a, 60000), true);
    assert.strictEqual(await replayNonce.claimOnce(c, 60000), true, "claiming one key does not consume a different key");
  });

  it("an already-expired TTL does not block (expiry is honored)", async function () {
    // A non-positive TTL makes expireAt <= now, so the claim is immediately
    // expired and a later claim of the same value succeeds — verifies the TTL is
    // actually applied, without a wall-clock sleep.
    var key = "k-" + b.crypto.generateToken(6);
    assert.strictEqual(await replayNonce.claimOnce(key, -1), true, "first claim records the nonce");
    assert.strictEqual(await replayNonce.claimOnce(key, 60000), true, "an expired prior claim does not block a fresh one");
  });
});
