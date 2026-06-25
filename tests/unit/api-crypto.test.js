const { describe, it } = require("node:test");
const assert = require("node:assert");
var fs = require("node:fs");
var path = require("node:path");
var b = require("../../lib/vendor/blamejs");
var { encryptPayload, decryptPayload, generateApiKey, FUTURE_SKEW_MS } = require("../../lib/api-crypto");

// Seal an arbitrary plaintext object into the production XChaCha20-Poly1305
// envelope (the exact shape encryptPayload emits), letting a test choose `_t`
// or omit `_d` to exercise the inner-AEAD freshness contract directly.
function sealEnvelope(obj, keyBase64) {
  var key = Buffer.from(keyBase64, "base64url");
  var plaintext = Buffer.from(JSON.stringify(obj), "utf8");
  return b.crypto.encryptPacked(plaintext, key).toString("base64url");
}

describe("api-crypto (XChaCha20-Poly1305 payload encryption)", function () {
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
    assert.notStrictEqual(e1, e2, "random nonce should produce different output");
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

describe("api-crypto replay-window freshness contract", function () {
  it("FUTURE_SKEW_MS is exported as the shared future-skew bound", function () {
    assert.strictEqual(typeof FUTURE_SKEW_MS, "number");
    assert.ok(FUTURE_SKEW_MS > 0, "future-skew tolerance must be positive");
  });

  it("accepts a fresh, current-_t envelope when a replay window is set", function () {
    var key = generateApiKey();
    var sealed = sealEnvelope({ _d: { ok: true }, _t: Date.now() }, key);
    var out = decryptPayload(sealed, key, 30000);
    assert.deepStrictEqual(out, { ok: true });
  });

  it("rejects an expired _t when a replay window is set", function () {
    var key = generateApiKey();
    var sealed = sealEnvelope({ _d: { x: 1 }, _t: Date.now() - 60000 }, key);
    assert.throws(function () {
      decryptPayload(sealed, key, 30000);
    }, /expired/i, "stale _t past the window should throw");
  });

  it("accepts a _t leading by up to FUTURE_SKEW_MS (clock-skew tolerance)", function () {
    var key = generateApiKey();
    // Lead by FUTURE_SKEW_MS minus a small margin so it stays inside tolerance.
    var sealed = sealEnvelope({ _d: { y: 2 }, _t: Date.now() + (FUTURE_SKEW_MS - 200) }, key);
    var out = decryptPayload(sealed, key, 30000);
    assert.deepStrictEqual(out, { y: 2 });
  });

  it("rejects a _t further in the future than FUTURE_SKEW_MS", function () {
    var key = generateApiKey();
    var sealed = sealEnvelope({ _d: { z: 3 }, _t: Date.now() + FUTURE_SKEW_MS + 5000 }, key);
    assert.throws(function () {
      decryptPayload(sealed, key, 30000);
    }, /future/i, "_t beyond the skew tolerance should throw");
  });

  it("rejects a missing/non-numeric _t when a replay window is set", function () {
    var key = generateApiKey();
    var sealedMissing = sealEnvelope({ _d: { a: 1 } }, key);
    assert.throws(function () {
      decryptPayload(sealedMissing, key, 30000);
    }, /timestamp/i, "no _t must fail closed under a replay window");
    var sealedBad = sealEnvelope({ _d: { a: 1 }, _t: "not-a-number" }, key);
    assert.throws(function () {
      decryptPayload(sealedBad, key, 30000);
    }, /timestamp/i, "non-numeric _t must fail closed under a replay window");
  });

  it("fails closed on a no-_d envelope when a replay window is set (finding #13)", function () {
    // A validly-AEAD-decrypted JSON payload that omits _d must NOT bypass the
    // freshness/replay enforcement. No legitimate producer ever omits _d; the
    // only way to mint one is to hold the session key, so treat it as malformed
    // and reject rather than returning it un-timestamp-checked.
    var key = generateApiKey();
    var sealed = sealEnvelope({ x: 1, _t: Date.now() }, key);
    assert.throws(function () {
      decryptPayload(sealed, key, 30000);
    }, /missing data/i, "no-_d envelope must be rejected under a replay window");
  });

  it("no-_d envelope still parses when NO replay window is requested", function () {
    // Backward behavior: without a replay window the freshness contract is not
    // engaged, so a JSON payload lacking _d is returned verbatim (e.g. {} round-trip).
    var key = generateApiKey();
    var sealed = sealEnvelope({ x: 1 }, key);
    var out = decryptPayload(sealed, key);
    assert.deepStrictEqual(out, { x: 1 });
  });

  it("nonce TTL covers the full future-dated freshness ceiling (finding #12)", function () {
    // The replay gap: a future-dated _t keeps the inner-AEAD window open until
    // _t + replayWindow, and _t may lead receive time by up to FUTURE_SKEW_MS,
    // so the freshness ceiling sits at receiveTime + replayWindow + FUTURE_SKEW_MS.
    // The single-use nonce in middleware/api-encrypt.js must be claimed for at
    // least that long or a replay landing after the old (replayWindow-only) nonce
    // lapses but before the freshness ceiling closes would re-claim and pass.
    // Verify the nonce TTL the middleware uses equals the freshness ceiling and
    // is bound to the same FUTURE_SKEW_MS the AEAD check uses.
    var apiEncryptSrc = fs.readFileSync(
      path.join(__dirname, "..", "..", "middleware", "api-encrypt.js"), "utf8");
    assert.ok(
      /NONCE_TTL\s*=\s*REPLAY_WINDOW\s*\+\s*FUTURE_SKEW_MS/.test(apiEncryptSrc),
      "nonce TTL must be REPLAY_WINDOW + FUTURE_SKEW_MS");
    assert.ok(
      /claimOnce\([^)]*,\s*NONCE_TTL\)/.test(apiEncryptSrc),
      "claimOnce must use the widened NONCE_TTL, not the bare REPLAY_WINDOW");

    // And the inner-AEAD check still accepts a maximally future-dated replay
    // while it remains within its own window (so the nonce, not the AEAD, is the
    // load-bearing defense in the previously-open ~FUTURE_SKEW_MS gap): a _t at
    // the max lead is fresh now, so decrypt succeeds and the live nonce is what
    // must refuse the replay.
    var key = generateApiKey();
    var sealed = sealEnvelope({ _d: { replayed: true }, _t: Date.now() + FUTURE_SKEW_MS - 100 }, key);
    var out = decryptPayload(sealed, key, 30000);
    assert.deepStrictEqual(out, { replayed: true },
      "a maximally future-dated _t is fresh at the inner AEAD — the nonce TTL is the gap closer");
  });
});
