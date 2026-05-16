/**
 * Unit tests for lib/vault-wrap.js — opt-in passphrase wrapping primitives.
 *
 * Uses argon2 fast parameters for speed. The wrap() function accepts
 * memoryCost/timeCost/parallelism overrides so tests don't pay the 64-MiB
 * default cost on every case.
 */
var { describe, it } = require("node:test");
var assert = require("node:assert");
var vw = require("../../lib/vendor/blamejs").vaultWrap;

// Fast Argon2 params — keeps the whole suite under a few seconds
var FAST = Object.freeze({ memoryCost: 1024, timeCost: 1, parallelism: 1 });

describe("vault-wrap format constants", function () {
  it("magic byte is 0xE2 (distinct from storage envelope 0xE1)", function () {
    assert.strictEqual(vw.MAGIC, 0xE2);
  });
  it("format version is 1", function () {
    assert.strictEqual(vw.FORMAT_VERSION, 1);
  });
  it("nonce length is 24 (XChaCha20-Poly1305 extended)", function () {
    assert.strictEqual(vw.NONCE_LENGTH, 24);
  });
  it("default Argon2 matches lib/crypto.js hashPassword", function () {
    assert.strictEqual(vw.DEFAULT_ARGON2.memoryCost, 65536);
    assert.strictEqual(vw.DEFAULT_ARGON2.timeCost, 3);
    assert.strictEqual(vw.DEFAULT_ARGON2.parallelism, 4);
  });
});

describe("vault-wrap round-trip", function () {
  it("wraps and unwraps a short string exactly", async function () {
    var pt = Buffer.from("hello vault");
    var sealed = await vw.wrap(pt, "secret", FAST);
    var back = await vw.unwrap(sealed, "secret");
    assert.strictEqual(Buffer.compare(pt, back), 0);
  });

  it("wraps and unwraps a realistic JSON vault key", async function () {
    var vaultKeyJson = JSON.stringify({
      publicKey: "-----BEGIN PUBLIC KEY-----\nMFk...\n-----END PUBLIC KEY-----",
      privateKey: "-----BEGIN PRIVATE KEY-----\nMIG...\n-----END PRIVATE KEY-----",
      ecPublicKey: "-----BEGIN PUBLIC KEY-----\nMHY...\n-----END PUBLIC KEY-----",
      ecPrivateKey: "-----BEGIN PRIVATE KEY-----\nMIG...\n-----END PRIVATE KEY-----",
    });
    var pt = Buffer.from(vaultKeyJson, "utf8");
    var sealed = await vw.wrap(pt, "my-strong-passphrase-2026", FAST);
    var back = await vw.unwrap(sealed, "my-strong-passphrase-2026");
    assert.strictEqual(back.toString("utf8"), vaultKeyJson);
  });

  it("wraps and unwraps binary plaintext (random bytes)", async function () {
    var pt = Buffer.alloc(1024);
    for (var i = 0; i < pt.length; i++) pt[i] = i % 256;
    var sealed = await vw.wrap(pt, "x", FAST);
    var back = await vw.unwrap(sealed, "x");
    assert.strictEqual(Buffer.compare(pt, back), 0);
  });

  it("wraps and unwraps UTF-8 passphrase with non-ASCII", async function () {
    var pt = Buffer.from("data");
    var sealed = await vw.wrap(pt, "пароль-with-空格-emoji-🔒", FAST);
    var back = await vw.unwrap(sealed, "пароль-with-空格-emoji-🔒");
    assert.strictEqual(Buffer.compare(pt, back), 0);
  });

  it("produces different ciphertext on each wrap (random salt + nonce)", async function () {
    var pt = Buffer.from("data");
    var s1 = await vw.wrap(pt, "pw", FAST);
    var s2 = await vw.wrap(pt, "pw", FAST);
    assert.notStrictEqual(Buffer.compare(s1, s2), 0, "two seals must differ");
  });

  it("uses different salt on each wrap", async function () {
    var pt = Buffer.from("data");
    var s1 = await vw.wrap(pt, "pw", FAST);
    var s2 = await vw.wrap(pt, "pw", FAST);
    var p1 = vw.parseHeader(s1).params;
    var p2 = vw.parseHeader(s2).params;
    assert.notStrictEqual(Buffer.compare(p1.salt, p2.salt), 0);
    assert.notStrictEqual(Buffer.compare(p1.nonce, p2.nonce), 0);
  });
});

describe("vault-wrap rejections", function () {
  it("rejects wrong passphrase", async function () {
    var sealed = await vw.wrap(Buffer.from("secret data"), "right", FAST);
    await assert.rejects(
      vw.unwrap(sealed, "wrong"),
      /Passphrase rejected or wrapped file corrupted/
    );
  });

  it("rejects empty passphrase on wrap", async function () {
    await assert.rejects(
      vw.wrap(Buffer.from("data"), "", FAST),
      /passphrase must not be empty/
    );
  });

  it("rejects empty passphrase on unwrap", async function () {
    var sealed = await vw.wrap(Buffer.from("data"), "pw", FAST);
    await assert.rejects(
      vw.unwrap(sealed, ""),
      /passphrase must not be empty/
    );
  });

  it("rejects passphrase exceeding 4096 byte sanity limit", async function () {
    var huge = "x".repeat(5000);
    await assert.rejects(
      vw.wrap(Buffer.from("data"), huge, FAST),
      /passphrase exceeds/
    );
  });

  it("rejects bad magic byte", async function () {
    var sealed = await vw.wrap(Buffer.from("data"), "pw", FAST);
    sealed[0] = 0xFF;
    await assert.rejects(
      vw.unwrap(sealed, "pw"),
      /not a wrapped vault file/
    );
  });

  it("rejects unsupported format version", async function () {
    var sealed = await vw.wrap(Buffer.from("data"), "pw", FAST);
    sealed[1] = 0xFF;
    await assert.rejects(
      vw.unwrap(sealed, "pw"),
      /unsupported wrapped-vault format version/
    );
  });

  it("rejects unsupported KDF ID", async function () {
    var sealed = await vw.wrap(Buffer.from("data"), "pw", FAST);
    sealed[2] = 0xFF;
    await assert.rejects(
      vw.unwrap(sealed, "pw"),
      /unsupported KDF ID/
    );
  });

  it("rejects out-of-bounds memory cost", async function () {
    var sealed = await vw.wrap(Buffer.from("data"), "pw", FAST);
    sealed.writeUInt32BE(100 * 1024 * 1024, 4); // 100 GiB
    await assert.rejects(
      vw.unwrap(sealed, "pw"),
      /memory cost out of bounds/
    );
  });

  it("rejects truncated file (header incomplete)", async function () {
    var sealed = await vw.wrap(Buffer.from("data"), "pw", FAST);
    var truncated = sealed.subarray(0, 20);
    await assert.rejects(
      vw.unwrap(truncated, "pw"),
      /truncated|too short/i
    );
  });

  it("rejects truncated ciphertext", async function () {
    var sealed = await vw.wrap(Buffer.from("data"), "pw", FAST);
    var truncated = sealed.subarray(0, sealed.length - 10);
    await assert.rejects(
      vw.unwrap(truncated, "pw"),
      /truncated|corrupted/i
    );
  });
});

describe("vault-wrap tampering", function () {
  it("rejects any single-byte flip in the ciphertext", async function () {
    var pt = Buffer.from("a reasonably short plaintext");
    var sealed = await vw.wrap(pt, "pw", FAST);
    var parsed = vw.parseHeader(sealed);
    // Flip each ciphertext byte; all must fail AEAD
    for (var i = parsed.headerEnd; i < sealed.length; i++) {
      var tamp = Buffer.from(sealed);
      tamp[i] ^= 0x01;
      await assert.rejects(vw.unwrap(tamp, "pw"), /rejected|corrupted/i);
    }
  });

  it("rejects flip in nonce (last byte of nonce region)", async function () {
    var sealed = await vw.wrap(Buffer.from("data"), "pw", FAST);
    var parsed = vw.parseHeader(sealed);
    // nonce starts at 12 + saltLen + 2 and is 24 bytes
    var saltLen = sealed[11];
    var nonceEnd = 12 + saltLen + 2 + 24 - 1;
    var tamp = Buffer.from(sealed);
    tamp[nonceEnd] ^= 0x01;
    await assert.rejects(vw.unwrap(tamp, "pw"), /rejected|corrupted/i);
  });

  it("rejects flip in salt (last byte of salt region)", async function () {
    var sealed = await vw.wrap(Buffer.from("data"), "pw", FAST);
    var saltLen = sealed[11];
    var tamp = Buffer.from(sealed);
    tamp[12 + saltLen - 1] ^= 0x01;
    await assert.rejects(vw.unwrap(tamp, "pw"), /rejected|corrupted/i);
  });

  it("rejects reserved-byte flip (AAD catches it even though we don't validate the byte)", async function () {
    var sealed = await vw.wrap(Buffer.from("data"), "pw", FAST);
    var tamp = Buffer.from(sealed);
    tamp[3] = 0x42; // reserved byte
    await assert.rejects(vw.unwrap(tamp, "pw"), /rejected|corrupted/i);
  });
});

describe("vault-wrap header parsing", function () {
  it("parseHeader reports correct structural fields", async function () {
    var sealed = await vw.wrap(Buffer.from("hello"), "pw", {
      memoryCost: 2048,
      timeCost: 2,
      parallelism: 2,
      saltLength: 24,
    });
    var parsed = vw.parseHeader(sealed);
    assert.strictEqual(parsed.params.memoryCost, 2048);
    assert.strictEqual(parsed.params.timeCost, 2);
    assert.strictEqual(parsed.params.parallelism, 2);
    assert.strictEqual(parsed.params.salt.length, 24);
    assert.strictEqual(parsed.params.nonce.length, 24);
    assert.strictEqual(parsed.params.ciphertextLength, 5 + 16); // "hello" + Poly1305 tag
  });

  it("parseHeader refuses non-Buffer input gracefully (coerces)", function () {
    // Feed a Uint8Array (parseHeader should accept it via Buffer.from)
    var u8 = new Uint8Array([0xE2, 0x01, 0x01, 0x00]);
    // Too short — should throw about truncation, not type
    assert.throws(function () { vw.parseHeader(u8); }, /too short|truncated/i);
  });
});
