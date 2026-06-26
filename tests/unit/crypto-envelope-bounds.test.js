/**
 * Regression — truncated 0xE1 envelope blobs must fail closed with the typed
 * "Invalid envelope: ..." error contract, never a raw Node RangeError
 * (ERR_OUT_OF_RANGE). A corrupted/truncated at-rest 0xE1 blob (reached via
 * vault unseal / legacy-envelope-migrate) used to read length fields and slice
 * subarrays without bounds checks, leaking an uncaught RangeError.
 */
const { describe, it } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const nodeCrypto = require("node:crypto");
var projectRoot = path.join(__dirname, "..", "..");
var crypto = require(path.join(projectRoot, "lib", "crypto.js"));

var ENV_MAGIC = crypto.ENV_MAGIC;          // 0xE1
var KEM = crypto.KEM;                       // { ML_KEM_1024: 0x02, ML_KEM_1024_P384: 0x03 }
var CIPHER = crypto.CIPHER;                 // { XCHACHA20_POLY: 0x02 }
var KDF_ALG = crypto.KDF_ALG;               // { SHAKE256: 0x02 }

// A real keypair + ML-KEM ciphertext, so envelopes can carry a kemCt that
// actually decapsulates — letting the truncation tests reach the ecEphLen /
// nonce bounds checks that sit *after* decapsulation, not fail early on a
// dummy key.
var keys = crypto.generateEncryptionKeyPair();
var realKemCt = nodeCrypto.encapsulate(nodeCrypto.createPublicKey(keys.publicKey)).ciphertext;

function u16(n) { var b = Buffer.alloc(2); b.writeUInt16BE(n, 0); return b; }

// Run a packed buffer through the public decrypt() base64 entry point.
function decryptBuf(buf) {
  return crypto.decrypt(buf.toString("base64"), keys);
}

function assertTypedEnvelopeError(buf, label) {
  assert.throws(
    function () { decryptBuf(buf); },
    function (err) {
      assert.ok(err instanceof Error, label + ": expected an Error");
      assert.ok(
        /^Invalid envelope/.test(err.message),
        label + ": message must start with 'Invalid envelope', got: " + err.message
      );
      assert.notStrictEqual(err.code, "ERR_OUT_OF_RANGE", label + ": must not be a bare RangeError");
      assert.ok(!(err instanceof RangeError), label + ": must not be a RangeError");
      return true;
    }
  );
}

describe("crypto envelope bounds (truncated 0xE1)", function () {

  it("rejects a buffer shorter than the 4-byte suite header", function () {
    assertTypedEnvelopeError(Buffer.from([ENV_MAGIC, KEM.ML_KEM_1024, CIPHER.XCHACHA20_POLY]), "<4 bytes");
    assertTypedEnvelopeError(Buffer.from([ENV_MAGIC]), "1 byte");
  });

  it("rejects a header with no kemCt length field", function () {
    // 4-byte header only — no room for the 2-byte kemCtLen.
    var buf = Buffer.from([ENV_MAGIC, KEM.ML_KEM_1024, CIPHER.XCHACHA20_POLY, KDF_ALG.SHAKE256]);
    assertTypedEnvelopeError(buf, "header only");
  });

  it("rejects a kemCtLen that runs past the buffer end", function () {
    // header + kemCtLen=0x0400 (1024) but no kemCt bytes follow.
    var buf = Buffer.concat([
      Buffer.from([ENV_MAGIC, KEM.ML_KEM_1024, CIPHER.XCHACHA20_POLY, KDF_ALG.SHAKE256]),
      u16(1024),
    ]);
    assertTypedEnvelopeError(buf, "kemCt overrun");
  });

  it("rejects a hybrid envelope missing the EC ephemeral length field", function () {
    // Real header + real kemCt, then truncated — decapsulate succeeds, so the
    // failure lands on the bounds-checked ecEphLen read, not earlier.
    var buf = Buffer.concat([
      Buffer.from([ENV_MAGIC, KEM.ML_KEM_1024_P384, CIPHER.XCHACHA20_POLY, KDF_ALG.SHAKE256]),
      u16(realKemCt.length), realKemCt,
      // no ecEphLen bytes
    ]);
    assertTypedEnvelopeError(buf, "hybrid missing ecEphLen");
  });

  it("rejects a hybrid ecEphLen that runs past the buffer end", function () {
    var buf = Buffer.concat([
      Buffer.from([ENV_MAGIC, KEM.ML_KEM_1024_P384, CIPHER.XCHACHA20_POLY, KDF_ALG.SHAKE256]),
      u16(realKemCt.length), realKemCt,
      u16(256),                        // ecEphLen = 256, no bytes follow
    ]);
    assertTypedEnvelopeError(buf, "ecEph overrun");
  });

  it("rejects a buffer truncated where the 24-byte nonce should be", function () {
    // Standalone ML-KEM-1024 path with a real kemCt, then fewer than 24 nonce bytes.
    var buf = Buffer.concat([
      Buffer.from([ENV_MAGIC, KEM.ML_KEM_1024, CIPHER.XCHACHA20_POLY, KDF_ALG.SHAKE256]),
      u16(realKemCt.length), realKemCt,
      Buffer.alloc(10),                // only 10 of the 24 nonce bytes
    ]);
    assertTypedEnvelopeError(buf, "nonce truncation");
  });

  it("rejects a buffer with the nonce present but no ciphertext", function () {
    var buf = Buffer.concat([
      Buffer.from([ENV_MAGIC, KEM.ML_KEM_1024, CIPHER.XCHACHA20_POLY, KDF_ALG.SHAKE256]),
      u16(realKemCt.length), realKemCt,
      Buffer.alloc(24),                // full nonce, zero ciphertext bytes after it
    ]);
    // Empty-ciphertext path: a Poly1305 tag is missing, so decrypt fails — but it
    // must be a typed envelope error from the pos>length check or a noble auth
    // failure, never a bare RangeError.
    assert.throws(
      function () { decryptBuf(buf); },
      function (err) {
        assert.ok(err instanceof Error);
        assert.notStrictEqual(err.code, "ERR_OUT_OF_RANGE", "no-ciphertext must not surface ERR_OUT_OF_RANGE");
        return true;
      }
    );
  });
});
