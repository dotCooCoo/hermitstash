// codebase-patterns:allow-file raw-byte-literal — protocol-shape constants (PQC envelope sizes / nonce / key lengths)
/**
 * Centralized crypto module — swap algorithms in one place.
 *
 * ---- Algorithm suite (PQC only, no backwards compatibility) ----
 * KEM:        ML-KEM-1024 + P-384 ECDH hybrid
 * Symmetric:  XChaCha20-Poly1305
 * KDF:        SHAKE256
 * Hash:       SHA3-512
 * HMAC:       HMAC-SHA3-512
 * Password:   Argon2id
 * Signatures: SLH-DSA-SHAKE-256f (default) / ML-DSA-87 (legacy, still verified)
 *             generateSigningKeyPair() defaults to slh-dsa-shake-256f; pass
 *             "ml-dsa-87" explicitly if you need a smaller key/signature.
 *             sign()/verify() auto-detect the algorithm from the key PEM, so
 *             existing ml-dsa-87 keys persisted in databases continue to work.
 *
 * ---- Envelope versioning ----
 * byte 0: 0xE1 (magic), byte 1: KEM ID, byte 2: cipher ID, byte 3: KDF ID
 */
var nodeCrypto = require("node:crypto");
var b = require("./vendor/blamejs");
var { xchacha20poly1305 } = require("./vendor/blamejs/lib/vendor/noble-ciphers.cjs");

// ---- Envelope constants ----

var ENV_MAGIC = 0xE1;
var KEM = { ML_KEM_1024: 0x02, ML_KEM_1024_P384: 0x03 };
var CIPHER = { XCHACHA20_POLY: 0x02 };
var KDF_ALG = { SHAKE256: 0x02 };
// (The ACTIVE_KEM/CIPHER/KDF "new-encryption default" constants were removed with
// the 0xE1 encrypt path; decrypt dispatches on each blob's own header bytes.)

// ===========================================================
// Core primitives — everything else is built from these
// ===========================================================

// Hash: any algorithm, returns Buffer
function hash(data, algorithm, outputLength) {
  var opts = outputLength ? { outputLength: outputLength } : undefined;
  return nodeCrypto.createHash(algorithm, opts).update(data).digest();
}

// ===========================================================
// Public API — built on core primitives
// ===========================================================
//
// random/generateBytes/generateToken/sha3Hash/timingSafeEqual/
// generateEncryptionKeyPair/sign/verify are re-exported from b.crypto.* below
// (see the exports block) — the framework owns the single implementation. Only
// the HS-specific pieces (hashEmail's 'hs-email:' prefix, the slh-dsa-shake-256f
// signing default, the legacy 0xE1 decrypt reader, and the share-id shim) live
// in this file.

// ---- Hashing ----

// hashEmail keeps the HS 'hs-email:' prefix + lowercase normalization; no
// blamejs equivalent exists, so it stays HS-side, delegating the hash itself
// to b.crypto.sha3Hash.
function hashEmail(email) { return email ? b.crypto.sha3Hash("hs-email:" + String(email).toLowerCase()) : null; }

// ---- KDF ----

function kdf(input, outputLength) { return hash(input, "shake256", outputLength); }

// ---- Random ----

// generateShareId has no b.crypto equivalent; it is a 256-bit token rendered as
// 64 hex chars (b.crypto.generateToken defaults to 32 bytes). Keep the shim so
// existing callers and the 64-hex contract (tests/unit/regression.test.js) hold.
function generateShareId() { return b.crypto.generateToken(32); }

// ---- Key generation ----

// b.crypto.generateSigningKeyPair defaults to ml-dsa-87; HS's stated default is
// slh-dsa-shake-256f. Wrap it so a no-arg call keeps the HS default rather than
// silently switching algorithms.
function generateSigningKeyPair(algorithm) { return b.crypto.generateSigningKeyPair(algorithm || "slh-dsa-shake-256f"); }

// ---- Encrypt path retired (0xE1 is decrypt-only) ----
// The legacy 0xE1 envelope's 4-byte header (magic + KEM/cipher/KDF ids) is not
// bound into the AEAD, unlike blamejs's AAD-bound 0xE2 envelope. No new 0xE1 blobs
// are created anywhere in HermitStash — all current encryption goes through the
// 0xE2 path (b.crypto.encryptPacked / vault sealing) — so the encrypt() and
// encryptMlkemOnly() producers were removed to guarantee no un-authenticated-header
// envelope can be minted. decrypt() below remains so existing 0xE1 data still reads
// during the migration window.

// ---- Decrypt ----
// The 4-byte envelope header (magic 0xE1, KEM id, cipher id, KDF id) chooses the
// algorithms: decryptEnvelope dispatches on those bytes, so both KEM 0x02
// (ML-KEM-1024) and 0x03 (ML-KEM-1024 + P-384 hybrid) decrypt, with XChaCha20
// (0x02) + SHAKE256 (0x02). A new envelope format requires a NEW magic plus a
// separate decrypt path — never widen this magic check to accept other values.

function decrypt(ciphertext, privateKeys) {
  var packed = Buffer.from(ciphertext, "base64");
  if (packed[0] !== ENV_MAGIC) throw new Error("Invalid envelope: unsupported format (legacy data requires migration)");
  return decryptEnvelope(packed, privateKeys);
}

function decryptEnvelope(packed, privateKeys) {
  var kemId = packed[1], cipherId = packed[2], kdfId = packed[3], pos = 4;

  if (cipherId !== CIPHER.XCHACHA20_POLY) throw new Error("Invalid envelope: unsupported cipher (only XChaCha20-Poly1305 supported)");
  if (kdfId !== KDF_ALG.SHAKE256) throw new Error("Invalid envelope: unsupported KDF (only SHAKE256 supported)");

  var kemCtLen = packed.readUInt16BE(pos); pos += 2;
  var kemCt = packed.subarray(pos, pos + kemCtLen); pos += kemCtLen;

  var mlkemPriv = nodeCrypto.createPrivateKey(typeof privateKeys === "string" ? privateKeys : privateKeys.privateKey);
  var mlkemSs = nodeCrypto.decapsulate(mlkemPriv, kemCt);
  var symmetricKey;

  if (kemId === KEM.ML_KEM_1024_P384) {
    var ecEphLen = packed.readUInt16BE(pos); pos += 2;
    var ecEphDer = packed.subarray(pos, pos + ecEphLen); pos += ecEphLen;
    var ecPrivPem = typeof privateKeys === "string" ? null : privateKeys.ecPrivateKey;
    if (!ecPrivPem) throw new Error("Hybrid KEM requires EC private key");
    var ecSs = nodeCrypto.diffieHellman({
      privateKey: nodeCrypto.createPrivateKey(ecPrivPem),
      publicKey: nodeCrypto.createPublicKey({ key: ecEphDer, type: "spki", format: "der" }),
    });
    symmetricKey = kdf(Buffer.concat([mlkemSs, ecSs]), 32);
  } else if (kemId === KEM.ML_KEM_1024) {
    symmetricKey = kdf(mlkemSs, 32);
  } else {
    throw new Error("Invalid envelope: unsupported KEM ID " + kemId + " (only ML-KEM-1024 supported)");
  }

  var nonce = packed.subarray(pos, pos + 24); pos += 24;
  return Buffer.from(xchacha20poly1305(symmetricKey, nonce).decrypt(packed.subarray(pos))).toString("utf8");
}

// ---- Exports ----

module.exports = {
  // Re-exported from b.crypto.* — the framework owns the single implementation.
  // These keep the historical cryptoLib.<fn> surface so existing callers need no
  // repointing while the duplicate HS copies are gone.
  sha3Hash: b.crypto.sha3Hash,
  timingSafeEqual: b.crypto.timingSafeEqual,
  generateEncryptionKeyPair: b.crypto.generateEncryptionKeyPair,
  sign: b.crypto.sign,
  verify: b.crypto.verify,
  generateToken: b.crypto.generateToken,
  generateBytes: b.crypto.generateBytes,
  // HS-specific surface (no faithful b.crypto equivalent / a default to preserve):
  hashEmail: hashEmail,
  generateSigningKeyPair: generateSigningKeyPair,
  generateShareId: generateShareId,
  decrypt: decrypt,
  ENV_MAGIC: ENV_MAGIC,
  KEM: KEM,
  CIPHER: CIPHER,
  KDF_ALG: KDF_ALG,
};
