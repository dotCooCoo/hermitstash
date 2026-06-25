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

// Random: SHAKE256-derived bytes. SHAKE256 is the FIPS 202 XOF (variable-
// length output), so this works correctly for any byteLength — the previous
// SHA3-512 implementation silently truncated to 64 bytes for n > 64. The
// belt-and-suspenders pattern (post-hash node:crypto.randomBytes through a
// FIPS 202 primitive) is preserved; only the function family member changed
// from a fixed-output hash to its native XOF sibling.
function random(byteLength) {
  var n = byteLength || 32;
  return hash(nodeCrypto.randomBytes(n), "shake256", n);
}

// Key pair: any algorithm, standard PEM encoding
function generateKeyPair(algorithm, options) {
  var pair = nodeCrypto.generateKeyPairSync(algorithm, Object.assign({
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  }, options || {}));
  return { publicKey: pair.publicKey, privateKey: pair.privateKey };
}

// Constant-time comparison
function timingSafeEqual(a, b) {
  var bufA = Buffer.isBuffer(a) ? a : Buffer.from(String(a));
  var bufB = Buffer.isBuffer(b) ? b : Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return nodeCrypto.timingSafeEqual(bufA, bufB);
}

// ===========================================================
// Public API — built on core primitives
// ===========================================================

// ---- Hashing ----

function sha3Hash(data) { return hash(data, "sha3-512").toString("hex"); }
function hashEmail(email) { return email ? sha3Hash("hs-email:" + String(email).toLowerCase()) : null; }

// ---- KDF ----

function kdf(input, outputLength) { return hash(input, "shake256", outputLength); }

// ---- Random ----

function generateBytes(byteLength) { return Buffer.from(random(byteLength)); }
function generateToken(byteLength) { return random(byteLength || 32).toString("hex"); }
function generateShareId() { return generateToken(32); }

// ---- Key generation ----

function generateEncryptionKeyPair() {
  var mlkem = generateKeyPair("ml-kem-1024");
  var ec = generateKeyPair("ec", { namedCurve: "P-384" });
  return { publicKey: mlkem.publicKey, privateKey: mlkem.privateKey, ecPublicKey: ec.publicKey, ecPrivateKey: ec.privateKey };
}

function generateSigningKeyPair(algorithm) { return generateKeyPair(algorithm || "slh-dsa-shake-256f"); }

// ---- Signatures (auto-detect algorithm from key PEM) ----

function sign(data, privateKeyPem) { return nodeCrypto.sign(null, Buffer.from(data), privateKeyPem); }
function verify(data, signature, publicKeyPem) { return nodeCrypto.verify(null, Buffer.from(data), publicKeyPem, signature); }

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
  sha3Hash: sha3Hash,
  hashEmail: hashEmail,
  timingSafeEqual: timingSafeEqual,
  generateEncryptionKeyPair: generateEncryptionKeyPair,
  generateSigningKeyPair: generateSigningKeyPair,
  decrypt: decrypt,
  sign: sign,
  verify: verify,
  generateToken: generateToken,
  generateBytes: generateBytes,
  generateShareId: generateShareId,
  ENV_MAGIC: ENV_MAGIC,
  KEM: KEM,
  CIPHER: CIPHER,
  KDF_ALG: KDF_ALG,
};
