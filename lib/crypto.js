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
var nodeCrypto = require("crypto");
var argon2 = require("./vendor/argon2");
var { xchacha20poly1305 } = require("./vendor/noble-ciphers.cjs");

// ---- Envelope constants ----

var ENV_MAGIC = 0xE1;
var KEM = { ML_KEM_1024: 0x02, ML_KEM_1024_P384: 0x03 };
var CIPHER = { XCHACHA20_POLY: 0x02 };
var KDF_ALG = { SHAKE256: 0x02 };
var ACTIVE_KEM = KEM.ML_KEM_1024_P384;
var ACTIVE_CIPHER = CIPHER.XCHACHA20_POLY;
var ACTIVE_KDF = KDF_ALG.SHAKE256;

// ===========================================================
// Core primitives — everything else is built from these
// ===========================================================

// Hash: any algorithm, returns Buffer
function hash(data, algorithm, outputLength) {
  var opts = outputLength ? { outputLength: outputLength } : undefined;
  return nodeCrypto.createHash(algorithm, opts).update(data).digest();
}

// HMAC: any algorithm, returns hex string
function hmac(key, data, algorithm) {
  return nodeCrypto.createHmac(algorithm, key).update(data).digest("hex");
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
function hmacSha3(key, data) { return hmac(key, data, "sha3-512"); }
function hashEmail(email) { return email ? sha3Hash("hs-email:" + String(email).toLowerCase()) : null; }

// ---- KDF ----

function kdf(input, outputLength) { return hash(input, "shake256", outputLength); }

// ---- Password ----

var _fastArgon = process.env.ARGON2_FAST === "1";
var _argonOpts = _fastArgon
  ? { type: argon2.argon2id, memoryCost: 1024, timeCost: 1, parallelism: 1 }
  : { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 4 };

function hashPassword(password) {
  return argon2.hash(String(password), _argonOpts);
}
function verifyPassword(password, h) { return argon2.verify(h, String(password)); }

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

// ---- Encrypt (envelope format: ML-KEM-1024 + P-384 ECDH hybrid + SHAKE256 + XChaCha20) ----

function encrypt(plaintext, publicKeys) {
  var mlkemPubPem = typeof publicKeys === "string" ? publicKeys : publicKeys.publicKey;
  var ecPubPem = typeof publicKeys === "string" ? null : publicKeys.ecPublicKey;
  if (!ecPubPem) return encryptMlkemOnly(plaintext, mlkemPubPem);

  var mlkemPub = nodeCrypto.createPublicKey(mlkemPubPem);
  var kem = nodeCrypto.encapsulate(mlkemPub);
  var ephEc = generateKeyPair("ec", { namedCurve: "P-384", publicKeyEncoding: { type: "spki", format: "der" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });
  var ecSs = nodeCrypto.diffieHellman({ privateKey: nodeCrypto.createPrivateKey(ephEc.privateKey), publicKey: nodeCrypto.createPublicKey(ecPubPem) });
  var key = kdf(Buffer.concat([kem.sharedKey, ecSs]), 32);
  var nonce = generateBytes(24);
  var ct = xchacha20poly1305(key, nonce).encrypt(Buffer.from(plaintext, "utf8"));

  var kemCtLen = Buffer.alloc(2); kemCtLen.writeUInt16BE(kem.ciphertext.length);
  var ecEphDer = ephEc.publicKey;
  var ecEphLen = Buffer.alloc(2); ecEphLen.writeUInt16BE(ecEphDer.length);

  return Buffer.concat([
    Buffer.from([ENV_MAGIC, ACTIVE_KEM, ACTIVE_CIPHER, ACTIVE_KDF]),
    kemCtLen, kem.ciphertext, ecEphLen, ecEphDer, nonce, Buffer.from(ct),
  ]).toString("base64");
}

function encryptMlkemOnly(plaintext, publicKeyPem) {
  var kem = nodeCrypto.encapsulate(nodeCrypto.createPublicKey(publicKeyPem));
  var key = kdf(kem.sharedKey, 32);
  var nonce = generateBytes(24);
  var ct = xchacha20poly1305(key, nonce).encrypt(Buffer.from(plaintext, "utf8"));
  var kemCtLen = Buffer.alloc(2); kemCtLen.writeUInt16BE(kem.ciphertext.length);
  return Buffer.concat([
    Buffer.from([ENV_MAGIC, KEM.ML_KEM_1024, ACTIVE_CIPHER, ACTIVE_KDF]),
    kemCtLen, kem.ciphertext, nonce, Buffer.from(ct),
  ]).toString("base64");
}

// ---- Decrypt (ML-KEM-1024 only, XChaCha20 only, SHAKE256 only) ----

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

// ---- Symmetric buffer encrypt/decrypt (XChaCha20-Poly1305 only) ----

function decryptPacked(packed, key) {
  if (packed[0] !== 0x02) throw new Error("Invalid packed format: unsupported version (only XChaCha20-Poly1305 v2 supported)");
  return Buffer.from(xchacha20poly1305(key, packed.subarray(1, 25)).decrypt(packed.subarray(25)));
}

function encryptPacked(buffer, key) {
  var nonce = random(24);
  var ct = xchacha20poly1305(key, nonce).encrypt(buffer);
  return Buffer.concat([Buffer.from([0x02]), Buffer.from(nonce), Buffer.from(ct)]);
}

// ---- Exports ----

module.exports = {
  hashPassword: hashPassword,
  verifyPassword: verifyPassword,
  sha3Hash: sha3Hash,
  hmacSha3: hmacSha3,
  hashEmail: hashEmail,
  timingSafeEqual: timingSafeEqual,
  generateEncryptionKeyPair: generateEncryptionKeyPair,
  generateSigningKeyPair: generateSigningKeyPair,
  encrypt: encrypt,
  decrypt: decrypt,
  sign: sign,
  verify: verify,
  generateToken: generateToken,
  generateBytes: generateBytes,
  generateShareId: generateShareId,
  encryptPacked: encryptPacked,
  decryptPacked: decryptPacked,
  ENV_MAGIC: ENV_MAGIC,
  KEM: KEM,
  CIPHER: CIPHER,
  KDF_ALG: KDF_ALG,
};
