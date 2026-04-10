/**
 * Centralized crypto module — swap algorithms in one place.
 *
 * ---- Algorithm suite ----
 * KEM:        ML-KEM-1024 + P-384 ECDH hybrid
 * Symmetric:  XChaCha20-Poly1305
 * KDF:        SHAKE256
 * Hash:       SHA3-512
 * HMAC:       HMAC-SHA3-512
 * Password:   Argon2id
 * Signatures: ML-DSA-87 / SLH-DSA-SHAKE-256f (auto-detected from key)
 *
 * ---- Envelope versioning ----
 * byte 0: 0xE1 (magic), byte 1: KEM ID, byte 2: cipher ID, byte 3: KDF ID
 */
var nodeCrypto = require("crypto");
var argon2 = require("./vendor/argon2");
var { xchacha20poly1305 } = require("./vendor/noble-ciphers.cjs");

// ---- Envelope constants ----

var ENV_MAGIC = 0xE1;
var KEM = { ML_KEM_768: 0x01, ML_KEM_1024: 0x02, ML_KEM_1024_P384: 0x03 };
var CIPHER = { AES_256_GCM: 0x01, XCHACHA20_POLY: 0x02 };
var KDF_ALG = { SHA3_256: 0x01, SHAKE256: 0x02 };
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

// Random: SHA3-512 derived bytes
function random(byteLength) {
  var n = byteLength || 32;
  return hash(nodeCrypto.randomBytes(n), "sha3-512").subarray(0, n);
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
function kdfLegacy(input) { return hash(input, "sha3-256"); }

// ---- Password ----

// Test mode uses fast Argon2 params (set NODE_ENV=test or ARGON2_FAST=1)
var _fastArgon = process.env.NODE_ENV === "test" || process.env.ARGON2_FAST === "1";
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

function generateSigningKeyPair(algorithm) { return generateKeyPair(algorithm || "ml-dsa-87"); }

// ---- Signatures (auto-detect algorithm from key PEM) ----

function sign(data, privateKeyPem) { return nodeCrypto.sign(null, Buffer.from(data), privateKeyPem); }
function verify(data, signature, publicKeyPem) { return nodeCrypto.verify(null, Buffer.from(data), publicKeyPem, signature); }

// ---- Encrypt (envelope format) ----

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
    Buffer.from([ENV_MAGIC, kem.ciphertext.length > 1200 ? KEM.ML_KEM_1024 : KEM.ML_KEM_768, ACTIVE_CIPHER, ACTIVE_KDF]),
    kemCtLen, kem.ciphertext, nonce, Buffer.from(ct),
  ]).toString("base64");
}

// ---- Decrypt (auto-detect format) ----

function decrypt(ciphertext, privateKeys) {
  var packed = Buffer.from(ciphertext, "base64");
  if (packed[0] === ENV_MAGIC) return decryptEnvelope(packed, privateKeys);
  if (packed[0] === 0x02) return decryptLegacy(packed, privateKeys, true);
  return decryptLegacy(packed, privateKeys, false);
}

function decryptEnvelope(packed, privateKeys) {
  var kemId = packed[1], cipherId = packed[2], kdfId = packed[3], pos = 4;
  var kemCtLen = packed.readUInt16BE(pos); pos += 2;
  var kemCt = packed.subarray(pos, pos + kemCtLen); pos += kemCtLen;

  var mlkemPriv = nodeCrypto.createPrivateKey(typeof privateKeys === "string" ? privateKeys : privateKeys.privateKey);
  var mlkemSs = nodeCrypto.decapsulate(mlkemPriv, kemCt);
  var deriveKey = kdfId === KDF_ALG.SHAKE256 ? kdf : kdfLegacy;
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
    symmetricKey = deriveKey(Buffer.concat([mlkemSs, ecSs]), 32);
  } else {
    symmetricKey = deriveKey(mlkemSs, 32);
  }

  if (cipherId === CIPHER.XCHACHA20_POLY) {
    var nonce = packed.subarray(pos, pos + 24); pos += 24;
    return Buffer.from(xchacha20poly1305(symmetricKey, nonce).decrypt(packed.subarray(pos))).toString("utf8");
  }
  var iv = packed.subarray(pos, pos + 12); pos += 12;
  var tag = packed.subarray(pos, pos + 16); pos += 16;
  var decipher = nodeCrypto.createDecipheriv("aes-256-gcm", symmetricKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(packed.subarray(pos)), decipher.final()]).toString("utf8");
}

// Select right key for legacy KEM ciphertext (768=1088 bytes, 1024=1568 bytes)
function selectKey(privateKeys, kemCtLen) {
  if (typeof privateKeys === "string") return privateKeys;
  return (kemCtLen < 1200 && privateKeys._legacyPrivateKey) ? privateKeys._legacyPrivateKey : privateKeys.privateKey;
}

// V2 (xchacha20) and V1 (aes-gcm) share the same structure, differ only in cipher
function decryptLegacy(packed, privateKeys, isV2) {
  var offset = isV2 ? 1 : 0;
  var kemLen = packed.readUInt16BE(offset);
  var kemCt = packed.subarray(offset + 2, offset + 2 + kemLen);
  var rest = packed.subarray(offset + 2 + kemLen);
  var privPem = selectKey(privateKeys, kemLen);
  var sharedKey = kdfLegacy(nodeCrypto.decapsulate(nodeCrypto.createPrivateKey(privPem), kemCt));

  if (isV2) {
    // V2: nonce(24) + ct_with_tag
    return Buffer.from(xchacha20poly1305(sharedKey, rest.subarray(0, 24)).decrypt(rest.subarray(24))).toString("utf8");
  }
  // V1: iv(12) + tag(16) + enc
  var decipher = nodeCrypto.createDecipheriv("aes-256-gcm", sharedKey, rest.subarray(0, 12));
  decipher.setAuthTag(rest.subarray(12, 28));
  return Buffer.concat([decipher.update(rest.subarray(28)), decipher.final()]).toString("utf8");
}

// ---- Symmetric buffer decrypt (shared by storage.js and db.js) ----

function decryptPacked(packed, key) {
  if (packed[0] === 0x02) {
    return Buffer.from(xchacha20poly1305(key, packed.subarray(1, 25)).decrypt(packed.subarray(25)));
  }
  // Legacy AES-256-GCM: iv(12) + tag(16) + enc
  var decipher = nodeCrypto.createDecipheriv("aes-256-gcm", key, packed.subarray(0, 12));
  decipher.setAuthTag(packed.subarray(12, 28));
  return Buffer.concat([decipher.update(packed.subarray(28)), decipher.final()]);
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
