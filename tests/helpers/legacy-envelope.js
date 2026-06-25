// Test-only constructor for the legacy 0xE1 storage envelope.
//
// HermitStash retired the production encrypt() path for 0xE1 (its 4-byte header is
// not AAD-bound, unlike the current 0xE2 envelope) — no code mints 0xE1 blobs
// anymore. But lib/crypto.decrypt() must keep reading 0xE1 data during the
// migration window, so the backward-compatibility test still needs to produce a
// 0xE1 envelope to decrypt. That construction lives here, in test fixtures, rather
// than as an exported footgun on the production crypto surface. The byte layout
// mirrors lib/crypto's decryptEnvelope exactly:
//   [0xE1][kemId][cipherId][kdfId][kemCtLen:2][kemCt][ecEphLen:2][ecEphDer][nonce:24][ct]

var nodeCrypto = require("node:crypto");
var { xchacha20poly1305 } = require("../../lib/vendor/blamejs/lib/vendor/noble-ciphers.cjs");

var ENV_MAGIC = 0xE1;
var KEM_MLKEM = 0x02;      // ML-KEM-1024 only
var KEM_HYBRID = 0x03;     // ML-KEM-1024 + P-384
var CIPHER_XCHACHA = 0x02; // XChaCha20-Poly1305
var KDF_SHAKE = 0x02;      // SHAKE256

function kdf(input, outputLength) {
  return nodeCrypto.createHash("shake256", { outputLength: outputLength }).update(input).digest();
}

// Mirror the retired lib/crypto.encrypt dispatch: a string public key (or keys
// object with no ecPublicKey) builds the ML-KEM-1024-only 0xE1 envelope; a full
// keypair builds the ML-KEM-1024 + P-384 hybrid. Both decrypt through
// lib/crypto.decrypt.
function encryptLegacy0xE1(plaintext, publicKeys) {
  var mlkemPubPem = typeof publicKeys === "string" ? publicKeys : publicKeys.publicKey;
  var ecPubPem = typeof publicKeys === "string" ? null : publicKeys.ecPublicKey;
  if (!ecPubPem) return encryptLegacy0xE1Mlkem(plaintext, mlkemPubPem);
  return encryptLegacy0xE1Hybrid(plaintext, publicKeys);
}

// ML-KEM-1024-only 0xE1 envelope: [0xE1][0x02][cipher][kdf][kemCtLen:2][kemCt][nonce:24][ct]
function encryptLegacy0xE1Mlkem(plaintext, mlkemPubPem) {
  var kem = nodeCrypto.encapsulate(nodeCrypto.createPublicKey(mlkemPubPem));
  var key = kdf(kem.sharedKey, 32);
  var nonce = nodeCrypto.randomBytes(24);
  var ct = xchacha20poly1305(key, nonce).encrypt(Buffer.from(plaintext, "utf8"));
  var kemCtLen = Buffer.alloc(2); kemCtLen.writeUInt16BE(kem.ciphertext.length);
  return Buffer.concat([
    Buffer.from([ENV_MAGIC, KEM_MLKEM, CIPHER_XCHACHA, KDF_SHAKE]),
    kemCtLen, kem.ciphertext, nonce, Buffer.from(ct),
  ]).toString("base64");
}

// Hybrid (ML-KEM-1024 + P-384) 0xE1 envelope from a keypair as returned by
// lib/crypto.generateEncryptionKeyPair().
function encryptLegacy0xE1Hybrid(plaintext, keys) {
  var kem = nodeCrypto.encapsulate(nodeCrypto.createPublicKey(keys.publicKey));
  var ephEc = nodeCrypto.generateKeyPairSync("ec", {
    namedCurve: "P-384",
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  var ecSs = nodeCrypto.diffieHellman({
    privateKey: nodeCrypto.createPrivateKey(ephEc.privateKey),
    publicKey: nodeCrypto.createPublicKey(keys.ecPublicKey),
  });
  var key = kdf(Buffer.concat([kem.sharedKey, ecSs]), 32);
  var nonce = nodeCrypto.randomBytes(24);
  var ct = xchacha20poly1305(key, nonce).encrypt(Buffer.from(plaintext, "utf8"));

  var kemCtLen = Buffer.alloc(2); kemCtLen.writeUInt16BE(kem.ciphertext.length);
  var ecEphDer = ephEc.publicKey;
  var ecEphLen = Buffer.alloc(2); ecEphLen.writeUInt16BE(ecEphDer.length);

  return Buffer.concat([
    Buffer.from([ENV_MAGIC, KEM_HYBRID, CIPHER_XCHACHA, KDF_SHAKE]),
    kemCtLen, kem.ciphertext, ecEphLen, ecEphDer, nonce, Buffer.from(ct),
  ]).toString("base64");
}

module.exports = { encryptLegacy0xE1: encryptLegacy0xE1 };
