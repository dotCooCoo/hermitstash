"use strict";
/**
 * Centralized crypto module — envelope-versioned PQC primitives.
 *
 * Algorithm suite (modernity bar, per blamejs principle #8):
 *   KEM:        ML-KEM-1024 + P-384 ECDH hybrid (FIPS 203 + classical defense in depth)
 *   Symmetric:  XChaCha20-Poly1305 (24-byte nonce — no nonce-reuse risk under volume)
 *   KDF:        SHAKE256 (FIPS 202)
 *   Hash:       SHA3-512
 *   HMAC:       HMAC-SHA3-512
 *   Signatures: ML-DSA-87 / SLH-DSA-SHAKE-256f (auto-detected from key PEM)
 *
 * Argon2id lives in lib/vault-wrap.js (used to derive vault and
 * audit-signing key passphrases), not here.
 *
 * Envelope versioning (lib/constants.js → ENVELOPE_MAGIC, KEM_IDS, etc.):
 *   byte 0: ENVELOPE_MAGIC (0xE1)
 *   byte 1: KEM ID
 *   byte 2: CIPHER ID
 *   byte 3: KDF ID
 *
 * Old data decrypts under whichever IDs were written into its envelope; new
 * writes use ACTIVE.{KEM, CIPHER, KDF}. Algorithm rotation is forward-only —
 * see roadmap "Modernity posture" for the rotation policy.
 */
var nodeCrypto = require("crypto");
var { xchacha20poly1305 } = require("./vendor/noble-ciphers.cjs");
var C = require("./constants");

// ===========================================================
// Core primitives — everything else is built from these
// ===========================================================

function hash(data, algorithm, outputLength) {
  var opts = outputLength ? { outputLength: outputLength } : undefined;
  return nodeCrypto.createHash(algorithm, opts).update(data).digest();
}

function hmac(key, data, algorithm) {
  return nodeCrypto.createHmac(algorithm, key).update(data).digest("hex");
}

function random(byteLength) {
  var n = byteLength || 32;
  // SHAKE256 over OS-RNG bytes. The OS RNG (nodeCrypto.randomBytes) is
  // already cryptographically secure on modern platforms; passing
  // through a hash adds defense-in-depth (stops a hypothetical
  // randomBytes weakness from being directly observable downstream)
  // without measurable cost. SHAKE256 is the right XOF here because it
  // supports arbitrary output length — the previous implementation
  // used SHA3-512 + subarray, which silently truncated to 64 bytes
  // when callers requested more. SHAKE256 is also already the
  // framework's KDF / browser-side derivation primitive, so the same
  // hash family does double duty.
  return nodeCrypto.createHash("shake256", { outputLength: n })
    .update(nodeCrypto.randomBytes(n))
    .digest();
}

function generateKeyPair(algorithm, options) {
  var pair = nodeCrypto.generateKeyPairSync(algorithm, Object.assign({
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  }, options || {}));
  return { publicKey: pair.publicKey, privateKey: pair.privateKey };
}

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

// (SHA-1 is intentionally NOT exported from b.crypto. The framework's
//  only legitimate SHA-1 use is the HaveIBeenPwned k-anonymity API in
//  lib/auth/password.js, which imports lib/framework-sha1-hibp.js
//  directly. Public b.crypto.sha1* is permanently off the table — a
//  future caller wanting SHA-1 for storage / signing / fingerprinting
//  would re-introduce a broken primitive into the crypto surface this
//  framework spent every other line keeping out.)

// ---- KDF ----
function kdf(input, outputLength) { return hash(input, "shake256", outputLength); }

// _suiteFixedInfo — NIST SP 800-56C r2 §4.1 OtherInfo / RFC 9180
// (HPKE) §5.1 suite_id binding. Returns the byte string that the KDF
// MUST absorb alongside the shared-secret(s) so a key derived under
// one suite is not silently usable under a different suite. Same
// label is recovered on decrypt by re-reading the envelope-prefix
// bytes (kemId / cipherId / kdfId).
function _suiteFixedInfo(kemId, cipherId, kdfId) {
  return Buffer.concat([
    Buffer.from(C.ENVELOPE_FIXED_INFO_LABEL, "utf8"),
    Buffer.from([0x00, kemId, cipherId, kdfId, 0x00]),
  ]);
}

// ---- Random ----
function generateBytes(byteLength) { return Buffer.from(random(byteLength)); }
function generateToken(byteLength) { return random(byteLength || 32).toString("hex"); }

// ---- Subresource Integrity (W3C SRI 1.0) ----
//
// b.crypto.sri(content, { algorithm? }) — returns a `sha###-base64`
// integrity attribute string operators paste into <script integrity="...">
// or <link integrity="..."> tags. Defends against CDN compromise + ISP
// MITM injection — the browser refuses to load the resource when its
// hash diverges from the integrity attribute.
//
// W3C SRI 1.0 §3.2 lists sha256 / sha384 / sha512 as the supported
// digest algorithms; sha384 is the recommended default (collision
// margin without sha512's 64-byte overhead).
//
//   b.crypto.sri(scriptBuffer, { algorithm: "sha384" })
//   → "sha384-AbCdEf...="
//
//   b.crypto.sri(["a", "b"], { algorithm: "sha384" })   // array → multi-hash
//   → "sha384-X1... sha384-X2..."   (per W3C §3.3 multi-integrity)
var SRI_ALGORITHMS = { "sha256": "sha256", "sha384": "sha384", "sha512": "sha512" };

function sri(content, opts) {
  opts = opts || {};
  var algorithm = (opts.algorithm || "sha384").toLowerCase();
  if (!SRI_ALGORITHMS[algorithm]) {
    throw new Error("crypto.sri: unsupported algorithm '" + algorithm +
      "' (W3C SRI 1.0 §3.2 supports sha256/sha384/sha512)");
  }
  // Array input — emit multiple integrity tokens space-separated per
  // W3C §3.3 (browser picks the strongest one it recognizes).
  if (Array.isArray(content)) {
    return content.map(function (c) { return sri(c, opts); }).join(" ");
  }
  var buf;
  if (Buffer.isBuffer(content)) buf = content;
  else if (typeof content === "string") buf = Buffer.from(content, "utf8");
  else if (content instanceof Uint8Array) buf = Buffer.from(content);
  else throw new Error("crypto.sri: content must be a Buffer, Uint8Array, string, or array of those");
  var digest = nodeCrypto.createHash(algorithm).update(buf).digest("base64");
  return algorithm + "-" + digest;
}

// ---- Key generation ----
function generateEncryptionKeyPair() {
  var mlkem = generateKeyPair("ml-kem-1024");
  var ec = generateKeyPair("ec", { namedCurve: "P-384" });
  return {
    publicKey:    mlkem.publicKey,
    privateKey:   mlkem.privateKey,
    ecPublicKey:  ec.publicKey,
    ecPrivateKey: ec.privateKey,
  };
}

function generateSigningKeyPair(algorithm) {
  return generateKeyPair(algorithm || "ml-dsa-87");
}

// ---- Signatures (auto-detect algorithm from key PEM) ----
function sign(data, privateKeyPem) {
  return nodeCrypto.sign(null, Buffer.from(data), privateKeyPem);
}

function verify(data, signature, publicKeyPem) {
  return nodeCrypto.verify(null, Buffer.from(data), publicKeyPem, signature);
}

// Track whether the hybrid-disabled audit has been emitted at least
// once per process, so a high-volume KEM-only deployment doesn't peg
// the audit bus with one event per encrypt() call. Operators who want
// the per-call signal can call encryptMlkemOnly directly (which never
// emits) or read the metric at b.metrics — the count is preserved.
var _hybridDisabledAuditEmitted = false;

// ---- Envelope encrypt (ML-KEM-1024 + P-384 ECDH hybrid + SHAKE256 + XChaCha20) ----
function encrypt(plaintext, publicKeys) {
  var mlkemPubPem = typeof publicKeys === "string" ? publicKeys : publicKeys.publicKey;
  var ecPubPem = typeof publicKeys === "string" ? null : publicKeys.ecPublicKey;
  if (!ecPubPem) {
    // Operator passed only an ML-KEM public key — silently dropping
    // the P-384 hybrid leg means the operator's defense-in-depth
    // posture (classical ECDH backstop on top of PQC KEM) is gone
    // without any signal. Audit ONCE per process (M2 audit-dedup —
    // pre-v0.8.22 every plain-KEM call emitted, pegging the audit
    // bus). Operators who genuinely want KEM-only should call
    // encryptMlkemOnly explicitly so this audit doesn't fire.
    if (!_hybridDisabledAuditEmitted) {
      _hybridDisabledAuditEmitted = true;
      setImmediate(function () {
        try {
          var auditMod = require("./audit");                                        // allow:inline-require — circular-load defense (audit imports crypto)
          auditMod.safeEmit({
            action:   "system.crypto.hybrid_disabled",
            outcome:  "success",
            metadata: { reason: "no-ec-public-key", note: "encrypt() received only mlkem; ecPublicKey absent — call encryptMlkemOnly explicitly to silence (audited once per process)" },
          });
        } catch (_e) { /* drop-silent — best-effort */ }
      });
    }
    return encryptMlkemOnly(plaintext, mlkemPubPem);
  }

  var mlkemPub = nodeCrypto.createPublicKey(mlkemPubPem);
  var kem = nodeCrypto.encapsulate(mlkemPub);
  var ephEc = generateKeyPair("ec", {
    namedCurve: "P-384",
    publicKeyEncoding:  { type: "spki",  format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  var ecSs = nodeCrypto.diffieHellman({
    privateKey: nodeCrypto.createPrivateKey(ephEc.privateKey),
    publicKey:  nodeCrypto.createPublicKey(ecPubPem),
  });
  var key = kdf(Buffer.concat([kem.sharedKey, ecSs,
    _suiteFixedInfo(C.ACTIVE.KEM, C.ACTIVE.CIPHER, C.ACTIVE.KDF)]),
    C.BYTES.bytes(32));
  var nonce = generateBytes(C.BYTES.bytes(24));
  // Bind the 4-byte envelope header (MAGIC + kemId + cipherId + kdfId)
  // as AAD so a tampered header (algorithm-substitution attack) fails
  // the Poly1305 tag.
  var headerAad = Buffer.from([C.ENVELOPE_MAGIC, C.ACTIVE.KEM, C.ACTIVE.CIPHER, C.ACTIVE.KDF]);
  var ct = xchacha20poly1305(key, nonce, headerAad).encrypt(Buffer.from(plaintext, "utf8"));

  var kemCtLen = Buffer.alloc(2); kemCtLen.writeUInt16BE(kem.ciphertext.length);
  var ecEphDer = ephEc.publicKey;
  var ecEphLen = Buffer.alloc(2); ecEphLen.writeUInt16BE(ecEphDer.length);

  return Buffer.concat([
    headerAad,
    kemCtLen, kem.ciphertext, ecEphLen, ecEphDer, nonce, Buffer.from(ct),
  ]).toString("base64");
}

function encryptMlkemOnly(plaintext, publicKeyPem) {
  var kem = nodeCrypto.encapsulate(nodeCrypto.createPublicKey(publicKeyPem));
  var key = kdf(Buffer.concat([kem.sharedKey,
    _suiteFixedInfo(C.KEM_IDS.ML_KEM_1024, C.ACTIVE.CIPHER, C.ACTIVE.KDF)]),
    C.BYTES.bytes(32));
  var nonce = generateBytes(C.BYTES.bytes(24));
  var headerAad = Buffer.from([C.ENVELOPE_MAGIC, C.KEM_IDS.ML_KEM_1024,
    C.ACTIVE.CIPHER, C.ACTIVE.KDF]);
  var ct = xchacha20poly1305(key, nonce, headerAad).encrypt(Buffer.from(plaintext, "utf8"));
  var kemCtLen = Buffer.alloc(2); kemCtLen.writeUInt16BE(kem.ciphertext.length);
  return Buffer.concat([
    headerAad,
    kemCtLen, kem.ciphertext, nonce, Buffer.from(ct),
  ]).toString("base64");
}

// ---- Envelope decrypt (dispatches on envelope IDs, supports both KEM IDs) ----
function decrypt(ciphertext, privateKeys) {
  var packed = Buffer.from(ciphertext, "base64");
  if (packed[0] === 0xE1) {                                                       // allow:raw-byte-literal — legacy envelope magic
    throw new Error("Invalid envelope: legacy 0xE1 format predates the FixedInfo " +
      "KDF binding (NIST SP 800-56C r2 §4.1) — re-seal data under the current envelope");
  }
  if (packed[0] !== C.ENVELOPE_MAGIC) {
    throw new Error("Invalid envelope: unsupported format");
  }
  return decryptEnvelope(packed, privateKeys);
}

function decryptEnvelope(packed, privateKeys) {
  var kemId = packed[1], cipherId = packed[2], kdfId = packed[3], pos = 4;

  if (cipherId !== C.CIPHER_IDS.XCHACHA20_POLY1305) {
    throw new Error("Invalid envelope: unsupported cipher (only XChaCha20-Poly1305 supported)");
  }
  if (kdfId !== C.KDF_IDS.SHAKE256) {
    throw new Error("Invalid envelope: unsupported KDF (only SHAKE256 supported)");
  }

  var kemCtLen = packed.readUInt16BE(pos); pos += 2;
  var kemCt = packed.subarray(pos, pos + kemCtLen); pos += kemCtLen;

  var mlkemPriv = nodeCrypto.createPrivateKey(
    typeof privateKeys === "string" ? privateKeys : privateKeys.privateKey
  );
  var mlkemSs = nodeCrypto.decapsulate(mlkemPriv, kemCt);
  var symmetricKey;

  if (kemId === C.KEM_IDS.ML_KEM_1024_P384) {
    var ecEphLen = packed.readUInt16BE(pos); pos += 2;
    var ecEphDer = packed.subarray(pos, pos + ecEphLen); pos += ecEphLen;
    var ecPrivPem = typeof privateKeys === "string" ? null : privateKeys.ecPrivateKey;
    if (!ecPrivPem) throw new Error("Hybrid KEM requires EC private key");
    var ecSs = nodeCrypto.diffieHellman({
      privateKey: nodeCrypto.createPrivateKey(ecPrivPem),
      publicKey:  nodeCrypto.createPublicKey({ key: ecEphDer, type: "spki", format: "der" }),
    });
    symmetricKey = kdf(Buffer.concat([mlkemSs, ecSs,
      _suiteFixedInfo(kemId, cipherId, kdfId)]), C.BYTES.bytes(32));
  } else if (kemId === C.KEM_IDS.ML_KEM_1024) {
    symmetricKey = kdf(Buffer.concat([mlkemSs,
      _suiteFixedInfo(kemId, cipherId, kdfId)]), C.BYTES.bytes(32));
  } else if (kemId === C.KEM_IDS.ML_KEM_768_X25519) {
    // ML-KEM-768 + X25519 hybrid envelope. The mlkemPriv must be an
    // ML-KEM-768 key (not 1024); operators are responsible for passing
    // the correct keypair via privateKeys when the envelope was sealed
    // with this algorithm. Same length-prefixed shape as the P-384
    // hybrid: 2-byte ec-eph-len + DER X25519 pubkey + nonce + ct.
    var x25519EphLen = packed.readUInt16BE(pos); pos += 2;
    var x25519EphDer = packed.subarray(pos, pos + x25519EphLen); pos += x25519EphLen;
    var x25519PrivPem = typeof privateKeys === "string" ? null : privateKeys.x25519PrivateKey;
    if (!x25519PrivPem) throw new Error("ML-KEM-768 + X25519 hybrid envelope requires x25519PrivateKey");
    var x25519Ss = nodeCrypto.diffieHellman({
      privateKey: nodeCrypto.createPrivateKey(x25519PrivPem),
      publicKey:  nodeCrypto.createPublicKey({ key: x25519EphDer, type: "spki", format: "der" }),
    });
    symmetricKey = kdf(Buffer.concat([mlkemSs, x25519Ss,
      _suiteFixedInfo(kemId, cipherId, kdfId)]), C.BYTES.bytes(32));
  } else {
    throw new Error("Invalid envelope: unsupported KEM ID " + kemId);
  }

  var nonce = packed.subarray(pos, pos + C.BYTES.bytes(24)); pos += C.BYTES.bytes(24);
  // Re-derive the 4-byte envelope-header AAD from the bytes we just
  // dispatched on. A tampered header (algorithm-substitution attack)
  // surfaces here as a Poly1305 tag verification failure.
  var headerAad = packed.subarray(0, 4);                                          // allow:raw-byte-literal — envelope-header byte slice
  return Buffer.from(
    xchacha20poly1305(symmetricKey, nonce, headerAad).decrypt(packed.subarray(pos))
  ).toString("utf8");
}

// ---- Symmetric buffer encrypt/decrypt (for storage) ----
//
// Optional `aad` (additional authenticated data) is mixed into the
// Poly1305 tag — encrypt-time and decrypt-time AAD must match exactly
// or decrypt fails. Used by primitives that want encryption-context
// binding (b.breakGlass.encryptCell binds (table, rowId, column) so a
// ciphertext from row A literally cannot decrypt as row B even with
// the same key).
function encryptPacked(buffer, key, aad) {
  var nonce = random(C.BYTES.bytes(24));
  var ct = xchacha20poly1305(key, nonce, aad ? Buffer.from(aad) : undefined).encrypt(buffer);
  return Buffer.concat([
    Buffer.from([C.FORMAT.XCHACHA20_POLY1305]),
    Buffer.from(nonce),
    Buffer.from(ct),
  ]);
}

function decryptPacked(packed, key, aad) {
  if (packed[0] !== C.FORMAT.XCHACHA20_POLY1305) {
    throw new Error("Invalid packed format: unsupported version");
  }
  return Buffer.from(
    xchacha20poly1305(key, packed.subarray(1, 25), aad ? Buffer.from(aad) : undefined)
      .decrypt(packed.subarray(25))
  );
}

// ---- ML-KEM-768 + X25519 hybrid (TLS-interop envelope) ----
//
// The IETF / Cloudflare / Chrome standardized hybrid for TLS 1.3
// (codepoint 0x11EC). Smaller payload than ML-KEM-1024 + P-384
// (~1.1 KB vs ~1.6 KB), wider interop with peers using the same
// hybrid (Cloudflare Workers, Chrome, blamejs-on-the-other-side).
//
// Operators wire this when the recipient publishes ML-KEM-768 +
// X25519 keys. Generation:
//
//   var pair = b.crypto.generateMlkem768X25519KeyPair();
//   // → { mlkemPublicKey, mlkemPrivateKey,
//   //     x25519PublicKey, x25519PrivateKey }
//
//   var envelope = b.crypto.encryptMlkem768X25519(plaintext, {
//     mlkemPublicKey:    recipient.mlkemPublicKey,
//     x25519PublicKey:   recipient.x25519PublicKey,
//   });
//
// Decryption goes through the existing b.crypto.decrypt(envelope,
// privateKeys) — the envelope-magic dispatch handles KEM_IDS.
// ML_KEM_768_X25519. privateKeys MUST shape as { privateKey,
// x25519PrivateKey } — privateKey is the ML-KEM-768 PEM, NOT the
// default ML-KEM-1024.

function generateMlkem768X25519KeyPair() {
  var mlkem = generateKeyPair("ml-kem-768");
  var x25519 = generateKeyPair("x25519");
  return {
    mlkemPublicKey:    mlkem.publicKey,
    mlkemPrivateKey:   mlkem.privateKey,
    x25519PublicKey:   x25519.publicKey,
    x25519PrivateKey:  x25519.privateKey,
  };
}

function encryptMlkem768X25519(plaintext, recipient) {
  if (!recipient || !recipient.mlkemPublicKey || !recipient.x25519PublicKey) {
    throw new Error("encryptMlkem768X25519 requires { mlkemPublicKey, x25519PublicKey }");
  }
  var mlkemPub = nodeCrypto.createPublicKey(recipient.mlkemPublicKey);
  var kem = nodeCrypto.encapsulate(mlkemPub);
  var ephX25519 = generateKeyPair("x25519", {
    publicKeyEncoding:  { type: "spki",  format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  var x25519Ss = nodeCrypto.diffieHellman({
    privateKey: nodeCrypto.createPrivateKey(ephX25519.privateKey),
    publicKey:  nodeCrypto.createPublicKey(recipient.x25519PublicKey),
  });
  var key = kdf(Buffer.concat([kem.sharedKey, x25519Ss,
    _suiteFixedInfo(C.KEM_IDS.ML_KEM_768_X25519, C.ACTIVE.CIPHER, C.ACTIVE.KDF)]),
    C.BYTES.bytes(32));
  var nonce = generateBytes(C.BYTES.bytes(24));
  var headerAad = Buffer.from([C.ENVELOPE_MAGIC, C.KEM_IDS.ML_KEM_768_X25519,
    C.ACTIVE.CIPHER, C.ACTIVE.KDF]);
  var ct = xchacha20poly1305(key, nonce, headerAad).encrypt(Buffer.from(plaintext, "utf8"));

  var kemCtLen = Buffer.alloc(2); kemCtLen.writeUInt16BE(kem.ciphertext.length);
  var x25519EphDer = ephX25519.publicKey;
  var x25519EphLen = Buffer.alloc(2); x25519EphLen.writeUInt16BE(x25519EphDer.length);

  return Buffer.concat([
    headerAad,
    kemCtLen, kem.ciphertext, x25519EphLen, x25519EphDer, nonce, Buffer.from(ct),
  ]).toString("base64");
}

// Symmetric named-pair to encryptMlkem768X25519. Operators wiring the
// IETF / Cloudflare / Chrome TLS-1.3 hybrid (codepoint 0x11EC) want
// the encrypt + decrypt halves under symmetric, discoverable names.
//
// The generic b.crypto.decrypt already dispatches by KEM ID and
// handles ML_KEM_768_X25519 envelopes correctly; this helper REJECTS
// any other KEM ID at the head, so an operator who calls
// decryptMlkem768X25519 with a ciphertext sealed under a different
// algorithm gets a clear error rather than the generic "unsupported
// KEM ID" path.
//
//   recipient: { privateKey, x25519PrivateKey }   — operator's keys
//   ciphertext: base64 envelope from encryptMlkem768X25519
function decryptMlkem768X25519(ciphertext, recipient) {
  if (!recipient || typeof recipient !== "object" ||
      !recipient.privateKey || !recipient.x25519PrivateKey) {
    throw new Error("decryptMlkem768X25519 requires { privateKey, x25519PrivateKey } " +
                    "(privateKey is the ML-KEM-768 PEM, x25519PrivateKey is the X25519 PEM)");
  }
  var packed = Buffer.from(ciphertext, "base64");
  if (packed[0] !== C.ENVELOPE_MAGIC) {
    throw new Error("decryptMlkem768X25519: invalid envelope (bad magic byte)");
  }
  if (packed[1] !== C.KEM_IDS.ML_KEM_768_X25519) {
    throw new Error("decryptMlkem768X25519: envelope KEM ID is " + packed[1] +
                    ", expected " + C.KEM_IDS.ML_KEM_768_X25519 +
                    " (ML_KEM_768_X25519). Use b.crypto.decrypt for KEM-id dispatch.");
  }
  return decryptEnvelope(packed, recipient);
}

// ---- Cert-peer envelope primitives ----
//
// The framework's default `encrypt` / `decrypt` source the recipient
// from a published framework keypair (operator owns both halves). The
// cert-peer variants source the recipient from a TLS peer cert (peer
// owns the ECDH P-384 half) plus a peer-supplied ML-KEM-1024 pubkey.
// Wire format is unchanged — the envelope dispatches on the same
// version bytes and KEM ID. Only the input keys differ.
//
// Use cases beyond the b.middleware.apiEncrypt strategy:
//   - Sealed-storage records with peer recipients (operator A seals
//     to operator B's TLS cert + KEM pubkey).
//   - Cross-service messages between cert-identified peers without
//     a shared framework keypair.
//   - Audit log entries tagged with peer recipients.

function _extractEcdhP384FromCert(certDer) {
  // The cert's SubjectPublicKeyInfo carries the ECDH P-384 pubkey when
  // the cert is issued for that curve. node:crypto's X509Certificate
  // exposes `publicKey` as a KeyObject; we only export the SPKI as PEM
  // so the existing `encrypt` path consumes the same shape it accepts
  // for `ecPublicKey`.
  var cert = new nodeCrypto.X509Certificate(certDer);
  var keyObj = cert.publicKey;
  var details = keyObj.asymmetricKeyDetails || {};
  if (keyObj.asymmetricKeyType !== "ec" ||
      details.namedCurve !== "secp384r1") {
    var err = new Error(
      "cert public key is not ECDH P-384 (got asymmetricKeyType=" +
      keyObj.asymmetricKeyType + ", namedCurve=" + details.namedCurve + ")");
    err.code = "crypto/cert-key-not-ecdh-p384";
    throw err;
  }
  return keyObj.export({ type: "spki", format: "pem" });
}

// encryptEnvelopeAsCertPeer — produce a cert-bound envelope for the
// peer identified by their TLS cert + ML-KEM-1024 pubkey.
//
//   var envelope = b.crypto.encryptEnvelopeAsCertPeer(plaintext, {
//     peerCertDer:    Buffer | Uint8Array,    // peer's TLS cert (DER)
//     peerKemPubkey:  string,                  // peer's ML-KEM-1024 pubkey PEM
//   });
function encryptEnvelopeAsCertPeer(plaintext, opts) {
  if (!opts || typeof opts !== "object") {
    throw new Error("encryptEnvelopeAsCertPeer: opts object required");
  }
  if (!opts.peerCertDer) {
    var e1 = new Error("peerCertDer required (peer's TLS cert as DER bytes)");
    e1.code = "crypto/peer-cert-missing";
    throw e1;
  }
  if (typeof opts.peerKemPubkey !== "string") {                                  // allow:inline-require-non-empty-string-validation — crypto module avoids validateOpts dependency to stay minimal
    var e2 = new Error("peerKemPubkey required (peer's ML-KEM-1024 pubkey PEM)");
    e2.code = "crypto/peer-kem-pubkey-missing";
    throw e2;
  }
  if (opts.peerKemPubkey.length === 0) {
    var e2b = new Error("peerKemPubkey is empty");
    e2b.code = "crypto/peer-kem-pubkey-missing";
    throw e2b;
  }
  var ecPubPem = _extractEcdhP384FromCert(opts.peerCertDer);
  return encrypt(plaintext, {
    publicKey:   opts.peerKemPubkey,
    ecPublicKey: ecPubPem,
  });
}

// decryptEnvelopeAsCertPeer — decrypt an envelope sealed to this
// operator's TLS cert ECDH-pubkey + ML-KEM-1024 pubkey.
//
//   var plaintext = b.crypto.decryptEnvelopeAsCertPeer(envelope, {
//     certPrivateKey: KeyObject | string,    // this operator's cert P-384 priv
//     kemSecret:      string,                 // this operator's ML-KEM-1024 priv PEM
//   });
function decryptEnvelopeAsCertPeer(envelope, opts) {
  if (!opts || typeof opts !== "object") {
    throw new Error("decryptEnvelopeAsCertPeer: opts object required");
  }
  if (!opts.certPrivateKey) {
    var e1 = new Error("certPrivateKey required");
    e1.code = "crypto/cert-private-key-missing";
    throw e1;
  }
  if (typeof opts.kemSecret !== "string") {                                      // allow:inline-require-non-empty-string-validation — crypto module avoids validateOpts dependency to stay minimal
    var e2 = new Error("kemSecret required (operator's ML-KEM-1024 priv PEM)");
    e2.code = "crypto/kem-secret-missing";
    throw e2;
  }
  if (opts.kemSecret.length === 0) {
    var e2b = new Error("kemSecret is empty");
    e2b.code = "crypto/kem-secret-missing";
    throw e2b;
  }
  // Normalize certPrivateKey to PEM string (existing decrypt accepts
  // PEM string).
  var ecPrivPem;
  if (typeof opts.certPrivateKey === "string") {
    ecPrivPem = opts.certPrivateKey;
  } else if (typeof opts.certPrivateKey.export === "function") {
    var details = opts.certPrivateKey.asymmetricKeyDetails || {};
    if (opts.certPrivateKey.asymmetricKeyType !== "ec" ||
        details.namedCurve !== "secp384r1") {
      var e3 = new Error(
        "certPrivateKey is not ECDH P-384 (got asymmetricKeyType=" +
        opts.certPrivateKey.asymmetricKeyType + ", namedCurve=" +
        details.namedCurve + ")");
      e3.code = "crypto/cert-key-not-ecdh-p384";
      throw e3;
    }
    ecPrivPem = opts.certPrivateKey.export({ type: "pkcs8", format: "pem" });
  } else {
    var e4 = new Error("certPrivateKey must be a KeyObject or PEM string");
    e4.code = "crypto/cert-private-key-bad-shape";
    throw e4;
  }
  return decrypt(envelope, {
    privateKey:   opts.kemSecret,
    ecPrivateKey: ecPrivPem,
  });
}

// Operator-audit accessor — exposes every supported KEM hybrid for
// compliance audit visibility ("which envelopes does this deploy
// accept on decrypt?").
// ---- Certificate fingerprint helpers ----
//
// Operators pinning peer-cert fingerprints (mtls bootstrap, webhook
// verification, certificate transparency cross-checks) want a stable
// SHA3-512 hash of the DER bytes plus a colon-separated hex form that
// matches what most operator tooling renders for X.509 fingerprints.
// hashCertFingerprint accepts either a Buffer (DER) or a PEM string;
// if PEM, the BEGIN/END envelope is stripped and the base64 body is
// decoded before hashing. The hash is the framework's standard SHA3-
// 512 (not SHA-256 — operators using OpenSSL's `-sha256` defaults can
// keep their own SHA-256 hashes, this primitive is the framework-
// canonical form). Returns { hex, colon } so callers can compare
// against either rendering.
function _pemToDer(pemOrDer) {
  if (Buffer.isBuffer(pemOrDer)) return pemOrDer;
  if (typeof pemOrDer !== "string") {
    throw new TypeError("crypto.hashCertFingerprint: input must be a Buffer (DER) or a PEM-encoded string");
  }
  var match = pemOrDer.match(/-----BEGIN [A-Z0-9 ]+-----([\s\S]+?)-----END [A-Z0-9 ]+-----/);
  if (!match) {
    throw new TypeError("crypto.hashCertFingerprint: PEM input lacks BEGIN/END markers");
  }
  return Buffer.from(match[1].replace(/\s+/g, ""), "base64");
}
function hashCertFingerprint(pemOrDer) {
  var der = _pemToDer(pemOrDer);
  var digest = hash(der, "sha3-512");
  var hex = digest.toString("hex");
  // Colon-separated, uppercase — matches openssl x509 -fingerprint
  // output style (which is SHA-1 by default, but the rendering shape
  // operators expect is the same).
  var colon = hex.toUpperCase().match(/.{2}/g).join(":");
  return { hex: hex, colon: colon };
}
// Compares a peer's PEM/DER cert against an allowlist of pinned
// fingerprints. Allowlist entries may be the colon form, the lower-
// case hex form, or both — every comparison runs through
// timingSafeEqual to avoid leaking which entry matched.
function isCertRevoked(pemOrDer, denyList) {
  if (!Array.isArray(denyList)) {
    throw new TypeError("crypto.isCertRevoked: denyList must be an array of fingerprint strings");
  }
  var fp = hashCertFingerprint(pemOrDer);
  var fpHex = Buffer.from(fp.hex, "hex");
  var fpColon = Buffer.from(fp.colon);
  for (var i = 0; i < denyList.length; i++) {
    var entry = denyList[i];
    if (typeof entry !== "string" || entry.length === 0) continue;
    var normalized = entry.indexOf(":") !== -1 ? entry.toUpperCase() : entry.toLowerCase();
    var normalizedBuf = entry.indexOf(":") !== -1 ? Buffer.from(normalized) : Buffer.from(normalized, "hex");
    var compareBuf  = entry.indexOf(":") !== -1 ? fpColon : fpHex;
    if (normalizedBuf.length === compareBuf.length &&
        nodeCrypto.timingSafeEqual(normalizedBuf, compareBuf)) {
      return true;
    }
  }
  return false;
}

var SUPPORTED_KEM_ALGORITHMS = Object.freeze([
  { id: "ml-kem-1024",          envelopeId: C.KEM_IDS.ML_KEM_1024,        description: "ML-KEM-1024 KEM-only (legacy single-component)" },
  { id: "ml-kem-1024-p384",     envelopeId: C.KEM_IDS.ML_KEM_1024_P384,   description: "ML-KEM-1024 + ECDH P-384 hybrid (framework default)" },
  { id: "ml-kem-768-x25519",    envelopeId: C.KEM_IDS.ML_KEM_768_X25519,  description: "ML-KEM-768 + X25519 hybrid (IETF / Cloudflare / Chrome TLS 1.3 codepoint 0x11EC)" },
]);

module.exports = {
  sri:                          sri,
  // Hashing
  sha3Hash:                    sha3Hash,
  hmacSha3:                    hmacSha3,
  kdf:                         kdf,
  // Comparison
  timingSafeEqual:             timingSafeEqual,
  // Cert fingerprint helpers
  hashCertFingerprint:         hashCertFingerprint,
  isCertRevoked:               isCertRevoked,
  // Random
  generateBytes:               generateBytes,
  generateToken:               generateToken,
  // Keys
  generateEncryptionKeyPair:   generateEncryptionKeyPair,
  generateSigningKeyPair:      generateSigningKeyPair,
  generateMlkem768X25519KeyPair: generateMlkem768X25519KeyPair,
  // Signatures
  sign:                        sign,
  verify:                      verify,
  // Envelope encrypt/decrypt
  encrypt:                     encrypt,
  decrypt:                     decrypt,
  encryptMlkem768X25519:       encryptMlkem768X25519,
  decryptMlkem768X25519:       decryptMlkem768X25519,
  encryptEnvelopeAsCertPeer:   encryptEnvelopeAsCertPeer,
  decryptEnvelopeAsCertPeer:   decryptEnvelopeAsCertPeer,
  SUPPORTED_KEM_ALGORITHMS:    SUPPORTED_KEM_ALGORITHMS,
  // Symmetric buffer encrypt/decrypt
  encryptPacked:               encryptPacked,
  decryptPacked:               decryptPacked,
};
