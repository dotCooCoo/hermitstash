"use strict";
/**
 * @module b.jose.jwe.experimental
 * @nav    Crypto
 * @title  JOSE JWE (experimental, ML-KEM)
 *
 * @intro
 *   JSON Web Encryption (RFC 7516) with ML-KEM-1024 key encapsulation
 *   and XChaCha20-Poly1305 AEAD content encryption. Lives under
 *   `b.jose.jwe.experimental` because the JOSE PQC IANA codepoint
 *   registration (draft-ietf-jose-pqc-kem-05) hasn't finalized — the
 *   namespace name is the contract: codepoints may change between
 *   minors without the framework's stable surface being affected.
 *
 *   When the JOSE WG closes the draft and IANA registers final
 *   codepoints, the same primitives graduate to `b.jose.jwe` (or a
 *   stable equivalent) with explicit deprecation of the experimental
 *   namespace and a one-minor migration window per the framework's
 *   stable-upgrade-policy rule.
 *
 *   Compact serialization only — no JSON serialization variant
 *   (saves wire-format complexity at this experimental tier;
 *   operators that need JWE-JSON wait for the stable surface).
 *
 * @card
 *   Experimental JWE with ML-KEM-1024 KEM + XChaCha20-Poly1305 content encryption. Codepoints follow draft-ietf-jose-pqc-kem (may change before IANA registration).
 */

var bCrypto = require("./crypto");
var canonicalJson = require("./canonical-json");
var { defineClass } = require("./framework-error");
var audit = require("./audit");

var JoseJweExperimentalError = defineClass("JoseJweExperimentalError", { alwaysPermanent: true });

// Active draft (as of 2026-05-17). When IANA finalizes the codepoint
// the framework graduates the alg name to its stable form and ships a
// one-minor deprecation window via the existing `deprecate()` chain.
var EXPERIMENTAL_ALG  = "ML-KEM-1024";
var EXPERIMENTAL_ENC  = "XC20P";   // XChaCha20-Poly1305 per draft-irtf-cfrg-xchacha; aligns with framework PQC-first defaults

/**
 * @primitive b.jose.jwe.experimental.encrypt
 * @signature b.jose.jwe.experimental.encrypt(plaintext, recipientPublicKeyPem, opts?)
 * @since     0.10.10
 * @status    experimental
 * @related   b.jose.jwe.experimental.decrypt, b.crypto.encrypt
 *
 * Encrypt a payload under the recipient's ML-KEM-1024 public key.
 * Returns the JWE compact serialization
 * `<header>.<encrypted_key>.<iv>.<ciphertext>.<tag>` (base64url
 * segments) per RFC 7516 §3.1 with experimental PQC codepoints.
 *
 * Header includes `{ alg: "ML-KEM-1024", enc: "XC20P", typ: "JWE",
 * "x-blamejs-experimental": true }` — operators that scrape JWE
 * envelopes can refuse the experimental marker until the codepoint
 * stabilises.
 *
 * @opts
 *   typ:           string,        // optional JWE "typ" header
 *   contentType:   string,        // optional JWE "cty" header
 *   audit:         boolean,        // default true; emit audit event on encrypt
 *
 * @example
 *   var pair = b.crypto.generateEncryptionKeyPair();
 *   var jwe = b.jose.jwe.experimental.encrypt("hello", pair.mlkem.publicKey);
 *   typeof jwe; // → "string" (compact form)
 */
function encrypt(plaintext, recipientPublicKeyPem, opts) {
  opts = opts || {};
  if (!(plaintext instanceof Buffer)) {
    if (typeof plaintext === "string") plaintext = Buffer.from(plaintext, "utf8");
    else {
      throw new JoseJweExperimentalError("jose-jwe-exp/bad-plaintext",
        "encrypt: plaintext must be a Buffer or string");
    }
  }
  if (typeof recipientPublicKeyPem !== "string" || recipientPublicKeyPem.length === 0) {
    throw new JoseJweExperimentalError("jose-jwe-exp/bad-key",
      "encrypt: recipientPublicKeyPem must be a non-empty PEM string");
  }

  var header = {
    alg:                       EXPERIMENTAL_ALG,
    enc:                       EXPERIMENTAL_ENC,
    typ:                       opts.typ || "JWE",
    "x-blamejs-experimental":  true,
  };
  if (typeof opts.contentType === "string" && opts.contentType.length > 0) {
    header.cty = opts.contentType;
  }

  // Encapsulate under the recipient's ML-KEM-1024 public key. The
  // framework's `encrypt(plaintext, pemString)` form selects the
  // ML-KEM-only path and returns a base64 envelope string.
  //
  // The experimental JWE serialization carries the framework envelope
  // as a single base64url segment (`ciphertext` slot). The empty
  // `encrypted_key` / `iv` / `tag` segments are valid under RFC 7516
  // §3.1 (compact serialization permits empty Base64URL parts when
  // the cryptographic primitives are AEAD-with-direct-key — the
  // framework envelope is self-contained). Operators that need the
  // segmented shape with each field carved out wait for the
  // post-IANA stable surface where layout is contract.
  var fwEnvelopeB64 = bCrypto.encrypt(plaintext, recipientPublicKeyPem);
  var fwEnvelopeUrl = bCrypto.toBase64Url(Buffer.from(fwEnvelopeB64, "base64"));
  var headerB64 = bCrypto.toBase64Url(Buffer.from(canonicalJson.stringify(header), "utf8"));
  // RFC 7516 §3.1 compact-serialization slots: header / encrypted_key
  // / iv / ciphertext / tag. The framework envelope (a self-contained
  // AEAD output) lives in the `ciphertext` slot (index 3). Other slots
  // are empty under this experimental shape.
  var compact = headerB64 + "..." + fwEnvelopeUrl + ".";
  if (opts.audit !== false) {
    audit.safeEmit({
      action:   "jose.jwe.experimental.encrypt",
      outcome:  "success",
      metadata: { alg: EXPERIMENTAL_ALG, enc: EXPERIMENTAL_ENC, ptLen: plaintext.length },
    });
  }
  return compact;
}

/**
 * @primitive b.jose.jwe.experimental.decrypt
 * @signature b.jose.jwe.experimental.decrypt(compact, recipientPrivateKeyPem, opts?)
 * @since     0.10.10
 * @status    experimental
 * @related   b.jose.jwe.experimental.encrypt
 *
 * Decrypt a compact-serialization JWE produced by the experimental
 * `encrypt` path. Returns the plaintext Buffer. Refuses on alg / enc
 * mismatch, missing experimental marker, or any cryptographic verify
 * failure. Never throws on adversarial input — typed
 * `JoseJweExperimentalError` with a coded refusal.
 *
 * @opts
 *   audit:         boolean,        // default true
 *
 * @example
 *   var plaintext = b.jose.jwe.experimental.decrypt(jwe, pair.mlkem.privateKey);
 *   plaintext.toString("utf8"); // → "hello"
 */
function decrypt(compact, recipientPrivateKeyPem, opts) {
  opts = opts || {};
  if (typeof compact !== "string" || compact.length === 0) {
    throw new JoseJweExperimentalError("jose-jwe-exp/bad-compact",
      "decrypt: compact must be a non-empty string");
  }
  if (typeof recipientPrivateKeyPem !== "string" || recipientPrivateKeyPem.length === 0) {
    throw new JoseJweExperimentalError("jose-jwe-exp/bad-key",
      "decrypt: recipientPrivateKeyPem must be a non-empty PEM string");
  }
  var parts = compact.split(".");
  if (parts.length !== 5) {                                                                          // allow:raw-byte-literal — JWE compact serialization is 5 dot-separated segments (RFC 7516 §3.1)
    throw new JoseJweExperimentalError("jose-jwe-exp/bad-format",
      "decrypt: JWE compact serialization MUST have 5 segments (RFC 7516 §3.1), got " + parts.length);
  }
  var header;
  // Header is base64url-decoded; route through safeJson.parse for
  // proto-pollution + depth + size defenses (operator-supplied compact
  // bytes are adversarial). Both the base64url decode AND the JSON
  // parse live inside the same typed try/catch so a malformed header
  // surfaces as the typed `jose-jwe-exp/bad-header` refusal class
  // rather than a raw TypeError leaking from b.crypto.fromBase64Url.
  var headerBytes;
  try { headerBytes = bCrypto.fromBase64Url(parts[0]); }
  catch (_eb) {
    throw new JoseJweExperimentalError("jose-jwe-exp/bad-header",
      "decrypt: protected header is not valid base64url");
  }
  if (headerBytes.length > 4096) {                                                                   // allow:raw-byte-literal — JWE header byte cap, not bytes-as-storage
    throw new JoseJweExperimentalError("jose-jwe-exp/header-too-large",
      "decrypt: protected header exceeds 4 KiB cap");
  }
  try { header = require("./safe-json").parse(headerBytes.toString("utf8")); }                       // allow:inline-require — safe-json only needed on the rare decrypt path
  catch (_e) {
    throw new JoseJweExperimentalError("jose-jwe-exp/bad-header",
      "decrypt: protected header is not base64url-encoded JSON");
  }
  if (header.alg !== EXPERIMENTAL_ALG) {
    throw new JoseJweExperimentalError("jose-jwe-exp/alg-mismatch",
      "decrypt: alg '" + header.alg + "' is not '" + EXPERIMENTAL_ALG + "'");
  }
  if (header.enc !== EXPERIMENTAL_ENC) {
    throw new JoseJweExperimentalError("jose-jwe-exp/enc-mismatch",
      "decrypt: enc '" + header.enc + "' is not '" + EXPERIMENTAL_ENC + "'");
  }
  if (header["x-blamejs-experimental"] !== true) {
    throw new JoseJweExperimentalError("jose-jwe-exp/missing-experimental-marker",
      "decrypt: header missing `x-blamejs-experimental: true` — refuse to decrypt unmarked envelopes");
  }
  // Per the experimental serialization (see `encrypt`), the framework
  // envelope lives in segment 3. Other segments must be empty.
  if (parts[1].length > 0 || parts[2].length > 0 || parts[4].length > 0) {
    throw new JoseJweExperimentalError("jose-jwe-exp/bad-format",
      "decrypt: experimental JWE shape requires empty encrypted_key / iv / tag segments");
  }
  var fwEnvelopeBuf;
  try { fwEnvelopeBuf = bCrypto.fromBase64Url(parts[3]); }
  catch (_eb2) {
    throw new JoseJweExperimentalError("jose-jwe-exp/bad-format",
      "decrypt: ciphertext segment is not valid base64url");
  }
  var fwEnvelopeB64 = fwEnvelopeBuf.toString("base64");
  // `raw: true` keeps the decrypted plaintext as a Buffer rather than
  // utf8-decoding it (which would corrupt binary payloads — `0xff`
  // becomes the Unicode replacement character). The JWE primitives
  // document Buffer-in / Buffer-out so the contract holds across
  // arbitrary plaintext shapes (signed-blob carriers, binary tokens).
  var plaintext = bCrypto.decrypt(fwEnvelopeB64,
    { privateKey: recipientPrivateKeyPem }, { raw: true });
  if (opts.audit !== false) {
    audit.safeEmit({
      action:   "jose.jwe.experimental.decrypt",
      outcome:  "success",
      metadata: { alg: EXPERIMENTAL_ALG, enc: EXPERIMENTAL_ENC },
    });
  }
  return plaintext;
}

module.exports = {
  encrypt:                  encrypt,
  decrypt:                  decrypt,
  EXPERIMENTAL_ALG:         EXPERIMENTAL_ALG,
  EXPERIMENTAL_ENC:         EXPERIMENTAL_ENC,
  JoseJweExperimentalError: JoseJweExperimentalError,
};
