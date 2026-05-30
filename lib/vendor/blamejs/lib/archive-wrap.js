"use strict";
/**
 * archive-wrap — recipient-based whole-archive encryption substrate
 * for the b.archive family. Composes b.crypto.encrypt (ML-KEM-1024 +
 * P-384 ECDH hybrid + SHAKE256 + XChaCha20-Poly1305 envelope) so
 * archive bytes hitting an adapter can be a sealed envelope rather
 * than the raw format.
 *
 * Operators compose explicitly for v0.12.10:
 *
 *   var sealed = b.archive.wrap(t.toBuffer(), { recipient: pubKeys });
 *   await b.archive.adapters.fs(path).write(sealed);
 *
 *   var sealed = await fs.promises.readFile(path);
 *   var bytes  = b.archive.unwrap(sealed, { recipient: privKeys });
 *   var reader = b.archive.read.tar(b.archive.adapters.buffer(bytes));
 *
 * Three recipient strategies: a static hybrid-PQC key-pair, a peer
 * certificate, and `"tenant"` — a deterministic per-tenant symmetric
 * seal keyed by the vault root (no key-pair to manage; unwrap
 * re-derives from the tenant id). b.backup's `cryptoStrategy:
 * "recipient"` consumes the same substrate.
 */

var C = require("./constants");
var lazyRequire = require("./lazy-require");
var { defineClass } = require("./framework-error");

var ArchiveWrapError = defineClass("ArchiveWrapError", { alwaysPermanent: true });

var bCrypto = lazyRequire(function () { return require("./crypto"); });
var backupCrypto = lazyRequire(function () { return require("./backup/crypto"); });
var agentTenant = lazyRequire(function () { return require("./agent-tenant"); });

// Envelope magic — 5-byte ASCII prefix the safe-archive sniffer
// recognises. Distinct from b.crypto.encrypt's base64 envelope so
// archive-wrap output can carry an unambiguous "this is an archive
// wrap envelope" magic before the operator-controlled payload.
var ARCH_WRAP_MAGIC = "BAWRP";                                                       // allow:raw-byte-literal — 5-byte ASCII archive-wrap recipient envelope magic
var ARCH_WRAP_VERSION = 0x01;                                                        // allow:raw-byte-literal — recipient version byte (hybrid-KEM envelope)
// Tenant strategy uses the same BAWRP magic with a distinct version
// byte: the body is a symmetric XChaCha20-Poly1305 packed ciphertext
// (b.crypto.encryptPacked) keyed by the tenant's vault-derived key,
// not a hybrid-KEM envelope. unwrap dispatches on the version byte so
// a tenant envelope is never fed to the KEM decrypt path.
var ARCH_WRAP_VERSION_TENANT = 0x02;                                                 // allow:raw-byte-literal — tenant symmetric-seal version byte
// Purpose label for the per-tenant key derivation (domain-separates
// the archive-wrap key from a tenant's seal / audit / session keys).
var TENANT_KEY_PURPOSE = "archive-wrap";
var ARCH_WRAP_HEADER_BYTES = C.BYTES.bytes(6);                                        // magic(5) + version(1)
// Passphrase variant — wire format: magic(5) + version(1) + saltLen(1)
// + salt(saltLen bytes) + encrypted bytes (24-byte nonce + ciphertext+tag
// from backup-crypto encryptWithPassphrase). The salt-prefix shape
// lets the framework rotate KDF parameters in future minors without
// per-envelope version bumps (each envelope carries its own salt).
var ARCH_PASSPHRASE_MAGIC = "BAWPP";                                                 // allow:raw-byte-literal — 5-byte passphrase-wrap envelope magic
var ARCH_PASSPHRASE_VERSION = 0x01;                                                  // allow:raw-byte-literal — passphrase version byte
var ARCH_PASSPHRASE_HEADER_BYTES = C.BYTES.bytes(7);                                  // magic(5) + version(1) + saltLen(1)

/**
 * @primitive b.archive.wrap
 * @signature b.archive.wrap(bytes, opts)
 * @since     0.12.10
 * @status    stable
 * @related   b.archive.unwrap, b.crypto.encrypt, b.backup.bundleAdapterStorage
 *
 * Wrap archive bytes in a recipient-encrypted envelope. The envelope
 * is the framework's standard hybrid PQC seal (ML-KEM-1024 + P-384
 * ECDH hybrid + SHAKE256 KDF + XChaCha20-Poly1305 AEAD) prefixed
 * with a 6-byte archive-wrap header (`BAWRP` magic + version byte)
 * so format sniffers can distinguish wrap envelopes from raw
 * archives without trial decryption.
 *
 * Recipient strategies:
 *   - static key  — `{ recipient: { publicKey, ecPublicKey } }` (ML-KEM-1024
 *                   pubkey PEM + P-384 ECDH pubkey PEM).
 *   - peer cert   — `{ recipient: { peerCertDer, peerKemPubkey } }` composes
 *                   `b.crypto.encryptEnvelopeAsCertPeer` (extracts the
 *                   P-384 half from the cert).
 *   - tenant      — `{ recipient: "tenant", tenantId: "alpha" }` seals
 *                   under a deterministic per-tenant key derived from the
 *                   vault root (`b.agent.tenant.derivedKey`) with
 *                   XChaCha20-Poly1305, the tenant id mixed into the AEAD
 *                   AAD so one tenant's envelope cannot open under
 *                   another's key. No recipient key-pair to manage;
 *                   `unwrap` re-derives from the same `tenantId`. Requires
 *                   an initialized vault.
 *
 * @opts
 *   recipient:  object | string,   // see strategies above; required
 *   tenantId:   string,            // required when recipient === "tenant"
 *
 * @example
 *   var pair   = b.crypto.generateEncryptionKeyPair();
 *   var sealed = b.archive.wrap(tarBytes, { recipient: pair });
 *   // sealed is a Buffer carrying BAWRP+version+envelope; write to
 *   // any adapter sink. On read, hand to b.archive.unwrap with the
 *   // matching privKeys to recover tarBytes.
 */
function wrap(bytes, opts) {
  opts = opts || {};
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) {
    throw new ArchiveWrapError("archive-wrap/bad-input",
      "wrap: bytes must be a Buffer or Uint8Array");
  }
  if (bytes.length === 0) {
    throw new ArchiveWrapError("archive-wrap/empty-input",
      "wrap: bytes is empty — nothing to seal");
  }
  if (!opts.recipient) {
    throw new ArchiveWrapError("archive-wrap/no-recipient",
      "wrap: opts.recipient is required (static key object | \"tenant\" string | peer-cert object)");
  }
  var enc = _encryptForRecipient(bytes, opts);
  // enc.body is the envelope bytes (base64 KEM envelope for static /
  // peer-cert recipients, symmetric packed ciphertext for tenant).
  // Prepend the 6-byte archive-wrap header stamped with the strategy's
  // version byte so safeArchive's sniffer + unwrap can identify the
  // envelope (and pick the right decrypt path) without trial decryption.
  var header = Buffer.alloc(ARCH_WRAP_HEADER_BYTES);
  header.write(ARCH_WRAP_MAGIC, 0, 5, "ascii");
  header[5] = enc.version;
  return Buffer.concat([header, enc.body]);
}

/**
 * @primitive b.archive.unwrap
 * @signature b.archive.unwrap(sealed, opts)
 * @since     0.12.10
 * @status    stable
 * @related   b.archive.wrap, b.crypto.decrypt
 *
 * Recover archive bytes from a recipient-encrypted envelope produced
 * by `b.archive.wrap`. Verifies the 6-byte `BAWRP` header before
 * attempting decryption so non-envelope inputs (raw archive bytes,
 * other-magic envelopes) fail with `archive-wrap/bad-magic` rather
 * than a crypto-level error.
 *
 * @opts
 *   recipient:  object | "tenant",  // { privateKey, ecPrivateKey } | { certPrivateKey, kemSecret } | "tenant"
 *   tenantId:   string,             // required when the envelope was sealed with recipient: "tenant"
 *
 * @example
 *   var bytes  = b.archive.unwrap(sealed, { recipient: privPair });
 *   var reader = b.archive.read.tar(b.archive.adapters.buffer(bytes));
 *   // tenant envelope:
 *   var t = b.archive.unwrap(sealedForTenant, { recipient: "tenant", tenantId: "alpha" });
 */
function unwrap(sealed, opts) {
  opts = opts || {};
  if (!Buffer.isBuffer(sealed) && !(sealed instanceof Uint8Array)) {
    throw new ArchiveWrapError("archive-wrap/bad-input",
      "unwrap: sealed must be a Buffer or Uint8Array");
  }
  if (sealed.length < ARCH_WRAP_HEADER_BYTES) {
    throw new ArchiveWrapError("archive-wrap/bad-magic",
      "unwrap: input shorter than 6-byte archive-wrap header");
  }
  var buf = Buffer.isBuffer(sealed) ? sealed : Buffer.from(sealed);
  var magic = buf.slice(0, 5).toString("ascii");
  if (magic !== ARCH_WRAP_MAGIC) {
    throw new ArchiveWrapError("archive-wrap/bad-magic",
      "unwrap: input does not start with archive-wrap magic " +
      JSON.stringify(ARCH_WRAP_MAGIC) + "; got " + JSON.stringify(magic));
  }
  var version = buf[5];
  // Tenant strategy: symmetric packed ciphertext keyed by the
  // vault-derived per-tenant key. Re-derive from opts.tenantId and
  // decrypt under the same tenant-bound AAD that wrap sealed with.
  if (version === ARCH_WRAP_VERSION_TENANT) {
    if (opts.recipient !== undefined && opts.recipient !== "tenant") {
      throw new ArchiveWrapError("archive-wrap/recipient-mismatch",
        "unwrap: this envelope was sealed with recipient: \"tenant\" — pass opts.tenantId " +
        "(and either omit opts.recipient or set it to \"tenant\"), not a key-pair recipient");
    }
    var tenantKey = _tenantKey(opts.tenantId);
    var packedBody = buf.slice(ARCH_WRAP_HEADER_BYTES);
    try {
      return bCrypto().decryptPacked(packedBody, tenantKey, _tenantAad(opts.tenantId));
    } catch (e) {
      var terr = new ArchiveWrapError("archive-wrap/decrypt-failed",
        "unwrap: tenant envelope decryption refused (wrong tenantId or rotated vault?): " +
        ((e && e.message) || String(e)));
      terr.cause = e;
      throw terr;
    }
  }
  if (version !== ARCH_WRAP_VERSION) {
    throw new ArchiveWrapError("archive-wrap/bad-version",
      "unwrap: archive-wrap version " + version + " not supported by this build");
  }
  if (!opts.recipient || typeof opts.recipient !== "object") {
    throw new ArchiveWrapError("archive-wrap/no-recipient",
      "unwrap: opts.recipient is required ({ privateKey, ecPrivateKey } " +
      "for the static-key path, { certPrivateKey, kemSecret } for the peer-cert path, " +
      "or \"tenant\" + opts.tenantId for the tenant path)");
  }
  var envelope = buf.slice(ARCH_WRAP_HEADER_BYTES).toString("utf-8");
  var plaintext;
  try {
    if (opts.recipient.certPrivateKey) {
      // Cert-peer path: encryptEnvelopeAsCertPeer composed
      // `encrypt(bytes, { publicKey, ecPublicKey })` where the
      // ecPublicKey was extracted from the cert. The inverse passes
      // the operator's kemSecret + certPrivateKey (P-384) through
      // the same decrypt code path. raw:true preserves binary
      // archive bytes losslessly.
      plaintext = bCrypto().decrypt(envelope, {
        privateKey:    opts.recipient.kemSecret,
        ecPrivateKey:  opts.recipient.certPrivateKey,
      }, { raw: true });
    } else {
      // raw:true returns the decrypted Buffer (lossless for arbitrary
      // binary archive payloads — utf-8 string conversion would
      // corrupt gzip / zip / tar bytes).
      plaintext = bCrypto().decrypt(envelope, opts.recipient, { raw: true });
    }
  } catch (e) {
    var err = new ArchiveWrapError("archive-wrap/decrypt-failed",
      "unwrap: envelope decryption refused: " + ((e && e.message) || String(e)));
    err.cause = e;
    throw err;
  }
  return Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext);
}

// Resolve a tenant's deterministic 32-byte archive-wrap key from the
// vault root. Throws a clear archive-wrap error (rather than a deep
// agent-tenant one) when tenantId is missing; the vault-not-initialized
// case surfaces from agentTenant.derivedKey unchanged.
function _tenantKey(tenantId) {
  if (typeof tenantId !== "string" || tenantId.length === 0) {
    throw new ArchiveWrapError("archive-wrap/no-tenant-id",
      "recipient: \"tenant\" requires opts.tenantId (a non-empty string)");
  }
  return Buffer.from(agentTenant().derivedKey(tenantId, TENANT_KEY_PURPOSE), "hex");
}

// AAD context-binds the symmetric envelope to the tenant: the Poly1305
// tag covers this, so a tenant-A envelope cannot be decrypted under
// tenant-B's key even if an attacker swaps headers between envelopes.
function _tenantAad(tenantId) {
  return Buffer.from("archive-wrap|tenant|" + tenantId, "utf8");
}

// Returns { version, body } so wrap() can stamp the right version byte:
// hybrid-KEM recipients use ARCH_WRAP_VERSION with a base64 envelope
// body; the tenant strategy uses ARCH_WRAP_VERSION_TENANT with a
// symmetric packed-ciphertext body.
function _encryptForRecipient(bytes, opts) {
  var r = opts.recipient;
  if (typeof r === "string") {
    if (r === "tenant") {
      var tenantKey = _tenantKey(opts.tenantId);
      var packed = bCrypto().encryptPacked(Buffer.from(bytes), tenantKey, _tenantAad(opts.tenantId));
      return { version: ARCH_WRAP_VERSION_TENANT, body: packed };
    }
    throw new ArchiveWrapError("archive-wrap/bad-recipient",
      "wrap: recipient string " + JSON.stringify(r) + " not recognised; the only string recipient is \"tenant\" (with opts.tenantId)");
  }
  if (r.peerCertDer || r.peerKemPubkey) {
    if (!r.peerCertDer || !r.peerKemPubkey) {
      throw new ArchiveWrapError("archive-wrap/bad-recipient",
        "wrap: peer-cert strategy requires BOTH peerCertDer + peerKemPubkey");
    }
    return {
      version: ARCH_WRAP_VERSION,
      body: Buffer.from(bCrypto().encryptEnvelopeAsCertPeer(bytes, {
        peerCertDer:    r.peerCertDer,
        peerKemPubkey:  r.peerKemPubkey,
      }), "utf-8"),
    };
  }
  if (r.publicKey) {
    // Codex P2 on v0.12.10 PR #161 — b.crypto.encrypt falls back to
    // ML-KEM-only when ecPublicKey is undefined (with a one-shot
    // audit). For archive-wrap's recipient contract the hybrid leg
    // (P-384 ECDH defence-in-depth backstop on top of ML-KEM-1024)
    // is the documented behaviour; refuse upfront so partial
    // recipient objects can't silently degrade the seal posture.
    // Operators who genuinely want KEM-only call
    // b.crypto.encryptMlkem768X25519 directly.
    if (!r.ecPublicKey) {
      throw new ArchiveWrapError("archive-wrap/hybrid-required",
        "wrap: static-key recipient requires BOTH publicKey (ML-KEM-1024 PEM) " +
        "and ecPublicKey (P-384 ECDH PEM). Partial recipients trip b.crypto.encrypt's " +
        "ML-KEM-only fallback which silently degrades the hybrid contract this primitive promises.");
    }
    return {
      version: ARCH_WRAP_VERSION,
      body: Buffer.from(bCrypto().encrypt(bytes, {
        publicKey:    r.publicKey,
        ecPublicKey:  r.ecPublicKey,
      }), "utf-8"),
    };
  }
  throw new ArchiveWrapError("archive-wrap/bad-recipient",
    "wrap: recipient must be { publicKey, ecPublicKey } | { peerCertDer, peerKemPubkey } | \"tenant\"");
}

function _isWrapMagic(buf) {
  return buf.length >= ARCH_WRAP_HEADER_BYTES &&
    buf.slice(0, 5).toString("ascii") === ARCH_WRAP_MAGIC;
}

function _isPassphraseMagic(buf) {
  return buf.length >= ARCH_PASSPHRASE_HEADER_BYTES &&
    buf.slice(0, 5).toString("ascii") === ARCH_PASSPHRASE_MAGIC;
}

/**
 * @primitive b.archive.sniffEnvelope
 * @signature b.archive.sniffEnvelope(bytes)
 * @since     0.12.14
 * @status    stable
 * @related   b.archive.wrap, b.archive.unwrap, b.archive.wrapWithPassphrase, b.archive.unwrapWithPassphrase
 *
 * Identify the envelope shape carried by a buffer without attempting
 * decryption. Returns one of:
 *   - `"recipient"` — `BAWRP` header (v0.12.10 hybrid PQC envelope).
 *     Operator routes through `b.archive.unwrap(bytes, { recipient })`.
 *   - `"passphrase"` — `BAWPP` header (v0.12.11 Argon2id + XChaCha20
 *     envelope). Operator routes through
 *     `b.archive.unwrapWithPassphrase(bytes, { passphrase })`.
 *   - `"none"` — no archive-wrap envelope magic. The bytes are
 *     either raw archive content (gz / tar / zip) or an unrelated
 *     payload; operator routes to the appropriate `b.archive.read.*`
 *     primitive (or refuses entirely).
 *
 * The sniff is byte 0-4 inspection ONLY — no cryptographic work,
 * no allocation beyond a 5-byte ASCII compare. Safe to call on
 * adversarial input.
 *
 * @example
 *   var kind = b.archive.sniffEnvelope(payloadBytes);
 *   switch (kind) {
 *     case "recipient":  return b.archive.unwrap(payloadBytes, { recipient });
 *     case "passphrase": return b.archive.unwrapWithPassphrase(payloadBytes, { passphrase });
 *     case "none":       return payloadBytes;
 *   }
 */
function sniffEnvelope(bytes) {
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) {
    return "none";
  }
  // Codex P2A on v0.12.14 PR #165 — `Buffer.from(uint8Array)` copies
  // the entire input, turning a constant-time 5-byte probe into an
  // O(n) allocation. Use the zero-copy view form so the sniff is
  // truly cheap regardless of input size.
  var buf = Buffer.isBuffer(bytes)
    ? bytes
    : Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (buf.length < 5) return "none";
  // Codex P2B on v0.12.14 PR #165 — match on the 5-byte ASCII magic
  // alone, NOT on the full header (which requires version + saltLen
  // bytes). A truncated envelope (`BAWRP` + nothing else) is still a
  // recipient envelope; the unwrap call surfaces the truncation with
  // a structured `archive-wrap/truncated-envelope` error. Returning
  // "none" on truncated input would misclassify damaged envelopes as
  // raw payload and the operator's dispatch switch would skip the
  // wrap error path entirely.
  var magic = buf.slice(0, 5).toString("ascii");
  if (magic === ARCH_WRAP_MAGIC) return "recipient";
  if (magic === ARCH_PASSPHRASE_MAGIC) return "passphrase";
  return "none";
}

/**
 * @primitive b.archive.wrapWithPassphrase
 * @signature b.archive.wrapWithPassphrase(bytes, opts)
 * @since     0.12.11
 * @status    stable
 * @related   b.archive.unwrapWithPassphrase, b.archive.wrap
 *
 * Wrap archive bytes in a passphrase-derived envelope. The envelope
 * wire format is the framework's standard Argon2id (RFC 9106) +
 * XChaCha20-Poly1305 AEAD with a fresh per-envelope salt prefixed in
 * a 7-byte `BAWPP` header (5-byte magic + 1-byte version + 1-byte
 * salt length). Operators choosing the passphrase strategy (vs the
 * recipient strategy from `b.archive.wrap`) reach for this primitive
 * when they don't want to manage KEM keypairs but do want
 * encryption-at-rest under operator-controlled material.
 *
 * @opts
 *   passphrase:           Buffer | string,   // required; >= minEntropyBits
 *   minEntropyBits:       number,            // default 80; HIPAA recipe sets 128
 *
 * @example
 *   var sealed = await b.archive.wrapWithPassphrase(tarBytes, {
 *     passphrase:     "operator-supplied-long-passphrase",
 *     minEntropyBits: 128,
 *   });
 */
async function wrapWithPassphrase(bytes, opts) {
  opts = opts || {};
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) {
    throw new ArchiveWrapError("archive-wrap/bad-input",
      "wrapWithPassphrase: bytes must be a Buffer or Uint8Array");
  }
  if (bytes.length === 0) {
    throw new ArchiveWrapError("archive-wrap/empty-input",
      "wrapWithPassphrase: bytes is empty");
  }
  if (typeof opts.passphrase !== "string" && !Buffer.isBuffer(opts.passphrase)) {
    throw new ArchiveWrapError("archive-wrap/no-passphrase",
      "wrapWithPassphrase: opts.passphrase is required (string or Buffer)");
  }
  var passLen = typeof opts.passphrase === "string"
    ? Buffer.byteLength(opts.passphrase, "utf-8")
    : opts.passphrase.length;
  // Entropy estimate — character-set-aware bit count via Shannon's
  // bound assuming uniform random selection over the observed
  // alphabet. Operators sourcing passphrases from a random-bytes
  // generator (high entropy density) pass without issue; operators
  // typing dictionary phrases trip the gate.
  // Codex P1 on v0.12.11 PR #162 — typeof NaN === "number" passes
  // typeof gate but bypasses downstream comparisons. Use isFinite
  // so NaN / Infinity can't slip past the entropy gate.
  var minEntropy;
  if (opts.minEntropyBits === undefined || opts.minEntropyBits === null) {
    minEntropy = 80;                                                                  // allow:raw-byte-literal — entropy-bits default, not byte count
  } else if (Number.isFinite(opts.minEntropyBits) && opts.minEntropyBits >= 0) {
    minEntropy = Math.floor(opts.minEntropyBits);
  } else {
    throw new ArchiveWrapError("archive-wrap/bad-arg",
      "wrapWithPassphrase: opts.minEntropyBits must be a finite non-negative number; got " +
      JSON.stringify(opts.minEntropyBits) + " (NaN / Infinity refused so the entropy gate can't be bypassed)");
  }
  var estimated = _estimatePassphraseEntropyBits(opts.passphrase);
  if (estimated < minEntropy) {
    throw new ArchiveWrapError("archive-wrap/weak-passphrase",
      "wrapWithPassphrase: passphrase estimated entropy " + estimated +
      " bits is below opts.minEntropyBits=" + minEntropy +
      " (length=" + passLen + " bytes). Strengthen the passphrase or lower the gate; " +
      "HIPAA recipe is 128+ bits.");
  }
  var fresh = await backupCrypto().encryptWithFreshSalt(bytes, opts.passphrase);
  var saltBytes = Buffer.from(fresh.salt, "hex");
  if (saltBytes.length > 0xff) {
    throw new ArchiveWrapError("archive-wrap/salt-too-long",
      "wrapWithPassphrase: salt length " + saltBytes.length +
      " exceeds 255-byte wire limit");
  }
  var header = Buffer.alloc(ARCH_PASSPHRASE_HEADER_BYTES);
  header.write(ARCH_PASSPHRASE_MAGIC, 0, 5, "ascii");
  header[5] = ARCH_PASSPHRASE_VERSION;
  header[6] = saltBytes.length;
  return Buffer.concat([header, saltBytes, fresh.encrypted]);
}

/**
 * @primitive b.archive.unwrapWithPassphrase
 * @signature b.archive.unwrapWithPassphrase(sealed, opts)
 * @since     0.12.11
 * @status    stable
 * @related   b.archive.wrapWithPassphrase
 *
 * Recover archive bytes from a passphrase-derived envelope produced
 * by `b.archive.wrapWithPassphrase`. Verifies the 7-byte `BAWPP`
 * header before attempting key derivation so non-envelope inputs
 * fail with `archive-wrap/bad-magic` rather than burning Argon2id
 * compute on bad bytes.
 *
 * @opts
 *   passphrase:  Buffer | string,   // required; same passphrase used at wrap-time
 *
 * @example
 *   var recovered = await b.archive.unwrapWithPassphrase(sealed, {
 *     passphrase: "operator-supplied-long-passphrase",
 *   });
 */
async function unwrapWithPassphrase(sealed, opts) {
  opts = opts || {};
  if (!Buffer.isBuffer(sealed) && !(sealed instanceof Uint8Array)) {
    throw new ArchiveWrapError("archive-wrap/bad-input",
      "unwrapWithPassphrase: sealed must be a Buffer or Uint8Array");
  }
  if (sealed.length < ARCH_PASSPHRASE_HEADER_BYTES) {
    throw new ArchiveWrapError("archive-wrap/bad-magic",
      "unwrapWithPassphrase: input shorter than 7-byte BAWPP header");
  }
  var buf = Buffer.isBuffer(sealed) ? sealed : Buffer.from(sealed);
  var magic = buf.slice(0, 5).toString("ascii");
  if (magic !== ARCH_PASSPHRASE_MAGIC) {
    throw new ArchiveWrapError("archive-wrap/bad-magic",
      "unwrapWithPassphrase: input does not start with passphrase-wrap magic " +
      JSON.stringify(ARCH_PASSPHRASE_MAGIC) + "; got " + JSON.stringify(magic));
  }
  var version = buf[5];
  if (version !== ARCH_PASSPHRASE_VERSION) {
    throw new ArchiveWrapError("archive-wrap/bad-version",
      "unwrapWithPassphrase: passphrase-wrap version " + version + " not supported");
  }
  if (typeof opts.passphrase !== "string" && !Buffer.isBuffer(opts.passphrase)) {
    throw new ArchiveWrapError("archive-wrap/no-passphrase",
      "unwrapWithPassphrase: opts.passphrase is required");
  }
  var saltLen = buf[6];
  if (sealed.length < ARCH_PASSPHRASE_HEADER_BYTES + saltLen) {
    throw new ArchiveWrapError("archive-wrap/truncated-envelope",
      "unwrapWithPassphrase: header claims " + saltLen + "-byte salt but only " +
      (sealed.length - ARCH_PASSPHRASE_HEADER_BYTES) + " bytes remain");
  }
  var saltHex = buf.slice(ARCH_PASSPHRASE_HEADER_BYTES,
    ARCH_PASSPHRASE_HEADER_BYTES + saltLen).toString("hex");
  var encrypted = buf.slice(ARCH_PASSPHRASE_HEADER_BYTES + saltLen);
  try {
    return await backupCrypto().decryptWithPassphrase(encrypted, opts.passphrase, saltHex);
  } catch (e) {
    var err = new ArchiveWrapError("archive-wrap/decrypt-failed",
      "unwrapWithPassphrase: decryption refused (wrong passphrase or tampered envelope): " +
      ((e && e.message) || String(e)));
    err.cause = e;
    throw err;
  }
}

function _estimatePassphraseEntropyBits(passphrase) {
  // Codex P2 on v0.12.11 PR #162 — Buffer passphrases (CSPRNG-
  // generated random bytes) shouldn't be UTF-8 decoded for entropy
  // estimation; the decoding artifacts (invalid sequences, BOM,
  // surrogate pairs) make the alphabet-class measure unstable and
  // falsely reject strong random buffers. Treat Buffer input as
  // raw bytes: observed-alphabet bit count over the byte values
  // gives a stable approximation that credits CSPRNG output
  // correctly (a 16-byte buffer with full byte variation scores
  // 16 * log2(16+) ≈ 64-128 bits) and refuses all-zero buffers
  // (alphabet=1, score 0).
  if (Buffer.isBuffer(passphrase)) {
    if (passphrase.length === 0) return 0;
    var seen = new Set();
    for (var bi = 0; bi < passphrase.length; bi += 1) {
      seen.add(passphrase[bi]);
    }
    var byteAlphabet = seen.size;
    if (byteAlphabet === 0) return 0;
    return Math.floor(passphrase.length * Math.log2(byteAlphabet));
  }
  var s = typeof passphrase === "string" ? passphrase : String(passphrase);
  if (s.length === 0) return 0;
  // String passphrases — operator-typed phrases. Observed character-
  // class alphabet count. log2(alphabetSize) bits per character is
  // the standard NIST/OWASP "estimate by character classes" measure.
  var hasLower = false, hasUpper = false, hasDigit = false, hasSpecial = false;
  for (var i = 0; i < s.length; i += 1) {
    var c = s.charCodeAt(i);
    if (c >= 0x61 && c <= 0x7a) hasLower = true;
    else if (c >= 0x41 && c <= 0x5a) hasUpper = true;
    else if (c >= 0x30 && c <= 0x39) hasDigit = true;
    else hasSpecial = true;
  }
  var alphabet = 0;
  if (hasLower) alphabet += 26;                                                       // allow:raw-byte-literal — alphabet-size term, not byte count
  if (hasUpper) alphabet += 26;                                                       // allow:raw-byte-literal — alphabet-size term, not byte count
  if (hasDigit) alphabet += 10;                                                       // allow:raw-byte-literal — alphabet-size term, not byte count
  if (hasSpecial) alphabet += 32;                                                     // allow:raw-byte-literal — alphabet-size term, not byte count
  if (alphabet === 0) return 0;
  return Math.floor(s.length * Math.log2(alphabet));
}

module.exports = {
  wrap:                  wrap,
  unwrap:                unwrap,
  wrapWithPassphrase:    wrapWithPassphrase,
  unwrapWithPassphrase:  unwrapWithPassphrase,
  sniffEnvelope:         sniffEnvelope,
  ArchiveWrapError:      ArchiveWrapError,
  // Exposed for sibling modules + sniffer
  _isWrapMagic:          _isWrapMagic,
  _isPassphraseMagic:    _isPassphraseMagic,
  ARCH_WRAP_MAGIC:       ARCH_WRAP_MAGIC,
  ARCH_PASSPHRASE_MAGIC: ARCH_PASSPHRASE_MAGIC,
};
