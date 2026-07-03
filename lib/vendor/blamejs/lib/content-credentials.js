// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.contentCredentials
 * @featured true
 * @nav    AI
 * @title  Content Credentials
 *
 * @intro
 *   C2PA 2.1 content provenance — sign assets with a manifest
 *   declaring origin, edits, AI involvement.
 *
 *   California SB-942 (Cal. Bus. & Prof. Code §22757) + AB-853,
 *   effective 2026-08-02, require generative-AI providers to embed a
 *   latent disclosure carrying provider name, system identifier,
 *   system version, content timestamp, and a unique content ID in
 *   every AI-generated image / video / audio asset distributed in
 *   California. SB-942 names C2PA as an acceptable format.
 *
 *   The framework can't push bytes into format-specific muxers (JPEG
 *   XMP / PNG iTXt / MP4 boxes vary per codec). What it does ship:
 *   build a C2PA-shaped manifest with the SB-942 required fields,
 *   sign it with the audit-sign keypair (ML-DSA-87 by default),
 *   record a tamper-evident audit row, and verify inbound manifests
 *   on the receive side. Operators hand the signed manifest to their
 *   format-specific embedder.
 *
 * @card
 *   C2PA 2.1 content provenance — sign assets with a manifest declaring origin, edits, AI involvement.
 */

var nodeCrypto = require("node:crypto");
var C = require("./constants");
var bCrypto = require("./crypto");
var x509Chain = require("./x509-chain");
var canonicalJson = require("./canonical-json");
var safeJson = require("./safe-json");
var validateOpts = require("./validate-opts");
var audit = require("./audit");
var tsa = require("./tsa");
var cbor = require("./cbor");
var redact = require("./redact");
var { defineClass } = require("./framework-error");
var ContentCredentialsError = defineClass("ContentCredentialsError", { alwaysPermanent: true });

var STR_LEN_MAX = 256;                                                                        // string-length cap, not bytes
var ID_LEN_MAX  = 128;                                                                        // string-length cap, not bytes
var SEMVER_RE = /^[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][A-Za-z0-9.-]+)?$/;
var ID_RE     = /^[a-zA-Z0-9._:/-]{1,128}$/;
var SHA3_HEX_LEN = 128;                                                                       // SHA3-512 hex length, not bytes
var C_PAYLOAD_MAX = C.BYTES.mib(1);                                                           // C2PA COSE payload / claims parse cap

// Required fields per SB-942 §22757(a) — every AI-generated asset
// must disclose provider + system + timestamp + contentId.
var REQUIRED_FIELDS = ["provider", "system", "systemVersion", "contentId"];

function _validateBuildOpts(opts) {
  if (!opts || typeof opts !== "object") {
    throw ContentCredentialsError.factory("content-credentials/bad-opts",
      "contentCredentials.build: opts required");
  }
  for (var i = 0; i < REQUIRED_FIELDS.length; i += 1) {
    var f = REQUIRED_FIELDS[i];
    validateOpts.requireNonEmptyString(opts[f],
      "contentCredentials.build: " + f, ContentCredentialsError, "MISSING_" + f.toUpperCase());
  }
  if (opts.provider.length > STR_LEN_MAX) {
    throw ContentCredentialsError.factory("content-credentials/bad-provider",
      "provider exceeds " + STR_LEN_MAX + " chars");
  }
  if (opts.system.length > ID_LEN_MAX || !ID_RE.test(opts.system)) {
    throw ContentCredentialsError.factory("content-credentials/bad-system",
      "system must match " + ID_RE);
  }
  if (opts.systemVersion.length > 64 || !SEMVER_RE.test(opts.systemVersion)) {                // semver length cap, not bytes
    throw ContentCredentialsError.factory("content-credentials/bad-version",
      "systemVersion must be semver");
  }
  if (opts.contentId.length > ID_LEN_MAX || !ID_RE.test(opts.contentId)) {
    throw ContentCredentialsError.factory("content-credentials/bad-content-id",
      "contentId must match " + ID_RE);
  }
  if (opts.contentType !== undefined) {
    if (typeof opts.contentType !== "string" || opts.contentType.length === 0 ||
        opts.contentType.length > ID_LEN_MAX || !/^[a-zA-Z]+\/[A-Za-z0-9._+-]+$/.test(opts.contentType)) {
      throw ContentCredentialsError.factory("content-credentials/bad-content-type",
        "contentType must be a valid IANA media type");
    }
  }
  if (opts.contentSha3 !== undefined) {
    if (typeof opts.contentSha3 !== "string" || opts.contentSha3.length !== SHA3_HEX_LEN ||
        !/^[a-f0-9]+$/i.test(opts.contentSha3)) {
      throw ContentCredentialsError.factory("content-credentials/bad-content-hash",
        "contentSha3 must be lowercase hex SHA3-512 (" + SHA3_HEX_LEN + " chars)");
    }
  }
}

/**
 * @primitive b.contentCredentials.build
 * @signature b.contentCredentials.build(opts)
 * @since     0.8.44
 * @related   b.contentCredentials.sign, b.contentCredentials.verify, b.contentCredentials.required
 *
 * Build an unsigned C2PA 2.1-shaped manifest carrying the SB-942
 * §22757(a) required fields (provider, system, system version,
 * content ID) plus optional content type, SHA3-512 digest, and a
 * visible-disclosure string. Returns a frozen object so downstream
 * code can't mutate the claims before signing. `generatedAt`
 * defaults to `Date.now()` so the manifest carries a real timestamp
 * unless the operator pins one for testing.
 *
 * @opts
 *   provider:          string,             // e.g. "Acme AI Inc."
 *   providerContact:   string,             // optional contact URL
 *   system:            string,             // model id, e.g. "acme-image-v3"
 *   systemVersion:     string,             // semver
 *   contentId:         string,             // unique per asset
 *   contentType:       string,             // IANA media type (optional)
 *   contentSha3:       string,             // SHA3-512 hex (optional)
 *   generatedAt:       number,             // ms epoch (optional)
 *   visibleDisclosure: string,             // operator display text (optional)
 *
 * @example
 *   var manifest = b.contentCredentials.build({
 *     provider:      "Acme AI Inc.",
 *     system:        "acme-image-v3",
 *     systemVersion: "3.2.1",
 *     contentId:     "img-2026-05-08-abc123",
 *     contentType:   "image/png",
 *     generatedAt:   Date.UTC(2026, 4, 8),
 *   });
 *   manifest.aiGenerated;        // → true
 *   manifest.system.id;          // → "acme-image-v3"
 *   manifest.content.id;         // → "img-2026-05-08-abc123"
 */
function build(opts) {
  _validateBuildOpts(opts);
  var generatedAt = typeof opts.generatedAt === "number" ? opts.generatedAt : Date.now();
  var manifest = {
    "@context":   "https://c2pa.org/specifications/specifications/2.1/",
    type:         "c2pa.manifest",
    aiGenerated:  true,
    provider: {
      name:    opts.provider,
      contact: opts.providerContact || null,
    },
    system: {
      id:      opts.system,
      version: opts.systemVersion,
    },
    content: {
      id:           opts.contentId,
      type:         opts.contentType || null,
      sha3_512:     opts.contentSha3 || null,
    },
    generatedAt:    generatedAt,
    generatedAtIso: new Date(generatedAt).toISOString(),
    citations:      ["california-sb-942", "california-ab-853", "c2pa-2.1"],
    // Optional operator-supplied display assertion (SB-942 §22757(b))
    visibleDisclosure: opts.visibleDisclosure || null,
  };
  return Object.freeze(manifest);
}

/**
 * @primitive b.contentCredentials.required
 * @signature b.contentCredentials.required(opts)
 * @since     0.8.44
 * @related   b.contentCredentials.build, b.contentCredentials.verify
 *
 * Pre-flight check that returns the list of SB-942 §22757(a) fields
 * missing from a candidate input — useful for operator UIs that
 * surface "what's needed before we can disclose" without round-
 * tripping through `build` and catching the throw. Returns `[]`
 * when every required field is present and non-empty.
 *
 * @opts
 *   provider:      string,                 // required
 *   system:        string,                 // required
 *   systemVersion: string,                 // required
 *   contentId:     string,                 // required
 *
 * @example
 *   b.contentCredentials.required({
 *     provider:      "Acme AI Inc.",
 *     system:        "acme-image-v3",
 *     systemVersion: "3.2.1",
 *     contentId:     "img-001",
 *   });
 *   // → []
 *
 *   b.contentCredentials.required({ provider: "Acme AI Inc." });
 *   // → ["missing-system", "missing-systemVersion", "missing-contentId"]
 */
function required(opts) {
  var errors = [];
  if (!opts || typeof opts !== "object") return ["opts-required"];
  for (var i = 0; i < REQUIRED_FIELDS.length; i += 1) {
    if (typeof opts[REQUIRED_FIELDS[i]] !== "string" || opts[REQUIRED_FIELDS[i]].length === 0) {
      errors.push("missing-" + REQUIRED_FIELDS[i]);
    }
  }
  return errors;
}

/**
 * @primitive b.contentCredentials.sign
 * @signature b.contentCredentials.sign(manifest, opts)
 * @since     0.8.44
 * @related   b.contentCredentials.build, b.contentCredentials.verify, b.crypto.sign
 *
 * Canonicalize the manifest (RFC 8785 JCS via `b.canonicalJson`) and
 * sign it with `b.crypto.sign` using the operator's private-key PEM
 * — typically the ML-DSA-87 audit-sign keypair. Returns an envelope
 * with the original manifest plus the base64-encoded signature.
 * Audits the disclosure under `contentcredentials.signed` unless the
 * caller passes `audit:false`.
 *
 * @opts
 *   privateKeyPem: string,                 // PEM-encoded signing key
 *   audit:         boolean,                // default true
 *
 * @example
 *   var pair = b.crypto.generateSigningKeyPair("ml-dsa-87");
 *   var manifest = b.contentCredentials.build({
 *     provider:      "Acme AI Inc.",
 *     system:        "acme-image-v3",
 *     systemVersion: "3.2.1",
 *     contentId:     "img-2026-05-08-abc123",
 *   });
 *   var envelope = b.contentCredentials.sign(manifest, {
 *     privateKeyPem: pair.privateKey,
 *   });
 *   typeof envelope.signature;   // → "string"
 */
function sign(manifest, opts) {
  opts = opts || {};
  if (!manifest || typeof manifest !== "object") {
    throw ContentCredentialsError.factory("content-credentials/bad-manifest",
      "contentCredentials.sign: manifest required");
  }
  validateOpts.requireNonEmptyString(opts.privateKeyPem,
    "contentCredentials.sign: privateKeyPem", ContentCredentialsError, "BAD_KEY");
  var canonical = canonicalJson.stringify(manifest);
  var signature = bCrypto.sign(Buffer.from(canonical, "utf8"), opts.privateKeyPem);
  var auditOn = opts.audit !== false;
  if (auditOn) {
    audit.safeEmit({
      action:   "contentcredentials.signed",
      outcome:  "success",
      metadata: {
        provider:   manifest.provider && manifest.provider.name,
        system:     manifest.system   && manifest.system.id,
        contentId:  manifest.content  && manifest.content.id,
      },
    });
  }
  return {
    manifest:  manifest,
    signature: signature.toString("base64"),
  };
}

/**
 * @primitive b.contentCredentials.verify
 * @signature b.contentCredentials.verify(envelope, publicKeyPem, opts)
 * @since     0.8.44
 * @related   b.contentCredentials.sign, b.contentCredentials.build, b.crypto.verify
 *
 * Verify a signed envelope produced by `sign`. Re-canonicalizes the
 * manifest, checks the signature with `b.crypto.verify` against the
 * operator-supplied public-key PEM, and re-runs the SB-942 required-
 * field presence check on the verified claims so a manifest with a
 * valid signature but missing fields fails closed. Never throws —
 * returns `{ valid, claims, reason }`. Audits successful
 * verifications under `contentcredentials.verified` unless
 * `audit:false`.
 *
 * @opts
 *   audit: boolean,                        // default true
 *
 * @example
 *   var pair = b.crypto.generateSigningKeyPair("ml-dsa-87");
 *   var manifest = b.contentCredentials.build({
 *     provider:      "Acme AI Inc.",
 *     system:        "acme-image-v3",
 *     systemVersion: "3.2.1",
 *     contentId:     "img-001",
 *   });
 *   var envelope = b.contentCredentials.sign(manifest, {
 *     privateKeyPem: pair.privateKey,
 *   });
 *   var result = b.contentCredentials.verify(envelope, pair.publicKey);
 *   result.valid;   // → true
 */
function verify(envelope, publicKeyPem, opts) {
  opts = opts || {};
  if (!envelope || typeof envelope !== "object" || !envelope.manifest || !envelope.signature) {
    return { valid: false, claims: null, reason: "envelope-shape" };
  }
  if (typeof publicKeyPem !== "string" || publicKeyPem.length === 0) {
    return { valid: false, claims: null, reason: "public-key-required" };
  }
  var canonical = canonicalJson.stringify(envelope.manifest);
  var sigBuf;
  try { sigBuf = Buffer.from(envelope.signature, "base64"); }
  catch (_e) {
    return { valid: false, claims: null, reason: "signature-base64-bad" };
  }
  var ok = bCrypto.verify(Buffer.from(canonical, "utf8"), sigBuf, publicKeyPem);
  if (!ok) {
    return { valid: false, claims: null, reason: "signature-mismatch" };
  }
  // SB-942 §22757(a) field-presence check on the verified manifest.
  var missing = required({
    provider:      envelope.manifest.provider && envelope.manifest.provider.name,
    system:        envelope.manifest.system   && envelope.manifest.system.id,
    systemVersion: envelope.manifest.system   && envelope.manifest.system.version,
    contentId:     envelope.manifest.content  && envelope.manifest.content.id,
  });
  if (missing.length > 0) {
    return { valid: false, claims: null, reason: "missing-required:" + missing.join(",") };
  }
  if (opts.audit !== false) {
    audit.safeEmit({
      action:   "contentcredentials.verified",
      outcome:  "success",
      metadata: {
        provider:   envelope.manifest.provider.name,
        system:     envelope.manifest.system.id,
        contentId:  envelope.manifest.content.id,
      },
    });
  }
  return { valid: true, claims: envelope.manifest, reason: null };
}

// ---- C2PA 2.x COSE_Sign1 interop wrapper -------------------------
//
// Framework's `sign()` produces a JCS-canonicalized + ML-DSA-87/SLH-DSA
// signature shape — fine for blamejs-internal verifiers but does NOT
// interop with the c2patool / JPEG Trust / Adobe verifiers, which
// expect COSE_Sign1 (RFC 9052) per C2PA spec §11.
//
// `signCose` wraps the same manifest payload in a minimal COSE_Sign1
// CBOR structure with:
//   - protected header { 1: alg }  (RFC 9052 §3.1)
//   - unprotected header { 33: x5chain } if certChain supplied
//   - payload: the JCS-canonicalized manifest bytes
//   - signature: the ML-DSA-87 / Ed25519 signature
//
// The CBOR is hand-encoded — keeps the framework's "zero npm runtime
// deps" rule intact. Verifiers consume the bytes via standard COSE
// libraries (jose-py / c2pa-rs / etc.).

// COSE algorithm registry codepoints (RFC 9053 §2.1 + draft-ietf-cose-* for PQ).
// IANA registry IDs, not byte counts.
var COSE_ALGS = {
  "ed25519":    -8,    // COSE alg id
  "es256":      -7,    // COSE alg id
  "es384":      -35,   // COSE alg id
  "es512":      -36,   // COSE alg id
  "ml-dsa-44":  -48,   // COSE alg id (draft)
  "ml-dsa-65":  -49,   // COSE alg id (draft)
  "ml-dsa-87":  -50,   // COSE alg id (draft)
  "slh-dsa-sha2-128s":   -51,   // COSE alg id (draft)
  "slh-dsa-shake-256f":  -56,   // COSE alg id (draft)
};

// CBOR encoder (RFC 8949 §3). The integer thresholds 24/256/65536/4294967296
// are CBOR-spec length-encoding boundaries — not byte counts.
// CBOR encoding thresholds, not byte counts.
function _cborUint(n) {
  if (n < 24)         return Buffer.from([n]);                                                                                                // CBOR threshold
  if (n < 256)        return Buffer.from([0x18, n]);                                                                                          // CBOR threshold
  if (n < 65536)      return Buffer.from([0x19, (n >> 8) & 0xFF, n & 0xFF]);                                                                  // CBOR threshold
  if (n < 4294967296) return Buffer.from([0x1A, (n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]);                              // CBOR threshold
  throw ContentCredentialsError.factory("content-credentials/cbor-overflow", "cbor uint too large: " + n);
}

function _cborNint(n) {
  var v = -1 - n;
  if (v < 24)    return Buffer.from([0x20 | v]);                                                                                              // CBOR threshold
  if (v < 256)   return Buffer.from([0x38, v]);                                                                                               // CBOR threshold
  if (v < 65536) return Buffer.from([0x39, (v >> 8) & 0xFF, v & 0xFF]);                                                                       // CBOR threshold
  return Buffer.from([0x3A, (v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF]);
}

function _cborInt(n) {
  return n >= 0 ? _cborUint(n) : _cborNint(n);
}

function _cborBytes(buf) {
  var n = buf.length;
  var head;
  if (n < 24)         head = Buffer.from([0x40 | n]);                                                                                          // CBOR threshold
  else if (n < 256)   head = Buffer.from([0x58, n]);                                                                                           // CBOR threshold
  else if (n < 65536) head = Buffer.from([0x59, (n >> 8) & 0xFF, n & 0xFF]);                                                                   // CBOR threshold
  else                head = Buffer.from([0x5A, (n >>> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]);
  return Buffer.concat([head, buf]);
}

function _cborArrayHeader(n) {
  if (n < 24)    return Buffer.from([0x80 | n]);                                                                                               // CBOR threshold
  if (n < 256)   return Buffer.from([0x98, n]);                                                                                                // CBOR threshold
  if (n < 65536) return Buffer.from([0x99, (n >> 8) & 0xFF, n & 0xFF]);                                                                        // CBOR threshold
  throw ContentCredentialsError.factory("content-credentials/cbor-overflow", "cbor array too large: " + n);
}

function _cborMapHeader(n) {
  if (n < 24)    return Buffer.from([0xA0 | n]);                                                                                               // CBOR threshold
  if (n < 256)   return Buffer.from([0xB8, n]);                                                                                                // CBOR threshold
  throw ContentCredentialsError.factory("content-credentials/cbor-overflow", "cbor map too large: " + n);
}

function _cborTag(tag) {
  if (tag < 24)         return Buffer.from([0xC0 | tag]);                                                                                      // CBOR threshold
  if (tag < 256)        return Buffer.from([0xD8, tag]);                                                                                       // CBOR threshold
  if (tag < 65536)      return Buffer.from([0xD9, (tag >> 8) & 0xFF, tag & 0xFF]);                                                             // CBOR threshold
  return Buffer.from([0xDA, (tag >> 24) & 0xFF, (tag >> 16) & 0xFF, (tag >> 8) & 0xFF, tag & 0xFF]);
}

// COSE unprotected-header labels carried on the COSE_Sign1 (IANA COSE
// header-parameter codepoints, RFC 9360 / RFC 9921 — integer labels,
// not durations or byte counts).
var HDR_X5CHAIN = 33;                                       // x5chain (IANA COSE codepoint; see block comment above)
var HDR_SIG_TST2 = 35;                                      // C2PA sigTst2 timestamp container (IANA COSE codepoint)

// C2PA COSE CounterSignature context string (RFC 9921 / C2PA 2.x
// Technical Spec §"Time-stamps"): the Sig_structure-shaped ToBeSigned a
// timestamp imprint is computed over is prefixed with this context so a
// countersignature cannot be confused with a primary COSE_Sign1.
var COUNTERSIGNATURE_CONTEXT = "CounterSignature";

// The countersignature imprint hash. Mirrored on BOTH the sign side
// (the digest handed to tsa.buildRequest as a pre-hashed imprint) and
// the verify side (handed to tsa.verifyToken as opts.hash) so the two
// imprint computations cannot drift. SHA-512 default; SHA-384 / 512 +
// SHA3 allowed via tsa.IMPRINT_HASHES; SHA-1 / MD5 are absent there.
var DEFAULT_TST_HASH = "SHA-512";

function _resolveTstHashAlg(hashAlg, fnName) {
  var name = hashAlg || DEFAULT_TST_HASH;
  // Reuse the TSA module's imprint-hash allowlist — never re-derive the
  // permitted set here (a second list would be the drift the project's
  // single-source-of-truth rule forbids).
  if (!Object.prototype.hasOwnProperty.call(tsa.IMPRINT_HASHES, name)) {
    throw ContentCredentialsError.factory("content-credentials/bad-tst-hash",
      fnName + ": timestamp.hashAlg must be one of " +
      Object.keys(tsa.IMPRINT_HASHES).join(" / "));
  }
  return name;
}

// Build the C2PA COSE CounterSignature ToBeSigned (RFC 9921 / C2PA 2.x):
//   [ "CounterSignature",
//     body_protected   (= the COSE_Sign1 protected-header bstr),
//     sign_protected    (= empty bstr — no per-countersignature header),
//     external_aad      (= empty bstr),
//     payload           (= the COSE_Sign1 payload bstr),
//     other             (= the COSE_Sign1 signature bytes) ]
// CBOR-encoded locally with the same primitives the COSE_Sign1 uses, so
// the bytes the imprint covers are exactly the signed structure — never
// a chain-only or signature-only shortcut.
function _counterSignatureToBeSigned(protectedBstr, payloadBstr, sigBytes) {
  var ctxBytes = Buffer.from(COUNTERSIGNATURE_CONTEXT, "utf8");
  var ctxBstr;
  if (ctxBytes.length < 24) ctxBstr = Buffer.concat([Buffer.from([0x60 | ctxBytes.length]), ctxBytes]);   // CBOR text-string threshold
  else                      ctxBstr = Buffer.concat([Buffer.from([0x78, ctxBytes.length]), ctxBytes]);
  return Buffer.concat([
    _cborArrayHeader(6),
    ctxBstr,                              // "CounterSignature"
    protectedBstr,                        // body_protected (already a bstr)
    _cborBytes(Buffer.alloc(0)),          // sign_protected (empty)
    _cborBytes(Buffer.alloc(0)),          // external_aad (empty)
    payloadBstr,                          // payload (already a bstr)
    _cborBytes(sigBytes),                 // other (the COSE_Sign1 signature)
  ]);
}

/**
 * @primitive b.contentCredentials.signCose
 * @signature b.contentCredentials.signCose(manifest, opts)
 * @since     0.8.77
 * @status    stable
 * @compliance soc2
 * @related   b.contentCredentials.sign, b.contentCredentials.verifyCose, b.tsa.buildRequest, b.tsa.verifyToken, b.cose.sign
 *
 * C2PA 2.x interop sign — wraps the manifest in a COSE_Sign1 CBOR
 * envelope (RFC 9052) so the result interops with c2patool / JPEG
 * Trust / Adobe / external C2PA verifiers. The simpler `sign()`
 * primitive ships a blamejs-internal envelope shape; this one ships
 * COSE bytes.
 *
 * An RFC 3161 timestamp countersignature (`sigTst2`, RFC 9921 / C2PA 2.x
 * Technical Spec) is attached when an `opts.timestamp` context is
 * present, proving the manifest was signed before the timestamp
 * authority's asserted time. The countersignature imprint is computed
 * over the CounterSignature ToBeSigned — `[ "CounterSignature",
 * body_protected, sign_protected (empty), external_aad (empty), payload,
 * other (= the COSE_Sign1 signature) ]` — hashed with `timestamp.hashAlg`
 * (default SHA-512; the allowed set is `b.tsa.IMPRINT_HASHES`), and the
 * digest is handed to `b.tsa.buildRequest` as a PRE-HASHED imprint
 * (`{ hashed: true, hashAlg }`). Two modes: pass `timestamp.token` (a DER
 * TimeStampToken already obtained from a TSA) to attach it directly, or
 * omit it to get back a `timestampRequest` (the DER bytes to POST as
 * `application/timestamp-query`, the nonce to keep, and the
 * ToBeSigned imprint) so the operator can fetch a token and re-call with
 * it. Once attached, the token sits under COSE unprotected-header label
 * 35 (`sigTst2`) alongside the x5chain (label 33).
 *
 * Timestamping is fail-closed: when no TSA context is supplied the call
 * does NOT silently emit an un-timestamped signature — set
 * `timestamp: false` with `timestampOptOutReason` to record an audited,
 * deliberate opt-out. An un-timestamped C2PA claim is vulnerable to the
 * key-compromise backdating class
 * ([CVE-2025-52556](https://nvd.nist.gov/vuln/detail/CVE-2025-52556),
 * timestamp-validation bypass) — opting out is an operator decision, not
 * a default.
 *
 * Returns `{ manifest, coseSign1: Buffer, alg, timestamped, timestampRequest? }`.
 * Operators embed the `coseSign1` Buffer in the image's C2PA box (JPEG XT
 * marker, PNG iTXt chunk, MP4 'jumb' box per C2PA §13).
 *
 * @opts
 *   {
 *     privateKeyPem: string,            // required
 *     alg?:          "ed25519" | "es256" | "es384" | "es512" |
 *                    "ml-dsa-44" | "ml-dsa-65" | "ml-dsa-87" |
 *                    "slh-dsa-shake-256f",   // default "ml-dsa-87"
 *     certChain?:    Buffer[],          // X.509 DER buffers; emitted as x5chain (header label 33)
 *     timestamp?:    {                  // RFC 3161 sigTst2 countersignature (default ON when present)
 *       token?:           Buffer,       //   a DER TimeStampToken to attach (mode a)
 *       signature?:       string,       //   the base64 the request call returned — pins the
 *                                       //   randomized COSE signature so the imprint matches
 *       trustAnchorsPem?: string|string[], // anchors echoed for later verifyCose
 *       hashAlg?:         string,       //   default "SHA-512"; one of b.tsa.IMPRINT_HASHES
 *     } | false,                        // false = explicit opt-out (requires timestampOptOutReason)
 *     timestampOptOutReason?: string,   // required when timestamp:false — audited
 *     audit?:        boolean,           // default true
 *   }
 *
 * @example
 *   var pair = b.crypto.generateSigningKeyPair("ml-dsa-87");
 *   var manifest = b.contentCredentials.build({
 *     provider: "Acme AI", system: "acme-v3",
 *     systemVersion: "3.2.1", contentId: "img-001",
 *   });
 *   // Request-builder mode: get the TSA query bytes to POST.
 *   var req = b.contentCredentials.signCose(manifest, {
 *     privateKeyPem: pair.privateKey, alg: "ml-dsa-87", timestamp: {},
 *   });
 *   // POST req.timestampRequest.der to the TSA, then re-call, re-supplying
 *   // the same signature so the countersigned imprint still matches:
 *   var cose = b.contentCredentials.signCose(manifest, {
 *     privateKeyPem: pair.privateKey, alg: "ml-dsa-87",
 *     timestamp: { token: tsaTokenDer, signature: req.timestampRequest.signature },
 *   });
 *   // cose.coseSign1 is the CBOR bytes to embed in the image's C2PA box.
 */
function signCose(manifest, opts) {
  opts = opts || {};
  if (!manifest || typeof manifest !== "object") {
    throw ContentCredentialsError.factory("content-credentials/bad-manifest",
      "contentCredentials.signCose: manifest required");
  }
  validateOpts.requireNonEmptyString(opts.privateKeyPem,
    "contentCredentials.signCose: privateKeyPem", ContentCredentialsError, "BAD_KEY");
  var algName = (opts.alg || "ml-dsa-87").toLowerCase();
  if (!(algName in COSE_ALGS)) {
    throw ContentCredentialsError.factory("content-credentials/bad-alg",
      "contentCredentials.signCose: alg '" + algName +
      "' not in COSE alg registry. Known: " + Object.keys(COSE_ALGS).join(", "));
  }
  var algId = COSE_ALGS[algName];

  // Timestamp posture is resolved up front so the fail-closed contract
  // is decided before any signing work. Three states:
  //   - timestamp object present  → countersign (attach or request).
  //   - timestamp:false           → explicit opt-out (reason required).
  //   - timestamp absent          → fail-closed: refuse to silently emit
  //                                 an un-timestamped C2PA signature.
  var tsState = _resolveTimestampPosture(opts, "contentCredentials.signCose");

  // Protected header: map { 1: alg }
  var protBytes = Buffer.concat([
    _cborMapHeader(1),
    _cborInt(1),               // key: 1 (alg)
    _cborInt(algId),           // value: COSE alg id
  ]);
  var protectedBstr = _cborBytes(protBytes);

  // Payload — canonicalized manifest bytes.
  var canonicalPayload = Buffer.from(canonicalJson.stringify(manifest), "utf8");
  var payloadBstr      = _cborBytes(canonicalPayload);

  // Sig_structure per RFC 9052 §4.4: ["Signature1", protected, external_aad="", payload]
  var sigStructureBufs = [
    _cborArrayHeader(4),
    null,                                              // "Signature1" text string — filled in below
    protectedBstr,
    _cborBytes(Buffer.alloc(0)),                       // external_aad (empty)
    payloadBstr,
  ];
  // First entry is the text string "Signature1" — major-type 3
  var sigText = Buffer.from("Signature1", "utf8");
  var sigTextBstr;
  if (sigText.length < 24)      sigTextBstr = Buffer.concat([Buffer.from([0x60 | sigText.length]), sigText]);                                 // CBOR text-string threshold
  else                          sigTextBstr = Buffer.concat([Buffer.from([0x78, sigText.length]), sigText]);
  sigStructureBufs[1] = sigTextBstr;
  var toBeSigned = Buffer.concat(sigStructureBufs);

  // The COSE_Sign1 signature. ML-DSA / SLH-DSA signatures are
  // RANDOMIZED, so re-signing produces different bytes — and the
  // sigTst2 countersignature binds the EXACT signature bytes. In the
  // two-call request→attach flow the operator must therefore re-supply
  // the same signature (`timestamp.signature`, the base64 the request
  // call returned); when present it is decoded and verified to match
  // this key before reuse, so a stale or foreign signature is refused.
  var signature;
  if (tsState.mode === "attach" && tsState.reuseSignature != null) {
    var reused;
    try { reused = Buffer.from(tsState.reuseSignature, "base64"); }
    catch (_eReuse) {
      throw ContentCredentialsError.factory("content-credentials/bad-reuse-signature",
        "contentCredentials.signCose: timestamp.signature must be base64");
    }
    // The reused signature MUST verify against this manifest under this
    // key — otherwise the embedded signature and the countersigned
    // imprint would not correspond to the bytes actually signed.
    if (!_publicKeyFromPrivatePem(opts.privateKeyPem, reused, toBeSigned)) {
      throw ContentCredentialsError.factory("content-credentials/reuse-signature-mismatch",
        "contentCredentials.signCose: timestamp.signature does not verify against this manifest + key");
    }
    signature = reused;
  } else {
    // Sign with framework's b.crypto.sign — algorithm picked from the PEM.
    signature = bCrypto.sign(toBeSigned, opts.privateKeyPem);
  }

  // Request-builder mode: when a countersignature was asked for but no
  // token was supplied, compute the CounterSignature ToBeSigned, hash it
  // as the RFC 3161 imprint, and hand the PRE-HASHED digest to
  // b.tsa.buildRequest. The operator POSTs the returned der, obtains a
  // token, and re-calls signCose with timestamp.token + timestamp.signature
  // set (the latter pins the same randomized signature). No token is
  // fabricated here, so no timestamped signature is emitted yet.
  var timestampRequest = null;
  if (tsState.mode === "request") {
    var reqTbs = _counterSignatureToBeSigned(protectedBstr, payloadBstr, signature);
    var reqDigest = nodeCrypto
      .createHash(tsa.IMPRINT_HASHES[tsState.hashAlg].nodeHash).update(reqTbs).digest();
    // tsa.buildRequest opt shape (mirror of the verify side below):
    //   { hashed: true, hashAlg: <tsState.hashAlg> } — the digest is the imprint.
    var built = tsa.buildRequest(reqDigest, { hashed: true, hashAlg: tsState.hashAlg });
    timestampRequest = {
      der:           built.der,
      nonce:         built.nonce,
      hashAlg:       tsState.hashAlg,
      toBeSigned:    reqTbs,
      messageImprint: built.messageImprint,
      // The exact (randomized) signature this request was built over —
      // re-supply as timestamp.signature on the follow-up attach call.
      signature:     signature.toString("base64"),
    };
  }

  // Unprotected header: a CBOR map carrying x5chain (label 33) when a
  // cert chain is supplied AND the sigTst2 timestamp container (label
  // 35) when a token was attached.
  var unprotEntries = [];
  if (Array.isArray(opts.certChain) && opts.certChain.length > 0) {
    var chainArray;
    if (opts.certChain.length === 1) {
      // Single-cert form: header value is the DER bytes directly.
      chainArray = _cborBytes(opts.certChain[0]);
    } else {
      var chainBufs = [_cborArrayHeader(opts.certChain.length)];
      opts.certChain.forEach(function (der) { chainBufs.push(_cborBytes(der)); });
      chainArray = Buffer.concat(chainBufs);
    }
    unprotEntries.push({ label: HDR_X5CHAIN, value: chainArray });
  }
  if (tsState.mode === "attach") {
    // sigTst2 tstContainer: a single TimeStampToken bstr under label 35.
    unprotEntries.push({ label: HDR_SIG_TST2, value: _cborBytes(tsState.token) });
  }
  var unprotBufs = [_cborMapHeader(unprotEntries.length)];
  for (var ue = 0; ue < unprotEntries.length; ue += 1) {
    unprotBufs.push(_cborInt(unprotEntries[ue].label));
    unprotBufs.push(unprotEntries[ue].value);
  }
  var unprotectedHdr = Buffer.concat(unprotBufs);

  // COSE_Sign1 = tagged-18 array [protected, unprotected, payload, signature]
  var coseSign1 = Buffer.concat([
    _cborTag(18),                                      // CBOR tag 18 = COSE_Sign1
    _cborArrayHeader(4),
    protectedBstr,
    unprotectedHdr,
    payloadBstr,
    _cborBytes(signature),
  ]);

  if (opts.audit !== false) {
    audit.safeEmit({
      action:   "contentcredentials.signed_cose",
      outcome:  tsState.mode === "optout" ? "warning" : "success",
      metadata: {
        provider:    manifest.provider && manifest.provider.name,
        system:      manifest.system   && manifest.system.id,
        contentId:   manifest.content  && manifest.content.id,
        alg:         algName,
        bytes:       coseSign1.length,
        timestamped: tsState.mode === "attach",
        timestampMode: tsState.mode,
        timestampOptOutReason: tsState.mode === "optout" ? tsState.reason : undefined,
      },
    });
  }

  return {
    manifest:        manifest,
    coseSign1:       coseSign1,
    alg:             algName,
    timestamped:     tsState.mode === "attach",
    timestampRequest: timestampRequest,
  };
}

// Resolve the timestamp posture for signCose. THROWS (config-time tier)
// on a missing-or-malformed timestamp opt — an un-timestamped C2PA
// signature is a deliberate, audited operator decision, never a silent
// default. Returns one of:
//   { mode: "attach",  token, hashAlg }   — a TimeStampToken to embed
//   { mode: "request", hashAlg }          — build a TSA query for later
//   { mode: "optout",  reason }           — explicit, reasoned opt-out
function _resolveTimestampPosture(opts, fnName) {
  if (opts.timestamp === false) {
    // Explicit opt-out — require a recorded reason so the audit row
    // explains why this C2PA claim carries no trusted time.
    validateOpts.requireNonEmptyString(opts.timestampOptOutReason,
      fnName + ": timestampOptOutReason (required when timestamp:false)",
      ContentCredentialsError, "TIMESTAMP_OPT_OUT_NO_REASON");
    return { mode: "optout", reason: opts.timestampOptOutReason };
  }
  if (opts.timestamp === undefined || opts.timestamp === null) {
    throw ContentCredentialsError.factory("content-credentials/timestamp-required",
      fnName + ": an RFC 3161 timestamp (sigTst2) is required — pass opts.timestamp " +
      "({ token } to attach, or {} to get a TSA request) or opt out explicitly with " +
      "timestamp:false + timestampOptOutReason. An un-timestamped C2PA claim is " +
      "vulnerable to the key-compromise backdating class (CVE-2025-52556).");
  }
  if (typeof opts.timestamp !== "object" || Array.isArray(opts.timestamp)) {
    throw ContentCredentialsError.factory("content-credentials/bad-timestamp",
      fnName + ": opts.timestamp must be an object ({ token?, trustAnchorsPem?, hashAlg? }) or false");
  }
  validateOpts(opts.timestamp, ["token", "trustAnchorsPem", "hashAlg", "signature"], fnName + ".timestamp");
  var hashAlg = _resolveTstHashAlg(opts.timestamp.hashAlg, fnName);
  if (opts.timestamp.token !== undefined && opts.timestamp.token !== null) {
    if (!Buffer.isBuffer(opts.timestamp.token)) {
      throw ContentCredentialsError.factory("content-credentials/bad-timestamp-token",
        fnName + ": timestamp.token must be a DER TimeStampToken Buffer");
    }
    var reuse = null;
    if (opts.timestamp.signature !== undefined && opts.timestamp.signature !== null) {
      if (typeof opts.timestamp.signature !== "string" || opts.timestamp.signature.length === 0) {
        throw ContentCredentialsError.factory("content-credentials/bad-reuse-signature",
          fnName + ": timestamp.signature must be the base64 signature the request call returned");
      }
      reuse = opts.timestamp.signature;
    }
    return { mode: "attach", token: opts.timestamp.token, hashAlg: hashAlg, reuseSignature: reuse };
  }
  return { mode: "request", hashAlg: hashAlg };
}

// Verify a candidate signature over `data` using the public half of the
// supplied private-key PEM — used to confirm a reused (randomized) COSE
// signature was produced by this key over this manifest before it is
// re-embedded. Returns true/false, never throws.
function _publicKeyFromPrivatePem(privateKeyPem, signature, data) {
  try {
    var pubPem = nodeCrypto.createPublicKey(privateKeyPem)
      .export({ type: "spki", format: "pem" });
    return bCrypto.verify(data, signature, pubPem);
  } catch (_e) {
    return false;
  }
}

// Decode a COSE_Sign1 (tagged-18 or bare 4-element array) through the
// bounded b.cbor decoder. Returns { protectedBstr, unprotected (Map),
// payload (Buffer), signature (Buffer) } or throws a ContentCredentials
// error describing the malformed shape.
function _decodeCoseSign1(coseSign1) {
  var decoded;
  try {
    decoded = cbor.decode(coseSign1, { allowedTags: [18] });   // COSE_Sign1 CBOR tag
  } catch (e) {
    throw ContentCredentialsError.factory("content-credentials/cose-malformed",
      "verifyCose: not decodable CBOR: " + ((e && e.message) || e));
  }
  var arr = (decoded instanceof cbor.Tag && decoded.tag === 18) ? decoded.value : decoded;
  if (!Array.isArray(arr) || arr.length !== 4) {
    throw ContentCredentialsError.factory("content-credentials/cose-malformed",
      "verifyCose: not a COSE_Sign1 (expected a 4-element array)");
  }
  if (!Buffer.isBuffer(arr[0]) || !Buffer.isBuffer(arr[2]) || !Buffer.isBuffer(arr[3])) {
    throw ContentCredentialsError.factory("content-credentials/cose-malformed",
      "verifyCose: protected header, payload, and signature must be byte strings");
  }
  if (!(arr[1] instanceof Map)) {
    throw ContentCredentialsError.factory("content-credentials/cose-malformed",
      "verifyCose: unprotected header must be a CBOR map");
  }
  return { protectedBstr: arr[0], unprotected: arr[1], payload: arr[2], signature: arr[3] };
}

/**
 * @primitive b.contentCredentials.verifyCose
 * @signature b.contentCredentials.verifyCose(coseSign1, publicKeyPem, opts)
 * @since     0.14.11
 * @status    stable
 * @compliance soc2
 * @related   b.contentCredentials.signCose, b.tsa.verifyToken, b.cose.verify, b.contentCredentials.verify
 *
 * Verify a COSE_Sign1 produced by `signCose` and, when present, its
 * RFC 3161 `sigTst2` timestamp countersignature. The COSE_Sign1 bytes
 * are decoded through the bounded `b.cbor` codec; the Sig_structure
 * (RFC 9052 §4.4) is reconstructed and the signature verified with
 * `b.crypto.verify` against the operator-supplied public-key PEM. When a
 * timestamp token sits under unprotected-header label 35, its imprint is
 * recomputed over the CounterSignature ToBeSigned with the same
 * `hashAlg` (default SHA-512; the allowed set is `b.tsa.IMPRINT_HASHES`)
 * and the digest is handed to `b.tsa.verifyToken` as a PRE-HASHED imprint
 * (`{ hash, hashAlg }`).
 *
 * The ONLY timestamp-verification path is `b.tsa.verifyToken`, which
 * performs the full RFC 3161 §2.4.2 / §2.3 check — the CMS signature over
 * the signed attributes, the `messageDigest` recompute, and the critical,
 * sole `id-kp-timeStamping` EKU — NOT a chain-only shortcut. A chain-only
 * timestamp check is the
 * [CVE-2025-52556](https://nvd.nist.gov/vuln/detail/CVE-2025-52556) /
 * [CWE-347](https://cwe.mitre.org/data/definitions/347.html) improper-
 * signature-verification class and is never done here. `b.tsa.verifyToken`
 * throws on every failure; this primitive wraps that call and converts a
 * thrown `TsaError` into `{ timestamp: { valid: false, reason } }` so
 * `verifyCose` NEVER throws — it returns
 * `{ valid, reason, claims, alg, timestamp }` fail-closed.
 *
 * `opts.requireTimestamp` (default true) fails closed when the COSE_Sign1
 * carries no `sigTst2` token; set it false only when the operator
 * deliberately accepts un-timestamped claims (mirrors `signCose`'s
 * `timestamp:false` opt-out). `opts.timestampTrustAnchorsPem` enables the
 * timestamp cert-chain + validity check inside `b.tsa.verifyToken`.
 *
 * @opts
 *   {
 *     requireTimestamp?:          boolean,           // default true — refuse a token-less COSE_Sign1
 *     timestampHashAlg?:          string,            // default "SHA-512"; one of b.tsa.IMPRINT_HASHES
 *     timestampTrustAnchorsPem?:  string|string[],   // anchors → b.tsa.verifyToken chain check
 *     timestampNonce?:            Buffer,            // require the token nonce to match
 *     audit?:                     boolean,           // default true
 *   }
 *
 * @example
 *   var res = b.contentCredentials.verifyCose(cose.coseSign1, pair.publicKey, {
 *     timestampTrustAnchorsPem: tsaRootPem,
 *   });
 *   res.valid;               // → true
 *   res.timestamp.valid;     // → true
 *   res.timestamp.genTime;   // → Date (the TSA-asserted signing time)
 */
function verifyCose(coseSign1, publicKeyPem, opts) {
  opts = opts || {};
  var auditOn = opts.audit !== false;
  if (!Buffer.isBuffer(coseSign1)) {
    return { valid: false, reason: "cose-not-buffer", claims: null, alg: null, timestamp: null };
  }
  if (typeof publicKeyPem !== "string" || publicKeyPem.length === 0) {
    return { valid: false, reason: "public-key-required", claims: null, alg: null, timestamp: null };
  }
  var requireTimestamp = opts.requireTimestamp !== false;
  var hashAlg;
  try { hashAlg = _resolveTstHashAlg(opts.timestampHashAlg, "verifyCose"); }
  catch (e) { return { valid: false, reason: (e && e.code) || "bad-tst-hash", claims: null, alg: null, timestamp: null }; }

  var parts;
  try { parts = _decodeCoseSign1(coseSign1); }
  catch (e2) { return { valid: false, reason: (e2 && e2.code) || "cose-malformed", claims: null, alg: null, timestamp: null }; }

  // b.cbor.decode returns a bstr's CONTENT bytes (no CBOR header). The
  // Sig_structure and CounterSignature ToBeSigned both embed the
  // protected header / payload AS bstrs (header + content) — re-wrap the
  // decoded content so the bytes match exactly what signCose signed over.
  var protectedBstrFull = _cborBytes(parts.protectedBstr);
  var payloadBstrFull    = _cborBytes(parts.payload);

  // The protected header is a CBOR map { 1: algId } — decode it for the
  // returned alg name (informational; verify auto-detects from the PEM).
  var algName = null;
  try {
    var protMap = parts.protectedBstr.length === 0 ? new Map() : cbor.decode(parts.protectedBstr);
    if (protMap instanceof Map) {
      var algId = protMap.get(1);
      Object.keys(COSE_ALGS).forEach(function (k) { if (COSE_ALGS[k] === algId) algName = k; });
    }
  } catch (_eAlg) { algName = null; }

  // Reconstruct Sig_structure (RFC 9052 §4.4) and verify the primary
  // COSE_Sign1 signature with b.crypto.verify (auto-detects the PQC alg
  // from the PEM).
  var sigStructure = Buffer.concat([
    _cborArrayHeader(4),
    (function () {
      var t = Buffer.from("Signature1", "utf8");
      return t.length < 24 ? Buffer.concat([Buffer.from([0x60 | t.length]), t])                    // CBOR text-string threshold
                           : Buffer.concat([Buffer.from([0x78, t.length]), t]);
    })(),
    protectedBstrFull,
    _cborBytes(Buffer.alloc(0)),                       // external_aad (empty)
    payloadBstrFull,
  ]);
  var sigOk;
  try { sigOk = bCrypto.verify(sigStructure, parts.signature, publicKeyPem); }
  catch (_eSig) { sigOk = false; }
  if (!sigOk) {
    if (auditOn) {
      audit.safeEmit({ action: "contentcredentials.verified_cose", outcome: "denied",
        metadata: { reason: "signature-mismatch", alg: algName } });
    }
    return { valid: false, reason: "signature-mismatch", claims: null, alg: algName, timestamp: null };
  }

  // Recover the manifest claims from the verified payload bytes.
  var claims = null;
  try { claims = safeJson.parse(parts.payload.toString("utf8"), { maxBytes: C_PAYLOAD_MAX }); }
  catch (_eClaims) { claims = null; }

  // sigTst2 (label 35) timestamp countersignature. THE ONLY verification
  // path is b.tsa.verifyToken (full RFC 3161 §2.4.2/§2.3 — CMS signature
  // + messageDigest recompute + critical sole id-kp-timeStamping EKU,
  // NOT a chain-only check). It throws on every failure; we convert a
  // thrown TsaError into { valid:false, reason } so verifyCose stays
  // fail-closed and never throws.
  var tstToken = parts.unprotected.get(HDR_SIG_TST2);
  var timestamp = null;
  if (Buffer.isBuffer(tstToken)) {
    var tbs = _counterSignatureToBeSigned(protectedBstrFull, payloadBstrFull, parts.signature);
    var digest = nodeCrypto.createHash(tsa.IMPRINT_HASHES[hashAlg].nodeHash).update(tbs).digest();
    try {
      // tsa.verifyToken opt shape (mirror of the sign-side buildRequest
      // shape): { hash: <digest>, hashAlg, trustAnchorsPem?, nonce? } —
      // the imprint is the pre-hashed CounterSignature ToBeSigned digest.
      var verifyTokenOpts = { hash: digest, hashAlg: hashAlg };
      if (opts.timestampTrustAnchorsPem !== undefined && opts.timestampTrustAnchorsPem !== null) {
        verifyTokenOpts.trustAnchorsPem = opts.timestampTrustAnchorsPem;
      }
      if (opts.timestampNonce !== undefined && opts.timestampNonce !== null) {
        verifyTokenOpts.nonce = opts.timestampNonce;
      }
      var tstOut = tsa.verifyToken(tstToken, verifyTokenOpts);
      timestamp = {
        valid:     true,
        reason:    null,
        genTime:   tstOut.genTime,
        policy:    tstOut.policy,
        serialHex: tstOut.serialHex,
        hashAlg:   tstOut.hashAlg,
      };
    } catch (eTst) {
      // A TsaError (imprint-mismatch / bad-eku / untrusted-chain / …) is
      // a failed timestamp, not a crash — record it fail-closed.
      timestamp = { valid: false, reason: (eTst && eTst.code) || "timestamp-verify-failed",
        genTime: null, policy: null, serialHex: null, hashAlg: hashAlg };
    }
  } else if (requireTimestamp) {
    if (auditOn) {
      audit.safeEmit({ action: "contentcredentials.verified_cose", outcome: "denied",
        metadata: { reason: "timestamp-required", alg: algName } });
    }
    return { valid: false, reason: "timestamp-required", claims: claims, alg: algName,
      timestamp: { valid: false, reason: "absent", genTime: null, policy: null, serialHex: null, hashAlg: hashAlg } };
  }

  // A present-but-invalid timestamp fails the whole verification closed.
  if (timestamp && timestamp.valid === false) {
    if (auditOn) {
      audit.safeEmit({ action: "contentcredentials.verified_cose", outcome: "denied",
        metadata: { reason: "timestamp-invalid:" + timestamp.reason, alg: algName } });
    }
    return { valid: false, reason: "timestamp-invalid:" + timestamp.reason, claims: claims,
      alg: algName, timestamp: timestamp };
  }

  // SB-942 §22757(a) field-presence check on the verified payload —
  // mirrors verify(). A cryptographically valid COSE_Sign1 over a
  // non-manifest payload (e.g. {foo:"bar"}) or a manifest missing the
  // disclosure fields must NOT verify as a content credential, even for
  // an opted-out / arbitrary-timestamped signature.
  var missingCose = required({
    provider:      claims && claims.provider && claims.provider.name,
    system:        claims && claims.system   && claims.system.id,
    systemVersion: claims && claims.system   && claims.system.version,
    contentId:     claims && claims.content  && claims.content.id,
  });
  if (missingCose.length > 0) {
    if (auditOn) {
      audit.safeEmit({ action: "contentcredentials.verified_cose", outcome: "denied",
        metadata: { reason: "missing-required:" + missingCose.join(","), alg: algName } });
    }
    return { valid: false, reason: "missing-required:" + missingCose.join(","), claims: claims,
      alg: algName, timestamp: timestamp };
  }

  if (auditOn) {
    audit.safeEmit({
      action:   "contentcredentials.verified_cose",
      outcome:  "success",
      metadata: {
        provider:    claims && claims.provider && claims.provider.name,
        system:      claims && claims.system   && claims.system.id,
        contentId:   claims && claims.content  && claims.content.id,
        alg:         algName,
        timestamped: !!(timestamp && timestamp.valid),
      },
    });
  }
  return { valid: true, reason: null, claims: claims, alg: algName, timestamp: timestamp };
}

// ---- CAWG identity assertion (Identity Assertion v1.2) -----------
//
// The Creator Assertions Working Group (CAWG) Identity Assertion binds a
// verifiable creator/organization identity to a C2PA manifest. Two
// binding paths:
//   - "x509"  — a signed organization identity. verified:true ONLY when
//               an identityTrustAnchorsPem is supplied AND the leaf chain
//               verifies to it. Self-presented x509 without a trusted
//               anchor is reported verified:false.
//   - "identity-claims-aggregator" — individual identity attested by an
//               aggregator. Self-asserted; never verified:true here (no
//               aggregator-key trust root is supplied in v1).
// The signer_payload hash-binds the referenced assertions (a SHA3-512
// digest over each canonicalized assertion) so the identity assertion
// cannot be transplanted onto a different manifest's assertions.

var IDENTITY_BINDINGS = Object.freeze({ "x509": true, "identity-claims-aggregator": true });

// Hash-bind a referenced assertion (any JSON-serializable claim object)
// to a stable SHA3-512 hex digest over its RFC 8785 canonical form.
function _hashAssertion(assertion) {
  var canonical = canonicalJson.stringify(assertion);
  return nodeCrypto.createHash("sha3-512").update(Buffer.from(canonical, "utf8")).digest("hex");
}

/**
 * @primitive b.contentCredentials.attachIdentityAssertion
 * @signature b.contentCredentials.attachIdentityAssertion(opts)
 * @since     0.14.11
 * @status    stable
 * @compliance soc2, gdpr
 * @related   b.contentCredentials.verifyIdentityAssertion, b.contentCredentials.signCose, b.crypto.sign
 *
 * Build a CAWG Identity Assertion v1.2 — a signed creator/organization
 * identity bound to a C2PA manifest's other assertions. The
 * `signer_payload` hash-binds each referenced assertion (a SHA3-512
 * digest over its RFC 8785 canonical form) so the identity statement
 * cannot be transplanted onto a different manifest. Two binding paths:
 * `"x509"` for a signed organization identity and
 * `"identity-claims-aggregator"` for an individual whose claims an
 * aggregator attests. The claim signature is produced with
 * `b.crypto.sign` (ML-DSA-87 by default).
 *
 * Self-asserted identity carries NO trust by itself — verification
 * (`verifyIdentityAssertion`) only reports `verified:true` for an
 * `x509` binding when a trust anchor is supplied and the chain verifies.
 * This matches the CAWG model: the assertion records a claim; trust comes
 * from the verifier's anchors, never from the claim's own bytes.
 *
 * @opts
 *   {
 *     binding:          "x509" | "identity-claims-aggregator",  // required
 *     subject:          object,         // required — the asserted identity fields (name, id, org, …)
 *     referencedAssertions: object[],   // required — the manifest assertions this identity binds
 *     privateKeyPem:    string,         // required — claim signing key
 *     audit:            boolean,        // default true
 *   }
 *
 * @example
 *   var pair = b.crypto.generateSigningKeyPair("ml-dsa-87");
 *   var ia = b.contentCredentials.attachIdentityAssertion({
 *     binding: "x509",
 *     subject: { name: "Acme Newsroom", org: "Acme Media", id: "acme-001" },
 *     referencedAssertions: [{ label: "c2pa.actions", data: { action: "c2pa.created" } }],
 *     privateKeyPem: pair.privateKey,
 *   });
 *   ia.signer_payload.referenced_assertions.length;   // → 1
 *   typeof ia.signature;                               // → "string"
 */
function attachIdentityAssertion(opts) {
  opts = opts || {};
  validateOpts.requireObject(opts, "contentCredentials.attachIdentityAssertion", ContentCredentialsError);
  validateOpts(opts, ["binding", "subject", "referencedAssertions", "privateKeyPem", "audit"],
    "contentCredentials.attachIdentityAssertion");
  if (typeof opts.binding !== "string" || !Object.prototype.hasOwnProperty.call(IDENTITY_BINDINGS, opts.binding)) {
    throw ContentCredentialsError.factory("content-credentials/bad-identity-binding",
      "attachIdentityAssertion: binding must be one of " + Object.keys(IDENTITY_BINDINGS).join(" / "));
  }
  if (!opts.subject || typeof opts.subject !== "object" || Array.isArray(opts.subject)) {
    throw ContentCredentialsError.factory("content-credentials/bad-identity-subject",
      "attachIdentityAssertion: subject must be a non-empty object");
  }
  if (Object.keys(opts.subject).length === 0) {
    throw ContentCredentialsError.factory("content-credentials/bad-identity-subject",
      "attachIdentityAssertion: subject must carry at least one identity field");
  }
  if (!Array.isArray(opts.referencedAssertions) || opts.referencedAssertions.length === 0) {
    throw ContentCredentialsError.factory("content-credentials/bad-referenced-assertions",
      "attachIdentityAssertion: referencedAssertions must be a non-empty array");
  }
  validateOpts.requireNonEmptyString(opts.privateKeyPem,
    "attachIdentityAssertion: privateKeyPem", ContentCredentialsError, "BAD_KEY");

  // signer_payload (CAWG §"Signer payload"): the asserted subject + the
  // hash-bound list of referenced assertions.
  var referenced = opts.referencedAssertions.map(function (a) {
    return { hash: _hashAssertion(a), alg: "sha3-512" };
  });
  var signerPayload = {
    binding:               opts.binding,
    subject:               opts.subject,
    referenced_assertions: referenced,
  };
  var canonical = canonicalJson.stringify(signerPayload);
  var signature = bCrypto.sign(Buffer.from(canonical, "utf8"), opts.privateKeyPem);

  if (opts.audit !== false) {
    audit.safeEmit({
      action:   "contentcredentials.identity_attached",
      outcome:  "success",
      // PII minimization (T10): the asserted subject is operator-/self-
      // supplied identity — pass it through b.redact.redact before it
      // reaches the audit sink so a name / email / id can't leak raw.
      metadata: {
        binding:           opts.binding,
        subject:           redact.redact(opts.subject),
        referencedCount:   referenced.length,
      },
    });
  }

  return {
    type:           "cawg.identity",
    version:        "1.2",
    signer_payload: signerPayload,
    signature:      signature.toString("base64"),
  };
}

/**
 * @primitive b.contentCredentials.verifyIdentityAssertion
 * @signature b.contentCredentials.verifyIdentityAssertion(assertion, publicKeyPem, opts)
 * @since     0.14.11
 * @status    stable
 * @compliance soc2, gdpr
 * @related   b.contentCredentials.attachIdentityAssertion, b.crypto.verify, b.contentCredentials.verifyCose
 *
 * Verify a CAWG Identity Assertion v1.2 produced by
 * `attachIdentityAssertion`. Re-canonicalizes the `signer_payload`,
 * checks the claim signature with `b.crypto.verify`, and re-confirms the
 * hash-binding of every referenced assertion the operator re-supplies in
 * `opts.referencedAssertions` (so a valid signature over transplanted
 * assertions still fails closed). Never throws — returns
 * `{ valid, verified, binding, subject, reason }`.
 *
 * `valid` means the signature and assertion hash-binding check out.
 * `verified` is stricter and applies the CAWG trust model: it is
 * `true` ONLY for an `x509` binding when `opts.identityTrustAnchorsPem`
 * is supplied AND the leaf certificate chain verifies to a supplied
 * anchor. A self-asserted identity (no anchor, or the
 * `identity-claims-aggregator` path) is reported `verified:false` even
 * when `valid:true` — self-asserted data never yields `verified:true`
 * without a verified trust anchor
 * ([CVE-2026-34677](https://nvd.nist.gov/vuln/detail/CVE-2026-34677),
 * the unverified-identity-assertion trust-confusion class). Surfaced /
 * audited identity fields pass through `b.redact.redact` (PII
 * minimization).
 *
 * @opts
 *   {
 *     referencedAssertions:    object[],          // required — re-confirm the hash-binding
 *     identityTrustAnchorsPem: string|string[],   // x509 leaf-chain anchors (enables verified:true)
 *     identityCertChainPem:    string|string[],   // x509 leaf + intermediates to chain-check
 *     audit:                   boolean,           // default true
 *   }
 *
 * @example
 *   var res = b.contentCredentials.verifyIdentityAssertion(ia, pair.publicKey, {
 *     referencedAssertions: [{ label: "c2pa.actions", data: { action: "c2pa.created" } }],
 *     identityTrustAnchorsPem: orgRootPem,
 *     identityCertChainPem:    orgLeafPem,
 *   });
 *   res.valid;      // → true  (signature + hash-binding)
 *   res.verified;   // → true  (x509 leaf chained to a trusted anchor)
 */
function verifyIdentityAssertion(assertion, publicKeyPem, opts) {
  opts = opts || {};
  var auditOn = opts.audit !== false;
  function _fail(reason) {
    return { valid: false, verified: false, binding: null, subject: null, reason: reason };
  }
  if (!assertion || typeof assertion !== "object" || !assertion.signer_payload || !assertion.signature) {
    return _fail("assertion-shape");
  }
  if (typeof publicKeyPem !== "string" || publicKeyPem.length === 0) {
    return _fail("public-key-required");
  }
  var sp = assertion.signer_payload;
  if (!sp || typeof sp !== "object" || typeof sp.binding !== "string" || !Object.prototype.hasOwnProperty.call(IDENTITY_BINDINGS, sp.binding) ||
      !Array.isArray(sp.referenced_assertions)) {
    return _fail("signer-payload-shape");
  }

  // (1) signature over the canonicalized signer_payload.
  var canonical = canonicalJson.stringify(sp);
  var sigBuf;
  try { sigBuf = Buffer.from(assertion.signature, "base64"); }
  catch (_eB64) { return _fail("signature-base64-bad"); }
  var sigOk;
  try { sigOk = bCrypto.verify(Buffer.from(canonical, "utf8"), sigBuf, publicKeyPem); }
  catch (_eV) { sigOk = false; }
  if (!sigOk) {
    if (auditOn) {
      audit.safeEmit({ action: "contentcredentials.identity_verified", outcome: "denied",
        metadata: { binding: sp.binding, reason: "signature-mismatch" } });
    }
    return _fail("signature-mismatch");
  }

  // (2) re-confirm the hash-binding of every referenced assertion the
  //     caller re-supplies — a valid signature over transplanted
  //     assertions must still fail closed.
  if (!Array.isArray(opts.referencedAssertions) || opts.referencedAssertions.length === 0) {
    return _fail("referenced-assertions-required");
  }
  var supplied = opts.referencedAssertions.map(_hashAssertion);
  var bound = sp.referenced_assertions.map(function (r) { return r && r.hash; });
  if (supplied.length !== bound.length) {
    return _fail("referenced-assertions-count-mismatch");
  }
  for (var i = 0; i < supplied.length; i += 1) {
    if (bound.indexOf(supplied[i]) === -1) {
      if (auditOn) {
        audit.safeEmit({ action: "contentcredentials.identity_verified", outcome: "denied",
          metadata: { binding: sp.binding, reason: "assertion-hash-mismatch" } });
      }
      return _fail("assertion-hash-mismatch");
    }
  }

  // (3) trust resolution. verified:true ONLY for x509 with a supplied
  //     anchor that the leaf chain verifies to. Self-asserted data
  //     (no anchor, or the aggregator path) stays verified:false even
  //     though valid:true.
  var verified = false;
  var trustReason = null;
  if (sp.binding === "x509" &&
      opts.identityTrustAnchorsPem !== undefined && opts.identityTrustAnchorsPem !== null) {
    var chainRes = _verifyIdentityX509Chain(opts.identityCertChainPem, opts.identityTrustAnchorsPem);
    verified = chainRes.ok;
    trustReason = chainRes.reason;
  } else if (sp.binding === "identity-claims-aggregator") {
    trustReason = "aggregator-self-asserted";
  } else {
    trustReason = "no-trust-anchor";
  }

  if (auditOn) {
    audit.safeEmit({
      action:   "contentcredentials.identity_verified",
      outcome:  verified ? "success" : "warning",
      metadata: {
        binding:  sp.binding,
        verified: verified,
        reason:   trustReason,
        // PII minimization (T10) — redact the asserted subject fields.
        subject:  redact.redact(sp.subject),
      },
    });
  }

  return {
    valid:    true,
    verified: verified,
    binding:  sp.binding,
    subject:  sp.subject,
    reason:   trustReason,
  };
}

// Verify an x509 identity leaf chains to a supplied trust anchor and is
// currently valid. Returns { ok, reason } — never throws. Accepts a
// single PEM string or an array for both the chain and the anchors.
function _verifyIdentityX509Chain(certChainPem, trustAnchorsPem) {
  var chain = typeof certChainPem === "string" ? [certChainPem]
    : (Array.isArray(certChainPem) ? certChainPem : null);
  if (!chain || chain.length === 0) {
    return { ok: false, reason: "no-cert-chain" };
  }
  var anchors = typeof trustAnchorsPem === "string" ? [trustAnchorsPem]
    : (Array.isArray(trustAnchorsPem) ? trustAnchorsPem : null);
  if (!anchors || anchors.length === 0 ||
      !anchors.every(function (a) { return typeof a === "string" && a.length > 0; })) {
    return { ok: false, reason: "bad-trust-anchors" };
  }
  var certs, anchorCerts;
  try { certs = chain.map(function (p) { return new nodeCrypto.X509Certificate(p); }); }
  catch (_eChain) { return { ok: false, reason: "bad-chain-cert" }; }
  try { anchorCerts = anchors.map(function (a) { return new nodeCrypto.X509Certificate(a); }); }
  catch (_eAnchor) { return { ok: false, reason: "bad-anchor-cert" }; }

  var now = Date.now();
  // Every cert in the presented chain must currently be valid.
  for (var ci = 0; ci < certs.length; ci += 1) {
    if (now < certs[ci].validFromDate.getTime() || now > certs[ci].validToDate.getTime()) {
      return { ok: false, reason: ci === 0 ? "leaf-expired" : "chain-cert-expired" };
    }
  }
  // Walk the presented chain: each cert must be issued AND signed by the
  // next cert up. A [leaf, intermediate] chain links leaf→intermediate
  // here, then the top (intermediate) is matched against the anchors
  // below — so identities signed through an intermediate CA verify, not
  // only direct-root / self-signed leaves.
  for (var li = 0; li < certs.length - 1; li += 1) {
    var child = certs[li], parent = certs[li + 1];
    // issuerValidlyIssued enforces basicConstraints cA:TRUE on the parent in
    // addition to the issuance + signature linkage — a non-CA cert cannot be
    // an intermediate issuer (basicConstraints bypass, CVE-2002-0862 class).
    var linked = x509Chain.issuerValidlyIssued(parent, child);
    if (!linked) { return { ok: false, reason: "broken-chain" }; }
  }
  // The top of the presented chain must chain to (or BE) a trust anchor.
  var top = certs[certs.length - 1];
  for (var a = 0; a < anchorCerts.length; a += 1) {
    var anchor = anchorCerts[a];
    var chained = false;
    if (top.fingerprint256 === anchor.fingerprint256) {
      chained = true;   // top of the chain IS the anchor (root-in-chain or self-signed leaf == anchor)
    } else {
      // issuerValidlyIssued enforces basicConstraints cA:TRUE on the anchor
      // in addition to issuance + signature (basicConstraints bypass class).
      chained = x509Chain.issuerValidlyIssued(anchor, top);
    }
    if (chained) {
      if (now < anchor.validFromDate.getTime() || now > anchor.validToDate.getTime()) {
        return { ok: false, reason: "anchor-expired" };
      }
      return { ok: true, reason: "x509-chain-verified" };
    }
  }
  return { ok: false, reason: "untrusted-chain" };
}

/**
 * @primitive b.contentCredentials.cacImplicitLabel
 * @signature b.contentCredentials.cacImplicitLabel(opts)
 * @since     0.10.8
 * @status    stable
 * @compliance cac-genai-label
 * @related   b.contentCredentials.build, b.contentCredentials.cacImplicitLabelRead
 *
 * Build the GB 45438-2025 "Cybersecurity Technology — Labeling Method
 * for Content Generated by Artificial Intelligence" implicit metadata
 * block (effective 2025-09-01 per CAC Measures for Labeling AI-
 * Generated Synthetic Content). The framework owns the implicit lane
 * (metadata); the visible explicit label is application-layer
 * rendering. Operators co-emit alongside the C2PA-COSE manifest by
 * declaring `cac-genai-label` posture on `b.contentCredentials.build`.
 *
 * @opts
 *   providerName:   string,         // UTF-8 ≤256 bytes
 *   providerCode:   string,         // 18-char 统一社会信用代码 (Chinese USCC)
 *   contentId:      string,         // globally-unique asset id
 *   contentKind:    string,         // "text"|"image"|"audio"|"video"|"virtual-scene"|"other"
 *   generatedAt:    string,         // ISO 8601 UTC
 *
 * @example
 *   var label = b.contentCredentials.cacImplicitLabel({
 *     providerName: "Example AI",
 *     providerCode: "91110000600037341A",
 *     contentId:    "asset-2026-05-17-abc123",
 *     contentKind:  "image",
 *     generatedAt:  "2026-05-17T20:00:00Z",
 *   });
 *   // → { aigcMarker: "AIGC", providerName, providerCode, contentId, contentKind, generatedAt }
 */
var CAC_KIND_ENUM = Object.freeze({
  text: true, image: true, audio: true, video: true,
  "virtual-scene": true, other: true,
});
var CAC_USCC_RE = /^[0-9A-HJ-NPQRTUWXY]{18}$/;
var ISO8601_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

function cacImplicitLabel(opts) {
  if (!opts || typeof opts !== "object") {
    throw new ContentCredentialsError("cac-implicit-label/bad-opts",
      "cacImplicitLabel: opts object required");
  }
  validateOpts.requireNonEmptyString(opts.providerName,
    "cacImplicitLabel: providerName", ContentCredentialsError,
    "cac-implicit-label/bad-provider-name");
  if (Buffer.byteLength(opts.providerName, "utf8") > STR_LEN_MAX) {
    throw new ContentCredentialsError("cac-implicit-label/oversize-provider-name",
      "cacImplicitLabel: providerName exceeds " + STR_LEN_MAX + " bytes (UTF-8)");
  }
  if (typeof opts.providerCode !== "string" || opts.providerCode.length !== 18 ||
      !CAC_USCC_RE.test(opts.providerCode)) {                                                    // allow:regex-no-length-cap — length-bounded immediately above
    throw new ContentCredentialsError("cac-implicit-label/bad-provider-code",
      "cacImplicitLabel: providerCode must be an 18-char unified social credit code " +
      "(统一社会信用代码 per GB 32100-2015 / GB 45438-2025)");
  }
  if (typeof opts.contentId !== "string" || opts.contentId.length === 0 ||
      opts.contentId.length > 128) {                                                             // contentId char cap, not bytes
    throw new ContentCredentialsError("cac-implicit-label/bad-content-id",
      "cacImplicitLabel: contentId must be 1-128 chars");
  }
  if (!ID_RE.test(opts.contentId)) {                                                             // allow:regex-no-length-cap — length-bounded immediately above
    throw new ContentCredentialsError("cac-implicit-label/bad-content-id",
      "cacImplicitLabel: contentId must match [A-Za-z0-9._:/-]");
  }
  if (typeof opts.contentKind !== "string" || !Object.prototype.hasOwnProperty.call(CAC_KIND_ENUM, opts.contentKind)) {
    throw new ContentCredentialsError("cac-implicit-label/bad-content-kind",
      "cacImplicitLabel: contentKind must be one of " +
      Object.keys(CAC_KIND_ENUM).join("/"));
  }
  if (typeof opts.generatedAt !== "string" || !ISO8601_RE.test(opts.generatedAt)) {
    throw new ContentCredentialsError("cac-implicit-label/bad-generated-at",
      "cacImplicitLabel: generatedAt must be ISO 8601 UTC (e.g. 2026-05-17T20:00:00Z)");
  }
  return Object.freeze({
    aigcMarker:   "AIGC",
    providerName: opts.providerName,
    providerCode: opts.providerCode,
    contentId:    opts.contentId,
    contentKind:  opts.contentKind,
    generatedAt:  opts.generatedAt,
  });
}

/**
 * @primitive b.contentCredentials.cacImplicitLabelRead
 * @signature b.contentCredentials.cacImplicitLabelRead(bytesOrObject)
 * @since     0.10.8
 * @status    stable
 * @compliance cac-genai-label
 * @related   b.contentCredentials.cacImplicitLabel
 *
 * Reverse parser for the GB 45438-2025 implicit label. Accepts either
 * a `Buffer` / `string` containing the JSON-serialized block (as the
 * sender embedded in XMP / EXIF / MP4-box / etc.) or the already-
 * parsed object. Returns the validated label shape or throws on any
 * field that fails the same gate `cacImplicitLabel({...})` enforces.
 *
 * @example
 *   var label = b.contentCredentials.cacImplicitLabelRead(jsonBuf);
 *   // → { aigcMarker: "AIGC", providerName, providerCode, ... }
 */
function cacImplicitLabelRead(input) {
  var obj;
  if (Buffer.isBuffer(input)) {
    try { obj = safeJson.parse(input.toString("utf8"), { maxBytes: 64 * 1024 }); }              // allow:raw-byte-literal — 64 KiB CAC label cap
    catch (e) {
      throw new ContentCredentialsError("cac-implicit-label/bad-json",
        "cacImplicitLabelRead: JSON parse failed: " + (e && e.message));
    }
  } else if (typeof input === "string") {
    try { obj = safeJson.parse(input, { maxBytes: 64 * 1024 }); }                                // allow:raw-byte-literal — 64 KiB CAC label cap
    catch (e2) {
      throw new ContentCredentialsError("cac-implicit-label/bad-json",
        "cacImplicitLabelRead: JSON parse failed: " + (e2 && e2.message));
    }
  } else if (input && typeof input === "object") {
    obj = input;
  } else {
    throw new ContentCredentialsError("cac-implicit-label/bad-input",
      "cacImplicitLabelRead: input must be Buffer / string / object (got " + typeof input + ")");
  }
  if (obj.aigcMarker !== "AIGC") {
    throw new ContentCredentialsError("cac-implicit-label/missing-aigc-marker",
      "cacImplicitLabelRead: aigcMarker field must equal 'AIGC' (GB 45438-2025 §6)");
  }
  return cacImplicitLabel({
    providerName: obj.providerName,
    providerCode: obj.providerCode,
    contentId:    obj.contentId,
    contentKind:  obj.contentKind,
    generatedAt:  obj.generatedAt,
  });
}

module.exports = {
  build:      build,
  sign:       sign,
  signCose:   signCose,
  verifyCose: verifyCose,
  verify:     verify,
  required:   required,
  attachIdentityAssertion: attachIdentityAssertion,
  verifyIdentityAssertion: verifyIdentityAssertion,
  cacImplicitLabel:     cacImplicitLabel,
  cacImplicitLabelRead: cacImplicitLabelRead,
  REQUIRED_FIELDS: REQUIRED_FIELDS.slice(),
  COSE_ALGS:  Object.assign({}, COSE_ALGS),
  ContentCredentialsError: ContentCredentialsError,
};
