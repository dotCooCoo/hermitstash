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

var bCrypto = require("./crypto");
var canonicalJson = require("./canonical-json");
var safeJson = require("./safe-json");
var validateOpts = require("./validate-opts");
var audit = require("./audit");
var { defineClass } = require("./framework-error");
var ContentCredentialsError = defineClass("ContentCredentialsError", { alwaysPermanent: true });

var STR_LEN_MAX = 256;                                                                        // string-length cap, not bytes
var ID_LEN_MAX  = 128;                                                                        // string-length cap, not bytes
var SEMVER_RE = /^[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][A-Za-z0-9.-]+)?$/;
var ID_RE     = /^[a-zA-Z0-9._:/-]{1,128}$/;
var SHA3_HEX_LEN = 128;                                                                       // SHA3-512 hex length, not bytes

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

/**
 * @primitive b.contentCredentials.signCose
 * @signature b.contentCredentials.signCose(manifest, opts)
 * @since     0.8.77
 * @related   b.contentCredentials.sign
 *
 * C2PA 2.x interop sign — wraps the manifest in a COSE_Sign1 CBOR
 * envelope (RFC 9052) so the result interops with c2patool / JPEG
 * Trust / Adobe / external C2PA verifiers. The simpler `sign()`
 * primitive ships a blamejs-internal envelope shape; this one ships
 * COSE bytes.
 *
 * Returns `{ manifest, coseSign1: Buffer, alg }`. Operators embed
 * the `coseSign1` Buffer in the image's C2PA box (JPEG XT marker,
 * PNG iTXt chunk, MP4 'jumb' box per C2PA §13).
 *
 * @opts
 *   {
 *     privateKeyPem: string,            // required
 *     alg?:          "ed25519" | "es256" | "es384" | "es512" |
 *                    "ml-dsa-44" | "ml-dsa-65" | "ml-dsa-87" |
 *                    "slh-dsa-shake-256f",   // default "ml-dsa-87"
 *     certChain?:    Buffer[],          // X.509 DER buffers; emitted as x5chain (header label 33)
 *     audit?:        boolean,           // default true
 *   }
 *
 * @example
 *   var pair = b.crypto.generateSigningKeyPair("ml-dsa-87");
 *   var manifest = b.contentCredentials.build({
 *     provider: "Acme AI", system: "acme-v3",
 *     systemVersion: "3.2.1", contentId: "img-001",
 *   });
 *   var cose = b.contentCredentials.signCose(manifest, {
 *     privateKeyPem: pair.privateKey,
 *     alg:           "ml-dsa-87",
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

  // Protected header: map { 1: alg }
  var protBytes = Buffer.concat([
    _cborMapHeader(1),
    _cborInt(1),               // key: 1 (alg)
    _cborInt(algId),           // value: COSE alg id
  ]);
  var protectedBstr = _cborBytes(protBytes);

  // Unprotected header: map { 33: x5chain } when cert chain supplied;
  // else empty map {}.
  var unprotectedHdr;
  if (Array.isArray(opts.certChain) && opts.certChain.length > 0) {
    var chainArray;
    if (opts.certChain.length === 1) {
      // Single-cert form: header value is the DER bytes directly.
      chainArray = _cborBytes(opts.certChain[0]);
    } else {
      var chainBufs = [_cborArrayHeader(opts.certChain.length)];
      opts.certChain.forEach(function (der) {
        chainBufs.push(_cborBytes(der));
      });
      chainArray = Buffer.concat(chainBufs);
    }
    unprotectedHdr = Buffer.concat([
      _cborMapHeader(1),
      _cborInt(33),             // allow:raw-time-literal — RFC 9360 x5chain COSE header label; coincidental multiple-of-60, not a duration, C.TIME N/A
      chainArray,
    ]);
  } else {
    unprotectedHdr = _cborMapHeader(0);                // empty {}
  }

  // Payload — canonicalized manifest bytes.
  var canonicalPayload = Buffer.from(canonicalJson.stringify(manifest), "utf8");
  var payloadBstr      = _cborBytes(canonicalPayload);

  // Sig_structure per RFC 9052 §4.4: ["Signature1", protected, external_aad="", payload]
  var sigStructureBufs = [
    _cborArrayHeader(4),
    Buffer.concat([_cborBytes(Buffer.from("Signature1", "utf8"))]),
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

  // Sign with framework's b.crypto.sign — algorithm picked from the PEM.
  var signature = bCrypto.sign(toBeSigned, opts.privateKeyPem);

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
      outcome:  "success",
      metadata: {
        provider:   manifest.provider && manifest.provider.name,
        system:     manifest.system   && manifest.system.id,
        contentId:  manifest.content  && manifest.content.id,
        alg:        algName,
        bytes:      coseSign1.length,
      },
    });
  }

  return {
    manifest:  manifest,
    coseSign1: coseSign1,
    alg:       algName,
  };
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
  if (typeof opts.contentKind !== "string" || !CAC_KIND_ENUM[opts.contentKind]) {
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
  verify:     verify,
  required:   required,
  cacImplicitLabel:     cacImplicitLabel,
  cacImplicitLabelRead: cacImplicitLabelRead,
  REQUIRED_FIELDS: REQUIRED_FIELDS.slice(),
  COSE_ALGS:  Object.assign({}, COSE_ALGS),
  ContentCredentialsError: ContentCredentialsError,
};
