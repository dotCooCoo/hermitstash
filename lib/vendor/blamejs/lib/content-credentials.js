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
var nodeTypes = require("node:util").types;
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
var lazyRequire = require("./lazy-require");
var { defineClass } = require("./framework-error");

var pki = lazyRequire(function () { return require("./vendor/blamejs-pki.cjs"); });
var ContentCredentialsError = defineClass("ContentCredentialsError", { alwaysPermanent: true });

var STR_LEN_MAX = 256;
var ID_LEN_MAX  = 128;
var SEMVER_RE = /^[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][A-Za-z0-9.-]+)?$/;
var ID_RE     = /^[a-zA-Z0-9._:/-]{1,128}$/;
var SHA3_HEX_LEN = 128;
var C_PAYLOAD_MAX = C.BYTES.mib(1);

var REQUIRED_FIELDS = ["provider", "system", "systemVersion", "contentId"];

function _validateBuildOpts(opts) {
  if (!opts || typeof opts !== "object") {
    throw ContentCredentialsError.factory("content-credentials/bad-opts",
      "contentCredentials.build: opts required");
  }
  for (var i = 0; i < REQUIRED_FIELDS.length; i += 1) {
    var f = REQUIRED_FIELDS[i];
    validateOpts.requireNonEmptyString(opts[f],
      "contentCredentials.build: " + f, ContentCredentialsError,
      "content-credentials/missing-" + f.replace(/([a-z0-9])([A-Z])/g, "$1-$2").toLowerCase());
  }
  if (opts.provider.length > STR_LEN_MAX) {
    throw ContentCredentialsError.factory("content-credentials/bad-provider",
      "provider exceeds " + STR_LEN_MAX + " chars");
  }
  if (opts.system.length > ID_LEN_MAX || !ID_RE.test(opts.system)) {
    throw ContentCredentialsError.factory("content-credentials/bad-system",
      "system must match " + ID_RE);
  }
  if (opts.systemVersion.length > 64 || !SEMVER_RE.test(opts.systemVersion)) {
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
  if (opts.generatedAt !== undefined &&
      (typeof opts.generatedAt !== "number" || !isFinite(opts.generatedAt) ||
       Math.abs(opts.generatedAt) > 8.64e15)) {
    throw ContentCredentialsError.factory("content-credentials/bad-generated-at",
      "contentCredentials.build: generatedAt must be a finite epoch-millis number within the valid Date range");
  }
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
    visibleDisclosure: opts.visibleDisclosure || null,
  };
  return _deepFreeze(manifest);
}

function _deepFreeze(obj) {
  if (obj && typeof obj === "object" && !Object.isFrozen(obj)) {
    var keys = Object.keys(obj);
    for (var i = 0; i < keys.length; i += 1) {
      var v = obj[keys[i]];
      if (v && typeof v === "object") _deepFreeze(v);
    }
    Object.freeze(obj);
  }
  return obj;
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
 * caller passes `audit:false`. A `manifest` that is not an object throws
 * `content-credentials/bad-manifest`, a missing or empty `privateKeyPem`
 * throws `content-credentials/bad-key`, and a `privateKeyPem` that
 * `b.crypto.compromisedKey` reports throws
 * `content-credentials/compromised-key`.
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
    "contentCredentials.sign: privateKeyPem", ContentCredentialsError, "content-credentials/bad-key");
  _assertSigningKeyNotCompromised(opts.privateKeyPem, "contentCredentials.sign");
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
 * valid signature but missing fields fails closed. A public key that
 * `b.crypto.compromisedKey` reports returns `reason: "compromised-key"`.
 * It never throws and returns `{ valid, claims, reason }`. It audits successful
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
  if (_isCompromised(_compromisedVerdict(publicKeyPem))) {
    return { valid: false, claims: null, reason: "compromised-key" };
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

// registry: https://www.iana.org/assignments/cose/cose.xhtml#algorithms
var COSE_ALGS = {
  "ed25519":    -8,
  "es256":      -7,
  "es384":      -35,
  "es512":      -36,
  "ml-dsa-44":  -48,
  "ml-dsa-65":  -49,
  "ml-dsa-87":  -50,
};

var COSE_ALG_KEYS = {
  "ed25519":   { keyType: "ed25519",   hash: null },
  "es256":     { keyType: "ec", curve: "prime256v1", hash: "sha256" },
  "es384":     { keyType: "ec", curve: "secp384r1",  hash: "sha384" },
  "es512":     { keyType: "ec", curve: "secp521r1",  hash: "sha512" },
  "ml-dsa-44": { keyType: "ml-dsa-44", hash: null },
  "ml-dsa-65": { keyType: "ml-dsa-65", hash: null },
  "ml-dsa-87": { keyType: "ml-dsa-87", hash: null },
};

function _isCompromised(verdict) {
  return verdict !== null && verdict.id !== "unreadable";
}

function _compromisedVerdict(key) {
  return x509Chain._compromiseVerdict(key);
}

function _assertSigningKeyNotCompromised(key, fnName) {
  var found = _compromisedVerdict(key);
  if (_isCompromised(found)) {
    throw ContentCredentialsError.factory("content-credentials/compromised-key",
      fnName + ": privateKeyPem is a compromised key: " + found.reason);
  }
}

function _keyMatchesAlg(key, algName) {
  var want = COSE_ALG_KEYS[algName];
  if (!want || !key || key.asymmetricKeyType !== want.keyType) return false;
  if (want.curve === undefined) return true;
  return !!(key.asymmetricKeyDetails && key.asymmetricKeyDetails.namedCurve === want.curve);
}

function _describeKey(key) {
  if (!key) return "no key";
  if (key.asymmetricKeyType === "ec" && key.asymmetricKeyDetails) {
    return "an ec key on " + key.asymmetricKeyDetails.namedCurve;
  }
  return "a " + key.asymmetricKeyType + " key";
}

function _signForAlg(data, privateKey, algName) {
  var p = COSE_ALG_KEYS[algName];
  if (p.hash === null) return nodeCrypto.sign(null, data, privateKey);
  return nodeCrypto.sign(p.hash, data, { key: privateKey, dsaEncoding: "ieee-p1363" });
}

function _verifyForAlg(data, signature, publicKey, algName) {
  var p = COSE_ALG_KEYS[algName];
  try {
    if (p.hash === null) return nodeCrypto.verify(null, data, publicKey, signature);
    return nodeCrypto.verify(p.hash, data, { key: publicKey, dsaEncoding: "ieee-p1363" }, signature);
  } catch (_e) {
    return false;
  }
}

function _cborUint(n) {
  if (n < 24)         return Buffer.from([n]);
  if (n < 256)        return Buffer.from([0x18, n]);
  if (n < 65536)      return Buffer.from([0x19, (n >> 8) & 0xFF, n & 0xFF]);
  if (n < 4294967296) return Buffer.from([0x1A, (n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]);
  throw ContentCredentialsError.factory("content-credentials/cbor-overflow", "cbor uint too large: " + n);
}

function _cborNint(n) {
  var v = -1 - n;
  if (v < 24)    return Buffer.from([0x20 | v]);
  if (v < 256)   return Buffer.from([0x38, v]);
  if (v < 65536) return Buffer.from([0x39, (v >> 8) & 0xFF, v & 0xFF]);
  return Buffer.from([0x3A, (v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF]);
}

function _cborInt(n) {
  return n >= 0 ? _cborUint(n) : _cborNint(n);
}

function _cborBytes(buf) {
  var n = buf.length;
  var head;
  if (n < 24)         head = Buffer.from([0x40 | n]);
  else if (n < 256)   head = Buffer.from([0x58, n]);
  else if (n < 65536) head = Buffer.from([0x59, (n >> 8) & 0xFF, n & 0xFF]);
  else                head = Buffer.from([0x5A, (n >>> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]);
  return Buffer.concat([head, buf]);
}

function _cborArrayHeader(n) {
  if (n < 24)    return Buffer.from([0x80 | n]);
  if (n < 256)   return Buffer.from([0x98, n]);
  if (n < 65536) return Buffer.from([0x99, (n >> 8) & 0xFF, n & 0xFF]);
  throw ContentCredentialsError.factory("content-credentials/cbor-overflow", "cbor array too large: " + n);
}

var CBOR_ARRAY4_HEADER = _cborArrayHeader(4);

function _cborMapHeader(n) {
  if (n < 24)    return Buffer.from([0xA0 | n]);
  if (n < 256)   return Buffer.from([0xB8, n]);
  throw ContentCredentialsError.factory("content-credentials/cbor-overflow", "cbor map too large: " + n);
}

function _cborTag(tag) {
  if (tag < 24)         return Buffer.from([0xC0 | tag]);
  if (tag < 256)        return Buffer.from([0xD8, tag]);
  if (tag < 65536)      return Buffer.from([0xD9, (tag >> 8) & 0xFF, tag & 0xFF]);
  return Buffer.from([0xDA, (tag >> 24) & 0xFF, (tag >> 16) & 0xFF, (tag >> 8) & 0xFF, tag & 0xFF]);
}

var HDR_ALG = 1;
var HDR_X5CHAIN = 33;

var C2PA_SIG_TST2_LABEL = "sigTst2";
var LEGACY_TST_LABEL = 35;
var C2PA_TST_TOKENS = "tstTokens";
var C2PA_TST_VAL = "val";

var COUNTERSIGNATURE_CONTEXT = "CounterSignature";

var DEFAULT_TST_HASH = "SHA-512";

function _resolveTstHashAlg(hashAlg, fnName) {
  var name = hashAlg || DEFAULT_TST_HASH;
  if (!Object.prototype.hasOwnProperty.call(tsa.IMPRINT_HASHES, name)) {
    throw ContentCredentialsError.factory("content-credentials/bad-tst-hash",
      fnName + ": timestamp.hashAlg must be one of " +
      Object.keys(tsa.IMPRINT_HASHES).join(" / "));
  }
  return name;
}

function _counterSignatureToBeSigned(protectedBytes, sigBytes) {
  return cbor.encode([COUNTERSIGNATURE_CONTEXT, protectedBytes, Buffer.alloc(0), cbor.encode(sigBytes)]);
}

function _sigTst2Container(token) {
  var entry = new Map([[C2PA_TST_VAL, token]]);
  return new Map([[C2PA_TST_TOKENS, [entry]]]);
}

function _sigTst2Token(value) {
  if (!(value instanceof Map)) return null;
  var tokens = value.get(C2PA_TST_TOKENS);
  if (!Array.isArray(tokens) || tokens.length !== 1) return null;
  if (!(tokens[0] instanceof Map)) return null;
  var val = tokens[0].get(C2PA_TST_VAL);
  return Buffer.isBuffer(val) && val.length > 0 ? val : null;
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
 * The protected header carries the COSE algorithm (label 1) and, when
 * `certChain` is given, the x5chain (label 33), which C2PA 2.1 section
 * 14.5 requires in the protected header. `alg` must match the key:
 * `ed25519` an Ed25519 key, `es256` / `es384` / `es512` an EC key on
 * P-256 / P-384 / P-521, and `ml-dsa-44` / `ml-dsa-65` / `ml-dsa-87` the
 * ML-DSA key of that parameter set; any other pairing throws
 * `content-credentials/alg-key-mismatch`. A `privateKeyPem` that
 * `b.crypto.compromisedKey` reports throws
 * `content-credentials/compromised-key`. ECDSA signatures are SHA-256 /
 * SHA-384 / SHA-512 over the Sig_structure, carried as r || s (RFC 9053
 * section 2.1). SLH-DSA has no COSE algorithm in the IANA registry and is
 * refused with `content-credentials/bad-alg`.
 *
 * An RFC 3161 timestamp (the C2PA 2.x v2 time-stamp, `sigTst2`) is
 * attached when an `opts.timestamp` context is present, proving the
 * manifest was signed before the timestamp authority's asserted time. The
 * imprint is computed over the CounterSignature ToBeSigned that C2PA 2.x
 * section 10.3.2.5 defines: `[ "CounterSignature", body_protected,
 * external_aad (empty), payload ]`, where the payload is the COSE_Sign1
 * signature serialized as a CBOR byte string. It is hashed with
 * `timestamp.hashAlg` (default SHA-512; the allowed set is
 * `b.tsa.IMPRINT_HASHES`), and the digest is handed to `b.tsa.buildRequest`
 * as a PRE-HASHED imprint (`{ hashed: true, hashAlg }`). Two modes: pass
 * `timestamp.token` (a DER TimeStampToken already obtained from a TSA) to
 * attach it directly, or omit it to get back a `timestampRequest` (the DER
 * bytes to POST as `application/timestamp-query`, the nonce to keep, and
 * the ToBeSigned imprint) so the operator can fetch a token and re-call
 * with it. Once attached, the token sits in the unprotected header under
 * the text label `"sigTst2"` as the tstContainer
 * `{ "tstTokens": [ { "val": <TimeStampToken> } ] }`.
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
 * Omitting `opts.timestamp` throws `content-credentials/timestamp-required`.
 * `timestamp: false` without a non-empty `timestampOptOutReason` throws
 * `content-credentials/timestamp-opt-out-no-reason`. A `timestamp` that is
 * not an object, or is an array, throws `content-credentials/bad-timestamp`.
 * A `timestamp.hashAlg` outside `b.tsa.IMPRINT_HASHES` throws
 * `content-credentials/bad-tst-hash`, and a `timestamp.token` that is not a
 * Buffer throws `content-credentials/bad-timestamp-token`. A
 * `timestamp.signature` that is not a non-empty string throws
 * `content-credentials/bad-reuse-signature`, and one that does not verify
 * against this manifest and key throws
 * `content-credentials/reuse-signature-mismatch`.
 *
 * A `manifest` that is not an object throws
 * `content-credentials/bad-manifest`. A missing or empty `privateKeyPem`,
 * or one that does not read as a private key, throws
 * `content-credentials/bad-key`. A `certChain` entry that is not a Buffer or
 * Uint8Array throws `content-credentials/bad-cert-chain`, and a `certChain`
 * of 65,536 or more entries throws `content-credentials/cbor-overflow`.
 *
 * Returns `{ manifest, coseSign1: Buffer, alg, timestamped, timestampRequest? }`.
 * Operators embed the `coseSign1` Buffer in the image's C2PA box (JPEG XT
 * marker, PNG iTXt chunk, MP4 'jumb' box per C2PA §13).
 *
 * @opts
 *   {
 *     privateKeyPem: string,            // required
 *     alg?:          "ed25519" | "es256" | "es384" | "es512" |
 *                    "ml-dsa-44" | "ml-dsa-65" | "ml-dsa-87",   // default "ml-dsa-87"; must match the key
 *     certChain?:    Buffer[],          // X.509 DER buffers; emitted as x5chain (protected header label 33)
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
    "contentCredentials.signCose: privateKeyPem", ContentCredentialsError, "content-credentials/bad-key");
  var algName = (opts.alg || "ml-dsa-87").toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(COSE_ALGS, algName)) {
    throw ContentCredentialsError.factory("content-credentials/bad-alg",
      "contentCredentials.signCose: alg '" + algName +
      "' not in COSE alg registry. Known: " + Object.keys(COSE_ALGS).join(", "));
  }
  var algId = COSE_ALGS[algName];
  var privateKey;
  try { privateKey = nodeCrypto.createPrivateKey(opts.privateKeyPem); }
  catch (eKey) {
    throw ContentCredentialsError.factory("content-credentials/bad-key",
      "contentCredentials.signCose: privateKeyPem is not a readable private key: " +
      ((eKey && eKey.message) || String(eKey)));
  }
  if (!_keyMatchesAlg(privateKey, algName)) {
    throw ContentCredentialsError.factory("content-credentials/alg-key-mismatch",
      "contentCredentials.signCose: alg '" + algName + "' does not match the signing key (" +
      _describeKey(privateKey) + ")");
  }
  _assertSigningKeyNotCompromised(privateKey, "contentCredentials.signCose");

  var tsState = _resolveTimestampPosture(opts, "contentCredentials.signCose");

  var chainArray = null;
  if (Array.isArray(opts.certChain) && opts.certChain.length > 0) {
    opts.certChain.forEach(function (der, idx) {
      if (!nodeTypes.isUint8Array(der)) {
        throw ContentCredentialsError.factory("content-credentials/bad-cert-chain",
          "contentCredentials.signCose: certChain[" + idx + "] must be a Buffer/Uint8Array of DER bytes");
      }
    });
    if (opts.certChain.length === 1) {
      chainArray = _cborBytes(opts.certChain[0]);
    } else {
      var chainBufs = [_cborArrayHeader(opts.certChain.length)];
      opts.certChain.forEach(function (der) { chainBufs.push(_cborBytes(der)); });
      chainArray = Buffer.concat(chainBufs);
    }
  }

  var protParts = [_cborMapHeader(chainArray ? 2 : 1), _cborInt(HDR_ALG), _cborInt(algId)];
  if (chainArray) protParts.push(_cborInt(HDR_X5CHAIN), chainArray);
  var protBytes = Buffer.concat(protParts);
  var protectedBstr = _cborBytes(protBytes);

  var canonicalPayload = Buffer.from(canonicalJson.stringify(manifest), "utf8");
  var payloadBstr      = _cborBytes(canonicalPayload);

  var sigStructureBufs = [
    CBOR_ARRAY4_HEADER,
    null,
    protectedBstr,
    _cborBytes(Buffer.alloc(0)),
    payloadBstr,
  ];
  var sigText = Buffer.from("Signature1", "utf8");
  var sigTextBstr;
  if (sigText.length < 24)      sigTextBstr = Buffer.concat([Buffer.from([0x60 | sigText.length]), sigText]);
  else                          sigTextBstr = Buffer.concat([Buffer.from([0x78, sigText.length]), sigText]);
  sigStructureBufs[1] = sigTextBstr;
  var toBeSigned = Buffer.concat(sigStructureBufs);

  var signature;
  if (tsState.mode === "attach" && tsState.reuseSignature != null) {
    var reused;
    try { reused = Buffer.from(tsState.reuseSignature, "base64"); }
    catch (_eReuse) {
      throw ContentCredentialsError.factory("content-credentials/bad-reuse-signature",
        "contentCredentials.signCose: timestamp.signature must be base64");
    }
    if (!_verifyForAlg(toBeSigned, reused, nodeCrypto.createPublicKey(privateKey), algName)) {
      throw ContentCredentialsError.factory("content-credentials/reuse-signature-mismatch",
        "contentCredentials.signCose: timestamp.signature does not verify against this manifest + key");
    }
    signature = reused;
  } else {
    signature = _signForAlg(toBeSigned, privateKey, algName);
  }

  var timestampRequest = null;
  if (tsState.mode === "request") {
    var reqTbs = _counterSignatureToBeSigned(protBytes, signature);
    var reqDigest = nodeCrypto
      .createHash(tsa.IMPRINT_HASHES[tsState.hashAlg].nodeHash).update(reqTbs).digest();
    var built = tsa.buildRequest(reqDigest, { hashed: true, hashAlg: tsState.hashAlg });
    timestampRequest = {
      der:           built.der,
      nonce:         built.nonce,
      hashAlg:       tsState.hashAlg,
      toBeSigned:    reqTbs,
      messageImprint: built.messageImprint,
      signature:     signature.toString("base64"),
    };
  }

  var unprotectedHdr = tsState.mode === "attach"
    ? cbor.encode(new Map([[C2PA_SIG_TST2_LABEL, _sigTst2Container(tsState.token)]]))
    : _cborMapHeader(0);

  var coseSign1 = Buffer.concat([
    _cborTag(18),
    CBOR_ARRAY4_HEADER,
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

function _resolveTimestampPosture(opts, fnName) {
  if (opts.timestamp === false) {
    validateOpts.requireNonEmptyString(opts.timestampOptOutReason,
      fnName + ": timestampOptOutReason (required when timestamp:false)",
      ContentCredentialsError, "content-credentials/timestamp-opt-out-no-reason");
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

function _decodeCoseSign1(coseSign1) {
  var decoded;
  try {
    decoded = cbor.decode(coseSign1, { allowedTags: [18] });
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
 * Verify a COSE_Sign1 that embeds a `b.contentCredentials` manifest as its
 * payload, as `signCose` writes it, and, when present, its RFC 3161
 * `sigTst2` time-stamp, read from the unprotected header where C2PA 2.x
 * places it. The signer's certificate chain is not read; the caller
 * passes the public key. A detached (nil) payload, which a C2PA 2.x claim
 * signature carries, returns `reason: "content-credentials/cose-malformed"`,
 * and a correctly signed payload that is not a `b.contentCredentials`
 * manifest returns `reason: "missing-required:<fields>"`. The
 * COSE_Sign1 bytes are decoded through the bounded `b.cbor` codec; the
 * Sig_structure (RFC 9052 §4.4) is reconstructed and the signature
 * verified against the operator-supplied public-key PEM with the algorithm
 * the protected header names. A protected header without an algorithm, or
 * with one outside `b.contentCredentials.COSE_ALGS`, returns
 * `reason: "unknown-alg"`; a public key that does not match that algorithm
 * returns `reason: "alg-key-mismatch"`, and a public key that
 * `b.crypto.compromisedKey` reports returns `reason: "compromised-key"`.
 * All three are decided before any signature check. A time-stamp from a
 * TSA whose signer, chain or anchor key is compromised returns
 * `reason: "timestamp-invalid:tsa/compromised-key"`.
 *
 * The time-stamp is read from the unprotected header's `"sigTst2"`
 * tstContainer, which must hold exactly one token in
 * `{ "tstTokens": [ { "val": <TimeStampToken> } ] }`; any other shape
 * returns `reason: "timestamp-invalid:sigtst2-malformed"`. The token's
 * imprint is recomputed over the C2PA v2 CounterSignature ToBeSigned with
 * the same `hashAlg` (default SHA-512; the allowed set is
 * `b.tsa.IMPRINT_HASHES`) and the digest is handed to `b.tsa.verifyToken`
 * as a PRE-HASHED imprint (`{ hash, hashAlg }`). A `timestampHashAlg`
 * outside that set returns `reason: "content-credentials/bad-tst-hash"`.
 *
 * `signCose` in 0.21.2 and earlier wrote the token as a byte string under
 * the integer unprotected-header label 35. `verifyCose` does not read that
 * label: a COSE_Sign1 with no `sigTst2` and a token under label 35 returns
 * `reason: "timestamp-invalid:legacy-label-35"` with
 * `timestamp.reason: "legacy-label-35"`, whatever `requireTimestamp` is set
 * to. Re-sign the manifest with `signCose` to replace it.
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

  var protectedBstrFull = _cborBytes(parts.protectedBstr);
  var payloadBstrFull    = _cborBytes(parts.payload);

  var algName = null;
  try {
    var protMap = parts.protectedBstr.length === 0 ? new Map() : cbor.decode(parts.protectedBstr);
    if (protMap instanceof Map) {
      var algId = protMap.get(HDR_ALG);
      Object.keys(COSE_ALGS).forEach(function (k) { if (COSE_ALGS[k] === algId) algName = k; });
    }
  } catch (_eAlg) { algName = null; }
  if (algName === null) {
    if (auditOn) {
      audit.safeEmit({ action: "contentcredentials.verified_cose", outcome: "denied",
        metadata: { reason: "unknown-alg", alg: null } });
    }
    return { valid: false, reason: "unknown-alg", claims: null, alg: null, timestamp: null };
  }

  var publicKey = null;
  try { publicKey = nodeCrypto.createPublicKey(publicKeyPem); }
  catch (_eKey) { publicKey = null; }
  if (publicKey !== null && !_keyMatchesAlg(publicKey, algName)) {
    if (auditOn) {
      audit.safeEmit({ action: "contentcredentials.verified_cose", outcome: "denied",
        metadata: { reason: "alg-key-mismatch", alg: algName } });
    }
    return { valid: false, reason: "alg-key-mismatch", claims: null, alg: algName, timestamp: null };
  }
  if (publicKey !== null && _isCompromised(_compromisedVerdict(publicKey))) {
    if (auditOn) {
      audit.safeEmit({ action: "contentcredentials.verified_cose", outcome: "denied",
        metadata: { reason: "compromised-key", alg: algName } });
    }
    return { valid: false, reason: "compromised-key", claims: null, alg: algName, timestamp: null };
  }

  var sigStructure = Buffer.concat([
    CBOR_ARRAY4_HEADER,
    (function () {
      var t = Buffer.from("Signature1", "utf8");
      return t.length < 24 ? Buffer.concat([Buffer.from([0x60 | t.length]), t])
                           : Buffer.concat([Buffer.from([0x78, t.length]), t]);
    })(),
    protectedBstrFull,
    _cborBytes(Buffer.alloc(0)),
    payloadBstrFull,
  ]);
  var sigOk = publicKey !== null && _verifyForAlg(sigStructure, parts.signature, publicKey, algName);
  if (!sigOk) {
    if (auditOn) {
      audit.safeEmit({ action: "contentcredentials.verified_cose", outcome: "denied",
        metadata: { reason: "signature-mismatch", alg: algName } });
    }
    return { valid: false, reason: "signature-mismatch", claims: null, alg: algName, timestamp: null };
  }

  var claims = null;
  try { claims = safeJson.parse(parts.payload.toString("utf8"), { maxBytes: C_PAYLOAD_MAX }); }
  catch (_eClaims) { claims = null; }

  var sigTst2 = parts.unprotected.has(C2PA_SIG_TST2_LABEL) ? parts.unprotected.get(C2PA_SIG_TST2_LABEL) : undefined;
  var tstToken = sigTst2 === undefined ? null : _sigTst2Token(sigTst2);
  var legacyTst = sigTst2 === undefined ? parts.unprotected.get(LEGACY_TST_LABEL) : undefined;
  var timestamp = null;
  if (sigTst2 !== undefined && tstToken === null) {
    timestamp = { valid: false, reason: "sigtst2-malformed",
      genTime: null, policy: null, serialHex: null, hashAlg: hashAlg };
  } else if (Buffer.isBuffer(legacyTst) && legacyTst.length > 0) {
    timestamp = { valid: false, reason: "legacy-label-35",
      genTime: null, policy: null, serialHex: null, hashAlg: hashAlg };
  } else if (tstToken !== null) {
    var tbs = _counterSignatureToBeSigned(parts.protectedBstr, parts.signature);
    var digest = nodeCrypto.createHash(tsa.IMPRINT_HASHES[hashAlg].nodeHash).update(tbs).digest();
    try {
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

  if (timestamp && timestamp.valid === false) {
    if (auditOn) {
      audit.safeEmit({ action: "contentcredentials.verified_cose", outcome: "denied",
        metadata: { reason: "timestamp-invalid:" + timestamp.reason, alg: algName } });
    }
    return { valid: false, reason: "timestamp-invalid:" + timestamp.reason, claims: claims,
      alg: algName, timestamp: timestamp };
  }

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

var IDENTITY_BINDINGS = Object.freeze({ "x509": true, "identity-claims-aggregator": true });
var IDENTITY_SUBJECT_ATTRIBUTES = Object.freeze({
  name:     "2.5.4.3",
  org:      "2.5.4.10",
  orgUnit:  "2.5.4.11",
  country:  "2.5.4.6",
  locality: "2.5.4.7",
  state:    "2.5.4.8",
  id:       "2.5.4.5",
});

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
 * `b.crypto.sign` (ML-DSA-87 by default). A `binding` outside the two
 * paths throws `content-credentials/bad-identity-binding`, a `subject` that
 * is not a non-empty object throws `content-credentials/bad-identity-subject`,
 * an empty `referencedAssertions` throws
 * `content-credentials/bad-referenced-assertions`, a missing or empty
 * `privateKeyPem` throws `content-credentials/bad-key`, and a
 * `privateKeyPem` that `b.crypto.compromisedKey` reports throws
 * `content-credentials/compromised-key`.
 *
 * `verifyIdentityAssertion` reports `verified:true` only for an `x509`
 * binding, and only when a trust anchor is supplied, the leaf certificate
 * chain verifies to that anchor, the leaf certificate carries the claim key,
 * and the leaf certificate's subject holds every `subject` field (see
 * `verifyIdentityAssertion` for the field names).
 *
 * @opts
 *   {
 *     binding:          "x509" | "identity-claims-aggregator",  // required
 *     subject:          object,         // required; the asserted identity fields (name, org, orgUnit, country, locality, state, id)
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
    "attachIdentityAssertion: privateKeyPem", ContentCredentialsError, "content-credentials/bad-key");
  _assertSigningKeyNotCompromised(opts.privateKeyPem, "attachIdentityAssertion");

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
 * assertions still fails closed). It never throws and returns
 * `{ valid, verified, binding, subject, reason }`.
 *
 * `valid` means the signature and assertion hash-binding check out.
 * `verified` is stricter and applies the CAWG trust model: it is
 * `true` ONLY for an `x509` binding when `opts.identityTrustAnchorsPem`
 * is supplied AND the leaf certificate chain verifies to a supplied
 * anchor AND the leaf certificate vouches for the claim. The leaf
 * certificate must carry `publicKeyPem`, or the result is
 * `verified:false` with `reason: "leaf-key-mismatch"`. Every field of the
 * signed `subject` must be one of `name` (commonName), `org`
 * (organizationName), `orgUnit` (organizationalUnitName), `country`
 * (countryName), `locality` (localityName), `state`
 * (stateOrProvinceName) or `id` (serialNumber), holding a string equal to
 * that attribute in the leaf certificate's subject, or the result is
 * `verified:false` with `reason: "subject-not-certified"`. A claim key that
 * `b.crypto.compromisedKey` reports returns `valid:false` with
 * `reason: "compromised-key"`. A chain certificate with such a key, or a
 * trust anchor with such a key that is a chain certificate or is named as
 * the issuer of one, returns `verified:false` with the same reason. A
 * compromised anchor that took no part in the chain is skipped. A chain
 * certificate whose key `b.crypto.compromisedKey` cannot read returns
 * `verified:false` with `reason: "bad-chain-cert"`, and a trust anchor
 * whose key it cannot read anchors no chain. The chain
 * is resolved with `b.x509Chain.resolveChain`. A self-asserted
 * identity (no anchor, or the `identity-claims-aggregator` path) is
 * reported `verified:false` even when `valid:true`
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

  if (_isCompromised(_compromisedVerdict(publicKeyPem))) {
    if (auditOn) {
      audit.safeEmit({ action: "contentcredentials.identity_verified", outcome: "denied",
        metadata: { binding: sp.binding, reason: "compromised-key" } });
    }
    return _fail("compromised-key");
  }
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

  if (!Array.isArray(opts.referencedAssertions) || opts.referencedAssertions.length === 0) {
    return _fail("referenced-assertions-required");
  }
  var supplied = opts.referencedAssertions.map(_hashAssertion);
  var bound = sp.referenced_assertions.map(function (r) { return r && r.hash; });
  if (supplied.length !== bound.length) {
    return _fail("referenced-assertions-count-mismatch");
  }
  var boundRemaining = bound.slice();
  for (var i = 0; i < supplied.length; i += 1) {
    var mIdx = boundRemaining.indexOf(supplied[i]);
    if (mIdx === -1) {
      if (auditOn) {
        audit.safeEmit({ action: "contentcredentials.identity_verified", outcome: "denied",
          metadata: { binding: sp.binding, reason: "assertion-hash-mismatch" } });
      }
      return _fail("assertion-hash-mismatch");
    }
    boundRemaining.splice(mIdx, 1);
  }

  var verified = false;
  var trustReason = null;
  if (sp.binding === "x509" &&
      opts.identityTrustAnchorsPem !== undefined && opts.identityTrustAnchorsPem !== null) {
    var chainRes = _verifyIdentityX509Chain(opts.identityCertChainPem, opts.identityTrustAnchorsPem);
    trustReason = chainRes.reason;
    if (chainRes.ok && !_leafCarriesKey(chainRes.leaf, publicKeyPem)) trustReason = "leaf-key-mismatch";
    else if (chainRes.ok && !_subjectCertified(sp.subject, chainRes.leaf)) trustReason = "subject-not-certified";
    verified = trustReason === "x509-chain-verified";
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
  try { certs = chain.map(function (p) { return bCrypto._x509(p); }); }
  catch (_eChain) { return { ok: false, reason: "bad-chain-cert" }; }
  try { anchorCerts = anchors.map(function (a) { return bCrypto._x509(a); }); }
  catch (_eAnchor) { return { ok: false, reason: "bad-anchor-cert" }; }
  for (var vi = 0; vi < certs.length; vi += 1) {
    var verdict = _compromisedVerdict(certs[vi]);
    if (verdict !== null) return { ok: false, reason: _isCompromised(verdict) ? "compromised-key" : "bad-chain-cert" };
  }

  var now = Date.now();
  var pool = certs.slice(1);
  var res = x509Chain.resolveChain(certs[0], pool, anchorCerts, { validAt: x509Chain._validAt(new Date(now)) });
  var refusal = x509Chain._chainRefusal(res, {
    compromised:      "compromised-key",
    invalidCert:      "anchor-expired",
    pathlen:          "chain-pathlen-exceeded",
    nameconstraint:   "name-constraint-violation",
    untrusted:        "untrusted-chain",
    untrustedMessage: "",
  }, { leaf: certs[0], pool: pool, anchors: anchorCerts });
  if (refusal !== null && refusal.code === "compromised-key") return { ok: false, reason: refusal.code };
  for (var ci = 0; ci < certs.length; ci += 1) {
    if (now < certs[ci].validFromDate.getTime() || now > certs[ci].validToDate.getTime()) {
      return { ok: false, reason: ci === 0 ? "leaf-expired" : "chain-cert-expired" };
    }
  }
  for (var li = 0; li < certs.length - 1; li += 1) {
    var child = certs[li], parent = certs[li + 1];
    var linked = x509Chain.issuerValidlyIssued(parent, child);
    if (!linked) { return { ok: false, reason: "broken-chain" }; }
  }
  if (refusal !== null) return { ok: false, reason: refusal.code };
  return { ok: true, reason: "x509-chain-verified", leaf: certs[0] };
}

function _leafCarriesKey(leaf, publicKeyPem) {
  try {
    var claimed = nodeCrypto.createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
    return claimed.equals(leaf.publicKey.export({ type: "spki", format: "der" }));
  } catch (_e) {
    return false;
  }
}

function _subjectAttributeValues(leaf) {
  var out = Object.create(null);
  pki().schema.x509.parse(leaf.raw).subject.rdns.forEach(function (rdn) {
    rdn.forEach(function (atv) {
      if (typeof atv.value !== "string") return;
      if (!out[atv.type]) out[atv.type] = [];
      out[atv.type].push(atv.value);
    });
  });
  return out;
}

function _subjectCertified(subject, leaf) {
  if (!subject || typeof subject !== "object" || Array.isArray(subject)) return false;
  var fields = Object.keys(subject);
  if (fields.length === 0) return false;
  var values;
  try { values = _subjectAttributeValues(leaf); }
  catch (_e) { return false; }
  return fields.every(function (field) {
    if (!Object.prototype.hasOwnProperty.call(IDENTITY_SUBJECT_ATTRIBUTES, field)) return false;
    var certified = values[IDENTITY_SUBJECT_ATTRIBUTES[field]];
    return typeof subject[field] === "string" && Array.isArray(certified) && certified.indexOf(subject[field]) !== -1;
  });
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
var ISO8601_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;                               // allow:duplicate-regex — ISO-8601 instant shape ships in three primitives (ai-model-manifest, metrics text-render, content-credentials); none of the three imports safe-schema, whose DATETIME_RE also admits a numeric offset, so sharing it would pull a validation module into a hot-path sink for a 50-byte literal

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
      opts.contentId.length > 128) {
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
