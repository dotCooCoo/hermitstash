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

var crypto = require("./crypto");
var canonicalJson = require("./canonical-json");
var validateOpts = require("./validate-opts");
var audit = require("./audit");
var { defineClass } = require("./framework-error");
var ContentCredentialsError = defineClass("ContentCredentialsError", { alwaysPermanent: true });

var STR_LEN_MAX = 256;                                                                        // allow:raw-byte-literal — string-length cap, not bytes
var ID_LEN_MAX  = 128;                                                                        // allow:raw-byte-literal — string-length cap, not bytes
var SEMVER_RE = /^[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][A-Za-z0-9.-]+)?$/;
var ID_RE     = /^[a-zA-Z0-9._:/-]{1,128}$/;
var SHA3_HEX_LEN = 128;                                                                       // allow:raw-byte-literal — SHA3-512 hex length, not bytes

// Required fields per SB-942 §22757(a) — every AI-generated asset
// must disclose provider + system + timestamp + contentId.
var REQUIRED_FIELDS = ["provider", "system", "systemVersion", "contentId"];

function _validateBuildOpts(opts) {
  if (!opts || typeof opts !== "object") {
    throw ContentCredentialsError.factory("BAD_OPTS",
      "contentCredentials.build: opts required");
  }
  for (var i = 0; i < REQUIRED_FIELDS.length; i += 1) {
    var f = REQUIRED_FIELDS[i];
    validateOpts.requireNonEmptyString(opts[f],
      "contentCredentials.build: " + f, ContentCredentialsError, "MISSING_" + f.toUpperCase());
  }
  if (opts.provider.length > STR_LEN_MAX) {
    throw ContentCredentialsError.factory("BAD_PROVIDER",
      "provider exceeds " + STR_LEN_MAX + " chars");
  }
  if (opts.system.length > ID_LEN_MAX || !ID_RE.test(opts.system)) {
    throw ContentCredentialsError.factory("BAD_SYSTEM",
      "system must match " + ID_RE);
  }
  if (opts.systemVersion.length > 64 || !SEMVER_RE.test(opts.systemVersion)) {                // allow:raw-byte-literal — semver length cap, not bytes
    throw ContentCredentialsError.factory("BAD_VERSION",
      "systemVersion must be semver");
  }
  if (opts.contentId.length > ID_LEN_MAX || !ID_RE.test(opts.contentId)) {
    throw ContentCredentialsError.factory("BAD_CONTENT_ID",
      "contentId must match " + ID_RE);
  }
  if (opts.contentType !== undefined) {
    if (typeof opts.contentType !== "string" || opts.contentType.length === 0 ||
        opts.contentType.length > ID_LEN_MAX || !/^[a-zA-Z]+\/[A-Za-z0-9._+-]+$/.test(opts.contentType)) {
      throw ContentCredentialsError.factory("BAD_CONTENT_TYPE",
        "contentType must be a valid IANA media type");
    }
  }
  if (opts.contentSha3 !== undefined) {
    if (typeof opts.contentSha3 !== "string" || opts.contentSha3.length !== SHA3_HEX_LEN ||
        !/^[a-f0-9]+$/i.test(opts.contentSha3)) {
      throw ContentCredentialsError.factory("BAD_CONTENT_HASH",
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
    throw ContentCredentialsError.factory("BAD_MANIFEST",
      "contentCredentials.sign: manifest required");
  }
  validateOpts.requireNonEmptyString(opts.privateKeyPem,
    "contentCredentials.sign: privateKeyPem", ContentCredentialsError, "BAD_KEY");
  var canonical = canonicalJson.stringify(manifest);
  var signature = crypto.sign(Buffer.from(canonical, "utf8"), opts.privateKeyPem);
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
  var ok = crypto.verify(Buffer.from(canonical, "utf8"), sigBuf, publicKeyPem);
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

module.exports = {
  build:      build,
  sign:       sign,
  verify:     verify,
  required:   required,
  REQUIRED_FIELDS: REQUIRED_FIELDS.slice(),
  ContentCredentialsError: ContentCredentialsError,
};
