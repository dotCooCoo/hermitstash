"use strict";
/**
 * b.contentCredentials — California SB-942 / AB-853 + C2PA 2.1
 * content-provenance manifest builder for AI-generated assets.
 *
 * California SB-942 (Cal. Bus. & Prof. Code §22757) + AB-853, both
 * effective 2026-08-02, require providers of generative AI systems
 * to embed a latent (machine-readable) provenance disclosure in
 * every AI-generated image / video / audio asset distributed in
 * California. The disclosure MUST carry:
 *
 *   - Provider name
 *   - System (model) identifier + version
 *   - Content timestamp (when generated)
 *   - Unique content ID
 *
 * SB-942 specifically cites C2PA (Coalition for Content Provenance
 * and Authenticity) as an acceptable disclosure format. C2PA 2.1+
 * manifests carry signed assertions with the same fields.
 *
 * The framework can't embed the manifest into image/video/audio
 * bytes directly (that requires format-specific muxers — JPEG XMP /
 * PNG iTXt / MP4 ContentBoxes / etc. that vary per codec). What it
 * CAN do:
 *
 *   - Build a C2PA-shaped manifest carrying the required fields.
 *   - Sign the manifest with the framework's audit-sign keypair
 *     (ML-DSA-87 — or operator-supplied SigStore key).
 *   - Emit a tamper-evident audit row recording the disclosure.
 *   - Validate inbound manifests presented by upstream content
 *     pipelines (the receiver side of the same chain).
 *
 * Operator workflow:
 *
 *   var manifest = b.contentCredentials.build({
 *     provider:        "Acme AI Inc.",
 *     system:          "acme-image-v3",
 *     systemVersion:   "3.2.1",
 *     contentId:       "img-2026-05-08-abc123",
 *     contentType:     "image/png",
 *     contentSha3:     hashHex,
 *     // operator's display attribution + machine-readable fields
 *   });
 *   var signed = b.contentCredentials.sign(manifest, { signWith: ... });
 *   // operator hands `signed.manifest` to their muxer for embedding
 *
 * Public API:
 *
 *   contentCredentials.build(opts) -> manifest (unsigned)
 *   contentCredentials.sign(manifest, opts) -> { manifest, signature }
 *   contentCredentials.verify(envelope, publicKeyPem) -> { valid, claims }
 *   contentCredentials.required(opts) -> array of missing-field errors
 *     (returns [] when the operator's input satisfies SB-942 minimums)
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
