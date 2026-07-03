// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.ai.modelManifest
 * @nav    AI
 * @title  AI Model Manifest (AIBOM)
 *
 * @intro
 *   CycloneDX 1.6 ML-BOM emitter for AI bills of materials. EU AI Act
 *   Art. 11 + Annex IV require technical documentation for high-risk
 *   AI systems; the EU CRA (Regulation (EU) 2024/2847) transposition
 *   deadline (2027-12-11) extends SBOM-style documentation to AI
 *   components in products with digital elements. ML-BOM extends the
 *   CycloneDX 1.5 machine-learning component type with model-card,
 *   dataset, hyperparameter, formulation, and external-service
 *   sections per the OWASP CycloneDX Authoritative Guide to AI/ML-BOM
 *   and CycloneDX spec issue #702 (EU CRA alignment).
 *
 *   Two paths:
 *   - `build({...})` constructs a 1.6-conformant JSON BOM in memory.
 *   - `sign(bom, { privateKeyPem })` signs the canonical-JSON-1785
 *     representation with the operator's signing key (ML-DSA-87 by
 *     default per project hard-rule 2). `verify(envelope, publicKeyPem)`
 *     re-canonicalizes and checks before trusting any field.
 *
 *   Self-validation: `build` rejects BOMs missing CycloneDX 1.6
 *   required fields (`bomFormat`, `specVersion`, `metadata.timestamp`,
 *   `metadata.component` when shipping a model). Catches malformed
 *   inputs at emit time, not at downstream validator.
 *
 * @card
 *   CycloneDX 1.6 AI bill of materials (AIBOM) — model cards, datasets, hyperparameters, training workflows. ML-DSA-87 signed.
 */

var bCrypto = require("./crypto");
var canonicalJson = require("./canonical-json");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");
var audit = require("./audit");

var AiModelManifestError = defineClass("AiModelManifestError", { alwaysPermanent: true });

var SPEC_VERSION = "1.6";
var BOM_FORMAT = "CycloneDX";
var COMPONENT_TYPE_MODEL = "machine-learning-model";
var VALID_DATA_TYPES = Object.freeze({
  "source-code": true, configuration: true, dataset: true, definition: true,
  "device-driver": true, documentation: true, evidence: true, executable: true,
  file: true, firmware: true, framework: true, library: true,
  "machine-learning-model": true, manifest: true, "operating-system": true,
  patch: true, platform: true, "test-case": true,
});
var ISO8601_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;                                // allow:duplicate-regex — ISO-8601 instant shape ships in three primitives (metrics text-render, content-credentials, mail-server-imap APPEND); each is bounded by its own caller and the regex itself is 50 bytes — extracting into a cross-module dep wouldn't carry its weight
var BOM_REF_RE = /^[A-Za-z0-9._:/+-]{1,256}$/;                                                  // CycloneDX bom-ref string-length cap, not bytes

function _requireString(obj, key, ownerName) {
  if (typeof obj[key] !== "string" || obj[key].length === 0) {
    throw new AiModelManifestError("aibom/bad-" + key,
      ownerName + ": " + key + " must be a non-empty string");
  }
}

function _validateModelComponent(c) {
  if (!c || typeof c !== "object") {
    throw new AiModelManifestError("aibom/bad-model-component",
      "build: opts.model must be an object");
  }
  _requireString(c, "name", "build.model");
  _requireString(c, "version", "build.model");
  if (c["bom-ref"] !== undefined) {
    if (typeof c["bom-ref"] !== "string" || c["bom-ref"].length > 256) {                         // bom-ref string-length cap, not bytes
      throw new AiModelManifestError("aibom/bad-bom-ref",
        "build.model: bom-ref must be a string of length 1-256");
    }
    if (!BOM_REF_RE.test(c["bom-ref"])) {                                                        // allow:regex-no-length-cap — length-bounded immediately above
      throw new AiModelManifestError("aibom/bad-bom-ref",
        "build.model: bom-ref must match [A-Za-z0-9._:/+-]");
    }
  }
  // modelCard is CycloneDX 1.6 §4.5.5; required for ML components when
  // the operator wants downstream tooling (e.g. Dependency-Track) to
  // surface the card. We do not REQUIRE the card here (some operators
  // ship a hash-only ML-BOM by policy) but we do validate shape when
  // present.
  if (c.modelCard !== undefined) {
    if (typeof c.modelCard !== "object") {
      throw new AiModelManifestError("aibom/bad-model-card",
        "build.model.modelCard: must be an object");
    }
  }
}

function _validateDataComponent(d, idx) {
  if (!d || typeof d !== "object") {
    throw new AiModelManifestError("aibom/bad-dataset",
      "build.datasets[" + idx + "]: must be an object");
  }
  _requireString(d, "name", "build.datasets[" + idx + "]");
  if (d.type !== undefined && !Object.prototype.hasOwnProperty.call(VALID_DATA_TYPES, d.type)) {
    throw new AiModelManifestError("aibom/bad-dataset-type",
      "build.datasets[" + idx + "].type '" + d.type + "' not in CycloneDX 1.6 data-type vocabulary");
  }
}

/**
 * @primitive b.ai.modelManifest.build
 * @signature b.ai.modelManifest.build(opts)
 * @since     0.10.8
 * @status    stable
 * @compliance eu-ai-act-art-11, nist-ai-600-1, iso-42001, iso-23894
 * @related   b.ai.modelManifest.sign, b.ai.modelManifest.verify
 *
 * Build a CycloneDX 1.6 ML-BOM JSON document for the supplied model
 * + datasets + hyperparameters + formulation + external services.
 * Returns a frozen plain object ready for `sign({...})` or direct
 * serialization. Validates against the spec's required-field set at
 * emit time (`bomFormat` / `specVersion` / `metadata.timestamp` /
 * `metadata.component`) plus the ML-BOM-specific shape (model
 * component type, dataset type vocabulary, bom-ref grammar).
 *
 * @opts
 *   model:           object,        // { name, version, license?, bom-ref?, modelCard? }
 *   datasets:        object[],      // [{ name, type?, contents?, classification?, ... }]
 *   hyperparameters: object,        // kv pairs → properties[]
 *   formulation:     object[],      // [{ ref, components, workflows }]
 *   services:        object[],      // [{ name, endpoints, authenticated }]
 *   tool:            object,        // tool metadata; defaults to blamejs core
 *   timestamp:       string,        // ISO 8601 UTC; defaults to now
 *   serialNumber:    string,        // urn:uuid:...; defaults to fresh UUIDv4
 *
 * @example
 *   var bom = b.ai.modelManifest.build({
 *     model: { name: "acme-classifier", version: "1.2.3" },
 *     datasets: [{ name: "training-2026", type: "dataset" }],
 *   });
 *   bom.bomFormat;   // → "CycloneDX"
 *   bom.specVersion; // → "1.6"
 */
function build(opts) {
  opts = opts || {};
  _validateModelComponent(opts.model);
  if (opts.datasets !== undefined) {
    if (!Array.isArray(opts.datasets)) {
      throw new AiModelManifestError("aibom/bad-datasets",
        "build: opts.datasets must be an array");
    }
    for (var i = 0; i < opts.datasets.length; i += 1) _validateDataComponent(opts.datasets[i], i);
  }
  var timestamp = opts.timestamp || new Date().toISOString();
  if (!ISO8601_RE.test(timestamp)) {
    throw new AiModelManifestError("aibom/bad-timestamp",
      "build: timestamp must be ISO 8601 UTC (e.g. 2026-05-17T20:00:00Z)");
  }
  var serialNumber = opts.serialNumber || _uuidUrn();
  if (typeof serialNumber !== "string" || serialNumber.indexOf("urn:uuid:") !== 0) {
    throw new AiModelManifestError("aibom/bad-serial-number",
      "build: serialNumber must start with `urn:uuid:`");
  }

  var primaryComponent = Object.assign({
    type:    COMPONENT_TYPE_MODEL,
    "bom-ref": opts.model["bom-ref"] || ("model:" + opts.model.name + "@" + opts.model.version),
  }, opts.model);
  primaryComponent.type = COMPONENT_TYPE_MODEL;

  var components = [];
  // Per CycloneDX 1.6 §4.7: the primary component goes in
  // metadata.component, NOT in components[]. Datasets, hyperparameter-
  // bearing components, and external dependencies live in components[].
  if (Array.isArray(opts.datasets)) {
    for (var di = 0; di < opts.datasets.length; di += 1) {
      var ds = opts.datasets[di];
      components.push(Object.assign({
        type: ds.type || "data",
        "bom-ref": ds["bom-ref"] || ("dataset:" + ds.name),
      }, ds));
    }
  }

  // Hyperparameters → CycloneDX properties[] kv pairs per spec
  // issue #702 EU CRA alignment.
  var properties = [];
  if (opts.hyperparameters && typeof opts.hyperparameters === "object") {
    var keys = Object.keys(opts.hyperparameters);
    for (var k = 0; k < keys.length; k += 1) {
      var key = keys[k];
      properties.push({ name: "ai:hyperparameter:" + key,
                        value: String(opts.hyperparameters[key]) });
    }
  }

  var bom = {
    bomFormat:     BOM_FORMAT,
    specVersion:   SPEC_VERSION,
    serialNumber:  serialNumber,
    version:       1,
    metadata: {
      timestamp: timestamp,
      tools: [Object.assign({
        vendor:  "blamejs",
        name:    "@blamejs/core",
        version: _frameworkVersion(),
      }, opts.tool || {})],
      component: primaryComponent,
    },
  };
  if (components.length > 0) bom.components = components;
  if (properties.length > 0) bom.properties = properties;
  if (Array.isArray(opts.formulation) && opts.formulation.length > 0) {
    bom.formulation = opts.formulation;
  }
  if (Array.isArray(opts.services) && opts.services.length > 0) {
    bom.services = opts.services;
  }
  if (Array.isArray(opts.dependencies) && opts.dependencies.length > 0) {
    bom.dependencies = opts.dependencies;
  }
  return Object.freeze(bom);
}

/**
 * @primitive b.ai.modelManifest.sign
 * @signature b.ai.modelManifest.sign(bom, opts)
 * @since     0.10.8
 * @status    stable
 * @compliance eu-ai-act-art-11
 * @related   b.ai.modelManifest.build, b.ai.modelManifest.verify
 *
 * Sign an AIBOM produced by `build({...})`. Signature is over the
 * canonical-JSON-1785 representation of the BOM (deterministic byte
 * stream regardless of object-key insertion order); the operator's
 * `privateKeyPem` selects the signing alg (ML-DSA-87 by default per
 * the project's PQC-first crypto rule). Returns `{ bom, signature }`
 * where `signature` is base64-encoded.
 *
 * @opts
 *   privateKeyPem:  string,        // PEM-encoded private key
 *   audit:          boolean,        // default true
 *
 * @example
 *   var pair = b.crypto.generateSigningKeyPair("ml-dsa-87");
 *   var bom = b.ai.modelManifest.build({ model: { name: "x", version: "1" }});
 *   var env = b.ai.modelManifest.sign(bom, { privateKeyPem: pair.privateKey });
 *   typeof env.signature; // → "string"
 */
function sign(bom, opts) {
  opts = opts || {};
  if (!bom || typeof bom !== "object") {
    throw new AiModelManifestError("aibom/bad-bom",
      "sign: bom must be an object produced by build({...})");
  }
  validateOpts.requireNonEmptyString(opts.privateKeyPem,
    "sign: opts.privateKeyPem", AiModelManifestError, "aibom/bad-key");
  var canonical = canonicalJson.stringify(bom);
  var signature = bCrypto.sign(Buffer.from(canonical, "utf8"), opts.privateKeyPem);
  if (opts.audit !== false) {
    audit.safeEmit({
      action:   "aibom.signed",
      outcome:  "success",
      metadata: {
        modelName:    bom.metadata && bom.metadata.component && bom.metadata.component.name,
        modelVersion: bom.metadata && bom.metadata.component && bom.metadata.component.version,
        serialNumber: bom.serialNumber,
      },
    });
  }
  return Object.freeze({
    bom:       bom,
    signature: signature.toString("base64"),
  });
}

/**
 * @primitive b.ai.modelManifest.verify
 * @signature b.ai.modelManifest.verify(envelope, publicKeyPem, opts)
 * @since     0.10.8
 * @status    stable
 * @compliance eu-ai-act-art-11
 * @related   b.ai.modelManifest.sign
 *
 * Verify an envelope produced by `sign(bom, {...})`. Re-canonicalizes
 * the BOM with `canonicalJson.stringify` (NEVER trusts an embedded
 * "signedBytes" field — defends the CVE-2025-29774 / CVE-2025-29775
 * xml-crypto-style signature-substitution class) and checks the
 * signature with `b.crypto.verify` against the supplied public-key
 * PEM. Returns `{ valid, bom, reason }`; never throws.
 *
 * @opts
 *   audit:           boolean,        // default true
 *
 * @example
 *   var result = b.ai.modelManifest.verify(envelope, pair.publicKey);
 *   if (!result.valid) console.log(result.reason);
 */
function verify(envelope, publicKeyPem, opts) {
  opts = opts || {};
  if (!envelope || typeof envelope !== "object" || !envelope.bom || !envelope.signature) {
    return { valid: false, bom: null, reason: "envelope-shape" };
  }
  if (typeof publicKeyPem !== "string" || publicKeyPem.length === 0) {
    return { valid: false, bom: null, reason: "public-key-required" };
  }
  if (envelope.bom.specVersion !== SPEC_VERSION || envelope.bom.bomFormat !== BOM_FORMAT) {
    return { valid: false, bom: null, reason: "bom-spec-mismatch" };
  }
  var canonical = canonicalJson.stringify(envelope.bom);
  var sigBuf;
  try { sigBuf = Buffer.from(envelope.signature, "base64"); }
  catch (_e) { return { valid: false, bom: null, reason: "signature-base64-bad" }; }
  // `b.crypto.verify` can throw on malformed public-key PEM (Node's
  // crypto layer surfaces `DECODER routines::unsupported` and similar).
  // The documented contract here is `{ valid, bom, reason }` with no
  // throws — wrap so a hostile / mistyped key returns a structured
  // verdict instead of crashing the request path.
  var ok;
  try { ok = bCrypto.verify(Buffer.from(canonical, "utf8"), sigBuf, publicKeyPem); }
  catch (_e2) { return { valid: false, bom: null, reason: "public-key-malformed" }; }
  if (!ok) return { valid: false, bom: null, reason: "signature-invalid" };
  if (opts.audit !== false) {
    audit.safeEmit({
      action:   "aibom.verified",
      outcome:  "success",
      metadata: {
        modelName:    envelope.bom.metadata && envelope.bom.metadata.component &&
                      envelope.bom.metadata.component.name,
        serialNumber: envelope.bom.serialNumber,
      },
    });
  }
  return { valid: true, bom: envelope.bom, reason: null };
}

// UUIDv4 via the framework's CSPRNG path. Used for `serialNumber`
// defaults — operators may supply their own for cross-build stability.
function _uuidUrn() {
  var b = bCrypto.generateBytes(16);                                                            // RFC 9562 §4.1 UUIDv4 is a 16-byte (128-bit) primitive
  b[6] = (b[6] & 0x0f) | 0x40;                                                                  // UUIDv4 version nibble (RFC 9562 §4.4)
  b[8] = (b[8] & 0x3f) | 0x80;                                                                  // UUIDv4 variant nibble (RFC 9562 §4.4)
  var h = b.toString("hex");
  return "urn:uuid:" + h.slice(0, 8) + "-" + h.slice(8, 12) + "-" +                              // RFC 9562 §4 UUID text representation hex offsets (8-4-4-4-12)
         h.slice(12, 16) + "-" + h.slice(16, 20) + "-" + h.slice(20);                            // RFC 9562 §4 UUID hex offsets
}

// package.json read lives behind the call to dodge a circular-load
// chain: framework boot pulls index.js → ai-model-manifest → audit →
// db → framework-error → constants → package.json. Reading
// package.json at boot time would close the cycle. The lazy read is
// idempotent and the result is cached on first call.
var _cachedVersion = null;
function _frameworkVersion() {
  if (_cachedVersion) return _cachedVersion;
  try { _cachedVersion = require("../package.json").version; }                                  // allow:inline-require — lazy package-version read to avoid boot-time circular load
  catch (_e) { _cachedVersion = "0.0.0"; }
  return _cachedVersion;
}

module.exports = {
  build:               build,
  sign:                sign,
  verify:              verify,
  SPEC_VERSION:        SPEC_VERSION,
  BOM_FORMAT:          BOM_FORMAT,
  AiModelManifestError: AiModelManifestError,
};
