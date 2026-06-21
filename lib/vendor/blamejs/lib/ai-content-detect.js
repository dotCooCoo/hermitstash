"use strict";
/**
 * @module b.ai.aiContentDetect
 * @nav    AI
 * @title  AI Content Detection
 *
 * @intro
 *   Inbound-asset provenance detector. Counterpart to the outbound
 *   `b.contentCredentials` seal path: the operator extracts whatever
 *   provenance metadata their format-specific muxer surfaces
 *   (C2PA-COSE envelope from JPEG XMP / PNG iTXt / MP4 boxes, CAC
 *   implicit-label JSON from the embedded metadata block, IPTC
 *   `digitalSourceType` when an IPTC PhotoMetadata reader is wired),
 *   feeds them to `report({...})`, and renders the normalized result
 *   in their user-facing UI. California AB-853 §22757.21 requires the
 *   disclosure; the framework owns the validation + trust-list anchor
 *   layer, the application owns the rendering.
 *
 *   Trust-list anchored: the operator declares which signer subjects
 *   are acceptable. Default trust list is empty — the framework does
 *   not ship a curated CA list. Operators that want a one-line ramp
 *   point at the public C2PA Trust List per
 *   https://opensource.contentauthenticity.org/docs/trust-list.
 *
 *   Posture vocabulary: `strict` (refuse on signature invalid, refuse
 *   on signer not on trust list), `balanced` (refuse on cryptographic
 *   tamper, audit-only on missing provenance), `permissive`
 *   (audit-only across the board). Default `balanced`.
 *
 *   IPTC `digitalSourceType` PhotoMetadata reading is forward-watch —
 *   the framework ships no XMP / EXIF parser yet, so operators that
 *   want IPTC detection pre-parse with their tool of choice and pass
 *   the field via `opts.ipmd`. AB-853 names C2PA as "widely adopted".
 *   A built-in IPTC PhotoMetadata reader is deferred pending a vendoring
 *   decision for an XMP/EXIF parser; the `opts.ipmd` escape hatch covers
 *   the gap until then.
 *
 * @card
 *   Inbound provenance detector — composes C2PA verify + CAC implicit-label parser + operator-supplied IPTC field, returns a normalized report for AB-853 / EU AI Act Art. 50 / CAC disclosure UIs.
 */

var lazyRequire = require("./lazy-require");
var contentCredentials = lazyRequire(function () { return require("./content-credentials"); });
var audit = require("./audit");
var { defineClass } = require("./framework-error");
var gateContract = require("./gate-contract");

var AiContentDetectError = defineClass("AiContentDetectError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "balanced";
var PROFILES = Object.freeze({
  strict:     { refuseUnsigned: true,  refuseUnpinned: true,  auditOnly: false },
  balanced:   { refuseUnsigned: false, refuseUnpinned: false, auditOnly: false },
  permissive: { refuseUnsigned: false, refuseUnpinned: false, auditOnly: true },
});

var COMPLIANCE_POSTURES = Object.freeze({
  "ca-ab-853":          "strict",
  "ca-sb-942":          "strict",
  "eu-ai-act-art-50":   "strict",
  "cac-genai-label":    "strict",
  "nist-ai-600-1":      "balanced",
  "iso-42001":          "balanced",
  "iso-23894":          "balanced",
  "nist-ai-rmf":        "balanced",
});

var _resolveProfile = gateContract.makeProfileResolver({
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  defaults:   DEFAULT_PROFILE,
  errorClass: AiContentDetectError,
  codePrefix: "ai-content-detect",
  byObject:   true,
});

/**
 * @primitive b.ai.aiContentDetect.report
 * @signature b.ai.aiContentDetect.report(opts)
 * @since     0.10.8
 * @status    stable
 * @compliance ca-ab-853, ca-sb-942, eu-ai-act-art-50, cac-genai-label, nist-ai-600-1, iso-42001, iso-23894, nist-ai-rmf
 * @related   b.contentCredentials.verify, b.contentCredentials.cacImplicitLabelRead
 *
 * Build a normalized `provenanceReport` from the provenance artifacts
 * an operator's muxer extracted from an inbound asset. At least one
 * of `c2paEnvelope`, `cacImplicitLabel`, or `ipmd` must be supplied;
 * absence of all three returns `kind: "none"` with `verified: false`.
 *
 * @opts
 *   c2paEnvelope:       object,         // { manifest, signature } from operator's C2PA extractor
 *   c2paPublicKeyPem:   string,         // PEM for verify (operator-pinned signer key)
 *   cacImplicitLabel:   Buffer|string|object, // GB 45438-2025 implicit metadata block
 *   ipmd:               object,         // IPTC PhotoMetadata digitalSourceType field (operator-pre-parsed)
 *   trustList:          string[],       // acceptable signer subject identifiers
 *   profile:            "strict"|"balanced"|"permissive",
 *   posture:            string,         // pins profile per posture vocabulary
 *
 * @example
 *   var report = b.ai.aiContentDetect.report({
 *     c2paEnvelope: env, c2paPublicKeyPem: pem,
 *     trustList: ["CN=Acme AI, O=Acme, C=US"],
 *     posture: "ca-ab-853",
 *   });
 *   report.kind;     // → "c2pa"
 *   report.verified; // → true if signature OK and signer on trustList
 */
function report(opts) {
  opts = opts || {};
  var profile = _resolveProfile(opts);
  var trustList = Array.isArray(opts.trustList) ? opts.trustList.slice() : [];
  var alerts = [];

  var has = {
    c2pa: opts.c2paEnvelope && typeof opts.c2paEnvelope === "object",
    cac:  opts.cacImplicitLabel !== undefined && opts.cacImplicitLabel !== null,
    ipmd: opts.ipmd && typeof opts.ipmd === "object",
  };
  if (!has.c2pa && !has.cac && !has.ipmd) {
    if (profile.refuseUnsigned) {
      throw new AiContentDetectError("ai-content-detect/no-provenance",
        "report: strict profile requires at least one provenance artifact " +
        "(c2paEnvelope, cacImplicitLabel, or ipmd) — got none");
    }
    var out = {
      kind: "none", verified: false, alerts: ["no-provenance"], rawDisclosure: null,
    };
    if (!profile.auditOnly) {
      try {
        audit.safeEmit({
          action: "aicontentdetect.report", outcome: "denied",
          metadata: { kind: "none", reason: "no-provenance" },
        });
      } catch (_e) { /* drop-silent */ }
    }
    return Object.freeze(out);
  }

  var verified = false;
  var kind = "none";
  var manifest = null;
  var signerSubject = null;
  var signedAt = null;
  var cacLabel = null;
  var ipmd = null;

  if (has.c2pa) {
    kind = "c2pa";
    var keyMissing = typeof opts.c2paPublicKeyPem !== "string" || opts.c2paPublicKeyPem.length === 0;
    if (keyMissing) {
      // Strict refuses outright on a missing key — caller cannot
      // produce a verified disclosure without it, so the report
      // would be useless under the AB-853 / EU AI Act Art. 50
      // posture cascade.
      if (profile.refuseUnsigned) {
        throw new AiContentDetectError("ai-content-detect/c2pa-public-key-missing",
          "report: strict profile requires c2paPublicKeyPem when c2paEnvelope is supplied");
      }
      alerts.push("c2pa-public-key-missing");
    } else {
      var v = contentCredentials().verify(opts.c2paEnvelope, opts.c2paPublicKeyPem, { audit: false });
      if (v.valid) {
        verified = true;
        manifest = v.claims;
        signerSubject = opts.c2paEnvelope.signerSubject ||
                        (v.claims && v.claims.signer && v.claims.signer.subject) || null;
        signedAt = (v.claims && v.claims.signedAt) || null;
      } else {
        // Strict refuses on cryptographic-verify failure — a tampered
        // or signature-invalid envelope MUST NOT produce a
        // disclosure object the caller might surface as anything
        // other than "refused." The append-alert-and-continue path
        // is the balanced / permissive shape; strict throws.
        if (profile.refuseUnsigned) {
          throw new AiContentDetectError("ai-content-detect/c2pa-verify-failed",
            "report: strict profile refuses tampered / invalid C2PA envelope (" +
            v.reason + ")");
        }
        alerts.push("c2pa-verify-failed:" + v.reason);
      }
    }
    if (verified && trustList.length > 0) {
      if (!signerSubject || trustList.indexOf(signerSubject) === -1) {
        if (profile.refuseUnpinned) {
          throw new AiContentDetectError("ai-content-detect/signer-not-on-trust-list",
            "report: signer '" + (signerSubject || "(unknown)") +
            "' is not on the operator-supplied trust list");
        }
        verified = false;
        alerts.push("signer-not-on-trust-list");
      }
    } else if (verified && trustList.length === 0) {
      alerts.push("trust-list-empty");
    }
  }

  if (has.cac) {
    try { cacLabel = contentCredentials().cacImplicitLabelRead(opts.cacImplicitLabel); }
    catch (e) {
      alerts.push("cac-label-parse-failed:" + (e && e.code));
    }
    if (cacLabel && kind === "none") kind = "cac";
  }

  if (has.ipmd) {
    ipmd = Object.freeze(Object.assign({}, opts.ipmd));
    if (kind === "none") kind = "iptc";
  }

  var rawDisclosure = {
    c2pa:  has.c2pa ? { manifest: manifest, signerSubject: signerSubject, signedAt: signedAt } : null,
    cac:   cacLabel,
    iptc:  ipmd,
  };

  if (!profile.auditOnly) {
    try {
      audit.safeEmit({
        action: "aicontentdetect.report",
        outcome: verified ? "success" : "warning",
        metadata: {
          kind:           kind,
          verified:       verified,
          signerSubject:  signerSubject,
          alerts:         alerts.slice(),
        },
      });
    } catch (_e) { /* drop-silent */ }
  }

  return Object.freeze({
    kind:          kind,
    verified:      verified,
    manifest:      manifest,
    signerSubject: signerSubject,
    signedAt:      signedAt,
    cacLabel:      cacLabel,
    ipmd:          ipmd,
    alerts:        Object.freeze(alerts),
    rawDisclosure: Object.freeze(rawDisclosure),
  });
}

/**
 * @primitive b.ai.aiContentDetect.compliancePosture
 * @signature b.ai.aiContentDetect.compliancePosture(posture)
 * @since     0.10.8
 * @status    stable
 *
 * Return the effective profile name (`strict` / `balanced` /
 * `permissive`) for a compliance posture, or `null` for unknown
 * posture names. Operators introspect the cascade before wiring
 * default-on paths.
 *
 * @example
 *   b.ai.aiContentDetect.compliancePosture("ca-ab-853"); // → "strict"
 */
var compliancePosture = gateContract.makePostureAccessor(COMPLIANCE_POSTURES);

module.exports = {
  report:               report,
  compliancePosture:    compliancePosture,
  PROFILES:             PROFILES,
  COMPLIANCE_POSTURES:  COMPLIANCE_POSTURES,
  AiContentDetectError: AiContentDetectError,
};
