"use strict";
/**
 * guard-jwt — JWT identifier-safety primitive (b.guardJwt).
 *
 * Validates user-supplied JWT compact-serialization strings against
 * the canonical CVE-class refuse list before hand-off to a verifier.
 * KIND="identifier" — consumes ctx.identifier (or ctx.token).
 *
 * Threat catalog:
 *   - Shape malformation — not 3 dot-separated base64url segments
 *     (RFC 7515 §3 / RFC 7519 §3 compact serialization).
 *   - alg=none — RFC 7518 §3.6 explicit "no signature" — universally
 *     refused; the canonical alg-confusion CVE class
 *     (CVE-2015-9235 jsonwebtoken; CVE-2018-0114 java-jwt).
 *   - alg algorithm-confusion — operator's verifier may treat HS256
 *     with an RSA public key as HMAC, allowing forgery; flag any
 *     unexpected alg.
 *   - kid path traversal — kid header used by some operators to
 *     resolve key files; `..` / `/` / null-byte in kid would escape
 *     the keystore directory.
 *   - typ confusion — typ != "jwt" / "JWT" / "JWS" indicates a non-
 *     JWT token coerced into the slot.
 *   - Oversized header / payload / signature — defense against
 *     decompression bombs and parser DoS.
 *   - exp / nbf / iat sanity — exp in the past, nbf in the far
 *     future, iat way in the future all indicate replay or clock-
 *     skew issues.
 *   - Unknown crit fields — RFC 7515 §4.1.11 — operator MUST refuse
 *     tokens carrying crit headers it doesn't understand.
 *   - BIDI / null / control / zero-width universal refuse.
 *
 *   var rv = b.guardJwt.validate(jwtString, { profile: "strict" });
 *   var g  = b.guardJwt.gate({ profile: "strict" });
 */

var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var safeJson = require("./safe-json");
var { GuardJwtError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardJwtError.factory;

// JWT compact serialization shape — three base64url segments separated
// by dots. base64url alphabet is A-Z / a-z / 0-9 / `-` / `_`.
var JWT_SHAPE_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;

// kid path-traversal indicators.
var KID_TRAVERSAL_RE = /\.\.|\/|\\|%2e%2e|%2f|%5c/i;

// Default operator-allowed alg list — PQC-first per the framework.
var DEFAULT_ALLOWED_ALGS = Object.freeze([
  "ML-DSA-87", "ML-DSA-65", "ML-DSA-44",
  "SLH-DSA-SHAKE-256f", "SLH-DSA-SHAKE-256s",
  "SLH-DSA-SHA2-256f", "SLH-DSA-SHA2-256s",
  "EdDSA", "ES256", "ES384", "ES512",
  "RS256", "RS384", "RS512",
  "PS256", "PS384", "PS512",
]);

function _b64urlDecodeJson(seg) {
  if (!seg) return null;
  var pad = (4 - (seg.length % 4)) % 4;
  var b64 = seg.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
  try {
    var json = Buffer.from(b64, "base64").toString("utf8");
    return safeJson.parse(json, { rejectProto: true });
  } catch (_e) {
    return null;
  }
}

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    bidiPolicy:           "reject",
    controlPolicy:        "reject",
    nullBytePolicy:       "reject",
    zeroWidthPolicy:      "reject",
    algNonePolicy:        "reject",
    algAllowlistPolicy:   "reject",
    kidTraversalPolicy:   "reject",
    typConfusionPolicy:   "reject",
    expSanityPolicy:      "reject",
    nbfSanityPolicy:      "reject",
    iatSanityPolicy:      "reject",
    critUnknownPolicy:    "reject",
    allowedAlgs:          DEFAULT_ALLOWED_ALGS,
    requiredClaims:       ["iss", "exp", "iat"],
    knownCrit:            [],                                                    // empty — every crit field is unknown by default
    nbfFutureSlackMs:     C.TIME.minutes(5),
    iatFutureSlackMs:     C.TIME.minutes(5),
    maxHeaderBytes:       C.BYTES.kib(2),
    maxPayloadBytes:      C.BYTES.kib(8),
    maxSignatureBytes:    C.BYTES.kib(4),
    maxBytes:             C.BYTES.kib(16),
    maxRuntimeMs:         C.TIME.seconds(2),
  },
  "balanced": {
    bidiPolicy:           "reject",
    controlPolicy:        "reject",
    nullBytePolicy:       "reject",
    zeroWidthPolicy:      "reject",
    algNonePolicy:        "reject",                                              // alg=none refused at every profile
    algAllowlistPolicy:   "audit",
    kidTraversalPolicy:   "reject",                                              // kid traversal refused at every profile
    typConfusionPolicy:   "audit",
    expSanityPolicy:      "audit",
    nbfSanityPolicy:      "audit",
    iatSanityPolicy:      "audit",
    critUnknownPolicy:    "reject",                                              // unknown crit refused at every profile (RFC 7515)
    allowedAlgs:          DEFAULT_ALLOWED_ALGS,
    requiredClaims:       ["iss", "exp"],
    knownCrit:            [],
    nbfFutureSlackMs:     C.TIME.minutes(15),
    iatFutureSlackMs:     C.TIME.minutes(15),
    maxHeaderBytes:       C.BYTES.kib(2),
    maxPayloadBytes:      C.BYTES.kib(32),
    maxSignatureBytes:    C.BYTES.kib(8),
    maxBytes:             C.BYTES.kib(64),
    maxRuntimeMs:         C.TIME.seconds(2),
  },
  "permissive": {
    bidiPolicy:           "reject",                                              // BIDI refused at every profile
    controlPolicy:        "reject",                                              // controls refused at every profile
    nullBytePolicy:       "reject",                                              // null refused at every profile
    zeroWidthPolicy:      "reject",                                              // zero-width refused at every profile
    algNonePolicy:        "reject",                                              // alg=none refused at every profile
    algAllowlistPolicy:   "allow",
    kidTraversalPolicy:   "reject",                                              // kid traversal refused at every profile
    typConfusionPolicy:   "audit",
    expSanityPolicy:      "audit",
    nbfSanityPolicy:      "audit",
    iatSanityPolicy:      "audit",
    critUnknownPolicy:    "reject",                                              // unknown crit refused at every profile
    allowedAlgs:          null,
    requiredClaims:       [],
    knownCrit:            [],
    nbfFutureSlackMs:     C.TIME.hours(1),
    iatFutureSlackMs:     C.TIME.hours(1),
    maxHeaderBytes:       C.BYTES.kib(4),
    maxPayloadBytes:      C.BYTES.kib(64),
    maxSignatureBytes:    C.BYTES.kib(16),
    maxBytes:             C.BYTES.kib(128),
    maxRuntimeMs:         C.TIME.seconds(2),
  },
});

var DEFAULTS = Object.freeze(Object.assign({}, PROFILES["strict"], {
  mode: "enforce",
}));

var COMPLIANCE_POSTURES = Object.freeze({
  "hipaa":   Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(256),
  }),
  "pci-dss": Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(256),
  }),
  "gdpr":    Object.assign({}, PROFILES["balanced"], {
    forensicSnippetBytes: C.BYTES.bytes(128),
  }),
  "soc2":    Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(512),
  }),
});

function _resolveOpts(opts) {
  return gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardJwtError,
    errCodePrefix:      "jwt",
  });
}

function _detectIssues(input, opts) {
  var issues = [];
  if (typeof input !== "string") {
    return [{ kind: "bad-input", severity: "high",
              ruleId: "jwt.bad-input",
              snippet: "jwt is not a string" }];
  }
  if (input.length === 0) {
    return [{ kind: "empty", severity: "high",
              ruleId: "jwt.empty",
              snippet: "jwt is empty" }];
  }
  if (Buffer.byteLength(input, "utf8") > opts.maxBytes) {
    return [{ kind: "jwt-cap", severity: "high",
              ruleId: "jwt.jwt-cap",
              snippet: "jwt input exceeds maxBytes " + opts.maxBytes }];
  }

  var charThreats = codepointClass.detectCharThreats(input, opts, "jwt");
  for (var ci = 0; ci < charThreats.length; ci += 1) issues.push(charThreats[ci]);

  if (!JWT_SHAPE_RE.test(input)) {                                               // allow:regex-no-length-cap — input bounded by maxBytes
    issues.push({
      kind: "jwt-shape", severity: "high",
      ruleId: "jwt.jwt-shape",
      snippet: "input does not match JWT compact-serialization shape " +
               "(three base64url segments separated by dots)",
    });
    return issues;
  }

  var segments = input.split(".");
  var headerSeg = segments[0];
  var payloadSeg = segments[1];
  var signatureSeg = segments[2];

  if (Buffer.byteLength(headerSeg, "utf8") > opts.maxHeaderBytes) {
    issues.push({
      kind: "header-cap", severity: "high",
      ruleId: "jwt.header-cap",
      snippet: "JWT header segment exceeds maxHeaderBytes " +
               opts.maxHeaderBytes,
    });
  }
  if (Buffer.byteLength(payloadSeg, "utf8") > opts.maxPayloadBytes) {
    issues.push({
      kind: "payload-cap", severity: "high",
      ruleId: "jwt.payload-cap",
      snippet: "JWT payload segment exceeds maxPayloadBytes " +
               opts.maxPayloadBytes,
    });
  }
  if (Buffer.byteLength(signatureSeg, "utf8") > opts.maxSignatureBytes) {
    issues.push({
      kind: "signature-cap", severity: "high",
      ruleId: "jwt.signature-cap",
      snippet: "JWT signature segment exceeds maxSignatureBytes " +
               opts.maxSignatureBytes,
    });
  }

  var header = _b64urlDecodeJson(headerSeg);
  if (!header || typeof header !== "object") {
    issues.push({
      kind: "header-decode", severity: "high",
      ruleId: "jwt.header-decode",
      snippet: "JWT header is not decodable JSON or contains " +
               "prototype-pollution keys",
    });
    return issues;
  }

  // alg=none — universal refuse.
  if (typeof header.alg === "string" &&
      header.alg.toLowerCase() === "none") {
    issues.push({
      kind: "alg-none", severity: "critical",
      ruleId: "jwt.alg-none",
      snippet: "JWT header alg=none — RFC 7518 §3.6 explicit-no-signature; " +
               "canonical CVE-class refuse",
    });
  }
  // alg allowlist enforcement.
  if (opts.algAllowlistPolicy !== "allow" &&
      opts.allowedAlgs && Array.isArray(opts.allowedAlgs)) {
    if (typeof header.alg !== "string" ||
        opts.allowedAlgs.indexOf(header.alg) === -1) {
      issues.push({
        kind: "alg-not-allowed",
        severity: opts.algAllowlistPolicy === "reject" ? "high" : "warn",
        ruleId: "jwt.alg-not-allowed",
        snippet: "JWT alg `" + (header.alg || "<missing>") + "` not in " +
                 "operator allowlist (" + opts.allowedAlgs.length +
                 " entries)",
      });
    }
  }

  // kid path-traversal.
  if (typeof header.kid === "string" &&
      opts.kidTraversalPolicy !== "allow" &&
      KID_TRAVERSAL_RE.test(header.kid)) {                                       // allow:regex-no-length-cap — header object size bounded by maxHeaderBytes
    issues.push({
      kind: "kid-traversal", severity: "critical",
      ruleId: "jwt.kid-traversal",
      snippet: "JWT kid `" + header.kid + "` contains path-traversal " +
               "indicators (`..`, `/`, `\\`, percent-encoded forms) — " +
               "operator keyResolver MUST sanitize before file-system " +
               "use",
    });
  }

  // typ confusion.
  if (typeof header.typ === "string" &&
      opts.typConfusionPolicy !== "allow") {
    var typLow = header.typ.toLowerCase();
    if (typLow !== "jwt" && typLow !== "jws" && typLow !== "at+jwt" &&
        typLow !== "id_token") {
      issues.push({
        kind: "typ-confusion",
        severity: opts.typConfusionPolicy === "reject" ? "high" : "warn",
        ruleId: "jwt.typ-confusion",
        snippet: "JWT typ `" + header.typ + "` is not a known JWT-shape " +
                 "media-type token",
      });
    }
  }

  // Unknown crit fields.
  if (Array.isArray(header.crit) && opts.critUnknownPolicy !== "allow") {
    var known = opts.knownCrit || [];
    for (var ki = 0; ki < header.crit.length; ki += 1) {
      var c = header.crit[ki];
      if (known.indexOf(c) === -1) {
        issues.push({
          kind: "crit-unknown",
          severity: opts.critUnknownPolicy === "reject" ? "high" : "warn",
          ruleId: "jwt.crit-unknown",
          snippet: "JWT crit `" + c + "` is not in operator's knownCrit " +
                   "allowlist (RFC 7515 §4.1.11 requires refusing unknown crit)",
        });
      }
    }
  }

  // Payload claim sanity (only if payload is decodable).
  var payload = _b64urlDecodeJson(payloadSeg);
  if (payload && typeof payload === "object") {
    var nowSec = Math.floor(Date.now() / 1000);                                  // allow:raw-byte-literal — seconds-per-millisecond conversion

    // exp in the past.
    if (typeof payload.exp === "number" &&
        opts.expSanityPolicy !== "allow") {
      if (payload.exp < nowSec) {
        issues.push({
          kind: "exp-past",
          severity: opts.expSanityPolicy === "reject" ? "high" : "warn",
          ruleId: "jwt.exp-past",
          snippet: "JWT exp " + payload.exp + " is in the past " +
                   "(now=" + nowSec + ")",
        });
      }
    }

    // nbf far-future.
    if (typeof payload.nbf === "number" &&
        opts.nbfSanityPolicy !== "allow") {
      var nbfSlackSec = Math.floor(opts.nbfFutureSlackMs / 1000);                // allow:raw-byte-literal — seconds-per-millisecond conversion
      if (payload.nbf > nowSec + nbfSlackSec) {
        issues.push({
          kind: "nbf-far-future",
          severity: opts.nbfSanityPolicy === "reject" ? "high" : "warn",
          ruleId: "jwt.nbf-far-future",
          snippet: "JWT nbf " + payload.nbf + " is more than " +
                   nbfSlackSec + " seconds in the future",
        });
      }
    }

    // iat far-future.
    if (typeof payload.iat === "number" &&
        opts.iatSanityPolicy !== "allow") {
      var iatSlackSec = Math.floor(opts.iatFutureSlackMs / 1000);                // allow:raw-byte-literal — seconds-per-millisecond conversion
      if (payload.iat > nowSec + iatSlackSec) {
        issues.push({
          kind: "iat-far-future",
          severity: opts.iatSanityPolicy === "reject" ? "high" : "warn",
          ruleId: "jwt.iat-far-future",
          snippet: "JWT iat " + payload.iat + " is more than " +
                   iatSlackSec + " seconds in the future",
        });
      }
    }

    // Required claims.
    if (Array.isArray(opts.requiredClaims)) {
      for (var rci = 0; rci < opts.requiredClaims.length; rci += 1) {
        var c2 = opts.requiredClaims[rci];
        if (payload[c2] === undefined) {
          issues.push({
            kind: "claim-missing", severity: "high",
            ruleId: "jwt.claim-missing",
            snippet: "JWT payload missing required claim `" + c2 + "`",
          });
        }
      }
    }
  }

  return issues;
}

function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes", "maxHeaderBytes", "maxPayloadBytes", "maxSignatureBytes",
     "nbfFutureSlackMs", "iatFutureSlackMs"],
    "guardJwt.validate", GuardJwtError, "jwt.bad-opt");
  if (typeof input !== "string") {
    return {
      ok: false,
      issues: [{ kind: "bad-input", severity: "high",
                 ruleId: "jwt.bad-input",
                 snippet: "jwt is not a string" }],
    };
  }
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

function sanitize(input, opts) {
  opts = _resolveOpts(opts);
  if (typeof input !== "string") {
    throw _err("jwt.bad-input", "sanitize requires string input");
  }
  // JWT shape can't be repaired — sanitize either passes through
  // valid input or throws.
  var issues = _detectIssues(input, opts);
  for (var i = 0; i < issues.length; i += 1) {
    if (issues[i].severity === "critical" || issues[i].severity === "high") {
      throw _err(issues[i].ruleId || "jwt.refused",
        "guardJwt.sanitize: " + issues[i].snippet);
    }
  }
  return input;
}

function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardJwt:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var identifier = ctx && (ctx.identifier || ctx.token || ctx.jwt || "");
      if (!identifier) return { ok: true, action: "serve" };
      var rv = validate(identifier, opts);
      if (rv.issues.length === 0) return { ok: true, action: "serve" };
      var hasCritical = rv.issues.some(function (i) {
        return i.severity === "critical";
      });
      var hasHigh = rv.issues.some(function (i) {
        return i.severity === "high";
      });
      if (!hasCritical && !hasHigh) {
        return { ok: true, action: "audit-only", issues: rv.issues };
      }
      return { ok: false, action: "refuse", issues: rv.issues };
    });
}

var buildProfile = gateContract.makeProfileBuilder(PROFILES);

function compliancePosture(name) {
  return gateContract.lookupCompliancePosture(name, COMPLIANCE_POSTURES,
    _err, "jwt");
}

var _jwtRulePacks = gateContract.makeRulePackLoader(GuardJwtError, "jwt");
var loadRulePack = _jwtRulePacks.load;

// Operator helper — `kidSafe(kid)` throws on traversal indicators.
// Documented as the contract for keyResolver implementations.
function kidSafe(kid) {
  if (typeof kid !== "string" || kid.length === 0) {
    throw _err("jwt.kid-empty", "kid must be a non-empty string");
  }
  if (KID_TRAVERSAL_RE.test(kid)) {                                              // allow:regex-no-length-cap — operator-supplied kid; bounded by upstream JWT size cap
    throw _err("jwt.kid-traversal",
      "kid `" + kid + "` contains path-traversal indicators");
  }
  for (var i = 0; i < kid.length; i += 1) {
    var cc = kid.charCodeAt(i);
    if (cc < 0x20 || cc === 0x7F) {                                              // allow:raw-byte-literal — control-byte boundary check
      throw _err("jwt.kid-control",
        "kid contains control byte at index " + i);
    }
  }
  return kid;
}

module.exports = {
  // ---- guard-* family registry exports ----
  NAME:                "jwt",
  KIND:                "identifier",
  INTEGRATION_FIXTURES: Object.freeze({
    kind:              "identifier",
    // Benign: minimal v4 token with alg=ES256, valid JSON header / payload.
    benignBytes: Buffer.from(
      "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9." +
      "eyJpc3MiOiJleGFtcGxlIiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjE3MDAwMDAwMDB9." +
      "sig", "utf8"),
    benignIdentifier:
      "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9." +
      "eyJpc3MiOiJleGFtcGxlIiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjE3MDAwMDAwMDB9." +
      "sig",
    // Hostile: alg=none — universal refuse class.
    hostileBytes: Buffer.from(
      "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." +
      "eyJzdWIiOiJhdHRhY2tlciIsImV4cCI6OTk5OTk5OTk5OX0.", "utf8"),
    hostileIdentifier:
      "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." +
      "eyJzdWIiOiJhdHRhY2tlciIsImV4cCI6OTk5OTk5OTk5OX0.",
  }),
  // ---- primitive surface ----
  validate:            validate,
  sanitize:            sanitize,
  gate:                gate,
  kidSafe:             kidSafe,
  buildProfile:        buildProfile,
  compliancePosture:   compliancePosture,
  loadRulePack:        loadRulePack,
  PROFILES:            PROFILES,
  DEFAULTS:            DEFAULTS,
  COMPLIANCE_POSTURES: COMPLIANCE_POSTURES,
  GuardJwtError:       GuardJwtError,
};
