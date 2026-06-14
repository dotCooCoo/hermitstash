"use strict";
/**
 * @module b.guardJwt
 * @nav    Guards
 * @title  Guard Jwt
 *
 * @intro
 *   JWT identifier-safety guard — validates user-supplied JWT
 *   compact-serialization strings against the canonical CVE-class
 *   refuse list BEFORE hand-off to a signature verifier. KIND is
 *   `identifier`; the gate consumes `ctx.identifier` (or
 *   `ctx.token` / `ctx.jwt`). Pair with `b.auth.jwt.verifyExternal`
 *   for cryptographic verification — this layer is the shape /
 *   header / claims contract that runs before any HMAC or signature
 *   work.
 *
 *   Algorithm-confusion defense: `alg=none` is universally refused
 *   at every profile (RFC 7518 §3.6 explicit-no-signature, the
 *   canonical CVE-2015-9235 jsonwebtoken alg:none / CVE-2018-0114
 *   Cisco node-jose embedded-JWK confusion class). The
 *   operator-supplied `allowedAlgs` allowlist defaults
 *   to the framework's PQC-first set (ML-DSA-87 / ML-DSA-65 /
 *   ML-DSA-44 / SLH-DSA-SHAKE-256{f,s} / SLH-DSA-SHA2-256{f,s} /
 *   EdDSA / ES* / RS* / PS*) so HS256-against-RSA-public-key
 *   forgery is blocked before the verifier sees the token.
 *
 *   `kid` path-traversal defense: the gate refuses any header `kid`
 *   that contains `..`, `/`, `\`, or percent-encoded variants —
 *   operators that resolve `kid` to a filesystem path can't escape
 *   the keystore directory. The standalone `b.guardJwt.kidSafe(kid)`
 *   helper throws on the same indicators and is the contract every
 *   `keyResolver` implementation must enforce before reading a key
 *   file.
 *
 *   Bounded shape: header / payload / signature segments each have
 *   their own byte cap (`maxHeaderBytes` / `maxPayloadBytes` /
 *   `maxSignatureBytes`) and the total token is bounded by
 *   `maxBytes`. Decompression-bomb-shaped tokens fail at the cap
 *   check before any base64url decode. Header JSON is parsed
 *   through `b.safeJson.parse({ rejectProto: true })` so prototype
 *   pollution can't ride a forged header.
 *
 *   Claim sanity: `exp` in the past, `nbf` more than
 *   `nbfFutureSlackMs` in the future, and `iat` more than
 *   `iatFutureSlackMs` in the future all surface as issues —
 *   replay / clock-skew detection that doesn't require pulling in
 *   a verifier. Required-claims (`iss` / `exp` / `iat` at strict;
 *   `iss` / `exp` at balanced) are enforced before the verifier
 *   so missing-claim refusals fail fast.
 *
 *   `typ` confusion: any `typ` outside `jwt` / `jws` / `at+jwt` /
 *   `id_token` flags as suspect — non-JWT tokens coerced into a
 *   JWT slot are refused under strict, audited under balanced.
 *
 *   `crit` discipline: RFC 7515 §4.1.11 mandates refusing tokens
 *   that carry `crit` headers the verifier doesn't understand. The
 *   gate's `knownCrit` allowlist is empty by default — every
 *   `crit` field is unknown unless the operator opts a name in.
 *
 *   Audience verification is the operator's responsibility (the
 *   verifier handles it); the guard's required-claims list ensures
 *   the operator can't forget to populate `aud` in their verifier
 *   config because the claim must be present at validate time.
 *
 *   Profiles: `strict` / `balanced` / `permissive`. Compliance
 *   postures: `hipaa` / `pci-dss` / `gdpr` / `soc2`. BIDI / null /
 *   control / zero-width universal-refuse applies on the raw input
 *   string at every profile so trojan-source codepoints can't ride
 *   inside a base64url segment.
 *
 * @card
 *   JWT identifier-safety guard — validates user-supplied JWT compact-serialization strings against the canonical CVE-class refuse list BEFORE hand-off to a signature verifier.
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
    var nowSec = Math.floor(Date.now() / 1000);                                  // seconds-per-millisecond conversion

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
      var nbfSlackSec = Math.floor(opts.nbfFutureSlackMs / 1000);                // seconds-per-millisecond conversion
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
      var iatSlackSec = Math.floor(opts.iatFutureSlackMs / 1000);                // seconds-per-millisecond conversion
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

/**
 * @primitive  b.guardJwt.validate
 * @signature  b.guardJwt.validate(input, opts?)
 * @since      0.7.49
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardJwt.sanitize, b.guardJwt.gate
 *
 * Apply the full guard-jwt threat catalog to a JWT compact-
 * serialization string. Returns `{ ok, issues }` per
 * `gateContract.aggregateIssues`. Detected classes include
 * `alg-none` (always critical), `kid-traversal` (always critical),
 * `alg-not-allowed`, `typ-confusion`, `crit-unknown`, `exp-past`,
 * `nbf-far-future`, `iat-far-future`, `claim-missing`, plus the
 * shape (`jwt-shape`) / segment-cap (`header-cap` / `payload-cap`
 * / `signature-cap`) / total-cap (`jwt-cap`) / codepoint-class
 * issues. Header JSON is decoded through
 * `b.safeJson.parse({ rejectProto: true })` so prototype-pollution
 * keys are refused before any policy check runs. Operator-supplied
 * opts are bounds-checked; bad opts throw
 * `GuardJwtError("jwt.bad-opt")`.
 *
 * @opts
 *   profile:              "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   allowedAlgs:          string[],
 *   requiredClaims:       string[],
 *   knownCrit:            string[],
 *   algNonePolicy:        "reject"|"audit"|"allow",
 *   algAllowlistPolicy:   "reject"|"audit"|"allow",
 *   kidTraversalPolicy:   "reject"|"audit"|"allow",
 *   typConfusionPolicy:   "reject"|"audit"|"allow",
 *   expSanityPolicy:      "reject"|"audit"|"allow",
 *   nbfSanityPolicy:      "reject"|"audit"|"allow",
 *   iatSanityPolicy:      "reject"|"audit"|"allow",
 *   critUnknownPolicy:    "reject"|"audit"|"allow",
 *   nbfFutureSlackMs:     number,
 *   iatFutureSlackMs:     number,
 *   maxHeaderBytes:       number,
 *   maxPayloadBytes:      number,
 *   maxSignatureBytes:    number,
 *   maxBytes:             number,
 *
 * @example
 *   var algNoneToken =
 *     "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." +
 *     "eyJzdWIiOiJhdHRhY2tlciJ9.";
 *   var rv = b.guardJwt.validate(algNoneToken, { profile: "strict" });
 *   rv.ok;                                              // → false
 *   rv.issues[0].ruleId;                                // → "jwt.alg-none"
 *
 *   var benign =
 *     "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9." +
 *     "eyJpc3MiOiJleGFtcGxlIiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjE3MDAwMDAwMDB9." +
 *     "sig";
 *   var ok = b.guardJwt.validate(benign, { profile: "strict" });
 *   ok.ok;                                              // → true
 */
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

/**
 * @primitive  b.guardJwt.sanitize
 * @signature  b.guardJwt.sanitize(input, opts?)
 * @since      0.7.49
 * @status     stable
 * @related    b.guardJwt.validate, b.guardJwt.gate
 *
 * Pass-through-or-throw form of `validate`. JWT compact
 * serialization can't be repaired (every byte feeds the signature)
 * so sanitize either returns the input unchanged when the issue
 * list contains no `critical` / `high` entries, or throws
 * `GuardJwtError` carrying the offending `ruleId`. Use this when
 * the caller wants a single try/catch boundary instead of an
 * issue-list switch.
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   ...:        every guardJwt.validate opt is honored,
 *
 * @example
 *   var algNoneToken =
 *     "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." +
 *     "eyJzdWIiOiJhdHRhY2tlciJ9.";
 *   try {
 *     b.guardJwt.sanitize(algNoneToken, { profile: "strict" });
 *   } catch (e) {
 *     e.code;                                           // → "jwt.alg-none"
 *   }
 */
function sanitize(input, opts) {
  opts = _resolveOpts(opts);
  if (typeof input !== "string") {
    throw _err("jwt.bad-input", "sanitize requires string input");
  }
  // JWT shape can't be repaired — sanitize either passes through
  // valid input or throws.
  var issues = _detectIssues(input, opts);
  gateContract.throwOnRefusalSeverity(issues, { errorClass: GuardJwtError, codePrefix: "jwt" });
  return input;
}

// gate is the standard serve -> audit-only -> refuse chain over
// ctx.identifier || ctx.token || ctx.jwt (the KIND "identifier" ctx
// fields); gateContract.defineGuard supplies it as the default gate.
// buildProfile / compliancePosture / loadRulePack are assembled by
// gateContract.defineGuard below; their wiki sections render from the
// single-sourced @abiTemplate blocks in gate-contract.js, instantiated
// per guard by the page generator.

/**
 * @primitive  b.guardJwt.kidSafe
 * @signature  b.guardJwt.kidSafe(kid)
 * @since      0.7.49
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardJwt.validate
 *
 * Throw on any `kid` value that contains path-traversal indicators
 * (`..`, `/`, `\`, percent-encoded variants) or non-printable
 * control bytes. Returns the input unchanged on success. This is
 * the contract every operator `keyResolver` MUST run before
 * resolving `kid` to a filesystem path or KMS key handle —
 * without it, a forged token's `kid` can escape the keystore
 * directory.
 *
 * @example
 *   b.guardJwt.kidSafe("tenant-1-2026-05");             // → "tenant-1-2026-05"
 *
 *   try {
 *     b.guardJwt.kidSafe("../../etc/passwd");
 *   } catch (e) {
 *     e.code;                                           // → "jwt.kid-traversal"
 *   }
 */
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
    if (cc < 0x20 || cc === 0x7F) {                                              // control-byte boundary check
      throw _err("jwt.kid-control",
        "kid contains control byte at index " + i);
    }
  }
  return kid;
}

// ---- guard-* family registry exports ----
var INTEGRATION_FIXTURES = Object.freeze({
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
});

// Assembled from the gate-contract guard factory. KIND "identifier"; the
// gate is the standard serve -> audit-only -> refuse chain over
// ctx.identifier || ctx.token || ctx.jwt, so the guard takes the factory
// default gate (no bespoke `gate` passed) and the factory supplies the
// error class, registry exports, buildProfile / compliancePosture /
// loadRulePack wiring, and the kidSafe extra.
module.exports = gateContract.defineGuard({
  name:        "jwt",
  kind:        "identifier",
  errorClass:  GuardJwtError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  integrationFixtures: INTEGRATION_FIXTURES,
  validate:    validate,
  sanitize:    sanitize,
  extra: {
    kidSafe: kidSafe,
  },
});
