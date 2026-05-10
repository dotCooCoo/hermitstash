"use strict";
/**
 * @module b.guardAuth
 * @nav    Guards
 * @title  Guard Auth
 *
 * @intro
 *   Composite auth-bundle safety primitive (KIND="auth-bundle"). One
 *   gate that sequences `b.guardJwt` (bearer token), `b.guardOauth`
 *   (authorization-code / token-exchange flow shape), `b.cookies.parseSafe`
 *   (Cookie header), and a light request-header threat scan
 *   (Content-Length + Transfer-Encoding header smuggling per RFC 9112
 *   §6.1) into a single check operators wire into the request
 *   lifecycle. Consumes `ctx.authBundle`:
 *
 *     {
 *       jwtToken?:        string,    // routed to guardJwt
 *       oauthFlow?:       object,    // routed to guardOauth
 *       cookieHeader?:    string,    // routed to b.cookies.parseSafe
 *       requestHeaders?:  object,    // routed through threat detection
 *     }
 *
 *   Each sub-validator runs independently; aggregated issues carry a
 *   `source` field (`"jwt"` / `"oauth"` / `"cookies"` / `"headers"` /
 *   `"auth"`) tagging which sub-guard raised them so operators see
 *   the full failure surface in one verdict.
 *
 *   Refusal posture: stale-token / alg=none JWT / unknown OAuth grant /
 *   CL+TE header smuggling all surface as high-severity issues. Strict
 *   profile requires at least one auth input via `requireAtLeastOne` —
 *   a bundle with no jwtToken / oauthFlow / cookieHeader / requestHeaders
 *   is refused so operators don't accidentally ship an unauthenticated
 *   request through a gate they thought was active.
 *
 *   Profiles: `strict` / `balanced` / `permissive`. Compliance postures:
 *   `hipaa` / `pci-dss` / `gdpr` / `soc2`. Operators select via
 *   `{ profile: "strict" }` or `{ compliance: "hipaa" }`; postures
 *   overlay on the profile baseline.
 *
 * @card
 *   Composite auth-bundle safety primitive (KIND="auth-bundle").
 */

var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var guardJwt = require("./guard-jwt");
var guardOauth = require("./guard-oauth");
var cookies = require("./cookies");
var { GuardAuthError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardAuthError.factory;

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    bidiPolicy:        "reject",
    controlPolicy:     "reject",
    nullBytePolicy:    "reject",
    zeroWidthPolicy:   "reject",
    childProfile:      "strict",
    requireAtLeastOne: true,
    maxBytes:          C.BYTES.kib(64),
    maxRuntimeMs:      C.TIME.seconds(2),
  },
  "balanced": {
    bidiPolicy:        "reject",
    controlPolicy:     "reject",
    nullBytePolicy:    "reject",
    zeroWidthPolicy:   "reject",
    childProfile:      "balanced",
    requireAtLeastOne: false,
    maxBytes:          C.BYTES.kib(128),
    maxRuntimeMs:      C.TIME.seconds(2),
  },
  "permissive": {
    bidiPolicy:        "reject",                                                 // BIDI refused at every profile
    controlPolicy:     "reject",                                                  // controls refused at every profile
    nullBytePolicy:    "reject",                                                  // null refused at every profile
    zeroWidthPolicy:   "reject",                                                  // zero-width refused at every profile
    childProfile:      "permissive",
    requireAtLeastOne: false,
    maxBytes:          C.BYTES.kib(512),
    maxRuntimeMs:      C.TIME.seconds(2),
  },
});

var DEFAULTS = Object.freeze(Object.assign({}, PROFILES["strict"], {
  mode: "enforce",
}));

var COMPLIANCE_POSTURES = Object.freeze({
  "hipaa":   Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(512),
  }),
  "pci-dss": Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(512),
  }),
  "gdpr":    Object.assign({}, PROFILES["balanced"], {
    forensicSnippetBytes: C.BYTES.bytes(256),
  }),
  "soc2":    Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(1024),
  }),
});

function _resolveOpts(opts) {
  return gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardAuthError,
    errCodePrefix:      "auth",
  });
}

function _detectIssues(bundle, opts) {
  var issues = [];
  if (!bundle || typeof bundle !== "object") {
    return [{ kind: "bad-input", severity: "high",
              ruleId: "auth.bad-input", source: "auth",
              snippet: "auth bundle is not an object" }];
  }

  var sawAny = false;

  // JWT routing.
  if (typeof bundle.jwtToken === "string" && bundle.jwtToken.length > 0) {
    sawAny = true;
    var jwtRv = guardJwt.validate(bundle.jwtToken,
                                  { profile: opts.childProfile });
    for (var ji = 0; ji < jwtRv.issues.length; ji += 1) {
      issues.push(Object.assign({}, jwtRv.issues[ji], { source: "jwt" }));
    }
  }

  // OAuth routing.
  if (bundle.oauthFlow && typeof bundle.oauthFlow === "object") {
    sawAny = true;
    var oauthRv = guardOauth.validate(bundle.oauthFlow,
      Object.assign({ profile: opts.childProfile },
        opts.allowedRedirectUris ?
          { allowedRedirectUris: opts.allowedRedirectUris } : {}));
    for (var oi = 0; oi < oauthRv.issues.length; oi += 1) {
      issues.push(Object.assign({}, oauthRv.issues[oi], { source: "oauth" }));
    }
  }

  // Cookie-header threat detection.
  if (typeof bundle.cookieHeader === "string" && bundle.cookieHeader.length > 0) {
    sawAny = true;
    var ckRv = cookies.parseSafe(bundle.cookieHeader, {});
    for (var ci = 0; ci < ckRv.issues.length; ci += 1) {
      var iss = ckRv.issues[ci];
      issues.push({
        kind:     "cookie-" + iss.kind,
        severity: iss.severity,
        source:   "cookies",
        ruleId:   "auth.cookie-" + iss.kind,
        snippet:  iss.snippet,
      });
    }
  }

  // Request-header threat detection — light shape (CRLF / token-grammar
  // would otherwise be done by b.middleware.headers; here we sample
  // for the high-severity classes only).
  if (bundle.requestHeaders && typeof bundle.requestHeaders === "object") {
    sawAny = true;
    var rh = bundle.requestHeaders;
    if (rh["content-length"] !== undefined &&
        rh["transfer-encoding"] !== undefined) {
      issues.push({
        kind: "header-smuggling-cl-te", severity: "high",
        source: "headers", ruleId: "auth.header-smuggling-cl-te",
        snippet: "request carries both Content-Length and Transfer-" +
                 "Encoding (RFC 9112 §6.1 — CL.TE / TE.CL smuggling " +
                 "vector)",
      });
    }
  }

  if (opts.requireAtLeastOne && !sawAny) {
    issues.push({
      kind: "no-auth-input", severity: "high",
      source: "auth", ruleId: "auth.no-auth-input",
      snippet: "auth bundle has no jwtToken / oauthFlow / cookieHeader / " +
               "requestHeaders — strict requires at least one input",
    });
  }

  return issues;
}

/**
 * @primitive  b.guardAuth.validate
 * @signature  b.guardAuth.validate(input, opts?)
 * @since      0.7.41
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardAuth.sanitize, b.guardAuth.gate, b.guardJwt.validate, b.guardOauth.validate
 *
 * Inspect an auth-bundle object and return `{ ok, issues, summary }`.
 * Each issue carries `{ kind, severity, ruleId, source, snippet }`
 * with severity in `"warn"|"high"|"critical"` and `source` tagging
 * the sub-guard that raised it (`"jwt"` / `"oauth"` / `"cookies"` /
 * `"headers"` / `"auth"`). Pure inspection — never mutates input or
 * throws on hostile bundles.
 *
 * Strict profile sets `requireAtLeastOne: true` so an empty bundle
 * (no jwtToken / oauthFlow / cookieHeader / requestHeaders) emits a
 * `no-auth-input` issue — guards against an operator wiring a gate
 * onto a request that ships no credentials at all.
 *
 * @opts
 *   profile:           "strict"|"balanced"|"permissive",
 *   compliance:        "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   childProfile:      "strict"|"balanced"|"permissive",   // forwarded to guardJwt / guardOauth
 *   requireAtLeastOne: boolean,
 *   allowedRedirectUris: string[],   // forwarded to guardOauth
 *   maxBytes:          number,       // bundle JSON-byte cap
 *
 * @example
 *   var rv = b.guardAuth.validate({
 *     jwtToken: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.",
 *   }, { profile: "strict" });
 *   rv.ok;                                             // → false
 *   rv.issues.some(function (i) { return i.source === "jwt"; });   // → true
 */
function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes"],
    "guardAuth.validate", GuardAuthError, "auth.bad-opt");
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

/**
 * @primitive  b.guardAuth.sanitize
 * @signature  b.guardAuth.sanitize(input, opts?)
 * @since      0.7.41
 * @status     stable
 * @related    b.guardAuth.validate, b.guardAuth.gate
 *
 * Strict pass-through validator. The auth-bundle is composed of values
 * the framework cannot safely mutate (forging a JWT alg / rewriting an
 * OAuth state parameter / dropping cookies would be silently dangerous
 * — sanitize must never disarm an actual attack token), so this
 * function refuses (throws `GuardAuthError`) on any critical or high
 * issue and returns the input unchanged when clean.
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive",
 *   compliance: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *
 * @example
 *   var clean = b.guardAuth.sanitize({
 *     jwtToken: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9." +
 *               "eyJpc3MiOiJleGFtcGxlIiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjE3MDAwMDAwMDB9.sig",
 *     cookieHeader: "sid=abc123",
 *   }, { profile: "balanced" });
 *   clean.cookieHeader;                                // → "sid=abc123"
 */
function sanitize(input, opts) {
  opts = _resolveOpts(opts);
  if (!input || typeof input !== "object") {
    throw _err("auth.bad-input", "sanitize requires bundle object");
  }
  var issues = _detectIssues(input, opts);
  for (var i = 0; i < issues.length; i += 1) {
    if (issues[i].severity === "critical" || issues[i].severity === "high") {
      throw _err(issues[i].ruleId || "auth.refused",
        "guardAuth.sanitize [" + issues[i].source + "]: " +
        issues[i].snippet);
    }
  }
  return input;
}

/**
 * @primitive  b.guardAuth.gate
 * @signature  b.guardAuth.gate(opts?)
 * @since      0.7.41
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardAuth.validate, b.guardAuth.sanitize, b.middleware.bearerAuth
 *
 * Build a `b.gateContract` gate that consumes `ctx.authBundle` (or
 * `ctx.auth`) and dispatches to guardJwt / guardOauth / cookies /
 * header-smuggling detection. Action chain on validation:
 * `serve` (no bundle, or bundle clean) → `audit-only` (warn-only
 * issues) → `refuse` (any critical or high issue from any
 * sub-validator). No `sanitize` action — the auth bundle isn't
 * repairable in transit.
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive",
 *   compliance: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   name:       string,    // gate identity for audit / observability
 *   childProfile: "strict"|"balanced"|"permissive",
 *   allowedRedirectUris: string[],
 *
 * @example
 *   var authGate = b.guardAuth.gate({ profile: "strict" });
 *   var verdict = await authGate.check({ authBundle: {
 *     jwtToken: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.",
 *   } });
 *   verdict.action;                                    // → "refuse"
 */
function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardAuth:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var bundle = ctx && (ctx.authBundle || ctx.auth);
      if (!bundle) return { ok: true, action: "serve" };
      var rv = validate(bundle, opts);
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

/**
 * @primitive  b.guardAuth.buildProfile
 * @signature  b.guardAuth.buildProfile(opts)
 * @since      0.7.41
 * @status     stable
 * @related    b.guardAuth.gate, b.guardAuth.compliancePosture
 *
 * Compose a derived profile from one or more named bases plus inline
 * overrides. `opts.extends` is a profile name (`"strict"` /
 * `"balanced"` / `"permissive"`) or an array of names; later entries
 * shadow earlier ones. Inline `opts` keys win last. Used to keep
 * operator-defined profiles traceable to a baseline rather than
 * re-typing every key.
 *
 * @opts
 *   extends: string|string[],   // base profile name(s) to compose
 *
 * @example
 *   var custom = b.guardAuth.buildProfile({
 *     extends: "balanced",
 *     requireAtLeastOne: true,
 *   });
 *   custom.requireAtLeastOne;                          // → true
 *   custom.bidiPolicy;                                 // → "reject"
 */
var buildProfile = gateContract.makeProfileBuilder(PROFILES);

/**
 * @primitive  b.guardAuth.compliancePosture
 * @signature  b.guardAuth.compliancePosture(name)
 * @since      0.7.41
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardAuth.gate, b.guardAuth.buildProfile
 *
 * Look up a compliance-posture overlay by name (`"hipaa"` /
 * `"pci-dss"` / `"gdpr"` / `"soc2"`). Returns a shallow clone of the
 * posture object — the caller may mutate freely. Throws
 * `GuardAuthError("auth.bad-posture")` on unknown name.
 *
 * @example
 *   var posture = b.guardAuth.compliancePosture("hipaa");
 *   posture.forensicSnippetBytes;                      // → 512
 *   posture.bidiPolicy;                                // → "reject"
 */
function compliancePosture(name) {
  return gateContract.lookupCompliancePosture(name, COMPLIANCE_POSTURES,
    _err, "auth");
}

var _authRulePacks = gateContract.makeRulePackLoader(GuardAuthError, "auth");
/**
 * @primitive  b.guardAuth.loadRulePack
 * @signature  b.guardAuth.loadRulePack(pack)
 * @since      0.7.41
 * @status     stable
 * @related    b.guardAuth.gate
 *
 * Register an operator-supplied rule pack with the guard-auth
 * registry. The pack is identified by `pack.id` (non-empty string)
 * and stored for later inspection / dispatch by gates that opt in
 * via `opts.rulePackId`. Returns the pack object unchanged on
 * success; throws `GuardAuthError("auth.bad-opt")` when `pack` is
 * missing or `pack.id` is not a non-empty string.
 *
 * @example
 *   var pack = b.guardAuth.loadRulePack({
 *     id: "tenant-bearer-prefix",
 *     rules: [
 *       { id: "tenant-prefix", severity: "high",
 *         detect: function (b2) { return b2.jwtToken && b2.jwtToken.indexOf("tenant_") !== 0; },
 *         reason: "JWT does not carry the required tenant_ prefix" },
 *     ],
 *   });
 *   pack.id;                                           // → "tenant-bearer-prefix"
 */
var loadRulePack = _authRulePacks.load;

module.exports = {
  // ---- guard-* family registry exports ----
  NAME:                "auth",
  KIND:                "auth-bundle",
  INTEGRATION_FIXTURES: Object.freeze({
    kind:              "auth-bundle",
    benignBytes: Buffer.from(JSON.stringify({
      jwtToken: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9." +
                "eyJpc3MiOiJleGFtcGxlIiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjE3MDAwMDAwMDB9.sig",
      cookieHeader: "sid=abc123; theme=dark",
    }), "utf8"),
    hostileBytes: Buffer.from(JSON.stringify({
      jwtToken: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.",
    }), "utf8"),
    benignAuthBundle: {
      jwtToken: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9." +
                "eyJpc3MiOiJleGFtcGxlIiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjE3MDAwMDAwMDB9.sig",
      cookieHeader: "sid=abc123; theme=dark",
    },
    // Hostile: alg=none JWT — universal refuse routed through guardJwt.
    hostileAuthBundle: {
      jwtToken: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.",
    },
  }),
  // ---- primitive surface ----
  validate:            validate,
  sanitize:            sanitize,
  gate:                gate,
  buildProfile:        buildProfile,
  compliancePosture:   compliancePosture,
  loadRulePack:        loadRulePack,
  PROFILES:            PROFILES,
  DEFAULTS:            DEFAULTS,
  COMPLIANCE_POSTURES: COMPLIANCE_POSTURES,
  GuardAuthError:      GuardAuthError,
};
