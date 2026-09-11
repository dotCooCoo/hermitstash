// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
 *   `{ profile: "strict" }` or `{ compliancePosture: "hipaa" }`; postures
 *   overlay on the profile baseline.
 *
 * @card
 *   Composite auth-bundle safety primitive (KIND="auth-bundle").
 */

var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var guardJwt = require("./guard-jwt");
var guardOauth = require("./guard-oauth");
var cookies = require("./cookies");
var { GuardAuthError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var OAUTH_FORWARDED_OPTS = Object.freeze([
  "compliancePosture",
  "pkcePolicy",
  "statePolicy",
  "redirectUriPolicy",
  "responseTypePolicy",
  "scopeTamperingPolicy",
  "issuerOnCallbackPolicy",
  "codeReusePolicy",
  "allowedRedirectUris",
  "allowedResponseTypes",
  "seenCodeStore",
  "maxParamBytes",
  "bidiPolicy",
  "controlPolicy",
  "nullBytePolicy",
  "zeroWidthPolicy",
]);

function _forwardOauthOpts(opts) {
  var out = { profile: opts.childProfile };
  if (Object.prototype.hasOwnProperty.call(opts, "oauthMaxBytes") &&
      opts.oauthMaxBytes !== undefined) {
    out.maxBytes = opts.oauthMaxBytes;
  }
  for (var i = 0; i < OAUTH_FORWARDED_OPTS.length; i += 1) {
    var k = OAUTH_FORWARDED_OPTS[i];
    if (Object.prototype.hasOwnProperty.call(opts, k) && opts[k] !== undefined) {
      out[k] = opts[k];
    }
  }
  return out;
}

var PROFILES = Object.freeze({
  "strict": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    childProfile:      "strict",
    requireAtLeastOne: true,
    maxBytes:          C.BYTES.kib(64),
    maxRuntimeMs:      C.TIME.seconds(2),
  },
  "balanced": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    childProfile:      "balanced",
    requireAtLeastOne: false,
    maxBytes:          C.BYTES.kib(128),
    maxRuntimeMs:      C.TIME.seconds(2),
  },
  "permissive": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    childProfile:      "permissive",
    requireAtLeastOne: false,
    maxBytes:          C.BYTES.kib(512),
    maxRuntimeMs:      C.TIME.seconds(2),
  },
});

function _detectIssues(bundle, opts) {
  var issues = [];
  if (!bundle || typeof bundle !== "object") {
    return [{ kind: "bad-input", severity: "high",
              ruleId: "auth.bad-input", source: "auth",
              snippet: "auth bundle is not an object" }];
  }

  var sawAny = false;

  if (typeof bundle.jwtToken === "string" && bundle.jwtToken.length > 0) {
    sawAny = true;
    var jwtRv = guardJwt.validate(bundle.jwtToken,
                                  { profile: opts.childProfile });
    for (var ji = 0; ji < jwtRv.issues.length; ji += 1) {
      issues.push(Object.assign({}, jwtRv.issues[ji], { source: "jwt" }));
    }
  }

  if (bundle.oauthFlow && typeof bundle.oauthFlow === "object") {
    sawAny = true;
    var oauthRv = guardOauth.validate(bundle.oauthFlow,
      _forwardOauthOpts(opts));
    for (var oi = 0; oi < oauthRv.issues.length; oi += 1) {
      issues.push(Object.assign({}, oauthRv.issues[oi], { source: "oauth" }));
    }
  }

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
 * Inspect an auth-bundle object and return `{ ok, issues }`.
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
 * When an `oauthFlow` is present every `b.guardOauth` option is forwarded to
 * it — `seenCodeStore` and `codeReusePolicy` included, which its code-replay
 * check needs to be satisfiable through this wrapper, and the character
 * policies (`bidiPolicy`, `controlPolicy`, `nullBytePolicy`,
 * `zeroWidthPolicy`) it applies to every parameter.
 *
 * `compliancePosture` is forwarded too, and the child applies its own
 * precedence to it — a posture overlays the profile there, so
 * `{ compliancePosture: "hipaa", childProfile: "permissive" }` is checked under
 * hipaa, exactly as the same pair would be by a direct `b.guardOauth` call. The
 * wrapper does not re-decide that: an option means the same thing whichever
 * entry point you use it from.
 *
 * The exception is `maxBytes`, which both guards define and mean differently —
 * the whole auth bundle here, the flow in `b.guardOauth`. Pass `oauthMaxBytes`
 * for the child's; the two are independent and both apply.
 *
 * @opts
 *   profile:           "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   childProfile:      "strict"|"balanced"|"permissive",   // forwarded to guardJwt / guardOauth
 *   requireAtLeastOne: boolean,
 *   maxBytes:          number,       // bundle JSON-byte cap
 *   oauthMaxBytes:     number,       // guardOauth's flow cap, not this one
 *
 * @example
 *   // A token whose header is { "alg": "none" } — unsigned, so anyone can
 *   // mint one. Refused under every profile.
 *   var rv = b.guardAuth.validate({
 *     jwtToken: unsignedToken,
 *   }, { profile: "strict" });
 *   rv.ok;                                             // → false
 *   rv.issues.some(function (i) { return i.source === "jwt"; });   // → true
 */

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
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *
 * @example
 *   // signedToken carries { "alg": "ES256", "typ": "JWT" } over claims
 *   // { iss, exp, iat } — an ordinary signed bearer token.
 *   var clean = b.guardAuth.sanitize({
 *     jwtToken:     signedToken,
 *     cookieHeader: "sid=abc123",
 *   }, { profile: "balanced" });
 *   clean.cookieHeader;                                // → "sid=abc123"
 */
var _sanitizeTransform = gateContract.identitySanitize;

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
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   name:       string,    // gate identity for audit / observability
 *   childProfile: "strict"|"balanced"|"permissive",
 *   allowedRedirectUris: string[],
 *
 * @example
 *   var authGate = b.guardAuth.gate({ profile: "strict" });
 *   var verdict = await authGate.check({ authBundle: {
 *     jwtToken: unsignedToken,                         // header { "alg": "none" }
 *   } });
 *   verdict.action;                                    // → "refuse"
 */
function gate(opts) {
  opts = _guard.resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardAuth:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var bundle = ctx && (ctx.authBundle || ctx.auth);
      if (!bundle) return { ok: true, action: "serve" };
      var rv = module.exports.validate(bundle, opts);
      return gateContract.severityDisposition(rv.issues);
    });
}

function _sampleJwt(header, claims, signature) {
  var part = function (obj) {
    return Buffer.from(JSON.stringify(obj), "utf8").toString("base64url");
  };
  return part(header) + "." + part(claims) + "." + (signature || "");
}

var _BENIGN_JWT = _sampleJwt(
  { alg: "ES256", typ: "JWT" },
  { iss: "example", exp: 9999999999, iat: 1700000000 },
  "sig");
var _HOSTILE_JWT = _sampleJwt({ alg: "none" }, { sub: "x" }, "");

var INTEGRATION_FIXTURES = Object.freeze({
  kind:              "auth-bundle",
  benignBytes: Buffer.from(JSON.stringify({
    jwtToken:     _BENIGN_JWT,
    cookieHeader: "sid=abc123; theme=dark",
  }), "utf8"),
  hostileBytes: Buffer.from(JSON.stringify({
    jwtToken: _HOSTILE_JWT,
  }), "utf8"),
  benignAuthBundle: {
    jwtToken:     _BENIGN_JWT,
    cookieHeader: "sid=abc123; theme=dark",
  },
  hostileAuthBundle: {
    jwtToken: _HOSTILE_JWT,
  },
});

var CHILD_OWNED_POLICIES = Object.freeze([
  "bidiPolicy", "controlPolicy", "nullBytePolicy", "zeroWidthPolicy", "tagsPolicy",
]);
var FORWARDED_POLICY_ENUM = Object.freeze(
  OAUTH_FORWARDED_OPTS.reduce(function (acc, key) {
    if (CHILD_OWNED_POLICIES.indexOf(key) !== -1) return acc;
    var vocabulary = guardOauth.POLICY_VOCABULARY &&
                     guardOauth.POLICY_VOCABULARY[key];
    if (Array.isArray(vocabulary)) acc[key] = vocabulary;
    return acc;
  }, {}));

var _guard = module.exports = gateContract.defineGuard({
  enumOpts:    FORWARDED_POLICY_ENUM,
  name:        "auth",
  kind:        "auth-bundle",
  errorClass:  GuardAuthError,
  profiles:    PROFILES,
  base:        512,
  integrationFixtures: INTEGRATION_FIXTURES,
  detect:            _detectIssues,
  sanitizeTransform: _sanitizeTransform,
  intOpts:           ["maxBytes"],
  gate:        gate,
});
