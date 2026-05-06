"use strict";
/**
 * guard-auth — Composite auth-bundle safety primitive (b.guardAuth).
 *
 * Composes guardJwt + guardOauth + the cookie/header middleware
 * validators into a single auth-flow check. KIND="auth-bundle" —
 * consumes `ctx.authBundle` shape:
 *   {
 *     jwtToken?:           string,           // routed to guardJwt
 *     oauthFlow?:          object,           // routed to guardOauth
 *     cookieHeader?:       string,           // routed to b.cookies.parseSafe
 *     requestHeaders?:     object,           // routed through threat-detection
 *   }
 *
 * Each sub-validator runs independently; aggregated issues are
 * returned with a `source` field tagging which sub-guard raised them.
 * Operators get one gate to drop into a request lifecycle that covers
 * the full canonical-auth threat surface.
 *
 *   var rv = b.guardAuth.validate({
 *     jwtToken:     bearerToken,
 *     oauthFlow:    req.query,
 *     cookieHeader: req.headers.cookie,
 *     requestHeaders: req.headers,
 *   }, { profile: "strict" });
 *
 *   var g = b.guardAuth.gate({ profile: "strict" });
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

function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes"],
    "guardAuth.validate", GuardAuthError, "auth.bad-opt");
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

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

var buildProfile = gateContract.makeProfileBuilder(PROFILES);

function compliancePosture(name) {
  return gateContract.lookupCompliancePosture(name, COMPLIANCE_POSTURES,
    _err, "auth");
}

var _authRulePacks = gateContract.makeRulePackLoader(GuardAuthError, "auth");
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
