"use strict";
/**
 * guard-oauth — OAuth flow-shape safety primitive (b.guardOauth).
 *
 * Validates user-supplied OAuth 2.x / OIDC authorization-code-flow
 * parameter bundles before the framework's b.auth.oauth client
 * exchanges them. KIND="oauth-flow" — consumes ctx.oauthFlow.
 *
 * Threat catalog:
 *   - PKCE missing or non-S256 — RFC 7636 mandates code_verifier;
 *     OAuth 2.1 mandates S256 (no plain). The plaintext "plain"
 *     method is downgrade-attack class.
 *   - state missing / replayed — RFC 6749 §10.12 + §10.14; without
 *     state-binding the flow is open to CSRF.
 *   - redirect_uri not in allowlist — RFC 6749 §3.1.2 + OAuth 2.1
 *     mandate exact-match (no prefix / wildcard / scheme drift).
 *   - response_type not in allowlist — refuse "token" implicit flow
 *     (deprecated in OAuth 2.1) and "id_token" outside OIDC; require
 *     operator-allowed types.
 *   - scope tampering — refuse scope values containing whitespace
 *     other than space (RFC 6749 §3.3) or non-printable bytes.
 *   - issuer (iss) missing on callback — RFC 9207 mandates iss
 *     parameter on authorization response to defeat the IdP-mix-up
 *     attack.
 *   - code reuse — operator-supplied seenCodeStore detects
 *     authorization-code replay (RFC 6749 §10.5).
 *   - excessive parameter / value length — defense against parser
 *     DoS and decompression-bomb-shaped clients.
 *   - BIDI / null / control / zero-width universal refuse.
 *
 *   var rv = b.guardOauth.validate({ redirect_uri, state, ... },
 *                                  { profile: "strict" });
 *   var g  = b.guardOauth.gate({ profile: "strict" });
 */

var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var { GuardOauthError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardOauthError.factory;

var SCOPE_TOKEN_RE = /^[\x21\x23-\x5b\x5d-\x7e]+$/;                              // allow:raw-byte-literal — RFC 6749 §3.3 scope-token charset
var DEFAULT_RESPONSE_TYPES = Object.freeze(["code"]);

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    bidiPolicy:               "reject",
    controlPolicy:             "reject",
    nullBytePolicy:            "reject",
    zeroWidthPolicy:           "reject",
    pkcePolicy:                "require-s256",
    statePolicy:               "require",
    redirectUriPolicy:         "require-exact-allowlist",
    responseTypePolicy:        "require-allowlist",
    scopeTamperingPolicy:      "reject",
    issuerOnCallbackPolicy:    "require",                                        // RFC 9207
    codeReusePolicy:           "reject",
    allowedResponseTypes:      DEFAULT_RESPONSE_TYPES,
    maxParamBytes:             C.BYTES.kib(2),
    maxBytes:                  C.BYTES.kib(8),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
  "balanced": {
    bidiPolicy:               "reject",
    controlPolicy:             "reject",
    nullBytePolicy:            "reject",
    zeroWidthPolicy:           "reject",
    pkcePolicy:                "require-any",                                    // S256 or plain
    statePolicy:               "require",
    redirectUriPolicy:         "require-exact-allowlist",
    responseTypePolicy:        "require-allowlist",
    scopeTamperingPolicy:      "reject",
    issuerOnCallbackPolicy:    "audit",
    codeReusePolicy:           "reject",
    allowedResponseTypes:      Object.freeze(["code", "code id_token"]),
    maxParamBytes:             C.BYTES.kib(2),
    maxBytes:                  C.BYTES.kib(8),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
  "permissive": {
    bidiPolicy:               "reject",                                          // BIDI refused at every profile
    controlPolicy:             "reject",                                          // controls refused at every profile
    nullBytePolicy:            "reject",                                          // null refused at every profile
    zeroWidthPolicy:           "reject",                                          // zero-width refused at every profile
    pkcePolicy:                "audit",
    statePolicy:               "audit",
    redirectUriPolicy:         "audit",
    responseTypePolicy:        "audit",
    scopeTamperingPolicy:      "reject",                                          // scope tampering refused at every profile
    issuerOnCallbackPolicy:    "audit",
    codeReusePolicy:           "reject",                                          // code reuse refused at every profile
    allowedResponseTypes:      null,
    maxParamBytes:             C.BYTES.kib(4),
    maxBytes:                  C.BYTES.kib(16),
    maxRuntimeMs:              C.TIME.seconds(2),
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
    errorClass:         GuardOauthError,
    errCodePrefix:      "oauth",
  });
}

function _detectIssues(flow, opts) {
  var issues = [];
  if (!flow || typeof flow !== "object") {
    return [{ kind: "bad-input", severity: "high",
              ruleId: "oauth.bad-input",
              snippet: "oauth flow is not an object" }];
  }

  // Total-bytes cap — JSON-stringify proxy for input size.
  try {
    var serialized = JSON.stringify(flow);
    if (Buffer.byteLength(serialized, "utf8") > opts.maxBytes) {
      return [{ kind: "flow-cap", severity: "high",
                ruleId: "oauth.flow-cap",
                snippet: "oauth flow exceeds maxBytes " + opts.maxBytes }];
    }
  } catch (_e) { /* unstringifiable — flagged below */ }

  // Codepoint-class threats applied to every string value at the
  // top-level (operator nests via `flow` so this catches the canonical
  // OAuth params).
  var keys = Object.keys(flow);
  for (var ki = 0; ki < keys.length; ki += 1) {
    var v = flow[keys[ki]];
    if (typeof v !== "string") continue;
    if (Buffer.byteLength(v, "utf8") > opts.maxParamBytes) {
      issues.push({
        kind: "param-cap", severity: "high",
        ruleId: "oauth.param-cap",
        snippet: "oauth param `" + keys[ki] + "` exceeds maxParamBytes " +
                 opts.maxParamBytes,
      });
      continue;
    }
    var charThreats = codepointClass.detectCharThreats(v, opts, "oauth");
    for (var ci = 0; ci < charThreats.length; ci += 1) {
      issues.push(Object.assign({}, charThreats[ci], {
        snippet: "oauth.param `" + keys[ki] + "`: " + charThreats[ci].snippet,
      }));
    }
  }

  // PKCE.
  if (opts.pkcePolicy !== "audit" && opts.pkcePolicy !== "allow") {
    var hasVerifier  = typeof flow.code_verifier === "string" && flow.code_verifier.length > 0;
    var hasChallenge = typeof flow.code_challenge === "string" && flow.code_challenge.length > 0;
    if (!hasVerifier && !hasChallenge) {
      issues.push({
        kind: "pkce-missing", severity: "high",
        ruleId: "oauth.pkce-missing",
        snippet: "neither code_verifier nor code_challenge present " +
                 "(RFC 7636 / OAuth 2.1 require PKCE for every client)",
      });
    }
    if (hasChallenge && opts.pkcePolicy === "require-s256") {
      var method = flow.code_challenge_method || "plain";
      if (method !== "S256") {
        issues.push({
          kind: "pkce-method", severity: "high",
          ruleId: "oauth.pkce-method",
          snippet: "code_challenge_method `" + method + "` not S256 " +
                   "(OAuth 2.1 forbids `plain` — downgrade-attack class)",
        });
      }
    }
  }

  // state.
  if (opts.statePolicy === "require") {
    if (typeof flow.state !== "string" || flow.state.length === 0) {
      issues.push({
        kind: "state-missing", severity: "high",
        ruleId: "oauth.state-missing",
        snippet: "state parameter missing — required for CSRF defense " +
                 "(RFC 6749 §10.12)",
      });
    }
  }

  // redirect_uri.
  if (typeof flow.redirect_uri === "string" &&
      opts.redirectUriPolicy === "require-exact-allowlist") {
    var allowlist = opts.allowedRedirectUris;
    // When the operator hasn't configured an allowlist, the gate can't
    // enforce exact-match; skip the check entirely. Operator-side
    // configuration warnings live in the operator's startup audit, not
    // in per-request issue lists.
    if (Array.isArray(allowlist) && allowlist.length > 0 &&
        allowlist.indexOf(flow.redirect_uri) === -1) {
      issues.push({
        kind: "redirect-uri-not-allowed", severity: "high",
        ruleId: "oauth.redirect-uri-not-allowed",
        snippet: "redirect_uri `" + flow.redirect_uri + "` not in " +
                 "operator allowlist (RFC 6749 §3.1.2 / OAuth 2.1 " +
                 "mandate exact-match)",
      });
    }
  }

  // response_type.
  if (typeof flow.response_type === "string" &&
      opts.responseTypePolicy === "require-allowlist" &&
      Array.isArray(opts.allowedResponseTypes)) {
    if (opts.allowedResponseTypes.indexOf(flow.response_type) === -1) {
      issues.push({
        kind: "response-type-not-allowed", severity: "high",
        ruleId: "oauth.response-type-not-allowed",
        snippet: "response_type `" + flow.response_type + "` not in " +
                 "operator allowedResponseTypes",
      });
    }
  }

  // scope tampering.
  if (typeof flow.scope === "string" &&
      opts.scopeTamperingPolicy !== "allow") {
    var scopes = flow.scope.split(" ");
    for (var si = 0; si < scopes.length; si += 1) {
      var s = scopes[si];
      if (s.length === 0) continue;
      if (!SCOPE_TOKEN_RE.test(s)) {                                             // allow:regex-no-length-cap — scope value bounded by maxParamBytes
        issues.push({
          kind: "scope-token-shape",
          severity: opts.scopeTamperingPolicy === "reject" ? "high" : "warn",
          ruleId: "oauth.scope-token-shape",
          snippet: "scope token `" + s + "` violates RFC 6749 §3.3 " +
                   "scope-token charset (whitespace / control / non-printable)",
        });
      }
    }
  }

  // RFC 9207 issuer on callback.
  if (opts.issuerOnCallbackPolicy === "require" &&
      flow._isCallback === true) {
    if (typeof flow.iss !== "string" || flow.iss.length === 0) {
      issues.push({
        kind: "issuer-missing", severity: "high",
        ruleId: "oauth.issuer-missing",
        snippet: "iss parameter missing on callback — RFC 9207 mandates " +
                 "issuer identification to defeat IdP-mix-up attack",
      });
    }
  }

  // code reuse — operator supplies seenCodeStore + reportSeen() / hasSeen().
  if (typeof flow.code === "string" &&
      opts.codeReusePolicy !== "allow" &&
      opts.seenCodeStore && typeof opts.seenCodeStore.hasSeen === "function") {
    try {
      if (opts.seenCodeStore.hasSeen(flow.code)) {
        issues.push({
          kind: "code-reused", severity: "critical",
          ruleId: "oauth.code-reused",
          snippet: "authorization code already exchanged — replay class " +
                   "(RFC 6749 §10.5)",
        });
      }
    } catch (_e) { /* drop-silent — operator-supplied store */ }
  }

  return issues;
}

function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes", "maxParamBytes"],
    "guardOauth.validate", GuardOauthError, "oauth.bad-opt");
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

function sanitize(input, opts) {
  opts = _resolveOpts(opts);
  // OAuth flows can't be repaired — sanitize either passes through
  // valid input or throws.
  var issues = _detectIssues(input, opts);
  for (var i = 0; i < issues.length; i += 1) {
    if (issues[i].severity === "critical" || issues[i].severity === "high") {
      throw _err(issues[i].ruleId || "oauth.refused",
        "guardOauth.sanitize: " + issues[i].snippet);
    }
  }
  return input;
}

function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardOauth:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var flow = ctx && (ctx.oauthFlow || ctx.flow);
      if (!flow) return { ok: true, action: "serve" };
      var rv = validate(flow, opts);
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
    _err, "oauth");
}

var _oauthRulePacks = gateContract.makeRulePackLoader(GuardOauthError, "oauth");
var loadRulePack = _oauthRulePacks.load;

module.exports = {
  // ---- guard-* family registry exports ----
  NAME:                "oauth",
  KIND:                "oauth-flow",
  INTEGRATION_FIXTURES: Object.freeze({
    kind:              "oauth-flow",
    benignBytes:       Buffer.from(JSON.stringify({
      response_type: "code",
      redirect_uri:  "https://app.example.com/callback",
      state:         "csrf-rand-1",
      scope:         "openid profile",
      code_challenge: "abc123def456ghi789jkl012mno345pqr678",                   // allow:raw-byte-literal — base64url-shaped fixture
      code_challenge_method: "S256",
    }), "utf8"),
    hostileBytes:      Buffer.from(JSON.stringify({
      response_type: "code",
      redirect_uri:  "https://attacker.example/callback",
      // state missing — CSRF class
      scope:         "openid",
    }), "utf8"),
    benignOauthFlow: {
      response_type: "code",
      redirect_uri:  "https://app.example.com/callback",
      state:         "csrf-rand-1",
      scope:         "openid profile",
      code_challenge: "abc123def456ghi789jkl012mno345pqr678",                   // allow:raw-byte-literal — base64url-shaped fixture
      code_challenge_method: "S256",
    },
    hostileOauthFlow: {
      response_type: "code",
      redirect_uri:  "https://attacker.example/callback",
      // state missing → state-missing refuse
      scope:         "openid",
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
  GuardOauthError:     GuardOauthError,
};
