// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.guardOauth
 * @nav    Guards
 * @title  Guard Oauth
 *
 * @intro
 *   OAuth 2.x / OIDC authorization-code-flow shape guard —
 *   validates user-supplied parameter bundles BEFORE the
 *   framework's `b.auth.oauth` client exchanges them with the IdP.
 *   KIND is `oauth-flow`; the gate consumes `ctx.oauthFlow` (or
 *   `ctx.flow`) shape `{ response_type, redirect_uri, state,
 *   code_challenge, code_challenge_method, scope, code, iss,
 *   _isCallback }`. The guard runs the spec-mandated refuse list
 *   so misconfigured callers can't downgrade the flow.
 *
 *   PKCE enforcement: `strict` requires `S256` (RFC 7636 + OAuth
 *   2.1; the `plain` method is a downgrade-attack class). `balanced`
 *   accepts S256 or plain. `permissive` audits without enforcing.
 *   Missing `code_verifier` AND missing `code_challenge` always
 *   surfaces as `oauth.pkce-missing` because OAuth 2.1 mandates
 *   PKCE for every client class.
 *
 *   `state` enforcement: required at strict / balanced. Without
 *   state-binding the authorization callback is open to CSRF (RFC
 *   6749 §10.12). The guard refuses missing `state`; operator-side
 *   replay defense (rotating + comparing) is the responsibility of
 *   the caller's session layer.
 *
 *   `nonce` is OIDC-specific replay defense — the guard's required-
 *   claims parity is enforced via the operator's
 *   `b.auth.jwt.verifyExternal` config, not in the flow shape, so
 *   nonce is documented here but checked by the verifier.
 *
 *   `redirect_uri` exact-match: when the operator supplies
 *   `allowedRedirectUris`, every callback must be a byte-for-byte
 *   match. RFC 6749 §3.1.2 + OAuth 2.1 forbid prefix, wildcard, or
 *   scheme drift — the canonical CVE-class for this is the
 *   "redirect_uri loose-match" account-takeover bug. When no
 *   allowlist is configured the gate skips the check (operator-side
 *   misconfiguration warning lives in the startup audit, not in
 *   per-request issue lists).
 *
 *   `response_type` allowlist: `strict` allows only `code`.
 *   `balanced` adds `code id_token`. `permissive` skips. Implicit-
 *   flow `token` and `id_token` outside OIDC are deprecated in
 *   OAuth 2.1 and refused under the strict / balanced allowlists.
 *
 *   Scope-token discipline: every space-separated scope must
 *   conform to the RFC 6749 §3.3 charset (`%x21 / %x23-5B /
 *   %x5D-7E`). Whitespace-other-than-space, control bytes, and
 *   non-printable bytes in scope tokens are refused under strict
 *   / balanced and audited under permissive.
 *
 *   RFC 9207 issuer-on-callback: when the request bundle is
 *   marked `_isCallback: true`, the `iss` parameter MUST be
 *   present at strict — defeats the IdP-mix-up attack class.
 *   `balanced` audits, `permissive` skips.
 *
 *   Token-introspection bounds: `maxParamBytes` (default 2 KiB at
 *   strict / balanced) and `maxBytes` (default 8 KiB) cap each
 *   parameter and the total flow JSON. Decompression-bomb-shaped
 *   clients can't push the introspection / metadata layer past
 *   these bounds.
 *
 *   Code-reuse defense: when the operator wires a `seenCodeStore`
 *   with `hasSeen(code)`, the guard refuses any authorization code
 *   already exchanged (RFC 6749 §10.5). The store implementation
 *   is the operator's responsibility — typically a short-TTL
 *   `b.cache` entry.
 *
 *   Profiles: `strict` / `balanced` / `permissive`. Compliance
 *   postures: `hipaa` / `pci-dss` / `gdpr` / `soc2`. BIDI / null /
 *   control / zero-width universal-refuse applies on every string-
 *   valued top-level parameter at every profile so trojan-source
 *   codepoints can't ride a state or scope value.
 *
 * @card
 *   OAuth 2.x / OIDC authorization-code-flow shape guard — validates user-supplied parameter bundles BEFORE the framework's `b.auth.oauth` client exchanges them with the IdP.
 */

var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var { GuardOauthError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var DEFAULT_RESPONSE_TYPES = Object.freeze(["code"]);

var PROFILES = Object.freeze({
  "strict": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    pkcePolicy:                "require-s256",
    statePolicy:               "require",
    redirectUriPolicy:         "require-exact-allowlist",
    responseTypePolicy:        "require-allowlist",
    scopeTamperingPolicy:      "reject",
    issuerOnCallbackPolicy:    "require",
    codeReusePolicy:           "reject",
    allowedResponseTypes:      DEFAULT_RESPONSE_TYPES,
    maxParamBytes:             C.BYTES.kib(2),
    maxBytes:                  C.BYTES.kib(8),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
  "balanced": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    pkcePolicy:                "require-any",
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
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    pkcePolicy:                "audit",
    statePolicy:               "audit",
    redirectUriPolicy:         "audit",
    responseTypePolicy:        "audit",
    scopeTamperingPolicy:      "reject",
    issuerOnCallbackPolicy:    "audit",
    codeReusePolicy:           "reject",
    allowedResponseTypes:      null,
    maxParamBytes:             C.BYTES.kib(4),
    maxBytes:                  C.BYTES.kib(16),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
});

var SCOPE_TOKEN_RANGES = [0x21, [0x23, 0x5B], [0x5D, 0x7E]];

function _isScopeToken(s) {
  return codepointClass.isRunOfRanges(s, SCOPE_TOKEN_RANGES, 1);
}

function _detectIssues(flow, opts) {
  var issues = [];
  if (!flow || typeof flow !== "object") {
    return [{ kind: "bad-input", severity: "high",
              ruleId: "oauth.bad-input",
              snippet: "oauth flow is not an object" }];
  }

  try {
    var serialized = JSON.stringify(flow);
    if (Buffer.byteLength(serialized, "utf8") > opts.maxBytes) {
      return [{ kind: "flow-cap", severity: "high",
                ruleId: "oauth.flow-cap",
                snippet: "oauth flow exceeds maxBytes " + opts.maxBytes }];
    }
  } catch (_e) { /* unstringifiable — flagged below */ }

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

  if (typeof flow.redirect_uri === "string" &&
      opts.redirectUriPolicy === "require-exact-allowlist") {
    var allowlist = opts.allowedRedirectUris;
    if (!Array.isArray(allowlist)) {
      issues.push({
        kind: "redirect-uri-allowlist-missing", severity: "warn",
        ruleId: "oauth.redirect-uri-allowlist-missing",
        snippet: "redirectUriPolicy is \"require-exact-allowlist\" but no " +
                 "allowedRedirectUris were configured — the exact-match check " +
                 "cannot be performed (set the allowlist, or choose " +
                 "redirectUriPolicy \"audit\"/\"allow\" to accept the risk)",
      });
    } else if (allowlist.indexOf(flow.redirect_uri) === -1) {
      issues.push({
        kind: "redirect-uri-not-allowed", severity: "high",
        ruleId: "oauth.redirect-uri-not-allowed",
        snippet: "redirect_uri `" + flow.redirect_uri + "` not in " +
                 "operator allowlist (RFC 6749 §3.1.2 / OAuth 2.1 " +
                 "mandate exact-match)",
      });
    }
  }

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

  if (typeof flow.scope === "string" &&
      opts.scopeTamperingPolicy !== "allow") {
    var scopes = flow.scope.split(" ");
    for (var si = 0; si < scopes.length; si += 1) {
      var s = scopes[si];
      if (s.length === 0) continue;
      if (!_isScopeToken(s)) {
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

  if (typeof flow.code === "string" && opts.codeReusePolicy !== "allow" &&
      !(opts.seenCodeStore && typeof opts.seenCodeStore.hasSeen === "function")) {
    issues.push({
      kind: "code-reuse-unverifiable", severity: "high",
      ruleId: "oauth.code-reuse-unverifiable",
      snippet: "codeReusePolicy is \"" + (opts.codeReusePolicy || "reject") +
               "\" but no seenCodeStore.hasSeen() was supplied — cannot prove " +
               "the authorization code is unused; refusing (fail-closed, " +
               "RFC 6749 §10.5)",
    });
  }
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
    } catch (_e) {
      issues.push({
        kind: "code-reuse-unverifiable", severity: "high",
        ruleId: "oauth.code-reuse-unverifiable",
        snippet: "replay store (seenCodeStore.hasSeen) errored — cannot prove " +
                 "the authorization code is unused; refusing (fail-closed, RFC 6749 §10.5)",
      });
    }
  }

  return issues;
}

/**
 * @primitive  b.guardOauth.validate
 * @signature  b.guardOauth.validate(input, opts?)
 * @since      0.7.49
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardOauth.sanitize, b.guardOauth.gate
 *
 * Apply the full guard-oauth threat catalog to a flow bundle.
 * Returns `{ ok, issues }` per
 * `gateContract.aggregateIssues`. Detected classes include
 * `pkce-missing`, `pkce-method` (e.g. plain under require-s256),
 * `state-missing`, `redirect-uri-not-allowed`,
 * `response-type-not-allowed`, `scope-token-shape`,
 * `issuer-missing`, `code-reused` (always critical), plus per-
 * parameter `param-cap` and total-flow `flow-cap` bounds and
 * codepoint-class issues on every string parameter. Operator-
 * supplied opts are bounds-checked; bad opts throw
 * `GuardOauthError("oauth/bad-opt")`.
 *
 * @opts
 *   profile:                 "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   pkcePolicy:              "require-s256"|"require-any"|"audit"|"allow",
 *   statePolicy:             "require"|"audit"|"allow",
 *   redirectUriPolicy:       "require-exact-allowlist"|"audit"|"allow",
 *   responseTypePolicy:      "require-allowlist"|"audit"|"allow",
 *   scopeTamperingPolicy:    "reject"|"audit"|"allow",
 *   issuerOnCallbackPolicy:  "require"|"audit"|"allow",
 *   codeReusePolicy:         "reject"|"allow",
 *   allowedRedirectUris:     string[],
 *   allowedResponseTypes:    string[],
 *   seenCodeStore:           { hasSeen: function(code): boolean },
 *   maxParamBytes:           number,
 *   maxBytes:                number,
 *
 * @example
 *   var hostile = {
 *     response_type: "code",
 *     redirect_uri:  "https://attacker.example/callback",
 *     scope:         "openid",
 *   };
 *   var rv = b.guardOauth.validate(hostile, { profile: "strict" });
 *   rv.ok;                                              // → false
 *   rv.issues[0].ruleId;                                // → "oauth.pkce-missing"
 *
 *   var benign = {
 *     response_type: "code",
 *     redirect_uri:  "https://app.example.com/callback",
 *     state:         "csrf-rand-1",
 *     scope:         "openid profile",
 *     code_challenge: "abc123def456ghi789jkl012mno345pqr678",
 *     code_challenge_method: "S256",
 *   };
 *   var ok = b.guardOauth.validate(benign, {
 *     profile: "strict",
 *     allowedRedirectUris: ["https://app.example.com/callback"],
 *   });
 *   ok.ok;                                              // → true
 */

/**
 * @primitive  b.guardOauth.sanitize
 * @signature  b.guardOauth.sanitize(input, opts?)
 * @since      0.7.49
 * @status     stable
 * @related    b.guardOauth.validate, b.guardOauth.gate
 *
 * Pass-through-or-throw form of `validate`. OAuth flow bundles
 * can't be partially repaired — a missing `state` or wrong
 * `redirect_uri` is a refuse-class outcome, not something the
 * guard can patch up safely. Returns the input unchanged when
 * the issue list contains no `critical` / `high` entries; throws
 * `GuardOauthError` carrying the offending `ruleId` otherwise.
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   ...:        every guardOauth.validate opt is honored,
 *
 * @example
 *   try {
 *     b.guardOauth.sanitize({
 *       response_type: "code",
 *       redirect_uri:  "https://app.example.com/callback",
 *       scope:         "openid",
 *     }, { profile: "strict" });
 *   } catch (e) {
 *     e.code;                                           // → "oauth.pkce-missing"
 *   }
 */
var _sanitizeTransform = gateContract.identitySanitize;

/**
 * @primitive  b.guardOauth.gate
 * @signature  b.guardOauth.gate(opts?)
 * @since      0.7.49
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardOauth.validate, b.guardOauth.sanitize
 *
 * Build a `gateContract.buildGuardGate`-shaped gate that pulls
 * `ctx.oauthFlow` (or `ctx.flow`) and dispatches to `validate`.
 * Returns `{ ok: true, action: "serve" }` when the issue list is
 * empty, `{ ok: true, action: "audit-only", issues }` when only
 * low-severity issues fire, and `{ ok: false, action: "refuse",
 * issues }` on any `critical` / `high` issue. Compose into the
 * authorization-callback handler before exchanging the code with
 * the IdP — refusal on a hostile callback prevents the token
 * exchange entirely.
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   name:       string,            // gate label for audit trails
 *   ...:        every guardOauth.validate opt is honored,
 *
 * @example
 *   var oauthGate = b.guardOauth.gate({
 *     profile: "strict",
 *     allowedRedirectUris: ["https://app.example.com/callback"],
 *   });
 *   var rv = await oauthGate.check({
 *     oauthFlow: {
 *       response_type: "code",
 *       redirect_uri:  "https://attacker.example/callback",
 *       state:         "csrf-rand-1",
 *       scope:         "openid",
 *       code_challenge: "abc123def456ghi789jkl012mno345pqr678",
 *       code_challenge_method: "S256",
 *     },
 *   });
 *   rv.action;                                          // → "refuse"
 */
function gate(opts) {
  opts = _guard.resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardOauth:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var flow = ctx && (ctx.oauthFlow || ctx.flow);
      if (!flow) return { ok: true, action: "serve" };
      var rv = module.exports.validate(flow, opts);
      return gateContract.severityDisposition(rv.issues);
    });
}

var INTEGRATION_FIXTURES = Object.freeze({
  kind:              "oauth-flow",
  benignBytes:       Buffer.from(JSON.stringify({
    response_type: "code",
    redirect_uri:  "https://app.example.com/callback",
    state:         "csrf-rand-1",
    scope:         "openid profile",
    code_challenge: "abc123def456ghi789jkl012mno345pqr678",
    code_challenge_method: "S256",
  }), "utf8"),
  hostileBytes:      Buffer.from(JSON.stringify({
    response_type: "code",
    redirect_uri:  "https://attacker.example/callback",
    scope:         "openid",
  }), "utf8"),
  benignOauthFlow: {
    response_type: "code",
    redirect_uri:  "https://app.example.com/callback",
    state:         "csrf-rand-1",
    scope:         "openid profile",
    code_challenge: "abc123def456ghi789jkl012mno345pqr678",
    code_challenge_method: "S256",
  },
  gateOpts: {
    allowedRedirectUris: ["https://app.example.com/callback"],
  },
  hostileOauthFlow: {
    response_type: "code",
    redirect_uri:  "https://attacker.example/callback",
    scope:         "openid",
  },
});

var POLICY_ENUM = gateContract.policyVocabulary(
  ["scopeTamperingPolicy"], gateContract.POLICY_VALUES.rejectAuditAllow, {
    pkcePolicy:             ["require-s256", "require-any", "audit", "allow"],
    statePolicy:            ["require", "audit", "audit-only", "allow"],
    redirectUriPolicy:      ["require-exact-allowlist", "audit", "audit-only", "allow"],
    responseTypePolicy:     ["require-allowlist", "audit", "audit-only", "allow"],
    issuerOnCallbackPolicy: ["require", "audit", "audit-only", "allow"],
    codeReusePolicy:        ["reject", "allow"],
  });

var _guard = module.exports = gateContract.defineGuard({
  enumOpts:    POLICY_ENUM,
  name:        "oauth",
  kind:        "oauth-flow",
  errorClass:  GuardOauthError,
  profiles:    PROFILES,
  base:        256,
  integrationFixtures: INTEGRATION_FIXTURES,
  detect:             _detectIssues,
  sanitizeTransform:  _sanitizeTransform,
  intOpts:            ["maxBytes", "maxParamBytes"],
  gate:        gate,
});
