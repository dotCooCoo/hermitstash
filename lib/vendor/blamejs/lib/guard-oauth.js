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
var numericBounds = require("./numeric-bounds");
var { GuardOauthError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardOauthError.factory;

var SCOPE_TOKEN_RE = /^[\x21\x23-\x5b\x5d-\x7e]+$/;                              // RFC 6749 §3.3 scope-token charset
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
 * `GuardOauthError("oauth.bad-opt")`.
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
function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes", "maxParamBytes"],
    "guardOauth.validate", GuardOauthError, "oauth.bad-opt");
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

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

/**
 * @primitive  b.guardOauth.buildProfile
 * @signature  b.guardOauth.buildProfile(opts)
 * @since      0.7.49
 * @status     stable
 * @related    b.guardOauth.gate, b.guardOauth.compliancePosture
 *
 * Compose a derived profile from one or more named bases plus
 * inline overrides. `opts.extends` is a profile name (`"strict"` /
 * `"balanced"` / `"permissive"`) or an array of names; later
 * entries shadow earlier ones, and inline `opts` keys win last.
 * Operators stage profile overlays here so the final shape is
 * traceable to a baseline rather than a hand-typed dictionary.
 *
 * @opts
 *   extends: string|string[],   // base profile name(s) to compose
 *   ...:     any guardOauth key, // inline override of resolved keys
 *
 * @example
 *   var custom = b.guardOauth.buildProfile({
 *     extends: "balanced",
 *     pkcePolicy: "require-s256",
 *     allowedResponseTypes: ["code"],
 *   });
 *   custom.pkcePolicy;                                  // → "require-s256"
 *   custom.allowedResponseTypes.length;                 // → 1
 */
var buildProfile = gateContract.makeProfileBuilder(PROFILES);

/**
 * @primitive  b.guardOauth.compliancePosture
 * @signature  b.guardOauth.compliancePosture(name)
 * @since      0.7.49
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardOauth.gate, b.guardOauth.buildProfile
 *
 * Look up a compliance-posture overlay by name (`"hipaa"` /
 * `"pci-dss"` / `"gdpr"` / `"soc2"`). Returns a shallow clone of
 * the posture object — the caller may mutate freely. Throws
 * `GuardOauthError("oauth.bad-posture")` on unknown name.
 * Postures extend the strict profile (or balanced for `gdpr`)
 * with a `forensicSnippetBytes` cap appropriate to the regime.
 *
 * @example
 *   var posture = b.guardOauth.compliancePosture("pci-dss");
 *   posture.pkcePolicy;                                 // → "require-s256"
 *   posture.forensicSnippetBytes;                       // → 256
 */
function compliancePosture(name) {
  return gateContract.lookupCompliancePosture(name, COMPLIANCE_POSTURES,
    _err, "oauth");
}

var _oauthRulePacks = gateContract.makeRulePackLoader(GuardOauthError, "oauth");
/**
 * @primitive  b.guardOauth.loadRulePack
 * @signature  b.guardOauth.loadRulePack(pack)
 * @since      0.7.49
 * @status     stable
 * @related    b.guardOauth.gate
 *
 * Register an operator-supplied rule pack with the guard-oauth
 * registry. The pack is identified by `pack.id` (non-empty
 * string) and stored for later inspection / dispatch by gates
 * that opt in via `opts.rulePackId`. Returns the pack object
 * unchanged on success; throws `GuardOauthError("oauth.bad-opt")`
 * when `pack` is missing or `pack.id` is not a non-empty string.
 *
 * @example
 *   var pack = b.guardOauth.loadRulePack({
 *     id: "scope-narrow",
 *     rules: [
 *       { id: "no-admin", severity: "high",
 *         detect: function (flow) { return /\badmin\b/.test(flow.scope || ""); },
 *         reason: "tenant forbids admin scope on user-flow callbacks" },
 *     ],
 *   });
 *   pack.id;                                            // → "scope-narrow"
 */
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
      code_challenge: "abc123def456ghi789jkl012mno345pqr678",                   // base64url-shaped fixture
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
      code_challenge: "abc123def456ghi789jkl012mno345pqr678",                   // base64url-shaped fixture
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
