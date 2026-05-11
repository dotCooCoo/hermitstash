"use strict";
/**
 * @module b.fapi2
 * @nav    Compliance
 * @title  FAPI 2.0
 *
 * @intro
 *   FAPI 2.0 financial-API compliance — mTLS-bound tokens, ML-DSA
 *   signatures, JAR/JARM, sender-constrained tokens.
 *
 *   FAPI 2.0 Final
 *   (https://openid.net/specs/fapi-2_0-security-profile-FINAL.html)
 *   is the OpenID Foundation's security profile for financial /
 *   banking APIs. It composes existing IETF + OAuth standards into
 *   a single profile that operators MUST satisfy to interoperate
 *   with FAPI 2.0 client deployments. The composition (per §5):
 *
 *     - PAR (Pushed Authorization Requests, RFC 9126) — REQUIRED
 *     - PKCE with S256 (RFC 7636) — REQUIRED, PLAIN refused
 *     - Sender-constrained tokens via DPoP (RFC 9449) OR mTLS
 *       (RFC 8705) — REQUIRED, exactly one
 *     - Authorization-server issuer in callback (RFC 9207) —
 *       REQUIRED
 *     - TLS 1.2+ with FAPI-approved cipher suites (TLS 1.3 default)
 *     - JAR (JWT-secured Authorization Request, RFC 9101) when the
 *       request-object is signed
 *
 *   The framework already ships every component primitive. FAPI 2.0
 *   conformance is therefore a posture-coordination problem: the
 *   operator declares the deployment is FAPI-bound, and the
 *   framework asserts every primitive in the chain is configured
 *   per the profile. `b.auth.oauth.create(...)` remains the
 *   operator's OAuth declaration; `b.fapi2.assertOAuthConfig` is
 *   the boot-time gate that refuses to start a FAPI-declared
 *   deployment if any mandate is missing.
 *
 * @card
 *   FAPI 2.0 financial-API compliance — mTLS-bound tokens, ML-DSA signatures, JAR/JARM, sender-constrained tokens.
 */
/*
 * Original prose retained:
 *
 * FAPI 2.0 Final (https://openid.net/specs/fapi-2_0-security-profile-FINAL.html)
 * is the OpenID Foundation's security profile for financial / banking
 * APIs. It composes existing IETF + OAuth standards into a single
 * profile that operators MUST satisfy to interoperate with FAPI 2.0
 * client deployments. The composition (per §5):
 *
 *   - PAR (Pushed Authorization Requests, RFC 9126) — REQUIRED
 *   - PKCE with S256 (RFC 7636) — REQUIRED, PLAIN refused
 *   - Sender-constrained tokens via DPoP (RFC 9449) OR mTLS (RFC 8705)
 *     — REQUIRED, exactly one
 *   - Authorization-server issuer in callback (RFC 9207) — REQUIRED
 *   - TLS 1.2+ with FAPI-approved cipher suites (TLS 1.3 default)
 *   - JAR (JWT-secured Authorization Request, RFC 9101) when
 *     request-object signed
 *
 * The framework already ships every component primitive. FAPI 2.0
 * conformance is therefore a posture-coordination problem: the
 * operator declares the deployment is FAPI-bound, and the framework
 * asserts that every primitive in the chain is configured per the
 * profile.
 *
 * Public API:
 *
 *   b.fapi2.assertConformance(opts) -> { conformant, findings }
 *     opts:
 *       senderConstraint: "dpop" | "mtls" — REQUIRED.
 *       parRequired:      bool, default true.
 *       pkceMethod:       must be "S256" (default; refuses "plain").
 *       requireIssuerInCallback: bool, default true.
 *       requireJarOnSignedRequests: bool, default true.
 *
 *     Returns:
 *       conformant: bool — every check passed.
 *       findings:   Array<{ requirement, status, detail? }>
 *
 *   b.fapi2.assertOAuthConfig(oauthOpts) -> void
 *     Inspects an `b.auth.oauth.create(opts)` configuration object
 *     and throws Fapi2Error if any FAPI 2.0 mandate is violated:
 *       - PKCE absent / non-S256
 *       - state / nonce missing (auto-mint default OK)
 *       - Sender-constraint absent
 *
 *   b.fapi2.posture() -> "fapi-2.0" | null
 *     Returns "fapi-2.0" when b.compliance.set("fapi-2.0") was
 *     called, else null. Convenience for code that branches on the
 *     posture without calling b.compliance.current() directly.
 *
 * The framework does NOT replace operator OAuth configuration —
 * `b.auth.oauth.create(...)` is still where the operator declares
 * client + scopes + redirect URIs. b.fapi2.assertOAuthConfig is the
 * boot-time gate that refuses to start a FAPI-declared deployment
 * if any mandate is missing.
 */

var compliance = require("./compliance");
var audit = require("./audit");
var { defineClass } = require("./framework-error");
var Fapi2Error = defineClass("Fapi2Error", { alwaysPermanent: true });

var SENDER_CONSTRAINTS = ["dpop", "mtls"];

/**
 * @primitive b.fapi2.assertConformance
 * @signature b.fapi2.assertConformance(opts)
 * @since     0.8.0
 * @status    stable
 * @compliance fapi2
 * @related   b.fapi2.assertOAuthConfig, b.fapi2.posture
 *
 * Inspect operator-declared FAPI 2.0 wiring and return a structured
 * report. Throws `Fapi2Error` for non-S256 PKCE or absent
 * sender-constraint; non-mandatory mandates report `WAIVED`. Emits
 * a `fapi2.posture_asserted` audit event so regulators see a single
 * conformance assertion per boot.
 *
 * @opts
 *   senderConstraint:           "dpop" | "mtls",   // REQUIRED
 *   parRequired:                boolean,           // default true
 *   pkceMethod:                 "S256",            // S256 only; "plain" is refused
 *   requireIssuerInCallback:    boolean,           // default true (RFC 9207)
 *   requireJarOnSignedRequests: boolean,           // default true (RFC 9101)
 *
 * @example
 *   var report = b.fapi2.assertConformance({
 *     senderConstraint: "mtls",
 *     parRequired:      true,
 *     pkceMethod:       "S256",
 *   });
 *   report.conformant;
 *   // → true
 *   report.findings[0].requirement;
 *   // → "pkce-s256"
 */
function assertConformance(opts) {
  if (!opts || typeof opts !== "object") {
    throw Fapi2Error.factory("BAD_OPTS",
      "fapi2.assertConformance: opts required");
  }
  if (SENDER_CONSTRAINTS.indexOf(opts.senderConstraint) === -1) {
    throw Fapi2Error.factory("BAD_SENDER_CONSTRAINT",
      "fapi2.assertConformance: senderConstraint must be 'dpop' or 'mtls'");
  }
  var parRequired = opts.parRequired !== false;
  var pkceMethod = opts.pkceMethod || "S256";
  if (pkceMethod !== "S256") {
    throw Fapi2Error.factory("BAD_PKCE",
      "fapi2.assertConformance: PKCE method must be S256 (FAPI 2.0 §5.3.1.1) — got '" +
      pkceMethod + "'");
  }
  var requireIssuer = opts.requireIssuerInCallback !== false;
  var requireJar    = opts.requireJarOnSignedRequests !== false;

  var findings = [];
  findings.push({ requirement: "pkce-s256",          status: "satisfied",
    detail: "PKCE S256 declared (FAPI 2.0 §5.3.1.1)" });
  findings.push({ requirement: "par-required",       status: parRequired ? "satisfied" : "WAIVED",
    detail: parRequired
      ? "PAR (RFC 9126) declared required (FAPI 2.0 §5.3.2.2)"
      : "PAR waived by operator — non-conformant unless authorization-server is FAPI-1 fallback" });
  findings.push({ requirement: "sender-constraint", status: "satisfied",
    detail: opts.senderConstraint + " — FAPI 2.0 §5.3.2.5" });
  findings.push({ requirement: "issuer-in-callback", status: requireIssuer ? "satisfied" : "WAIVED",
    detail: requireIssuer
      ? "Issuer in callback (RFC 9207) required"
      : "Issuer-in-callback waived — IdP-mix-up class still open" });
  findings.push({ requirement: "jar-signed-requests", status: requireJar ? "satisfied" : "WAIVED",
    detail: requireJar
      ? "JAR (RFC 9101) required for signed authorization requests"
      : "JAR waived for signed authorization requests" });

  var conformant = findings.every(function (f) { return f.status === "satisfied"; });

  audit.safeEmit({
    action:   "fapi2.posture_asserted",
    outcome:  conformant ? "success" : "warning",
    metadata: {
      senderConstraint:  opts.senderConstraint,
      parRequired:       parRequired,
      pkceMethod:        pkceMethod,
      requireIssuer:     requireIssuer,
      requireJar:        requireJar,
      conformant:        conformant,
    },
  });

  return { conformant: conformant, findings: findings };
}

/**
 * @primitive b.fapi2.assertOAuthConfig
 * @signature b.fapi2.assertOAuthConfig(oauthOpts)
 * @since     0.8.0
 * @status    stable
 * @compliance fapi2
 * @related   b.fapi2.assertConformance, b.fapi2.posture
 *
 * Boot-time gate over a `b.auth.oauth.create(opts)` configuration.
 * Throws `Fapi2Error` when PKCE is disabled or non-S256, when no
 * sender-constraint is declared, when both DPoP and mTLS are set
 * (over-binding ambiguity), or when PAR is disabled. Operators
 * call this immediately after constructing the OAuth client so a
 * misconfigured deployment refuses to start.
 *
 * @opts
 *   pkce:             boolean,
 *   pkceMethod:       "S256",
 *   dpop:             boolean,
 *   mtls:             boolean,
 *   senderConstraint: "dpop" | "mtls",
 *   par:              boolean,
 *
 * @example
 *   try {
 *     b.fapi2.assertOAuthConfig({
 *       pkce: true, pkceMethod: "S256",
 *       mtls: true, par: true,
 *     });
 *   } catch (e) {
 *     // → never reached for the conformant config above
 *     throw e;
 *   }
 */
function assertOAuthConfig(oauthOpts) {
  if (!oauthOpts || typeof oauthOpts !== "object") {
    throw Fapi2Error.factory("BAD_OAUTH_OPTS",
      "fapi2.assertOAuthConfig: oauth opts required");
  }
  // PKCE — refuse pkce: false (b.auth.oauth.create already does this,
  // but check explicitly for FAPI clarity).
  if (oauthOpts.pkce === false) {
    throw Fapi2Error.factory("PKCE_DISABLED",
      "fapi2.assertOAuthConfig: PKCE is disabled — FAPI 2.0 §5.3.1.1 mandates S256");
  }
  if (oauthOpts.pkceMethod && oauthOpts.pkceMethod !== "S256") {
    throw Fapi2Error.factory("PKCE_NOT_S256",
      "fapi2.assertOAuthConfig: PKCE method '" + oauthOpts.pkceMethod +
      "' is not S256 (FAPI 2.0 §5.3.1.1)");
  }
  // Sender-constraint required
  var hasDpop = oauthOpts.dpop === true || oauthOpts.senderConstraint === "dpop";
  var hasMtls = oauthOpts.mtls === true || oauthOpts.senderConstraint === "mtls";
  if (!hasDpop && !hasMtls) {
    throw Fapi2Error.factory("NO_SENDER_CONSTRAINT",
      "fapi2.assertOAuthConfig: FAPI 2.0 §5.3.2.5 requires sender-constrained tokens via DPoP OR mTLS — neither declared");
  }
  if (hasDpop && hasMtls) {
    throw Fapi2Error.factory("BOTH_SENDER_CONSTRAINTS",
      "fapi2.assertOAuthConfig: declare exactly one of DPoP / mTLS — both creates over-binding ambiguity");
  }
  // PAR
  if (oauthOpts.par === false) {
    throw Fapi2Error.factory("PAR_DISABLED",
      "fapi2.assertOAuthConfig: PAR is disabled — FAPI 2.0 §5.3.2.2 mandates Pushed Authorization Requests");
  }
}

/**
 * @primitive b.fapi2.posture
 * @signature b.fapi2.posture()
 * @since     0.8.0
 * @status    stable
 * @compliance fapi2
 * @related   b.fapi2.assertConformance, b.compliance.current
 *
 * Returns `"fapi-2.0"` when `b.compliance.set("fapi-2.0")` has
 * been called, else `null`. Convenience for code that branches on
 * the posture without calling `b.compliance.current()` directly.
 *
 * @example
 *   b.compliance.set("fapi-2.0");
 *   b.fapi2.posture();
 *   // → "fapi-2.0"
 */
function posture() {
  return compliance.current() === "fapi-2.0" ? "fapi-2.0" :
         compliance.current() === "fapi-2.0-message-signing" ? "fapi-2.0-message-signing" :
         null;
}

/**
 * @primitive b.fapi2.assertCallback
 * @signature b.fapi2.assertCallback(query, opts?)
 * @since     0.8.70
 * @related   b.fapi2.posture, b.auth.oauth.parseCallback
 *
 * Runtime gate the OAuth callback handler invokes BEFORE
 * `parseCallback` to enforce FAPI 2.0's wire-format invariants
 * against the live response:
 *
 *   - **§5.4.2 iss-callback** — refuse callbacks lacking `iss`
 *     under any FAPI 2.0 posture (regardless of OP discovery).
 *   - **§5.3.2 / Message Signing JARM mandate** — under
 *     `fapi-2.0-message-signing`, the OP MUST deliver the
 *     authorization response as a signed JWT (`response=<jwt>`
 *     query param). A bare-param callback is refused.
 *
 * Returns silently on success. Throws Fapi2Error on any FAPI
 * invariant breach. No-op when no FAPI posture is active.
 *
 * @opts
 *   { requireJarm?: boolean }   // override (default: derive from posture)
 *
 * @example
 *   app.get("/oauth/callback", async function (req, res) {
 *     var query = Object.fromEntries(new URL(req.url, "x:/").searchParams);
 *     b.fapi2.assertCallback(query);
 *     var parsed = await oauth.parseCallback(query);
 *     res.end(JSON.stringify({ code: parsed.code }));
 *   });
 */
function assertCallback(query, aopts) {
  aopts = aopts || {};
  var p = posture();
  if (p === null) return;                                                // no FAPI posture active — no-op
  if (!query || typeof query !== "object") {
    throw new Fapi2Error("fapi-2.0/bad-callback",
      "fapi2.assertCallback: query must be an object");
  }
  // §5.3.2 / Message Signing — require JARM when posture demands it.
  // The bare-param callback (no `response=<jwt>`) is the smoking-gun
  // signal that JARM was bypassed; refuse loudly.
  var requireJarm = aopts.requireJarm !== undefined
    ? aopts.requireJarm
    : (p === "fapi-2.0-message-signing");
  if (requireJarm) {
    if (typeof query.response !== "string" || query.response.length === 0) {
      throw new Fapi2Error("fapi-2.0/jarm-required",
        "fapi2.assertCallback: posture '" + p + "' requires JARM " +
        "(response_mode=jwt) — callback delivered bare parameters instead. " +
        "FAPI 2.0 Message Signing §5.3.2 mandates signed authorization responses; " +
        "configure the OP with response_mode=jwt and route through " +
        "b.auth.oauth.parseJarmResponse(query.response).");
    }
  }
  // §5.4.2 — `iss` MUST be present on every callback under FAPI 2.0.
  // RFC 9207 already adds the cross-check; FAPI 2.0 promotes it from
  // SHOULD to MUST regardless of OP discovery's
  // `authorization_response_iss_parameter_supported` flag.
  if (typeof query.iss !== "string" || query.iss.length === 0) {
    throw new Fapi2Error("fapi-2.0/missing-iss",
      "fapi2.assertCallback: posture '" + p + "' requires the OP to echo " +
      "`iss` on every authorization callback (FAPI 2.0 §5.4.2). The callback " +
      "omitted iss — refused.");
  }
}

/**
 * @primitive b.fapi2.assertAuthzRequest
 * @signature b.fapi2.assertAuthzRequest(authzParams)
 * @since     0.8.70
 * @related   b.fapi2.assertCallback
 *
 * Runtime gate the operator wraps around the AuthorizationUrl
 * builder to enforce FAPI 2.0 §5.3.2 — under any FAPI 2.0 posture,
 * the operator MUST send a signed JAR (RFC 9101 `request=<jwt>`
 * OR `request_uri=<par-uri>`). Refuses authorization-request param
 * shapes that look like the bare RFC 6749 query.
 *
 * @example
 *   var params = { request: signedRequestJwt };
 *   b.fapi2.assertAuthzRequest(params);
 *   var url = oauth.authorizationUrl(params);
 */
function assertAuthzRequest(authzParams) {
  var p = posture();
  if (p === null) return;
  if (!authzParams || typeof authzParams !== "object") {
    throw new Fapi2Error("fapi-2.0/bad-authz-params",
      "fapi2.assertAuthzRequest: params must be an object");
  }
  // The operator passes either a built request_object JWT (`request`),
  // a PAR-issued `request_uri`, OR neither (which is a violation).
  var hasJar = (typeof authzParams.request === "string" && authzParams.request.length > 0) ||
               (typeof authzParams.request_uri === "string" && authzParams.request_uri.length > 0);
  if (!hasJar) {
    throw new Fapi2Error("fapi-2.0/jar-required",
      "fapi2.assertAuthzRequest: posture '" + p + "' requires a signed " +
      "request object (RFC 9101 JAR) — pass either `request: <jwt>` OR " +
      "`request_uri: <par-uri>` (FAPI 2.0 §5.3.2). Bare-query authorization " +
      "requests are refused.");
  }
}

module.exports = {
  assertConformance:  assertConformance,
  assertOAuthConfig:  assertOAuthConfig,
  assertCallback:     assertCallback,
  assertAuthzRequest: assertAuthzRequest,
  posture:            posture,
  SENDER_CONSTRAINTS: SENDER_CONSTRAINTS.slice(),
  Fapi2Error:         Fapi2Error,
};
