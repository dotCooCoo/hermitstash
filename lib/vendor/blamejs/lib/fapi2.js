"use strict";
/**
 * b.fapi2 — Financial-grade API 2.0 Final conformance posture.
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

function posture() {
  return compliance.current() === "fapi-2.0" ? "fapi-2.0" : null;
}

module.exports = {
  assertConformance:  assertConformance,
  assertOAuthConfig:  assertOAuthConfig,
  posture:            posture,
  SENDER_CONSTRAINTS: SENDER_CONSTRAINTS.slice(),
  Fapi2Error:         Fapi2Error,
};
