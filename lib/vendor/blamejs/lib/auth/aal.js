"use strict";
/**
 * NIST SP 800-63-4 Authentication Assurance Levels.
 *
 * Three bands (AAL1, AAL2, AAL3) describe the rigor of the
 * authentication ceremony that gated this session. Operators wiring
 * step-up flows compare the AAL band of an incoming request against
 * the minimum required for a given route — break-glass / financial /
 * PHI / admin paths gate at AAL2 or AAL3, low-risk read paths at
 * AAL1.
 *
 *   const aal = b.auth.aal.fromMethods({
 *     password:  true,    // memorized secret (single factor)
 *     webauthn:  true,    // multi-factor cryptographic authenticator
 *   });   // → "AAL3"
 *
 *   b.middleware.requireAal({ minimum: "AAL2" })
 *
 * SP 800-63-4 (final, 2026) replaces SP 800-63-3 (2017). The band
 * ordering is unchanged; the framework helpers reflect the 2026
 * vocabulary (memorized secret / single-factor / multi-factor /
 * phishing-resistant) rather than the older "Something you know /
 * are / have" trichotomy.
 */

var validateOpts = require("../validate-opts");
var { AuthError } = require("../framework-error");

// ---- band constants ----
//
// Strings (not enums) so operator audit logs / observability sinks
// see the canonical "AAL1" / "AAL2" / "AAL3" labels directly.

var AAL1 = "AAL1";
var AAL2 = "AAL2";
var AAL3 = "AAL3";

var BANDS_ORDER = [AAL1, AAL2, AAL3];

function _bandRank(band) {
  var idx = BANDS_ORDER.indexOf(band);
  if (idx === -1) return -1;
  return idx;
}

// ---- method classification ----
//
// Per SP 800-63B / 63-4 §4.2.1 — each authenticator class carries an
// implicit factor count. The compose helper below combines a set of
// satisfied methods into the resulting AAL band.
//
// METHOD CLASSES:
//   - password / pin   → memorized-secret single factor
//   - totp             → out-of-band single factor
//   - sms              → restricted single factor (SP 800-63-4 §5.1.3.3
//                        marks SMS as RESTRICTED — fine for AAL1 only)
//   - webauthn         → cryptographic multi-factor (verifier-attached
//                        UV=true → phishing-resistant per SP 800-63B §5.2.5)
//   - passkey          → synonym for webauthn-with-UV (operator
//                        contract: a "passkey" implies UV=true)
//   - hardware         → hardware cryptographic single factor
//                        (smart card, FIDO U2F-only)
//   - mtls             → cryptographic single factor; combine with
//                        memorized secret for AAL2
//
// The compose function takes a methods-object `{ password: true,
// webauthn: true, ... }` and returns the resulting band. Operators
// supply the methods object based on what THEIR auth flow verified.

var KNOWN_METHODS = [
  "password", "pin", "totp", "sms", "webauthn", "passkey",
  "hardware", "mtls",
  // `uv` is a webauthn-side qualifier: when true, the
  // authenticator-data UV bit was set on the assertion. Required
  // for AAL3 paired with `webauthn` / `passkey` per SP 800-63-4
  // §5.1.7.
  "uv",
];

function fromMethods(methods) {
  if (!methods || typeof methods !== "object") {
    throw new AuthError("auth-aal/bad-methods",
      "fromMethods: methods must be an object like { password: true, webauthn: true, uv: true }");
  }
  var has = function (m) { return methods[m] === true; };
  // SP 800-63-4 §5.1.7 — WebAuthn / passkey satisfies AAL3 only when
  // user verification (UV) was actually performed on the assertion
  // (MF-CRYPT requires the verifier to confirm the user authorized
  // the operation). Pre-v0.9.2 this returned AAL3 unconditionally
  // for any webauthn:true assertion; an operator using
  // `userVerification: "preferred"` whose authenticator skipped UV
  // landed in AAL3 despite not satisfying the spec's MF requirement.
  //
  // The operator passes `methods.uv: true` when verifyAuthentication's
  // result confirmed UV on the authenticator data (vendor's
  // `userVerified` flag). When `uv` is omitted or false, webauthn
  // alone caps at AAL2 (SF-CRYPT — the cryptographic authenticator
  // is verified, but user-verification proof is missing).
  // Operators wanting the legacy optimistic path can pass
  // `methods.uv: true` based on their startAuthentication
  // `userVerification: "required"` setting having forced UV.
  if ((has("webauthn") || has("passkey")) && has("uv")) return AAL3;
  if ((has("webauthn") || has("passkey")) && !has("uv")) {
    // SF-CRYPT (cryptographic but no UV-bound MF). Combine with a
    // memorized secret to satisfy MF.
    if (has("password") || has("pin")) return AAL3;
    return AAL2;
  }
  if (has("hardware") && (has("password") || has("pin"))) return AAL3;

  if (has("password") || has("pin")) {
    if (has("totp") || has("sms") || has("hardware") || has("mtls")) return AAL2;
    return AAL1;     // memorized secret alone
  }

  if (has("hardware") || has("mtls")) return AAL1;

  throw new AuthError("auth-aal/no-methods",
    "fromMethods: methods object did not assert any known authenticator " +
    "(known: " + KNOWN_METHODS.join(", ") + ")");
}

function isValidBand(band) {
  return band === AAL1 || band === AAL2 || band === AAL3;
}

function meets(actualBand, requiredBand) {
  if (!isValidBand(actualBand)) return false;
  if (!isValidBand(requiredBand)) return false;
  return _bandRank(actualBand) >= _bandRank(requiredBand);
}

// ---- helper for operator-side AAL ↔ AMR JWT claim ----
//
// SP 800-63-4 doesn't define a JWT claim shape; operators emitting
// access tokens with AAL info typically use `acr` / `amr` (RFC 9068
// §3 / OpenID Connect Core §2). The framework leaves that wiring to
// the operator — but the constants make the AMR strings consistent.
// RFC 8176 §2 — registered AMR values. Pre-v0.9.x mapped WEBAUTHN to
// `fido-u2f`; that's the OLD U2F protocol AMR. Modern WebAuthn
// authenticators use the `hwk` ("proof-of-possession of a hardware-
// secured key") AMR — the same one HARDWARE uses, since WebAuthn IS
// a hardware-cryptographic-authenticator binding. PASSKEY remains a
// distinct AMR for the synced multi-device case (operators using the
// FIDO-published "passkey" AMR can disambiguate from one-device hwk).
var AMR = Object.freeze({
  PASSWORD:  "pwd",
  PIN:       "pin",
  TOTP:      "otp",
  SMS:       "sms",
  WEBAUTHN:  "hwk",
  PASSKEY:   "passkey",
  HARDWARE:  "hwk",
  MTLS:      "mtls",
});

module.exports = {
  AAL1:         AAL1,
  AAL2:         AAL2,
  AAL3:         AAL3,
  BANDS:        Object.freeze([AAL1, AAL2, AAL3]),
  KNOWN_METHODS: Object.freeze(KNOWN_METHODS),
  AMR:          AMR,
  fromMethods:  fromMethods,
  isValidBand:  isValidBand,
  meets:        meets,
  // Operator-facing optional-band validator — used by middleware below.
  _validateOpts: validateOpts,
};
