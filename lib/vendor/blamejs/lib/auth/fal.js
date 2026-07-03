// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.auth.fal
 * @nav        Identity
 * @title      NIST 800-63-4 FAL Classifier
 * @order      120
 *
 * @intro
 *   NIST SP 800-63-4 Federation Assurance Levels — FAL1 / FAL2 /
 *   FAL3. While AAL describes the rigor of authentication (what the
 *   user did to prove they are who they say they are), FAL describes
 *   the rigor of the FEDERATION assertion that carried that
 *   authentication from the IdP to the RP.
 *
 *   FAL bands per NIST 800-63C-4:
 *
 *     FAL1: Bearer assertion delivered through the front channel
 *           (typical OIDC ID token over the browser redirect).
 *           Signed by the IdP; verified by the RP. No audience
 *           binding beyond the standard `aud` claim.
 *
 *     FAL2: Bearer assertion delivered through the back channel
 *           OR front-channel assertion that is encrypted to the RP.
 *           Replay-protection nonce required. Typical OIDC
 *           Authorization Code Flow with mTLS or DPoP-bound token.
 *
 *     FAL3: Holder-of-Key assertion. RP verifies the subject
 *           cryptographically holds a key bound to the assertion
 *           (mTLS client-cert pinned to the subject, DPoP-bound +
 *           audience-restricted, OR SAML HoK SubjectConfirmation).
 *           Defeats stolen-bearer-token replay.
 *
 *   Operators classify the FAL of an incoming federation assertion
 *   via `fromAssertion(opts)` — pass the assertion's properties
 *   (channel, encrypted, hokBinding, etc.) and get back the band.
 *   Compose with `b.middleware.requireFal({ minimum: "FAL2" })` for
 *   the gate.
 *
 * @card
 *   NIST 800-63-4 Federation Assurance Level classifier — describes the rigor of the federation assertion (FAL1 bearer / FAL2 encrypted-or-back-channel / FAL3 Holder-of-Key) carried from IdP to RP.
 */

var validateOpts = require("../validate-opts");
var { AuthError } = require("../framework-error");

var FAL1 = "FAL1";
var FAL2 = "FAL2";
var FAL3 = "FAL3";

var BANDS = Object.freeze([FAL1, FAL2, FAL3]);

function _bandRank(band) {
  if (band === FAL1) return 1;
  if (band === FAL2) return 2;
  if (band === FAL3) return 3;
  return 0;
}

/**
 * @primitive b.auth.fal.isValidBand
 * @signature b.auth.fal.isValidBand(band)
 * @since     0.8.87
 * @status    stable
 *
 * Predicate returning `true` when `band` is one of the documented
 * FAL band strings (`"FAL1"` / `"FAL2"` / `"FAL3"`).
 *
 * @example
 *   b.auth.fal.isValidBand("FAL2");  // → true
 *   b.auth.fal.isValidBand("FALX");  // → false
 */
function isValidBand(band) {
  return _bandRank(band) > 0;
}

/**
 * @primitive b.auth.fal.meets
 * @signature b.auth.fal.meets(actualBand, requiredBand)
 * @since     0.8.87
 * @status    stable
 *
 * Predicate returning `true` when `actualBand` satisfies the
 * `requiredBand` floor (FAL3 ≥ FAL2 ≥ FAL1). Invalid band strings
 * on either argument return `false` — operators using `meets`
 * directly for authorization decisions never get a "true" verdict
 * out of a malformed input pair.
 *
 * @example
 *   b.auth.fal.meets("FAL3", "FAL2");    // → true
 *   b.auth.fal.meets("FAL1", "FAL2");    // → false
 *   b.auth.fal.meets("FAL1", "FALX");    // → false (invalid required band)
 *   b.auth.fal.meets("bad", "bad");      // → false (both invalid)
 */
function meets(actualBand, requiredBand) {
  // Validate BOTH inputs before comparing ranks. The previous
  // implementation compared raw ranks (`>=`) — unknown bands mapped
  // to rank 0 and `0 >= 0` returned true, contradicting the
  // documented contract and producing false-positive authorization
  // decisions for operators using meets() directly.
  if (!isValidBand(actualBand) || !isValidBand(requiredBand)) return false;
  return _bandRank(actualBand) >= _bandRank(requiredBand);
}

/**
 * @primitive b.auth.fal.fromAssertion
 * @signature b.auth.fal.fromAssertion(opts)
 * @since     0.8.87
 * @status    stable
 *
 * Classify an incoming federation assertion's FAL band per NIST
 * 800-63C-4. Returns one of `"FAL1"` / `"FAL2"` / `"FAL3"`. Throws
 * `auth/bad-fal-opts` on missing required fields.
 *
 *   - HoK binding (mTLS client-cert pinned, DPoP-bound, SAML HoK) → FAL3
 *   - Back-channel delivery OR encrypted-to-RP front-channel +
 *     replay-protection nonce → FAL2
 *   - Anything else → FAL1
 *
 * The classifier is conservative: missing replay-protection on a
 * back-channel assertion downgrades to FAL1 because §5.2 requires
 * nonce / jti binding before back-channel can claim FAL2.
 *
 * @opts
 *   channel:                  "front" | "back",   // REQUIRED
 *   encrypted:                boolean,             // assertion encrypted to RP
 *   replayProtected:          boolean,             // nonce / jti / iat binding present
 *   backChannelAuthenticated: boolean,             // back-channel transport-auth'd (mTLS / signed) — required for FAL2 over plain back-channel
 *   hokBinding:               "mtls" | "dpop" | "saml-hok" | null,
 *                                                  // proof-of-possession binding present
 *   bearerOnly:               boolean,             // alias for hokBinding === null
 *
 * @example
 *   var fal = b.auth.fal.fromAssertion({
 *     channel:         "back",
 *     encrypted:       false,
 *     replayProtected: true,
 *     hokBinding:      null,
 *   });
 *   // → "FAL2"
 *
 *   var fal3 = b.auth.fal.fromAssertion({
 *     channel:         "back",
 *     hokBinding:      "mtls",
 *     replayProtected: true,
 *   });
 *   // → "FAL3"
 */
function fromAssertion(opts) {
  if (!opts || typeof opts !== "object") {
    throw new AuthError("auth/bad-fal-opts",
      "fal.fromAssertion: opts required (channel + replayProtected at minimum)");
  }
  if (opts.channel !== "front" && opts.channel !== "back") {
    throw new AuthError("auth/bad-fal-opts",
      "fal.fromAssertion: channel must be 'front' or 'back'");
  }
  var hokBinding = opts.hokBinding;
  // `bearerOnly: true` is the explicit alias for "no proof-of-possession
  // binding" (hokBinding === null). It contradicts a non-null hokBinding;
  // refuse the contradiction at the entry point rather than silently
  // picking one — an operator who sets both has a config bug.
  if (opts.bearerOnly === true) {
    if (hokBinding !== undefined && hokBinding !== null) {
      throw new AuthError("auth/bad-fal-opts",
        "fal.fromAssertion: bearerOnly:true conflicts with hokBinding '" + hokBinding +
        "' (bearerOnly forces no proof-of-possession binding)");
    }
    hokBinding = null;
  }
  if (hokBinding !== undefined && hokBinding !== null) {
    if (hokBinding !== "mtls" && hokBinding !== "dpop" && hokBinding !== "saml-hok") {
      throw new AuthError("auth/bad-fal-opts",
        "fal.fromAssertion: hokBinding must be 'mtls' | 'dpop' | 'saml-hok' | null");
    }
  }

  // FAL3 — Holder-of-Key with replay protection.
  if (hokBinding && opts.replayProtected === true) {
    return FAL3;
  }

  // FAL2 per NIST SP 800-63C-4 §5.2 requires "injection
  // protection" on the back-channel: either the back-channel itself is
  // encrypted-and-authenticated (mTLS / signed transport) OR the
  // assertion is encrypted to the RP. A plain HTTP back-channel with
  // only nonce/jti replay protection is FAL1 — `replayProtected` alone
  // doesn't satisfy the §5.2 MUST. Operators using a plain
  // back-channel set `backChannelAuthenticated: true` when their
  // transport carries server-to-server mTLS / signed-JWT auth.
  var replaySafe = opts.replayProtected === true;
  var injectionProtected = opts.encrypted === true || opts.backChannelAuthenticated === true;
  if (replaySafe && injectionProtected && (opts.channel === "back" || opts.encrypted === true)) {
    return FAL2;
  }

  // Everything else — FAL1 (bearer front-channel).
  return FAL1;
}

/**
 * @primitive b.auth.fal.requireFal
 * @signature b.auth.fal.requireFal(minimumBand)
 * @since     0.8.87
 * @status    stable
 * @related   b.auth.fal.fromAssertion
 *
 * Build a guard that throws `auth/fal-insufficient` when the
 * supplied band is below the minimum. The middleware form
 * (`b.middleware.requireFal`) wraps this guard at the request layer.
 *
 * @example
 *   var fal3Only = b.auth.fal.requireFal("FAL3");
 *   fal3Only(req.session.federationFal);
 *   // throws auth/fal-insufficient if not FAL3
 */
function requireFal(minimumBand) {
  validateOpts.requireNonEmptyString(
    minimumBand, "fal.requireFal.minimumBand", AuthError, "auth/bad-fal-band");
  if (!isValidBand(minimumBand)) {
    throw new AuthError("auth/bad-fal-band",
      "fal.requireFal: minimumBand must be one of " + BANDS.join(", "));
  }
  return function falGuard(actualBand) {
    if (!isValidBand(actualBand) || !meets(actualBand, minimumBand)) {
      throw new AuthError("auth/fal-insufficient",
        "fal.requireFal: actual band '" + actualBand + "' does not meet minimum '" + minimumBand + "'");
    }
    return actualBand;
  };
}

module.exports = {
  FAL1:           FAL1,
  FAL2:           FAL2,
  FAL3:           FAL3,
  BANDS:          BANDS,
  isValidBand:    isValidBand,
  meets:          meets,
  fromAssertion:  fromAssertion,
  requireFal:     requireFal,
};
