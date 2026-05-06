"use strict";
/**
 * Passkey / WebAuthn (FIDO2) — registration + authentication primitives.
 *
 * Built on the vendored @simplewebauthn/server (lib/vendor/simplewebauthn-
 * server.cjs). This file is a thin wrapper that names the surface in the
 * framework's auth-namespace style and validates inputs through
 * AuthError so failures are framed consistently with auth.password and
 * auth.totp. The vendor handles CBOR parsing, attestation statement
 * validation, COSE key conversion, and signature verification across
 * the WebAuthn algorithm set; we don't reimplement any of it.
 *
 * The four phases of a WebAuthn flow:
 *
 *   Registration (user adds a passkey to their account):
 *     1. server: startRegistration({ rpName, rpId, userName, userDisplayName,
 *        excludeCredentials? }) → { challenge, … }. Server stores the
 *        challenge in the session.
 *     2. browser: navigator.credentials.create({ publicKey: <options> })
 *        → registration response with attestation.
 *     3. server: verifyRegistration({ response, expectedChallenge,
 *        expectedOrigin, expectedRPID }) → { verified, registrationInfo:
 *        { credential: { id, publicKey, counter }, … } }. Persist
 *        credential.id (base64url) + credential.publicKey + counter.
 *
 *   Authentication (user logs in with their passkey):
 *     1. server: startAuthentication({ rpId, userVerification? })
 *        → { challenge, … }. Server stores challenge in session.
 *     2. browser: navigator.credentials.get({ publicKey: <options> })
 *        → assertion response.
 *     3. server: lookup the credential by response.id (base64url),
 *        then verifyAuthentication({ response, expectedChallenge,
 *        expectedOrigin, expectedRPID, credential: { id, publicKey,
 *        counter, transports? } }) → { verified, authenticationInfo:
 *        { newCounter } }. Persist newCounter (clone-detection).
 *
 * Public API (b.auth.passkey.*):
 *   await passkey.startRegistration(opts)        → registration options
 *   await passkey.verifyRegistration(opts)       → { verified, registrationInfo? }
 *   await passkey.startAuthentication(opts)      → authentication options
 *   await passkey.verifyAuthentication(opts)     → { verified, authenticationInfo? }
 *
 * Framework defaults:
 *   - attestationType: "none" — don't request attestation. Most apps
 *     don't need it, and "direct" or "enterprise" attestation has
 *     deployment friction (cert chains, MDS lookups). Operators who
 *     genuinely need attestation override.
 *   - residentKey: "preferred" — discoverable credentials when the
 *     authenticator supports them; falls back to non-discoverable.
 *   - userVerification: "preferred" — accept biometric / PIN when
 *     available; fall back to presence-only.
 *   - hints: ["client-device", "hybrid"] — surface platform
 *     authenticators (Touch ID, Windows Hello) AND cross-device
 *     (1Password / Bitwarden / mobile-as-roaming-authenticator).
 *
 * No middleware decisions made here — the wrapper does NOT touch
 * sessions, audit, or DB. Routes integrate that themselves; the
 * primitive stays the smallest correct surface.
 */
var safeBuffer = require("../safe-buffer");
var _wa = require("../vendor/simplewebauthn-server.cjs");
var { AuthError } = require("../framework-error");

// W3C WebAuthn name field cap — same as the rpName/userName ceiling in
// the spec's CredentialUserEntity / PublicKeyCredentialEntity dictionaries
// (no normative limit but RPs broadly cap at 256 to defeat DOM cost).
var MAX_NAME_LEN = 256;                                                            // allow:raw-byte-literal — UTF-16 codepoint count, not bytes

function _vendor() {
  return _wa;
}

function _requireString(v, name) {
  if (typeof v !== "string" || v.length === 0) {
    throw new AuthError("auth-passkey/missing-" + name,
      name + " is required (non-empty string)");
  }
}

// ---- Registration ----

async function startRegistration(opts) {
  if (!opts) throw new AuthError("auth-passkey/missing-opts", "opts is required");
  _requireString(opts.rpName, "rpName");
  _requireString(opts.rpId, "rpId");
  _requireString(opts.userName, "userName");

  var sel = opts.authenticatorSelection || {};
  var options = await _vendor().generateRegistrationOptions({
    rpName:               opts.rpName,
    rpID:                 opts.rpId,
    userName:             opts.userName,
    userDisplayName:      opts.userDisplayName || opts.userName,
    attestationType:      opts.attestationType || "none",
    excludeCredentials:   opts.excludeCredentials || [],
    authenticatorSelection: {
      residentKey:               sel.residentKey       || "preferred",
      userVerification:          sel.userVerification  || "preferred",
      authenticatorAttachment:   sel.authenticatorAttachment,
      requireResidentKey:        sel.requireResidentKey,
    },
    timeout:              opts.timeout,
    extensions:           opts.extensions,
  });
  // Hint the browser to surface platform + cross-device authenticators
  // (Touch ID / Windows Hello AND 1Password / Bitwarden / phone-as-key).
  if (!opts.hints) {
    options.hints = ["client-device", "hybrid"];
  } else {
    options.hints = opts.hints;
  }
  return options;
}

async function verifyRegistration(opts) {
  if (!opts) throw new AuthError("auth-passkey/missing-opts", "opts is required");
  if (!opts.response) {
    throw new AuthError("auth-passkey/missing-response", "opts.response is required");
  }
  _requireString(opts.expectedChallenge, "expectedChallenge");
  _requireString(opts.expectedOrigin, "expectedOrigin");
  _requireString(opts.expectedRPID, "expectedRPID");

  return await _vendor().verifyRegistrationResponse({
    response:           opts.response,
    expectedChallenge:  opts.expectedChallenge,
    expectedOrigin:     opts.expectedOrigin,
    expectedRPID:       opts.expectedRPID,
    requireUserVerification: opts.requireUserVerification !== false,
  });
}

// ---- Authentication ----

async function startAuthentication(opts) {
  if (!opts) throw new AuthError("auth-passkey/missing-opts", "opts is required");
  _requireString(opts.rpId, "rpId");

  var options = await _vendor().generateAuthenticationOptions({
    rpID:               opts.rpId,
    userVerification:   opts.userVerification || "preferred",
    allowCredentials:   opts.allowCredentials || [],
    timeout:            opts.timeout,
    extensions:         opts.extensions,
  });
  if (!opts.hints) {
    options.hints = ["client-device", "hybrid"];
  } else {
    options.hints = opts.hints;
  }
  return options;
}

async function verifyAuthentication(opts) {
  if (!opts) throw new AuthError("auth-passkey/missing-opts", "opts is required");
  if (!opts.response) {
    throw new AuthError("auth-passkey/missing-response", "opts.response is required");
  }
  _requireString(opts.expectedChallenge, "expectedChallenge");
  _requireString(opts.expectedOrigin, "expectedOrigin");
  _requireString(opts.expectedRPID, "expectedRPID");
  if (!opts.credential || !opts.credential.id || !opts.credential.publicKey) {
    throw new AuthError("auth-passkey/missing-credential",
      "opts.credential { id, publicKey, counter? } is required");
  }

  return await _vendor().verifyAuthenticationResponse({
    response:           opts.response,
    expectedChallenge:  opts.expectedChallenge,
    expectedOrigin:     opts.expectedOrigin,
    expectedRPID:       opts.expectedRPID,
    credential:         {
      id:         opts.credential.id,
      publicKey:  opts.credential.publicKey,
      counter:    opts.credential.counter || 0,
      transports: opts.credential.transports,
    },
    requireUserVerification: opts.requireUserVerification !== false,
  });
}

// ---- WebAuthn Signal API (W3C draft, 2024) ----
//
// The signal* methods build the JSON descriptor that the operator
// returns to the client; the browser then calls the matching
// `PublicKeyCredential.signal*` method to clean up stale passkeys
// and refresh user details. These are pure builders — no I/O — so
// validation throws at the boundary and the descriptor shape is the
// W3C draft schema verbatim.

function _b64urlValid(s) {
  return typeof s === "string" && s.length > 0 && safeBuffer.BASE64URL_RE.test(s);
}

function signalUnknownCredential(opts) {
  if (!opts) throw new AuthError("auth-passkey/missing-opts", "opts is required");
  _requireString(opts.rpId, "rpId");
  _requireString(opts.credentialId, "credentialId");
  if (!_b64urlValid(opts.credentialId)) {
    throw new AuthError("auth-passkey/bad-credential-id",
      "credentialId must be base64url (no padding)");
  }
  return {
    rpId:         opts.rpId,
    credentialId: opts.credentialId,
  };
}

function signalAllAcceptedCredentials(opts) {
  if (!opts) throw new AuthError("auth-passkey/missing-opts", "opts is required");
  _requireString(opts.rpId, "rpId");
  _requireString(opts.userId, "userId");
  if (!_b64urlValid(opts.userId)) {
    throw new AuthError("auth-passkey/bad-user-id",
      "userId must be base64url (no padding)");
  }
  if (!Array.isArray(opts.allAcceptedCredentialIds)) {
    throw new AuthError("auth-passkey/bad-accepted-list",
      "allAcceptedCredentialIds must be an array");
  }
  for (var i = 0; i < opts.allAcceptedCredentialIds.length; i++) {
    if (!_b64urlValid(opts.allAcceptedCredentialIds[i])) {
      throw new AuthError("auth-passkey/bad-accepted-list",
        "allAcceptedCredentialIds[" + i + "] must be base64url");
    }
  }
  return {
    rpId:                     opts.rpId,
    userId:                   opts.userId,
    allAcceptedCredentialIds: opts.allAcceptedCredentialIds.slice(),
  };
}

function signalCurrentUserDetails(opts) {
  if (!opts) throw new AuthError("auth-passkey/missing-opts", "opts is required");
  _requireString(opts.rpId, "rpId");
  _requireString(opts.userId, "userId");
  if (!_b64urlValid(opts.userId)) {
    throw new AuthError("auth-passkey/bad-user-id",
      "userId must be base64url (no padding)");
  }
  _requireString(opts.name, "name");
  _requireString(opts.displayName, "displayName");
  // RP-relevant length cap — the descriptor is a hint to the browser,
  // not a stored value, but absurdly long names indicate a misuse and
  // we refuse rather than truncate silently.
  if (opts.name.length > MAX_NAME_LEN) {
    throw new AuthError("auth-passkey/name-too-long",
      "name must be <= " + MAX_NAME_LEN + " characters");
  }
  if (opts.displayName.length > MAX_NAME_LEN) {
    throw new AuthError("auth-passkey/displayname-too-long",
      "displayName must be <= " + MAX_NAME_LEN + " characters");
  }
  return {
    rpId:        opts.rpId,
    userId:      opts.userId,
    name:        opts.name,
    displayName: opts.displayName,
  };
}

module.exports = {
  startRegistration:            startRegistration,
  verifyRegistration:           verifyRegistration,
  startAuthentication:          startAuthentication,
  verifyAuthentication:         verifyAuthentication,
  signalUnknownCredential:      signalUnknownCredential,
  signalAllAcceptedCredentials: signalAllAcceptedCredentials,
  signalCurrentUserDetails:     signalCurrentUserDetails,
};
