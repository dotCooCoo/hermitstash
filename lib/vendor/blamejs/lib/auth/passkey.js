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
var MAX_NAME_LEN = 256;                                                            // UTF-16 codepoint count, not bytes

function _vendor() {
  return _wa;
}

function _requireString(v, name) {
  if (typeof v !== "string" || v.length === 0) {
    throw new AuthError("auth-passkey/missing-" + name,
      name + " is required (non-empty string)");
  }
}

// WebAuthn extensions allowlist. Pre-v0.9.x `opts.extensions`
// was forwarded verbatim to the vendor, letting an operator (or a
// caller threading user-input through opts) ship arbitrary extension
// keys to the authenticator. Restrict to the framework-supported
// extension surface (`prf` / `largeBlob` / `credBlob`) and route every
// value through the matching `extensions.<name>(args)` builder so the
// shape is validated. Operators with custom extensions opt in via
// { allowUnknownExtensions: true } with a documented reason.
var ALLOWED_EXTENSION_KEYS = Object.freeze({
  prf:        1,
  largeBlob:  1,
  credBlob:   1,
});
function _validateExtensions(extensions, allowUnknown) {
  if (extensions === undefined || extensions === null) return undefined;
  if (typeof extensions !== "object" || Array.isArray(extensions)) {
    throw new AuthError("auth-passkey/bad-extensions",
      "opts.extensions must be a plain object");
  }
  var out = {};
  var keys = Object.keys(extensions);
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    if (!Object.prototype.hasOwnProperty.call(ALLOWED_EXTENSION_KEYS, k)) {
      if (allowUnknown === true) {
        out[k] = extensions[k];
        continue;
      }
      throw new AuthError("auth-passkey/unknown-extension",
        "opts.extensions['" + k + "'] not in the framework-supported set " +
        "(allowed: " + Object.keys(ALLOWED_EXTENSION_KEYS).join(", ") +
        "). Pass `allowUnknownExtensions: true` to opt out.");
    }
    // Route every recognised extension through its builder so the
    // shape is validated (PRF eval salt length, largeBlob support
    // values, credBlob ≤ 32 bytes). Builder output replaces the raw
    // input so the wire shape is always the spec-correct one.
    if (k === "prf")       Object.assign(out, _prfExt(extensions.prf));
    if (k === "largeBlob") Object.assign(out, _largeBlobExt(extensions.largeBlob));
    if (k === "credBlob")  Object.assign(out, _credBlobExt(extensions.credBlob));
  }
  return out;
}

// ---- Registration ----

async function startRegistration(opts) {
  if (!opts) throw new AuthError("auth-passkey/missing-opts", "opts is required");
  _requireString(opts.rpName, "rpName");
  _requireString(opts.rpId, "rpId");
  _requireString(opts.userName, "userName");

  var sel = opts.authenticatorSelection || {};
  var safeExtensions = _validateExtensions(opts.extensions, opts.allowUnknownExtensions === true);
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
    extensions:           safeExtensions,
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

function _validateExpectedOrigin(value) {
  if (typeof value === "string") {
    if (value.length === 0) {
      throw new AuthError("auth-passkey/missing-expectedOrigin",
        "expectedOrigin must be a non-empty string or array of strings");
    }
    return;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) {
      throw new AuthError("auth-passkey/missing-expectedOrigin",
        "expectedOrigin array must contain at least one non-empty string");
    }
    for (var i = 0; i < value.length; i += 1) {
      if (typeof value[i] !== "string" || value[i].length === 0) {
        throw new AuthError("auth-passkey/missing-expectedOrigin",
          "expectedOrigin[" + i + "] must be a non-empty string");
      }
    }
    return;
  }
  throw new AuthError("auth-passkey/missing-expectedOrigin",
    "expectedOrigin must be a non-empty string or array of strings");
}

async function verifyRegistration(opts) {
  if (!opts) throw new AuthError("auth-passkey/missing-opts", "opts is required");
  if (!opts.response) {
    throw new AuthError("auth-passkey/missing-response", "opts.response is required");
  }
  _requireString(opts.expectedChallenge, "expectedChallenge");
  // Multi-origin deployments (web + admin subdomain) need string[].
  _validateExpectedOrigin(opts.expectedOrigin);
  _requireString(opts.expectedRPID, "expectedRPID");

  var rv = await _vendor().verifyRegistrationResponse({
    response:           opts.response,
    expectedChallenge:  opts.expectedChallenge,
    expectedOrigin:     opts.expectedOrigin,
    expectedRPID:       opts.expectedRPID,
    requireUserVerification: opts.requireUserVerification !== false,
  });
  // WebAuthn L3 §6.1.3 — surface authenticator-data BE/BS flags as
  // named fields. backupEligible (BE) signals the credential CAN be
  // backed up to a cloud account; backupState (BS) signals it IS
  // currently backed up. Operators key trust decisions on these
  // (single-device passkey → require step-up; multi-device synced
  // passkey → strong signal). The vendor parses authData and exposes
  // credentialDeviceType ("singleDevice" | "multiDevice") and
  // credentialBackedUp (boolean) on registrationInfo; we map them to
  // the spec's flag names and add them to the top-level result so
  // callers don't have to dig through registrationInfo.
  if (rv && rv.registrationInfo) {
    rv.backupEligible = rv.registrationInfo.credentialDeviceType === "multiDevice";
    rv.backupState    = rv.registrationInfo.credentialBackedUp === true;
  } else {
    rv = rv || {};
    rv.backupEligible = false;
    rv.backupState    = false;
  }
  return rv;
}

// ---- Authentication ----

// startAuthentication accepts an optional `mediation` token that the
// caller passes through verbatim to the browser as
// `navigator.credentials.get({ publicKey, mediation })`. The descriptor
// itself doesn't carry mediation — it's a separate argument on the
// page — but startAuthentication echoes it onto the returned options
// so the operator's transport (typically a JSON GET) carries it to
// the page without losing the value. Allowed tokens per the W3C
// Credential Management spec: "silent" / "optional" / "required" /
// "conditional". "conditional" enables passkey autofill on
// <input autocomplete="webauthn">.
// Null-prototype map so `opts.mediation === "__proto__"` /
// `"constructor"` can't truthy-match an inherited property and slip
// past the allowlist.
var ALLOWED_MEDIATION = Object.assign(Object.create(null),
  { silent: 1, optional: 1, required: 1, conditional: 1 });

async function startAuthentication(opts) {
  if (!opts) throw new AuthError("auth-passkey/missing-opts", "opts is required");
  _requireString(opts.rpId, "rpId");
  if (opts.mediation !== undefined &&
      !Object.prototype.hasOwnProperty.call(ALLOWED_MEDIATION, opts.mediation)) {
    throw new AuthError("auth-passkey/bad-mediation",
      "mediation must be one of silent/optional/required/conditional");
  }

  var safeAuthExtensions = _validateExtensions(opts.extensions, opts.allowUnknownExtensions === true);
  var options = await _vendor().generateAuthenticationOptions({
    rpID:               opts.rpId,
    userVerification:   opts.userVerification || "preferred",
    allowCredentials:   opts.allowCredentials || [],
    timeout:            opts.timeout,
    extensions:         safeAuthExtensions,
  });
  if (!opts.hints) {
    options.hints = ["client-device", "hybrid"];
  } else {
    options.hints = opts.hints;
  }
  if (opts.mediation !== undefined) {
    options.mediation = opts.mediation;
  }
  return options;
}

// conditionalAuthOptions — convenience wrapper for the passkey-autofill
// flow (mediation: "conditional"). Browsers require an empty
// allowCredentials list, presence-only userVerification (so the
// autofill chip can surface without forcing biometric), and a present
// challenge. Returns an object shaped for
// `navigator.credentials.get({ publicKey: <opts>, mediation: "conditional" })`.
async function conditionalAuthOptions(opts) {
  if (!opts) throw new AuthError("auth-passkey/missing-opts", "opts is required");
  _requireString(opts.rpId, "rpId");

  var safeCondExtensions = _validateExtensions(opts.extensions, opts.allowUnknownExtensions === true);
  var options = await _vendor().generateAuthenticationOptions({
    rpID:               opts.rpId,
    // For conditional UI the spec mandates an empty allowCredentials
    // list — discoverable credentials only. Supplying a list here
    // suppresses the autofill chip in current browsers.
    allowCredentials:   [],
    userVerification:   opts.userVerification || "preferred",
    timeout:            opts.timeout,
    extensions:         safeCondExtensions,
  });
  options.mediation = "conditional";
  if (!opts.hints) {
    options.hints = ["client-device", "hybrid"];
  } else {
    options.hints = opts.hints;
  }
  return options;
}

// ---- WebAuthn L3 extension helpers (PRF / largeBlob / credBlob) ----
//
// Pre-compute the spec-correct shape so callers don't have to remember
// (a) what the field is called this year, (b) which inputs travel as
// base64url vs Uint8Array, (c) which support the {support:"required"}
// contract. Validation tier: throw at config-time. Misuse here is a
// coding bug, not a request-shape thing.

// CTAP2.1 §6.5 — PRF eval inputs are 32-byte salts. Caps every
// extension input that ships through the binary normalizer.
var MAX_EXT_INPUT_BYTES = 32;                                                                    // CTAP2.1 §6.5 PRF salt length

function _b64urlExtInput(value, name, maxBytes) {
  // Accept a base64url string OR a Buffer / Uint8Array. Normalize the
  // wire shape to base64url (the JSON descriptor ships base64url; the
  // browser turns it into an ArrayBuffer before passing to the
  // authenticator).
  //
  // When `maxBytes` is set, refuse decoded inputs longer than
  // the cap. Per CTAP2.1 §6.5 PRF salts are 32 bytes; pre-v0.9.x the
  // framework accepted arbitrary length, which is undefined behavior on
  // authenticators that may truncate / reject / behave inconsistently.
  if (typeof value === "string") {
    if (value.length === 0 || !safeBuffer.BASE64URL_RE.test(value)) {
      throw new AuthError("auth-passkey/bad-extension-input",
        name + " must be base64url (no padding) when string");
    }
    if (typeof maxBytes === "number") {
      var decoded = Buffer.from(value, "base64url");
      if (safeBuffer.byteLengthOf(decoded) > maxBytes) {
        throw new AuthError("auth-passkey/extension-input-too-large",
          name + " decoded length " + decoded.length + " exceeds " + maxBytes + " bytes");
      }
    }
    return value;
  }
  if (Buffer.isBuffer(value)) {
    if (typeof maxBytes === "number" && safeBuffer.byteLengthOf(value) > maxBytes) {
      throw new AuthError("auth-passkey/extension-input-too-large",
        name + " length " + value.length + " exceeds " + maxBytes + " bytes");
    }
    return value.toString("base64url");
  }
  if (value instanceof Uint8Array) {
    if (typeof maxBytes === "number" && safeBuffer.byteLengthOf(value) > maxBytes) {
      throw new AuthError("auth-passkey/extension-input-too-large",
        name + " length " + value.length + " exceeds " + maxBytes + " bytes");
    }
    return Buffer.from(value).toString("base64url");
  }
  throw new AuthError("auth-passkey/bad-extension-input",
    name + " must be base64url string, Buffer, or Uint8Array");
}

// PRF (Pseudo-Random Function) extension — WebAuthn L3 §10.1.2.
// Authenticator-bound HKDF source. eval inputs are 32-byte salts; the
// authenticator returns deterministic 32-byte outputs the operator
// uses as a key-encryption key (vault unlock, file-encryption seed).
// Shape: `{ prf: { eval: { first, second? } } }` per extension-id "prf".
function _prfExt(args) {
  if (!args || !args.eval) {
    throw new AuthError("auth-passkey/missing-eval",
      "extensions.prf({ eval: { first, second? } }) is required");
  }
  if (args.eval.first === undefined || args.eval.first === null) {
    throw new AuthError("auth-passkey/missing-prf-first",
      "extensions.prf eval.first is required");
  }
  // CTAP2.1 §6.5 caps PRF salts at 32 bytes.
  var out = { prf: { eval: { first: _b64urlExtInput(args.eval.first, "eval.first", MAX_EXT_INPUT_BYTES) } } };
  if (args.eval.second !== undefined && args.eval.second !== null) {
    out.prf.eval.second = _b64urlExtInput(args.eval.second, "eval.second", MAX_EXT_INPUT_BYTES);
  }
  return out;
}

// largeBlob extension — WebAuthn L3 §10.3.
// Per-credential opaque blob storage. At registration the operator
// asks for support: "preferred" | "required". At auth time the
// operator asks to read OR write, never both in the same assertion.
function _largeBlobExt(args) {
  if (!args) {
    throw new AuthError("auth-passkey/missing-largeblob",
      "extensions.largeBlob({ support? | read? | write? }) is required");
  }
  var out = { largeBlob: {} };
  var SUPPORT = { preferred: 1, required: 1 };
  var modes = 0;
  if (args.support !== undefined) {
    if (!Object.prototype.hasOwnProperty.call(SUPPORT, args.support)) {
      throw new AuthError("auth-passkey/bad-largeblob-support",
        "extensions.largeBlob support must be 'preferred' or 'required'");
    }
    out.largeBlob.support = args.support;
    modes++;
  }
  if (args.read === true) {
    out.largeBlob.read = true;
    modes++;
  } else if (args.read !== undefined && args.read !== false) {
    throw new AuthError("auth-passkey/bad-largeblob-read",
      "extensions.largeBlob read must be a boolean");
  }
  if (args.write !== undefined && args.write !== null) {
    if (!Buffer.isBuffer(args.write) && !(args.write instanceof Uint8Array)) {
      throw new AuthError("auth-passkey/bad-largeblob-write",
        "extensions.largeBlob write must be a Uint8Array / Buffer");
    }
    out.largeBlob.write = Buffer.from(args.write).toString("base64url");
    modes++;
  }
  if (modes === 0) {
    throw new AuthError("auth-passkey/empty-largeblob",
      "extensions.largeBlob({}) needs support, read, or write");
  }
  if (args.read === true && args.write !== undefined && args.write !== null) {
    throw new AuthError("auth-passkey/conflicting-largeblob",
      "extensions.largeBlob — read and write are mutually exclusive");
  }
  return out;
}

// credBlob extension — WebAuthn L3 §10.5.
// Server-supplied opaque blob (≤32 bytes per CTAP2.1) bound to the
// credential at registration. Returned in subsequent assertions.
// Shape: `{ credBlob: <base64url> }`.
function _credBlobExt(args) {
  if (!args || args.blob === undefined || args.blob === null) {
    throw new AuthError("auth-passkey/missing-credblob",
      "extensions.credBlob({ blob }) is required");
  }
  var buf;
  if (Buffer.isBuffer(args.blob)) {
    buf = args.blob;
  } else if (args.blob instanceof Uint8Array) {
    buf = Buffer.from(args.blob);
  } else {
    throw new AuthError("auth-passkey/bad-credblob",
      "extensions.credBlob blob must be a Uint8Array / Buffer");
  }
  if (buf.length === 0 || buf.length > 32) {                                       // CTAP2.1 §11.1 credBlob max
    throw new AuthError("auth-passkey/credblob-bad-length",
      "extensions.credBlob blob must be 1-32 bytes (CTAP2.1 §11.1)");
  }
  return { credBlob: buf.toString("base64url") };
}

var extensions = {
  prf:       _prfExt,
  largeBlob: _largeBlobExt,
  credBlob:  _credBlobExt,
};

async function verifyAuthentication(opts) {
  if (!opts) throw new AuthError("auth-passkey/missing-opts", "opts is required");
  if (!opts.response) {
    throw new AuthError("auth-passkey/missing-response", "opts.response is required");
  }
  _requireString(opts.expectedChallenge, "expectedChallenge");
  _validateExpectedOrigin(opts.expectedOrigin);
  _requireString(opts.expectedRPID, "expectedRPID");
  if (!opts.credential || !opts.credential.id || !opts.credential.publicKey) {
    throw new AuthError("auth-passkey/missing-credential",
      "opts.credential { id, publicKey, counter? } is required");
  }
  // Counter regression bypass fix — pre-v0.9.2
  // shape `opts.credential.counter || 0` silently zeroed an
  // undefined / null / NaN counter, defeating CTAP 2.1 clone-
  // detection on credentials whose stored counter is > 0. An
  // operator who deserialized the credential from a column that
  // dropped the counter would unknowingly accept a cloned
  // authenticator. Require an explicit non-negative integer.
  var counter;
  if (opts.credential.counter === undefined || opts.credential.counter === null) {
    // First-time-stored credentials legitimately have no counter
    // yet (registration ran on a vendor returning 0). Operators
    // MUST persist whatever the vendor returned; if they didn't,
    // refuse rather than silently coerce.
    throw new AuthError("auth-passkey/missing-counter",
      "opts.credential.counter is required (set to 0 at registration; " +
      "store the newCounter returned by verifyAuthentication on every " +
      "successful auth). undefined / null is refused to prevent clone-" +
      "detection bypass when the persisted column is missing.");
  }
  if (typeof opts.credential.counter !== "number" ||
      !isFinite(opts.credential.counter) ||
      opts.credential.counter < 0 ||
      Math.floor(opts.credential.counter) !== opts.credential.counter) {
    throw new AuthError("auth-passkey/bad-counter",
      "opts.credential.counter must be a non-negative integer (got " +
      typeof opts.credential.counter + ")");
  }
  counter = opts.credential.counter;

  var rv = await _vendor().verifyAuthenticationResponse({
    response:           opts.response,
    expectedChallenge:  opts.expectedChallenge,
    expectedOrigin:     opts.expectedOrigin,
    expectedRPID:       opts.expectedRPID,
    credential:         {
      id:         opts.credential.id,
      publicKey:  opts.credential.publicKey,
      counter:    counter,
      transports: opts.credential.transports,
    },
    requireUserVerification: opts.requireUserVerification !== false,
  });
  // WebAuthn L3 §6.1.3 — same BE/BS surfacing as verifyRegistration.
  // Authentication assertions also carry the BE/BS bits in authData; a
  // credential that registered as single-device but later asserts as
  // multi-device (or vice versa) is a backup-state-changed signal worth
  // auditing at the operator level. We expose the current values so the
  // caller can compare against what they persisted at registration.
  if (rv && rv.authenticationInfo) {
    rv.backupEligible = rv.authenticationInfo.credentialDeviceType === "multiDevice";
    rv.backupState    = rv.authenticationInfo.credentialBackedUp === true;
  } else {
    rv = rv || {};
    rv.backupEligible = false;
    rv.backupState    = false;
  }
  return rv;
}

/**
 * @primitive b.auth.passkey.compareBackupState
 * @signature b.auth.passkey.compareBackupState(prev, current)
 * @since     0.9.57
 *
 * WebAuthn L3 §6.1.3. Inspect the credential's persisted BE
 * (backupEligible) + BS (backupState) flags against the values
 * surfaced on a fresh assertion. Returns a normalized verdict the
 * operator routes into audit / step-up decisions:
 *
 *   - `ok` — flags unchanged
 *   - `be-flipped-on` — credential newly backup-eligible (the
 *     authenticator manufacturer enabled cloud-backup on a previously
 *     single-device credential; suspicious — operator surfaces
 *     step-up)
 *   - `be-flipped-off` — credential lost backup eligibility (rare;
 *     authenticator firmware downgrade or vendor policy change)
 *   - `bs-flipped-on` — credential is now backed up (user enrolled
 *     in cloud-sync after initial registration; legitimate but
 *     audit-worthy)
 *   - `bs-flipped-off` — credential no longer backed up (user
 *     disabled cloud-sync; legitimate but audit-worthy)
 *
 * Operators wire this against the credential row's persisted
 * `backupEligible` / `backupState` fields and the corresponding
 * fields on `verifyAuthentication`'s return value.
 *
 * @example
 *   var rv   = await b.auth.passkey.verifyAuthentication(opts);
 *   var diff = b.auth.passkey.compareBackupState(stored, rv);
 *   if (diff.verdict !== "ok") {
 *     await audit.emit({ event: "passkey.backup-state-changed", metadata: diff });
 *     if (diff.verdict === "be-flipped-on") { requireStepUp(); }
 *   }
 */
function compareBackupState(prev, current) {
  if (!prev || typeof prev !== "object") {
    throw new AuthError("auth-passkey/bad-compare-backup",
      "compareBackupState: prev must be an object with { backupEligible, backupState }");
  }
  if (!current || typeof current !== "object") {
    throw new AuthError("auth-passkey/bad-compare-backup",
      "compareBackupState: current must be an object with { backupEligible, backupState }");
  }
  var pBE = prev.backupEligible === true;
  var pBS = prev.backupState    === true;
  var cBE = current.backupEligible === true;
  var cBS = current.backupState    === true;
  var verdict = "ok";
  if (pBE !== cBE) verdict = cBE ? "be-flipped-on"  : "be-flipped-off";
  else if (pBS !== cBS) verdict = cBS ? "bs-flipped-on" : "bs-flipped-off";
  return {
    verdict:                verdict,
    prevBackupEligible:     pBE,
    prevBackupState:        pBS,
    currentBackupEligible:  cBE,
    currentBackupState:     cBS,
  };
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
  conditionalAuthOptions:       conditionalAuthOptions,
  extensions:                   extensions,
  signalUnknownCredential:      signalUnknownCredential,
  signalAllAcceptedCredentials: signalAllAcceptedCredentials,
  signalCurrentUserDetails:     signalCurrentUserDetails,
  compareBackupState:           compareBackupState,
  ALLOWED_EXTENSION_KEYS:       ALLOWED_EXTENSION_KEYS,
};
