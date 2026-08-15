// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Passkey / WebAuthn (FIDO2) — registration + authentication primitives.
 *
 * Ceremony options are built here; the cryptographic verification runs
 * in the vendored @blamejs/pki webauthn module (lib/vendor/blamejs-
 * pki.cjs), which handles CBOR parsing, attestation statement
 * validation, COSE key conversion, and signature verification across
 * the WebAuthn algorithm set. This file names the surface in the
 * framework's auth-namespace style, applies the relying party's
 * ceremony policy (algorithm allow-list, cross-origin refusal,
 * credential-ID binding, sign-counter regression), and frames failures
 * through AuthError consistently with auth.password and auth.totp.
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
 *        credential.id is read out of the ATTESTATION, not off the wire —
 *        persist that one. A response whose id / rawId names a different
 *        credential than the authenticator attested is refused, so it can
 *        never claim a row that belongs to somebody else.
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
 *     requireResidentKey (the WebAuthn L1 boolean) is derived from it,
 *     never read alongside it, so the pair cannot disagree; passing the
 *     legacy boolean alone still raises residentKey to "required".
 *   - userVerification: "preferred" — accept biometric / PIN when
 *     available; fall back to presence-only.
 *   - hints: ["client-device", "hybrid"] — surface platform
 *     authenticators (Touch ID, Windows Hello) AND cross-device
 *     (1Password / Bitwarden / mobile-as-roaming-authenticator). The
 *     default follows authenticatorAttachment when one is set
 *     ("cross-platform" -> ["security-key", "hybrid"], "platform" ->
 *     ["client-device"]) so the browser is not steered at an
 *     authenticator the attachment forbids. An explicit `hints` list
 *     passes through untouched.
 *   - allowedAlgorithms: [-8, -7, -257] — Ed25519, ES256, RS256. One
 *     list drives both halves of a ceremony: what startRegistration
 *     offers in pubKeyCredParams AND what the verifiers accept, so a
 *     deployment can't advertise one set and honour another. Widen it
 *     for credentials issued before the default narrowed:
 *     allowedAlgorithms: [-8, -7, -257, -36] also accepts ES512.
 *     Supported: -8, -7, -35, -36, -37, -38, -39, -257, -258, -259.
 *     RSA with SHA-1 (-65535) is refused however it is asked for.
 *   - Attestation trust anchors, per format: an apple statement chains
 *     to Apple's root, android-key to Google's, android-safetynet to
 *     GlobalSign — all pinned in lib/auth/webauthn-attestation-roots.js.
 *     Without anchoring, a "direct" attestation proves only that
 *     SOMEBODY signed it. packed / tpm / fido-u2f are NOT anchored
 *     against a pinned bundle: their chains end at whichever vendor
 *     made the key, and WebAuthn anchors those through the credential's
 *     FIDO metadata entry (b.auth.fidoMds3). attestationRoots /
 *     safetyNetRoots REPLACE the pinned set for one call, and an
 *     explicit override applies to every chain-bearing format.
 *   - registrationInfo.anchoredTo names the root a chain terminated
 *     at, or is null when it anchored at nothing — which is the normal
 *     outcome for a packed / tpm / fido-u2f security key with no
 *     attestationRoots supplied, and means the AAGUID in the statement
 *     is a CLAIM rather than a verified fact. An RP that acts on
 *     attestation provenance sets requireAttestationAnchor: true (off
 *     by default: refusing unanchored chains would reject every
 *     ordinary security key, which is not what any WebAuthn verifier
 *     does) and/or checks the AAGUID with b.auth.fidoMds3.
 *   - android-safetynet also requires Google's ctsProfileMatch (the
 *     device passed compatibility testing and is not tampered with)
 *     and refuses a response older than 60s or dated in the future —
 *     a device-integrity claim is about a moment, and an unbounded one
 *     replays. requireCtsProfileMatch: false and safetyNetMaxAgeMs
 *     move those.
 *   - credProps is requested on every registration, and the browser's
 *     answer comes back as registrationInfo.clientExtensionResults
 *     .credProps.rk — whether the credential you got is actually
 *     discoverable. Client-reported and unsigned, unlike
 *     authenticatorExtensionResults; a UX signal, not a guarantee.
 *   - Cross-origin ceremonies (clientData.crossOrigin true — WebAuthn
 *     ran in an iframe, not at the top level) are refused. A deployment
 *     that is deliberately embedded names its embedders:
 *     allowCrossOrigin: ["https://partner.example"], matched against
 *     clientData.topOrigin. `true` accepts any embedder, for the case
 *     where the partner set is not a list you can write down.
 *
 * No middleware decisions made here — the wrapper does NOT touch
 * sessions, audit, or DB. Routes integrate that themselves; the
 * primitive stays the smallest correct surface.
 */
var nodeCrypto = require("node:crypto");
var _pkiToolkit = require("../vendor/blamejs-pki.cjs");
var bCrypto = require("../crypto");
var attestationRoots = require("./webauthn-attestation-roots");
var C = require("../constants");
var cbor = require("../cbor");
var safeBuffer = require("../safe-buffer");
var safeJson = require("../safe-json");
var { AuthError } = require("../framework-error");

// W3C WebAuthn name field cap — same as the rpName/userName ceiling in
// the spec's CredentialUserEntity / PublicKeyCredentialEntity dictionaries
// (no normative limit but RPs broadly cap at 256 to defeat DOM cost).
var MAX_NAME_LEN = 256;                                                            // UTF-16 codepoint count, not bytes

function _pki() {
  return _pkiToolkit;
}

// base64url -> Buffer for the wire fields a WebAuthn response carries. Every
// one of these is attacker-supplied, so a value that is not a string is a
// refusal rather than a coercion.
function _wireBytes(value, field) {
  if (typeof value !== "string" || value.length === 0) {
    throw new AuthError("auth-passkey/bad-response",
      "response." + field + " must be a base64url string");
  }
  // CANONICAL base64url, not merely decodable. Node's decoder discards
  // characters it does not recognize, so "AQ!ID" and "A Q I D" decode to the
  // same bytes as "AQID" -- the verifier then sees the genuine signed bytes
  // and says yes, while the posted response has unboundedly many spellings.
  // Anything deduplicating or rate-limiting on the response as sent (replay
  // caches, idempotency keys, request digests) sees each spelling as new.
  if (_canonicalBase64Url(value) === null) {
    throw new AuthError("auth-passkey/bad-response",
      "response." + field + " must be canonical base64url");
  }
  return Buffer.from(value, "base64url");
}

// CollectedClientData.crossOrigin (WebAuthn L3 §5.8.1) — true when the
// ceremony ran in a frame whose top-level origin is NOT this origin. The
// underlying verifier never reads the field, so without this an RP embedded in
// a hostile top-level page is indistinguishable from a same-origin one: the
// signature, the challenge, the origin and the RP ID all check out, because
// the ceremony really did happen at this origin — inside somebody else's page.
//
// Refused by default, because that is the safe reading and a legitimate
// cross-origin RP knows it is one. `allowCrossOrigin: true` opts in.
//
// FAIL-CLOSED on a clientDataJSON that is present but unreadable. This is a
// gate, and a gate that cannot read its input must not pass it: an earlier
// version returned (allowed) on a parse failure, on the assumption that the
// verifier would refuse the document anyway. It does not -- the verifier
// accepts client data far larger than any bound worth putting on a policy
// parser, so anything between the two limits sailed through with the
// cross-origin policy never applied. The bound here now matches what the
// verifier will accept, and exceeding it refuses rather than skips.
//
// A missing or non-string field is left to _wireBytes, which names that
// problem precisely; reporting it as a cross-origin refusal would send an
// operator looking for the wrong thing.
function _refuseCrossOrigin(response, opts, ceremony) {
  var allow = opts && opts.allowCrossOrigin;
  // `true` is the blunt opt-in: every embedder, for a deployment whose
  // partners are not a list it can write down.
  if (allow === true) return;

  var raw = response && response.response && response.response.clientDataJSON;
  if (typeof raw !== "string" || raw.length === 0) return;
  var parsed;
  try {
    parsed = safeJson.parse(Buffer.from(raw, "base64url").toString("utf8"),
                            { maxBytes: MAX_CLIENT_DATA_BYTES });
  } catch (e) {
    throw new AuthError("auth-passkey/unreadable-client-data",
      "clientDataJSON could not be read to apply the cross-origin policy -- " +
      "refusing rather than skipping the check: " + ((e && e.message) || e));
  }
  if (!parsed || typeof parsed !== "object") {
    throw new AuthError("auth-passkey/unreadable-client-data",
      "clientDataJSON is not an object -- refusing rather than skipping the " +
      "cross-origin check");
  }
  if (parsed.crossOrigin !== true) return;

  // An ARRAY names the embedders this deployment actually has. Without it the
  // opt-in would be a switch that turns the protection off rather than aims
  // it: `true` accepts the hostile page just as readily as the partner one.
  //
  // clientData.topOrigin is the page the ceremony ran inside. A browser that
  // reports crossOrigin without naming it cannot be matched against a list, so
  // it does not pass one -- an unnamed embedder is exactly the case the list
  // was written to exclude.
  if (Array.isArray(allow) && allow.length > 0 &&
      typeof parsed.topOrigin === "string" && allow.indexOf(parsed.topOrigin) !== -1) {
    return;
  }

  throw new AuthError("auth-passkey/cross-origin-ceremony",
    ceremony + " ran in a cross-origin frame (clientData.crossOrigin is true)" +
    (typeof parsed.topOrigin === "string"
      ? ", embedded by " + JSON.stringify(parsed.topOrigin)
      : ", and the browser did not name the embedding page") +
    " -- the top-level page is not this origin. Pass allowCrossOrigin as an " +
    "array of permitted top origins, or true for any, only if the relying " +
    "party is deliberately embedded.");
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
  var algorithms = _resolveAllowedAlgorithms(opts.allowedAlgorithms);
  // One discoverability requirement, stated once. `residentKey` is the modern
  // field and decides when present; the L1 boolean `requireResidentKey` still
  // states the same requirement on its own and raises residentKey with it,
  // rather than being read and dropped.
  var residentKey = sel.residentKey ||
    (sel.requireResidentKey === true ? "required" : "preferred");
  var safeExtensions = _validateExtensions(opts.extensions, opts.allowUnknownExtensions === true);
  // Building the descriptor rather than delegating it: it is a JSON document
  // the browser reads, with no signature and no secret in it beyond the
  // challenge, so the only thing a library adds here is its own opinion about
  // defaults. The user handle stays a fresh random value per ceremony, which is
  // what this primitive has always emitted.
  var options = {
    challenge:            _freshChallenge(),
    rp:                   { name: opts.rpName, id: opts.rpId },
    user: {
      id:                 bCrypto.generateBytes(USER_HANDLE_BYTES).toString("base64url"),
      name:               opts.userName,
      displayName:        opts.userDisplayName || opts.userName,
    },
    pubKeyCredParams:     algorithms.map(function (a) { return { alg: a, type: "public-key" }; }),
    timeout:              _resolveTimeout(opts.timeout),
    attestation:          opts.attestationType || "none",
    excludeCredentials:   _credentialDescriptors(opts.excludeCredentials, "excludeCredentials"),
    authenticatorSelection: {
      residentKey:               residentKey,
      userVerification:          sel.userVerification  || "preferred",
      // Tied to residentKey, never read independently. The two fields state
      // ONE requirement -- "this credential must be discoverable" -- and
      // browsers in the field read one or the other, so a pair that disagrees
      // lets a browser create a NON-discoverable credential for a relying
      // party that required one. Nothing fails at registration: the credential
      // works, and only username-less and conditional-UI login are missing.
      requireResidentKey:        residentKey === "required",
    },
    // credProps is requested on every registration, merged over whatever the
    // caller asked for. The browser answers with clientExtensionResults
    // .credProps.rk -- whether the credential it actually created is
    // discoverable. residentKey: "preferred" means the authenticator is free
    // to say no, so without this the relying party cannot tell whether it got
    // a passkey it can offer username-less or conditional login with, and has
    // to assume the worse case for every credential.
    //
    // Merged AFTER the caller's extensions so it cannot be turned off by
    // accident, and it is not in ALLOWED_EXTENSION_KEYS because it takes no
    // caller input -- there is nothing here for a caller to get wrong.
    extensions:           Object.assign({}, safeExtensions, { credProps: true }),
  };
  if (sel.authenticatorAttachment !== undefined) {
    options.authenticatorSelection.authenticatorAttachment = sel.authenticatorAttachment;
  }
  // Hint the browser at which authenticators to surface. An explicit list is
  // the operator's call and passes through untouched.
  //
  // The DEFAULT follows authenticatorAttachment, because the two say the same
  // thing and the browser gives hints precedence in the UI: hinting at the
  // platform authenticator during a cross-platform ceremony offers the user a
  // path the attachment forbids, and the credential creation is then refused
  // on the authenticator they picked. With no attachment set, surface both
  // families — platform (Touch ID / Windows Hello) and cross-device
  // (1Password / Bitwarden / phone-as-key).
  if (!opts.hints) {
    if (sel.authenticatorAttachment === "cross-platform") {
      options.hints = ["security-key", "hybrid"];
    } else if (sel.authenticatorAttachment === "platform") {
      options.hints = ["client-device"];
    } else {
      options.hints = ["client-device", "hybrid"];
    }
  } else {
    options.hints = opts.hints;
  }
  return options;
}

// The algorithms this relying party will accept, in preference order:
// Ed25519, ES256, RS256. Offered at registration and enforced at verification —
// an authenticator that returns a credential outside this set is refused rather
// than trusted because it was asked nicely.
var DEFAULT_ALGORITHMS = Object.freeze([-8, -7, -257]);

// Every COSE signature algorithm the verifier can actually check, by IANA COSE
// identifier. An operator may widen to any of these for credentials registered
// before the default narrowed -- refusing an assertion from a credential this
// same system issued locks the user out, and re-registration is not always a
// path they have.
//
// This list is what the verifier supports, proven by exercising each entry end
// to end (register + assert with a real key of that algorithm) rather than
// copied from a table. Anything absent is refused at the call, so an operator
// finds out at boot rather than at a failed login.
//
// RSA with SHA-1 (-65535) is NOT here and cannot be opted into. SHA-1 is
// unfit for signatures and the option exists to keep working credentials
// working, not to make a broken primitive reachable through configuration.
var SUPPORTED_ALGORITHMS = Object.freeze({
  "-8":    "EdDSA (Ed25519)",
  "-7":    "ES256",
  "-35":   "ES384",
  "-36":   "ES512",
  "-37":   "PS256",
  "-38":   "PS384",
  "-39":   "PS512",
  "-257":  "RS256",
  "-258":  "RS384",
  "-259":  "RS512",
});
var REFUSED_ALGORITHMS = Object.freeze({ "-65535": "RSA with SHA-1" });

// Authenticator extension outputs are a small CBOR map (credProtect is one
// integer; credBlob is capped at 32 bytes by CTAP2.1). The cap is a bound on
// untrusted input, not a spec limit.
var MAX_EXTENSION_CBOR_BYTES = 4096;                                               // allow:raw-byte-literal — bound on an untrusted CBOR map
// Attestation objects run to a few KiB; a TPM statement with a full chain is
// the large end. Generous, because falling past it means anchoring decisions
// are made without reading the statement.
var MAX_ATTESTATION_CBOR_BYTES = C.BYTES.kib(64);
// How old a Google-signed SafetyNet statement may be. Matches the bound the
// previous verifier enforced; a device-integrity claim is about a moment, and
// an unbounded one replays.
var DEFAULT_SAFETYNET_MAX_AGE_MS = C.TIME.seconds(60);
// Attestation formats whose webauthn/verify-failed means a bad SIGNATURE and
// nothing else, so it can be reported as an ordinary negative result. Every
// other format either binds the attestation to the ceremony under the same
// code (apple, tpm, android-key) or is not yet known to this list -- both
// keep the exceptional path.
var SIGNATURE_ONLY_VERIFY_FAILED = Object.freeze({
  "packed":            1,
  "fido-u2f":          1,
  "android-safetynet": 1,
});
// The cross-origin policy parser reads whatever the verifier will accept.
// A bound BELOW the verifier's leaves a band of sizes where the document is
// verified but the policy never ran -- measured against the vendored
// verifier, which refuses at 1 MiB.
var MAX_CLIENT_DATA_BYTES = C.BYTES.mib(1);
var CHALLENGE_BYTES = 32;                                                        // allow:raw-byte-literal — WebAuthn 13.4.3 requires >= 16; 32 is the common floor
var USER_HANDLE_BYTES = 32;                                                        // allow:raw-byte-literal — 13.4.4 caps the user handle at 64
var DEFAULT_TIMEOUT_MS = 60000;                                                    // allow:raw-byte-literal // allow:raw-time-literal — the ceremony timeout browsers expect

// The authenticator model identifier, as the dashed UUID string the rest of
// the framework speaks. The verifier hands it over as 16 raw bytes.
//
// This is the seam into b.auth.fidoMds3: verifyAuthenticator(blob,
// registrationInfo) takes the object verifyRegistration returns, and its
// lookup is by UUID string. Handing bytes across that boundary breaks the
// documented composition of the two primitives, which neither one's own tests
// would notice. Formatted here, once, rather than at the call site.
function _aaguidString(raw) {
  if (typeof raw === "string") return raw;
  if (!raw) return null;
  var hex = safeBuffer.toBuffer(raw).toString("hex");
  if (hex.length !== 32) return hex;                                                // allow:raw-byte-literal — 16 bytes as hex
  return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16),
          hex.slice(16, 20), hex.slice(20)].join("-");
}

// The stored credential key, as whatever shape the operator's storage handed
// back, reduced to bytes. A BLOB column yields a Buffer, a TEXT column yields
// the base64url string that was written to it, and both are the same key.
//
// A string is decoded as base64url -- the encoding every other string in this
// module uses -- and never as UTF-8. Reading base64url text as UTF-8 does not
// fail; it produces different bytes that are not a COSE key, so the login is
// refused with a message about a malformed credential and the operator goes
// looking for corruption in a row that is intact. Anything that is neither
// bytes nor base64url is refused by name for the same reason: a wrong-shaped
// value must not be coerced into bytes that merely happen to parse.
function _storedKeyBytes(stored) {
  if (typeof stored === "string") {
    // Padding is accepted here for the same reason as on a credential id, and
    // it matters MORE: a COSE key's length usually calls for it. An ES256 key
    // is 77 bytes, which encodes to 103 characters plus one '='. Refusing
    // that would advertise TEXT-column support and then reject the ordinary
    // output of every padding-emitting encoder.
    //
    // Canonical, not merely padded-shaped: a string that does not round-trip
    // decodes to different bytes, which is a different key, and the login
    // would fail with a message about a malformed credential.
    if (_canonicalBase64Url(stored) === null) {
      throw new AuthError("auth-passkey/bad-credential-key",
        "credential.publicKey is a string but not canonical base64url -- " +
        "store the COSE key bytes, or their base64url text");
    }
    return Buffer.from(stored, "base64url");
  }
  try {
    return safeBuffer.toBuffer(stored);
  } catch (e) {
    throw new AuthError("auth-passkey/bad-credential-key",
      "credential.publicKey must be the stored COSE key as bytes (Buffer / " +
      "Uint8Array) or base64url text: " + ((e && e.message) || e));
  }
}

// Recover the parsed COSE key object from the credential key BYTES an operator
// persisted at registration. Bytes are the form that survives a database
// column, and the form every existing credential row already holds, so the
// stored contract stays bytes; the verifier wants the parsed object.
//
// An operator who persisted the parsed object instead still works: it is
// handed back unchanged.
function _coseKeyObject(stored) {
  if (stored && typeof stored === "object" && !Buffer.isBuffer(stored) &&
      !(stored instanceof Uint8Array)) {
    return stored;                                    // already the parsed object
  }
  try {
    return _pki().webauthn.parseCoseKey(_storedKeyBytes(stored));
  } catch (e) {
    if (e && e.isAuthError) throw e;                  // our own bad-credential-key
    throw new AuthError("auth-passkey/bad-credential-key",
      "credential.publicKey is not a decodable COSE key: " + ((e && e.message) || e));
  }
}

// Re-frame a refusal from the verification library as this primitive's own
// error. The contract operators code against is `catch (e) { if (e.isAuthError)
// ... }` with an auth-passkey/* code, the same shape as auth.password and
// auth.totp; a refusal that escapes in the library's own type falls straight
// through that handler into a 500, and names the library in the operator's
// logs. The verifier's code is preserved after the namespace swap because WHICH
// check refused is the actionable part.
//
// Every call into the verifier goes through this, so a path cannot be added
// that reports a refusal differently from its neighbours -- which is exactly
// how the registration ceremony came to report a stale challenge, the most
// ordinary failure there is, in a type nothing caught.
function _refuse(ceremony, e) {
  // An error this module already raised is returned UNCHANGED. The try blocks
  // this runs in wrap more than the verifier call -- reading wire fields and
  // decoding the stored key happen inside them too -- and those throw
  // AuthErrors that are already in this namespace. Re-framing one produced
  // `auth-passkey/auth-passkey/bad-response`, which matches nothing a caller
  // dispatches on, so the most ordinary malformed-input cases became
  // unroutable. Fixed here rather than by hoisting each call out of the try,
  // so a call added inside one later cannot reintroduce it.
  if (e && e.isAuthError === true) return e;
  return new AuthError(
    "auth-passkey/" + String((e && e.code) || "verification-failed")
                        .replace(/^webauthn\//, ""),
    ceremony + " refused: " + ((e && e.message) || String(e)));
}

// The authenticator's OWN extension outputs, decoded from the signed
// authenticator data. Distinct from clientExtensionResults, which the browser
// reports and nothing signs: these bytes are inside the region the attestation
// or assertion signature covers, so credProtect / credBlob / minPinLength
// answers here are the authenticator's, not a claim the page made.
//
// The verifier hands them over as raw CBOR. Decoded through b.cbor rather
// than a local parser: bounded by default, refuses indefinite-length items,
// reserved additional-info, duplicate keys and trailing bytes — the same
// decoder every other untrusted-CBOR path in the framework uses.
//
// Drop-silent on garbage. This is a reporting field, not a gate; a malformed
// extension map must not fail a ceremony whose signature verified, and no
// security decision is made on the result. Absent when there is nothing to
// report, so "no extensions" stays distinguishable from "empty map".
function _authenticatorExtensions(raw) {
  if (!raw) return undefined;
  var bytes;
  try { bytes = safeBuffer.toBuffer(raw); } catch (_e) { return undefined; }
  if (bytes.length === 0) return undefined;
  var decoded;
  try {
    decoded = cbor.decode(bytes, { maxBytes: MAX_EXTENSION_CBOR_BYTES });
  } catch (_e) { return undefined; }
  if (!(decoded instanceof Map)) return undefined;
  var out = _plainFromCbor(decoded);
  return Object.keys(out).length > 0 ? out : undefined;
}

// CBOR decodes maps to Map, which is the right in-memory type and the wrong
// one to hand back. A Map serializes to `{}` -- so a result carrying one
// looks correct in memory and loses the data the moment an operator persists
// or logs it, with nothing failing. Extension outputs nest (largeBlob and
// devicePubKey both carry structures), so converting only the outer level
// moves the loss one layer down rather than fixing it.
//
// Buffers pass through untouched: they are the byte values an extension
// reports, and walking into one would turn it into an object of indices.
function _plainFromCbor(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return value.map(_plainFromCbor);
  if (value instanceof Map) {
    // Built with a null prototype (see _plainObject) so a signed extension
    // named `__proto__` stays an own property.
    var out = _plainObject();
    value.forEach(function (v, k) {
      // EVERY key is kept, including integer CBOR labels, which become their
      // decimal string form — what the previous verifier produced, and what a
      // plain object can represent. Keeping only string keys emptied any map
      // that is labelled numerically, and a COSE key is exactly that: a
      // devicePubKey's nested `dpk` is all integer labels, so a verified
      // public key came back as `{}`.
      //
      // A map mixing integer 1 with text "1" would collide here. Canonical
      // CBOR permits it, no real extension emits it, and last-wins is what
      // the previous verifier did — worth knowing, not worth dropping the
      // surrounding data to guard against.
      out[typeof k === "string" ? k : String(k)] = _plainFromCbor(v);
    });
    return out;
  }
  return value;
}

// The anchors a registration would actually be judged against, for a given
// attestation object and options. Internal, and exported so a test can assert
// the decision directly rather than inferring it from which refusal came
// back -- refusals for unrelated reasons are indistinguishable from the right
// one, which is how an option that silently did nothing survived review.
function _resolvedAnchors(attestationObjectBase64Url, opts) {
  opts = opts || {};
  var plan = _anchorPlan(_wireBytes(attestationObjectBase64Url, "attestationObject"));
  if (plan === null || plan === "refuse") return { refused: true };
  var resolved = _withAnchors({}, plan,
    _resolveRootCertificates(opts.attestationRoots, null),
    _resolveRootCertificates(opts.safetyNetRoots, attestationRoots.SAFETYNET_ROOTS),
    opts.requireCtsProfileMatch !== false);
  return {
    refused:          false,
    fmt:              plan.fmt,
    hasChain:         plan.hasChain === true,
    rootCertificates: resolved.rootCertificates || null,
    safetyNet:        resolved.verifySafetyNetJws === true,
  };
}

// Fold the anchoring plan into the verifier options: name only the anchors
// this statement can actually use, so the verifier's refusal of an
// inapplicable anchor never fires on a legitimate ceremony.
function _withAnchors(base, plan, rootsOverride, safetyNetRoots, requireCts) {
  if (plan.safetyNet) {
    // The SafetyNet JWS chain is a second chain with its own anchor, and the
    // verifier will not check it unless asked. Left off, every SafetyNet
    // registration is refused as an unsupported format.
    base.verifySafetyNetJws = true;
    base.safetyNetRoots = safetyNetRoots;
    // ctsProfileMatch is the whole point of a SafetyNet attestation: it is
    // Google's statement that the device passed compatibility testing and is
    // not rooted or otherwise tampered with. A JWS that verifies while
    // reporting ctsProfileMatch:false is a correctly-signed statement that
    // the device FAILED -- accepting it keeps the signature check and throws
    // away the answer.
    base.requireCtsProfileMatch = requireCts;
  } else if (rootsOverride && plan.hasChain) {
    // An explicit override applies to EVERY statement that carries a chain,
    // not only the formats the framework pins. A deployment naming its own
    // anchors for its own packed / tpm / fido-u2f authenticators is asking
    // for that chain to be checked; skipping it because the framework ships
    // no default for that format would leave the verifier accepting any
    // internally-valid chain an attacker minted, while the operator believed
    // otherwise.
    base.rootCertificates = rootsOverride;
  } else if (plan.roots) {
    // The manufacturer roots this format's x5c chain must terminate at.
    // Without them the verifier checks the statement's signature and
    // certificate profile but not WHERE the chain ends -- so an RP that asked
    // for direct attestation, an RP asking "which authenticator model is
    // this?", would accept a manufacturer claim rooted in a CA the attacker
    // minted.
    base.rootCertificates = plan.roots;
  }
  return base;
}

// Which anchoring options this particular attestation can take.
//
// The verifier refuses an anchor it cannot use: handing rootCertificates to a
// `none` or self attestation raises webauthn/anchor-not-applicable rather than
// being ignored, which is the right posture -- an anchor that silently does
// nothing is how an RP comes to believe a ceremony was anchored when it was
// not. So the caller has to ask only for what the statement supports.
//
// Anchors are chosen by FORMAT, because that is what decides which roots are
// the right ones. `apple` chains to Apple's root, `android-key` to Google's,
// `android-safetynet` to GlobalSign through its JWS.
//
// `packed` / `tpm` / `fido-u2f` full attestation is deliberately NOT anchored
// against a pinned bundle: those chains terminate at whichever vendor made
// the key — Yubico, Feitian, SoloKeys — and there is no fixed set to pin.
// WebAuthn anchors them through the FIDO metadata entry for the credential's
// AAGUID instead, which is what b.auth.fidoMds3 does. Pinning this bundle
// against them would refuse every legitimate security key that is not an
// Apple or Android device.
//
// Returns null when the format cannot be determined -- the caller REFUSES on
// that. Skipping anchoring instead would be a bypass with a shape: hand this
// an `apple` attestation larger than the bound, or one this decoder chokes
// on, and it would sail through the verifier with no roots to chain to, which
// is exactly the self-issued manufacturer claim the anchoring exists to stop.
// The policy cannot be chosen without reading the format, so not reading the
// format has to be fatal.
function _anchorPlan(attestationObject) {
  var decoded;
  try {
    decoded = cbor.decode(attestationObject, { maxBytes: MAX_ATTESTATION_CBOR_BYTES });
  } catch (_e) { return null; }
  if (!(decoded instanceof Map)) return null;
  var fmt = decoded.get("fmt");
  // A `compound` statement (WebAuthn 8.9) nests several attestations, each
  // with its own format and its own trust path. Keying anchors off the OUTER
  // format alone would hand the verifier nothing to chain a nested `apple` or
  // `android-key` element to -- the same unanchored manufacturer claim this
  // planner exists to prevent, one level down.
  //
  // Refused rather than half-anchored. The verifier this release replaced did
  // not implement compound at all, so nothing that worked before stops
  // working; what would be new is accepting a format whose anchoring this
  // layer cannot yet get right. Re-open when anchors can be derived per
  // nested element and driven by a fixture end to end.
  if (fmt === "compound") return "refuse";
  var named = typeof fmt === "string" ? fmt : null;
  if (fmt === "android-safetynet") {
    return { roots: null, hasChain: false, safetyNet: true, fmt: named };
  }
  // Whether this statement carries a chain at all is a separate question from
  // whether the framework pins roots for its format. An operator naming their
  // own anchors is answering the first: they have packed / tpm / fido-u2f
  // authenticators of their own and want that chain checked. Conflating the
  // two made the override a no-op for exactly those formats -- the operator
  // asked for anchoring and got none, which is worse than the default,
  // because they believed the chain was being checked.
  var attStmt = decoded.get("attStmt");
  var hasChain = attStmt instanceof Map && attStmt.has("x5c");
  var roots = hasChain ? (attestationRoots.ROOTS_BY_FORMAT[fmt] || null) : null;
  return { roots: roots, hasChain: hasChain, safetyNet: false, fmt: named };
}

// The ceremony timeout the browser is handed, validated at the entry point.
//
// A bare typeof check lets NaN, Infinity and negatives through into the
// options document, where they are the BROWSER's problem: the ceremony fails
// client-side, far from the operator's typo, and the framework reported
// nothing. Config-time tier -- the caller catches it at boot instead.
//
// One resolver for all three builders, because a rule enforced in two of
// three places is the shape every other miss in this module took.
function _resolveTimeout(value) {
  if (value === undefined || value === null) return DEFAULT_TIMEOUT_MS;
  if (typeof value !== "number" || !isFinite(value) || value < 0) {
    throw new AuthError("auth-passkey/bad-timeout",
      "timeout must be a finite, non-negative number of milliseconds (got " +
      String(value) + ")");
  }
  return value;
}

// The SafetyNet age bound, validated at the entry point.
//
// A bare typeof check would let NaN and Infinity through, and both silently
// disable the bound: every comparison against NaN is false, and nothing is
// older than Infinity. An operator who fat-fingers this option would get no
// replay protection and no indication of it, which is worse than the refusal
// they would have understood.
function _resolveSafetyNetMaxAge(value) {
  if (value === undefined || value === null) return DEFAULT_SAFETYNET_MAX_AGE_MS;
  if (typeof value !== "number" || !isFinite(value) || value < 0) {
    throw new AuthError("auth-passkey/bad-safetynet-max-age",
      "safetyNetMaxAgeMs must be a finite, non-negative number of " +
      "milliseconds (got " + String(value) + ")");
  }
  return value;
}

// Refuse a SafetyNet attestation whose Google-signed payload is stale.
//
// The verifier checks the JWS signature and the chain, and uses timestampMs
// as the instant the chain is judged at -- but it does not bound the
// statement's AGE. A SafetyNet response is a point-in-time claim about a
// device, so without a bound one captured months ago replays for as long as
// the relying party keeps the matching challenge outstanding, and "this
// device was untampered" silently becomes "this device was untampered once".
//
// Ordering does not change the verdict: these payload bytes are the same
// before and after signature verification, so a response is accepted only if
// it is BOTH fresh and genuinely signed either way. Running the age check
// first means a replayed genuine response is named as stale rather than
// surfacing as some chain error, and a forged fresh timestamp still has to
// get past the signature immediately afterwards.
//
// A future timestamp is refused too: it cannot be honest, and tolerating it
// would let a claimed clock skew buy unbounded age.
function _requireFreshSafetyNet(attestationObject, maxAgeMs, now) {
  var decoded;
  try {
    decoded = cbor.decode(attestationObject, { maxBytes: MAX_ATTESTATION_CBOR_BYTES });
  } catch (_e) { decoded = null; }
  var attStmt = decoded instanceof Map ? decoded.get("attStmt") : null;
  var jws = attStmt instanceof Map ? attStmt.get("response") : null;
  if (!jws) {
    throw new AuthError("auth-passkey/safetynet-unreadable",
      "the SafetyNet response could not be read to check its age -- refusing " +
      "rather than accepting a statement of unknown freshness");
  }
  // The JWS is attacker-supplied CBOR: a truthy non-byte value here (a nested
  // map, say) makes toBuffer throw its OWN error type, which escapes this
  // gate un-framed -- no isAuthError, no auth-passkey/* code -- and a handler
  // written to the documented contract misses it. Framed as the refusal it
  // is: a SafetyNet response whose age cannot be read.
  var parts;
  try {
    parts = safeBuffer.toBuffer(jws).toString("utf8").split(".");
  } catch (e) {
    throw new AuthError("auth-passkey/safetynet-unreadable",
      "the SafetyNet response is not a readable JWS: " + ((e && e.message) || e));
  }
  var payload = null;
  if (parts.length === 3) {
    try {
      payload = safeJson.parse(Buffer.from(parts[1], "base64url").toString("utf8"),
                               { maxBytes: MAX_EXTENSION_CBOR_BYTES });
    } catch (_e) { payload = null; }
  }
  var stamp = payload && payload.timestampMs;
  if (typeof stamp === "string") stamp = Number(stamp);
  if (typeof stamp !== "number" || !isFinite(stamp)) {
    throw new AuthError("auth-passkey/safetynet-unreadable",
      "the SafetyNet response carries no readable timestampMs -- refusing " +
      "rather than accepting a statement of unknown freshness");
  }
  if (stamp > now) {
    throw new AuthError("auth-passkey/safetynet-stale",
      "the SafetyNet response is timestamped in the future (" + stamp +
      " > " + now + ")");
  }
  if (now - stamp > maxAgeMs) {
    throw new AuthError("auth-passkey/safetynet-stale",
      "the SafetyNet response is " + (now - stamp) + "ms old, past the " +
      maxAgeMs + "ms bound -- a captured response must not replay");
  }
}

// WebAuthn defines one credential type, "public-key" (L3 sec. 5.8.2). Both
// ceremonies check it, so a malformed response is refused at the door rather
// than reaching the verifier and being recorded with a type nothing checked.
function _requireCredentialType(response) {
  var type = response && response.type;
  if (type !== "public-key") {
    throw new AuthError("auth-passkey/bad-credential-type",
      "response.type must be \"public-key\" (got " + JSON.stringify(type) + ")");
  }
}

// Read a PEM as an X.509 certificate, or throw. Named so the parse is an
// expression with a result rather than a bare constructor call.
function _parseCertificate(pem) {
  return new nodeCrypto.X509Certificate(pem);
}

// Resolve an operator's trust-anchor override against the shipped bundle.
// Config-time tier: a malformed override throws rather than falling back to
// the default, because silently ignoring it would leave an operator believing
// they had narrowed trust to their own roots while every vendor root stayed
// live -- the opposite of what they asked for.
function _resolveRootCertificates(value, shipped) {
  if (value === undefined || value === null) return shipped;
  if (!Array.isArray(value) || value.length === 0) {
    throw new AuthError("auth-passkey/bad-attestation-roots",
      "attestation root overrides must be a non-empty array of PEM strings " +
      "-- an empty list anchors nothing and is never read as 'use the " +
      "shipped roots'");
  }
  for (var i = 0; i < value.length; i += 1) {
    if (typeof value[i] !== "string") {
      throw new AuthError("auth-passkey/bad-attestation-roots",
        "attestation root [" + i + "] must be a PEM certificate string");
    }
    // PARSED, not sniffed for a "-----BEGIN" substring. A truncated or
    // non-certificate PEM passes a substring test and then either never
    // reaches the verifier -- for a format this layer does not anchor, the
    // operator would never learn their configuration is broken -- or surfaces
    // much later as a refused ceremony rather than the config error it is.
    try {
      _parseCertificate(value[i]);
    } catch (e) {
      throw new AuthError("auth-passkey/bad-attestation-roots",
        "attestation root [" + i + "] is not a readable X.509 certificate: " +
        ((e && e.message) || e));
    }
  }
  return value;
}

// Resolve opts.allowedAlgorithms to the list both halves of a ceremony use --
// what startRegistration advertises in pubKeyCredParams AND what the verifiers
// enforce. One option drives both so a deployment can never offer one set and
// accept another.
//
// Config-time tier: a bad list throws at the entry point rather than degrading
// to the default, because silently ignoring it is how an operator ends up
// believing they widened the set while every legacy login keeps failing.
function _resolveAllowedAlgorithms(value) {
  if (value === undefined || value === null) return DEFAULT_ALGORITHMS;
  if (!Array.isArray(value) || value.length === 0) {
    throw new AuthError("auth-passkey/bad-algorithm",
      "allowedAlgorithms must be a non-empty array of COSE algorithm " +
      "identifiers -- an empty list permits nothing and is never read as " +
      "'any algorithm'");
  }
  var out = [];
  for (var i = 0; i < value.length; i += 1) {
    var alg = value[i];
    if (typeof alg !== "number" || !isFinite(alg) || Math.floor(alg) !== alg) {
      throw new AuthError("auth-passkey/bad-algorithm",
        "allowedAlgorithms[" + i + "] must be an integer COSE algorithm " +
        "identifier (got " + typeof alg + ")");
    }
    if (REFUSED_ALGORITHMS[String(alg)] !== undefined) {
      throw new AuthError("auth-passkey/bad-algorithm",
        "allowedAlgorithms[" + i + "] is " + REFUSED_ALGORITHMS[String(alg)] +
        " (" + alg + "), which is not fit for signatures and cannot be " +
        "enabled -- a credential using it has to be re-registered");
    }
    if (SUPPORTED_ALGORITHMS[String(alg)] === undefined) {
      throw new AuthError("auth-passkey/bad-algorithm",
        "allowedAlgorithms[" + i + "] is " + alg + ", which this verifier " +
        "cannot check -- supported identifiers are " +
        Object.keys(SUPPORTED_ALGORITHMS).join(", "));
    }
    if (out.indexOf(alg) === -1) out.push(alg);
  }
  return out;
}

// The expected challenge as bytes, from the operator's stored base64url.
//
// Canonical, for the same reason every other base64url field in this module
// is: Node's decoder discards characters it does not recognize, so a stored
// challenge of "AQ!ID" decodes equal to "AQID" and a response would verify
// against a challenge that was not the one held. The framework's own
// _freshChallenge emits canonical text, so this only bites a session store
// that corrupted the value or a caller minting challenges themselves -- which
// is exactly when a silent equivalence is hardest to notice.
//
// One helper for both ceremonies, so the two cannot diverge.
function _challengeBytes(value) {
  if (_canonicalBase64Url(value) === null) {
    throw new AuthError("auth-passkey/bad-expectedChallenge",
      "expectedChallenge must be canonical base64url");
  }
  return Buffer.from(value, "base64url");
}

// A deep copy of a caller-supplied value, taken at validation time.
//
// Snapshotting the REFERENCE is not a snapshot: the caller keeps the response
// object while the asynchronous verification runs, and mutating what is
// inside it still shows through into the result. These values are the browser
// JSON a relying party posted -- plain objects, arrays, strings, numbers,
// booleans -- so a structural copy is exact.
//
// Anything outside that shape is returned as-is rather than mangled: this
// guards against a caller mutating their own data mid-flight, not against
// hostile input, and losing a value would be worse than sharing it.
function _snapshotValue(value) {
  if (value === null || typeof value !== "object") return value;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return value.map(_snapshotValue);
  if (Object.getPrototypeOf(value) !== Object.prototype &&
      Object.getPrototypeOf(value) !== null) {
    return value;
  }
  var out = _plainObject();
  Object.keys(value).forEach(function (k) { out[k] = _snapshotValue(value[k]); });
  return out;
}

// A key/value object built out of caller- or authenticator-supplied names.
//
// Null prototype, always. Assigning a key called `__proto__` to an ordinary
// object hits the legacy prototype setter instead of creating an own
// property: the key vanishes from Object.keys and from JSON, and its contents
// reappear as INHERITED properties. Both converters in this file build from
// untrusted key names, and the second one reintroduced the bug the first had
// already fixed -- so they share this rather than each remembering.
function _plainObject() {
  return Object.create(null);
}

// Refuse a wire-supplied credential ID that disagrees with the authoritative
// one -- the ID inside the attestation at registration, the stored record's ID
// at authentication. A response carries the same identity twice (`id` and its
// binary spelling `rawId`) and an operator may key on either, so BOTH are
// checked against the one authority rather than against each other.
//
// Absent is fine: WebAuthn requires the field, but an operator normalizing a
// response before handing it over may drop one of the two spellings, and the
// authoritative value is what gets used either way. Present-and-different is
// not -- that is a claim on an identity nothing signed.
function _requireCredentialIdMatches(response, authoritativeId, why) {
  if (typeof response !== "object" || response === null) return;
  // Compared in CANONICAL form, not as raw strings. A stored id may carry the
  // '=' padding whichever encoder wrote the row emitted -- the case
  // _credentialDescriptors deliberately supports -- while the browser returns
  // the unpadded spelling. Two spellings of ONE credential must not read as
  // two credentials, or the compatibility this binding sits next to would
  // lock out exactly the deployments it was added for.
  var expected = _canonicalBase64Url(authoritativeId);
  var fields = ["id", "rawId"];
  var stated = 0;
  for (var i = 0; i < fields.length; i += 1) {
    var wireValue = response[fields[i]];
    if (wireValue === undefined || wireValue === null) continue;
    stated += 1;
    var got = typeof wireValue === "string" ? _canonicalBase64Url(wireValue) : null;
    // A null on either side is a value that does not canonically name one
    // credential; it can never match, and saying so beats comparing garbage.
    if (got === null || expected === null || got !== expected) {
      throw new AuthError("auth-passkey/credential-id-mismatch",
        "response." + fields[i] + " is " + JSON.stringify(wireValue) +
        " but " + why + " is " + JSON.stringify(authoritativeId));
    }
  }
  // Tolerating ONE missing spelling is compatibility -- an operator
  // normalizing a response may drop either, and the authoritative value is
  // used regardless. Tolerating BOTH is a hole: the loop then compares
  // nothing, and the binding this function exists to enforce is skipped for
  // a response that never named a credential at all. WebAuthn requires the
  // outer identifier, and so did the verifier this replaces.
  if (stated === 0) {
    throw new AuthError("auth-passkey/missing-credential-id",
      "the response states no credential id -- one of response.id or " +
      "response.rawId is required, and without either there is nothing to " +
      "bind to " + why);
  }
}

// A ceremony challenge: fresh CSPRNG bytes, base64url for transport. Returned
// as a string because that is what the browser receives and what the operator
// stores in the session to compare later. b.crypto.generateBytes rather than
// node:crypto directly, so the challenge comes from the same SHAKE256-over-
// OS-RNG source as every other secret the framework mints.
function _freshChallenge() {
  return bCrypto.generateBytes(CHALLENGE_BYTES).toString("base64url");
}

// Credential descriptors as the browser expects them: { id, type, transports? }.
// Accepts either a bare base64url id or an object, because operators persist
// whichever their storage made convenient.
function _credentialDescriptors(list, field) {
  if (list === undefined || list === null) return [];
  if (!Array.isArray(list)) {
    throw new AuthError("auth-passkey/bad-" + field, field + " must be an array");
  }
  return list.map(function (entry, i) {
    var id = typeof entry === "string" ? entry : (entry && entry.id);
    if (typeof id !== "string" || id.length === 0) {
      throw new AuthError("auth-passkey/bad-" + field,
        field + "[" + i + "] needs a base64url credential id");
    }
    // Trailing '=' padding is normalized away rather than refused. base64url
    // is canonically unpadded, but plenty of encoders emit it, and a
    // credential id is something a deployment STORED possibly years ago with
    // whichever encoder it had. Refusing padding here would not reject an
    // attack; it would stop that deployment from starting authentication or
    // excluding a credential at all, with no path forward short of rewriting
    // the column.
    //
    // An id that does not canonically denote one credential is refused rather
    // than decoded: Node's lenient decoder would turn it into some OTHER
    // credential's id and the ceremony would proceed against the wrong
    // descriptor.
    var normalized = _canonicalBase64Url(id);
    if (normalized === null) {
      throw new AuthError("auth-passkey/bad-" + field,
        field + "[" + i + "].id must be canonical base64url");
    }
    var out = { id: normalized, type: "public-key" };
    if (entry && Array.isArray(entry.transports) && entry.transports.length) {
      out.transports = entry.transports.slice();
    }
    return out;
  });
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

  // WebAuthn defines exactly one credential type. Checked rather than
  // defaulted into the result: a response with a missing or altered `type`
  // is malformed, and writing "public-key" over it -- or storing whatever it
  // said -- puts a value in the credential row that nothing verified, which
  // then misleads any consumer dispatching on it.
  _requireCredentialType(opts.response);
  _refuseCrossOrigin(opts.response, opts, "registration");
  // Resolved BEFORE the verifier call: a bad list is an operator's own
  // configuration error, and the catch below rewrites every code it sees into
  // the auth-passkey namespace, which would restate one already there.
  var regAlgorithms = _resolveAllowedAlgorithms(opts.allowedAlgorithms);
  // Operator override REPLACES the format's pinned set rather than extending
  // it: a deployment that names its own anchors is narrowing trust to a set
  // it controls, and silently adding the vendor roots back would defeat that.
  // null when not supplied, so the per-format default stands.
  // Snapshotted before the await, for the reason above: these are reported in
  // the result and read off an object the caller still holds while the
  // asynchronous verification runs.
  var reportedRegRpId = opts.expectedRPID;
  var reportedRegType = opts.response.type;
  var reportedRegClientExtensions = _snapshotValue(opts.response.clientExtensionResults);
  var reportedRegTransports = _snapshotValue(
    (opts.response.response || {}).transports);
  // The outer credential id, snapshotted too. Its binding check is the one
  // thing here that CANNOT run before the await -- the authoritative id comes
  // out of the attestation, so there is nothing to compare against until the
  // verifier returns. Reading the response again at that point would compare
  // whatever the caller's object holds by then: a mismatching response could
  // be corrected into passing, or a valid one edited into failing.
  var statedRegIds = {
    id:    opts.response.id,
    rawId: opts.response.rawId,
  };
  var regRoots = _resolveRootCertificates(opts.attestationRoots, null);
  var regSafetyNetRoots = _resolveRootCertificates(opts.safetyNetRoots,
                                                   attestationRoots.SAFETYNET_ROOTS);
  var regInner = opts.response.response || {};
  var attestationObject = _wireBytes(regInner.attestationObject, "attestationObject");
  var clientDataJSON = _wireBytes(regInner.clientDataJSON, "clientDataJSON");
  var regAnchorPlan = _anchorPlan(attestationObject);
  if (regAnchorPlan === null) {
    throw new AuthError("auth-passkey/bad-attestation-object",
      "the attestation object could not be read well enough to decide which " +
      "trust anchors apply -- refusing rather than verifying it unanchored");
  }
  if (regAnchorPlan === "refuse") {
    throw new AuthError("auth-passkey/unsupported-attestation-format",
      "compound attestation statements are not accepted: each nested " +
      "element carries its own trust path, and this primitive cannot yet " +
      "anchor them individually -- accepting one unanchored would defeat " +
      "the attestation provenance it is asked for");
  }

  // clientData is checked here rather than delegated: the attestation verifier
  // takes the client-data HASH, so the ceremony type, challenge and origin are
  // this layer's to compare. Decoded challenge bytes, not the base64url text —
  // two spellings of one challenge must not be able to disagree.
  var clientData;
  try {
    clientData = _pki().webauthn.parseClientData(clientDataJSON, {
      expectedType:      "webauthn.create",
      expectedChallenge: _challengeBytes(opts.expectedChallenge),
      expectedOrigin:    opts.expectedOrigin,
    });
  } catch (e) {
    throw _refuse("registration response", e);
  }

  if (regAnchorPlan.safetyNet) {
    _requireFreshSafetyNet(attestationObject,
      _resolveSafetyNetMaxAge(opts.safetyNetMaxAgeMs), Date.now());
  }
  // An RP that relies on attestation PROVENANCE can require the chain to have
  // terminated somewhere trusted. Off by default, because that is what every
  // WebAuthn verifier does: packed / tpm / fido-u2f chains end at whichever
  // vendor made the key, and the spec anchors them through the FIDO metadata
  // entry for the credential's AAGUID rather than a fixed root list -- so
  // refusing them by default would reject every ordinary security key. The
  // consequence, unchanged from previous releases and from the verifier this
  // one replaces, is that an unanchored chain proves only that SOMEBODY
  // signed the statement, and the AAGUID inside it is a claim.
  //
  // With this set, a statement carrying a chain must have anchored; the
  // result's anchoredTo says which root it reached.
  var requireAnchor = opts.requireAttestationAnchor === true;

  var att;
  try {
    att = await _pki().webauthn.verify(attestationObject,
      nodeCrypto.createHash("sha256").update(clientDataJSON).digest(),
      _withAnchors({
        expectedRpId:            opts.expectedRPID,
        requireUserPresence:     true,
        requireUserVerification: opts.requireUserVerification !== false,
        allowedAlgorithms:       regAlgorithms,
      }, regAnchorPlan, regRoots, regSafetyNetRoots,
         opts.requireCtsProfileMatch !== false));
  } catch (e) {
    // A signature that does not verify is a NORMAL negative outcome, exactly
    // as on the authentication path: the caller writes
    // `if (!rv.verified) deny()`, and throwing turns an ordinary bad
    // attestation into an unhandled exception where a refusal belongs.
    // Everything else -- a binding that disagrees, an unanchored chain, a
    // policy the ceremony failed -- stays exceptional, because which check
    // refused is the actionable part.
    //
    // The verifier spends ONE code, webauthn/verify-failed, on two different
    // things: a bad signature, and a failed attestation BINDING -- the apple
    // nonce, TPM's certInfo extraData and attested Name, android-key's
    // KeyDescription (attestationChallenge, allApplications, origin,
    // purpose). A binding violation is an attack indicator and must keep its
    // own refusal path rather than being flattened into an ordinary decline.
    //
    // An ALLOW-list, not an exclusion list: these are the formats whose
    // verify-failed means a signature and nothing else. A format not named
    // here -- including one a future verifier adds -- keeps the exceptional
    // path, so the failure mode of forgetting to update this is a noisier
    // refusal rather than a silent downgrade. Keyed on the format, never on
    // the vendor's message text, which is prose and not a contract.
    if (e && e.code === "webauthn/verify-failed" &&
        SIGNATURE_ONLY_VERIFY_FAILED[regAnchorPlan.fmt] === 1) {
      return {
        verified: false,
        registrationInfo: null,
        backupEligible: false,
        backupState: false,
      };
    }
    throw _refuse("registration response", e);
  }

  if (requireAnchor && regAnchorPlan.hasChain && !att.anchoredTo) {
    throw new AuthError("auth-passkey/attestation-not-anchored",
      "the attestation carries a certificate chain that did not terminate at " +
      "a trusted root, so the authenticator model it claims is unverified -- " +
      "supply attestationRoots for this deployment's authenticators, or " +
      "check the credential's AAGUID against FIDO metadata with " +
      "b.auth.fidoMds3");
  }

  var regFlags = att.flags || {};
  // The attested authenticator data, for the fields the verdict does not
  // surface. Drop-silent: the verifier has already accepted these bytes, so a
  // re-parse failing here is not a reason to refuse a verified ceremony —
  // it only means the reporting-only fields below go unreported.
  var regAuthData = {};
  try {
    regAuthData = _pki().webauthn.parseAuthenticatorData(
      _pki().webauthn.parseAttestationObject(attestationObject).authDataBytes) || {};
  } catch (_e) { regAuthData = {}; }
  // The authoritative credential ID is the one inside attestedCredentialData,
  // which the attestation signs over. response.id / response.rawId are
  // client-supplied and covered by nothing, so a registration may claim any
  // ID at all while attesting its own key. An RP keying its credential table
  // on the returned value would then overwrite the victim's row with the
  // attacker's public key. Persist the ATTESTED id, and refuse outright when
  // the wire disagrees rather than silently correcting it — a mismatch is
  // either an attack or a broken client, and neither should register.
  var attestedId = safeBuffer.toBuffer(att.credentialId).toString("base64url");
  _requireCredentialIdMatches(statedRegIds, attestedId,
    "the credential ID inside the attestation");

  var rv = {
    verified: att.attestationVerified === true,
    registrationInfo: {
      // The credential key is persisted as BYTES: that is what a database
      // column holds and what every already-stored credential is. The parsed
      // object is reconstructed at login.
      credential: {
        id:        attestedId,
        publicKey: safeBuffer.toBuffer(att.credentialPublicKeyBytes),
        counter:   att.signCount,
        // getTransports() from the browser: which way this authenticator can
        // be reached (usb / nfc / ble / internal / hybrid). Persist it and
        // hand it back in allowCredentials, and the next login goes straight
        // to the right transport instead of prompting for all of them.
        // Left ABSENT rather than defaulted to [] when the client reports
        // nothing, so "not reported" stays distinguishable from "none".
        transports: reportedRegTransports,
      },
      credentialType:       reportedRegType,
      credentialDeviceType: regFlags.be === true ? "multiDevice" : "singleDevice",
      credentialBackedUp:   regFlags.bs === true,
      aaguid:               _aaguidString(att.aaguid),
      fmt:                  att.fmt,
      attestationType:      att.attestationType,
      anchoredTo:           att.anchoredTo,
      userVerified:         regFlags.uv === true,
      // The origin and RP ID this ceremony was verified AGAINST, and the
      // attestation it was verified FROM. Echoed back so an audit record, or
      // a later re-check against a refreshed metadata BLOB, can be written
      // from the verification result alone rather than by re-deriving what
      // the request was.
      //
      // The origin is the one the ceremony actually happened at, taken from
      // the verified client data -- not expectedOrigin, which may be an
      // allow-list of several and would record the whole list on every row.
      origin:               clientData.origin,
      rpID:                 reportedRegRpId,
      attestationObject:    attestationObject,
      // The attestation verdict does not carry the authenticator's extension
      // outputs, so they come from the attested authenticator data — the same
      // bytes the attestation signed over.
      authenticatorExtensionResults: _authenticatorExtensions(regAuthData.extensions),
      // The BROWSER's extension answers, including credProps.rk -- whether
      // the credential it created is actually discoverable, which is the
      // whole reason credProps is requested. Surfaced so a caller reads it
      // off the verification result rather than digging back into the raw
      // response it posted.
      //
      // Deliberately a separate field from authenticatorExtensionResults
      // above: these are client-reported and NOTHING signs them, while those
      // sit inside the bytes the attestation covers. An RP that treats
      // credProps.rk as authoritative for a security decision is trusting
      // the page; it is a UX signal, not a guarantee.
      clientExtensionResults: reportedRegClientExtensions,
    },
  };
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
  var options = {
    rpId:               opts.rpId,
    challenge:          _freshChallenge(),
    allowCredentials:   _credentialDescriptors(opts.allowCredentials, "allowCredentials"),
    timeout:            _resolveTimeout(opts.timeout),
    userVerification:   opts.userVerification || "preferred",
    extensions:         safeAuthExtensions,
  };
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
  var options = {
    rpId:               opts.rpId,
    challenge:          _freshChallenge(),
    // For conditional UI the spec mandates an empty allowCredentials
    // list — discoverable credentials only. Supplying a list here
    // suppresses the autofill chip in current browsers.
    allowCredentials:   [],
    timeout:            _resolveTimeout(opts.timeout),
    userVerification:   opts.userVerification || "preferred",
    extensions:         safeCondExtensions,
  };
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
    // Canonical, like every other base64url this module accepts. A
    // non-canonical salt ("YW" re-encodes to "YQ") is passed to the browser
    // verbatim while its decoded length is measured from different bytes, so
    // the value the authenticator receives is not the one that was checked.
    if (_canonicalBase64Url(value) === null) {
      throw new AuthError("auth-passkey/bad-extension-input",
        name + " must be canonical base64url when string");
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

  // The stored record must be the one the assertion names. Not a signature
  // concern — a wrong record carries a wrong public key and the signature
  // fails anyway — but an operator who looks a credential up by USER rather
  // than by credential ID can pair a valid key with the wrong row, and that
  // deserves its own name instead of surfacing as an opaque signature failure.
  //
  // Ordered LAST of the credential guards deliberately: the missing/!bad
  // publicKey and counter checks above are the ones that protect something, so
  // they keep reporting first when several are wrong at once.
  _requireCredentialIdMatches(opts.response, opts.credential.id,
    "the stored opts.credential.id -- look the credential up BY the asserted id");
  _requireCredentialType(opts.response);
  _refuseCrossOrigin(opts.response, opts, "authentication");
  // Snapshot every caller-supplied value the RESULT reports, taken here --
  // after validation and BEFORE the await. Verification is asynchronous and
  // the caller keeps a reference to opts throughout, so reading these
  // afterwards reports whatever the object holds by then rather than what was
  // checked. The sharp one is the credential id: a consumer that persists
  // newCounter against authenticationInfo.credentialID would update the wrong
  // credential row while the response said verified: true.
  var reportedCredentialId = opts.credential.id;
  var reportedRpId = opts.expectedRPID;
  var reportedClientExtensions = _snapshotValue(opts.response.clientExtensionResults);
  // Resolved BEFORE the verifier call. The catch below turns a failed signature
  // into `verified: false` rather than an exception, so leaving this inside it
  // would report an operator's malformed algorithm list as an ordinary failed
  // login -- a configuration error that reads as "wrong passkey".
  var authAlgorithms = _resolveAllowedAlgorithms(opts.allowedAlgorithms);
  var inner = opts.response.response || {};
  // The challenge crosses as base64url on the wire and is stored that way, but
  // the verifier compares the DECODED bytes — deliberately, so two spellings of
  // one challenge cannot disagree. Decode here rather than pass the string.
  var assertion;
  try {
    assertion = await _pki().webauthn.verifyAssertion({
      authenticatorData:   _wireBytes(inner.authenticatorData, "authenticatorData"),
      clientDataJSON:      _wireBytes(inner.clientDataJSON, "clientDataJSON"),
      signature:           _wireBytes(inner.signature, "signature"),
      credentialPublicKey: _coseKeyObject(opts.credential.publicKey),
      previousSignCount:   counter,
      expectedChallenge:   _challengeBytes(opts.expectedChallenge),
      expectedOrigin:      opts.expectedOrigin,
      expectedRpId:        opts.expectedRPID,
      requireUserPresence: true,
      requireUserVerification: opts.requireUserVerification !== false,
      allowedAlgorithms:   authAlgorithms,
    });
  } catch (e) {
    // A signature that does not verify is a NORMAL negative outcome — the
    // ordinary failed login — and is reported as `verified: false`, not raised.
    // Operator code reads `if (!rv.verified) deny()`; throwing here would turn
    // every wrong-key attempt into an unhandled exception and a 500 where a 401
    // belongs. The underlying verifier raises for this case, so it is mapped
    // back rather than passed through.
    if (e && e.code === "webauthn/bad-signature") {
      return {
        verified: false,
        authenticationInfo: null,
        backupEligible: false,
        backupState: false,
      };
    }
    // Everything else IS exceptional: a binding that disagrees (rp id, origin,
    // challenge), a counter that went backwards, a ceremony flag the policy
    // required. Those are configuration or attack conditions rather than a
    // failed guess, and each keeps the verifier's own code because which check
    // refused is the actionable part.
    throw _refuse("authentication assertion", e);
  }

  // The flags the VERIFIER read, not a second read of the caller's object.
  // Re-parsing response.response.authenticatorData here would report bits
  // from whatever those bytes hold NOW -- the verification is async, and the
  // caller may reuse or mutate the response object while it is pending -- so
  // a ceremony could return verified:true alongside UV/BE/BS values no
  // signature ever covered. The registration path already reads att.flags
  // for the same reason.
  var flags = assertion.flags || {};
  // WebAuthn L3 §6.1.3 — same BE/BS surfacing as verifyRegistration.
  // Authentication assertions also carry the BE/BS bits in authData; a
  // credential that registered as single-device but later asserts as
  // multi-device (or vice versa) is a backup-state-changed signal worth
  // auditing at the operator level. We expose the current values so the
  // caller can compare against what they persisted at registration.
  return {
    verified: assertion.signatureVerified === true,
    authenticationInfo: {
      newCounter:           assertion.signCount,
      credentialID:         reportedCredentialId,
      userVerified:         flags.uv === true,
      credentialDeviceType: flags.be === true ? "multiDevice" : "singleDevice",
      credentialBackedUp:   flags.bs === true,
      // The origin the ceremony actually happened at, from the verified client
      // data — not expectedOrigin, which may be an allow-list of several. The
      // registration result answers the same question the same way, and both
      // are written to the same audit row: a value that is a string after one
      // ceremony and an array after the other is a shape no consumer handles,
      // and records every permitted origin instead of the one that was used.
      // Null rather than falling back to expectedOrigin if the verifier ever
      // stops reporting it: "which origin" is then genuinely unknown, and an
      // audit row naming every permitted origin is worse than one saying so.
      origin:               (assertion.clientData && assertion.clientData.origin) || null,
      rpID:                 reportedRpId,
      authenticatorExtensionResults: _authenticatorExtensions(assertion.extensions),
      // Client-reported and unsigned, as at registration. Kept beside the
      // signed set rather than merged into it.
      clientExtensionResults: reportedClientExtensions,
    },
    backupEligible: flags.be === true,
    backupState:    flags.bs === true,
  };
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


// A credential id as stored, normalized to canonical unpadded base64url --
// or null if the input does not unambiguously denote one credential.
//
// Node's base64 decoder is lenient in two directions, and both change WHICH
// credential an id names rather than failing:
//
//   "YW"     decodes to one byte and re-encodes as "YQ" -- a different id,
//            because the final quantum carries bits that encode nothing.
//   "Y"      a lone leftover character decodes to NOTHING, so a descriptor
//            silently becomes the empty id.
//   "YWJj==" padding on an already-complete quantum; the identity survives,
//            but the encoding is malformed.
//
// So the check is a round trip: an id is accepted only if re-encoding the
// bytes it decodes to reproduces it. That is the definition of "this string
// is the canonical name of these bytes", and it needs no reasoning about
// quantum arithmetic to be convincing. Padding, when present, must also be
// the amount the data length calls for -- the same anti-malleability rule
// b.base32.decode applies, so several spellings of one id cannot all pass.
function _canonicalBase64Url(s) {
  if (typeof s !== "string" || s.length === 0) return null;
  if (!/^[A-Za-z0-9_-]+={0,2}$/.test(s)) return null;
  var padded = s.indexOf("=");
  var data = padded === -1 ? s : s.slice(0, padded);
  if (padded !== -1) {
    var padCount = s.length - data.length;
    if ((data.length + padCount) % 4 !== 0) return null;                          // allow:raw-byte-literal — base64 quantum
    if (padCount !== (4 - (data.length % 4)) % 4) return null;                    // allow:raw-byte-literal — base64 quantum
  }
  var canonical = Buffer.from(s, "base64url").toString("base64url");
  return canonical === data ? canonical : null;
}

function signalUnknownCredential(opts) {
  if (!opts) throw new AuthError("auth-passkey/missing-opts", "opts is required");
  _requireString(opts.rpId, "rpId");
  _requireString(opts.credentialId, "credentialId");
  // Canonical, not merely base64url-shaped. The browser ACTS on this id --
  // signalUnknownCredential asks it to remove the named credential -- and a
  // non-canonical spelling decodes to different bytes, so "YW" would name
  // "YQ". Naming the wrong credential here deletes the wrong passkey.
  var credentialId = _canonicalBase64Url(opts.credentialId);
  if (credentialId === null) {
    throw new AuthError("auth-passkey/bad-credential-id",
      "credentialId must be canonical base64url");
  }
  return {
    rpId:         opts.rpId,
    credentialId: credentialId,
  };
}

function signalAllAcceptedCredentials(opts) {
  if (!opts) throw new AuthError("auth-passkey/missing-opts", "opts is required");
  _requireString(opts.rpId, "rpId");
  _requireString(opts.userId, "userId");
  var userId = _canonicalBase64Url(opts.userId);
  if (userId === null) {
    throw new AuthError("auth-passkey/bad-user-id",
      "userId must be canonical base64url");
  }
  if (!Array.isArray(opts.allAcceptedCredentialIds)) {
    throw new AuthError("auth-passkey/bad-accepted-list",
      "allAcceptedCredentialIds must be an array");
  }
  // Every entry canonical, for the sharper reason: the browser treats this
  // list as exhaustive and removes credentials NOT on it. An id that decodes
  // to different bytes leaves the credential it was meant to name unlisted,
  // and the browser deletes the passkey the operator was trying to keep.
  var accepted = [];
  for (var i = 0; i < opts.allAcceptedCredentialIds.length; i++) {
    var one = typeof opts.allAcceptedCredentialIds[i] === "string"
      ? _canonicalBase64Url(opts.allAcceptedCredentialIds[i]) : null;
    if (one === null) {
      throw new AuthError("auth-passkey/bad-accepted-list",
        "allAcceptedCredentialIds[" + i + "] must be canonical base64url");
    }
    accepted.push(one);
  }
  return {
    rpId:                     opts.rpId,
    userId:                   userId,
    allAcceptedCredentialIds: accepted,
  };
}

function signalCurrentUserDetails(opts) {
  if (!opts) throw new AuthError("auth-passkey/missing-opts", "opts is required");
  _requireString(opts.rpId, "rpId");
  _requireString(opts.userId, "userId");
  var currentUserId = _canonicalBase64Url(opts.userId);
  if (currentUserId === null) {
    throw new AuthError("auth-passkey/bad-user-id",
      "userId must be canonical base64url");
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
    userId:      currentUserId,
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
  // Internal — the anchoring decision for one attestation object, so a test
  // can assert WHICH roots a ceremony would be judged against. The
  // alternative is inferring it from a refusal, and a refusal that happens
  // for an unrelated reason looks identical to the right one.
  _resolvedAnchors:             _resolvedAnchors,
  compareBackupState:           compareBackupState,
  ALLOWED_EXTENSION_KEYS:       ALLOWED_EXTENSION_KEYS,
};
