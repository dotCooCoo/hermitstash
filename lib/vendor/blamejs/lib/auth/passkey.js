// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var nodeCrypto = require("node:crypto");
var _pkiToolkit = require("../vendor/blamejs-pki.cjs");
var bCrypto = require("../crypto");
var attestationRoots = require("./webauthn-attestation-roots");
var C = require("../constants");
var cbor = require("../cbor");
var safeBuffer = require("../safe-buffer");
var safeJson = require("../safe-json");
var { AuthError } = require("../framework-error");

var MAX_NAME_LEN = 256;

function _pki() {
  return _pkiToolkit;
}

function _wireBytes(value, field) {
  if (typeof value !== "string" || value.length === 0) {
    throw new AuthError("auth-passkey/bad-response",
      "response." + field + " must be a base64url string");
  }
  if (_canonicalBase64Url(value) === null) {
    throw new AuthError("auth-passkey/bad-response",
      "response." + field + " must be canonical base64url");
  }
  return Buffer.from(value, "base64url");
}

function _refuseCrossOrigin(response, opts, ceremony) {
  var allow = opts && opts.allowCrossOrigin;
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

  if (Array.isArray(allow) &&
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
    if (k === "prf")       Object.assign(out, _prfExt(extensions.prf));
    if (k === "largeBlob") Object.assign(out, _largeBlobExt(extensions.largeBlob));
    if (k === "credBlob")  Object.assign(out, _credBlobExt(extensions.credBlob));
  }
  return out;
}

async function startRegistration(opts) {
  if (!opts) throw new AuthError("auth-passkey/missing-opts", "opts is required");
  _requireString(opts.rpName, "rpName");
  _requireString(opts.rpId, "rpId");
  _requireString(opts.userName, "userName");

  var sel = opts.authenticatorSelection || {};
  var algorithms = _resolveAllowedAlgorithms(opts.allowedAlgorithms);
  var residentKey = sel.residentKey ||
    (sel.requireResidentKey === true ? "required" : "preferred");
  var safeExtensions = _validateExtensions(opts.extensions, opts.allowUnknownExtensions === true);
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
      requireResidentKey:        residentKey === "required",
    },
    extensions:           Object.assign({}, safeExtensions, { credProps: true }),
  };
  if (sel.authenticatorAttachment !== undefined) {
    options.authenticatorSelection.authenticatorAttachment = sel.authenticatorAttachment;
  }
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

var DEFAULT_ALGORITHMS = Object.freeze([-8, -7, -257]);

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

var MAX_EXTENSION_CBOR_BYTES = 4096;                                               // allow:raw-byte-literal — bound on an untrusted CBOR map
var MAX_ATTESTATION_CBOR_BYTES = C.BYTES.kib(64);
var DEFAULT_SAFETYNET_MAX_AGE_MS = C.TIME.seconds(60);
var SIGNATURE_ONLY_VERIFY_FAILED = Object.freeze({
  "packed":            1,
  "fido-u2f":          1,
  "android-safetynet": 1,
});
var MAX_CLIENT_DATA_BYTES = C.BYTES.mib(1);
var CHALLENGE_BYTES = 32;                                                        // allow:raw-byte-literal — WebAuthn 13.4.3 requires >= 16; 32 is the common floor
var USER_HANDLE_BYTES = 32;                                                        // allow:raw-byte-literal — 13.4.4 caps the user handle at 64
var DEFAULT_TIMEOUT_MS = 60000;                                                    // allow:raw-byte-literal // allow:raw-time-literal — the ceremony timeout browsers expect

function _aaguidString(raw) {
  if (typeof raw === "string") return raw;
  if (!raw) return null;
  var hex = safeBuffer.toBuffer(raw).toString("hex");
  if (hex.length !== 32) return hex;                                                // allow:raw-byte-literal — 16 bytes as hex
  return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16),
          hex.slice(16, 20), hex.slice(20)].join("-");
}

function _storedKeyBytes(stored) {
  if (typeof stored === "string") {
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

function _coseKeyObject(stored) {
  if (stored && typeof stored === "object" && !Buffer.isBuffer(stored) &&
      !(stored instanceof Uint8Array)) {
    return stored;
  }
  try {
    return _pki().webauthn.parseCoseKey(_storedKeyBytes(stored));
  } catch (e) {
    if (e && e.isAuthError) throw e;
    throw new AuthError("auth-passkey/bad-credential-key",
      "credential.publicKey is not a decodable COSE key: " + ((e && e.message) || e));
  }
}

function _refuse(ceremony, e) {
  if (e && e.isAuthError === true) return e;
  return new AuthError(
    "auth-passkey/" + String((e && e.code) || "verification-failed")
                        .replace(/^webauthn\//, ""),
    ceremony + " refused: " + ((e && e.message) || String(e)));
}

// Drop-silent on garbage. This is a reporting field, not a gate; a malformed
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

function _plainFromCbor(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return value;
  if (Array.isArray(value)) return value.map(_plainFromCbor);
  if (value instanceof Map) {
    var out = _plainObject();
    value.forEach(function (v, k) {
      out[typeof k === "string" ? k : String(k)] = _plainFromCbor(v);
    });
    return out;
  }
  return value;
}

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

function _withAnchors(base, plan, rootsOverride, safetyNetRoots, requireCts) {
  if (plan.safetyNet) {
    base.verifySafetyNetJws = true;
    base.safetyNetRoots = safetyNetRoots;
    base.requireCtsProfileMatch = requireCts;
  } else if (rootsOverride && plan.hasChain) {
    base.rootCertificates = rootsOverride;
  } else if (plan.roots) {
    base.rootCertificates = plan.roots;
  }
  return base;
}

function _anchorPlan(attestationObject) {
  var decoded;
  try {
    decoded = cbor.decode(attestationObject, { maxBytes: MAX_ATTESTATION_CBOR_BYTES });
  } catch (_e) { return null; }
  if (!(decoded instanceof Map)) return null;
  var fmt = decoded.get("fmt");
  if (fmt === "compound") return "refuse";
  var named = typeof fmt === "string" ? fmt : null;
  if (fmt === "android-safetynet") {
    return { roots: null, hasChain: false, safetyNet: true, fmt: named };
  }
  var attStmt = decoded.get("attStmt");
  var hasChain = attStmt instanceof Map && attStmt.has("x5c");
  var roots = hasChain ? (attestationRoots.ROOTS_BY_FORMAT[fmt] || null) : null;
  return { roots: roots, hasChain: hasChain, safetyNet: false, fmt: named };
}

function _resolveTimeout(value) {
  if (value === undefined || value === null) return DEFAULT_TIMEOUT_MS;
  if (typeof value !== "number" || !isFinite(value) || value < 0) {
    throw new AuthError("auth-passkey/bad-timeout",
      "timeout must be a finite, non-negative number of milliseconds (got " +
      String(value) + ")");
  }
  return value;
}

function _resolveSafetyNetMaxAge(value) {
  if (value === undefined || value === null) return DEFAULT_SAFETYNET_MAX_AGE_MS;
  if (typeof value !== "number" || !isFinite(value) || value < 0) {
    throw new AuthError("auth-passkey/bad-safetynet-max-age",
      "safetyNetMaxAgeMs must be a finite, non-negative number of " +
      "milliseconds (got " + String(value) + ")");
  }
  return value;
}

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

function _requireCredentialType(response) {
  var type = response && response.type;
  if (type !== "public-key") {
    throw new AuthError("auth-passkey/bad-credential-type",
      "response.type must be \"public-key\" (got " + JSON.stringify(type) + ")");
  }
}

function _parseCertificate(pem) {
  return new nodeCrypto.X509Certificate(pem);
}

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

function _challengeBytes(value) {
  if (_canonicalBase64Url(value) === null) {
    throw new AuthError("auth-passkey/bad-expectedChallenge",
      "expectedChallenge must be canonical base64url");
  }
  return Buffer.from(value, "base64url");
}

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

function _plainObject() {
  return Object.create(null);
}

function _requireCredentialIdMatches(response, authoritativeId, why) {
  if (typeof response !== "object" || response === null) return;
  var expected = _canonicalBase64Url(authoritativeId);
  var fields = ["id", "rawId"];
  var stated = 0;
  for (var i = 0; i < fields.length; i += 1) {
    var wireValue = response[fields[i]];
    if (wireValue === undefined || wireValue === null) continue;
    stated += 1;
    var got = typeof wireValue === "string" ? _canonicalBase64Url(wireValue) : null;
    if (got === null || expected === null || got !== expected) {
      throw new AuthError("auth-passkey/credential-id-mismatch",
        "response." + fields[i] + " is " + JSON.stringify(wireValue) +
        " but " + why + " is " + JSON.stringify(authoritativeId));
    }
  }
  if (stated === 0) {
    throw new AuthError("auth-passkey/missing-credential-id",
      "the response states no credential id -- one of response.id or " +
      "response.rawId is required, and without either there is nothing to " +
      "bind to " + why);
  }
}

function _freshChallenge() {
  return bCrypto.generateBytes(CHALLENGE_BYTES).toString("base64url");
}

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
  _validateExpectedOrigin(opts.expectedOrigin);
  _requireString(opts.expectedRPID, "expectedRPID");

  _requireCredentialType(opts.response);
  _refuseCrossOrigin(opts.response, opts, "registration");
  var regAlgorithms = _resolveAllowedAlgorithms(opts.allowedAlgorithms);
  var reportedRegRpId = opts.expectedRPID;
  var reportedRegType = opts.response.type;
  var reportedRegClientExtensions = _snapshotValue(opts.response.clientExtensionResults);
  var reportedRegTransports = _snapshotValue(
    (opts.response.response || {}).transports);
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
  // Drop-silent: a parse failure leaves the flags at their defaults.
  var regAuthData = {};
  try {
    regAuthData = _pki().webauthn.parseAuthenticatorData(
      _pki().webauthn.parseAttestationObject(attestationObject).authDataBytes) || {};
  } catch (_e) { regAuthData = {}; }
  var attestedId = safeBuffer.toBuffer(att.credentialId).toString("base64url");
  _requireCredentialIdMatches(statedRegIds, attestedId,
    "the credential ID inside the attestation");

  var rv = {
    verified: att.attestationVerified === true,
    registrationInfo: {
      credential: {
        id:        attestedId,
        publicKey: safeBuffer.toBuffer(att.credentialPublicKeyBytes),
        counter:   att.signCount,
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
      origin:               clientData.origin,
      rpID:                 reportedRegRpId,
      attestationObject:    attestationObject,
      authenticatorExtensionResults: _authenticatorExtensions(regAuthData.extensions),
      clientExtensionResults: reportedRegClientExtensions,
    },
  };
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

async function conditionalAuthOptions(opts) {
  if (!opts) throw new AuthError("auth-passkey/missing-opts", "opts is required");
  _requireString(opts.rpId, "rpId");

  var safeCondExtensions = _validateExtensions(opts.extensions, opts.allowUnknownExtensions === true);
  var options = {
    rpId:               opts.rpId,
    challenge:          _freshChallenge(),
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

var MAX_EXT_INPUT_BYTES = 32;

function _b64urlExtInput(value, name, maxBytes) {
  if (typeof value === "string") {
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

function _prfExt(args) {
  if (!args || !args.eval) {
    throw new AuthError("auth-passkey/missing-eval",
      "extensions.prf({ eval: { first, second? } }) is required");
  }
  if (args.eval.first === undefined || args.eval.first === null) {
    throw new AuthError("auth-passkey/missing-prf-first",
      "extensions.prf eval.first is required");
  }
  var out = { prf: { eval: { first: _b64urlExtInput(args.eval.first, "eval.first", MAX_EXT_INPUT_BYTES) } } };
  if (args.eval.second !== undefined && args.eval.second !== null) {
    out.prf.eval.second = _b64urlExtInput(args.eval.second, "eval.second", MAX_EXT_INPUT_BYTES);
  }
  return out;
}

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
  if (buf.length === 0 || buf.length > 32) {
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
  var counter;
  if (opts.credential.counter === undefined || opts.credential.counter === null) {
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

  _requireCredentialIdMatches(opts.response, opts.credential.id,
    "the stored opts.credential.id -- look the credential up BY the asserted id");
  _requireCredentialType(opts.response);
  _refuseCrossOrigin(opts.response, opts, "authentication");
  var reportedCredentialId = opts.credential.id;
  var reportedRpId = opts.expectedRPID;
  var reportedClientExtensions = _snapshotValue(opts.response.clientExtensionResults);
  var authAlgorithms = _resolveAllowedAlgorithms(opts.allowedAlgorithms);
  var inner = opts.response.response || {};
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
    if (e && e.code === "webauthn/bad-signature") {
      return {
        verified: false,
        authenticationInfo: null,
        backupEligible: false,
        backupState: false,
      };
    }
    throw _refuse("authentication assertion", e);
  }

  var flags = assertion.flags || {};
  return {
    verified: assertion.signatureVerified === true,
    authenticationInfo: {
      newCounter:           assertion.signCount,
      credentialID:         reportedCredentialId,
      userVerified:         flags.uv === true,
      credentialDeviceType: flags.be === true ? "multiDevice" : "singleDevice",
      credentialBackedUp:   flags.bs === true,
      origin:               (assertion.clientData && assertion.clientData.origin) || null,
      rpID:                 reportedRpId,
      authenticatorExtensionResults: _authenticatorExtensions(assertion.extensions),
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
  _resolvedAnchors:             _resolvedAnchors,
  compareBackupState:           compareBackupState,
  ALLOWED_EXTENSION_KEYS:       ALLOWED_EXTENSION_KEYS,
};
