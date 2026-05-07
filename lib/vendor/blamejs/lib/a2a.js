"use strict";
/**
 * A2A (Agent-to-Agent) v1.x signed agent-card primitive.
 *
 * Linux Foundation Agentic AI Foundation A2A protocol — agents
 * advertise their capabilities, identity, endpoints, and policies via
 * an "agent card" that another agent fetches before initiating
 * collaboration. The 1.x protocol moved to required signed cards: the
 * card is a JSON document signed (detached signature) by the issuing
 * agent's identity key. Verifiers reject unsigned or expired cards.
 *
 * Public API:
 *
 *   a2a.signCard(card, privateKeyPem, opts) -> { card, signature, signedAt, expiresAt }
 *     Canonicalizes the card and returns a signed envelope. The
 *     signature is over the SHA3-512 hash of the canonical-JSON
 *     serialization (RFC 8785). Algorithm is whatever's pinned in
 *     privateKeyPem (defaults to ML-DSA-87 per framework crypto
 *     defaults). opts:
 *       ttlMs    — default 24 hours.
 *       audit    — bool, default true.
 *       errorClass — A2aError by default.
 *
 *   a2a.verifyCard(envelope, publicKeyPem, opts) -> { valid, claims, reason? }
 *     Verifies the signature, expiry, and required-fields shape.
 *     opts:
 *       maxBytes  — card cap (default 64 KiB).
 *       clockSkewMs — allowance on expiresAt (default 5 minutes).
 *       expectedIssuer — optional string; refuse if card.issuer !== this.
 *
 *   a2a.canonicalize(card) -> string
 *     RFC 8785-aligned canonical JSON (sorted keys, no whitespace).
 *     Exposed for operators that store the canonical form alongside
 *     the signature.
 *
 *   a2a.createCard(opts) -> card
 *     Convenience constructor:
 *       opts: { issuer, agentId, capabilities, endpoints, policies, contact, version }
 *     All fields validated for shape.
 */

var crypto = require("./crypto");
var canonicalJson = require("./canonical-json");
var C = require("./constants");
var nb = require("./numeric-bounds");
var audit = require("./audit");
var { A2aError } = require("./framework-error");

var REQUIRED_CARD_FIELDS = ["issuer", "agentId", "capabilities", "version"];
var ID_MAX     = 256;                                                                       // allow:raw-byte-literal — string-length cap, not bytes
var SEMVER_MAX = 64;                                                                        // allow:raw-byte-literal — string-length cap, not bytes
var CAP_NAME_MAX = 128;                                                                     // allow:raw-byte-literal — string-length cap, not bytes
var SHAKE256_BYTES = 64;                                                                    // allow:raw-byte-literal — SHA3-512 output is 64 bytes (FIPS 202)
var ID_RE     = /^[a-zA-Z0-9._:/-]{1,256}$/;
var SEMVER_RE = /^[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[A-Za-z0-9.-]+)?$/;

function _validateCardShape(card, errorClass) {
  if (!card || typeof card !== "object" || Array.isArray(card)) {
    throw errorClass.factory("BAD_CARD",
      "a2a: card must be an object");
  }
  for (var i = 0; i < REQUIRED_CARD_FIELDS.length; i += 1) {
    var f = REQUIRED_CARD_FIELDS[i];
    if (typeof card[f] === "undefined" || card[f] === null) {
      throw errorClass.factory("MISSING_FIELD",
        "a2a: card." + f + " is required");
    }
  }
  if (typeof card.issuer !== "string" || card.issuer.length > ID_MAX || !ID_RE.test(card.issuer)) {
    throw errorClass.factory("BAD_FIELD",
      "a2a: card.issuer shape (must match " + ID_RE + ")");
  }
  if (typeof card.agentId !== "string" || card.agentId.length > ID_MAX || !ID_RE.test(card.agentId)) {
    throw errorClass.factory("BAD_FIELD",
      "a2a: card.agentId shape");
  }
  if (typeof card.version !== "string" || card.version.length > SEMVER_MAX || !SEMVER_RE.test(card.version)) {
    throw errorClass.factory("BAD_FIELD",
      "a2a: card.version must be semver");
  }
  if (!Array.isArray(card.capabilities)) {
    throw errorClass.factory("BAD_FIELD",
      "a2a: card.capabilities must be an array");
  }
  for (var c = 0; c < card.capabilities.length; c += 1) {
    var cap = card.capabilities[c];
    if (typeof cap !== "string" || cap.length === 0 || cap.length > CAP_NAME_MAX) {
      throw errorClass.factory("BAD_FIELD",
        "a2a: card.capabilities[" + c + "] must be 1-128 char string");
    }
  }
  if (card.endpoints !== undefined) {
    if (!Array.isArray(card.endpoints)) {
      throw errorClass.factory("BAD_FIELD",
        "a2a: card.endpoints must be an array");
    }
    for (var e = 0; e < card.endpoints.length; e += 1) {
      var ep = card.endpoints[e];
      if (!ep || typeof ep !== "object" || typeof ep.url !== "string") {
        throw errorClass.factory("BAD_FIELD",
          "a2a: card.endpoints[" + e + "] must have a string url");
      }
      if (!/^https:\/\//.test(ep.url) && !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])/.test(ep.url)) {
        throw errorClass.factory("INSECURE_ENDPOINT",
          "a2a: card.endpoints[" + e + "].url must be HTTPS (or localhost)");
      }
    }
  }
}

function canonicalize(card) {
  return canonicalJson.stringify(card);
}

function createCard(opts) {
  opts = opts || {};
  var card = {
    issuer:       opts.issuer,
    agentId:      opts.agentId,
    version:      opts.version || "1.0.0",
    capabilities: Array.isArray(opts.capabilities) ? opts.capabilities.slice() : [],
  };
  if (opts.endpoints) card.endpoints = opts.endpoints;
  if (opts.policies)  card.policies  = opts.policies;
  if (opts.contact)   card.contact   = opts.contact;
  if (opts.metadata)  card.metadata  = opts.metadata;
  _validateCardShape(card, A2aError);
  return card;
}

function signCard(card, privateKeyPem, opts) {
  opts = opts || {};
  var errorClass = opts.errorClass || A2aError;
  var auditOn = opts.audit !== false;
  _validateCardShape(card, errorClass);

  if (typeof privateKeyPem !== "string" || privateKeyPem.length === 0) {
    throw errorClass.factory("BAD_KEY",
      "a2a.signCard: privateKeyPem required");
  }

  nb.requirePositiveFiniteIntIfPresent(opts.ttlMs, "a2a.signCard: opts.ttlMs", errorClass, "BAD_TTL");
  var ttlMs = opts.ttlMs || C.TIME.hours(24);
  var signedAt = Date.now();
  var expiresAt = signedAt + ttlMs;

  var envelopePayload = {
    card:      card,
    signedAt:  signedAt,
    expiresAt: expiresAt,
  };
  var canonical = canonicalize(envelopePayload);
  var digest = crypto.shake256
    ? crypto.shake256(Buffer.from(canonical, "utf8"), SHAKE256_BYTES)
    : null;
  var dataToSign = digest ? digest : Buffer.from(canonical, "utf8");
  var signature = crypto.sign(dataToSign, privateKeyPem);

  if (auditOn) {
    audit.safeEmit({
      action:   "a2a.card_signed",
      outcome:  "success",
      metadata: { issuer: card.issuer, agentId: card.agentId, expiresAt: expiresAt },
    });
  }

  return {
    card:      card,
    signedAt:  signedAt,
    expiresAt: expiresAt,
    signature: signature.toString("base64"),
  };
}

function verifyCard(envelope, publicKeyPem, opts) {
  opts = opts || {};
  var errorClass = opts.errorClass || A2aError;
  nb.requirePositiveFiniteIntIfPresent(opts.maxBytes, "a2a.verifyCard: opts.maxBytes", errorClass, "BAD_MAX_BYTES");
  nb.requireNonNegativeFiniteIntIfPresent(opts.clockSkewMs, "a2a.verifyCard: opts.clockSkewMs", errorClass, "BAD_SKEW");
  var maxBytes = opts.maxBytes || C.BYTES.kib(64);
  var clockSkewMs = opts.clockSkewMs !== undefined ? opts.clockSkewMs : C.TIME.minutes(5);
  var expectedIssuer = typeof opts.expectedIssuer === "string" ? opts.expectedIssuer : null;
  var auditOn = opts.audit !== false;

  if (!envelope || typeof envelope !== "object") {
    return { valid: false, claims: null, reason: "envelope-not-object" };
  }
  if (!envelope.card || !envelope.signature ||
      typeof envelope.signedAt !== "number" || typeof envelope.expiresAt !== "number") {
    return { valid: false, claims: null, reason: "envelope-shape" };
  }
  try { _validateCardShape(envelope.card, errorClass); }
  catch (e) {
    return { valid: false, claims: null, reason: "card-shape:" + e.code };
  }
  if (expectedIssuer && envelope.card.issuer !== expectedIssuer) {
    if (auditOn) {
      audit.safeEmit({
        action:   "a2a.card_rejected",
        outcome:  "denied",
        reason:   "issuer-mismatch",
        metadata: { expected: expectedIssuer, got: envelope.card.issuer },
      });
    }
    return { valid: false, claims: null, reason: "issuer-mismatch" };
  }

  var now = Date.now();
  if (envelope.expiresAt + clockSkewMs < now) {
    if (auditOn) {
      audit.safeEmit({
        action:   "a2a.card_rejected",
        outcome:  "denied",
        reason:   "expired",
        metadata: { expiresAt: envelope.expiresAt, now: now },
      });
    }
    return { valid: false, claims: null, reason: "expired" };
  }
  if (envelope.signedAt - clockSkewMs > now) {
    return { valid: false, claims: null, reason: "future-signed" };
  }

  var canonical = canonicalize({
    card:      envelope.card,
    signedAt:  envelope.signedAt,
    expiresAt: envelope.expiresAt,
  });
  if (Buffer.byteLength(canonical, "utf8") > maxBytes) {
    return { valid: false, claims: null, reason: "card-too-large" };
  }
  var digest = crypto.shake256
    ? crypto.shake256(Buffer.from(canonical, "utf8"), SHAKE256_BYTES)
    : null;
  var dataToVerify = digest ? digest : Buffer.from(canonical, "utf8");
  var sigBuf;
  try { sigBuf = Buffer.from(envelope.signature, "base64"); }
  catch (_e) {
    return { valid: false, claims: null, reason: "signature-base64-bad" };
  }
  var ok = crypto.verify(dataToVerify, sigBuf, publicKeyPem);
  if (!ok) {
    if (auditOn) {
      audit.safeEmit({
        action:   "a2a.card_rejected",
        outcome:  "denied",
        reason:   "signature-mismatch",
        metadata: { issuer: envelope.card.issuer, agentId: envelope.card.agentId },
      });
    }
    return { valid: false, claims: null, reason: "signature-mismatch" };
  }
  if (auditOn) {
    audit.safeEmit({
      action:   "a2a.card_verified",
      outcome:  "success",
      metadata: { issuer: envelope.card.issuer, agentId: envelope.card.agentId },
    });
  }
  return {
    valid:  true,
    claims: envelope.card,
    reason: null,
  };
}

module.exports = {
  signCard:     signCard,
  verifyCard:   verifyCard,
  canonicalize: canonicalize,
  createCard:   createCard,
};
