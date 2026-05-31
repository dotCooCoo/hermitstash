"use strict";
/**
 * @module b.a2a
 * @nav    AI
 * @title  Agent-to-Agent
 *
 * @intro
 *   Linux Foundation A2A (Agent-to-Agent) standard — agents advertise
 *   identity, declared capabilities, endpoints, and policies via a
 *   signed "agent card" that a peer agent fetches before initiating
 *   collaboration. Cards are JSON documents canonicalized via RFC
 *   8785 (sorted keys, deterministic whitespace), hashed with
 *   SHAKE256 (64-byte output), and signed under the issuing agent's
 *   identity key. The default signing algorithm follows
 *   `b.crypto.sign` — ML-DSA-87 (FIPS 204) or SLH-DSA-SHAKE-256f
 *   (FIPS 205) auto-detected from the PEM. Verifiers refuse
 *   unsigned, expired, future-signed, or shape-malformed cards and
 *   emit audit events on every accept / deny outcome.
 *
 *   The card schema is intentionally narrow: required fields are
 *   `issuer`, `agentId`, `version` (semver), and `capabilities`
 *   (string array). Optional fields are `endpoints` (each must be
 *   HTTPS or a localhost loopback), `policies`, `contact`, and a
 *   free-form `metadata` bag. Capability names are bounded to 128
 *   chars; identifiers match `[a-zA-Z0-9._:/-]{1,256}`. Operators
 *   build cards via `createCard`, sign with `signCard`, and the
 *   peer side calls `verifyCard` against the issuer's published
 *   public key.
 *
 * @card
 *   Linux Foundation A2A (Agent-to-Agent) standard — agents advertise identity, declared capabilities, endpoints, and policies via a signed "agent card" that a peer agent fetches before initiating collaboration.
 */

var bCrypto = require("./crypto");
var canonicalJson = require("./canonical-json");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var audit = require("./audit");
var { A2aError } = require("./framework-error");

var REQUIRED_CARD_FIELDS = ["issuer", "agentId", "capabilities", "version"];
var ID_MAX     = 256;                                                                       // string-length cap, not bytes
var SEMVER_MAX = 64;                                                                        // string-length cap, not bytes
var CAP_NAME_MAX = 128;                                                                     // string-length cap, not bytes
var SHAKE256_BYTES = 64;                                                                    // SHA3-512 output is 64 bytes (FIPS 202)
var ID_RE     = /^[a-zA-Z0-9._:/-]{1,256}$/;
var SEMVER_RE = /^[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[A-Za-z0-9.-]+)?$/;

function _validateCardShape(card, errorClass) {
  if (!card || typeof card !== "object" || Array.isArray(card)) {
    throw errorClass.factory("a2a/bad-card",
      "a2a: card must be an object");
  }
  for (var i = 0; i < REQUIRED_CARD_FIELDS.length; i += 1) {
    var f = REQUIRED_CARD_FIELDS[i];
    if (typeof card[f] === "undefined" || card[f] === null) {
      throw errorClass.factory("a2a/missing-field",
        "a2a: card." + f + " is required");
    }
  }
  if (typeof card.issuer !== "string" || card.issuer.length > ID_MAX || !ID_RE.test(card.issuer)) {
    throw errorClass.factory("a2a/bad-field",
      "a2a: card.issuer shape (must match " + ID_RE + ")");
  }
  if (typeof card.agentId !== "string" || card.agentId.length > ID_MAX || !ID_RE.test(card.agentId)) {
    throw errorClass.factory("a2a/bad-field",
      "a2a: card.agentId shape");
  }
  if (typeof card.version !== "string" || card.version.length > SEMVER_MAX || !SEMVER_RE.test(card.version)) {
    throw errorClass.factory("a2a/bad-field",
      "a2a: card.version must be semver");
  }
  if (!Array.isArray(card.capabilities)) {
    throw errorClass.factory("a2a/bad-field",
      "a2a: card.capabilities must be an array");
  }
  for (var c = 0; c < card.capabilities.length; c += 1) {
    var cap = card.capabilities[c];
    if (typeof cap !== "string" || cap.length === 0 || cap.length > CAP_NAME_MAX) {
      throw errorClass.factory("a2a/bad-field",
        "a2a: card.capabilities[" + c + "] must be 1-128 char string");
    }
  }
  if (card.endpoints !== undefined) {
    if (!Array.isArray(card.endpoints)) {
      throw errorClass.factory("a2a/bad-field",
        "a2a: card.endpoints must be an array");
    }
    for (var e = 0; e < card.endpoints.length; e += 1) {
      var ep = card.endpoints[e];
      if (!ep || typeof ep !== "object" || typeof ep.url !== "string") {
        throw errorClass.factory("a2a/bad-field",
          "a2a: card.endpoints[" + e + "] must have a string url");
      }
      if (!/^https:\/\//.test(ep.url) && !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])/.test(ep.url)) {
        throw errorClass.factory("a2a/insecure-endpoint",
          "a2a: card.endpoints[" + e + "].url must be HTTPS (or localhost)");
      }
    }
  }
}

/**
 * @primitive b.a2a.canonicalize
 * @signature b.a2a.canonicalize(card)
 * @since     0.7.45
 * @status    stable
 * @related   b.a2a.signCard, b.a2a.verifyCard
 *
 * Returns the RFC 8785 JCS (JSON Canonicalization Scheme) string
 * form of an agent card — sorted keys, deterministic number form,
 * no insignificant whitespace. Exposed so operators that store the
 * canonical bytes alongside the signature can recompute the
 * digest without re-walking the object tree. `signCard` and
 * `verifyCard` use the same canonicalizer internally.
 *
 * @example
 *   var b = require("blamejs").create();
 *   var bytes = b.a2a.canonicalize({
 *     issuer:       "agent.example.com",
 *     agentId:      "ops-bot-1",
 *     version:      "1.0.0",
 *     capabilities: ["chat.respond", "tool.search"]
 *   });
 *   bytes.indexOf("\"agentId\":\"ops-bot-1\"") >= 0;
 *   // → true (keys appear in lexicographic order)
 */
function canonicalize(card) {
  return canonicalJson.stringify(card);
}

/**
 * @primitive b.a2a.createCard
 * @signature b.a2a.createCard(opts)
 * @since     0.7.45
 * @status    stable
 * @related   b.a2a.signCard, b.a2a.verifyCard
 *
 * Validates and returns a fresh agent-card object from `opts`. All
 * fields are shape-checked: `issuer` and `agentId` against the ID
 * regex, `version` against semver, every entry in `capabilities`
 * bounded to 128 chars, every `endpoints[].url` required to be HTTPS
 * (or a localhost loopback). Throws `A2aError` with codes
 * `MISSING_FIELD` / `BAD_FIELD` / `INSECURE_ENDPOINT` when input is
 * malformed — fail-at-config-time so a typo doesn't reach the wire.
 *
 * @opts
 *   {
 *     issuer:       string,         // 1..256 chars, [a-zA-Z0-9._:/-]
 *     agentId:      string,         // 1..256 chars, same shape
 *     version?:     string,         // semver; default "1.0.0"
 *     capabilities: string[],       // each 1..128 chars
 *     endpoints?:   { url: string, ... }[],  // each url HTTPS or localhost
 *     policies?:    object,
 *     contact?:     object,
 *     metadata?:    object
 *   }
 *
 * @example
 *   var b = require("blamejs").create();
 *   var card = b.a2a.createCard({
 *     issuer:       "agent.example.com",
 *     agentId:      "ops-bot-1",
 *     version:      "1.0.0",
 *     capabilities: ["chat.respond", "tool.search"],
 *     endpoints:    [{ url: "https://agent.example.com/a2a/v1" }]
 *   });
 *   card.version;
 *   // → "1.0.0"
 */
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

/**
 * @primitive b.a2a.signCard
 * @signature b.a2a.signCard(card, privateKeyPem, opts)
 * @since     0.7.45
 * @status    stable
 * @related   b.a2a.verifyCard, b.a2a.createCard, b.crypto.sign
 *
 * Canonicalizes the envelope `{ card, signedAt, expiresAt }` via RFC
 * 8785, hashes the result with SHAKE256 (64-byte output), and signs
 * the digest under `privateKeyPem`. The signing algorithm is
 * whatever the PEM declares — ML-DSA-87 by default, SLH-DSA-SHAKE-
 * 256f for the hash-based posture. Returns a base64-signature
 * envelope ready to publish over the A2A discovery channel. Emits a
 * `a2a.card_signed` audit event unless `opts.audit === false`.
 *
 * @opts
 *   {
 *     ttlMs?:     number,    // expiresAt = signedAt + ttlMs; default 24 h
 *     audit?:     boolean,   // default true
 *     errorClass?: ErrorClass // default A2aError
 *   }
 *
 * @example
 *   var b = require("blamejs").create();
 *   var card = b.a2a.createCard({
 *     issuer:       "agent.example.com",
 *     agentId:      "ops-bot-1",
 *     version:      "1.0.0",
 *     capabilities: ["chat.respond"]
 *   });
 *   var kp = b.crypto.generateSigningKeyPair();
 *   var envelope = b.a2a.signCard(card, kp.privateKeyPem);
 *   envelope.signature.length > 0;
 *   // → true (base64 ML-DSA-87 signature)
 */
function signCard(card, privateKeyPem, opts) {
  opts = opts || {};
  var errorClass = opts.errorClass || A2aError;
  var auditOn = opts.audit !== false;
  _validateCardShape(card, errorClass);

  if (typeof privateKeyPem !== "string" || privateKeyPem.length === 0) {
    throw errorClass.factory("a2a/bad-key",
      "a2a.signCard: privateKeyPem required");
  }

  numericBounds.requirePositiveFiniteIntIfPresent(opts.ttlMs, "a2a.signCard: opts.ttlMs", errorClass, "BAD_TTL");
  var ttlMs = opts.ttlMs || C.TIME.hours(24);
  var signedAt = Date.now();
  var expiresAt = signedAt + ttlMs;

  var envelopePayload = {
    card:      card,
    signedAt:  signedAt,
    expiresAt: expiresAt,
  };
  var canonical = canonicalize(envelopePayload);
  var digest = bCrypto.shake256
    ? bCrypto.shake256(Buffer.from(canonical, "utf8"), SHAKE256_BYTES)
    : null;
  var dataToSign = digest ? digest : Buffer.from(canonical, "utf8");
  var signature = bCrypto.sign(dataToSign, privateKeyPem);

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

/**
 * @primitive b.a2a.verifyCard
 * @signature b.a2a.verifyCard(envelope, publicKeyPem, opts)
 * @since     0.7.45
 * @status    stable
 * @related   b.a2a.signCard, b.a2a.createCard, b.crypto.verify
 *
 * Verifies a signed A2A envelope: shape-checks `card`, applies the
 * `expectedIssuer` filter when present, refuses if `expiresAt` is in
 * the past or `signedAt` is in the future (allowing
 * `clockSkewMs`), refuses if the canonical bytes exceed `maxBytes`,
 * recomputes the SHAKE256 digest, and runs `b.crypto.verify` against
 * `publicKeyPem`. Returns `{ valid, claims, reason }` — never throws
 * on a verification failure, so a peer agent can branch on `reason`
 * and emit its own audit event. Emits an `a2a.card_verified` /
 * `a2a.card_rejected` audit event unless `opts.audit === false`.
 *
 * @opts
 *   {
 *     maxBytes?:        number,   // canonical-bytes cap; default 64 KiB
 *     clockSkewMs?:     number,   // skew on signedAt/expiresAt; default 5 min
 *     expectedIssuer?:  string,   // refuse when card.issuer mismatches
 *     audit?:           boolean,  // default true
 *     errorClass?:      ErrorClass // default A2aError
 *   }
 *
 * @example
 *   var b = require("blamejs").create();
 *   var result = b.a2a.verifyCard(envelope, peerPublicKeyPem, {
 *     expectedIssuer: "agent.example.com"
 *   });
 *   result.valid;
 *   // → true (or false with reason "expired" / "signature-mismatch" / ...)
 */
function verifyCard(envelope, publicKeyPem, opts) {
  opts = opts || {};
  var errorClass = opts.errorClass || A2aError;
  numericBounds.requirePositiveFiniteIntIfPresent(opts.maxBytes, "a2a.verifyCard: opts.maxBytes", errorClass, "BAD_MAX_BYTES");
  numericBounds.requireNonNegativeFiniteIntIfPresent(opts.clockSkewMs, "a2a.verifyCard: opts.clockSkewMs", errorClass, "BAD_SKEW");
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
  var digest = bCrypto.shake256
    ? bCrypto.shake256(Buffer.from(canonical, "utf8"), SHAKE256_BYTES)
    : null;
  var dataToVerify = digest ? digest : Buffer.from(canonical, "utf8");
  var sigBuf;
  try { sigBuf = Buffer.from(envelope.signature, "base64"); }
  catch (_e) {
    return { valid: false, claims: null, reason: "signature-base64-bad" };
  }
  var ok = bCrypto.verify(dataToVerify, sigBuf, publicKeyPem);
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

var tasks = require("./a2a-tasks");

module.exports = {
  signCard:     signCard,
  verifyCard:   verifyCard,
  canonicalize: canonicalize,
  createCard:   createCard,
  tasks:        {
    send:   tasks.send,
    get:    tasks.get,
    cancel: tasks.cancel,
    ALLOWED_METHODS: tasks.ALLOWED_METHODS,
  },
  middleware: tasks.middleware,
  A2aTasksError: tasks.A2aTasksError,
};
