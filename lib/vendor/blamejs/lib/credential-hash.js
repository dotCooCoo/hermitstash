"use strict";
/**
 * b.credentialHash — envelope-versioned credential hashing.
 *
 * Stores a verifiable digest of a credential (API key secret, shared
 * bearer token, etc.) as a base64-encoded envelope:
 *
 *     byte 0: 0xC1 (CREDENTIAL_MAGIC)
 *     byte 1: <algorithm ID>
 *     bytes 2..N: algorithm-specific payload
 *
 * The verify path dispatches on byte 1, so old credentials remain
 * verifiable regardless of what ACTIVE.CRED_HASH points at today.
 * When a new algorithm becomes the framework default, existing rows
 * surface via `needsRehash()` and the next successful verify rotates
 * them transparently — same pattern as `b.auth.password.needsRehash`.
 *
 *   var env = await b.credentialHash.hash(secretBytes);
 *   // → "wQEx..." (base64)
 *
 *   var ok = await b.credentialHash.verify(secretBytes, env);
 *   // → true / false
 *
 *   var info = b.credentialHash.inspect(env);
 *   // → { algoId, algoName, payloadBytes }
 *
 *   if (b.credentialHash.needsRehash(env)) {
 *     await db.update({ credentialHash: await b.credentialHash.hash(secretBytes) });
 *   }
 *
 * Active algorithm: SHAKE256 (0x01). Suitable for high-entropy random
 * secrets (≥ 128 bits) — fast verify (microseconds), brute-force
 * infeasible at the entropy level the framework generates. SHAKE256
 * is an XOF: the envelope payload length drives the digest size, so
 * a future operator can request a 96-byte (or 32-byte) digest without
 * a primitive change — the same algorithm ID covers all output sizes.
 * Operators with low-entropy or operator-supplied secrets should pin
 * Argon2id (0x02) per-registry: `hash(s, { algo: "argon2id" })`.
 *
 * Why SHAKE256 over SHA3-512 as the active:
 *   - SHAKE256 is an extensible-output function (XOF). The envelope
 *     payload's actual byte length tells the verify path how many
 *     bytes to recompute. Changing digest size = no algo rotation.
 *   - Same family as the framework KDF (`crypto.kdf`), so one
 *     primitive does double duty.
 *   - SHA-3 family fixed-size mode locks the byte count at 64 — the
 *     moment we want a different size, we'd have to rotate algos.
 *
 * Why not Argon2id by default for api-key:
 *   - Argon2id at framework defaults costs ~250ms per verify call.
 *     For request-path verification that's a real latency hit.
 *     SHAKE256 is microseconds.
 *   - For ≥128-bit random secrets, the memory-hard property buys
 *     nothing — brute force is infeasible regardless of hash.
 *
 * Why the envelope still matters with SHAKE256 as active:
 *   - Algorithm agility — when SHA-3 family ever shows weakness, or
 *     a stronger XOF lands, ACTIVE.CRED_HASH rotates with no need
 *     to re-issue every credential. Old rows verify under their
 *     stored algo byte; new rows use the active.
 *   - Transparent rehash via needsRehash() drains old algos at the
 *     pace of organic verify traffic.
 *
 * Validation policy:
 *
 *   - hash() opts (algo, params)         → throw at call site
 *   - hash() secret type / length        → throw at call site
 *   - verify() envelope shape unparsable → return false (tolerant read)
 *   - verify() unknown algo ID           → return false (tolerant read)
 *   - inspect() bad envelope             → return null (tolerant read)
 */

var crypto = require("./crypto");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var { FrameworkError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });

function _emitEvent(n, v, l) { observability().safeEvent(n, v, l || {}); }

// Default SHAKE256 output size for newly-issued credentials. 128
// bytes (1024 bits) is double the SHAKE256 capacity (512 bits, which
// caps collision-resistance); the extra bytes don't add to that
// guarantee but cost nothing — base64 expansion is ~172 chars in a
// TEXT column, verify is sub-microsecond, and a longer digest hurts
// no foreseeable attack while protecting against any unforeseen
// partial-collision attack class. Per the framework's modernity
// posture (highest practical bar where cost is negligible), default
// to the larger size; operators pass `{ params: { length: 64 } }`
// to opt into the SHA3-512-comparable byte count if they need it.
var SHAKE256_DEFAULT_LENGTH = C.BYTES.bytes(128);
// Minimum payload length both hash() and verify() enforce. 16 bytes
// (128 bits) is the floor below which the digest's collision space
// becomes brute-forceable. The asymmetry between hash() (rejected < 16
// at config time) and verify() (silently accepted any length) let a
// truncated stored envelope verify with trivial work; both ends now
// refuse short payloads symmetrically.
var SHAKE256_MIN_LENGTH = C.BYTES.bytes(16);

function _shake256(secret, length) {
  // crypto.kdf wraps SHAKE256 with arbitrary output length. That's the
  // exact primitive we need — the framework's KDF and credential-hash
  // share one underlying XOF.
  return crypto.kdf(secret, length);
}


// auth/password is required lazily because it imports the (large)
// argon2 vendor; loading it for SHA3-only callers is wasted work.
var passwordPrimitive = lazyRequire(function () { return require("./auth/password"); });

class CredentialHashError extends FrameworkError {
  constructor(message, code) {
    super(message, code || "credential-hash/invalid");
    this.name = "CredentialHashError";
    this.isCredentialHashError = true;
  }
}

var ALGOS = Object.freeze({
  SHAKE256: "shake256",
  ARGON2ID: "argon2id",
});

var DEFAULTS = Object.freeze({
  algo: ALGOS.SHAKE256,
});

// Map between human-readable algo names (used in opts) and the wire
// algorithm IDs (used in the envelope byte). The envelope byte is
// what's persisted; the string is what operators read in code.
var NAME_TO_ID = Object.freeze({
  "shake256": C.CRED_HASH_IDS.SHAKE256,
  "argon2id": C.CRED_HASH_IDS.ARGON2ID,
});
var ID_TO_NAME = Object.freeze({
  0x01: "shake256",
  0x02: "argon2id",
});

// ---- Call-site validation (throw on bad input) ----

function _validateSecret(secret) {
  if (typeof secret !== "string" && !Buffer.isBuffer(secret)) {
    throw new CredentialHashError(
      "credentialHash: secret must be a string or Buffer, got " + typeof secret,
      "credential-hash/bad-secret");
  }
  var len = Buffer.isBuffer(secret) ? secret.length : Buffer.byteLength(secret, "utf8");
  if (len === 0) {
    throw new CredentialHashError(
      "credentialHash: secret must be non-empty",
      "credential-hash/bad-secret");
  }
}

function _validateOpts(opts) {
  if (!opts) return;
  if (opts.algo !== undefined && typeof opts.algo !== "string") {
    throw new CredentialHashError(
      "credentialHash: algo must be a string ('sha3-512' or 'argon2id')",
      "credential-hash/bad-opt");
  }
  if (opts.algo !== undefined && !Object.prototype.hasOwnProperty.call(NAME_TO_ID, opts.algo)) {
    throw new CredentialHashError(
      "credentialHash: unknown algo '" + opts.algo + "', expected one of " +
        JSON.stringify(Object.keys(NAME_TO_ID)),
      "credential-hash/bad-opt");
  }
  if (opts.params !== undefined && (typeof opts.params !== "object" || Array.isArray(opts.params))) {
    throw new CredentialHashError(
      "credentialHash: params must be a plain object",
      "credential-hash/bad-opt");
  }
}

// ---- Envelope (de)serialization ----

function _envelope(algoId, payload) {
  var head = Buffer.from([C.CREDENTIAL_MAGIC, algoId]);
  return Buffer.concat([head, payload]).toString("base64");
}

function _decodeEnvelope(env) {
  if (typeof env !== "string" || env.length === 0) return null;
  var buf;
  try { buf = Buffer.from(env, "base64"); }
  catch (_e) { return null; }
  if (buf.length < 2) return null;
  if (buf[0] !== C.CREDENTIAL_MAGIC) return null;
  var algoId = buf[1];
  if (!Object.prototype.hasOwnProperty.call(ID_TO_NAME, algoId)) return null;
  return { algoId: algoId, payload: buf.slice(2) };
}

// ---- Public surface ----

async function hash(secret, opts) {
  _validateSecret(secret);
  _validateOpts(opts);
  var algoName = (opts && opts.algo) || DEFAULTS.algo;
  var algoId = NAME_TO_ID[algoName];

  if (algoId === C.CRED_HASH_IDS.SHAKE256) {
    var length = (opts && opts.params && opts.params.length) || SHAKE256_DEFAULT_LENGTH;
    if (typeof length !== "number" || !isFinite(length) ||
        length < SHAKE256_MIN_LENGTH || Math.floor(length) !== length) {
      throw new CredentialHashError(
        "credentialHash.hash: SHAKE256 length must be an integer >= " +
        SHAKE256_MIN_LENGTH + ", got " + JSON.stringify(length),
        "credential-hash/bad-opt");
    }
    var env = _envelope(algoId, _shake256(secret, length));
    _emitEvent("credentialHash.hash", 1, { algo: algoName });
    return env;
  }
  if (algoId === C.CRED_HASH_IDS.ARGON2ID) {
    var plain = Buffer.isBuffer(secret) ? secret.toString("utf8") : secret;
    var phc = await passwordPrimitive().hash(plain, opts && opts.params);
    var argonEnv = _envelope(algoId, Buffer.from(phc, "utf8"));
    _emitEvent("credentialHash.hash", 1, { algo: algoName });
    return argonEnv;
  }
  // Unreachable — _validateOpts rejects unknown algos.
  throw new CredentialHashError(
    "credentialHash.hash: unsupported algo id 0x" + algoId.toString(0x10),
    "credential-hash/unsupported");
}

async function verify(secret, envelope) {
  // Tolerant read: any malformed envelope → false. Lets operators write
  //   if (!await ch.verify(s, row.hash)) return res.status(401);
  // without try/catch ceremony. We still reject obvious caller bugs
  // (non-string-or-Buffer secret) loudly because that signals broken
  // request plumbing rather than a bad credential.
  if (typeof secret !== "string" && !Buffer.isBuffer(secret)) {
    _emitEvent("credentialHash.verify", 1, { outcome: "failure", reason: "bad-secret-type" });
    return false;
  }
  var len = Buffer.isBuffer(secret) ? secret.length : Buffer.byteLength(secret, "utf8");
  if (len === 0) {
    _emitEvent("credentialHash.verify", 1, { outcome: "failure", reason: "empty-secret" });
    return false;
  }

  var decoded = _decodeEnvelope(envelope);
  if (!decoded) {
    _emitEvent("credentialHash.verify", 1, { outcome: "failure", reason: "bad-envelope" });
    return false;
  }
  var algoName = ID_TO_NAME[decoded.algoId];

  if (decoded.algoId === C.CRED_HASH_IDS.SHAKE256) {
    // Enforce the same minimum payload length that hash() enforces (16
    // bytes / 128 bits). Without this, a storage bug or attacker
    // tampering that truncates the stored envelope to just a few bytes
    // produces a hash with catastrophically reduced collision space —
    // a 1-byte payload has only 256 possible values, brute-forceable
    // in microseconds. The asymmetry between hash() (rejects < 16) and
    // verify() (accepted anything) was the silent gap; both ends now
    // refuse weak digests symmetrically.
    if (decoded.payload.length < SHAKE256_MIN_LENGTH) {
      _emitEvent("credentialHash.verify", 1,
        { outcome: "failure", reason: "payload-too-short", algo: algoName });
      return false;
    }
    var expected = _shake256(secret, decoded.payload.length);
    var ok = crypto.timingSafeEqual(expected, decoded.payload);
    _emitEvent("credentialHash.verify", 1,
      { outcome: ok ? "success" : "failure", algo: algoName });
    return ok;
  }
  if (decoded.algoId === C.CRED_HASH_IDS.ARGON2ID) {
    var phc = decoded.payload.toString("utf8");
    var plain = Buffer.isBuffer(secret) ? secret.toString("utf8") : secret;
    var argOk = false;
    try { argOk = await passwordPrimitive().verify(phc, plain); }
    catch (_e) { argOk = false; }
    _emitEvent("credentialHash.verify", 1,
      { outcome: argOk ? "success" : "failure", algo: algoName });
    return argOk;
  }
  _emitEvent("credentialHash.verify", 1, { outcome: "failure", reason: "unknown-algo" });
  return false;
}

function inspect(envelope) {
  var decoded = _decodeEnvelope(envelope);
  if (!decoded) return null;
  return {
    algoId:       decoded.algoId,
    algoName:     ID_TO_NAME[decoded.algoId],
    payloadBytes: decoded.payload.length,
  };
}

function needsRehash(envelope, opts) {
  var decoded = _decodeEnvelope(envelope);
  if (!decoded) return true;     // unrecognized → migrate aggressively
  var targetAlgoName = (opts && opts.algo) || DEFAULTS.algo;
  var targetId = NAME_TO_ID[targetAlgoName] || C.ACTIVE.CRED_HASH;
  if (decoded.algoId !== targetId) return true;
  if (decoded.algoId === C.CRED_HASH_IDS.ARGON2ID) {
    // Defer the parameter-lag check to the password primitive's
    // own needsRehash so the threshold stays in one place.
    var phc = decoded.payload.toString("utf8");
    try { return passwordPrimitive().needsRehash(phc, opts && opts.params); }
    catch (_e) { return true; }
  }
  return false;
}

module.exports = {
  hash:                 hash,
  verify:               verify,
  inspect:              inspect,
  needsRehash:          needsRehash,
  ALGOS:                ALGOS,
  DEFAULTS:             DEFAULTS,
  CredentialHashError:  CredentialHashError,
};
