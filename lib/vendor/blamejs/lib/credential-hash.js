"use strict";
/**
 * @module b.credentialHash
 * @nav    Identity
 * @title  Credential Hash
 *
 * @intro
 *   Derive a deterministic, verifiable hash for credential lookup
 *   (API-key secret, shared bearer token, webhook signing key) without
 *   storing the credential itself. The default is an Argon2id-style
 *   fingerprint over a SHAKE256 MAC — same chassis the password
 *   primitive uses, but tuned for high-entropy machine-generated
 *   secrets where memory-hard work is unnecessary.
 *
 *   Rows persist a base64 envelope:
 *
 *     byte 0:    0xC1 (CREDENTIAL_MAGIC)
 *     byte 1:    algorithm ID (0x01 SHAKE256 | 0x02 Argon2id)
 *     bytes 2-N: algorithm-specific payload
 *
 *   `verify` dispatches on the algorithm byte so old rows remain
 *   verifiable regardless of what `ACTIVE.CRED_HASH` is today. When a
 *   new algorithm becomes the framework default, existing rows surface
 *   via `needsRehash()` and the next successful verify rotates them
 *   transparently — same pattern as `b.auth.password.needsRehash`.
 *
 *   Active algorithm: SHAKE256 (0x01). Suitable for high-entropy random
 *   secrets (>= 128 bits) — verify is microseconds, brute force is
 *   infeasible at the entropy level the framework generates. SHAKE256
 *   is an XOF: the envelope payload length drives the digest size, so
 *   a future operator can request a 96-byte (or 32-byte) digest with no
 *   algorithm rotation. Operators with low-entropy or operator-supplied
 *   secrets pin Argon2id per-registry via `{ algo: "argon2id" }`.
 *
 *   Validation tiers:
 *     - hash() opts and secret shape — throw at call site (config-time)
 *     - verify() malformed envelope or unknown algo ID — return false
 *     - inspect() malformed envelope — return null
 *
 * @card
 *   Derive a deterministic, verifiable hash for credential lookup (API-key secret, shared bearer token, webhook signing key) without storing the credential itself.
 */

var bCrypto = require("./crypto");
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
  return bCrypto.kdf(secret, length);
}


// auth/password is required lazily because it imports the (large)
// argon2 vendor; loading it for SHA3-only callers is wasted work.
var passwordModule = lazyRequire(function () { return require("./auth/password"); });

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

/**
 * @primitive  b.credentialHash.hash
 * @signature  b.credentialHash.hash(secret, opts?)
 * @since      0.2.28
 * @status     stable
 * @compliance pci-dss, soc2, hipaa
 * @related    b.credentialHash.verify, b.credentialHash.needsRehash
 *
 * Hash a credential secret into a base64 envelope ready for storage in
 * a `credentialHash` column. Default algorithm is SHAKE256 with a
 * 128-byte output; pass `{ algo: "argon2id" }` for low-entropy or
 * operator-supplied secrets. Throws on a non-string-or-Buffer secret,
 * an unknown algorithm, a non-object `params`, or a SHAKE256 length
 * below the 16-byte (128-bit) collision-space floor.
 *
 * @opts
 *   algo:   "shake256" | "argon2id",
 *   params: {
 *     length: number,                             // SHAKE256 output bytes (default 128)
 *     ...                                         // Argon2id m / t / p forwarded to b.auth.password
 *   },
 *
 * @example
 *   var token = b.crypto.generateToken();          // 32 random bytes, base64url
 *   var env   = await b.credentialHash.hash(token);
 *   // → "wQE..." (base64 envelope)
 *
 *   // Operator-supplied (low-entropy) secret pins Argon2id:
 *   var humanEnv = await b.credentialHash.hash("partner-shared-key", { algo: "argon2id" });
 *   // → "wQI..." (base64 envelope, algo byte 0x02)
 */
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
    var phc = await passwordModule().hash(plain, opts && opts.params);
    var argonEnv = _envelope(algoId, Buffer.from(phc, "utf8"));
    _emitEvent("credentialHash.hash", 1, { algo: algoName });
    return argonEnv;
  }
  // Unreachable — _validateOpts rejects unknown algos.
  throw new CredentialHashError(
    "credentialHash.hash: unsupported algo id 0x" + algoId.toString(0x10),
    "credential-hash/unsupported");
}

/**
 * @primitive  b.credentialHash.verify
 * @signature  b.credentialHash.verify(secret, envelope)
 * @since      0.2.28
 * @status     stable
 * @compliance pci-dss, soc2, hipaa
 * @related    b.credentialHash.hash, b.credentialHash.needsRehash
 *
 * Constant-time check that `secret` matches the stored envelope.
 * Tolerant read: malformed envelope / unknown algorithm / payload
 * shorter than 16 bytes returns `false` without throwing, so callers
 * write a single `if (!await verify(...))` branch without try/catch
 * ceremony. Emits `credentialHash.verify` observability events with
 * outcome + reason for SIEM dashboards.
 *
 * @example
 *   var ok = await b.credentialHash.verify(presented, row.credentialHash);
 *   if (!ok) {
 *     res.statusCode = 401;
 *     return res.end();
 *   }
 *   // → true / false
 */
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
    var ok = bCrypto.timingSafeEqual(expected, decoded.payload);
    _emitEvent("credentialHash.verify", 1,
      { outcome: ok ? "success" : "failure", algo: algoName });
    return ok;
  }
  if (decoded.algoId === C.CRED_HASH_IDS.ARGON2ID) {
    var phc = decoded.payload.toString("utf8");
    var plain = Buffer.isBuffer(secret) ? secret.toString("utf8") : secret;
    var argOk = false;
    try { argOk = await passwordModule().verify(phc, plain); }
    catch (_e) { argOk = false; }
    _emitEvent("credentialHash.verify", 1,
      { outcome: argOk ? "success" : "failure", algo: algoName });
    return argOk;
  }
  _emitEvent("credentialHash.verify", 1, { outcome: "failure", reason: "unknown-algo" });
  return false;
}

/**
 * @primitive  b.credentialHash.inspect
 * @signature  b.credentialHash.inspect(envelope)
 * @since      0.2.28
 * @status     stable
 * @related    b.credentialHash.needsRehash
 *
 * Decode the envelope's algorithm byte and payload length without
 * verifying the secret. Returns `null` for any malformed envelope
 * (missing magic byte, unknown algorithm, truncated). Used by
 * operator dashboards to count rows-by-algorithm during a rotation
 * window.
 *
 * @example
 *   var info = b.credentialHash.inspect(row.credentialHash);
 *   if (info && info.algoName === "shake256" && info.payloadBytes < 64) {
 *     console.warn("legacy SHAKE256 row, will be rotated on next verify");
 *   }
 *   // → { algoId: 0x01, algoName: "shake256", payloadBytes: 128 }
 */
function inspect(envelope) {
  var decoded = _decodeEnvelope(envelope);
  if (!decoded) return null;
  return {
    algoId:       decoded.algoId,
    algoName:     ID_TO_NAME[decoded.algoId],
    payloadBytes: decoded.payload.length,
  };
}

/**
 * @primitive  b.credentialHash.needsRehash
 * @signature  b.credentialHash.needsRehash(envelope, opts?)
 * @since      0.2.28
 * @status     stable
 * @related    b.credentialHash.hash, b.credentialHash.verify
 *
 * Returns `true` when the stored envelope was produced under an
 * algorithm or parameter set that no longer matches the framework
 * default. Operators wrap a successful `verify` with this and re-issue
 * the credential transparently — same shape as `b.auth.password`.
 * Argon2id rows defer the parameter-lag check to the password
 * primitive's own `needsRehash` so the threshold lives in one place.
 *
 * @opts
 *   algo:   "shake256" | "argon2id",              // pin the comparison target
 *   params: object,                               // Argon2id m / t / p targets
 *
 * @example
 *   if (await b.credentialHash.verify(secret, row.credentialHash)) {
 *     if (b.credentialHash.needsRehash(row.credentialHash)) {
 *       var fresh = await b.credentialHash.hash(secret);
 *       db.from("apiKeys").where({ _id: row._id }).update({ credentialHash: fresh });
 *     }
 *   }
 *   // → true / false
 */
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
    try { return passwordModule().needsRehash(phc, opts && opts.params); }
    catch (_e) { return true; }
  }
  if (decoded.algoId === C.CRED_HASH_IDS.SHAKE256) {
    // Length-rotation: rehash when the stored digest is SHORTER than the
    // configured/default output length. Upgrade-only (`<`, matching the Argon2
    // needsRehash convention) — a longer-than-target digest is not actively
    // shortened. Without this compare, raising the SHAKE256 length never
    // triggered a rehash and the advertised rotation was a silent no-op.
    var targetLength = (opts && opts.params && opts.params.length) || SHAKE256_DEFAULT_LENGTH;
    if (decoded.payload.length < targetLength) return true;
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
