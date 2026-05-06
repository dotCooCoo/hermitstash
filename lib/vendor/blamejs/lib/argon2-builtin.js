"use strict";
/**
 * Thin wrapper over Node's built-in `crypto.argon2` that produces and
 * parses the PHC string format
 * (`$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`).
 *
 * Replaces the vendored `lib/vendor/argon2/` prebuilds (which the
 * framework carried since v0.4.x). Node 24+ ships a stable
 * `crypto.argon2*` API; vendoring the third-party native module is no
 * longer necessary, eliminates the supply-chain weight of platform-
 * specific prebuilds, and keeps the framework's "zero npm runtime
 * deps" posture intact without dragging argon2 prebuild artifacts
 * across every install.
 *
 * Operators wanting to supply their own argon2 implementation (e.g.
 * pinned to a specific upstream commit, or routed through a hardware-
 * backed accelerator) override at the call site by passing `argon2:`
 * in opts to `b.auth.password.hash` / `.verify` / `.needsRehash`. The
 * supplied object MUST expose the same `hash` / `verify` /
 * `needsRehash` shape this wrapper exposes.
 */

var nodeCrypto = require("crypto");
var blamejsCrypto = require("./crypto");
var C = require("./constants");

var ARGON2ID = "argon2id";

// Argon2 v1.3 — the only version current implementations emit.
var ARGON2_VERSION = 0x13;                                                       // allow:raw-byte-literal — argon2 algorithm version

var DEFAULT_HASH_LENGTH = C.BYTES.bytes(32);
var DEFAULT_SALT_LENGTH = C.BYTES.bytes(16);

// Standard PHC base64 — no padding, alphabet [A-Za-z0-9+/].
function _b64NoPad(buf) {
  return buf.toString("base64").replace(/=+$/g, "");
}

function _fromB64NoPad(s) {
  // Node tolerates missing padding in `Buffer.from(s, "base64")` so we
  // pass straight through; the no-pad form is what PHC strings emit
  // on the wire.
  return Buffer.from(s, "base64");
}

function _phcEncode(salt, hash, params) {
  return "$argon2id$v=" + ARGON2_VERSION +
         "$m=" + params.memoryCost +
         ",t=" + params.timeCost +
         ",p=" + params.parallelism +
         "$" + _b64NoPad(salt) +
         "$" + _b64NoPad(hash);
}

// Parse a PHC string into structured form. Accepts only argon2id
// shapes — argon2i / argon2d are intentionally not supported by the
// framework wrapper.
function _phcDecode(stored) {
  if (typeof stored !== "string" || stored.length === 0) return null;
  var parts = stored.split("$");
  if (parts.length !== 6) return null;
  if (parts[0] !== "" || parts[1] !== ARGON2ID) return null;
  var ver = /^v=(\d+)$/.exec(parts[2]);
  if (!ver) return null;
  var version = parseInt(ver[1], 10);
  if (!isFinite(version) || version <= 0) return null;
  var paramTokens = parts[3].split(",");
  var p = { memoryCost: NaN, timeCost: NaN, parallelism: NaN };
  for (var i = 0; i < paramTokens.length; i += 1) {
    var t = paramTokens[i];
    var eq = t.indexOf("=");
    if (eq === -1) return null;
    var k = t.slice(0, eq);
    var v = parseInt(t.slice(eq + 1), 10);
    if (!isFinite(v)) return null;
    if (k === "m") p.memoryCost = v;
    else if (k === "t") p.timeCost = v;
    else if (k === "p") p.parallelism = v;
  }
  if (!isFinite(p.memoryCost) || !isFinite(p.timeCost) || !isFinite(p.parallelism)) return null;
  var salt;
  var hash;
  try { salt = _fromB64NoPad(parts[4]); }
  catch (_e) { return null; }
  try { hash = _fromB64NoPad(parts[5]); }
  catch (_e) { return null; }
  return { version: version, params: p, salt: salt, hash: hash };
}

function _runArgon2(message, salt, params, hashLength) {
  // Use the async variant so the call queues onto the libuv threadpool
  // instead of blocking the main event loop. argon2 with framework
  // defaults (64 MiB / 3 passes / 1 lane) takes ~100ms per call;
  // blocking the loop that long stalls every concurrent timer the
  // test suite is also running and trips spurious flakes in
  // safe-async-loops fixtures.
  return new Promise(function (resolve, reject) {
    nodeCrypto.argon2(ARGON2ID, {
      message:     message,
      nonce:       salt,
      memory:      params.memoryCost,
      passes:      params.timeCost,
      parallelism: params.parallelism,
      tagLength:   hashLength,
    }, function (err, result) {
      if (err) reject(err);
      else resolve(result);
    });
  });
}

// ---- public surface ----

async function hash(plain, opts) {
  opts = opts || {};
  var params = {
    memoryCost:  opts.memoryCost  || C.BYTES.kib(64),                            // 64 MiB
    timeCost:    opts.timeCost    || 3,
    parallelism: opts.parallelism || 1,
  };
  var hashLength = opts.hashLength || DEFAULT_HASH_LENGTH;
  var salt = opts.salt || nodeCrypto.randomBytes(DEFAULT_SALT_LENGTH);
  var message = Buffer.isBuffer(plain) ? plain : Buffer.from(String(plain), "utf8");
  var raw = await _runArgon2(message, salt, params, hashLength);
  // raw: true — return the unwrapped Buffer (used by vault key
  // derivation + backup KDF where the bytes feed directly into
  // XChaCha20). Default produces a PHC-string-encoded password hash.
  if (opts.raw === true) return raw;
  return _phcEncode(salt, raw, params);
}

async function verify(stored, plain) {
  var dec = _phcDecode(stored);
  if (!dec) return false;
  var message = Buffer.isBuffer(plain) ? plain : Buffer.from(String(plain), "utf8");
  var actual;
  try { actual = await _runArgon2(message, dec.salt, dec.params, dec.hash.length); }
  catch (_e) { return false; }
  return blamejsCrypto.timingSafeEqual(actual, dec.hash);
}

function needsRehash(stored, opts) {
  opts = opts || {};
  var dec = _phcDecode(stored);
  if (!dec) return true;
  if (dec.version !== ARGON2_VERSION) return true;
  var memoryCost  = opts.memoryCost  || C.BYTES.kib(64);                         // same defaults as hash()
  var timeCost    = opts.timeCost    || 3;
  var parallelism = opts.parallelism || 1;
  if (dec.params.memoryCost  < memoryCost)  return true;
  if (dec.params.timeCost    < timeCost)    return true;
  if (dec.params.parallelism < parallelism) return true;
  return false;
}

module.exports = {
  argon2id:    ARGON2ID,
  hash:        hash,
  verify:      verify,
  needsRehash: needsRehash,
  // Test-only — let the test harness exercise the PHC encode/decode
  // round trip without re-running actual hashing.
  _phcEncode:  _phcEncode,
  _phcDecode:  _phcDecode,
};
