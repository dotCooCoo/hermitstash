// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeCrypto = require("node:crypto");
var bCrypto = require("./crypto");
var C = require("./constants");
var validateOpts = require("./validate-opts");
var observability = require("./observability");
var { Argon2Error } = require("./framework-error");

var ARGON2ID = "argon2id";

var ARGON2_VERSION = 0x13;

var DEFAULT_HASH_LENGTH = C.BYTES.bytes(32);
var DEFAULT_SALT_LENGTH = C.BYTES.bytes(16);
var MAX_TAG_BYTES = C.BYTES.kib(1);
var MAX_SALT_BYTES = C.BYTES.kib(1);

function _b64NoPad(buf) {
  var s = buf.toString("base64");
  var end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 0x3D ) end -= 1;
  return end === s.length ? s : s.slice(0, end);
}

function _fromB64NoPad(s) {
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

function _positiveInt(n) {
  return typeof n === "number" && isFinite(n) && n > 0 && Math.floor(n) === n;
}

function isGateRefusal(err) {
  return !!(err && err.isArgon2Error === true && err.permanent === false);
}

var COST_CEILING_DEFAULT = Object.freeze({
  memoryCost:  C.BYTES.kib(64) * 8,
  timeCost:    3 * 8,
  parallelism: 16,
});
var _costCeiling = COST_CEILING_DEFAULT;

function costCeiling(opts) {
  if (opts === undefined) return Object.assign({}, _costCeiling);
  if (opts === null) {
    _costCeiling = COST_CEILING_DEFAULT;
    return Object.assign({}, _costCeiling);
  }
  validateOpts(opts, ["memoryCost", "timeCost", "parallelism"],
    "argon2.costCeiling");
  var next = Object.assign({}, _costCeiling, opts);
  ["memoryCost", "timeCost", "parallelism"].forEach(function (k) {
    if (!_positiveInt(next[k])) {
      throw new TypeError("argon2.costCeiling: " + k +
        " must be a positive finite integer");
    }
  });
  _costCeiling = Object.freeze(next);
  return Object.assign({}, _costCeiling);
}

function _withinCeiling(p) {
  return p.memoryCost  <= _costCeiling.memoryCost &&
         p.timeCost    <= _costCeiling.timeCost &&
         p.parallelism <= _costCeiling.parallelism;
}

function exceedsCostCeiling(stored) {
  var dec = _phcDecode(typeof stored === "string" ? stored : String(stored == null ? "" : stored));
  return !!(dec && !_withinCeiling(dec.params));
}

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
  if (!_positiveInt(p.memoryCost) || !_positiveInt(p.timeCost) ||
      !_positiveInt(p.parallelism)) return null;
  var salt;
  var hash;
  try { salt = _fromB64NoPad(parts[4]); }
  catch (_e) { return null; }
  try { hash = _fromB64NoPad(parts[5]); }
  catch (_e) { return null; }
  if (salt.length === 0 || salt.length > MAX_SALT_BYTES) return null;
  if (hash.length === 0 || hash.length > MAX_TAG_BYTES) return null;
  return { version: version, params: p, salt: salt, hash: hash };
}

var GATE_DEFAULT_LIMIT = 8;
var _limit = GATE_DEFAULT_LIMIT;
var _active = 0;
var _waiters = [];
var _maxQueued = Infinity;
var _waitTimeoutMs = 0;

function gate(n, opts) {
  var nextLimit = _limit;
  var nextMaxQueued = _maxQueued;
  var nextWaitTimeoutMs = _waitTimeoutMs;
  if (n !== undefined && n !== null) {
    if (!_positiveInt(n)) {
      throw new Argon2Error("argon2/bad-gate",
        "argon2.gate(n): n must be a positive integer");
    }
    nextLimit = n;
  }
  if (opts !== undefined && opts !== null) {
    validateOpts(opts, ["maxQueued", "waitTimeoutMs"], "argon2.gate");
    if (opts.maxQueued !== undefined) {
      if (opts.maxQueued !== Infinity && !_positiveInt(opts.maxQueued) && opts.maxQueued !== 0) {
        throw new Argon2Error("argon2/bad-gate",
          "argon2.gate: maxQueued must be a non-negative integer or Infinity");
      }
      nextMaxQueued = opts.maxQueued;
    }
    if (opts.waitTimeoutMs !== undefined) {
      if (opts.waitTimeoutMs !== 0 && !_positiveInt(opts.waitTimeoutMs)) {
        throw new Argon2Error("argon2/bad-gate",
          "argon2.gate: waitTimeoutMs must be 0 or a positive integer");
      }
      nextWaitTimeoutMs = opts.waitTimeoutMs;
    }
  }
  _limit = nextLimit;
  _maxQueued = nextMaxQueued;
  _waitTimeoutMs = nextWaitTimeoutMs;
  _startWaiters();
  return stats();
}

function stats() {
  return {
    running:       _active,
    waiting:       _waiters.length,
    limit:         _limit,
    maxQueued:     _maxQueued,
    waitTimeoutMs: _waitTimeoutMs,
  };
}

function _startWaiters() {
  while (_waiters.length > 0 && _active < _limit) {
    var w = _waiters.shift();
    if (w.timer) clearTimeout(w.timer);
    _active += 1;
    w.resolve();
  }
}

function _acquire() {
  if (_active < _limit) {
    _active += 1;
    return Promise.resolve();
  }
  if (_waiters.length >= _maxQueued) {
    return Promise.reject(new Argon2Error("argon2/busy",
      "argon2: " + _active + " run(s) in flight and " + _waiters.length +
      " waiting, at the configured maxQueued of " + _maxQueued));
  }
  return new Promise(function (resolve, reject) {
    var entry = { resolve: resolve, reject: reject, timer: null };
    if (_waitTimeoutMs > 0) {
      entry.timer = setTimeout(function () {
        var at = _waiters.indexOf(entry);
        if (at !== -1) _waiters.splice(at, 1);
        reject(new Argon2Error("argon2/queue-timeout",
          "argon2: waited " + _waitTimeoutMs + "ms for a slot"));
      }, _waitTimeoutMs);
      if (entry.timer.unref) entry.timer.unref();
    }
    _waiters.push(entry);
  });
}

function _release() {
  _active -= 1;
  _startWaiters();
}

function _runArgon2(message, salt, params, hashLength) {
  return _acquire().then(function () {
    return _runArgon2Ungated(message, salt, params, hashLength)
      .then(function (v) { _release(); return v; },
            function (e) { _release(); throw e; });
  });
}

function _runArgon2Ungated(message, salt, params, hashLength) {
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

async function hash(plain, opts) {
  opts = opts || {};
  var params = {
    memoryCost:  opts.memoryCost  || C.BYTES.kib(64),
    timeCost:    opts.timeCost    || 3,
    parallelism: opts.parallelism || 1,
  };
  var hashLength = opts.hashLength || DEFAULT_HASH_LENGTH;
  if (opts.raw !== true && !_withinCeiling(params)) {
    throw new Argon2Error("argon2/cost-over-ceiling",
      "argon2.hash: m=" + params.memoryCost + ",t=" + params.timeCost +
      ",p=" + params.parallelism + " is over the ceiling verify will accept " +
      "(m=" + _costCeiling.memoryCost + ",t=" + _costCeiling.timeCost +
      ",p=" + _costCeiling.parallelism + "); raise it with costCeiling first");
  }
  var salt = opts.salt || nodeCrypto.randomBytes(DEFAULT_SALT_LENGTH);
  var message = Buffer.isBuffer(plain) ? plain : Buffer.from(String(plain), "utf8");
  var raw = await _runArgon2(message, salt, params, hashLength);
  if (opts.raw === true) return raw;
  return _phcEncode(salt, raw, params);
}

async function verify(stored, plain) {
  var dec = _phcDecode(stored);
  if (!dec) return false;
  if (!_withinCeiling(dec.params)) {
    try {
      observability.safeEvent("auth.password.cost_over_ceiling", 1, {
        memoryCost:  dec.params.memoryCost,
        timeCost:    dec.params.timeCost,
        parallelism: dec.params.parallelism,
      });
    } catch (_e) { /* hot-path sink, drop-silent by design */ }
    return false;
  }
  var message = Buffer.isBuffer(plain) ? plain : Buffer.from(String(plain), "utf8");
  var actual;
  try { actual = await _runArgon2(message, dec.salt, dec.params, dec.hash.length); }
  catch (e) {
    if (isGateRefusal(e)) throw e;
    return false;
  }
  return bCrypto.timingSafeEqual(actual, dec.hash);
}

function needsRehash(stored, opts) {
  opts = opts || {};
  var dec = _phcDecode(stored);
  if (!dec) return true;
  if (dec.version !== ARGON2_VERSION) return true;
  if (!_withinCeiling(dec.params)) return true;
  var memoryCost  = opts.memoryCost  || C.BYTES.kib(64);
  var timeCost    = opts.timeCost    || 3;
  var parallelism = opts.parallelism || 1;
  if (dec.params.memoryCost  < memoryCost)  return true;
  if (dec.params.timeCost    < timeCost)    return true;
  if (dec.params.parallelism < parallelism) return true;
  return false;
}

module.exports = {
  argon2id:       ARGON2ID,
  isGateRefusal:  isGateRefusal,
  exceedsCostCeiling: exceedsCostCeiling,
  hash:        hash,
  verify:      verify,
  needsRehash: needsRehash,
  costCeiling: costCeiling,
  gate:        gate,
  stats:       stats,
  _phcEncode:  _phcEncode,
  _phcDecode:  _phcDecode,
};
