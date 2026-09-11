// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeCrypto = require("node:crypto");
var bCrypto = require("./crypto");
var C = require("./constants");

var ARGON2ID = "argon2id";

var ARGON2_VERSION = 0x13;

var DEFAULT_HASH_LENGTH = C.BYTES.bytes(32);
var DEFAULT_SALT_LENGTH = C.BYTES.bytes(16);

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
  var salt = opts.salt || nodeCrypto.randomBytes(DEFAULT_SALT_LENGTH);
  var message = Buffer.isBuffer(plain) ? plain : Buffer.from(String(plain), "utf8");
  var raw = await _runArgon2(message, salt, params, hashLength);
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
  return bCrypto.timingSafeEqual(actual, dec.hash);
}

function needsRehash(stored, opts) {
  opts = opts || {};
  var dec = _phcDecode(stored);
  if (!dec) return true;
  if (dec.version !== ARGON2_VERSION) return true;
  var memoryCost  = opts.memoryCost  || C.BYTES.kib(64);
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
  _phcEncode:  _phcEncode,
  _phcDecode:  _phcDecode,
};
