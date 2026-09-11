// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeCrypto = require("node:crypto");
var zlib = require("node:zlib");
var bCrypto = require("../crypto");
var safeJson = require("../safe-json");
var validateOpts = require("../validate-opts");
var C = require("../constants");
var jwt = require("./jwt");
var { defineClass } = require("../framework-error");

var StatusListError = defineClass("StatusListError", { alwaysPermanent: true });

var SUPPORTED_BIT_SIZES = { 1: 1, 2: 1, 4: 1, 8: 1 };
var STATUS_VALID                = 0;
var STATUS_INVALID              = 1;
var STATUS_SUSPENDED            = 2;
var STATUS_APPLICATION_SPECIFIC = 3;

var MAX_LIST_BYTES = C.BYTES.mib(1);

function _b64url(buf) { return bCrypto.toBase64Url(buf); }

var _fromB64url = bCrypto.makeBase64UrlDecoder({
  errorClass: StatusListError,
  code:       "status-list/bad-base64",
  badMessage: "status-list segment is not valid base64url",
});

function _validateBits(bits) {
  if (!Object.prototype.hasOwnProperty.call(SUPPORTED_BIT_SIZES, bits)) {
    throw new StatusListError("status-list/bad-bits",
      "statusList: bits must be 1, 2, 4, or 8 (draft §6.1.1) — got " + bits);
  }
}

function _validateStatus(status, bits) {
  if (typeof status !== "number" || !isFinite(status) || status < 0 || (status >> 0) !== status) {
    throw new StatusListError("status-list/bad-status",
      "statusList: status must be a non-negative integer — got " + status);
  }
  var max = (1 << bits) - 1;
  if (status > max) {
    throw new StatusListError("status-list/bad-status",
      "statusList: status " + status + " exceeds bits=" + bits + " ceiling " + max);
  }
}

function create(opts) {
  validateOpts.requireObject(opts, "statusList.create", StatusListError);
  validateOpts(opts, ["size", "bits", "fill"], "statusList.create");
  var size = opts.size;
  if (typeof size !== "number" || !isFinite(size) || size <= 0 || (size >> 0) !== size) {
    throw new StatusListError("status-list/bad-size",
      "statusList.create: size must be a positive integer — got " + size);
  }
  var bits = opts.bits === undefined ? 1 : opts.bits;
  _validateBits(bits);
  var bitBytes = Math.ceil((size * bits) / 8);
  var bytes = Buffer.alloc(bitBytes);
  if (opts.fill !== undefined && opts.fill !== 0) {
    _validateStatus(opts.fill, bits);
    for (var i = 0; i < size; i += 1) _setAt(bytes, bits, i, opts.fill);
  }

  function set(idx, status) {
    if (typeof idx !== "number" || idx < 0 || idx >= size || (idx >> 0) !== idx) {
      throw new StatusListError("status-list/bad-index",
        "statusList.set: idx out of range — got " + idx + ", size=" + size);
    }
    _validateStatus(status, bits);
    _setAt(bytes, bits, idx, status);
  }

  function get(idx) {
    if (typeof idx !== "number" || idx < 0 || idx >= size || (idx >> 0) !== idx) {
      throw new StatusListError("status-list/bad-index",
        "statusList.get: idx out of range — got " + idx + ", size=" + size);
    }
    return _getAt(bytes, bits, idx);
  }

  function snapshot() {
    return { size: size, bits: bits, bytes: Buffer.from(bytes) };
  }

  async function toJwt(jwtOpts) {
    validateOpts.requireObject(jwtOpts, "statusList.toJwt", StatusListError);
    validateOpts(jwtOpts, [
      "issuer", "subject", "privateKey", "algorithm",
      "expiresInSec", "notBeforeSec", "now", "ttl",
    ], "statusList.toJwt");
    validateOpts.requireNonEmptyString(jwtOpts.issuer,
      "statusList.toJwt: issuer", StatusListError, "status-list/bad-issuer");
    validateOpts.requireNonEmptyString(jwtOpts.subject,
      "statusList.toJwt: subject", StatusListError, "status-list/bad-subject");
    var deflated = zlib.deflateRawSync(bytes);
    if (deflated.length > MAX_LIST_BYTES) {
      throw new StatusListError("status-list/too-large",
        "statusList.toJwt: compressed list exceeds " + MAX_LIST_BYTES + " bytes — shard the list");
    }
    var lst = _b64url(deflated);
    var claims = {
      iss:         jwtOpts.issuer,
      sub:         jwtOpts.subject,
      status_list: { bits: bits, lst: lst },
    };
    if (typeof jwtOpts.ttl === "number") claims.ttl = jwtOpts.ttl;
    return await jwt.sign(claims, {
      privateKey:   jwtOpts.privateKey,
      algorithm:    jwtOpts.algorithm,
      typ:          "statuslist+jwt",
      expiresInSec: jwtOpts.expiresInSec,
      notBeforeSec: jwtOpts.notBeforeSec,
      now:          jwtOpts.now,
    });
  }

  return {
    set:        set,
    get:        get,
    size:       size,
    bits:       bits,
    snapshot:   snapshot,
    toJwt:      toJwt,
  };
}

function _setAt(bytes, bits, idx, status) {
  if (bits === 8) { bytes[idx] = status & 0xff; return; }
  var bitOffset = idx * bits;
  var byteIdx   = Math.floor(bitOffset / 8);
  var bitInByte = bitOffset % 8;
  var mask      = ((1 << bits) - 1) << bitInByte;
  bytes[byteIdx] = (bytes[byteIdx] & ~mask) | ((status << bitInByte) & mask);
}

function _getAt(bytes, bits, idx) {
  if (bits === 8) return bytes[idx];
  var bitOffset = idx * bits;
  var byteIdx   = Math.floor(bitOffset / 8);
  var bitInByte = bitOffset % 8;
  var mask      = (1 << bits) - 1;
  return (bytes[byteIdx] >> bitInByte) & mask;
}

async function fromJwt(token, opts) {
  validateOpts.requireObject(opts, "statusList.fromJwt", StatusListError);
  if (typeof token !== "string" || token.length === 0) {
    throw new StatusListError("status-list/bad-token",
      "statusList.fromJwt: token must be a non-empty string");
  }
  var claims = await jwt.verify(token, {
    publicKey:    opts.publicKey,
    keyResolver:  opts.keyResolver,
    algorithms:   opts.algorithms,
    issuer:       opts.expectedIssuer,
    audience:     opts.expectedAudience,
    clockToleranceSec: opts.clockToleranceSec,
    now:          opts.now,
    expectedTyp:  "statuslist+jwt",
  });
  var sl = claims.status_list;
  if (!sl || typeof sl !== "object" || typeof sl.lst !== "string") {
    throw new StatusListError("status-list/bad-claims",
      "statusList.fromJwt: payload missing status_list.lst (draft §6.1)");
  }
  var bits = sl.bits === undefined ? 1 : sl.bits;
  _validateBits(bits);
  var deflated;
  try { deflated = _fromB64url(sl.lst); }
  catch (e) {
    throw new StatusListError("status-list/bad-base64",
      "statusList.fromJwt: lst is not valid base64url: " + ((e && e.message) || String(e)));
  }
  if (deflated.length > MAX_LIST_BYTES) {
    throw new StatusListError("status-list/too-large",
      "statusList.fromJwt: compressed list exceeds " + MAX_LIST_BYTES + " bytes");
  }
  var inflated;
  try { inflated = zlib.inflateRawSync(deflated, { maxOutputLength: MAX_LIST_BYTES * 8 }); }
  catch (e) {
    throw new StatusListError("status-list/inflate-failed",
      "statusList.fromJwt: zlib inflate failed: " + ((e && e.message) || String(e)));
  }
  var size = (inflated.length * 8) / bits;
  return {
    list: {
      size:     size,
      bits:     bits,
      get:      function (idx) {
        if (typeof idx !== "number" || idx < 0 || idx >= size || (idx >> 0) !== idx) {
          throw new StatusListError("status-list/bad-index",
            "statusList.fromJwt get: idx out of range — got " + idx + ", size=" + size +
            " (an out-of-range status index fails closed, never reads as status 0/valid)");
        }
        return _getAt(inflated, bits, idx);
      },
      snapshot: function () { return { size: size, bits: bits, bytes: Buffer.from(inflated) }; },
    },
    claims: claims,
  };
}

void safeJson;
void nodeCrypto;

module.exports = {
  create:      create,
  fromJwt:     fromJwt,
  STATUS_VALID:                 STATUS_VALID,
  STATUS_INVALID:               STATUS_INVALID,
  STATUS_SUSPENDED:             STATUS_SUSPENDED,
  STATUS_APPLICATION_SPECIFIC:  STATUS_APPLICATION_SPECIFIC,
  StatusListError:              StatusListError,
};
