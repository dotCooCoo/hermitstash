"use strict";
/**
 * OAuth Token Status List (draft-ietf-oauth-status-list-20).
 *
 * An issuer publishes a JWT-wrapped bitstring at a URL; relying
 * parties fetch + check the bit at index N to determine if the
 * credential whose `status_list` claim points at that URL + index
 * has been revoked / suspended / is still valid. The format is the
 * canonical replacement for the older "status list" mechanisms in
 * SD-JWT VC and OpenID for Verifiable Credentials.
 *
 * Status values per draft §4.2:
 *   0 = VALID
 *   1 = INVALID
 *   2 = SUSPENDED
 *   3 = APPLICATION_SPECIFIC
 *   ... (1-bit / 2-bit / 4-bit / 8-bit `bits` size — operator picks)
 *
 *   var list = b.auth.statusList.create({ size: 1024, bits: 1 });
 *   list.set(42, 1);                                  // mark idx 42 INVALID
 *   var jwt = await list.toJwt({
 *     issuer:     "https://issuer.example.com",
 *     subject:    "https://issuer.example.com/status/list/1",
 *     privateKey: env("STATUS_LIST_PRIVATE_KEY_PEM"),
 *     algorithm:  "ML-DSA-87",      // matches b.auth.jwt's PQC default
 *   });
 *
 *   // Receive side:
 *   var rv = await b.auth.statusList.fromJwt(jwt, { publicKey: pem });
 *   rv.list.get(42)   // → 1 (INVALID)
 *
 * The JWT payload shape per draft §6.1:
 *   {
 *     iss: "<issuer>",
 *     sub: "<this-list-uri>",
 *     iat: <issued-at>,
 *     exp: <optional-expires>,
 *     ttl: <optional-cache-ttl>,
 *     status_list: { bits: 1|2|4|8, lst: "<base64url(zlib(bitstring))>" },
 *   }
 *
 * The bitstring is zlib-deflated (RFC 1951 raw deflate per draft
 * §6.1.4) before base64url encoding so a million-entry list collapses
 * to a few KB on the wire when most bits are zero.
 */

var nodeCrypto = require("crypto");
var zlib = require("node:zlib");
var safeJson = require("../safe-json");
var validateOpts = require("../validate-opts");
var C = require("../constants");
var jwt = require("./jwt");
var { defineClass } = require("../framework-error");

var StatusListError = defineClass("StatusListError", { alwaysPermanent: true });

var SUPPORTED_BIT_SIZES = { 1: 1, 2: 1, 4: 1, 8: 1 };                            // allow:raw-byte-literal — bit-size enum (1/2/4/8 bits per status), not bytes
var STATUS_VALID                = 0;
var STATUS_INVALID              = 1;
var STATUS_SUSPENDED            = 2;
var STATUS_APPLICATION_SPECIFIC = 3;

// Cap the on-the-wire compressed payload at 1 MiB (a million 1-bit
// entries compress to ~125 KB when most are zero; 8 MiB on the wire
// is more than the spec's expected use). Operators publishing larger
// status lists should shard.
var MAX_LIST_BYTES = C.BYTES.mib(1);

function _b64url(buf) {
  return buf.toString("base64").replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function _fromB64url(s) {
  var padded = s.replace(/-/g, "+").replace(/_/g, "/");
  while (padded.length % 4) padded += "=";                                       // allow:raw-byte-literal — base64 quartet padding
  return Buffer.from(padded, "base64");
}

function _validateBits(bits) {
  if (!SUPPORTED_BIT_SIZES[bits]) {
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
  // Allocate the bit-packed buffer up front. byteCount = ceil(size*bits/8).
  var bitBytes = Math.ceil((size * bits) / 8);                                   // allow:raw-byte-literal — bits-per-byte conversion
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

  // ---- JWT issuance ----
  // Returns the canonical JWT payload + signed compact form per
  // draft §6.1. The signing key is operator-supplied; the framework
  // wraps b.auth.jwt.sign with the status-list-specific claim shape.
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

// ---- bit-packed helpers ----

function _setAt(bytes, bits, idx, status) {
  if (bits === 8) { bytes[idx] = status & 0xff; return; }                        // allow:raw-byte-literal — byte mask
  var bitOffset = idx * bits;
  var byteIdx   = Math.floor(bitOffset / 8);                                     // allow:raw-byte-literal — bits-per-byte
  var bitInByte = bitOffset % 8;                                                 // allow:raw-byte-literal — bits-per-byte
  var mask      = ((1 << bits) - 1) << bitInByte;
  bytes[byteIdx] = (bytes[byteIdx] & ~mask) | ((status << bitInByte) & mask);
}

function _getAt(bytes, bits, idx) {
  if (bits === 8) return bytes[idx];                                             // allow:raw-byte-literal — 8-bit fast path
  var bitOffset = idx * bits;
  var byteIdx   = Math.floor(bitOffset / 8);                                     // allow:raw-byte-literal — bits-per-byte
  var bitInByte = bitOffset % 8;                                                 // allow:raw-byte-literal — bits-per-byte
  var mask      = (1 << bits) - 1;
  return (bytes[byteIdx] >> bitInByte) & mask;
}

// ---- JWT verification ----

async function fromJwt(token, opts) {
  validateOpts.requireObject(opts, "statusList.fromJwt", StatusListError);
  if (typeof token !== "string" || token.length === 0) {
    throw new StatusListError("status-list/bad-token",
      "statusList.fromJwt: token must be a non-empty string");
  }
  // Verify the JWT signature using the framework's b.auth.jwt verifier.
  // Allow operator-supplied algorithms (defaults to PQC list).
  var claims = await jwt.verify(token, {
    publicKey:    opts.publicKey,
    keyResolver:  opts.keyResolver,
    algorithms:   opts.algorithms,
    issuer:       opts.expectedIssuer,
    audience:     opts.expectedAudience,
    clockToleranceSec: opts.clockToleranceSec,
    now:          opts.now,
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
  try { inflated = zlib.inflateRawSync(deflated, { maxOutputLength: MAX_LIST_BYTES * 8 }); }      // allow:raw-byte-literal — 8x compression-ratio cap
  catch (e) {
    throw new StatusListError("status-list/inflate-failed",
      "statusList.fromJwt: zlib inflate failed: " + ((e && e.message) || String(e)));
  }
  // Reconstruct the list object pointing at the inflated bytes.
  var size = (inflated.length * 8) / bits;                                       // allow:raw-byte-literal — bits-per-byte
  return {
    list: {
      size:     size,
      bits:     bits,
      get:      function (idx) { return _getAt(inflated, bits, idx); },
      snapshot: function () { return { size: size, bits: bits, bytes: Buffer.from(inflated) }; },
    },
    claims: claims,
  };
}

// Provide structured-error helpers so a tree-shake-friendly consumer
// can write switch(status) { case b.auth.statusList.STATUS_VALID: ... }.
void safeJson;                                                                   // imported for symmetry; reserved for future helpers
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
