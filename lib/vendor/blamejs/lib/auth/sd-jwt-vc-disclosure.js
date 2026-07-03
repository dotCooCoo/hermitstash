// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * SD-JWT VC disclosure encoding/decoding helper.
 *
 * Per draft-ietf-oauth-sd-jwt-vc §4.1, a disclosure is the
 * base64url-encoded JSON serialisation of one of:
 *
 *   For object members:    [<salt>, <claim_name>, <claim_value>]
 *   For array elements:    [<salt>, <array_element>]
 *
 * The salt is a 128-bit random value (base64url) preventing dictionary
 * attacks on the disclosure digests. Operators that need deterministic
 * salt for testing pass opts.saltSource.
 */

var nodeCrypto = require("node:crypto");
var safeJson = require("../safe-json");
var { AuthError } = require("../framework-error");

var DEFAULT_SALT_BYTES = 16;          // 128-bit salt per spec recommendation

function _newSalt(opts) {
  if (opts && opts.saltSource && typeof opts.saltSource === "function") {
    var s = opts.saltSource();
    if (typeof s !== "string" || s.length === 0) {
      throw new AuthError("auth-sd-jwt-vc/bad-salt",
        "saltSource must return a non-empty string");
    }
    return s;
  }
  var bytes = nodeCrypto.randomBytes(DEFAULT_SALT_BYTES);
  return bytes.toString("base64url");
}

function encode(claimName, claimValue, opts) {
  if (typeof claimName !== "string" || claimName.length === 0) {
    throw new AuthError("auth-sd-jwt-vc/bad-claim-name",
      "encode: claimName must be a non-empty string");
  }
  if (claimValue === undefined) {
    throw new AuthError("auth-sd-jwt-vc/bad-claim-value",
      "encode: claimValue must not be undefined");
  }
  var salt = _newSalt(opts);
  var arr = [salt, claimName, claimValue];
  var jsonStr = safeJson.stringify(arr);
  return Buffer.from(jsonStr, "utf8").toString("base64url");
}

function encodeArrayElement(elementValue, opts) {
  if (elementValue === undefined) {
    throw new AuthError("auth-sd-jwt-vc/bad-element-value",
      "encodeArrayElement: elementValue must not be undefined");
  }
  var salt = _newSalt(opts);
  var arr = [salt, elementValue];
  var jsonStr = safeJson.stringify(arr);
  return Buffer.from(jsonStr, "utf8").toString("base64url");
}

function decode(disclosureStr) {
  if (typeof disclosureStr !== "string" || disclosureStr.length === 0) {
    return null;
  }
  var jsonStr;
  try { jsonStr = Buffer.from(disclosureStr, "base64url").toString("utf8"); }
  catch (_e) { return null; }
  var parsed;
  try { parsed = safeJson.parse(jsonStr, { maxBytes: 64 * 1024 }); }                // allow:raw-byte-literal — disclosure cap (64 KB)
  catch (_e) { return null; }
  if (!Array.isArray(parsed)) return null;
  if (parsed.length === 3) {
    return {
      salt:       parsed[0],
      name:       parsed[1],
      value:      parsed[2],
      isElement:  false,
    };
  }
  if (parsed.length === 2) {
    return {
      salt:       parsed[0],
      value:      parsed[1],
      isElement:  true,
    };
  }
  return null;
}

module.exports = {
  encode:             encode,
  encodeArrayElement: encodeArrayElement,
  decode:             decode,
  DEFAULT_SALT_BYTES: DEFAULT_SALT_BYTES,
};
