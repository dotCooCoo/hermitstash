// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var pkg = require("../package.json");

function _validateDuration(unit, n) {
  if (typeof n !== "number" || !isFinite(n) || n < 0) {
    throw new TypeError("C.TIME." + unit + ": expected non-negative finite number, got " +
      (typeof n) + " " + JSON.stringify(n));
  }
}
var TIME = Object.freeze({
  seconds: function (n) { _validateDuration("seconds", n); return n * 1000; },
  minutes: function (n) { _validateDuration("minutes", n); return n * 60000; },
  hours:   function (n) { _validateDuration("hours",   n); return n * 3600000; },
  days:    function (n) { _validateDuration("days",    n); return n * 86400000; },
  weeks:   function (n) { _validateDuration("weeks",   n); return n * 604800000; },
});

function _validateBytes(unit, n) {
  if (typeof n !== "number" || !isFinite(n) || n < 0) {
    throw new TypeError("C.BYTES." + unit + ": expected non-negative finite number, got " +
      (typeof n) + " " + JSON.stringify(n));
  }
}
var BYTES = Object.freeze({
  bytes: function (n) { _validateBytes("bytes", n); return n; },
  kib:   function (n) { _validateBytes("kib",   n); return n * 1024; },
  mib:   function (n) { _validateBytes("mib",   n); return n * 1024 * 1024; },
  gib:   function (n) { _validateBytes("gib",   n); return n * 1024 * 1024 * 1024; },
});

var STATUS = Object.freeze({
  CONTINUE: 100, SWITCHING_PROTOCOLS: 101, PROCESSING: 102, EARLY_HINTS: 103,

  OK: 200, CREATED: 201, ACCEPTED: 202, NON_AUTHORITATIVE_INFORMATION: 203,
  NO_CONTENT: 204, RESET_CONTENT: 205, PARTIAL_CONTENT: 206, MULTI_STATUS: 207,
  ALREADY_REPORTED: 208, IM_USED: 226,

  MULTIPLE_CHOICES: 300, MOVED_PERMANENTLY: 301, FOUND: 302, SEE_OTHER: 303,
  NOT_MODIFIED: 304, USE_PROXY: 305, TEMPORARY_REDIRECT: 307,
  PERMANENT_REDIRECT: 308,

  BAD_REQUEST: 400, UNAUTHORIZED: 401, PAYMENT_REQUIRED: 402, FORBIDDEN: 403,
  NOT_FOUND: 404, METHOD_NOT_ALLOWED: 405, NOT_ACCEPTABLE: 406,
  PROXY_AUTHENTICATION_REQUIRED: 407, REQUEST_TIMEOUT: 408, CONFLICT: 409,
  GONE: 410, LENGTH_REQUIRED: 411, PRECONDITION_FAILED: 412,
  CONTENT_TOO_LARGE: 413, URI_TOO_LONG: 414, UNSUPPORTED_MEDIA_TYPE: 415,
  RANGE_NOT_SATISFIABLE: 416, EXPECTATION_FAILED: 417, IM_A_TEAPOT: 418,
  MISDIRECTED_REQUEST: 421, UNPROCESSABLE_CONTENT: 422, LOCKED: 423,
  FAILED_DEPENDENCY: 424, TOO_EARLY: 425, UPGRADE_REQUIRED: 426,
  PRECONDITION_REQUIRED: 428, TOO_MANY_REQUESTS: 429,
  REQUEST_HEADER_FIELDS_TOO_LARGE: 431, UNAVAILABLE_FOR_LEGAL_REASONS: 451,

  INTERNAL_SERVER_ERROR: 500, NOT_IMPLEMENTED: 501, BAD_GATEWAY: 502,
  SERVICE_UNAVAILABLE: 503, GATEWAY_TIMEOUT: 504,
  HTTP_VERSION_NOT_SUPPORTED: 505, VARIANT_ALSO_NEGOTIATES: 506,
  INSUFFICIENT_STORAGE: 507, LOOP_DETECTED: 508, NOT_EXTENDED: 510,
  NETWORK_AUTHENTICATION_REQUIRED: 511,
});

function _validateStatus(name, n) {
  if (typeof n !== "number" || !isFinite(n) || Math.floor(n) !== n) {
    throw new TypeError("C.HTTP." + name + ": status must be a whole number, got " +
      (typeof n) + " " + JSON.stringify(n));
  }
}

var HTTP = Object.freeze({
  STATUS: STATUS,

  informational: function (n) { _validateStatus("informational", n); return n >= 100 && n < 200; },
  success:       function (n) { _validateStatus("success", n);       return n >= 200 && n < 300; },
  redirect:      function (n) { _validateStatus("redirect", n);      return n >= 300 && n < 400; },
  clientError:   function (n) { _validateStatus("clientError", n);   return n >= 400 && n < 500; },
  serverError:   function (n) { _validateStatus("serverError", n);   return n >= 500 && n < 600; },

  bodiless: function (n) {
    _validateStatus("bodiless", n);
    return (n >= 100 && n < 200) || n === STATUS.NO_CONTENT ||
           n === STATUS.RESET_CONTENT || n === STATUS.NOT_MODIFIED;
  },
});

var ENVELOPE_MAGIC = 0xE2;
var ENVELOPE_FIXED_INFO_LABEL = "blamejs/v1";

var KEM_IDS = Object.freeze({
  ML_KEM_1024:        0x02,
  ML_KEM_1024_P384:   0x03,
  ML_KEM_768_X25519:  0x04,
});

var CIPHER_IDS = Object.freeze({
  XCHACHA20_POLY1305: 0x02,
});

var KDF_IDS = Object.freeze({
  SHAKE256:           0x02,
});

var CREDENTIAL_MAGIC = 0xC1;

var CRED_HASH_IDS = Object.freeze({
  SHAKE256:   0x01,
  ARGON2ID:   0x02,
});

var ACTIVE = Object.freeze({
  KEM:        KEM_IDS.ML_KEM_1024_P384,
  CIPHER:     CIPHER_IDS.XCHACHA20_POLY1305,
  KDF:        KDF_IDS.SHAKE256,
  CRED_HASH:  CRED_HASH_IDS.SHAKE256,
});

var FORMAT = Object.freeze({
  XCHACHA20_POLY1305: 0x02,
});

var PQC_GROUPS = Object.freeze({
  SecP256r1MLKEM768:     0x11EB,
  X25519MLKEM768:        0x11EC,
  SecP384r1MLKEM1024:    0x11ED,
});

var TLS_GROUP_PREFERENCE = Object.freeze([
  "X25519MLKEM768",
  "SecP256r1MLKEM768",
  "SecP384r1MLKEM1024",
  "X25519",
]);

var TLS_GROUP_CURVE_STR = TLS_GROUP_PREFERENCE.join(":");

var TLS_SERVER_FALLBACK_CURVES = Object.freeze([
  "X25519", "X448", "secp256r1", "secp384r1", "secp521r1",
]);

var _certCompression = null;
function TLS_CERT_COMPRESSION() {
  if (_certCompression !== null) return _certCompression;
  var list = [];
  try {
    var nodeTls = require("node:tls");
    if (typeof nodeTls.getCertificateCompressionAlgorithms === "function") {
      var reported = nodeTls.getCertificateCompressionAlgorithms();
      if (Array.isArray(reported)) list = reported.slice();
    }
  } catch (_e) { list = []; }
  _certCompression = Object.freeze(list);
  return _certCompression;
}


var VAULT_PREFIX = "vault:";

var ROW_PREFIX = "vault.row:";

var HASH_PREFIX = Object.freeze({
  EMAIL:       "bj-email:",
  IP:          "bj-ip:",
  TOKEN:       "bj-token:",
});

module.exports = {
  version:                pkg.version,
  TIME:                   TIME,
  BYTES:                  BYTES,
  HTTP:                   HTTP,
  ENVELOPE_MAGIC:         ENVELOPE_MAGIC,
  ENVELOPE_FIXED_INFO_LABEL: ENVELOPE_FIXED_INFO_LABEL,
  CREDENTIAL_MAGIC:       CREDENTIAL_MAGIC,
  KEM_IDS:                KEM_IDS,
  CIPHER_IDS:             CIPHER_IDS,
  KDF_IDS:                KDF_IDS,
  CRED_HASH_IDS:          CRED_HASH_IDS,
  ACTIVE:                 ACTIVE,
  FORMAT:                 FORMAT,
  PQC_GROUPS:             PQC_GROUPS,
  TLS_GROUP_PREFERENCE:   TLS_GROUP_PREFERENCE,
  TLS_SERVER_FALLBACK_CURVES: TLS_SERVER_FALLBACK_CURVES,
  TLS_GROUP_CURVE_STR:    TLS_GROUP_CURVE_STR,
  TLS_CERT_COMPRESSION:   TLS_CERT_COMPRESSION,
  VAULT_PREFIX:           VAULT_PREFIX,
  ROW_PREFIX:             ROW_PREFIX,
  HASH_PREFIX:            HASH_PREFIX,
};
