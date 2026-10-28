// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * @module b.constants
 * @nav    Primitives
 * @title  Constants
 * @slug   constants
 *
 * @intro
 *   The durations, sizes and protocol identifiers the framework's own
 *   options are written in, so a caller writes the same thing the
 *   framework reads.
 *
 *   <code>b.constants.TIME</code> and <code>b.constants.BYTES</code> exist
 *   because an option holding a bare number is a unit waiting to be
 *   guessed: <code>ttl: 300</code> is five minutes or five seconds
 *   depending on which primitive reads it, and <code>maxBytes:
 *   1000000</code> is a megabyte only if nobody meant MiB. Every duration
 *   the framework takes is milliseconds and every size is bytes, and these
 *   convert into them from a unit that is written down.
 *
 *   Both refuse a value that is not a non-negative finite number, so
 *   <code>TIME.minutes(undefined)</code> throws where the arithmetic would
 *   have produced <code>NaN</code> and carried on into a timer.
 *
 *   The rest is protocol identity: HTTP status numbers by name, the
 *   envelope and credential magic bytes, the KEM, cipher and KDF
 *   identifiers, the post-quantum TLS group preference, and the prefixes
 *   that mark a sealed value.
 *
 * @card
 *   The durations, sizes, status codes and protocol identifiers the
 *   framework's options are written in. TIME and BYTES convert a written
 *   unit into the milliseconds and bytes every option takes.
 */

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

// registry: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
var PQC_GROUPS = Object.freeze({
  MLKEM512:              0x0200,
  MLKEM768:              0x0201,
  MLKEM1024:             0x0202,
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

var BROTLI_DECODER_FIXED = Object.freeze({
  lineParts: 1,
  lines:     Object.freeze({ "22": [22, 23, 4], "24": [24, 22, 1], "26": [26, 12, 1] }),
  allFrom:   [27, 0, 0],
});

var OPENSSL_CRLDP_FIXED = Object.freeze({
  lineParts: 2,
  lines:     Object.freeze({
    "3.4": [3, 4, 8], "3.5": [3, 5, 9], "3.6": [3, 6, 5], "4.0": [4, 0, 3],
  }),
  allFrom:   [4, 1, 0],
});

var NODE_VERSION_RE = /^v?(\d{1,6})\.(\d{1,6})\.(\d{1,6})(?![\d.])(-?)/;
var OPENSSL_VERSION_RE = /^(\d{1,6})\.(\d{1,6})\.(\d{1,6})(?![\d.])(-?)/;
var OPENSSL_VERSION_PREFIX = "OpenSSL ";

function _parseVersionWith(re, text) {
  var m = re.exec(text);
  if (!m) return null;
  return {
    major:      parseInt(m[1], 10),
    minor:      parseInt(m[2], 10),
    patch:      parseInt(m[3], 10),
    prerelease: m[4] === "-",
    text:       text,
  };
}

function _parseNodeVersion(version) {
  if (typeof version !== "string") return null;
  return _parseVersionWith(NODE_VERSION_RE, version);
}

function _parseOpensslVersion(version) {
  if (typeof version !== "string") return null;
  var text = version.indexOf(OPENSSL_VERSION_PREFIX) === 0
    ? version.slice(OPENSSL_VERSION_PREFIX.length) : version;
  return _parseVersionWith(OPENSSL_VERSION_RE, text);
}

function _compareTriple(got, floor) {
  for (var i = 0; i < 3; i++) {
    if (got[i] !== floor[i]) return got[i] > floor[i] ? 1 : -1;
  }
  return 0;
}

function _atOrAboveFloor(parsed, floor) {
  var cmp = _compareTriple([parsed.major, parsed.minor, parsed.patch], floor);
  return parsed.prerelease ? cmp > 0 : cmp >= 0;
}

function _versionFixed(parsed, table) {
  if (parsed === null) return false;
  if (_atOrAboveFloor(parsed, table.allFrom)) return true;
  var line = [parsed.major, parsed.minor].slice(0, table.lineParts).join(".");
  if (!Object.prototype.hasOwnProperty.call(table.lines, line)) return false;
  return _atOrAboveFloor(parsed, table.lines[line]);
}

function _brotliDecoderPatched(version) {
  return _versionFixed(_parseNodeVersion(version), BROTLI_DECODER_FIXED);
}

function _opensslCrldpPatched(version) {
  return _versionFixed(_parseOpensslVersion(version), OPENSSL_CRLDP_FIXED);
}

function _certCompressionFor(reported, version) {
  var list = Array.isArray(reported) ? reported.slice() : [];
  if (!_brotliDecoderPatched(version)) {
    list = list.filter(function (name) { return name !== "brotli"; });
  }
  return Object.freeze(list);
}

/**
 * @primitive b.constants.TLS_CERT_COMPRESSION
 * @signature b.constants.TLS_CERT_COMPRESSION()
 * @since     0.18.17
 * @status    stable
 * @related   b.network.tls.certificateCompressionAlgorithms
 *
 * The TLS certificate-compression algorithms (RFC 8879) this Node build
 * offers, as a frozen array of their names. It is a function rather than
 * an array because the answer comes from the runtime, and a build that
 * reports none answers an empty array.
 *
 * On a Node release older than 22.23.4, 24.22.1 or 26.12.1 (and on the
 * odd-numbered 23.x and 25.x lines) the array does not include `"brotli"`.
 * The Brotli decoder in those releases writes out of bounds on a crafted
 * stream (CVE-2026-111497), and a TLS peer reaches the decoder during the
 * handshake, before the certificate chain is verified. A prerelease build
 * (a version with a `-` suffix such as `24.22.1-pre`) at one of those
 * releases is treated as unfixed, and so is a version string that does
 * not parse. On those releases `b.network.tls.buildOptions` and
 * `b.network.tls.applyToContext` refuse an explicit `certificateCompression`
 * that lists `"brotli"` with `tls/unsafe-cert-compression`.
 *
 * The first call asks `node:tls` and every later call answers the same
 * array, so a caller may read it per connection.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.constants.TLS_CERT_COMPRESSION();
 *   // → ["zlib", "brotli", "zstd"] on Node 26.12.1
 *   // → ["zlib", "zstd"] on Node 24.21.0
 */
var _certCompression = null;
function TLS_CERT_COMPRESSION() {
  if (_certCompression !== null) return _certCompression;
  var reported = [];
  try {
    var nodeTls = require("node:tls");
    if (typeof nodeTls.getCertificateCompressionAlgorithms === "function") {
      reported = nodeTls.getCertificateCompressionAlgorithms();
    }
  } catch (_e) { reported = []; }
  _certCompression = _certCompressionFor(reported, process.versions.node);
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
  _brotliDecoderPatched:  _brotliDecoderPatched,
  _opensslCrldpPatched:   _opensslCrldpPatched,
  _parseNodeVersion:      _parseNodeVersion,
  _parseOpensslVersion:   _parseOpensslVersion,
  _certCompressionFor:    _certCompressionFor,
  VAULT_PREFIX:           VAULT_PREFIX,
  ROW_PREFIX:             ROW_PREFIX,
  HASH_PREFIX:            HASH_PREFIX,
};
