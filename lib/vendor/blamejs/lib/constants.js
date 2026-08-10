// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Framework constants — values fixed by blamejs design.
 *
 * App-specific values (paths, asset versions, theme, animation, OAuth
 * allowlists) are supplied via createApp() configuration in the consuming
 * app. Nothing in this file is mutable per-deployment.
 *
 * Naming follows the roadmap "Naming conventions" section: SCREAMING_SNAKE
 * for constants, lowercase namespace exports.
 */

var pkg = require("../package.json");

// ---- Time helpers (ms) ----
// Functional generators instead of pre-defined discrete constants:
// any duration the framework or app needs is built from these, so the
// reader sees the unit at the call site (`C.TIME.minutes(45)` instead of
// adding a new FORTY_FIVE_MIN constant). All return integer milliseconds.
//
// Throw on non-finite or negative input — these are config-time helpers,
// so a typo (`C.TIME.minutes(opts.x)` where opts.x is undefined) should
// surface at boot instead of silently becoming `NaN` or `0` and shipping
// a 0ms timeout into production.
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

// ---- Byte helpers (binary / IEC units) ----
// Same pattern as TIME — units at the call site instead of pre-baked
// constants. Returns bytes; multiplications are 1024-based per IEC 80000-13
// (KiB/MiB/GiB), since every existing byte literal in the framework
// already uses 1024 multiplication.
//
// Throw on bad input — same rationale as TIME: bad input surfaces at
// the call site, not as a silent NaN cap that disables size limits.
function _validateBytes(unit, n) {
  if (typeof n !== "number" || !isFinite(n) || n < 0) {
    throw new TypeError("C.BYTES." + unit + ": expected non-negative finite number, got " +
      (typeof n) + " " + JSON.stringify(n));
  }
}
var BYTES = Object.freeze({
  // Passthrough for protocol-fixed byte counts (32-byte salt, 16-byte
  // nonce, 8-byte counter, etc.) — keeps every byte literal routed
  // through C.BYTES so the codebase has a single source of truth.
  // Equivalent to `n` but names the unit at the call site.
  bytes: function (n) { _validateBytes("bytes", n); return n; },
  kib:   function (n) { _validateBytes("kib",   n); return n * 1024; },
  mib:   function (n) { _validateBytes("mib",   n); return n * 1024 * 1024; },
  gib:   function (n) { _validateBytes("gib",   n); return n * 1024 * 1024 * 1024; },
});

// ---- HTTP status codes ----
//
// The registry, named, so a response class is written as what it means rather
// than as a number a reader has to recognise. Every code RFC 9110 defines, plus
// the registered ones from the RFCs that extend it (WebDAV 207/208/422-424,
// early hints 103, 418, 425, 428/429/431 and 451, and 511) — an operator
// reading a status here should find it whatever RFC put it there.
//
// The predicates carry the reasoning the numbers do not. Which statuses may
// carry a body is a rule stated across RFC 9110 §6.4.1 and §15, and getting it
// wrong is not cosmetic: destroying a bodiless response to signal a truncation
// throws away a response that was already complete.
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

// A fraction is not a status even when it lands inside a band: `200.5` is not a
// success, and saying it is lets a number arrived at by arithmetic or read from
// configuration pass here and be refused later by the socket, with the handler
// already run.
//
// Being OUTSIDE 100-599 is answered rather than refused, because callers reach
// these with a status they did not choose. `b.webhook` reports on a delivery
// whose transport failed with `statusCode` defaulted to 0 and asks whether that
// was a success; the truthful answer is no, and throwing there would turn a
// failed delivery into a crash.
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

  // Carries no body, whatever the handler writes: every 1xx, and 204, 205 and
  // 304. RFC 9110 §15.3.5 / §15.3.6 / §15.4.5. A response to HEAD is bodiless
  // too, but that is a property of the request rather than the status, so the
  // caller answers for it.
  bodiless: function (n) {
    _validateStatus("bodiless", n);
    return (n >= 100 && n < 200) || n === STATUS.NO_CONTENT ||
           n === STATUS.RESET_CONTENT || n === STATUS.NOT_MODIFIED;
  },
});

// ---- Crypto envelope versioning ----
// Every encrypted blob starts with a 4-byte header that identifies the
// algorithms used. This enables algorithm agility — any component can
// be swapped without re-encrypting existing data. Old envelopes always
// remain readable; new writes use ACTIVE.{KEM, CIPHER, KDF}.
//
// See roadmap "Modernity posture: highest practical bar, forward only"
// for the algorithm rotation policy.

// Envelope wire format. Pre-v1 increment of magic byte to 0xE2 (was
// 0xE1) signals FixedInfo-bound KDF: SHAKE256 absorbs the suite-id
// triple (kemId / cipherId / kdfId) plus the literal "blamejs/v1"
// label alongside the shared secret(s). Per NIST SP 800-56C r2 §4.1
// OtherInfo + RFC 9180 (HPKE) §5.1 suite-binding requirement. 0xE1
// envelopes are no longer accepted; framework data sealed pre-bump
// must be regenerated.
var ENVELOPE_MAGIC = 0xE2;
var ENVELOPE_FIXED_INFO_LABEL = "blamejs/v1";

var KEM_IDS = Object.freeze({
  ML_KEM_1024:        0x02,
  ML_KEM_1024_P384:   0x03,
  // 0x04 — ML-KEM-768 + X25519 hybrid. The IETF / Cloudflare / Chrome
  // standardized hybrid for TLS 1.3 (codepoint 0x11EC, draft-kwiatkowski-
  // tls-ecdhe-mlkem). Smaller payload than ML-KEM-1024+P384 (~1.1 KB
  // vs ~1.6 KB), wider interop with non-blamejs peers using the same
  // hybrid. ACTIVE.KEM stays on ML_KEM_1024_P384 — operators opt in to
  // the smaller hybrid via b.crypto.encrypt(..., { algorithm: "ml-kem-
  // 768-x25519" }) when targeting a peer that needs it.
  ML_KEM_768_X25519:  0x04,
});

var CIPHER_IDS = Object.freeze({
  XCHACHA20_POLY1305: 0x02,
});

var KDF_IDS = Object.freeze({
  SHAKE256:           0x02,
});

// ---- Credential hash envelope (separate from data envelope) ----
// Used for storing verifiable digests of credentials (API key secrets,
// shared bearer tokens, etc.) where the framework needs forward-
// compatible algorithm rotation. The credential envelope format is:
//
//   byte 0: 0xC1 (CREDENTIAL_MAGIC — distinct from 0xE1 storage envelope)
//   byte 1: <CRED_HASH_IDS algorithm ID>
//   bytes 2..N: algorithm-specific payload
//
// Encoded base64 (URL-safe) so the column type stays TEXT. The verify
// path dispatches on byte 1, so historical credentials always remain
// verifiable regardless of what ACTIVE.CRED_HASH points at today.
//
// Why a separate magic byte from 0xE1: storage-envelope blobs and
// credential-envelope strings live in different columns and have
// different lifetimes; making the magic byte distinct prevents a
// confused-deputy mix-up where a corrupted credential field decodes
// as a storage envelope.

var CREDENTIAL_MAGIC = 0xC1;

var CRED_HASH_IDS = Object.freeze({
  SHAKE256:   0x01,    // XOF digest of operator-chosen length. Default
                       // 64 bytes; payload length itself drives the
                       // output size on verify, so a future operator
                       // can request 96 bytes without an algorithm
                       // rotation. Suitable for high-entropy secrets
                       // (>= 128 bits random) where memory-hardness
                       // buys nothing. Same family as the framework
                       // KDF, so the verify path uses one primitive.
  ARGON2ID:   0x02,    // PHC string payload. Suitable for low-entropy
                       // or paranoia-mode storage; cost ~250ms per
                       // verify. Defer to b.auth.password's PHC parser.
});

var ACTIVE = Object.freeze({
  KEM:        KEM_IDS.ML_KEM_1024_P384,
  CIPHER:     CIPHER_IDS.XCHACHA20_POLY1305,
  KDF:        KDF_IDS.SHAKE256,
  CRED_HASH:  CRED_HASH_IDS.SHAKE256,
});

// ---- Storage-buffer envelope marker ----
// Used by encryptPacked / decryptPacked for symmetric buffer encryption.
// Single-byte version preceding nonce + ciphertext.
var FORMAT = Object.freeze({
  XCHACHA20_POLY1305: 0x02,
});

// ---- PQC TLS group IDs (IANA TLS Supported Groups Registry) ----
// Every ML-KEM hybrid the framework knows, by IANA codepoint. This table is
// what the inbound PQC gate builds its accept-set from, so it MUST list every
// hybrid TLS_GROUP_PREFERENCE offers outbound: a hybrid present there but
// missing here is advertised to peers while the gate answers a ClientHello
// offering only that group with a fatal handshake_failure — refusing a
// compliant post-quantum client. Kept in codepoint order.
var PQC_GROUPS = Object.freeze({
  SecP256r1MLKEM768:     0x11EB,
  X25519MLKEM768:        0x11EC,
  SecP384r1MLKEM1024:    0x11ED,
});

// Preference list for OUTBOUND TLS (clients only — the server's
// accept-groups are configured separately). Node TLS sends a key share for
// the FIRST entry and picks the first mutually-supported group during the
// handshake. X25519 (classical) is the LAST-RESORT fallback for peers that
// support no ML-KEM hybrid yet — still much of the public TLS surface in
// 2026 (webhooks, OAuth/OIDC, ACME, third-party APIs).
//
// The framework always PREFERS a hybrid on every handshake; classical
// X25519 is only negotiated when the peer offers none of the hybrids. When
// a connection lands on classical instead, the outbound path emits a
// `tls.classical_downgrade` audit event (lib/pqc-agent.js) so operators can
// see which peers forced a non-PQC negotiation and track their
// dependencies' PQC readiness. Weaker non-hybrid classical groups
// (P-256 / P-384) are deliberately NOT offered — the fallback floor is the
// X25519 group.
//
// Order matters for more than preference. X25519MLKEM768 leads because it
// is the hybrid deployed peers actually implement; listing a
// less-implemented hybrid first costs a HelloRetryRequest — an extra
// round trip on EVERY handshake — and Node delivers an EMPTY stapled OCSP
// response across a retried handshake, which silently breaks
// `b.network.tls.ocsp.requireStapled` against servers that do staple. The
// stronger ML-KEM-1024 hybrid stays in the list, so a peer that supports
// only that group still negotiates it (one retry, in the rare case that
// earns it). This order matches the `b.network.tls.preferredGroups`
// default; the two lists are asserted equal in the test suite so they
// cannot drift apart again.
var TLS_GROUP_PREFERENCE = Object.freeze([
  "X25519MLKEM768",
  "SecP256r1MLKEM768",
  "SecP384r1MLKEM1024",
  "X25519",
]);

var TLS_GROUP_CURVE_STR = TLS_GROUP_PREFERENCE.join(":");

// ---- RFC 8879 certificate compression ----
// Every compression algorithm this runtime can decompress, in the order the
// runtime reports them. Both halves of a TLS connection use the same list:
// as a client it says "send me a compressed Certificate", as a server it
// says "I will compress mine for a client that asked".
//
// It pays more here than on a classical stack. The framework's own leaf
// certificates are ML-DSA-87 — ~4.6 KB of signature before any of the
// public key or chain — so an uncompressed Certificate message dominates
// the handshake, and shrinking it is the single largest handshake-size win
// available.
//
// This is NOT the record-layer compression CRIME attacked. RFC 8879
// compresses only the Certificate message, which is public, fixed, and not
// attacker-influenced: its compressed length reveals nothing about a
// secret, and no attacker-chosen plaintext shares a compression context
// with one.
//
// A function rather than a value so `node:tls` stays out of the boot graph
// of every module that requires constants (a runtime without a TLS module
// can still read C.TIME / C.BYTES). Memoized on first call, frozen so no
// caller can mutate the shared list; empty on a runtime predating the API,
// which callers read as "do not advertise the extension".
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


// ---- Vault sealed-value prefix ----
var VAULT_PREFIX = "vault:";

// ---- Per-row-key sealed-column prefix ----
// Columns encrypted under a row-scoped key (K_row) — distinct from the
// vault-root `vault:` / AAD-bound `vault.aad:` prefixes so the read path
// can route a cell to its decrypt: K_row-sealed cells unwrap the row's
// secret from `_blamejs_per_row_keys`, derive K_row, then decrypt under
// it (XChaCha20-Poly1305, AEAD-bound to (table, rowId, column,
// schemaVersion)). Destroying the row's wrapped secret leaves these
// cells mathematically undecryptable — the crypto-shred substrate.
var ROW_PREFIX = "vault.row:";

// ---- Default hash namespaces for derived-hash indexed lookups ----
// Apps add their own via app-config registries. The 'bj-' namespace
// prevents collision between framework-derived and app-derived hashes.
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
  TLS_GROUP_CURVE_STR:    TLS_GROUP_CURVE_STR,
  TLS_CERT_COMPRESSION:   TLS_CERT_COMPRESSION,
  VAULT_PREFIX:           VAULT_PREFIX,
  ROW_PREFIX:             ROW_PREFIX,
  HASH_PREFIX:            HASH_PREFIX,
};
