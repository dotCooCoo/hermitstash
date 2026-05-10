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
var PQC_GROUPS = Object.freeze({
  X25519MLKEM768:        0x11EC,
  SecP384r1MLKEM1024:    0x11ED,
});

// Highest-first preference list. Node TLS picks the first mutually-
// supported group during the handshake, so SecP384r1MLKEM1024
// (P-384 + ML-KEM-1024) is what we always use when the peer also
// advertises it. X25519MLKEM768 is the only fallback — both are
// PQC hybrids with current standardized parameter sets.
//
// Weaker hybrids (e.g. P-256 + ML-KEM-768) are deliberately excluded
// from the framework's default preference. An operator integrating
// with a peer that only supports a weaker PQC group constructs their
// own https.Agent outside lib/pqc-agent so the downgrade is visible
// in the diff — the framework primitive cannot be coaxed into
// negotiating below this list.
var TLS_GROUP_PREFERENCE = Object.freeze([
  "SecP384r1MLKEM1024",
  "X25519MLKEM768",
  "SecP256r1MLKEM768",
]);

var TLS_GROUP_CURVE_STR = TLS_GROUP_PREFERENCE.join(":");

// ---- Vault sealed-value prefix ----
var VAULT_PREFIX = "vault:";

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
  VAULT_PREFIX:           VAULT_PREFIX,
  HASH_PREFIX:            HASH_PREFIX,
};
