// codebase-patterns:allow-file raw-process-env — constants.js IS the canonical reader of boot-time DATA_DIR / MTLS_CA_* paths
/**
 * Code layer — developer-set values that the admin UI does not touch.
 * Paths, versions, theme, and animation values live here.
 *
 * User-facing text (siteName, dropTitle, etc.) lives in config.js
 * and is changeable via the admin settings UI.
 */

var nodeFs = require("node:fs");
var nodePath = require("node:path");
var b = require("./vendor/blamejs");

// Forwarded from b.constants for external consumers (sync-client tests
// that load HS's lib/constants directly). The source of truth lives in
// blamejs; this re-export preserves the legacy import shape.
var PQC_GROUPS = b.constants.PQC_GROUPS;
var TLS_GROUP_PREFERENCE = b.constants.TLS_GROUP_PREFERENCE;
var TLS_GROUP_CURVE_STR = b.constants.TLS_GROUP_CURVE_STR;

/**
 * Compute a full SHA3-512 content hash for cache-busting.
 * Falls back to a timestamp if the file is missing (dev/build scenarios).
 */
function fileHash(relativePath) {
  try {
    var fullPath = nodePath.join(__dirname, "..", "public", relativePath);
    var content = nodeFs.readFileSync(fullPath);
    return b.crypto.sha3Hash(content);
  } catch (_e) {
    return Date.now().toString(36);
  }
}

var cssHash = fileHash("css/style.css");
var jsHash = fileHash("js/animations.js");
var apiJsHash = fileHash("js/api.js");
var vaultPqHash = fileHash("js/vault-pq.js");
var helpersHash = fileHash("js/helpers.js");
var webauthnHash = fileHash("js/webauthn-helpers.js");

// ---- Crypto prefixes (used by vault, field-crypto, session) ----
var VAULT_PREFIX = "vault:";

// ---- Hash salt prefixes (used by field-crypto, crypto.js) ----
// Used by b.crypto.namespaceHash(prefix, value), which appends the
// `:` separator internally — wire format is `<prefix>:<value>` SHA3-512.
// Don't reintroduce a trailing `:` on these values; namespaceHash adds it.
var HASH_PREFIX = {
  EMAIL: "hs-email",
  SHARE_ID: "hs-share",
  IP: "hs-ip",
  BLOCKED_IP: "hs-blockedip",
  SLUG: "hs-slug",
  ACCESS_CODE: "hs-access-code",
  CERT_FP: "hs-certfp",
  ENROLLMENT: "hs-enroll",
};

// ---- Time helpers ----
// Re-export of blamejs's function-style time helpers — C.TIME.seconds(n),
// minutes(n), hours(n), days(n), weeks(n). Returns integer milliseconds.
// Named-constant aliases (C.TIME.ONE_HOUR etc.) were retired in v1.9.39 —
// every call site now reads the unit at the call site instead of looking
// it up in a named-constant table.
var TIME = b.constants.TIME;

// ---- Byte constants ----
// Re-export of blamejs's IEC-binary byte helpers (bytes, kib, mib, gib).
// Same rationale as TIME — function form names the unit at the call site
// instead of a global constant lookup. The codebase-patterns lint gate
// flags raw numeric literals divisible by 8 that should route through
// these helpers (or be marked as a protocol constant with a per-line
// allow marker).
var BYTES = b.constants.BYTES;

// ---- Encryption format markers ----
var FORMAT = {
  XCHACHA20: 0x02,  // version byte for XChaCha20-Poly1305 (storage/db)
};

// ---- Pagination defaults (admin/user list APIs) ----
// Single source for the page-size policy shared by the admin/user list
// endpoints. DEFAULT_LIMIT is the per-page size when ?limit is absent;
// MAX_LIMIT caps an operator-supplied ?limit; ACTIVITY_FEED is the fixed
// size of the dashboard activity widget (no client override).
var PAGINATION = {
  DEFAULT_LIMIT: 25,
  MAX_LIMIT: 200,
  MIN_LIMIT: 1,
  DEFAULT_PAGE: 1,
  ACTIVITY_FEED: 20,
};

// ---- Vault rotation inventory ----
// Forwarded to b.vaultRotate.{validateSchemaMatch, rotate}. Operator-vetted
// "raw" columns (PKs, FKs, timestamps, hash-only fields, counters, enums)
// — the drift detector excludes these from its sealed-shape scan.
var ROTATION_INFRA_COLUMNS = [
  "_id", "data", "createdAt", "updatedAt", "deletedAt",
  "lastLogin", "lockedUntil", "accessedAt", "lastAttempt", "lastTriggered",
  "expectedFiles", "receivedFiles", "skippedCount", "totalSize", "downloads",
  "failedLoginAttempts", "status", "role", "active",
  "keyHash", "tokenHash", "codeHash", "fingerprintHash", "emailHash",
  "shareIdHash", "bundleShareIdHash", "slugHash",
  "userId", "ownerId", "teamId", "bundleId", "uploadedBy",
  "bundleShareId", "stashId", "boundStashId", "boundBundleId",
  "size", "seq", "vaultEncrypted", "type",
  "expiresAt", "attempts", "statusCode", "webhookId",
  "key", "value",
  "originalKeyId", "reissue",
  "certIssuedAt", "certExpiresAt",
  "revokedAt", "joinedAt",
  "fingerprintBound", "stashBound", "bundleBound",
  "totpAlgorithm", "vaultMode", "totpEnabled", "vaultEnabled", "vaultStealth",
  "totpLastStep",
  "failures",
  "scope",
  "version",
  "argon2Salt",
  "stats",
];

// Files outside the SQLite DB that the rotator must rewrite under the
// new vault key. Each entry maps 1:1 onto a b.vaultRotate.rotate
// `paths.additionalSealed` row (db.key.enc → `paths.dbKeySealed`).
// `required:false` lets a deployment skip files that don't exist
// (e.g. operator never enabled CA_KEY_SEALED).
var ROTATION_SEALED_FILES = [
  { relativePath: "db.key.enc",                 required: true,  description: "SQLite file encryption key" },
  { relativePath: "ca.key.sealed",              required: false, description: "mTLS CA private key (vault-sealed PEM)" },
  { relativePath: "tls/privkey.pem.sealed",     required: false, description: "TLS server private key (vault-sealed PEM)" },
  { relativePath: "api-encrypt-keypair.sealed", required: false, description: "blamejs apiEncrypt server keypair (vault-sealed JSON of 4 PEMs)" },
];

// Non-sealed files copied through to the staging dir verbatim.
var ROTATION_VERBATIM_FILES = [
  { relativePath: "ca.key", required: false },
  { relativePath: "ca.crt", required: false },
];

// Non-sealed directories copied through verbatim. tls/ holds the
// server cert chain (fullchain.pem) and possibly the plaintext privkey
// when TLS_KEY_SEALED is unset.
var ROTATION_VERBATIM_DIRS = [
  { relativePath: "tls", required: false },
];

// mTLS CA cert-stack generation. Bumped atomically with any change to
// b.mtlsEngine.algorithmEnvelope (currently ECDSA P-384 / SHA-384,
// AES-256-CBC PKCS#12 bags, HMAC-SHA-512 outer MAC). Each issued CA
// embeds this in its subject DN as `OU=CAv{N}`; existing CAs at a
// lower generation surface as `isLegacy:true` from b.mtlsCa.status().
var CA_GENERATION = 2;

var DATA_DIR = process.env.HERMITSTASH_DATA_DIR || nodePath.join(__dirname, "..", "data");

// ---- Resolved data paths (single source of truth) ----
// Every module uses these instead of nodePath.join(DATA_DIR, ...) locally.
// Workers receive paths via workerData from the parent process.
var PATHS = {
  DATA_DIR:    DATA_DIR,
  VAULT_KEY:   nodePath.join(DATA_DIR, "vault.key"),
  // Opt-in passphrase-wrapped vault key. When VAULT_PASSPHRASE_MODE=required
  // the server reads this file instead of VAULT_KEY. See docs/THREAT_MODEL.md
  // and lib/vault-wrap.js for the 0xE2-magic wrapped format.
  VAULT_KEY_SEALED:            nodePath.join(DATA_DIR, "vault.key.sealed"),
  VAULT_KEY_SEALED_TMP:        nodePath.join(DATA_DIR, "vault.key.sealed.tmp"),
  // Marker file written during setup/remove tool execution. Enables boot-time
  // recovery if the process crashes between the atomic rename and the
  // plaintext unlink. Deleted once migration completes.
  VAULT_KEY_MIGRATION_PENDING: nodePath.join(DATA_DIR, "vault.key.migration-pending"),
  VAULT_KEY_UNSEAL_PENDING:    nodePath.join(DATA_DIR, "vault.key.unseal-pending"),
  DB_ENC:      nodePath.join(DATA_DIR, "hermitstash.db.enc"),
  DB_KEY_ENC:  nodePath.join(DATA_DIR, "db.key.enc"),
  // One-shot completion marker for the keyed-MAC blind-index backfill
  // (lib/derived-hash-backfill.js). Present once every derived index has been
  // rewritten from the legacy unkeyed digest to the keyed MAC.
  DERIVED_HASH_BACKFILL_MARKER: nodePath.join(DATA_DIR, "derived-hash-keyed.marker"),
  // v1.9.3 full vault key rotation — siblings of DATA_DIR, not children.
  // The rotation tool writes a rotated copy to DATA_ROTATING_DIR, then
  // atomically renames DATA_DIR → DATA_OLD_PREFIX+<ISO timestamp> and
  // DATA_ROTATING_DIR → DATA_DIR. ROTATION_PENDING is a JSON marker that
  // drives boot-time recovery if the tool crashes mid-swap (spec §6.1).
  DATA_ROTATING_DIR:      DATA_DIR + ".rotating",
  DATA_ROTATION_PENDING:  DATA_DIR + ".rotation-pending",
  DATA_OLD_PREFIX:        DATA_DIR + ".old.",
  CA_KEY:      process.env.MTLS_CA_KEY || nodePath.join(DATA_DIR, "ca.key"),
  CA_CERT:     process.env.MTLS_CA_CERT || nodePath.join(DATA_DIR, "ca.crt"),
  // v1.9.4 opt-in vault-sealed CA key. When CA_KEY_SEALED=required the
  // mtls-ca module reads this file instead of CA_KEY. Format: single-line
  // `vault:<base64>` (lib/pem-seal.js).
  CA_KEY_SEALED: (process.env.MTLS_CA_KEY || nodePath.join(DATA_DIR, "ca.key")) + ".sealed",
  TLS_DIR:     nodePath.join(DATA_DIR, "tls"),
  // v1.9.4 opt-in vault-sealed TLS server private key.
  TLS_KEY_SEALED: nodePath.join(DATA_DIR, "tls", "privkey.pem.sealed"),
  // v1.9.15 server-side keypair for blamejs per-session apiEncrypt
  // protocol (ML-KEM-1024 + P-384 ECDH hybrid). PEMs sealed as a
  // single vault: line. See lib/api-encrypt-keypair.js.
  API_ENCRYPT_KEYPAIR_SEALED: nodePath.join(DATA_DIR, "api-encrypt-keypair.sealed"),
  INITIAL_ADMIN_PASSWORD: nodePath.join(DATA_DIR, "initial-admin-password.txt"),
  // Admin-uploaded site logo and per-stash logos. Stored in the writable
  // data directory rather than under public/img/ because in Docker the app
  // source tree is part of the read-only image layer (EACCES on mkdir).
  // Served via explicit GET routes (see server.js), not serveStatic.
  CUSTOM_LOGO_DIR: nodePath.join(DATA_DIR, "custom-logos"),
  STASH_LOGO_DIR:  nodePath.join(DATA_DIR, "stash-logos"),
};

module.exports = {
  DATA_DIR: DATA_DIR,
  PATHS: PATHS,
  version: "1.12.11",
  cssVersion: cssHash,
  jsVersion: jsHash,
  apiJsVersion: apiJsHash,
  vaultPqVersion: vaultPqHash,
  helpersVersion: helpersHash,
  webauthnVersion: webauthnHash,

  // Asset paths — change here to update everywhere
  paths: {
    logo: "/img/logos/white.svg",
    logoDark: "/img/logos/black.svg",
    logoColor: "/img/logos/purple.svg",
    favicon16: "/img/icons/favicon-16x16.png",
    favicon32: "/img/icons/favicon-32x32.png",
    appleTouchIcon: "/img/icons/apple-touch-icon.png",
    icon192: "/img/icons/icon-192.png",
    icon512: "/img/icons/icon-512.png",
    ogImage: "/img/og-image.png",
    manifest: "/manifest.json",
    css: "/css/style.css",
    js: "/js/animations.js",
  },

  // Theme — visual constants not editable by admin
  theme: {
    color: "#8B5CF6",
    bgColor: "#0f0f0f",
  },

  // Crypto / prefixes
  VAULT_PREFIX: VAULT_PREFIX,
  HASH_PREFIX: HASH_PREFIX,
  TIME: TIME,
  BYTES: BYTES,
  FORMAT: FORMAT,
  PAGINATION: PAGINATION,
  ROTATION_INFRA_COLUMNS:  ROTATION_INFRA_COLUMNS,
  ROTATION_SEALED_FILES:   ROTATION_SEALED_FILES,
  ROTATION_VERBATIM_FILES: ROTATION_VERBATIM_FILES,
  ROTATION_VERBATIM_DIRS:  ROTATION_VERBATIM_DIRS,
  CA_GENERATION:           CA_GENERATION,
  PQC_GROUPS:              PQC_GROUPS,
  TLS_GROUP_PREFERENCE:    TLS_GROUP_PREFERENCE,
  TLS_GROUP_CURVE_STR:     TLS_GROUP_CURVE_STR,
  // Animation — timing, easing, thresholds
  animation: {
    scrollThreshold: 0.12,
    scrollMargin: "0px 0px -60px 0px",
    fadeInDuration: "0.8s",
    fadeInEasing: "cubic-bezier(0.34, 1.56, 0.64, 1)",
    staggerDelay: 0.1,
    counterDuration: 1500,
    parallaxSpeed: 0.3,
    rotatePerspective: "1000px",
  },
};
