/**
 * Vault passphrase seal/unseal operations — extracted from
 * scripts/vault-passphrase-{setup,remove}.js so the logic is callable
 * from both the operator CLIs and the v1.9.9 admin UI Action endpoints.
 *
 * Pure with respect to UI: throws on errors, returns success descriptors.
 * Callers handle CLI prints / HTTP responses / audit logs themselves.
 *
 * Crash safety preserved: each operation goes through .tmp + fsync +
 * marker + atomic rename; lib/vault.js boot recovery (recoverFromMarker)
 * cleans up half-completed migrations identically regardless of which
 * caller initiated the operation.
 */
"use strict";

var fs = require("fs");

var C = require("./constants");
var vaultWrap = require("./vault-wrap");
var { sha3Hash } = require("./crypto");

var PLAINTEXT_PATH = C.PATHS.VAULT_KEY;
var SEALED_PATH = C.PATHS.VAULT_KEY_SEALED;
var SEALED_TMP_PATH = C.PATHS.VAULT_KEY_SEALED_TMP;
var PLAINTEXT_TMP_PATH = PLAINTEXT_PATH + ".tmp";
var SETUP_MARKER_PATH = C.PATHS.VAULT_KEY_MIGRATION_PENDING;
var REMOVE_MARKER_PATH = C.PATHS.VAULT_KEY_UNSEAL_PENDING;
var MARKER_TMP_SUFFIX = ".tmp";

// ---- fsync helpers (best-effort cross-platform) ----

function _fsyncPath(p) {
  try {
    var fd = fs.openSync(p, "r+");
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  } catch (_e) { /* Windows rejects fsync on some fd modes; best-effort */ }
}

function _fsyncDataDir() {
  try {
    var fd = fs.openSync(C.DATA_DIR, "r");
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  } catch (_e) { /* dir fsync not portable; best-effort */ }
}

// ---- Pre-flight: caller-side validation ----
//
// Returns { ok: true } or { ok: false, reason: string }. Caller decides
// whether to log + exit (CLI) or return 4xx (HTTP). Pure FS inspection,
// no side effects.

function preflightSealable() {
  if (!fs.existsSync(PLAINTEXT_PATH)) {
    return { ok: false, reason: "plaintext vault.key does not exist — nothing to seal" };
  }
  if (fs.existsSync(SEALED_PATH)) {
    return { ok: false, reason: "vault.key.sealed already exists; refusing to overwrite" };
  }
  if (fs.existsSync(SEALED_TMP_PATH)) {
    return { ok: false, reason: "stale vault.key.sealed.tmp from a previous crash; restart the server briefly to let boot recovery clean it, then retry" };
  }
  if (fs.existsSync(SETUP_MARKER_PATH)) {
    return { ok: false, reason: "stale vault.key.migration-pending marker from a previous crash; restart the server briefly for recovery, then retry" };
  }
  return { ok: true };
}

function preflightUnsealable() {
  if (!fs.existsSync(SEALED_PATH)) {
    return { ok: false, reason: "vault.key.sealed does not exist — nothing to unseal" };
  }
  if (fs.existsSync(PLAINTEXT_PATH)) {
    return { ok: false, reason: "plaintext vault.key already exists; refusing to overwrite" };
  }
  if (fs.existsSync(PLAINTEXT_TMP_PATH)) {
    return { ok: false, reason: "stale vault.key.tmp from a previous crash; restart the server briefly for recovery, then retry" };
  }
  if (fs.existsSync(REMOVE_MARKER_PATH)) {
    return { ok: false, reason: "stale vault.key.unseal-pending marker from a previous crash; restart the server briefly for recovery, then retry" };
  }
  return { ok: true };
}

// ---- Seal: plaintext vault.key → vault.key.sealed ----
//
// Throws Error on:
//   - pre-flight failure (caller should run preflightSealable first)
//   - vaultWrap.wrap() failure
//   - round-trip verification mismatch
//   - filesystem failure during the .tmp/marker/rename dance
//
// On success: vault.key.sealed exists, vault.key removed (unless opts.keepPlaintext),
// no marker remaining. Returns { sealedPath, plaintextDeleted }.

async function sealVaultKey(passphrase, opts) {
  opts = opts || {};
  var pre = preflightSealable();
  if (!pre.ok) throw new Error(pre.reason);

  var plaintextBytes = fs.readFileSync(PLAINTEXT_PATH);
  var sealedBytes = await vaultWrap.wrap(plaintextBytes, passphrase);

  // Step 1: write .tmp + fsync
  fs.writeFileSync(SEALED_TMP_PATH, sealedBytes, { mode: 0o600 });
  _fsyncPath(SEALED_TMP_PATH);
  _fsyncDataDir();

  // Step 2: in-process round-trip verify
  var verifyBytes = fs.readFileSync(SEALED_TMP_PATH);
  var unwrapped;
  try {
    unwrapped = await vaultWrap.unwrap(verifyBytes, passphrase);
  } catch (e) {
    try { fs.unlinkSync(SEALED_TMP_PATH); } catch (_) { /* cleanup */ }
    throw new Error("round-trip verification failed: " + e.message + " — vault.key is UNCHANGED");
  }
  if (Buffer.compare(unwrapped, plaintextBytes) !== 0) {
    try { fs.unlinkSync(SEALED_TMP_PATH); } catch (_) { /* cleanup */ }
    throw new Error("round-trip produced different bytes than the original — vault.key is UNCHANGED. Filesystem may be faulty.");
  }

  // Step 3: write migration marker
  var marker = {
    format: 1,
    hashAlg: "sha3-512",
    startedAt: new Date().toISOString(),
    sealedSha3: sha3Hash(sealedBytes),
    keepPlaintext: !!opts.keepPlaintext,
  };
  var markerTmp = SETUP_MARKER_PATH + MARKER_TMP_SUFFIX;
  fs.writeFileSync(markerTmp, JSON.stringify(marker), { mode: 0o600 });
  _fsyncPath(markerTmp);
  fs.renameSync(markerTmp, SETUP_MARKER_PATH);
  _fsyncDataDir();

  // Step 4: atomic rename sealed file into place
  fs.renameSync(SEALED_TMP_PATH, SEALED_PATH);
  _fsyncDataDir();

  // Step 5: delete plaintext (unless keepPlaintext)
  if (!opts.keepPlaintext) {
    fs.unlinkSync(PLAINTEXT_PATH);
    _fsyncDataDir();
  }

  // Step 6: delete migration marker
  fs.unlinkSync(SETUP_MARKER_PATH);
  _fsyncDataDir();

  return { sealedPath: SEALED_PATH, plaintextDeleted: !opts.keepPlaintext };
}

// ---- Unseal: vault.key.sealed → plaintext vault.key ----
//
// Throws on pre-flight failure, wrong passphrase ("passphrase rejected"),
// or filesystem failure. On success: vault.key exists, vault.key.sealed
// removed, no marker. Returns { plaintextPath }.

async function unsealVaultKey(passphrase) {
  var pre = preflightUnsealable();
  if (!pre.ok) throw new Error(pre.reason);

  var sealedBytes = fs.readFileSync(SEALED_PATH);
  var plaintextBytes;
  try {
    plaintextBytes = await vaultWrap.unwrap(sealedBytes, passphrase);
  } catch (e) {
    throw new Error("passphrase rejected: " + e.message + " — vault.key.sealed is UNCHANGED");
  }

  // Step 1: write plaintext.tmp + fsync
  fs.writeFileSync(PLAINTEXT_TMP_PATH, plaintextBytes, { mode: 0o600 });
  _fsyncPath(PLAINTEXT_TMP_PATH);
  _fsyncDataDir();

  // Step 2: round-trip sanity — re-read tmp, verify bytes match
  var verifyBytes = fs.readFileSync(PLAINTEXT_TMP_PATH);
  if (Buffer.compare(verifyBytes, plaintextBytes) !== 0) {
    try { fs.unlinkSync(PLAINTEXT_TMP_PATH); } catch (_) { /* cleanup */ }
    throw new Error("plaintext.tmp re-read differs from in-memory bytes — filesystem may be faulty. vault.key.sealed is UNCHANGED");
  }

  // Step 3: write unseal-pending marker
  var marker = {
    format: 1,
    hashAlg: "sha3-512",
    startedAt: new Date().toISOString(),
    // For the unseal path, sealedSha3 refers to the PLAINTEXT target
    // (vault.js's recoverFromMarker hashes whatever targetFilePath is).
    sealedSha3: sha3Hash(plaintextBytes),
  };
  var markerTmp = REMOVE_MARKER_PATH + MARKER_TMP_SUFFIX;
  fs.writeFileSync(markerTmp, JSON.stringify(marker), { mode: 0o600 });
  _fsyncPath(markerTmp);
  fs.renameSync(markerTmp, REMOVE_MARKER_PATH);
  _fsyncDataDir();

  // Step 4: atomic rename plaintext into place
  fs.renameSync(PLAINTEXT_TMP_PATH, PLAINTEXT_PATH);
  _fsyncDataDir();

  // Step 5: delete sealed file
  fs.unlinkSync(SEALED_PATH);
  _fsyncDataDir();

  // Step 6: delete marker
  fs.unlinkSync(REMOVE_MARKER_PATH);
  _fsyncDataDir();

  return { plaintextPath: PLAINTEXT_PATH };
}

module.exports = {
  preflightSealable: preflightSealable,
  preflightUnsealable: preflightUnsealable,
  sealVaultKey: sealVaultKey,
  unsealVaultKey: unsealVaultKey,
};
