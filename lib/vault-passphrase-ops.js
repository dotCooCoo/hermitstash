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

var nodeFs = require("node:fs");

var C = require("./constants");
var b = require("./vendor/blamejs");

var PLAINTEXT_PATH = C.PATHS.VAULT_KEY;
var SEALED_PATH = C.PATHS.VAULT_KEY_SEALED;
var SEALED_TMP_PATH = C.PATHS.VAULT_KEY_SEALED_TMP;
var PLAINTEXT_TMP_PATH = PLAINTEXT_PATH + ".tmp";
var SETUP_MARKER_PATH = C.PATHS.VAULT_KEY_MIGRATION_PENDING;
var REMOVE_MARKER_PATH = C.PATHS.VAULT_KEY_UNSEAL_PENDING;

// TOCTOU/symlink-safe read of the wrapped-vault-key temp/marker files this
// module writes — shared with vault.js + pem-seal.js via lib/safe-read.
var _safeRead = require("./secret-read").safeReadSecretFile;

// ---- Pre-flight: caller-side validation ----
//
// Returns { ok: true } or { ok: false, reason: string }. Caller decides
// whether to log + exit (CLI) or return 4xx (HTTP). Pure FS inspection,
// no side effects.

function preflightSealable() {
  if (!nodeFs.existsSync(PLAINTEXT_PATH)) {
    return { ok: false, reason: "plaintext vault.key does not exist — nothing to seal" };
  }
  if (nodeFs.existsSync(SEALED_PATH)) {
    return { ok: false, reason: "vault.key.sealed already exists; refusing to overwrite" };
  }
  if (nodeFs.existsSync(SEALED_TMP_PATH)) {
    return { ok: false, reason: "stale vault.key.sealed.tmp from a previous crash; restart the server briefly to let boot recovery clean it, then retry" };
  }
  if (nodeFs.existsSync(SETUP_MARKER_PATH)) {
    return { ok: false, reason: "stale vault.key.migration-pending marker from a previous crash; restart the server briefly for recovery, then retry" };
  }
  return { ok: true };
}

function preflightUnsealable() {
  if (!nodeFs.existsSync(SEALED_PATH)) {
    return { ok: false, reason: "vault.key.sealed does not exist — nothing to unseal" };
  }
  if (nodeFs.existsSync(PLAINTEXT_PATH)) {
    return { ok: false, reason: "plaintext vault.key already exists; refusing to overwrite" };
  }
  if (nodeFs.existsSync(PLAINTEXT_TMP_PATH)) {
    return { ok: false, reason: "stale vault.key.tmp from a previous crash; restart the server briefly for recovery, then retry" };
  }
  if (nodeFs.existsSync(REMOVE_MARKER_PATH)) {
    return { ok: false, reason: "stale vault.key.unseal-pending marker from a previous crash; restart the server briefly for recovery, then retry" };
  }
  return { ok: true };
}

// ---- Seal: plaintext vault.key → vault.key.sealed ----
//
// Throws Error on:
//   - pre-flight failure (caller should run preflightSealable first)
//   - b.vaultWrap.wrap() failure
//   - round-trip verification mismatch
//   - filesystem failure during the .tmp/marker/rename dance
//
// On success: vault.key.sealed exists, vault.key removed (unless opts.keepPlaintext),
// no marker remaining. Returns { sealedPath, plaintextDeleted }.

async function sealVaultKey(passphrase, opts) {
  opts = opts || {};
  var pre = preflightSealable();
  if (!pre.ok) throw new Error(pre.reason);

  var plaintextBytes = _safeRead(PLAINTEXT_PATH);
  var sealedBytes = await b.vaultWrap.wrap(plaintextBytes, passphrase);

  // Step 1: staged exclusive, symlink-refusing tmp create + fsync (no rename
  // yet — we re-read + round-trip-verify the staged bytes before committing).
  // A symlink pre-planted at the tmp path is removed (the LINK, not its target)
  // and the O_EXCL create then fails closed if anything re-appears in the race
  // window (CWE-59 / CWE-377).
  b.atomicFile.writeExclSync(SEALED_TMP_PATH, sealedBytes, { fileMode: 0o600 });
  b.atomicFile.fsyncDir(C.DATA_DIR);

  // Step 2: in-process round-trip verify (re-read the staged tmp safely)
  var verifyBytes = _safeRead(SEALED_TMP_PATH);
  var unwrapped;
  try {
    unwrapped = await b.vaultWrap.unwrap(verifyBytes, passphrase);
  } catch (e) {
    try { nodeFs.unlinkSync(SEALED_TMP_PATH); } catch (_) { /* cleanup */ }
    throw new Error("round-trip verification failed: " + e.message + " — vault.key is UNCHANGED");
  }
  if (Buffer.compare(unwrapped, plaintextBytes) !== 0) {
    try { nodeFs.unlinkSync(SEALED_TMP_PATH); } catch (_) { /* cleanup */ }
    throw new Error("round-trip produced different bytes than the original — vault.key is UNCHANGED. Filesystem may be faulty.");
  }

  // Step 3: write migration marker
  var marker = {
    format: 1,
    hashAlg: "sha3-512",
    startedAt: new Date().toISOString(),
    sealedSha3: b.crypto.sha3Hash(sealedBytes),
    keepPlaintext: !!opts.keepPlaintext,
  };
  // Atomic marker write — temp + fsync + rename + parent-dir fsync built in.
  b.atomicFile.writeSync(SETUP_MARKER_PATH, JSON.stringify(marker), { fileMode: 0o600 });
  b.atomicFile.fsyncDir(C.DATA_DIR);

  // Step 4: commit — atomic rename (Windows-transient-lock retry) + dir fsync
  b.atomicFile.renameWithRetry(SEALED_TMP_PATH, SEALED_PATH);
  b.atomicFile.fsyncDir(C.DATA_DIR);

  // Step 5: delete plaintext (unless keepPlaintext)
  if (!opts.keepPlaintext) {
    nodeFs.unlinkSync(PLAINTEXT_PATH);
    b.atomicFile.fsyncDir(C.DATA_DIR);
  }

  // Step 6: delete migration marker
  nodeFs.unlinkSync(SETUP_MARKER_PATH);
  b.atomicFile.fsyncDir(C.DATA_DIR);

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

  var sealedBytes = _safeRead(SEALED_PATH);
  var plaintextBytes;
  try {
    plaintextBytes = await b.vaultWrap.unwrap(sealedBytes, passphrase);
  } catch (e) {
    throw new Error("passphrase rejected: " + e.message + " — vault.key.sealed is UNCHANGED");
  }

  // Step 1: staged exclusive, symlink-refusing tmp create + fsync (no rename
  // yet — re-read + verify before commit). Same CWE-59 / CWE-377 posture.
  b.atomicFile.writeExclSync(PLAINTEXT_TMP_PATH, plaintextBytes, { fileMode: 0o600 });
  b.atomicFile.fsyncDir(C.DATA_DIR);

  // Step 2: round-trip sanity — re-read tmp safely, verify bytes match
  var verifyBytes = _safeRead(PLAINTEXT_TMP_PATH);
  if (Buffer.compare(verifyBytes, plaintextBytes) !== 0) {
    try { nodeFs.unlinkSync(PLAINTEXT_TMP_PATH); } catch (_) { /* cleanup */ }
    throw new Error("plaintext.tmp re-read differs from in-memory bytes — filesystem may be faulty. vault.key.sealed is UNCHANGED");
  }

  // Step 3: write unseal-pending marker
  var marker = {
    format: 1,
    hashAlg: "sha3-512",
    startedAt: new Date().toISOString(),
    // For the unseal path, sealedSha3 refers to the PLAINTEXT target
    // (vault.js's recoverFromMarker hashes whatever targetFilePath is).
    sealedSha3: b.crypto.sha3Hash(plaintextBytes),
  };
  // Atomic marker write — temp + fsync + rename + parent-dir fsync built in.
  b.atomicFile.writeSync(REMOVE_MARKER_PATH, JSON.stringify(marker), { fileMode: 0o600 });
  b.atomicFile.fsyncDir(C.DATA_DIR);

  // Step 4: commit — atomic rename (Windows-transient-lock retry) + dir fsync
  b.atomicFile.renameWithRetry(PLAINTEXT_TMP_PATH, PLAINTEXT_PATH);
  b.atomicFile.fsyncDir(C.DATA_DIR);

  // Step 5: delete sealed file
  nodeFs.unlinkSync(SEALED_PATH);
  b.atomicFile.fsyncDir(C.DATA_DIR);

  // Step 6: delete marker
  nodeFs.unlinkSync(REMOVE_MARKER_PATH);
  b.atomicFile.fsyncDir(C.DATA_DIR);

  return { plaintextPath: PLAINTEXT_PATH };
}

module.exports = {
  preflightSealable: preflightSealable,
  preflightUnsealable: preflightUnsealable,
  sealVaultKey: sealVaultKey,
  unsealVaultKey: unsealVaultKey,
};
