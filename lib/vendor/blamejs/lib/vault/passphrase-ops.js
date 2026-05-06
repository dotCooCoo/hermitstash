"use strict";
/**
 * vault-passphrase-ops — seal / unseal / rotate the vault's passphrase wrap.
 *
 * Operator workflows the framework needs to support without forcing
 * everyone through a CLI: turn a plaintext vault.key into a passphrase-
 * wrapped vault.key.sealed (seal), the reverse (unseal), or change the
 * passphrase on an already-sealed file (rotate). Crash-safe: each
 * operation goes through .tmp + fsync + atomic rename so a power-loss
 * mid-operation leaves either the OLD file or the NEW file intact, never
 * a half-written one.
 *
 *   var ops = b.vaultPassphraseOps;
 *
 *   var pre = ops.preflightSealable({ dataDir });
 *   // → { ok: true } or { ok: false, reason: "..." }
 *
 *   await ops.seal({ dataDir, passphrase, keepPlaintext: false });
 *   // → { sealedPath, plaintextDeleted }
 *
 *   await ops.unseal({ dataDir, passphrase });
 *   // → { plaintextPath }
 *
 *   await ops.rotate({ dataDir, oldPassphrase, newPassphrase });
 *   // → { sealedPath }
 *
 * Filenames the framework looks at (relative to dataDir):
 *   vault.key            — plaintext keypair JSON
 *   vault.key.sealed     — passphrase-wrapped keypair (Argon2id +
 *                           XChaCha20-Poly1305, see lib/vault-wrap.js)
 *
 * Round-trip verification: every seal/unseal re-reads the .tmp it just
 * wrote and confirms the bytes match before the atomic rename. If the
 * filesystem reordered or corrupted the write, the operation aborts
 * with the original file untouched.
 */

var fs = require("fs");
var path = require("path");
var atomicFile = require("../atomic-file");
var vaultWrap = require("./wrap");
var { defineClass } = require("../framework-error");

var VaultPassphraseError = defineClass("VaultPassphraseError", { alwaysPermanent: true });

var PLAINTEXT_NAME = "vault.key";
var SEALED_NAME    = "vault.key.sealed";

function _paths(dataDir) {
  return {
    plaintext:     path.join(dataDir, PLAINTEXT_NAME),
    plaintextTmp:  path.join(dataDir, PLAINTEXT_NAME + ".tmp"),
    sealed:        path.join(dataDir, SEALED_NAME),
    sealedTmp:     path.join(dataDir, SEALED_NAME + ".tmp"),
  };
}

function _requireDataDir(opts) {
  if (!opts || typeof opts.dataDir !== "string" || opts.dataDir.length === 0) {
    throw new VaultPassphraseError("vault-passphrase/no-datadir",
      "opts.dataDir is required (path to the framework data directory)");
  }
  if (!fs.existsSync(opts.dataDir)) {
    throw new VaultPassphraseError("vault-passphrase/no-datadir",
      "opts.dataDir does not exist: " + opts.dataDir);
  }
}

function _requirePassphrase(opts, fieldName) {
  var name = fieldName || "passphrase";
  if (!opts || !Buffer.isBuffer(opts[name])) {
    throw new VaultPassphraseError("vault-passphrase/no-passphrase",
      "opts." + name + " is required and must be a Buffer (the operator passphrase bytes)");
  }
}

// fsync-by-path semantic: open then sync then close. atomicFile.fsync
// expects an already-open fd; this wrapper opens the file we just
// wrote, flushes its contents, and closes — the right shape when we
// don't have the original write fd around.
function _fsyncPath(p) {
  try {
    var fd = fs.openSync(p, "r+");
    try { atomicFile.fsync(fd); } finally { fs.closeSync(fd); }
  } catch (_e) { /* best-effort across filesystems */ }
}

// ---- Pre-flight checks (no side effects) ----

function preflightSealable(opts) {
  _requireDataDir(opts);
  var p = _paths(opts.dataDir);
  if (!fs.existsSync(p.plaintext)) {
    return { ok: false, reason: "plaintext " + PLAINTEXT_NAME + " does not exist — nothing to seal" };
  }
  if (fs.existsSync(p.sealed)) {
    return { ok: false, reason: SEALED_NAME + " already exists; refusing to overwrite" };
  }
  if (fs.existsSync(p.sealedTmp)) {
    return { ok: false, reason: "stale " + SEALED_NAME + ".tmp from a previous crash; remove it manually after verifying the directory state" };
  }
  return { ok: true };
}

function preflightUnsealable(opts) {
  _requireDataDir(opts);
  var p = _paths(opts.dataDir);
  if (!fs.existsSync(p.sealed)) {
    return { ok: false, reason: SEALED_NAME + " does not exist — nothing to unseal" };
  }
  if (fs.existsSync(p.plaintext)) {
    return { ok: false, reason: "plaintext " + PLAINTEXT_NAME + " already exists; refusing to overwrite" };
  }
  if (fs.existsSync(p.plaintextTmp)) {
    return { ok: false, reason: "stale " + PLAINTEXT_NAME + ".tmp from a previous crash; remove it manually after verifying the directory state" };
  }
  return { ok: true };
}

function preflightRotatable(opts) {
  _requireDataDir(opts);
  var p = _paths(opts.dataDir);
  if (!fs.existsSync(p.sealed)) {
    return { ok: false, reason: SEALED_NAME + " does not exist — rotate has nothing to operate on" };
  }
  if (fs.existsSync(p.sealedTmp)) {
    return { ok: false, reason: "stale " + SEALED_NAME + ".tmp from a previous crash; remove it manually after verifying the directory state" };
  }
  return { ok: true };
}

// ---- Seal: plaintext vault.key → vault.key.sealed ----

async function seal(opts) {
  _requireDataDir(opts);
  _requirePassphrase(opts, "passphrase");
  var pre = preflightSealable(opts);
  if (!pre.ok) {
    throw new VaultPassphraseError("vault-passphrase/preflight-failed", pre.reason);
  }
  var p = _paths(opts.dataDir);
  var keepPlaintext = !!opts.keepPlaintext;

  var plainBytes = fs.readFileSync(p.plaintext);
  var sealedBytes = await vaultWrap.wrap(plainBytes, opts.passphrase);

  // Step 1: write sealed.tmp + fsync
  fs.writeFileSync(p.sealedTmp, sealedBytes, { mode: 0o600 });
  _fsyncPath(p.sealedTmp);
  atomicFile.fsyncDir(opts.dataDir);

  // Step 2: round-trip verify the .tmp before committing the rename
  var verifyBytes = fs.readFileSync(p.sealedTmp);
  var unwrapped;
  try {
    unwrapped = await vaultWrap.unwrap(verifyBytes, opts.passphrase);
  } catch (e) {
    try { fs.unlinkSync(p.sealedTmp); } catch (_e) { /* cleanup */ }
    throw new VaultPassphraseError("vault-passphrase/verify-failed",
      "round-trip verification of sealed file failed: " + ((e && e.message) || String(e)) +
      " — original " + PLAINTEXT_NAME + " is UNCHANGED");
  }
  if (Buffer.compare(unwrapped, plainBytes) !== 0) {
    try { fs.unlinkSync(p.sealedTmp); } catch (_e) { /* cleanup */ }
    throw new VaultPassphraseError("vault-passphrase/verify-mismatch",
      "round-trip produced different bytes than the original — original " + PLAINTEXT_NAME +
      " is UNCHANGED. Filesystem may be faulty.");
  }

  // Step 3: atomic rename sealed.tmp → sealed
  fs.renameSync(p.sealedTmp, p.sealed);
  atomicFile.fsyncDir(opts.dataDir);

  // Step 4: delete plaintext (unless keepPlaintext)
  if (!keepPlaintext) {
    fs.unlinkSync(p.plaintext);
    atomicFile.fsyncDir(opts.dataDir);
  }

  return {
    sealedPath:       p.sealed,
    plaintextDeleted: !keepPlaintext,
  };
}

// ---- Unseal: vault.key.sealed → plaintext vault.key ----

async function unseal(opts) {
  _requireDataDir(opts);
  _requirePassphrase(opts, "passphrase");
  var pre = preflightUnsealable(opts);
  if (!pre.ok) {
    throw new VaultPassphraseError("vault-passphrase/preflight-failed", pre.reason);
  }
  var p = _paths(opts.dataDir);

  var sealedBytes = fs.readFileSync(p.sealed);
  var plainBytes;
  try {
    plainBytes = await vaultWrap.unwrap(sealedBytes, opts.passphrase);
  } catch (e) {
    throw new VaultPassphraseError("vault-passphrase/passphrase-rejected",
      "passphrase rejected: " + ((e && e.message) || String(e)) +
      " — " + SEALED_NAME + " is UNCHANGED");
  }

  // Step 1: write plaintext.tmp + fsync
  fs.writeFileSync(p.plaintextTmp, plainBytes, { mode: 0o600 });
  _fsyncPath(p.plaintextTmp);
  atomicFile.fsyncDir(opts.dataDir);

  // Step 2: round-trip sanity — re-read tmp and verify
  var verifyBytes = fs.readFileSync(p.plaintextTmp);
  if (Buffer.compare(verifyBytes, plainBytes) !== 0) {
    try { fs.unlinkSync(p.plaintextTmp); } catch (_e) { /* cleanup */ }
    throw new VaultPassphraseError("vault-passphrase/verify-mismatch",
      "plaintext.tmp re-read differs from in-memory bytes — filesystem may be faulty. " +
      SEALED_NAME + " is UNCHANGED");
  }

  // Step 3: atomic rename plaintext.tmp → plaintext
  fs.renameSync(p.plaintextTmp, p.plaintext);
  atomicFile.fsyncDir(opts.dataDir);

  // Step 4: delete sealed file
  fs.unlinkSync(p.sealed);
  atomicFile.fsyncDir(opts.dataDir);

  return { plaintextPath: p.plaintext };
}

// ---- Rotate: change passphrase on an already-sealed file ----
//
// Implemented as unwrap-with-old + wrap-with-new + atomic-rename. The
// underlying vault keypair bytes are unchanged — only the passphrase
// wrapping (Argon2id KDF + XChaCha20-Poly1305 nonce/key) rotates.

async function rotate(opts) {
  _requireDataDir(opts);
  _requirePassphrase(opts, "oldPassphrase");
  _requirePassphrase(opts, "newPassphrase");
  var pre = preflightRotatable(opts);
  if (!pre.ok) {
    throw new VaultPassphraseError("vault-passphrase/preflight-failed", pre.reason);
  }
  var p = _paths(opts.dataDir);

  var sealedBytes = fs.readFileSync(p.sealed);
  var plainBytes;
  try {
    plainBytes = await vaultWrap.unwrap(sealedBytes, opts.oldPassphrase);
  } catch (e) {
    throw new VaultPassphraseError("vault-passphrase/passphrase-rejected",
      "old passphrase rejected: " + ((e && e.message) || String(e)) +
      " — " + SEALED_NAME + " is UNCHANGED");
  }
  var newSealedBytes = await vaultWrap.wrap(plainBytes, opts.newPassphrase);

  // Step 1: write new sealed.tmp + fsync
  fs.writeFileSync(p.sealedTmp, newSealedBytes, { mode: 0o600 });
  _fsyncPath(p.sealedTmp);
  atomicFile.fsyncDir(opts.dataDir);

  // Step 2: round-trip verify with NEW passphrase, AND assert unwrap
  // with the OLD passphrase fails — otherwise the rotation didn't take.
  var verifyBytes = fs.readFileSync(p.sealedTmp);
  var verifyPlain;
  try { verifyPlain = await vaultWrap.unwrap(verifyBytes, opts.newPassphrase); }
  catch (e) {
    try { fs.unlinkSync(p.sealedTmp); } catch (_e) { /* cleanup */ }
    throw new VaultPassphraseError("vault-passphrase/verify-failed",
      "round-trip with new passphrase failed: " + ((e && e.message) || String(e)) +
      " — " + SEALED_NAME + " is UNCHANGED");
  }
  if (Buffer.compare(verifyPlain, plainBytes) !== 0) {
    try { fs.unlinkSync(p.sealedTmp); } catch (_e) { /* cleanup */ }
    throw new VaultPassphraseError("vault-passphrase/verify-mismatch",
      "rotated sealed file decrypts under new passphrase but to different bytes — " +
      SEALED_NAME + " is UNCHANGED. Filesystem may be faulty.");
  }
  // Best-effort regression check: the same bytes must NOT unwrap under
  // the old passphrase. If they do, the wrap library handed back the
  // input unchanged — refuse to commit.
  try {
    await vaultWrap.unwrap(verifyBytes, opts.oldPassphrase);
    try { fs.unlinkSync(p.sealedTmp); } catch (_e) { /* cleanup */ }
    throw new VaultPassphraseError("vault-passphrase/rotate-noop",
      "old passphrase still unwraps the new sealed bytes — rotation did not take effect");
  } catch (e) {
    if (e && e.code === "vault-passphrase/rotate-noop") throw e;
    // any other error means old passphrase fails on new sealed → expected
  }

  // Step 3: atomic rename — swap in the new sealed file
  fs.renameSync(p.sealedTmp, p.sealed);
  atomicFile.fsyncDir(opts.dataDir);

  return { sealedPath: p.sealed };
}

module.exports = {
  preflightSealable:    preflightSealable,
  preflightUnsealable:  preflightUnsealable,
  preflightRotatable:   preflightRotatable,
  seal:                 seal,
  unseal:               unseal,
  rotate:               rotate,
  VaultPassphraseError: VaultPassphraseError,
  PLAINTEXT_NAME:       PLAINTEXT_NAME,
  SEALED_NAME:          SEALED_NAME,
};
