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

var nodeFs = require("node:fs");
var nodePath = require("node:path");
var atomicFile = require("../atomic-file");
var C = require("../constants");
var frameworkFiles = require("../framework-files");
var vaultWrap = require("./wrap");
var { defineClass } = require("../framework-error");

var VaultPassphraseError = defineClass("VaultPassphraseError", { alwaysPermanent: true });

var PLAINTEXT_NAME = frameworkFiles.fileName("vaultKey");
var SEALED_NAME    = frameworkFiles.fileName("vaultKey") + ".sealed";

function _paths(dataDir) {
  return {
    plaintext:     nodePath.join(dataDir, PLAINTEXT_NAME),
    plaintextTmp:  nodePath.join(dataDir, PLAINTEXT_NAME + ".tmp"),
    sealed:        nodePath.join(dataDir, SEALED_NAME),
    sealedTmp:     nodePath.join(dataDir, SEALED_NAME + ".tmp"),
  };
}

function _requireDataDir(opts) {
  if (!opts || typeof opts.dataDir !== "string" || opts.dataDir.length === 0) {
    throw new VaultPassphraseError("vault-passphrase/no-datadir",
      "opts.dataDir is required (path to the framework data directory)");
  }
  if (!nodeFs.existsSync(opts.dataDir)) {
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

// ---- Pre-flight checks (no side effects) ----

function preflightSealable(opts) {
  _requireDataDir(opts);
  var p = _paths(opts.dataDir);
  if (!nodeFs.existsSync(p.plaintext)) {
    return { ok: false, reason: "plaintext " + PLAINTEXT_NAME + " does not exist — nothing to seal" };
  }
  if (nodeFs.existsSync(p.sealed)) {
    return { ok: false, reason: SEALED_NAME + " already exists; refusing to overwrite" };
  }
  if (nodeFs.existsSync(p.sealedTmp)) {
    return { ok: false, reason: "stale " + SEALED_NAME + ".tmp from a previous crash; remove it manually after verifying the directory state" };
  }
  return { ok: true };
}

function preflightUnsealable(opts) {
  _requireDataDir(opts);
  var p = _paths(opts.dataDir);
  if (!nodeFs.existsSync(p.sealed)) {
    return { ok: false, reason: SEALED_NAME + " does not exist — nothing to unseal" };
  }
  if (nodeFs.existsSync(p.plaintext)) {
    return { ok: false, reason: "plaintext " + PLAINTEXT_NAME + " already exists; refusing to overwrite" };
  }
  if (nodeFs.existsSync(p.plaintextTmp)) {
    return { ok: false, reason: "stale " + PLAINTEXT_NAME + ".tmp from a previous crash; remove it manually after verifying the directory state" };
  }
  return { ok: true };
}

function preflightRotatable(opts) {
  _requireDataDir(opts);
  var p = _paths(opts.dataDir);
  if (!nodeFs.existsSync(p.sealed)) {
    return { ok: false, reason: SEALED_NAME + " does not exist — rotate has nothing to operate on" };
  }
  if (nodeFs.existsSync(p.sealedTmp)) {
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

  var plainBytes = atomicFile.fdSafeReadSync(p.plaintext, { maxBytes: C.BYTES.kib(64) });
  var sealedBytes = await vaultWrap.wrap(plainBytes, opts.passphrase);

  // Step 1: write sealed.tmp (exclusive + no-follow create, fsynced) — a
  // bare writeFileSync to this PREDICTABLE temp name would follow a symlink
  // pre-planted at sealed.tmp (CWE-59); writeExclSync clears any stale entry
  // then creates with O_EXCL | O_NOFOLLOW and fsyncs the bytes.
  atomicFile.writeExclSync(p.sealedTmp, sealedBytes, { fileMode: 0o600 });
  atomicFile.fsyncDir(opts.dataDir);

  // Step 2: round-trip verify the .tmp before committing the rename
  var verifyBytes = atomicFile.fdSafeReadSync(p.sealedTmp, { maxBytes: C.BYTES.kib(64) });
  var unwrapped;
  try {
    unwrapped = await vaultWrap.unwrap(verifyBytes, opts.passphrase);
  } catch (e) {
    try { nodeFs.unlinkSync(p.sealedTmp); } catch (_e) { /* cleanup */ }
    throw new VaultPassphraseError("vault-passphrase/verify-failed",
      "round-trip verification of sealed file failed: " + ((e && e.message) || String(e)) +
      " — original " + PLAINTEXT_NAME + " is UNCHANGED");
  }
  if (Buffer.compare(unwrapped, plainBytes) !== 0) {
    try { nodeFs.unlinkSync(p.sealedTmp); } catch (_e) { /* cleanup */ }
    throw new VaultPassphraseError("vault-passphrase/verify-mismatch",
      "round-trip produced different bytes than the original — original " + PLAINTEXT_NAME +
      " is UNCHANGED. Filesystem may be faulty.");
  }

  // Step 3: atomic rename sealed.tmp → sealed
  atomicFile.renameWithRetry(p.sealedTmp, p.sealed);
  atomicFile.fsyncDir(opts.dataDir);

  // Step 4: delete plaintext (unless keepPlaintext)
  if (!keepPlaintext) {
    nodeFs.unlinkSync(p.plaintext);
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

  var sealedBytes = atomicFile.fdSafeReadSync(p.sealed, { maxBytes: C.BYTES.kib(64) });
  var plainBytes;
  try {
    plainBytes = await vaultWrap.unwrap(sealedBytes, opts.passphrase);
  } catch (e) {
    throw new VaultPassphraseError("vault-passphrase/passphrase-rejected",
      "passphrase rejected: " + ((e && e.message) || String(e)) +
      " — " + SEALED_NAME + " is UNCHANGED");
  }

  // Step 1: write plaintext.tmp (exclusive + no-follow create, fsynced) — a
  // bare writeFileSync to this PREDICTABLE temp name would follow a symlink
  // pre-planted at plaintext.tmp (CWE-59); writeExclSync clears any stale
  // entry then creates with O_EXCL | O_NOFOLLOW and fsyncs the bytes.
  atomicFile.writeExclSync(p.plaintextTmp, plainBytes, { fileMode: 0o600 });
  atomicFile.fsyncDir(opts.dataDir);

  // Step 2: round-trip sanity — re-read tmp and verify
  var verifyBytes = atomicFile.fdSafeReadSync(p.plaintextTmp, { maxBytes: C.BYTES.kib(64) });
  if (Buffer.compare(verifyBytes, plainBytes) !== 0) {
    try { nodeFs.unlinkSync(p.plaintextTmp); } catch (_e) { /* cleanup */ }
    throw new VaultPassphraseError("vault-passphrase/verify-mismatch",
      "plaintext.tmp re-read differs from in-memory bytes — filesystem may be faulty. " +
      SEALED_NAME + " is UNCHANGED");
  }

  // Step 3: atomic rename plaintext.tmp → plaintext
  atomicFile.renameWithRetry(p.plaintextTmp, p.plaintext);
  atomicFile.fsyncDir(opts.dataDir);

  // Step 4: delete sealed file
  nodeFs.unlinkSync(p.sealed);
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

  var sealedBytes = atomicFile.fdSafeReadSync(p.sealed, { maxBytes: C.BYTES.kib(64) });
  var plainBytes;
  try {
    plainBytes = await vaultWrap.unwrap(sealedBytes, opts.oldPassphrase);
  } catch (e) {
    throw new VaultPassphraseError("vault-passphrase/passphrase-rejected",
      "old passphrase rejected: " + ((e && e.message) || String(e)) +
      " — " + SEALED_NAME + " is UNCHANGED");
  }
  var newSealedBytes = await vaultWrap.wrap(plainBytes, opts.newPassphrase);

  // Step 1: write new sealed.tmp (exclusive + no-follow create, fsynced) — a
  // bare writeFileSync to this PREDICTABLE temp name would follow a symlink
  // pre-planted at sealed.tmp (CWE-59); writeExclSync clears any stale entry
  // then creates with O_EXCL | O_NOFOLLOW and fsyncs the bytes.
  atomicFile.writeExclSync(p.sealedTmp, newSealedBytes, { fileMode: 0o600 });
  atomicFile.fsyncDir(opts.dataDir);

  // Step 2: round-trip verify with NEW passphrase, AND assert unwrap
  // with the OLD passphrase fails — otherwise the rotation didn't take.
  var verifyBytes = atomicFile.fdSafeReadSync(p.sealedTmp, { maxBytes: C.BYTES.kib(64) });
  var verifyPlain;
  try { verifyPlain = await vaultWrap.unwrap(verifyBytes, opts.newPassphrase); }
  catch (e) {
    try { nodeFs.unlinkSync(p.sealedTmp); } catch (_e) { /* cleanup */ }
    throw new VaultPassphraseError("vault-passphrase/verify-failed",
      "round-trip with new passphrase failed: " + ((e && e.message) || String(e)) +
      " — " + SEALED_NAME + " is UNCHANGED");
  }
  if (Buffer.compare(verifyPlain, plainBytes) !== 0) {
    try { nodeFs.unlinkSync(p.sealedTmp); } catch (_e) { /* cleanup */ }
    throw new VaultPassphraseError("vault-passphrase/verify-mismatch",
      "rotated sealed file decrypts under new passphrase but to different bytes — " +
      SEALED_NAME + " is UNCHANGED. Filesystem may be faulty.");
  }
  // Best-effort regression check: the same bytes must NOT unwrap under
  // the old passphrase. If they do, the wrap library handed back the
  // input unchanged — refuse to commit.
  try {
    await vaultWrap.unwrap(verifyBytes, opts.oldPassphrase);
    try { nodeFs.unlinkSync(p.sealedTmp); } catch (_e) { /* cleanup */ }
    throw new VaultPassphraseError("vault-passphrase/rotate-noop",
      "old passphrase still unwraps the new sealed bytes — rotation did not take effect");
  } catch (e) {
    if (e && e.code === "vault-passphrase/rotate-noop") throw e;
    // any other error means old passphrase fails on new sealed → expected
  }

  // Step 3: atomic rename — swap in the new sealed file
  atomicFile.renameWithRetry(p.sealedTmp, p.sealed);
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
