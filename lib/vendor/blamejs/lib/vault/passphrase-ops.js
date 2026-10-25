// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.vaultPassphraseOps
 * @nav    Crypto
 * @title  Vault Passphrase Ops
 * @slug   vault-passphrase-ops
 *
 * @intro
 *   Moving the vault key between its plaintext and sealed forms, and changing
 *   the passphrase that seals it. These are the operations where a crash at
 *   the wrong moment could leave a deployment with no readable key, so each
 *   one writes to a temporary file, verifies by unsealing what it just wrote,
 *   and only then replaces the live file.
 *
 *   Nothing overwrites. Sealing refuses when a sealed file already exists,
 *   unsealing refuses when a plaintext key is already there, and both refuse
 *   when a temporary file from an earlier crash is still present, because that
 *   file is evidence the directory needs looking at before another write.
 *
 *   Each operation has a preflight that answers the same question without
 *   doing anything, so an operator or a CLI can report what would happen
 *   before asking for it. The failure reason is the same text either way.
 *
 * @card
 *   Seal, unseal and re-passphrase the vault key through a verified temporary
 *   file, refusing to overwrite an existing key or to run past a crash's
 *   leftovers.
 */

var nodeFs = require("node:fs");
var nodePath = require("node:path");
var argon2 = require("../argon2-builtin");
var atomicFile = require("../atomic-file");
var C = require("../constants");
var frameworkFiles = require("../framework-files");
var validateOpts = require("../validate-opts");
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

/**
 * @primitive b.vaultPassphraseOps.preflightSealable
 * @signature b.vaultPassphraseOps.preflightSealable(opts)
 * @since     0.1.96
 * @status    stable
 * @related   b.vaultPassphraseOps.seal, b.vaultPassphraseOps.preflightUnsealable
 *
 * Answer `{ ok, reason }` for whether sealing would proceed, without writing
 * anything.
 *
 * It is not ok when there is no plaintext key to seal, when a sealed file
 * already exists, or when a `.tmp` file from an earlier crash is still there.
 * `seal` runs this and raises `vault-passphrase/preflight-failed` with the same
 * reason, so a CLI can report the refusal before asking an operator for a
 * passphrase.
 *
 * A missing `dataDir`, or one that does not exist, raises
 * `vault-passphrase/no-datadir`: that is a question about the call rather than
 * about the directory's state, so it raises instead of answering `ok: false`.
 *
 * @opts
 *   dataDir: string,   // required; the framework data directory
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.vaultPassphraseOps.preflightSealable({ dataDir: "./data" });
 *   // → { ok: true } or { ok: false, reason: "…" }
 */
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

/**
 * @primitive b.vaultPassphraseOps.preflightUnsealable
 * @signature b.vaultPassphraseOps.preflightUnsealable(opts)
 * @since     0.1.96
 * @status    stable
 * @related   b.vaultPassphraseOps.unseal, b.vaultPassphraseOps.preflightSealable
 *
 * Answer `{ ok, reason }` for whether unsealing would proceed, without writing
 * anything.
 *
 * It is not ok when there is no sealed file, when a plaintext key is already
 * present, or when a `.tmp` file from an earlier crash is still there.
 * Refusing while a plaintext key exists is the important one: unsealing over
 * it would replace a key that may be the only copy of what the data was
 * encrypted under.
 *
 * @opts
 *   dataDir: string,   // required; the framework data directory
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.vaultPassphraseOps.preflightUnsealable({ dataDir: "./data" });
 */
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

/**
 * @primitive b.vaultPassphraseOps.preflightRotatable
 * @signature b.vaultPassphraseOps.preflightRotatable(opts)
 * @since     0.1.96
 * @status    stable
 * @related   b.vaultPassphraseOps.rotate
 *
 * Answer `{ ok, reason }` for whether a passphrase rotation would proceed,
 * without writing anything.
 *
 * It is not ok when there is no sealed file, since a rotation has nothing to
 * re-seal, or when a `.tmp` file from an earlier crash is still present. There
 * is no plaintext check here: a rotation reads the sealed file and writes the
 * sealed file, so a plaintext key beside it is not in the way.
 *
 * @opts
 *   dataDir: string,   // required; the framework data directory
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.vaultPassphraseOps.preflightRotatable({ dataDir: "./data" });
 */
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

/**
 * @primitive b.vaultPassphraseOps.seal
 * @signature b.vaultPassphraseOps.seal(opts)
 * @since     0.1.96
 * @status    stable
 * @related   b.vaultPassphraseOps.unseal, b.vaultWrap.wrap, b.vault.init
 *
 * Seal the plaintext vault key under a passphrase, so the deployment moves
 * from a key readable on disk to one that needs the passphrase to open.
 *
 * `passphrase` has to be a Buffer rather than a string, because a Buffer can
 * be zeroed once the derivation is done. A string cannot, so it is refused
 * with `vault-passphrase/no-passphrase`.
 *
 * A missing `dataDir`, or one that does not exist, raises
 * `vault-passphrase/no-datadir`, and a state the preflight refuses raises
 * `vault-passphrase/preflight-failed` carrying its reason.
 *
 * The sealed file is written to a temporary name, unsealed again and compared
 * byte for byte with the original, and only then put in place. A round-trip
 * that cannot be unsealed at all raises `vault-passphrase/verify-failed`, and
 * one that unseals to different bytes raises
 * `vault-passphrase/verify-mismatch`. Either way the temporary file is removed
 * and the plaintext key is left exactly as it was, which both messages state.
 *
 * It resolves with `{ sealedPath, plaintextDeleted }`. The plaintext key is
 * removed once the sealed file is in place, which is the point of sealing;
 * `keepPlaintext: true` leaves it on disk and reports `plaintextDeleted:
 * false`. That is for a migration that needs both forms briefly, and it means
 * the key is still readable to anything that can read the directory, so the
 * plaintext copy wants removing once the sealed one is proven.
 *
 * `keepPlaintext` must be a boolean, raising `vault-passphrase/bad-opt`
 * otherwise. Anything truthy was read as true, so a configuration file
 * deserialized into the string `"false"` left the plaintext key on disk while
 * the call reported it deleted.
 *
 * @opts
 *   dataDir:       string,   // required; the framework data directory
 *   passphrase:    string,   // required; a Buffer of passphrase bytes
 *   keepPlaintext: boolean,  // true leaves the plaintext key on disk
 *
 * @example
 *   // requires: a passphrase source, and ./data holding a plaintext vault key
 *   var b = require("@blamejs/core");
 *   var pass = await b.vaultPassphraseSource.getPassphrase();
 *   try { await b.vaultPassphraseOps.seal({ dataDir: "./data", passphrase: pass }); }
 *   finally { pass.fill(0); }
 */
async function seal(opts) {
  _requireDataDir(opts);
  _requirePassphrase(opts, "passphrase");
  var pre = preflightSealable(opts);
  if (!pre.ok) {
    throw new VaultPassphraseError("vault-passphrase/preflight-failed", pre.reason);
  }
  var p = _paths(opts.dataDir);
  validateOpts.optionalBoolean(opts.keepPlaintext,
    "seal: opts.keepPlaintext (anything truthy was read as true, so a string " +
    "\"false\" left the plaintext key on disk while the call reported it deleted)",
    VaultPassphraseError, "vault-passphrase/bad-opt");
  var keepPlaintext = opts.keepPlaintext === true;

  var plainBytes = atomicFile.fdSafeReadSync(p.plaintext, { maxBytes: C.BYTES.kib(64) });
  var sealedBytes = await vaultWrap.wrap(plainBytes, opts.passphrase);

  atomicFile.writeExclSync(p.sealedTmp, sealedBytes, { fileMode: 0o600 });
  atomicFile.fsyncDir(opts.dataDir);

  var verifyBytes = atomicFile.fdSafeReadSync(p.sealedTmp, { maxBytes: C.BYTES.kib(64) });
  var unwrapped;
  try {
    unwrapped = await vaultWrap.unwrap(verifyBytes, opts.passphrase);
  } catch (e) {
    try { nodeFs.unlinkSync(p.sealedTmp); } catch (_e) { /* cleanup */ }
    if (argon2.isArgon2Error(e)) throw e;
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

  atomicFile.renameWithRetry(p.sealedTmp, p.sealed);
  atomicFile.fsyncDir(opts.dataDir);

  if (!keepPlaintext) {
    nodeFs.unlinkSync(p.plaintext);
    atomicFile.fsyncDir(opts.dataDir);
  }

  return {
    sealedPath:       p.sealed,
    plaintextDeleted: !keepPlaintext,
  };
}

/**
 * @primitive b.vaultPassphraseOps.unseal
 * @signature b.vaultPassphraseOps.unseal(opts)
 * @since     0.1.96
 * @status    stable
 * @related   b.vaultPassphraseOps.seal, b.vaultWrap.unwrap
 *
 * Write the vault key back out in plaintext, for a deployment moving to a
 * model where the key is protected by the filesystem rather than a passphrase.
 *
 * It refuses when a plaintext key already exists, since overwriting it could
 * destroy the only copy of the key the data was encrypted under. It also
 * refuses while a `.tmp` file from an earlier crash is present.
 *
 * The plaintext is written to a temporary name and verified first, and only
 * then put in place. **The sealed file is deleted once it is.** An
 * interrupted unseal therefore leaves the sealed file intact and the
 * deployment booting as before, but a completed one does not: the directory
 * now holds a plaintext key and no sealed one.
 *
 * That is a mode change, not just a file change. `b.vault.init` refuses
 * `wrapped` mode when only the plaintext key is present, so the deployment has
 * to boot as `plaintext` afterwards, or be re-sealed with
 * `b.vaultPassphraseOps.seal` before it boots again.
 *
 * It resolves with `{ plaintextPath }`.
 *
 * @opts
 *   dataDir:    string,   // required; the framework data directory
 *   passphrase: string,   // required; a Buffer of passphrase bytes
 *
 * @example
 *   // requires: a passphrase source, and ./data holding a sealed vault key
 *   var b = require("@blamejs/core");
 *   var pass = await b.vaultPassphraseSource.getPassphrase();
 *   try {
 *     await b.vaultPassphraseOps.unseal({ dataDir: "./data", passphrase: pass });
 *   } finally {
 *     pass.fill(0);
 *   }
 *   // ./data now holds the plaintext key and no sealed one: boot as
 *   // mode "plaintext", or re-seal before starting again.
 */
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
    if (argon2.isArgon2Error(e)) throw e;
    if (vaultWrap.isUnreadableFile(e)) {
      throw new VaultPassphraseError("vault-passphrase/sealed-file-unreadable",
        SEALED_NAME + " cannot be read: " + ((e && e.message) || String(e)) +
        " — the passphrase was never tested, and " + SEALED_NAME + " is UNCHANGED");
    }
    throw new VaultPassphraseError("vault-passphrase/passphrase-rejected",
      "passphrase rejected: " + ((e && e.message) || String(e)) +
      " — " + SEALED_NAME + " is UNCHANGED");
  }

  atomicFile.writeExclSync(p.plaintextTmp, plainBytes, { fileMode: 0o600 });
  atomicFile.fsyncDir(opts.dataDir);

  var verifyBytes = atomicFile.fdSafeReadSync(p.plaintextTmp, { maxBytes: C.BYTES.kib(64) });
  if (Buffer.compare(verifyBytes, plainBytes) !== 0) {
    try { nodeFs.unlinkSync(p.plaintextTmp); } catch (_e) { /* cleanup */ }
    throw new VaultPassphraseError("vault-passphrase/verify-mismatch",
      "plaintext.tmp re-read differs from in-memory bytes — filesystem may be faulty. " +
      SEALED_NAME + " is UNCHANGED");
  }

  atomicFile.renameWithRetry(p.plaintextTmp, p.plaintext);
  atomicFile.fsyncDir(opts.dataDir);

  nodeFs.unlinkSync(p.sealed);
  atomicFile.fsyncDir(opts.dataDir);

  return { plaintextPath: p.plaintext };
}

/**
 * @primitive b.vaultPassphraseOps.rotate
 * @signature b.vaultPassphraseOps.rotate(opts)
 * @since     0.1.96
 * @status    stable
 * @related   b.vaultPassphraseOps.seal, b.vaultRotate.rotate
 *
 * Change the passphrase a sealed vault key is sealed under. The keypair itself
 * does not change, so nothing encrypted under it needs re-encrypting: this is
 * the operation for a passphrase that leaked or for an operator leaving, not
 * for retiring a key.
 *
 * Both `oldPassphrase` and `newPassphrase` are required Buffers. The old one
 * has to open the existing file, so a rotation cannot be used to replace a
 * sealed key the caller cannot already read.
 *
 * The re-sealed file is written to a temporary name, unsealed under the new
 * passphrase and compared with the original bytes before replacing anything.
 * A failure leaves the existing sealed file untouched, which the error message
 * states, because the operator's next question is whether the vault still
 * opens with the old passphrase.
 *
 * Retiring the keypair rather than the passphrase is `b.vaultRotate.rotate`.
 *
 * @opts
 *   dataDir:       string,   // required; the framework data directory
 *   oldPassphrase: string,   // required; a Buffer that opens the current file
 *   newPassphrase: string,   // required; a Buffer to re-seal under
 *
 * @example
 *   // requires: OLD_PASSPHRASE and NEW_PASSPHRASE set, and ./data holding a
 *   // sealed vault key the old one opens
 *   var b = require("@blamejs/core");
 *   await b.vaultPassphraseOps.rotate({
 *     dataDir:       "./data",
 *     oldPassphrase: Buffer.from(process.env.OLD_PASSPHRASE),
 *     newPassphrase: Buffer.from(process.env.NEW_PASSPHRASE),
 *   });
 */
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
    if (argon2.isArgon2Error(e)) throw e;
    if (vaultWrap.isUnreadableFile(e)) {
      throw new VaultPassphraseError("vault-passphrase/sealed-file-unreadable",
        SEALED_NAME + " cannot be read: " + ((e && e.message) || String(e)) +
        " — the old passphrase was never tested, and " + SEALED_NAME + " is UNCHANGED");
    }
    throw new VaultPassphraseError("vault-passphrase/passphrase-rejected",
      "old passphrase rejected: " + ((e && e.message) || String(e)) +
      " — " + SEALED_NAME + " is UNCHANGED");
  }
  var newSealedBytes = await vaultWrap.wrap(plainBytes, opts.newPassphrase);

  atomicFile.writeExclSync(p.sealedTmp, newSealedBytes, { fileMode: 0o600 });
  atomicFile.fsyncDir(opts.dataDir);

  var verifyBytes = atomicFile.fdSafeReadSync(p.sealedTmp, { maxBytes: C.BYTES.kib(64) });
  var verifyPlain;
  try { verifyPlain = await vaultWrap.unwrap(verifyBytes, opts.newPassphrase); }
  catch (e) {
    try { nodeFs.unlinkSync(p.sealedTmp); } catch (_e) { /* cleanup */ }
    if (argon2.isArgon2Error(e)) throw e;
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
  try {
    await vaultWrap.unwrap(verifyBytes, opts.oldPassphrase);
    try { nodeFs.unlinkSync(p.sealedTmp); } catch (_e) { /* cleanup */ }
    throw new VaultPassphraseError("vault-passphrase/rotate-noop",
      "old passphrase still unwraps the new sealed bytes — rotation did not take effect");
  } catch (e) {
    if (e && e.code === "vault-passphrase/rotate-noop") throw e;
    if (!e || e.code !== "vault-wrap/passphrase-rejected") {
      try { nodeFs.unlinkSync(p.sealedTmp); } catch (_e) { /* cleanup */ }
      throw e;
    }
  }

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
