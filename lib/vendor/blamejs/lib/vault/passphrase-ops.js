// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

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

  atomicFile.writeExclSync(p.sealedTmp, sealedBytes, { fileMode: 0o600 });
  atomicFile.fsyncDir(opts.dataDir);

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

  atomicFile.writeExclSync(p.sealedTmp, newSealedBytes, { fileMode: 0o600 });
  atomicFile.fsyncDir(opts.dataDir);

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
  try {
    await vaultWrap.unwrap(verifyBytes, opts.oldPassphrase);
    try { nodeFs.unlinkSync(p.sealedTmp); } catch (_e) { /* cleanup */ }
    throw new VaultPassphraseError("vault-passphrase/rotate-noop",
      "old passphrase still unwraps the new sealed bytes — rotation did not take effect");
  } catch (e) {
    if (e && e.code === "vault-passphrase/rotate-noop") throw e;
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
