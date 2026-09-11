// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeFs = require("node:fs");
var nodePath = require("node:path");
var atomicFile = require("../atomic-file");
var safePath = require("../safe-path");
var bCrypto = require("./crypto");
var backupManifest = require("./manifest");
var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");

var BackupBundleError = defineClass("BackupBundleError", { alwaysPermanent: true });

function _emit(cb, ev) {
  if (typeof cb === "function") {
    try { cb(ev); } catch (_e) { /* progress-callback errors are non-fatal */ }
  }
}

function _encryptedPathFor(relativePath) {
  var posix = relativePath.split(nodePath.sep).join("/");
  return "files/" + posix + ".enc";
}

async function create(opts) {
  var t0 = Date.now();
  opts = opts || {};
  if (typeof opts.dataDir !== "string" || !nodeFs.existsSync(opts.dataDir)) {
    throw new BackupBundleError("backup-bundle/no-datadir",
      "create: opts.dataDir is required and must exist");
  }
  validateOpts.requireNonEmptyString(opts.outDir, "create: opts.outDir", BackupBundleError, "backup-bundle/no-outdir");
  if (nodeFs.existsSync(opts.outDir)) {
    throw new BackupBundleError("backup-bundle/outdir-exists",
      "create: outDir already exists: " + opts.outDir +
      " (refusing to overwrite — pick a fresh path)");
  }
  if (!Buffer.isBuffer(opts.passphrase) && typeof opts.passphrase !== "string") {
    throw new BackupBundleError("backup-bundle/no-passphrase",
      "create: opts.passphrase is required (Buffer or string)");
  }
  if (typeof opts.vaultKeyJson !== "string" || opts.vaultKeyJson.length === 0) {
    throw new BackupBundleError("backup-bundle/no-vault-key-json",
      "create: opts.vaultKeyJson is required (the in-memory vault keypair JSON; " +
      "use vault.getKeysJson() or read vault.key from disk)");
  }
  if (!Array.isArray(opts.files) || opts.files.length === 0) {
    throw new BackupBundleError("backup-bundle/no-files",
      "create: opts.files must be a non-empty array of include entries");
  }
  var passphrase = opts.passphrase;
  var dataDir = opts.dataDir;
  var outDir = opts.outDir;
  var progress = opts.progressCallback;

  atomicFile.ensureDir(outDir);
  atomicFile.ensureDir(nodePath.join(outDir, "files"));

  _emit(progress, { phase: "wrap_vault_key" });
  var wrappedVk = await bCrypto.encryptWithFreshSalt(opts.vaultKeyJson, passphrase);

  var fileEntries = [];
  var totalBytes = 0;

  for (var i = 0; i < opts.files.length; i++) {
    var entry = opts.files[i];
    if (!entry || typeof entry.relativePath !== "string" || entry.relativePath.length === 0) {
      throw new BackupBundleError("backup-bundle/bad-include",
        "create: files[" + i + "] requires { relativePath: string }");
    }
    if (entry.relativePath.indexOf("..") !== -1 || /^[/\\]/.test(entry.relativePath) ||
        entry.relativePath.indexOf(":") !== -1) {
      throw new BackupBundleError("backup-bundle/bad-include",
        "create: files[" + i + "].relativePath must be a relative path without '..', a leading separator, or a colon (got '" + entry.relativePath + "')");
    }
    var srcPath = safePath.resolve(dataDir, entry.relativePath);
    if (!nodeFs.existsSync(srcPath)) {
      if (entry.required) {
        throw new BackupBundleError("backup-bundle/missing-required",
          "create: required file missing: " + entry.relativePath);
      }
      _emit(progress, { phase: "skip_missing", relativePath: entry.relativePath });
      continue;
    }
    var stat = nodeFs.statSync(srcPath);
    if (!stat.isFile()) {
      throw new BackupBundleError("backup-bundle/not-a-file",
        "create: '" + entry.relativePath + "' is not a regular file");
    }

    _emit(progress, { phase: "read", relativePath: entry.relativePath, size: stat.size });
    var plain = atomicFile.fdSafeReadSync(srcPath, {
      errorFor: function (kind, detail) {
        if (kind === "short-read") {
          return new BackupBundleError("backup-bundle/short-read",
            "create: short read on '" + entry.relativePath + "': " + detail.read + " of " + detail.size + " bytes");
        }
        return undefined;
      },
    });
    var checksum = bCrypto.checksum(plain);
    var encResult = await bCrypto.encryptWithFreshSalt(plain, passphrase, entry.relativePath);
    var encPath = _encryptedPathFor(entry.relativePath);
    var destFull = nodePath.join(outDir, encPath);
    atomicFile.ensureDir(nodePath.dirname(destFull));
    atomicFile.writeSync(destFull, encResult.encrypted, { fileMode: 0o600 });

    var kind = entry.kind || "raw";
    if (!Object.prototype.hasOwnProperty.call(backupManifest.VALID_KINDS, kind)) {
      throw new BackupBundleError("backup-bundle/bad-kind",
        "create: files[" + i + "].kind must be one of raw, vault-sealed, plaintext (got '" + kind + "')");
    }

    fileEntries.push({
      relativePath:  entry.relativePath,
      encryptedPath: encPath,
      size:          plain.length,
      encryptedSize: encResult.encrypted.length,
      checksum:      checksum,
      salt:          encResult.salt,
      kind:          kind,
    });
    totalBytes += encResult.encrypted.length;
    _emit(progress, {
      phase: "encrypted",
      relativePath: entry.relativePath,
      encryptedSize: encResult.encrypted.length,
    });
  }

  if (fileEntries.length === 0) {
    throw new BackupBundleError("backup-bundle/empty",
      "create: no files included in bundle (every entry was missing or skipped)");
  }

  _emit(progress, { phase: "write_manifest" });
  var manifest = backupManifest.create({
    vaultKeySalt: wrappedVk.salt,
    vaultKeyEnc:  wrappedVk.encrypted.toString("base64"),
    files:        fileEntries,
    metadata:     opts.metadata || undefined,
    aadBound:     true,
  });
  var shouldSign = opts.sign !== false;
  if (shouldSign) {
    try { backupManifest.sign(manifest); }
    catch (e) {
      var msg = (e && e.message) || String(e);
      if (msg.indexOf("auditSign.init() must be awaited") !== -1) {
        _emit(progress, { phase: "manifest-unsigned", reason: "audit-sign-not-initialized" });
      } else if (opts.signOptional === true) {
        _emit(progress, { phase: "manifest-unsigned", reason: msg });
      } else {
        throw new BackupBundleError("backup-bundle/sign-failed",
          "create: manifest sign failed: " + msg);
      }
    }
  }
  var manifestPath = nodePath.join(outDir, "manifest.json");
  atomicFile.writeSync(manifestPath, backupManifest.serialize(manifest), { fileMode: 0o600 });

  var durationMs = Date.now() - t0;
  _emit(progress, {
    phase: "done",
    fileCount: fileEntries.length,
    bundleSize: totalBytes,
    durationMs: durationMs,
  });
  return {
    manifest:     manifest,
    manifestPath: manifestPath,
    outDir:       outDir,
    bundleSize:   totalBytes,
    fileCount:    fileEntries.length,
    durationMs:   durationMs,
  };
}

module.exports = {
  create:             create,
  BackupBundleError:  BackupBundleError,
};
