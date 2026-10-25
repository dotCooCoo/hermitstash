// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.backupBundle
 * @nav    Production
 * @title  Backup Bundle
 * @slug   backup-bundle
 *
 * @intro
 *   Writes one restorable backup: every included file encrypted under a
 *   bundle key, the vault keypair sealed under the operator's passphrase, and
 *   a manifest recording what the bundle holds and the digest of each entry.
 *
 *   The passphrase protects the vault key rather than each file, and the
 *   bundle key encrypts the files, so a restore derives from the passphrase
 *   once and the file count does not multiply the derivations.
 *
 *   The output directory has to be a path that does not exist yet. Writing
 *   over an existing one could mix entries from two backups and produce a
 *   manifest describing neither, so the call refuses instead of merging.
 *
 * @card
 *   Write a restorable backup: files encrypted under a bundle key, the vault
 *   keypair sealed under the operator's passphrase, and a manifest digesting
 *   every entry.
 */

var nodeFs = require("node:fs");
var nodePath = require("node:path");
var atomicFile = require("../atomic-file");
var safePath = require("../safe-path");
var bCrypto = require("./crypto");
var backupManifest = require("./manifest");
var safeAsync = require("../safe-async");
var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");

var BackupBundleError = defineClass("BackupBundleError", { alwaysPermanent: true });

function _emit(cb, ev) { safeAsync.safeInvoke(cb, ev); }

function _encryptedPathFor(relativePath) {
  var posix = relativePath.split(nodePath.sep).join("/");
  return "files/" + posix + ".enc";
}

function _claimOutDir(outDir) {
  atomicFile.ensureDir(nodePath.dirname(nodePath.resolve(outDir)));
  try {
    nodeFs.mkdirSync(outDir, { mode: 0o700 });
  } catch (e) {
    if (e && e.code === "EEXIST") {
      throw new BackupBundleError("backup-bundle/outdir-exists",
        "create: opts.outDir already exists: " + outDir +
        " (refusing to overwrite — pick a fresh path)");
    }
    throw e;
  }
}

/**
 * @primitive b.backupBundle.create
 * @signature b.backupBundle.create(opts)
 * @since     0.1.96
 * @status    stable
 * @related   b.backupManifest.create, b.restoreBundle.extract, b.backupCrypto.deriveKey
 *
 * Write a bundle and resolve with `{ manifest, manifestPath, outDir,
 * bundleSize, fileCount, durationMs }`.
 *
 * `dataDir` has to exist and `outDir` has to not: an existing `outDir` raises
 * `backup-bundle/outdir-exists` rather than being written into. `passphrase`
 * seals the vault keypair supplied as `vaultKeyJson`, which is the in-memory
 * keypair from `b.vault.getKeysJson()`. `files` lists what to include and must
 * not be empty.
 *
 * Each missing requirement has its own code, so a failed call says which one:
 * `backup-bundle/no-datadir`, `backup-bundle/no-outdir`,
 * `backup-bundle/no-passphrase`, `backup-bundle/no-vault-key-json` and
 * `backup-bundle/no-files`.
 *
 * An include entry is refused with `backup-bundle/bad-include` when it carries
 * no `relativePath`, `backup-bundle/bad-kind` for a `kind` outside the set the
 * manifest accepts, `backup-bundle/missing-required` when an entry marked
 * required is not on disk, `backup-bundle/not-a-file` when its path is a
 * directory, `backup-bundle/empty` when the include list resolves to nothing
 * to write, and `backup-bundle/short-read` when a file returns fewer bytes
 * than its size said, which would otherwise put a truncated entry in the
 * bundle under a correct digest. A signing failure the `signOptional` escape
 * does not cover raises `backup-bundle/sign-failed`.
 *
 * The manifest is signed unless `sign` is `false`. It is a toggle rather than
 * a key: the signature comes from the deployment's audit-signing key, so
 * `b.auditSign.init` has to have run for a bundle to be signed. When it has
 * not, the bundle is written unsigned and the progress callback reports a
 * `manifest-unsigned` phase with `audit-sign-not-initialized`, so an operator
 * can see that the bundle cannot later be proven to be theirs. Any other
 * signing failure raises `backup-bundle/sign-failed` unless `signOptional` is
 * true, which records the reason and keeps the backup.
 *
 * `sign` and `signOptional` must be booleans, raising `backup-bundle/bad-opt`
 * otherwise. A `"false"` for `sign` read as "not false" and signed anyway,
 * while one for `signOptional` read as "not true" and refused the bundle,
 * so a typo in either moved the outcome without saying so.
 *
 * `progressCallback` receives a phase per step and a `done` event carrying the
 * file count, bundle size and duration.
 *
 * @opts
 *   dataDir:          string,   // required; must exist
 *   outDir:           string,   // required; must not exist
 *   passphrase:       string,   // required; Buffer or string
 *   vaultKeyJson:     string,   // required; the in-memory vault keypair JSON
 *   files:            array,    // required; non-empty include entries
 *   metadata:         object,   // carried into the manifest
 *   sign:             boolean,  // false writes the manifest unsigned
 *   signOptional:     boolean,  // true continues when signing is unavailable
 *   progressCallback: object,   // function (event) per phase
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var res = await b.backupBundle.create({
 *     dataDir:      "./data",
 *     outDir:       "./backups/2026-10-06",
 *     passphrase:   process.env.BACKUP_PASSPHRASE,
 *     vaultKeyJson: b.vault.getKeysJson(),
 *     files:        [{ relativePath: "app.db" }],
 *   });
 *   res.fileCount;                 // → 1
 *   res.manifestPath;              // → the manifest a restore reads first
 */
async function create(opts) {
  var t0 = Date.now();
  opts = opts || {};
  if (typeof opts.dataDir !== "string" || !nodeFs.existsSync(opts.dataDir)) {
    throw new BackupBundleError("backup-bundle/no-datadir",
      "create: opts.dataDir is required and must exist");
  }
  validateOpts.optionalBoolean(opts.sign,
    "create: opts.sign", BackupBundleError, "backup-bundle/bad-opt");
  validateOpts.optionalBoolean(opts.signOptional,
    "create: opts.signOptional (anything other than a boolean was read as " +
    "false, so a bundle meant to continue unsigned refused instead)",
    BackupBundleError, "backup-bundle/bad-opt");
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
  var outDir = opts.outDir;
  var progress = opts.progressCallback;

  _emit(progress, { phase: "wrap_vault_key" });
  var bundleSalt = bCrypto.newSalt();
  var bundleKey = await bCrypto.deriveKey(passphrase, bundleSalt);

  try {
    _claimOutDir(outDir);
    atomicFile.ensureDir(nodePath.join(outDir, "files"));
    return await _createWithBundleKey(opts, bundleKey, bundleSalt, t0);
  } finally {
    bundleKey.fill(0);
  }
}

function _shortReadErrorFor(relativePath) {
  return function (kind, detail) {
    if (kind === "short-read") {
      return new BackupBundleError("backup-bundle/short-read",
        "create: short read on '" + relativePath + "': " + detail.read + " of " + detail.size + " bytes");
    }
    return undefined;
  };
}

async function _createWithBundleKey(opts, bundleKey, bundleSalt, t0) {
  var dataDir = opts.dataDir;
  var outDir = opts.outDir;
  var progress = opts.progressCallback;
  var vaultKeySalt = bCrypto.newSalt();
  var vaultKeyEnc = bCrypto.encryptUnderSubkey(opts.vaultKeyJson, bundleKey, vaultKeySalt,
    bCrypto.VAULT_KEY_LABEL, bCrypto.VAULT_KEY_LABEL);

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
      errorFor: _shortReadErrorFor(entry.relativePath),
    });
    var checksum = bCrypto.checksum(plain);
    var fileSalt = bCrypto.newSalt();
    var encResult = {
      salt:      fileSalt,
      encrypted: bCrypto.encryptUnderSubkey(plain, bundleKey, fileSalt,
        bCrypto.fileKeyLabel(entry.relativePath), entry.relativePath),
    };
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
    vaultKeySalt: vaultKeySalt,
    vaultKeyEnc:  vaultKeyEnc.toString("base64"),
    files:        fileEntries,
    metadata:     opts.metadata || undefined,
    aadBound:     true,
    keyScheme:    backupManifest.KEY_SCHEME_BUNDLE,
    bundleSalt:   bundleSalt,
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
