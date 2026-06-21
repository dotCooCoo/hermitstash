"use strict";
/**
 * backup-bundle — produce an encrypted backup bundle on disk.
 *
 * Given a dataDir + file include list + passphrase, walks each file,
 * encrypts its bytes via backup-crypto, computes a sha3-512 checksum
 * of the plaintext, and emits a bundle directory:
 *
 *   <outDir>/manifest.json     — backup-manifest schema
 *   <outDir>/files/<path>.enc  — per-file encrypted blob
 *
 * Where <path> mirrors the file's relativePath under dataDir (subdirs
 * preserved). The manifest is the only authoritative description of
 * the bundle's contents — a restorer reads it first, then streams
 * each blob into staging.
 *
 *   await b.backupBundle.create({
 *     dataDir:      "./data",
 *     outDir:       "./backups/2026-04-27.bundle",  // must NOT exist
 *     passphrase:   Buffer.from("operator passphrase"),
 *     vaultKeyJson: "<vault.key contents>",           // string; encrypted into manifest
 *     files: [
 *       { relativePath: "db.enc",         kind: "raw",          required: true },
 *       { relativePath: "db.key.enc",     kind: "raw",          required: true },
 *       { relativePath: "vault.key",      kind: "raw",          required: false },
 *       { relativePath: "ca.key.sealed",  kind: "vault-sealed", required: false },
 *     ],
 *     metadata:     { reason: "scheduled-daily" },
 *     progressCallback: function (event) { ... },
 *   });
 *   // → { manifest, manifestPath, outDir, bundleSize, fileCount, durationMs }
 *
 * vaultKeyJson is encrypted with the operator passphrase + a fresh
 * salt and stored in the manifest's vaultKeyEnc. With only the
 * passphrase, a restorer on a different machine can recover the
 * framework's vault keypair and unseal the bundle's vault-sealed
 * files post-restore. Without the passphrase, the bundle is opaque.
 *
 * Per-file salts: each file gets its own fresh salt. Argon2id is
 * memory-hard but per-file fresh-salt means an attacker who recovers
 * one file's key from the passphrase has no leverage on other files
 * — the salt rotation forces the full Argon2 computation per file.
 *
 * The bundler does NOT compress files. Operators with large datasets
 * who want compression run their backup pipeline through their own
 * compressor (gzip, zstd) downstream of the framework primitive.
 */

var nodeFs = require("node:fs");
var nodePath = require("node:path");
var atomicFile = require("../atomic-file");
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

// Map relativePath → encryptedPath inside the bundle. Mirrors the
// directory structure under files/ and appends .enc so every blob
// has a clear stride and isn't confused with the source file.
function _encryptedPathFor(relativePath) {
  // POSIX-normalize separators in the bundle so manifests written on
  // Windows and Linux look the same on disk.
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

  // 1. Encrypt the vault key JSON
  _emit(progress, { phase: "wrap_vault_key" });
  var wrappedVk = await bCrypto.encryptWithFreshSalt(opts.vaultKeyJson, passphrase);

  // 2. Walk each include entry, encrypt the bytes, emit a blob
  var fileEntries = [];
  var totalBytes = 0;

  for (var i = 0; i < opts.files.length; i++) {
    var entry = opts.files[i];
    if (!entry || typeof entry.relativePath !== "string" || entry.relativePath.length === 0) {
      throw new BackupBundleError("backup-bundle/bad-include",
        "create: files[" + i + "] requires { relativePath: string }");
    }
    if (entry.relativePath.indexOf("..") !== -1 || /^[/\\]/.test(entry.relativePath)) {
      throw new BackupBundleError("backup-bundle/bad-include",
        "create: files[" + i + "].relativePath must be a relative path (got '" + entry.relativePath + "')");
    }
    var srcPath = nodePath.join(dataDir, entry.relativePath);
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
      // Directories aren't supported in this slice — the bundler
      // operates on a flat list of files. Operator wanting a recursive
      // sweep walks the dir themselves and passes the resulting list.
      throw new BackupBundleError("backup-bundle/not-a-file",
        "create: '" + entry.relativePath + "' is not a regular file");
    }

    _emit(progress, { phase: "read", relativePath: entry.relativePath, size: stat.size });
    // CodeQL js/file-system-race defense — open + fstat + readSync binds
    // every byte we encrypt to the inode statSync just measured. The
    // earlier required-vs-skip branch above (existsSync → continue when
    // not entry.required) is honored before we reach this point; the
    // dest path is then computed from entry.relativePath, not srcPath.
    // TOCTOU-safe read via atomic-file; the short-read message keeps the
    // per-entry relativePath context via errorFor.
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
    // Bind the ciphertext to this blob's canonical relativePath as AEAD
    // associated data. A blob copied to a different manifest entry (the
    // restore-corruption / blob-remap attack) then fails the Poly1305 tag on
    // restore — tamper-evident even on an unsigned bundle (manifest.aadBound).
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
    // Nothing to write; refuse to emit an empty manifest. Operators
    // who genuinely want an "empty backup" need to revisit their
    // include list.
    throw new BackupBundleError("backup-bundle/empty",
      "create: no files included in bundle (every entry was missing or skipped)");
  }

  // 3. Build the manifest and write it last (so a half-written bundle
  // can be detected by absence of manifest.json — an integrity tell)
  _emit(progress, { phase: "write_manifest" });
  var manifest = backupManifest.create({
    vaultKeySalt: wrappedVk.salt,
    vaultKeyEnc:  wrappedVk.encrypted.toString("base64"),
    files:        fileEntries,
    metadata:     opts.metadata || undefined,
    aadBound:     true,   // every blob above was sealed with its relativePath as AEAD AAD
  });
  // Sign the manifest with the audit-sign keypair so a tampered
  // manifest fails verification on restore. The signer is best-
  // effort: callers running outside an audit-sign-initialized process
  // (CLI tooling, ad-hoc bundlers) can pass `opts.sign: false` to
  // emit an unsigned bundle. Default ON to match the rest of the
  // framework's signed-by-default posture.
  var shouldSign = opts.sign !== false;
  if (shouldSign) {
    try { backupManifest.sign(manifest); }
    catch (e) {
      var msg = (e && e.message) || String(e);
      // auditSign.init() not awaited yet — emit unsigned bundle. Callers
      // running outside the framework's boot sequence (CLI tooling,
      // ad-hoc bundlers, primitive smoke tests) can finish without a
      // signed manifest; restore-side `requireSignature: true` opt
      // refuses any unsigned manifest.
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
