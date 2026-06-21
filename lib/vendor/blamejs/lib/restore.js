"use strict";
/**
 * restore — operator-facing restore from a backup bundle in storage.
 *
 * Mirror of lib/backup. Pulls a bundle from a storage backend,
 * decrypts it via lib/restore-bundle into a staging directory, then
 * swaps that staging into place as the new dataDir via
 * lib/restore-rollback (saving the previous dataDir as a versioned
 * rollback point). Operators stop the framework first, run restore,
 * then start the framework — same workflow as a database restore.
 *
 *   var restore = b.restore.create({
 *     dataDir:      "./data",
 *     storage:      b.backup.diskStorage({ root: "./backups" }),
 *     passphrase:   Buffer.from("operator backup passphrase"),
 *     rollbackRoot: "./data.rollbacks",   // optional; default <dataDir>.rollbacks
 *     audit:        true,
 *   });
 *
 *   await restore.list();                 // → [{ bundleId, createdAt, size }]
 *   await restore.inspect(bundleId);      // → manifest (no decrypt; no passphrase
 *                                            //  needed for inspect)
 *
 *   await restore.run({
 *     bundleId,
 *     filter,                              // optional file filter
 *     marker: { reason: "incident-2026-04-27" },
 *   });
 *   // → { bundleId, fileCount, totalBytes, rollbackPath, vaultKeyJson,
 *   //     durationMs }
 *
 *   await restore.rollback();              // → reverts the most recent restore
 *   await restore.listRollbacks();         // → [{ rollbackPath, swappedAt, marker }]
 *   await restore.purgeRollbacks({ keep });
 *
 * vaultKeyJson: the manifest's vaultKeyEnc decrypted via the passphrase,
 * returned to the caller as a string. Returned but NOT auto-installed —
 * the caller decides what to do with it (the swap may have already put
 * the bundle's vault.key file into place if the bundle included one;
 * operators with vault-passphrase-wrapped setups handle the placement
 * themselves before re-starting the framework).
 *
 * Failure modes (each cleans up the tmp pull dir + staging dir):
 *   - bundle not in storage → restore/bundle-not-found
 *   - manifest absent / bad → restore/missing-manifest
 *   - wrong passphrase → restore/decrypt-failed
 *   - tampered blob → restore/decrypt-failed (AEAD tag check)
 *   - checksum mismatch → restore/checksum-mismatch
 *   - swap fails after extract → restore/swap-failed (staging is
 *     preserved at the path returned in error.stagingDir for operator
 *     manual recovery)
 */

var nodeFs = require("node:fs");
var os = require("node:os");
var nodePath = require("node:path");
var C = require("./constants");
var bCrypto = require("./crypto");
var numericChecks = require("./numeric-checks");
var restoreBundle = require("./restore-bundle");
var restoreRollback = require("./restore-rollback");
var validateOpts = require("./validate-opts");
var auditEmit = require("./audit-emit");
var { FrameworkError } = require("./framework-error");

class RestoreError extends FrameworkError {
  constructor(code, message, permanent) {
    super(message, code);
    this.name = "RestoreError";
    this.permanent = !!permanent;
    this.isRestoreError = true;
  }
}

function _validateStorage(storage) {
  validateOpts.requireMethods(storage,
    ["readBundle", "listBundles", "hasBundle"],
    "storage backend", RestoreError, "restore/bad-storage");
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "dataDir", "storage", "passphrase", "rollbackRoot", "audit",
    "maxPulledBytes", "maxPulledFiles",
    "requireSignature", "expectedFingerprint", "verifySignature",
  ], "restore");
  validateOpts.requireNonEmptyString(opts.dataDir, "create: opts.dataDir", RestoreError, "restore/no-datadir");
  _validateStorage(opts.storage);
  if (!Buffer.isBuffer(opts.passphrase) && typeof opts.passphrase !== "string") {
    throw new RestoreError("restore/no-passphrase",
      "create: opts.passphrase is required (Buffer or string)");
  }

  var dataDir = opts.dataDir;
  var storage = opts.storage;
  var passphrase = opts.passphrase;
  var rollbackRoot = opts.rollbackRoot || (dataDir + ".rollbacks");
  var auditOn = opts.audit !== false;
  // Manifest-signature policy. The framework signs bundles best-effort (an
  // unsigned bundle is the documented CLI / standalone / worker case), so the
  // non-opt-in integrity default is the per-blob AEAD path-binding below
  // (which defeats the blob-remap attack on EVERY bundle, signed or not);
  // requireSignature is the additional provenance policy operators under
  // HIPAA/PCI opt into to mandate a verified signer. expectedFingerprint pins
  // a signer; verifySignature:false allows a cold/cross-org restore. All
  // three are threaded into restoreBundle.extract on every run — previously
  // omitted entirely, so a present signature was never even verified and a
  // requireSignature policy could not be enforced (CWE-347).
  var requireSignature = opts.requireSignature === true;
  var expectedFingerprint = opts.expectedFingerprint;
  var verifySignature = opts.verifySignature;

  // Preflight footprint caps. Defended against storage that returns a
  // tampered or oversized bundle: we cap both the storage-reported size
  // (cheap, before pull) AND the actually-pulled bytes/file-count
  // (defense-in-depth in case the backend lied). Default 4 GiB / 100K
  // files keeps the small-bundle path uncapped while bounding the
  // pathological case.
  // Default file-count cap = 0x186A0 (100,000). Bounds the pathological
  // case where a tampered bundle claims a small total size but contains
  // an unbounded number of zero-byte files. Operators with large bundles
  // override.
  var DEFAULT_MAX_PULLED_FILES = 0x186A0;
  var maxPulledBytes = numericChecks.isPositiveFinite(opts.maxPulledBytes)
    ? opts.maxPulledBytes : C.BYTES.gib(4);
  var maxPulledFiles = numericChecks.isPositiveInt(opts.maxPulledFiles)
    ? opts.maxPulledFiles : DEFAULT_MAX_PULLED_FILES;

  function _walkPullDirFootprint(dir) {
    var totalBytes = 0, fileCount = 0;
    var stack = [dir];
    while (stack.length > 0) {
      var current = stack.pop();
      var entries;
      try { entries = nodeFs.readdirSync(current, { withFileTypes: true }); }
      catch (_e) { continue; }
      for (var i = 0; i < entries.length; i++) {
        var entry = entries[i];
        var full = nodePath.join(current, entry.name);
        if (entry.isDirectory()) {
          stack.push(full);
        } else if (entry.isFile()) {
          fileCount++;
          if (fileCount > maxPulledFiles) {
            return { tooManyFiles: true, fileCount: fileCount };
          }
          try {
            totalBytes += nodeFs.statSync(full).size;
            if (totalBytes > maxPulledBytes) {
              return { tooManyBytes: true, totalBytes: totalBytes };
            }
          } catch (_e) { /* file vanished mid-walk */ }
        }
      }
    }
    return { totalBytes: totalBytes, fileCount: fileCount };
  }

  var _emitAudit = auditEmit.gatedReasonEmitter({ audit: auditOn });

  async function list() { return await storage.listBundles(); }

  // Find a bundle in storage.listBundles() output and check its
  // reported size against maxPulledBytes BEFORE pulling. listBundles()
  // returns the storage-reported size; cheap to scan and rejects an
  // oversized object before any bytes hit local disk. Returns the
  // bundle metadata when within bounds, throws when oversized, returns
  // null when listBundles doesn't surface the bundle (e.g. listing is
  // truncated by the backend).
  async function _preflightBundleSize(bundleId) {
    var listed;
    try { listed = await storage.listBundles(); }
    catch (_e) { return null; }
    if (!Array.isArray(listed)) return null;
    for (var i = 0; i < listed.length; i++) {
      var entry = listed[i];
      if (entry && entry.bundleId === bundleId) {
        if (typeof entry.size === "number" && entry.size > maxPulledBytes) {
          throw new RestoreError("restore/bundle-too-large",
            "bundle '" + bundleId + "' reports size " + entry.size +
            " bytes, exceeds maxPulledBytes " + maxPulledBytes);
        }
        return entry;
      }
    }
    return null;
  }

  async function inspect(bundleId) {
    if (typeof bundleId !== "string" || bundleId.length === 0) {
      throw new RestoreError("restore/bad-bundle-id", "inspect: bundleId is required");
    }
    var has = await storage.hasBundle(bundleId);
    if (!has) {
      throw new RestoreError("restore/bundle-not-found",
        "inspect: bundle '" + bundleId + "' not in storage");
    }
    await _preflightBundleSize(bundleId);
    var pullDir = nodePath.join(os.tmpdir(),
      "blamejs-restore-inspect-" + bCrypto.generateToken(4));
    try {
      await storage.readBundle(bundleId, pullDir);
      var pulled = _walkPullDirFootprint(pullDir);
      if (pulled.tooManyBytes) {
        throw new RestoreError("restore/pulled-too-large",
          "bundle '" + bundleId + "' pulled " + pulled.totalBytes +
          " bytes (caught mid-pull), exceeds maxPulledBytes " + maxPulledBytes);
      }
      if (pulled.tooManyFiles) {
        throw new RestoreError("restore/pulled-too-many-files",
          "bundle '" + bundleId + "' pulled " + pulled.fileCount +
          " files, exceeds maxPulledFiles " + maxPulledFiles);
      }
      return restoreBundle.inspect({ bundleDir: pullDir });
    } finally {
      try { nodeFs.rmSync(pullDir, { recursive: true, force: true }); } catch (_e) { /* best-effort tmpdir cleanup */ }
    }
  }

  async function run(runOpts) {
    runOpts = runOpts || {};
    var t0 = Date.now();
    var bundleId = runOpts.bundleId;
    if (typeof bundleId !== "string" || bundleId.length === 0) {
      throw new RestoreError("restore/bad-bundle-id", "run: opts.bundleId is required");
    }
    var has = await storage.hasBundle(bundleId);
    if (!has) {
      throw new RestoreError("restore/bundle-not-found",
        "run: bundle '" + bundleId + "' not in storage");
    }

    var pullId = bCrypto.generateToken(4);
    var pullDir    = nodePath.join(os.tmpdir(), "blamejs-restore-pull-"    + pullId);
    var stagingDir = nodePath.join(os.tmpdir(), "blamejs-restore-staging-" + pullId);

    function _cleanupTmp() {
      try { nodeFs.rmSync(pullDir,    { recursive: true, force: true }); } catch (_e) { /* best-effort tmpdir cleanup */ }
      try { nodeFs.rmSync(stagingDir, { recursive: true, force: true }); } catch (_e) { /* best-effort tmpdir cleanup */ }
    }

    // 1. Pull bundle out of storage
    // Preflight: reject an oversized bundle BEFORE pulling bytes to
    // disk. Cheap when the backend lists size; no-op when it doesn't.
    try {
      await _preflightBundleSize(bundleId);
    } catch (e) {
      _cleanupTmp();
      _emitAudit("restore.failure",
        { bundleId: bundleId, reason: (e && e.message) || String(e) },
        "failure");
      throw e;
    }
    try {
      await storage.readBundle(bundleId, pullDir);
    } catch (e) {
      _cleanupTmp();
      _emitAudit("restore.failure",
        { bundleId: bundleId, reason: "storage.readBundle: " + ((e && e.message) || String(e)) },
        "failure");
      throw new RestoreError("restore/storage-read-failed",
        "pulling bundle from storage failed: " + ((e && e.message) || String(e)));
    }
    // Defense-in-depth: walk the pulled bundle and re-check footprint.
    // Catches a backend that under-reported size in listBundles or that
    // doesn't surface size at all.
    var pulled = _walkPullDirFootprint(pullDir);
    if (pulled.tooManyBytes || pulled.tooManyFiles) {
      _cleanupTmp();
      var capCode = pulled.tooManyBytes ? "restore/pulled-too-large" : "restore/pulled-too-many-files";
      var capMsg = pulled.tooManyBytes
        ? "bundle '" + bundleId + "' pulled " + pulled.totalBytes + " bytes, exceeds maxPulledBytes " + maxPulledBytes
        : "bundle '" + bundleId + "' pulled " + pulled.fileCount + " files, exceeds maxPulledFiles " + maxPulledFiles;
      _emitAudit("restore.failure", { bundleId: bundleId, reason: capMsg }, "failure");
      throw new RestoreError(capCode, capMsg);
    }

    // 2. Decrypt + verify into stagingDir
    var extracted;
    try {
      extracted = await restoreBundle.extract({
        bundleDir:        pullDir,
        stagingDir:       stagingDir,
        passphrase:       passphrase,
        filter:           runOpts.filter,
        progressCallback: runOpts.progressCallback,
        requireSignature:    requireSignature,
        expectedFingerprint: expectedFingerprint,
        verifySignature:     verifySignature,
      });
    } catch (e) {
      _cleanupTmp();
      // Map restore-bundle error codes to restore/* domain so consumer
      // code sees a single error namespace
      var code = e && e.code;
      var mappedCode = "restore/extract-failed";
      if (code === "restore-bundle/decrypt-failed")     mappedCode = "restore/decrypt-failed";
      else if (code === "restore-bundle/checksum-mismatch") mappedCode = "restore/checksum-mismatch";
      else if (code === "restore-bundle/missing-manifest")  mappedCode = "restore/missing-manifest";
      else if (code === "restore-bundle/missing-blob")      mappedCode = "restore/missing-blob";
      else if (code === "restore-bundle/size-mismatch")     mappedCode = "restore/size-mismatch";
      else if (code === "restore-bundle/missing-signature") mappedCode = "restore/missing-signature";
      else if (code === "restore-bundle/bad-signature")     mappedCode = "restore/bad-signature";
      _emitAudit("restore.failure",
        { bundleId: bundleId, reason: (e && e.message) || String(e) }, "failure");
      throw new RestoreError(mappedCode,
        "extract failed: " + ((e && e.message) || String(e)));
    }

    // 3. Atomic swap. On swap failure, the stagingDir is preserved so
    // an operator can recover manually — we do NOT delete it here.
    var swapResult;
    try {
      swapResult = restoreRollback.swap({
        stagingDir:    stagingDir,
        dataDir:       dataDir,
        rollbackRoot:  rollbackRoot,
        marker:        Object.assign({ bundleId: bundleId }, runOpts.marker || {}),
      });
    } catch (e) {
      // Pull dir is safe to clean (the source bundle is in storage);
      // staging stays for manual recovery.
      try { nodeFs.rmSync(pullDir, { recursive: true, force: true }); } catch (_e) { /* best-effort tmpdir cleanup */ }
      _emitAudit("restore.failure",
        { bundleId: bundleId, reason: "swap: " + ((e && e.message) || String(e)) },
        "failure");
      var err = new RestoreError("restore/swap-failed",
        "atomic swap failed after successful extract — staging preserved at " +
        stagingDir + ": " + ((e && e.message) || String(e)));
      err.stagingDir = stagingDir;
      throw err;
    }

    // 4. Clean up the pull dir (source bundle still in storage)
    try { nodeFs.rmSync(pullDir, { recursive: true, force: true }); } catch (_e) { /* best-effort tmpdir cleanup */ }

    var summary = {
      bundleId:     bundleId,
      fileCount:    extracted.fileCount,
      totalBytes:   extracted.totalBytes,
      rollbackPath: swapResult.rollbackPath,
      vaultKeyJson: extracted.vaultKeyJson,
      durationMs:   Date.now() - t0,
    };
    _emitAudit("restore.success", {
      bundleId:     bundleId,
      fileCount:    extracted.fileCount,
      totalBytes:   extracted.totalBytes,
      rollbackPath: swapResult.rollbackPath,
      durationMs:   summary.durationMs,
    });
    return summary;
  }

  async function rollback(rollbackOpts) {
    rollbackOpts = rollbackOpts || {};
    // Either an explicit rollbackPath OR pull the most-recent one
    var target = rollbackOpts.rollbackPath;
    if (!target) {
      var bundles = restoreRollback.list({ rollbackRoot: rollbackRoot });
      if (bundles.length === 0) {
        throw new RestoreError("restore/no-rollbacks",
          "rollback: no rollback points found at " + rollbackRoot);
      }
      target = bundles[0].rollbackPath;
    }
    var r;
    try {
      r = await restoreRollback.rollback({
        dataDir:      dataDir,
        rollbackPath: target,
        rollbackRoot: rollbackRoot,
      });
    } catch (e) {
      _emitAudit("restore.rollback.failure",
        { rollbackPath: target, reason: (e && e.message) || String(e) }, "failure");
      throw new RestoreError("restore/rollback-failed",
        "rollback failed: " + ((e && e.message) || String(e)));
    }
    _emitAudit("restore.rollback.success",
      { rollbackPath: target, discardedAt: r.discardedAt });
    return r;
  }

  function listRollbacks() {
    return restoreRollback.list({ rollbackRoot: rollbackRoot });
  }
  function purgeRollbacks(purgeOpts) {
    return restoreRollback.purge({
      rollbackRoot: rollbackRoot,
      keep:         (purgeOpts && purgeOpts.keep) || 0,
    });
  }

  return {
    list:           list,
    inspect:        inspect,
    run:            run,
    rollback:       rollback,
    listRollbacks:  listRollbacks,
    purgeRollbacks: purgeRollbacks,
    storage:        storage,
    rollbackRoot:   rollbackRoot,
  };
}

module.exports = {
  create:        create,
  RestoreError:  RestoreError,
};
