// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

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
  var requireSignature = opts.requireSignature === true;
  var expectedFingerprint = opts.expectedFingerprint;
  var verifySignature = opts.verifySignature;

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

    var dataDirEntries = [];
    try { dataDirEntries = nodeFs.readdirSync(dataDir); } catch (_e) { dataDirEntries = []; }
    if (extracted.fileCount === 0 && dataDirEntries.length > 0) {
      _cleanupTmp();
      _emitAudit("restore.failure",
        { bundleId: bundleId, reason: "refusing zero-file restore over a non-empty dataDir" },
        "failure");
      throw new RestoreError("restore/empty-extract-refused",
        "refusing to swap a zero-file restore over the non-empty dataDir '" + dataDir +
        "' (a filter matched no manifest entry, or the manifest is empty) — this would wipe live data");
    }

    var swapResult;
    try {
      swapResult = restoreRollback.swap({
        stagingDir:    stagingDir,
        dataDir:       dataDir,
        rollbackRoot:  rollbackRoot,
        marker:        Object.assign({ bundleId: bundleId }, runOpts.marker || {}),
      });
    } catch (e) {
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
