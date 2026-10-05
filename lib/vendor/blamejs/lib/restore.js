// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.restore
 * @nav    Production
 * @title  Restore
 *
 * @intro
 *   Restore a backup bundle from storage into a live data directory.
 *   `b.restore.create` binds a storage backend, the backup passphrase and
 *   the data directory; the engine it returns lists and inspects bundles,
 *   restores one, and reverses a restore through `b.restoreRollback`.
 *
 *   A restore runs in four steps. The engine pulls the bundle out of
 *   storage, decrypts it with `b.restoreBundle.extract` (checking each
 *   file's size and SHA3-512 checksum and the manifest signature), renames
 *   the live data directory into the rollback root, and renames the
 *   decrypted directory onto the data directory. Both renames stay on one
 *   filesystem: the pulled and decrypted copies are written under
 *   `stagingRoot`, which defaults to the parent directory of the rollback
 *   root, and `run()` refuses a layout the renames cannot complete before
 *   it decrypts anything.
 *
 *   The framework keeps its files open, so a restore runs as
 *   `stop framework -> run() -> start framework`, the same shape as a
 *   database restore. Every outcome lands on `b.audit` as
 *   `restore.success` or `restore.failure` unless `audit: false`.
 *
 * @card
 *   Restore a backup bundle into a live data directory, with the previous directory kept as a rollback point.
 */

var nodeFs = require("node:fs");
var os = require("node:os");
var nodePath = require("node:path");
var atomicFile = require("./atomic-file");
var C = require("./constants");
var bCrypto = require("./crypto");
var numericChecks = require("./numeric-checks");
var restoreBundle = require("./restore-bundle");
var restoreRollback = require("./restore-rollback");
var safeMountInfo = require("./safe-mount-info");
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

var RESTORE_PULL_PREFIX = ".blamejs-restore-pull-";
var RESTORE_STAGING_PREFIX = ".blamejs-restore-staging-";

function _validateStorage(storage) {
  validateOpts.requireMethods(storage,
    ["readBundle", "listBundles", "hasBundle"],
    "storage backend", RestoreError, "restore/bad-storage");
}

/**
 * @primitive b.restore.create
 * @signature b.restore.create(opts)
 * @since     0.1.89
 * @status    stable
 * @compliance hipaa, pci-dss, gdpr, soc2, dora
 * @related   b.backup.create, b.restoreBundle.extract, b.restoreRollback.rollback
 *
 * Build a restore engine bound to a data directory, a storage backend and
 * the backup passphrase. The returned object carries `list`, `inspect`,
 * `run`, `rollback`, `listRollbacks`, `purgeRollbacks`, the wired `storage`
 * and the resolved `rollbackRoot`. Building it throws `restore/no-datadir`
 * when `dataDir` is absent or empty, and `restore/no-passphrase` when
 * `passphrase` is neither a Buffer nor a string.
 *
 * `run({ bundleId })` pulls that bundle, decrypts it, renames the live data
 * directory into the rollback root and renames the decrypted copy onto the
 * data directory. It resolves with `{ bundleId, fileCount, totalBytes,
 * rollbackPath, vaultKeyJson, durationMs }`. A signed manifest is trusted
 * only under `expectedFingerprint` or an active or rotated `b.auditSign`
 * key, so a process that does not hold the signing key passes
 * `expectedFingerprint`. `requireSignature: true` refuses a bundle with no
 * signature, and combining it with `verifySignature: false` throws
 * `restore/bad-opts`.
 *
 * Both renames must stay on one filesystem. Before pulling anything,
 * `run()` throws `restore/datadir-is-mount-point` for a data directory that
 * is a mount point, `restore/cross-device` for a `stagingRoot` or
 * `rollbackRoot` on another filesystem, `restore/bad-staging-root` or
 * `restore/bad-rollback-root` for one inside the data directory by either
 * its written path or its canonical one, and `restore/datadir-is-symlink`
 * for a data directory that is a symbolic link. A failure
 * after decryption removes the decrypted staging directory and rejects with
 * `restore/swap-failed`; the bundle in storage can be restored again. Every
 * `restore-bundle/<name>` failure is reported as `restore/<name>`.
 *
 * A `storage` missing any of `readBundle`, `listBundles` and `hasBundle` throws
 * `restore/bad-storage`.
 *
 * @opts
 *   dataDir:             string,           // required; the live data directory
 *   storage:             StorageBackend,   // required; b.backup.diskStorage() or custom
 *   passphrase:          Buffer | string,  // required; the backup passphrase
 *   rollbackRoot:        string,           // default: <dataDir>.rollbacks
 *   stagingRoot:         string,           // default: the parent directory of rollbackRoot
 *   audit:               boolean,          // default true
 *   maxPulledBytes:      number,           // default 4 GiB
 *   maxPulledFiles:      number,           // default 100000
 *   requireSignature:    boolean,          // refuse a bundle whose manifest is unsigned
 *   expectedFingerprint: string,           // trust only the key with this fingerprint
 *   verifySignature:     boolean,          // default true
 *   mountInfoPath:       string,           // default null — read mount points from this file instead of
 *                                          // the platform's own, for the cross-device and
 *                                          // mount-point checks above
 *
 * @example
 *   var fs   = require("node:fs");
 *   var path = require("node:path");
 *   var os   = require("node:os");
 *
 *   var root = fs.mkdtempSync(path.join(os.tmpdir(), "restore-store-"));
 *   var engine = b.restore.create({
 *     dataDir:    path.join(root, "data"),
 *     storage:    b.backup.diskStorage({ root: root }),
 *     passphrase: Buffer.from("operator backup passphrase"),
 *   });
 *
 *   typeof engine.run;        // → "function"
 *   typeof engine.rollback;   // → "function"
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "dataDir", "storage", "passphrase", "rollbackRoot", "stagingRoot", "audit",
    "maxPulledBytes", "maxPulledFiles",
    "requireSignature", "expectedFingerprint", "verifySignature",
    "mountInfoPath",
  ], "restore");
  validateOpts.requireNonEmptyString(opts.dataDir, "create: opts.dataDir", RestoreError, "restore/no-datadir");
  if (opts.stagingRoot !== undefined) {
    validateOpts.requireNonEmptyString(opts.stagingRoot, "create: opts.stagingRoot", RestoreError, "restore/bad-staging-root");
  }
  _validateStorage(opts.storage);
  if (!Buffer.isBuffer(opts.passphrase) && typeof opts.passphrase !== "string") {
    throw new RestoreError("restore/no-passphrase",
      "create: opts.passphrase is required (Buffer or string)");
  }

  var dataDir = opts.dataDir;
  var storage = opts.storage;
  var passphrase = opts.passphrase;
  var rollbackRoot = opts.rollbackRoot || (dataDir + ".rollbacks");
  var stagingRoot = opts.stagingRoot !== undefined
    ? opts.stagingRoot : nodePath.dirname(nodePath.resolve(rollbackRoot));
  var auditOn = opts.audit !== false;
  var mountInfoPath = typeof opts.mountInfoPath === "string" && opts.mountInfoPath.length > 0
    ? opts.mountInfoPath : null;
  validateOpts.optionalBoolean(opts.requireSignature,
    "restore.create: opts.requireSignature (whether a bundle carrying no signature from a " +
    "known key is refused; anything other than a boolean was read as false, which restores " +
    "an unsigned bundle under a configuration that asked for the opposite)",
    RestoreError, "restore/bad-opts");
  var requireSignature = opts.requireSignature === true;
  var expectedFingerprint = opts.expectedFingerprint;
  var verifySignature = opts.verifySignature;
  if (requireSignature && verifySignature === false) {
    throw new RestoreError("restore/bad-opts",
      "create: requireSignature: true cannot be combined with verifySignature: false");
  }

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

  function _canonicalOfNearestExisting(p) {
    var current = nodePath.resolve(p);
    var trailing = [];
    for (;;) {
      try {
        return nodePath.join.apply(null, [nodeFs.realpathSync.native(current)].concat(trailing));
      } catch (e) {
        var parent = nodePath.dirname(current);
        if (!e || (e.code !== "ENOENT" && e.code !== "ENOTDIR") || parent === current) return current;
        trailing.unshift(nodePath.basename(current));
        current = parent;
      }
    }
  }

  function _mountEntries() {
    return mountInfoPath === null
      ? safeMountInfo.read()
      : safeMountInfo.read({ path: mountInfoPath });
  }

  function _mountPointOf(p) {
    var entries = _mountEntries();
    if (entries === null) return null;
    var match = safeMountInfo.bestMatch(entries, _canonicalOfNearestExisting(p));
    return match === null ? null : match.mountPoint;
  }

  function _isMountPoint(p) {
    var real = _canonicalOfNearestExisting(p);
    var entries = _mountEntries();
    if (entries !== null) {
      for (var i = 0; i < entries.length; i += 1) {
        if (entries[i].mountPoint === real) return true;
      }
      return false;
    }
    var parent = nodePath.dirname(real);
    if (parent === real) return true;
    try { return nodeFs.statSync(real).dev !== nodeFs.statSync(parent).dev; }
    catch (_e) { return false; }
  }

  function _deviceOfNearestExisting(p) {
    var current = nodePath.resolve(p);
    for (;;) {
      try { return { path: current, dev: nodeFs.statSync(current).dev }; }
      catch (e) {
        var parent = nodePath.dirname(current);
        if (!e || e.code !== "ENOENT" || parent === current) throw e;
        current = parent;
      }
    }
  }

  function _firstDanglingComponent(p) {
    var resolved = nodePath.resolve(p);
    var segments = [];
    var current = resolved;
    for (;;) {
      var parent = nodePath.dirname(current);
      if (parent === current) break;
      segments.unshift(nodePath.basename(current));
      current = parent;
    }
    var prefix = current;
    for (var i = 0; i < segments.length; i += 1) {
      prefix = nodePath.join(prefix, segments[i]);
      var link = null;
      try { link = nodeFs.lstatSync(prefix); }
      catch (e) {
        if (e && e.code === "ENOENT") return null;
        throw e;
      }
      try { nodeFs.statSync(prefix); }
      catch (e2) {
        if (e2 && (e2.code === "ENOENT" || e2.code === "ELOOP")) return prefix;
        throw e2;
      }
      if (!link.isSymbolicLink() && !link.isDirectory() && i < segments.length - 1) return prefix;
    }
    return null;
  }

  function _isInside(base, candidate) {
    var relative = nodePath.relative(base, candidate);
    return relative === "" ||
      (relative.split(nodePath.sep)[0] !== ".." && !nodePath.isAbsolute(relative));
  }

  function _requireSwappableLayout() {
    var lexicalDataDir = nodePath.resolve(dataDir);
    var resolvedDataDir = _canonicalOfNearestExisting(dataDir);
    var lexicalStat = null;
    try { lexicalStat = nodeFs.lstatSync(lexicalDataDir); }
    catch (e) { if (!e || e.code !== "ENOENT") throw e; }
    if (lexicalStat !== null && lexicalStat.isSymbolicLink()) {
      throw new RestoreError("restore/datadir-is-symlink",
        "dataDir '" + dataDir + "' is a symbolic link. A restore renames dataDir aside, which " +
        "would store the link rather than the data and leave a rollback point that cannot be " +
        "restored; point dataDir at the directory itself");
    }
    var inside = [["stagingRoot", stagingRoot], ["rollbackRoot", rollbackRoot]];
    for (var n = 0; n < inside.length; n++) {
      if (_isInside(lexicalDataDir, nodePath.resolve(inside[n][1])) ||
          _isInside(resolvedDataDir, _canonicalOfNearestExisting(inside[n][1]))) {
        throw new RestoreError("restore/bad-" + (n === 0 ? "staging" : "rollback") + "-root",
          inside[n][0] + " '" + inside[n][1] + "' is dataDir or inside it; a restore moves dataDir aside, " +
          "so " + inside[n][0] + " must be outside dataDir");
      }
    }
    var roles = [
      ["dataDir", dataDir, "restore/datadir-not-a-directory"],
      ["stagingRoot", stagingRoot, "restore/bad-staging-root"],
      ["rollbackRoot", rollbackRoot, "restore/bad-rollback-root"],
    ];
    for (var r = 0; r < roles.length; r += 1) {
      var link = null;
      try { link = nodeFs.lstatSync(nodePath.resolve(roles[r][1])); }
      catch (e) { if (!e || e.code !== "ENOENT") throw e; }
      var present = null;
      try { present = nodeFs.statSync(nodePath.resolve(roles[r][1])); }
      catch (e2) { if (!e2 || (e2.code !== "ENOENT" && e2.code !== "ELOOP")) throw e2; }
      if (link !== null && present === null) {
        throw new RestoreError(roles[r][2],
          roles[r][0] + " '" + roles[r][1] + "' is a symbolic link that resolves to nothing. " +
          "A restore would create its directory through the link, which fails when the link " +
          "points nowhere; point " + roles[r][0] + " at a directory or at a link that resolves");
      }
      var dangling = _firstDanglingComponent(roles[r][1]);
      if (dangling !== null) {
        throw new RestoreError(roles[r][2],
          roles[r][0] + " '" + roles[r][1] + "' is reached through '" + dangling + "', which " +
          "resolves to nothing. A restore would create its directory under that path, which " +
          "fails; point " + roles[r][0] + " somewhere every directory above it exists");
      }
      if (present !== null && !present.isDirectory()) {
        throw new RestoreError(roles[r][2],
          roles[r][0] + " '" + roles[r][1] + "' exists and is not a directory. A restore renames " +
          "directories into and out of place, and the rollback it leaves behind must be a " +
          "directory to be restorable; point " + roles[r][0] + " at a directory");
      }
    }
    var dataParent = _deviceOfNearestExisting(nodePath.dirname(resolvedDataDir));
    var live = null;
    try { live = nodeFs.statSync(resolvedDataDir); } catch (e) { if (!e || e.code !== "ENOENT") throw e; }
    if (live !== null && (live.dev !== dataParent.dev || _isMountPoint(resolvedDataDir))) {
      throw new RestoreError("restore/datadir-is-mount-point",
        "dataDir '" + dataDir + "' is on a different filesystem from its parent directory (a mount point). " +
        "A restore replaces dataDir by renaming it, which a mount point does not allow; " +
        "point dataDir at a directory inside the mounted volume");
    }
    var dataMount = _mountPointOf(nodePath.dirname(resolvedDataDir));
    var checks = [["stagingRoot", stagingRoot], ["rollbackRoot", rollbackRoot]];
    for (var i = 0; i < checks.length; i++) {
      var found = _deviceOfNearestExisting(checks[i][1]);
      var foundMount = _mountPointOf(checks[i][1]);
      if (dataMount !== null && foundMount !== null && foundMount !== dataMount) {
        throw new RestoreError("restore/cross-device",
          checks[i][0] + " '" + checks[i][1] + "' is on mount '" + foundMount +
          "', and dataDir's parent '" + dataParent.path + "' is on mount '" + dataMount +
          "'. A restore renames between them, and a rename cannot cross mount points even " +
          "when both are the same filesystem, as a bind mount is; pass a " + checks[i][0] +
          " on the same mount as dataDir");
      }
      if (found.dev !== dataParent.dev) {
        throw new RestoreError("restore/cross-device",
          checks[i][0] + " '" + checks[i][1] + "' (on the filesystem of '" + found.path + "') is not on the filesystem of " +
          "dataDir's parent '" + dataParent.path + "'. A restore renames between them, and a rename cannot cross filesystems; " +
          "pass a " + checks[i][0] + " on the same filesystem as dataDir");
      }
    }
  }

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

    try {
      _requireSwappableLayout();
    } catch (e) {
      _emitAudit("restore.failure",
        { bundleId: bundleId, reason: (e && e.message) || String(e) }, "failure");
      throw e;
    }
    var workId = atomicFile.pathTimestamp() + "-" + bCrypto.generateToken(4);
    atomicFile.ensureDir(stagingRoot);
    var pullDir    = nodePath.join(stagingRoot, RESTORE_PULL_PREFIX + workId);
    var stagingDir = nodePath.join(stagingRoot, RESTORE_STAGING_PREFIX + workId);
    atomicFile.removeStaleDirs(stagingRoot, { prefix: RESTORE_PULL_PREFIX, olderThanMs: C.TIME.hours(24) });
    atomicFile.removeStaleDirs(stagingRoot, { prefix: RESTORE_STAGING_PREFIX, olderThanMs: C.TIME.hours(24) });

    var _releasePullBeat = function () {};
    function _cleanupTmp() {
      _releasePullBeat();
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
    var pullBeat = atomicFile.heartbeat(pullDir);
    _releasePullBeat = function () {
      if (pullBeat === null) return;
      var beat = pullBeat;
      pullBeat = null;
      beat.stop();
    };
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
      var mappedCode = typeof code === "string" && code.indexOf("restore-bundle/") === 0
        ? "restore/" + code.slice("restore-bundle/".length)
        : "restore/extract-failed";
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
    var rollbackRootExisted = nodeFs.existsSync(rollbackRoot);
    try {
      swapResult = restoreRollback.swap({
        stagingDir:    stagingDir,
        dataDir:       dataDir,
        rollbackRoot:  rollbackRoot,
        marker:        Object.assign({ bundleId: bundleId }, runOpts.marker || {}),
      });
    } catch (e) {
      _cleanupTmp();
      if (!rollbackRootExisted) {
        try { nodeFs.rmdirSync(rollbackRoot); } catch (_e) { /* not empty, or already gone: left in place */ }
      }
      _emitAudit("restore.failure",
        { bundleId: bundleId, reason: "swap: " + ((e && e.message) || String(e)) },
        "failure");
      throw new RestoreError("restore/swap-failed",
        "swap failed after a successful extract, and the decrypted staging directory was removed " +
        "(the bundle in storage can be restored again): " + ((e && e.message) || String(e)));
    }

    _releasePullBeat();
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
