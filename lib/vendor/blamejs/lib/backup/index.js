"use strict";
/**
 * backup — operator-facing backup orchestration.
 *
 * Wires lib/backup-bundle (encrypt + emit a bundle directory) to a
 * pluggable storage backend, plus retention policy + audit emission.
 * Ships with a local-filesystem backend (b.backup.localStorage); S3
 * or any custom backend drops in through the same interface.
 *
 *   var backup = b.backup.create({
 *     dataDir:      "./data",
 *     storage:      b.backup.localStorage({ root: "./backups" }),
 *     passphrase:   Buffer.from("operator backup passphrase"),
 *     files: [
 *       { relativePath: "db.enc",       kind: "raw",          required: true },
 *       { relativePath: "db.key.enc",   kind: "raw",          required: true },
 *       { relativePath: "vault.key",    kind: "raw",          required: false },
 *       { relativePath: "ca.key.sealed",kind: "vault-sealed", required: false },
 *     ],
 *     vaultKeyJson: function () { return fs.readFileSync('./data/vault.key','utf8'); },
 *     retention:    { keep: 7 },        // keep latest 7; older purged after run
 *     audit:        true,
 *     scheduler:    b.scheduler,        // optional; needed for backup.schedule()
 *   });
 *
 *   await backup.run({ metadata: { reason: "daily" } });
 *     // → { bundleId, bundleSize, fileCount, durationMs }
 *   await backup.list();
 *     // → [{ bundleId, createdAt, size, fileCount }]
 *   await backup.delete(bundleId);
 *   await backup.purgeOlder({ keep: 7 });
 *   await backup.read(bundleId, destDir);  // pull a bundle back to disk
 *                                            // (without decrypting — that's
 *                                            //  restore-bundle's job)
 *
 *   backup.schedule({ cron: "0 2 * * *", timezone: "America/New_York" });
 *     // returns a scheduler task name; wires through b.scheduler
 *
 * Storage backend contract:
 *
 *   {
 *     async writeBundle(bundleId, sourceDir)  copy sourceDir contents under bundleId
 *     async readBundle(bundleId, destDir)     copy bundle out to destDir
 *     async listBundles()                     → [{ bundleId, createdAt, size }]
 *     async deleteBundle(bundleId)
 *     async hasBundle(bundleId)               → boolean
 *   }
 *
 * vaultKeyJson can be either:
 *   - A string (the operator already has the JSON in hand)
 *   - A function returning a string (or async returning a string) — the
 *     framework calls this each backup so a long-running app doesn't pin
 *     the vault key in memory between runs
 *
 * Bundle IDs are filesystem-safe timestamps with millisecond precision
 * plus a 4-byte random suffix: "2026-04-27T14-00-00-123Z-a8f30b21".
 * Colons + dots in standard ISO-8601 are replaced with dashes so the
 * id works as a directory name on every platform (Windows reserves ':'
 * for drive letters). String sort still gives chronological order.
 */

var fs = require("fs");
var os = require("os");
var path = require("path");
var crypto = require("../crypto");
var atomicFile = require("../atomic-file");
var backupBundle = require("./bundle");
var lazyRequire = require("../lazy-require");
var validateOpts = require("../validate-opts");
var audit = lazyRequire(function () { return require("../audit"); });
// lazyRequire ../db so backup stays a leaf module operators can use
// without the rest of the framework's DB chain loaded in the same
// module graph (CLI tools, stand-alone backup runners). The db()
// callable resolves on first access.
var dbModuleLazy = lazyRequire(function () { return require("../db"); });
var { defineClass } = require("../framework-error");

var BackupError = defineClass("BackupError");

// "2026-04-27T14-00-00-123Z-a8f30b21" — atomicFile.pathTimestamp() form
// (ISO with ':'+'.' replaced by '-') plus a random suffix.
var BUNDLE_ID_RE = /^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z-[0-9a-f]{8}$/;

// Cap on bundle-id length BEFORE the regex test — a malicious /
// pathological input can't make the regex engine spin if we bound
// length first. Bundle IDs in the wild are 32-ish chars; a 128-cap
// is comfortable.
var BUNDLE_ID_MAX_LEN = 0x80;
function _isValidBundleId(s) {
  return typeof s === "string" && s.length > 0 &&
    s.length <= BUNDLE_ID_MAX_LEN && BUNDLE_ID_RE.test(s);
}

function _generateBundleId() {
  return atomicFile.pathTimestamp() + "-" + crypto.generateToken(4);
}

function _dirSize(p) {
  var total = 0;
  var entries = fs.readdirSync(p, { withFileTypes: true });
  for (var i = 0; i < entries.length; i++) {
    var f = path.join(p, entries[i].name);
    if (entries[i].isDirectory()) total += _dirSize(f);
    else if (entries[i].isFile()) total += fs.statSync(f).size;
  }
  return total;
}

// ---- Local filesystem storage backend (the default) ----

function localStorage(opts) {
  opts = opts || {};
  validateOpts.requireNonEmptyString(opts.root, "localStorage: opts.root", BackupError, "backup/no-storage-root");
  var root = opts.root;

  function _bundlePath(bundleId) {
    if (!_isValidBundleId(bundleId)) {
      throw new BackupError("backup/bad-bundle-id",
        "bundleId must match the framework's timestamp+suffix format");
    }
    return path.join(root, bundleId);
  }

  return {
    name: "local",
    async writeBundle(bundleId, sourceDir) {
      atomicFile.ensureDir(root);
      var dest = _bundlePath(bundleId);
      if (fs.existsSync(dest)) {
        throw new BackupError("backup/bundle-exists",
          "writeBundle: bundle '" + bundleId + "' already exists in storage");
      }
      atomicFile.copyDirRecursive(sourceDir, dest);
    },
    async readBundle(bundleId, destDir) {
      var src = _bundlePath(bundleId);
      if (!fs.existsSync(src)) {
        throw new BackupError("backup/bundle-not-found",
          "readBundle: '" + bundleId + "' not in storage at " + root);
      }
      if (fs.existsSync(destDir)) {
        throw new BackupError("backup/dest-exists",
          "readBundle: destDir already exists: " + destDir);
      }
      atomicFile.copyDirRecursive(src, destDir);
    },
    async listBundles() {
      if (!fs.existsSync(root)) return [];
      var entries = fs.readdirSync(root, { withFileTypes: true });
      var out = [];
      for (var i = 0; i < entries.length; i++) {
        if (!entries[i].isDirectory()) continue;
        if (!_isValidBundleId(entries[i].name)) continue;
        var p = path.join(root, entries[i].name);
        var stat;
        try { stat = fs.statSync(p); } catch (_e) { continue; }
        var size;
        try { size = _dirSize(p); } catch (_e) { size = 0; }
        out.push({
          bundleId:  entries[i].name,
          createdAt: stat.mtime.toISOString(),
          size:      size,
        });
      }
      // Newest first
      out.sort(function (a, b) { return a.bundleId < b.bundleId ? 1 : -1; });
      return out;
    },
    async deleteBundle(bundleId) {
      var p = _bundlePath(bundleId);
      if (!fs.existsSync(p)) return;
      fs.rmSync(p, { recursive: true, force: true });
    },
    async hasBundle(bundleId) {
      try { return fs.existsSync(_bundlePath(bundleId)); }
      catch (_e) { return false; }
    },
  };
}

// ---- Engine ----

function _validateStorage(storage) {
  if (!storage || typeof storage !== "object") {
    throw new BackupError("backup/bad-storage",
      "storage backend is required (use b.backup.localStorage or pass a custom one)");
  }
  var required = ["writeBundle", "readBundle", "listBundles", "deleteBundle", "hasBundle"];
  for (var i = 0; i < required.length; i++) {
    if (typeof storage[required[i]] !== "function") {
      throw new BackupError("backup/bad-storage",
        "storage backend missing method '" + required[i] + "'");
    }
  }
}

async function _resolveVaultKeyJson(vaultKeyJsonOpt) {
  if (typeof vaultKeyJsonOpt === "string") return vaultKeyJsonOpt;
  if (typeof vaultKeyJsonOpt === "function") {
    var r = vaultKeyJsonOpt();
    if (r && typeof r.then === "function") r = await r;
    if (typeof r !== "string" || r.length === 0) {
      throw new BackupError("backup/bad-vault-key",
        "vaultKeyJson function must return a non-empty string");
    }
    return r;
  }
  throw new BackupError("backup/no-vault-key-json",
    "opts.vaultKeyJson is required (string or function returning a string)");
}

function create(opts) {
  opts = opts || {};
  if (typeof opts.dataDir !== "string" || !fs.existsSync(opts.dataDir)) {
    throw new BackupError("backup/no-datadir",
      "create: opts.dataDir is required and must exist");
  }
  _validateStorage(opts.storage);
  if (!Buffer.isBuffer(opts.passphrase) && typeof opts.passphrase !== "string") {
    throw new BackupError("backup/no-passphrase",
      "create: opts.passphrase is required (Buffer or string)");
  }
  if (!Array.isArray(opts.files) || opts.files.length === 0) {
    throw new BackupError("backup/no-files",
      "create: opts.files must be a non-empty array of include entries");
  }
  if (opts.vaultKeyJson === undefined) {
    throw new BackupError("backup/no-vault-key-json",
      "create: opts.vaultKeyJson is required (string or function returning string)");
  }

  var dataDir = opts.dataDir;
  var storage = opts.storage;
  var passphrase = opts.passphrase;
  var files = opts.files;
  var vaultKeyJsonOpt = opts.vaultKeyJson;
  var retention = opts.retention || null;
  var auditOn = opts.audit !== false;
  var scheduler = opts.scheduler || null;
  // flushBeforeBackup — call db.flushToDisk() (or operator-supplied
  // flush) before snapshotting so encrypted-at-rest dbs are current.
  // In encrypted-at-rest mode the framework re-encrypts to disk every
  // ~5 min; without a pre-flush a backup of db.enc could be that
  // stale relative to the live tmpfs DB. Pass false to skip when the
  // operator's calling backup against a process that doesn't own the
  // DB (e.g. an out-of-band backup tool reading a paused replica).
  var flushBeforeBackup = typeof opts.flushBeforeBackup === "function"
    ? opts.flushBeforeBackup
    : (opts.flushBeforeBackup === false ? null : null);
  // requireFlush — when true, a flush failure FAILS the backup instead
  // of producing a (potentially stale) snapshot. Operators on
  // encrypted-at-rest with hard freshness requirements (compliance,
  // audit, point-in-time recovery) opt in. Default false preserves the
  // long-standing best-effort posture for operators who care about
  // backup completing more than freshness.
  var requireFlush = opts.requireFlush === true;
  // Default: try b.db.flushToDisk if available. Wired this way so the
  // backup primitive doesn't take a hard dependency on b.db (operators
  // running backup against an external db handle still work).
  if (flushBeforeBackup === null && opts.flushBeforeBackup !== false) {
    try {
      var dbModule = dbModuleLazy();
      if (typeof dbModule.flushToDisk === "function") {
        flushBeforeBackup = function () { dbModule.flushToDisk(); };
      }
    } catch (_e) { /* db not available in this module graph — flush is a no-op */ }
  }

  function _emitAudit(action, info, outcome) {
    if (!auditOn) return;
    audit().safeEmit({
      action:   action,
      outcome:  outcome,
      metadata: info || {},
      reason:   info && info.reason ? info.reason : null,
    });
  }

  async function run(runOpts) {
    runOpts = runOpts || {};
    var t0 = Date.now();
    var bundleId = _generateBundleId();
    var stagingDir = path.join(os.tmpdir(),
      "blamejs-backup-staging-" + bundleId.replace(/[:.]/g, "-"));

    // Flush the live DB to disk so the snapshot is current. Default
    // posture is best-effort — a flush failure logs but doesn't fail
    // the whole backup. With requireFlush:true the failure aborts the
    // backup so a stale snapshot never lands in storage.
    if (flushBeforeBackup) {
      try { await flushBeforeBackup(); }
      catch (e) {
        var flushReason = (e && e.message) || String(e);
        _emitAudit("backup.flush.failure",
          { bundleId: bundleId, reason: flushReason },
          requireFlush ? "failure" : "warning");
        if (requireFlush) {
          _emitAudit("backup.failure",
            { bundleId: bundleId, reason: "flush-required-but-failed: " + flushReason },
            "failure");
          throw new BackupError("backup/flush-required-failed",
            "backup flush required but failed: " + flushReason);
        }
      }
    }

    var vaultKeyJson;
    try {
      vaultKeyJson = await _resolveVaultKeyJson(vaultKeyJsonOpt);
    } catch (e) {
      _emitAudit("backup.failure", { bundleId: bundleId, reason: e.message }, "failure");
      throw e;
    }

    var bundleResult;
    try {
      bundleResult = await backupBundle.create({
        dataDir:      dataDir,
        outDir:       stagingDir,
        passphrase:   passphrase,
        vaultKeyJson: vaultKeyJson,
        files:        files,
        metadata:     Object.assign({ bundleId: bundleId }, runOpts.metadata || {}),
        progressCallback: runOpts.progressCallback,
      });
    } catch (e) {
      try { fs.rmSync(stagingDir, { recursive: true, force: true }); } catch (_e) { /* best-effort tmpdir cleanup */ }
      _emitAudit("backup.failure",
        { bundleId: bundleId, reason: (e && e.message) || String(e) }, "failure");
      throw e;
    }

    try {
      await storage.writeBundle(bundleId, stagingDir);
    } catch (e) {
      try { fs.rmSync(stagingDir, { recursive: true, force: true }); } catch (_e) { /* best-effort tmpdir cleanup */ }
      _emitAudit("backup.failure",
        { bundleId: bundleId, reason: "storage.writeBundle: " + ((e && e.message) || String(e)) },
        "failure");
      throw new BackupError("backup/storage-write-failed",
        "writing bundle to storage failed: " + ((e && e.message) || String(e)));
    }

    try { fs.rmSync(stagingDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }

    var summary = {
      bundleId:   bundleId,
      bundleSize: bundleResult.bundleSize,
      fileCount:  bundleResult.fileCount,
      durationMs: Date.now() - t0,
      storage:    storage.name || "custom",
    };
    _emitAudit("backup.success", summary);

    // Retention sweep — best-effort. A failure here logs but does NOT
    // fail the run (the bundle is already safely written; pruning
    // can be retried).
    if (retention && typeof retention.keep === "number" && retention.keep > 0) {
      try {
        var purged = await purgeOlder({ keep: retention.keep });
        summary.retentionPurged = purged.deleted;
      } catch (e) {
        _emitAudit("backup.retention.failure",
          { bundleId: bundleId, reason: (e && e.message) || String(e) },
          "warning");
      }
    }
    return summary;
  }

  async function list() {
    return await storage.listBundles();
  }

  async function deleteBundle(bundleId) {
    if (!_isValidBundleId(bundleId)) {
      throw new BackupError("backup/bad-bundle-id",
        "bundleId must match the framework's timestamp+suffix format");
    }
    await storage.deleteBundle(bundleId);
    _emitAudit("backup.deleted", { bundleId: bundleId });
  }

  async function read(bundleId, destDir) {
    if (!_isValidBundleId(bundleId)) {
      throw new BackupError("backup/bad-bundle-id",
        "bundleId must match the framework's timestamp+suffix format");
    }
    await storage.readBundle(bundleId, destDir);
  }

  async function purgeOlder(purgeOpts) {
    purgeOpts = purgeOpts || {};
    var keep = typeof purgeOpts.keep === "number" && purgeOpts.keep >= 0
      ? Math.floor(purgeOpts.keep) : 0;
    var bundles = await storage.listBundles();
    // listBundles returns newest first; keep the first `keep`, purge rest.
    var toDelete = bundles.slice(keep);
    var deleted = [];
    for (var i = 0; i < toDelete.length; i++) {
      try {
        await storage.deleteBundle(toDelete[i].bundleId);
        deleted.push(toDelete[i].bundleId);
      } catch (e) {
        _emitAudit("backup.deleted.failure",
          { bundleId: toDelete[i].bundleId, reason: (e && e.message) || String(e) },
          "failure");
      }
    }
    if (deleted.length > 0) {
      _emitAudit("backup.retention.swept", { kept: keep, deleted: deleted });
    }
    return { kept: keep, deleted: deleted };
  }

  function schedule(scheduleOpts) {
    if (!scheduler || typeof scheduler.create !== "function") {
      throw new BackupError("backup/no-scheduler",
        "schedule: opts.scheduler must be wired at create() to use schedule()");
    }
    scheduleOpts = scheduleOpts || {};
    if (typeof scheduleOpts.cron !== "string" || scheduleOpts.cron.length === 0) {
      throw new BackupError("backup/bad-schedule",
        "schedule: opts.cron is required (POSIX 5-field cron expression)");
    }
    var name = scheduleOpts.name || "blamejs.backup";
    // Operators wire scheduler instances themselves; create() returns a
    // scheduler we can append to.
    var schedInstance = scheduler.create({ audit: auditOn });
    schedInstance.schedule({
      name:     name,
      cron:     scheduleOpts.cron,
      timezone: scheduleOpts.timezone,
      run:      async function () {
        try { await run({ metadata: { reason: "scheduled" } }); }
        catch (_e) { /* errors already audited inside run() */ }
      },
    });
    return { name: name, instance: schedInstance };
  }

  return {
    run:           run,
    list:          list,
    delete:        deleteBundle,
    read:          read,
    purgeOlder:    purgeOlder,
    schedule:      schedule,
    storage:       storage,
  };
}

// recommendedFiles — return the framework-default include list for
// a given DB at-rest mode + vault wrap mode. Operators with custom
// data files extend the result; operators with the standard layout
// can use it as-is.
//
//   var files = b.backup.recommendedFiles({
//     atRest:    b.db.getMode(),         // 'plain' | 'encrypted'
//     vaultMode: b.vault.getMode(),      // 'plaintext' | 'wrapped'
//     additionalSealed: ["ca.key.sealed", "tls/privkey.pem.sealed"],
//   });
//
// The list adapts to mode:
//   plain DB       → blamejs.db (the live SQLite file)
//   encrypted DB   → db.enc + db.key.enc (the at-rest envelope + sealed key)
//   plaintext vault→ vault.key
//   wrapped vault  → vault.key.sealed
function recommendedFiles(opts) {
  opts = opts || {};
  var atRest = opts.atRest || "encrypted";
  var vaultMode = opts.vaultMode || "wrapped";
  var dbName = opts.dbName || "blamejs.db";
  var files = [];

  if (atRest === "encrypted") {
    files.push({ relativePath: "db.enc",     kind: "raw", required: true });
    files.push({ relativePath: "db.key.enc", kind: "raw", required: true });
  } else {
    files.push({ relativePath: dbName,       kind: "raw", required: true });
  }

  if (vaultMode === "wrapped") {
    files.push({ relativePath: "vault.key.sealed", kind: "raw", required: true });
  } else {
    files.push({ relativePath: "vault.key", kind: "raw", required: true });
  }

  // Audit-signing key (always present; sealed in wrapped mode)
  files.push({
    relativePath: vaultMode === "wrapped" ? "audit-sign.key.sealed" : "audit-sign.key",
    kind: "raw", required: false,
  });

  // Operator-supplied additional sealed files (CA, TLS, etc.)
  if (Array.isArray(opts.additionalSealed)) {
    for (var i = 0; i < opts.additionalSealed.length; i++) {
      files.push({
        relativePath: opts.additionalSealed[i],
        kind: "vault-sealed",
        required: false,
      });
    }
  }

  return files;
}

module.exports = {
  create:           create,
  localStorage:     localStorage,
  recommendedFiles: recommendedFiles,
  BackupError:      BackupError,
  BUNDLE_ID_RE:     BUNDLE_ID_RE,
};
