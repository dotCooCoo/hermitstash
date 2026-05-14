"use strict";

/**
 * Backup module — encrypted off-site backups to S3-compatible storage.
 *
 * Heavy work (Argon2id, file I/O, S3 uploads) runs in a worker thread
 * via backup-worker.js to avoid blocking the main event loop.
 *
 * Lightweight operations (testConnection, getBackupHistory, verifyPassphrase)
 * remain on the main thread.
 */

var nodePath = require("node:path");
var b = require("./vendor/blamejs");
var config = require("./config");
var audit = require("./audit");
var S3Client = require("./s3-client");

var C = require("./constants");
var DATA_DIR = C.DATA_DIR;
var PATHS = C.PATHS;

// Lazy-load to break circular dependencies (backup ↔ vault/db/storage
// — vault.init writes through backup; db loads vault; storage holds the
// uploadDir backup reads).
var storageLazy = b.lazyRequire(function () { return require("./storage"); });
var vaultLazy   = b.lazyRequire(function () { return require("./vault"); });
var dbLazy      = b.lazyRequire(function () { return require("./db"); });

// Paths that workers need — resolved here so the filename strings live in one
// place (lib/constants.js) rather than being re-derived inside worker code.
function workerPaths() {
  return {
    dataDir: DATA_DIR,
    vaultKey: PATHS.VAULT_KEY,
    dbEnc: PATHS.DB_ENC,
    dbKeyEnc: PATHS.DB_KEY_ENC,
    caKey: PATHS.CA_KEY,
    caCert: PATHS.CA_CERT,
    tlsDir: PATHS.TLS_DIR,
  };
}

// ---- Backend factory (for lightweight main-thread ops) ----

function getBackend(overrideConfig) {
  var cfg = overrideConfig || config.backup.s3;
  if (!cfg.bucket || !cfg.accessKey || !cfg.secretKey) {
    throw new Error("Backup S3 credentials not configured");
  }
  return new S3Client(cfg);
}

// ---- Operation lock (prevents concurrent backup/restore) ----

var _operationRunning = false;
function isOperationRunning() { return _operationRunning; }

// ---- Shared helpers ----

function resolveUploadDir() {
  return storageLazy().uploadDir;
}

function backupS3Config() {
  return {
    bucket: config.backup.s3.bucket, region: config.backup.s3.region,
    accessKey: config.backup.s3.accessKey, secretKey: config.backup.s3.secretKey,
    endpoint: config.backup.s3.endpoint,
  };
}

function storageS3Config() {
  var s = config.storage && config.storage.s3;
  if (!s || !s.bucket) return null;
  return { bucket: s.bucket, region: s.region, accessKey: s.accessKey, secretKey: s.secretKey, endpoint: s.endpoint };
}

// ---- Run backup (worker thread) ----

async function runBackup(passphrase) {
  if (_operationRunning) throw new Error("A backup or restore is already in progress.");
  _operationRunning = true;
  audit.log(audit.ACTIONS.BACKUP_STARTED, {
    performedBy: "system",
    details: "Backup started: scope=" + (config.backup.scope || "db"),
  });

  // Pass the in-memory vault keys JSON to the worker. In wrapped mode
  // (VAULT_PASSPHRASE_MODE=required) the plaintext vault.key doesn't
  // exist on disk — only vault.key.sealed — so the worker can't read it.
  // Capturing the keys here via vault.getKeysJson() lets the worker
  // encrypt them for backup without needing to unwrap independently.
  var vaultKeyJson = vaultLazy().getKeysJson();

  // Produce an up-to-date encrypted DB snapshot on demand. This fixes:
  //   - Test mode (HERMITSTASH_DB_PATH set → encPath=null): encryptDbFile
  //     is a no-op; without this snapshot backup has no DB content.
  //   - Production: the periodic 5-minute encrypt may not have fired
  //     since the last write, so PATHS.dbEnc could be stale.
  // snapshotEncryptedDb checkpoints the WAL first, guaranteeing the
  // snapshot reflects all committed transactions.
  var dbEncSnapshot = dbLazy().snapshotEncryptedDb();

  // b.backup.runInWorker handles the worker spawn, single-message
  // settle, error/exit dispatch, and (optional) timeout. The backup
  // worker posts exactly one final message — `{ manifest }` on
  // success or `{ error }` on failure — which fits this single-shot
  // contract.
  var msg;
  try {
    msg = await b.backup.runInWorker({
      workerScript: nodePath.join(__dirname, "backup-worker.js"),
      args: {
        passphrase: passphrase,
        paths: workerPaths(),
        vaultKeyJson: vaultKeyJson,
        dbEncSnapshot: dbEncSnapshot,
        s3Config: backupS3Config(),
        scope: config.backup.scope || "db",
        retention: config.backup.retention || 7,
        storageBackend: config.storage && config.storage.backend || "local",
        s3StorageConfig: storageS3Config(),
        uploadDir: resolveUploadDir(),
        version: C.version,
      },
    });
  } catch (err) {
    _operationRunning = false;
    audit.log(audit.ACTIONS.BACKUP_FAILED, {
      performedBy: "system",
      details: "Backup worker crashed: " + err.message,
    });
    throw err;
  }
  _operationRunning = false;

  if (msg && msg.error) {
    audit.log(audit.ACTIONS.BACKUP_FAILED, {
      performedBy: "system",
      details: "Backup failed: " + msg.error,
    });
    throw new Error(msg.error);
  }

  var manifest = msg.manifest;
  audit.log(audit.ACTIONS.BACKUP_COMPLETED, {
    performedBy: "system",
    details: "Backup completed: " + manifest.stats.dbFiles + " db files, " +
      manifest.stats.uploadFiles + " upload files, " +
      (manifest.stats.totalSize / 1048576).toFixed(1) + " MB, " + // allow:raw-byte-literal — display size threshold
      manifest.stats.durationMs + " ms",
  });
  return manifest;
}

// ---- History (lightweight, stays on main thread) ----

async function getBackupHistory() {
  var backend = getBackend();
  var allKeys = await backend.list("backups/");
  var manifestKeys = allKeys.filter(function (k) { return k.endsWith("/manifest.json"); }).sort().reverse();

  var history = [];
  for (var i = 0; i < Math.min(manifestKeys.length, 20); i++) {
    try {
      var data = await backend.getBuffer(manifestKeys[i]);
      var m = b.safeJson.parse(data.toString("utf8"));
      history.push({ timestamp: m.timestamp, scope: m.scope, version: m.hermitstashVersion, storageBackend: m.storageBackend || null, storageBucket: m.storageBucket || null, dbFiles: m.stats.dbFiles, uploadFiles: m.stats.uploadFiles, totalSize: m.stats.totalSize, durationMs: m.stats.durationMs, status: "completed" });
    } catch (_e) {
      history.push({ timestamp: manifestKeys[i], status: "corrupt" });
    }
  }
  return history;
}

// ---- Test connection (lightweight, stays on main thread) ----

async function testConnection(s3Config) {
  var client = new S3Client(s3Config);
  await client.testConnection();
  return true;
}

// ---- Get manifest header for a specific backup ----

async function getBackupManifest(timestamp) {
  var backend = getBackend();
  var allKeys = await backend.list("backups/");
  var manifestKeys = allKeys.filter(function (k) { return k.endsWith("/manifest.json"); }).sort();
  for (var i = 0; i < manifestKeys.length; i++) {
    try {
      var data = await backend.getBuffer(manifestKeys[i]);
      var m = b.safeJson.parse(data.toString("utf8"));
      if (m.timestamp === timestamp) return m;
    } catch (_e) { /* skip corrupt/unreadable manifests — continue scanning */ }
  }
  return null;
}

// ---- Restore (worker thread) ----

async function runRestore(passphrase, timestamp, opts) {
  if (_operationRunning) throw new Error("A backup or restore is already in progress.");
  _operationRunning = true;
  var dryRun = !!(opts && opts.dryRun);
  audit.log(audit.ACTIONS.RESTORE_STARTED, {
    performedBy: "system",
    details: "Restore started from backup: " + timestamp + (dryRun ? " (dry-run)" : ""),
  });

  // In wrapped mode, restore must re-wrap the extracted plaintext vault
  // key with the CURRENT server's passphrase before writing to disk —
  // otherwise we'd create both vault.key and vault.key.sealed, triggering
  // the boot-time invariant-violation abort on next restart. vault.init()
  // retains the passphrase in memory for exactly this reason.
  var wrapMode = (b.safeEnv.readVar("VAULT_PASSPHRASE_MODE", { default: "disabled" })).toLowerCase();
  var currentVaultPassphrase = null;
  if (wrapMode === "required" && !dryRun) {
    // getCurrentPassphrase returns a Buffer; workerData is structured-cloned
    // so the Buffer survives the worker postMessage.
    currentVaultPassphrase = vaultLazy().getCurrentPassphrase();
  }

  // restore-worker posts exactly one final message — `{ type: "success",
  // stats }` or `{ type: "error", error }` — which fits b.backup.runInWorker's
  // single-message contract. Step-level progress events log to the worker's
  // stdout for operator visibility; the parent doesn't stream them anywhere.
  var msg;
  try {
    msg = await b.backup.runInWorker({
      workerScript: nodePath.join(__dirname, "restore-worker.js"),
      args: {
        passphrase: passphrase,
        timestamp: timestamp,
        paths: workerPaths(),
        uploadDir: resolveUploadDir(),
        s3Config: backupS3Config(),
        scope: "full",
        currentStorageBackend: config.storage && config.storage.backend || "local",
        s3StorageConfig: storageS3Config(),
        dryRun: dryRun,
        vaultPassphraseMode: wrapMode,
        currentVaultPassphrase: currentVaultPassphrase,
      },
    });
  } catch (err) {
    _operationRunning = false;
    audit.log(audit.ACTIONS.RESTORE_FAILED, {
      performedBy: "system",
      details: "Restore worker crashed: " + err.message,
    });
    throw err;
  }
  _operationRunning = false;

  if (msg && msg.type === "error") {
    audit.log(audit.ACTIONS.RESTORE_FAILED, {
      performedBy: "system",
      details: "Restore failed: " + msg.error,
    });
    throw new Error(msg.error);
  }

  audit.log(audit.ACTIONS.RESTORE_COMPLETED, {
    performedBy: "system",
    details: "Restore completed: " + (msg.stats ? msg.stats.dbFiles + " db files, " + msg.stats.uploadFiles + " upload files" : "success"),
  });
  return { success: true, stats: msg.stats };
}

// ---- Verify passphrase ----

async function verifyPassphrase(passphrase) {
  if (!config.backup.passphraseHash) return false;
  return b.auth.password.verify(config.backup.passphraseHash, String(passphrase));
}

// ---- Last attempt tracking + admin status surface ----
//
// The scheduled backup job records the outcome of every tick (skipped/failed/
// completed with reason) into the settings table under SCHEDULED_BACKUP_LAST_
// ATTEMPT. The admin UI's GET /admin/backup/history calls getBackupStatus()
// to surface this — closes the v1.9.3-era silent-failure gap where backups
// would silently no-op every 12h with no visibility.

var LAST_ATTEMPT_KEY = "SCHEDULED_BACKUP_LAST_ATTEMPT";

function setLastBackupAttempt(attempt) {
  var db = dbLazy();
  var existing = db.settings.findOne({ key: LAST_ATTEMPT_KEY });
  var serialized = JSON.stringify(attempt);
  if (existing) {
    db.settings.update({ key: LAST_ATTEMPT_KEY }, { $set: { value: serialized, updatedAt: new Date().toISOString() } });
  } else {
    db.settings.insert({ _id: LAST_ATTEMPT_KEY, key: LAST_ATTEMPT_KEY, value: serialized, updatedAt: new Date().toISOString() });
  }
}

function getLastBackupAttempt() {
  var db = dbLazy();
  var row = db.settings.findOne({ key: LAST_ATTEMPT_KEY });
  if (!row || !row.value) return null;
  try { return JSON.parse(row.value); } catch (_e) { return null; } // allow:bare-json-parse — parsing JSON we wrote in this same module to settings.value
}

// Admin-UI-facing status: derives "is the backup feature actually able to
// run right now?" from current config + last attempt. Used by GET
// /admin/backup/history to surface diagnostics like "backups are silently
// skipping because there's no passphrase configured."
function getBackupStatus() {
  var enabled = !!config.backup.enabled;
  var hasBucket = !!(config.backup.s3 && config.backup.s3.bucket);
  var hasCreds = !!(config.backup.s3 && config.backup.s3.accessKey && config.backup.s3.secretKey);
  var hasPassphrase = !!config.backup.passphrase;

  var configured = enabled && hasBucket && hasCreds && hasPassphrase;
  var blocked = enabled && !configured;
  var blockedReason = null;
  if (blocked) {
    var reasons = [];
    if (!hasBucket) reasons.push("BACKUP_S3_BUCKET is not set");
    if (!hasCreds) reasons.push("BACKUP_S3_ACCESS_KEY / BACKUP_S3_SECRET_KEY are not set");
    if (!hasPassphrase) reasons.push("BACKUP_PASSPHRASE is not set");
    blockedReason = reasons.join("; ");
  }

  return {
    enabled: enabled,
    configured: configured,
    blocked: blocked,
    blockedReason: blockedReason,
    lastAttempt: getLastBackupAttempt(),
  };
}

module.exports = {
  runBackup: runBackup,
  runRestore: runRestore,
  isOperationRunning: isOperationRunning,
  getBackupHistory: getBackupHistory,
  getBackupManifest: getBackupManifest,
  testConnection: testConnection,
  verifyPassphrase: verifyPassphrase,
  getBackend: getBackend,
  setLastBackupAttempt: setLastBackupAttempt,
  getLastBackupAttempt: getLastBackupAttempt,
  getBackupStatus: getBackupStatus,
};
