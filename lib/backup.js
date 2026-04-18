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

var path = require("path");
var { Worker } = require("worker_threads");
var config = require("./config");
var audit = require("./audit");
var argon2 = require("./vendor/argon2");
var S3Client = require("./s3-client");
var { sha3Hash } = require("./crypto");

var DATA_DIR = require("./constants").DATA_DIR;

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
  return require("./storage").uploadDir;
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

function runBackup(passphrase) {
  if (_operationRunning) return Promise.reject(new Error("A backup or restore is already in progress."));
  _operationRunning = true;
  return new Promise(function (resolve, reject) {
    audit.log(audit.ACTIONS.BACKUP_STARTED, {
      performedBy: "system",
      details: "Backup started: scope=" + (config.backup.scope || "db"),
    });

    var worker = new Worker(path.join(__dirname, "backup-worker.js"), {
      workerData: {
        passphrase: passphrase,
        dataDir: DATA_DIR,
        s3Config: backupS3Config(),
        scope: config.backup.scope || "db",
        retention: config.backup.retention || 7,
        storageBackend: config.storage && config.storage.backend || "local",
        s3StorageConfig: storageS3Config(),
        uploadDir: resolveUploadDir(),
        version: require("./constants").version,
      },
    });

    var settled = false;

    worker.on("message", function (msg) {
      if (settled) return;
      settled = true;
      _operationRunning = false;
      if (msg.error) {
        audit.log(audit.ACTIONS.BACKUP_FAILED, {
          performedBy: "system",
          details: "Backup failed: " + msg.error,
        });
        reject(new Error(msg.error));
      } else {
        var manifest = msg.manifest;
        audit.log(audit.ACTIONS.BACKUP_COMPLETED, {
          performedBy: "system",
          details: "Backup completed: " + manifest.stats.dbFiles + " db files, " +
            manifest.stats.uploadFiles + " upload files, " +
            (manifest.stats.totalSize / 1048576).toFixed(1) + " MB, " +
            manifest.stats.durationMs + " ms",
        });
        resolve(manifest);
      }
    });

    worker.on("error", function (err) {
      if (settled) return;
      settled = true;
      _operationRunning = false;
      audit.log(audit.ACTIONS.BACKUP_FAILED, {
        performedBy: "system",
        details: "Backup worker crashed: " + err.message,
      });
      reject(err);
    });

    worker.on("exit", function (code) {
      _operationRunning = false;
      if (settled) return;
      if (code !== 0) {
        settled = true;
        var err = new Error("Backup worker exited with code " + code);
        audit.log(audit.ACTIONS.BACKUP_FAILED, {
          performedBy: "system",
          details: err.message,
        });
        reject(err);
      }
    });
  });
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
      var m = JSON.parse(data.toString("utf8"));
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
      var m = JSON.parse(data.toString("utf8"));
      if (m.timestamp === timestamp) return m;
    } catch (_e) {}
  }
  return null;
}

// ---- Restore (worker thread) ----

function runRestore(passphrase, timestamp) {
  if (_operationRunning) return Promise.reject(new Error("A backup or restore is already in progress."));
  _operationRunning = true;
  return new Promise(function (resolve, reject) {
    audit.log(audit.ACTIONS.RESTORE_STARTED, {
      performedBy: "system",
      details: "Restore started from backup: " + timestamp,
    });

    var worker = new Worker(path.join(__dirname, "restore-worker.js"), {
      workerData: {
        passphrase: passphrase,
        timestamp: timestamp,
        dataDir: DATA_DIR,
        uploadDir: resolveUploadDir(),
        s3Config: backupS3Config(),
        scope: "full",
        currentStorageBackend: config.storage && config.storage.backend || "local",
        s3StorageConfig: storageS3Config(),
      },
    });

    var lastProgress = null;
    var settled = false;

    worker.on("message", function (msg) {
      if (msg.type === "progress") {
        lastProgress = msg;
      } else if (msg.type === "error") {
        if (settled) return;
        settled = true;
        _operationRunning = false;
        audit.log(audit.ACTIONS.RESTORE_FAILED, {
          performedBy: "system",
          details: "Restore failed: " + msg.error,
        });
        reject(new Error(msg.error));
      } else if (msg.type === "success") {
        if (settled) return;
        settled = true;
        _operationRunning = false;
        audit.log(audit.ACTIONS.RESTORE_COMPLETED, {
          performedBy: "system",
          details: "Restore completed: " + (msg.stats ? msg.stats.dbFiles + " db files, " + msg.stats.uploadFiles + " upload files" : "success"),
        });
        resolve({ success: true, stats: msg.stats, lastProgress: lastProgress });
      }
    });

    worker.on("error", function (err) {
      if (settled) return;
      settled = true;
      _operationRunning = false;
      audit.log(audit.ACTIONS.RESTORE_FAILED, {
        performedBy: "system",
        details: "Restore worker crashed: " + err.message,
      });
      reject(err);
    });

    worker.on("exit", function (code) {
      _operationRunning = false;
      if (settled) return;
      if (code !== 0) {
        settled = true;
        var err = new Error("Restore worker exited with code " + code);
        audit.log(audit.ACTIONS.RESTORE_FAILED, {
          performedBy: "system",
          details: err.message,
        });
        reject(err);
      }
    });
  });
}

// ---- Verify passphrase ----

async function verifyPassphrase(passphrase) {
  if (!config.backup.passphraseHash) return false;
  return argon2.verify(config.backup.passphraseHash, passphrase);
}

module.exports = { runBackup: runBackup, runRestore: runRestore, isOperationRunning: isOperationRunning, getBackupHistory: getBackupHistory, getBackupManifest: getBackupManifest, testConnection: testConnection, verifyPassphrase: verifyPassphrase, getBackend: getBackend };
