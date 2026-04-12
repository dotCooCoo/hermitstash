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

var DATA_DIR = path.join(__dirname, "..", "data");

// ---- Backend factory (for lightweight main-thread ops) ----

function getBackend(overrideConfig) {
  var cfg = overrideConfig || config.backup.s3;
  if (!cfg.bucket || !cfg.accessKey || !cfg.secretKey) {
    throw new Error("Backup S3 credentials not configured");
  }
  return new S3Client(cfg);
}

// ---- Run backup (worker thread) ----

function runBackup(passphrase) {
  return new Promise(function (resolve, reject) {
    audit.log(audit.ACTIONS.BACKUP_STARTED, {
      performedBy: "system",
      details: "Backup started: scope=" + (config.backup.scope || "db"),
    });

    var uploadDir = config.storage && config.storage.uploadDir
      ? (path.isAbsolute(config.storage.uploadDir)
          ? config.storage.uploadDir
          : path.resolve(__dirname, "..", config.storage.uploadDir))
      : path.resolve(__dirname, "..", "uploads");

    var worker = new Worker(path.join(__dirname, "backup-worker.js"), {
      workerData: {
        passphrase: passphrase,
        dataDir: DATA_DIR,
        s3Config: {
          bucket: config.backup.s3.bucket,
          region: config.backup.s3.region,
          accessKey: config.backup.s3.accessKey,
          secretKey: config.backup.s3.secretKey,
          endpoint: config.backup.s3.endpoint,
        },
        scope: config.backup.scope || "db",
        retention: config.backup.retention || 7,
        storageBackend: config.storage && config.storage.backend || "local",
        uploadDir: uploadDir,
        version: require("./constants").version,
      },
    });

    worker.on("message", function (msg) {
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
      audit.log(audit.ACTIONS.BACKUP_FAILED, {
        performedBy: "system",
        details: "Backup worker crashed: " + err.message,
      });
      reject(err);
    });

    worker.on("exit", function (code) {
      if (code !== 0) {
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
      history.push({ timestamp: m.timestamp, scope: m.scope, version: m.hermitstashVersion, dbFiles: m.stats.dbFiles, uploadFiles: m.stats.uploadFiles, totalSize: m.stats.totalSize, durationMs: m.stats.durationMs, status: "completed" });
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

// ---- Verify passphrase ----

async function verifyPassphrase(passphrase) {
  if (!config.backup.passphraseHash) return false;
  return argon2.verify(config.backup.passphraseHash, passphrase);
}

module.exports = { runBackup: runBackup, getBackupHistory: getBackupHistory, testConnection: testConnection, verifyPassphrase: verifyPassphrase, getBackend: getBackend };
