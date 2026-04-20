"use strict";

/**
 * Backup Job — scheduled off-site backup to S3-compatible storage.
 * Registered as a scheduled task in server.js.
 *
 * Reads the backup passphrase from vault-sealed config, runs the
 * backup with the configured scope, and logs success/failure.
 */

var logger = require("../shared/logger");
var config = require("../../lib/config");
var vault = require("../../lib/vault");
var backup = require("../../lib/backup");

async function run() {
  if (!config.backup.enabled) return;
  if (!config.backup.s3.bucket) return;
  if (backup.isOperationRunning()) { logger.info("[backup] Skipping — another backup or restore is in progress"); return; }

  // The passphrase is vault-sealed in settings for scheduled runs
  var passphrase = config.backup.passphrase;
  if (passphrase) {
    try { passphrase = vault.unseal(passphrase); } catch (_e) { /* not sealed — treat as plaintext (legacy config) */ }
  }
  if (!passphrase) {
    logger.error("[backup] No backup passphrase configured — skipping scheduled backup");
    return;
  }

  try {
    var manifest = await backup.runBackup(passphrase);
    logger.info("[backup] Completed", { dbFiles: manifest.stats.dbFiles, uploadFiles: manifest.stats.uploadFiles, totalMB: (manifest.stats.totalSize / 1048576).toFixed(1), durationMs: manifest.stats.durationMs });
  } catch (err) {
    logger.error("[backup] Failed", { error: err.message });
  }
}

module.exports = { run: run };
