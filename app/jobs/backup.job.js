"use strict";

/**
 * Backup Job — scheduled off-site backup to S3-compatible storage.
 * Registered as a scheduled task in server.js.
 *
 * Reads the backup passphrase from vault-sealed config, runs the
 * backup with the configured scope, and logs success/failure.
 */

var config = require("../../lib/config");
var vault = require("../../lib/vault");
var backup = require("../../lib/backup");

async function run() {
  if (!config.backup.enabled) return;
  if (!config.backup.s3.bucket) return;

  // The passphrase is vault-sealed in settings for scheduled runs
  var passphrase = config.backup.passphrase;
  if (passphrase) {
    try { passphrase = vault.unseal(passphrase); } catch (_e) {}
  }
  if (!passphrase) {
    console.error("[backup] No backup passphrase configured — skipping scheduled backup");
    return;
  }

  try {
    var manifest = await backup.runBackup(passphrase);
    console.log("[backup] Completed: " + manifest.stats.dbFiles + " db files, " +
      manifest.stats.uploadFiles + " upload files, " +
      (manifest.stats.totalSize / 1048576).toFixed(1) + " MB in " +
      manifest.stats.durationMs + " ms");
  } catch (err) {
    console.error("[backup] Failed:", err.message);
  }
}

module.exports = { run: run };
