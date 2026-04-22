"use strict";

/**
 * Backup Job — scheduled off-site backup to S3-compatible storage.
 * Registered as a scheduled task in server.js.
 *
 * Reads the backup passphrase from vault-sealed config, runs the
 * backup with the configured scope, and logs success/failure.
 *
 * Every skip/failure also writes:
 *   - an audit log entry (BACKUP_SKIPPED or BACKUP_FAILED)
 *   - a `lastBackupAttempt` row in the settings table (timestamp + status
 *     + reason) so the admin UI can surface "backups have been silently
 *     skipping for X days" instead of just "No backups found"
 */

var logger = require("../shared/logger");
var config = require("../../lib/config");
var vault = require("../../lib/vault");
var backup = require("../../lib/backup");
var audit = require("../../lib/audit");

// `lastBackupAttempt` is stored in the settings table as a vault-sealed
// JSON blob keyed under SCHEDULED_BACKUP_LAST_ATTEMPT. Helpers in lib/backup.js
// read/write it; the admin UI's GET /admin/backup/history surfaces it.
function recordAttempt(status, reason, extra) {
  try {
    backup.setLastBackupAttempt({
      timestamp: new Date().toISOString(),
      status: status,           // "skipped" | "failed" | "completed"
      reason: reason || null,   // human-readable
      stats: extra || null,     // { dbFiles, uploadFiles, totalSize, durationMs } on success
    });
  } catch (e) {
    logger.error("[backup] Could not persist lastBackupAttempt", { error: e.message });
  }
}

async function run() {
  // Operator-disabled: NOT a problem state. No audit, no lastBackupAttempt
  // record — there's nothing to surface to a UI in a meaningful way, and
  // recording every disabled tick would spam the audit log.
  if (!config.backup.enabled) return;

  // Backup enabled but no S3 bucket — misconfiguration. Surface it.
  if (!config.backup.s3.bucket) {
    var s3Reason = "Backup is enabled but BACKUP_S3_BUCKET is not configured.";
    logger.error("[backup] Skipping — " + s3Reason);
    audit.log(audit.ACTIONS.BACKUP_SKIPPED, { performedBy: "system", details: s3Reason });
    recordAttempt("skipped", s3Reason);
    return;
  }

  // Concurrency guard — transient, not a misconfiguration. Log only.
  if (backup.isOperationRunning()) {
    logger.info("[backup] Skipping — another backup or restore is in progress");
    return;
  }

  // The passphrase is vault-sealed in settings for scheduled runs
  var passphrase = config.backup.passphrase;
  if (passphrase) {
    try { passphrase = vault.unseal(passphrase); } catch (_e) { /* not sealed — treat as plaintext (legacy config) */ }
  }

  if (!passphrase) {
    var pwReason = "Backup is enabled but no passphrase is configured. Set BACKUP_PASSPHRASE in the admin Backup section.";
    logger.error("[backup] Skipping — " + pwReason);
    audit.log(audit.ACTIONS.BACKUP_SKIPPED, { performedBy: "system", details: pwReason });
    recordAttempt("skipped", pwReason);
    return;
  }

  try {
    var manifest = await backup.runBackup(passphrase);
    logger.info("[backup] Completed", { dbFiles: manifest.stats.dbFiles, uploadFiles: manifest.stats.uploadFiles, totalMB: (manifest.stats.totalSize / 1048576).toFixed(1), durationMs: manifest.stats.durationMs });
    recordAttempt("completed", null, manifest.stats);
  } catch (err) {
    logger.error("[backup] Failed", { error: err.message });
    recordAttempt("failed", err.message);
  }
}

module.exports = { run: run };
