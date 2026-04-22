/**
 * Centralized audit logging.
 * Every security-relevant action flows through audit.log().
 *
 * PII protection:
 *   - Emails: vault-sealed (ML-KEM-1024 + P-384 hybrid + XChaCha20-Poly1305)
 *   - IPs: SHA3-512 hashed (one-way, truncated)
 *   - User-agents: not stored
 */
var config = require("./config");
var { sha3Hash } = require("./crypto");
var { HASH_PREFIX, TIME } = require("./constants");

// Lazy-require db to avoid circular dependency (vault -> config -> audit -> db)
var _db = null;
function db() {
  if (!_db) _db = require("./db");
  return _db;
}

// ---- Action Constants ----
var ACTIONS = {
  // Auth
  LOGIN_SUCCESS: "login_success",
  LOGIN_FAILED_BAD_PASSWORD: "login_failed_bad_password",
  LOGIN_FAILED_NO_ACCOUNT: "login_failed_no_account",
  USER_REGISTERED: "user_registered",
  LOGOUT: "logout",
  AUTH_FAILED_PAGE: "auth_failed_page",

  // File operations
  BUNDLE_INITIALIZED: "bundle_initialized",
  BUNDLE_FILE_UPLOADED: "bundle_file_uploaded",
  BUNDLE_FINALIZED: "bundle_finalized",
  UPLOAD_REJECTED: "upload_rejected",

  // File management
  FILE_DOWNLOADED: "file_downloaded",
  FILE_DELETED: "file_deleted",

  // Bundle operations
  BUNDLE_VIEWED: "bundle_viewed",
  BUNDLE_FILE_DOWNLOADED: "bundle_file_downloaded",
  BUNDLE_ZIP_DOWNLOADED: "bundle_zip_downloaded",

  // Admin
  ADMIN_DASHBOARD_VIEWED: "admin_dashboard_viewed",
  ADMIN_FILE_DELETED: "admin_file_deleted",
  ADMIN_BUNDLE_DELETED: "admin_bundle_deleted",
  ADMIN_SETTINGS_VIEWED: "admin_settings_viewed",
  ADMIN_SETTINGS_CHANGED: "admin_settings_changed",

  // User management
  USER_CREATED_BY_ADMIN: "user_created_by_admin",
  USER_ROLE_CHANGED: "user_role_changed",
  USER_SUSPENDED: "user_suspended",
  USER_UNSUSPENDED: "user_unsuspended",
  USER_DELETED: "user_deleted",

  // Profile
  DISPLAY_NAME_CHANGED: "display_name_changed",
  EMAIL_CHANGED: "email_changed",
  PASSWORD_CHANGED: "password_changed",
  ACCOUNT_SELF_DELETED: "account_self_deleted",

  // System
  SERVER_STARTED: "server_started",
  DEFAULT_ADMIN_CREATED: "default_admin_created",
  VAULT_KEY_GENERATED: "vault_key_generated",

  // Cleanup
  FILE_EXPIRY_CLEANUP: "file_expiry_cleanup",
  AUDIT_RETENTION_CLEANUP: "audit_retention_cleanup",

  // Email verification
  EMAIL_VERIFICATION_SENT: "email_verification_sent",
  EMAIL_VERIFIED: "email_verified",
  EMAIL_VERIFICATION_FAILED: "email_verification_failed",
  EMAIL_VERIFICATION_RESENT: "email_verification_resent",

  // Email
  EMAIL_SENT: "email_sent",
  EMAIL_SEND_FAILED: "email_send_failed",
  EMAIL_QUOTA_EXCEEDED: "email_quota_exceeded",

  // 2FA / TOTP
  TOTP_ENABLED: "totp_enabled",
  TOTP_DISABLED: "totp_disabled",
  TOTP_FAILED: "totp_failed",

  // Passkey / WebAuthn
  PASSKEY_REGISTERED: "passkey_registered",
  PASSKEY_LOGIN_SUCCESS: "passkey_login_success",
  PASSKEY_LOGIN_FAILED: "passkey_login_failed",
  PASSKEY_REMOVED: "passkey_removed",

  // Teams
  TEAM_CREATED: "team_created",
  TEAM_DELETED: "team_deleted",
  TEAM_MEMBER_ADDED: "team_member_added",
  TEAM_MEMBER_REMOVED: "team_member_removed",

  // Security
  SUSPENDED_USER_BLOCKED: "suspended_user_blocked",
  ADMIN_ACCESS_DENIED: "admin_access_denied",
  INVALID_SESSION: "invalid_session",
  CERT_REVOKED: "cert_revoked",

  // Password reset
  PASSWORD_RESET_REQUESTED: "password_reset_requested",
  PASSWORD_RESET_SUCCESS: "password_reset_success",
  PASSWORD_RESET_FAILED: "password_reset_failed",

  // Jobs
  JOB_FAILED: "job_failed",

  // Email-gated bundle access
  BUNDLE_ACCESS_CODE_SENT: "bundle_access_code_sent",
  BUNDLE_ACCESS_CODE_VERIFIED: "bundle_access_code_verified",
  BUNDLE_ACCESS_CODE_FAILED: "bundle_access_code_failed",

  // Backup
  BACKUP_STARTED: "backup_started",
  BACKUP_COMPLETED: "backup_completed",
  BACKUP_FAILED: "backup_failed",
  BACKUP_SKIPPED: "backup_skipped",
  BACKUP_PASSPHRASE_SET: "backup_passphrase_set",

  // v1.9.9 — admin UI security actions
  VAULT_PASSPHRASE_ENABLED: "vault_passphrase_enabled",
  VAULT_PASSPHRASE_DISABLED: "vault_passphrase_disabled",
  CA_KEY_SEALED: "ca_key_sealed",
  CA_KEY_UNSEALED: "ca_key_unsealed",
  TLS_KEY_SEALED: "tls_key_sealed",
  TLS_KEY_UNSEALED: "tls_key_unsealed",

  // Restore
  RESTORE_STARTED: "restore_started",
  RESTORE_COMPLETED: "restore_completed",
  RESTORE_FAILED: "restore_failed",

  // Certificates
  CERT_RENEWED: "cert_renewed",
  CERT_REISSUED: "cert_reissued",
  ENROLLMENT_REDEEMED: "enrollment_redeemed",

  // Out-of-bounds / anomalies
  RATE_LIMIT_HIT: "rate_limit_hit",
  BLOCKED: "blocked",
};

// ---- IP extraction ----
var _rateLimit = null;
function getIp(req) {
  if (!req) return null;
  if (!_rateLimit) _rateLimit = require("./rate-limit");
  return _rateLimit.getIp(req);
}

// ---- Core log function ----

/**
 * Log an audit event.
 * @param {string} action - Action constant from ACTIONS
 * @param {object} opts
 * @param {string} [opts.targetId] - ID of affected entity
 * @param {string} [opts.targetEmail] - Email of affected entity
 * @param {string} [opts.performedBy] - User ID or "system"
 * @param {string} [opts.performedByEmail] - Email of performer
 * @param {string} [opts.details] - Human-readable summary
 * @param {object} [opts.req] - HTTP request (auto-extracts IP, user-agent, user)
 */
function log(action, opts) {
  opts = opts || {};

  // Stealth mode: skip audit for vault operations when user has stealth enabled
  if (opts.stealth || (opts.req && opts.req.user && opts.req.user.vaultStealth === "true" && opts.vaultOp)) {
    return;
  }

  // Auto-populate from req
  var performedBy = opts.performedBy || null;
  var performedByEmail = opts.performedByEmail || null;
  if (opts.req && opts.req.user && !performedBy) {
    performedBy = opts.req.user._id;
    performedByEmail = opts.req.user.email;
  }

  // Seal PII before storage
  var rawIp = opts.req ? getIp(opts.req) : null;

  var entry = {
    action: action,
    targetId: opts.targetId || null,
    targetEmail: opts.targetEmail || null,
    performedBy: performedBy,
    performedByEmail: performedByEmail,
    details: opts.details || null,
    createdAt: new Date().toISOString(),
    ip: rawIp ? sha3Hash(HASH_PREFIX.IP + rawIp).substring(0, 16) : null,
  };

  try {
    db().auditLog.insert(entry);
  } catch (e) {
    // If DB isn't ready yet (during startup), log to console
    console.error("[audit]", action, opts.details || "", e.message);
  }
}

// ---- Retention cleanup ----
function startRetentionCleanup() {
  var days = parseInt(config.auditRetentionDays, 10) || 0;
  if (days <= 0) return;

  function cleanup() {
    try {
      var cutoff = new Date(Date.now() - days * TIME.ONE_DAY).toISOString();
      // Use raw SQL — the ORM doesn't support $lt operator
      var result = db().rawExec("DELETE FROM audit_log WHERE createdAt < ?", cutoff);
      var removed = result.changes || 0;
      if (removed > 0) log(ACTIONS.AUDIT_RETENTION_CLEANUP, { performedBy: "system", details: "Audit retention: removed " + removed + " entries older than " + days + " days" });
    } catch (_e) { /* ignore during startup */ }
  }

  // Run on start + every 24 hours
  setTimeout(cleanup, 5000);
  var timer = setInterval(cleanup, TIME.ONE_DAY);
  timer.unref();
}

// Start retention if configured (deferred to avoid circular dep)
process.nextTick(startRetentionCleanup);

/**
 * Unseal a raw audit log entry for inspection/testing.
 * Returns a copy with all sealed fields decrypted.
 */
function unsealEntry(entry) {
  if (!entry) return entry;
  var fieldCrypto = require("./field-crypto");
  return fieldCrypto.unsealDoc("audit_log", Object.assign({}, entry));
}

module.exports = { log: log, ACTIONS: ACTIONS, unsealEntry: unsealEntry };
