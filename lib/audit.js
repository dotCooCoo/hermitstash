/**
 * Centralized audit logging.
 * Every security-relevant action flows through audit.log().
 *
 * PII protection:
 *   - Emails: vault-sealed (ML-KEM-1024 + P-384 hybrid + XChaCha20-Poly1305)
 *   - IPs: SHA3-512 hashed (one-way, truncated)
 *   - User-agents: not stored
 */
var clientIp = require("../lib/client-ip");
var config = require("./config");
var b = require("./vendor/blamejs");
var logger = require("../app/shared/logger");
var C = require("./constants");
var { HASH_PREFIX, TIME } = C;

// Lazy-require db / field-crypto to avoid circular dependency
// (vault -> config -> audit -> db; field-crypto -> audit on unseal paths).
var db = b.lazyRequire(function () { return require("./db"); });
var fieldCryptoLazy = b.lazyRequire(function () { return require("./field-crypto"); });

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
  ADMIN_FENCE_DENIED: "admin_fence_denied",

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
  STASH_MEMBER_ADDED: "stash_member_added",
  STASH_MEMBER_REMOVED: "stash_member_removed",

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
function getIp(req) {
  if (!req) return null;
  return clientIp.getIp(req);
}

// ---- Tamper-evidence chain (opt-in via config.auditChainEnabled) ----
//
// When enabled, every audit row carries a hash chain: rowHash =
// SHA3-512(prevHash || canonicalize(stored-row-fields) || nonce), with each
// row's prevHash equal to the previous row's rowHash in monotonicCounter order
// (first row anchors on b.auditChain.ZERO_HASH). b.auditChain owns the math;
// this module owns the HS-side append (seal the row first so the chain hashes
// the AT-REST representation, then insert) and the query callbacks the verifier
// reuses.
//
// HermitStash serves requests from ONE process (only the backup/restore workers
// spawn, and they don't write audit rows), so an in-process promise-chain
// serializer is sufficient to keep getChainTip → computeRowHash → insert atomic
// per append. Without it two concurrent appends would read the same tip and
// fork the chain.
var _chainTail = Promise.resolve();

// Physical column set of audit_log (read once, lazily). Used to materialize a
// null for every stored column so the row we HASH carries the same key set the
// verifier reads back via `SELECT *` — JSON canonicalization distinguishes a
// missing key from key:null, so the sets must match exactly. prevHash / rowHash
// / nonce are excluded from the hashable set (they're the chain envelope, set
// after the hash is computed).
var _CHAIN_ENVELOPE_COLS = ["prevHash", "rowHash", "nonce"];
var _physColsCache = null;
function _auditPhysicalColumns() {
  if (_physColsCache) return _physColsCache;
  var info = db().rawQuery("PRAGMA table_info(audit_log)");
  _physColsCache = info.map(function (c) { return c.name; });
  return _physColsCache;
}

// queryOne / queryAll callbacks for b.auditChain.{getChainTip,verifyChain}.
// The primitives emit bare-table SQL with `?` placeholders; HS runs single-node
// SQLite, so we execute the SQL against the local DB. Exported so the verify
// service walks the SAME chain these appends write.
//
// Because the chain is OPT-IN, a DB enabled mid-life can hold historical rows
// that predate the chain (monotonicCounter / prevHash / rowHash / nonce all
// NULL). Those rows are not chain members; left in, they sort first under
// `ORDER BY monotonicCounter ASC` and the verifier would treat a NULL prevHash
// as a chain break. Scope the audit_log read to chained rows only so the walk
// starts at the genuine chain origin. (The anchor-table read targets a
// different table and is passed through untouched.)
function _scopeAuditRows(sql) {
  if (/\bFROM\s+audit_log\b/i.test(sql) && !/\bWHERE\b/i.test(sql)) {
    // Inject the chain-member filter ahead of ORDER BY / LIMIT, or append it.
    // A bare SELECT (no ORDER BY) must still get the WHERE, otherwise pre-chain
    // rows (monotonicCounter NULL) leak into the verifier and break the anchor.
    if (/\bORDER\s+BY\b/i.test(sql)) {
      return sql.replace(/\bORDER\s+BY\b/i, "WHERE monotonicCounter IS NOT NULL ORDER BY");
    }
    if (/\bLIMIT\b/i.test(sql)) {
      return sql.replace(/\bLIMIT\b/i, "WHERE monotonicCounter IS NOT NULL LIMIT");
    }
    return sql + " WHERE monotonicCounter IS NOT NULL";
  }
  return sql;
}
async function _chainQueryOne(sql, params) {
  return db().rawGet.apply(null, [_scopeAuditRows(sql)].concat(params || []));
}
async function _chainQueryAll(sql, params) {
  return db().rawQuery.apply(null, [_scopeAuditRows(sql)].concat(params || []));
}

// Append one already-built (plaintext) entry as a chained row. Runs inside the
// serializer so the tip read + hash + insert can't interleave with another
// append. Seals the row first (so the stored, at-rest values are what gets
// hashed), materializes every physical column so write-time and verify-time
// canonicalization see an identical key set, computes rowHash, then inserts the
// fully-sealed row WITHOUT re-sealing (raw()).
async function appendChained(entry) {
  var tip = await b.auditChain.getChainTip(_chainQueryOne, "audit_log");
  var counter = (tip.counter || 0) + 1;
  var nonce = b.crypto.generateBytes(C.BYTES.bytes(16));

  // Seal PII to the at-rest form, binding the AEAD tag to the row _id.
  var sealed = fieldCryptoLazy().sealDoc("audit_log", Object.assign({ monotonicCounter: counter }, entry), entry._id);

  // Materialize a null for every physical column (except the chain envelope) so
  // the hashable key set matches the `SELECT *` read-back the verifier walks.
  var hashable = {};
  var cols = _auditPhysicalColumns();
  for (var i = 0; i < cols.length; i++) {
    var col = cols[i];
    if (_CHAIN_ENVELOPE_COLS.indexOf(col) !== -1) continue;
    hashable[col] = (col in sealed && sealed[col] !== undefined) ? sealed[col] : null;
  }
  // The ORM stores a null `data` overflow column on every row; include it so the
  // recompute over the read-back row matches.
  if (cols.indexOf("data") !== -1) hashable.data = (sealed.data !== undefined ? sealed.data : null);

  var rowHash = b.auditChain.computeRowHash(tip.prevHash, hashable, nonce);

  // Insert the sealed row + chain envelope. raw() skips re-sealing (already
  // sealed); _split routes the chain columns (now in COLUMNS.audit_log) to real
  // columns and sets data=null exactly as the hashable set assumed.
  var storeRow = Object.assign({}, sealed, {
    prevHash: tip.prevHash,
    rowHash: rowHash,
    nonce: nonce,
  });
  db().auditLog.raw().insert(storeRow);
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
    // _id generated up front so it's part of the chain hash + AAD identity.
    _id: b.crypto.generateToken(C.BYTES.bytes(32)),
    action: action,
    targetId: opts.targetId || null,
    targetEmail: opts.targetEmail || null,
    performedBy: performedBy,
    performedByEmail: performedByEmail,
    details: opts.details || null,
    createdAt: new Date().toISOString(),
    // allow:raw-byte-literal — fixed 16-hex-char IP-hash truncation for storage
    ip: rawIp ? b.crypto.namespaceHash(HASH_PREFIX.IP, rawIp).substring(0, 16) : null,
  };

  // Chain-enabled write path: serialize the tip-read + hash + insert through the
  // module-level promise chain. log() stays sync/fire-and-forget — the caller is
  // not awaited; failures are logged, never thrown back into the caller.
  if (config.auditChainEnabled) {
    _chainTail = _chainTail.then(function () {
      return appendChained(entry);
    }).catch(function (e) {
      logger.error("[audit] chained insert failed", { action: action, err: e && e.message });
    });
    return;
  }

  try {
    db().auditLog.insert(entry);
  } catch (e) {
    // If DB isn't ready yet (during startup), log via structured logger. Do NOT
    // echo opts.details here — the audit detail can carry sensitive freeform text
    // (reset tokens, emails) and a DB-insert failure is diagnosable from the
    // action + error alone, so the content must not land in plaintext stderr.
    logger.error("[audit] insert failed", { action: action, err: e.message });
  }
}

// Test/diagnostic helper: await the in-flight chain serializer so a caller can
// observe every queued chained append after it returns. No-op when the chain is
// disabled (appends are synchronous in that path).
function drainChain() {
  return _chainTail;
}

// ---- Retention cleanup ----
function startRetentionCleanup() {
  var days = parseInt(config.auditRetentionDays, 10) || 0;
  if (days <= 0) return;

  function cleanup() {
    try {
      var cutoff = new Date(Date.now() - days * TIME.days(1)).toISOString();

      // Chain-enabled retention must move the chain origin before deleting the
      // oldest rows, or verifyChain breaks at the new first row ("prevHash
      // mismatch"). Capture the highest (monotonicCounter, rowHash) among the
      // rows about to be deleted and UPSERT it into the purge anchor — the
      // verifier then resumes the walk from the anchor instead of ZERO_HASH.
      // audit rows are inserted in time order, so createdAt < cutoff selects a
      // contiguous lowest-counter prefix; its MAX counter is the new origin.
      if (config.auditChainEnabled) {
        var boundary = db().rawGet(
          "SELECT monotonicCounter, rowHash FROM audit_log WHERE createdAt < ? AND monotonicCounter IS NOT NULL ORDER BY monotonicCounter DESC LIMIT 1",
          cutoff
        );
        if (boundary && boundary.rowHash != null) {
          db().rawExec(
            "INSERT INTO _blamejs_audit_purge_anchor (scope, lastPurgedCounter, lastPurgedRowHash, archiveBundleId, purgedAt) " +
            "VALUES ('audit', ?, ?, ?, ?) " +
            "ON CONFLICT(scope) DO UPDATE SET lastPurgedCounter = excluded.lastPurgedCounter, " +
            "lastPurgedRowHash = excluded.lastPurgedRowHash, archiveBundleId = excluded.archiveBundleId, purgedAt = excluded.purgedAt",
            boundary.monotonicCounter, boundary.rowHash, "hs-retention-cleanup", Date.now()
          );
        }
      }

      // Use raw SQL — the ORM doesn't support $lt operator
      var result = db().rawExec("DELETE FROM audit_log WHERE createdAt < ?", cutoff);
      var removed = result.changes || 0;
      if (removed > 0) log(ACTIONS.AUDIT_RETENTION_CLEANUP, { performedBy: "system", details: "Audit retention: removed " + removed + " entries older than " + days + " days" });
    } catch (_e) { /* ignore during startup */ }
  }

  // Run on start + every 24 hours
  setTimeout(cleanup, TIME.seconds(5));
  var timer = setInterval(cleanup, TIME.days(1));
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
  return fieldCryptoLazy().unsealDoc("audit_log", Object.assign({}, entry));
}

module.exports = {
  log: log,
  ACTIONS: ACTIONS,
  unsealEntry: unsealEntry,
  // Chain surface — the verify service walks the SAME chain these appends write.
  chainQueryOne: _chainQueryOne,
  chainQueryAll: _chainQueryAll,
  drainChain: drainChain,
};
