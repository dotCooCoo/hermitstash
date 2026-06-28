/**
 * Centralized audit logging.
 * Every security-relevant action flows through audit.log().
 *
 * PII protection:
 *   - Emails: vault-sealed (ML-KEM-1024 + P-384 hybrid + XChaCha20-Poly1305)
 *   - IPs: one-way SHA3-512 hash by default; full IP vault-sealed (reversible) when
 *     AUDIT_IP_FULL is enabled for investigations (new entries only)
 *   - Request path / user-agent: vault-sealed; user-agent captured only when
 *     AUDIT_CAPTURE_USER_AGENT is enabled
 */
var nodeFs = require("node:fs");
var clientIp = require("../lib/client-ip");
var config = require("./config");
var b = require("./vendor/blamejs");
var logger = require("../app/shared/logger");
var C = require("./constants");
var { HASH_PREFIX, TIME } = C;

// Stored-length caps for captured request context — character limits (not crypto
// byte sizes) that bound a hostile long path / user-agent / request-id from
// bloating an audit row.
var MAX_CONTEXT = { PATH: 512, USER_AGENT: 512, REQUEST_ID: 64, METHOD: 10 }; // allow:raw-byte-literal — character caps, not byte sizes

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
  USER_LIMITS_CHANGED: "user_limits_changed",
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
  AUDIT_EXPORTED: "audit_exported",

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

// ---- Request-context extraction (HOW / WHERE) ----
// The router sets req.pathname; fall back to the path portion of req.url. Bounded
// so a hostile long URL can't bloat a row. Query string is dropped (it can carry
// tokens/secrets — CWE-598).
function _requestPath(req) {
  var p = req.pathname || req.path || (req.url ? String(req.url).split("?")[0] : null);
  return p ? String(p).slice(0, MAX_CONTEXT.PATH) : null;
}
function _userAgent(req) {
  var ua = req.headers ? (req.headers["user-agent"] || req.headers["User-Agent"]) : null;
  return ua ? String(ua).slice(0, MAX_CONTEXT.USER_AGENT) : null;
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

  // Seal PII before storage. req carries the WHERE/HOW context when present.
  var req = opts.req || null;
  var rawIp = req ? getIp(req) : null;

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
    // WHERE: source IP. Default stores a one-way hash — the operator cannot recover
    // the address (privacy-preserving). With config.auditIpFull the full
    // canonicalized IP is stored vault-sealed (reversible) so an investigation can
    // read it; a deliberate, admin-opted privacy reduction that applies to NEW
    // entries only (already-hashed rows stay unrecoverable).
    // allow:raw-byte-literal — fixed 16-hex-char IP-hash truncation for storage
    ip: rawIp ? (config.auditIpFull ? String(rawIp) : b.crypto.namespaceHash(HASH_PREFIX.IP, String(rawIp)).substring(0, 16)) : null,
    // HOW: request verb, path, auth class, and correlation id.
    method: req && req.method ? String(req.method).toUpperCase().slice(0, MAX_CONTEXT.METHOD) : null,
    path: req ? _requestPath(req) : null,
    authType: req ? (req.apiKey ? "apikey" : (req.user ? "session" : "anonymous")) : null,
    requestId: req && req.requestId ? String(req.requestId).slice(0, MAX_CONTEXT.REQUEST_ID) : null,
    // user-agent is PII (device/browser fingerprint) — captured only when enabled.
    userAgent: (req && config.auditCaptureUserAgent) ? _userAgent(req) : null,
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

// ---- One-time chain re-anchor on audit-schema evolution ----
// The tamper chain hashes the full physical column set of each row. Adding the
// richer-context columns (method/path/authType/userAgent/requestId) widens that
// set, so rows chained BEFORE the upgrade would fail verifyChain under the new
// schema (the verifier materializes the now-NULL new columns and the canonical
// form no longer matches the write-time hash). Move the chain origin to the
// current tip exactly once: the verifier then resumes from post-upgrade rows;
// pre-upgrade rows stay readable but below the anchor. No-op when the chain is
// off (those rows carry a NULL monotonicCounter and are excluded from the walk)
// or when there are no chained rows yet. Marker-guarded so it runs at most once.
function _reanchorChainForSchemaChange() {
  var marker = C.PATHS.AUDIT_SCHEMA_ANCHOR_MARKER;
  var alreadyRan = false;
  try { alreadyRan = nodeFs.existsSync(marker); } catch (_e) { return; }
  if (alreadyRan) return;

  try {
    if (config.auditChainEnabled) {
      var tip = db().rawGet(
        "SELECT monotonicCounter, rowHash FROM audit_log WHERE monotonicCounter IS NOT NULL ORDER BY monotonicCounter DESC LIMIT 1"
      );
      if (tip && tip.rowHash != null) {
        db().rawExec(
          "INSERT INTO _blamejs_audit_purge_anchor (scope, lastPurgedCounter, lastPurgedRowHash, archiveBundleId, purgedAt) " +
          "VALUES ('audit', ?, ?, ?, ?) " +
          "ON CONFLICT(scope) DO UPDATE SET lastPurgedCounter = excluded.lastPurgedCounter, " +
          "lastPurgedRowHash = excluded.lastPurgedRowHash, archiveBundleId = excluded.archiveBundleId, purgedAt = excluded.purgedAt",
          tip.monotonicCounter, tip.rowHash, "hs-audit-schema-evolution", Date.now()
        );
        logger.warn("[audit] chain re-anchored to counter=" + tip.monotonicCounter +
          " after audit-log schema widening; pre-upgrade rows remain readable but are below the verify anchor");
      }
    }
    try {
      nodeFs.writeFileSync(marker, new Date().toISOString());
    } catch (markerErr) {
      // If the marker can't persist, this runs again next boot and re-anchors to
      // the THEN-current tip, advancing the anchor past post-upgrade rows and
      // silently shrinking the verified window. Surface it loudly so the operator
      // fixes DATA_DIR permissions — a functioning deployment always has a writable
      // DATA_DIR (it holds the DB + vault key), so this should never fire.
      logger.error("[audit] failed to persist the schema re-anchor marker — re-anchor may repeat until DATA_DIR is writable",
        { marker: marker, err: markerErr && markerErr.message });
    }
  } catch (e) {
    logger.error("[audit] chain re-anchor on schema change failed", { err: e && e.message });
  }
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

// Re-anchor the chain (if needed) before any retention/append touches it, then
// start retention. Deferred to nextTick so the DB module finishes loading first
// (avoids the vault -> config -> audit -> db circular import).
process.nextTick(function () {
  try { _reanchorChainForSchemaChange(); } catch (_e) { /* never block boot on re-anchor */ }
  startRetentionCleanup();
});

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
