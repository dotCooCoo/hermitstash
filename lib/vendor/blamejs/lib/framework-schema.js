"use strict";
/**
 * @module b.frameworkSchema
 * @nav    Production
 * @title  Framework Schema
 *
 * @intro
 *   Framework-defined SQL schema (audit / sessions / api_keys / cache /
 *   break-glass / scheduler-ticks / pubsub / rate-limit / seeders /
 *   etc.) — declarative, migration-aware, and dialect-portable across
 *   Postgres and SQLite.
 *
 *   When cluster mode is active the framework's audit chain, consent
 *   log, audit checkpoints, audit tip, scheduler ticks, rate-limit
 *   counters, pubsub fan-out, sessions, jobs, cache, seeders, and
 *   break-glass policies/grants live in the operator's external
 *   database (configured via `b.externalDb.init`). This module owns
 *   the DDL for those tables and exposes a single idempotent entry
 *   point — `b.frameworkSchema.ensureSchema` — that operators (or the
 *   framework's leader-acquire hook in a later release) call to create
 *   them at boot.
 *
 *   External-db tables are prefixed with `_blamejs_` so they never
 *   collide with the operator's application tables:
 *
 *     audit_log           — local-SQLite name
 *     _blamejs_audit_log  — external-db name
 *
 *   `b.frameworkSchema.tableName` exposes the mapping so write-
 *   dispatch code (`cluster-storage.js`) can use a single name
 *   reference. `b.frameworkSchema.LOCAL_TO_EXTERNAL` is the frozen
 *   read-only mapping object.
 *
 *   Append-only WORM enforcement: `ensureSchema` installs BEFORE
 *   DELETE / BEFORE UPDATE triggers on `audit_log`, `consent_log`,
 *   and `audit_checkpoints` — Postgres via plpgsql RAISE EXCEPTION
 *   functions, SQLite via `RAISE(ABORT, ...)`. Idempotent across
 *   reboots; any operator-applied DROP TRIGGER is restored on the
 *   next ensureSchema pass. MySQL is not currently supported —
 *   operators on MySQL must run on Postgres or SQLite until a MySQL
 *   adapter ships.
 *
 * @card
 *   Framework-defined SQL schema (audit / sessions / api_keys / cache / break-glass / scheduler-ticks / pubsub / rate-limit / seeders / etc.) — declarative, migration-aware, and dialect-portable across Postgres and SQLite.
 */

var externalDb = require("./external-db");
var { FrameworkError } = require("./framework-error");

class FrameworkSchemaError extends FrameworkError {
  constructor(message, code) {
    super(message);
    this.name = "FrameworkSchemaError";
    this.code = code || "framework-schema/invalid";
    this.isFrameworkSchemaError = true;
  }
}

// Local-SQLite name → external-db name. The prefix protects against
// operator-app-table collision when the framework writes alongside
// app tables in the same database.
var LOCAL_TO_EXTERNAL = Object.freeze({
  audit_log:          "_blamejs_audit_log",
  consent_log:        "_blamejs_consent_log",
  audit_checkpoints:  "_blamejs_audit_checkpoints",
  // No local equivalent — only exists in external-db. Coordinates with
  // the cluster module's lease + fencing-token guard.
  _blamejs_audit_tip:   "_blamejs_audit_tip",
  // Same shape and purpose as _blamejs_audit_tip but for consent_log.
  // Single-row coordination state recording the tip of the consent
  // chain so a new leader (or any boot) can detect external-db
  // rollback against the consent chain too.
  _blamejs_consent_tip: "_blamejs_consent_tip",
  // Single-row anchor recording the boundary of the most recent
  // audit-tools.purge(). After a purge, audit-chain.verifyChain reads
  // this row to set its starting prevHash to lastPurgedRowHash and skip
  // rows whose monotonicCounter ≤ lastPurgedCounter — without it the
  // chain math breaks the moment the row referenced by survivors'
  // prevHash is gone.
  _blamejs_audit_purge_anchor: "_blamejs_audit_purge_anchor",
  // Scheduler tick-claim table: closes the once-globally gap during
  // cluster leader hand-offs (where two leaders briefly coexist) by
  // making each fire claim a row before dispatching. UNIQUE on the
  // composite tickKey (name + ":" + scheduledAtUnix) — loser of the
  // INSERT race skips the tick.
  _blamejs_scheduler_ticks:    "_blamejs_scheduler_ticks",
  // Rate-limit cluster-shared backend storage — fixed-window counter
  // per key. The middleware atomically INSERT...ON CONFLICT increments
  // count within the current window and rolls over when the window
  // advances. Created in cluster mode by ensureSchema; mirrored in
  // single-node SQLite by db.js's FRAMEWORK_SCHEMA so the same SQL
  // works on either side of cluster-storage's dispatch.
  _blamejs_rate_limit_counters: "_blamejs_rate_limit_counters",
  // WebSocket channel-hub cluster fan-out — publish() writes a row,
  // other nodes poll for new ids and dispatch to their local
  // subscribers. Same dual-storage shape as sessions / jobs / etc.
  _blamejs_pubsub_messages:        "_blamejs_pubsub_messages",
  _blamejs_api_encrypt_nonces: "_blamejs_api_encrypt_nonces",
  // _blamejs_api_keys — operator-facing API-key registry table for the
  // b.apiKey primitive. PRIMARY KEY is namespace-scoped id (so multiple
  // namespaces can coexist in one table). Sealed columns: ownerId,
  // scopes (JSON array), metadata (JSON object). Indexed lookup by
  // ownerIdHash. The secret itself never lands here — only its
  // SHA3-512 hash, constant-time-compared on verify.
  _blamejs_api_keys: "_blamejs_api_keys",
  // _blamejs_sessions exists in both local SQLite (single-node mode,
  // created by db.js's FRAMEWORK_SCHEMA at boot) and external-db
  // (cluster mode, created by ensureSchema below). Same name in both
  // places — cluster-storage.execute routes the SQL to the right DB
  // based on cluster.isClusterMode().
  _blamejs_sessions:  "_blamejs_sessions",
  // _blamejs_jobs — same dual-storage pattern as sessions. The local-
  // protocol queue (lib/queue-local.js) routes through cluster-storage
  // so writes/reads land in the leader's external-db when cluster
  // mode is active and any node can observe the queue state.
  _blamejs_jobs:      "_blamejs_jobs",
  // _blamejs_cache — operator-facing cache primitive's cluster backend.
  // Single shared table across all CacheInstance instances; the
  // namespace prefix in cacheKey isolates instances. JSON-serialized
  // values, BIGINT expiresAt for ttl. Indexed on expiresAt for the
  // periodic prune query.
  _blamejs_cache:     "_blamejs_cache",
  // _blamejs_cache_tags — junction table for tag-based cache
  // invalidation on the cluster backend. Composite PK
  // (cacheKey, tag) lets a single cacheKey carry many tags;
  // index on tag makes invalidateTag(t) a single indexed scan.
  _blamejs_cache_tags: "_blamejs_cache_tags",
  // _blamejs_seeders — registry of applied seed files for b.seeders
  // (lib/seeders.js). Composite PK (env, name) lets the same filename
  // apply per env. Mirrors the local-SQLite shape in db.js
  // FRAMEWORK_SCHEMA so cluster-storage.execute routes to either side.
  _blamejs_seeders:        "_blamejs_seeders",
  _blamejs_seeders_lock:   "_blamejs_seeders_lock",
  // Break-glass policy + grant tables. Cluster-shared so a grant
  // issued on node A is honored on node B; policies updated on the
  // leader propagate to all followers via the shared table.
  _blamejs_break_glass_policies: "_blamejs_break_glass_policies",
  _blamejs_break_glass_grants:   "_blamejs_break_glass_grants",
});

/**
 * @primitive b.frameworkSchema.tableName
 * @signature b.frameworkSchema.tableName(localName)
 * @since     0.5.0
 * @status    stable
 * @related   b.frameworkSchema.ensureSchema
 *
 * Translate a local-SQLite table name into the external-db name. The
 * mapping is the frozen `LOCAL_TO_EXTERNAL` object — tables that already
 * carry the `_blamejs_` prefix locally pass through unchanged. Cluster
 * write-dispatch code uses this lookup so the same SQL works against
 * both backends without per-call branching.
 *
 * @example
 *   b.frameworkSchema.tableName("audit_log");
 *   // → "_blamejs_audit_log"
 *
 *   b.frameworkSchema.tableName("_blamejs_sessions");
 *   // → "_blamejs_sessions"
 *
 *   b.frameworkSchema.tableName("operator_app_table");
 *   // → "operator_app_table"
 */
function tableName(localName) {
  if (Object.prototype.hasOwnProperty.call(LOCAL_TO_EXTERNAL, localName)) {
    return LOCAL_TO_EXTERNAL[localName];
  }
  // For framework-internal tables that are already prefixed locally
  // (any name starting with _blamejs_), keep the same name.
  return localName;
}

// ---- Dialect-specific column types ----
// TEXT and BOOLEAN are identical across both. INTEGER and BLOB diverge.

function _types(dialect) {
  if (dialect === "postgres") {
    return { INT: "BIGINT", BLOB: "BYTEA" };
  }
  if (dialect === "sqlite") {
    return { INT: "INTEGER", BLOB: "BLOB" };
  }
  throw new FrameworkSchemaError(
    "unsupported dialect '" + dialect + "' (postgres or sqlite)",
    "framework-schema/unsupported-dialect"
  );
}

// ---- Table DDL builders ----
//
// Each builder returns { create: <CREATE TABLE SQL>, indexes: [<CREATE INDEX SQL>, ...] }.
// All DDL uses IF NOT EXISTS so re-running is idempotent.

function _auditLogDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL.audit_log;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  _id                  TEXT PRIMARY KEY," +
      "  recordedAt           " + t.INT + " NOT NULL," +
      "  monotonicCounter     " + t.INT + " NOT NULL," +
      "  actorUserId          TEXT," +
      "  actorUserIdHash      TEXT," +
      "  actorIp              TEXT," +
      "  actorUserAgent       TEXT," +
      "  actorSessionId       TEXT," +
      "  action               TEXT NOT NULL," +
      "  resourceKind         TEXT," +
      "  resourceId           TEXT," +
      "  resourceIdHash       TEXT," +
      "  outcome              TEXT NOT NULL," +
      "  reason               TEXT," +
      "  metadata             TEXT," +
      "  requestId            TEXT," +
      "  prevHash             TEXT NOT NULL," +
      "  rowHash              TEXT NOT NULL," +
      "  nonce                " + t.BLOB + " NOT NULL," +
      "  fencingToken         " + t.INT + " NOT NULL DEFAULT 0" +
      ")",
    indexes: [
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_actorUserIdHash ON " + name + " (actorUserIdHash)",
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_resourceIdHash ON " + name + " (resourceIdHash)",
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_recordedAt ON " + name + " (recordedAt)",
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_action ON " + name + " (action)",
      "CREATE UNIQUE INDEX IF NOT EXISTS idx_" + name + "_monotonic ON " + name + " (monotonicCounter)",
    ],
  };
}

function _consentLogDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL.consent_log;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  _id                  TEXT PRIMARY KEY," +
      "  recordedAt           " + t.INT + " NOT NULL," +
      "  monotonicCounter     " + t.INT + " NOT NULL," +
      "  subjectId            TEXT NOT NULL," +
      "  subjectIdHash        TEXT NOT NULL," +
      "  purpose              TEXT NOT NULL," +
      "  lawfulBasis          TEXT NOT NULL," +
      "  action               TEXT NOT NULL," +
      "  scope                TEXT," +
      "  channel              TEXT NOT NULL," +
      "  evidenceRef          TEXT," +
      "  prevHash             TEXT NOT NULL," +
      "  rowHash              TEXT NOT NULL," +
      "  nonce                " + t.BLOB + " NOT NULL," +
      "  fencingToken         " + t.INT + " NOT NULL DEFAULT 0" +
      ")",
    indexes: [
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_subjectIdHash ON " + name + " (subjectIdHash)",
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_recordedAt ON " + name + " (recordedAt)",
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_purpose ON " + name + " (purpose)",
      "CREATE UNIQUE INDEX IF NOT EXISTS idx_" + name + "_monotonic ON " + name + " (monotonicCounter)",
    ],
  };
}

function _auditCheckpointsDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL.audit_checkpoints;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  _id                  TEXT PRIMARY KEY," +
      "  createdAt            " + t.INT + " NOT NULL," +
      "  atMonotonicCounter   " + t.INT + " NOT NULL," +
      "  atRowHash            TEXT NOT NULL," +
      "  signature            " + t.BLOB + " NOT NULL," +
      "  publicKeyFingerprint TEXT NOT NULL," +
      "  fencingToken         " + t.INT + " NOT NULL DEFAULT 0" +
      ")",
    indexes: [
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_createdAt ON " + name + " (createdAt)",
      "CREATE UNIQUE INDEX IF NOT EXISTS idx_" + name + "_chkpt_counter ON " + name + " (atMonotonicCounter)",
    ],
  };
}

// audit_tip is single-row coordination state for cluster-mode rollback
// detection. The CHECK constraint on fencingToken is the canonical
// fencing-token guard from the cluster spec — enforced at the DB
// level so a partitioned old leader can't insert rows behind a new
// leader's back regardless of application-layer state.
//
// Postgres and SQLite both honour CHECK constraints. The single-row
// invariant is enforced via PRIMARY KEY on the constant-valued
// `scope` column.
function _auditTipDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL._blamejs_audit_tip;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  scope                TEXT PRIMARY KEY," +
      "  atMonotonicCounter   " + t.INT + " NOT NULL," +
      "  rowHash              TEXT," +
      "  signedAt             TEXT," +
      "  fencingToken         " + t.INT + " NOT NULL DEFAULT 0," +
      "  CHECK (scope = 'audit')" +
      ")",
    indexes: [],
  };
}

// Same shape + invariants as audit_tip but for the consent chain.
// Updated on every consent.grant / consent.withdraw write so the boot-
// time rollback check can detect external-db rollback against the
// consent chain (previously only the audit chain had this protection).
function _consentTipDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL._blamejs_consent_tip;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  scope                TEXT PRIMARY KEY," +
      "  atMonotonicCounter   " + t.INT + " NOT NULL," +
      "  rowHash              TEXT," +
      "  signedAt             TEXT," +
      "  fencingToken         " + t.INT + " NOT NULL DEFAULT 0," +
      "  CHECK (scope = 'consent')" +
      ")",
    indexes: [],
  };
}

// _blamejs_audit_purge_anchor — single-row chain-origin anchor written
// by audit-tools.purge(). Holds the lastRowHash of the most recently
// purged range so verifyChain can ground its walk at the new origin.
// Single-row invariant via PRIMARY KEY on the constant-valued `scope`
// column (matches _blamejs_audit_tip pattern).
function _auditPurgeAnchorDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL._blamejs_audit_purge_anchor;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  scope             TEXT PRIMARY KEY," +
      "  lastPurgedCounter " + t.INT + " NOT NULL," +
      "  lastPurgedRowHash TEXT NOT NULL," +
      "  archiveBundleId   TEXT NOT NULL," +
      "  purgedAt          " + t.INT + " NOT NULL," +
      "  CHECK (scope = 'audit')" +
      ")",
    indexes: [],
  };
}

// _blamejs_scheduler_ticks — exactly-once tick-claim table. PRIMARY KEY
// on composite tickKey makes concurrent INSERTs race; the loser skips
// the tick. claimedBy carries the node id for diagnostic.
function _schedulerTicksDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL._blamejs_scheduler_ticks;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  tickKey         TEXT PRIMARY KEY," +
      "  name            TEXT NOT NULL," +
      "  scheduledAtUnix " + t.INT + " NOT NULL," +
      "  claimedAtUnix   " + t.INT + " NOT NULL," +
      "  claimedBy       TEXT" +
      ")",
    indexes: [
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_scheduledAt ON " + name + " (scheduledAtUnix)",
    ],
  };
}

// _blamejs_rate_limit_counters — fixed-window counter table for the
// cluster-shared rate-limit backend. PRIMARY KEY on the rate-limit
// key lets INSERT...ON CONFLICT atomically increment within a window
// and roll over on window advance. The windowStart index supports
// retention sweeps of expired windows.
function _rateLimitCountersDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL._blamejs_rate_limit_counters;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  key         TEXT PRIMARY KEY," +
      "  windowStart " + t.INT + " NOT NULL," +
      "  count       " + t.INT + " NOT NULL DEFAULT 0" +
      ")",
    indexes: [
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_windowStart ON " + name + " (windowStart)",
    ],
  };
}

// _blamejs_pubsub_messages — cluster fan-out for `b.pubsub` (the
// generalization of the previous WebSocket-specific table). publish()
// on any node writes a row; other nodes poll for new ids past their
// last seen and dispatch to local subscribers. Auto-incrementing id
// is essential — postgres needs BIGSERIAL, sqlite gets INTEGER
// PRIMARY KEY (which auto-increments implicitly).
function _pubsubMessagesDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL._blamejs_pubsub_messages;
  var idCol = dialect === "postgres"
    ? "id          BIGSERIAL PRIMARY KEY"
    : "id          INTEGER PRIMARY KEY AUTOINCREMENT";
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  " + idCol + "," +
      "  topic       TEXT NOT NULL," +
      "  payload     TEXT NOT NULL," +
      "  publishedAt " + t.INT + " NOT NULL," +
      "  publishedBy TEXT NOT NULL" +
      ")",
    indexes: [
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_publishedAt ON " + name + " (publishedAt)",
    ],
  };
}

function _apiEncryptNoncesDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL._blamejs_api_encrypt_nonces;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  nonceHash TEXT PRIMARY KEY," +
      "  expireAt  " + t.INT + " NOT NULL" +
      ")",
    indexes: [
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_expireAt ON " + name + " (expireAt)",
    ],
  };
}

// _blamejs_api_keys — operator-facing API-key registry. PRIMARY KEY is
// the namespace-scoped id ("<namespace>:<idHex>"); ownerId/scopes/metadata
// are sealed by cryptoField. ownerIdHash supports indexed listForOwner
// lookups; expiresAt index supports purgeExpired sweeps.
function _apiKeysDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL._blamejs_api_keys;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  id                    TEXT PRIMARY KEY," +
      "  namespace             TEXT NOT NULL," +
      "  ownerId               TEXT NOT NULL," +
      "  ownerIdHash           TEXT NOT NULL," +
      "  secretHash            TEXT NOT NULL," +
      "  secondarySecretHash   TEXT," +
      "  secondaryExpiresAt    " + t.INT + "," +
      "  scopes                TEXT," +
      "  metadata              TEXT," +
      "  createdAt             " + t.INT + " NOT NULL," +
      "  expiresAt             " + t.INT + "," +
      "  revokedAt             " + t.INT + "," +
      "  lastUsedAt            " + t.INT + "," +
      "  prefix                TEXT NOT NULL" +
      ")",
    indexes: [
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_ownerIdHash ON " + name + " (ownerIdHash)",
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_namespace_owner ON " + name + " (namespace, ownerIdHash)",
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_expiresAt ON " + name + " (expiresAt)",
    ],
  };
}

// _blamejs_sessions — DB-backed session store. Mirrors the local-SQLite
// schema in db.js's FRAMEWORK_SCHEMA so single-node and cluster-mode
// behavior is identical at the column level. Sealed columns (userId,
// data) are stored vault-sealed; sidHash is the PRIMARY KEY (the raw
// session id never lands here).
function _sessionsDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL._blamejs_sessions;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  sidHash         TEXT PRIMARY KEY," +
      "  userId          TEXT NOT NULL," +
      "  userIdHash      TEXT NOT NULL," +
      "  data            TEXT," +
      "  createdAt       " + t.INT + " NOT NULL," +
      "  expiresAt       " + t.INT + " NOT NULL," +
      "  lastActivity    " + t.INT + " NOT NULL" +
      ")",
    indexes: [
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_userIdHash ON " + name + " (userIdHash)",
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_expiresAt ON " + name + " (expiresAt)",
    ],
  };
}

// _blamejs_jobs — local-protocol queue jobs. Mirrors db.js's
// FRAMEWORK_SCHEMA for the same table; sealed columns (payload,
// lastError) are stored vault-sealed. Indexes target the lease
// hot-path (queueName + status + availableAt) and lease-expiry
// sweep (leaseExpiresAt).
function _jobsDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL._blamejs_jobs;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  _id              TEXT PRIMARY KEY," +
      "  queueName        TEXT NOT NULL," +
      "  payload          TEXT," +
      "  status           TEXT NOT NULL," +
      "  enqueuedAt       " + t.INT + " NOT NULL," +
      "  availableAt      " + t.INT + " NOT NULL," +
      "  leasedAt         " + t.INT + "," +
      "  leaseExpiresAt   " + t.INT + "," +
      "  attempts         " + t.INT + " NOT NULL DEFAULT 0," +
      "  maxAttempts      " + t.INT + " NOT NULL DEFAULT 5," +
      "  lastError        TEXT," +
      "  finishedAt       " + t.INT + "," +
      "  traceId          TEXT," +
      "  classification   TEXT," +
      "  priority         " + t.INT + " NOT NULL DEFAULT 0," +
      "  repeatCron       TEXT," +
      "  repeatTimezone   TEXT," +
      "  flowId           TEXT," +
      "  flowChildName    TEXT," +
      "  dependsOn        TEXT" +
      ")",
    indexes: [
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_lease ON " + name + " (queueName, status, availableAt)",
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_priority ON " + name + " (queueName, status, priority, availableAt)",
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_flow ON " + name + " (flowId)",
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_leaseExpiresAt ON " + name + " (leaseExpiresAt)",
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_finishedAt ON " + name + " (finishedAt)",
    ],
  };
}

// _blamejs_seeders — registry of applied seed files for the b.seeders
// primitive (lib/seeders.js). Composite PK (env, name) so the same
// filename can apply per env without collision. rerunnable=1 entries
// have their appliedAt updated in place on each run; non-rerunnable
// entries are insert-once.
function _seedersDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL._blamejs_seeders;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  env         TEXT NOT NULL," +
      "  name        TEXT NOT NULL," +
      "  description TEXT," +
      "  appliedAt   TEXT NOT NULL," +
      "  rerunnable  " + t.INT + " NOT NULL DEFAULT 0," +
      "  PRIMARY KEY (env, name)" +
      ")",
    indexes: [],
  };
}

// _blamejs_seeders_lock — single-row advisory lock matching the
// _blamejs_migrations_lock pattern. CHECK enforces single row.
function _seedersLockDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL._blamejs_seeders_lock;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  scope     TEXT PRIMARY KEY CHECK (scope = 'lock')," +
      "  lockedAt  " + t.INT + " NOT NULL," +
      "  lockedBy  TEXT NOT NULL" +
      ")",
    indexes: [],
  };
}

// _blamejs_cache — operator-facing cache primitive's cluster backend
// (lib/cache.js). PRIMARY KEY is the composite "<namespace>:<key>" so a
// single shared table serves every CacheInstance regardless of namespace
// without per-namespace table proliferation. valueJson is the
// JSON-serialized stored value; expiresAt is the unix-ms TTL boundary
// (Number.MAX_SAFE_INTEGER for never-expiring entries). Indexed on
// expiresAt for the periodic prune query.
function _cacheDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL._blamejs_cache;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  cacheKey      TEXT PRIMARY KEY," +
      "  valueJson     TEXT NOT NULL," +
      "  expiresAt     " + t.INT + " NOT NULL," +
      "  updatedAt     " + t.INT + " NOT NULL" +
      ")",
    indexes: [
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_expiresAt ON " + name + " (expiresAt)",
    ],
  };
}

// _blamejs_cache_tags — tag→cacheKey junction for cluster-backend
// tag invalidation. b.cache.invalidateTag(t) finds matching cacheKeys
// via the indexed `tag` column, deletes them from _blamejs_cache, and
// drops the junction rows. Cleared on cache.clear() and del() too.
function _cacheTagsDDL(_dialect) {
  // Junction table is TEXT-only — no dialect-specific INT / BLOB needed.
  var name = LOCAL_TO_EXTERNAL._blamejs_cache_tags;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  cacheKey  TEXT NOT NULL," +
      "  tag       TEXT NOT NULL," +
      "  PRIMARY KEY (cacheKey, tag)" +
      ")",
    indexes: [
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_tag ON " + name + " (tag)",
    ],
  };
}

// _blamejs_break_glass_policies — column-level break-glass policy
// registry. One row per (table) declares which columns are
// glass-locked + the operator's grant rules. Sealed columns hide
// column-list / factor-list / bypass config from cleartext browsing.
function _breakGlassPoliciesDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL._blamejs_break_glass_policies;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  tableName                  TEXT PRIMARY KEY," +
      "  columnsJson                TEXT NOT NULL," +
      "  factorsJson                TEXT NOT NULL," +
      "  cryptographic              " + t.INT + " NOT NULL DEFAULT 0," +
      "  grantTtlMs                 " + t.INT + " NOT NULL," +
      "  maxRowsPerGrant            " + t.INT + " NOT NULL DEFAULT 1," +
      "  reasonRequired             " + t.INT + " NOT NULL DEFAULT 1," +
      "  reasonMinLength            " + t.INT + " NOT NULL DEFAULT 12," +
      "  pinIp                      " + t.INT + " NOT NULL DEFAULT 1," +
      "  sessionPin                 " + t.INT + " NOT NULL DEFAULT 1," +
      "  onLockedAccess             TEXT NOT NULL DEFAULT 'throw'," +
      "  requireScope               TEXT," +
      "  serviceAccountBypassJson   TEXT," +
      "  dekSealed                  TEXT," +
      "  auditReasonStorage         TEXT NOT NULL DEFAULT 'cleartext'," +
      "  updatedAt                  " + t.INT + " NOT NULL" +
      ")",
    indexes: [],
  };
}

// _blamejs_break_glass_grants — issued grants. One row per successful
// step-up. Default maxRowsPerGrant=1 enforces row-by-row auth per the
// operator-confirmed shape ("each row access = its own grant").
function _breakGlassGrantsDDL(dialect) {
  var t = _types(dialect);
  var name = LOCAL_TO_EXTERNAL._blamejs_break_glass_grants;
  return {
    create:
      "CREATE TABLE IF NOT EXISTS " + name + " (" +
      "  _id                TEXT PRIMARY KEY," +
      "  issuedToActorId    TEXT NOT NULL," +
      "  issuedToActorHash  TEXT NOT NULL," +
      "  factorType         TEXT NOT NULL," +
      "  reasonSealed       TEXT," +
      "  scopeTable         TEXT NOT NULL," +
      "  scopeColumnsJson   TEXT NOT NULL," +
      "  issuedAt           " + t.INT + " NOT NULL," +
      "  expiresAt          " + t.INT + " NOT NULL," +
      "  maxRowsPerGrant    " + t.INT + " NOT NULL," +
      "  rowsConsumed       " + t.INT + " NOT NULL DEFAULT 0," +
      "  revokedAt          " + t.INT + "," +
      "  sessionId          TEXT," +
      "  ip                 TEXT," +
      "  kwGrantHalf        TEXT" +
      ")",
    indexes: [
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_actor   ON " + name + " (issuedToActorHash)",
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_table   ON " + name + " (scopeTable)",
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_expires ON " + name + " (expiresAt)",
      "CREATE INDEX IF NOT EXISTS idx_" + name + "_revoked ON " + name + " (revokedAt)",
    ],
  };
}

// ---- ensureSchema ----

/**
 * @primitive b.frameworkSchema.ensureSchema
 * @signature b.frameworkSchema.ensureSchema(opts)
 * @since     0.5.0
 * @status    stable
 * @related   b.frameworkSchema.tableName, b.externalDb.init, b.audit
 *
 * Create every framework-owned table + index in the operator's
 * external database, then install append-only WORM triggers on
 * `_blamejs_audit_log`, `_blamejs_consent_log`, and
 * `_blamejs_audit_checkpoints`. Idempotent: every DDL uses
 * `IF NOT EXISTS` and re-running is safe across reboots.
 *
 * Returns `{ tables }` with the set of CREATE TABLE names emitted
 * so the operator can confirm the expected surface landed.
 *
 * Throws `FrameworkSchemaError("framework-schema/invalid-config")`
 * when `externalDbBackend` is missing and
 * `FrameworkSchemaError("framework-schema/unsupported-dialect")`
 * when `dialect` is anything other than `postgres` or `sqlite`.
 *
 * @opts
 *   externalDbBackend: string,     // backend name registered with b.externalDb (required)
 *   dialect:           "postgres"|"sqlite",  // default: "postgres"
 *
 * @example
 *   try {
 *     var report = await b.frameworkSchema.ensureSchema({
 *       externalDbBackend: "primary",
 *       dialect:           "postgres",
 *     });
 *     report.tables[0]; // → "_blamejs_audit_log"
 *   } catch (e) {
 *     e.code; // → "framework-schema/unsupported-dialect"
 *   }
 */
async function ensureSchema(opts) {
  if (!opts || !opts.externalDbBackend) {
    throw new FrameworkSchemaError(
      "ensureSchema requires { externalDbBackend: <name> }",
      "framework-schema/invalid-config"
    );
  }
  var dialect = (opts.dialect || "postgres").toLowerCase();
  if (dialect !== "postgres" && dialect !== "sqlite") {
    throw new FrameworkSchemaError(
      "unsupported dialect '" + dialect + "' (postgres or sqlite)",
      "framework-schema/unsupported-dialect"
    );
  }

  var ddls = [
    _auditLogDDL(dialect),
    _consentLogDDL(dialect),
    _auditCheckpointsDDL(dialect),
    _auditTipDDL(dialect),
    _consentTipDDL(dialect),
    _auditPurgeAnchorDDL(dialect),
    _schedulerTicksDDL(dialect),
    _rateLimitCountersDDL(dialect),
    _pubsubMessagesDDL(dialect),
    _apiEncryptNoncesDDL(dialect),
    _apiKeysDDL(dialect),
    _sessionsDDL(dialect),
    _jobsDDL(dialect),
    _cacheDDL(dialect),
    _cacheTagsDDL(dialect),
    _seedersDDL(dialect),
    _seedersLockDDL(dialect),
    _breakGlassPoliciesDDL(dialect),
    _breakGlassGrantsDDL(dialect),
  ];

  var created = [];
  for (var i = 0; i < ddls.length; i++) {
    var d = ddls[i];
    await externalDb.query(d.create, [], { backend: opts.externalDbBackend });
    for (var j = 0; j < d.indexes.length; j++) {
      await externalDb.query(d.indexes[j], [], { backend: opts.externalDbBackend });
    }
    created.push(d.create.match(/CREATE TABLE IF NOT EXISTS\s+(\S+)/)[1]);
  }

  // D-M11 — append-only WORM enforcement on audit_log / consent_log /
  // audit_checkpoints in cluster mode. Local-SQLite path already
  // installs CREATE TRIGGER IF NOT EXISTS via lib/db.js's
  // _installAppendOnlyTriggers; Postgres needs equivalent rules
  // (BEFORE-row triggers raising an exception) so a privileged
  // cluster-side actor with the framework role can't DELETE / UPDATE
  // a row out from under the chain. The chain integrity check still
  // catches it at next boot, but the trigger is the in-band defense.
  await _installWormTriggers(opts.externalDbBackend, dialect);

  return { tables: created };
}

// D-M11 — WORM enforcement helper. Idempotent: rebuilding triggers
// per boot is cheap and any operator-applied DROP TRIGGER is restored
// at the next ensureSchema pass.
async function _installWormTriggers(backend, dialect) {
  var wormTables = [
    LOCAL_TO_EXTERNAL.audit_log,
    LOCAL_TO_EXTERNAL.consent_log,
    LOCAL_TO_EXTERNAL.audit_checkpoints,
  ];
  for (var i = 0; i < wormTables.length; i++) {
    var t = wormTables[i];
    if (dialect === "postgres") {
      // Per-table trigger function. Postgres rejects the statement
      // with a SQLSTATE that bubbles up as a query-failure audit row.
      var fnName = t + "_worm_block";
      await externalDb.query(
        "CREATE OR REPLACE FUNCTION " + fnName + "() RETURNS trigger AS $$ " +
        "BEGIN RAISE EXCEPTION '" + t + " is append-only — % prohibited', TG_OP " +
        "USING ERRCODE = '0A000'; END; $$ LANGUAGE plpgsql",
        [], { backend: backend }
      );
      await externalDb.query(
        "DROP TRIGGER IF EXISTS no_delete_" + t + " ON " + t,
        [], { backend: backend }
      );
      await externalDb.query(
        "CREATE TRIGGER no_delete_" + t + " BEFORE DELETE ON " + t +
        " FOR EACH ROW EXECUTE FUNCTION " + fnName + "()",
        [], { backend: backend }
      );
      await externalDb.query(
        "DROP TRIGGER IF EXISTS no_update_" + t + " ON " + t,
        [], { backend: backend }
      );
      await externalDb.query(
        "CREATE TRIGGER no_update_" + t + " BEFORE UPDATE ON " + t +
        " FOR EACH ROW EXECUTE FUNCTION " + fnName + "()",
        [], { backend: backend }
      );
    } else {
      // SQLite cluster path. CREATE TRIGGER IF NOT EXISTS matches the
      // local-SQLite shape installed by lib/db.js.
      await externalDb.query(
        'CREATE TRIGGER IF NOT EXISTS "no_delete_' + t + '" ' +
        'BEFORE DELETE ON "' + t + '" ' +
        "BEGIN SELECT RAISE(ABORT, '" + t + " is append-only — DELETE prohibited'); END",
        [], { backend: backend }
      );
      await externalDb.query(
        'CREATE TRIGGER IF NOT EXISTS "no_update_' + t + '" ' +
        'BEFORE UPDATE ON "' + t + '" ' +
        "BEGIN SELECT RAISE(ABORT, '" + t + " is append-only — UPDATE prohibited'); END",
        [], { backend: backend }
      );
    }
  }
}

module.exports = {
  ensureSchema:           ensureSchema,
  tableName:              tableName,
  LOCAL_TO_EXTERNAL:      LOCAL_TO_EXTERNAL,
  FrameworkSchemaError:   FrameworkSchemaError,
};
