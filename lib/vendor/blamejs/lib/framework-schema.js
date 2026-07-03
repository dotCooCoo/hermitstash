// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
 *   functions, MySQL via `SIGNAL SQLSTATE '45000'`, SQLite via
 *   `RAISE(ABORT, ...)`. Idempotent across reboots; any operator-applied
 *   DROP TRIGGER is restored on the next ensureSchema pass.
 *
 *   Dialect portability: `postgres`, `mysql`, and `sqlite` are all
 *   supported targets. The integer token is BIGINT on Postgres + MySQL
 *   (a 32-bit INTEGER overflows a Date.now() ms-epoch value) and INTEGER
 *   on SQLite; the binary token is BYTEA / LONGBLOB / BLOB. TEXT columns
 *   that participate in a PRIMARY KEY or index become VARCHAR(191) on
 *   MySQL (which refuses an unbounded TEXT/BLOB in a key) and stay plain
 *   TEXT on Postgres + SQLite.
 *
 * @card
 *   Framework-defined SQL schema (audit / sessions / api_keys / cache / break-glass / scheduler-ticks / pubsub / rate-limit / seeders / etc.) — declarative, migration-aware, and dialect-portable across Postgres, MySQL, and SQLite.
 */

var externalDb = require("./external-db");
var safeSql = require("./safe-sql");
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
  // _blamejs_session_valid_from — per-subject valid-from boundary for
  // stateless-token revocation (b.session.bump / check / validFrom). Same
  // dual-storage shape as _blamejs_sessions; identity-mapped.
  _blamejs_session_valid_from: "_blamejs_session_valid_from",
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

// ---- Configurable framework-table prefix ----
//
// Every external-db (and prefixed local) framework table name carries a
// leading prefix so the framework's tables never collide with the
// operator's application tables. The default is `_blamejs_`; an operator
// running the framework alongside an app schema that itself uses
// `_blamejs_`-shaped names (or who simply wants a house prefix) can swap
// it at config-time via `setTablePrefix`. The default-prefix output is
// byte-identical to the historical hardcoded names, so this is a no-op
// for every existing deployment.
var DEFAULT_TABLE_PREFIX = "_blamejs_";
var currentPrefix = DEFAULT_TABLE_PREFIX;

/**
 * @primitive b.frameworkSchema.setTablePrefix
 * @signature b.frameworkSchema.setTablePrefix(prefix)
 * @since     0.14.30
 * @status    stable
 * @related   b.frameworkSchema.getTablePrefix, b.frameworkSchema.tableName, b.db.init
 *
 * Set the leading prefix applied to every framework-owned table name
 * (audit / consent / sessions / jobs / cache / break-glass / …). The
 * default is `_blamejs_`; pass a different value to namespace the
 * framework's tables away from an operator schema that would otherwise
 * collide. Config-time only — call it once, before schema creation
 * (`b.db.init` calls it for you when you pass `tablePrefix`). Throws a
 * `FrameworkSchemaError` ("framework-schema/invalid-prefix") when the
 * prefix is not a non-empty SQL identifier, so a typo surfaces at boot
 * rather than as a silently-misnamed table.
 *
 * The default-prefix output is byte-identical to the historical names,
 * so leaving the prefix unchanged is a no-op.
 *
 * @example
 *   b.frameworkSchema.setTablePrefix("acme_");
 *   b.frameworkSchema.tableName("audit_log");
 *   // → "acme_audit_log"
 *
 *   try { b.frameworkSchema.setTablePrefix(""); }
 *   catch (e) { e.code; } // → "framework-schema/invalid-prefix"
 */
function setTablePrefix(prefix) {
  try {
    safeSql.validateIdentifier(prefix, { allowReserved: true });
  } catch (e) {
    throw new FrameworkSchemaError(
      "setTablePrefix: prefix must be a non-empty SQL identifier — " +
        ((e && e.message) || String(e)),
      "framework-schema/invalid-prefix"
    );
  }
  currentPrefix = prefix;
  return currentPrefix;
}

/**
 * @primitive b.frameworkSchema.getTablePrefix
 * @signature b.frameworkSchema.getTablePrefix()
 * @since     0.14.30
 * @status    stable
 * @related   b.frameworkSchema.setTablePrefix, b.frameworkSchema.tableName
 *
 * Return the prefix currently applied to framework-owned table names —
 * `_blamejs_` unless `setTablePrefix` changed it.
 *
 * @example
 *   b.frameworkSchema.getTablePrefix();
 *   // → "_blamejs_"
 */
function getTablePrefix() {
  return currentPrefix;
}

// Swap the leading default prefix on a resolved external name for the
// configured prefix. With the default prefix this returns the name
// unchanged (byte-identical to the historical literal); any framework
// name not carrying the default prefix (there are none today) passes
// through untouched.
function _applyPrefix(externalName) {
  if (currentPrefix === DEFAULT_TABLE_PREFIX) return externalName;
  if (externalName.indexOf(DEFAULT_TABLE_PREFIX) === 0) {
    return currentPrefix + externalName.slice(DEFAULT_TABLE_PREFIX.length);
  }
  return externalName;
}

/**
 * @primitive b.frameworkSchema.tableName
 * @signature b.frameworkSchema.tableName(localName)
 * @since     0.5.0
 * @status    stable
 * @related   b.frameworkSchema.ensureSchema, b.frameworkSchema.setTablePrefix
 *
 * Translate a local-SQLite table name into the external-db name. The
 * mapping is the frozen `LOCAL_TO_EXTERNAL` object — tables that already
 * carry the framework prefix locally pass through the mapping unchanged.
 * The resolved name's leading prefix is then swapped to the configured
 * prefix (`setTablePrefix`); with the default `_blamejs_` prefix the
 * output is byte-identical to the historical names. Cluster
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
    return _applyPrefix(LOCAL_TO_EXTERNAL[localName]);
  }
  // Framework-internal tables already carrying the default prefix locally
  // but not in the LOCAL_TO_EXTERNAL map (e.g. `_blamejs_migrations`,
  // `_blamejs_migrations_lock`, `_blamejs_counters`) still honor the
  // configured prefix: swap the leading default prefix for the configured
  // one. Under the default prefix this returns the name byte-identical, so
  // it is a no-op for every existing deployment; under a custom prefix it
  // namespaces these tables the same way the mapped names are namespaced.
  return _applyPrefix(localName);
}

// ---- Dialect-specific column types ----
// BOOLEAN is identical across all three. INTEGER, BLOB, and the
// "TEXT-used-in-a-key" token diverge.
//
//   INT  — ms-epoch counters / timestamps. Postgres BIGINT, SQLite
//          INTEGER, MySQL BIGINT (a 32-bit INTEGER overflows a
//          Date.now() ms value, so BIGINT is required on MySQL too).
//   BLOB — Postgres BYTEA, SQLite BLOB, MySQL LONGBLOB.
//   KT   — "key text": a TEXT column that appears in a PRIMARY KEY or an
//          index. MySQL refuses BLOB/TEXT in a key without a prefix
//          length, so on MySQL such columns must be VARCHAR(n). 191 is
//          the utf8mb4 index-safe length (191 * 4 bytes = 764 < the
//          historical 767-byte InnoDB index-prefix limit), so a KT
//          column is index-safe under every default MySQL/InnoDB
//          configuration. On Postgres + SQLite a KT column is plain
//          TEXT (both index TEXT without a length), so the on-disk shape
//          is byte-identical to the historical schema there.
//
// Plain TEXT columns that are NEVER in a key (free-form payloads,
// metadata, reason strings) stay TEXT on every dialect — only key
// participants take the VARCHAR(n) treatment, so column values are not
// length-capped beyond what the schema needs.
var MYSQL_KEY_TEXT_LEN = 191;

//   DT   — "defaulted text": a short TEXT column that carries a string
//          DEFAULT (e.g. an enum-like 'throw' / 'cleartext'). MySQL refuses
//          a DEFAULT on a TEXT/BLOB column (error 1101), so such a column is
//          VARCHAR(n) on MySQL and plain TEXT on Postgres + SQLite (both
//          allow a TEXT default). Same VARCHAR(191) width as KT.
function _types(dialect) {
  if (dialect === "postgres") {
    return { INT: "BIGINT", BLOB: "BYTEA", KT: "TEXT", DT: "TEXT" };
  }
  if (dialect === "sqlite") {
    return { INT: "INTEGER", BLOB: "BLOB", KT: "TEXT", DT: "TEXT" };
  }
  if (dialect === "mysql") {
    return {
      INT:  "BIGINT",
      BLOB: "LONGBLOB",
      KT:   "VARCHAR(" + MYSQL_KEY_TEXT_LEN + ")",
      DT:   "VARCHAR(" + MYSQL_KEY_TEXT_LEN + ")",
    };
  }
  throw new FrameworkSchemaError(
    "unsupported dialect '" + dialect + "' (postgres, sqlite, or mysql)",
    "framework-schema/unsupported-dialect"
  );
}

// ---- Declarative, quote-by-construction DDL builder ----
//
// Every column identifier is emitted through safeSql.quoteIdentifier so
// the on-disk name preserves its camelCase EXACTLY on every dialect.
// Postgres folds UNQUOTED identifiers to lowercase; the framework's DML
// reads camelCase (`row.rowHash` / `row.monotonicCounter`) and the
// chain-writer INSERTs safeSql.quoteIdentifier-quoted camelCase columns,
// so the DDL MUST quote to match — an unquoted DDL silently breaks the
// audit chain, consent chain, and cluster leadership on Postgres
// (the INSERT targets a column that doesn't exist; SELECT * returns
// lowercase keys). Quoting also makes reserved-word columns (`key`,
// `count`, `name`) safe by construction.
//
// A column entry is one of:
//   { col: "<name>", def: "<TYPE> [constraints]" }   → "<name>" <TYPE> ...
//   { pk:  ["<col>", ...] }                            → PRIMARY KEY ("a", "b")
//   { raw: "<verbatim clause>" }                       → table-level CHECK etc.
// An index entry is { suffix, cols: [...], unique? }.
//
// Each builder returns { create: <CREATE TABLE SQL>, indexes: [...] }.
// All DDL uses IF NOT EXISTS so re-running is idempotent.

// safeSql.quoteIdentifier dialect token: mysql → backtick, everything
// else → double-quote (postgres + sqlite share the SQL-standard form).
function _qd(dialect) {
  return dialect === "mysql" ? "mysql" : (dialect === "sqlite" ? "sqlite" : "postgres");
}

function _buildCreate(name, dialect, columns) {
  var qd = _qd(dialect);
  var parts = columns.map(function (c) {
    if (c.raw) return "  " + c.raw;
    if (c.pk) {
      return "  PRIMARY KEY (" +
        c.pk.map(function (k) { return safeSql.quoteIdentifier(k, qd); }).join(", ") + ")";
    }
    return "  " + safeSql.quoteIdentifier(c.col, qd) + " " + c.def;
  });
  return "CREATE TABLE IF NOT EXISTS " + name + " (" + parts.join(",") + ")";
}

// Cap a generated index name to the strictest dialect identifier limit
// (Postgres NAMEDATALEN 63). A longer name is truncated with a short stable
// checksum suffix so two long names cannot collide after truncation. The
// name is a fresh label (never quoted / re-referenced), so sanitizing to a
// bare identifier is safe.
function _capIndexName(raw) {
  // Framework index names are built from controlled identifiers (the
  // _blamejs_* table name + an identifier suffix), so only the length needs
  // bounding - a name over the limit is truncated with a short stable
  // checksum suffix so two long names can't collide after truncation.
  if (raw.length <= safeSql.MAX_IDENTIFIER_LENGTH) return raw;
  var h = 0;
  for (var i = 0; i < raw.length; i += 1) h = (h * 31 + raw.charCodeAt(i)) >>> 0;
  return raw.slice(0, safeSql.MAX_IDENTIFIER_LENGTH - 9) + "_" + h.toString(36);
}

function _buildIndexes(name, dialect, indexes) {
  var qd = _qd(dialect);
  // MySQL has no CREATE INDEX IF NOT EXISTS — the clause is a syntax error
  // there. Postgres + SQLite support it (idempotent re-creation). On MySQL
  // the bare CREATE INDEX is emitted and ensureSchema swallows the
  // duplicate-key-name error on re-run so the idempotence contract holds.
  // The keyword phrase is a per-dialect string LITERAL (not a keyword + a
  // variable) so the identifier-quoting detector reads it as the static
  // clause it is.
  var createIndex = dialect === "mysql" ? "CREATE INDEX " : "CREATE INDEX IF NOT EXISTS ";
  var createUnique = dialect === "mysql" ? "CREATE UNIQUE INDEX " : "CREATE UNIQUE INDEX IF NOT EXISTS ";
  return (indexes || []).map(function (ix) {
    var idxName = _capIndexName("idx_" + name + "_" + ix.suffix);
    return (ix.unique ? createUnique : createIndex) + idxName + " ON " + name +
      " (" + ix.cols.map(function (col) { return safeSql.quoteIdentifier(col, qd); }).join(", ") + ")";
  });
}

function _table(name, dialect, columns, indexes) {
  return {
    create:  _buildCreate(name, dialect, columns),
    indexes: _buildIndexes(name, dialect, indexes),
  };
}

function _auditLogDDL(dialect) {
  var t = _types(dialect);
  return _table(tableName("audit_log"), dialect, [
    { col: "_id",              def: t.KT + " PRIMARY KEY" },
    { col: "recordedAt",       def: t.INT + " NOT NULL" },
    { col: "monotonicCounter", def: t.INT + " NOT NULL" },
    { col: "actorUserId",      def: "TEXT" },
    { col: "actorUserIdHash",  def: t.KT },
    { col: "actorIp",          def: "TEXT" },
    { col: "actorUserAgent",   def: "TEXT" },
    { col: "actorSessionId",   def: "TEXT" },
    { col: "action",           def: t.KT + " NOT NULL" },
    { col: "resourceKind",     def: t.KT },
    { col: "resourceId",       def: "TEXT" },
    { col: "resourceIdHash",   def: t.KT },
    { col: "outcome",          def: t.KT + " NOT NULL" },
    { col: "reason",           def: "TEXT" },
    { col: "metadata",         def: "TEXT" },
    { col: "requestId",        def: "TEXT" },
    { col: "prevHash",         def: "TEXT NOT NULL" },
    { col: "rowHash",          def: "TEXT NOT NULL" },
    { col: "nonce",            def: t.BLOB + " NOT NULL" },
    { col: "fencingToken",     def: t.INT + " NOT NULL DEFAULT 0" },
  ], [
    { suffix: "actorUserIdHash", cols: ["actorUserIdHash"] },
    { suffix: "resourceIdHash",  cols: ["resourceIdHash"] },
    { suffix: "recordedAt",      cols: ["recordedAt"] },
    { suffix: "action",          cols: ["action"] },
    { suffix: "resourceKind",    cols: ["resourceKind"] },
    { suffix: "outcome",         cols: ["outcome"] },
    { suffix: "monotonic",       cols: ["monotonicCounter"], unique: true },
  ]);
}

function _consentLogDDL(dialect) {
  var t = _types(dialect);
  return _table(tableName("consent_log"), dialect, [
    { col: "_id",              def: t.KT + " PRIMARY KEY" },
    { col: "recordedAt",       def: t.INT + " NOT NULL" },
    { col: "monotonicCounter", def: t.INT + " NOT NULL" },
    { col: "subjectId",        def: "TEXT NOT NULL" },
    { col: "subjectIdHash",    def: t.KT + " NOT NULL" },
    { col: "purpose",          def: t.KT + " NOT NULL" },
    { col: "lawfulBasis",      def: "TEXT NOT NULL" },
    { col: "action",           def: "TEXT NOT NULL" },
    { col: "scope",            def: "TEXT" },
    { col: "channel",          def: "TEXT NOT NULL" },
    { col: "evidenceRef",      def: "TEXT" },
    { col: "prevHash",         def: "TEXT NOT NULL" },
    { col: "rowHash",          def: "TEXT NOT NULL" },
    { col: "nonce",            def: t.BLOB + " NOT NULL" },
    { col: "fencingToken",     def: t.INT + " NOT NULL DEFAULT 0" },
  ], [
    { suffix: "subjectIdHash", cols: ["subjectIdHash"] },
    { suffix: "recordedAt",    cols: ["recordedAt"] },
    { suffix: "purpose",       cols: ["purpose"] },
    { suffix: "monotonic",     cols: ["monotonicCounter"], unique: true },
  ]);
}

function _auditCheckpointsDDL(dialect) {
  var t = _types(dialect);
  return _table(tableName("audit_checkpoints"), dialect, [
    { col: "_id",                  def: t.KT + " PRIMARY KEY" },
    { col: "createdAt",            def: t.INT + " NOT NULL" },
    { col: "atMonotonicCounter",   def: t.INT + " NOT NULL" },
    { col: "atRowHash",            def: "TEXT NOT NULL" },
    { col: "signature",            def: t.BLOB + " NOT NULL" },
    { col: "publicKeyFingerprint", def: "TEXT NOT NULL" },
    { col: "fencingToken",         def: t.INT + " NOT NULL DEFAULT 0" },
  ], [
    { suffix: "createdAt",     cols: ["createdAt"] },
    { suffix: "chkpt_counter", cols: ["atMonotonicCounter"], unique: true },
  ]);
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
  return _table(tableName("_blamejs_audit_tip"), dialect, [
    { col: "scope",              def: t.KT + " PRIMARY KEY" },
    { col: "atMonotonicCounter", def: t.INT + " NOT NULL" },
    { col: "rowHash",            def: "TEXT" },
    { col: "signedAt",           def: "TEXT" },
    { col: "fencingToken",       def: t.INT + " NOT NULL DEFAULT 0" },
    { raw: "CHECK (" + safeSql.quoteIdentifier("scope", _qd(dialect)) + " = 'audit')" },
  ], []);
}

// Same shape + invariants as audit_tip but for the consent chain.
// Updated on every consent.grant / consent.withdraw write so the boot-
// time rollback check can detect external-db rollback against the
// consent chain (previously only the audit chain had this protection).
function _consentTipDDL(dialect) {
  var t = _types(dialect);
  return _table(tableName("_blamejs_consent_tip"), dialect, [
    { col: "scope",              def: t.KT + " PRIMARY KEY" },
    { col: "atMonotonicCounter", def: t.INT + " NOT NULL" },
    { col: "rowHash",            def: "TEXT" },
    { col: "signedAt",           def: "TEXT" },
    { col: "fencingToken",       def: t.INT + " NOT NULL DEFAULT 0" },
    { raw: "CHECK (" + safeSql.quoteIdentifier("scope", _qd(dialect)) + " = 'consent')" },
  ], []);
}

// _blamejs_audit_purge_anchor — single-row chain-origin anchor written
// by audit-tools.purge(). Holds the lastRowHash of the most recently
// purged range so verifyChain can ground its walk at the new origin.
// Single-row invariant via PRIMARY KEY on the constant-valued `scope`
// column (matches _blamejs_audit_tip pattern).
function _auditPurgeAnchorDDL(dialect) {
  var t = _types(dialect);
  return _table(tableName("_blamejs_audit_purge_anchor"), dialect, [
    { col: "scope",             def: t.KT + " PRIMARY KEY" },
    { col: "lastPurgedCounter", def: t.INT + " NOT NULL" },
    { col: "lastPurgedRowHash", def: "TEXT NOT NULL" },
    { col: "archiveBundleId",   def: "TEXT NOT NULL" },
    { col: "purgedAt",          def: t.INT + " NOT NULL" },
    { raw: "CHECK (" + safeSql.quoteIdentifier("scope", _qd(dialect)) + " = 'audit')" },
  ], []);
}

// _blamejs_scheduler_ticks — exactly-once tick-claim table. PRIMARY KEY
// on composite tickKey makes concurrent INSERTs race; the loser skips
// the tick. claimedBy carries the node id for diagnostic.
function _schedulerTicksDDL(dialect) {
  var t = _types(dialect);
  return _table(tableName("_blamejs_scheduler_ticks"), dialect, [
    { col: "tickKey",         def: t.KT + " PRIMARY KEY" },
    { col: "name",            def: "TEXT NOT NULL" },
    { col: "scheduledAtUnix", def: t.INT + " NOT NULL" },
    { col: "claimedAtUnix",   def: t.INT + " NOT NULL" },
    { col: "claimedBy",       def: "TEXT" },
  ], [
    { suffix: "scheduledAt", cols: ["scheduledAtUnix"] },
  ]);
}

// _blamejs_rate_limit_counters — fixed-window counter table for the
// cluster-shared rate-limit backend. PRIMARY KEY on the rate-limit
// key lets INSERT...ON CONFLICT atomically increment within a window
// and roll over on window advance. The windowStart index supports
// retention sweeps of expired windows.
function _rateLimitCountersDDL(dialect) {
  var t = _types(dialect);
  return _table(tableName("_blamejs_rate_limit_counters"), dialect, [
    { col: "key",         def: t.KT + " PRIMARY KEY" },
    { col: "windowStart", def: t.INT + " NOT NULL" },
    { col: "count",       def: t.INT + " NOT NULL DEFAULT 0" },
  ], [
    { suffix: "windowStart", cols: ["windowStart"] },
  ]);
}

// _blamejs_pubsub_messages — cluster fan-out for `b.pubsub` (the
// generalization of the previous WebSocket-specific table). publish()
// on any node writes a row; other nodes poll for new ids past their
// last seen and dispatch to local subscribers. Auto-incrementing id
// is essential — postgres needs BIGSERIAL, sqlite gets INTEGER PRIMARY
// KEY (which auto-increments implicitly), mysql gets BIGINT
// AUTO_INCREMENT (which requires an explicit PRIMARY KEY clause).
function _pubsubMessagesDDL(dialect) {
  var t = _types(dialect);
  var idType = dialect === "postgres"
    ? "BIGSERIAL PRIMARY KEY"
    : (dialect === "mysql"
        ? "BIGINT AUTO_INCREMENT PRIMARY KEY"
        : "INTEGER PRIMARY KEY AUTOINCREMENT");
  return _table(tableName("_blamejs_pubsub_messages"), dialect, [
    { col: "id",          def: idType },
    { col: "topic",       def: "TEXT NOT NULL" },
    { col: "payload",     def: "TEXT NOT NULL" },
    { col: "publishedAt", def: t.INT + " NOT NULL" },
    { col: "publishedBy", def: "TEXT NOT NULL" },
  ], [
    { suffix: "publishedAt", cols: ["publishedAt"] },
  ]);
}

function _apiEncryptNoncesDDL(dialect) {
  var t = _types(dialect);
  return _table(tableName("_blamejs_api_encrypt_nonces"), dialect, [
    { col: "nonceHash", def: t.KT + " PRIMARY KEY" },
    { col: "expireAt",  def: t.INT + " NOT NULL" },
  ], [
    { suffix: "expireAt", cols: ["expireAt"] },
  ]);
}

// _blamejs_api_keys — operator-facing API-key registry. PRIMARY KEY is
// the namespace-scoped id ("<namespace>:<idHex>"); ownerId/scopes/metadata
// are sealed by cryptoField. ownerIdHash supports indexed listForOwner
// lookups; expiresAt index supports purgeExpired sweeps.
function _apiKeysDDL(dialect) {
  var t = _types(dialect);
  return _table(tableName("_blamejs_api_keys"), dialect, [
    { col: "id",                  def: t.KT + " PRIMARY KEY" },
    { col: "namespace",           def: t.KT + " NOT NULL" },
    { col: "ownerId",             def: "TEXT NOT NULL" },
    { col: "ownerIdHash",         def: t.KT + " NOT NULL" },
    { col: "secretHash",          def: "TEXT NOT NULL" },
    { col: "secondarySecretHash", def: "TEXT" },
    { col: "secondaryExpiresAt",  def: t.INT },
    { col: "scopes",              def: "TEXT" },
    { col: "metadata",            def: "TEXT" },
    { col: "createdAt",           def: t.INT + " NOT NULL" },
    { col: "expiresAt",           def: t.INT },
    { col: "revokedAt",           def: t.INT },
    { col: "lastUsedAt",          def: t.INT },
    { col: "prefix",              def: "TEXT NOT NULL" },
  ], [
    { suffix: "ownerIdHash",     cols: ["ownerIdHash"] },
    { suffix: "namespace_owner", cols: ["namespace", "ownerIdHash"] },
    { suffix: "expiresAt",       cols: ["expiresAt"] },
  ]);
}

// _blamejs_sessions — DB-backed session store. Mirrors the local-SQLite
// schema in db.js's FRAMEWORK_SCHEMA so single-node and cluster-mode
// behavior is identical at the column level. Sealed columns (userId,
// data) are stored vault-sealed; sidHash is the PRIMARY KEY (the raw
// session id never lands here).
function _sessionsDDL(dialect) {
  var t = _types(dialect);
  return _table(tableName("_blamejs_sessions"), dialect, [
    { col: "sidHash",      def: t.KT + " PRIMARY KEY" },
    { col: "userId",       def: "TEXT NOT NULL" },
    { col: "userIdHash",   def: t.KT + " NOT NULL" },
    { col: "data",         def: "TEXT" },
    { col: "createdAt",    def: t.INT + " NOT NULL" },
    { col: "expiresAt",    def: t.INT + " NOT NULL" },
    { col: "lastActivity", def: t.INT + " NOT NULL" },
  ], [
    { suffix: "userIdHash", cols: ["userIdHash"] },
    { suffix: "expiresAt",  cols: ["expiresAt"] },
  ]);
}

// _blamejs_session_valid_from — monotonic per-subject valid-from boundary for
// stateless-token revocation. Mirrors the local-SQLite schema in db.js's
// FRAMEWORK_SCHEMA so single-node and cluster behavior are identical.
// subjectHash is the PRIMARY KEY (the plaintext subject id never lands here);
// validFromEpoch is the monotonic boundary (ms); updatedAt records the bump.
function _sessionValidFromDDL(dialect) {
  var t = _types(dialect);
  return _table(tableName("_blamejs_session_valid_from"), dialect, [
    { col: "subjectHash",    def: t.KT + " PRIMARY KEY" },
    { col: "validFromEpoch", def: t.INT + " NOT NULL" },
    { col: "updatedAt",      def: t.INT + " NOT NULL" },
  ], []);
}

// _blamejs_jobs — local-protocol queue jobs. Mirrors db.js's
// FRAMEWORK_SCHEMA for the same table; sealed columns (payload,
// lastError) are stored vault-sealed. Indexes target the lease
// hot-path (queueName + status + availableAt) and lease-expiry
// sweep (leaseExpiresAt).
function _jobsDDL(dialect) {
  var t = _types(dialect);
  return _table(tableName("_blamejs_jobs"), dialect, [
    { col: "_id",            def: t.KT + " PRIMARY KEY" },
    { col: "queueName",      def: t.KT + " NOT NULL" },
    { col: "payload",        def: "TEXT" },
    { col: "status",         def: t.KT + " NOT NULL" },
    { col: "enqueuedAt",     def: t.INT + " NOT NULL" },
    { col: "availableAt",    def: t.INT + " NOT NULL" },
    { col: "leasedAt",       def: t.INT },
    { col: "leaseExpiresAt", def: t.INT },
    { col: "attempts",       def: t.INT + " NOT NULL DEFAULT 0" },
    { col: "maxAttempts",    def: t.INT + " NOT NULL DEFAULT 5" },
    { col: "lastError",      def: "TEXT" },
    { col: "finishedAt",     def: t.INT },
    { col: "traceId",        def: "TEXT" },
    { col: "classification", def: "TEXT" },
    { col: "priority",       def: t.INT + " NOT NULL DEFAULT 0" },
    { col: "repeatCron",     def: "TEXT" },
    { col: "repeatTimezone", def: "TEXT" },
    { col: "flowId",         def: t.KT },
    { col: "flowChildName",  def: "TEXT" },
    { col: "dependsOn",      def: "TEXT" },
  ], [
    { suffix: "lease",          cols: ["queueName", "status", "availableAt"] },
    { suffix: "priority",       cols: ["queueName", "status", "priority", "availableAt"] },
    { suffix: "flow",           cols: ["flowId"] },
    { suffix: "leaseExpiresAt", cols: ["leaseExpiresAt"] },
    { suffix: "finishedAt",     cols: ["finishedAt"] },
  ]);
}

// _blamejs_seeders — registry of applied seed files for the b.seeders
// primitive (lib/seeders.js). Composite PK (env, name) so the same
// filename can apply per env without collision. rerunnable=1 entries
// have their appliedAt updated in place on each run; non-rerunnable
// entries are insert-once.
function _seedersDDL(dialect) {
  var t = _types(dialect);
  return _table(tableName("_blamejs_seeders"), dialect, [
    { col: "env",         def: t.KT + " NOT NULL" },
    { col: "name",        def: t.KT + " NOT NULL" },
    { col: "description", def: "TEXT" },
    { col: "appliedAt",   def: "TEXT NOT NULL" },
    { col: "rerunnable",  def: t.INT + " NOT NULL DEFAULT 0" },
    { pk: ["env", "name"] },
  ], []);
}

// _blamejs_seeders_lock — single-row advisory lock matching the
// _blamejs_migrations_lock pattern. CHECK enforces single row.
function _seedersLockDDL(dialect) {
  var t = _types(dialect);
  return _table(tableName("_blamejs_seeders_lock"), dialect, [
    { col: "scope",    def: t.KT + " PRIMARY KEY CHECK (" +
                            safeSql.quoteIdentifier("scope", _qd(dialect)) + " = 'lock')" },
    { col: "lockedAt", def: t.INT + " NOT NULL" },
    { col: "lockedBy", def: "TEXT NOT NULL" },
  ], []);
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
  return _table(tableName("_blamejs_cache"), dialect, [
    { col: "cacheKey",  def: t.KT + " PRIMARY KEY" },
    { col: "valueJson", def: "TEXT NOT NULL" },
    { col: "expiresAt", def: t.INT + " NOT NULL" },
    { col: "updatedAt", def: t.INT + " NOT NULL" },
  ], [
    { suffix: "expiresAt", cols: ["expiresAt"] },
  ]);
}

// _blamejs_cache_tags — tag→cacheKey junction for cluster-backend
// tag invalidation. b.cache.invalidateTag(t) finds matching cacheKeys
// via the indexed `tag` column, deletes them from _blamejs_cache, and
// drops the junction rows. Cleared on cache.clear() and del() too.
function _cacheTagsDDL(dialect) {
  // Junction table is TEXT-only, but every column participates in a key
  // (composite PK + the tag index), so all take the key-text token —
  // VARCHAR(n) on MySQL (TEXT in a key is refused there), plain TEXT on
  // Postgres + SQLite.
  var t = _types(dialect);
  return _table(tableName("_blamejs_cache_tags"), dialect, [
    { col: "cacheKey", def: t.KT + " NOT NULL" },
    { col: "tag",      def: t.KT + " NOT NULL" },
    { pk: ["cacheKey", "tag"] },
  ], [
    { suffix: "tag", cols: ["tag"] },
  ]);
}

// _blamejs_break_glass_policies — column-level break-glass policy
// registry. One row per (table) declares which columns are
// glass-locked + the operator's grant rules. Sealed columns hide
// column-list / factor-list / bypass config from cleartext browsing.
function _breakGlassPoliciesDDL(dialect) {
  var t = _types(dialect);
  return _table(tableName("_blamejs_break_glass_policies"), dialect, [
    { col: "tableName",                def: t.KT + " PRIMARY KEY" },
    { col: "columnsJson",              def: "TEXT NOT NULL" },
    { col: "factorsJson",              def: "TEXT NOT NULL" },
    { col: "cryptographic",            def: t.INT + " NOT NULL DEFAULT 0" },
    { col: "grantTtlMs",               def: t.INT + " NOT NULL" },
    { col: "maxRowsPerGrant",          def: t.INT + " NOT NULL DEFAULT 1" },
    { col: "reasonRequired",           def: t.INT + " NOT NULL DEFAULT 1" },
    { col: "reasonMinLength",          def: t.INT + " NOT NULL DEFAULT 12" },
    { col: "pinIp",                    def: t.INT + " NOT NULL DEFAULT 1" },
    { col: "sessionPin",               def: t.INT + " NOT NULL DEFAULT 1" },
    { col: "onLockedAccess",           def: t.DT + " NOT NULL DEFAULT 'throw'" },
    { col: "requireScope",             def: "TEXT" },
    { col: "serviceAccountBypassJson", def: "TEXT" },
    { col: "dekSealed",                def: "TEXT" },
    { col: "auditReasonStorage",       def: t.DT + " NOT NULL DEFAULT 'cleartext'" },
    { col: "updatedAt",                def: t.INT + " NOT NULL" },
  ], []);
}

// _blamejs_break_glass_grants — issued grants. One row per successful
// step-up. Default maxRowsPerGrant=1 enforces row-by-row auth
// ("each row access = its own grant").
function _breakGlassGrantsDDL(dialect) {
  var t = _types(dialect);
  return _table(tableName("_blamejs_break_glass_grants"), dialect, [
    { col: "_id",               def: t.KT + " PRIMARY KEY" },
    { col: "issuedToActorId",   def: "TEXT NOT NULL" },
    { col: "issuedToActorHash", def: t.KT + " NOT NULL" },
    { col: "factorType",        def: "TEXT NOT NULL" },
    { col: "reasonSealed",      def: "TEXT" },
    { col: "scopeTable",        def: t.KT + " NOT NULL" },
    { col: "scopeColumnsJson",  def: "TEXT NOT NULL" },
    { col: "issuedAt",          def: t.INT + " NOT NULL" },
    { col: "expiresAt",         def: t.INT + " NOT NULL" },
    { col: "maxRowsPerGrant",   def: t.INT + " NOT NULL" },
    { col: "rowsConsumed",      def: t.INT + " NOT NULL DEFAULT 0" },
    { col: "revokedAt",         def: t.INT },
    { col: "sessionId",         def: "TEXT" },
    { col: "ip",                def: "TEXT" },
    { col: "kwGrantHalf",       def: "TEXT" },
  ], [
    { suffix: "actor",   cols: ["issuedToActorHash"] },
    { suffix: "table",   cols: ["scopeTable"] },
    { suffix: "expires", cols: ["expiresAt"] },
    { suffix: "revoked", cols: ["revokedAt"] },
  ]);
}

// Every framework-owned table builder, in creation order. Single source
// for ensureSchema's DDL pass AND the canonical-column registry below.
function _allDDLs(dialect) {
  return [
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
    _sessionValidFromDDL(dialect),
    _jobsDDL(dialect),
    _cacheDDL(dialect),
    _cacheTagsDDL(dialect),
    _seedersDDL(dialect),
    _seedersLockDDL(dialect),
    _breakGlassPoliciesDDL(dialect),
    _breakGlassGrantsDDL(dialect),
  ];
}

// Canonical, case-preserving column names across every framework table —
// derived from the GENERATED DDL (the only quoted identifiers in a CREATE
// statement are the column names; the table name is unquoted), so the set
// can never drift from the actual schema. The codebase-patterns
// `framework-column-must-be-quoted` detector consumes this set to flag any
// camelCase framework-column reference left unquoted in SQL, which would
// fold to lowercase on Postgres and miss the column. Computed once over
// both supported dialects at module load.
var CANONICAL_COLUMNS = (function () {
  var set = new Set();
  var all = _allDDLs("postgres").concat(_allDDLs("sqlite"));
  for (var i = 0; i < all.length; i++) {
    var quoted = all[i].create.match(/"([A-Za-z_][A-Za-z0-9_]*)"/g) || [];
    for (var j = 0; j < quoted.length; j++) set.add(quoted[j].slice(1, -1));
  }
  return set;
})();

// Per-column type CATEGORY ("int" | "blob" | "text"), derived from the
// generated DDL so it can never drift from the real schema. Drivers
// disagree on the JS shape of non-text columns: node-postgres returns
// BIGINT as a STRING and BYTEA as a Buffer; better-sqlite3 returns
// INTEGER as a number and BLOB as a Buffer. coerceRow() uses this map to
// normalize every framework column to one stable JS shape regardless of
// backend — without it, BIGINT-as-string breaks numeric comparisons and
// hash-chain recomputation on Postgres (the chain only verified on
// SQLite). Computed once over both supported dialects at module load.
var COLUMN_TYPES = (function () {
  var map = {};
  var all = _allDDLs("postgres").concat(_allDDLs("sqlite"));
  // Match a quoted column name followed by its TYPE word (the PK-clause
  // `("cacheKey", "tag")` form has a comma/paren after the name, never a
  // type word, so it is correctly skipped).
  var re = /"([A-Za-z_][A-Za-z0-9_]*)"\s+([A-Za-z]+)/g;
  for (var i = 0; i < all.length; i++) {
    var m; re.lastIndex = 0;
    while ((m = re.exec(all[i].create)) !== null) {
      var col = m[1];
      if (Object.prototype.hasOwnProperty.call(map, col)) continue;  // first def wins
      var typeWord = m[2].toUpperCase();
      map[col] = (typeWord === "BIGINT" || typeWord === "INTEGER" ||
                  typeWord === "INT"    || typeWord === "BIGSERIAL")
        ? "int"
        : (typeWord === "BYTEA" || typeWord === "BLOB") ? "blob" : "text";
    }
  }
  return Object.freeze(map);
})();

/**
 * @primitive b.frameworkSchema.coerceRow
 * @signature b.frameworkSchema.coerceRow(row)
 * @since     0.14.29
 * @status    stable
 * @related   b.frameworkSchema.coerceRows, b.externalDb.query
 *
 * Normalize one driver-returned framework row to a type-stable JS shape
 * using `COLUMN_TYPES`, so a framework column reads identically on every
 * backend: `int` columns become JS numbers (node-postgres hands BIGINT
 * back as a string), `blob` columns become Buffers. `text` columns and
 * any column NOT in the framework schema (operator tables, computed
 * aliases) pass through untouched; `null` stays `null`. Idempotent — safe
 * to call on an already-coerced or SQLite-shaped row. Mutates and returns
 * the row.
 *
 * A BIGINT beyond `Number.MAX_SAFE_INTEGER` is left as a string rather
 * than silently losing precision (framework counters/timestamps stay well
 * within 2^53, so this never bites in practice).
 *
 * @example
 *   var row = frameworkSchema.coerceRow(driverRow);
 *   typeof row.monotonicCounter;  // → "number" (was "1" on Postgres)
 *   Buffer.isBuffer(row.nonce);   // → true
 */
function coerceRow(row) {
  if (!row || typeof row !== "object") return row;
  var keys = Object.keys(row);
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    var cat = COLUMN_TYPES[k];
    if (!cat) continue;
    var v = row[k];
    if (v === null || v === undefined) continue;
    if (cat === "int") {
      // node-postgres returns BIGINT / int8 as a decimal string. Coerce
      // back to a JS number only when it round-trips exactly as a safe
      // integer (canonical decimal, no leading zeros or sign padding);
      // leave anything outside safe-integer range as the string so no
      // precision is silently lost.
      if (typeof v === "string") {
        var n = Number(v);
        if (Number.isSafeInteger(n) && String(n) === v) row[k] = n;
      }
    } else if (cat === "blob") {
      if (!Buffer.isBuffer(v) && v instanceof Uint8Array) row[k] = Buffer.from(v);
    }
  }
  return row;
}

/**
 * @primitive b.frameworkSchema.coerceRows
 * @signature b.frameworkSchema.coerceRows(rows)
 * @since     0.14.29
 * @status    stable
 * @related   b.frameworkSchema.coerceRow
 *
 * Apply `coerceRow` to every row in an array (in place); returns the
 * array. A non-array argument is returned unchanged.
 *
 * @example
 *   var rows = frameworkSchema.coerceRows(await queryAll(sql));
 */
function coerceRows(rows) {
  if (Array.isArray(rows)) {
    for (var i = 0; i < rows.length; i++) coerceRow(rows[i]);
  }
  return rows;
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
 * when `dialect` is anything other than `postgres`, `mysql`, or
 * `sqlite`.
 *
 * @opts
 *   externalDbBackend: string,     // backend name registered with b.externalDb (required)
 *   dialect:           "postgres"|"mysql"|"sqlite",  // default: "postgres"
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
  if (dialect !== "postgres" && dialect !== "sqlite" && dialect !== "mysql") {
    throw new FrameworkSchemaError(
      "unsupported dialect '" + dialect + "' (postgres, sqlite, or mysql)",
      "framework-schema/unsupported-dialect"
    );
  }

  var ddls = _allDDLs(dialect);

  var created = [];
  for (var i = 0; i < ddls.length; i++) {
    var d = ddls[i];
    await externalDb.query(d.create, [], { backend: opts.externalDbBackend });
    for (var j = 0; j < d.indexes.length; j++) {
      // MySQL has no CREATE INDEX IF NOT EXISTS, so a second ensureSchema
      // pass re-issues a plain CREATE INDEX and the engine rejects the
      // duplicate index name (error 1061 "Duplicate key name"). That is the
      // intended idempotent end state — the index already exists — so the
      // duplicate error is swallowed on MySQL only; every other dialect uses
      // the native IF NOT EXISTS and never reaches here.
      if (dialect === "mysql") {
        try {
          await externalDb.query(d.indexes[j], [], { backend: opts.externalDbBackend });
        } catch (e) {
          if (!/duplicate|exist|1061/i.test((e && e.message) || "")) throw e;
        }
      } else {
        await externalDb.query(d.indexes[j], [], { backend: opts.externalDbBackend });
      }
    }
    created.push(d.create.match(/CREATE TABLE IF NOT EXISTS\s+(\S+)/)[1]);
  }

  // Append-only WORM enforcement on audit_log / consent_log /
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

// WORM enforcement helper. Idempotent: rebuilding triggers
// per boot is cheap and any operator-applied DROP TRIGGER is restored
// at the next ensureSchema pass.
async function _installWormTriggers(backend, dialect) {
  var wormTables = [
    tableName("audit_log"),
    tableName("consent_log"),
    tableName("audit_checkpoints"),
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
    } else if (dialect === "mysql") {
      // MySQL has no CREATE TRIGGER IF NOT EXISTS, so DROP-then-CREATE
      // is the idempotent shape (matches the Postgres path). The body
      // SIGNALs SQLSTATE '45000' (unhandled user-defined exception) with
      // an append-only MESSAGE_TEXT — MySQL aborts the DELETE/UPDATE and
      // the driver surfaces it as a query-failure audit row, exactly like
      // the Postgres RAISE EXCEPTION and the SQLite RAISE(ABORT).
      var qt = "`" + t + "`";
      await externalDb.query(
        "DROP TRIGGER IF EXISTS no_delete_" + t, [], { backend: backend }
      );
      await externalDb.query(
        "CREATE TRIGGER no_delete_" + t + " BEFORE DELETE ON " + qt +
        " FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = '" +
        t + " is append-only — DELETE prohibited'",
        [], { backend: backend }
      );
      await externalDb.query(
        "DROP TRIGGER IF EXISTS no_update_" + t, [], { backend: backend }
      );
      await externalDb.query(
        "CREATE TRIGGER no_update_" + t + " BEFORE UPDATE ON " + qt +
        " FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = '" +
        t + " is append-only — UPDATE prohibited'",
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
  setTablePrefix:         setTablePrefix,
  getTablePrefix:         getTablePrefix,
  DEFAULT_TABLE_PREFIX:   DEFAULT_TABLE_PREFIX,
  LOCAL_TO_EXTERNAL:      LOCAL_TO_EXTERNAL,
  CANONICAL_COLUMNS:      CANONICAL_COLUMNS,
  COLUMN_TYPES:           COLUMN_TYPES,
  coerceRow:              coerceRow,
  coerceRows:             coerceRows,
  FrameworkSchemaError:   FrameworkSchemaError,
};
