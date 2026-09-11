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
var lazyRequire = require("./lazy-require");
var safeSql = require("./safe-sql");
var { FrameworkError } = require("./framework-error");

// Lazy: cluster-storage requires THIS module at its top level, so a top-of-file
// require back would be a load cycle. Only the driver-error predicates are
// needed here, and only from inside a catch, so the load is deferred to first
// use rather than the two modules being merged to avoid the edge.
var clusterStorage = lazyRequire(function () { return require("./cluster-storage"); });

class FrameworkSchemaError extends FrameworkError {
  constructor(message, code) {
    super(message);
    this.name = "FrameworkSchemaError";
    this.code = code || "framework-schema/invalid";
    this.isFrameworkSchemaError = true;
  }
}

var LOCAL_TO_EXTERNAL = Object.freeze({
  audit_log:          "_blamejs_audit_log",
  consent_log:        "_blamejs_consent_log",
  audit_checkpoints:  "_blamejs_audit_checkpoints",
  _blamejs_audit_tip:   "_blamejs_audit_tip",
  _blamejs_consent_tip: "_blamejs_consent_tip",
  _blamejs_audit_purge_anchor: "_blamejs_audit_purge_anchor",
  _blamejs_scheduler_ticks:    "_blamejs_scheduler_ticks",
  _blamejs_rate_limit_counters: "_blamejs_rate_limit_counters",
  _blamejs_pubsub_messages:        "_blamejs_pubsub_messages",
  _blamejs_api_encrypt_nonces: "_blamejs_api_encrypt_nonces",
  _blamejs_api_keys: "_blamejs_api_keys",
  _blamejs_sessions:  "_blamejs_sessions",
  _blamejs_session_valid_from: "_blamejs_session_valid_from",
  _blamejs_jobs:      "_blamejs_jobs",
  _blamejs_cache:     "_blamejs_cache",
  _blamejs_cache_tags: "_blamejs_cache_tags",
  _blamejs_seeders:        "_blamejs_seeders",
  _blamejs_seeders_lock:   "_blamejs_seeders_lock",
  _blamejs_break_glass_policies: "_blamejs_break_glass_policies",
  _blamejs_break_glass_grants:   "_blamejs_break_glass_grants",
});

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
  return _applyPrefix(localName);
}

var MYSQL_KEY_TEXT_LEN = 191;

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

function _qd(dialect) {
  return dialect === "mysql" ? "mysql" : (dialect === "sqlite" ? "sqlite" : "postgres");
}

function _buildCreate(name, dialect, columns) {
  var qd = _qd(dialect);
  var parts = columns.map(function (c) {
    if (c.raw) return "  " + c.raw;
    if (c.pk) {
      return "  PRIMARY KEY (" +
        c.pk.map(function (k) {
          return safeSql.quoteIdentifier(k, qd, { allowReserved: true });
        }).join(", ") + ")";
    }
    return "  " + safeSql.quoteIdentifier(c.col, qd, { allowReserved: true }) + " " + c.def;
  });
  return "CREATE TABLE IF NOT EXISTS " + _qTable(name, qd) + " (" + parts.join(",") + ")";
}

function _qTable(name, qd) {
  return safeSql.quoteIdentifier(name, qd, { allowReserved: true });
}

function _capIndexName(raw) {
  if (raw.length <= safeSql.MAX_IDENTIFIER_LENGTH) return raw;
  var h = 0;
  for (var i = 0; i < raw.length; i += 1) h = (h * 31 + raw.charCodeAt(i)) >>> 0;
  return raw.slice(0, safeSql.MAX_IDENTIFIER_LENGTH - 9) + "_" + h.toString(36);
}

function _buildIndexes(name, dialect, indexes) {
  var qd = _qd(dialect);
  var createIndex = dialect === "mysql" ? "CREATE INDEX " : "CREATE INDEX IF NOT EXISTS ";
  var createUnique = dialect === "mysql" ? "CREATE UNIQUE INDEX " : "CREATE UNIQUE INDEX IF NOT EXISTS ";
  return (indexes || []).map(function (ix) {
    var idxName = _capIndexName("idx_" + name + "_" + ix.suffix);
    return (ix.unique ? createUnique : createIndex) + idxName + " ON " + _qTable(name, qd) +
      " (" + ix.cols.map(function (col) {
        return safeSql.quoteIdentifier(col, qd, { allowReserved: true });
      }).join(", ") + ")";
  });
}

function _buildAlters(name, dialect, columns, addIfMissing) {
  var qd = _qd(dialect);
  return addIfMissing.map(function (colName) {
    var decl = null;
    for (var i = 0; i < columns.length; i += 1) {
      if (columns[i] && columns[i].col === colName) { decl = columns[i]; break; }
    }
    if (!decl) {
      throw new FrameworkSchemaError(
        "additive column '" + colName + "' is not declared on " + name,
        "framework-schema/undeclared-additive-column"
      );
    }
    if (/\bNOT\s+NULL\b/i.test(decl.def) && !/\bDEFAULT\b/i.test(decl.def)) {
      throw new FrameworkSchemaError(
        "additive column '" + colName + "' on " + name +
          " is NOT NULL without a DEFAULT — it cannot be added to an existing table",
        "framework-schema/invalid-additive-column"
      );
    }
    // allow:hand-rolled-sql — framework-declared column DDL; identifiers quoted by construction
    return "ALTER TABLE " + _qTable(name, qd) + " ADD COLUMN " +
      safeSql.quoteIdentifier(colName, qd, { allowReserved: true }) + " " + decl.def;
  });
}

function _table(name, dialect, columns, indexes, addIfMissing) {
  return {
    name:    name,
    create:  _buildCreate(name, dialect, columns),
    indexes: _buildIndexes(name, dialect, indexes),
    alters:  (addIfMissing && addIfMissing.length > 0)
      ? _buildAlters(name, dialect, columns, addIfMissing) : [],
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

function _auditPurgeAnchorDDL(dialect) {
  var t = _types(dialect);
  return _table(tableName("_blamejs_audit_purge_anchor"), dialect, [
    { col: "scope",             def: t.KT + " PRIMARY KEY" },
    { col: "lastPurgedCounter", def: t.INT + " NOT NULL" },
    { col: "lastPurgedRowHash", def: "TEXT NOT NULL" },
    { col: "archiveBundleId",   def: "TEXT NOT NULL" },
    { col: "purgedAt",          def: t.INT + " NOT NULL" },
    { col: "firstPurgedCounter",   def: t.INT + " NOT NULL DEFAULT 0" },
    { col: "archiveRowsDigest",    def: "TEXT" },
    { col: "archiveCheckpointDigest", def: "TEXT" },
    { col: "archiveManifestDigest", def: "TEXT" },
    { col: "signature",            def: t.BLOB },
    { col: "publicKeyFingerprint", def: "TEXT" },
    { col: "fencingToken",         def: t.INT + " NOT NULL DEFAULT 0" },
    { raw: "CHECK (" + safeSql.quoteIdentifier("scope", _qd(dialect)) + " = 'audit')" },
  ], [], ["firstPurgedCounter", "archiveRowsDigest", "archiveCheckpointDigest",
          "archiveManifestDigest",
          "signature", "publicKeyFingerprint", "fencingToken"]);
}

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

function _sessionValidFromDDL(dialect) {
  var t = _types(dialect);
  return _table(tableName("_blamejs_session_valid_from"), dialect, [
    { col: "subjectHash",    def: t.KT + " PRIMARY KEY" },
    { col: "validFromEpoch", def: t.INT + " NOT NULL" },
    { col: "updatedAt",      def: t.INT + " NOT NULL" },
  ], []);
}

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

function _seedersLockDDL(dialect) {
  var t = _types(dialect);
  return _table(tableName("_blamejs_seeders_lock"), dialect, [
    { col: "scope",    def: t.KT + " PRIMARY KEY CHECK (" +
                            safeSql.quoteIdentifier("scope", _qd(dialect)) + " = 'lock')" },
    { col: "lockedAt", def: t.INT + " NOT NULL" },
    { col: "lockedBy", def: "TEXT NOT NULL" },
  ], []);
}

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

function _cacheTagsDDL(dialect) {
  var t = _types(dialect);
  return _table(tableName("_blamejs_cache_tags"), dialect, [
    { col: "cacheKey", def: t.KT + " NOT NULL" },
    { col: "tag",      def: t.KT + " NOT NULL" },
    { pk: ["cacheKey", "tag"] },
  ], [
    { suffix: "tag", cols: ["tag"] },
  ]);
}

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

var CANONICAL_COLUMNS = (function () {
  var set = new Set();
  var all = _allDDLs("postgres").concat(_allDDLs("sqlite"));
  for (var i = 0; i < all.length; i++) {
    var quoted = all[i].create.match(/"([A-Za-z_][A-Za-z0-9_]*)"/g) || [];
    for (var j = 0; j < quoted.length; j++) {
      var ident = quoted[j].slice(1, -1);
      if (ident === all[i].name) continue;
      set.add(ident);
    }
  }
  return set;
})();

var COLUMN_TYPES = (function () {
  var map = {};
  var all = _allDDLs("postgres").concat(_allDDLs("sqlite"));
  var re = /"([A-Za-z_][A-Za-z0-9_]*)"\s+([A-Za-z]+)/g;
  for (var i = 0; i < all.length; i++) {
    var m; re.lastIndex = 0;
    while ((m = re.exec(all[i].create)) !== null) {
      var col = m[1];
      if (Object.prototype.hasOwnProperty.call(map, col)) continue;
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
    for (var a = 0; a < d.alters.length; a++) {
      try {
        await externalDb.query(d.alters[a], [], { backend: opts.externalDbBackend });
      } catch (e) {
        var msg = (e && e.message) || "";
        if (!/duplicate column|column .* already exists|1060|42701/i.test(msg)) throw e;
      }
    }
    for (var j = 0; j < d.indexes.length; j++) {
      if (dialect === "mysql") {
        try {
          await externalDb.query(d.indexes[j], [], { backend: opts.externalDbBackend });
        } catch (e) {
          if (!clusterStorage().duplicateIndexCode(e)) throw e;
        }
      } else {
        await externalDb.query(d.indexes[j], [], { backend: opts.externalDbBackend });
      }
    }
    created.push(d.name);
  }

  await _installWormTriggers(opts.externalDbBackend, dialect);

  return { tables: created };
}

function _wrapMysqlTriggerPrivilegeError(e, t) {
  var msg = (e && e.message) || String(e);
  if (!/1419|SUPER privilege and binary logging/i.test(msg)) return e;
  return new FrameworkSchemaError(
    "cannot install the append-only guard on `" + t + "`: MySQL refuses " +
    "CREATE TRIGGER from a role without SUPER while binary logging is enabled. " +
    "The TRIGGER privilege alone is not sufficient. Grant SUPER to the role the " +
    "framework connects as, or set log_bin_trust_function_creators=1 on the " +
    "server, then start again. The guard is what stops an audit row being " +
    "removed in-band, so it is not installed silently. Original error: " + msg,
    "framework-schema/mysql-trigger-privilege");
}

function _sqliteWormWhen(boundedBy, anchorTable) {
  if (boundedBy == null) return "";
  return 'WHEN NOT COALESCE(OLD."' + boundedBy + '" <= ' +
    '(SELECT "lastPurgedCounter" FROM "' + anchorTable + '" WHERE "scope" = \'audit\'), 0) ';
}

async function _installDeleteTrigger(backend, dialect, t, boundedBy) {
  var anchorTable = tableName("_blamejs_audit_purge_anchor");
  if (dialect === "mysql") {
    await externalDb.query(
      "DROP TRIGGER IF EXISTS no_delete_" + t, [], { backend: backend });
    var deny = "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = '" +
      t + " is append-only — DELETE prohibited'";
    var permitted = "COALESCE(OLD.`" + boundedBy + "` <= (SELECT `lastPurgedCounter` FROM `" +
      anchorTable + "` WHERE `scope` = 'audit'), FALSE)";
    var body = boundedBy == null
      ? "BEGIN " + deny + "; END"
      : "BEGIN IF NOT " + permitted + " THEN " + deny + "; END IF; END";
    try {
      await externalDb.query(
        "CREATE TRIGGER no_delete_" + t + " BEFORE DELETE ON `" + t + "` " +
        "FOR EACH ROW " + body,
        [], { backend: backend });
    } catch (e) { throw _wrapMysqlTriggerPrivilegeError(e, t); }
    return;
  }
  await externalDb.query(
    'DROP TRIGGER IF EXISTS "no_delete_' + t + '"', [], { backend: backend });
  await externalDb.query(
    'CREATE TRIGGER "no_delete_' + t + '" ' +
    'BEFORE DELETE ON "' + t + '" ' + _sqliteWormWhen(boundedBy, anchorTable) +
    "BEGIN SELECT RAISE(ABORT, '" + t + " is append-only — DELETE prohibited'); END",
    [], { backend: backend });
}

var WORM_DELETE_ALLOWED_WHEN = {
  audit_log:         "monotonicCounter",
  audit_checkpoints: "atMonotonicCounter",
  consent_log:       null,
};

function _wormBoundaryColumn(logicalName) {
  return Object.prototype.hasOwnProperty.call(WORM_DELETE_ALLOWED_WHEN, logicalName)
    ? WORM_DELETE_ALLOWED_WHEN[logicalName] : null;
}

async function _installWormTriggers(backend, dialect) {
  var wormTables = [
    tableName("audit_log"),
    tableName("consent_log"),
    tableName("audit_checkpoints"),
  ];
  var logicalNames = ["audit_log", "consent_log", "audit_checkpoints"];
  var anchorTable = tableName("_blamejs_audit_purge_anchor");
  for (var i = 0; i < wormTables.length; i++) {
    var t = wormTables[i];
    var boundedBy = _wormBoundaryColumn(logicalNames[i]);
    if (dialect === "postgres") {
      var fnName = t + "_worm_block";
      var qtPg = _qTable(t, "postgres");
      var allowClause = boundedBy === null ? "FALSE"
        : 'COALESCE(OLD."' + boundedBy + '" <= (SELECT "lastPurgedCounter" FROM ' +
          _qTable(anchorTable, "postgres") + " WHERE scope = 'audit'), FALSE)";
      await externalDb.query(
        "CREATE OR REPLACE FUNCTION " + fnName + "() RETURNS trigger AS $$ " +
        "BEGIN " +
        "IF TG_OP = 'DELETE' AND (" + allowClause + ") THEN RETURN OLD; END IF; " +
        "RAISE EXCEPTION '" + t + " is append-only — % prohibited', TG_OP " +
        "USING ERRCODE = '0A000'; END; $$ LANGUAGE plpgsql",
        [], { backend: backend }
      );
      await externalDb.query(
        "DROP TRIGGER IF EXISTS no_delete_" + t + " ON " + qtPg,
        [], { backend: backend }
      );
      await externalDb.query(
        "CREATE TRIGGER no_delete_" + t + " BEFORE DELETE ON " + qtPg +
        " FOR EACH ROW EXECUTE FUNCTION " + fnName + "()",
        [], { backend: backend }
      );
      await externalDb.query(
        "DROP TRIGGER IF EXISTS no_update_" + t + " ON " + qtPg,
        [], { backend: backend }
      );
      await externalDb.query(
        "CREATE TRIGGER no_update_" + t + " BEFORE UPDATE ON " + qtPg +
        " FOR EACH ROW EXECUTE FUNCTION " + fnName + "()",
        [], { backend: backend }
      );
    } else if (dialect === "mysql") {
      var qt = "`" + t + "`";
      await _installDeleteTrigger(backend, dialect, t, boundedBy);
      await externalDb.query(
        "DROP TRIGGER IF EXISTS no_update_" + t, [], { backend: backend }
      );
      try {
        await externalDb.query(
          "CREATE TRIGGER no_update_" + t + " BEFORE UPDATE ON " + qt +
          " FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = '" +
          t + " is append-only — UPDATE prohibited'",
          [], { backend: backend }
        );
      } catch (e) { throw _wrapMysqlTriggerPrivilegeError(e, t); }
    } else {
      await _installDeleteTrigger(backend, dialect, t, boundedBy);
      await externalDb.query(
        'CREATE TRIGGER IF NOT EXISTS "no_update_' + t + '" ' +
        'BEFORE UPDATE ON "' + t + '" ' +
        "BEGIN SELECT RAISE(ABORT, '" + t + " is append-only — UPDATE prohibited'); END",
        [], { backend: backend }
      );
    }
  }
}

/**
 * @primitive b.frameworkSchema.withDeleteTriggersSuspended
 * @signature b.frameworkSchema.withDeleteTriggersSuspended(opts, fn)
 * @since     0.18.58
 * @status    stable
 * @related   b.frameworkSchema.ensureSchema, b.auditTools.purge
 *
 * Run `fn` with the append-only BEFORE-DELETE triggers dropped from the
 * cluster audit tables, then put them back.
 *
 * **The purge does not use this.** Every dialect's guard is now bounded by the
 * purge anchor — it stays installed and permits only the rows the anchor
 * already licenses — so a purge never takes it off, and the window this opens
 * is not on the framework's own path. It remains for an operator performing a
 * supervised removal by hand: it grants nothing they could not do with `DROP
 * TRIGGER` themselves, and it puts back exactly what it took off.
 *
 * Understand the cost before calling it. A `DROP TRIGGER` is global, so for as
 * long as `fn` runs, any other connection holding the framework role can
 * delete audit rows too — the protection is off for the database, not for the
 * caller. The triggers are restored in a `finally`, so they come back whether
 * `fn` succeeded or threw, and a table that could not be restored is named in
 * the error. A process killed mid-call leaves them off until the next
 * `ensureSchema`, which every boot runs.
 *
 * Postgres is not supported: its guard is a trigger FUNCTION shared by every
 * WORM table, so dropping the triggers and putting them back is not the same
 * operation there. `dialect` is required — there is no dialect it would be
 * safe to guess for DDL against an operator's audit tables.
 *
 * @opts
 *   externalDbBackend: string,  // the cluster backend name
 *   dialect:           string,  // mysql | sqlite  (required)
 *
 * @example
 *   await b.frameworkSchema.withDeleteTriggersSuspended(
 *     { externalDbBackend: "primary", dialect: "mysql" },
 *     async function () { await deleteTheArchivedRange(); });
 */
var SUSPENDABLE_DIALECTS = ["mysql", "sqlite"];

async function withDeleteTriggersSuspended(opts, fn) {
  if (!opts || !opts.externalDbBackend) {
    throw new FrameworkSchemaError(
      "withDeleteTriggersSuspended requires { externalDbBackend }",
      "framework-schema/invalid-config"
    );
  }
  if (typeof fn !== "function") {
    throw new FrameworkSchemaError(
      "withDeleteTriggersSuspended requires a function",
      "framework-schema/invalid-config"
    );
  }
  if (typeof opts.dialect !== "string" || opts.dialect === "") {
    throw new FrameworkSchemaError(
      "withDeleteTriggersSuspended requires { dialect } — one of " +
        SUSPENDABLE_DIALECTS.join(", "),
      "framework-schema/invalid-config"
    );
  }
  var dialect = opts.dialect.toLowerCase();
  var backend = opts.externalDbBackend;

  if (SUSPENDABLE_DIALECTS.indexOf(dialect) === -1) {
    throw new FrameworkSchemaError(
      "withDeleteTriggersSuspended does not support " + dialect + ": supported " +
        "dialects are " + SUSPENDABLE_DIALECTS.join(", ") + ". Postgres is " +
        "excluded because its guard is a trigger FUNCTION shared by every WORM " +
        "table, so dropping the triggers and putting them back is not the same " +
        "operation there. Nothing in the framework needs this on any dialect — " +
        "the guard is anchor-bounded and a purge leaves it installed; see " +
        "wormGuardIsAnchorBounded",
      "framework-schema/unsupported-dialect"
    );
  }
  var dropped = [];
  var bodyErr = null;
  var result;
  try {
    var tables = [tableName("audit_log"), tableName("audit_checkpoints")];
    var boundsFor = {};
    boundsFor[tableName("audit_log")] = _wormBoundaryColumn("audit_log");
    boundsFor[tableName("audit_checkpoints")] = _wormBoundaryColumn("audit_checkpoints");
    for (var i = 0; i < tables.length; i += 1) {
      var name = "no_delete_" + tables[i];
      await externalDb.query(   // allow:hand-rolled-sql — trigger DDL
        "DROP TRIGGER IF EXISTS " +
          safeSql.quoteIdentifier(name, dialect === "mysql" ? "mysql" : "sqlite",
            { allowReserved: true }),
        [], { backend: backend });
      dropped.push(tables[i]);
    }
    result = await fn();
  } catch (e) {
    bodyErr = e;
  }

  var unrestored = [];
  for (var r = 0; r < dropped.length; r += 1) {
    try {
      await _installDeleteTrigger(backend, dialect, dropped[r], boundsFor[dropped[r]]);
    } catch (_e) {
      unrestored.push(dropped[r]);
    }
  }

  if (unrestored.length > 0) {
    throw new FrameworkSchemaError(
      "the append-only DELETE guard could not be restored on " +
        unrestored.join(", ") + " — those tables are writable until the next " +
        "ensureSchema, which every boot runs" +
        (bodyErr ? ". The purge itself failed with: " + (bodyErr.message || String(bodyErr)) : ""),
      "framework-schema/worm-guard-not-restored"
    );
  }
  if (bodyErr) throw bodyErr;
  return result;
}

/**
 * @primitive b.frameworkSchema.wormGuardIsAnchorBounded
 * @signature b.frameworkSchema.wormGuardIsAnchorBounded(dialect)
 * @since     0.18.58
 * @status    stable
 * @related   b.frameworkSchema.withDeleteTriggersSuspended, b.auditTools.purge
 *
 * Whether this dialect's append-only guard decides per row against the purge
 * anchor's recorded boundary. When it does, a sanctioned deletion needs
 * nothing from the caller: the anchor is written before the rows go, so the
 * guard already permits exactly what the purge will delete and refuses
 * everything else. When it does not, the caller has to take the guard off for
 * the deletion — see `withDeleteTriggersSuspended` for what that costs.
 *
 * It answers for the guards `ensureSchema` installs, which is every guard on a
 * cluster or external-database volume. A single-node `b.db` volume is NOT in
 * scope: its local SQLite triggers refuse a DELETE outright, and its purge
 * suspends and reinstalls them inside one transaction rather than consulting
 * this. Asking here about that volume would get the answer for a different
 * guard.
 *
 * All three dialects are bounded, by two mechanisms. Postgres and MySQL
 * express the condition in the trigger body — MySQL's needs
 * `IF … THEN SIGNAL …; END IF`, whose internal semicolon makes the body
 * compound, so a protocol driver sends it as one message and only a CLI needs
 * DELIMITER to keep from splitting it. SQLite has no such body, so the
 * condition rides in a `WHEN` clause, where a subquery can read the boundary
 * without the purge ever taking the guard off. A dialect this module installs
 * no guard for is reported unbounded rather than assumed safe.
 *
 * @example
 *   b.frameworkSchema.wormGuardIsAnchorBounded("postgres");  // → true
 *   b.frameworkSchema.wormGuardIsAnchorBounded("sqlite");    // → true
 *   b.frameworkSchema.wormGuardIsAnchorBounded("oracle");    // → false
 */
function wormGuardIsAnchorBounded(dialect) {
  var d = (dialect || "").toLowerCase();
  return d === "postgres" || d === "mysql" || d === "sqlite";
}

module.exports = {
  ensureSchema:           ensureSchema,
  withDeleteTriggersSuspended: withDeleteTriggersSuspended,
  wormGuardIsAnchorBounded: wormGuardIsAnchorBounded,
  _wrapMysqlTriggerPrivilegeErrorForTest: _wrapMysqlTriggerPrivilegeError,
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
