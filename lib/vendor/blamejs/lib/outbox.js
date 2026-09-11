// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Transactional outbox — at-least-once event publication without
 * distributed transactions.
 *
 * Pattern: when handling a request, write the business state change
 * AND an outbox row in the SAME database transaction. A separate
 * publisher worker reads the outbox table, publishes events to the
 * message bus, and marks each row as published. Crashes between the
 * commit and the publish leave the row pending — the worker retries
 * after restart, so every event is delivered at least once.
 *
 *   var outbox = b.outbox.create({
 *     externalDb:    b.externalDb,
 *     table:         "outbox_events",
 *     publisher:     async function (event) { await myBus.publish(event); },
 *     pollIntervalMs: C.TIME.seconds(1),
 *     batchSize:     100,
 *     retryBackoff:  { initialMs: C.TIME.seconds(1),
 *                      maxMs:     C.TIME.minutes(5), factor: 2 },
 *     maxAttempts:   10,
 *     audit:         true,
 *   });
 *
 *   // 1. Inside the operator's transaction
 *   await b.externalDb.transaction(async function (xdb) {
 *     await xdb.query("UPDATE accounts SET balance = balance - $1 WHERE id = $2",
 *                     [amount, accountId]);
 *     await outbox.enqueue({
 *       topic:   "account.debited",
 *       payload: { accountId: accountId, amount: amount },
 *       key:     accountId,
 *       headers: { "trace-id": traceId },
 *     }, xdb);
 *   });
 *
 *   // 2. Publisher worker (poll + dispatch + mark published)
 *   await outbox.start();
 *
 *   // 3. Graceful shutdown
 *   await outbox.stop();
 *
 * Schema:
 *   outbox.declareSchema(externalDb)  — runs idempotent CREATE TABLE +
 *                                       index DDL on the operator's
 *                                       backend. Operators that prefer
 *                                       to manage migrations themselves
 *                                       skip this and write the table
 *                                       in their own migration file.
 *
 * Picking semantics:
 *   - Postgres backends: SELECT ... FOR UPDATE SKIP LOCKED. Multiple
 *     publishers compete cooperatively without deadlocking each other.
 *   - SQLite (single-writer): plain SELECT inside a transaction.
 *
 * Failure:
 *   - publisher throws → row stays pending, attempts++, next_attempt_at
 *     advances by retry-backoff curve.
 *   - attempts > maxAttempts → row marked as 'dead', moved out of the
 *     pending pool, audit emission "outbox.dead-letter".
 *
 * Drop-silent posture:
 *   - Polling failures (DB transiently unreachable) are logged once per
 *     30s and swallowed — the worker keeps polling.
 *   - Publisher exceptions are caught, attempts++, normal retry path.
 */

var C = require("./constants");
var lazyRequire = require("./lazy-require");
var safeAsync = require("./safe-async");
var safeJson = require("./safe-json");
var safeSql = require("./safe-sql");
var sql = require("./sql");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var OutboxError = defineClass("OutboxError", { alwaysPermanent: true });

var audit = lazyRequire(function () { return require("./audit"); });
var observability = lazyRequire(function () { return require("./observability"); });

var DEFAULT_POLL_MS         = C.TIME.seconds(1);
var DEFAULT_BATCH_SIZE      = 100;
var DEFAULT_MAX_ATTEMPTS    = 10;
var DEFAULT_BACKOFF_INITIAL = C.TIME.seconds(1);
var DEFAULT_BACKOFF_MAX     = C.TIME.minutes(5);
var DEFAULT_BACKOFF_FACTOR  = 2;
var DEFAULT_CLAIM_RECLAIM_MS = C.TIME.minutes(5);
var TOPIC_MAX_LEN           = C.BYTES.bytes(255);
var KEY_MAX_LEN             = C.BYTES.bytes(255);

function _validateTableName(name) {
  return safeSql.quoteIdentifier(name, undefined, { allowReserved: true });
}

function _tableOpts(dialect) { return { dialect: dialect, quoteName: true }; }

function _foldTableForDialect(name, dialect) {
  return dialect === "postgres" ? String(name).toLowerCase() : name;
}

function _sqlDialect(externalDb) {
  var d = externalDb && externalDb.dialect;
  if (d === "postgres" || d === "mysql") return d;
  return "sqlite";
}

function _utcNowExpr(externalDb) {
  return new Date();
}

var DEFAULT_DEBEZIUM_CONNECTOR_VERSION = "1.0.0";

function _debeziumSchemaFor(payloadObj) {
  return {
    type: "struct",
    optional: false,
    name:    "blamejs.outbox.Envelope",
    fields: [
      { type: "struct", optional: true, field: "before",
        name: "blamejs.outbox.Row" },
      { type: "struct", optional: true, field: "after",
        name: "blamejs.outbox.Row" },
      { type: "struct", optional: false, field: "source",
        name: "blamejs.outbox.Source",
        fields: [
          { type: "string", optional: false, field: "connector" },
          { type: "string", optional: false, field: "version"   },
          { type: "string", optional: true,  field: "db"        },
          { type: "string", optional: false, field: "table"     },
          { type: "int64",  optional: false, field: "ts_ms"     },
        ],
      },
      { type: "string", optional: false, field: "op" },
      { type: "int64",  optional: false, field: "ts_ms" },
    ],
  };
}

function _toDebeziumEnvelope(rawEvent, opts) {
  var payload = rawEvent.payload && typeof rawEvent.payload === "object"
    ? rawEvent.payload : { value: rawEvent.payload };
  var op = (rawEvent.headers && typeof rawEvent.headers === "object" &&
            typeof rawEvent.headers["debezium-op"] === "string")
    ? rawEvent.headers["debezium-op"]
    : "c";
  var nowMs = Date.now();
  return {
    schema: _debeziumSchemaFor(payload),
    payload: {
      before: (payload && payload.before) || null,
      after:  (payload && payload.after !== undefined) ? payload.after : payload,
      source: {
        /* c8 ignore next 2 */
        connector: opts.connectorName || "blamejs",
        version:   opts.connectorVersion || DEFAULT_DEBEZIUM_CONNECTOR_VERSION,
        db:        opts.dbName || null,
        table:     rawEvent.topic,
        ts_ms:     nowMs,
      },
      op:    op,
      ts_ms: nowMs,
      key:      rawEvent.key       || null,
      headers:  rawEvent.headers   || null,
      attempts: rawEvent.attempts  || 0,
      eventId:  rawEvent.id        || null,
    },
  };
}

function create(opts) {
  validateOpts.requireObject(opts, "outbox", OutboxError);
  validateOpts(opts, [
    "externalDb", "table", "publisher",
    "pollIntervalMs", "batchSize", "maxAttempts", "claimReclaimMs",
    "retryBackoff", "audit", "name",
    "envelope", "connectorName", "connectorVersion", "dbName",
  ], "outbox.create");

  validateOpts.shape(opts, {
    externalDb: function (v) {
      if (!v || typeof v.transaction !== "function") {
        throw new OutboxError("outbox/bad-externaldb",
          "outbox.create: externalDb must be the b.externalDb namespace (with transaction/query)");
      }
      var cap = v.supportsTransactions;
      var atomic = true;
      if (typeof cap === "function") {
        try { atomic = !!cap(); } catch (_e) { atomic = true; }
      } else if (cap === false) {
        atomic = false;
      }
      if (!atomic) {
        throw new OutboxError("outbox/non-atomic-backend",
          "outbox.create: externalDb backend cannot provide interactive " +
          "transactions (supportsTransactions: false — a stateless / " +
          "autocommit-per-statement adapter). The outbox dual-write guarantee " +
          "requires the business write and the enqueue INSERT to commit " +
          "atomically in one transaction; on this backend they would not. " +
          "Supply interactive beginTx / commit / rollback hooks, or a batch " +
          "adapter, on the externalDb backend first.");
      }
    },
    table: function (v) {
      validateOpts.requireNonEmptyString(v,
        "outbox.create: table", OutboxError, "outbox/bad-table");
      _validateTableName(v);
    },
    publisher: function (v) {
      if (typeof v !== "function") {
        throw new OutboxError("outbox/bad-publisher",
          "outbox.create: publisher must be an async function (event) → void");
      }
    },
    pollIntervalMs: "optional-positive-finite",
    batchSize:      "optional-positive-finite",
    maxAttempts:    "optional-positive-finite",
    claimReclaimMs: "optional-positive-finite",
    retryBackoff: {
      optional: true,
      shape: {
        initialMs: "optional-positive-finite",
        maxMs:     "optional-positive-finite",
        factor:    "optional-positive-finite",
      },
    },
    audit:            "optional-boolean",
    name:             "optional-string",
    envelope:         "optional-string",
    connectorName:    "optional-string",
    connectorVersion: "optional-string",
    dbName:           "optional-string",
  }, "outbox.create", OutboxError, "outbox/bad-opts");

  var pollIntervalMs = opts.pollIntervalMs || DEFAULT_POLL_MS;
  var batchSize      = opts.batchSize      || DEFAULT_BATCH_SIZE;
  var maxAttempts    = opts.maxAttempts    || DEFAULT_MAX_ATTEMPTS;
  var claimReclaimMs = opts.claimReclaimMs || DEFAULT_CLAIM_RECLAIM_MS;
  var name           = opts.name           || "outbox";

  var backoff = opts.retryBackoff || {};
  validateOpts.optionalPositiveFinite(backoff.initialMs,
    "outbox.create: retryBackoff.initialMs", OutboxError, "outbox/bad-opts");
  validateOpts.optionalPositiveFinite(backoff.maxMs,
    "outbox.create: retryBackoff.maxMs", OutboxError, "outbox/bad-opts");
  validateOpts.optionalPositiveFinite(backoff.factor,
    "outbox.create: retryBackoff.factor", OutboxError, "outbox/bad-opts");
  var backoffInitial = backoff.initialMs || DEFAULT_BACKOFF_INITIAL;
  var backoffMax     = backoff.maxMs     || DEFAULT_BACKOFF_MAX;
  var backoffFactor  = backoff.factor    || DEFAULT_BACKOFF_FACTOR;

  var auditOn        = opts.audit !== false;
  var externalDb     = opts.externalDb;
  opts = Object.assign({}, opts, { table: _foldTableForDialect(opts.table, _sqlDialect(externalDb)) });
  var publisher      = opts.publisher;
  var envelope       = opts.envelope || "raw";
  if (envelope !== "raw" && envelope !== "debezium") {
    throw new OutboxError("outbox/bad-envelope",
      "outbox.create: envelope must be 'raw' (default) or 'debezium', got " +
      JSON.stringify(envelope));
  }
  var connectorName    = opts.connectorName || "blamejs";
  var connectorVersion = opts.connectorVersion || DEFAULT_DEBEZIUM_CONNECTOR_VERSION;
  var dbName           = opts.dbName || null;

  function _backoffMs(attempts) {
    var ms = backoffInitial * Math.pow(backoffFactor, Math.max(0, attempts - 1));
    if (ms > backoffMax) ms = backoffMax;
    return Math.floor(ms);
  }

  var _emitMetric = observability().namespaced("outbox");
  var _emitAudit = audit().namespaced(null, { audit: auditOn });

  async function enqueue(event, txn) {
    if (!txn || typeof txn.query !== "function") {
      throw new OutboxError("outbox/bad-txn",
        "outbox.enqueue: txn must be the txClient from externalDb.transaction()");
    }
    if (!event || typeof event !== "object") {
      throw new OutboxError("outbox/bad-event",
        "outbox.enqueue: event must be a non-null object");
    }
    if (typeof event.topic !== "string" || event.topic.length === 0 ||
        event.topic.length > TOPIC_MAX_LEN) {
      throw new OutboxError("outbox/bad-event",
        "outbox.enqueue: event.topic must be a non-empty string ≤ " +
        TOPIC_MAX_LEN + " chars");
    }
    if (event.payload === undefined) {
      throw new OutboxError("outbox/bad-event",
        "outbox.enqueue: event.payload is required (JSON-serializable)");
    }
    if (event.key !== undefined && event.key !== null) {
      if (typeof event.key !== "string" || event.key.length > KEY_MAX_LEN) {
        throw new OutboxError("outbox/bad-event",
          "outbox.enqueue: event.key must be a string ≤ " + KEY_MAX_LEN + " chars");
      }
    }
    var headers = event.headers || null;
    if (headers !== null && (typeof headers !== "object" || Array.isArray(headers))) {
      throw new OutboxError("outbox/bad-event",
        "outbox.enqueue: event.headers must be a plain object or null");
    }

    var payloadJson;
    var headersJson;
    try {
      payloadJson = safeJson.stringify(event.payload);
      headersJson = headers ? safeJson.stringify(headers) : null;
    } catch (e) {
      throw new OutboxError("outbox/bad-event",
        "outbox.enqueue: payload/headers must be JSON-serializable: " + e.message);
    }

    var now = _utcNowExpr(externalDb);
    var stmt = sql.insert(opts.table, _tableOpts(_sqlDialect(externalDb)))
      .values({
        topic:           event.topic,
        payload:         payloadJson,
        key:             event.key || null,
        headers:         headersJson,
        enqueued_at:     now,
        next_attempt_at: now,
        attempts:        0,
        status:          "pending",
      })
      .toExternalSql(_sqlDialect(externalDb));
    await txn.query(stmt.sql, stmt.params);
    _emitMetric("enqueued", 1);
  }

  async function declareSchema(xdb) {
    var target = xdb || externalDb;
    var dialect = _sqlDialect(target);
    var tsType = dialect === "postgres" ? "TIMESTAMPTZ" : "TIMESTAMP";
    var ddl = sql.toExternalSql(sql.createTable(opts.table, [
      { name: "id",              serial: true },
      { name: "topic",           type: "VARCHAR(255)", notNull: true },
      { name: "payload",         type: "TEXT",         notNull: true },
      { name: "key",             type: "VARCHAR(255)" },
      { name: "headers",         type: "TEXT" },
      { name: "enqueued_at",     type: tsType,         notNull: true },
      { name: "next_attempt_at", type: tsType,         notNull: true },
      { name: "published_at",    type: tsType },
      { name: "claimed_at",      type: tsType },
      { name: "attempts",        type: "INTEGER",      notNull: true, default: 0 },
      { name: "last_error",      type: "TEXT" },
      { name: "status",          type: "VARCHAR(16)",  notNull: true, default: "pending" },
    ], _tableOpts(dialect)), dialect);
    var idxCols = dialect === "mysql" ? ["status", "next_attempt_at"] : ["next_attempt_at"];
    var idxOpts = _tableOpts(dialect);
    if (dialect !== "mysql") idxOpts.where = "status = 'pending'";
    var idx = sql.toExternalSql(sql.createIndex(opts.table + "_pending_idx", opts.table,
      idxCols, idxOpts), dialect);
    await target.query(ddl.sql, ddl.params);
    await target.query(idx.sql, idx.params);
    try {
      var alter = sql.toExternalSql(sql.alterTable(opts.table,
        { addColumn: { name: "claimed_at", type: tsType } }, _tableOpts(dialect)), dialect);
      await target.query(alter.sql, alter.params);
    } catch (_e) { /* column already present — idempotent add */ }
  }

  var workerHandle = null;
  var stopping = false;
  var inFlight = null;

  function _supportsForUpdateSkipLocked() {
    var d = externalDb.dialect;
    return d === "postgres" || d === "mysql";
  }

  async function _claimBatch() {
    var supportsSkipLocked = _supportsForUpdateSkipLocked();
    var dialect = _sqlDialect(externalDb);
    var CLAIM_COLS = ["id", "topic", "payload", "key", "headers", "attempts"];
    return await externalDb.transaction(async function (xdb) {
      var nowExpr = _utcNowExpr(externalDb);
      var selectBuilder = sql.select(opts.table, _tableOpts(dialect))
        .columns(CLAIM_COLS)
        .whereRaw("status = 'pending'", [], { allowLiterals: true })
        .whereRaw("next_attempt_at <= ?", [nowExpr])
        .orderBy("next_attempt_at")
        .limit(batchSize);
      if (supportsSkipLocked) selectBuilder.forUpdate({ skipLocked: true });
      var selectSql = selectBuilder.toExternalSql(dialect);
      var rows = await xdb.query(selectSql.sql, selectSql.params);
      if (!rows || !rows.rows || rows.rows.length === 0) return [];
      var ids = rows.rows.map(function (r) { return r.id; });
      var actuallyClaimed;
      if (supportsSkipLocked) {
        var claimUpdate = sql.update(opts.table, _tableOpts(dialect))
          .set({ status: "in-flight", claimed_at: _utcNowExpr(externalDb) })
          .whereInArray("id", ids)
          .toExternalSql(dialect);
        await xdb.query(claimUpdate.sql, claimUpdate.params);
        actuallyClaimed = rows.rows;
      } else {
        var markUpdate = sql.update(opts.table, _tableOpts(dialect))
          .set({ status: "in-flight", claimed_at: _utcNowExpr(externalDb) })
          .whereRaw("status = 'pending'", [], { allowLiterals: true })
          .whereInArray("id", ids)
          .toExternalSql(dialect);
        await xdb.query(markUpdate.sql, markUpdate.params);
        var afterSelect = sql.select(opts.table, _tableOpts(dialect))
          .columns(CLAIM_COLS)
          .whereRaw("status = 'in-flight'", [], { allowLiterals: true })
          .whereInArray("id", ids)
          .toExternalSql(dialect);
        var afterRows = await xdb.query(afterSelect.sql, afterSelect.params);
        actuallyClaimed = (afterRows && afterRows.rows) || [];
      }
      return actuallyClaimed.map(function (r) {
        return {
          id:       r.id,
          topic:    r.topic,
          payload:  r.payload,
          key:      r.key,
          headers:  r.headers,
          attempts: r.attempts,
        };
      });
    });
  }

  async function _reapStaleInflight() {
    var dialect = _sqlDialect(externalDb);
    var cutoff = new Date(Date.now() - claimReclaimMs);
    var stmt = sql.update(opts.table, _tableOpts(dialect))
      .set({ status: "pending", claimed_at: null })
      .whereRaw("status = 'in-flight'", [], { allowLiterals: true })
      .whereRaw("(claimed_at IS NULL OR claimed_at <= ?)", [cutoff])
      .toExternalSql(dialect);
    var res = await externalDb.query(stmt.sql, stmt.params);
    return res;
  }

  async function _markPublished(id) {
    var dialect = _sqlDialect(externalDb);
    var stmt = sql.update(opts.table, _tableOpts(dialect))
      .set({ status: "published", published_at: _utcNowExpr(externalDb) })
      .where("id", id)
      .toExternalSql(dialect);
    await externalDb.query(stmt.sql, stmt.params);
  }

  async function _markRetry(id, attempts, errMsg) {
    var dialect = _sqlDialect(externalDb);
    var nextAt = new Date(Date.now() + _backoffMs(attempts + 1));
    var stmt = sql.update(opts.table, _tableOpts(dialect))
      .set({
        status:          "pending",
        attempts:        attempts + 1,
        last_error:      String(errMsg).slice(0, 1024),
        next_attempt_at: nextAt,
      })
      .where("id", id)
      .toExternalSql(dialect);
    await externalDb.query(stmt.sql, stmt.params);
  }

  async function _markDead(id, attempts, errMsg) {
    var dialect = _sqlDialect(externalDb);
    var stmt = sql.update(opts.table, _tableOpts(dialect))
      .set({
        status:     "dead",
        attempts:   attempts + 1,
        last_error: String(errMsg).slice(0, 1024),
      })
      .where("id", id)
      .toExternalSql(dialect);
    await externalDb.query(stmt.sql, stmt.params);
    _emitAudit("system.outbox.deadletter", "failure", { id: id, attempts: attempts + 1 });
    _emitMetric("dead-letter", 1);
  }

  async function _processOnce() {
    try { await _reapStaleInflight(); }
    catch (_e) { /* drop-silent — reaper retries next poll */ }
    var batch = await _claimBatch();
    if (batch.length === 0) return 0;
    for (var i = 0; i < batch.length; i++) {
      var row = batch[i];
      try {
        var event = {
          id:       row.id,
          topic:    row.topic,
          payload:  row.payload ? safeJson.parse(row.payload, { maxBytes: C.BYTES.mib(8) }) : null,
          key:      row.key,
          headers:  row.headers ? safeJson.parse(row.headers, { maxBytes: C.BYTES.mib(1) }) : null,
          attempts: row.attempts,
        };
        var publishEvent = (envelope === "debezium")
          ? _toDebeziumEnvelope(event, {
              connectorName:    connectorName,
              connectorVersion: connectorVersion,
              dbName:           dbName,
            })
          : event;
        await publisher(publishEvent);
        await _markPublished(row.id);
        _emitMetric("published", 1);
      } catch (e) {
        var nextAttempts = row.attempts + 1;
        if (nextAttempts >= maxAttempts) {
          try { await _markDead(row.id, row.attempts, (e && e.message) || String(e)); }
          catch (_e) { /* drop-silent — worker keeps moving */ }
        } else {
          try { await _markRetry(row.id, row.attempts, (e && e.message) || String(e)); }
          catch (_e) { /* drop-silent — worker keeps moving */ }
        }
        _emitMetric("publish-failed", 1);
      }
    }
    return batch.length;
  }

  function start() {
    if (workerHandle) return;
    stopping = false;
    workerHandle = safeAsync.repeating(async function () {
      if (stopping || inFlight) return;
      inFlight = _processOnce()
        .catch(function () { /* drop-silent — see _processOnce */ })
        .finally(function () { inFlight = null; });
    }, pollIntervalMs, { name: name + "-publisher" });
    _emitAudit("system.outbox.started", "success", { name: name });
  }

  async function stop() {
    stopping = true;
    if (workerHandle) {
      workerHandle.stop();
      workerHandle = null;
    }
    if (inFlight) {
      // inFlight is _processOnce().catch(...).finally(...), which never rejects, so this drop-silent catch cannot fire.
      /* c8 ignore next */
      try { await inFlight; } catch (_e) { /* drop-silent */ }
    }
    _emitAudit("system.outbox.stopped", "success", { name: name });
  }

  async function _statusCount(status) {
    var dialect = _sqlDialect(externalDb);
    var stmt = sql.select(opts.table, _tableOpts(dialect))
      .count("*", "n")
      .whereRaw("status = '" + status + "'", [], { allowLiterals: true })
      .toExternalSql(dialect);
    var res = await externalDb.query(stmt.sql, stmt.params);
    return Number((res && res.rows && res.rows[0] && res.rows[0].n) || 0);
  }

  async function pendingCount() { return await _statusCount("pending"); }
  async function deadCount() { return await _statusCount("dead"); }

  return {
    enqueue:       enqueue,
    declareSchema: declareSchema,
    start:         start,
    stop:          stop,
    pendingCount:  pendingCount,
    deadCount:     deadCount,
    _processOnce:  _processOnce,
  };
}

module.exports = {
  create:      create,
  OutboxError: OutboxError,
};
