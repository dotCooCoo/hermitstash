"use strict";
/**
 * b.inbox — transactional dedupe-on-receive.
 *
 * Companion to `b.outbox`. Where outbox guarantees at-least-once
 * delivery, inbox lets the receiver guarantee exactly-once handling
 * by recording every (source, messageId) pair in the same transaction
 * as the business state change. If the same event is delivered twice
 * (network retry, replay, broker re-dispatch on consumer failure),
 * the second handler refuses with a duplicate-key constraint and the
 * application sees a clean short-circuit.
 *
 *   var inbox = b.inbox.create({
 *     externalDb:    b.externalDb,
 *     table:         "inbox_events",
 *     retentionDays: 30,                 // sweep older rows
 *     audit:         true,
 *   });
 *
 *   // High-level API — recommended for most callers:
 *   await inbox.handle({
 *     messageId: kafkaEvent.headers["x-event-id"],
 *     source:    "kafka:orders.created.v1",
 *     payload:   kafkaEvent.payload,                // optional, audit only
 *   }, async function (xdb) {
 *     // Business state change runs exactly once per (source, messageId).
 *     await xdb.query("INSERT INTO orders ...", [...]);
 *   });
 *
 *   // Low-level API — operator manages the transaction directly:
 *   await b.externalDb.transaction(async function (xdb) {
 *     var fresh = await inbox.recordReceive({
 *       messageId: id, source: "kafka:orders.created",
 *     }, xdb);
 *     if (!fresh) return;                             // duplicate; skip
 *     await xdb.query("INSERT INTO orders ...", [...]);
 *   });
 *
 *   // Schema:
 *   await inbox.declareSchema(b.externalDb);
 *
 *   // Periodic retention sweep (operator wires their scheduler):
 *   await inbox.sweep();
 *
 * Schema columns:
 *
 *   message_id     TEXT     — primary part of the dedupe tuple
 *   source         TEXT     — namespace (kafka topic, queue name, ...)
 *   received_at    TIMESTAMP
 *   processed_at   TIMESTAMP NULL  — set when handle() commits
 *   metadata_json  JSONB / TEXT (operator-supplied audit blob)
 *
 *   PRIMARY KEY (source, message_id)  — enforces idempotence.
 *
 * Picking semantics:
 *   - Postgres backends: ON CONFLICT (source, message_id) DO NOTHING
 *     RETURNING * lets `recordReceive` decide fresh vs duplicate in
 *     a single round-trip.
 *   - SQLite: INSERT OR IGNORE + SELECT changes() to test fresh-ness.
 */

var C = require("./constants");
var lazyRequire = require("./lazy-require");
var safeJson = require("./safe-json");
var safeSql = require("./safe-sql");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var InboxError = defineClass("InboxError", { alwaysPermanent: true });

var audit = lazyRequire(function () { return require("./audit"); });
var observability = lazyRequire(function () { return require("./observability"); });

function _validateTableName(name) {
  try { safeSql.validateIdentifier(name); }
  catch (e) {
    throw new InboxError("inbox/bad-table",
      "inbox.create: table " + JSON.stringify(name) +
      " is not a safe SQL identifier — " + e.message);
  }
}

function _utcNowExpr(externalDb) {
  // Both backends accept this expression; SQLite returns ISO-8601,
  // Postgres returns timestamptz.
  if (externalDb && typeof externalDb.dialect === "string" &&
      externalDb.dialect === "postgres") {
    return "NOW()";
  }
  return "CURRENT_TIMESTAMP";
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "externalDb", "table", "retentionDays", "audit",
    "maxPayloadBytes", "messageIdMaxLen", "sourceMaxLen",
  ], "inbox.create");
  if (!opts.externalDb || typeof opts.externalDb.transaction !== "function") {
    throw new InboxError("inbox/bad-externaldb",
      "inbox.create: externalDb must be a b.externalDb instance");
  }
  validateOpts.requireNonEmptyString(opts.table,
    "inbox.create: table", InboxError, "inbox/bad-table");
  _validateTableName(opts.table);

  var externalDb     = opts.externalDb;
  var table          = opts.table;
  var retentionDays  = (typeof opts.retentionDays === "number" && opts.retentionDays > 0)        // allow:numeric-opt-Infinity
    ? opts.retentionDays : 30;                                                                   // allow:raw-byte-literal — default retention days
  var auditOn        = opts.audit !== false;
  var maxPayloadBytes = (typeof opts.maxPayloadBytes === "number" && opts.maxPayloadBytes > 0)   // allow:numeric-opt-Infinity
    ? opts.maxPayloadBytes : C.BYTES.kib(64);
  var messageIdMaxLen = (typeof opts.messageIdMaxLen === "number" && opts.messageIdMaxLen > 0)   // allow:numeric-opt-Infinity
    ? opts.messageIdMaxLen : 256;                                                                // allow:raw-byte-literal — message-id length cap
  var sourceMaxLen = (typeof opts.sourceMaxLen === "number" && opts.sourceMaxLen > 0)            // allow:numeric-opt-Infinity
    ? opts.sourceMaxLen : 256;                                                                   // allow:raw-byte-literal — source length cap

  function _emitAudit(action, outcome, metadata) {
    if (!auditOn) return;
    try {
      audit().safeEmit({
        action:   action,
        outcome:  outcome,
        actor:    null,
        metadata: metadata || {},
      });
    } catch (_e) { /* drop-silent */ }
  }

  function _validateReceiveOpts(receiveOpts, label) {
    if (!receiveOpts || typeof receiveOpts !== "object") {
      throw new InboxError("inbox/bad-receive",
        label + ": receiveOpts must be an object");
    }
    validateOpts.requireNonEmptyString(receiveOpts.messageId,
      label + ": messageId", InboxError, "inbox/bad-receive");
    validateOpts.requireNonEmptyString(receiveOpts.source,
      label + ": source", InboxError, "inbox/bad-receive");
    if (receiveOpts.messageId.length > messageIdMaxLen) {
      throw new InboxError("inbox/bad-receive",
        label + ": messageId exceeds " + messageIdMaxLen + " chars");
    }
    if (receiveOpts.source.length > sourceMaxLen) {
      throw new InboxError("inbox/bad-receive",
        label + ": source exceeds " + sourceMaxLen + " chars");
    }
  }

  async function recordReceive(receiveOpts, txn) {
    if (!txn || typeof txn.query !== "function") {
      throw new InboxError("inbox/bad-txn",
        "recordReceive: txn must be a transaction handle (call inside externalDb.transaction)");
    }
    _validateReceiveOpts(receiveOpts, "recordReceive");
    var metaJson = null;
    if (receiveOpts.metadata != null) {
      var serialized = safeJson.stringify(receiveOpts.metadata);
      if (serialized.length > maxPayloadBytes) {
        throw new InboxError("inbox/bad-receive",
          "recordReceive: metadata serialized exceeds maxPayloadBytes (" +
          maxPayloadBytes + " bytes)");
      }
      metaJson = serialized;
    }
    var nowExpr = _utcNowExpr(externalDb);
    var dialect = (externalDb.dialect === "postgres") ? "postgres" : "sqlite";

    if (dialect === "postgres") {
      var rs = await txn.query(
        "INSERT INTO " + table +
        " (message_id, source, received_at, metadata_json) " +
        " VALUES ($1, $2, " + nowExpr + ", $3::jsonb) " +
        " ON CONFLICT (source, message_id) DO NOTHING " +
        " RETURNING message_id",
        [receiveOpts.messageId, receiveOpts.source, metaJson]);
      var fresh = rs && rs.rows && rs.rows.length === 1;
      _emitAudit("inbox.received", fresh ? "success" : "duplicate", {
        source: receiveOpts.source, messageId: receiveOpts.messageId,
        fresh: fresh,
      });
      return fresh;
    }

    // SQLite path — INSERT OR IGNORE + check changes()
    await txn.query(
      "INSERT OR IGNORE INTO " + table +
      " (message_id, source, received_at, metadata_json) " +
      " VALUES (?, ?, " + nowExpr + ", ?)",
      [receiveOpts.messageId, receiveOpts.source, metaJson]);
    var changedResult = await txn.query("SELECT changes() AS c");
    var changedRow = changedResult.rows && changedResult.rows[0];
    var sqlFresh = !!(changedRow && Number(changedRow.c) === 1);
    _emitAudit("inbox.received", sqlFresh ? "success" : "duplicate", {
      source: receiveOpts.source, messageId: receiveOpts.messageId,
      fresh: sqlFresh,
    });
    return sqlFresh;
  }

  async function markProcessed(receiveOpts, txn) {
    if (!txn || typeof txn.query !== "function") {
      throw new InboxError("inbox/bad-txn",
        "markProcessed: txn must be a transaction handle");
    }
    _validateReceiveOpts(receiveOpts, "markProcessed");
    var nowExpr = _utcNowExpr(externalDb);
    var dialect = (externalDb.dialect === "postgres") ? "postgres" : "sqlite";
    var sql = "UPDATE " + table +
              " SET processed_at = " + nowExpr +
              " WHERE source = " + (dialect === "postgres" ? "$1" : "?") +
              " AND message_id = " + (dialect === "postgres" ? "$2" : "?");
    await txn.query(sql, [receiveOpts.source, receiveOpts.messageId]);
  }

  async function handle(receiveOpts, handler) {
    if (typeof handler !== "function") {
      throw new InboxError("inbox/bad-handler",
        "handle: handler must be an async function (xdb) → void");
    }
    var startMs = Date.now();
    var fresh = false;
    var handlerErr = null;
    var result;
    try {
      result = await externalDb.transaction(async function (xdb) {
        fresh = await recordReceive(receiveOpts, xdb);
        if (!fresh) return null;
        var inner = await handler(xdb);
        await markProcessed(receiveOpts, xdb);
        return inner;
      });
    } catch (e) {
      handlerErr = e;
      _emitAudit("inbox.handle_failed", "fail", {
        source: receiveOpts.source, messageId: receiveOpts.messageId,
        message: e && e.message || String(e),
      });
      throw e;
    }
    _emitAudit("inbox.handled", fresh ? "success" : "duplicate", {
      source: receiveOpts.source, messageId: receiveOpts.messageId,
      fresh: fresh, elapsedMs: Date.now() - startMs,
    });
    if (!handlerErr) {
      try {
        observability().safeEvent("inbox.message_handled", {
          source: receiveOpts.source, fresh: fresh,
        });
      } catch (_e) { /* drop-silent */ }
    }
    return { fresh: fresh, result: fresh ? result : null };
  }

  async function declareSchema(xdb) {
    var dialect = (xdb && xdb.dialect === "postgres") ? "postgres" : "sqlite";
    if (dialect === "postgres") {
      await xdb.query(
        "CREATE TABLE IF NOT EXISTS " + table + " (" +
        "  message_id   TEXT NOT NULL," +
        "  source       TEXT NOT NULL," +
        "  received_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()," +
        "  processed_at TIMESTAMPTZ NULL," +
        "  metadata_json JSONB NULL," +
        "  PRIMARY KEY (source, message_id)" +
        ")");
      await xdb.query(
        "CREATE INDEX IF NOT EXISTS " + table + "_received_at_idx " +
        "ON " + table + " (received_at)");
    } else {
      await xdb.query(
        "CREATE TABLE IF NOT EXISTS " + table + " (" +
        "  message_id   TEXT NOT NULL," +
        "  source       TEXT NOT NULL," +
        "  received_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP," +
        "  processed_at TEXT NULL," +
        "  metadata_json TEXT NULL," +
        "  PRIMARY KEY (source, message_id)" +
        ")");
      await xdb.query(
        "CREATE INDEX IF NOT EXISTS " + table + "_received_at_idx " +
        "ON " + table + " (received_at)");
    }
  }

  async function sweep() {
    var dialect = (externalDb.dialect === "postgres") ? "postgres" : "sqlite";
    var deleted = 0;
    await externalDb.transaction(async function (xdb) {
      if (dialect === "postgres") {
        var rs = await xdb.query(
          "DELETE FROM " + table +
          " WHERE received_at < NOW() - $1::interval " +
          " AND (processed_at IS NOT NULL OR received_at < NOW() - $2::interval)",
          [retentionDays + " days", (retentionDays * 2) + " days"]);
        deleted = (rs && typeof rs.rowCount === "number") ? rs.rowCount : 0;
      } else {
        var staleDate = new Date(Date.now() - retentionDays * C.TIME.days(1)).toISOString();
        var unprocStaleDate = new Date(Date.now() - retentionDays * 2 * C.TIME.days(1)).toISOString();
        await xdb.query(
          "DELETE FROM " + table +
          " WHERE received_at < ? " +
          " AND (processed_at IS NOT NULL OR received_at < ?)",
          [staleDate, unprocStaleDate]);
        var changedResult = await xdb.query("SELECT changes() AS c");
        var changedRow = changedResult.rows && changedResult.rows[0];
        deleted = changedRow ? Number(changedRow.c) : 0;
      }
    });
    _emitAudit("inbox.swept", "success", {
      deleted: deleted, retentionDays: retentionDays,
    });
    return deleted;
  }

  async function isFresh(receiveOpts) {
    _validateReceiveOpts(receiveOpts, "isFresh");
    var dialect = (externalDb.dialect === "postgres") ? "postgres" : "sqlite";
    var sql = "SELECT 1 FROM " + table +
              " WHERE source = " + (dialect === "postgres" ? "$1" : "?") +
              " AND message_id = " + (dialect === "postgres" ? "$2" : "?");
    var rs = await externalDb.transaction(async function (xdb) {
      return await xdb.query(sql, [receiveOpts.source, receiveOpts.messageId]);
    });
    return !rs || !rs.rows || rs.rows.length === 0;
  }

  async function getReceiveStats(opts2) {
    opts2 = opts2 || {};
    var sourceFilter = (typeof opts2.source === "string" && opts2.source.length > 0)
      ? opts2.source : null;
    var dialect = (externalDb.dialect === "postgres") ? "postgres" : "sqlite";
    var stats = await externalDb.transaction(async function (xdb) {
      var sql = "SELECT COUNT(*) AS total," +
                "       COUNT(processed_at) AS processed " +
                "  FROM " + table +
                (sourceFilter ? " WHERE source = " +
                  (dialect === "postgres" ? "$1" : "?") : "");
      var args = sourceFilter ? [sourceFilter] : [];
      var rs = await xdb.query(sql, args);
      var row = rs.rows && rs.rows[0];
      return {
        total:     row ? Number(row.total) : 0,
        processed: row ? Number(row.processed) : 0,
      };
    });
    stats.unprocessed = stats.total - stats.processed;
    return stats;
  }

  return {
    declareSchema:  declareSchema,
    recordReceive:  recordReceive,
    markProcessed:  markProcessed,
    handle:         handle,
    sweep:          sweep,
    isFresh:        isFresh,
    getStats:       getReceiveStats,
    table:          table,
    retentionDays:  retentionDays,
  };
}

module.exports = {
  create:     create,
  InboxError: InboxError,
};
