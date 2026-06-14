"use strict";
/**
 * @module b.inbox
 * @nav    Production
 * @title  Inbox
 *
 * @intro
 *   Transactional dedupe-on-receive for inbound message handlers.
 *   Companion to `b.outbox`: where outbox guarantees at-least-once
 *   delivery, inbox lets the receiver guarantee exactly-once handling
 *   by recording every `(source, messageId)` pair in the same database
 *   transaction as the business state change. A duplicate redelivery
 *   (network retry, replay, broker re-dispatch on consumer failure)
 *   collides with the primary-key constraint and the second handler
 *   short-circuits cleanly.
 *
 *   Schema (declared via `declareSchema(externalDb)`): `message_id
 *   TEXT`, `source TEXT`, `received_at TIMESTAMP`, `processed_at
 *   TIMESTAMP NULL`, `metadata_json JSONB|TEXT`, with `PRIMARY KEY
 *   (source, message_id)`. Postgres uses `ON CONFLICT … DO NOTHING
 *   RETURNING` to decide fresh-vs-duplicate in one round-trip; SQLite
 *   3.35+ uses `INSERT OR IGNORE … RETURNING 1` to avoid the
 *   `changes()` race when callers issue intervening statements on the
 *   same transaction handle.
 *
 *   Defenses on the input side: `messageId` and `source` are bounded
 *   in length (default 256 chars each) and rejected for NUL / C0 /
 *   DEL control characters before they reach the primary key — Postgres
 *   TEXT may truncate at NUL, opening a dedupe-collision attack where
 *   `"abc\\0attacker"` and `"abc"` collide. `metadata` is JSON-
 *   serialized through `safeJson` and capped at `maxPayloadBytes`
 *   (default 64 KiB).
 *
 *   Two APIs: high-level `handle(opts, handler)` opens a transaction,
 *   records receive, runs the handler exactly once when fresh, marks
 *   processed, commits — recommended for most callers. Low-level
 *   `recordReceive(opts, txn)` lets operators manage the transaction
 *   directly when they need fine-grained control over what runs in
 *   the dedupe envelope.
 *
 * @card
 *   Transactional dedupe-on-receive for inbound message handlers.
 */

var C = require("./constants");
var lazyRequire = require("./lazy-require");
var safeJson = require("./safe-json");
var safeSql = require("./safe-sql");
var sql = require("./sql");
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

// Map the operator backend's dialect tag to the b.sql dialect vocabulary
// (postgres -> $1..$N at toExternalSql; sqlite/other -> `?`).
function _sqlDialect(externalDb) {
  return (externalDb && externalDb.dialect === "postgres") ? "postgres" : "sqlite";
}

// The server-clock timestamp expression, as an allowlisted b.sql function
// cell (emits the keyword the engine evaluates, binds no param). Postgres
// returns timestamptz from NOW(); the portable CURRENT_TIMESTAMP serves
// sqlite. Used directly in a b.sql values()/set() cell.
function _utcNowCell(externalDb) {
  return (externalDb && externalDb.dialect === "postgres")
    ? sql.fn("NOW") : sql.fn("CURRENT_TIMESTAMP");
}

/**
 * @primitive b.inbox.create
 * @signature b.inbox.create(opts)
 * @since     0.8.48
 * @status    stable
 * @related   b.outbox, b.externalDb, b.audit
 *
 * Build an inbox dedupe-store. Returns
 * `{ declareSchema, recordReceive, markProcessed, handle, sweep,
 * isFresh, getStats, table, retentionDays }`. Operators call
 * `declareSchema` once at boot, `handle` per inbound message, and
 * `sweep` periodically (under their own scheduler) to age out
 * processed rows past retention.
 *
 * @opts
 *   externalDb:      Object,   // b.externalDb instance (transaction()-shaped)
 *   table:           string,   // SQL identifier; required
 *   retentionDays:   number,   // sweep horizon (default 30); unprocessed rows kept 2x as long
 *   audit:           boolean,  // emit inbox.* audit events (default true)
 *   maxPayloadBytes: number,   // metadata serialized cap (default 64 KiB)
 *   messageIdMaxLen: number,   // chars (default 256)
 *   sourceMaxLen:    number,   // chars (default 256)
 *
 * @example
 *   var inbox = b.inbox.create({
 *     externalDb:    externalDbInstance,
 *     table:         "inbox_events",
 *     retentionDays: 30,
 *   });
 *
 *   await inbox.declareSchema(externalDbInstance);
 *
 *   var outcome = await inbox.handle({
 *     messageId: "evt-9f3c4d",
 *     source:    "kafka:orders.created.v1",
 *   }, async function (xdb) {
 *     await xdb.query("INSERT INTO orders (id) VALUES ($1)", ["o-42"]);
 *     return { orderId: "o-42" };
 *   });
 *   outcome.fresh;             // → true on first delivery, false on replay
 *   outcome.result.orderId;    // → "o-42"
 *
 *   // Replay short-circuits:
 *   var replay = await inbox.handle({
 *     messageId: "evt-9f3c4d", source: "kafka:orders.created.v1",
 *   }, async function () { return { orderId: "should-not-run" }; });
 *   replay.fresh;              // → false
 *   replay.result;             // → null
 *
 *   var stats = await inbox.getStats({ source: "kafka:orders.created.v1" });
 *   stats.total;               // → 1
 *   stats.processed;           // → 1
 *
 *   var deleted = await inbox.sweep();   // age out beyond retention
 */
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
  var tableRaw       = opts.table;
  // The table identifier reaches SQL through b.sql, which validates +
  // quotes it by construction on every emitted statement; _validateTableName
  // above fails fast at create() time on a bad name.
  var retentionDays  = (typeof opts.retentionDays === "number" && opts.retentionDays > 0)        // allow:numeric-opt-Infinity
    ? opts.retentionDays : 30;                                                                   // default retention days
  var auditOn        = opts.audit !== false;
  var maxPayloadBytes = (typeof opts.maxPayloadBytes === "number" && opts.maxPayloadBytes > 0)   // allow:numeric-opt-Infinity
    ? opts.maxPayloadBytes : C.BYTES.kib(64);
  var messageIdMaxLen = (typeof opts.messageIdMaxLen === "number" && opts.messageIdMaxLen > 0)   // allow:numeric-opt-Infinity
    ? opts.messageIdMaxLen : 256;                                                                // message-id length cap
  var sourceMaxLen = (typeof opts.sourceMaxLen === "number" && opts.sourceMaxLen > 0)            // allow:numeric-opt-Infinity
    ? opts.sourceMaxLen : 256;                                                                   // source length cap

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
    // Reject NUL + C0 control characters in messageId / source. Both
    // values flow into the (source, message_id) PRIMARY KEY and into
    // audit metadata. Postgres TEXT may reject `\0` mid-statement, OR
    // (depending on driver) silently truncate at the null byte —
    // opening a dedupe-collision attack where "abc\0attacker" and
    // "abc" collide as the same key. Refusing at the gate also keeps
    // operator audit metadata sane.
    _rejectControlChars(receiveOpts.messageId, label, "messageId");
    _rejectControlChars(receiveOpts.source,    label, "source");
  }

  function _rejectControlChars(value, label, field) {
    for (var i = 0; i < value.length; i += 1) {
      var code = value.charCodeAt(i);
      if (code === 0 || (code < 32 && code !== 9) || code === 127) {     // ASCII control codepoints (NUL + C0 + DEL); allow tab
        throw new InboxError("inbox/bad-receive",
          label + ": " + field + " contains control character at index " + i +
          " (codepoint " + code + ")");
      }
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
    var dialect = _sqlDialect(externalDb);
    var nowCell = _utcNowCell(externalDb);

    // ON CONFLICT (source, message_id) DO NOTHING RETURNING message_id:
    // a fresh insert returns one row, a duplicate redelivery returns none
    // (the collision short-circuits). received_at takes the server-clock
    // function cell (NOW() / CURRENT_TIMESTAMP, no param); metadata_json
    // binds with a ::jsonb cast on Postgres and as a plain `?` on sqlite.
    // RETURNING message_id (rather than RETURNING 1) is the portable
    // presence sentinel - one row iff the insert landed - across both
    // dialects, collapsing the prior INSERT-then-SELECT-changes() race
    // into one round-trip on sqlite too.
    var metaCell = (dialect === "postgres") ? sql.cast(metaJson, "jsonb") : metaJson;
    var stmt = sql.upsert(tableRaw, { dialect: dialect })
      .columns(["message_id", "source", "received_at", "metadata_json"])
      .values({
        message_id:    receiveOpts.messageId,
        source:        receiveOpts.source,
        received_at:   nowCell,
        metadata_json: metaCell,
      })
      .onConflict(["source", "message_id"])
      .doNothing()
      .returning(["message_id"])
      .toExternalSql(dialect);
    var rs = await txn.query(stmt.sql, stmt.params);
    var fresh = !!(rs && rs.rows && rs.rows.length === 1);
    _emitAudit("inbox.received", "success", {
      source: receiveOpts.source, messageId: receiveOpts.messageId,
      fresh: fresh,
    });
    return fresh;
  }

  async function markProcessed(receiveOpts, txn) {
    if (!txn || typeof txn.query !== "function") {
      throw new InboxError("inbox/bad-txn",
        "markProcessed: txn must be a transaction handle");
    }
    _validateReceiveOpts(receiveOpts, "markProcessed");
    var dialect = _sqlDialect(externalDb);
    var stmt = sql.update(tableRaw, { dialect: dialect })
      .set({ processed_at: _utcNowCell(externalDb) })
      .where("source", receiveOpts.source)
      .where("message_id", receiveOpts.messageId)
      .toExternalSql(dialect);
    await txn.query(stmt.sql, stmt.params);
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
      _emitAudit("inbox.handle_failed", "failure", {
        source: receiveOpts.source, messageId: receiveOpts.messageId,
        message: e && e.message || String(e),
      });
      throw e;
    }
    _emitAudit("inbox.handled", "success", {
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
    var dialect = _sqlDialect(xdb);
    // received_at / processed_at are a timestamp-with-zone column on
    // Postgres and a TEXT (ISO-8601) column on sqlite; metadata_json is
    // JSONB on Postgres and TEXT on sqlite. The composite (source,
    // message_id) primary key is the dedupe collision boundary. Verbatim
    // type strings sit in type position after the quoted column name.
    var tsType = dialect === "postgres" ? "TIMESTAMPTZ" : "TEXT";
    var tsDefault = dialect === "postgres" ? "NOW()" : "CURRENT_TIMESTAMP";
    var jsonType = dialect === "postgres" ? "JSONB" : "TEXT";
    var ddl = sql.toExternalSql(sql.createTable(tableRaw, [
      { name: "message_id",    type: "TEXT",   notNull: true },
      { name: "source",        type: "TEXT",   notNull: true },
      // The DEFAULT here is a SQL function keyword, not a bound literal -
      // expressed via the `constraints` verbatim clause so the type map
      // does not quote NOW() / CURRENT_TIMESTAMP as a string default.
      { name: "received_at",   type: tsType,   notNull: true, constraints: "DEFAULT " + tsDefault },
      { name: "processed_at",  type: tsType },
      { name: "metadata_json", type: jsonType },
    ], { dialect: dialect, primaryKey: ["source", "message_id"] }), dialect);
    await xdb.query(ddl.sql, ddl.params);

    var idx = sql.toExternalSql(sql.createIndex(tableRaw + "_received_at_idx", tableRaw,
      ["received_at"], { dialect: dialect }), dialect);
    await xdb.query(idx.sql, idx.params);
  }

  async function sweep() {
    var dialect = _sqlDialect(externalDb);
    var deleted = 0;
    await externalDb.transaction(async function (xdb) {
      if (dialect === "postgres") {
        // received_at < NOW() - <retention>::interval, with the
        // unprocessed grace of 2x retention. The interval STRINGS bind as
        // a ::interval-cast `?` (the cast value-cell form); NOW() is the
        // server-clock function token in the predicate (a guarded raw
        // fragment - no string literal, no bound value).
        var delStmt = sql.delete(tableRaw, { dialect: "postgres" })
          .whereRaw("received_at < NOW() - ?::interval", [retentionDays + " days"])
          .whereRaw("(processed_at IS NOT NULL OR received_at < NOW() - ?::interval)",
            [(retentionDays * 2) + " days"])
          .toExternalSql("postgres");
        var rs = await xdb.query(delStmt.sql, delStmt.params);
        deleted = (rs && typeof rs.rowCount === "number") ? rs.rowCount : 0;
      } else {
        var staleDate = new Date(Date.now() - retentionDays * C.TIME.days(1)).toISOString();
        var unprocStaleDate = new Date(Date.now() - retentionDays * 2 * C.TIME.days(1)).toISOString();
        var delSqlite = sql.delete(tableRaw, { dialect: "sqlite" })
          .where("received_at", "<", staleDate)
          .whereRaw("(processed_at IS NOT NULL OR received_at < ?)", [unprocStaleDate])
          .toExternalSql("sqlite");
        await xdb.query(delSqlite.sql, delSqlite.params);
        // SELECT changes() reports the row count of the last sqlite write
        // on this connection. b.sql.catalog has no changes() builder (it
        // is a sqlite-internal scalar with no table), so emit it through
        // the same dialect-final terminal as a guarded raw projection on a
        // zero-table SELECT is not expressible; the single-statement
        // changes() probe is a fixed, parameter-free sqlite scalar query.
        var changedResult = await xdb.query(
          sql.toExternalSql(sql.catalog.changes(), "sqlite").sql);
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
    var dialect = _sqlDialect(externalDb);
    // SELECT 1 ... is a presence probe; the constant 1 projection is a
    // builder-emitted raw scalar (no column, no bound value).
    var stmt = sql.select(tableRaw, { dialect: dialect })
      .selectRaw("1")
      .where("source", receiveOpts.source)
      .where("message_id", receiveOpts.messageId)
      .toExternalSql(dialect);
    var rs = await externalDb.transaction(async function (xdb) {
      return await xdb.query(stmt.sql, stmt.params);
    });
    return !rs || !rs.rows || rs.rows.length === 0;
  }

  async function getReceiveStats(opts2) {
    opts2 = opts2 || {};
    var sourceFilter = (typeof opts2.source === "string" && opts2.source.length > 0)
      ? opts2.source : null;
    var dialect = _sqlDialect(externalDb);
    var stats = await externalDb.transaction(async function (xdb) {
      // COUNT(*) total + COUNT(processed_at) processed (the latter counts
      // only non-NULL processed_at, i.e. handled rows), optionally scoped
      // to one source.
      var builder = sql.select(tableRaw, { dialect: dialect })
        .count("*", "total")
        .count("processed_at", "processed");
      if (sourceFilter) builder.where("source", sourceFilter);
      var stmt = builder.toExternalSql(dialect);
      var rs = await xdb.query(stmt.sql, stmt.params);
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
    table:          tableRaw,
    retentionDays:  retentionDays,
  };
}

module.exports = {
  create:     create,
  InboxError: InboxError,
};
