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
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var OutboxError = defineClass("OutboxError", { alwaysPermanent: true });

var audit = lazyRequire(function () { return require("./audit"); });
var observability = lazyRequire(function () { return require("./observability"); });

var DEFAULT_POLL_MS         = C.TIME.seconds(1);
var DEFAULT_BATCH_SIZE      = 100;                                                 // row count, not bytes
var DEFAULT_MAX_ATTEMPTS    = 10;                                                  // attempt count, not bytes
var DEFAULT_BACKOFF_INITIAL = C.TIME.seconds(1);
var DEFAULT_BACKOFF_MAX     = C.TIME.minutes(5);
var DEFAULT_BACKOFF_FACTOR  = 2;                                                   // multiplier, not bytes
var TOPIC_MAX_LEN           = C.BYTES.bytes(255);
var KEY_MAX_LEN             = C.BYTES.bytes(255);

function _validateTableName(name) {
  // SQL identifier — quoteIdentifier rejects anything with embedded
  // quotes, schema-qualified names valid via dot-separated parts.
  return safeSql.quoteIdentifier(name);
}

function _utcNowExpr(externalDb) {
  // The framework's externalDb backends wrap Postgres + SQLite. Both
  // accept a parameterized timestamp via JS Date → ISO string for
  // most uses, but for the next_attempt_at advance we need an absolute
  // moment computed in JS land so the publisher's clock is the source
  // of truth (DB clock skew is a recurring outbox bug).
  return new Date();
}

// Debezium-shape change-event envelope. Operators integrating with
// downstream Kafka Connect / Debezium consumers opt-in via
// `outbox.create({ envelope: "debezium" })`. The envelope wraps the
// operator's payload as `payload.after` and carries Debezium
// connector-shape metadata (`source`, `op`, `ts_ms`).
//
// Reference: Debezium 2.x ChangeEvent envelope —
//   { schema: { type, fields, optional, name }, payload: {...} }
//
// We don't ship a schema-registry hookup — the payload's schema is
// "operator-supplied JSON object" by default. Operators integrating
// with Confluent Schema Registry attach `event.debezium.schema` to
// override per-event.
var DEFAULT_DEBEZIUM_CONNECTOR_VERSION = "1.0.0";                                  // version string

function _debeziumSchemaFor(payloadObj) {
  // Best-effort schema synthesis. Debezium consumers expect a JSON
  // schema description of `payload`. We emit a permissive object
  // schema so consumers that don't rely on the schema field still
  // round-trip the payload cleanly.
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
  // rawEvent is the operator-shape `{ topic, payload, key, headers,
  // attempts, id }` we already pass to plain publishers. We adapt
  // it here so existing operator schemas work unchanged.
  var payload = rawEvent.payload && typeof rawEvent.payload === "object"
    ? rawEvent.payload : { value: rawEvent.payload };
  var op = (rawEvent.headers && typeof rawEvent.headers === "object" &&
            typeof rawEvent.headers["debezium-op"] === "string")
    ? rawEvent.headers["debezium-op"]
    : "c";  // default: create. Operators emit u (update) / d (delete) via headers.
  var nowMs = Date.now();
  return {
    schema: _debeziumSchemaFor(payload),
    payload: {
      before: (payload && payload.before) || null,
      after:  (payload && payload.after !== undefined) ? payload.after : payload,
      source: {
        connector: opts.connectorName || "blamejs",
        version:   opts.connectorVersion || DEFAULT_DEBEZIUM_CONNECTOR_VERSION,
        db:        opts.dbName || null,
        table:     rawEvent.topic,                      // topic is the table-shape stable identifier
        ts_ms:     nowMs,
      },
      op:    op,
      ts_ms: nowMs,
      // Operator-shape passthrough: `key` / `headers` / `attempts`
      // travel as Debezium-extension fields so consumers that need
      // them aren't forced to fabricate.
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
    "pollIntervalMs", "batchSize", "maxAttempts",
    "retryBackoff", "audit", "name",
    "envelope", "connectorName", "connectorVersion", "dbName",
  ], "outbox.create");

  if (!opts.externalDb || typeof opts.externalDb.transaction !== "function") {
    throw new OutboxError("outbox/bad-externaldb",
      "outbox.create: externalDb must be the b.externalDb namespace (with transaction/query)");
  }
  validateOpts.requireNonEmptyString(opts.table,
    "outbox.create: table", OutboxError, "outbox/bad-table");
  var quotedTable = _validateTableName(opts.table);

  if (typeof opts.publisher !== "function") {
    throw new OutboxError("outbox/bad-publisher",
      "outbox.create: publisher must be an async function (event) → void");
  }
  validateOpts.optionalPositiveFinite(opts.pollIntervalMs,
    "outbox.create: pollIntervalMs", OutboxError, "outbox/bad-opts");
  validateOpts.optionalPositiveFinite(opts.batchSize,
    "outbox.create: batchSize", OutboxError, "outbox/bad-opts");
  validateOpts.optionalPositiveFinite(opts.maxAttempts,
    "outbox.create: maxAttempts", OutboxError, "outbox/bad-opts");

  var pollIntervalMs = opts.pollIntervalMs || DEFAULT_POLL_MS;
  var batchSize      = opts.batchSize      || DEFAULT_BATCH_SIZE;
  var maxAttempts    = opts.maxAttempts    || DEFAULT_MAX_ATTEMPTS;
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

  function _emitMetric(verb, n) {
    try { observability().safeEvent("outbox." + verb, n || 1, {}); }
    catch (_e) { /* drop-silent */ }
  }
  function _emitAudit(action, outcome, metadata) {
    if (!auditOn) return;
    try {
      audit().safeEmit({
        action:   action,
        outcome:  outcome,
        metadata: metadata || {},
      });
    } catch (_e) { /* drop-silent */ }
  }

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

    var sql = "INSERT INTO " + quotedTable +
      " (topic, payload, key, headers, enqueued_at, next_attempt_at, attempts, status)" +
      " VALUES ($1, $2, $3, $4, $5, $5, 0, 'pending')";
    var now = _utcNowExpr(externalDb);
    await txn.query(sql, [
      event.topic, payloadJson, event.key || null, headersJson, now,
    ]);
    _emitMetric("enqueued", 1);
  }

  async function declareSchema(xdb) {
    var target = xdb || externalDb;
    var ddl =
      "CREATE TABLE IF NOT EXISTS " + quotedTable + " (" +
        "id BIGSERIAL PRIMARY KEY, " +
        "topic VARCHAR(255) NOT NULL, " +
        "payload TEXT NOT NULL, " +
        "key VARCHAR(255), " +
        "headers TEXT, " +
        "enqueued_at TIMESTAMPTZ NOT NULL, " +
        "next_attempt_at TIMESTAMPTZ NOT NULL, " +
        "published_at TIMESTAMPTZ, " +
        "attempts INTEGER NOT NULL DEFAULT 0, " +
        "last_error TEXT, " +
        "status VARCHAR(16) NOT NULL DEFAULT 'pending'" +
      ")";
    var idxName = _validateTableName(opts.table + "_pending_idx");
    var idx =
      "CREATE INDEX IF NOT EXISTS " + idxName + " ON " + quotedTable +
      " (next_attempt_at) WHERE status = 'pending'";
    await target.query(ddl, []);
    await target.query(idx, []);
  }

  // ---- Publisher worker ----

  var workerHandle = null;
  var stopping = false;
  var inFlight = null;

  // `FOR UPDATE SKIP LOCKED` is Postgres / MySQL 8+ only.
  // SQLite (single-writer at the DB level, but WAL mode lets multiple
  // processes share the file with concurrent SELECTs) doesn't support
  // SKIP LOCKED — feeding it Postgres syntax silently double-publishes
  // every row when two processes poll in parallel. Detect the dialect
  // at runtime; only emit FOR UPDATE SKIP LOCKED when the backend
  // declares postgres / mysql.
  //
  // Operator-visible: dialect comes from `externalDb.dialect` (set at
  // `b.externalDb.create({ dialect: "postgres" | "mysql" | "sqlite" }`).
  // Other backends fall back to the conservative "mark-then-update"
  // path that works on every SQL dialect at the cost of a tiny race
  // window between the SELECT + UPDATE (mitigated by status='in-flight'
  // marker — duplicate publishes still bounded by retry visibility).
  function _supportsForUpdateSkipLocked() {
    var d = externalDb.dialect;
    return d === "postgres" || d === "mysql";
  }

  async function _claimBatch() {
    var supportsSkipLocked = _supportsForUpdateSkipLocked();
    return await externalDb.transaction(async function (xdb) {
      var nowExpr = _utcNowExpr(externalDb);
      var selectSql =
        "SELECT id, topic, payload, key, headers, attempts" +
        " FROM " + quotedTable +
        " WHERE status = 'pending' AND next_attempt_at <= $1" +
        " ORDER BY next_attempt_at" +
        " LIMIT $2";
      if (supportsSkipLocked) {
        selectSql += " FOR UPDATE SKIP LOCKED";
      }
      var rows = await xdb.query(selectSql, [nowExpr, batchSize]);
      if (!rows || !rows.rows || rows.rows.length === 0) return [];
      var ids = rows.rows.map(function (r) { return r.id; });
      // Atomic claim: when the dialect lacks SKIP LOCKED, the UPDATE
      // WHERE status='pending' AND id IN (...) ensures only ONE publisher
      // sees each row transition from 'pending' to 'in-flight' — the
      // other publisher's UPDATE matches zero rows and its batch shrinks.
      // We re-select after the UPDATE to know which IDs we actually
      // claimed (sqlite UPDATE doesn't return affected rows the same
      // way Postgres does).
      var actuallyClaimed;
      if (supportsSkipLocked) {
        // Postgres/MySQL: row lock held; ANY($1) update is safe.
        await xdb.query(
          "UPDATE " + quotedTable + " SET status = 'in-flight' WHERE id = ANY($1)",
          [ids]
        );
        actuallyClaimed = rows.rows;
      } else {
        // SQLite (or "other") path: emit a portable UPDATE that
        // refuses overlap by gating on status='pending'. After the
        // update we re-read the in-flight rows we own; rows that
        // another publisher beat us to are skipped.
        // Use placeholders so the SQL stays parameterized regardless
        // of dialect array semantics.
        var placeholders = ids.map(function (_, i) { return "$" + (i + 1); }).join(",");
        await xdb.query(
          "UPDATE " + quotedTable +
          " SET status = 'in-flight' WHERE status = 'pending' AND id IN (" + placeholders + ")",
          ids
        );
        var afterRows = await xdb.query(
          "SELECT id, topic, payload, key, headers, attempts FROM " + quotedTable +
          " WHERE status = 'in-flight' AND id IN (" + placeholders + ")",
          ids
        );
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

  async function _markPublished(id) {
    await externalDb.query(
      "UPDATE " + quotedTable +
      " SET status = 'published', published_at = $1 WHERE id = $2",
      [_utcNowExpr(externalDb), id]
    );
  }

  async function _markRetry(id, attempts, errMsg) {
    var nextAt = new Date(Date.now() + _backoffMs(attempts + 1));
    await externalDb.query(
      "UPDATE " + quotedTable +
      " SET status = 'pending', attempts = $1, last_error = $2, next_attempt_at = $3" +
      " WHERE id = $4",
      [attempts + 1, String(errMsg).slice(0, 1024), nextAt, id]                    // error-message char cap
    );
  }

  async function _markDead(id, attempts, errMsg) {
    await externalDb.query(
      "UPDATE " + quotedTable +
      " SET status = 'dead', attempts = $1, last_error = $2 WHERE id = $3",
      [attempts + 1, String(errMsg).slice(0, 1024), id]                            // error-message char cap
    );
    _emitAudit("system.outbox.deadletter", "failure", { id: id, attempts: attempts + 1 });
    _emitMetric("dead-letter", 1);
  }

  async function _processOnce() {
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
      try { await inFlight; } catch (_e) { /* drop-silent */ }
    }
    _emitAudit("system.outbox.stopped", "success", { name: name });
  }

  async function pendingCount() {
    var res = await externalDb.query(
      "SELECT COUNT(*) AS n FROM " + quotedTable + " WHERE status = 'pending'", []
    );
    return Number((res && res.rows && res.rows[0] && res.rows[0].n) || 0);
  }

  async function deadCount() {
    var res = await externalDb.query(
      "SELECT COUNT(*) AS n FROM " + quotedTable + " WHERE status = 'dead'", []
    );
    return Number((res && res.rows && res.rows[0] && res.rows[0].n) || 0);
  }

  return {
    enqueue:       enqueue,
    declareSchema: declareSchema,
    start:         start,
    stop:          stop,
    pendingCount:  pendingCount,
    deadCount:     deadCount,
    _processOnce:  _processOnce,                                                   // test hook — drive a single poll deterministically
  };
}

module.exports = {
  create:      create,
  OutboxError: OutboxError,
};
