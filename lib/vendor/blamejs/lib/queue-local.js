"use strict";
/**
 * Local-protocol queue adapter — DB-backed, dialect-portable.
 *
 * Single-node: backed by the framework's main DB (_blamejs_jobs in
 * local SQLite, baked into FRAMEWORK_SCHEMA).
 * Cluster mode: backed by external-db (_blamejs_jobs created via
 * frameworkSchema.ensureSchema). cluster-storage.execute routes the
 * same SQL to the right place based on cluster.isClusterMode().
 *
 * Lease semantics:
 *   enqueue → INSERT status='pending'
 *   lease   → atomic UPDATE pending→inflight (single statement with
 *             RETURNING; no transaction needed — the WHERE clause's
 *             subquery + Postgres's row-lock-then-recheck behavior
 *             makes concurrent leasers safe automatically. The unlucky
 *             leaser sees zero rows and tries again on the next tick.)
 *   complete→ UPDATE inflight→done
 *   fail    → single UPDATE with CASE WHEN attempts < maxAttempts
 *             (retry) ELSE (final failure) — collapsed into one
 *             statement so the same code path works in both single-
 *             node and cluster mode without a cross-dialect
 *             transaction primitive.
 *   sweep   → orphaned 'inflight' rows whose lease expired → 'pending'
 *
 * Field-crypto integration: payload + lastError are sealed columns
 * (declared in db.js's FRAMEWORK_SCHEMA registration). enqueue seals
 * before INSERT; lease unseals the leased rows before returning to
 * the caller. cluster-storage's RETURNING clause hands back sealed
 * blobs which we run through cryptoField.unsealRow explicitly.
 *
 * Bring-your-own database: the local backend defaults to the
 * framework's main DB (single-node) / external-db (cluster) via
 * cluster-storage, and to the table "_blamejs_jobs". An operator can
 * point the backend at their own store, table, and schema through the
 * protocol config — see create(config). The physical table reference
 * is composed through b.safeSql identifier quoting (never raw string
 * interpolation), so an operator-supplied table/schema cannot smuggle
 * SQL through the identifier slot (SQL identifier injection, CWE-89).
 * Sealing stays keyed off the logical column map registered for
 * "_blamejs_jobs", so payload + lastError remain sealed regardless of
 * which physical table the rows land in.
 */
var cluster = require("./cluster");
var clusterStorage = require("./cluster-storage");
var C = require("./constants");
var { generateToken } = require("./crypto");
var cryptoField = require("./crypto-field");
var lazyRequire = require("./lazy-require");
var numericBounds = require("./numeric-bounds");
var safeJson = require("./safe-json");
var safeSql = require("./safe-sql");
var scheduler = require("./scheduler");
var { QueueError } = require("./framework-error");

var _err = QueueError.factory;

// Logical table name the field-crypto schema is keyed on. This is the
// COLUMN→seal map registered in db.js's FRAMEWORK_SCHEMA, NOT the
// physical table the SQL writes to. An operator who points the backend
// at their own table still seals payload + lastError through this map,
// so a bring-your-own table inherits the same at-rest protection.
var SEAL_TABLE = "_blamejs_jobs";

// Default physical table for the local backend.
var DEFAULT_TABLE = "_blamejs_jobs";

// vault is lazy-required because some flows (sealed lastError) only
// touch it on retry-with-error paths, and the import order
// (queue-local → vault → db → audit → cluster) tolerates the late bind.
var vault = lazyRequire(function () { return require("./vault"); });

// Column order kept as a constant so the placeholders + values lists
// stay in sync. Mirrors db.js's FRAMEWORK_SCHEMA for _blamejs_jobs.
var JOB_COLS = [
  "_id", "queueName", "payload", "status",
  "enqueuedAt", "availableAt", "leasedAt", "leaseExpiresAt",
  "attempts", "maxAttempts", "lastError", "finishedAt",
  "traceId", "classification", "priority",
  "repeatCron", "repeatTimezone",
  "flowId", "flowChildName", "dependsOn",
];

// Sentinel availableAt for flow children that haven't yet had their
// dependencies satisfied — far future so the lease query never picks
// them. Parent-completion sets a real availableAt when all deps complete.
var FLOW_BLOCKED_AVAILABLE_AT = Number.MAX_SAFE_INTEGER;

// Columns returned by lease() / used by RETURNING. Subset of JOB_COLS
// — only what callers need; fewer bytes over the wire in cluster mode.
var LEASE_RETURN_COLS = [
  "_id", "queueName", "payload",
  "attempts", "maxAttempts", "traceId", "classification",
  "enqueuedAt", "leaseExpiresAt",
  "repeatCron", "repeatTimezone", "flowId", "flowChildName",
];

function _quotedList(cols) {
  return cols.map(function (c) { return '"' + c + '"'; }).join(", ");
}

function _placeholders(cols) {
  return cols.map(function () { return "?"; }).join(", ");
}

function _shapeLeasedRow(raw) {
  // raw is a row coming back from RETURNING — payload is sealed if
  // present. Run through cryptoField's unseal pipeline so the caller
  // gets cleartext.
  var unsealed = cryptoField.unsealRow(SEAL_TABLE, raw);
  return {
    jobId:          unsealed._id,
    queueName:      unsealed.queueName,
    payload:        unsealed.payload ? safeJson.parse(unsealed.payload, { maxBytes: C.BYTES.mib(64) }) : null,
    attempts:       Number(unsealed.attempts),
    maxAttempts:    Number(unsealed.maxAttempts),
    traceId:        unsealed.traceId,
    classification: unsealed.classification,
    enqueuedAt:     Number(unsealed.enqueuedAt),
    leaseExpiresAt: Number(unsealed.leaseExpiresAt),
    repeatCron:     unsealed.repeatCron     || null,
    repeatTimezone: unsealed.repeatTimezone || null,
    flowId:         unsealed.flowId         || null,
    flowChildName:  unsealed.flowChildName  || null,
  };
}

// Validate a bring-your-own store handle at config time. It must expose
// the execute / executeOne / executeAll trio that cluster-storage does,
// since every method here dispatches through that surface.
var _REQUIRED_STORE_METHODS = ["execute", "executeOne", "executeAll"];
function _resolveStore(handle) {
  if (handle === undefined || handle === null) return clusterStorage;
  if (typeof handle !== "object") {
    throw _err("INVALID_DB_HANDLE",
      "queue local config.db must be a storage handle exposing execute/executeOne/executeAll, got " +
        typeof handle, true);
  }
  for (var i = 0; i < _REQUIRED_STORE_METHODS.length; i++) {
    var m = _REQUIRED_STORE_METHODS[i];
    if (typeof handle[m] !== "function") {
      throw _err("INVALID_DB_HANDLE",
        "queue local config.db is missing required method '" + m + "()'", true);
    }
  }
  return handle;
}

// Compose the physical table reference from config.table + config.schema,
// quoting each identifier through b.safeSql so an operator-supplied name
// cannot interpolate SQL through the identifier slot (CWE-89). Returns
// the bare default name unquoted when no custom table/schema is given so
// the framework's cluster-mode table rewrite (resolveTables) still fires
// on the default jobs table; any custom name is fully validated + quoted.
function _resolveTableRef(config) {
  var table = config.table !== undefined && config.table !== null
    ? config.table : DEFAULT_TABLE;
  if (typeof table !== "string") {
    throw _err("INVALID_TABLE",
      "queue local config.table must be a string identifier, got " + typeof table, true);
  }
  var schema = config.schema;
  if (schema !== undefined && schema !== null && typeof schema !== "string") {
    throw _err("INVALID_SCHEMA",
      "queue local config.schema must be a string identifier, got " + typeof schema, true);
  }
  var usingDefault = (table === DEFAULT_TABLE) &&
    (schema === undefined || schema === null);
  if (usingDefault) {
    // Byte-identical default SQL — unquoted bare name so cluster-mode
    // resolveTables continues to recognize and rewrite the jobs table.
    return DEFAULT_TABLE;
  }
  // Any custom table/schema is validated + dialect-quoted. validateIdentifier
  // / quoteQualified THROW (SafeSqlError) on a bad identifier; surface that
  // as the queue's config-time error so the operator catches the typo at
  // boot rather than on first enqueue.
  try {
    if (schema !== undefined && schema !== null && schema !== "") {
      return safeSql.quoteQualified([schema, table]);
    }
    return safeSql.quoteIdentifier(table);
  } catch (e) {
    throw _err("INVALID_TABLE",
      "queue local table/schema failed identifier validation: " + e.message, true);
  }
}

function create(config) {
  config = config || {};
  // Bring-your-own store + table. Defaults preserve the prior behavior
  // exactly: cluster-storage dispatch to the framework's main DB
  // (single-node) / external-db (cluster), table "_blamejs_jobs".
  var store = _resolveStore(config.db);
  // qTable holds the physical table reference already validated +
  // dialect-quoted by _resolveTableRef (via safeSql.quoteIdentifier /
  // quoteQualified, or the framework's bare default name). The `q` prefix
  // marks it as a safe-to-interpolate identifier so it is never re-quoted.
  var qTable = _resolveTableRef(config);

  async function enqueue(queueName, payload, opts) {
    cluster.requireLeader();
    opts = opts || {};
    var nowMs = Date.now();
    // ----------------------------------------------------------------------
    // SCHEDULING PRECEDENCE — the contract for every queue.enqueue caller
    // ----------------------------------------------------------------------
    // The queue accepts TWO ways to express "when should this job run":
    //   - opts.availableAt  (absolute unix-ms)   — precise, framework-internal
    //   - opts.delaySeconds (integer seconds)    — operator shorthand
    //
    // PRECEDENCE: opts.availableAt wins when finite. Operators passing both
    // get the absolute value; the relative form is computed from
    // Date.now() and is therefore strictly less precise (loses sub-second
    // resolution AND drifts on the internal-clock-vs-caller delta).
    //
    // If you're a caller computing a precise time (cron-repeat,
    // scheduler.scheduleAt, notify.deferUntil), pass opts.availableAt
    // ONLY. Don't pass both — the second one is noise (and was the
    // shape that caused the v0.6.21 silent-drift bug). If you only have
    // a relative offset, pass opts.delaySeconds ONLY.
    // ----------------------------------------------------------------------
    var availableAt;
    if (typeof opts.availableAt === "number" && isFinite(opts.availableAt)) {
      availableAt = opts.availableAt;
    } else {
      availableAt = nowMs + (opts.delaySeconds ? C.TIME.seconds(opts.delaySeconds) : 0);
    }

    var priority = (typeof opts.priority === "number" && isFinite(opts.priority))
      ? Math.floor(opts.priority) : 0;
    var repeatCron     = opts.repeat && typeof opts.repeat.cron === "string"
                            ? opts.repeat.cron : null;
    var repeatTimezone = opts.repeat && typeof opts.repeat.timezone === "string"
                            ? opts.repeat.timezone : null;
    var flowId         = typeof opts.flowId === "string" ? opts.flowId : null;
    var flowChildName  = typeof opts.flowChildName === "string" ? opts.flowChildName : null;
    var dependsOn      = Array.isArray(opts.dependsOn) && opts.dependsOn.length > 0
                            ? JSON.stringify(opts.dependsOn) : null;
    // Flow children with deps wait at MAX_SAFE_INTEGER until parent
    // completion bumps availableAt — keeps them out of the lease index.
    var effectiveAvailableAt = (dependsOn ? FLOW_BLOCKED_AVAILABLE_AT : availableAt);

    var row = {
      _id:             generateToken(C.BYTES.bytes(16)),
      queueName:       queueName,
      payload:         payload === undefined ? null : JSON.stringify(payload),
      status:          "pending",
      enqueuedAt:      nowMs,
      availableAt:     effectiveAvailableAt,
      leasedAt:        null,
      leaseExpiresAt:  null,
      attempts:        0,
      maxAttempts:     opts.maxAttempts != null ? opts.maxAttempts : 5,
      lastError:       null,
      finishedAt:      null,
      traceId:         opts.traceId || null,
      classification:  opts.classification || null,
      priority:        priority,
      repeatCron:      repeatCron,
      repeatTimezone:  repeatTimezone,
      flowId:          flowId,
      flowChildName:   flowChildName,
      dependsOn:       dependsOn,
    };
    var sealed = cryptoField.sealRow(SEAL_TABLE, row);
    var values = JOB_COLS.map(function (c) { return c in sealed ? sealed[c] : null; });

    await store.execute(
      "INSERT INTO " + qTable + " (" + _quotedList(JOB_COLS) + ") " +
      "VALUES (" + _placeholders(JOB_COLS) + ")",
      values
    );
    return {
      jobId:          row._id,
      queueName:      queueName,
      enqueuedAt:     nowMs,
      availableAt:    availableAt,
      classification: row.classification,
    };
  }

  async function lease(queueName, leaseMs, count) {
    cluster.requireLeader();
    var nowMs = Date.now();
    var leaseExpiresAt = nowMs + leaseMs;
    var maxRows = count != null ? count : 1;

    // Single-statement atomic lease. The IN-subquery picks the head of
    // the queue; the outer UPDATE locks those rows and only updates
    // rows that still match status='pending' after the lock acquires
    // (Postgres EvalPlanQual; SQLite is single-writer so the same row
    // can't be picked twice). RETURNING hands back the leased columns
    // so we don't need a separate SELECT after the UPDATE.
    var sql =
      "UPDATE " + qTable + " " +
      "SET status = 'inflight', leasedAt = ?, leaseExpiresAt = ?, attempts = attempts + 1 " +
      "WHERE _id IN (" +
      "  SELECT _id FROM " + qTable + " " +
      "  WHERE queueName = ? AND status = 'pending' AND availableAt <= ? " +
      "  ORDER BY priority DESC, availableAt ASC, enqueuedAt ASC " +
      "  LIMIT ?" +
      ") " +
      "RETURNING " + _quotedList(LEASE_RETURN_COLS);
    var result = await store.execute(
      sql,
      [nowMs, leaseExpiresAt, queueName, nowMs, maxRows]
    );
    var leased = [];
    for (var i = 0; i < result.rows.length; i++) {
      leased.push(_shapeLeasedRow(result.rows[i]));
    }
    return leased;
  }

  // extendLease — push the lease expiry forward for a long-running job.
  // Handler context exposes this as `ctx.extendLease(ms)`. The job must
  // still be in 'inflight' status (i.e. not yet swept by sweepExpired);
  // otherwise the call no-ops and returns false.
  async function extendLease(jobId, additionalMs) {
    cluster.requireLeader();
    if (typeof additionalMs !== "number" || additionalMs <= 0) {
      throw _err("INVALID_LEASE_EXTENSION",
        "extendLease: additionalMs must be a positive number", true);
    }
    var newExpiry = Date.now() + additionalMs;
    var result = await store.execute(
      "UPDATE " + qTable + " SET leaseExpiresAt = ? " +
      "WHERE _id = ? AND status = 'inflight'",
      [newExpiry, jobId]
    );
    return (result.rowCount || 0) > 0;
  }

  async function complete(jobId) {
    cluster.requireLeader();
    var nowMs = Date.now();
    // Read the row first so we can act on repeat / flow metadata after
    // the status flip. Single SELECT + UPDATE pair under the same
    // jobId — race-free under SQLite (single-writer); cluster-storage
    // dispatches both calls to the same backend.
    var rowRes = await store.execute(
      "SELECT _id, queueName, payload, repeatCron, repeatTimezone, " +
      "       flowId, flowChildName, priority, classification, traceId " +
      "FROM " + qTable + " WHERE _id = ?",
      [jobId]
    );
    var row = (rowRes && rowRes.rows && rowRes.rows[0]) || null;

    await store.execute(
      "UPDATE " + qTable + " SET status = 'done', finishedAt = ?, leaseExpiresAt = NULL " +
      "WHERE _id = ? AND status = 'inflight'",
      [nowMs, jobId]
    );

    // Repeat-in-queue: cron-recurring job re-enqueues itself for the
    // next firing time. Failures (which take the fail() path) don't
    // re-enqueue — operators investigate before the cron resumes.
    if (row && row.repeatCron) {
      try {
        var unsealedRow = cryptoField.unsealRow(SEAL_TABLE, row);
        var cron = scheduler.parseCron(unsealedRow.repeatCron);
        var nextMs = scheduler.nextCronFire(cron, new Date(nowMs), unsealedRow.repeatTimezone || null);
        await enqueue(unsealedRow.queueName,
          unsealedRow.payload ? safeJson.parse(unsealedRow.payload, { maxBytes: C.BYTES.mib(64) }) : null,
          {
            // availableAt is the precise next-fire ms — pass it alone.
            // Don't also pass delaySeconds (the v0.6.22 / v0.6.23 fix
            // codified that opts.availableAt wins, but mixing both is
            // the shape that masked the silent-drift bug; keep this
            // call site clean as documentation by example).
            availableAt:     nextMs,
            repeat:          { cron: unsealedRow.repeatCron, timezone: unsealedRow.repeatTimezone },
            priority:        Number(unsealedRow.priority) || 0,
            classification:  unsealedRow.classification || null,
            traceId:         unsealedRow.traceId || null,
          });
      } catch (_e) { /* repeat re-enqueue best-effort — cron resumes next tick if op fixes the issue */ }
    }

    // Flow propagation: walk siblings whose dependsOn includes this
    // jobId (or this job's flowChildName) and bump availableAt to now
    // if ALL their deps are now complete.
    if (row && row.flowId) {
      await _maybeReleaseFlowChildren(row.flowId, jobId, row.flowChildName, nowMs);
    }
    return true;
  }

  async function _maybeReleaseFlowChildren(flowId, completedJobId, completedChildName, nowMs) {
    var siblingsRes = await store.execute(
      "SELECT _id, dependsOn, flowChildName, status, availableAt FROM " + qTable + " " +
      "WHERE flowId = ? AND status = 'pending' AND availableAt > ?",
      [flowId, nowMs]
    );
    var siblings = (siblingsRes && siblingsRes.rows) || [];
    for (var i = 0; i < siblings.length; i++) {
      var sib = siblings[i];
      if (!sib.dependsOn) continue;
      var deps;
      try { deps = safeJson.parse(sib.dependsOn, { maxBytes: C.BYTES.mib(1) }); }
      catch (_e) { continue; }
      if (!Array.isArray(deps) || deps.length === 0) continue;
      // Resolve which deps are satisfied. Each dep is either a jobId
      // or a flowChildName; we accept both shapes against the flow.
      var allDone = true;
      for (var d = 0; d < deps.length; d++) {
        var dep = deps[d];
        // Quick path: just-completed job matches by id or child name.
        if (dep === completedJobId || (completedChildName && dep === completedChildName)) continue;
        // Otherwise SELECT to confirm done.
        var depRes = await store.execute(
          "SELECT 1 FROM " + qTable + " WHERE flowId = ? AND status = 'done' AND " +
          "  (_id = ? OR flowChildName = ?) LIMIT 1",
          [flowId, dep, dep]
        );
        if (!depRes || !depRes.rows || depRes.rows.length === 0) { allDone = false; break; }
      }
      if (allDone) {
        await store.execute(
          "UPDATE " + qTable + " SET availableAt = ? WHERE _id = ?",
          [nowMs, sib._id]
        );
      }
    }
  }

  async function fail(jobId, errorMessage, opts) {
    cluster.requireLeader();
    opts = opts || {};
    var retryDelayMs = opts.retryDelayMs != null ? opts.retryDelayMs : 0;
    var nowMs = Date.now();
    var sealedErr = errorMessage ? vault().seal(String(errorMessage)) : null;

    // Single-statement decision: retry vs final failure based on the
    // row's current attempts/maxAttempts. CASE expressions split the
    // status / availableAt / finishedAt updates per branch — same
    // semantics as the previous SELECT-then-UPDATE-in-transaction
    // path, but no cross-dialect transaction primitive needed.
    await store.execute(
      "UPDATE " + qTable + " SET " +
      "  status = CASE WHEN attempts < maxAttempts THEN 'pending' ELSE 'failed' END, " +
      "  lastError = ?, " +
      "  leaseExpiresAt = NULL, " +
      "  availableAt = CASE WHEN attempts < maxAttempts THEN ? ELSE availableAt END, " +
      "  finishedAt  = CASE WHEN attempts < maxAttempts THEN NULL ELSE ? END " +
      "WHERE _id = ?",
      [sealedErr, nowMs + retryDelayMs, nowMs, jobId]
    );
    return true;
  }

  async function sweepExpired() {
    cluster.requireLeader();
    var result = await store.execute(
      "UPDATE " + qTable + " SET status = 'pending', leaseExpiresAt = NULL " +
      "WHERE status = 'inflight' AND leaseExpiresAt < ?",
      [Date.now()]
    );
    return result.rowCount || 0;
  }

  async function size(queueName) {
    var row = await store.executeOne(
      "SELECT COUNT(*) AS n FROM " + qTable + " " +
      "WHERE queueName = ? AND (status = 'pending' OR status = 'inflight')",
      [queueName]
    );
    return row ? Number(row.n) : 0;
  }

  // ---- DLQ (dead-letter queue) ----
  //
  // Jobs that exhausted their retry budget land in status='failed' with
  // finishedAt set + lastError sealed. dlqList surfaces them for
  // operator review; dlqRetry resets a job back to 'pending' so it can
  // be reprocessed (operator-driven — never automatic).

  async function dlqList(queueName, opts) {
    opts = opts || {};
    var limit = 100;
    if (opts.limit !== undefined) {
      if (!numericBounds.isPositiveFiniteInt(opts.limit)) {
        throw new QueueError("queue/bad-opt",
          "queue.dlqList: limit must be a positive finite integer; got " +
            numericBounds.shape(opts.limit), true);
      }
      limit = opts.limit;
    }
    var rows = await store.executeAll(
      "SELECT _id, queueName, payload, status, enqueuedAt, finishedAt, " +
      "       attempts, maxAttempts, lastError, traceId, classification " +
      "FROM " + qTable + " " +
      "WHERE queueName = ? AND status = 'failed' " +
      "ORDER BY finishedAt DESC LIMIT ?",
      [queueName, limit]
    );
    return rows.map(function (row) {
      var unsealed = cryptoField.unsealRow(SEAL_TABLE, row);
      return {
        jobId:       row._id,
        queueName:   row.queueName,
        payload:     unsealed.payload ? safeJson.parse(unsealed.payload, { maxBytes: C.BYTES.mib(64) }) : null,
        status:      row.status,
        enqueuedAt:  Number(row.enqueuedAt),
        finishedAt:  row.finishedAt ? Number(row.finishedAt) : null,
        attempts:    Number(row.attempts),
        maxAttempts: Number(row.maxAttempts),
        lastError:   unsealed.lastError || null,
        traceId:     row.traceId || null,
        classification: row.classification || null,
      };
    });
  }

  async function dlqRetry(jobId) {
    cluster.requireLeader();
    var nowMs = Date.now();
    var result = await store.execute(
      "UPDATE " + qTable + " SET " +
      "  status = 'pending', " +
      "  attempts = 0, " +
      "  availableAt = ?, " +
      "  finishedAt = NULL, " +
      "  leasedAt = NULL, " +
      "  leaseExpiresAt = NULL, " +
      "  lastError = NULL " +
      "WHERE _id = ? AND status = 'failed'",
      [nowMs, jobId]
    );
    return (result.rowCount || 0) > 0;
  }

  async function dlqSize(queueName) {
    var row = await store.executeOne(
      "SELECT COUNT(*) AS n FROM " + qTable + " " +
      "WHERE queueName = ? AND status = 'failed'",
      [queueName]
    );
    return row ? Number(row.n) : 0;
  }

  async function purge(queueName) {
    cluster.requireLeader();
    var result = await store.execute(
      "DELETE FROM " + qTable + " WHERE queueName = ?",
      [queueName]
    );
    return result.rowCount || 0;
  }

  // patchFlowDeps — the second pass of enqueueFlow. Writes the resolved
  // dependsOn jobIds and parks availableAt at MAX_SAFE_INTEGER for a flow
  // child that has dependencies. Lives on the backend (not in queue.js)
  // so it targets THIS backend's configured store + table — a
  // bring-your-own table receives the flow graph the same way the
  // first-pass enqueue did, instead of the dispatcher writing to the
  // default jobs table behind the backend's back. depIds is serialized
  // to JSON for the dependsOn column.
  async function patchFlowDeps(jobId, depIds) {
    cluster.requireLeader();
    var result = await store.execute(
      "UPDATE " + qTable + " SET dependsOn = ?, availableAt = ? WHERE _id = ?",
      [JSON.stringify(depIds), FLOW_BLOCKED_AVAILABLE_AT, jobId]
    );
    return (result.rowCount || 0) > 0;
  }

  return {
    protocol:       "local",
    enqueue:        enqueue,
    lease:          lease,
    extendLease:    extendLease,
    complete:       complete,
    fail:           fail,
    sweepExpired:   sweepExpired,
    size:           size,
    purge:          purge,
    dlqList:        dlqList,
    dlqRetry:       dlqRetry,
    dlqSize:        dlqSize,
    patchFlowDeps:  patchFlowDeps,
  };
}

module.exports = { create: create };
