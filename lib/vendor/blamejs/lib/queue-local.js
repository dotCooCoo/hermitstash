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
var sql = require("./sql");
var scheduler = require("./scheduler");
var { QueueError } = require("./framework-error");

var _err = QueueError.factory;

// Logical table name the field-crypto schema is keyed on. This is the
// COLUMN→seal map registered in db.js's FRAMEWORK_SCHEMA, NOT the
// physical table the SQL writes to. An operator who points the backend
// at their own table still seals payload + lastError through this map,
// so a bring-your-own table inherits the same at-rest protection. The KEY
// must stay byte-identical to db.js's registerTable literal.
// allow:hand-rolled-sql — cryptoField seal-table registry KEY, not a SQL table.
var SEAL_TABLE = "_blamejs_jobs";

// Default LOGICAL table for the local backend. Passed BARE to b.sql so
// clusterStorage.resolveTables rewrites it to the configured cluster name
// (applying the configurable prefix); a custom config.table is quoted at
// build time instead. b.sql owns the quoting; this is the logical name.
// allow:hand-rolled-sql — framework logical jobs-table name handed to b.sql, not a SQL literal.
var DEFAULT_TABLE = "_blamejs_jobs";

// vault is lazy-required because some flows (sealed lastError) only
// touch it on retry-with-error paths, and the import order
// (queue-local → vault → db → audit → cluster) tolerates the late bind.
var vault = lazyRequire(function () { return require("./vault"); });

// Self-register the _blamejs_jobs sealed-column declaration with
// cryptoField so payload + lastError seal at rest even when db.init never
// ran in this process. cryptoField.sealRow is a SILENT pass-through for an
// unregistered table — a standalone redis/sqs queue node (no db.init) would
// otherwise write job payloads (webhook bodies, credentials, PII) in
// cleartext. db.init registers the same shape from its FRAMEWORK_SCHEMA;
// registerTable is idempotent, and probing getSchema (rather than a module
// boolean) keeps this reset-safe — db._resetForTest() clears the cryptoField
// registry between tests, and a boolean cache would then leave seal a no-op.
function _ensureSealTable() {
  if (cryptoField.getSchema(SEAL_TABLE)) return;
  cryptoField.registerTable(SEAL_TABLE, {
    sealedFields: ["payload", "lastError"],
  });
}

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

// Resolve the b.sql table-builder options from config.table + config.schema.
// Every SQL statement is composed through b.sql, which quotes identifiers
// through b.safeSql so an operator-supplied name cannot interpolate SQL
// through the identifier slot (CWE-89). The DEFAULT logical table is passed
// BARE (quoteName off) so the framework's cluster-mode rewrite
// (clusterStorage.resolveTables) still fires on the jobs table and applies
// the configurable prefix; any custom table/schema is validated + quoted at
// build time instead (no rewrite — it is the operator's own table).
//
// Returns { name, opts } where `opts` is spread into every b.sql verb call:
//   default → { dialect: "sqlite" }                  (bare name, rewritten)
//   custom  → { dialect: "sqlite", quoteName: true } (quoted, no rewrite)
//   custom+schema → adds { schema } (b.sql emits the quoted schema.table form)
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
    // Bare default — b.sql leaves it unquoted so cluster-mode resolveTables
    // recognizes + rewrites the jobs table (and applies the prefix).
    return { name: DEFAULT_TABLE, opts: { dialect: "sqlite" } };
  }
  // Any custom table/schema is validated + dialect-quoted by b.sql at build
  // time. validateIdentifier (run inside b.sql's TableRef) THROWs
  // (SqlBuilderError / SafeSqlError) on a bad identifier; surface that as the
  // queue's config-time error so the operator catches the typo at boot rather
  // than on first enqueue.
  var opts = { dialect: "sqlite", quoteName: true };
  if (schema !== undefined && schema !== null && schema !== "") opts.schema = schema;
  try {
    // Validate the custom identifier(s) at config time with the STRICTER
    // policy (allowReserved off — a reserved word like `select` is refused
    // for a bring-your-own queue table, matching the prior
    // quoteIdentifier / quoteQualified contract). b.sql then quotes the
    // already-validated name at build time. validateIdentifier THROWs
    // (SafeSqlError) on a bad shape / reserved word / injection-shaped
    // schema, surfaced here as the queue's config-time error so the
    // operator catches the typo at boot rather than on first enqueue.
    safeSql.validateIdentifier(table);
    if (opts.schema) safeSql.validateIdentifier(opts.schema);
  } catch (e) {
    throw _err("INVALID_TABLE",
      "queue local table/schema failed identifier validation: " + e.message, true);
  }
  return { name: table, opts: opts };
}

function create(config) {
  config = config || {};
  // Bring-your-own store + table. Defaults preserve the prior behavior
  // exactly: cluster-storage dispatch to the framework's main DB
  // (single-node) / external-db (cluster), table "_blamejs_jobs".
  var store = _resolveStore(config.db);
  // ref = { name, opts } for every b.sql verb call — the bare default
  // jobs table (clusterStorage rewrites it + applies the configurable
  // prefix) or a validated + quoted custom table/schema. Small helpers
  // open each verb builder pre-bound to this table so the table reference
  // is resolved in exactly one place.
  var ref = _resolveTableRef(config);
  function _select() { return sql.select(ref.name, ref.opts); }
  function _insert() { return sql.insert(ref.name, ref.opts); }
  function _update() { return sql.update(ref.name, ref.opts); }
  function _delete() { return sql.delete(ref.name, ref.opts); }
  // Quoted column expression for a setRaw RHS that references the column's
  // own pre-update value (attempts/availableAt). dialect-sqlite quoting is
  // the double-quote form clusterStorage's Postgres path keeps.
  function _qc(col) { return safeSql.quoteIdentifier(col, "sqlite", { allowReserved: true }); }

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
    // Build the full column→value map in JOB_COLS order (a missing sealed
    // column binds NULL, matching the prior positional-values shape). b.sql
    // quotes every column + binds every value as a placeholder.
    var insertRow = {};
    for (var ci = 0; ci < JOB_COLS.length; ci++) {
      var col = JOB_COLS[ci];
      insertRow[col] = col in sealed ? sealed[col] : null;
    }
    var insertBuilt = _insert().columns(JOB_COLS).values(insertRow).toSql();
    await store.execute(insertBuilt.sql, insertBuilt.params);
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
    // so we don't need a separate SELECT after the UPDATE. maxRows is a
    // framework-computed integer emitted inline via b.sql's .limit() (a
    // bound LIMIT param has no portable form across the subquery path);
    // attempts = attempts + 1 is a setRaw over the column's own value.
    var leaseInner = _select()
      .columns(["_id"])
      .where("queueName", queueName)
      .where("status", "pending")
      .whereOp("availableAt", "<=", nowMs)
      .orderBy("priority", "desc")
      .orderBy("availableAt", "asc")
      .orderBy("enqueuedAt", "asc")
      .limit(maxRows);
    var leaseBuilt = _update()
      .set("status", "inflight")
      .set("leasedAt", nowMs)
      .set("leaseExpiresAt", leaseExpiresAt)
      .setRaw("attempts", _qc("attempts") + " + 1", [])
      .whereIn("_id", leaseInner)
      .returning(LEASE_RETURN_COLS)
      .toSql();
    var result = await store.execute(leaseBuilt.sql, leaseBuilt.params);
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
    var built = _update()
      .set("leaseExpiresAt", newExpiry)
      .where("_id", jobId)
      .where("status", "inflight")
      .toSql();
    var result = await store.execute(built.sql, built.params);
    return (result.rowCount || 0) > 0;
  }

  async function complete(jobId) {
    cluster.requireLeader();
    var nowMs = Date.now();
    // Read the row first so we can act on repeat / flow metadata after
    // the status flip. Single SELECT + UPDATE pair under the same
    // jobId — race-free under SQLite (single-writer); cluster-storage
    // dispatches both calls to the same backend.
    var rowBuilt = _select()
      .columns(["_id", "queueName", "payload", "repeatCron", "repeatTimezone",
                "flowId", "flowChildName", "priority", "classification", "traceId"])
      .where("_id", jobId)
      .toSql();
    var rowRes = await store.execute(rowBuilt.sql, rowBuilt.params);
    var row = (rowRes && rowRes.rows && rowRes.rows[0]) || null;

    var doneBuilt = _update()
      .set("status", "done")
      .set("finishedAt", nowMs)
      .set("leaseExpiresAt", null)
      .where("_id", jobId)
      .where("status", "inflight")
      .toSql();
    await store.execute(doneBuilt.sql, doneBuilt.params);

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
    var siblingsBuilt = _select()
      .columns(["_id", "dependsOn", "flowChildName", "status", "availableAt"])
      .where("flowId", flowId)
      .where("status", "pending")
      .whereOp("availableAt", ">", nowMs)
      .toSql();
    var siblingsRes = await store.execute(siblingsBuilt.sql, siblingsBuilt.params);
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
        // Otherwise SELECT to confirm done. The (_id = ? OR flowChildName = ?)
        // disjunction is a whereGroup so it AND-composes at one precedence
        // level with the flowId + status equalities.
        var depBuilt = _select()
          .columns(["_id"])
          .where("flowId", flowId)
          .where("status", "done")
          .whereGroup(function (g) { g.where("_id", dep).orWhere("flowChildName", dep); })
          .limit(1)
          .toSql();
        var depRes = await store.execute(depBuilt.sql, depBuilt.params);
        if (!depRes || !depRes.rows || depRes.rows.length === 0) { allDone = false; break; }
      }
      if (allDone) {
        var releaseBuilt = _update()
          .set("availableAt", nowMs)
          .where("_id", sib._id)
          .toSql();
        await store.execute(releaseBuilt.sql, releaseBuilt.params);
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
    // path, but no cross-dialect transaction primitive needed. Each CASE
    // is a b.sql setRaw value-expression (guarded by b.guardSql) over the
    // row's own columns; the branch values bind as `?` placeholders (the
    // prior 'pending'/'failed' SQL literals now bind, which keeps the raw
    // fragment literal-free).
    var attemptsLt = _qc("attempts") + " < " + _qc("maxAttempts");
    var failBuilt = _update()
      .setRaw("status", "CASE WHEN " + attemptsLt + " THEN ? ELSE ? END", ["pending", "failed"])
      .set("lastError", sealedErr)
      .set("leaseExpiresAt", null)
      .setRaw("availableAt", "CASE WHEN " + attemptsLt + " THEN ? ELSE " + _qc("availableAt") + " END",
              [nowMs + retryDelayMs])
      .setRaw("finishedAt", "CASE WHEN " + attemptsLt + " THEN NULL ELSE ? END", [nowMs])
      .where("_id", jobId)
      .toSql();
    await store.execute(failBuilt.sql, failBuilt.params);
    return true;
  }

  async function sweepExpired() {
    cluster.requireLeader();
    var built = _update()
      .set("status", "pending")
      .set("leaseExpiresAt", null)
      .where("status", "inflight")
      .whereOp("leaseExpiresAt", "<", Date.now())
      .toSql();
    var result = await store.execute(built.sql, built.params);
    return result.rowCount || 0;
  }

  async function size(queueName) {
    // (status = 'pending' OR status = 'inflight') is an IN-list over the two
    // active states — b.sql expands it to (?, ?) bound placeholders.
    var built = _select()
      .count("*", "n")
      .where("queueName", queueName)
      .whereIn("status", ["pending", "inflight"])
      .toSql();
    var row = await store.executeOne(built.sql, built.params);
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
    var built = _select()
      .columns(["_id", "queueName", "payload", "status", "enqueuedAt", "finishedAt",
                "attempts", "maxAttempts", "lastError", "traceId", "classification"])
      .where("queueName", queueName)
      .where("status", "failed")
      .orderBy("finishedAt", "desc")
      .limit(limit)
      .toSql();
    var rows = await store.executeAll(built.sql, built.params);
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
    // NULL resets bind as null params (the prior SQL-literal NULLs); the
    // string-literal statuses bind too.
    var built = _update()
      .set({
        status:         "pending",
        attempts:       0,
        availableAt:    nowMs,
        finishedAt:     null,
        leasedAt:       null,
        leaseExpiresAt: null,
        lastError:      null,
      })
      .where("_id", jobId)
      .where("status", "failed")
      .toSql();
    var result = await store.execute(built.sql, built.params);
    return (result.rowCount || 0) > 0;
  }

  async function dlqSize(queueName) {
    var built = _select()
      .count("*", "n")
      .where("queueName", queueName)
      .where("status", "failed")
      .toSql();
    var row = await store.executeOne(built.sql, built.params);
    return row ? Number(row.n) : 0;
  }

  async function purge(queueName) {
    cluster.requireLeader();
    var built = _delete().where("queueName", queueName).toSql();
    var result = await store.execute(built.sql, built.params);
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
    var built = _update()
      .set("dependsOn", JSON.stringify(depIds))
      .set("availableAt", FLOW_BLOCKED_AVAILABLE_AT)
      .where("_id", jobId)
      .toSql();
    var result = await store.execute(built.sql, built.params);
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

module.exports = {
  create:           create,
  // Idempotent, reset-safe self-registration of the _blamejs_jobs sealed-
  // column declaration. queue.init calls this so seal-at-rest engages on a
  // standalone queue node that never ran db.init.
  _ensureSealTable: _ensureSealTable,
};
