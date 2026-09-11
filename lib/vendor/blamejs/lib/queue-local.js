// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
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

// allow:hand-rolled-sql — cryptoField seal-table registry KEY, not a SQL table.
var SEAL_TABLE = "_blamejs_jobs";

// allow:hand-rolled-sql — framework logical jobs-table name handed to b.sql, not a SQL literal.
var DEFAULT_TABLE = "_blamejs_jobs";

// vault is lazy-required because some flows (sealed lastError) only
// touch it on retry-with-error paths, and the import order
// (queue-local → vault → db → audit → cluster) tolerates the late bind.
var vault = lazyRequire(function () { return require("./vault"); });

function _ensureSealTable() {
  if (cryptoField.getSchema(SEAL_TABLE)) return;
  cryptoField.registerTable(SEAL_TABLE, {
    sealedFields: ["payload", "lastError"],
  });
}

var JOB_COLS = [
  "_id", "queueName", "payload", "status",
  "enqueuedAt", "availableAt", "leasedAt", "leaseExpiresAt",
  "attempts", "maxAttempts", "lastError", "finishedAt",
  "traceId", "classification", "priority",
  "repeatCron", "repeatTimezone",
  "flowId", "flowChildName", "dependsOn",
];

var FLOW_BLOCKED_AVAILABLE_AT = Number.MAX_SAFE_INTEGER;

var LEASE_RETURN_COLS = [
  "_id", "queueName", "payload",
  "attempts", "maxAttempts", "traceId", "classification",
  "enqueuedAt", "leaseExpiresAt",
  "repeatCron", "repeatTimezone", "flowId", "flowChildName",
];

function _shapeLeasedRow(raw) {
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

var _REQUIRED_STORE_METHODS = ["execute", "executeOne", "executeAll"];
function _resolveStore(handle) {
  if (handle === undefined || handle === null) return clusterStorage;
  if (typeof handle !== "object") {
    throw _err("queue-local/invalid-db-handle",
      "queue local config.db must be a storage handle exposing execute/executeOne/executeAll, got " +
        typeof handle, true);
  }
  for (var i = 0; i < _REQUIRED_STORE_METHODS.length; i++) {
    var m = _REQUIRED_STORE_METHODS[i];
    if (typeof handle[m] !== "function") {
      throw _err("queue-local/invalid-db-handle",
        "queue local config.db is missing required method '" + m + "()'", true);
    }
  }
  return handle;
}

function _resolveTableRef(config) {
  var table = config.table !== undefined && config.table !== null
    ? config.table : DEFAULT_TABLE;
  if (typeof table !== "string") {
    throw _err("queue-local/invalid-table",
      "queue local config.table must be a string identifier, got " + typeof table, true);
  }
  var schema = config.schema;
  if (schema !== undefined && schema !== null && typeof schema !== "string") {
    throw _err("queue-local/invalid-schema",
      "queue local config.schema must be a string identifier, got " + typeof schema, true);
  }
  var usingDefault = (table === DEFAULT_TABLE) &&
    (schema === undefined || schema === null);
  if (usingDefault) {
    return { name: DEFAULT_TABLE, opts: { dialect: "sqlite" } };
  }
  var opts = { dialect: "sqlite", quoteName: true };
  if (schema !== undefined && schema !== null && schema !== "") opts.schema = schema;
  try {
    safeSql.validateIdentifier(table);
    if (opts.schema) safeSql.validateIdentifier(opts.schema);
  } catch (e) {
    throw _err("queue-local/invalid-table",
      "queue local table/schema failed identifier validation: " + e.message, true);
  }
  return { name: table, opts: opts };
}

function create(config) {
  config = config || {};
  var store = _resolveStore(config.db);
  var ref = _resolveTableRef(config);
  function _dialect() {
    if (store === clusterStorage) return clusterStorage.dialect();
    if (typeof store.dialect === "function") return store.dialect();
    return (typeof config.dialect === "string" && config.dialect) ? config.dialect : "sqlite";
  }
  function _opts() { return Object.assign({}, ref.opts, { dialect: _dialect() }); }
  function _select() { return sql.select(ref.name, _opts()); }
  function _insert() { return sql.insert(ref.name, _opts()); }
  function _update() { return sql.update(ref.name, _opts()); }
  function _delete() { return sql.delete(ref.name, _opts()); }
  function _qc(col) { return safeSql.quoteIdentifier(col, _dialect(), { allowReserved: true }); }

  async function enqueue(queueName, payload, opts) {
    cluster.requireLeader();
    opts = opts || {};
    var nowMs = Date.now();
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

  function _leaseCandidates(queueName, nowMs, maxRows) {
    return _select()
      .columns(["_id"])
      .where("queueName", queueName)
      .where("status", "pending")
      .whereOp("availableAt", "<=", nowMs)
      .orderBy("priority", "desc")
      .orderBy("availableAt", "asc")
      .orderBy("enqueuedAt", "asc")
      .limit(maxRows);
  }

  async function lease(queueName, leaseMs, count) {
    cluster.requireLeader();
    var nowMs = Date.now();
    var leaseExpiresAt = nowMs + leaseMs;
    var maxRows = count != null ? count : 1;
    var dialect = _dialect();
    var i;

    if (dialect === "sqlite") {
      var leaseBuilt = _update()
        .set("status", "inflight")
        .set("leasedAt", nowMs)
        .set("leaseExpiresAt", leaseExpiresAt)
        .setRaw("attempts", _qc("attempts") + " + 1", [])
        .whereIn("_id", _leaseCandidates(queueName, nowMs, maxRows))
        .returning(LEASE_RETURN_COLS)
        .toSql();
      var result = await store.execute(leaseBuilt.sql, leaseBuilt.params);
      var leased = [];
      for (i = 0; i < result.rows.length; i++) leased.push(_shapeLeasedRow(result.rows[i]));
      return leased;
    }

    if (typeof store.transaction !== "function") {
      throw _err("queue-local/cluster-tx-unsupported",
        "queue lease on a '" + dialect + "' backend requires an interactive transaction, but the " +
        "configured store exposes no transaction(); use the default cluster store or supply a " +
        "transaction-capable store", true);
    }
    return await store.transaction(async function (tx) {
      var selBuilt = _leaseCandidates(queueName, nowMs, maxRows)
        .forUpdate({ skipLocked: true })
        .toSql();
      var selRes = await tx.execute(selBuilt.sql, selBuilt.params);
      var ids = ((selRes && selRes.rows) || []).map(function (r) { return r._id; });
      if (ids.length === 0) return [];

      var upd = _update()
        .set("status", "inflight")
        .set("leasedAt", nowMs)
        .set("leaseExpiresAt", leaseExpiresAt)
        .setRaw("attempts", _qc("attempts") + " + 1", [])
        .where("status", "pending")
        .whereInArray("_id", ids);

      var rows;
      if (dialect === "postgres") {
        var updBuilt = upd.returning(LEASE_RETURN_COLS).toSql();
        var updRes = await tx.execute(updBuilt.sql, updBuilt.params);
        rows = (updRes && updRes.rows) || [];
      } else {
        var u = upd.toSql();
        await tx.execute(u.sql, u.params);
        var rbBuilt = _select()
          .columns(LEASE_RETURN_COLS)
          .where("status", "inflight")
          .whereInArray("_id", ids)
          .toSql();
        var rbRes = await tx.execute(rbBuilt.sql, rbBuilt.params);
        rows = (rbRes && rbRes.rows) || [];
      }
      var out = [];
      for (i = 0; i < rows.length; i++) out.push(_shapeLeasedRow(rows[i]));
      return out;
    });
  }

  async function extendLease(jobId, additionalMs, opts) {
    cluster.requireLeader();
    if (typeof additionalMs !== "number" || additionalMs <= 0) {
      throw _err("queue-local/invalid-lease-extension",
        "extendLease: additionalMs must be a positive number", true);
    }
    var newExpiry = Date.now() + additionalMs;
    var extUpd = _update()
      .set("leaseExpiresAt", newExpiry)
      .where("_id", jobId)
      .where("status", "inflight");
    if (opts && opts.attempt != null) extUpd = extUpd.where("attempts", opts.attempt);
    var built = extUpd.toSql();
    var result = await store.execute(built.sql, built.params);
    return (result.rowCount || 0) > 0;
  }

  async function complete(jobId, opts) {
    cluster.requireLeader();
    var nowMs = Date.now();
    var rowBuilt = _select()
      .columns(["_id", "queueName", "payload", "repeatCron", "repeatTimezone",
                "flowId", "flowChildName", "priority", "classification", "traceId",
                "maxAttempts"])
      .where("_id", jobId)
      .toSql();
    var rowRes = await store.execute(rowBuilt.sql, rowBuilt.params);
    var row = (rowRes && rowRes.rows && rowRes.rows[0]) || null;

    var doneUpd = _update()
      .set("status", "done")
      .set("finishedAt", nowMs)
      .set("leaseExpiresAt", null)
      .where("_id", jobId)
      .where("status", "inflight");
    if (opts && opts.attempt != null) doneUpd = doneUpd.where("attempts", opts.attempt);
    var doneBuilt = doneUpd.toSql();
    var doneRes = await store.execute(doneBuilt.sql, doneBuilt.params);
    if ((doneRes.rowCount || 0) === 0) return false;

    if (row && row.repeatCron) {
      try {
        var unsealedRow = cryptoField.unsealRow(SEAL_TABLE, row);
        var cron = scheduler.parseCron(unsealedRow.repeatCron);
        var nextMs = scheduler.nextCronFire(cron, new Date(nowMs), unsealedRow.repeatTimezone || null);
        var repeatMax = Number(unsealedRow.maxAttempts);
        await enqueue(unsealedRow.queueName,
          unsealedRow.payload ? safeJson.parse(unsealedRow.payload, { maxBytes: C.BYTES.mib(64) }) : null,
          {
            availableAt:     nextMs,
            repeat:          { cron: unsealedRow.repeatCron, timezone: unsealedRow.repeatTimezone },
            priority:        Number(unsealedRow.priority) || 0,
            maxAttempts:     (isFinite(repeatMax) && repeatMax > 0) ? repeatMax : undefined,
            classification:  unsealedRow.classification || null,
            traceId:         unsealedRow.traceId || null,
          });
      } catch (_e) { /* repeat re-enqueue best-effort — cron resumes next tick if op fixes the issue */ }
    }

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
      var allDone = true;
      for (var d = 0; d < deps.length; d++) {
        var dep = deps[d];
        if (dep === completedJobId || (completedChildName && dep === completedChildName)) continue;
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

    var attemptsLt = _qc("attempts") + " < " + _qc("maxAttempts");
    var failUpd = _update()
      .setRaw("status", "CASE WHEN " + attemptsLt + " THEN ? ELSE ? END", ["pending", "failed"])
      .set("lastError", sealedErr)
      .set("leaseExpiresAt", null)
      .setRaw("availableAt", "CASE WHEN " + attemptsLt + " THEN ? ELSE " + _qc("availableAt") + " END",
              [nowMs + retryDelayMs])
      .setRaw("finishedAt", "CASE WHEN " + attemptsLt + " THEN NULL ELSE ? END", [nowMs])
      .where("_id", jobId)
      .where("status", "inflight");
    if (opts.attempt != null) failUpd = failUpd.where("attempts", opts.attempt);
    var failBuilt = failUpd.toSql();
    var failRes = await store.execute(failBuilt.sql, failBuilt.params);
    return (failRes.rowCount || 0) > 0;
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
    var built = _select()
      .count("*", "n")
      .where("queueName", queueName)
      .whereIn("status", ["pending", "inflight"])
      .toSql();
    var row = await store.executeOne(built.sql, built.params);
    return row ? Number(row.n) : 0;
  }

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

  async function patchFlowDeps(jobId, depIds) {
    cluster.requireLeader();
    var built = _update()
      .set("dependsOn", JSON.stringify(depIds))
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
  _ensureSealTable: _ensureSealTable,
};
