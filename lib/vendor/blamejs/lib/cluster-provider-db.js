// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var C = require("./constants");
var { generateToken } = require("./crypto");
var externalDb = require("./external-db");
var frameworkSchema = require("./framework-schema");
var lazyRequire = require("./lazy-require");
var { ClusterProviderError } = require("./framework-error");

var _err = ClusterProviderError.factory;

// Lazy requires — cluster.js requires this module while cluster-storage /
// sql are still mid-load (cluster -> cluster-provider-db -> external-db ->
// external-db-migrate -> cluster-storage -> cluster), so a top-of-file
// require would resolve to an unfinished module. clusterStorage.placeholderize
// translates the b.sql `?` output to Postgres `$N`; sql is the b.sql builder.
// Both are resolved at first SQL emission, by which point the cycle has settled.
var clusterStorage = lazyRequire(function () { return require("./cluster-storage"); });
var sql = lazyRequire(function () { return require("./sql"); });

function create(config) {
  if (!config || !config.externalDbBackend) {
    throw _err("cluster-provider-db/invalid-config",
      "cluster-provider-db requires { externalDbBackend: <name> }", true);
  }

  var LEADER_TABLE = frameworkSchema.tableName("_blamejs_leader");          // allow:hand-rolled-sql — single canonical logical-name reference
  var STATE_TABLE  = frameworkSchema.tableName("_blamejs_cluster_state");   // allow:hand-rolled-sql — single canonical logical-name reference
  var backendName = config.externalDbBackend;
  var dialect = (config.dialect || "postgres").toLowerCase();
  if (dialect !== "postgres" && dialect !== "sqlite" && dialect !== "mysql") {
    throw _err("cluster-provider-db/unsupported-dialect",
      "cluster-provider-db dialect must be 'postgres', 'sqlite', or 'mysql' (got: " + dialect + ")",
      true);
  }

  var qchar = dialect === "mysql" ? "`" : "\"";
  function _qraw(col) { return qchar + col + qchar; }

  function _selfCol(col) {
    return dialect === "postgres" ? (LEADER_TABLE + "." + _qraw(col)) : _qraw(col);
  }

  function _emit(builder) {
    var built = builder.toSql();
    return {
      sql:    clusterStorage().placeholderize(built.sql, dialect),
      params: built.params,
    };
  }

  function _q(sql, params) {
    return externalDb.query(sql, params || [], { backend: backendName });
  }

  function _run(builder) {
    var e = _emit(builder);
    return _q(e.sql, e.params);
  }

  async function ensureSchema() {
    var intType = dialect === "sqlite" ? "INTEGER" : "BIGINT";
    var pkText = dialect === "mysql" ? "VARCHAR(64)" : "TEXT";
    var bodyText = dialect === "mysql" ? "VARCHAR(255)" : "TEXT";
    var leaderCheck = dialect === "mysql" ? "" : ", CHECK (scope = 'leader')";   // allow:hand-rolled-sql — static DDL CHECK literal
    var stateCheck  = dialect === "mysql" ? "" : ", CHECK (scope = 'state')";    // allow:hand-rolled-sql — static DDL CHECK literal

    await _q(sql().createTable(LEADER_TABLE, [
      { name: "scope",        type: pkText,   primaryKey: true },
      { name: "nodeId",       type: bodyText, notNull: true },
      { name: "leaseId",      type: bodyText, notNull: true },
      { name: "acquiredAt",   type: intType,  notNull: true },
      { name: "expiresAt",    type: intType,  notNull: true },
      { name: "fencingToken", type: intType,  notNull: true },
      { name: "endpoint",     type: bodyText, constraints: leaderCheck },
    ], { dialect: dialect }).sql);
    try {
      await _q(sql().alterTable(LEADER_TABLE,
        { addColumn: { name: "endpoint", type: bodyText } }, { dialect: dialect }).sql);
    } catch (_e) { /* column already exists — fine */ }

    await _q(sql().createTable(STATE_TABLE, [
      { name: "scope",          type: pkText,   primaryKey: true },
      { name: "vaultKeyFp",     type: bodyText, notNull: true },
      { name: "recordedAt",     type: intType,  notNull: true },
      { name: "recordedByNode", type: bodyText, notNull: true, constraints: stateCheck },
    ], { dialect: dialect }).sql);
  }

  async function acquireLease(nodeId, leaseTtlMs, opts) {
    if (!nodeId) throw _err("cluster-provider-db/invalid-node-id", "nodeId required", true);
    if (typeof leaseTtlMs !== "number" || leaseTtlMs <= 0) {
      throw _err("cluster-provider-db/invalid-ttl", "leaseTtlMs must be a positive number", true);
    }
    var endpoint = (opts && opts.endpoint) || null;
    var leaseId = generateToken(C.BYTES.bytes(16));
    var nowMs = Date.now();
    var expiresAt = nowMs + leaseTtlMs;

    var acquire = sql().upsert(LEADER_TABLE, { dialect: dialect })
      .columns(["scope", "nodeId", "leaseId", "acquiredAt", "expiresAt", "fencingToken", "endpoint"])
      .values({
        scope: "leader", nodeId: nodeId, leaseId: leaseId,
        acquiredAt: nowMs, expiresAt: expiresAt, fencingToken: 1, endpoint: endpoint,
      })
      .doUpdate({
        nodeId: "?", leaseId: "?", acquiredAt: "?", expiresAt: "?",
        fencingToken: _selfCol("fencingToken") + " + 1",
        endpoint: "?",
      }, [nodeId, leaseId, nowMs, expiresAt, endpoint])
      .conflictWhere(_selfCol("expiresAt") + " < ?", [nowMs], { guardColumn: "expiresAt" })
      .returning(["nodeId", "leaseId", "acquiredAt", "expiresAt", "fencingToken", "endpoint"]);

    var row;
    if (dialect === "mysql") {
      var mBuilt = acquire.toSql();
      await _q(clusterStorage().placeholderize(mBuilt.sql, dialect), mBuilt.params);
      var rb = mBuilt.readbackSql;
      var sel = await _q(clusterStorage().placeholderize(rb.sql, dialect), rb.params);
      if (!sel.rows || sel.rows.length === 0) return null;
      row = sel.rows[0];
    } else {
      acquire.onConflict(["scope"]);
      var result = await _run(acquire);
      if (!result.rows || result.rows.length === 0) return null;
      row = result.rows[0];
    }
    if (row.nodeId !== nodeId || row.leaseId !== leaseId) {
      return null;
    }
    return {
      nodeId:        row.nodeId,
      leaseId:       row.leaseId,
      acquiredAt:    Number(row.acquiredAt),
      expiresAt:     Number(row.expiresAt),
      fencingToken:  Number(row.fencingToken),
      endpoint:      row.endpoint || null,
    };
  }

  async function renewLease(lease, opts) {
    if (!lease || !lease.leaseId) throw _err("cluster-provider-db/invalid-lease", "lease required", true);
    var nowMs = Date.now();
    var ttlMs = lease.expiresAt - lease.acquiredAt;
    var newAcquiredAt = nowMs;
    var newExpiresAt = nowMs + ttlMs;
    var endpoint = (opts && opts.endpoint !== undefined) ? opts.endpoint : lease.endpoint || null;

    var renewCols = ["nodeId", "leaseId", "acquiredAt", "expiresAt", "fencingToken", "endpoint"];
    var row;
    if (dialect === "mysql") {
      var rvBuilt = sql().update(LEADER_TABLE, { dialect: dialect })
        .set({ acquiredAt: newAcquiredAt, expiresAt: newExpiresAt, endpoint: endpoint })
        .where("scope", "leader").where("nodeId", lease.nodeId).where("leaseId", lease.leaseId)
        .toSql();
      var rv = await _q(clusterStorage().placeholderize(rvBuilt.sql, dialect), rvBuilt.params);
      var affected = rv && (rv.affectedRows || rv.rowCount || 0);
      if (!affected) {
        throw _err("cluster-provider-db/lease-lost",
          "lease for node '" + lease.nodeId + "' was taken over (renewal rejected)",
          false);
      }
      var sel = await _run(sql().select(LEADER_TABLE, { dialect: dialect })
        .columns(renewCols).where("scope", "leader"));
      if (!sel.rows || sel.rows.length === 0 ||
          sel.rows[0].nodeId !== lease.nodeId ||
          sel.rows[0].leaseId !== lease.leaseId) {
        throw _err("cluster-provider-db/lease-lost",
          "lease for node '" + lease.nodeId + "' was taken over after renewal",
          false);
      }
      row = sel.rows[0];
    } else {
      var result = await _run(sql().update(LEADER_TABLE, { dialect: dialect })
        .set({ acquiredAt: newAcquiredAt, expiresAt: newExpiresAt, endpoint: endpoint })
        .where("scope", "leader").where("nodeId", lease.nodeId).where("leaseId", lease.leaseId)
        .returning(renewCols));
      if (!result.rows || result.rows.length === 0) {
        throw _err("cluster-provider-db/lease-lost",
          "lease for node '" + lease.nodeId + "' was taken over (renewal rejected)",
          false);
      }
      row = result.rows[0];
    }
    return {
      nodeId:        row.nodeId,
      leaseId:       row.leaseId,
      acquiredAt:    Number(row.acquiredAt),
      expiresAt:     Number(row.expiresAt),
      fencingToken:  Number(row.fencingToken),
      endpoint:      row.endpoint || null,
    };
  }

  async function releaseLease(lease) {
    if (!lease || !lease.leaseId) return;
    await _run(sql().update(LEADER_TABLE, { dialect: dialect })
      .set({ expiresAt: 0 })
      .where("scope", "leader").where("nodeId", lease.nodeId).where("leaseId", lease.leaseId));
  }

  async function currentLeader() {
    var result = await _run(sql().select(LEADER_TABLE, { dialect: dialect })
      .columns(["nodeId", "expiresAt", "fencingToken", "endpoint"])
      .where("scope", "leader"));
    if (!result.rows || result.rows.length === 0) return null;
    var row = result.rows[0];
    if (Number(row.expiresAt) < Date.now()) return null;
    return {
      nodeId:           row.nodeId,
      leaseExpiresAt:   Number(row.expiresAt),
      fencingToken:     Number(row.fencingToken),
      endpoint:         row.endpoint || null,
    };
  }

  return {
    kind:           "db",
    backendName:    backendName,
    dialect:        dialect,
    ensureSchema:   ensureSchema,
    acquireLease:   acquireLease,
    renewLease:     renewLease,
    releaseLease:   releaseLease,
    currentLeader: currentLeader,
  };
}

module.exports = {
  create: create,
};
