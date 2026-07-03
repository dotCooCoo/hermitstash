// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Default cluster-coordination provider — DB-row-based leader election.
 *
 * Uses an externalDb backend (already configured via b.externalDb.init)
 * as the coordination point. A single row in `_blamejs_leader` holds
 * the current lease; acquireLease is `INSERT ... ON CONFLICT ... DO
 * UPDATE WHERE expiresAt < now() RETURNING ...`, which is atomic in
 * Postgres and SQLite.
 *
 * Fencing tokens: every successful acquire bumps a monotonic integer.
 * Leader-only DB writes include the current token; the audit-tip row's
 * CHECK constraint rejects any incoming token below the stored one,
 * which fences out a partitioned old leader even if its application-
 * layer `_requireLeader()` gate somehow allowed the call through.
 *
 * Dialects: Postgres / SQLite use `INSERT ... ON CONFLICT ... DO
 * UPDATE WHERE ... RETURNING` (atomic acquire-or-steal in one
 * statement). MySQL takes a different shape because its
 * `ON DUPLICATE KEY UPDATE` doesn't support a WHERE clause: each
 * column update is gated by `IF(expiresAt < <nowMs>, VALUES(col), col)`
 * so a non-expired lease is preserved untouched, and the followup
 * SELECT reveals who currently holds the row. Both shapes are
 * row-level atomic at the database — no client-side locking required.
 *
 * Public API:
 *   create({ externalDbBackend, dialect? }) → provider instance
 *
 * Provider instance:
 *   ensureSchema()                                async; idempotent CREATE
 *                                                 TABLE + ALTER for
 *                                                 endpoint migration
 *   acquireLease(nodeId, leaseTtlMs, opts?)       async; → Lease | null.
 *                                                 opts.endpoint persists
 *                                                 in the row for discovery.
 *   renewLease(lease, opts?)                      async; → Lease (throws on
 *                                                 takeover). opts.endpoint
 *                                                 refreshes the row.
 *   releaseLease(lease)                           async; → void
 *   currentLeader()                               async; →
 *                                                 { nodeId, leaseExpiresAt,
 *                                                   fencingToken,
 *                                                   endpoint } | null
 *
 * Lease object shape:
 *   { nodeId, leaseId, acquiredAt, expiresAt, fencingToken, endpoint }
 */
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
    throw _err("INVALID_CONFIG",
      "cluster-provider-db requires { externalDbBackend: <name> }", true);
  }

  // The coordination tables, resolved through frameworkSchema so the
  // configurable framework-table prefix is honored. These names are
  // already `_blamejs_`-prefixed; the resolve is a no-op under the default
  // prefix and namespaces them under a custom one. Resolved here (not at
  // module load) because cluster.js requires this module while
  // framework-schema is mid-load — its tableName export is not yet bound.
  var LEADER_TABLE = frameworkSchema.tableName("_blamejs_leader");          // allow:hand-rolled-sql — single canonical logical-name reference
  var STATE_TABLE  = frameworkSchema.tableName("_blamejs_cluster_state");   // allow:hand-rolled-sql — single canonical logical-name reference
  var backendName = config.externalDbBackend;
  var dialect = (config.dialect || "postgres").toLowerCase();
  if (dialect !== "postgres" && dialect !== "sqlite" && dialect !== "mysql") {
    throw _err("UNSUPPORTED_DIALECT",
      "cluster-provider-db dialect must be 'postgres', 'sqlite', or 'mysql' (got: " + dialect + ")",
      true);
  }

  // The backtick / double-quote identifier-quote char b.sql raw fragments
  // (the upsert fencing increment + conflict guard) must use so a fragment
  // composes into the dialect-final statement with consistent quoting.
  var qchar = dialect === "mysql" ? "`" : "\"";
  function _qraw(col) { return qchar + col + qchar; }

  // Existing-row self-reference inside an upsert's DO UPDATE / conflict guard.
  // Postgres' ON CONFLICT DO UPDATE puts BOTH the target row and the `excluded`
  // proposed row in scope with identical columns, so a bare column is ambiguous
  // (SQLSTATE 42702) — the existing-row reference must be table-qualified.
  // SQLite resolves a bare column to the target (no `excluded` ambiguity); MySQL
  // uses the ON DUPLICATE KEY IF()-fold (no `excluded` table) and b.sql reads the
  // bare column for that fold — so both keep the unqualified form.
  function _selfCol(col) {
    return dialect === "postgres" ? (LEADER_TABLE + "." + _qraw(col)) : _qraw(col);
  }

  // Emit a b.sql builder to dialect-final { sql, params }: b.sql always
  // emits `?` placeholders, so translate them to `$N` for Postgres (the
  // externalDb driver receives the SQL verbatim and never renumbers).
  // SQLite + MySQL both accept `?`.
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

  // Run a b.sql builder against the backend.
  function _run(builder) {
    var e = _emit(builder);
    return _q(e.sql, e.params);
  }

  async function ensureSchema() {
    // Postgres + MySQL: BIGINT for ms-precision timestamps. SQLite:
    // INTEGER (which is wide enough to hold a 64-bit value).
    var intType = dialect === "sqlite" ? "INTEGER" : "BIGINT";
    // MySQL needs explicit lengths on TEXT columns when used as a
    // PRIMARY KEY; VARCHAR(64) covers our scope/nodeId/leaseId values
    // with room to spare. Postgres and SQLite happily PRIMARY-KEY a
    // plain TEXT column.
    var pkText = dialect === "mysql" ? "VARCHAR(64)" : "TEXT";
    var bodyText = dialect === "mysql" ? "VARCHAR(255)" : "TEXT";
    // MySQL doesn't enforce CHECK constraints in some MariaDB / older
    // MySQL versions; the constant-scope invariant is a documentation
    // belt-and-braces — application code only ever writes 'leader' /
    // 'state' so the check is informational. Skip on MySQL to avoid
    // CREATE TABLE failures on installations where CHECK is parsed
    // but then dropped silently (which would cause version drift). The
    // scope CHECK is a static, operator-controlled literal carried as the
    // last column's verbatim constraint (b.sql guards it with allowLiterals
    // since it is not operator input).
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
    // Migration for installs that pre-date the endpoint column. Both
    // Postgres (≥9.6) and SQLite (≥3.35, March 2021) support ADD COLUMN
    // IF NOT EXISTS; MySQL 8.0.29+ does as well. We go through try/catch
    // to keep the path version-agnostic — the only "expected" failure
    // here is "column already exists," which we swallow.
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
    if (!nodeId) throw _err("INVALID_NODE_ID", "nodeId required", true);
    if (typeof leaseTtlMs !== "number" || leaseTtlMs <= 0) {
      throw _err("INVALID_TTL", "leaseTtlMs must be a positive number", true);
    }
    var endpoint = (opts && opts.endpoint) || null;
    var leaseId = generateToken(C.BYTES.bytes(16));
    var nowMs = Date.now();
    var expiresAt = nowMs + leaseTtlMs;

    // One upsert builder serves every dialect. Postgres / SQLite emit
    // `INSERT ... ON CONFLICT (scope) DO UPDATE SET ... WHERE expiresAt < ?
    // RETURNING ...` (atomic acquire-or-steal in one statement). MySQL has
    // no `ON CONFLICT ... WHERE` / `RETURNING`, so b.sql folds the conflict
    // guard into `IF(expiresAt < ?, <new>, <old>)` per column (the still-
    // valid lease is preserved, the expired one overwritten) and emits a
    // readback SELECT keyed on scope='leader'. The fencing-token bump
    // (`fencingToken + 1`) is the only non-proposed-value assignment; every
    // other column re-binds the proposed value (equivalent to EXCLUDED.col /
    // VALUES(col)). guardColumn names expiresAt so the MySQL fold assigns it
    // LAST — IF() evaluates each column against the PRE-update row state, so
    // expiresAt must change after the columns whose guard reads it.
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
      // b.sql's MySQL upsert returns the readback SELECT alongside (the
      // RETURNING-equivalent); run it to learn who currently holds the row.
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
      // Another node won the race (the row reflects their values, not ours).
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
    if (!lease || !lease.leaseId) throw _err("INVALID_LEASE", "lease required", true);
    var nowMs = Date.now();
    var newExpiresAt = nowMs + (lease.expiresAt - lease.acquiredAt);
    // opts.endpoint, when provided, refreshes the stored endpoint so
    // operators who hot-update their config see the discovery row catch
    // up. Default = preserve whatever was stored at acquire time.
    var endpoint = (opts && opts.endpoint !== undefined) ? opts.endpoint : lease.endpoint || null;

    // Match on (nodeId, leaseId) so a takeover is detectable: if our
    // leaseId is no longer in the row, the SELECT-after-UPDATE
    // returns either no row OR a row with a different leaseId, and
    // we throw LEASE_LOST. Don't bump fencingToken on renewal — only
    // on a fresh acquire.
    var renewCols = ["nodeId", "leaseId", "acquiredAt", "expiresAt", "fencingToken", "endpoint"];
    var row;
    if (dialect === "mysql") {
      // MySQL has no RETURNING — UPDATE then read back, with a takeover
      // detected when the read-back row no longer carries our leaseId.
      var rvBuilt = sql().update(LEADER_TABLE, { dialect: dialect })
        .set({ expiresAt: newExpiresAt, endpoint: endpoint })
        .where("scope", "leader").where("nodeId", lease.nodeId).where("leaseId", lease.leaseId)
        .toSql();
      var rv = await _q(clusterStorage().placeholderize(rvBuilt.sql, dialect), rvBuilt.params);
      var affected = rv && (rv.affectedRows || rv.rowCount || 0);
      if (!affected) {
        throw _err("LEASE_LOST",
          "lease for node '" + lease.nodeId + "' was taken over (renewal rejected)",
          false);
      }
      var sel = await _run(sql().select(LEADER_TABLE, { dialect: dialect })
        .columns(renewCols).where("scope", "leader"));
      if (!sel.rows || sel.rows.length === 0 ||
          sel.rows[0].nodeId !== lease.nodeId ||
          sel.rows[0].leaseId !== lease.leaseId) {
        throw _err("LEASE_LOST",
          "lease for node '" + lease.nodeId + "' was taken over after renewal",
          false);
      }
      row = sel.rows[0];
    } else {
      var result = await _run(sql().update(LEADER_TABLE, { dialect: dialect })
        .set({ expiresAt: newExpiresAt, endpoint: endpoint })
        .where("scope", "leader").where("nodeId", lease.nodeId).where("leaseId", lease.leaseId)
        .returning(renewCols));
      if (!result.rows || result.rows.length === 0) {
        throw _err("LEASE_LOST",
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
    // Clear our row so the next acquire wins immediately. Match on
    // leaseId so a takeover-then-release race doesn't clear someone
    // else's lease.
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
