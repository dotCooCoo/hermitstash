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
var { ClusterProviderError } = require("./framework-error");

var _err = ClusterProviderError.factory;

function create(config) {
  if (!config || !config.externalDbBackend) {
    throw _err("INVALID_CONFIG",
      "cluster-provider-db requires { externalDbBackend: <name> }", true);
  }
  var backendName = config.externalDbBackend;
  var dialect = (config.dialect || "postgres").toLowerCase();
  if (dialect !== "postgres" && dialect !== "sqlite" && dialect !== "mysql") {
    throw _err("UNSUPPORTED_DIALECT",
      "cluster-provider-db dialect must be 'postgres', 'sqlite', or 'mysql' (got: " + dialect + ")",
      true);
  }

  // Postgres + SQLite use $1/$2 placeholders; MySQL uses ?. Keeping a
  // single helper means the SQL builder doesn't have to care.
  function _placeholder(n) {
    return dialect === "mysql" ? "?" : "$" + n;
  }

  function _q(sql, params) {
    return externalDb.query(sql, params || [], { backend: backendName });
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
    // but then dropped silently (which would cause version drift).
    var leaderCheck = dialect === "mysql" ? "" : ", CHECK (scope = 'leader')";
    var stateCheck  = dialect === "mysql" ? "" : ", CHECK (scope = 'state')";

    await _q(
      "CREATE TABLE IF NOT EXISTS _blamejs_leader (" +
      "  scope         " + pkText + " PRIMARY KEY," +
      "  nodeId        " + bodyText + " NOT NULL," +
      "  leaseId       " + bodyText + " NOT NULL," +
      "  acquiredAt    " + intType + " NOT NULL," +
      "  expiresAt     " + intType + " NOT NULL," +
      "  fencingToken  " + intType + " NOT NULL," +
      "  endpoint      " + bodyText + leaderCheck +
      ")"
    );
    // Migration for installs that pre-date the endpoint column. Both
    // Postgres (≥9.6) and SQLite (≥3.35, March 2021) support ADD COLUMN
    // IF NOT EXISTS; MySQL 8.0.29+ does as well. We go through try/catch
    // to keep the path version-agnostic — the only "expected" failure
    // here is "column already exists," which we swallow.
    try {
      await _q("ALTER TABLE _blamejs_leader ADD COLUMN endpoint " + bodyText);
    } catch (_e) { /* column already exists — fine */ }

    await _q(
      "CREATE TABLE IF NOT EXISTS _blamejs_cluster_state (" +
      "  scope           " + pkText + " PRIMARY KEY," +
      "  vaultKeyFp      " + bodyText + " NOT NULL," +
      "  recordedAt      " + intType + " NOT NULL," +
      "  recordedByNode  " + bodyText + " NOT NULL" + stateCheck +
      ")"
    );
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

    var row;
    if (dialect === "mysql") {
      // MySQL has no `ON CONFLICT ... DO UPDATE WHERE` and no
      // `RETURNING`. Atomicity comes from `INSERT ... ON DUPLICATE
      // KEY UPDATE` evaluated as one statement; the WHERE-clause
      // semantics are implemented per-column with `IF(expiresAt <
      // nowMs, VALUES(col), col)` so a still-valid lease is preserved
      // and an expired one is overwritten. The follow-up SELECT
      // reveals who currently holds the row — same as Postgres'
      // RETURNING but as a separate statement.
      var insertSql =
        "INSERT INTO _blamejs_leader " +
        "  (scope, nodeId, leaseId, acquiredAt, expiresAt, fencingToken, endpoint) " +
        "VALUES " +
        "  ('leader', ?, ?, ?, ?, 1, ?) " +
        "ON DUPLICATE KEY UPDATE " +
        "  nodeId       = IF(expiresAt < ?, VALUES(nodeId), nodeId)," +
        "  leaseId      = IF(expiresAt < ?, VALUES(leaseId), leaseId)," +
        "  acquiredAt   = IF(expiresAt < ?, VALUES(acquiredAt), acquiredAt)," +
        "  fencingToken = IF(expiresAt < ?, fencingToken + 1, fencingToken)," +
        "  endpoint     = IF(expiresAt < ?, VALUES(endpoint), endpoint)," +
        // expiresAt MUST be the last assignment — IF() evaluates each
        // column against the row state BEFORE that column's update is
        // applied, so checking expiresAt for the other columns first
        // and overwriting it last keeps the predicate consistent.
        "  expiresAt    = IF(expiresAt < ?, VALUES(expiresAt), expiresAt)";
      await _q(insertSql, [
        nodeId, leaseId, nowMs, expiresAt, endpoint,
        nowMs, nowMs, nowMs, nowMs, nowMs, nowMs,
      ]);
      var sel = await _q(
        "SELECT nodeId, leaseId, acquiredAt, expiresAt, fencingToken, endpoint " +
        "FROM _blamejs_leader WHERE scope = 'leader'"
      );
      if (!sel.rows || sel.rows.length === 0) return null;
      row = sel.rows[0];
    } else {
      // Postgres / SQLite — single-statement RETURNING.
      var sql =
        "INSERT INTO _blamejs_leader " +
        "  (scope, nodeId, leaseId, acquiredAt, expiresAt, fencingToken, endpoint) " +
        "VALUES " +
        "  ('leader', " + _placeholder(1) + ", " + _placeholder(2) + ", " +
        "   " + _placeholder(3) + ", " + _placeholder(4) + ", 1, " + _placeholder(5) + ") " +
        "ON CONFLICT (scope) DO UPDATE SET " +
        "  nodeId       = EXCLUDED.nodeId," +
        "  leaseId      = EXCLUDED.leaseId," +
        "  acquiredAt   = EXCLUDED.acquiredAt," +
        "  expiresAt    = EXCLUDED.expiresAt," +
        "  fencingToken = _blamejs_leader.fencingToken + 1," +
        "  endpoint     = EXCLUDED.endpoint " +
        "WHERE _blamejs_leader.expiresAt < " + _placeholder(6) + " " +
        "RETURNING nodeId, leaseId, acquiredAt, expiresAt, fencingToken, endpoint";
      var result = await _q(sql, [nodeId, leaseId, nowMs, expiresAt, endpoint, nowMs]);
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
    var row;
    if (dialect === "mysql") {
      var rv = await _q(
        "UPDATE _blamejs_leader SET " +
        "  expiresAt = ?, endpoint = ? " +
        "WHERE scope = 'leader' AND nodeId = ? AND leaseId = ?",
        [newExpiresAt, endpoint, lease.nodeId, lease.leaseId]
      );
      var affected = rv && (rv.affectedRows || rv.rowCount || 0);
      if (!affected) {
        throw _err("LEASE_LOST",
          "lease for node '" + lease.nodeId + "' was taken over (renewal rejected)",
          false);
      }
      var sel = await _q(
        "SELECT nodeId, leaseId, acquiredAt, expiresAt, fencingToken, endpoint " +
        "FROM _blamejs_leader WHERE scope = 'leader'"
      );
      if (!sel.rows || sel.rows.length === 0 ||
          sel.rows[0].nodeId !== lease.nodeId ||
          sel.rows[0].leaseId !== lease.leaseId) {
        throw _err("LEASE_LOST",
          "lease for node '" + lease.nodeId + "' was taken over after renewal",
          false);
      }
      row = sel.rows[0];
    } else {
      var sql =
        "UPDATE _blamejs_leader SET " +
        "  expiresAt = " + _placeholder(1) + "," +
        "  endpoint  = " + _placeholder(2) + " " +
        "WHERE scope = 'leader' AND nodeId = " + _placeholder(3) +
        "  AND leaseId = " + _placeholder(4) + " " +
        "RETURNING nodeId, leaseId, acquiredAt, expiresAt, fencingToken, endpoint";
      var result = await _q(sql, [newExpiresAt, endpoint, lease.nodeId, lease.leaseId]);
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
    var sql =
      "UPDATE _blamejs_leader SET " +
      "  expiresAt = 0 " +
      "WHERE scope = 'leader' AND nodeId = " + _placeholder(1) +
      "  AND leaseId = " + _placeholder(2);
    await _q(sql, [lease.nodeId, lease.leaseId]);
  }

  async function currentLeader() {
    var result = await _q(
      "SELECT nodeId, expiresAt, fencingToken, endpoint FROM _blamejs_leader " +
      "WHERE scope = 'leader'"
    );
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
