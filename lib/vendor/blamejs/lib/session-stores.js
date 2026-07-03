// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.session.stores
 * @nav        Identity
 * @title      Session stores
 * @order      460
 * @card       Pluggable backends for `b.session`. Default keeps sessions in
 *             the framework's main DB; the `localDbThin` adapter routes
 *             session writes to an isolated SQLite file (typically tmpfs)
 *             so heavy session churn doesn't fight the main DB's WAL
 *             fsync + at-rest re-encryption cycle.
 *
 * @intro
 *   `b.session` writes through a pluggable storage backend. The default
 *   uses `b.clusterStorage`, which dispatches to the framework's main
 *   DB in single-node deployments and to the configured external DB in
 *   cluster mode. Sealed-column sealing, derived-hash lookup, and
 *   audit emission live in `b.session` itself, not in the store —
 *   adapters only need to expose the two primitives `b.session` calls
 *   into:
 *
 *     execute(sql, params)    -> Promise<{ rows: Row[], rowCount: number }>
 *     executeOne(sql, params) -> Promise<Row | null>
 *
 *   `b.session.stores.localDbThin({ file })` ships first-party. It
 *   wraps `b.localDb.thin` with the matching `_blamejs_sessions`
 *   schema (sidHash PRIMARY KEY, userId, userIdHash, data, createdAt,
 *   expiresAt, lastActivity) plus the indexes session-side queries
 *   need (userIdHash for `destroyAllForUser`, expiresAt for
 *   `purgeExpired`). Operators typically point `file` at tmpfs (e.g.
 *   `/dev/shm/blamejs-sessions.db`) so session inserts run RAM-fast
 *   and don't compete with the main DB's encryption-flush cycle.
 *
 *   Wire it once at boot, before the first session call:
 *
 *     var sessionStore = b.session.stores.localDbThin({ file: "/dev/shm/sessions.db" });
 *     b.session.useStore(sessionStore);
 */

var frameworkSchema = require("./framework-schema");
var localDbThin  = require("./local-db-thin");
var sql          = require("./sql");
var validateOpts = require("./validate-opts");

// Logical session-table name — resolved through frameworkSchema.tableName
// so a configured table prefix (b.frameworkSchema.setTablePrefix) is
// honored. This isolated localDbThin file owns its own schema; the name
// must agree with the main-DB / cluster-mode session table b.session
// reads + the sealedFields registry key (db.js registers under the
// logical name).
var SESSION_LOGICAL = "_blamejs_sessions";   // allow:hand-rolled-sql — canonical logical table-name declaration

// b.sql opts for this adapter's schema DDL + every statement b.session
// builds against it. The localDbThin backend is a dedicated node:sqlite
// file (always sqlite, independent of cluster mode — see local-db-thin.js),
// so the dialect is the literal "sqlite": this store NEVER dispatches to an
// external Postgres / MySQL backend. Making the dialect explicit (rather than
// leaning on b.sql's "sqlite" default) keeps the quoting intent documented +
// matches the cluster-routed data-layer files threading
// clusterStorage.dialect() through the same opts seam.
var SQL_OPTS = { dialect: "sqlite" };

// CREATE TABLE + the two session-side indexes (userIdHash for
// destroyAllForUser, expiresAt for purgeExpired), built through b.sql so
// every identifier is quoted by construction and the table name resolves
// through the configurable prefix. DDL binds no values, so each builder
// returns { sql } only; the statements are joined for the adapter's
// schemaSql.
function _sessionSchemaSql() {
  var table = frameworkSchema.tableName(SESSION_LOGICAL);
  var create = sql.createTable(table, [
    { name: "sidHash",      type: "text", primaryKey: true },
    { name: "userId",       type: "text" },
    { name: "userIdHash",   type: "text" },
    { name: "data",         type: "text" },
    { name: "createdAt",    type: "int" },
    { name: "expiresAt",    type: "int" },
    { name: "lastActivity", type: "int" },
  ], SQL_OPTS).sql;
  var idxUser = sql.createIndex(table + "_userIdHash_idx", table, ["userIdHash"], SQL_OPTS).sql;
  var idxExp  = sql.createIndex(table + "_expiresAt_idx", table, ["expiresAt"], SQL_OPTS).sql;
  return [create + ";", idxUser + ";", idxExp + ";"].join("\n");
}

/**
 * @primitive b.session.stores.localDbThin
 * @signature b.session.stores.localDbThin(opts)
 * @since     0.8.61
 * @status    stable
 * @related   b.session.useStore, b.localDb.thin
 *
 * Returns a session-store adapter backed by a dedicated `b.localDb.thin`
 * SQLite file. The adapter exposes `execute(sql, params)` and
 * `executeOne(sql, params)` — the contract `b.session` consumes — so
 * passing it to `b.session.useStore(store)` redirects every session
 * read/write to the isolated file without touching the framework's
 * main DB.
 *
 * Typical use is to point `file` at tmpfs (`/dev/shm/sessions.db` on
 * Linux, an in-memory volume on Windows) so session inserts don't
 * fight the main DB's WAL fsync + encrypted-at-rest re-flush cycle.
 * The adapter creates the schema on first open, so no manual migration
 * is required.
 *
 * @opts
 *   {
 *     file:       string,                    // required absolute path
 *     recovery?:  "refuse" | "rename-and-recreate", // forwards to b.localDb.thin
 *     pragmas?:   object,                    // extra PRAGMA overrides
 *     audit?:     boolean,                   // localDb.thin audit emission
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var store = b.session.stores.localDbThin({ file: "/dev/shm/sessions.db" });
 *   b.session.useStore(store);
 *   // From here on every b.session.* call routes through the tmpfs file.
 */
function localDbThinStore(opts) {
  validateOpts.requireObject(opts, "session.stores.localDbThin", TypeError, "session-stores/bad-opts");
  validateOpts.requireNonEmptyString(opts.file, "session.stores.localDbThin: opts.file",
    TypeError, "session-stores/bad-file");
  // node:sqlite is sync — open the handle eagerly so the first
  // session call doesn't pay an open + integrity_check on the
  // request hot path. Recovery defaults to "refuse" so a corrupt
  // session file surfaces as a startup error rather than silently
  // logging out every user; operators wanting clear-on-corrupt opt in.
  var handle = localDbThin.thin({
    file:       opts.file,
    schemaSql:  _sessionSchemaSql(),
    recovery:   opts.recovery || "refuse",
    pragmas:    opts.pragmas,
    audit:      opts.audit !== false,
  });

  // Wrap the synchronous prepare/run/all paths in resolved Promises so
  // the b.session call sites — all `await store.execute(...)` — see the
  // same shape as the cluster-storage default.
  function execute(sql, params) {
    params = params || [];
    var stmt = handle.prepare(sql);
    if (/^\s*SELECT\b/i.test(sql) || /\bRETURNING\b/i.test(sql)) {
      var rows = stmt.all.apply(stmt, params);
      return Promise.resolve({ rows: rows, rowCount: rows.length });
    }
    var info = stmt.run.apply(stmt, params);
    return Promise.resolve({ rows: [], rowCount: info.changes });
  }

  function executeOne(sql, params) {
    return execute(sql, params).then(function (r) {
      return r.rows.length > 0 ? r.rows[0] : null;
    });
  }

  return {
    execute:     execute,
    executeOne:  executeOne,
    close:       function () { try { handle.close(); } catch (_e) { /* best-effort */ } },
    file:        handle.file,
  };
}

module.exports = {
  localDbThin: localDbThinStore,
};
