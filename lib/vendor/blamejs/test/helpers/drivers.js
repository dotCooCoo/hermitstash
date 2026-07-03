// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Test driver fakes — in-memory + sqlite-backed shapes that match the
 * external-db dispatcher contract. Tests verify dispatcher logic
 * (pooling, retry, classification, transaction, audit) without
 * standing up a real Postgres.
 */

function _makeFakeDriver(opts) {
  opts = opts || {};
  var connectCount = 0;
  var queryCount = 0;
  var store = {};
  var failNextN = opts.failNextN || 0;
  var failPermanent = opts.failPermanent || false;

  return {
    connect: async function () {
      connectCount += 1;
      return { id: "client-" + connectCount, store: store };
    },
    query: async function (client, sql, params) {
      queryCount += 1;
      if (failNextN > 0) {
        failNextN -= 1;
        var e = new Error("simulated failure");
        e.code = failPermanent ? "PERMANENT" : "ECONNRESET";
        e.permanent = failPermanent;
        throw e;
      }
      if (/^SELECT 1$/i.test(sql)) return { rows: [{ "?column?": 1 }], rowCount: 1 };
      if (/^BEGIN/i.test(sql) || /^COMMIT/i.test(sql) || /^ROLLBACK/i.test(sql)) {
        return { rows: [], rowCount: 0 };
      }
      var insertMatch = sql.match(/^INSERT INTO kv \(id, value\) VALUES \(\$1, \$2\)/i);
      if (insertMatch) {
        client.store[params[0]] = params[1];
        return { rows: [], rowCount: 1 };
      }
      var selectMatch = sql.match(/^SELECT id, value FROM kv WHERE id = \$1/i);
      if (selectMatch) {
        var v = client.store[params[0]];
        if (v === undefined) return { rows: [], rowCount: 0 };
        return { rows: [{ id: params[0], value: v }], rowCount: 1 };
      }
      var deleteMatch = sql.match(/^DELETE FROM kv WHERE id = \$1/i);
      if (deleteMatch) {
        var existed = params[0] in client.store;
        delete client.store[params[0]];
        return { rows: [], rowCount: existed ? 1 : 0 };
      }
      throw new Error("fake driver: unknown SQL: " + sql);
    },
    close: async function () { /* no-op */ },
    ping:  async function () { return true; },
    getStats: function () { return { connectCount: connectCount, queryCount: queryCount }; },
  };
}

function _makeSqliteDriver(dbPath) {
  var sqlite = require("node:sqlite");
  var dbHandle = new sqlite.DatabaseSync(dbPath);
  return {
    connect: async function () { return { db: dbHandle }; },
    query: async function (client, sql, params) {
      params = params || [];
      // Cluster provider's prepared SQL uses $N placeholders; SQLite
      // takes ?-placeholders. Translate.
      var translated = sql.replace(/\$([0-9]+)/g, "?");
      var stmt = client.db.prepare(translated);
      var trimmed = sql.trim().toUpperCase();
      if (trimmed.startsWith("SELECT") || /\sRETURNING\s/i.test(sql)) {
        var rows = stmt.all.apply(stmt, params);
        return { rows: rows, rowCount: rows.length };
      }
      var info = stmt.run.apply(stmt, params);
      return { rows: [], rowCount: info.changes };
    },
    close: async function () { /* shared handle, closed by test teardown */ },
    _close: function () { try { dbHandle.close(); } catch (_e) {} },
  };
}

/**
 * Fake MySQL driver — emulates just enough of MySQL's wire semantics
 * to exercise lib/cluster-provider-db's MySQL dialect path:
 *
 *   - `?` placeholders (not `$1..$N`)
 *   - Affected-row count surfaces as `affectedRows` (mysql2 style)
 *   - `INSERT ... ON DUPLICATE KEY UPDATE` with `IF(<predicate>, x, y)`
 *     evaluates the predicate against existing-row state and copies
 *     the appropriate column.
 *   - `SELECT ... FROM _blamejs_leader WHERE scope = 'leader'` returns
 *     the current row (or empty if absent).
 *
 * The store is a single object keyed by row primary key; the cluster
 * provider only ever touches the `_blamejs_leader` and
 * `_blamejs_cluster_state` tables, both of which have a one-row
 * 'leader' / 'state' singleton.
 */
function _makeFakeMysqlDriver() {
  var rows = { _blamejs_leader: null, _blamejs_cluster_state: null };
  var loggedSql = [];
  var clientCounter = 0;
  return {
    connect: async function () { clientCounter += 1; return { id: clientCounter }; },
    query: async function (_client, sql, params) {
      params = params || [];
      loggedSql.push({ sql: sql, params: params.slice() });
      var t = sql.trim();
      // CREATE / ALTER — accept silently.
      if (/^CREATE TABLE IF NOT EXISTS/i.test(t)) return { rows: [], affectedRows: 0 };
      if (/^ALTER TABLE/i.test(t))                return { rows: [], affectedRows: 0 };

      // INSERT ... ON DUPLICATE KEY UPDATE — only modeled for
      // _blamejs_leader since that's the only place the provider uses
      // it. Existing-row predicate is `expiresAt < ?` for every IF().
      var inLeader = /INSERT INTO _blamejs_leader/i.test(t) &&
                     /ON DUPLICATE KEY UPDATE/i.test(t);
      if (inLeader) {
        // The provider composes this upsert through b.sql, which binds the
        // VALUES list (scope first) then the ON DUPLICATE KEY UPDATE IF()
        // params. Layout:
        //   VALUES: [0]=scope 'leader', [1]=nodeId, [2]=leaseId,
        //           [3]=acquiredAt, [4]=expiresAt, [5]=fencingToken(1),
        //           [6]=endpoint
        //   then the IF(expiresAt < ?, <new>, <old>) guards + proposed
        //   values; every guard binds nowMs, the first at [7].
        var newRow = {
          scope: "leader", nodeId: params[1], leaseId: params[2],
          acquiredAt: params[3], expiresAt: params[4], endpoint: params[6],
          fencingToken: 1,
        };
        var existing = rows._blamejs_leader;
        if (!existing) {
          rows._blamejs_leader = newRow;
        } else {
          var nowPredicate = params[7];
          if (existing.expiresAt < nowPredicate) {
            // Steal — IF() → use VALUES(*) for non-fencingToken cols,
            // bump fencingToken.
            existing.nodeId       = newRow.nodeId;
            existing.leaseId      = newRow.leaseId;
            existing.acquiredAt   = newRow.acquiredAt;
            existing.endpoint     = newRow.endpoint;
            existing.fencingToken = existing.fencingToken + 1;
            existing.expiresAt    = newRow.expiresAt;
          }
          // else: row preserved untouched.
        }
        return { rows: [], affectedRows: 1 };
      }

      // UPDATE _blamejs_leader SET `expiresAt` = ?, `endpoint` = ?
      // WHERE `scope` = ? AND `nodeId` = ? AND `leaseId` = ?  (renew).
      // The provider composes this through b.sql: identifiers are
      // backtick-quoted and the scope value binds (params[2]='leader')
      // ahead of nodeId (params[3]) / leaseId (params[4]).
      var renewMatch = /^UPDATE _blamejs_leader SET[\s\S]*`?expiresAt`? = \?[\s\S]*`?endpoint`? = \?[\s\S]*WHERE `?scope`? = \? AND `?nodeId`? = \? AND `?leaseId`? = \?/i.test(t);
      if (renewMatch) {
        var r = rows._blamejs_leader;
        if (r && r.nodeId === params[3] && r.leaseId === params[4]) {
          r.expiresAt = params[0];
          r.endpoint  = params[1];
          return { rows: [], affectedRows: 1 };
        }
        return { rows: [], affectedRows: 0 };
      }

      // UPDATE _blamejs_leader SET `expiresAt` = ? WHERE ... (release).
      // b.sql binds expiresAt=0 (params[0]) + scope (params[1]) + nodeId
      // (params[2]) + leaseId (params[3]).
      var releaseMatch = /^UPDATE _blamejs_leader SET[\s\S]*`?expiresAt`? = \?\s+WHERE/i.test(t);
      if (releaseMatch) {
        var rr = rows._blamejs_leader;
        if (rr && rr.nodeId === params[2] && rr.leaseId === params[3]) {
          rr.expiresAt = params[0];
        }
        return { rows: [], affectedRows: 1 };
      }

      // SELECT ... FROM _blamejs_leader WHERE `scope` = ?  (b.sql binds the
      // scope value rather than inlining the 'leader' literal).
      if (/^SELECT[\s\S]+FROM _blamejs_leader WHERE `?scope`? = (?:\?|'leader')/i.test(t)) {
        var rl = rows._blamejs_leader;
        if (!rl) return { rows: [], affectedRows: 0 };
        return { rows: [Object.assign({}, rl)], affectedRows: 1 };
      }

      throw new Error("fake mysql driver: unknown SQL: " + t);
    },
    close: async function () { /* no-op */ },
    _loggedSql: function () { return loggedSql; },
    _state: function () { return rows; },
  };
}

function _makeFakeServiceAccount() {
  var nodeCrypto = require("crypto");
  var pair = nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return {
    type:           "service_account",
    project_id:     "test-project",
    client_email:   "test-sa@test-project.iam.gserviceaccount.com",
    private_key:    pair.privateKey,
    private_key_id: "test-key-id-001",
  };
}

module.exports = {
  _makeFakeDriver:         _makeFakeDriver,
  _makeSqliteDriver:       _makeSqliteDriver,
  _makeFakeMysqlDriver:    _makeFakeMysqlDriver,
  _makeFakeServiceAccount: _makeFakeServiceAccount,
};
