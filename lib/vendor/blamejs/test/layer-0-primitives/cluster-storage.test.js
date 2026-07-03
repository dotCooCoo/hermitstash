// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * cluster-storage — cluster-aware framework-state SQL dispatch.
 *
 * Focus: the transaction() primitive (added v0.13.38) — atomic commit,
 * rollback-on-throw, and single-node serialization so a concurrent
 * execute() can't interleave a statement into an open transaction on the
 * shared SQLite connection.
 *
 * Run standalone: `node test/layer-0-primitives/cluster-storage.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var fs      = require("node:fs");
var os      = require("node:os");
var path    = require("node:path");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

var SCHEMA = [{ name: "cs_tx_t", columns: { k: "TEXT PRIMARY KEY", v: "INTEGER" } }];

function testSurface() {
  check("clusterStorage namespace",      typeof b.clusterStorage === "object");
  check("clusterStorage.transaction fn", typeof b.clusterStorage.transaction === "function");
}

async function testTransactionCommits() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cs-tx-commit-"));
  try {
    await setupTestDb(tmp, SCHEMA);
    var cs = b.clusterStorage;
    await cs.transaction(async function (tx) {
      await tx.execute("INSERT INTO cs_tx_t (k, v) VALUES (?, ?)", ["a", 1]);
      await tx.execute("INSERT INTO cs_tx_t (k, v) VALUES (?, ?)", ["b", 2]);
      var seen = await tx.executeOne("SELECT COUNT(*) AS n FROM cs_tx_t");
      check("tx: rows visible inside the transaction", seen.n === 2);
    });
    var after = await cs.executeOne("SELECT COUNT(*) AS n FROM cs_tx_t");
    check("tx: commit persisted both rows", after.n === 2);
  } finally {
    b.db._resetForTest();
    await teardownTestDb(tmp);
  }
}

async function testTransactionRollsBackOnThrow() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cs-tx-rollback-"));
  try {
    await setupTestDb(tmp, SCHEMA);
    var cs = b.clusterStorage;
    await cs.execute("INSERT INTO cs_tx_t (k, v) VALUES (?, ?)", ["keep", 1]);
    var threw = null;
    try {
      await cs.transaction(async function (tx) {
        await tx.execute("INSERT INTO cs_tx_t (k, v) VALUES (?, ?)", ["gone", 2]);
        throw new Error("boom");
      });
    } catch (e) { threw = e; }
    check("tx: throw propagates to caller",       threw && threw.message === "boom");
    var rows = await cs.executeAll("SELECT k FROM cs_tx_t ORDER BY k");
    check("tx: rolled-back row absent",            rows.length === 1 && rows[0].k === "keep");
  } finally {
    b.db._resetForTest();
    await teardownTestDb(tmp);
  }
}

async function testTransactionSerializesExecute() {
  // A concurrent execute() must NOT interleave a statement into an open
  // single-node transaction on the shared connection — it waits until the
  // transaction commits.
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cs-tx-serial-"));
  try {
    await setupTestDb(tmp, SCHEMA);
    var cs = b.clusterStorage;
    var order = [];
    var txP = cs.transaction(async function (tx) {
      order.push("tx-begin");
      await tx.execute("INSERT INTO cs_tx_t (k, v) VALUES (?, ?)", ["d", 4]);
      await helpers.passiveObserve(40, "cluster-storage tx: hold the transaction open");
      order.push("tx-end");
    });
    var exP = cs.execute("INSERT INTO cs_tx_t (k, v) VALUES (?, ?)", ["e", 5])
      .then(function () { order.push("exec-done"); });
    await Promise.all([txP, exP]);
    check("tx: concurrent execute waited for commit (no mid-tx interleave)",
          order.join(",") === "tx-begin,tx-end,exec-done");
    var n = await cs.executeOne("SELECT COUNT(*) AS n FROM cs_tx_t");
    check("tx: both writes landed", n.n === 2);
  } finally {
    b.db._resetForTest();
    await teardownTestDb(tmp);
  }
}

async function testTransactionRejectsBadArg() {
  var threw = null;
  try { await b.clusterStorage.transaction("not-a-fn"); } catch (e) { threw = e; }
  check("tx: non-function arg rejected", threw && threw.code === "cluster-storage/bad-arg");
}

// A WITH (CTE) read must reach the caller's row set. The local-exec method
// choice keyed on a leading "SELECT" mis-routed "WITH c AS (...) SELECT ..." to
// .run(), which on node:sqlite returns only a changes count and SILENTLY DROPS
// the rows — the caller saw an empty result. The classifier now resolves the
// CTE's effective verb so the read uses .all().
async function testCteReadReturnsRows() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cs-cte-read-"));
  try {
    await setupTestDb(tmp, SCHEMA);
    var cs = b.clusterStorage;
    await cs.execute("INSERT INTO cs_tx_t (k, v) VALUES (?, ?)", ["a", 1]);
    await cs.execute("INSERT INTO cs_tx_t (k, v) VALUES (?, ?)", ["b", 2]);

    // Plain SELECT control — already worked.
    var plain = await cs.execute("SELECT k, v FROM cs_tx_t ORDER BY k");
    check("plain SELECT returns both rows", plain.rows.length === 2);

    // CTE read — the regression. Was: rows.length === 0 (rows dropped by .run()).
    var cte = await cs.execute(
      "WITH picked AS (SELECT k, v FROM cs_tx_t WHERE v >= ?) SELECT k, v FROM picked ORDER BY k", [1]);
    check("WITH (CTE) read returns rows (not silently dropped)", cte.rows.length === 2);
    check("WITH (CTE) read returns the actual data", cte.rows[0].k === "a" && cte.rows[1].k === "b");

    // executeOne over a CTE read resolves the single row too.
    var one = await cs.executeOne(
      "WITH t AS (SELECT COUNT(*) AS n FROM cs_tx_t) SELECT n FROM t");
    check("executeOne over a CTE read resolves the row", one && one.n === 2);

    // A WITH (CTE) write still applies its changes (not mis-read as a query).
    await cs.execute(
      "WITH src AS (SELECT 'c' AS k, 3 AS v) INSERT INTO cs_tx_t (k, v) SELECT k, v FROM src");
    var after = await cs.executeOne("SELECT COUNT(*) AS n FROM cs_tx_t");
    check("WITH (CTE) write persisted its row", after.n === 3);
  } finally {
    b.db._resetForTest();
    await teardownTestDb(tmp);
  }
}

async function run() {
  testSurface();
  await testTransactionCommits();
  await testTransactionRollsBackOnThrow();
  await testTransactionSerializesExecute();
  await testTransactionRejectsBadArg();
  await testCteReadReturnsRows();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[cluster-storage] OK — " + helpers.getChecks() + " checks passed"); },
    // Rethrow rather than console.error(e.stack): this test seeds a vault
    // passphrase via setupTestDb, and logging the error object trips
    // CodeQL's clear-text-logging taint (passphrase -> error -> log). The
    // rethrow lets Node print the uncaught error + stack itself and exit
    // non-zero, with no logging sink for the taint to reach.
    function (e) { process.exitCode = 1; throw e; }
  );
}
