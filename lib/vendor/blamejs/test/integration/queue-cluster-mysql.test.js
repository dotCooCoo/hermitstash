// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Live MySQL coverage for the queue-local CLUSTER lease path — the dialect-
 * aware enqueue + the transactional FOR UPDATE SKIP LOCKED claim that only
 * runs when the queue's store is a postgres/mysql cluster backend. Host smoke
 * exercises ONLY the sqlite single-statement RETURNING path; nothing proved
 * the b.sql the cluster path emits is MySQL-valid until this file. The three
 * MySQL-specific traps the lease reshape exists to clear:
 *
 *   - identifier quoting: b.sql must emit BACKTICK-quoted camelCase columns
 *     (`queueName`, `availableAt`, …), not the double-quotes MySQL reads as
 *     string literals (the pre-reshape builders defaulted to the sqlite
 *     dialect → "queueName" → ERROR 1064 on the very first enqueue);
 *   - no RETURNING: MySQL rejects `UPDATE … RETURNING`, so the lease re-SELECTs
 *     the claimed rows by their locked ids instead;
 *   - no self-referencing subquery UPDATE: the guarded UPDATE binds a LITERAL
 *     id list (`_id IN (?, ?)`) rather than updating a table named in its own
 *     subquery (MySQL ERROR 1093).
 *
 * Driven through the REAL queue-local consumer surface (the backend factory
 * b.queue.init wires): enqueue / lease / complete / fail / sweepExpired /
 * dlqList against a real MySQL 8 server. RED before the dialect reshape (the
 * first enqueue throws 1064); GREEN after.
 *
 * HARNESS LIMIT — read before extending: the "driver" is the stateless
 * docker-exec mysql shim shared with data-layer-cluster-mysql (every query()
 * is a fresh `mysql -e`, so BEGIN / the body / COMMIT and FOR UPDATE SKIP
 * LOCKED each land on a SEPARATE connection — the transaction is non-atomic
 * and the row lock does not hold). This file therefore validates DIALECT
 * CORRECTNESS of the cluster lease SQL, NOT lock-based double-lease
 * prevention; the latter is covered by the sqlite single-writer path and by
 * outbox._claimBatch (the canonical competing-consumer claim this mirrors)
 * against a pooled driver. Do not add a concurrent-double-lease assertion
 * here — it cannot be made meaningful on the stateless shim.
 *
 * RUN: node scripts/test-integration.js --skip-service-check queue-cluster-mysql
 */

var execFileSync = require("node:child_process").execFileSync;
var fs       = require("node:fs");
var os       = require("node:os");
var path     = require("node:path");
var helpers  = require("../helpers");
var check    = helpers.check;
var services = require("../helpers/services");
var b = require("../../");
var queueLocal = require("../../lib/queue-local");

var CONTAINER = "blamejs-test-mysql";
var DB_NAME   = "blamejs_queue_cluster_test";

// ---- one-shot mysql (setup / teardown / out-of-band assertions) ----
function _mysqlRoot(sql, dbName) {
  var args = ["exec", "-i", CONTAINER, "mysql", "-uroot", "-pblamejs_test_root", "--batch", "--raw"];
  if (dbName) args.push(dbName);
  args.push("-e", sql);
  return execFileSync("docker", args, { stdio: ["pipe", "pipe", "pipe"] }).toString("utf8");
}

// ---- docker-exec mysql driver (faithful to a text-protocol driver) ----
// Identical contract to data-layer-cluster-mysql's shim: ROW_COUNT() is read
// in the SAME invocation as the DML so affectedRows is connection-consistent.
function _makeDockerMysqlDriver() {
  return {
    connect: async function () { return { id: 1 }; },
    query: async function (_client, sql, params) {
      params = params || [];
      var bound = _bindParams(sql, params);
      var t = bound.trim();
      if (/^(CREATE|ALTER|INSERT|UPDATE|DELETE|DROP|REPLACE|TRUNCATE|BEGIN|START|COMMIT|ROLLBACK)\b/i.test(t)) {
        // Transaction-control statements (BEGIN/COMMIT/ROLLBACK) are no-ops on
        // the stateless shim — run them but don't read ROW_COUNT().
        if (/^(BEGIN|START|COMMIT|ROLLBACK)\b/i.test(t)) { _exec(bound.replace(/;\s*$/, "")); return { rows: [], affectedRows: 0, rowCount: 0 }; }
        var stmt = bound.replace(/;\s*$/, "");
        var ar = _exec(stmt + "; SELECT ROW_COUNT() AS n");
        var parsed = _parseBatch(ar);
        var n = parsed.rows[0] ? Number(parsed.rows[0].n) : 0;
        if (!isFinite(n) || n < 0) n = 0;
        return { rows: [], affectedRows: n, rowCount: n };
      }
      var out = _exec(bound);
      var parsedSel = _parseBatch(out);
      return { rows: parsedSel.rows, rowCount: parsedSel.rows.length };
    },
    close: async function () { /* no-op */ },
    dialect: "mysql",
  };
}

function _exec(sql) {
  try {
    return execFileSync("docker",
      ["exec", "-i", CONTAINER, "mysql", "-uroot", "-pblamejs_test_root",
       "--batch", "--raw", DB_NAME, "-e", sql],
      { stdio: ["pipe", "pipe", "pipe"] }).toString("utf8");
  } catch (e) {
    var msg = e.stderr ? e.stderr.toString("utf8") : (e.message || String(e));
    var errLine = (msg.split(/\r?\n/).filter(function (l) {
      return /ERROR \d+/.test(l);
    })[0]) || msg.trim();
    var err = new Error(errLine.trim());
    var m = /ERROR (\d+) \(([0-9A-Za-z]{5})\)/.exec(msg);
    if (m) { err.errno = Number(m[1]); err.code = m[2]; err.sqlState = m[2]; }
    throw err;
  }
}

function _bindParams(sql, params) {
  var i = 0;
  return sql.replace(/\?/g, function () {
    if (i >= params.length) throw new Error("placeholder/param count mismatch");
    var p = params[i++];
    if (p === null || p === undefined) return "NULL";
    if (typeof p === "number") return String(p);
    if (typeof p === "boolean") return p ? "1" : "0";
    return "'" + String(p).replace(/\\/g, "\\\\").replace(/'/g, "''") + "'";
  });
}

function _parseBatch(out) {
  var lines = out.split(/\r?\n/).filter(function (l) { return l.length > 0; });
  if (lines.length < 1) return { rows: [] };
  var headers = lines[0].split("\t");
  var rows = [];
  for (var i = 1; i < lines.length; i++) {
    var cells = lines[i].split("\t");
    var row = {};
    for (var j = 0; j < headers.length; j++) {
      var v = cells[j];
      row[headers[j]] = (v === "NULL" || v === undefined) ? null : v;
    }
    rows.push(row);
  }
  return { rows: rows };
}

function _countMysql(table, whereClause) {
  var sql = "SELECT count(*) AS n FROM " + table +
    (whereClause ? " WHERE " + whereClause : "");
  var out = _mysqlRoot(sql, DB_NAME);
  var parsed = _parseBatch(out);
  return parsed.rows[0] ? Number(parsed.rows[0].n) : 0;
}

// One out-of-band column read for a single job row.
function _jobCol(jobId, col) {
  var out = _mysqlRoot(
    "SELECT `" + col + "` AS v FROM `_blamejs_jobs` WHERE `_id` = '" +
      jobId.replace(/'/g, "''") + "'", DB_NAME);
  var parsed = _parseBatch(out);
  return parsed.rows[0] ? parsed.rows[0].v : null;
}

var OWNED_TABLES = [
  "_blamejs_jobs",
  "_blamejs_cluster_state",
  "_blamejs_leader",
  "_blamejs_audit_tip",
  "_blamejs_consent_tip",
];

function _ensureTipTables() {
  _mysqlRoot(
    "CREATE TABLE IF NOT EXISTS `_blamejs_audit_tip` (" +
    "  `scope` VARCHAR(64) PRIMARY KEY," +
    "  `atMonotonicCounter` BIGINT NOT NULL DEFAULT 0," +
    "  `rowHash` TEXT," +
    "  `signedAt` TEXT," +
    "  `fencingToken` BIGINT NOT NULL DEFAULT 0)", DB_NAME);
  _mysqlRoot(
    "CREATE TABLE IF NOT EXISTS `_blamejs_consent_tip` (" +
    "  `scope` VARCHAR(64) PRIMARY KEY," +
    "  `atMonotonicCounter` BIGINT NOT NULL DEFAULT 0," +
    "  `rowHash` TEXT," +
    "  `signedAt` TEXT," +
    "  `fencingToken` BIGINT NOT NULL DEFAULT 0)", DB_NAME);
}

// The jobs table, backtick-quoted camelCase columns matching JOB_COLS in
// queue-local. BIGINT holds the unix-ms timestamps AND the flow-blocked
// sentinel (Number.MAX_SAFE_INTEGER = 9.007e15, well inside BIGINT range).
function _createJobsTable() {
  _mysqlRoot("DROP TABLE IF EXISTS `_blamejs_jobs`", DB_NAME);
  _mysqlRoot(
    "CREATE TABLE `_blamejs_jobs` (" +
    "  `_id`            VARCHAR(64) PRIMARY KEY," +
    "  `queueName`      VARCHAR(255) NOT NULL," +
    "  `payload`        LONGTEXT," +
    "  `status`         VARCHAR(32) NOT NULL," +
    "  `enqueuedAt`     BIGINT NOT NULL," +
    "  `availableAt`    BIGINT NOT NULL," +
    "  `leasedAt`       BIGINT," +
    "  `leaseExpiresAt` BIGINT," +
    "  `attempts`       BIGINT NOT NULL DEFAULT 0," +
    "  `maxAttempts`    BIGINT NOT NULL DEFAULT 5," +
    "  `lastError`      LONGTEXT," +
    "  `finishedAt`     BIGINT," +
    "  `traceId`        VARCHAR(255)," +
    "  `classification` VARCHAR(255)," +
    "  `priority`       BIGINT NOT NULL DEFAULT 0," +
    "  `repeatCron`     VARCHAR(255)," +
    "  `repeatTimezone` VARCHAR(255)," +
    "  `flowId`         VARCHAR(255)," +
    "  `flowChildName`  VARCHAR(255)," +
    "  `dependsOn`      LONGTEXT," +
    "  KEY `lease_idx` (`queueName`, `status`, `availableAt`)" +
    ")", DB_NAME);
}

function _dropOwned() {
  for (var i = 0; i < OWNED_TABLES.length; i++) {
    try { _mysqlRoot("DROP TABLE IF EXISTS `" + OWNED_TABLES[i] + "`", DB_NAME); } catch (_e) {}
  }
}

async function run() {
  var svc = await services.requireService("mysql");
  if (!svc.ok) throw new Error("mysql unreachable: " + svc.reason);

  _mysqlRoot("CREATE DATABASE IF NOT EXISTS " + DB_NAME);
  _dropOwned();

  var driver = _makeDockerMysqlDriver();
  b.cluster._resetForTest();
  b.externalDb._resetForTest();
  b.db._resetForTest();   // clears the cryptoField table registry between runs
  b.externalDb.init({
    backends: {
      ops: {
        connect: driver.connect, query: driver.query, close: driver.close,
        dialect: "mysql",
      },
    },
  });

  var vaultDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-q-cl-my-"));
  await helpers.setupVaultOnly(vaultDir);
  // Re-register the _blamejs_jobs sealed-column map (payload + lastError):
  // db._resetForTest cleared the cryptoField registry, and no db.init runs in
  // this standalone process, so seal-at-rest would silently pass through
  // without it. This proves the cluster path seals + unseals on MySQL too.
  queueLocal._ensureSealTable();

  _ensureTipTables();
  _createJobsTable();

  await b.cluster.init({
    nodeId:            "queue-node-my",
    role:              "leader",
    leaseTtl:          b.constants.TIME.seconds(60),
    heartbeatInterval: b.constants.TIME.seconds(20),
    externalDbBackend: "ops",
    dialect:           "mysql",
  });

  try {
    check("queue-cluster (mysql): cluster mode routes the queue store to MySQL",
          b.cluster.isClusterMode() === true && b.clusterStorage.dialect() === "mysql");

    var q = queueLocal.create({});   // default store = clusterStorage → external "ops" (MySQL)

    await _proveEnqueueAndClusterLease(q);
    await _proveComplete(q);
    await _proveFailRetryThenFinalDlq(q);
    await _proveSweepExpired(q);
    await _proveDelayedNotLeased(q);
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) {}
    b.cluster._resetForTest();
    try { await b.externalDb.shutdown(); } catch (_e) {}
    b.externalDb._resetForTest();
    try { helpers.teardownVaultOnly(vaultDir); } catch (_e) {}
    _dropOwned();
  }
}

// ======================================================================
// 1. enqueue (dialect INSERT) + the transactional cluster lease — the #35
//    headline. Three jobs, distinct priorities; lease(2) must hand back the
//    two highest-priority head-of-queue jobs in order, flip them inflight,
//    increment attempts, and round-trip the sealed payload — all through
//    MySQL-valid SQL (backticks, no RETURNING, literal id-list UPDATE).
// ======================================================================
async function _proveEnqueueAndClusterLease(q) {
  var Q = "q-claim";
  await q.enqueue(Q, { job: "low" },  { priority: 0 });
  await q.enqueue(Q, { job: "high" }, { priority: 10 });
  await q.enqueue(Q, { job: "mid" },  { priority: 5 });

  check("enqueue (mysql): three INSERTs landed (backtick-quoted camelCase, no 1064)",
        _countMysql("`_blamejs_jobs`", "`queueName` = 'q-claim'") === 3);
  check("enqueue (mysql): all three start pending",
        _countMysql("`_blamejs_jobs`", "`queueName` = 'q-claim' AND `status` = 'pending'") === 3);
  check("enqueue (mysql): the sealed payload is NOT stored in cleartext",
        _countMysql("`_blamejs_jobs`", "`queueName` = 'q-claim' AND `payload` LIKE '%\"job\"%'") === 0);

  var leased = await q.lease(Q, b.constants.TIME.seconds(30), 2);
  check("cluster-lease (mysql): leased exactly 2 (FOR UPDATE SKIP LOCKED + guarded UPDATE ran)",
        Array.isArray(leased) && leased.length === 2);
  // The ORDER BY priority desc in the candidate SELECT governs WHICH rows are
  // claimed (the two highest-priority head-of-queue jobs), not the order of
  // the returned array — the MySQL readback re-SELECT is not itself ordered
  // (nor is RETURNING on PG/sqlite). Assert the claimed SET, and separately
  // that the low-priority job is left behind (the priority guarantee).
  var leasedJobs = leased.map(function (l) { return l.payload && l.payload.job; });
  check("cluster-lease (mysql): the two HIGHEST-priority jobs were claimed (high + mid)",
        leasedJobs.indexOf("high") !== -1 && leasedJobs.indexOf("mid") !== -1 &&
        leasedJobs.indexOf("low") === -1);
  check("cluster-lease (mysql): both sealed payloads round-tripped through unseal to objects",
        leased[0].payload && typeof leased[0].payload.job === "string" &&
        leased[1].payload && typeof leased[1].payload.job === "string");
  check("cluster-lease (mysql): leased rows report attempts incremented to 1",
        leased[0].attempts === 1 && leased[1].attempts === 1);
  check("cluster-lease (mysql): the two leased rows flipped to inflight on the server",
        _countMysql("`_blamejs_jobs`", "`queueName` = 'q-claim' AND `status` = 'inflight'") === 2);
  check("cluster-lease (mysql): the un-leased low-priority job stays pending",
        _countMysql("`_blamejs_jobs`", "`queueName` = 'q-claim' AND `status` = 'pending'") === 1);
  check("cluster-lease (mysql): server-side attempts column incremented to 1",
        Number(_jobCol(leased[0].jobId, "attempts")) === 1);

  // stash the leased ids for the next sections
  _proveEnqueueAndClusterLease._leased = leased;
}

// ======================================================================
// 2. complete() — SELECT-then-guarded-UPDATE pair, both dialect-routed.
// ======================================================================
async function _proveComplete(q) {
  var leased = _proveEnqueueAndClusterLease._leased;
  var high = leased[0];
  var ok = await q.complete(high.jobId);
  check("complete (mysql): inflight→done flip returned true", ok === true);
  check("complete (mysql): status is done with finishedAt set on the server",
        _jobCol(high.jobId, "status") === "done" && _jobCol(high.jobId, "finishedAt") !== null);

  var again = await q.complete(high.jobId);
  check("complete (mysql): a second complete() on the done row no-ops (status guard)",
        again === false);
}

// ======================================================================
// 3. fail() — retry CASE branch (attempts < maxAttempts → pending) and the
//    final-failure branch (→ failed, surfaced via dlqList with the sealed
//    lastError decrypted). The CASE-expression UPDATE is the cross-dialect
//    no-transaction fail path; prove it is MySQL-valid + correct.
// ======================================================================
async function _proveFailRetryThenFinalDlq(q) {
  // --- retry branch: the 'mid' job (attempts 1, maxAttempts default 5) ---
  var mid = _proveEnqueueAndClusterLease._leased[1];
  var retried = await q.fail(mid.jobId, "transient blip", { retryDelayMs: 0 });
  check("fail-retry (mysql): inflight→pending retry returned true", retried === true);
  check("fail-retry (mysql): retried job is pending again (attempts 1 < max 5)",
        _jobCol(mid.jobId, "status") === "pending");
  check("fail-retry (mysql): lastError is sealed, not cleartext on the server",
        _jobCol(mid.jobId, "lastError") !== null &&
        !/transient blip/.test(String(_jobCol(mid.jobId, "lastError"))));

  // the retried job + the still-pending low job are both leasable again
  var released = await q.lease("q-claim", b.constants.TIME.seconds(30), 5);
  check("fail-retry (mysql): the retried job re-enters the lease set",
        released.length === 2);

  // --- final-failure branch: a fresh queue, maxAttempts 1 ---
  var FQ = "q-final";
  await q.enqueue(FQ, { job: "doomed" }, { maxAttempts: 1 });
  var fl = await q.lease(FQ, b.constants.TIME.seconds(30), 1);
  check("fail-final (mysql): the doomed job leased (attempts→1 == maxAttempts)",
        fl.length === 1 && fl[0].attempts === 1);
  var finalFail = await q.fail(fl[0].jobId, "fatal error", { retryDelayMs: 0 });
  check("fail-final (mysql): the exhausted job's fail returned true", finalFail === true);
  check("fail-final (mysql): exhausted job moved to failed (DLQ) on the server",
        _jobCol(fl[0].jobId, "status") === "failed" && _jobCol(fl[0].jobId, "finishedAt") !== null);
  check("fail-final (mysql): dlqSize counts the failed job",
        (await q.dlqSize(FQ)) === 1);
  var dlq = await q.dlqList(FQ);
  check("fail-final (mysql): dlqList unseals lastError back to cleartext",
        dlq.length === 1 && dlq[0].lastError === "fatal error" &&
        dlq[0].payload && dlq[0].payload.job === "doomed");
}

// ======================================================================
// 4. sweepExpired() — a lease whose expiry has passed returns to pending.
//    Single dialect-routed UPDATE with a leaseExpiresAt < now guard.
// ======================================================================
async function _proveSweepExpired(q) {
  var SQ = "q-sweep";
  await q.enqueue(SQ, { job: "sweepable" });
  var leased = await q.lease(SQ, 1, 1);   // leaseExpiresAt = now + 1ms
  check("sweep (mysql): job leased before sweep", leased.length === 1);
  await helpers.passiveObserve(30, "queue-cluster (mysql): lease ms window elapses before sweep");
  var swept = await q.sweepExpired();
  check("sweep (mysql): sweepExpired re-queued at least the expired lease",
        swept >= 1);
  check("sweep (mysql): the swept job is pending again with leaseExpiresAt cleared",
        _jobCol(leased[0].jobId, "status") === "pending" &&
        _jobCol(leased[0].jobId, "leaseExpiresAt") === null);
}

// ======================================================================
// 5. a job scheduled in the future is NOT leasable (availableAt > now guard
//    in the head-of-queue SELECT), but still counts toward size().
// ======================================================================
async function _proveDelayedNotLeased(q) {
  var DQ = "q-delay";
  await q.enqueue(DQ, { job: "later" }, { availableAt: Date.now() + b.constants.TIME.minutes(5) });
  var leased = await q.lease(DQ, b.constants.TIME.seconds(30), 5);
  check("delay (mysql): a future-availableAt job is not leased", leased.length === 0);
  check("delay (mysql): the future job still counts toward size()",
        (await q.size(DQ)) === 1);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
