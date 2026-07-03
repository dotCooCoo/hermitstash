// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Live Postgres coverage for the queue-local CLUSTER lease path — the
 * dialect-aware enqueue + the transactional FOR UPDATE SKIP LOCKED claim that
 * only runs when the queue's store is a postgres/mysql cluster backend. Host
 * smoke exercises ONLY the sqlite single-statement RETURNING path; this proves
 * the Postgres branch of queue-local.lease() against a real server:
 *
 *   - the head-of-queue rows are SELECT … FOR UPDATE SKIP LOCKED inside a
 *     transaction (so concurrent leasers see disjoint sets — no double-lease
 *     from the frozen-materialized-subquery the single-statement form hits on
 *     Postgres), then
 *   - the guarded UPDATE … WHERE status='pending' AND "_id" IN (…) RETURNING
 *     hands the claimed rows back in one round trip (Postgres supports
 *     RETURNING; this is the branch MySQL can't take).
 *
 * Driven through the REAL queue-local consumer surface (the backend factory
 * b.queue.init wires): enqueue / lease / complete / fail / sweepExpired /
 * dlqList against real Postgres. RED before the dialect reshape (the
 * single-statement RETURNING UPDATE freezes its subquery qual on PG, so
 * concurrent leasers double-claim); GREEN after.
 *
 * The "driver" is the persistent-session docker-exec psql shim shared in
 * spirit with data-layer-cluster-pg — a held psql process per client, so a
 * transaction's BEGIN / body / COMMIT and the FOR UPDATE locks run on ONE
 * session (faithful to node-postgres). BIGINT comes back as a JS STRING
 * (node-pg's int8 default); _shapeLeasedRow's Number() coercion is what
 * normalizes the framework int columns.
 *
 * RUN: node scripts/test-integration.js --skip-service-check queue-cluster-pg
 */

var spawn        = require("node:child_process").spawn;
var execFileSync = require("node:child_process").execFileSync;
var fs       = require("node:fs");
var os       = require("node:os");
var path     = require("node:path");
var helpers  = require("../helpers");
var check    = helpers.check;
var services = require("../helpers/services");
var b = require("../../");
var queueLocal = require("../../lib/queue-local");

var CONTAINER = "blamejs-test-postgres";
var NULL_SENTINEL = "__BJNULL__";
var PSQL_ARGS = "psql -U blamejs -d blamejs_test -A " +
                "-v ON_ERROR_STOP=0 -P null=__BJNULL__ 2>&1";

// ---- one-shot psql (setup / teardown / out-of-band assertions) ----
function _psql(sql) {
  var prelude = "\\pset fieldsep '\\t'\n";
  var out = execFileSync(
    "docker",
    ["exec", "-i", CONTAINER, "sh", "-c",
     "psql -U blamejs -d blamejs_test -qtA -P null=__BJNULL__ 2>&1"],
    { input: prelude + sql + "\n", stdio: ["pipe", "pipe", "pipe"] }
  ).toString("utf8");
  if (/^ERROR:/m.test(out)) {
    throw new Error("psql setup failed for [" + sql + "]:\n" + out);
  }
  return out;
}

// ---- persistent-session docker-exec psql driver (faithful to node-pg) ----
var _seq = 0;
function _makeDockerPgDriver() {
  return {
    connect: function () {
      return new Promise(function (resolve, reject) {
        var child = spawn(
          "docker",
          ["exec", "-i", CONTAINER, "sh", "-c",
           PSQL_ARGS + " ; echo __BLAMEJS_PSQL_EXIT__"],
          { stdio: ["pipe", "pipe", "pipe"] }
        );
        var client = { child: child, buf: "", pending: null, closed: false };
        child.on("error", function (e) {
          if (client.pending) { var p = client.pending; client.pending = null; p.reject(e); }
        });
        child.on("close", function () {
          client.closed = true;
          if (client.pending) {
            var p = client.pending; client.pending = null;
            p.reject(new Error("psql session closed mid-statement"));
          }
        });
        child.stdout.on("data", function (chunk) {
          client.buf += chunk.toString("utf8");
          _drain(client);
        });
        var primeSentinel = "__BJ_PRIME__";
        client.pending = {
          sentinel: primeSentinel,
          resolve:  function () { resolve(client); },
          reject:   reject,
        };
        client.child.stdin.write(
          "\\pset fieldsep '\\t'\n\\pset footer off\n\\set VERBOSITY verbose\n" +
          "\\echo " + primeSentinel + "\n");
      });
    },

    query: function (client, sql, params) {
      params = params || [];
      var bound = _bindParams(sql, params);
      var sentinel = "__BJ_EOR_" + (++_seq) + "__";
      return new Promise(function (resolve, reject) {
        if (client.closed) { reject(new Error("psql session is closed")); return; }
        client.pending = { sentinel: sentinel, resolve: resolve, reject: reject };
        client.child.stdin.write(bound + "\n;\n\\echo " + sentinel + "\n");
      });
    },

    close: function (client) {
      return new Promise(function (resolve) {
        if (client.closed) { resolve(); return; }
        try { client.child.stdin.end("\\q\n"); } catch (_e) { /* best effort */ }
        var done = false;
        client.child.on("close", function () { if (!done) { done = true; resolve(); } });
        setTimeout(function () {
          if (done) return;
          done = true;
          try { client.child.kill("SIGKILL"); } catch (_e) {}
          resolve();
        }, 2000);
      });
    },

    dialect: "postgres",
  };
}

function _drain(client) {
  if (!client.pending) return;
  var sentinel = client.pending.sentinel;
  var marker = "\n" + sentinel + "\n";
  var idx = client.buf.indexOf(marker);
  var startAtZero = client.buf.indexOf(sentinel + "\n") === 0;
  var block;
  if (idx !== -1) {
    block = client.buf.slice(0, idx);
    client.buf = client.buf.slice(idx + marker.length);
  } else if (startAtZero) {
    block = "";
    client.buf = client.buf.slice((sentinel + "\n").length);
  } else {
    return;
  }
  var p = client.pending;
  client.pending = null;
  var parsed;
  try { parsed = _parseBlock(block); }
  catch (e) { return p.reject(e); }
  if (parsed.error) return p.reject(parsed.error);
  p.resolve({ rows: parsed.rows, rowCount: parsed.rowCount });
}

function _bindParams(sql, params) {
  return sql.replace(/\$(\d+)/g, function (_m, n) {
    var i = Number(n) - 1;
    if (i < 0 || i >= params.length) {
      throw new Error("placeholder $" + n + " has no matching param");
    }
    var v = params[i];
    if (v === null || v === undefined) return "NULL";
    // node-postgres serializes a JS array param for `"_id" = ANY($n)` into a
    // Postgres array on the wire; the docker-exec shim reproduces that as an
    // ARRAY[…] literal so the queue's array-param lease UPDATE is exercised
    // faithfully (a plain String(arr) would comma-join → "malformed array
    // literal"). The lease returns early on an empty id set, so ARRAY[] never
    // actually reaches here, but render it typed for completeness.
    if (Array.isArray(v)) {
      if (v.length === 0) return "'{}'";
      return "ARRAY[" + v.map(function (el) {
        if (el === null || el === undefined) return "NULL";
        if (typeof el === "number") return String(el);
        if (typeof el === "boolean") return el ? "TRUE" : "FALSE";
        return "'" + String(el).replace(/'/g, "''") + "'";
      }).join(",") + "]";
    }
    if (typeof v === "number") return String(v);
    if (typeof v === "boolean") return v ? "TRUE" : "FALSE";
    return "'" + String(v).replace(/'/g, "''") + "'";
  });
}

var _CMD_TAG_RE = /^(INSERT|UPDATE|DELETE|MERGE|SELECT|COPY|MOVE)\b(?:\s+\d+)*\s*$/;
var _CTRL_TAG_RE = /^(BEGIN|COMMIT|ROLLBACK|SET|RESET|SAVEPOINT|RELEASE|START|CREATE|DROP|ALTER|GRANT|REVOKE|TRUNCATE|COMMENT|DO|CALL|VACUUM|ANALYZE|EXPLAIN|TABLE|SHOW|DISCARD)\b/;

function _parseBlock(block) {
  var lines = block.split(/\r?\n/);
  while (lines.length && lines[lines.length - 1] === "") lines.pop();

  for (var i = 0; i < lines.length; i++) {
    var em = /^ERROR:\s+([0-9A-Za-z]{5}):\s*(.*)$/.exec(lines[i]);
    if (em) {
      var err = new Error("Postgres " + em[1] + ": " + em[2]);
      err.code = em[1];
      return { error: err };
    }
  }

  var affected = null;
  var dataLines = [];
  for (var j = 0; j < lines.length; j++) {
    var ln = lines[j];
    if (/^(NOTICE|WARNING|DETAIL|HINT|LINE|LOCATION|CONTEXT|STATEMENT):/.test(ln)) continue;
    var tm = _CMD_TAG_RE.exec(ln);
    if (tm) {
      var nums = ln.trim().split(/\s+/).slice(1).map(Number);
      if (nums.length) affected = nums[nums.length - 1];
      continue;
    }
    if (_CTRL_TAG_RE.test(ln) && ln.indexOf("\t") === -1) continue;
    dataLines.push(ln);
  }

  var rows = [];
  if (dataLines.length >= 1) {
    var headers = dataLines[0].split("\t");
    for (var k = 1; k < dataLines.length; k++) {
      var cells = dataLines[k].split("\t");
      var row = {};
      for (var c = 0; c < headers.length; c++) {
        var cell = cells[c];
        row[headers[c]] = (cell === NULL_SENTINEL || cell === undefined) ? null : cell;
      }
      rows.push(row);
    }
  }
  var rowCount = (affected !== null) ? affected : rows.length;
  return { rows: rows, rowCount: rowCount, error: null };
}

var OWNED_TABLES = [
  "_blamejs_jobs",
  "_blamejs_cluster_state",
  "_blamejs_leader",
  "_blamejs_audit_tip",
  "_blamejs_consent_tip",
];

function _dropOwned() {
  _psql(OWNED_TABLES.map(function (t) {
    return "DROP TABLE IF EXISTS " + t + " CASCADE;";
  }).join("\n"));
}

// Out-of-band single-column read for one job row (double-quoted camelCase).
function _jobCol(jobId, col) {
  var out = _psql("SELECT \"" + col + "\" FROM \"_blamejs_jobs\" WHERE \"_id\" = '" +
    jobId.replace(/'/g, "''") + "';");
  var v = out.split(/\r?\n/).filter(function (l) { return l.length > 0; })[0];
  return (v === undefined || v === NULL_SENTINEL) ? null : v;
}

function _countPg(whereClause) {
  var out = _psql("SELECT count(*) FROM \"_blamejs_jobs\"" +
    (whereClause ? " WHERE " + whereClause : "") + ";");
  var v = out.split(/\r?\n/).filter(function (l) { return l.length > 0; })[0];
  return Number(v);
}

function _createJobsTable() {
  _psql("DROP TABLE IF EXISTS \"_blamejs_jobs\" CASCADE;");
  _psql(
    "CREATE TABLE \"_blamejs_jobs\" (" +
    "  \"_id\"            VARCHAR(64) PRIMARY KEY," +
    "  \"queueName\"      VARCHAR(255) NOT NULL," +
    "  \"payload\"        TEXT," +
    "  \"status\"         VARCHAR(32) NOT NULL," +
    "  \"enqueuedAt\"     BIGINT NOT NULL," +
    "  \"availableAt\"    BIGINT NOT NULL," +
    "  \"leasedAt\"       BIGINT," +
    "  \"leaseExpiresAt\" BIGINT," +
    "  \"attempts\"       BIGINT NOT NULL DEFAULT 0," +
    "  \"maxAttempts\"    BIGINT NOT NULL DEFAULT 5," +
    "  \"lastError\"      TEXT," +
    "  \"finishedAt\"     BIGINT," +
    "  \"traceId\"        VARCHAR(255)," +
    "  \"classification\" VARCHAR(255)," +
    "  \"priority\"       BIGINT NOT NULL DEFAULT 0," +
    "  \"repeatCron\"     VARCHAR(255)," +
    "  \"repeatTimezone\" VARCHAR(255)," +
    "  \"flowId\"         VARCHAR(255)," +
    "  \"flowChildName\"  VARCHAR(255)," +
    "  \"dependsOn\"      TEXT" +
    ");");
  _psql("CREATE INDEX \"_blamejs_jobs_lease_idx\" ON \"_blamejs_jobs\" " +
    "(\"queueName\", \"status\", \"availableAt\");");
}

async function run() {
  var pg = await services.requireService("postgres");
  if (!pg.ok) throw new Error("postgres unreachable: " + pg.reason);

  _dropOwned();

  var driver = _makeDockerPgDriver();
  b.cluster._resetForTest();
  b.externalDb._resetForTest();
  b.db._resetForTest();
  b.externalDb.init({
    backends: {
      ops: {
        connect: driver.connect, query: driver.query, close: driver.close,
        dialect: "postgres",
      },
    },
  });

  var vaultDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-q-cl-pg-"));
  await helpers.setupVaultOnly(vaultDir);
  queueLocal._ensureSealTable();

  _createJobsTable();

  await b.cluster.init({
    nodeId:            "queue-node-pg",
    role:              "leader",
    leaseTtl:          b.constants.TIME.seconds(60),
    heartbeatInterval: b.constants.TIME.seconds(20),
    externalDbBackend: "ops",
    dialect:           "postgres",
  });

  try {
    check("queue-cluster (pg): cluster mode routes the queue store to Postgres",
          b.cluster.isClusterMode() === true && b.clusterStorage.dialect() === "postgres");

    var q = queueLocal.create({});

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
// 1. enqueue (dialect INSERT) + the transactional cluster lease via the
//    Postgres RETURNING branch — the #35 headline on PG.
// ======================================================================
async function _proveEnqueueAndClusterLease(q) {
  var Q = "q-claim";
  await q.enqueue(Q, { job: "low" },  { priority: 0 });
  await q.enqueue(Q, { job: "high" }, { priority: 10 });
  await q.enqueue(Q, { job: "mid" },  { priority: 5 });

  check("enqueue (pg): three INSERTs landed (double-quoted camelCase identifiers)",
        _countPg("\"queueName\" = 'q-claim'") === 3);
  check("enqueue (pg): all three start pending",
        _countPg("\"queueName\" = 'q-claim' AND \"status\" = 'pending'") === 3);
  check("enqueue (pg): the sealed payload is NOT stored in cleartext",
        _countPg("\"queueName\" = 'q-claim' AND \"payload\" LIKE '%\"job\"%'") === 0);

  var leased = await q.lease(Q, b.constants.TIME.seconds(30), 2);
  check("cluster-lease (pg): leased exactly 2 via FOR UPDATE SKIP LOCKED + RETURNING",
        Array.isArray(leased) && leased.length === 2);
  // ORDER BY priority desc governs WHICH rows are claimed, not the RETURNING
  // array order (Postgres does not guarantee RETURNING follows the qual's
  // ORDER BY). Assert the claimed SET + that the low-priority job is left.
  var leasedJobs = leased.map(function (l) { return l.payload && l.payload.job; });
  check("cluster-lease (pg): the two HIGHEST-priority jobs were claimed (high + mid)",
        leasedJobs.indexOf("high") !== -1 && leasedJobs.indexOf("mid") !== -1 &&
        leasedJobs.indexOf("low") === -1);
  check("cluster-lease (pg): RETURNING handed back rows with attempts coerced to 1",
        leased[0].attempts === 1 && leased[1].attempts === 1);
  check("cluster-lease (pg): the two leased rows flipped to inflight on the server",
        _countPg("\"queueName\" = 'q-claim' AND \"status\" = 'inflight'") === 2);
  check("cluster-lease (pg): the un-leased low-priority job stays pending",
        _countPg("\"queueName\" = 'q-claim' AND \"status\" = 'pending'") === 1);
  check("cluster-lease (pg): server-side attempts column incremented to 1",
        Number(_jobCol(leased[0].jobId, "attempts")) === 1);

  _proveEnqueueAndClusterLease._leased = leased;
}

// ======================================================================
// 2. complete()
// ======================================================================
async function _proveComplete(q) {
  var high = _proveEnqueueAndClusterLease._leased[0];
  var ok = await q.complete(high.jobId);
  check("complete (pg): inflight→done flip returned true", ok === true);
  check("complete (pg): status is done with finishedAt set on the server",
        _jobCol(high.jobId, "status") === "done" && _jobCol(high.jobId, "finishedAt") !== null);

  var again = await q.complete(high.jobId);
  check("complete (pg): a second complete() on the done row no-ops (status guard)",
        again === false);
}

// ======================================================================
// 3. fail() — retry CASE branch + final-failure → DLQ.
// ======================================================================
async function _proveFailRetryThenFinalDlq(q) {
  var mid = _proveEnqueueAndClusterLease._leased[1];
  var retried = await q.fail(mid.jobId, "transient blip", { retryDelayMs: 0 });
  check("fail-retry (pg): inflight→pending retry returned true", retried === true);
  check("fail-retry (pg): retried job is pending again (attempts 1 < max 5)",
        _jobCol(mid.jobId, "status") === "pending");
  check("fail-retry (pg): lastError is sealed, not cleartext on the server",
        _jobCol(mid.jobId, "lastError") !== null &&
        !/transient blip/.test(String(_jobCol(mid.jobId, "lastError"))));

  var released = await q.lease("q-claim", b.constants.TIME.seconds(30), 5);
  check("fail-retry (pg): the retried job re-enters the lease set",
        released.length === 2);

  var FQ = "q-final";
  await q.enqueue(FQ, { job: "doomed" }, { maxAttempts: 1 });
  var fl = await q.lease(FQ, b.constants.TIME.seconds(30), 1);
  check("fail-final (pg): the doomed job leased (attempts→1 == maxAttempts)",
        fl.length === 1 && fl[0].attempts === 1);
  var finalFail = await q.fail(fl[0].jobId, "fatal error", { retryDelayMs: 0 });
  check("fail-final (pg): the exhausted job's fail returned true", finalFail === true);
  check("fail-final (pg): exhausted job moved to failed (DLQ) on the server",
        _jobCol(fl[0].jobId, "status") === "failed" && _jobCol(fl[0].jobId, "finishedAt") !== null);
  check("fail-final (pg): dlqSize counts the failed job",
        (await q.dlqSize(FQ)) === 1);
  var dlq = await q.dlqList(FQ);
  check("fail-final (pg): dlqList unseals lastError back to cleartext",
        dlq.length === 1 && dlq[0].lastError === "fatal error" &&
        dlq[0].payload && dlq[0].payload.job === "doomed");
}

// ======================================================================
// 4. sweepExpired()
// ======================================================================
async function _proveSweepExpired(q) {
  var SQ = "q-sweep";
  await q.enqueue(SQ, { job: "sweepable" });
  var leased = await q.lease(SQ, 1, 1);
  check("sweep (pg): job leased before sweep", leased.length === 1);
  await helpers.passiveObserve(30, "queue-cluster (pg): lease ms window elapses before sweep");
  var swept = await q.sweepExpired();
  check("sweep (pg): sweepExpired re-queued at least the expired lease", swept >= 1);
  check("sweep (pg): the swept job is pending again with leaseExpiresAt cleared",
        _jobCol(leased[0].jobId, "status") === "pending" &&
        _jobCol(leased[0].jobId, "leaseExpiresAt") === null);
}

// ======================================================================
// 5. a future-availableAt job is not leasable but still counts in size().
// ======================================================================
async function _proveDelayedNotLeased(q) {
  var DQ = "q-delay";
  await q.enqueue(DQ, { job: "later" }, { availableAt: Date.now() + b.constants.TIME.minutes(5) });
  var leased = await q.lease(DQ, b.constants.TIME.seconds(30), 5);
  check("delay (pg): a future-availableAt job is not leased", leased.length === 0);
  check("delay (pg): the future job still counts toward size()",
        (await q.size(DQ)) === 1);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
