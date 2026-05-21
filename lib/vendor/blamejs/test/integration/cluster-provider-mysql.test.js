"use strict";
/**
 * Live cluster-provider-db MySQL dialect test against the docker
 * mysql container. The "driver" is a minimal docker-exec shim — every
 * query() call shells `mysql -e "<SQL>"` inside the container via
 * execFileSync (no shell). It removes the npm-mysql-driver dep
 * entirely AND exercises the framework's MySQL SQL against a real
 * server.
 */
var execFileSync = require("node:child_process").execFileSync;
var helpers = require("../helpers");
var check = helpers.check;
var services = require("../helpers/services");
var b = require("../../");

var DB_NAME = "blamejs_provider_test";

function _execMysql(sql) {
  var out;
  try {
    out = execFileSync("docker",
      ["exec", "-i", "blamejs-test-mysql",
       "mysql", "-uroot", "-pblamejs_test_root", "--batch", "--raw", DB_NAME, "-e", sql],
      { stdio: ["pipe", "pipe", "pipe"] }
    ).toString("utf8");
  } catch (e) {
    var err = new Error(e.stderr ? e.stderr.toString("utf8") : (e.message || String(e)));
    err.cause = e;
    throw err;
  }
  return out;
}

function _bindParams(sql, params) {
  // The cluster provider emits ? placeholders for MySQL. Substitute
  // them with quoted literals — fine for this test since every value
  // is operator-controlled (nodeId / leaseId / numbers / null).
  var i = 0;
  return sql.replace(/\?/g, function () {
    if (i >= params.length) throw new Error("placeholder/param count mismatch");
    var p = params[i++];
    if (p === null || p === undefined) return "NULL";
    if (typeof p === "number") return String(p);
    return "'" + String(p).replace(/'/g, "''") + "'";
  });
}

function _parseBatch(out) {
  var lines = out.split(/\r?\n/).filter(function (l) { return l.length > 0; });
  if (lines.length < 1) return { rows: [], affectedRows: 0 };
  var headers = lines[0].split("\t");
  var rows = [];
  for (var i = 1; i < lines.length; i++) {
    var cells = lines[i].split("\t");
    var row = {};
    for (var j = 0; j < headers.length; j++) {
      var v = cells[j];
      if (v === "NULL") v = null;
      row[headers[j]] = v;
    }
    rows.push(row);
  }
  return { rows: rows, affectedRows: rows.length };
}

function _makeDockerMysqlDriver() {
  return {
    connect: async function () { return { id: 1 }; },
    query: async function (_client, sql, params) {
      params = params || [];
      var bound = _bindParams(sql, params);
      var t = bound.trim();
      if (/^(CREATE|ALTER|INSERT|UPDATE|DELETE|DROP)/i.test(t)) {
        _execMysql(bound);
        try {
          var ar = _execMysql("SELECT ROW_COUNT() AS n");
          var parsed = _parseBatch(ar);
          var n = parsed.rows[0] ? Number(parsed.rows[0].n) : 0;
          return { rows: [], affectedRows: n };
        } catch (_e) {
          return { rows: [], affectedRows: 0 };
        }
      }
      var out = _execMysql(bound);
      var parsedSel = _parseBatch(out);
      for (var i = 0; i < parsedSel.rows.length; i++) {
        var row = parsedSel.rows[i];
        if (row.acquiredAt   != null) row.acquiredAt   = Number(row.acquiredAt);
        if (row.expiresAt    != null) row.expiresAt    = Number(row.expiresAt);
        if (row.fencingToken != null) row.fencingToken = Number(row.fencingToken);
      }
      return parsedSel;
    },
    close: async function () { /* no-op */ },
  };
}

async function run() {
  var mysqlSvc = await services.requireService("mysql");
  if (!mysqlSvc.ok) throw new Error("mysql unreachable: " + mysqlSvc.reason);

  execFileSync("docker",
    ["exec", "blamejs-test-mysql", "mysql", "-uroot", "-pblamejs_test_root",
     "-e", "CREATE DATABASE IF NOT EXISTS " + DB_NAME],
    { stdio: "pipe" });
  execFileSync("docker",
    ["exec", "blamejs-test-mysql", "mysql", "-uroot", "-pblamejs_test_root", DB_NAME,
     "-e", "DROP TABLE IF EXISTS _blamejs_leader; DROP TABLE IF EXISTS _blamejs_cluster_state;"],
    { stdio: "pipe" });

  var driver = _makeDockerMysqlDriver();
  b.externalDb.init({
    backends: {
      "ops": {
        connect: driver.connect, query: driver.query, close: driver.close,
        dialect: "mysql",
      },
    },
  });

  var providerFactory = require("../../lib/cluster-provider-db");
  var pA = providerFactory.create({ externalDbBackend: "ops", dialect: "mysql" });
  var pB = providerFactory.create({ externalDbBackend: "ops", dialect: "mysql" });

  await pA.ensureSchema();
  check("ensureSchema runs against real mysql without error", true);

  var leaseA = await pA.acquireLease("node-A", b.constants.TIME.seconds(30));
  check("real-mysql: A acquired",           leaseA !== null);
  check("real-mysql: fencingToken = 1",     leaseA.fencingToken === 1);
  check("real-mysql: nodeId = 'node-A'",    leaseA.nodeId === "node-A");

  var leaseB = await pB.acquireLease("node-B", b.constants.TIME.seconds(30));
  check("real-mysql: B blocked while A holds", leaseB === null);

  var current = await pB.currentLeader();
  check("real-mysql: B's currentLeader sees A", current && current.nodeId === "node-A");

  var renewed = await pA.renewLease(leaseA);
  check("real-mysql: renewLease keeps fencingToken", renewed.fencingToken === 1);
  check("real-mysql: renewLease pushes expiresAt forward", renewed.expiresAt >= leaseA.expiresAt);

  await pA.releaseLease(renewed);
  var afterRelease = await pB.currentLeader();
  check("real-mysql: currentLeader null after release", afterRelease === null);

  var leaseShort = await pA.acquireLease("node-A", 100);
  check("real-mysql: short-TTL acquire succeeds", leaseShort !== null);
  var leaseTakeover = await helpers.waitUntil(async function () {
    return await pB.acquireLease("node-B", b.constants.TIME.seconds(30));
  }, { label: "real-mysql: B takes over after A's short-lease expires" });
  check("real-mysql: B takes over after expiry",  leaseTakeover !== null);
  check("real-mysql: takeover bumps fencingToken",
        leaseTakeover.fencingToken === leaseShort.fencingToken + 1);
  check("real-mysql: leader is now B",            leaseTakeover.nodeId === "node-B");

  var threw = null;
  try { await pA.renewLease(leaseShort); }
  catch (e) { threw = e; }
  check("real-mysql: old leader's renew throws LEASE_LOST",
        threw && threw.code === "LEASE_LOST");

  await pB.releaseLease(leaseTakeover);
  await b.externalDb.shutdown();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
