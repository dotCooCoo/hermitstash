"use strict";
/**
 * Live MySQL coverage for the b.sql-migrated cluster data layer — the
 * parts that only ran on sqlite host smoke before this file: cluster-
 * storage coercion (MySQL BIGINT text → JS number), pubsub-cluster
 * publish/poll/prune, the cluster vault-key-consistency upsert (MySQL's
 * `ON DUPLICATE KEY UPDATE scope = scope` DO-NOTHING fold + the backtick-
 * quoted camelCase readback), and external-db-migrate up/down/status +
 * advisory lock. The audit chain is Postgres/SQLite-only (frameworkSchema
 * refuses MySQL), so there is no MySQL audit-chain path to prove here —
 * that surface lives in the PG file.
 *
 * The "driver" is a docker-exec mysql shim — every query() shells
 *   mysql --batch --raw <db> -e "<SQL>"
 * inside the container via execFileSync (no shell parsing of SQL beyond
 * the single -e argument). Writes follow up with `SELECT ROW_COUNT()` for
 * affectedRows. It removes the npm-mysql-driver dep while exercising the
 * framework's real MySQL SQL against a real 8.x server.
 *
 * COERCION note: MySQL --batch renders every value as text, so a BIGINT
 * comes back as a STRING (like a streaming text protocol). The framework's
 * coerceRow normalizes the int framework columns back to JS numbers — the
 * property this file asserts on the real backend.
 *
 * RUN: node scripts/test-integration.js --skip-service-check data-layer-cluster-mysql
 */

var execFileSync = require("node:child_process").execFileSync;
var helpers  = require("../helpers");
var check    = helpers.check;
var services = require("../helpers/services");
var b = require("../../");

var CONTAINER = "blamejs-test-mysql";
var DB_NAME   = "blamejs_cluster_test";

// ---- one-shot mysql (setup / teardown / out-of-band assertions) ----
function _mysqlRoot(sql, dbName) {
  var args = ["exec", "-i", CONTAINER, "mysql", "-uroot", "-pblamejs_test_root", "--batch", "--raw"];
  if (dbName) args.push(dbName);
  args.push("-e", sql);
  return execFileSync("docker", args, { stdio: ["pipe", "pipe", "pipe"] }).toString("utf8");
}

// ---- docker-exec mysql driver (faithful to a text-protocol driver) ----
function _makeDockerMysqlDriver() {
  return {
    connect: async function () { return { id: 1 }; },
    query: async function (_client, sql, params) {
      params = params || [];
      var bound = _bindParams(sql, params);
      var t = bound.trim();
      // DML / DDL → run + read ROW_COUNT() for affectedRows (mysql2 style).
      // ROW_COUNT() is CONNECTION-scoped, so the statement + the read must
      // run in ONE mysql invocation (each `mysql -e` is a fresh connection);
      // a `;`-joined multi-statement keeps them on the same connection.
      if (/^(CREATE|ALTER|INSERT|UPDATE|DELETE|DROP|REPLACE|TRUNCATE)\b/i.test(t)) {
        var stmt = bound.replace(/;\s*$/, "");
        var ar = _exec(stmt + "; SELECT ROW_COUNT() AS n");
        var parsed = _parseBatch(ar);
        var n = parsed.rows[0] ? Number(parsed.rows[0].n) : 0;
        // ROW_COUNT() returns -1 for statements that don't affect rows
        // (e.g. CREATE/DROP); normalize that to 0 affected.
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
    // mysql writes its error to stderr; surface it with a SQLSTATE-ish code
    // when present so the framework's coded-error paths see something.
    var msg = e.stderr ? e.stderr.toString("utf8") : (e.message || String(e));
    // Strip the benign "World-writable config file ... ignored" / password
    // warnings mysql prints to stderr so the surfaced message is the real
    // ERROR line, not warning noise.
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

// --batch output is tab-separated with a header row; "NULL" is the null
// sentinel. Every cell is text (BIGINT included) — coerceRow's job.
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

// Tables this file owns, dropped in setup + teardown.
var OWNED_TABLES = [
  "_blamejs_pubsub_messages",
  "_blamejs_cluster_state",
  "_blamejs_leader",
  "_blamejs_externaldb_migrations",
  "_blamejs_externaldb_migrations_lock",
  "_blamejs_schema_version_history",
  "_blamejs_audit_tip",
  "_blamejs_consent_tip",
  "mig_demo_widgets_my",
];

// Empty chain-tip tables so cluster.init's rollback check takes the
// "no tip row → skip" branch instead of the "table missing" branch (the
// latter mis-handled on MySQL — see _proveChainTipSkipOnMysql). Backtick-
// quoted camelCase columns, matching the framework tip DDL.
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

function _dropOwned() {
  for (var i = 0; i < OWNED_TABLES.length; i++) {
    try { _mysqlRoot("DROP TABLE IF EXISTS `" + OWNED_TABLES[i] + "`", DB_NAME); } catch (_e) {}
  }
}

// Out-of-band COUNT(*) → JS number, parsed from the --batch header+value
// output ("n\n<count>").
function _countMysql(table, whereClause) {
  var sql = "SELECT count(*) AS n FROM " + table +
    (whereClause ? " WHERE " + whereClause : "");
  var out = _mysqlRoot(sql, DB_NAME);
  var parsed = _parseBatch(out);
  return parsed.rows[0] ? Number(parsed.rows[0].n) : 0;
}

// Soft findings — a recorded lib-bug surfaced live that must NOT halt the
// rest of the suite; printed at the end + makes the file exit non-zero.
var _softFindings = [];
function _softCheck(label, ok) {
  if (ok) { check(label, true); return; }
  _softFindings.push(label);
  console.error("[SOFT-FAIL] " + label);
}

async function run() {
  var svc = await services.requireService("mysql");
  if (!svc.ok) throw new Error("mysql unreachable: " + svc.reason);

  _mysqlRoot("CREATE DATABASE IF NOT EXISTS " + DB_NAME);
  _dropOwned();

  var driver = _makeDockerMysqlDriver();
  b.cluster._resetForTest();
  b.externalDb._resetForTest();
  b.externalDb.init({
    backends: {
      ops: {
        connect: driver.connect, query: driver.query, close: driver.close,
        dialect: "mysql",
      },
    },
  });

  try {
    // The cluster boot-time rollback check on the audit/consent chains is
    // gated by a missing-table skip. On MySQL the chain-tip tables don't
    // exist in this gates-only setup, so the check should SKIP — but the
    // skip-regex in cluster._checkChainTipRollback only recognizes Postgres/
    // SQLite phrasing ("no such table" / "does not exist"), NOT MySQL's
    // "Table 'x' doesn't exist". Surface that as the first proof, then
    // create empty tip tables so the remaining sections (which need
    // cluster.init to complete) can run.
    await _proveChainTipSkipOnMysql();
    _ensureTipTables();
    await _proveClusterStorageCoercion();
    await _provePubsubCluster();
    await _proveVaultKeyConsistency();
    await _proveExternalDbMigrate();
    await _proveRoleHardeningSkip();
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) {}
    b.cluster._resetForTest();
    try { await b.externalDb.shutdown(); } catch (_e) {}
    _dropOwned();
  }

  if (_softFindings.length > 0) {
    throw new Error("data-layer-cluster-mysql: " + _softFindings.length +
      " live-surfaced lib bug(s):\n  - " + _softFindings.join("\n  - "));
  }
}

// ======================================================================
// 0. cluster boot-time chain-tip rollback check, gates-only mode, MySQL.
//    cluster.init runs _checkChainTipRollback on the audit + consent
//    chains; when the tip table is absent (framework state not resident on
//    the external DB) it is DOCUMENTED to "skip silently (cluster gates-
//    only mode)". That skip keys off the driver error text via the regex
//    /no such table|does not exist|relation .* does not exist/i — which
//    recognizes Postgres ("does not exist") + SQLite ("no such table") but
//    NOT MySQL's "Table 'x' doesn't exist". So on MySQL the gates-only skip
//    mis-fires and cluster.init throws ER_NO_SUCH_TABLE (1146/42S02). This
//    asserts the CORRECT contract (init completes) so the MySQL-only gap
//    surfaces; the tables are absent here on purpose.
// ======================================================================
async function _proveChainTipSkipOnMysql() {
  // No tip tables exist (dropOwned cleared them). A gates-only cluster.init
  // should complete by skipping the rollback check.
  var initErr = null;
  try {
    await b.cluster.init({
      nodeId:            "tip-skip-node",
      role:              "leader",
      leaseTtl:          b.constants.TIME.seconds(30),
      heartbeatInterval: b.constants.TIME.seconds(10),
      externalDbBackend: "ops",
      dialect:           "mysql",
    });
  } catch (e) { initErr = e; }
  console.error("[chain-tip-skip mysql] " +
    (initErr ? ("code=" + (initErr.code || "") + " msg=" + (initErr.message || "").slice(0, 160))
             : "init completed (skipped)"));
  _softCheck("cluster (mysql): gates-only cluster.init skips the missing chain-tip " +
        "rollback check instead of throwing ER_NO_SUCH_TABLE on the MySQL " +
        "\"doesn't exist\" phrasing the skip-regex misses",
        initErr === null);
  // Reset for the next section regardless (init may have partially run).
  try { await b.cluster.shutdown(); } catch (_e) {}
  b.cluster._resetForTest();
}

// ======================================================================
// 1. cluster-storage coercion on real MySQL. execute() routes framework
//    SQL to the external DB in cluster mode, then coerceRows-normalizes
//    the driver-native shape. MySQL --batch hands BIGINT back as text;
//    assert the readback int columns are JS NUMBERS.
// ======================================================================
async function _proveClusterStorageCoercion() {
  await b.cluster.init({
    nodeId:            "cs-node-my",
    role:              "leader",
    leaseTtl:          b.constants.TIME.seconds(30),
    heartbeatInterval: b.constants.TIME.seconds(10),
    externalDbBackend: "ops",
    dialect:           "mysql",
  });
  check("cluster-storage (mysql): cluster mode routes framework state to MySQL",
        b.cluster.isClusterMode() === true);

  // Pubsub fan-out table — MySQL DDL with backtick-quoted camelCase columns
  // (mirrors framework-schema _pubsubMessagesDDL for mysql). MySQL preserves
  // identifier case, so the camelCase reads back verbatim regardless of
  // quoting; the BIGINT columns are the coercion subjects.
  _mysqlRoot(
    "CREATE TABLE IF NOT EXISTS `_blamejs_pubsub_messages` (" +
    "  `id`          BIGINT PRIMARY KEY AUTO_INCREMENT," +
    "  `topic`       TEXT NOT NULL," +
    "  `payload`     TEXT NOT NULL," +
    "  `publishedAt` BIGINT NOT NULL," +
    "  `publishedBy` VARCHAR(255) NOT NULL" +
    ")", DB_NAME);

  var bigAt = 1700000000000;
  var insRes = await b.clusterStorage.execute(
    "INSERT INTO `_blamejs_pubsub_messages` (`topic`,`payload`,`publishedAt`,`publishedBy`) " +
    "VALUES (?, ?, ?, ?)",
    ["coerce-topic", '{"k":1}', bigAt, "cs-node-my"]);
  check("cluster-storage (mysql): INSERT through execute() affected 1 row",
        insRes.rowCount === 1);

  var row = await b.clusterStorage.executeOne(
    "SELECT `id`,`topic`,`payload`,`publishedAt`,`publishedBy` " +
    "FROM `_blamejs_pubsub_messages` WHERE `publishedBy` = ?",
    ["cs-node-my"]);
  check("cluster-storage (mysql): round-tripped the row by camelCase key",
        row !== null && row.publishedBy === "cs-node-my" && row.topic === "coerce-topic");
  check("cluster-storage (mysql) COERCION: BIGINT publishedAt coerced text→number",
        typeof row.publishedAt === "number" && row.publishedAt === bigAt);
  check("cluster-storage (mysql) COERCION: BIGINT id coerced text→number",
        typeof row.id === "number" && row.id >= 1);
  check("cluster-storage (mysql) COERCION: text payload left as the string it is",
        typeof row.payload === "string" && row.payload === '{"k":1}');

  await b.cluster.shutdown();
  b.cluster._resetForTest();
}

// ======================================================================
// 2. pubsub-cluster publish / poll / prune on real MySQL.
// ======================================================================
async function _provePubsubCluster() {
  _mysqlRoot("DROP TABLE IF EXISTS `_blamejs_pubsub_messages`", DB_NAME);
  _mysqlRoot(
    "CREATE TABLE IF NOT EXISTS `_blamejs_pubsub_messages` (" +
    "  `id`          BIGINT PRIMARY KEY AUTO_INCREMENT," +
    "  `topic`       TEXT NOT NULL," +
    "  `payload`     TEXT NOT NULL," +
    "  `publishedAt` BIGINT NOT NULL," +
    "  `publishedBy` VARCHAR(255) NOT NULL" +
    ")", DB_NAME);

  await b.cluster.init({
    nodeId:            "node-pub-my",
    role:              "leader",
    leaseTtl:          b.constants.TIME.seconds(30),
    heartbeatInterval: b.constants.TIME.seconds(10),
    externalDbBackend: "ops",
    dialect:           "mysql",
  });

  var pubsubBackend = require("../../lib/pubsub-cluster");
  var pubView = { currentNodeId: function () { return "node-pub-my"; } };
  var subView = { currentNodeId: function () { return "node-sub-my"; } };

  var publisher = pubsubBackend.create({
    cluster: pubView, pollIntervalMs: 25, retentionMs: b.constants.TIME.minutes(1),
  });
  var subscriber = pubsubBackend.create({
    cluster: subView, pollIntervalMs: 25, retentionMs: b.constants.TIME.minutes(1),
  });

  // pubsub-cluster builds its INSERT/SELECT/DELETE through b.sql WITHOUT a
  // { dialect } option, so b.sql defaults to Postgres and double-quotes the
  // identifiers ("topic", "publishedAt", …). SQLite + Postgres accept double-
  // quoted identifiers; MySQL (no ANSI_QUOTES) reads them as STRING LITERALS,
  // so the statement is a syntax error (ER 1064). pubsub on a MySQL cluster
  // backend is therefore broken. Drive the real publish and record the
  // failure as a soft finding so the remaining sections still run.
  var pubErr = null;
  var pr = null;
  try { pr = await publisher.publishRemote("orders:created", { orderId: "o-7", amount: 42 }); }
  catch (e) { pubErr = e; }
  console.error("[pubsub-cluster mysql publish] " +
    (pubErr ? ("code=" + (pubErr.code || "") + " msg=" + (pubErr.message || "").slice(0, 160))
            : "ok"));
  _softCheck("pubsub-cluster (mysql): publishRemote composes valid MySQL — " +
        "pubsub-cluster's b.sql builders pass NO { dialect } so they emit " +
        "Postgres double-quoted identifiers, invalid as identifiers on MySQL",
        pubErr === null && pr && pr.remote === 1);

  if (pubErr === null) {
    var landed = _mysqlRoot(
      "SELECT `topic`,`publishedBy` FROM `_blamejs_pubsub_messages` " +
      "WHERE `topic` = 'orders:created'", DB_NAME);
    check("pubsub-cluster (mysql): publish row physically present on real MySQL",
          /orders:created/.test(landed) && /node-pub-my/.test(landed));

    var received = [];
    subscriber.start(function (topic, payload, meta) {
      received.push({ topic: topic, payload: payload, meta: meta });
    });
    await helpers.waitUntil(function () { return received.length >= 1; }, {
      timeoutMs: 15000,
      label: "pubsub-cluster (mysql): subscriber dispatched the remote row",
    }).catch(function () { /* retry below */ });
    if (received.length === 0) {
      await publisher.publishRemote("orders:created", { orderId: "o-8", amount: 99 });
      await helpers.waitUntil(function () { return received.length >= 1; }, {
        timeoutMs: 15000,
        label: "pubsub-cluster (mysql): subscriber dispatched a post-prime remote row",
      });
    }
    var first = received[0];
    check("pubsub-cluster (mysql): subscriber received the remote topic verbatim",
          first.topic === "orders:created");
    check("pubsub-cluster (mysql): meta.publishedBy is the PUBLISHER node",
          first.meta && first.meta.publishedBy === "node-pub-my");
    check("pubsub-cluster (mysql) COERCION: meta.publishedAt resolved to a finite number",
          typeof first.meta.publishedAt === "number" && isFinite(first.meta.publishedAt));
    subscriber.stop();
    publisher.stop();

    // ---- prune ----
    _mysqlRoot("DELETE FROM `_blamejs_pubsub_messages`", DB_NAME);
    _mysqlRoot(
      "INSERT INTO `_blamejs_pubsub_messages` (`topic`,`payload`,`publishedAt`,`publishedBy`) " +
      "VALUES ('expired','{}',1,'node-other'), " +
      "('fresh','{}'," + (Date.now() + 60000) + ",'node-other')", DB_NAME);
    var pruner = pubsubBackend.create({
      cluster: subView, pollIntervalMs: 25, retentionMs: 1, pruneEveryMs: 1,
    });
    pruner.start(function () { /* no-op */ });
    await helpers.waitUntil(function () {
      return _countMysql("`_blamejs_pubsub_messages`", "`topic` = 'expired'") === 0;
    }, { timeoutMs: 15000, label: "pubsub-cluster (mysql): prune DELETE removed the expired row" });
    check("pubsub-cluster (mysql): prune removed the expired row", true);
    check("pubsub-cluster (mysql): prune left the un-expired row intact",
          _countMysql("`_blamejs_pubsub_messages`", "`topic` = 'fresh'") === 1);
    pruner.stop();
  } else {
    try { subscriber.stop(); } catch (_e) {}
    try { publisher.stop(); } catch (_e) {}
  }

  await b.cluster.shutdown();
  b.cluster._resetForTest();
}

// ======================================================================
// 3. cluster vault-key-consistency upsert on real MySQL. cluster.init's
//    _checkVaultKeyConsistency emits `INSERT ... ON DUPLICATE KEY UPDATE
//    scope = scope` (the MySQL fold for DO NOTHING), then a backtick-quoted
//    SELECT reading vaultKeyFp / recordedByNode / rotationEpoch back. Prove
//    a first boot RECORDS the fingerprint, a second boot with the SAME key
//    reads it back + AGREES (no VAULT_KEY_DRIFT), and the DO-NOTHING fold
//    preserved the first recorder.
// ======================================================================
async function _proveVaultKeyConsistency() {
  var fs   = require("node:fs");
  var os   = require("node:os");
  var path = require("node:path");
  var vaultDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vk-my-"));
  await helpers.setupVaultOnly(vaultDir);

  _mysqlRoot("DROP TABLE IF EXISTS `_blamejs_cluster_state`", DB_NAME);
  _mysqlRoot("DROP TABLE IF EXISTS `_blamejs_leader`", DB_NAME);

  await b.cluster.init({
    nodeId:            "vk-node-A-my",
    role:              "leader",
    leaseTtl:          b.constants.TIME.seconds(30),
    heartbeatInterval: b.constants.TIME.seconds(10),
    externalDbBackend: "ops",
    dialect:           "mysql",
  });
  check("vault-key (mysql): first boot completed (recorded fingerprint, no drift)", true);

  var stateRow = _mysqlRoot(
    "SELECT `vaultKeyFp`,`recordedByNode` FROM `_blamejs_cluster_state` " +
    "WHERE `scope` = 'state'", DB_NAME);
  check("vault-key (mysql): cluster-state row recorded by this node",
        /vk-node-A-my/.test(stateRow));
  check("vault-key (mysql): recorded fingerprint is a 128-hex SHA3-512 digest",
        /\b[0-9a-f]{128}\b/.test(stateRow));

  await b.cluster.shutdown();
  b.cluster._resetForTest();

  // Second boot, SAME vault key → reads back + agrees (DO-NOTHING fold).
  var secondBootErr = null;
  try {
    await b.cluster.init({
      nodeId:            "vk-node-B-my",
      role:              "follower",
      leaseTtl:          b.constants.TIME.seconds(30),
      heartbeatInterval: b.constants.TIME.seconds(10),
      externalDbBackend: "ops",
      dialect:           "mysql",
    });
  } catch (e) { secondBootErr = e; }
  check("vault-key (mysql): second boot with the SAME key did NOT throw " +
        "VAULT_KEY_DRIFT (canonical fingerprint read back by camelCase key + matched)",
        secondBootErr === null);
  if (secondBootErr) {
    check("VAULT-KEY (mysql) DETAIL: " + (secondBootErr.code || "") + " " +
          (secondBootErr.message || String(secondBootErr)).slice(0, 200), false);
  }

  var stillA = _mysqlRoot(
    "SELECT `recordedByNode` FROM `_blamejs_cluster_state` WHERE `scope` = 'state'", DB_NAME);
  check("vault-key (mysql): ON DUPLICATE KEY UPDATE scope=scope preserved the first recorder",
        /vk-node-A-my/.test(stillA));

  await b.cluster.shutdown();
  b.cluster._resetForTest();
  try { helpers.teardownVaultOnly(vaultDir); } catch (_e) {}
}

// ======================================================================
// 4. external-db-migrate up / down / status + advisory lock on real MySQL.
//    Same end-to-end shape as the PG file. The lock-contention recovery
//    (INSERT-conflict → holder-naming SELECT) is the contrast point:
//    MySQL does NOT abort the whole transaction on a duplicate-key error,
//    so the recovery SELECT runs and the operator gets the clean
//    "migration lock is held by <holder>" message (the PG file shows this
//    path failing on Postgres, where the conflict aborts the txn).
// ======================================================================
async function _proveExternalDbMigrate() {
  var fs   = require("node:fs");
  var os   = require("node:os");
  var path = require("node:path");

  _mysqlRoot("DROP TABLE IF EXISTS `_blamejs_externaldb_migrations`", DB_NAME);
  _mysqlRoot("DROP TABLE IF EXISTS `_blamejs_externaldb_migrations_lock`", DB_NAME);
  _mysqlRoot("DROP TABLE IF EXISTS `_blamejs_schema_version_history`", DB_NAME);
  _mysqlRoot("DROP TABLE IF EXISTS `mig_demo_widgets_my`", DB_NAME);

  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mig-my-"));
  // NOTE: the migration runner's tracking/history/lock DDL is emitted with
  // { dialect: "postgres" } inside external-db-migrate.js, but the only
  // dialect-specific token there is the BIGINT/INTEGER type, which MySQL
  // accepts. The operator migration body below uses MySQL-portable SQL.
  fs.writeFileSync(path.join(dir, "0001-create-widgets.js"),
    "module.exports = {\n" +
    "  description: 'create widgets',\n" +
    "  up:   async function (xdb) {\n" +
    "    await xdb.query('CREATE TABLE IF NOT EXISTS mig_demo_widgets_my (`id` VARCHAR(64) PRIMARY KEY, `n` BIGINT)', []);\n" +
    "  },\n" +
    "  down: async function (xdb) {\n" +
    "    await xdb.query('DROP TABLE IF EXISTS mig_demo_widgets_my', []);\n" +
    "  },\n" +
    "};\n");

  var migrate = b.externalDb.migrate.create({ dir: dir, backend: "ops", signHistory: false });

  var migrateUsable = true;
  var pre;
  try {
    pre = await migrate.status();
  } catch (e) {
    // If the runner's postgres-dialect bookkeeping DDL doesn't apply on
    // MySQL, record that as a soft finding (the migrate runner advertises
    // running against an externalDb backend, and MySQL is a declared
    // externalDb dialect) and skip the rest of this section.
    migrateUsable = false;
    _softCheck("migrate (mysql): status() runs the runner's bookkeeping DDL on MySQL " +
      "(got " + ((e && e.code) || "") + ": " + ((e && e.message) || String(e)).slice(0, 160) + ")",
      false);
  }

  if (migrateUsable) {
    check("migrate (mysql): status() before up reports the migration pending",
          pre.pending.indexOf("0001-create-widgets.js") !== -1 && pre.applied.length === 0);

    var upRes = await migrate.up();
    check("migrate (mysql): up() applied 0001-create-widgets.js",
          upRes.applied.indexOf("0001-create-widgets.js") !== -1);

    check("migrate (mysql): the migration's CREATE TABLE landed on real MySQL",
          _countMysql("information_schema.tables",
            "table_schema = '" + DB_NAME + "' AND table_name = 'mig_demo_widgets_my'") === 1);

    var trackRow = _mysqlRoot(
      "SELECT `name`,`description` FROM `_blamejs_externaldb_migrations` " +
      "WHERE `name` = '0001-create-widgets.js'", DB_NAME);
    check("migrate (mysql): tracking row recorded the applied migration",
          /0001-create-widgets\.js/.test(trackRow));

    check("migrate (mysql): advisory lock released after up() (0 lock rows remain)",
          _countMysql("`_blamejs_externaldb_migrations_lock`", null) === 0);

    var post = await migrate.status();
    check("migrate (mysql): status() after up reports it applied, none pending",
          post.applied.length === 1 && post.pending.length === 0);

    var upAgain = await migrate.up();
    check("migrate (mysql): re-running up() skips the already-applied migration",
          upAgain.skipped.indexOf("0001-create-widgets.js") !== -1 && upAgain.applied.length === 0);

    var downRes = await migrate.down({ steps: 1 });
    check("migrate (mysql): down() reverted the migration",
          downRes.reverted.indexOf("0001-create-widgets.js") !== -1);
    check("migrate (mysql): down() DROPped the migration's table",
          _countMysql("information_schema.tables",
            "table_schema = '" + DB_NAME + "' AND table_name = 'mig_demo_widgets_my'") === 0);

    // ---- lock contention (contrast vs PG): the holder-naming recovery
    //      SELECT runs because MySQL does not abort the txn on a dup-key. ----
    _mysqlRoot(
      "INSERT INTO `_blamejs_externaldb_migrations_lock` (`scope`,`lockedAt`,`lockedBy`) " +
      "VALUES ('lock'," + Date.now() + ",'other-process@host@deadbeef')", DB_NAME);
    var migrate2 = b.externalDb.migrate.create({ dir: dir, backend: "ops", signHistory: false });
    var lockErr = null;
    try { await migrate2.up(); } catch (e) { lockErr = e; }
    var lockMsg = (lockErr && lockErr.message) || "";
    console.error("[migrate-lock-contention mysql] code=" + ((lockErr && lockErr.code) || "") +
      " | message=" + lockMsg.slice(0, 220));
    check("migrate (mysql): up() threw when the advisory lock is held",
          lockErr !== null);
    check("migrate (mysql): lock-contention surfaces the operator-facing lock-held " +
          "message naming the holding process (MySQL keeps the txn alive on dup-key)",
          /lock.held|lock is held/i.test(lockMsg) && /other-process@host@deadbeef/.test(lockMsg));
    _mysqlRoot("DELETE FROM `_blamejs_externaldb_migrations_lock`", DB_NAME);
  }

  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
}

// ======================================================================
// 5. role-hardening on MySQL is a documented no-op (pg_roles is Postgres-
//    only). assertRoleHardening must SKIP cleanly with empty observed
//    lists rather than emitting MySQL-invalid SQL — the honest "no path
//    on this dialect" behavior, asserted live.
// ======================================================================
async function _proveRoleHardeningSkip() {
  var report = await b.externalDb.assertRoleHardening({
    backend:       "ops",
    declaredRoles: ["app_user"],
    mode:          "throw",   // even throw-mode must not raise on a non-PG dialect
    ignoreSystem:  true,
  });
  check("role-hardening (mysql): non-Postgres dialect skips cleanly (no observed roles)",
        Array.isArray(report.observed) && report.observed.length === 0);
  check("role-hardening (mysql): skip surfaces no unrecognized/missing under throw mode",
        report.unrecognized.length === 0);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
