"use strict";
/**
 * Live PG coverage for the b.sql-migrated cluster data layer — the parts
 * that ONLY ran on sqlite host smoke before this file: cluster-storage
 * coercion, pubsub-cluster publish/poll/prune, the cluster vault-key-
 * consistency upsert, external-db-migrate up/down/status+lock, and the
 * external-db pg_roles hardening scan. Each path is driven END-TO-END
 * against real Postgres and the row / side-effect is asserted, with
 * COERCION asserted on the real backend (node-postgres returns BIGINT as
 * a JS STRING; the framework's coerceRow normalizes it back to a number).
 *
 * The "driver" is a persistent docker-exec psql shim that reproduces a
 * real node-postgres driver's surface EXACTLY (the property the test
 * leans on):
 *   - column identifiers come back verbatim as Postgres reports them —
 *     case-PRESERVED for the quoted camelCase the framework DDL + b.sql
 *     emit (so `publishedBy` / `vaultKeyFp` survive, not folded to
 *     `publishedby` / `vaultkeyfp`),
 *   - BIGINT (int8) comes back as a JS STRING (the precision-safe
 *     node-postgres default) — coerceRow's job is to turn the framework
 *     int columns back into numbers,
 *   - SQL travels on stdin, never argv (no shell parsing of SQL).
 *
 * RUN: node scripts/test-integration.js --skip-service-check data-layer-cluster-pg
 */

var spawn        = require("node:child_process").spawn;
var execFileSync = require("node:child_process").execFileSync;
var helpers  = require("../helpers");
var check    = helpers.check;
var services = require("../helpers/services");
var b = require("../../");

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
    // Header row first — column names AS POSTGRES REPORTS THEM. The
    // framework DDL + b.sql quote every identifier, so the camelCase is
    // case-PRESERVED here, exactly as node-postgres keys the row object.
    var headers = dataLines[0].split("\t");
    for (var k = 1; k < dataLines.length; k++) {
      var cells = dataLines[k].split("\t");
      var row = {};
      for (var c = 0; c < headers.length; c++) {
        var cell = cells[c];
        // Every non-null cell is a STRING — including BIGINT columns,
        // mirroring node-postgres's int8-as-string default. The
        // framework's coerceRow is what turns the int framework columns
        // back into JS numbers; leaving them as strings here is the
        // faithful pre-coercion shape.
        row[headers[c]] = (cell === NULL_SENTINEL || cell === undefined) ? null : cell;
      }
      rows.push(row);
    }
  }
  var rowCount = (affected !== null) ? affected : rows.length;
  return { rows: rows, rowCount: rowCount, error: null };
}

// Tables this file owns, dropped in setup + teardown.
var OWNED_TABLES = [
  "_blamejs_pubsub_messages",
  "_blamejs_cluster_state",
  "_blamejs_leader",
  "_blamejs_externaldb_migrations",
  "_blamejs_externaldb_migrations_lock",
  "_blamejs_schema_version_history",
];

function _dropOwned() {
  _psql(OWNED_TABLES.map(function (t) {
    return "DROP TABLE IF EXISTS " + t + " CASCADE;";
  }).join("\n"));
}

// Soft findings — a recorded lib-bug surfaced live that must NOT halt the
// rest of the suite (the remaining sections are independent coverage). Each
// is printed at the end and makes the file exit non-zero, so the release
// gate still fails until the bug is fixed.
var _softFindings = [];
function _softCheck(label, ok) {
  if (ok) { check(label, true); return; }
  _softFindings.push(label);
  console.error("[SOFT-FAIL] " + label);
}

async function run() {
  var pg = await services.requireService("postgres");
  if (!pg.ok) throw new Error("postgres unreachable: " + pg.reason);

  _dropOwned();

  var driver = _makeDockerPgDriver();
  b.cluster._resetForTest();
  b.externalDb._resetForTest();
  b.externalDb.init({
    backends: {
      ops: {
        connect: driver.connect, query: driver.query, close: driver.close,
        dialect: "postgres",
      },
    },
  });

  try {
    await _proveClusterStorageCoercion();
    await _provePubsubCluster();
    await _proveVaultKeyConsistency();
    await _proveExternalDbMigrate();
    await _proveRoleHardening();
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) {}
    b.cluster._resetForTest();
    try { await b.externalDb.shutdown(); } catch (_e) {}
    _dropOwned();
  }

  // Surface any recorded soft findings as a hard suite failure so the
  // release gate stays red until the live-surfaced lib bug is fixed.
  if (_softFindings.length > 0) {
    throw new Error("data-layer-cluster-pg: " + _softFindings.length +
      " live-surfaced lib bug(s):\n  - " + _softFindings.join("\n  - "));
  }
}

// ======================================================================
// 1. cluster-storage coercion on real PG. b.clusterStorage.execute runs
//    framework-state SQL against the external DB in cluster mode, then
//    coerceRows-normalizes the driver-native shape (node-pg BIGINT→string)
//    back to the framework's canonical JS type. Drive a real round-trip
//    through a framework table (the pubsub fan-out table — BIGSERIAL id +
//    BIGINT publishedAt are the int columns) and assert the readback is a
//    JS NUMBER, not the string a raw node-pg driver would hand back.
// ======================================================================
async function _proveClusterStorageCoercion() {
  // cluster.init wires isClusterMode()→true so clusterStorage routes to PG.
  await b.cluster.init({
    nodeId:            "cs-node",
    role:              "leader",
    leaseTtl:          b.constants.TIME.seconds(30),
    heartbeatInterval: b.constants.TIME.seconds(10),
    externalDbBackend: "ops",
    dialect:           "postgres",
  });
  check("cluster-storage: cluster mode routes framework state to PG",
        b.cluster.isClusterMode() === true);

  // The pubsub fan-out table is created by the framework DDL with QUOTED
  // (case-preserving) camelCase columns. Emit the canonical quoted DDL
  // (mirrors framework-schema _pubsubMessagesDDL for postgres) so the
  // columns read back case-preserved exactly like the shipped DDL.
  _psql(
    'CREATE TABLE IF NOT EXISTS _blamejs_pubsub_messages (' +
    '  "id"          BIGSERIAL PRIMARY KEY,' +
    '  "topic"       TEXT NOT NULL,' +
    '  "payload"     TEXT NOT NULL,' +
    '  "publishedAt" BIGINT NOT NULL,' +
    '  "publishedBy" TEXT NOT NULL' +
    ')');

  // INSERT through clusterStorage.execute (the path the framework uses).
  var bigAt = 1700000000000;   // > 2^31, exercises BIGINT not INT
  var insRes = await b.clusterStorage.execute(
    'INSERT INTO _blamejs_pubsub_messages ("topic","payload","publishedAt","publishedBy") ' +
    'VALUES (?, ?, ?, ?)',
    ["coerce-topic", '{"k":1}', bigAt, "cs-node"]);
  check("cluster-storage: INSERT through execute() affected 1 row on real PG",
        insRes.rowCount === 1);

  // Read it back through executeOne — coerceRows runs here.
  var row = await b.clusterStorage.executeOne(
    'SELECT "id","topic","payload","publishedAt","publishedBy" ' +
    'FROM _blamejs_pubsub_messages WHERE "publishedBy" = ?',
    ["cs-node"]);
  check("cluster-storage: round-tripped the row by case-preserved camelCase key",
        row !== null && row.publishedBy === "cs-node" && row.topic === "coerce-topic");
  // COERCION: BIGINT publishedAt + BIGSERIAL id come back as JS NUMBERS,
  // not the decimal strings a raw node-pg driver hands over.
  check("cluster-storage COERCION: BIGINT publishedAt coerced string→number",
        typeof row.publishedAt === "number" && row.publishedAt === bigAt);
  check("cluster-storage COERCION: BIGSERIAL id coerced string→number",
        typeof row.id === "number" && row.id >= 1);
  // text columns pass through unchanged.
  check("cluster-storage COERCION: text payload left as the string it is",
        typeof row.payload === "string" && row.payload === '{"k":1}');

  await b.cluster.shutdown();
  b.cluster._resetForTest();
}

// ======================================================================
// 2. pubsub-cluster publish / poll / prune on real PG. The polling backend
//    reads rows back by camelCase keys (row.publishedBy / row.publishedAt /
//    row.id / row.topic / row.payload); on real PG those only resolve if
//    the DDL + b.sql kept the identifiers case-preserved. Drive a publish
//    from one "node" and a poll-dispatch on another, asserting the remote
//    row is delivered with the right topic + payload + publishedAt (as a
//    NUMBER), then prove the prune DELETE removes an expired row.
// ======================================================================
async function _provePubsubCluster() {
  // Fresh table (the coercion section left a row in it).
  _psql("DROP TABLE IF EXISTS _blamejs_pubsub_messages CASCADE;");
  _psql(
    'CREATE TABLE IF NOT EXISTS _blamejs_pubsub_messages (' +
    '  "id"          BIGSERIAL PRIMARY KEY,' +
    '  "topic"       TEXT NOT NULL,' +
    '  "payload"     TEXT NOT NULL,' +
    '  "publishedAt" BIGINT NOT NULL,' +
    '  "publishedBy" TEXT NOT NULL' +
    ')');

  // Cluster mode again so pubsub-cluster's clusterStorage.execute hits PG.
  await b.cluster.init({
    nodeId:            "node-pub",
    role:              "leader",
    leaseTtl:          b.constants.TIME.seconds(30),
    heartbeatInterval: b.constants.TIME.seconds(10),
    externalDbBackend: "ops",
    dialect:           "postgres",
  });

  var clusterClusterBackend = require("../../lib/pubsub-cluster");

  // Publisher "node" view + subscriber "node" view — distinct nodeIds so
  // the poll's `publishedBy <> nodeId` self-skip is what filters, exactly
  // like a real two-node deploy.
  var pubView = { currentNodeId: function () { return "node-pub"; } };
  var subView = { currentNodeId: function () { return "node-sub"; } };

  var publisher = clusterClusterBackend.create({
    cluster: pubView, pollIntervalMs: 25, retentionMs: b.constants.TIME.minutes(1),
  });
  var subscriber = clusterClusterBackend.create({
    cluster: subView, pollIntervalMs: 25, retentionMs: b.constants.TIME.minutes(1),
  });

  // publishRemote writes a row (publishedBy=node-pub). Returns { remote: 1 }.
  var pr = await publisher.publishRemote("orders:created", { orderId: "o-7", amount: 42 });
  check("pubsub-cluster: publishRemote reports remote:1", pr && pr.remote === 1);

  // The row physically landed on the server with the right shape.
  var landed = _psql(
    'SELECT "topic","publishedBy" FROM _blamejs_pubsub_messages ' +
    'WHERE "topic" = \'orders:created\';');
  check("pubsub-cluster: publish row physically present on real PG",
        /orders:created/.test(landed) && /node-pub/.test(landed));

  // Subscriber polls: first poll primes lastSeenId to MAX(id); subsequent
  // polls dispatch rows past it from OTHER nodes. Start the poll loop and
  // assert the remote message is delivered with the camelCase metadata.
  var received = [];
  subscriber.start(function (topic, payload, meta) {
    received.push({ topic: topic, payload: payload, meta: meta });
  });

  // The first poll primes (no dispatch); publish a SECOND row AFTER priming
  // so it has an id strictly greater than the primed lastSeenId and gets
  // dispatched. Poll until the subscriber observes it.
  await helpers.waitUntil(function () {
    // Re-publish on each tick until the subscriber's loop has primed and
    // then delivered. Cheap + deterministic: once primed, the next new row
    // (id > lastSeen, publishedBy != node-sub) dispatches.
    return received.length >= 1;
  }, {
    timeoutMs: 15000,
    label: "pubsub-cluster: subscriber dispatched the first remote row",
  }).catch(function () { /* fall through to a publish-then-wait retry below */ });

  if (received.length === 0) {
    // Priming consumed the only row; publish a fresh one strictly after the
    // prime and wait for delivery.
    await publisher.publishRemote("orders:created", { orderId: "o-8", amount: 99 });
    await helpers.waitUntil(function () { return received.length >= 1; }, {
      timeoutMs: 15000,
      label: "pubsub-cluster: subscriber dispatched a post-prime remote row",
    });
  }

  var first = received[0];
  check("pubsub-cluster: subscriber received the remote topic verbatim",
        first.topic === "orders:created");
  check("pubsub-cluster: subscriber received the remote payload (JSON string)",
        typeof first.payload === "string" && /"orderId"/.test(first.payload));
  // The poll reads row.publishedBy / row.publishedAt by camelCase key; meta
  // surfaces them. publishedAt is coerced to a NUMBER (Number(row.publishedAt)
  // in pubsub-cluster, atop coerceRows).
  check("pubsub-cluster: meta.publishedBy is the PUBLISHER node (not the subscriber)",
        first.meta && first.meta.publishedBy === "node-pub");
  check("pubsub-cluster COERCION: meta.publishedAt resolved to a finite number",
        typeof first.meta.publishedAt === "number" && isFinite(first.meta.publishedAt));

  subscriber.stop();
  publisher.stop();

  // ---- prune ----
  // Insert a deliberately-expired row (publishedAt far in the past) and an
  // un-expired row, then drive a poll with pruneEveryMs=1 so the prune fires
  // on the first tick (lastPruneAt starts at 0, so Date.now()-0 >= 1) and
  // DELETEs only the expired one. retentionMs=1ms so "now - 1ms" is the
  // cutoff — the past row is older than that, the fresh row is not.
  _psql("DELETE FROM _blamejs_pubsub_messages;");
  _psql(
    'INSERT INTO _blamejs_pubsub_messages ("topic","payload","publishedAt","publishedBy") ' +
    "VALUES ('expired','{}',1,'node-other'), " +
    "('fresh','{}'," + (Date.now() + 60000) + ",'node-other');");

  var pruner = clusterClusterBackend.create({
    cluster: subView, pollIntervalMs: 25, retentionMs: 1, pruneEveryMs: 1,
  });
  var pruneSeen = [];
  pruner.start(function (topic) { pruneSeen.push(topic); });
  // Wait until the expired row is gone (the prune DELETE landed) while the
  // fresh row survives. Poll the server directly.
  await helpers.waitUntil(function () {
    var n = _psql("SELECT count(*) AS n FROM _blamejs_pubsub_messages WHERE \"topic\" = 'expired';");
    return /^0$/m.test(n.trim());
  }, { timeoutMs: 15000, label: "pubsub-cluster: prune DELETE removed the expired row" });
  var freshLeft = _psql("SELECT count(*) AS n FROM _blamejs_pubsub_messages WHERE \"topic\" = 'fresh';");
  check("pubsub-cluster: prune removed the expired row", true);
  check("pubsub-cluster: prune left the un-expired row intact",
        /^1$/m.test(freshLeft.trim()));
  pruner.stop();

  await b.cluster.shutdown();
  b.cluster._resetForTest();
}

// ======================================================================
// 3. cluster vault-key-consistency upsert on real PG. cluster.init runs
//    _checkVaultKeyConsistency: an INSERT ... ON CONFLICT (scope) DO
//    NOTHING into _blamejs_cluster_state, then a SELECT reading
//    vaultKeyFp / recordedByNode / recordedAt / rotationEpoch back by
//    camelCase key. The whole path only works if the quoted DDL + b.sql
//    keep those identifiers case-preserved on real PG — a fold-to-lower
//    would make canonical.vaultKeyFp read undefined and either FATAL
//    (mismatch vs the local fingerprint) or silently mis-handle rotation.
//    Prove: first boot RECORDS this node's fingerprint, a second boot with
//    the SAME vault key reads it back and AGREES (no VAULT_KEY_DRIFT).
// ======================================================================
async function _proveVaultKeyConsistency() {
  var fs   = require("node:fs");
  var os   = require("node:os");
  var path = require("node:path");
  // The consistency check needs a real vault (it fingerprints the vault
  // public keys). setupVaultOnly stands one up without the full db; it
  // takes the data dir the keypair persists to.
  var vaultDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vk-pg-"));
  await helpers.setupVaultOnly(vaultDir);

  // Fresh coordination + leader tables. The provider's ensureSchema creates
  // them; drop first so the first boot is genuinely a first boot.
  _psql([
    "DROP TABLE IF EXISTS _blamejs_cluster_state CASCADE;",
    "DROP TABLE IF EXISTS _blamejs_leader CASCADE;",
  ].join("\n"));

  // ---- first boot: records this node's vault-key fingerprint ----
  await b.cluster.init({
    nodeId:            "vk-node-A",
    role:              "leader",
    leaseTtl:          b.constants.TIME.seconds(30),
    heartbeatInterval: b.constants.TIME.seconds(10),
    externalDbBackend: "ops",
    dialect:           "postgres",
  });
  check("vault-key: first boot completed (recorded fingerprint, no drift)", true);

  // The cluster-state row physically carries THIS node as recorder + a
  // 128-hex fingerprint under the case-preserved camelCase columns.
  var stateRow = _psql(
    'SELECT "vaultKeyFp","recordedByNode" FROM _blamejs_cluster_state ' +
    "WHERE \"scope\" = 'state';");
  check("vault-key: cluster-state row recorded by this node on real PG",
        /vk-node-A/.test(stateRow));
  check("vault-key: recorded fingerprint is a 128-hex SHA3-512 digest",
        /\b[0-9a-f]{128}\b/.test(stateRow));

  await b.cluster.shutdown();
  b.cluster._resetForTest();

  // ---- second boot: SAME vault key → reads back + AGREES (no drift) ----
  // The cluster-state row persists (not dropped). A second node booting with
  // the same vault key reads the canonical fingerprint via the camelCase
  // SELECT and finds it equals its own → no VAULT_KEY_DRIFT throw.
  var secondBootErr = null;
  try {
    await b.cluster.init({
      nodeId:            "vk-node-B",
      role:              "follower",   // follower still runs the consistency check
      leaseTtl:          b.constants.TIME.seconds(30),
      heartbeatInterval: b.constants.TIME.seconds(10),
      externalDbBackend: "ops",
      dialect:           "postgres",
    });
  } catch (e) { secondBootErr = e; }
  check("vault-key: second boot with the SAME key did NOT throw VAULT_KEY_DRIFT " +
        "(canonical fingerprint read back by camelCase key + matched)",
        secondBootErr === null);
  if (secondBootErr) {
    check("VAULT-KEY DETAIL: " + (secondBootErr.code || "") + " " +
          (secondBootErr.message || String(secondBootErr)).slice(0, 200), false);
  }

  // The canonical recorder is STILL node-A (DO NOTHING preserved the first
  // writer; node-B read + agreed rather than overwriting). Confirms the
  // ON CONFLICT DO NOTHING upsert behaved, and the read resolved.
  var stillA = _psql(
    'SELECT "recordedByNode" FROM _blamejs_cluster_state WHERE "scope" = \'state\';');
  check("vault-key: ON CONFLICT DO NOTHING preserved the first recorder (node-A)",
        /vk-node-A/.test(stillA));

  await b.cluster.shutdown();
  b.cluster._resetForTest();

  try { helpers.teardownVaultOnly(vaultDir); } catch (_e) {}
}

// ======================================================================
// 4. external-db-migrate up / down / status + the advisory lock on real
//    PG. Build a migrate runner over a temp migrations dir, run up() (which
//    runs each migration inside externalDb.transaction, records tracking +
//    signed history rows, and holds the single-row advisory lock), assert
//    the migration's table landed + the tracking/history rows are present,
//    then status() and down() and assert the rollback removed the table +
//    the tracking row.
// ======================================================================
async function _proveExternalDbMigrate() {
  var fs   = require("node:fs");
  var os   = require("node:os");
  var path = require("node:path");

  // Fresh runner bookkeeping tables.
  _psql([
    "DROP TABLE IF EXISTS _blamejs_externaldb_migrations CASCADE;",
    "DROP TABLE IF EXISTS _blamejs_externaldb_migrations_lock CASCADE;",
    "DROP TABLE IF EXISTS _blamejs_schema_version_history CASCADE;",
    "DROP TABLE IF EXISTS mig_demo_widgets CASCADE;",
  ].join("\n"));

  // Operator migration dir with one migration that CREATEs + DROPs a table.
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mig-pg-"));
  fs.writeFileSync(path.join(dir, "0001-create-widgets.js"),
    "module.exports = {\n" +
    "  description: 'create widgets',\n" +
    "  up:   async function (xdb) {\n" +
    "    await xdb.query('CREATE TABLE IF NOT EXISTS mig_demo_widgets (\"id\" TEXT PRIMARY KEY, \"n\" BIGINT)', []);\n" +
    "  },\n" +
    "  down: async function (xdb) {\n" +
    "    await xdb.query('DROP TABLE IF EXISTS mig_demo_widgets', []);\n" +
    "  },\n" +
    "};\n");

  var migrate = b.externalDb.migrate.create({
    dir: dir, backend: "ops", signHistory: false,
  });

  // ---- status() before up: 1 pending, 0 applied ----
  var pre = await migrate.status();
  check("migrate: status() before up reports the migration pending",
        pre.pending.indexOf("0001-create-widgets.js") !== -1 && pre.applied.length === 0);

  // ---- up(): applies the migration + records tracking row ----
  var upRes = await migrate.up();
  check("migrate: up() applied 0001-create-widgets.js",
        upRes.applied.indexOf("0001-create-widgets.js") !== -1);

  // The migration's table physically landed on real PG.
  var tblOk = _psql(
    "SELECT count(*) AS n FROM information_schema.tables " +
    "WHERE table_name = 'mig_demo_widgets';");
  check("migrate: the migration's CREATE TABLE landed on real PG",
        /^1$/m.test(tblOk.trim()));

  // The tracking row is present (case-preserved camelCase columns).
  var trackRow = _psql(
    'SELECT "name","description" FROM _blamejs_externaldb_migrations ' +
    "WHERE \"name\" = '0001-create-widgets.js';");
  check("migrate: tracking row recorded the applied migration on real PG",
        /0001-create-widgets\.js/.test(trackRow) && /create widgets/.test(trackRow));

  // The advisory lock table exists and the lock was RELEASED after up()
  // (the finally block deletes the holder's row).
  var lockCount = _psql("SELECT count(*) AS n FROM _blamejs_externaldb_migrations_lock;");
  check("migrate: advisory lock released after up() (0 lock rows remain)",
        /^0$/m.test(lockCount.trim()));

  // status() after up: 0 pending, 1 applied.
  var post = await migrate.status();
  check("migrate: status() after up reports it applied, none pending",
        post.applied.length === 1 && post.pending.length === 0 &&
        post.applied[0].name === "0001-create-widgets.js");

  // Re-running up() is idempotent: the already-applied migration is skipped.
  var upAgain = await migrate.up();
  check("migrate: re-running up() skips the already-applied migration",
        upAgain.skipped.indexOf("0001-create-widgets.js") !== -1 &&
        upAgain.applied.length === 0);

  // ---- down(): rolls back, drops the table, removes the tracking row ----
  var downRes = await migrate.down({ steps: 1 });
  check("migrate: down() reverted the migration",
        downRes.reverted.indexOf("0001-create-widgets.js") !== -1);
  var tblGone = _psql(
    "SELECT count(*) AS n FROM information_schema.tables " +
    "WHERE table_name = 'mig_demo_widgets';");
  check("migrate: down() DROPped the migration's table on real PG",
        /^0$/m.test(tblGone.trim()));
  var trackGone = _psql(
    "SELECT count(*) AS n FROM _blamejs_externaldb_migrations " +
    "WHERE \"name\" = '0001-create-widgets.js';");
  check("migrate: down() removed the tracking row",
        /^0$/m.test(trackGone.trim()));

  // ---- lock contention: a held lock blocks a second acquire ----
  // Manually plant a lock row (a different holder), then run up() — it must
  // refuse with the OPERATOR-FACING lock-held error ("migration lock is held
  // by <holder>") rather than running migrations OR surfacing a raw Postgres
  // SQLSTATE. _acquireLock acquires with `INSERT ... ON CONFLICT (scope) DO
  // NOTHING` so the PK conflict is a 0-row no-op rather than a 23505 that
  // would ABORT the surrounding transaction (SQLSTATE 25P02). Because the
  // transaction is NOT aborted, the holder-naming SELECT runs cleanly and
  // the operator gets the clear "migration lock is held by <holder>" message.
  _psql(
    'INSERT INTO _blamejs_externaldb_migrations_lock ("scope","lockedAt","lockedBy") ' +
    "VALUES ('lock'," + Date.now() + ",'other-process@host@deadbeef');");
  // Re-apply the migration so there is pending work the lock would gate.
  var migrate2 = b.externalDb.migrate.create({ dir: dir, backend: "ops", signHistory: false });
  var lockErr = null;
  try { await migrate2.up(); } catch (e) { lockErr = e; }
  var lockMsg = (lockErr && lockErr.message) || "";
  var lockCode = (lockErr && lockErr.code) || "";
  // Always surface the captured lock error so the evidence is in the run log.
  console.error("[migrate-lock-contention] code=" + lockCode +
    " | message=" + lockMsg.slice(0, 220));
  check("migrate: up() threw when the advisory lock is held (did not run migrations)",
        lockErr !== null);
  check("migrate: lock-contention surfaces the operator-facing lock-held " +
        "message naming the holding process — NOT a raw Postgres " +
        "aborted-transaction error (got code=" + lockCode + ")",
        /lock.held|lock is held/i.test(lockMsg) &&
        /other-process@host@deadbeef/.test(lockMsg));
  // Clean the planted lock (DELETE direct via psql — the lib may have left
  // the connection's view aborted, but psql is a fresh session).
  _psql("DELETE FROM _blamejs_externaldb_migrations_lock;");

  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
}

// ======================================================================
// 5. external-db pg_roles hardening scan on real PG. assertRoleHardening
//    SELECTs rolname from the live pg_roles catalog through b.sql and
//    compares to an operator allowlist. Prove: (a) a declaredRoles list
//    that omits a real, freshly-created role surfaces it as unrecognized
//    in audit mode, and (b) mode:"throw" raises ROLE_HARDENING_FAIL for
//    that same unrecognized role. The scan reads the REAL system catalog,
//    so this is a genuine live read, not a fixture.
// ======================================================================
async function _proveRoleHardening() {
  // Create a recognizable test role on the server so the scan has a known
  // non-system name to classify.
  _psql("DROP ROLE IF EXISTS blamejs_harden_probe;");
  _psql("CREATE ROLE blamejs_harden_probe NOLOGIN;");

  // ---- audit mode: the probe role is unrecognized (not in the allowlist) ----
  var report = await b.externalDb.assertRoleHardening({
    backend:       "ops",
    declaredRoles: ["blamejs"],   // the app role; NOT the probe
    mode:          "audit",
    ignoreSystem:  true,
  });
  check("role-hardening: scan read pg_roles and observed the live app role",
        report.observed.indexOf("blamejs") !== -1);
  check("role-hardening: the freshly-created probe role surfaces as unrecognized",
        report.unrecognized.indexOf("blamejs_harden_probe") !== -1);
  check("role-hardening: system roles (postgres / pg_*) are filtered by ignoreSystem",
        report.observed.indexOf("postgres") === -1 &&
        report.observed.every(function (n) { return n.indexOf("pg_") !== 0; }));

  // ---- declaredRoles that includes the probe → it is no longer unrecognized ----
  var clean = await b.externalDb.assertRoleHardening({
    backend:       "ops",
    declaredRoles: ["blamejs", "blamejs_harden_probe"],
    mode:          "audit",
    ignoreSystem:  true,
  });
  check("role-hardening: declaring the probe clears it from unrecognized",
        clean.unrecognized.indexOf("blamejs_harden_probe") === -1);

  // ---- throw mode: an unrecognized role fails closed ----
  var threw = null;
  try {
    await b.externalDb.assertRoleHardening({
      backend:       "ops",
      declaredRoles: ["blamejs"],
      mode:          "throw",
      ignoreSystem:  true,
    });
  } catch (e) { threw = e; }
  check("role-hardening: mode:'throw' raises ROLE_HARDENING_FAIL on an unrecognized role",
        threw !== null && threw.code === "ROLE_HARDENING_FAIL");

  _psql("DROP ROLE IF EXISTS blamejs_harden_probe;");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
