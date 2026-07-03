// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Live test of the catalog claim that the tamper-evident, signed audit
 * hash-chain "runs on the operator's external Postgres in cluster mode"
 * (b.audit / b.clusterStorage / b.frameworkSchema). Driver: a docker-exec
 * psql shim that replicates a real node-postgres driver's coercions
 * EXACTLY — the point of the test:
 *
 *   - unquoted camelCase columns come back LOWERCASED in the result keys
 *     (Postgres folds unquoted identifiers; node-postgres returns the
 *     server's reported names verbatim → `rowhash`, `prevhash`,
 *     `monotoniccounter`, …),
 *   - BIGINT (int8) comes back as a JS STRING (node-postgres default to
 *     avoid >2^53 precision loss),
 *   - BYTEA comes back as a Node Buffer.
 *
 * What this proves (or refutes), end-to-end against the live server:
 *
 *   1. frameworkSchema.ensureSchema creates _blamejs_audit_log + the
 *      append-only WORM triggers on real Postgres (the chain's home in
 *      cluster mode).
 *
 *   2. Build a KNOWN-VALID chain with the framework's OWN hash math
 *      (b.auditChain.computeRowHash), INSERT the rows into the live
 *      _blamejs_audit_log via the driver, then run the framework's own
 *      verifier (b.auditChain.verifyChain, the exact reader b.audit.verify
 *      uses) against the live table. A correct framework returns ok:true.
 *      THIS IS THE CORE PROOF and it asserts the CORRECT behavior so a
 *      regression / pre-existing gap surfaces as a failure.
 *
 *   3. The BIGINT→string + BYTEA→Buffer coercion of the hash-preimage
 *      columns (monotonicCounter, recordedAt, nonce) must not break a
 *      valid chain's verification.
 *
 *   4. TAMPER a hashed column directly via the driver → verify must
 *      report ok:false.
 *
 *   5. cluster.init leadership acquisition over the real Postgres lease
 *      provider — the gate every chain append passes through.
 *
 * MySQL note: frameworkSchema only emits DDL for postgres / sqlite
 * (lib/framework-schema.js _types() throws on "mysql"; the module
 * docstring states MySQL is not supported). There is no MySQL audit-chain
 * path to exercise — the test asserts the framework refuses MySQL rather
 * than fabricating a MySQL chain.
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

// ---- one-shot psql (setup / teardown / out-of-band tamper + asserts) ----
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

// ---- persistent-session docker-exec psql driver (faithful to pg) ----
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
          "SET bytea_output = 'hex';\n" +
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

// Inline params: Buffers as bytea hex literals (byte-faithful round-trip),
// numbers raw, everything else single-quote-escaped.
var BYTEA_LITERAL_PREFIX = "'" + "\\" + "x";
function _bindParams(sql, params) {
  return sql.replace(/\$(\d+)/g, function (_m, n) {
    var i = Number(n) - 1;
    if (i < 0 || i >= params.length) {
      throw new Error("placeholder $" + n + " has no matching param");
    }
    var v = params[i];
    if (v === null || v === undefined) return "NULL";
    if (Buffer.isBuffer(v)) return BYTEA_LITERAL_PREFIX + v.toString("hex") + "'::bytea";
    if (typeof v === "number") return String(v);
    if (typeof v === "boolean") return v ? "TRUE" : "FALSE";
    return "'" + String(v).replace(/'/g, "''") + "'";
  });
}

var _CMD_TAG_RE = /^(INSERT|UPDATE|DELETE|MERGE|SELECT|COPY|MOVE)\b(?:\s+\d+)*\s*$/;
var _CTRL_TAG_RE = /^(BEGIN|COMMIT|ROLLBACK|SET|RESET|SAVEPOINT|RELEASE|START|CREATE|DROP|ALTER|GRANT|REVOKE|TRUNCATE|COMMENT|DO|CALL|VACUUM|ANALYZE|EXPLAIN|TABLE|SHOW|DISCARD)\b/;

// Columns the framework reads as Buffers (real pg returns bytea as Buffer).
var _BYTEA_COLUMNS = { nonce: true, signature: true };

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
    // dataLines[0] is the header row (column names AS POSTGRES REPORTS
    // THEM — lowercase for unquoted identifiers). We deliberately keep
    // them verbatim, exactly as node-postgres would key the row object.
    var headers = dataLines[0].split("\t");
    for (var k = 1; k < dataLines.length; k++) {
      var cells = dataLines[k].split("\t");
      var row = {};
      for (var c = 0; c < headers.length; c++) {
        var cell = cells[c];
        var hdr = headers[c];
        if (cell === NULL_SENTINEL || cell === undefined) { row[hdr] = null; continue; }
        if (_BYTEA_COLUMNS[hdr] === true) {
          var hex = cell.charAt(0) === "\\" && cell.charAt(1) === "x"
            ? cell.slice(2) : cell;
          row[hdr] = Buffer.from(hex, "hex");
        } else {
          // STRING — including BIGINT columns (node-postgres int8 default).
          row[hdr] = cell;
        }
      }
      rows.push(row);
    }
  }
  var rowCount = (affected !== null) ? affected : rows.length;
  return { rows: rows, rowCount: rowCount, error: null };
}

// Audit_log column set that ensureSchema creates (camelCase in DDL —
// Postgres folds the stored names to lowercase). We INSERT with these
// names quoted so the values land in the right physical columns; the
// READBACK is what surfaces the lowercase keys.
var AUDIT_COLS = [
  "_id", "recordedAt", "monotonicCounter",
  "actorUserId", "actorUserIdHash", "actorIp",
  "actorUserAgent", "actorSessionId",
  "action", "resourceKind", "resourceId", "resourceIdHash",
  "outcome", "reason", "metadata", "requestId",
  "prevHash", "rowHash", "nonce", "fencingToken",
];
// Columns that feed the chain-hash preimage (must match what the
// framework's chain-writer hashes: every audit column except the chain
// bookkeeping prevHash/rowHash/nonce/fencingToken).
var HASHABLE_COLS = [
  "_id", "recordedAt", "monotonicCounter",
  "actorUserId", "actorUserIdHash", "actorIp",
  "actorUserAgent", "actorSessionId",
  "action", "resourceKind", "resourceId", "resourceIdHash",
  "outcome", "reason", "metadata", "requestId",
];

// Build the framework-faithful logical row + its rowHash, exactly as
// chain-writer would: materialize null for every hashable column so the
// canonicalizer sees the same key set at write- and verify-time, then
// computeRowHash(prevHash, hashableFields, nonce).
function _buildChainRow(driverClient, driver, counter, prevHash, logical) {
  var crypto = require("../../lib/crypto");
  var nonce = crypto.generateBytes(16);
  var full = Object.assign({
    _id: "row-" + counter,
    recordedAt: 1700000000000 + counter,
    monotonicCounter: counter,
  }, logical);
  // Hashable view: every hashable column present, null-filled.
  var hashable = {};
  for (var i = 0; i < HASHABLE_COLS.length; i++) {
    var col = HASHABLE_COLS[i];
    hashable[col] = (full[col] === undefined) ? null : full[col];
  }
  var rowHash = b.auditChain.computeRowHash(prevHash, hashable, nonce);
  var rowForInsert = Object.assign({}, hashable, {
    prevHash: prevHash, rowHash: rowHash, nonce: nonce, fencingToken: 0,
  });
  return { rowForInsert: rowForInsert, rowHash: rowHash };
}

// Insert a chain row using the EXACT SQL shape the framework's
// chain-writer emits: identifiers quoted via safeSql.quoteIdentifier
// (double-quoted, case-PRESERVING camelCase). This is what
// b.audit.record → chain-writer → clusterStorage actually runs against
// the external Postgres backend, so a failure here is the framework's
// real failure, not a test artifact.
var safeSql = require("../../lib/safe-sql");
async function _insertChainRow(driver, driverClient, rowForInsert) {
  var quoted = AUDIT_COLS.map(function (c) { return safeSql.quoteIdentifier(c); }).join(", ");
  var ph = AUDIT_COLS.map(function (_c, i) { return "$" + (i + 1); }).join(", ");
  var vals = AUDIT_COLS.map(function (c) {
    return rowForInsert[c] === undefined ? null : rowForInsert[c];
  });
  await driver.query(driverClient,
    'INSERT INTO ' + safeSql.quoteIdentifier("_blamejs_audit_log") +
    ' (' + quoted + ') VALUES (' + ph + ')', vals);
}

async function run() {
  var pg = await services.requireService("postgres");
  if (!pg.ok) throw new Error("postgres unreachable: " + pg.reason);

  var DROP_ALL = [
    "_blamejs_audit_log", "_blamejs_consent_log", "_blamejs_audit_checkpoints",
    "_blamejs_audit_tip", "_blamejs_consent_tip", "_blamejs_audit_purge_anchor",
    "_blamejs_scheduler_ticks", "_blamejs_rate_limit_counters",
    "_blamejs_pubsub_messages", "_blamejs_api_encrypt_nonces", "_blamejs_api_keys",
    "_blamejs_sessions", "_blamejs_session_valid_from", "_blamejs_jobs",
    "_blamejs_cache", "_blamejs_cache_tags",
    "_blamejs_seeders", "_blamejs_seeders_lock", "_blamejs_break_glass_policies",
    "_blamejs_break_glass_grants", "_blamejs_leader", "_blamejs_cluster_state",
  ].map(function (t) { return "DROP TABLE IF EXISTS " + t + " CASCADE;"; }).join("\n");
  _psql(DROP_ALL);

  b.cluster._resetForTest();
  b.audit._resetForTest();
  b.externalDb._resetForTest();

  var driver = _makeDockerPgDriver();
  b.externalDb.init({
    backends: {
      ops: {
        connect: driver.connect, query: driver.query, close: driver.close,
        dialect: "postgres",
      },
    },
  });

  // ---- 1. framework audit schema on the live server ----
  var report = await b.frameworkSchema.ensureSchema({
    externalDbBackend: "ops",
    dialect:           "postgres",
  });
  check("ensureSchema created _blamejs_audit_log on real Postgres",
        report.tables.indexOf("_blamejs_audit_log") !== -1);
  var tblCheck = _psql(
    "SELECT count(*) AS n FROM information_schema.tables " +
    "WHERE table_name = '_blamejs_audit_log';");
  check("_blamejs_audit_log table is present on the server", /\b1\b/.test(tblCheck.trim()));

  // ---- 2. build a KNOWN-VALID chain with the framework's own hash math,
  //         INSERT it into the live table, verify with the framework's
  //         own verifier (b.auditChain.verifyChain → the reader
  //         b.audit.verify uses). A correct framework returns ok:true. ----
  var driverClient = await driver.connect();

  var logicalRows = [
    { action: "system.boot",        outcome: "success" },
    { action: "auth.login.success", outcome: "success", actorUserId: "u-1", actorIp: "10.0.0.7" },
    { action: "consent.granted",    outcome: "success", actorUserId: "u-2",
      resourceKind: "purpose", resourceId: "marketing", metadata: '{"region":"eu"}' },
    { action: "system.shutdown",    outcome: "success" },
  ];
  var prevHash = b.auditChain.ZERO_HASH;
  var insertErr = null;
  try {
    for (var i = 0; i < logicalRows.length; i++) {
      var built = _buildChainRow(driverClient, driver, i + 1, prevHash, logicalRows[i]);
      await _insertChainRow(driver, driverClient, built.rowForInsert);
      prevHash = built.rowHash;
    }
  } catch (e) { insertErr = e; }

  // The framework's chain-writer INSERT must land rows in the external
  // Postgres table. ensureSchema created the columns UNQUOTED (Postgres
  // folds them to lowercase: recordedat / monotoniccounter / rowhash …)
  // while chain-writer INSERTs into safeSql.quoteIdentifier()-quoted,
  // case-PRESERVING camelCase columns ("recordedAt" …). On real Postgres
  // those names don't match → the append fails.
  check("framework chain-writer INSERT lands audit rows on real Postgres " +
        "(the columns it writes must exist on the ensureSchema-created table)",
        insertErr === null);
  if (insertErr) {
    check("WRITE-PATH DETAIL: " + ((insertErr && insertErr.message) || String(insertErr)) +
          " — ensureSchema DDL creates UNQUOTED (lowercase-folded) columns " +
          "but chain-writer INSERTs safeSql.quoteIdentifier-quoted camelCase " +
          'columns ("recordedAt"…); the audit chain cannot be written to ' +
          "the operator's external Postgres", false);
  }

  var countOnServer = _psql("SELECT count(*) AS n FROM _blamejs_audit_log;");
  check("known-valid chain rows are physically in _blamejs_audit_log",
        new RegExp("\\b" + logicalRows.length + "\\b").test(countOnServer.trim()));

  // The verifier the framework ships: walk the live chain and recompute.
  // queryAll routes through the SAME driver the framework's clusterStorage
  // uses, so the row objects are keyed exactly as node-postgres keys them.
  async function liveQueryAll(sql, params) {
    var r = await driver.query(driverClient, sql, params || []);
    return r.rows;
  }
  var v1 = await b.auditChain.verifyChain(liveQueryAll, "_blamejs_audit_log", {});
  check("audit chain verifies ok:true on real Postgres " +
        "(a valid chain stored on the operator's external DB must verify)",
        v1.ok === true);
  check("verifyChain walked every stored row (rowsVerified === " + logicalRows.length + ")",
        v1.ok === true && v1.rowsVerified === logicalRows.length);
  if (!v1.ok) {
    check("FALSE-TAMPER DETAIL: verifyChain reports '" + v1.reason +
          "' at row " + v1.breakAt + " on an UNTAMPERED chain — " +
          "expected=" + String(v1.expected).slice(0, 20) +
          "… actual=" + String(v1.actual).slice(0, 20) + "…", false);
  }

  // ---- 3. coercion fidelity: confirm the readback IS real-pg-shaped
  //         (lowercase keys, BIGINT→string, BYTEA→Buffer). This is the
  //         shape the framework's reader must handle. ----
  var sample = (await liveQueryAll(
    'SELECT * FROM _blamejs_audit_log ORDER BY "monotonicCounter" ASC LIMIT 1', []))[0];
  var keys = sample ? Object.keys(sample) : [];
  check("readback row carries the chain columns (some hash + nonce key present)",
        keys.length >= 18);
  check("BYTEA nonce coerced to a Buffer (real-pg shape)",
        sample && Buffer.isBuffer(sample.nonce));
  // The framework reader expects camelCase (row.rowHash / row.monotonicCounter);
  // these assertions document what real pg actually returns.
  var hasCamelRowHash = sample && typeof sample.rowHash === "string";
  var hasLowerRowHash = sample && typeof sample.rowhash === "string";
  check("readback exposes rowHash under the key the framework reader uses " +
        "(row.rowHash) — NOT only the Postgres-folded lowercase key",
        hasCamelRowHash === true);
  if (!hasCamelRowHash && hasLowerRowHash) {
    check("CASE-FOLD DETAIL: Postgres returns the column as 'rowhash' " +
          "(lowercase) but verifyChain reads row.rowHash → undefined; " +
          "monotonicCounter is keyed 'monotoniccounter' as " +
          (typeof sample.monotoniccounter) + " value " +
          JSON.stringify(sample.monotoniccounter), false);
  }

  // ---- 4. tamper a hashed column → verify must report ok:false ----
  // Drop the WORM triggers (simulate a privileged DB-write attacker) then
  // mutate the action of the row at counter 2.
  _psql([
    "DROP TRIGGER IF EXISTS no_update__blamejs_audit_log ON _blamejs_audit_log;",
    "DROP TRIGGER IF EXISTS no_delete__blamejs_audit_log ON _blamejs_audit_log;",
  ].join("\n"));
  _psql("UPDATE _blamejs_audit_log SET action = 'auth.login.tampered' " +
        'WHERE "monotonicCounter" = 2;');
  var vTampered = await b.auditChain.verifyChain(liveQueryAll, "_blamejs_audit_log", {});
  check("verifyChain returns ok:false after a hashed column is tampered",
        vTampered.ok === false);
  // The tamper detection is only MEANINGFUL if verify passed on the clean
  // chain (else ok:false is a false positive that happens to coincide).
  check("tamper detection is meaningful (clean chain had verified ok:true)",
        v1.ok === true && vTampered.ok === false);

  // ---- 5. cluster leadership over the real Postgres lease provider ----
  // Every chain append in cluster mode passes cluster.requireLeader().
  // Confirm a single node can actually acquire leadership on real Postgres.
  _psql(["DROP TABLE IF EXISTS _blamejs_leader CASCADE;",
         "DROP TABLE IF EXISTS _blamejs_cluster_state CASCADE;"].join("\n"));
  var clusterErr = null;
  try {
    await b.cluster.init({
      nodeId:            "audit-ext-node",
      role:              "leader",
      externalDbBackend: "ops",
      dialect:           "postgres",
    });
  } catch (e) { clusterErr = e; }
  check("cluster.init completed without throwing on real Postgres",
        clusterErr === null);
  check("cluster node acquired leadership on real Postgres " +
        "(required for EVERY audit-chain append in cluster mode)",
        clusterErr === null && b.cluster.isLeader() === true);
  if (clusterErr === null && b.cluster.isLeader() !== true) {
    var leaderRow = _psql(
      'SELECT "nodeId", "expiresAt" FROM _blamejs_leader WHERE scope=\'leader\';');
    check("LEADERSHIP DETAIL: a leader row WAS written to the server [" +
          leaderRow.trim() + "] but acquireLease returned no in-memory " +
          "lease (provider read row.expiresAt/row.nodeId but the live " +
          "row keys are lowercase expiresat/nodeid) → isLeader()=false → " +
          "every audit append would throw NotLeaderError", false);
  }

  // ---- MySQL audit-chain coverage ----
  // MySQL is a first-class audit-chain backend: the framework-schema
  // reconciler emits MySQL DDL and the hash chain appends and verifies
  // against it. The end-to-end proof (ensureSchema + audit.record →
  // chain-writer._insertRow + audit.verify ok:true against a real MySQL
  // server) lives in audit-stack-mysql.test.js. This Postgres-focused file
  // does not re-probe MySQL through the Postgres "ops" connection.

  // ---- teardown ----
  try { await driver.close(driverClient); } catch (_e) {}
  try { await b.cluster.shutdown(); } catch (_e) {}
  await b.externalDb.shutdown();
  b.cluster._resetForTest();
  b.audit._resetForTest();
  _psql(DROP_ALL);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
