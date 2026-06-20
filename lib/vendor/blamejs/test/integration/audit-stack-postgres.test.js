"use strict";
/**
 * Live PostgreSQL coverage for the migrated b.sql data layer that today
 * is only exercised against single-node SQLite host smoke:
 *
 *   lib/audit.js        — record() → chain-writer, checkpoint(),
 *                         _upsertAuditTip() fencing-token guard, verify(),
 *                         verifyCheckpoints()
 *   lib/audit-tools.js  — exportSlice / archive / verifyBundle / purge
 *   lib/chain-writer.js — _insertRow / counter primer / tip read on a real
 *                         backend
 *   lib/break-glass.js  — policy.set/get/list + grant + unsealRow consume,
 *                         all routed through clusterStorage to live Postgres
 *   lib/crypto-field.js — a K_row (vault.row:) sealed cell stored as TEXT in
 *                         Postgres and read back, proving the typed codec
 *                         (Buffer/object) survives a real round-trip
 *
 * The driver is a docker-exec psql shim that replicates a real
 * node-postgres driver's coercions: BIGINT (int8) → JS STRING, BYTEA →
 * Node Buffer, and unquoted identifiers folded to lowercase. The
 * framework's own clusterStorage.coerceRows (frameworkSchema.COLUMN_TYPES)
 * then normalizes those back to numbers / Buffers — this test asserts that
 * normalization end-to-end against the live server, NOT a hand-coerced
 * fake.
 *
 * Flow: setupTestDb (vault + local SQLite + cryptoField schema
 * registration for the framework tables) → frameworkSchema.ensureSchema on
 * Postgres → cluster.init (leader) flips the framework into cluster mode so
 * every audit / break-glass / consent write dispatches to the external
 * Postgres backend through the SAME b.sql + clusterStorage path operators
 * run in production.
 *
 * Tables are namespaced under the default _blamejs_ prefix; setup drops and
 * recreates them so a re-run is clean and concurrent integration tests in
 * other databases don't collide (this test owns blamejs_test).
 */

var spawn        = require("node:child_process").spawn;
var execFileSync = require("node:child_process").execFileSync;
var fs   = require("node:fs");
var os   = require("node:os");
var path = require("node:path");

var helpers  = require("../helpers");
var check    = helpers.check;
var services = require("../helpers/services");
var setupTestDb    = require("../helpers/db").setupTestDb;
var teardownTestDb = require("../helpers/db").teardownTestDb;
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

// ---- persistent-session docker-exec psql driver (faithful to node-postgres) ----
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
      if (process.env.BJ_TRACE_SQL === "1") { try { process.stderr.write("[SQL] " + sql + "\n"); } catch (_e) {} }
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
// numbers raw, booleans TRUE/FALSE, everything else single-quote-escaped.
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

// Columns the framework's audit / break-glass tables store as BYTEA — a real
// pg driver returns these as Buffers. clusterStorage.coerceRows then keeps
// them Buffers (idempotent), so the driver MUST hand Buffers up to match.
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
    // Header row keyed AS POSTGRES REPORTS IT — lowercase for unquoted
    // identifiers, case-preserving for the double-quoted camelCase columns
    // the framework's DDL created. Kept verbatim, exactly as node-postgres
    // would key the row object.
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

// Drop every framework table this test touches so a re-run is clean.
var FRAMEWORK_TABLES = [
  "_blamejs_audit_log", "_blamejs_consent_log", "_blamejs_audit_checkpoints",
  "_blamejs_audit_tip", "_blamejs_consent_tip", "_blamejs_audit_purge_anchor",
  "_blamejs_scheduler_ticks", "_blamejs_rate_limit_counters",
  "_blamejs_pubsub_messages", "_blamejs_api_encrypt_nonces", "_blamejs_api_keys",
  "_blamejs_sessions", "_blamejs_session_valid_from", "_blamejs_jobs",
  "_blamejs_cache", "_blamejs_cache_tags",
  "_blamejs_seeders", "_blamejs_seeders_lock", "_blamejs_break_glass_policies",
  "_blamejs_break_glass_grants", "_blamejs_leader", "_blamejs_cluster_state",
  // app-side table for break-glass + K_row storage round-trips
  "patients",
];

function _dropFrameworkTables() {
  _psql(FRAMEWORK_TABLES.map(function (t) {
    return "DROP TABLE IF EXISTS " + t + " CASCADE;";
  }).join("\n"));
}

async function run() {
  var pg = await services.requireService("postgres");
  if (!pg.ok) throw new Error("postgres unreachable: " + pg.reason);

  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-audit-pg-"));
  var driver = _makeDockerPgDriver();
  var driverClient = null;

  try {
    _dropFrameworkTables();

    // ---- Boot the framework: vault + local SQLite + cryptoField schema
    //      registration for the framework tables (audit_log /
    //      break_glass_* sealed-column declarations come from db.init's
    //      FRAMEWORK_SCHEMA). The "patients" app table is glass-locked +
    //      sealed for the break-glass + crypto-field portions. ----
    await setupTestDb(tmpDir, [
      {
        name: "patients",
        columns: {
          _id:        "TEXT PRIMARY KEY",
          mrn:        "TEXT",
          ssn:        "TEXT",
          residency:  "TEXT",
          notes:      "TEXT",
        },
        sealedFields: ["ssn", "notes"],
      },
    ]);

    // External backend + cluster mode. cluster.init flips
    // cluster.isClusterMode() true so clusterStorage routes the audit /
    // break-glass / consent SQL to the external Postgres backend.
    b.externalDb.init({
      backends: {
        ops: {
          connect: driver.connect, query: driver.query, close: driver.close,
          dialect: "postgres",
        },
      },
    });
    await b.frameworkSchema.ensureSchema({ externalDbBackend: "ops", dialect: "postgres" });
    check("ensureSchema created _blamejs_audit_log + break-glass tables on real Postgres",
          /\b1\b/.test(_psql(
            "SELECT count(*) AS n FROM information_schema.tables " +
            "WHERE table_name = '_blamejs_break_glass_grants';").trim()));

    await b.cluster.init({
      nodeId:            "audit-stack-node",
      role:              "leader",
      externalDbBackend: "ops",
      dialect:           "postgres",
    });
    check("cluster.init acquired leadership on real Postgres (gates every chain append)",
          b.cluster.isLeader() === true);
    check("framework is in cluster mode → framework SQL routes to external Postgres",
          b.clusterStorage.tableName("audit_log") === "_blamejs_audit_log");

    // A dedicated driver session for out-of-band readback assertions
    // keyed exactly as node-postgres keys rows.
    driverClient = await driver.connect();
    async function liveQueryAll(sql, params) {
      var r = await driver.query(driverClient, sql, params || []);
      return r.rows;
    }

    await _testAuditRecordAndChain(liveQueryAll);
    await _testCheckpointAndFence(liveQueryAll);
    await _testCoercionFidelity(liveQueryAll);
    await _testAuditToolsBundleAndPurge(tmpDir);
    await _testBreakGlass();
    await _testCryptoFieldKRowRoundTrip(liveQueryAll);
    await _testTamperDetection();

  } finally {
    try { if (driverClient) await driver.close(driverClient); } catch (_e) {}
    try { await b.cluster.shutdown(); } catch (_e) {}
    try { await b.externalDb.shutdown(); } catch (_e) {}
    try { await teardownTestDb(tmpDir); } catch (_e) {}
    try { _dropFrameworkTables(); } catch (_e) {}
  }
}

// ====================================================================
// 1. audit.record() → chain-writer._insertRow on real Postgres. Drives
//    the FULL primitive: counter primer (MAX(monotonicCounter)), tip read,
//    cryptoField seal, null-fill, computeRowHash, INSERT with prevHash /
//    rowHash / nonce / fencingToken, then verify() (the reader b.audit
//    ships). A correct framework verifies ok:true — the CORE proof.
// ====================================================================
async function _testAuditRecordAndChain(liveQueryAll) {
  var events = [
    { action: "system.boot",        outcome: "success" },
    { action: "auth.login.success", outcome: "success",
      actor: { userId: "u-1", ip: "10.0.0.7" } },
    { action: "consent.granted",    outcome: "success",
      actor: { userId: "u-2" },
      resource: { kind: "purpose", id: "marketing" },
      metadata: { region: "eu" } },
    { action: "system.shutdown",    outcome: "success" },
  ];
  var appended = [];
  for (var i = 0; i < events.length; i++) {
    appended.push(await b.audit.record(events[i]));
  }
  check("audit.record returned a monotonic counter per row (1..4)",
        appended[0].monotonicCounter === 1 && appended[3].monotonicCounter === 4);

  var count = _psql("SELECT count(*) AS n FROM _blamejs_audit_log;");
  check("audit.record landed 4 rows in _blamejs_audit_log on real Postgres",
        /\b4\b/.test(count.trim()));

  // The reader b.audit.verify uses, against the live table.
  var v = await b.audit.verify({});
  check("audit.verify walks the live Postgres chain and returns ok:true " +
        "(a valid chain on the operator's external DB must verify)", v.ok === true);
  check("audit.verify counted every stored row (rowsVerified === 4)",
        v.ok === true && v.rowsVerified === 4);
  if (!v.ok) {
    check("AUDIT-VERIFY DETAIL: verify reports '" + v.reason + "' at row " +
          v.breakAt + " on an untampered live chain", false);
  }

  // The second row's prevHash must equal the first row's rowHash — chain
  // linkage actually persisted, not a per-row island.
  var linked = await liveQueryAll(
    'SELECT "monotonicCounter", "prevHash", "rowHash" FROM _blamejs_audit_log ' +
    'ORDER BY "monotonicCounter" ASC', []);
  check("chain links across rows on Postgres (row2.prevHash === row1.rowHash)",
        linked.length === 4 && linked[1].prevHash === linked[0].rowHash);

  // Counter primer correctness: a brand-new chain-writer (fresh in-process
  // state via record after flush) must read MAX(monotonicCounter) from the
  // live table and continue, not restart at 1. Reset the audit module's
  // chain-writer in-process counter and append once more.
  b.audit._resetForTest();
  // _resetForTest tore down cluster wiring's audit ties but cluster mode
  // and externalDb remain; the counter primer re-reads MAX from Postgres.
  var more = await b.audit.record({ action: "system.boot", outcome: "success" });
  check("counter primer read MAX(monotonicCounter) from live Postgres on a " +
        "fresh chain-writer (continued at 5, did not restart at 1)",
        more.monotonicCounter === 5);
  var count2 = _psql("SELECT count(*) AS n FROM _blamejs_audit_log;");
  check("5 audit rows now present after primer-continued append",
        /\b5\b/.test(count2.trim()));
}

// ====================================================================
// 2. audit.checkpoint() → _insertCheckpoint + _upsertAuditTip fencing
//    guard on real Postgres. The tip UPSERT's WHERE clause
//    (storedToken <= EXCLUDED.token) is the canonical fencing-token guard;
//    a strictly-lower incoming token must be FENCED_OUT.
// ====================================================================
async function _testCheckpointAndFence(liveQueryAll) {
  var ck = await b.audit.checkpoint({});
  check("audit.checkpoint anchored the live chain tip", ck && ck.atMonotonicCounter === 5);

  var ckCount = _psql("SELECT count(*) AS n FROM _blamejs_audit_checkpoints;");
  check("checkpoint row landed in _blamejs_audit_checkpoints on Postgres",
        /\b1\b/.test(ckCount.trim()));

  var tip = await liveQueryAll(
    'SELECT "scope", "atMonotonicCounter", "fencingToken" FROM _blamejs_audit_tip ' +
    "WHERE scope = 'audit'", []);
  check("_upsertAuditTip wrote the single audit-tip row on Postgres",
        tip.length === 1 && tip[0].scope === "audit");
  check("audit-tip atMonotonicCounter coerced BIGINT→number and matches the chain tip",
        Number(tip[0].atMonotonicCounter) === 5);

  // verifyCheckpoints walks the live checkpoints + confirms the anchored
  // row still has its rowHash (ML-DSA signature verify + row match).
  var vc = await b.audit.verifyCheckpoints();
  check("audit.verifyCheckpoints returns ok:true against the live Postgres checkpoint",
        vc.ok === true && vc.checkpointsVerified === 1);
  if (!vc.ok) {
    check("VERIFY-CHECKPOINTS DETAIL: '" + vc.reason + "' at " + vc.breakAt, false);
  }

  // Fencing-token guard. The audit-tip currently holds the leader's
  // fencingToken. Directly UPSERT a HIGHER token (accepted) then attempt a
  // LOWER token (must be fenced out → 0 RETURNING rows). We exercise the
  // exact b.sql UPSERT shape the framework emits via a raw psql round-trip
  // so the DB-level guard is what's tested, not application state.
  var curTok = Number(tip[0].fencingToken);
  // Higher token accepted: storedToken <= EXCLUDED.token.
  var higher = _psql(
    'INSERT INTO _blamejs_audit_tip ("scope","atMonotonicCounter","rowHash","signedAt","fencingToken") ' +
    "VALUES ('audit', 5, 'h', 's', " + (curTok + 10) + ") " +
    'ON CONFLICT ("scope") DO UPDATE SET "fencingToken" = EXCLUDED."fencingToken" ' +
    'WHERE _blamejs_audit_tip."fencingToken" <= EXCLUDED."fencingToken" ' +
    'RETURNING "fencingToken";');
  check("fencing guard ACCEPTS a higher incoming token (RETURNING produced a row)",
        new RegExp("\\b" + (curTok + 10) + "\\b").test(higher));
  // Lower token rejected: WHERE storedToken(curTok+10) <= EXCLUDED(curTok+1) is false.
  var lower = _psql(
    'INSERT INTO _blamejs_audit_tip ("scope","atMonotonicCounter","rowHash","signedAt","fencingToken") ' +
    "VALUES ('audit', 5, 'h2', 's2', " + (curTok + 1) + ") " +
    'ON CONFLICT ("scope") DO UPDATE SET "fencingToken" = EXCLUDED."fencingToken" ' +
    'WHERE _blamejs_audit_tip."fencingToken" <= EXCLUDED."fencingToken" ' +
    'RETURNING "fencingToken";');
  // The DO UPDATE ... WHERE that filters out the row yields no RETURNING
  // output (no data line; only the "INSERT 0 0" tag).
  check("fencing guard REJECTS a strictly-lower incoming token (0 RETURNING rows → FENCED_OUT)",
        lower.indexOf(String(curTok + 1)) === -1);
  var stillHigh = _psql('SELECT "fencingToken" FROM _blamejs_audit_tip WHERE scope=\'audit\';');
  check("stored fencingToken stayed at the higher value (lower token did not overwrite)",
        new RegExp("\\b" + (curTok + 10) + "\\b").test(stillHigh.trim()));
}

// ====================================================================
// 3. Coercion fidelity on the live readback: the framework reader expects
//    camelCase keys + number counters + Buffer nonces, but Postgres hands
//    BIGINT back as a STRING and BYTEA as a Buffer. clusterStorage.coerceRows
//    must normalize. We read THROUGH clusterStorage (the framework path) and
//    assert the normalized JS shape — not the raw driver shape.
// ====================================================================
async function _testCoercionFidelity() {
  // Compose via b.sql so the camelCase column is double-quoted (Postgres
  // folds an unquoted identifier to lowercase). Bare logical table name —
  // clusterStorage rewrites audit_log → _blamejs_audit_log + coerces the row.
  var built = require("../../lib/sql").select("audit_log", { dialect: "sqlite" })
    .orderBy("monotonicCounter", "asc")
    .limit(1)
    .toSql();
  var rows = await b.clusterStorage.executeAll(built.sql, built.params);
  check("clusterStorage.executeAll read an audit row back from live Postgres",
        rows.length === 1);
  var row = rows[0];
  check("coercion: monotonicCounter is a JS number after clusterStorage.coerceRows " +
        "(node-postgres handed it back as a BIGINT string)",
        typeof row.monotonicCounter === "number" && row.monotonicCounter === 1);
  check("coercion: recordedAt BIGINT coerced to a JS number",
        typeof row.recordedAt === "number");
  check("coercion: nonce BYTEA coerced to a Node Buffer",
        Buffer.isBuffer(row.nonce));
  check("coercion: rowHash stays a string under the camelCase key the reader uses",
        typeof row.rowHash === "string" && row.rowHash.length > 0);
}

// ====================================================================
// 4. audit-tools exportSlice → verifyBundle round-trip reading from the
//    live Postgres audit_log via the DEFAULT clusterStorage readers, then
//    archive (needs a covering checkpoint) → verifyBundle, then the purge
//    monotonic gate + the live anchor UPSERT through clusterStorage.
// ====================================================================
async function _testAuditToolsBundleAndPurge(tmpDir) {
  var pass = Buffer.from("audit-bundle-passphrase-not-secret-1234567890", "utf8");

  // exportSlice reads rows from the live Postgres audit_log (default
  // _defaultReadRows → clusterStorage.executeAll) and writes an encrypted
  // bundle to disk. audit-tools refuses an existing out dir — pass a fresh
  // (non-existent) path under tmpDir.
  var exDir = path.join(tmpDir, "export-bundle");
  var ex = await b.auditTools.exportSlice({ out: exDir, passphrase: pass });
  check("audit-tools.exportSlice read the live Postgres chain + wrote a bundle " +
        "(rowCount === 5)", ex.rowCount === 5);

  var exVerify = await b.auditTools.verifyBundle({ in: exDir, passphrase: pass });
  check("audit-tools.verifyBundle round-trips the exported live-Postgres slice " +
        "(ok:true, walks the prevHash→rowHash chain)",
        exVerify.ok === true && exVerify.rowsVerified === 5);
  if (!exVerify.ok) {
    check("EXPORT-VERIFY DETAIL: '" + exVerify.reason + "'", false);
  }

  // archive needs a covering checkpoint (we wrote one at counter 5) and a
  // `before` boundary newer than every row. recordedAt is Date.now()-based,
  // so a `before` of now+1h covers all rows.
  var arDir = path.join(tmpDir, "archive-bundle");
  var ar = await b.auditTools.archive({
    out:        arDir,
    before:     Date.now() + b.constants.TIME.hours(1),
    passphrase: pass,
  });
  check("audit-tools.archive bundled every live-Postgres row under a covering " +
        "checkpoint (rowCount === 5)", ar.rowCount === 5);

  var arVerify = await b.auditTools.verifyBundle({ in: arDir, passphrase: pass });
  check("audit-tools.verifyBundle confirms the archive chain + checkpoint signature " +
        "over live-Postgres rows (ok:true)", arVerify.ok === true);
  check("archive bundle is kind 'archive' (carries the off-chain checkpoint anchor)",
        arVerify.kind === "archive");

  // purge monotonic gate. Drive the real purge() flow but inject a no-op
  // apply so we exercise the verifyBundle + monotonic-anchor logic against
  // the live archive WITHOUT physically deleting the chain mid-test (the
  // local purgeAuditChain path is single-node-only). Then separately
  // exercise the LIVE anchor UPSERT through clusterStorage so the
  // _blamejs_audit_purge_anchor table's b.sql UPSERT is proven on Postgres.
  var applied = null;
  var purgeRes = await b.auditTools.purge({
    confirm:    true,
    archive:    arDir,
    passphrase: pass,
    readAnchor: function () { return Promise.resolve(null); },   // origin: first purge
    apply: function (args) {
      applied = args;
      return Promise.resolve({
        rowsDeleted: ar.rowCount, checkpointsDeleted: 0,
        archiveBundleId: args.archiveBundleId,
      });
    },
  });
  check("audit-tools.purge verified the archive + passed the monotonic gate " +
        "(firstCounter===1 from origin) and reported rowsDeleted",
        purgeRes.purged === true && purgeRes.rowsDeleted === 5 &&
        applied && Number(applied.lastPurgedCounter) === 5);

  // Now prove the live anchor UPSERT (the only piece of purge's default
  // apply that targets the external DB via clusterStorage) actually runs on
  // Postgres: run _defaultApplyPurge's anchor write shape directly.
  await b.clusterStorage.execute(
    'INSERT INTO _blamejs_audit_purge_anchor ' +
    '("scope","lastPurgedCounter","lastPurgedRowHash","archiveBundleId","purgedAt") ' +
    "VALUES ('audit', ?, ?, ?, ?) " +
    'ON CONFLICT ("scope") DO UPDATE SET ' +
    '"lastPurgedCounter" = EXCLUDED."lastPurgedCounter", ' +
    '"lastPurgedRowHash" = EXCLUDED."lastPurgedRowHash", ' +
    '"archiveBundleId" = EXCLUDED."archiveBundleId", ' +
    '"purgedAt" = EXCLUDED."purgedAt"',
    [5, "anchor-hash", "bundle-1", Date.now()]);
  var anchorReadBack = await b.clusterStorage.executeOne(
    'SELECT "lastPurgedCounter", "lastPurgedRowHash" FROM _blamejs_audit_purge_anchor WHERE "scope" = ?',
    ["audit"]);
  check("purge anchor UPSERT through b.sql + clusterStorage landed on Postgres + " +
        "coerced lastPurgedCounter BIGINT→number",
        anchorReadBack && anchorReadBack.lastPurgedCounter === 5 &&
        anchorReadBack.lastPurgedRowHash === "anchor-hash");
}

// ====================================================================
// 5. break-glass policy + grant + unsealRow consume — the WHOLE flow
//    routed through clusterStorage to live Postgres: policy UPSERT (sealed),
//    policy.get/list (unseal + decode), grant (TOTP factor verify → sealed
//    grant row INSERT, with the issuedToActorHash derived hash NOT NULL
//    populated), then unsealRow (grant fetch + atomic rowsConsumed++ +
//    glass-locked column unseal of a real app row stored on Postgres).
// ====================================================================
async function _testBreakGlass() {
  b.breakGlass.init({ trustProxy: false });

  // The glass-locked app table is an OPERATOR table — the framework does
  // not own its DDL. In cluster mode break-glass reads it from the external
  // Postgres, so create it there with the same column shape db.init
  // registered for cryptoField sealing.
  _psql('CREATE TABLE IF NOT EXISTS patients (' +
        '"_id" TEXT PRIMARY KEY, "mrn" TEXT, "ssn" TEXT, ' +
        '"residency" TEXT, "notes" TEXT);');

  // Seed a glass-locked app row in Postgres via the framework's own write
  // path (clusterStorage) so the SSN column is cryptoField-sealed on disk.
  var patient = b.cryptoField.sealRow("patients", {
    _id: "patient-001", mrn: "MRN-1", ssn: "123-45-6789",
    residency: "eu", notes: "high blood pressure",
  });
  await b.clusterStorage.execute(
    'INSERT INTO patients ("_id","mrn","ssn","residency","notes") VALUES (?,?,?,?,?)',
    [patient._id, patient.mrn, patient.ssn, patient.residency, patient.notes]);
  var sealedOnDisk = _psql("SELECT ssn FROM patients WHERE _id = 'patient-001';");
  check("break-glass: glass-locked ssn is stored SEALED (vault:-prefixed) on Postgres",
        /vault[:.]/.test(sealedOnDisk.trim()));

  // policy.set → UPSERT into _blamejs_break_glass_policies (sealed columns).
  var setRes = await b.breakGlass.policy.set("patients", {
    columns:         ["ssn", "notes"],
    factors:         ["totp"],
    grantTtl:        b.constants.TIME.minutes(15),
    maxRowsPerGrant: 1,
    reasonMinLength: 12,
    pinIp:           false,
    sessionPin:      false,
  });
  check("break-glass: policy.set UPSERT landed on Postgres", setRes.applied === true);
  var polCount = _psql("SELECT count(*) AS n FROM _blamejs_break_glass_policies;");
  check("break-glass: one policy row physically present on Postgres",
        /\b1\b/.test(polCount.trim()));

  // policy.get round-trips the sealed/encoded policy from Postgres.
  var got = await b.breakGlass.policy.get("patients");
  check("break-glass: policy.get reads + unseals the Postgres policy row",
        got && got.table === "patients" &&
        got.columns.length === 2 && got.columns.indexOf("ssn") !== -1);
  check("break-glass: policy numeric fields coerced (grantTtl is a number)",
        typeof got.grantTtl === "number" && got.grantTtl > 0);

  var listed = await b.breakGlass.policy.list();
  check("break-glass: policy.list enumerates the glass-locked table from Postgres",
        listed.length === 1 && listed[0].table === "patients");

  // grant — mint a TOTP-backed grant. Generate a real TOTP secret + a code
  // valid at a fixed clock the verifier is threaded with.
  var totpSecret = b.auth.totp.generateSecret();
  var nowMs = Date.now();
  var code = b.auth.totp.generate(totpSecret, { now: nowMs });
  var req = {
    user:    { id: "dr-house", scopes: [] },
    socket:  { remoteAddress: "127.0.0.1" },
    headers: { "user-agent": "test-agent" },
    method:  "POST",
    url:     "/admin/break-glass",
  };
  var handle = await b.breakGlass.grant({
    req:     req,
    table:   "patients",
    columns: ["ssn"],
    reason:  "ER admit verifying identity for patient-001",
    factor:  { type: "totp", secret: totpSecret, code: code, now: nowMs },
  });
  check("break-glass: grant minted after live TOTP verify (handle has an id)",
        handle && typeof handle.id === "string" && handle.id.indexOf("bg-") === 0);

  var grantCount = _psql("SELECT count(*) AS n FROM _blamejs_break_glass_grants;");
  check("break-glass: grant row physically landed on Postgres", /\b1\b/.test(grantCount.trim()));
  // The grants DDL declares issuedToActorHash TEXT NOT NULL; the cryptoField
  // derived hash must have populated it, or the INSERT would have failed the
  // NOT NULL constraint on Postgres (strict) — assert it's non-null.
  var hashCell = _psql('SELECT "issuedToActorHash" FROM _blamejs_break_glass_grants LIMIT 1;');
  check("break-glass: issuedToActorHash NOT-NULL derived column populated on Postgres",
        hashCell.trim().length > 0 && !/__BJNULL__/.test(hashCell));

  // unsealRow consume — fetch grant from Postgres, atomic rowsConsumed++,
  // unseal the glass-locked ssn of the real Postgres-stored row.
  var unsealed = await b.breakGlass.unsealRow(handle, "patients", "patient-001");
  check("break-glass: unsealRow returned the decrypted glass-locked ssn",
        unsealed && unsealed.ssn === "123-45-6789");

  var consumed = _psql('SELECT "rowsConsumed" FROM _blamejs_break_glass_grants LIMIT 1;');
  check("break-glass: atomic rowsConsumed++ persisted on Postgres (now 1)",
        /\b1\b/.test(consumed.trim()));

  // Second consume on a maxRowsPerGrant:1 grant must be refused (exhausted).
  var exhaustedErr = null;
  try { await b.breakGlass.unsealRow(handle, "patients", "patient-001"); }
  catch (e) { exhaustedErr = e; }
  check("break-glass: second unseal refused — grant exhausted (row-by-row auth on Postgres)",
        exhaustedErr && /exhausted/i.test((exhaustedErr.code || "") + (exhaustedErr.message || "")));
}

// ====================================================================
// 6. crypto-field K_row (vault.row:) sealed cell stored on Postgres + read
//    back, proving the typed codec (Buffer / object / string) survives a
//    real TEXT round-trip + clusterStorage coercion. The wrapped row-secret
//    lives in the LOCAL per-row-keys registry (its by-design home); the
//    sealed CELL is what lands on Postgres.
// ====================================================================
async function _testCryptoFieldKRowRoundTrip(liveQueryAll) {
  b.cryptoField.declarePerRowKey("krow_demo", { keySize: 32 });
  b.cryptoField.registerTable("krow_demo", { sealedFields: ["secret", "blobCol", "objCol"] });

  // b.db itself is the local-db handle (exposes .prepare()); the per-row-key
  // registry (_blamejs_per_row_keys) is a LOCAL-only table by design — the
  // wrapped row-secret never leaves the framework's own db, while the sealed
  // CELL is what lands on Postgres.
  var dbHandle = b.db;
  check("crypto-field: local db handle (b.db) exposes .prepare() for the per-row-key registry",
        typeof dbHandle.prepare === "function");

  var rowId = "krow-row-1";
  var kRow = b.cryptoField.materializePerRowKey("krow_demo", rowId, dbHandle);
  check("crypto-field: materializePerRowKey produced a 32-byte K_row",
        Buffer.isBuffer(kRow) && kRow.length === 32);

  var origBuf = Buffer.from([0, 1, 2, 250, 251, 255]);
  var origObj = { kind: "phi", level: 9 };
  var sealed = b.cryptoField.sealRow("krow_demo",
    { _id: rowId, secret: "top-secret-string", blobCol: origBuf, objCol: origObj },
    { kRow: kRow, rowId: rowId });
  check("crypto-field: sealRow under K_row emitted vault.row: cells",
        b.cryptoField.isRowSealed(sealed.secret) &&
        b.cryptoField.isRowSealed(sealed.blobCol) &&
        b.cryptoField.isRowSealed(sealed.objCol));

  // Store the sealed cells on Postgres as TEXT, then read back.
  _psql('CREATE TABLE IF NOT EXISTS krow_demo (' +
        '"_id" TEXT PRIMARY KEY, "secret" TEXT, "blobCol" TEXT, "objCol" TEXT);');
  await b.clusterStorage.execute(
    'INSERT INTO krow_demo ("_id","secret","blobCol","objCol") VALUES (?,?,?,?)',
    [rowId, sealed.secret, sealed.blobCol, sealed.objCol]);

  var stored = (await liveQueryAll(
    'SELECT "_id","secret","blobCol","objCol" FROM krow_demo WHERE "_id" = $1', [rowId]))[0];
  check("crypto-field: vault.row: cells survived the Postgres TEXT round-trip intact",
        stored.secret === sealed.secret && stored.blobCol === sealed.blobCol &&
        stored.objCol === sealed.objCol);

  // Unseal the read-back row under K_row — the typed codec must restore the
  // ORIGINAL types (string / Buffer / object), proving no String() mangling
  // across the real backend round-trip.
  var unsealed = b.cryptoField.sealRow ? _unsealKRow("krow_demo", stored, kRow, rowId) : null;
  check("crypto-field: K_row unseal restored the string value byte-for-byte",
        unsealed.secret === "top-secret-string");
  check("crypto-field: K_row unseal restored the Buffer value byte-for-byte " +
        "(typed codec, NOT String()-mangled)",
        Buffer.isBuffer(unsealed.blobCol) && unsealed.blobCol.equals(origBuf));
  check("crypto-field: K_row unseal restored the object value (typed codec)",
        unsealed.objCol && unsealed.objCol.kind === "phi" && unsealed.objCol.level === 9);

  _psql("DROP TABLE IF EXISTS krow_demo;");
}

// Unseal vault.row: cells under a known K_row without going through the
// dbHandle fetch path (we already hold kRow). Mirrors the framework's
// K_row decrypt: decryptPacked under the (table,rowId,column,schemaVersion)
// AAD + the typed-codec decode. Uses only exported framework crypto so the
// AAD bytes match the seal side.
function _unsealKRow(table, row, kRow, rowId) {
  var vaultAad = require("../../lib/vault-aad");
  var crypto = require("../../lib/crypto");
  var ROW_PREFIX = require("../../lib/constants").ROW_PREFIX;
  var out = Object.assign({}, row);
  var cols = ["secret", "blobCol", "objCol"];
  for (var i = 0; i < cols.length; i++) {
    var col = cols[i];
    var v = row[col];
    if (typeof v !== "string" || v.indexOf(ROW_PREFIX) !== 0) continue;
    var aad = vaultAad.canonicalizeAad(vaultAad.buildColumnAad({
      table: table, rowId: rowId, column: col, schemaVersion: "1",
    }));
    var packed = Buffer.from(v.slice(ROW_PREFIX.length), "base64");
    var plain = crypto.decryptPacked(packed, kRow, aad).toString("utf8");
    out[col] = _decodeTyped(plain);
  }
  return out;
}

// Mirror of crypto-field's _decodeTyped for the test-side K_row unseal.
var TYPED_SENTINEL = String.fromCharCode(0) + "bjsv1:";
function _decodeTyped(str) {
  if (typeof str !== "string" || str.indexOf(TYPED_SENTINEL) !== 0) return str;
  var body = str.slice(TYPED_SENTINEL.length);
  var tag = body.slice(0, 2);
  var payload = body.slice(2);
  if (tag === "B:") return Buffer.from(payload, "base64");
  if (tag === "J:") return JSON.parse(payload);
  if (tag === "S:") return payload;
  return str;
}

// ====================================================================
// 7. Tamper detection on the live chain — drop the WORM triggers (privileged
//    DB-write attacker), mutate a hashed column, confirm verify reports
//    ok:false. Meaningful only because the clean chain verified ok:true.
// ====================================================================
async function _testTamperDetection() {
  _psql([
    "DROP TRIGGER IF EXISTS no_update__blamejs_audit_log ON _blamejs_audit_log;",
    "DROP TRIGGER IF EXISTS no_delete__blamejs_audit_log ON _blamejs_audit_log;",
  ].join("\n"));
  _psql("UPDATE _blamejs_audit_log SET action = 'auth.login.tampered' " +
        'WHERE "monotonicCounter" = 2;');
  var v = await b.audit.verify({});
  check("audit.verify returns ok:false after a hashed column is tampered on Postgres",
        v.ok === false);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
