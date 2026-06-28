"use strict";
/**
 * Live webhook-dispatcher test against the docker Postgres container. The
 * dispatcher's durable store composes b.sql -> b.externalDb, so smoke only
 * ever exercises it on SQLite; this proves the real Postgres dialect path:
 *
 *   - declareSchema renders valid Postgres DDL (serial -> BIGSERIAL, the
 *     TIMESTAMPTZ columns, the partial pending index) on a real server.
 *   - registerEndpoint INSERTs with the secret SEALED at rest (vault: prefix
 *     in the actual Postgres row, never the plaintext secret).
 *   - dispatch fans out one event into one delivery row per endpoint and the
 *     $1..$N-bound INSERT/UPDATE round-trips.
 *   - the retry claim TRANSACTION (mark-then-reselect) + the BIGINT `attempts`
 *     column coercing back through frameworkSchema for the count comparison.
 *   - maxAttempts -> dead-letter and dlq.replay on real Postgres.
 *
 * Delivery HTTP is a stubbed transport (no network); the storage path is real.
 *
 * RUN: node scripts/test-integration.js --skip-service-check webhook-dispatcher-pg
 */
var spawn        = require("node:child_process").spawn;
var execFileSync = require("node:child_process").execFileSync;
var fs   = require("node:fs");
var os   = require("node:os");
var path = require("node:path");
var helpers  = require("../helpers");
var check    = helpers.check;
var services = require("../helpers/services");
var b = require("../../");

var CONTAINER     = "blamejs-test-postgres";
var NULL_SENTINEL = "__BJNULL__";
var PSQL_ARGS = "psql -U blamejs -d blamejs_test -A -v ON_ERROR_STOP=0 -P null=__BJNULL__ 2>&1";

var ENDPOINTS_TABLE  = b.frameworkSchema.tableName("webhook_endpoints");
var DELIVERIES_TABLE = b.frameworkSchema.tableName("webhook_deliveries");

// ---- one-shot psql (setup / teardown / out-of-band assertions) ----
function _psql(sql) {
  var out = execFileSync(
    "docker",
    ["exec", "-i", CONTAINER, "sh", "-c", "psql -U blamejs -d blamejs_test -qtA -P null=__BJNULL__ 2>&1"],
    { input: sql + "\n", stdio: ["pipe", "pipe", "pipe"] }
  ).toString("utf8");
  if (/^ERROR:/m.test(out)) throw new Error("psql failed for [" + sql + "]:\n" + out);
  return out;
}

// ---- persistent-session docker-exec psql driver (faithful to node-postgres:
// BIGINT comes back as a string; quoted DDL preserves column case) ----
var _seq = 0;
function _makeDockerPgDriver() {
  return {
    connect: function () {
      return new Promise(function (resolve, reject) {
        var child = spawn("docker",
          ["exec", "-i", CONTAINER, "sh", "-c", PSQL_ARGS + " ; echo __BLAMEJS_PSQL_EXIT__"],
          { stdio: ["pipe", "pipe", "pipe"] });
        var client = { child: child, buf: "", pending: null, closed: false };
        child.on("error", function (e) { if (client.pending) { var p = client.pending; client.pending = null; p.reject(e); } });
        child.on("close", function () {
          client.closed = true;
          if (client.pending) { var p = client.pending; client.pending = null; p.reject(new Error("psql session closed mid-statement")); }
        });
        child.stdout.on("data", function (chunk) { client.buf += chunk.toString("utf8"); _drain(client); });
        var prime = "__BJ_PRIME__";
        client.pending = { sentinel: prime, resolve: function () { resolve(client); }, reject: reject };
        client.child.stdin.write("\\pset fieldsep '\\t'\n\\pset footer off\n\\echo " + prime + "\n");
      });
    },
    query: function (client, sql, params) {
      var bound = _bindParams(sql, params || []);
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
        try { client.child.stdin.end("\\q\n"); } catch (_e) {}
        var done = false;
        client.child.on("close", function () { if (!done) { done = true; resolve(); } });
        setTimeout(function () { if (done) return; done = true; try { client.child.kill("SIGKILL"); } catch (_e) {} resolve(); }, 2000);
      });
    },
  };
}

function _drain(client) {
  if (!client.pending) return;
  var sentinel = client.pending.sentinel;
  var marker = "\n" + sentinel + "\n";
  var idx = client.buf.indexOf(marker);
  var startAtZero = client.buf.indexOf(sentinel + "\n") === 0;
  var block;
  if (idx !== -1) { block = client.buf.slice(0, idx); client.buf = client.buf.slice(idx + marker.length); }
  else if (startAtZero) { block = ""; client.buf = client.buf.slice((sentinel + "\n").length); }
  else return;
  var p = client.pending; client.pending = null;
  var parsed;
  try { parsed = _parseBlock(block); } catch (e) { return p.reject(e); }
  if (parsed.error) return p.reject(parsed.error);
  p.resolve({ rows: parsed.rows, rowCount: parsed.rowCount });
}

function _bindOne(v) {
  if (v === null || v === undefined) return "NULL";
  if (typeof v === "number") return String(v);
  if (typeof v === "boolean") return v ? "TRUE" : "FALSE";
  return "'" + String(v).replace(/'/g, "''") + "'";
}
function _bindParams(sql, params) {
  return sql.replace(/\$(\d+)/g, function (_m, n) {
    var i = Number(n) - 1;
    if (i < 0 || i >= params.length) throw new Error("placeholder $" + n + " has no matching param");
    var v = params[i];
    // whereInArray emits `col = ANY($k)` for postgres with a JS array param;
    // a real node-postgres driver binds it as a postgres array. Replicate
    // that as an ARRAY[...] literal so the text-shim is faithful.
    if (Array.isArray(v)) return "ARRAY[" + v.map(_bindOne).join(",") + "]";
    return _bindOne(v);
  });
}

var _CMD_TAG_RE = /^(INSERT|UPDATE|DELETE|MERGE|SELECT|COPY|MOVE)\b(?:\s+\d+)*\s*$/;
var _CTRL_TAG_RE = /^(BEGIN|COMMIT|ROLLBACK|SET|RESET|SAVEPOINT|RELEASE|START|CREATE|DROP|ALTER|GRANT|REVOKE|TRUNCATE|COMMENT|DO|CALL|VACUUM|ANALYZE|EXPLAIN|TABLE|SHOW|DISCARD)\b/;

function _parseBlock(block) {
  var lines = block.split(/\r?\n/);
  while (lines.length && lines[lines.length - 1] === "") lines.pop();
  for (var i = 0; i < lines.length; i++) {
    var em = /^ERROR:\s+([0-9A-Za-z]{5}):\s*(.*)$/.exec(lines[i]);
    if (em) { var err = new Error("Postgres " + em[1] + ": " + em[2]); err.code = em[1]; return { error: err }; }
  }
  var affected = null, dataLines = [];
  for (var j = 0; j < lines.length; j++) {
    var ln = lines[j];
    if (/^(NOTICE|WARNING|DETAIL|HINT|LINE|LOCATION|CONTEXT|STATEMENT):/.test(ln)) continue;
    var tm = _CMD_TAG_RE.exec(ln);
    if (tm) { var nums = ln.trim().split(/\s+/).slice(1).map(Number); if (nums.length) affected = nums[nums.length - 1]; continue; }
    if (_CTRL_TAG_RE.test(ln) && ln.indexOf("\t") === -1) continue;
    dataLines.push(ln);
  }
  var rows = [];
  if (dataLines.length >= 1) {
    var headers = dataLines[0].split("\t");
    for (var k = 1; k < dataLines.length; k++) {
      var cells = dataLines[k].split("\t"), row = {};
      for (var c = 0; c < headers.length; c++) {
        var cell = cells[c];
        row[headers[c]] = (cell === NULL_SENTINEL || cell === undefined) ? null : cell;
      }
      rows.push(row);
    }
  }
  return { rows: rows, rowCount: (affected !== null) ? affected : rows.length, error: null };
}

// Thin externalDb over the persistent psql session: exactly the query /
// transaction / dialect surface the dispatcher consumes. transaction runs
// BEGIN/COMMIT on the same session (the dispatcher's claim path is the only
// transactional one).
function _pgExternalDb(client, driver) {
  var recorded = [];
  var xdb = {
    dialect: "postgres",
    recordedSql: recorded,
    query: function (s, p) {
      recorded.push(s);
      // The dispatcher binds JS Date params for the timestamp columns; the
      // psql shim inlines params textually, so Dates must become ISO strings
      // (a JS Date.toString() is not a portable TIMESTAMPTZ literal).
      var bound = (p || []).map(function (v) { return v instanceof Date ? v.toISOString() : v; });
      return driver.query(client, s, bound);
    },
    transaction: async function (fn) {
      await driver.query(client, "BEGIN", []);
      try { var r = await fn(xdb); await driver.query(client, "COMMIT", []); return r; }
      catch (e) { try { await driver.query(client, "ROLLBACK", []); } catch (_e) {} throw e; }
    },
  };
  return xdb;
}

function _stubTransport() {
  var calls = []; var nextStatus = 200;
  var fn = function (url, body, headers) { calls.push({ url: url, headers: headers }); return Promise.resolve({ status: nextStatus }); };
  fn.calls = calls; fn.setStatus = function (s) { nextStatus = s; };
  return fn;
}

function _dropTables() {
  _psql("DROP TABLE IF EXISTS " + DELIVERIES_TABLE + " CASCADE; DROP TABLE IF EXISTS " + ENDPOINTS_TABLE + " CASCADE;");
}

async function run() {
  var pg = await services.requireService("postgres");
  if (!pg.ok) throw new Error("postgres unreachable: " + pg.reason);
  _dropTables();

  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-wd-pg-"));
  await helpers.setupVaultOnly(tmpDir);   // for vault.seal of the per-endpoint secret

  var driver = _makeDockerPgDriver();
  var client = await driver.connect();
  var xdb = _pgExternalDb(client, driver);

  try {
    var now = 1700000000000;
    var clock = function () { return now; };
    var transport = _stubTransport();
    var wd = b.webhook.dispatcher({
      externalDb: xdb, httpRequest: transport, maxAttempts: 3,
      retryBackoff: { initialMs: 1000, maxMs: 5000, factor: 2 }, now: clock,
    });

    await wd.declareSchema();
    check("declareSchema renders valid Postgres DDL", true);

    var secret = "whsec_pg_secret_value";
    await wd.registerEndpoint({ endpointId: "ep_pg", url: "https://1.1.1.1/hooks", eventTypes: ["invoice.paid"], secret: secret });
    // Secret sealed at rest IN REAL POSTGRES.
    var sealedRow = _psql("SELECT secret_sealed FROM " + ENDPOINTS_TABLE + " WHERE endpoint_id = 'ep_pg';").trim();
    check("secret sealed at rest in Postgres (vault: prefix)", sealedRow.indexOf("vault:") === 0);
    check("plaintext secret NOT in Postgres row", sealedRow.indexOf("whsec_pg_secret_value") === -1);

    // dispatch → one delivery row, delivered (stub 200).
    var res = await wd.dispatch("invoice.paid", { id: "inv_pg_1", amount: 4200 });
    check("dispatch delivered on Postgres", res.delivered === 1 && res.failed === 0);
    var delivered = await wd.deliveries.list({ status: "delivered" });
    check("delivered row persisted in Postgres", delivered.length === 1);
    check("BIGINT attempts coerced to number 1", delivered[0].attempts === 1);
    check("responseStatus 200 round-trips", delivered[0].responseStatus === 200);

    // transient failure → stays pending with attempts incremented.
    transport.setStatus(503);
    await wd.dispatch("invoice.paid", { id: "inv_pg_2" });
    var pendingRows = _psql("SELECT count(*) FROM " + DELIVERIES_TABLE + " WHERE status = 'pending';").trim();
    check("transient failure pending in Postgres", pendingRows === "1");

    // processRetries claim transaction + dead-letter after maxAttempts.
    transport.setStatus(500);
    now += 10000; await wd.processRetries();   // attempt 2
    now += 10000; var r3 = await wd.processRetries();   // attempt 3 → dead
    check("processRetries dead-letters on Postgres", r3.dead === 1);
    var dlq = await wd.dlq.list();
    check("DLQ holds dead delivery on Postgres", dlq.length === 1 && dlq[0].attempts === 3);

    // The retry claim must row-lock with FOR UPDATE SKIP LOCKED on Postgres so
    // concurrent pollers see disjoint sets (no double-delivery). The two
    // processRetries() above ran against the real server, so a recorded claim
    // SELECT carrying that clause also proves Postgres accepted the syntax.
    var claimSelects = xdb.recordedSql.filter(function (s) {
      return /select/i.test(s) && /status = 'pending'/.test(s) && /next_attempt_at/.test(s);
    });
    check("processRetries claim SELECT uses FOR UPDATE SKIP LOCKED on real Postgres",
          claimSelects.length > 0 && claimSelects.every(function (s) { return /FOR UPDATE\s+SKIP LOCKED/i.test(s); }));

    // dlq.replay recovers.
    transport.setStatus(200);
    var replay = await wd.dlq.replay(dlq[0].deliveryId);
    check("dlq.replay delivers on Postgres", replay.ok === true);
    var dlqAfter = await wd.dlq.list();
    check("DLQ empty after replay on Postgres", dlqAfter.length === 0);
  } finally {
    try { await driver.close(client); } catch (_e) {}
    try { helpers.teardownVaultOnly(tmpDir); } catch (_e) {}
    _dropTables();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[webhook-dispatcher-pg] OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
