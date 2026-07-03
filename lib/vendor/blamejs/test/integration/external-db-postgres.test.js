// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Live b.externalDb test against the docker Postgres container — the
 * framework's advertised PRIMARY external-db dialect. The "driver" is a
 * docker-exec psql shim: connect() spawns a persistent
 *
 *   docker exec -i blamejs-test-postgres psql -U blamejs -d blamejs_test ...
 *
 * subprocess (SQL fed over stdin, never as argv — no shell parsing of
 * SQL), and query() writes one statement plus an `\echo <sentinel>`
 * marker, reading the merged stdout/stderr block up to that sentinel.
 * A persistent session per client is what lets the framework's
 * transaction() keep BEGIN / SET LOCAL gucs / body / COMMIT on one
 * backend session — the precondition for the RLS + sessionGucs proof.
 *
 * It removes any npm pg-driver dep AND exercises the framework's
 * Postgres SQL, the read/write classifier, the per-row residency write
 * gate, and ROW LEVEL SECURITY against a real server:
 *
 *   1. CRUD round-trip (CREATE / INSERT $1 / SELECT / UPDATE / DELETE)
 *      with real returned rows + affectedRows.
 *   2. The read/write classifier on real SQL (SELECT read; INSERT /
 *      UPDATE / DELETE + a WITH-wrapped INSERT write) drives the gate.
 *   3. The residency write gate WIRED on the real query path: a cross-
 *      border write is refused (and never persists), an in-region write
 *      succeeds (and persists).
 *   4. declareRowPolicy RLS actually blocks a row for an unauthorized
 *      tenant while the authorized tenant sees its row, via the
 *      framework's transaction({ sessionGucs }) SET LOCAL plumbing and a
 *      restricted non-owner role.
 */

var spawn        = require("node:child_process").spawn;
var execFileSync = require("node:child_process").execFileSync;
var helpers  = require("../helpers");
var check    = helpers.check;
var services = require("../helpers/services");
var b = require("../../");

var CONTAINER = "blamejs-test-postgres";
// The field separator is set over stdin via `\pset fieldsep '\t'` (psql
// interprets the backslash escape into a real TAB there); passing -F'\t'
// in argv through `sh -c` would deliver the literal two chars backslash-t
// instead. -A = unaligned WITH a header row (column names recoverable).
// NOTE: no -q — quiet mode suppresses the per-statement command tags
// ("INSERT 0 1" / "UPDATE 2" / "DELETE 1") that carry affectedRows; the
// one-time prelude confirmation lines are drained before the first query.
// null sentinel distinguishes a real NULL from an empty string.
var PSQL_ARGS = "psql -U blamejs -d blamejs_test -A " +
                "-v ON_ERROR_STOP=0 -P null=__BJNULL__ 2>&1";
var NULL_SENTINEL = "__BJNULL__";

// ---- one-shot psql (setup / teardown / out-of-band assertions) ----
// Shell-free SQL: the statement travels on stdin, never in argv.
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

// ---- persistent-session docker-exec psql driver ----
//
// Each client is a long-lived psql subprocess. Statements are written to
// its stdin terminated by an `\echo <sentinel>`; the driver reads merged
// stdout until the sentinel line, then parses the block. SQLSTATE-coded
// ERROR lines (psql VERBOSITY verbose) throw an Error carrying `.code`,
// so the framework's auth-failure / deadlock / RLS-denial handling sees a
// real Postgres SQLSTATE.
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
        var client = {
          child:   child,
          buf:     "",
          pending: null,   // { sentinel, resolve, reject }
          closed:  false,
          exitErr: null,
        };
        child.on("error", function (e) {
          client.exitErr = e;
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
        // Prime the session: tab field separator (a real TAB via psql's
        // backslash interpretation), unaligned WITH headers (so column
        // names are recoverable), no footer, verbose errors (SQLSTATE).
        // Without -q these \pset lines each print a confirmation; drain
        // everything up to a priming sentinel so the first real query's
        // block starts clean.
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
        // Terminate the statement, then echo the sentinel. A trailing ';'
        // on an already-';'-terminated statement is a harmless empty
        // statement to Postgres.
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

var _seq = 0;

// Read complete statement blocks out of client.buf as the sentinel for
// the in-flight statement appears.
function _drain(client) {
  if (!client.pending) return;
  var sentinel = client.pending.sentinel;
  var marker = "\n" + sentinel + "\n";
  // Sentinel may also appear at buffer start (block produced no output).
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
    return;   // sentinel not yet fully received
  }
  var p = client.pending;
  client.pending = null;
  var parsed;
  try {
    parsed = _parseBlock(block);
  } catch (e) {
    return p.reject(e);
  }
  if (parsed.error) return p.reject(parsed.error);
  p.resolve({ rows: parsed.rows, rowCount: parsed.rowCount });
}

// Substitute Postgres $1/$2 placeholders with quoted literals. Every
// test value is operator-controlled (ids / regions / numbers / null);
// strings are single-quote-escaped, numbers inlined, null → NULL. The
// framework passes params out-of-band to a real driver; this shim folds
// them in because psql-over-stdin has no bind protocol.
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

// Command-tag lines psql prints for non-SELECT statements.
var _CMD_TAG_RE = /^(INSERT|UPDATE|DELETE|MERGE|SELECT|COPY|MOVE)\b(?:\s+\d+)*\s*$/;
// A control-keyword tag (BEGIN / COMMIT / SET / CREATE TABLE / ...) — no
// rows, no countable affected rows for our purposes.
var _CTRL_TAG_RE = /^(BEGIN|COMMIT|ROLLBACK|SET|RESET|SAVEPOINT|RELEASE|START|CREATE|DROP|ALTER|GRANT|REVOKE|TRUNCATE|COMMENT|DO|CALL|VACUUM|ANALYZE|EXPLAIN|TABLE|SHOW|DISCARD)\b/;

function _parseBlock(block) {
  var lines = block.split(/\r?\n/);
  // Drop a trailing empty line from the final newline.
  while (lines.length && lines[lines.length - 1] === "") lines.pop();

  // Surface a real Postgres error with its SQLSTATE so the framework's
  // SQLSTATE-keyed paths (42501 RLS-denied, 28000 auth, 40001 deadlock)
  // see a coded error.
  for (var i = 0; i < lines.length; i++) {
    var em = /^ERROR:\s+([0-9A-Za-z]{5}):\s*(.*)$/.exec(lines[i]);
    if (em) {
      var err = new Error("Postgres " + em[1] + ": " + em[2]);
      err.code = em[1];
      return { error: err };
    }
  }

  // Affected-row count from a DML command tag (e.g. "INSERT 0 3" → 3,
  // "UPDATE 2" → 2). The tag is the LAST tag-shaped line of the block.
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

  // dataLines (if any) carry a header row first, then data rows.
  var rows = [];
  if (dataLines.length >= 1) {
    var headers = dataLines[0].split("\t");
    for (var k = 1; k < dataLines.length; k++) {
      var cells = dataLines[k].split("\t");
      var row = {};
      for (var c = 0; c < headers.length; c++) {
        var cell = cells[c];
        if (cell === NULL_SENTINEL || cell === undefined) { row[headers[c]] = null; continue; }
        // Native-type coercion at the driver boundary. A real pg driver
        // returns a Postgres `boolean` as a JS true/false; the psql text
        // protocol renders it 't'/'f'. declareRowPolicy.up() reads the
        // boolean pg_class.relrowsecurity to decide whether to ENABLE RLS
        // — left as the string "f" it would be JS-truthy and the ENABLE
        // would be skipped. Coerce the boolean system columns the
        // framework reads so the shim matches a real driver's typing.
        if (_BOOL_COLUMNS[headers[c]] === true && (cell === "t" || cell === "f")) {
          row[headers[c]] = (cell === "t");
        } else {
          row[headers[c]] = cell;
        }
      }
      rows.push(row);
    }
  }
  var rowCount = (affected !== null) ? affected : rows.length;
  return { rows: rows, rowCount: rowCount, error: null };
}

// Postgres system columns the framework reads as JS booleans (a real pg
// driver coerces these; the psql text protocol renders them 't'/'f').
var _BOOL_COLUMNS = { relrowsecurity: true, relforcerowsecurity: true };

// Run fn() under the gdpr posture, restoring the prior posture in a
// finally so parallel smoke files aren't poisoned.
async function _underGdpr(fn) {
  var prior = b.compliance.current();
  b.compliance.clear();
  b.compliance.set("gdpr");
  try { await fn(); }
  finally {
    b.compliance.clear();
    if (prior) b.compliance.set(prior);
  }
}

async function _expectThrow(label, fn, expectedCode) {
  var threw = null;
  try { await fn(); } catch (e) { threw = e; }
  check(label + ": threw " + expectedCode,
        threw !== null && threw.code === expectedCode);
  return threw;
}

async function run() {
  var pg = await services.requireService("postgres");
  if (!pg.ok) throw new Error("postgres unreachable: " + pg.reason);

  // ---- fresh schema ----
  _psql([
    "DROP TABLE IF EXISTS orders;",
    "DROP TABLE IF EXISTS eu_rows;",
    "DROP TABLE IF EXISTS rls_sessions;",
    "DROP ROLE IF EXISTS blamejs_rls_app;",
  ].join("\n"));

  var driver = _makeDockerPgDriver();
  b.externalDb._resetForTest();
  b.externalDb.init({
    backends: {
      ops: {
        connect: driver.connect, query: driver.query, close: driver.close,
        dialect: "postgres", residencyTag: "eu",
      },
    },
  });

  // ====================================================================
  // 1. CRUD round-trip against real Postgres.
  // ====================================================================
  await b.externalDb.query(
    "CREATE TABLE orders (id text PRIMARY KEY, region text, total int)", []);
  check("postgres: CREATE TABLE ran", true);

  var ins = await b.externalDb.query(
    "INSERT INTO orders (id, region, total) VALUES ($1, $2, $3)",
    ["o-1", "eu", 100]);
  check("postgres: INSERT affectedRows = 1", ins.rowCount === 1);

  await b.externalDb.query(
    "INSERT INTO orders (id, region, total) VALUES ($1, $2, $3)",
    ["o-2", "eu", 250]);

  var sel = await b.externalDb.query(
    "SELECT id, region, total FROM orders WHERE id = $1", ["o-1"]);
  check("postgres: SELECT returns one row", sel.rowCount === 1 && sel.rows.length === 1);
  check("postgres: SELECT round-trips id",     sel.rows[0].id === "o-1");
  check("postgres: SELECT round-trips region", sel.rows[0].region === "eu");
  check("postgres: SELECT round-trips total",  sel.rows[0].total === "100");

  var upd = await b.externalDb.query(
    "UPDATE orders SET total = $1 WHERE id = $2", [999, "o-1"]);
  check("postgres: UPDATE affectedRows = 1", upd.rowCount === 1);
  var selU = await b.externalDb.query("SELECT total FROM orders WHERE id = $1", ["o-1"]);
  check("postgres: UPDATE persisted", selU.rows[0].total === "999");

  var del = await b.externalDb.query("DELETE FROM orders WHERE id = $1", ["o-2"]);
  check("postgres: DELETE affectedRows = 1", del.rowCount === 1);
  var selAll = await b.externalDb.query("SELECT id FROM orders ORDER BY id", []);
  check("postgres: one row remains after DELETE",
        selAll.rowCount === 1 && selAll.rows[0].id === "o-1");

  // NULL round-trips as a real null (distinguished from empty string).
  await b.externalDb.query(
    "INSERT INTO orders (id, region, total) VALUES ($1, $2, $3)",
    ["o-null", null, 0]);
  var selNull = await b.externalDb.query(
    "SELECT region FROM orders WHERE id = $1", ["o-null"]);
  check("postgres: NULL column round-trips as null", selNull.rows[0].region === null);
  await b.externalDb.query("DELETE FROM orders WHERE id = $1", ["o-null"]);

  // ====================================================================
  // 2. read/write classifier on real SQL drives the gate.
  //    Under gdpr + eu backend: SELECT (read) passes untagged; a CTE-
  //    wrapped INSERT (write) is refused untagged — proving the
  //    classifier resolves the CTE main verb against real SQL the same
  //    way Postgres would execute it.
  // ====================================================================
  await _underGdpr(async function () {
    var s = await b.externalDb.query("SELECT id FROM orders WHERE id = $1", ["o-1"]);
    check("classifier: SELECT classified read → passes untagged, rows returned",
          s.rowCount === 1);
  });

  await _underGdpr(async function () {
    await _expectThrow("classifier: WITH ... INSERT (CTE write) refused untagged",
      function () {
        return b.externalDb.query(
          "WITH src AS (SELECT 'o-cte' AS id) INSERT INTO orders (id) SELECT id FROM src", []);
      },
      "RESIDENCY_GATE_REQUIRED");
  });
  // The refused CTE write never reached Postgres.
  var cteCheck = _psql("SELECT count(*) AS n FROM orders WHERE id = 'o-cte';");
  check("classifier: refused CTE write did not persist", /\b0\b/.test(cteCheck.trim()));

  // The SAME CTE write, run directly through psql, DOES place the row —
  // confirming the statement is a genuine write that Postgres executes,
  // not a no-op the gate refused for free.
  _psql("WITH src AS (SELECT 'o-cte-real' AS id) INSERT INTO orders (id) SELECT id FROM src;");
  var cteReal = _psql("SELECT count(*) AS n FROM orders WHERE id = 'o-cte-real';");
  check("classifier: that CTE shape is a real write on Postgres", /\b1\b/.test(cteReal.trim()));
  _psql("DELETE FROM orders WHERE id = 'o-cte-real';");

  // ====================================================================
  // 3. residency write gate WIRED on the real query path.
  //    eu backend + gdpr posture:
  //      - cross-border tag "us"  → RESIDENCY_TAG_MISMATCH, row absent
  //      - in-region   tag "eu"   → succeeds, row present
  // ====================================================================
  await _underGdpr(async function () {
    await _expectThrow("residency: cross-border write (tag 'us') refused",
      function () {
        return b.externalDb.query(
          "INSERT INTO orders (id, region, total) VALUES ($1, $2, $3)",
          ["o-us", "us", 1],
          { rowResidencyTag: "us" });
      },
      "RESIDENCY_TAG_MISMATCH");
  });
  var usCheck = _psql("SELECT count(*) AS n FROM orders WHERE id = 'o-us';");
  check("residency: refused cross-border write did NOT persist", /\b0\b/.test(usCheck.trim()));

  await _underGdpr(async function () {
    var ok = await b.externalDb.query(
      "INSERT INTO orders (id, region, total) VALUES ($1, $2, $3)",
      ["o-eu", "eu", 7],
      { rowResidencyTag: "eu" });
    check("residency: in-region write (tag 'eu') succeeded", ok.rowCount === 1);
  });
  var euCheck = _psql("SELECT count(*) AS n FROM orders WHERE id = 'o-eu';");
  check("residency: in-region write DID persist", /\b1\b/.test(euCheck.trim()));

  // Untagged write under gdpr + eu backend → gate required (wire not reached).
  await _underGdpr(async function () {
    await _expectThrow("residency: untagged write refused",
      function () {
        return b.externalDb.query(
          "INSERT INTO orders (id) VALUES ($1)", ["o-untagged"]);
      },
      "RESIDENCY_GATE_REQUIRED");
  });
  var untaggedCheck = _psql("SELECT count(*) AS n FROM orders WHERE id = 'o-untagged';");
  check("residency: untagged-refused write did NOT persist", /\b0\b/.test(untaggedCheck.trim()));

  // ====================================================================
  // 4 + 5. declareRowPolicy RLS + transaction({ sessionGucs }) SET LOCAL.
  //    A restricted, non-owner, non-superuser role + an RLS policy keyed
  //    on the app.tenant_id GUC. Through the framework's transaction()
  //    SET LOCAL plumbing, the authorized tenant sees its row and an
  //    unauthorized tenant sees zero — proving both the generated RLS DDL
  //    blocks rows AND the sessionGucs bindings take effect for the
  //    policy on a real session.
  // ====================================================================

  // Restricted role + table owned by the superuser; the role gets DML
  // grants but is subject to RLS (RLS never applies to owners/superusers).
  _psql([
    "CREATE ROLE blamejs_rls_app NOLOGIN;",
    "CREATE TABLE rls_sessions (id text PRIMARY KEY, tenant_id text NOT NULL, payload text);",
    "INSERT INTO rls_sessions VALUES ('s-acme','acme','acme-secret'), ('s-globex','globex','globex-secret');",
    "GRANT SELECT, INSERT, UPDATE, DELETE ON rls_sessions TO blamejs_rls_app;",
  ].join("\n"));

  // Apply the framework-generated RLS migration. declareRowPolicy returns
  // a migration spec whose up(xdb) issues the ENABLE + CREATE POLICY DDL;
  // drive it with a thin xdb that calls the live backend's query path
  // (explicit backend so a stray ALS role can't reroute it).
  var policy = b.db.declareRowPolicy({
    schema:    "public",
    table:     "rls_sessions",
    name:      "tenant_isolation",
    role:      "blamejs_rls_app",
    using:     "tenant_id = current_setting('app.tenant_id', true)",
    withCheck: "tenant_id = current_setting('app.tenant_id', true)",
    command:   "ALL",
  });
  check("declareRowPolicy: returns a migration spec", policy && typeof policy.up === "function");

  var applyXdb = {
    query: function (sql, params) {
      return b.externalDb.query(sql, params, { backend: "ops" });
    },
  };
  var applied = await policy.up(applyXdb, { externalDb: b.externalDb, backendName: "ops" });
  check("declareRowPolicy: applied (policy name returned)",
        applied && applied.policy === "public.rls_sessions.tenant_isolation");

  // Confirm RLS is actually enabled on the real table.
  var rlsState = _psql(
    "SELECT relrowsecurity FROM pg_class WHERE relname = 'rls_sessions';");
  check("RLS: ENABLE ROW LEVEL SECURITY took effect on the real table",
        /\bt\b/.test(rlsState.trim()));
  var polState = _psql(
    "SELECT polname FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid " +
    "WHERE c.relname = 'rls_sessions';");
  check("RLS: the policy exists in pg_policy", /tenant_isolation/.test(polState));

  // Authorized tenant — within a transaction set SET LOCAL role +
  // app.tenant_id via sessionGucs; the RLS policy filters to that tenant.
  var acmeRows = await b.externalDb.transaction(async function (tx) {
    return await tx.query("SELECT id, tenant_id FROM rls_sessions ORDER BY id", []);
  }, {
    backend:     "ops",
    sessionGucs: { "role": "blamejs_rls_app", "app.tenant_id": "acme" },
  });
  check("RLS: authorized tenant 'acme' sees exactly its 1 row",
        acmeRows.rowCount === 1 && acmeRows.rows.length === 1);
  check("RLS: the visible row is acme's", acmeRows.rows[0].id === "s-acme");

  // Unauthorized tenant — same table, a tenant value that owns no rows;
  // RLS yields zero rows even though the rows physically exist.
  var nobodyRows = await b.externalDb.transaction(async function (tx) {
    return await tx.query("SELECT id, tenant_id FROM rls_sessions ORDER BY id", []);
  }, {
    backend:     "ops",
    sessionGucs: { "role": "blamejs_rls_app", "app.tenant_id": "nobody" },
  });
  check("RLS: unauthorized tenant 'nobody' sees ZERO rows", nobodyRows.rowCount === 0);

  // The other real tenant ('globex') sees only its own row — confirms the
  // GUC value, not a constant, drives the policy.
  var globexRows = await b.externalDb.transaction(async function (tx) {
    return await tx.query("SELECT id FROM rls_sessions ORDER BY id", []);
  }, {
    backend:     "ops",
    sessionGucs: { "role": "blamejs_rls_app", "app.tenant_id": "globex" },
  });
  check("RLS: tenant 'globex' sees exactly its own row",
        globexRows.rowCount === 1 && globexRows.rows[0].id === "s-globex");

  // Control: the owning superuser (no SET LOCAL role) bypasses RLS and
  // sees every row — proves the prior zero/one results were RLS filtering,
  // not an empty table or a broken session.
  var allRows = await b.externalDb.query("SELECT id FROM rls_sessions ORDER BY id", []);
  check("RLS: owner/superuser bypasses RLS and sees all rows", allRows.rowCount === 2);

  // The WITH CHECK clause blocks a cross-tenant INSERT: as 'acme', try to
  // write a 'globex' row → 42501 (policy violation). This proves the
  // sessionGucs binding gates WRITES too, not just reads.
  await _expectThrow("RLS: WITH CHECK blocks a cross-tenant INSERT (SQLSTATE 42501)",
    function () {
      return b.externalDb.transaction(async function (tx) {
        await tx.query(
          "INSERT INTO rls_sessions (id, tenant_id, payload) VALUES ($1, $2, $3)",
          ["s-evil", "globex", "x"]);
      }, {
        backend:     "ops",
        sessionGucs: { "role": "blamejs_rls_app", "app.tenant_id": "acme" },
      });
    },
    "42501");
  var evilCheck = _psql("SELECT count(*) AS n FROM rls_sessions WHERE id = 's-evil';");
  check("RLS: the cross-tenant INSERT did NOT persist (rolled back)",
        /\b0\b/.test(evilCheck.trim()));

  // ---- teardown ----
  await b.externalDb.shutdown();
  b.compliance.clear();
  _psql([
    "DROP TABLE IF EXISTS orders;",
    "DROP TABLE IF EXISTS rls_sessions;",
    "DROP ROLE IF EXISTS blamejs_rls_app;",
  ].join("\n"));
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
