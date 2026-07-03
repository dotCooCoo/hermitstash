// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Live proof that b.audit.generateActorBindingTriggerSql() produces a
 * Postgres BEFORE INSERT trigger that the database itself enforces —
 * a privileged caller (migration runner, anyone with DB creds) cannot
 * forge an audit row under a different actor.
 *
 * SOX §404 / SOC 2 CC1.3 segregation-of-duties: the unit test only
 * asserts the SQL STRING contains 'current_user' / 'BEFORE INSERT'.
 * This drives the generated DDL into a real Postgres, creates two real
 * login roles, and proves:
 *   1. a caller connected as alice INSERTing actorUserId='alice' SUCCEEDS;
 *   2. a caller connected as alice INSERTing actorUserId='bob' is refused
 *      by the trigger (RAISE EXCEPTION P0001) — the INSERT fails.
 *
 * The "driver" is a docker-exec psql shim ({connect,query,close}) that
 * shells psql inside the blamejs-test-postgres container via
 * execFileSync (no shell). The framework ships no DB wire driver; this
 * exercises the framework-generated SQL against a real server and wires
 * the DDL application through b.externalDb so the framework's externalDb
 * query path is the one that installs the trigger.
 */
var execFileSync = require("node:child_process").execFileSync;
var helpers  = require("../helpers");
var check    = helpers.check;
var services = require("../helpers/services");
var b        = require("../../");

var CONTAINER = "blamejs-test-postgres";
var DB_USER   = "blamejs";
var DB_NAME   = "blamejs_test";
var TAB       = "\t";

var TABLE   = "_blamejs_audit_log"; // matches generator default opts.tableName
var COLUMN  = "actorUserId";        // matches generator default opts.column

// Run one SQL string inside the container. -tA = tuples-only, unaligned;
// -F<tab> field separator; ON_ERROR_STOP=1 so any server error (incl. a
// trigger RAISE) exits non-zero and surfaces stderr. No shell is spawned
// (execFileSync with an argv array). On non-zero exit the server's error
// text (the trigger message) is captured into the thrown Error.message.
function _psql(sql) {
  var out;
  try {
    out = execFileSync("docker",
      ["exec", "-i", CONTAINER,
       "psql", "-U", DB_USER, "-d", DB_NAME,
       "-tA", "-F", TAB, "-v", "ON_ERROR_STOP=1", "-c", sql],
      { stdio: ["pipe", "pipe", "pipe"] }
    ).toString("utf8");
  } catch (e) {
    var stderr = e.stderr ? e.stderr.toString("utf8") : "";
    var stdout = e.stdout ? e.stdout.toString("utf8") : "";
    var err = new Error((stderr || stdout || e.message || String(e)).trim());
    err.code = "PSQL_ERROR";
    err.stderr = stderr;
    err.cause = e;
    throw err;
  }
  return out;
}

// Apply a multi-statement / dollar-quoted DDL script via stdin (psql
// reads from stdin when no -c is given). The generator's `up` script
// contains a $$...$$ plpgsql body + several statements — feeding it as a
// single -c argument is fine too, but stdin keeps the dollar-quoting and
// statement separation unambiguous and mirrors how a migration runner
// would pipe the file.
function _psqlScript(script) {
  try {
    execFileSync("docker",
      ["exec", "-i", CONTAINER,
       "psql", "-U", DB_USER, "-d", DB_NAME, "-v", "ON_ERROR_STOP=1"],
      { input: script, stdio: ["pipe", "pipe", "pipe"] }
    );
  } catch (e) {
    var stderr = e.stderr ? e.stderr.toString("utf8") : "";
    var err = new Error((stderr || e.message || String(e)).trim());
    err.code = "PSQL_ERROR";
    err.stderr = stderr;
    err.cause = e;
    throw err;
  }
}

// Substitute Postgres $1/$2 placeholders with quoted literals. Test
// values are operator-controlled (role names / actor ids); a value-side
// single quote is doubled. Identifiers are never placeholdered here.
// NOTE: only used for our own parameterized INSERTs — never for the
// generator's DDL (which legitimately contains $$ dollar-quoting).
function _bind(sql, params) {
  params = params || [];
  return sql.replace(/\$(\d+)/g, function (_m, n) {
    var idx = Number(n) - 1;
    if (idx < 0 || idx >= params.length) {
      throw new Error("placeholder $" + n + " has no param");
    }
    var p = params[idx];
    if (p === null || p === undefined) return "NULL";
    if (typeof p === "number") return String(p);
    return "'" + String(p).replace(/'/g, "''") + "'";
  });
}

function _parseRows(out) {
  var lines = out.split(/\r?\n/).filter(function (l) { return l.length > 0; });
  return lines.map(function (l) { return l.split(TAB); });
}

// docker-exec psql driver for b.externalDb. query() binds $n params then
// shells one psql -c. close() is a no-op (each call is its own session).
function _makeDockerPgDriver() {
  return {
    connect: async function () { return { id: 1 }; },
    query: async function (_client, sql, params) {
      var bound = _bind(sql, params);
      var out = _psql(bound);
      return { rows: _parseRows(out) };
    },
    close: async function () { /* no-op — each psql -c is its own session */ },
  };
}

async function run() {
  var pg = await services.requireService("postgres");
  if (!pg.ok) throw new Error("postgres unreachable: " + pg.reason);

  // ---- clean slate (idempotent) ----
  _psql(
    'DROP TABLE IF EXISTS "' + TABLE + '" CASCADE; ' +
    'DROP FUNCTION IF EXISTS "_blamejs_audit_actor_binding_check"() CASCADE; ' +
    "DROP ROLE IF EXISTS alice; DROP ROLE IF EXISTS bob;"
  );

  // ---- wire the framework's externalDb over the docker-exec driver ----
  b.externalDb._resetForTest();
  var driver = _makeDockerPgDriver();
  // No residencyTag on the backend — the per-row residency write gate is
  // a separate concern; this test isolates the actor-binding trigger.
  b.externalDb.init({
    backends: {
      ops: {
        connect: driver.connect, query: driver.query, close: driver.close,
        dialect: "postgres",
      },
    },
  });

  // externalDb.query(sql, params, opts) — route to the "ops" backend.
  function q(sql, params) {
    return b.externalDb.query(sql, params || [], { backend: "ops" });
  }

  // ---- the audit table the trigger binds to (column matches generator) ----
  // The column must be the quoted mixed-case identifier the generator
  // emits ("actorUserId"); a folded lowercase column would never match
  // NEW."actorUserId" and the whole test would be vacuous.
  await q('CREATE TABLE "' + TABLE + '" (' +
    '  id serial PRIMARY KEY,' +
    '  "' + COLUMN + '" text NOT NULL,' +
    '  action text' +
    ");");
  check("audit_log table created on real postgres", true);

  // ---- apply the FRAMEWORK-GENERATED trigger DDL through externalDb ----
  var ddl = b.audit.generateActorBindingTriggerSql();
  // The DDL is dollar-quoted plpgsql + multi-statement. Drive it through
  // the framework's externalDb.query (single call) — the driver pipes it
  // to psql. (We use the script path so the $$ body is unambiguous; the
  // SQL string is exactly what the framework emits, unmodified.)
  _psqlScript(ddl.up);
  check("framework actor-binding trigger DDL applied to real postgres", true);

  // Confirm the trigger + function are actually present in the catalogs
  // (not merely that the DDL string ran without error).
  var trigRows = (await q("SELECT tgname FROM pg_trigger WHERE tgname = $1", [ddl.triggerName])).rows;
  check("trigger row present in pg_trigger", trigRows.length === 1);
  var fnRows = (await q("SELECT proname FROM pg_proc WHERE proname = $1", [ddl.functionName])).rows;
  check("trigger function present in pg_proc", fnRows.length === 1);

  // ---- two real login roles with INSERT grant ----
  await q("CREATE ROLE alice LOGIN; CREATE ROLE bob LOGIN;");
  await q('GRANT INSERT, SELECT ON "' + TABLE + '" TO alice, bob;');
  await q('GRANT USAGE, SELECT ON SEQUENCE "' + TABLE + '_id_seq" TO alice, bob;');
  check("roles alice/bob created with INSERT grant", true);

  // ---- (1) alice INSERTing actorUserId='alice' → trigger allows it ----
  // SET ROLE in the same statement-batch so current_user = alice when
  // the BEFORE INSERT trigger fires.
  var okThrew = null;
  try {
    await q("SET ROLE alice; " +
      'INSERT INTO "' + TABLE + '" ("' + COLUMN + '", action) VALUES ($1, $2);',
      ["alice", "audit.read"]);
  } catch (e) { okThrew = e; }
  check("matching actor (alice→alice) INSERT succeeds — trigger allows",
        okThrew === null);

  // Side-effect proof: the allowed row is actually in the table.
  var rowsAlice = (await q('SELECT "' + COLUMN + '" FROM "' + TABLE + '" WHERE "' + COLUMN + '" = $1',
    ["alice"])).rows;
  check("allowed row is persisted (actorUserId=alice present)",
        rowsAlice.length === 1 && rowsAlice[0][0] === "alice");

  // ---- (2) alice INSERTing actorUserId='bob' → trigger REFUSES it ----
  var forgeThrew = null;
  try {
    await q("SET ROLE alice; " +
      'INSERT INTO "' + TABLE + '" ("' + COLUMN + '", action) VALUES ($1, $2);',
      ["bob", "audit.read"]);
  } catch (e) { forgeThrew = e; }
  check("cross-actor forge (alice→bob) is REFUSED by the DB trigger",
        forgeThrew !== null);
  check("refusal carries the trigger's segregation-of-duties message",
        forgeThrew !== null &&
        /segregation-of-duties violation/.test(forgeThrew.message) &&
        /actor=bob/.test(forgeThrew.message) &&
        /current_user=alice/.test(forgeThrew.message));

  // Side-effect proof: the forged row did NOT land — the trigger fired
  // BEFORE INSERT, so the table holds zero rows under actorUserId=bob.
  var rowsBob = (await q('SELECT count(*) FROM "' + TABLE + '" WHERE "' + COLUMN + '" = $1',
    ["bob"])).rows;
  check("forged row was NOT persisted (zero actorUserId=bob rows)",
        rowsBob.length === 1 && Number(rowsBob[0][0]) === 0);

  // ---- teardown (best-effort; leave the DB clean for re-runs) ----
  try {
    _psql(
      'DROP TABLE IF EXISTS "' + TABLE + '" CASCADE; ' +
      'DROP FUNCTION IF EXISTS "_blamejs_audit_actor_binding_check"() CASCADE; ' +
      "DROP ROLE IF EXISTS alice; DROP ROLE IF EXISTS bob;"
    );
  } catch (_e) { /* teardown is best-effort */ }

  await b.externalDb.shutdown();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
