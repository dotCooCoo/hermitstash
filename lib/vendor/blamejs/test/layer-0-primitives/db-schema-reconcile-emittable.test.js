"use strict";
/**
 * dbSchema.reconcileTable verbatim column-TYPE string — statement-emittable
 * gate parity with b.sql.createTable. The TYPE string is concatenated
 * verbatim into CREATE TABLE (db-schema.js:264) + ALTER TABLE ADD COLUMN
 * (db-schema.js:271); neither concat routes through the catalog emittable
 * gate b.sql.createTable got in v0.15.3 (#105). RED today: reconcileTable
 * does NOT throw and the stacked DROP destroys the sentinel table.
 */

var helpers  = require("../helpers");
var check    = helpers.check;
var fs       = helpers.fs;
var os       = helpers.os;
var path     = helpers.path;
var sqlite   = require("node:sqlite");
var dbSchema = require("../../lib/db-schema");

// Real NUL built from a code point — never a literal NUL typed into source.
var NUL = String.fromCharCode(0);

function _openDb(tmpDir, name) {
  return new sqlite.DatabaseSync(path.join(tmpDir, name || "emit.db"));
}

function threwMatching(fn, pattern) {
  try { fn(); } catch (e) { return pattern.test(e.message || "") ? e : null; }
  return null;
}

function _sentinelAlive(db) {
  return db.prepare(
    "SELECT count(*) AS n FROM sqlite_master WHERE type='table' AND name='secrets'"
  ).get().n === 1;
}

function _seedSentinel(db) {
  dbSchema.runSql(db, "DROP TABLE IF EXISTS secrets");
  dbSchema.runSql(db, "CREATE TABLE secrets (k TEXT)");
  dbSchema.runSql(db, "INSERT INTO secrets VALUES ('topsecret')");
}

async function run() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-reconcile-emit-"));

  // ---- CREATE TABLE path: hostile TYPE stacks a DROP ----
  var dbCreate = _openDb(tmp, "create.db");
  _seedSentinel(dbCreate);
  check("setup: sentinel 'secrets' table exists before reconcile",
    _sentinelAlive(dbCreate));

  var createErr = threwMatching(function () {
    dbSchema.reconcileTable(dbCreate, {
      name: "t_create",
      columns: { id: "TEXT PRIMARY KEY", evil: "TEXT); DROP TABLE secrets; --" },
    }, { onDrift: "ignore" });
  }, /.*/);
  // RED today: createErr === null (no throw). GREEN: the catalog gate refuses.
  check("reconcileTable refuses a CREATE-path verbatim type that stacks a statement",
    !!createErr);
  // Load-bearing RED proof: the stacked DROP must NOT have executed.
  check("reconcileTable did not let the stacked DROP destroy the sentinel table (CREATE path)",
    _sentinelAlive(dbCreate));
  dbCreate.close();

  // ---- ADD COLUMN path: reconcile a table, then re-reconcile with a
  // hostile new-column TYPE so the ALTER TABLE ADD COLUMN concat fires. ----
  var dbAlter = _openDb(tmp, "alter.db");
  _seedSentinel(dbAlter);
  dbSchema.reconcileTable(dbAlter, {
    name: "t_alter", columns: { id: "TEXT PRIMARY KEY" },
  }, { onDrift: "ignore" });

  var alterErr = threwMatching(function () {
    dbSchema.reconcileTable(dbAlter, {
      name: "t_alter",
      columns: { id: "TEXT PRIMARY KEY", evil2: "TEXT); DROP TABLE secrets; --" },
    }, { onDrift: "ignore" });
  }, /.*/);
  check("reconcileTable refuses an ADD-COLUMN verbatim type that stacks a statement",
    !!alterErr);
  check("reconcileTable did not let the stacked DROP destroy the sentinel table (ADD COLUMN path)",
    _sentinelAlive(dbAlter));
  dbAlter.close();

  // ---- unbalanced-quote TYPE ----
  var dbQuote = _openDb(tmp, "quote.db");
  _seedSentinel(dbQuote);
  check("reconcileTable refuses a verbatim type with an unbalanced quote",
    !!threwMatching(function () {
      dbSchema.reconcileTable(dbQuote, {
        name: "t_quote", columns: { id: "TEXT PRIMARY KEY", c: "TEXT'" },
      }, { onDrift: "ignore" });
    }, /.*/));
  dbQuote.close();

  // ---- NUL byte in the TYPE string (built via String.fromCharCode(0)) ----
  var dbNul = _openDb(tmp, "nul.db");
  _seedSentinel(dbNul);
  check("reconcileTable refuses a verbatim type carrying a NUL byte",
    !!threwMatching(function () {
      dbSchema.reconcileTable(dbNul, {
        name: "t_nul", columns: { id: "TEXT PRIMARY KEY", c: "TEXT" + NUL + " DEFAULT x" },
      }, { onDrift: "ignore" });
    }, /.*/));
  dbNul.close();

  // ---- a legitimate verbatim type still reconciles (no over-rejection) ----
  var dbOk = _openDb(tmp, "ok.db");
  check("reconcileTable still allows a legitimate multi-word verbatim type",
    threwMatching(function () {
      dbSchema.reconcileTable(dbOk, {
        name: "t_ok",
        columns: { id: "TEXT PRIMARY KEY", n: "INTEGER NOT NULL DEFAULT 0", v: "VARCHAR(255)" },
      }, { onDrift: "ignore" });
    }, /.*/) === null);
  dbOk.close();

  fs.rmSync(tmp, { recursive: true, force: true });
  console.log("OK — db-schema reconcileTable emittable-gate tests");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
