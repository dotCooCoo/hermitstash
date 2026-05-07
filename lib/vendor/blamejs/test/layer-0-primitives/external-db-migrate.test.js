"use strict";
/**
 * b.externalDb.migrate — migration runner for an externalDb backend.
 *
 * End-to-end test against a SQLite-backed fake externalDb driver.
 * Covers up()/down()/status(), idempotent re-apply, lock acquisition,
 * down() refusal when the migration has no down(), audit emissions.
 */

var fs    = require("fs");
var os    = require("os");
var path  = require("path");
var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var _makeSqliteDriver = helpers._makeSqliteDriver;

function _tempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix + "-"));
}

function _writeMigration(dir, name, body) {
  fs.writeFileSync(path.join(dir, name), body);
}

function _initWith(driver, dialect) {
  b.externalDb._resetForTest();
  b.externalDb.init({
    backends: {
      main: {
        connect: driver.connect,
        query:   driver.query,
        close:   driver.close,
        dialect: dialect || "postgres",
      },
    },
  });
}

async function _expectThrow(label, fn, codeRe) {
  var threw = null;
  try { await fn(); } catch (e) { threw = e; }
  check(label,
    threw !== null && (codeRe ? codeRe.test(threw.code || "") : true));
}

async function run() {
  // ---------- create() rejects bad opts ----------

  _expectThrow("create rejects missing dir",
    function () { b.externalDb.migrate.create({}); },
    /externaldb-migrate\/no-dir/);

  _expectThrow("create rejects unknown opt",
    function () { b.externalDb.migrate.create({ dir: ".", bogus: 1 }); });
    // validateOpts throws without a code attribute — just assert it throws.

  _expectThrow("create rejects bad audit",
    function () { b.externalDb.migrate.create({ dir: ".", audit: { nope: true } }); },
    /externaldb-migrate\/bad-audit/);

  _expectThrow("create rejects negative staleAfterMs",
    function () { b.externalDb.migrate.create({ dir: ".", staleAfterMs: -1 }); },
    /externaldb-migrate\/bad-stale/);

  // ---------- End-to-end: apply two migrations against a sqlite-backed driver ----------

  var dataDir = _tempDir("blamejs-xmig-data");
  var migDir  = _tempDir("blamejs-xmig-mig");
  var sqlitePath = path.join(dataDir, "fake-pg.db");
  var driver = _makeSqliteDriver(sqlitePath);
  _initWith(driver, "postgres");

  _writeMigration(migDir, "0001-make-thing.js",
    'module.exports = {\n' +
    '  description: "create thing",\n' +
    '  up:   async function (xdb) { await xdb.query("CREATE TABLE thing (id INTEGER PRIMARY KEY, name TEXT)", []); },\n' +
    '  down: async function (xdb) { await xdb.query("DROP TABLE thing", []); },\n' +
    '};\n');

  _writeMigration(migDir, "0002-add-row.js",
    'module.exports = {\n' +
    '  description: "seed thing",\n' +
    '  up:   async function (xdb) { await xdb.query("INSERT INTO thing (id, name) VALUES ($1, $2)", [1, "hello"]); },\n' +
    '  down: async function (xdb) { await xdb.query("DELETE FROM thing WHERE id = $1", [1]); },\n' +
    '};\n');

  // Fake audit captor — proves the migrate runner emits.
  var auditEmits = [];
  var fakeAudit = {
    safeEmit: function (event) { auditEmits.push(event); },
  };

  var migrate = b.externalDb.migrate.create({
    dir:    migDir,
    audit:  fakeAudit,
  });

  // Initial status — both pending
  var s0 = await migrate.status();
  check("status before apply: 2 pending",
    s0.pending.length === 2 && s0.applied.length === 0);

  // Apply
  var r1 = await migrate.up();
  check("up applied both migrations",
    r1.applied.length === 2 &&
    r1.applied.indexOf("0001-make-thing.js") !== -1 &&
    r1.applied.indexOf("0002-add-row.js") !== -1);

  // Status after — both applied
  var s1 = await migrate.status();
  check("status after apply: 2 applied, 0 pending",
    s1.applied.length === 2 && s1.pending.length === 0);

  // The migration's CREATE TABLE actually ran — query through externalDb.query
  var thingRes = await b.externalDb.query("SELECT * FROM thing WHERE id = $1", [1]);
  check("migration's up() ran (row exists)",
    thingRes.rows.length === 1 && thingRes.rows[0].name === "hello");

  // Re-apply — idempotent, both skipped
  var r2 = await migrate.up();
  check("re-apply: both skipped", r2.applied.length === 0 && r2.skipped.length === 2);

  // Audit fired
  check("audit captured up.success events",
    auditEmits.filter(function (e) { return e.action === "externaldb.migrate.up" && e.outcome === "success"; }).length === 2);
  check("audit captured lock acquired+released",
    auditEmits.some(function (e) { return e.action === "externaldb.migrate.lock.acquired"; }) &&
    auditEmits.some(function (e) { return e.action === "externaldb.migrate.lock.released"; }));

  // ---------- down(steps:1) ----------

  var d1 = await migrate.down({ steps: 1 });
  check("down(steps:1) reverted most recent migration",
    d1.reverted.length === 1 && d1.reverted[0] === "0002-add-row.js");

  var thingRes2 = await b.externalDb.query("SELECT * FROM thing WHERE id = $1", [1]);
  check("down() actually rolled back the row",
    thingRes2.rows.length === 0);

  var s2 = await migrate.status();
  check("status after partial rollback: 1 applied, 1 pending",
    s2.applied.length === 1 && s2.pending.length === 1);

  // ---------- down on a migration with no down() ----------

  // First re-apply 0002 so we can exercise no-down on a different migration
  await migrate.up();

  // Now write a 0003 without a down()
  _writeMigration(migDir, "0003-no-down.js",
    'module.exports = {\n' +
    '  description: "no down",\n' +
    '  up: async function (xdb) { await xdb.query("CREATE TABLE no_down_t (id INTEGER)", []); },\n' +
    '};\n');

  var r3 = await migrate.up();
  check("up applied 0003-no-down",
    r3.applied.length === 1 && r3.applied[0] === "0003-no-down.js");

  await _expectThrow("down() without a down() function throws clear error",
    async function () { await migrate.down({ steps: 1 }); },
    /externaldb-migrate\/no-down/);

  // ---------- rejects bad migration file ----------

  _writeMigration(migDir, "0004-bad.js",
    'module.exports = { description: "bad" };  // no up()\n');

  await _expectThrow("up() throws on migration missing up()",
    async function () { await migrate.up(); },
    /externaldb-migrate\/missing-up/);

  // ---------- Cleanup ----------

  driver._close();
  b.externalDb._resetForTest();
  fs.rmSync(dataDir, { recursive: true, force: true });
  fs.rmSync(migDir,  { recursive: true, force: true });
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
