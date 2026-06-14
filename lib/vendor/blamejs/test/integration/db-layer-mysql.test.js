"use strict";
/**
 * Live test of the framework's SYNCHRONOUS data layer
 * (lib/db-query.js / lib/db-schema.js / lib/migrations.js /
 * lib/seeders.js) against the docker MySQL container.
 *
 * Same intent as db-layer-postgres.test.js: those four modules were built
 * for node:sqlite (synchronous) and compose every statement through b.sql
 * with { dialect: "sqlite" } — `?` placeholders + DOUBLE-QUOTED identifiers
 * — with NO per-dialect translation (clusterStorage, the advertised
 * rewrite layer, is bypassed by these single-node modules). Host smoke
 * only ever runs them on sqlite.
 *
 * MySQL-specific faithfulness in the adapter:
 *   - b.sql emits `"camelCase"` double-quoted identifiers. MySQL's default
 *     sql_mode treats `"..."` as a STRING literal, not an identifier, so a
 *     real MySQL driver must run with ANSI_QUOTES enabled for the
 *     framework's quote-by-construction SQL to parse at all. Each docker-
 *     exec mysql call is a fresh connection, so every statement is prefixed
 *     with `SET SESSION sql_mode=...,ANSI_QUOTES`.
 *   - `?` placeholders fold into the SQL as quoted literals at the adapter
 *     boundary (the mysql CLI has no bind protocol); every value here is
 *     operator-controlled.
 *   - run() returns { changes } from ROW_COUNT() issued in the SAME mysql
 *     invocation as the write (ROW_COUNT is connection-scoped).
 *   - BIGINT comes back as a JS string in --batch mode (matching the
 *     mysql2 BIGINT-as-string default the framework readers expect).
 *
 * The custom `check` helper is fail-fast, so this file records every
 * assertion through a local soft-check (all divergences surface in one
 * run) and ends with WORKING-path + KNOWN-BUG gate assertions so the file
 * is a stable green coverage gate that flips red the moment a lib is fixed.
 *
 * Tables/migration-rows are namespaced (bjml_*) in a dedicated bjml_test
 * database + dropped in setup + teardown so a concurrent test can't collide.
 */

var execFileSync = require("node:child_process").execFileSync;
var helpers  = require("../helpers");
var check    = helpers.check;
var services = require("../helpers/services");

var safeSql         = require("../../lib/safe-sql");
var frameworkSchema = require("../../lib/framework-schema");
var dbSchema        = require("../../lib/db-schema");
var migrations      = require("../../lib/migrations");
var seeders         = require("../../lib/seeders");
var { Query }       = require("../../lib/db-query");

var CONTAINER = "blamejs-test-mysql";
var DB_NAME   = "bjml_test";
// ANSI_QUOTES makes MySQL honor the b.sql double-quoted identifiers; without
// it every "col" parses as a string literal and the SQL is meaningless.
// PIPES_AS_CONCAT off-by-default is fine (we emit no `||`). Prefixed to every
// statement batch since each docker-exec is a fresh connection.
var SQLMODE = "SET SESSION sql_mode=CONCAT(@@sql_mode,',ANSI_QUOTES');\n";

var _results = [];
function soft(label, cond) {
  _results.push({ label: label, ok: !!cond });
  console.log((cond ? "  ok   " : "  FAIL ") + label);
  return !!cond;
}

// ---- shared synchronous docker-exec mysql ----
// SQL travels on stdin (never argv → no shell parsing). --batch gives
// TAB-separated, header-bearing output; --raw disables escaping so a
// value round-trips byte-faithfully. stderr captured + merged so a SQL
// error surfaces with its message.
function _mysqlRaw(sql, opts) {
  opts = opts || {};
  var db = opts.noDb ? [] : [DB_NAME];
  var args = ["exec", "-i", CONTAINER, "mysql", "-uroot", "-pblamejs_test_root",
              "--batch", "--raw"].concat(db);
  try {
    var out = execFileSync("docker", args,
      { input: (opts.noMode ? "" : SQLMODE) + sql + "\n",
        stdio: ["pipe", "pipe", "pipe"], maxBuffer: 64 * 1024 * 1024 });
    return { ok: true, out: out.toString("utf8") };
  } catch (e) {
    var stderr = e.stderr ? e.stderr.toString("utf8") : "";
    return { ok: false, out: (e.stdout ? e.stdout.toString("utf8") : ""), err: stderr || (e.message || String(e)) };
  }
}

// One-shot for setup / teardown / out-of-band assertions; throws on error.
function _mysql(sql, opts) {
  var r = _mysqlRaw(sql, opts);
  if (!r.ok) throw new Error("mysql setup failed for [" + sql.slice(0, 120) + "]: " + _clean(r.err));
  return r.out;
}

function _clean(s) {
  return String(s || "").split(/\r?\n/)
    .filter(function (l) { return l && l.indexOf("[Warning] World-writable") === -1; })
    .join(" ").slice(0, 220);
}

var BLOB_HEX = "0x";
function _bindQ(sql, params) {
  params = params || [];
  var i = 0;
  return sql.replace(/\?/g, function () {
    if (i >= params.length) throw new Error("placeholder/param count mismatch in: " + sql);
    var v = params[i++];
    if (v === null || v === undefined) return "NULL";
    if (Buffer.isBuffer(v)) return BLOB_HEX + (v.length ? v.toString("hex") : "00");
    if (typeof v === "number") return String(v);
    if (typeof v === "boolean") return v ? "1" : "0";
    return "'" + String(v).replace(/\\/g, "\\\\").replace(/'/g, "''") + "'";
  });
}

var _BLOB_COLUMNS = { blobcol: true, payload: true, nonce: true };

// Parse a --batch block: drop the warning line(s), header row first, then
// data rows. The SQLMODE `SET` produces no output. Multiple statements in
// one batch each emit their own header+rows; we parse the LAST result set
// (the SELECT we care about), since reads issue exactly one SELECT.
function _parseSelect(out) {
  var lines = out.split(/\r?\n/).filter(function (l) {
    return l.length > 0 && l.indexOf("[Warning] World-writable") === -1;
  });
  if (lines.length === 0) return [];
  var headers = lines[0].split("\t");
  var rows = [];
  for (var i = 1; i < lines.length; i++) {
    var cells = lines[i].split("\t");
    var row = {};
    for (var c = 0; c < headers.length; c++) {
      var hdr = headers[c];
      var cell = cells[c];
      if (cell === "NULL" || cell === undefined) { row[hdr] = null; continue; }
      if (_BLOB_COLUMNS[hdr] === true) {
        // --raw emits binary bytes verbatim; recover them as a Buffer.
        row[hdr] = Buffer.from(cell, "binary");
      } else {
        row[hdr] = cell;
      }
    }
    rows.push(row);
  }
  return rows;
}

function _isWrite(sql) {
  return /^\s*(INSERT|UPDATE|DELETE|REPLACE|MERGE)\b/i.test(sql);
}

// ---- node:sqlite-Statement-SHAPED adapter over real MySQL ----
function _makeMysqlAdapter() {
  return {
    prepare: function (sql) {
      return {
        get: function () {
          var params = Array.prototype.slice.call(arguments);
          var r = _mysqlRaw(_bindQ(sql, params));
          if (!r.ok) throw new Error("MySQL error: " + _clean(r.err));
          var rows = _parseSelect(r.out);
          return rows.length ? rows[0] : undefined;
        },
        all: function () {
          var params = Array.prototype.slice.call(arguments);
          var r = _mysqlRaw(_bindQ(sql, params));
          if (!r.ok) throw new Error("MySQL error: " + _clean(r.err));
          return _parseSelect(r.out);
        },
        run: function () {
          var params = Array.prototype.slice.call(arguments);
          var bound = _bindQ(sql, params);
          // ROW_COUNT() in the SAME connection/batch as the write reports
          // affectedRows (it is connection-scoped).
          var r = _mysqlRaw(bound + ";\nSELECT ROW_COUNT() AS rc;");
          if (!r.ok) throw new Error("MySQL error: " + _clean(r.err));
          var changes = 0;
          if (_isWrite(sql)) {
            var rows = _parseSelect(r.out);
            // The LAST result set is the ROW_COUNT() select.
            var last = rows.length ? rows[rows.length - 1] : null;
            if (last && last.rc !== undefined && last.rc !== null) changes = Number(last.rc);
          }
          return { changes: changes, lastInsertRowid: 0 };
        },
      };
    },
    exec: function (sql) {
      var r = _mysqlRaw(sql);
      if (!r.ok) throw new Error("MySQL error: " + _clean(r.err));
      return r.out;
    },
    // The handle declares its dialect so the data layer emits MySQL-correct
    // SQL: BACKTICK-quoted identifiers (the framework SQL no longer relies
    // on ANSI_QUOTES — backticks work in either sql_mode), the single-row
    // write resolves the PRIMARY KEY in a prior SELECT then writes
    // `WHERE pk = ?` (MySQL rejects a subquery referencing the UPDATE/DELETE
    // target — error 1093), listColumns reads information_schema, and the
    // migrations/seeders registry/lock tables use VARCHAR(191) for key text
    // columns + BIGINT for the ms-epoch lock timestamp.
    dialect: "mysql",
  };
}

function _from(adapter, table, declared) {
  return new Query(adapter, table, {
    declaredColumns: declared || null,
    columnGateMode:  declared ? "reject" : "off",
  });
}

function _block(label, fn) {
  try { fn(); return true; }
  catch (e) {
    soft(label + " (threw: " + ((e && e.message) || String(e)).replace(/\s+/g, " ").slice(0, 200) + ")", false);
    return false;
  }
}

async function run() {
  var mysqlSvc = await services.requireService("mysql");
  if (!mysqlSvc.ok) throw new Error("mysql unreachable: " + mysqlSvc.reason);

  // Dedicated database so we never touch other suites' fixtures.
  _mysql("CREATE DATABASE IF NOT EXISTS " + DB_NAME + ";", { noDb: true, noMode: true });

  var adapter = _makeMysqlAdapter();

  var T = "bjml_orders";
  var ALL_TABLES = [
    '"' + T + '"', '"bjml_things"', '"bjml_widgets"', '"bjml_seed_target"',
    '"_blamejs_migrations"', '"_blamejs_migrations_lock"',
    '"_blamejs_seeders"', '"_blamejs_seeders_lock"',
  ];
  function _dropAll() {
    _mysql(ALL_TABLES.map(function (t) { return "DROP TABLE IF EXISTS " + t + ";"; }).join("\n"));
  }
  _dropAll();

  // ====================================================================
  // 1. reconcileTable: CREATE TABLE IF NOT EXISTS + second-reconcile
  //    idempotence on real MySQL.
  // ====================================================================
  // region is declared VARCHAR (not TEXT) because the test indexes it
  // below: MySQL refuses an unbounded TEXT/BLOB column in an index without
  // a prefix length (error 1170). On MySQL an operator who wants an indexed
  // string column declares it VARCHAR — that is an operator-schema choice
  // the framework honors, not something reconcileIndex can guess a length
  // for. The Postgres sibling uses TEXT (Postgres indexes TEXT directly).
  var tableDef = {
    name: T,
    columns: { _id: "VARCHAR(64) PRIMARY KEY", region: "VARCHAR(64)", total: "BIGINT", note: "TEXT" },
  };
  var reconcileOk = _block(
    "reconcileTable: first reconcile (CREATE TABLE IF NOT EXISTS) runs on real MySQL",
    function () { dbSchema.reconcileTable(adapter, tableDef, { onDrift: "refuse" }); });
  if (reconcileOk) soft("reconcileTable: first reconcile ran clean on MySQL", true);

  var tblPresent = _mysql(
    "SELECT count(*) AS n FROM information_schema.tables WHERE table_schema='" +
    DB_NAME + "' AND table_name='" + T + "';");
  soft("reconcileTable: CREATE TABLE DDL landed the table on the server (portable b.sql DDL)",
       /\b1\b/.test(tblPresent));

  _block(
    "reconcileTable: SECOND reconcile is idempotent on real MySQL " +
      "(no spurious ALTER / duplicate-column / false drift)",
    function () { dbSchema.reconcileTable(adapter, tableDef, { onDrift: "refuse" }); });

  _block(
    "reconcileTable: declared index (CREATE INDEX IF NOT EXISTS) runs on real MySQL",
    function () {
      dbSchema.reconcileTable(adapter,
        { name: T, columns: tableDef.columns, indexes: [{ columns: ["region"], name: "bjml_orders_region_idx" }] },
        { onDrift: "ignore" });
    });

  // Ensure the table exists for the CRUD block regardless of reconcile.
  _mysql('CREATE TABLE IF NOT EXISTS "' + T + '" ' +
         '("_id" VARCHAR(64) PRIMARY KEY, "region" VARCHAR(64), "total" BIGINT, "note" TEXT);');

  // ====================================================================
  // 2. db.from() Query CRUD end-to-end on real MySQL.
  // ====================================================================
  var declared = new Set(["_id", "region", "total", "note"]);

  _block("db.from().insertOne runs on real MySQL", function () {
    var ins = _from(adapter, T, declared).insertOne({ _id: "o-1", region: "eu", total: 100, note: "first" });
    soft("db.from().insertOne returned the row with _id", ins && ins._id === "o-1");
  });
  _block("db.from().insertOne (rows 2,3) run on MySQL", function () {
    _from(adapter, T, declared).insertOne({ _id: "o-2", region: "eu", total: 250, note: "second" });
    _from(adapter, T, declared).insertOne({ _id: "o-3", region: "us", total: 70, note: "third" });
  });

  _block("db.from().where().first runs on MySQL", function () {
    var oneRow = _from(adapter, T, declared).where("_id", "o-1").first();
    soft("db.from().where().first round-trips id", oneRow && oneRow._id === "o-1");
    soft("db.from().first round-trips region", oneRow && oneRow.region === "eu");
    soft("db.from(): BIGINT total coerces to a JS string on real MySQL (mysql2 bigint-as-string default)",
         oneRow && typeof oneRow.total === "string" && oneRow.total === "100");
  });

  _block("db.from().where().orderBy().all runs on MySQL", function () {
    var euRows = _from(adapter, T, declared).where("region", "eu").orderBy("_id", "asc").all();
    soft("db.from().where().orderBy().all returns the eu rows in order",
         euRows.length === 2 && euRows[0]._id === "o-1" && euRows[1]._id === "o-2");
  });

  _block("db.from().count runs on MySQL", function () {
    var total = _from(adapter, T, declared).count();
    soft("db.from().count returns 3", Number(total) === 3);
  });

  _block("db.from().updateOne (single-row, PK resolve-then-write) runs on real MySQL", function () {
    var n = _from(adapter, T, declared).where("_id", "o-1").updateOne({ total: 999 });
    soft("db.from().updateOne reported a change", n === true);
    var after = _from(adapter, T, declared).where("_id", "o-1").first();
    soft("db.from().updateOne persisted", after && after.total === "999");
  });

  _block("db.from().updateMany (set-based) runs on real MySQL", function () {
    _from(adapter, T, declared).where("region", "eu").updateMany({ note: "bulk" });
    var bulk = _from(adapter, T, declared).where("_id", "o-2").first();
    soft("db.from().updateMany persisted", bulk && bulk.note === "bulk");
  });

  _block("db.from().increment (COALESCE+?) runs on real MySQL", function () {
    _from(adapter, T, declared).where("_id", "o-3").increment("total", 5);
    var inc = _from(adapter, T, declared).where("_id", "o-3").first();
    soft("db.from().increment persisted (70 + 5 = 75)", inc && inc.total === "75");
  });

  _block("db.from().deleteOne (single-row, PK resolve-then-write) runs on real MySQL", function () {
    _from(adapter, T, declared).where("_id", "o-3").deleteOne();
    var remain = _from(adapter, T, declared).count();
    soft("db.from().deleteOne removed one row (3 -> 2)", Number(remain) === 2);
  });

  _block("db.from().paginate runs on real MySQL", function () {
    var liveTotal = Number(_from(adapter, T, declared).count());
    var page = _from(adapter, T, declared).paginate({ orderBy: "_id", limit: 1, offset: 0 });
    soft("db.from().paginate envelope shape (items page-limited, total == live count)",
         page && page.items.length === 1 && Number(page.total) === liveTotal && page.totalPages >= 1);
  });

  // ---- coercion fidelity: BIGINT > 2^53 reads back as exact string ----
  _mysql('CREATE TABLE IF NOT EXISTS "bjml_things" ' +
         '("_id" VARCHAR(64) PRIMARY KEY, "bignum" BIGINT);');
  var thingsDeclared = new Set(["_id", "bignum"]);
  _block("db.from() reads a > 2^53 BIGINT back as an exact string on real MySQL", function () {
    _mysql('INSERT INTO "bjml_things" ("_id","bignum") VALUES (\'t-1\', 9007199254740993);');
    var t = _from(adapter, "bjml_things", thingsDeclared).where("_id", "t-1").first();
    soft("BIGINT > 2^53 reads back as an exact string (mysql2 bigint fidelity)",
         t && t.bignum === "9007199254740993");
  });

  // ====================================================================
  // 3. migrations: composite-PK + CHECK DDL, run-once tracking, the lock.
  // ====================================================================
  var os = require("node:os");
  var fs = require("node:fs");
  var path = require("node:path");
  var migDir = fs.mkdtempSync(path.join(os.tmpdir(), "bjml-mig-"));
  fs.writeFileSync(path.join(migDir, "0001-create-widgets.js"),
    'module.exports = { description: "widgets",' +
    ' up: function (db) { db["exec"]("CREATE TABLE IF NOT EXISTS \\"bjml_widgets\\" ' +
    '(\\"k\\" VARCHAR(64), \\"v\\" VARCHAR(64), PRIMARY KEY (\\"k\\", \\"v\\"), ' +
    'CHECK (CHAR_LENGTH(\\"k\\") > 0))"); },' +
    ' down: function (db) { db["exec"]("DROP TABLE IF EXISTS \\"bjml_widgets\\""); } };\n');
  _mysql('DROP TABLE IF EXISTS "bjml_widgets";');

  var mig = migrations.create({ db: adapter, dir: migDir });
  var migRan = false;
  await (async function () {
    try {
      var upResult = await mig.up();
      migRan = true;
      soft("migrations.up ran the migration on real MySQL", true);
      soft("migrations.up applied 0001-create-widgets.js",
           upResult.applied.indexOf("0001-create-widgets.js") !== -1);
    } catch (e) {
      soft("migrations.up runs on real MySQL (threw: " +
           ((e && e.message) || String(e)).replace(/\s+/g, " ").slice(0, 200) + ")", false);
    }
  })();

  if (migRan) {
    var widgetPresent = _mysql(
      "SELECT count(*) AS n FROM information_schema.tables WHERE table_schema='" +
      DB_NAME + "' AND table_name='bjml_widgets';");
    soft("migrations: composite-PK + CHECK table created on the server", /\b1\b/.test(widgetPresent));

    await (async function () {
      try {
        var up2 = await mig.up();
        soft("migrations.up is run-once (second up skips the applied migration)",
             up2.applied.length === 0 && up2.skipped.indexOf("0001-create-widgets.js") !== -1);
      } catch (e) {
        soft("migrations.up second run is run-once (threw: " + ((e && e.message) || String(e)).slice(0, 120) + ")", false);
      }
    })();

    try {
      var st = mig.status();
      soft("migrations.status reports 0001 applied on MySQL",
           st.applied.some(function (r) { return r.name === "0001-create-widgets.js"; }));
    } catch (e) {
      soft("migrations.status runs on MySQL (threw: " + ((e && e.message) || String(e)).slice(0, 120) + ")", false);
    }

    var lockTbl = frameworkSchema.tableName(migrations.LOCK_TABLE);
    await (async function () {
      try {
        _mysql('INSERT INTO ' + safeSql.quoteIdentifier(lockTbl, "sqlite") +
               ' ("scope", "lockedAt", "lockedBy") VALUES (\'lock\', ' + Date.now() +
               ", 'other-proc');");
        var lockThrew = null;
        try { await mig.up(); } catch (e) { lockThrew = e; }
        soft("migrations: a held advisory lock refuses a concurrent up() on MySQL",
             lockThrew !== null && /lock/i.test((lockThrew && lockThrew.message) || ""));
        _mysql('DELETE FROM ' + safeSql.quoteIdentifier(lockTbl, "sqlite") + " WHERE \"scope\" = 'lock';");
      } catch (e) {
        soft("migrations advisory-lock concurrency test ran on MySQL (threw: " +
             ((e && e.message) || String(e)).slice(0, 120) + ")", false);
      }
    })();

    // Stale-lock force-replace path. The DELETE+INSERT runs inside a
    // transaction whose boundary keyword is dialect-aware: `BEGIN IMMEDIATE`
    // is SQLite-only and a syntax error on MySQL, so the runner must emit a
    // portable `BEGIN`. Plant a STALE lock row (far in the past) then run
    // up({ staleAfterMs }) — the runner force-replaces it, skips the
    // already-applied migration, and releases.
    await (async function () {
      try {
        _mysql('DELETE FROM ' + safeSql.quoteIdentifier(lockTbl, "sqlite") + " WHERE \"scope\" = 'lock';");
        _mysql('INSERT INTO ' + safeSql.quoteIdentifier(lockTbl, "sqlite") +
               ' ("scope", "lockedAt", "lockedBy") VALUES (\'lock\', ' + (Date.now() - 3600000) +
               ", 'dead-proc');");
        var staleMig = migrations.create({ db: adapter, dir: migDir, staleAfterMs: 60000 });
        var staleThrew = null;
        try { await staleMig.up(); } catch (e) { staleThrew = e; }
        soft("migrations: stale-lock force-replace uses a portable BEGIN (not BEGIN IMMEDIATE) on MySQL",
             staleThrew === null);
        var deadRows = _mysql('SELECT count(*) AS "n" FROM ' + safeSql.quoteIdentifier(lockTbl, "sqlite") +
                             " WHERE \"lockedBy\" = 'dead-proc';");
        soft("migrations: the stale dead-proc lock was force-replaced + released on MySQL",
             /\b0\b/.test(deadRows));
        _mysql('DELETE FROM ' + safeSql.quoteIdentifier(lockTbl, "sqlite") + " WHERE \"scope\" = 'lock';");
      } catch (e) {
        soft("migrations stale-lock-replace test ran on MySQL (threw: " +
             ((e && e.message) || String(e)).replace(/\s+/g, " ").slice(0, 200) + ")", false);
      }
    })();
  }

  // ====================================================================
  // 4. seeders: composite-PK registry, env scoping, run-once + rerunnable.
  // ====================================================================
  var seedDir = fs.mkdtempSync(path.join(os.tmpdir(), "bjml-seed-"));
  fs.mkdirSync(path.join(seedDir, "dev"));
  _mysql('DROP TABLE IF EXISTS "bjml_seed_target";');
  _mysql('CREATE TABLE "bjml_seed_target" ("id" VARCHAR(64) PRIMARY KEY, "label" TEXT);');
  fs.writeFileSync(path.join(seedDir, "dev", "0001-admin.js"),
    'module.exports = { description: "admin",' +
    ' run: async function (db) { db.prepare("INSERT INTO \\"bjml_seed_target\\" ' +
    '(\\"id\\", \\"label\\") VALUES (?, ?)").run("admin", "Administrator"); } };\n');

  var seed = seeders.create({ db: adapter, dir: seedDir });
  var seedRan = false;
  await (async function () {
    try {
      var seedResult = await seed.run({ env: "dev" });
      seedRan = true;
      soft("seeders.run applied the seed on real MySQL", true);
      soft("seeders.run applied 0001-admin.js", seedResult.applied.indexOf("0001-admin.js") !== -1);
    } catch (e) {
      soft("seeders.run runs on real MySQL (threw: " +
           ((e && e.message) || String(e)).replace(/\s+/g, " ").slice(0, 200) + ")", false);
    }
  })();

  if (seedRan) {
    var seededRow = _mysql('SELECT label FROM "bjml_seed_target" WHERE id = \'admin\';');
    soft("seeders: the seed body actually wrote its row on MySQL", /Administrator/.test(seededRow));

    await (async function () {
      try {
        var seed2 = await seed.run({ env: "dev" });
        soft("seeders.run is run-once (second run skips the applied seed)",
             seed2.applied.length === 0 && seed2.skipped.indexOf("0001-admin.js") !== -1);
      } catch (e) {
        soft("seeders.run second run is run-once (threw: " + ((e && e.message) || String(e)).slice(0, 120) + ")", false);
      }
    })();

    try {
      var sst = seed.status({ env: "dev" });
      soft("seeders.status reports 0001-admin.js applied on MySQL",
           sst.applied.some(function (r) { return r.name === "0001-admin.js"; }));
    } catch (e) {
      soft("seeders.status runs on MySQL (threw: " + ((e && e.message) || String(e)).slice(0, 120) + ")", false);
    }
  }

  // ---- teardown ----
  try { fs.rmSync(migDir,  { recursive: true, force: true }); } catch (_e) {}
  try { fs.rmSync(seedDir, { recursive: true, force: true }); } catch (_e) {}
  _dropAll();

  // ---- summary ----
  //
  // The data layer is dialect-aware: with the handle declaring
  // dialect: "mysql", every soft-check above MUST pass on real MySQL. The
  // formerly-SQLite-only / MySQL-incompatible constructs are resolved:
  //   - db-schema.listColumns reads information_schema.columns (not the
  //     SQLite-only PRAGMA table_info), and reconcileTable / reconcileIndex
  //     emit backtick-quoted DDL (MySQL has no CREATE INDEX IF NOT EXISTS —
  //     a duplicate-index re-run is swallowed for idempotence).
  //   - db-query single-row updateOne/deleteOne resolve the PRIMARY KEY in a
  //     prior SELECT then write `WHERE pk = ?` (MySQL error 1093 forbids a
  //     subquery on the UPDATE/DELETE target table).
  //   - the migrations + seeders registry/lock tables use VARCHAR(191) for
  //     their key text columns (MySQL refuses unbounded TEXT in a key,
  //     error 1170) and BIGINT for the ms-epoch lock timestamp (a 32-bit
  //     INT overflows, error 1264).
  var failed = _results.filter(function (r) { return !r.ok; });

  console.log("\n[db-layer-mysql] " +
    (_results.length - failed.length) + "/" + _results.length + " checks passed");
  if (failed.length) {
    console.log("[db-layer-mysql] FAILURES:");
    failed.forEach(function (r) { console.log("  - " + r.label); });
  }

  // Replay every recorded finding through the hard `check` so the file
  // FAILS when any data-layer op does not work on real MySQL.
  for (var i = 0; i < _results.length; i++) {
    check(_results[i].label, _results[i].ok);
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
