"use strict";
/**
 * Live test of the framework's SYNCHRONOUS data layer
 * (lib/db-query.js / lib/db-schema.js / lib/migrations.js /
 * lib/seeders.js) against the docker Postgres container.
 *
 * Those four modules were built for node:sqlite (a SYNCHRONOUS engine):
 * db.from(table) and the schema reconciler / migration runner / seed
 * runner all call database.prepare(sql) then stmt.get/all/run(...params)
 * synchronously, plus database.exec(sql) for DDL. Every statement is
 * composed through b.sql with { dialect: "sqlite" } - `?` placeholders +
 * double-quoted "camelCase" identifiers - and the modules NEVER translate
 * that for an external dialect (the b.sql header advertises clusterStorage
 * as the rewrite layer, but these single-node modules bypass clusterStorage
 * entirely). Host smoke only ever runs them on sqlite.
 *
 * To prove the migrated b.sql actually executes on real Postgres, this
 * test wraps a docker-exec psql shim in a node:sqlite-Statement-SHAPED
 * adapter:
 *
 *   adapter.prepare(sql)  -> { get(...p), all(...p), run(...p) }
 *   adapter.exec(sql)     -> run DDL / BEGIN / COMMIT / ROLLBACK
 *
 * The adapter is SYNCHRONOUS (execFileSync) so the sync modules drive it
 * unmodified, and it is FAITHFUL to a real node-postgres driver:
 *   - `?` placeholders fold into the SQL as quoted literals at the adapter
 *     boundary (psql has no bind protocol over argv; every value here is
 *     operator-controlled).
 *   - the double-quoted "camelCase" identifiers b.sql emits pass through
 *     verbatim: Postgres HONORS double-quoted identifiers case-sensitively,
 *     so "monotonicCounter" stays camelCase (the casing-bug class lives here).
 *   - run() returns { changes } parsed from the psql command tag
 *     ("UPDATE 2" -> 2), matching node:sqlite's info.changes.
 *   - BIGINT comes back as a JS string (node-postgres int8 default) and
 *     BYTEA as a Buffer - the coercion the framework's readers must handle.
 *
 * Because the custom `check` helper is fail-fast (throws on the first
 * false), this file records every assertion through a local soft-check so
 * EVERY divergence surfaces in one run; a single summarizing check() at the
 * end fails the file when any soft-check failed.
 *
 * Tables/migration-rows are namespaced (bjpg_*) + dropped in setup +
 * teardown so a concurrent test can't collide.
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

var CONTAINER = "blamejs-test-postgres";
var NULL_SENTINEL = "__BJNULL__";

// ---- soft-check recorder (so all findings surface in one run) ----
var _results = [];
function soft(label, cond) {
  _results.push({ label: label, ok: !!cond });
  console.log((cond ? "  ok   " : "  FAIL ") + label);
  return !!cond;
}

// ---- shared synchronous docker-exec psql ----
// Field separator + footer are set via -P argv flags (NOT a \pset prelude)
// so psql prints no "Field separator is ..." confirmation line that a
// header parser would mistake for a data header. bytea_output is a SET
// (its only output is the harmless "SET" command tag, already filtered).
// fieldsep_zero would be cleaner but TAB suffices for our text columns.
// Field separator is a literal TAB embedded directly in the -P argument
// (built here in Node where the byte is exact — a $(printf) substitution
// inside sh -c gets eaten by word-splitting and yields an empty sep, which
// collapses multi-column rows into one unsplittable string). -P flags print
// no confirmation line (a \pset prelude would). 2>&1 merges the ERROR lines
// psql writes to stderr (ON_ERROR_STOP=0 → exit 0, errors only on stderr).
var TAB = "\t";
var _PSQL_BASE =
  "psql -U blamejs -d blamejs_test -v ON_ERROR_STOP=0 " +
  "-P footer=off -P null=" + NULL_SENTINEL + " -P 'fieldsep=" + TAB + "'";
function _psqlRaw(sql) {
  return execFileSync(
    "docker",
    ["exec", "-i", CONTAINER, "sh", "-c", _PSQL_BASE + " -At 2>&1"],
    { input: "SET bytea_output = 'hex';\n" + sql + "\n",
      stdio: ["pipe", "pipe", "pipe"], maxBuffer: 64 * 1024 * 1024 }
  ).toString("utf8");
}

function _psql(sql) {
  var out = _psqlRaw(sql);
  if (/^ERROR:/m.test(out)) {
    throw new Error("psql setup failed for [" + sql + "]:\n" + out);
  }
  return out;
}

var BYTEA_PREFIX = "'" + "\\" + "x";
function _bindQ(sql, params) {
  params = params || [];
  var i = 0;
  return sql.replace(/\?/g, function () {
    if (i >= params.length) {
      throw new Error("placeholder/param count mismatch in: " + sql);
    }
    var v = params[i++];
    if (v === null || v === undefined) return "NULL";
    if (Buffer.isBuffer(v)) return BYTEA_PREFIX + v.toString("hex") + "'::bytea";
    if (typeof v === "number") return String(v);
    if (typeof v === "boolean") return v ? "TRUE" : "FALSE";
    return "'" + String(v).replace(/'/g, "''") + "'";
  });
}

var _CMD_TAG_RE = /^(INSERT|UPDATE|DELETE|MERGE|SELECT|COPY|MOVE)\b(?:\s+\d+)*\s*$/;

function _parseError(out) {
  var lines = out.split(/\r?\n/);
  for (var i = 0; i < lines.length; i++) {
    var em = /^ERROR:\s+([0-9A-Za-z]{5}):\s*(.*)$/.exec(lines[i]) ||
             /^ERROR:\s+(.*)$/.exec(lines[i]);
    if (em) {
      var err = new Error("Postgres error: " + lines[i]);
      if (em.length === 3) err.code = em[1];
      return err;
    }
  }
  return null;
}

function _psqlHeader(sql) {
  return execFileSync(
    "docker",
    ["exec", "-i", CONTAINER, "sh", "-c", _PSQL_BASE + " -A 2>&1"],
    { input: "SET bytea_output = 'hex';\n" + sql + "\n",
      stdio: ["pipe", "pipe", "pipe"], maxBuffer: 64 * 1024 * 1024 }
  ).toString("utf8");
}

var _BYTEA_COLUMNS = { nonce: true, payload: true, blobcol: true };

function _rowsFromHeaderBlock(out) {
  var err = _parseError(out);
  if (err) throw err;
  var lines = out.split(/\r?\n/);
  var data = [];
  for (var i = 0; i < lines.length; i++) {
    var ln = lines[i];
    if (ln === "") continue;
    if (_CMD_TAG_RE.test(ln) && ln.indexOf("\t") === -1) continue;
    if (/^(BEGIN|COMMIT|ROLLBACK|SET|CREATE|DROP|ALTER)\b/.test(ln) &&
        ln.indexOf("\t") === -1) continue;
    data.push(ln);
  }
  if (data.length === 0) return [];
  var headers = data[0].split("\t");
  var rows = [];
  for (var r = 1; r < data.length; r++) {
    var cells = data[r].split("\t");
    var row = {};
    for (var c = 0; c < headers.length; c++) {
      var hdr = headers[c];
      var cell = cells[c];
      if (cell === NULL_SENTINEL || cell === undefined) { row[hdr] = null; continue; }
      if (_BYTEA_COLUMNS[hdr] === true) {
        var hex = (cell.charAt(0) === "\\" && cell.charAt(1) === "x") ? cell.slice(2) : cell;
        row[hdr] = Buffer.from(hex, "hex");
      } else {
        row[hdr] = cell;
      }
    }
    rows.push(row);
  }
  return rows;
}

function _affectedFromBlock(out) {
  var err = _parseError(out);
  if (err) throw err;
  var lines = out.split(/\r?\n/);
  var affected = 0;
  for (var i = 0; i < lines.length; i++) {
    if (_CMD_TAG_RE.test(lines[i])) {
      var nums = lines[i].trim().split(/\s+/).slice(1).map(Number);
      if (nums.length) affected = nums[nums.length - 1];
    }
  }
  return affected;
}

function _isWrite(sql) {
  return /^\s*(INSERT|UPDATE|DELETE|REPLACE|MERGE)\b/i.test(sql);
}

// ---- node:sqlite-Statement-SHAPED adapter over real Postgres ----
function _makePgAdapter() {
  return {
    prepare: function (sql) {
      return {
        get: function () {
          var params = Array.prototype.slice.call(arguments);
          var rows = _rowsFromHeaderBlock(_psqlHeader(_bindQ(sql, params)));
          return rows.length ? rows[0] : undefined;
        },
        all: function () {
          var params = Array.prototype.slice.call(arguments);
          return _rowsFromHeaderBlock(_psqlHeader(_bindQ(sql, params)));
        },
        run: function () {
          var params = Array.prototype.slice.call(arguments);
          var out = _psqlRaw(_bindQ(sql, params));
          var changes = _isWrite(sql) ? _affectedFromBlock(out) : (function () {
            var e = _parseError(out); if (e) throw e; return 0;
          })();
          return { changes: changes, lastInsertRowid: 0 };
        },
      };
    },
    exec: function (sql) {
      var out = _psqlRaw(sql);
      var e = _parseError(out);
      if (e) throw e;
      return out;
    },
    // The handle declares its dialect so the data layer (db-query /
    // db-schema / migrations / seeders) emits Postgres-correct SQL: the
    // single-row write resolves the PRIMARY KEY (`_id`) rather than the
    // SQLite-only `rowid`, listColumns reads information_schema rather than
    // `PRAGMA table_info`, and the lock timestamp is BIGINT (no 32-bit
    // overflow). Without this the layer falls back to the SQLite dialect.
    dialect: "postgres",
  };
}

function _from(adapter, table, declared) {
  return new Query(adapter, table, {
    declaredColumns: declared || null,
    columnGateMode:  declared ? "reject" : "off",
  });
}

// Run a block, recording an unexpected throw as a soft FAIL with the
// error text so a structural SQLite-ism surfaces with its PG error.
function _block(label, fn) {
  try { fn(); return true; }
  catch (e) {
    soft(label + " (threw: " + ((e && e.message) || String(e)).replace(/\s+/g, " ").slice(0, 200) + ")", false);
    return false;
  }
}

async function run() {
  var pg = await services.requireService("postgres");
  if (!pg.ok) throw new Error("postgres unreachable: " + pg.reason);

  var adapter = _makePgAdapter();

  var T = "bjpg_orders";
  var ALL_TABLES = [
    '"' + T + '"', '"bjpg_things"', '"bjpg_widgets"', '"bjpg_seed_target"',
    '"_blamejs_migrations"', '"_blamejs_migrations_lock"',
    '"_blamejs_seeders"', '"_blamejs_seeders_lock"',
  ];
  function _dropAll() {
    _psql(ALL_TABLES.map(function (t) { return "DROP TABLE IF EXISTS " + t + " CASCADE;"; }).join("\n"));
  }
  _dropAll();

  // ====================================================================
  // 1. reconcileTable: CREATE TABLE IF NOT EXISTS + second-reconcile
  //    idempotence (no spurious ALTER / drift) on real Postgres.
  // ====================================================================
  var tableDef = {
    name: T,
    columns: { _id: "TEXT PRIMARY KEY", region: "TEXT", total: "BIGINT", note: "TEXT" },
  };
  var reconcileOk = _block(
    "reconcileTable: first reconcile (CREATE TABLE IF NOT EXISTS) runs on real Postgres",
    function () { dbSchema.reconcileTable(adapter, tableDef, { onDrift: "refuse" }); });
  if (reconcileOk) {
    soft("reconcileTable: first reconcile ran clean on Postgres", true);
  }

  // The CREATE itself is portable b.sql DDL; confirm it landed even if a
  // later step in reconcileTable threw (so we can prove the failure point).
  var tblPresent = _psql(
    "SELECT count(*) FROM information_schema.tables WHERE table_name = '" + T + "';");
  soft("reconcileTable: CREATE TABLE DDL landed the table on the server (portable b.sql DDL)",
       /\b1\b/.test(tblPresent.trim()));

  _block(
    "reconcileTable: SECOND reconcile is idempotent on real Postgres " +
      "(no spurious ALTER / duplicate-column / false drift)",
    function () { dbSchema.reconcileTable(adapter, tableDef, { onDrift: "refuse" }); });

  // reconcileIndex path (CREATE INDEX IF NOT EXISTS).
  _block(
    "reconcileTable: declared index (CREATE INDEX IF NOT EXISTS) runs on real Postgres",
    function () {
      dbSchema.reconcileTable(adapter,
        { name: T, columns: tableDef.columns, indexes: [{ columns: ["region"], name: "bjpg_orders_region_idx" }] },
        { onDrift: "ignore" });
    });

  // Ensure the table exists for the CRUD block regardless of reconcile
  // outcome (create it directly if reconcile could not complete).
  _psql('CREATE TABLE IF NOT EXISTS "' + T + '" ' +
        '("_id" TEXT PRIMARY KEY, "region" TEXT, "total" BIGINT, "note" TEXT);');

  // ====================================================================
  // 2. db.from() Query CRUD end-to-end on real Postgres.
  // ====================================================================
  var declared = new Set(["_id", "region", "total", "note"]);

  _block("db.from().insertOne runs on real Postgres", function () {
    var ins = _from(adapter, T, declared).insertOne({ _id: "o-1", region: "eu", total: 100, note: "first" });
    soft("db.from().insertOne returned the row with _id", ins && ins._id === "o-1");
  });
  _block("db.from().insertOne (rows 2,3) run on Postgres", function () {
    _from(adapter, T, declared).insertOne({ _id: "o-2", region: "eu", total: 250, note: "second" });
    _from(adapter, T, declared).insertOne({ _id: "o-3", region: "us", total: 70, note: "third" });
  });

  _block("db.from().where().first runs on Postgres", function () {
    var oneRow = _from(adapter, T, declared).where("_id", "o-1").first();
    soft("db.from().where().first round-trips id", oneRow && oneRow._id === "o-1");
    soft("db.from().first round-trips region", oneRow && oneRow.region === "eu");
    soft("db.from(): BIGINT total coerces to a JS string on real Postgres (node-pg int8 default)",
         oneRow && typeof oneRow.total === "string" && oneRow.total === "100");
  });

  _block("db.from().where().orderBy().all runs on Postgres", function () {
    var euRows = _from(adapter, T, declared).where("region", "eu").orderBy("_id", "asc").all();
    soft("db.from().where().orderBy().all returns the eu rows in order",
         euRows.length === 2 && euRows[0]._id === "o-1" && euRows[1]._id === "o-2");
  });

  _block("db.from().count runs on Postgres", function () {
    var total = _from(adapter, T, declared).count();
    soft("db.from().count returns 3", Number(total) === 3);
  });

  _block("db.from().updateOne (single-row, rowid sub-select) runs on real Postgres", function () {
    var n = _from(adapter, T, declared).where("_id", "o-1").updateOne({ total: 999 });
    soft("db.from().updateOne reported a change", n === true);
    var after = _from(adapter, T, declared).where("_id", "o-1").first();
    soft("db.from().updateOne persisted", after && after.total === "999");
  });

  _block("db.from().updateMany (set-based) runs on real Postgres", function () {
    _from(adapter, T, declared).where("region", "eu").updateMany({ note: "bulk" });
    var bulk = _from(adapter, T, declared).where("_id", "o-2").first();
    soft("db.from().updateMany persisted", bulk && bulk.note === "bulk");
  });

  _block("db.from().increment (COALESCE+?) runs on real Postgres", function () {
    _from(adapter, T, declared).where("_id", "o-3").increment("total", 5);
    var inc = _from(adapter, T, declared).where("_id", "o-3").first();
    soft("db.from().increment persisted (70 + 5 = 75)", inc && inc.total === "75");
  });

  _block("db.from().deleteOne (single-row, rowid sub-select) runs on real Postgres", function () {
    _from(adapter, T, declared).where("_id", "o-3").deleteOne();
    var remain = _from(adapter, T, declared).count();
    soft("db.from().deleteOne removed one row (3 -> 2)", Number(remain) === 2);
  });

  _block("db.from().paginate runs on real Postgres", function () {
    // Independent of prior write state: assert the envelope against the
    // LIVE count rather than a fixed number (the single-row deleteOne may
    // not have run on Postgres, so the row total varies by bug state).
    var liveTotal = Number(_from(adapter, T, declared).count());
    var page = _from(adapter, T, declared).paginate({ orderBy: "_id", limit: 1, offset: 0 });
    soft("db.from().paginate envelope shape (items page-limited, total == live count)",
         page && page.items.length === 1 && Number(page.total) === liveTotal && page.totalPages >= 1);
  });

  // ---- coercion fidelity: BYTEA -> Buffer, BIGINT>2^53 -> exact string ----
  _psql('CREATE TABLE IF NOT EXISTS "bjpg_things" ' +
        '("_id" TEXT PRIMARY KEY, "blobcol" BYTEA, "bignum" BIGINT);');
  var thingsDeclared = new Set(["_id", "blobcol", "bignum"]);
  _block("db.from().insertOne with BYTEA runs on real Postgres", function () {
    _from(adapter, "bjpg_things", thingsDeclared)
      .insertOne({ _id: "t-1", blobcol: Buffer.from([0xde, 0xad, 0xbe, 0xef]) });
    var t = _from(adapter, "bjpg_things", thingsDeclared).where("_id", "t-1").first();
    soft("BYTEA column round-trips to a Buffer on real Postgres",
         t && Buffer.isBuffer(t.blobcol) && t.blobcol.toString("hex") === "deadbeef");
  });
  // A genuine > 2^53 BIGINT can't be expressed as a JS number literal (it
  // rounds), so write the exact value via raw psql, then prove db.from()'s
  // READER coerces it to the exact JS string a node-pg driver returns (the
  // framework's reader concern — no float precision loss on the way out).
  _block("db.from() reads a > 2^53 BIGINT back as an exact string on real Postgres", function () {
    _psql('UPDATE "bjpg_things" SET "bignum" = 9007199254740993 WHERE "_id" = \'t-1\';');
    var t = _from(adapter, "bjpg_things", thingsDeclared).where("_id", "t-1").first();
    soft("BIGINT > 2^53 reads back as an exact string (node-pg int8 fidelity)",
         t && t.bignum === "9007199254740993");
  });

  // ====================================================================
  // 3. migrations: composite-PK + CHECK DDL, run-once tracking, the lock.
  // ====================================================================
  var os = require("node:os");
  var fs = require("node:fs");
  var path = require("node:path");
  var migDir = fs.mkdtempSync(path.join(os.tmpdir(), "bjpg-mig-"));
  fs.writeFileSync(path.join(migDir, "0001-create-widgets.js"),
    'module.exports = { description: "widgets",' +
    ' up: function (db) { db["exec"]("CREATE TABLE IF NOT EXISTS \\"bjpg_widgets\\" ' +
    '(\\"k\\" TEXT, \\"v\\" TEXT, PRIMARY KEY (\\"k\\", \\"v\\"), ' +
    'CHECK (char_length(\\"k\\") > 0))"); },' +
    ' down: function (db) { db["exec"]("DROP TABLE IF EXISTS \\"bjpg_widgets\\""); } };\n');
  _psql('DROP TABLE IF EXISTS "bjpg_widgets";');

  var mig = migrations.create({ db: adapter, dir: migDir });
  var migRan = false;
  await (async function () {
    try {
      var upResult = await mig.up();
      migRan = true;
      soft("migrations.up ran the migration on real Postgres", true);
      soft("migrations.up applied 0001-create-widgets.js",
           upResult.applied.indexOf("0001-create-widgets.js") !== -1);
    } catch (e) {
      soft("migrations.up runs on real Postgres (threw: " +
           ((e && e.message) || String(e)).replace(/\s+/g, " ").slice(0, 200) + ")", false);
    }
  })();

  if (migRan) {
    var widgetPresent = _psql(
      "SELECT count(*) FROM information_schema.tables WHERE table_name = 'bjpg_widgets';");
    soft("migrations: composite-PK + CHECK table created on the server", /\b1\b/.test(widgetPresent.trim()));

    await (async function () {
      try {
        var up2 = await mig.up();
        soft("migrations.up is run-once (second up skips the applied migration)",
             up2.applied.length === 0 && up2.skipped.indexOf("0001-create-widgets.js") !== -1);
      } catch (e) {
        soft("migrations.up second run is run-once (threw: " +
             ((e && e.message) || String(e)).slice(0, 120) + ")", false);
      }
    })();

    try {
      var st = mig.status();
      soft("migrations.status reports 0001 applied on Postgres",
           st.applied.some(function (r) { return r.name === "0001-create-widgets.js"; }));
    } catch (e) {
      soft("migrations.status runs on Postgres (threw: " + ((e && e.message) || String(e)).slice(0, 120) + ")", false);
    }

    // advisory lock: a held 'lock' row refuses a concurrent up().
    var lockTbl = frameworkSchema.tableName(migrations.LOCK_TABLE);
    await (async function () {
      try {
        _psql('INSERT INTO ' + safeSql.quoteIdentifier(lockTbl) +
              ' ("scope", "lockedAt", "lockedBy") VALUES (\'lock\', ' + Date.now() +
              ", 'other-proc') ON CONFLICT (\"scope\") DO NOTHING;");
        var lockThrew = null;
        try { await mig.up(); } catch (e) { lockThrew = e; }
        soft("migrations: a held advisory lock refuses a concurrent up() on Postgres",
             lockThrew !== null && /lock/i.test((lockThrew && lockThrew.message) || ""));
        _psql('DELETE FROM ' + safeSql.quoteIdentifier(lockTbl) + " WHERE \"scope\" = 'lock';");
      } catch (e) {
        soft("migrations advisory-lock concurrency test ran on Postgres (threw: " +
             ((e && e.message) || String(e)).slice(0, 120) + ")", false);
      }
    })();

    // Stale-lock force-replace path. The DELETE+INSERT runs inside a
    // transaction whose boundary keyword is dialect-aware: `BEGIN IMMEDIATE`
    // is SQLite-only and a syntax error on Postgres, so the runner must emit
    // a portable `BEGIN`. We plant a STALE lock row (far in the past) then
    // run up({ staleAfterMs }) — the runner force-replaces the stale lock,
    // applies the (already-applied) migration as a no-op skip, and releases.
    await (async function () {
      try {
        var staleLockTbl = frameworkSchema.tableName(migrations.LOCK_TABLE);
        _psql('DELETE FROM ' + safeSql.quoteIdentifier(staleLockTbl) + " WHERE \"scope\" = 'lock';");
        _psql('INSERT INTO ' + safeSql.quoteIdentifier(staleLockTbl) +
              ' ("scope", "lockedAt", "lockedBy") VALUES (\'lock\', ' + (Date.now() - 3600000) +
              ", 'dead-proc') ON CONFLICT (\"scope\") DO NOTHING;");
        var staleMig = migrations.create({ db: adapter, dir: migDir, staleAfterMs: 60000 });
        var staleThrew = null;
        try { await staleMig.up(); } catch (e) { staleThrew = e; }
        soft("migrations: stale-lock force-replace uses a portable BEGIN (not BEGIN IMMEDIATE) on Postgres",
             staleThrew === null);
        // The dead-proc lock is gone; the runner replaced it and released.
        var lockRows = _psql('SELECT count(*) FROM ' + safeSql.quoteIdentifier(staleLockTbl) +
                             " WHERE \"lockedBy\" = 'dead-proc';");
        soft("migrations: the stale dead-proc lock was force-replaced + released on Postgres",
             /\b0\b/.test(lockRows.trim()));
        _psql('DELETE FROM ' + safeSql.quoteIdentifier(staleLockTbl) + " WHERE \"scope\" = 'lock';");
      } catch (e) {
        soft("migrations stale-lock-replace test ran on Postgres (threw: " +
             ((e && e.message) || String(e)).replace(/\s+/g, " ").slice(0, 200) + ")", false);
      }
    })();
  }

  // ====================================================================
  // 4. seeders: composite-PK registry, env scoping, run-once + rerunnable.
  // ====================================================================
  var seedDir = fs.mkdtempSync(path.join(os.tmpdir(), "bjpg-seed-"));
  fs.mkdirSync(path.join(seedDir, "dev"));
  _psql('DROP TABLE IF EXISTS "bjpg_seed_target";');
  _psql('CREATE TABLE "bjpg_seed_target" ("id" TEXT PRIMARY KEY, "label" TEXT);');
  fs.writeFileSync(path.join(seedDir, "dev", "0001-admin.js"),
    'module.exports = { description: "admin",' +
    ' run: async function (db) { db.prepare("INSERT INTO \\"bjpg_seed_target\\" ' +
    '(\\"id\\", \\"label\\") VALUES (?, ?)").run("admin", "Administrator"); } };\n');

  var seed = seeders.create({ db: adapter, dir: seedDir });
  var seedRan = false;
  await (async function () {
    try {
      var seedResult = await seed.run({ env: "dev" });
      seedRan = true;
      soft("seeders.run applied the seed on real Postgres", true);
      soft("seeders.run applied 0001-admin.js", seedResult.applied.indexOf("0001-admin.js") !== -1);
    } catch (e) {
      soft("seeders.run runs on real Postgres (threw: " +
           ((e && e.message) || String(e)).replace(/\s+/g, " ").slice(0, 200) + ")", false);
    }
  })();

  if (seedRan) {
    var seededRow = _psql("SELECT label FROM \"bjpg_seed_target\" WHERE id = 'admin';");
    soft("seeders: the seed body actually wrote its row on Postgres", /Administrator/.test(seededRow));

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
      soft("seeders.status reports 0001-admin.js applied on Postgres",
           sst.applied.some(function (r) { return r.name === "0001-admin.js"; }));
    } catch (e) {
      soft("seeders.status runs on Postgres (threw: " + ((e && e.message) || String(e)).slice(0, 120) + ")", false);
    }
  }

  // ---- teardown ----
  try { fs.rmSync(migDir,  { recursive: true, force: true }); } catch (_e) {}
  try { fs.rmSync(seedDir, { recursive: true, force: true }); } catch (_e) {}
  _dropAll();

  // ---- summary ----
  //
  // The data layer is dialect-aware: with the handle declaring
  // dialect: "postgres", every soft-check above MUST pass on real Postgres.
  // The three formerly-SQLite-only constructs are resolved:
  //   - db-schema.listColumns reads information_schema.columns (not the
  //     SQLite-only PRAGMA table_info), so reconcileTable + its second-run
  //     idempotence work.
  //   - db-query single-row updateOne/deleteOne resolve the PRIMARY KEY
  //     (`_id`) sub-select instead of the SQLite-only `rowid`.
  //   - the migrations + seeders lock table types lockedAt as BIGINT (no
  //     32-bit overflow of a Date.now() ms value), so the lock is
  //     acquirable and migrate.up / seed.run run end-to-end.
  var failed = _results.filter(function (r) { return !r.ok; });

  console.log("\n[db-layer-postgres] " +
    (_results.length - failed.length) + "/" + _results.length + " checks passed");
  if (failed.length) {
    console.log("[db-layer-postgres] FAILURES:");
    failed.forEach(function (r) { console.log("  - " + r.label); });
  }

  // Replay every recorded finding through the hard `check` so the file
  // FAILS (and the runner reports it) when any data-layer op does not work
  // on real Postgres.
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
