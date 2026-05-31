"use strict";
/**
 * b.db column-membership gate + whereRaw string-literal refusal.
 *
 * Column gate: a Query may only reference columns the table declared in
 * its schema. The default mode is "reject" (throw), so a typo'd or
 * attacker-influenced column name fails closed rather than silently
 * matching nothing (or, for a raw fragment, opening an injection path).
 * Modes: reject (default) | warn (audit, allow) | off (no gate).
 * .allowedColumns([...]) narrows further and is ALWAYS enforced.
 *
 * whereRaw / WhereBuilder.raw refuse an embedded string literal
 * ('...') unless { allowLiterals: true } — every value must bind
 * through the params array.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var fs   = helpers.fs;
var os   = helpers.os;
var path = helpers.path;

var SCHEMA = [{
  name: "things",
  columns: {
    _id:    "TEXT PRIMARY KEY",
    name:   "TEXT",
    status: "TEXT DEFAULT 'active'",
  },
  indexes: ["status"],
}];

async function initDb(tmpDir, columnGate) {
  process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
  helpers.setTestPassphraseEnv();
  b.cluster._resetForTest();
  b.audit._resetForTest();
  b.vault._resetForTest();
  b.db._resetForTest();
  await b.vault.init({ dataDir: tmpDir });
  var opts = { dataDir: tmpDir, tmpDir: path.join(tmpDir, "tmpfs"), schema: SCHEMA };
  if (columnGate !== undefined) opts.columnGate = columnGate;
  await b.db.init(opts);
}

function threwMatching(fn, pattern) {
  try { fn(); } catch (e) { return pattern.test(e.message) ? e : null; }
  return null;
}

async function run() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-colgate-"));

  // ---- default mode is reject ----
  await initDb(tmp);
  b.db.from("things").insertOne({ _id: "t1", name: "a", status: "active" });

  // declared columns pass
  check("declared column where() passes",
    b.db.from("things").where({ name: "a" }).first().status === "active");
  check("declared column select() passes",
    b.db.from("things").select(["name", "status"]).where({ _id: "t1" }).first().name === "a");

  // undeclared column is rejected (fail-closed)
  check("undeclared where() column rejected",
    !!threwMatching(function () { b.db.from("things").where({ nope: 1 }); },
      /not a declared column of 'things'/));
  check("undeclared orderBy() column rejected",
    !!threwMatching(function () { b.db.from("things").orderBy("bogus"); },
      /not a declared column/));
  check("undeclared select() column rejected",
    !!threwMatching(function () { b.db.from("things").select(["ghost"]); },
      /not a declared column/));

  // ---- getDeclaredColumns ----
  check("b.db.getDeclaredColumns is fn", typeof b.db.getDeclaredColumns === "function");
  var declared = b.db.getDeclaredColumns("things");
  check("getDeclaredColumns lists schema columns",
    declared.indexOf("_id") !== -1 && declared.indexOf("name") !== -1 && declared.indexOf("status") !== -1);
  check("getDeclaredColumns on unknown table → null",
    b.db.getDeclaredColumns("no_such_table") === null);

  // ---- allowedColumns() narrows + is always enforced ----
  check("allowedColumns() allows a member",
    b.db.from("things").allowedColumns(["name"]).where({ name: "a" }).first().name === "a");
  check("allowedColumns() rejects a declared-but-not-allowed column",
    !!threwMatching(function () {
      b.db.from("things").allowedColumns(["name"]).where({ status: "active" });
    }, /not in the allowedColumns\(\) set/));
  check("allowedColumns([]) rejected (non-empty array required)",
    !!threwMatching(function () { b.db.from("things").allowedColumns([]); },
      /non-empty array/));

  // ---- A5: whereRaw refuses embedded string literals ----
  var litErr = threwMatching(function () { b.db.from("things").whereRaw("status = 'active'"); },
    /string literal/);
  check("whereRaw refuses embedded string literal", !!litErr);
  check("whereRaw literal error code is sql/raw-literal", litErr && litErr.code === "sql/raw-literal");
  check("whereRaw with bound params is accepted",
    b.db.from("things").whereRaw("status = ?", ["active"]).first().name === "a");
  check("whereRaw allowLiterals opt-in is accepted",
    b.db.from("things").whereRaw("status = 'active'", [], { allowLiterals: true }).first().name === "a");

  b.db.close();
  fs.rmSync(tmp, { recursive: true, force: true });

  // ---- warn mode: audited, not thrown ----
  var tmp2 = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-colgate-warn-"));
  await initDb(tmp2, "warn");
  var warnThrew = false;
  try { b.db.from("things").where({ nope: 1 }); } catch (_e) { warnThrew = true; }
  check("warn mode does not throw on undeclared column", warnThrew === false);
  b.db.close();
  fs.rmSync(tmp2, { recursive: true, force: true });

  // ---- off mode: no gate ----
  var tmp3 = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-colgate-off-"));
  await initDb(tmp3, "off");
  var offThrew = false;
  try { b.db.from("things").where({ nope: 1 }); } catch (_e) { offThrew = true; }
  check("off mode does not gate undeclared column", offThrew === false);
  b.db.close();
  fs.rmSync(tmp3, { recursive: true, force: true });

  // ---- bad columnGate value rejected at db.init ----
  var tmp4 = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-colgate-bad-"));
  var initThrew = false;
  try { await initDb(tmp4, "loud"); } catch (e) { initThrew = /columnGate/.test(e.message); }
  check("db.init rejects unknown columnGate mode", initThrew);
  try { b.db.close(); } catch (_e) {}
  fs.rmSync(tmp4, { recursive: true, force: true });

  b.audit._resetForTest();
  b.db._resetForTest();
  b.vault._resetForTest();
  b.cluster._resetForTest();

  console.log("OK — db column-gate tests");
}

module.exports = { run: run };
if (require.main === module) {
  // Rethrow on failure so Node surfaces the error and exits non-zero,
  // instead of logging the caught error object — a taint analyzer traces
  // a logged error back to the test passphrase fixture (a non-secret
  // constant) and raises a false clear-text-logging alert.
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
