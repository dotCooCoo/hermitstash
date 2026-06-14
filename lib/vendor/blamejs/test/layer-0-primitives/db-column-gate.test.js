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
}, {
  // Residency-gate fixture table — `dataRegion` carries the per-row
  // residency tag (plaintext, inspected before sealRow); `addr` is a
  // region-bound column for the per-column gate.
  name: "residents",
  columns: {
    _id:        "TEXT PRIMARY KEY",
    name:       "TEXT",
    dataRegion: "TEXT",
    addr:       "TEXT",
  },
}];

async function initDb(tmpDir, columnGate, dataResidency) {
  process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
  helpers.setTestPassphraseEnv();
  b.cluster._resetForTest();
  b.audit._resetForTest();
  b.vault._resetForTest();
  b.db._resetForTest();
  await b.vault.init({ dataDir: tmpDir });
  var opts = { dataDir: tmpDir, tmpDir: path.join(tmpDir, "tmpfs"), schema: SCHEMA };
  if (columnGate !== undefined) opts.columnGate = columnGate;
  if (dataResidency !== undefined) opts.dataResidency = dataResidency;
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

  // ---- per-row + per-column residency write gates via db.from(...) ----
  await runRowResidencyGate();
  await runColumnResidencyGate();
  await runRowResidencyRegionGate();

  console.log("OK — db column-gate tests");
}

// Local per-row residency gate driven through db.from(table).insertOne /
// .updateOne. The fixture's db has NO dataResidency region configured,
// so the local-mismatch refusal can't fire here (the gate passes when no
// region is set) — this covers the missing-tag / invalid-tag refusals,
// the valid-tag success path (row written + readable back), and the
// update matrix. Region-mismatch lives in runRowResidencyRegionGate.
async function runRowResidencyGate() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-rowresid-"));
  await initDb(tmp);
  b.cryptoField.clearResidencyForTest();
  try {
    b.cryptoField.declarePerRowResidency("residents", {
      residencyColumn: "dataRegion",
      allowedTags:     ["eu-west-1", "us-east-1", "global"],
    });

    // INSERT without the tag column → refused.
    check("insert without residency tag refused",
          insertCode("residents", { _id: "r-miss", name: "x" }) ===
          "db-query/row-residency-tag-missing");

    // INSERT with a tag outside allowedTags → refused.
    check("insert with tag not in allowedTags refused",
          insertCode("residents", { _id: "r-bad", name: "x", dataRegion: "ap-south-1" }) ===
          "db-query/row-residency-tag-invalid");

    // INSERT with a valid tag → row written AND readable back.
    var ins = b.db.from("residents").insertOne({
      _id: "r-ok", name: "alice", dataRegion: "eu-west-1",
    });
    check("insert with valid residency tag returns the row",
          ins && ins._id === "r-ok" && ins.dataRegion === "eu-west-1");
    var readBack = b.db.from("residents").where({ _id: "r-ok" }).first();
    check("valid-tag row is readable back after insert",
          readBack && readBack.name === "alice" && readBack.dataRegion === "eu-west-1");

    // UPDATE that does NOT touch the residency column on a declared
    // table → passes (not a transfer).
    var updNonResidency = b.db.from("residents").where({ _id: "r-ok" }).updateOne({ name: "alice-2" });
    check("update not touching residency column passes", updNonResidency === true);
    check("non-residency update persisted",
          b.db.from("residents").where({ _id: "r-ok" }).first().name === "alice-2");

    // UPDATE that sets an out-of-allowlist tag → refused.
    check("update to out-of-allowlist residency tag refused",
          updateCode("residents", { _id: "r-ok" }, { dataRegion: "ap-south-1" }) ===
          "db-query/row-residency-tag-invalid");

    // UPDATE that explicitly NULLs the residency column → refused (the
    // row must not be nullable into an untagged state — INSERT requires
    // a tag, UPDATE must not clear it).
    check("update clearing residency column to null refused",
          updateCode("residents", { _id: "r-ok" }, { dataRegion: null }) ===
          "db-query/row-residency-tag-missing");
    check("residency tag intact after the refused null-update",
          b.db.from("residents").where({ _id: "r-ok" }).first().dataRegion === "eu-west-1");
  } finally {
    b.cryptoField.clearResidencyForTest();
    b.compliance.clear();
    b.db.close();
    fs.rmSync(tmp, { recursive: true, force: true });
    b.audit._resetForTest();
    b.db._resetForTest();
    b.vault._resetForTest();
    b.cluster._resetForTest();
  }
}

// Per-column residency gate wiring through db.from(...).insertOne. The
// fixture's db has a dataResidency region ("eu-west-1"); a column bound
// to a different region ("us-east-1") refuses under a cross-border
// regulated posture (gdpr) and passes (advisory) without a posture.
async function runColumnResidencyGate() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-colresid-"));
  await initDb(tmp, undefined, { region: "eu-west-1" });
  b.cryptoField.clearResidencyForTest();
  try {
    b.cryptoField.declareColumnResidency("residents", {
      columnResidency: { addr: "us-east-1" },
    });

    // Without a posture → write passes (advisory only).
    var insAdvisory = b.db.from("residents").insertOne({
      _id: "c-advisory", name: "noposture", addr: "10 Main St",
    });
    check("column-residency mismatch without posture passes (advisory)",
          insAdvisory && insAdvisory._id === "c-advisory");

    // Under gdpr → mismatched column refused.
    b.compliance.set("gdpr");
    check("column-residency mismatch under gdpr refused",
          insertCode("residents", { _id: "c-gdpr", name: "y", addr: "20 Main St" }) ===
          "db-query/column-residency-mismatch");
  } finally {
    b.compliance.clear();
    b.cryptoField.clearResidencyForTest();
    b.db.close();
    fs.rmSync(tmp, { recursive: true, force: true });
    b.audit._resetForTest();
    b.db._resetForTest();
    b.vault._resetForTest();
    b.cluster._resetForTest();
  }
}

// Per-row residency region gate — the fixture supports a custom
// dataResidency region, so this drives the cross-border local-mismatch
// refusal: under gdpr a tag in allowedTags but OUTSIDE the deployment's
// region set is refused; a tag inside the region set or "global" passes.
async function runRowResidencyRegionGate() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-rowresid-region-"));
  await initDb(tmp, undefined, { region: "eu-west-1" });
  b.cryptoField.clearResidencyForTest();
  try {
    b.cryptoField.declarePerRowResidency("residents", {
      residencyColumn: "dataRegion",
      allowedTags:     ["eu-west-1", "us-east-1", "global"],
    });
    b.compliance.set("gdpr");

    // Tag in allowedTags but outside the deployment region → refused.
    check("row tag outside deployment region under gdpr refused",
          insertCode("residents", { _id: "rr-us", name: "u", dataRegion: "us-east-1" }) ===
          "db-query/row-residency-local-mismatch");

    // Tag matching the deployment region → passes.
    var insEu = b.db.from("residents").insertOne({
      _id: "rr-eu", name: "e", dataRegion: "eu-west-1",
    });
    check("row tag matching deployment region passes",
          insEu && insEu._id === "rr-eu");

    // "global" tag → passes any region.
    var insGlobal = b.db.from("residents").insertOne({
      _id: "rr-global", name: "g", dataRegion: "global",
    });
    check("row tag 'global' passes any region", insGlobal && insGlobal._id === "rr-global");
  } finally {
    b.compliance.clear();
    b.cryptoField.clearResidencyForTest();
    b.db.close();
    fs.rmSync(tmp, { recursive: true, force: true });
    b.audit._resetForTest();
    b.db._resetForTest();
    b.vault._resetForTest();
    b.cluster._resetForTest();
  }
}

// insertCode / updateCode — return the thrown error's .code when the
// write refuses, else null. Compose the same chainable surface the gate
// runs under, so the refusal is exercised end-to-end (not a unit call).
function insertCode(table, row) {
  try { b.db.from(table).insertOne(row); } catch (e) { return e && e.code; }
  return null;
}

function updateCode(table, whereObj, changes) {
  try { b.db.from(table).where(whereObj).updateOne(changes); } catch (e) { return e && e.code; }
  return null;
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
