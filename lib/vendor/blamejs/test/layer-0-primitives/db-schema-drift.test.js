// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * dbSchema.reconcile / reconcileTable — schema-drift detection.
 *
 * reconcile is additive-only (CREATE IF NOT EXISTS + ALTER ADD COLUMN);
 * it never drops columns. The onDrift opt adds detection of config-vs-
 * live divergence without changing that non-destructive contract:
 *
 *   - onDrift unset = posture-driven default (v0.15.0): "ignore" on an
 *     unpinned / non-regulated deployment (back-compat); "refuse" when a
 *     regulated compliance posture is globally pinned.
 *   - "ignore" = tolerate a live table with an extra column silently
 *     (the explicit opt-out under a regulated posture).
 *   - "warn"   = detect, never throw (report returned to the caller).
 *   - "refuse" = throw at boot on the first drifted table (strict-schema
 *     posture).
 *
 * Drift cases covered: an undeclared (extra) live column and a clean
 * schema (no drift). Tested directly against a node:sqlite handle — the
 * same handle shape db.init drives — so the unit under test is the
 * reconcile diff, not the full vault/audit boot.
 */

var helpers = require("../helpers");
var check = helpers.check;
var fs   = helpers.fs;
var os   = helpers.os;
var path = helpers.path;
var sqlite = require("node:sqlite");
var dbSchema = require("../../lib/db-schema");
var compliance = require("../../lib/compliance");

function _openDb(tmpDir, name) {
  return new sqlite.DatabaseSync(path.join(tmpDir, name || "drift.db"));
}

function _liveColumns(db, table) {
  return db.prepare('PRAGMA table_info("' + table + '")').all()
    .map(function (r) { return r.name; });
}

function threwMatching(fn, pattern) {
  try { fn(); } catch (e) { return pattern.test(e.message) ? e : null; }
  return null;
}

var SCHEMA = [{
  name: "widgets",
  columns: {
    _id:    "TEXT PRIMARY KEY",
    label:  "TEXT",
    status: "TEXT DEFAULT 'active'",
  },
  indexes: ["status"],
}];

async function run() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-schema-drift-"));

  // ---- DRIFT_MODES exported ----
  check("DRIFT_MODES exported as the three reaction modes",
    Array.isArray(dbSchema.DRIFT_MODES) &&
    dbSchema.DRIFT_MODES.join(",") === "ignore,warn,refuse");

  // ---- clean schema → no drift in any mode ----
  var dbClean = _openDb(tmp);
  var cleanReport = dbSchema.reconcile(dbClean, SCHEMA, { onDrift: "refuse" });
  check("clean schema reconcile reports no drift", cleanReport.drifted === false);
  check("clean schema reconcile reports zero drifted tables", cleanReport.tables.length === 0);
  // re-running refuse on a freshly-reconciled DB must not throw
  check("clean schema refuse mode does not throw",
    threwMatching(function () { dbSchema.reconcile(dbClean, SCHEMA, { onDrift: "refuse" }); }, /.*/) === null);
  dbClean.close();

  // ---- introduce an undeclared (extra) live column out of band ----
  var dbDrift = _openDb(tmp);
  dbSchema.reconcile(dbDrift, SCHEMA); // default: ignore (back-compat path)
  dbSchema.runSql(dbDrift, 'ALTER TABLE "widgets" ADD COLUMN "rogue" TEXT');
  check("setup: rogue column is present in the live table",
    _liveColumns(dbDrift, "widgets").indexOf("rogue") !== -1);

  // default (no opts) tolerates drift silently — return value present,
  // not drifted is irrelevant; the key assertion is it does NOT throw.
  check("default reconcile (no opts) tolerates the extra column",
    threwMatching(function () { dbSchema.reconcile(dbDrift, SCHEMA); }, /.*/) === null);

  // explicit "ignore" is identical to default — no throw, not flagged.
  var ignoreReport = dbSchema.reconcile(dbDrift, SCHEMA, { onDrift: "ignore" });
  check("onDrift:'ignore' does not flag the extra column", ignoreReport.drifted === false);

  // "warn" detects but does NOT throw, and reports the extra column.
  var warnReport;
  check("onDrift:'warn' does not throw on the extra column",
    threwMatching(function () { warnReport = dbSchema.reconcile(dbDrift, SCHEMA, { onDrift: "warn" }); }, /.*/) === null);
  check("onDrift:'warn' flags drift", warnReport.drifted === true);
  check("onDrift:'warn' identifies the drifted table",
    warnReport.tables.length === 1 && warnReport.tables[0].table === "widgets");
  check("onDrift:'warn' lists the undeclared column as extra",
    warnReport.tables[0].extra.indexOf("rogue") !== -1);
  check("onDrift:'warn' reports no missing declared columns",
    warnReport.tables[0].missing.length === 0);

  // "refuse" throws on the same drift.
  var refuseErr = threwMatching(
    function () { dbSchema.reconcile(dbDrift, SCHEMA, { onDrift: "refuse" }); },
    /schema drift on table 'widgets'/);
  check("onDrift:'refuse' throws on the extra column", !!refuseErr);
  check("onDrift:'refuse' error names the undeclared column",
    refuseErr && /undeclared column\(s\) \[rogue\]/.test(refuseErr.message));

  // refuse mode never drops the column — non-destructive contract holds.
  check("refuse mode left the rogue column in place (non-destructive)",
    _liveColumns(dbDrift, "widgets").indexOf("rogue") !== -1);
  dbDrift.close();

  // ---- reconcileTable surfaced directly carries the same modes ----
  var dbT = _openDb(tmp);
  dbSchema.reconcileTable(dbT, SCHEMA[0]);
  dbSchema.runSql(dbT, 'ALTER TABLE "widgets" ADD COLUMN "sneaky" TEXT');
  var tReport = dbSchema.reconcileTable(dbT, SCHEMA[0], { onDrift: "warn" });
  check("reconcileTable warn returns a drift report",
    tReport && tReport.drift && tReport.drift.extra.indexOf("sneaky") !== -1);
  check("reconcileTable refuse throws on drift",
    !!threwMatching(function () { dbSchema.reconcileTable(dbT, SCHEMA[0], { onDrift: "refuse" }); },
      /schema drift on table 'widgets'/));
  dbT.close();

  // ---- bad onDrift value is a config-time throw ----
  var dbBad = _openDb(tmp);
  var enumErr = threwMatching(
    function () { dbSchema.reconcile(dbBad, SCHEMA, { onDrift: "loud" }); },
    /onDrift must be one of/);
  check("bad onDrift enum value throws at config time", !!enumErr);
  check("bad onDrift enum value throws a TypeError",
    enumErr instanceof TypeError);
  check("non-string onDrift value throws",
    !!threwMatching(function () { dbSchema.reconcile(dbBad, SCHEMA, { onDrift: 3 }); },
      /onDrift must be one of/));
  dbBad.close();

  // ---- posture-driven default (v0.15.0): a regulated pinned posture
  // flips the unset-onDrift default from "ignore" to "refuse"; an explicit
  // onDrift always wins (including "ignore" to opt back out). ----
  compliance._resetForTest();
  try {
    // Build a freshly-reconciled DB, then introduce out-of-band drift —
    // all while UNPINNED so the clean setup never trips the default.
    var dbPosture = _openDb(tmp, "drift-posture.db");
    dbSchema.reconcile(dbPosture, SCHEMA);
    dbSchema.runSql(dbPosture, 'ALTER TABLE "widgets" ADD COLUMN "posture_extra" TEXT');

    // Unpinned: unset onDrift stays "ignore" — drift tolerated silently.
    check("unpinned + unset onDrift tolerates drift (ignore default)",
      threwMatching(function () { dbSchema.reconcile(dbPosture, SCHEMA); }, /.*/) === null);

    // Pin a regulated posture: unset onDrift now refuses on the SAME drift.
    compliance.set("gdpr");
    check("regulated posture pinned + unset onDrift refuses drift (refuse default)",
      !!threwMatching(function () { dbSchema.reconcile(dbPosture, SCHEMA); },
        /schema drift on table 'widgets'/));
    // Explicit opt-out: onDrift "ignore" tolerates drift even under the
    // regulated posture (the documented escape hatch).
    check("explicit onDrift:'ignore' opts out under a regulated posture",
      threwMatching(function () { dbSchema.reconcile(dbPosture, SCHEMA, { onDrift: "ignore" }); }, /.*/) === null);
    dbPosture.close();
  } finally {
    compliance._resetForTest();
  }

  fs.rmSync(tmp, { recursive: true, force: true });
  console.log("OK — db schema-drift detection tests");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
