// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// B8a: the retention sweep loop must TERMINATE even when a full batch of rows is
// not removed from the candidate set by its action. The loop paged LIMIT-from-
// the-top and exited only when `rows.length < batchSize`, so any full batch that
// mutated nothing was re-selected forever:
//   - dryRun (preview) mutates NOTHING → every table with > batchSize past-TTL
//     rows looped infinitely (a preview that never returns — a DoS);
//   - a full batch all on legal-hold (skipped) → re-selected forever;
//   - (same for "warn"-stage and errored rows).
// The fix adds keyset pagination (ORDER BY _id, _id > cursor) so the loop always
// advances past rows it has already seen, regardless of whether they were
// actioned.
//
// RED on the buggy tree: run() never returns (the harness times out).
// GREEN after the fix: each scenario terminates and scans every row exactly once.

var fs = require("fs");
var path = require("path");
var os = require("os");
var helpers  = require("../helpers");
var dbHelper = require("../helpers/db");
var b     = helpers.b;
var check = helpers.check;

var N = 5;            // rows past TTL
var BATCH = 2;        // < N so the loop must iterate (and, when buggy, re-select)

function _seedRows(table, withHold) {
  var cols = "\"_id\" TEXT PRIMARY KEY, \"createdAt\" INTEGER, \"payload\" TEXT, \"__erasedAt\" INTEGER" +
    (withHold ? ", \"onHold\" INTEGER" : "");
  b.db.prepare("CREATE TABLE \"" + table + "\" (" + cols + ")").run();
  var longAgo = Date.now() - b.constants.TIME.days(400);
  for (var i = 0; i < N; i++) {
    if (withHold) {
      b.db.prepare("INSERT INTO \"" + table + "\" (\"_id\", \"createdAt\", \"payload\", \"__erasedAt\", \"onHold\") " +
        "VALUES (?, ?, ?, NULL, 1)").run("r-" + i, longAgo, "p-" + i);
    } else {
      b.db.prepare("INSERT INTO \"" + table + "\" (\"_id\", \"createdAt\", \"payload\", \"__erasedAt\") " +
        "VALUES (?, ?, ?, NULL)").run("r-" + i, longAgo, "p-" + i);
    }
  }
}

async function run() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-retention-term-"));
  await dbHelper.setupTestDb(tmpDir);
  try {
    // ---- dryRun: mutates nothing → must still terminate, scanning each row once ----
    b.cryptoField.registerTable("retention_dry", { sealedFields: ["payload"], rowIdField: "_id" });
    _seedRows("retention_dry", false);
    var ret1 = b.retention.create({ db: b.db, audit: false });
    ret1.declare({
      name: "dry-ttl", table: "retention_dry", ageField: "createdAt",
      ttlMs: b.constants.TIME.days(90), action: "erase", batchSize: BATCH,
    });
    var preview = await ret1.run("dry-ttl", { dryRun: true });
    check("dryRun sweep TERMINATES (did not infinite-loop)", !!preview);
    check("dryRun scans each row exactly once (no re-selection)", preview.scanned === N);
    check("dryRun would-process every past-TTL row", preview.processed === N);
    // Nothing was actually erased (preview).
    var stillThere = b.db.prepare("SELECT COUNT(*) AS n FROM \"retention_dry\" WHERE \"payload\" IS NOT NULL").get();
    check("dryRun left every row intact", stillThere.n === N);

    // ---- all-legal-hold: every candidate skipped → must still terminate ----
    b.cryptoField.registerTable("retention_held", { sealedFields: ["payload"], rowIdField: "_id" });
    _seedRows("retention_held", true);
    var ret2 = b.retention.create({ db: b.db, audit: false });
    ret2.declare({
      name: "held-ttl", table: "retention_held", ageField: "createdAt",
      ttlMs: b.constants.TIME.days(90), action: "erase", batchSize: BATCH,
      legalHoldField: "onHold",
    });
    var heldSweep = await ret2.run("held-ttl", { dryRun: false });
    check("all-legal-hold sweep TERMINATES (did not infinite-loop)", !!heldSweep);
    check("all-legal-hold scans each row exactly once", heldSweep.scanned === N);
    check("all-legal-hold honors the hold on every row", heldSweep.legalHoldsHonored === N);
    check("all-legal-hold processed none (all skipped)", heldSweep.processed === 0);
    var heldIntact = b.db.prepare("SELECT COUNT(*) AS n FROM \"retention_held\" WHERE \"payload\" IS NOT NULL").get();
    check("all-legal-hold left every held row intact", heldIntact.n === N);

    // ---- real erase still works + terminates (no over/under-scan) ----
    b.cryptoField.registerTable("retention_real", { sealedFields: ["payload"], rowIdField: "_id" });
    _seedRows("retention_real", false);
    var ret3 = b.retention.create({ db: b.db, audit: false });
    ret3.declare({
      name: "real-ttl", table: "retention_real", ageField: "createdAt",
      ttlMs: b.constants.TIME.days(90), action: "erase", batchSize: BATCH,
    });
    var realSweep = await ret3.run("real-ttl", { dryRun: false });
    check("real erase sweep terminates + scans each row once", realSweep.scanned === N);
    check("real erase processed every past-TTL row", realSweep.processed === N);
    var erased = b.db.prepare("SELECT COUNT(*) AS n FROM \"retention_real\" WHERE \"payload\" IS NULL").get();
    check("real erase NULLed every sealed payload", erased.n === N);
  } finally {
    await dbHelper.teardownTestDb(tmpDir);
  }
  console.log("OK — retention sweep termination (" + helpers.getChecks() + " checks)");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
