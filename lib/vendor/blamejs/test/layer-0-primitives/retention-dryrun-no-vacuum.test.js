// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// #120: a retention dry-run / preview must NOT touch the database. Under a
// regulated posture (gdpr / hipaa / …) whose POSTURE_DEFAULTS sets
// requireVacuumAfterErase, cryptoField.eraseRow schedules a FULL VACUUM and
// emits db.vacuum_after_erase. retention._erase called eraseRow at the top of
// the function — BEFORE the `if (dryRun) return` gate — so previewing an
// erase rule ran a full-table VACUUM per candidate row: a preview that locks
// the database and rewrites the whole file, the opposite of "preview".
//
// RED on the buggy tree: a dryRun run() fires vacuumAfterErase (spy count >= 1).
// GREEN after the fix: dryRun fires it 0 times; a real (committing) run still
// vacuums under the regulated posture.

var fs = require("fs");
var path = require("path");
var os = require("os");
var helpers  = require("../helpers");
var dbHelper = require("../helpers/db");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-retention-dryrun-"));
  await dbHelper.setupTestDb(tmpDir);

  // An operator app table with a sealed column, so retention routes the
  // candidate through _erase (sealed-column NULL-out) rather than the
  // _hardDelete fallback. The actual value need not be sealed at rest for
  // the bug to fire — _erase keys off getSealedFields(table) being non-empty.
  b.cryptoField.registerTable("retention_pii", {
    sealedFields: ["payload"],
    rowIdField:   "_id",
  });
  b.db.prepare(
    "CREATE TABLE \"retention_pii\" (" +
    "\"_id\" TEXT PRIMARY KEY, \"createdAt\" INTEGER, " +
    "\"payload\" TEXT, \"__erasedAt\" INTEGER)"
  ).run();
  var longAgo = Date.now() - b.constants.TIME.days(400);
  b.db.prepare(
    "INSERT INTO \"retention_pii\" (\"_id\", \"createdAt\", \"payload\", \"__erasedAt\") " +
    "VALUES (?, ?, ?, NULL)"
  ).run("row-1", longAgo, "subject-secret-payload");

  // Spy on the VACUUM seam. cryptoField.eraseRow resolves the db module via
  // lazyRequire and reads .vacuumAfterErase at call time, so replacing the
  // export observes (and still drives) the real call.
  var realVacuum = b.db.vacuumAfterErase;
  var vacuumCalls = 0;
  b.db.vacuumAfterErase = function (opts) {
    vacuumCalls++;
    return realVacuum.call(b.db, opts);
  };

  // gdpr → requireVacuumAfterErase: true, so eraseRow auto-vacuums.
  b.compliance.set("gdpr");

  try {
    var retention = b.retention.create({ db: b.db, audit: false });
    retention.declare({
      name:     "pii-ttl",
      table:    "retention_pii",
      ageField: "createdAt",
      ttlMs:    b.constants.TIME.days(90),
      action:   "erase",
    });

    // ---- the bug: a dry-run must not VACUUM ----
    vacuumCalls = 0;
    var preview = await retention.run("pii-ttl", { dryRun: true });
    check("#120 dry-run scans the past-TTL row",
          preview && preview.scanned >= 1);
    check("#120 dry-run reports it WOULD erase (no real work)",
          preview && preview.processed >= 1);
    check("#120 dry-run performs NO database VACUUM",
          vacuumCalls === 0);
    // The row must still be present + un-erased after a preview.
    var afterPreview = b.db.prepare(
      "SELECT \"payload\" FROM \"retention_pii\" WHERE \"_id\" = ?").get("row-1");
    check("#120 dry-run leaves the row's sealed column intact",
          afterPreview && afterPreview.payload === "subject-secret-payload");

    // ---- the real path still vacuums under the regulated posture ----
    vacuumCalls = 0;
    var real = await retention.run("pii-ttl", { dryRun: false });
    check("#120 real run erases the row", real && real.processed >= 1);
    check("#120 real run DOES vacuum under gdpr", vacuumCalls >= 1);
    var afterErase = b.db.prepare(
      "SELECT \"payload\" FROM \"retention_pii\" WHERE \"_id\" = ?").get("row-1");
    check("#120 real run NULLs the sealed column",
          afterErase && afterErase.payload === null);
  } finally {
    b.db.vacuumAfterErase = realVacuum;
    b.compliance.clear();
    await dbHelper.teardownTestDb(tmpDir);
  }
}

module.exports = { run: run };
