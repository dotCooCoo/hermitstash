// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.subject — GDPR data-subject rights (export / erase). Regression for the
 * no-subject-tables path: subject.export/exportData `return`ed _writeAudit()'s
 * value (undefined, it has no return) instead of the documented empty dump {},
 * so an operator exporting before declaring any subjectField-tagged table got
 * `undefined` and `Object.keys(dump)` / `dump.<table>` threw.
 */

var fs      = require("node:fs");
var os      = require("node:os");
var path    = require("node:path");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var { setupTestDb, teardownTestDb } = require("../helpers/db");

// A schema with NO subjectField-tagged column → db()._getSubjectTables() is
// empty → export/exportData takes the no-subject-tables early return.
var NO_SUBJECT_SCHEMA = [{ name: "widget", columns: { id: "TEXT PRIMARY KEY", name: "TEXT" } }];

async function run() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-subject-"));
  try {
    await setupTestDb(dir, NO_SUBJECT_SCHEMA);

    var dump = b.subject.exportData("subj-1");
    check("subject.exportData returns {} (not undefined) with no subject tables",
      dump !== undefined && JSON.stringify(dump) === "{}");
    check("subject.export is the same function as exportData (alias)",
      b.subject.export === b.subject.exportData);
    var keysOk = true;
    try { Object.keys(dump); } catch (_e) { keysOk = false; }
    check("Object.keys(export dump) does not throw on the empty-dump path", keysOk);
  } finally {
    await teardownTestDb(dir);
  }
}

if (require.main === module) {
  run().then(function () { console.log("subject OK — " + helpers.getChecks() + " checks"); },
    function (e) { console.error(e && e.stack || e); process.exit(1); });
}

module.exports = { run: run };
