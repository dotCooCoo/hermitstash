require("../helpers/isolate-db"); // must precede every HermitStash require
/**
 * lib/db.js creates a new database in auto_vacuum=INCREMENTAL, and
 * db.incrementalVacuum(n), which the daily incremental_vacuum job calls, moves
 * up to n free pages out of the file.
 */
var { describe, it } = require("node:test");
var assert = require("node:assert");
var db = require("../../lib/db");

function freelist() {
  return Number(db.rawGet("PRAGMA freelist_count").freelist_count);
}

describe("lib/db incremental vacuum", function () {
  it("creates a new database in auto_vacuum=INCREMENTAL", function () {
    assert.strictEqual(Number(db.rawGet("PRAGMA auto_vacuum").auto_vacuum), 2);
  });

  it("frees up to the requested number of pages and reports how many it freed", function () {
    db.rawExec("CREATE TABLE _vacuum_probe (id INTEGER PRIMARY KEY, v BLOB)");
    for (var i = 0; i < 1000; i++) db.rawExec("INSERT INTO _vacuum_probe (v) VALUES (?)", Buffer.alloc(1500, 1));
    db.rawExec("DELETE FROM _vacuum_probe");
    db.rawExec("DROP TABLE _vacuum_probe");
    var before = freelist();
    assert.ok(before > 100, "the probe left more than 100 free pages: " + before);
    assert.strictEqual(db.incrementalVacuum(100), 100);
    assert.strictEqual(freelist(), before - 100);
  });

  it("refuses a page count that is not a positive integer", function () {
    assert.throws(function () { db.incrementalVacuum(0); }, TypeError);
    assert.throws(function () { db.incrementalVacuum(1.5); }, TypeError);
    assert.throws(function () { db.incrementalVacuum("100); DROP TABLE users; --"); }, TypeError);
  });
});
