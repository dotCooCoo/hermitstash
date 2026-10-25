require("../helpers/isolate-db"); // must precede every HermitStash require
/**
 * lib/db.js rebuilds a database in auto_vacuum=NONE into auto_vacuum=INCREMENTAL
 * when it opens it, and keeps its rows.
 */
var { DatabaseSync } = require("node:sqlite");
var { describe, it } = require("node:test");
var assert = require("node:assert");

// A database as earlier releases created it: journal_mode=WAL set before
// auto_vacuum, which leaves it in auto_vacuum=NONE.
var seed = new DatabaseSync(process.env.HERMITSTASH_DB_PATH);
seed.exec("PRAGMA journal_mode=WAL");
seed.exec("PRAGMA auto_vacuum=INCREMENTAL");
seed.exec("CREATE TABLE _conversion_probe (id INTEGER PRIMARY KEY, v TEXT)");
seed.exec("INSERT INTO _conversion_probe (v) VALUES ('kept')");
var seededMode = Number(seed.prepare("PRAGMA auto_vacuum").get().auto_vacuum);
seed.close();

var db = require("../../lib/db");

describe("lib/db auto_vacuum conversion", function () {
  it("starts from a database in auto_vacuum=NONE", function () {
    assert.strictEqual(seededMode, 0);
  });

  it("rebuilds the database in auto_vacuum=INCREMENTAL when it opens it", function () {
    assert.strictEqual(Number(db.rawGet("PRAGMA auto_vacuum").auto_vacuum), 2);
  });

  it("keeps the rows the database held", function () {
    assert.deepStrictEqual(db.rawQuery("SELECT v FROM _conversion_probe").map(function (r) { return r.v; }), ["kept"]);
  });

  it("frees pages through the daily vacuum after the conversion", function () {
    db.rawExec("CREATE TABLE _conversion_fill (id INTEGER PRIMARY KEY, v BLOB)");
    for (var i = 0; i < 500; i++) db.rawExec("INSERT INTO _conversion_fill (v) VALUES (?)", Buffer.alloc(1500, 1));
    db.rawExec("DROP TABLE _conversion_fill");
    assert.ok(db.incrementalVacuum(100) > 0, "the vacuum freed at least one page");
  });
});
