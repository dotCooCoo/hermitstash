// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.sql SELECT OFFSET without LIMIT — dialect-portable emission.
 *
 * A bare `OFFSET n` (no LIMIT) is valid ONLY on Postgres; SQLite and
 * MySQL both reject it as a syntax error ("skip N, return the rest" has
 * no bare-OFFSET spelling there). The builder advertises that one query
 * text runs unchanged across sqlite / postgres / mysql, and the
 * framework's own backend is node:sqlite — so `b.sql.select(t).offset(n)`
 * (and every consumer that routes through it: `b.db.from(t).offset(n)`,
 * `b.db.collection(t).find(q, { offset })`) must emit a statement the
 * active backend accepts.
 *
 * This drives the real backend (node:sqlite prepares + runs the emitted
 * SQL) and the real consumer path (b.db.from), and asserts the emitted
 * string for all three dialects.
 */

var helpers        = require("../helpers");
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

var { DatabaseSync } = require("node:sqlite");

async function run() {
  var sql = b.sql;

  // ---- emitted SQL is dialect-valid for offset-without-limit ----
  check("sqlite offset-without-limit emits a LIMIT -1 sentinel before OFFSET",
        sql.select("t", { dialect: "sqlite" }).offset(5).toSql().sql ===
          "SELECT * FROM t LIMIT -1 OFFSET 5");
  check("mysql offset-without-limit emits the max-BIGINT LIMIT sentinel before OFFSET",
        sql.select("t", { dialect: "mysql" }).offset(5).toSql().sql ===
          "SELECT * FROM t LIMIT 18446744073709551615 OFFSET 5");
  check("postgres offset-without-limit emits LIMIT ALL before OFFSET",
        sql.select("t", { dialect: "postgres" }).offset(5).toSql().sql ===
          "SELECT * FROM t LIMIT ALL OFFSET 5");

  // ---- limit-present paths are byte-for-byte unchanged ----
  check("limit + offset unchanged",
        sql.select("t").limit(10).offset(20).toSql().sql === "SELECT * FROM t LIMIT 10 OFFSET 20");
  check("limit-only unchanged",
        sql.select("t").limit(10).toSql().sql === "SELECT * FROM t LIMIT 10");
  check("limit(0) unchanged",
        sql.select("t").limit(0).toSql().sql === "SELECT * FROM t LIMIT 0");
  check("no limit / no offset unchanged",
        sql.select("t").toSql().sql === "SELECT * FROM t");

  // ---- the emitted sqlite statement actually prepares + runs on node:sqlite ----
  var mem = new DatabaseSync(":memory:");
  mem.exec('CREATE TABLE "t" (a INTEGER)');
  mem.exec('INSERT INTO "t" VALUES (1),(2),(3),(4),(5)');
  var built = sql.select("t", { dialect: "sqlite", quoteName: true })
    .columns(["a"]).orderBy("a").offset(2).toSql();
  var got;
  try {
    var stmt = mem.prepare(built.sql);
    got = stmt.all.apply(stmt, built.params).map(function (r) { return r.a; });
  } catch (e) {
    throw new Error("emitted offset-only SQL failed to prepare/run on node:sqlite: " +
      ((e && e.message) || String(e)) + " — sql was: " + built.sql);
  }
  check("emitted sqlite offset-only SQL runs and skips the first N rows",
        JSON.stringify(got) === JSON.stringify([3, 4, 5]));
  mem.close();

  // ---- real consumer path: b.db.from(...).offset(n).all() over sqlite ----
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-sql-offset-"));
  try {
    await setupTestDb(tmpDir);
    b.db.from("users").insertOne({ _id: "a", status: "x" });
    b.db.from("users").insertOne({ _id: "b", status: "x" });
    b.db.from("users").insertOne({ _id: "c", status: "x" });
    var rows = b.db.from("users").orderBy("_id").offset(1).all();
    var ids = rows.map(function (r) { return r._id; });
    check("b.db.from(...).offset(1).all() returns the rows after the offset",
          JSON.stringify(ids) === JSON.stringify(["b", "c"]));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
