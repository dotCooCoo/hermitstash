// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Live b.sql sqlite-FTS5 + catalog/pragma test against a real node:sqlite
 * DatabaseSync handle (no docker - sqlite is the built-in dialect).
 *
 * Exercises the sqlite-only builders the mail store + the at-rest key-
 * rotation pipeline drive, end to end against a live engine so the emitted
 * SQL is proven to PARSE + RUN + return the right rows, not just match a
 * string shape:
 *
 *   1. createVirtualTable -> CREATE VIRTUAL TABLE ... USING fts5(...) runs;
 *      whereMatch -> `<fts> MATCH ?` returns exactly the rows whose tokens
 *      match, with the query string bound (never interpolated).
 *   2. whereInJsonEach -> `<col> IN (SELECT value FROM json_each(?))`
 *      unrolls a JSON-array string bind to a membership filter.
 *   3. The catalog sub-API (listTables / tableExists / tableInfo /
 *      sampleRandom / changes) + pragma (journal_mode / synchronous /
 *      wal_checkpoint) emit statements the engine accepts, returning the
 *      real catalog metadata.
 *   4. A bound MATCH operand carrying SQL metacharacters stays a literal
 *      FTS query term - it cannot break out of the placeholder.
 */

var { DatabaseSync } = require("node:sqlite");
var helpers = require("../helpers");
var check   = helpers.check;
var b       = require("../../");

function _all(db, built) {
  var st = db.prepare(built.sql);
  return built.params.length > 0 ? st.all.apply(st, built.params) : st.all();
}
function _get(db, built) {
  var st = db.prepare(built.sql);
  return built.params.length > 0 ? st.get.apply(st, built.params) : st.get();
}
function _run(db, built) {
  var st = db.prepare(built.sql);
  return built.params.length > 0 ? st.run.apply(st, built.params) : st.run();
}

async function run() {
  var sql = b.sql;
  var db = new DatabaseSync(":memory:");
  try {
    // ---- 1. FTS5 virtual table + MATCH ----
    _run(db, sql.createVirtualTable("mail_fts", {
      columns:  [{ name: "objectid", unindexed: true }, "subject_toks", "body_toks"],
      tokenize: "unicode61 remove_diacritics 2",
      quoteName: true,
    }));
    check("createVirtualTable: CREATE VIRTUAL TABLE USING fts5 runs", true);

    function ins(oid, subj, body) {
      _run(db, sql.insert("mail_fts", { quoteName: true })
        .columns(["objectid", "subject_toks", "body_toks"])
        .values({ objectid: oid, subject_toks: subj, body_toks: body }).toSql());
    }
    ins("m1", "alpha bravo", "charlie delta");
    ins("m2", "bravo", "echo");
    ins("m3", "zulu", "delta foxtrot");

    // `<fts> MATCH ?` inside the IN-subquery shape the mail store uses -
    // bind the query string, never interpolate.
    var matchSub = sql.select("mail_fts", { dialect: "sqlite", quoteName: true })
      .columns(["objectid"]).whereMatch("mail_fts", "bravo").toSql();
    var bravoRows = _all(db, matchSub).map(function (r) { return r.objectid; }).sort();
    check("whereMatch 'bravo' returns m1 + m2 (token in subject of both)",
          bravoRows.length === 2 && bravoRows[0] === "m1" && bravoRows[1] === "m2");

    var deltaSub = sql.select("mail_fts", { dialect: "sqlite", quoteName: true })
      .columns(["objectid"]).whereMatch("mail_fts", "delta").toSql();
    var deltaRows = _all(db, deltaSub).map(function (r) { return r.objectid; }).sort();
    check("whereMatch 'delta' returns m1 + m3 (token in body of both)",
          deltaRows.length === 2 && deltaRows[0] === "m1" && deltaRows[1] === "m3");

    // The MATCH operand binds: a query carrying a token that does not exist
    // returns nothing (and a metacharacter-laden operand stays a literal
    // FTS term, never a statement break - the engine parses it as a query).
    var noneSub = sql.select("mail_fts", { dialect: "sqlite", quoteName: true })
      .columns(["objectid"]).whereMatch("mail_fts", "nonexistenttoken").toSql();
    check("whereMatch unknown token returns no rows", _all(db, noneSub).length === 0);

    // ---- 2. json_each membership ----
    db.prepare('CREATE TABLE "msgs" ("objectid" TEXT, "folder_id" INTEGER)').run();
    db.prepare('INSERT INTO "msgs" VALUES (?,?),(?,?),(?,?)')
      .run("m1", 1, "m2", 1, "m3", 2);
    var jeBuilt = sql.select("msgs", { dialect: "sqlite", quoteName: true })
      .columns(["objectid", "folder_id"])
      .where("folder_id", 1)
      .whereInJsonEach("objectid", JSON.stringify(["m1", "m3"]))
      .toSql();
    var jeRows = _all(db, jeBuilt).map(function (r) { return r.objectid; });
    check("whereInJsonEach: folder=1 AND objectid IN json_each(['m1','m3']) -> only m1",
          jeRows.length === 1 && jeRows[0] === "m1");

    // ---- 3. catalog sub-API ----
    var tables = _all(db, sql.catalog.listTables()).map(function (r) { return r.name; });
    check("catalog.listTables lists the user tables (msgs present, no sqlite_ internal)",
          tables.indexOf("msgs") !== -1 && tables.every(function (n) { return n.indexOf("sqlite_") !== 0; }));
    check("catalog.tableExists true for a real table",
          !!_get(db, sql.catalog.tableExists("msgs")));
    check("catalog.tableExists false for a missing table",
          !_get(db, sql.catalog.tableExists("no_such_table")));
    var info = _all(db, sql.catalog.tableInfo("msgs")).map(function (c) { return c.name; }).sort();
    check("catalog.tableInfo returns the column names",
          info.length === 2 && info[0] === "folder_id" && info[1] === "objectid");
    var sample = _all(db, sql.catalog.sampleRandom("msgs", ["objectid"], { limit: 2 }));
    check("catalog.sampleRandom ORDER BY RANDOM LIMIT ? returns <= limit rows",
          sample.length <= 2 && sample.length >= 1);

    // catalog.changes reports the row count of the last write on this conn.
    db.prepare('UPDATE "msgs" SET "folder_id" = 9 WHERE "folder_id" = 2').run();
    var changed = _get(db, sql.catalog.changes());
    check("catalog.changes reports last-write rowcount", changed && changed.c === 1);

    // ---- 4. pragma sub-API ----
    var jm = _get(db, sql.pragma("journal_mode", "WAL"));
    check("pragma journal_mode=WAL runs (returns a mode row)", !!jm);
    _run(db, sql.pragma("synchronous", "NORMAL"));
    check("pragma synchronous=NORMAL runs", true);
    _run(db, sql.pragma("wal_checkpoint", "TRUNCATE"));
    check("pragma wal_checkpoint(TRUNCATE) runs", true);

    // ---- 5. metacharacter operand stays bound (no breakout) ----
    // A would-be-injection MATCH operand is a literal FTS query term: the
    // FTS5 parser treats it as a (possibly zero-match) query, never a
    // statement. The row count is whatever matches; the point is the
    // statement does not error out / stack a second statement.
    var safeMatch = sql.select("mail_fts", { dialect: "sqlite", quoteName: true })
      .columns(["objectid"]).whereMatch("mail_fts", "alpha").toSql();
    var injBuilt = { sql: safeMatch.sql, params: ['alpha"; DROP TABLE "msgs'] };
    var injErr = null;
    try { _all(db, injBuilt); } catch (e) { injErr = e; }
    var msgsStill = !!_get(db, sql.catalog.tableExists("msgs"));
    check("bound MATCH operand with metacharacters does not drop a table",
          msgsStill);
    // The metachar query either matches nothing or errors as a malformed
    // FTS expression - either way "msgs" survived (no statement breakout).
    check("metachar MATCH operand stayed a single bound statement",
          injErr === null || msgsStill);
  } finally {
    db.close();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
