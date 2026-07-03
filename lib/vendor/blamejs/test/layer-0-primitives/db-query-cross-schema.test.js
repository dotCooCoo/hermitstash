// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * db-query — schema-qualified table support.
 *
 * Tests run against a fake DB handle that records `prepare(sql)` calls
 * without executing — sufficient to verify SQL-shape and identifier
 * validation. The full execution path through real SQLite is exercised
 * by the layer-2 db tests already in the suite.
 */
var helpers = require("../helpers");
var check = helpers.check;
var dbQuery = require("../../lib/db-query");

function _fakeDb() {
  var prepared = [];
  return {
    prepared: prepared,
    prepare: function (sql) {
      prepared.push(sql);
      // Stmt stub — every method returns an empty result so the Query
      // doesn't crash before we read prepared SQL back.
      return {
        get:     function () { return null; },
        all:     function () { return []; },
        run:     function () { return { changes: 0 }; },
        iterate: function () { return { next: function () { return { done: true }; } }; },
      };
    },
  };
}

async function testRejectionPath() {
  var db = _fakeDb();
  var threwThree = null;
  try { new dbQuery.Query(db, "a.b.c"); }
  catch (e) { threwThree = e; }
  check("three-part identifier rejected",
        threwThree && /exactly 'schema.table'/.test(String(threwThree.message)));

  var threwEmpty = null;
  try { new dbQuery.Query(db, ".table"); }
  catch (e) { threwEmpty = e; }
  check("empty schema part rejected",
        threwEmpty !== null);

  var threwTrailing = null;
  try { new dbQuery.Query(db, "schema."); }
  catch (e) { threwTrailing = e; }
  check("empty table part rejected",
        threwTrailing !== null);

  var threwBadSchema = null;
  try { new dbQuery.Query(db, "DROP TABLE.users"); }
  catch (e) { threwBadSchema = e; }
  check("invalid schema identifier rejected",
        threwBadSchema !== null);

  var threwBadTable = null;
  try { new dbQuery.Query(db, "audit.DROP TABLE"); }
  catch (e) { threwBadTable = e; }
  check("invalid table identifier rejected",
        threwBadTable !== null);

  // Bare identifier without a dot still works — backward-compat.
  var bare = new dbQuery.Query(db, "users");
  check("bare table name still works", bare !== null);
}

async function testSchemaQualifiedSelectShape() {
  var db = _fakeDb();
  var q = new dbQuery.Query(db, "audit.events");

  q.where({ actorId: "u-1" }).first();
  check("first() emits SELECT FROM \"audit\".\"events\"",
        db.prepared.some(function (s) {
          return /SELECT \* FROM "audit"\."events"/.test(s);
        }));

  db.prepared.length = 0;
  new dbQuery.Query(db, "audit.events").select(["_id", "action"]).all();
  check("all() with select() emits projection on \"audit\".\"events\"",
        db.prepared.some(function (s) {
          return /SELECT "_id", "action" FROM "audit"\."events"/.test(s);
        }));

  db.prepared.length = 0;
  new dbQuery.Query(db, "audit.events").where({ recordedAt: 1 }).count();
  check("count() emits COUNT(*) FROM \"audit\".\"events\"",
        db.prepared.some(function (s) {
          // b.sql quotes the aggregate alias by construction: AS "n".
          return /SELECT COUNT\(\*\) AS "n" FROM "audit"\."events"/.test(s);
        }));
}

async function testSchemaQualifiedInsertUpdateDelete() {
  var db = _fakeDb();
  new dbQuery.Query(db, "audit.events").insertOne({ action: "login" });
  check("insertOne emits INSERT INTO \"audit\".\"events\"",
        db.prepared.some(function (s) {
          return /INSERT INTO "audit"\."events"/.test(s);
        }));

  db.prepared.length = 0;
  new dbQuery.Query(db, "audit.events")
    .where({ _id: "abc" })
    .updateOne({ action: "logout" });
  check("updateOne emits UPDATE \"audit\".\"events\"",
        db.prepared.some(function (s) {
          return /UPDATE "audit"\."events" SET/.test(s);
        }));
  check("updateOne sub-select uses qualified name",
        db.prepared.some(function (s) {
          // b.sql quotes the rowid pseudo-column by construction; the
          // single-row idiom is "rowid" = (SELECT "rowid" FROM ...).
          return /SELECT "rowid" FROM "audit"\."events"/.test(s);
        }));

  db.prepared.length = 0;
  new dbQuery.Query(db, "audit.events")
    .where({ _id: "abc" })
    .deleteOne();
  check("deleteOne emits DELETE FROM \"audit\".\"events\"",
        db.prepared.some(function (s) {
          return /DELETE FROM "audit"\."events"/.test(s);
        }));
}

async function testBareTableStillUnqualified() {
  // Backward compat — db.from("users") should NOT emit "main"."users"
  // or any schema prefix.
  var db = _fakeDb();
  new dbQuery.Query(db, "users").where({ status: "x" }).first();
  check("bare table name emits \"users\" without schema prefix",
        db.prepared.some(function (s) {
          return /FROM "users"/.test(s) && !/"main"/.test(s);
        }));
}

async function run() {
  await testRejectionPath();
  await testSchemaQualifiedSelectShape();
  await testSchemaQualifiedInsertUpdateDelete();
  await testBareTableStillUnqualified();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[db-query-cross-schema] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
