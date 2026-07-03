// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.db.from(table) chainable Query — v0.8.58 additions:
 *   - .increment(column, delta)
 *   - .whereGroup(qb => ...)
 *   - .orWhere(...)
 *   - .search(fields, term, opts?)
 *   - .paginate(opts)
 */

var helpers = require("../helpers");
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

var SCHEMA = [{
  name: "orders",
  columns: {
    _id:       "TEXT PRIMARY KEY",
    userId:    "TEXT",
    seq:       "INTEGER NOT NULL DEFAULT 0",
    received:  "INTEGER",
    status:    "TEXT",
  },
  indexes: ["userId", "status"],
}];

async function testIncrement() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "qx-"));
  try {
    await setupTestDb(tmpDir, SCHEMA);
    b.db.from("orders").insertOne({ _id: "o1", userId: "u1", seq: 0, status: "active" });
    var n = b.db.from("orders").where({ _id: "o1" }).increment("seq", 5);
    check("increment returns rows-changed",          n === 1);
    check("increment(+5) lifted seq from 0 to 5",    b.db.from("orders").where({ _id: "o1" }).first().seq === 5);
    b.db.from("orders").where({ _id: "o1" }).increment("seq", -2);
    check("increment(-2) brought seq down to 3",     b.db.from("orders").where({ _id: "o1" }).first().seq === 3);
    b.db.from("orders").where({ _id: "o1" }).increment("seq");
    check("increment() default delta is 1",          b.db.from("orders").where({ _id: "o1" }).first().seq === 4);
    // NULL counter starts at 0 via COALESCE.
    b.db.from("orders").insertOne({ _id: "o2", userId: "u2", received: null, status: "active" });
    b.db.from("orders").where({ _id: "o2" }).increment("received", 1);
    check("increment on NULL counter via COALESCE",  b.db.from("orders").where({ _id: "o2" }).first().received === 1);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testIncrementRefusesUnconditional() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "qx-"));
  try {
    await setupTestDb(tmpDir, SCHEMA);
    var threw = false;
    try { b.db.from("orders").increment("seq", 1); }
    catch (e) { threw = /unconditional/.test(e.message); }
    check("increment without where(...) refused",    threw);
    threw = false;
    try { b.db.from("orders").where({ _id: "o" }).increment("seq", 1.5); }
    catch (e) { threw = /finite integer/.test(e.message); }
    check("increment delta must be integer",         threw);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testWhereGroup() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "qx-"));
  try {
    await setupTestDb(tmpDir, SCHEMA);
    b.db.from("orders").insertOne({ _id: "a", userId: "u", status: "active",  seq: 1 });
    b.db.from("orders").insertOne({ _id: "b", userId: "u", status: "pending", seq: 2 });
    b.db.from("orders").insertOne({ _id: "c", userId: "u", status: "closed",  seq: 3 });
    var rows = b.db.from("orders").where({ userId: "u" }).whereGroup(function (qb) {
      qb.eq("status", "active").orEq("status", "pending");
    }).all();
    check("whereGroup AND-ed with outer where",      rows.length === 2);
    var sorted = rows.map(function (r) { return r._id; }).sort();
    check("whereGroup matched a and b only",         sorted[0] === "a" && sorted[1] === "b");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testOrWhere() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "qx-"));
  try {
    await setupTestDb(tmpDir, SCHEMA);
    b.db.from("orders").insertOne({ _id: "a", status: "active" });
    b.db.from("orders").insertOne({ _id: "b", status: "pending" });
    b.db.from("orders").insertOne({ _id: "c", status: "closed" });
    var rows = b.db.from("orders").where({ status: "active" }).orWhere({ status: "pending" }).all();
    check("orWhere object form",                     rows.length === 2);
    var threw = false;
    try { b.db.from("orders").orWhere({ status: "active" }); }
    catch (e) { threw = /no prior where/.test(e.message); }
    check("orWhere refuses without prior where",     threw);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testSearch() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "qx-"));
  try {
    await setupTestDb(tmpDir, SCHEMA);
    b.db.from("orders").insertOne({ _id: "a", userId: "alice" });
    b.db.from("orders").insertOne({ _id: "b", userId: "bob" });
    b.db.from("orders").insertOne({ _id: "c", userId: "alica" });
    check("search substring 'ali' matches alice + alica",
          b.db.from("orders").search(["userId"], "ali").all().length === 2);
    check("search prefix 'bo' matches bob",
          b.db.from("orders").search(["userId"], "bo", { match: "prefix" }).all().length === 1);
    check("search exact 'alice' matches one",
          b.db.from("orders").search(["userId"], "alice", { match: "exact" }).all().length === 1);
    check("search empty term is a no-op",
          b.db.from("orders").search(["userId"], "").all().length === 3);
    // SQL wildcards in user input MUST be escaped — `%` shouldn't broaden.
    check("search escapes user-supplied %",
          b.db.from("orders").search(["userId"], "%").all().length === 0);
    check("search escapes user-supplied _",
          b.db.from("orders").search(["userId"], "_").all().length === 0);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testPaginate() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "qx-"));
  try {
    await setupTestDb(tmpDir, SCHEMA);
    for (var i = 0; i < 12; i += 1) {
      b.db.from("orders").insertOne({ _id: "o" + i, userId: "u", seq: i, status: "active" });
    }
    var page1 = b.db.from("orders").where({ userId: "u" }).paginate({ limit: 5, offset: 0, orderBy: "seq" });
    check("paginate returns 5 items",                page1.items.length === 5);
    check("paginate.total reflects filtered count",  page1.total === 12);
    check("paginate.totalPages = ceil(12/5)",        page1.totalPages === 3);
    check("paginate.page = 1 at offset 0",           page1.page === 1);
    var page2 = b.db.from("orders").where({ userId: "u" }).paginate({ limit: 5, offset: 5, orderBy: "seq" });
    check("paginate page 2 has 5 items",             page2.items.length === 5);
    check("paginate page 2 .page === 2",             page2.page === 2);
    var page3 = b.db.from("orders").where({ userId: "u" }).paginate({ limit: 5, offset: 10, orderBy: "seq" });
    check("paginate page 3 has 2 items (tail)",      page3.items.length === 2);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testPaginateOptsRefusal() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "qx-"));
  try {
    await setupTestDb(tmpDir, SCHEMA);
    var threw = false;
    try { b.db.from("orders").paginate({ limit: 0 }); }
    catch (e) { threw = /positive integer/.test(e.message); }
    check("paginate refuses limit=0",                threw);
    threw = false;
    try { b.db.from("orders").paginate({ limit: 5, offset: -1 }); }
    catch (e) { threw = /non-negative integer/.test(e.message); }
    check("paginate refuses negative offset",        threw);
    threw = false;
    try { b.db.from("orders").paginate({ limit: 1001 }); }
    catch (e) { threw = /≤ 1000/.test(e.message); }
    check("paginate refuses limit > 1000",           threw);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  await testIncrement();
  await testIncrementRefusesUnconditional();
  await testWhereGroup();
  await testOrWhere();
  await testSearch();
  await testPaginate();
  await testPaginateOptsRefusal();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
