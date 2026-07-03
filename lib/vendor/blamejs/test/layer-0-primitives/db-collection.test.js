// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.db.collection(name) — Mongo-style facade over the chainable
 * Query builder. Maps `{ insert, find, findOne, update, remove,
 * count, paginate }` calls onto `b.db.from(name).*`.
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
  name: "users",
  columns: {
    _id:    "TEXT PRIMARY KEY",
    email:  "TEXT",
    failed: "INTEGER NOT NULL DEFAULT 0",
    age:    "INTEGER",
    name:   "TEXT",
  },
  indexes: ["email"],
}];

async function testInsertFind() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-"));
  try {
    await setupTestDb(tmpDir, SCHEMA);
    var users = b.db.collection("users");
    users.insert({ _id: "u1", email: "alice@x.com", age: 30 });
    users.insert({ _id: "u2", email: "bob@x.com", age: 40 });
    check("findOne by email returns u1",   users.findOne({ email: "alice@x.com" })._id === "u1");
    check("findOne miss returns null",     users.findOne({ email: "nobody@x.com" }) === null);
    check("count returns total",           users.count({}) === 2);
    check("count with filter",             users.count({ email: "alice@x.com" }) === 1);
    check("find returns array",            Array.isArray(users.find({})));
    check("find $gt operator",             users.find({ age: { $gt: 35 } }).length === 1);
    check("find $in operator",             users.find({ _id: { $in: ["u1", "u2"] } }).length === 2);
    check("find $ne operator",             users.find({ _id: { $ne: "u1" } }).length === 1);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testUpdateOperators() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-"));
  try {
    await setupTestDb(tmpDir, SCHEMA);
    var users = b.db.collection("users");
    users.insert({ _id: "u1", email: "a@x.com", failed: 0 });
    users.update({ _id: "u1" }, { $inc: { failed: 1 } });
    users.update({ _id: "u1" }, { $inc: { failed: 1 } });
    check("$inc bumped failed to 2",       users.findOne({ _id: "u1" }).failed === 2);
    users.update({ _id: "u1" }, { $set: { failed: 0 } });
    check("$set reset failed to 0",        users.findOne({ _id: "u1" }).failed === 0);
    users.update({ _id: "u1" }, { failed: 5 });
    check("plain object form treated as $set", users.findOne({ _id: "u1" }).failed === 5);
    users.update({ _id: "u1" }, { $unset: { age: 1 } });
    check("$unset sets to NULL",           users.findOne({ _id: "u1" }).age === null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testRemoveAndPaginate() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-"));
  try {
    await setupTestDb(tmpDir, SCHEMA);
    var users = b.db.collection("users");
    for (var i = 0; i < 7; i += 1) {
      users.insert({ _id: "u" + i, email: "u" + i + "@x.com", age: 20 + i });
    }
    var p = users.paginate({}, { limit: 3, offset: 0, orderBy: "_id" });
    check("paginate returns 3 items",      p.items.length === 3);
    check("paginate.total = 7",            p.total === 7);
    check("paginate.totalPages = 3",       p.totalPages === 3);
    var removed = users.remove({ _id: "u0" });
    check("remove returns 1 on hit",       removed === 1);
    check("count after remove",            users.count({}) === 6);
    var removedMany = users.remove({ age: { $gte: 23 } }, { many: true });
    check("remove many returns count",     removedMany >= 1);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testQueryShapeRefusals() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-"));
  try {
    await setupTestDb(tmpDir, SCHEMA);
    var users = b.db.collection("users");
    var threw = false;
    try { users.findOne(null); } catch (e) { threw = /plain object/.test(e.message); }
    check("findOne(null) refused",                  threw);
    threw = false;
    try { users.find({ x: { $bogus: 1 } }); }
    catch (e) { threw = /unsupported query operator/.test(e.message); }
    check("unknown query operator refused",         threw);
    threw = false;
    try { users.update({ _id: "x" }, { $bogus: 1 }); }
    catch (e) { threw = /unsupported update operator/.test(e.message); }
    check("unknown update operator refused",        threw);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testNameRefusal() {
  var threw = false;
  try { b.db.collection(""); } catch (e) { threw = e instanceof TypeError; }
  check("collection('') refused at config-time",   threw);
  threw = false;
  try { b.db.collection(null); } catch (e) { threw = e instanceof TypeError; }
  check("collection(null) refused",                threw);
}

async function run() {
  await testInsertFind();
  await testUpdateOperators();
  await testRemoveAndPaginate();
  await testQueryShapeRefusals();
  await testNameRefusal();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
