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

async function testQueryOperatorsExtra() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-"));
  try {
    await setupTestDb(tmpDir, SCHEMA);
    var users = b.db.collection("users");
    users.insert({ _id: "u1", email: "alice@x.com", age: 30, name: "Alice" });
    users.insert({ _id: "u2", email: "bob@x.com",   age: 40, name: "Bob" });
    check("find $eq operator",        users.find({ age: { $eq: 30 } }).length === 1);
    check("find $lt operator",        users.find({ age: { $lt: 35 } }).length === 1);
    check("find $lte operator",       users.find({ age: { $lte: 40 } }).length === 2);
    check("find $like exact match",   users.find({ name: { $like: "Alice" } }).length === 1);
    // $like is a SQL LIKE: the caller's % / _ are wildcards, matched
    // verbatim (not escaped to literals). Prefix / suffix / infix /
    // single-char patterns must all resolve against the stored rows.
    check("find $like % prefix wildcard",   users.find({ name: { $like: "Al%" } }).length === 1);
    check("find $like % suffix wildcard",   users.find({ name: { $like: "%ob" } }).length === 1);
    check("find $like % infix wildcard",    users.find({ name: { $like: "%o%" } }).length === 1);
    check("find $like _ single-char class", users.find({ name: { $like: "A_ice" } }).length === 1);
    check("find $like % matches all rows",  users.find({ name: { $like: "%" } }).length === 2);

    var threw = false;
    try { users.find({ name: { $like: 123 } }); }
    catch (e) { threw = /\$like requires a string/.test(e.message); }
    check("$like non-string refused",  threw);

    threw = false;
    try { users.find({ _id: { $in: "u1" } }); }
    catch (e) { threw = /\$in requires an array/.test(e.message); }
    check("$in non-array refused",     threw);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testInsertMany() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-"));
  try {
    await setupTestDb(tmpDir, SCHEMA);
    var users = b.db.collection("users");
    var out = users.insertMany([
      { _id: "m1", email: "m1@x.com", age: 11 },
      { _id: "m2", email: "m2@x.com", age: 22 },
    ]);
    check("insertMany returns inserted rows", Array.isArray(out) && out.length === 2);
    check("insertMany persisted both",        users.count({}) === 2);

    var threw = false;
    try { users.insertMany("not-an-array"); }
    catch (e) { threw = /docs must be an array/.test(e.message); }
    check("insertMany non-array refused",     threw);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testUpdateVariants() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-"));
  try {
    await setupTestDb(tmpDir, SCHEMA);
    var users = b.db.collection("users");
    users.insert({ _id: "u1", email: "a@x.com", age: 20, name: "A", failed: 0 });
    users.insert({ _id: "u2", email: "b@x.com", age: 30, name: "B", failed: 0 });

    // updateMany method drives the real-column many-row UPDATE path.
    var n = users.updateMany({ age: { $gte: 0 } }, { $set: { name: "Z" } });
    check("updateMany updates all matching rows",   n === 2);
    check("updateMany applied to u1",               users.findOne({ _id: "u1" }).name === "Z");

    // update(..., { many: true }) reaches the same path via the opts flag.
    var n2 = users.update({ age: { $gte: 0 } }, { $set: { name: "Y" } }, { many: true });
    check("update many:true updates matching rows", n2 === 2);

    // A single update matching zero rows reports 0 changed.
    check("update miss returns 0",                  users.update({ _id: "ghost" }, { $set: { name: "N" } }) === 0);

    var threw = false;
    try { users.update({ _id: "u1" }, { $inc: { failed: 1.5 } }); }
    catch (e) { threw = /must be an integer/.test(e.message); }
    check("$inc non-integer refused",               threw);

    threw = false;
    try { users.update({ _id: "u1" }, { $set: 5 }); }
    catch (e) { threw = /\$set value must be an object/.test(e.message); }
    check("$set non-object refused",                threw);

    threw = false;
    try { users.update({ _id: "u1" }, { $inc: 5 }); }
    catch (e) { threw = /\$inc value must be an object/.test(e.message); }
    check("$inc non-object refused",                threw);

    threw = false;
    try { users.update({ _id: "u1" }, { $unset: 5 }); }
    catch (e) { threw = /\$unset value must be an object/.test(e.message); }
    check("$unset non-object refused",              threw);

    threw = false;
    try { users.update({ _id: "u1" }, [1, 2]); }
    catch (e) { threw = /update must be a plain object/.test(e.message); }
    check("array update refused",                   threw);

    // An omitted filter is refused as an unconditional write.
    threw = false;
    try { users.update(null, { $set: { name: "X" } }); }
    catch (e) { threw = /unconditional update/.test(e.message); }
    check("update with no filter refused",          threw);

    threw = false;
    try { users.update(null, { $inc: { failed: 1 } }); }
    catch (e) { threw = /unconditional increment/.test(e.message); }
    check("increment with no filter refused",       threw);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testReadDefaults() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-"));
  try {
    await setupTestDb(tmpDir, SCHEMA);
    var users = b.db.collection("users");
    users.insert({ _id: "u1", email: "a@x.com", age: 20 });
    users.insert({ _id: "u2", email: "b@x.com", age: 40 });

    check("find() with no filter returns all",   users.find().length === 2);
    check("count() with no filter returns all",  users.count() === 2);

    var desc = users.find({}, { orderBy: "age", orderDir: "desc", limit: 1, offset: 0 });
    check("find with orderBy/limit/offset opts", desc.length === 1 && desc[0]._id === "u2");
    var asc = users.find({}, { orderBy: "age" });
    check("find with orderBy default direction", asc.length === 2 && asc[0]._id === "u1");

    var pg = users.paginate({});
    check("paginate with no opts defaults",      pg.total === 2 && pg.items.length === 2);
    var pg2 = users.paginate(null, { limit: 1 });
    check("paginate with omitted filter",        pg2.items.length === 1 && pg2.total === 2);

    // An omitted filter is refused as an unconditional delete.
    var threw = false;
    try { users.remove(); }
    catch (e) { threw = /unconditional delete/.test(e.message); }
    check("remove with no filter refused",       threw);

    check("remove miss returns 0",               users.remove({ _id: "ghost" }) === 0);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testSealedFieldsRegistry() {
  // First declaration on a fresh table registers a new derived-hash
  // schema; a second declaration on the same table extends it in place.
  var first = b.db.collection("col_reg_tbl", { sealedFields: { email: "emailHash" } });
  check("sealedFields first registration builds collection", first && first.name === "col_reg_tbl");
  var second = b.db.collection("col_reg_tbl", { sealedFields: { phone: "phoneHash", email: "emailHash" } });
  check("sealedFields re-declaration extends registration",  second && second.name === "col_reg_tbl");
}

async function testGhostTableIntrospection() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-"));
  try {
    await setupTestDb(tmpDir, SCHEMA);
    var ghost = b.db.collection("ghost_table", { overflow: "data" });
    var threw = false;
    try { ghost.insert({ _id: "g1", extra: "x" }); }
    catch (e) { threw = /table has no columns OR does not exist/.test(e.message); }
    check("introspection on missing table refused", threw);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// $like on a SEALED field: an exact pattern must still match via the derived-hash
// rewrite (as equality did), and a wildcard pattern — impossible against a hash —
// must be refused rather than silently matching the ciphertext (returning nothing).
async function testSealedFieldLikeQueries() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-sealed-"));
  try {
    await setupTestDb(tmpDir, [{
      name: "sealed_users",
      columns: { _id: "TEXT PRIMARY KEY", email: "TEXT", emailHash: "TEXT" },
      indexes: ["emailHash"],
    }]);
    var users = b.db.collection("sealed_users", { sealedFields: { email: "emailHash" } });
    users.insert({ _id: "u1", email: "alice@example.com" });
    check("exact $like on a sealed field still matches via the derived-hash rewrite",
          users.find({ email: { $like: "alice@example.com" } }).length === 1);
    var threw = false;
    try { users.find({ email: { $like: "alice%" } }); }
    catch (e) { threw = /\$like with a wildcard is not supported on the sealed/.test(e.message); }
    check("wildcard $like on a sealed field is refused (a hash can't be wildcard-matched)", threw);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// A field sealed through ANY registration (here: a separate collection instance
// with the opt) must be detected by a later plain collection() with no
// sealedFields opt — $like consults the global registry, not just local opts.
async function testSealedFieldLikeFromGlobalRegistry() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-sealed2-"));
  try {
    await setupTestDb(tmpDir, [{
      name: "sealed_g",
      columns: { _id: "TEXT PRIMARY KEY", email: "TEXT", emailHash: "TEXT" },
      indexes: ["emailHash"],
    }]);
    b.db.collection("sealed_g", { sealedFields: { email: "emailHash" } }).insert({ _id: "u1", email: "bob@x.com" });
    var plain = b.db.collection("sealed_g");   // NO sealedFields opt
    check("exact $like on a globally-sealed field (no local opt) matches via the rewrite",
          plain.find({ email: { $like: "bob@x.com" } }).length === 1);
    var threw = false;
    try { plain.find({ email: { $like: "bob%" } }); }
    catch (e) { threw = /\$like with a wildcard is not supported on the sealed/.test(e.message); }
    check("wildcard $like on a globally-sealed field (no local opt) is refused", threw);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  await testInsertFind();
  await testUpdateOperators();
  await testRemoveAndPaginate();
  await testQueryShapeRefusals();
  await testNameRefusal();
  await testQueryOperatorsExtra();
  await testInsertMany();
  await testUpdateVariants();
  await testReadDefaults();
  await testSealedFieldsRegistry();
  await testGhostTableIntrospection();
  await testSealedFieldLikeQueries();
  await testSealedFieldLikeFromGlobalRegistry();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
