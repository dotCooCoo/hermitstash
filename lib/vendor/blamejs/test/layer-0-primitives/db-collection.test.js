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

// A sealedFields map value that isn't a non-empty hash-column name is
// refused at construction time (a hash column must be a string identifier).
async function testSealedFieldValueRefusal() {
  var threw = false;
  try { b.db.collection("z_seal1", { sealedFields: { email: 123 } }); }
  catch (e) { threw = /must be a hash-column name/.test(e.message) && e instanceof TypeError; }
  check("sealedFields non-string hash column refused", threw);

  threw = false;
  try { b.db.collection("z_seal2", { sealedFields: { email: "" } }); }
  catch (e) { threw = /must be a hash-column name/.test(e.message) && e instanceof TypeError; }
  check("sealedFields empty-string hash column refused", threw);
}

// Schemaless-document mode: overflow + jsonColumns. Unknown insert fields
// fold into the JSON-text overflow column; listed jsonColumns are
// stringified on write and parsed on read; find/query on an unknown field
// rewrites to JSON_EXTRACT against the overflow column.
var OVERFLOW_SCHEMA = [{
  name: "docs",
  columns: {
    _id:   "TEXT PRIMARY KEY",
    email: "TEXT",
    roles: "TEXT",
    count: "INTEGER NOT NULL DEFAULT 0",
    data:  "TEXT",
  },
  indexes: ["email"],
}];

async function testOverflowInsertAndDecode() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-of-"));
  try {
    await setupTestDb(tmpDir, OVERFLOW_SCHEMA);
    var docs = b.db.collection("docs", { overflow: "data", jsonColumns: ["roles"] });
    // roles → JSON-stringified real column; dept + joined → folded into data.
    docs.insert({ _id: "d1", email: "alice@x.com", roles: ["admin", "user"], dept: "eng", joined: "2026-01-01" });

    var row = docs.findOne({ _id: "d1" });
    check("overflow decode merges folded fields back onto the row",
          row.dept === "eng" && row.joined === "2026-01-01");
    check("jsonColumns round-trip as a parsed array on read",
          Array.isArray(row.roles) && row.roles.length === 2 && row.roles[0] === "admin");
    check("overflow column itself is not surfaced on the decoded row", row.data === undefined);
    check("real columns still present after overflow decode",
          row._id === "d1" && row.email === "alice@x.com" && row.count === 0);

    // Overflow column supplied directly as an object, no extra keys:
    // stringified via the else-if branch of _prepareWriteDoc.
    docs.insert({ _id: "d2", email: "bob@x.com", data: { pre: 1 } });
    var d2 = docs.findOne({ _id: "d2" });
    check("overflow supplied as an object (no extras) is stringified then decoded", d2.pre === 1 && d2.data === undefined);

    // Extras AND an existing overflow object merge together.
    docs.insert({ _id: "d3", email: "cara@x.com", data: { pre: 9 }, extraKey: "v" });
    var d3 = docs.findOne({ _id: "d3" });
    check("existing overflow object merges with folded extras", d3.pre === 9 && d3.extraKey === "v");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// An overflow column declared BLOB comes back from storage as a Uint8Array,
// which is typeof "object" — it must be decoded as JSON, not spread byte-wise.
var BLOB_OVERFLOW_SCHEMA = [{
  name: "docs",
  columns: { _id: "TEXT PRIMARY KEY", email: "TEXT", data: "BLOB" },
}];

async function testOverflowBlobValueNotCorrupted() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-blob-"));
  try {
    await setupTestDb(tmpDir, BLOB_OVERFLOW_SCHEMA);
    // Seed the overflow column with JSON stored AS a BLOB (read back as a
    // Uint8Array), mirroring an operator who declares the column BLOB.
    b.db.from("docs").insertOne({ _id: "x", email: "a@x.com", data: Buffer.from(JSON.stringify({ a: 1, b: "keep" })) });
    var docs = b.db.collection("docs", { overflow: "data" });

    // READ: the BLOB payload decodes to its JSON keys, not numeric byte indices.
    var read = docs.findOne({ _id: "x" });
    check("overflow BLOB decodes to its JSON keys on read (not byte indices)",
          read.a === 1 && read.b === "keep" && read["0"] === undefined && read.data === undefined);

    // UPDATE (read-modify-write over a BLOB): the original payload survives and
    // the new key is added — no byte-index corruption of the overflow column.
    docs.update({ _id: "x" }, { $set: { newk: "v" } });
    var after = docs.findOne({ _id: "x" });
    check("overflow BLOB update preserves the original payload and adds the key",
          after.a === 1 && after.b === "keep" && after.newk === "v" && after["0"] === undefined);

    // WRITE: a Buffer overflow value supplied on insert (with extras) merges as
    // JSON, not as spread bytes.
    docs.insert({ _id: "y", email: "c@x.com", data: Buffer.from(JSON.stringify({ p: 9 })), extraKey: "z" });
    var y = docs.findOne({ _id: "y" });
    check("overflow Buffer value on insert merges with extras (no byte-index keys)",
          y.p === 9 && y.extraKey === "z" && y["0"] === undefined);

    // A Buffer overflow value supplied on insert with NO extras is decoded
    // and re-stored as JSON text (its keys surface, not spread bytes).
    docs.insert({ _id: "w", email: "e@x.com", data: Buffer.from(JSON.stringify({ q: 5 })) });
    var w = docs.findOne({ _id: "w" });
    check("overflow Buffer value (no extras) decoded+stored as JSON on insert",
          w.q === 5 && w["0"] === undefined && w.data === undefined);

    // A BLOB holding non-JSON bytes is left on the row as-is (no keys folded,
    // no byte-index corruption, no throw) — matching the non-JSON string
    // branch, which also surfaces an un-decodable overflow value verbatim.
    b.db.from("docs").insertOne({ _id: "z", email: "d@x.com", data: Buffer.from([0xff, 0x00, 0x01]) });
    var z = docs.findOne({ _id: "z" });
    check("overflow BLOB with non-JSON bytes is left verbatim (no byte-index keys folded on)",
          z._id === "z" && z.email === "d@x.com" && z["0"] === undefined && ArrayBuffer.isView(z.data));

    // A BLOB holding valid JSON that is NOT an object (an array) is not a valid
    // overflow payload — left verbatim, its elements not folded as keys.
    b.db.from("docs").insertOne({ _id: "arr", email: "e2@x.com", data: Buffer.from(JSON.stringify([1, 2, 3])) });
    var arr = docs.findOne({ _id: "arr" });
    check("overflow BLOB holding a JSON array is left verbatim (elements not folded on)",
          arr._id === "arr" && arr["0"] === undefined && ArrayBuffer.isView(arr.data));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testOverflowQueryOperators() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-ofq-"));
  try {
    await setupTestDb(tmpDir, OVERFLOW_SCHEMA);
    var docs = b.db.collection("docs", { overflow: "data" });
    docs.insert({ _id: "d1", email: "a@x.com", dept: "eng" });
    docs.insert({ _id: "d2", email: "b@x.com", dept: "sales" });

    check("overflow equality (bare value) rewrites to JSON_EXTRACT",
          docs.find({ dept: "eng" }).length === 1 && docs.find({ dept: "eng" })[0]._id === "d1");
    check("overflow $eq matches the folded field", docs.find({ dept: { $eq: "eng" } }).length === 1);
    check("overflow $ne matches the complement", docs.find({ dept: { $ne: "eng" } }).length === 1);
    check("overflow $in matches listed values", docs.find({ dept: { $in: ["eng", "sales"] } }).length === 2);
    check("overflow count filters via JSON_EXTRACT", docs.count({ dept: "eng" }) === 1);

    var threw = false;
    try { docs.find({ dept: { $in: [] } }); }
    catch (e) { threw = /\$in on overflow field 'dept' requires a non-empty array/.test(e.message) && e instanceof TypeError; }
    check("overflow $in with an empty array refused", threw);

    threw = false;
    try { docs.find({ dept: { $gt: "a" } }); }
    catch (e) { threw = /overflow field 'dept' supports \$eq \/ \$ne \/ \$in only/.test(e.message) && e instanceof TypeError; }
    check("overflow range operator refused (needs a real column)", threw);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testOverflowUpdates() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-ofu-"));
  try {
    await setupTestDb(tmpDir, OVERFLOW_SCHEMA);
    var docs = b.db.collection("docs", { overflow: "data" });
    docs.insert({ _id: "d1", email: "a@x.com", dept: "eng", joined: "2026" });

    // $set on an overflow field: read-modify-write on the JSON column.
    check("overflow $set reports one row changed", docs.update({ _id: "d1" }, { $set: { dept: "ops" } }) === 1);
    check("overflow $set persisted the new folded value", docs.findOne({ _id: "d1" }).dept === "ops");

    // $unset on an overflow field: the key is removed from the JSON, other
    // folded keys survive.
    check("overflow $unset reports one row changed", docs.update({ _id: "d1" }, { $unset: { joined: 1 } }) === 1);
    var afterUnset = docs.findOne({ _id: "d1" });
    check("overflow $unset removed only the named key", afterUnset.joined === undefined && afterUnset.dept === "ops");

    // A single update touching a real column AND an overflow field: the RMW
    // write carries the real change alongside the merged JSON.
    check("mixed real+overflow $set reports one row changed",
          docs.update({ _id: "d1" }, { $set: { email: "new@x.com", dept: "x2" } }) === 1);
    var mixed = docs.findOne({ _id: "d1" });
    check("mixed real+overflow $set persisted both", mixed.email === "new@x.com" && mixed.dept === "x2");

    // $inc against an overflow field is refused — JSON text can't atomically
    // increment.
    var threw = false;
    try { docs.update({ _id: "d1" }, { $inc: { dept: 1 } }); }
    catch (e) { threw = /\$inc on overflow field 'dept' is not supported/.test(e.message) && e instanceof TypeError; }
    check("overflow $inc refused", threw);

    // updateMany drives the many-row overflow RMW path (no limit).
    docs.insert({ _id: "g1", email: "g1@x.com", tag: "grp" });
    docs.insert({ _id: "g2", email: "g2@x.com", tag: "grp" });
    check("overflow updateMany changes every matching row",
          docs.updateMany({ tag: "grp" }, { $set: { tag: "grp2" } }) === 2);
    check("overflow updateMany persisted the new value on both rows",
          docs.findOne({ _id: "g1" }).tag === "grp2" && docs.findOne({ _id: "g2" }).tag === "grp2");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testExplicitColumnsAndIntrospectionErrors() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-cols-"));
  try {
    await setupTestDb(tmpDir, OVERFLOW_SCHEMA);

    // An explicit column whitelist bypasses PRAGMA introspection; an unknown
    // field still folds into overflow.
    var docsX = b.db.collection("docs", {
      columns:  ["_id", "email", "roles", "count", "data"],
      overflow: "data",
    });
    docsX.insert({ _id: "dx", email: "x@x.com", extra: "folded" });
    check("explicit columns whitelist folds unknown field into overflow",
          docsX.findOne({ _id: "dx" }).extra === "folded");

    // overflow column not present on the table → introspection-time refusal.
    var badOverflow = b.db.collection("docs", { overflow: "nope" });
    var threw = false;
    try { badOverflow.insert({ _id: "z1", email: "z@x.com" }); }
    catch (e) { threw = /overflow column 'nope' not present on table/.test(e.message); }
    check("overflow column missing from schema refused", threw);

    // jsonColumns referencing an unknown column → introspection-time refusal.
    var badJson = b.db.collection("docs", { jsonColumns: ["ghostcol"] });
    threw = false;
    try { badJson.insert({ _id: "z2", email: "z@x.com" }); }
    catch (e) { threw = /jsonColumns reference unknown columns/.test(e.message) && /ghostcol/.test(e.message); }
    check("jsonColumns referencing an unknown column refused", threw);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// The overflow read-modify-write requires an `_id` on each matched row to
// address the write-back. A table with an overflow column but no `_id` (seeded
// out-of-band, since collection.insert always assigns `_id`) trips the guard.
async function testOverflowUpdateWithoutIdRefused() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-noid-"));
  try {
    await setupTestDb(tmpDir, [{ name: "noid", columns: { k: "TEXT", data: "TEXT" } }]);
    b.db.prepare('INSERT INTO noid (k, data) VALUES (?, ?)').run("a", '{"foo":"bar"}');
    var noid = b.db.collection("noid", { overflow: "data" });
    var threw = false;
    try { noid.update({ k: "a" }, { $set: { baz: "q" } }); }
    catch (e) { threw = /overflow-field write requires an _id column/.test(e.message); }
    check("overflow update on a row without _id refused", threw);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// Malformed JSON in a jsonColumn or overflow column (corruption / out-of-band
// writes) is handled best-effort, never thrown: unparseable jsonColumns stay
// raw strings on read; unparseable overflow is left intact on read and treated
// as empty on a read-modify-write update.
async function testOverflowInvalidJsonPaths() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-badjson-"));
  try {
    await setupTestDb(tmpDir, [{
      name: "docs",
      columns: { _id: "TEXT PRIMARY KEY", roles: "TEXT", data: "TEXT" },
    }]);

    // A jsonColumn whose stored value isn't valid JSON is left as the raw
    // string on read (the parse failure is swallowed).
    var jc = b.db.collection("docs", { jsonColumns: ["roles"] });
    jc.insert({ _id: "j1", roles: "not-json{" });   // already a string → stored verbatim
    check("invalid-JSON jsonColumn left as the raw string on read",
          jc.findOne({ _id: "j1" }).roles === "not-json{");

    var of = b.db.collection("docs", { overflow: "data" });

    // An overflow column holding invalid JSON (out-of-band write) is left
    // untouched on read — not merged onto the row, not deleted.
    b.db.prepare('INSERT INTO docs (_id, data) VALUES (?, ?)').run("bad", "not-json{");
    check("invalid-JSON overflow column left intact on read (no merge)",
          of.findOne({ _id: "bad" }).data === "not-json{");

    // An overflow $set whose row has invalid-JSON overflow treats the existing
    // as empty and writes the new merged JSON.
    b.db.prepare('INSERT INTO docs (_id, data) VALUES (?, ?)').run("bad2", "not-json{");
    check("overflow $set over an invalid-JSON row reports one change",
          of.update({ _id: "bad2" }, { $set: { newk: "v" } }) === 1);
    check("overflow $set over an invalid-JSON row sets the new folded key",
          of.findOne({ _id: "bad2" }).newk === "v");

    // An overflow column that parses to a falsy value ("null") is coerced to
    // an empty object before the merge.
    b.db.prepare('INSERT INTO docs (_id, data) VALUES (?, ?)').run("nul", "null");
    check("overflow $set over a null-parsing row reports one change",
          of.update({ _id: "nul" }, { $set: { nk: "v2" } }) === 1);
    check("overflow $set over a null-parsing row sets the new folded key",
          of.findOne({ _id: "nul" }).nk === "v2");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// An unconditional update (null / empty filter) of an OVERFLOW field must be
// REFUSED exactly like a real-column one. The overflow read-modify-write reads
// matched rows then writes each by _id (a WHERE'd write), so it would slip past
// db-query's unconditional-write guard and silently mutate every row.
async function testOverflowUnconditionalUpdateRefused() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-ovuncond-"));
  try {
    await setupTestDb(tmpDir, [{
      name: "ov_uncond", columns: { _id: "TEXT PRIMARY KEY", name: "TEXT", data: "TEXT" },
    }]);
    var c = b.db.collection("ov_uncond", { overflow: "data" });
    await c.insert({ _id: "a", name: "alice", dept: "eng" });   // dept → overflow (data)
    await c.insert({ _id: "b", name: "bob",   dept: "sales" });
    var ovErr = null;
    try { c.update(null, { $set: { dept: "HACKED" } }); } catch (e) { ovErr = e; }
    check("overflow unconditional update is refused (call where() first)",
          ovErr && /refusing unconditional update/.test(ovErr.message));
    check("the refused overflow update mutated no row",
          c.findOne({ _id: "a" }).dept === "eng" &&
          c.findOne({ _id: "b" }).dept === "sales");
    // Parity: a real-column unconditional update is refused the same way.
    var realErr = null;
    try { c.update(null, { $set: { name: "HACKED" } }); } catch (e) { realErr = e; }
    check("real-column unconditional update is refused the same way (parity)",
          realErr && /refusing unconditional update/.test(realErr.message));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// When PRAGMA introspection itself fails (db closed / not yet init-resolved),
// _columns() wraps the underlying engine error into an actionable column-list
// message rather than leaking the raw failure. insertMany runs _prepareWriteDoc
// (→ _columns) BEFORE db().from(), so the introspection catch — not from()'s
// own init guard — is what fires here.
async function testIntrospectionErrorWrapped() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-introq-"));
  try {
    await setupTestDb(tmpDir, [{ name: "docs", columns: { _id: "TEXT PRIMARY KEY", data: "TEXT" } }]);
    var docs = b.db.collection("docs", { overflow: "data" });
    b.db.close();   // subsequent db API calls refuse — PRAGMA table_info throws inside _columns()
    var err = null;
    try { docs.insertMany([{ _id: "z1", extra: "y" }]); } catch (e) { err = e; }
    check("introspection failure wraps into a column-list error",
          err !== null && /unable to introspect column list/.test(err.message));
    check("wrapped introspection error preserves the underlying cause",
          err !== null && /Underlying error:/.test(err.message));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// The overflow column is ALSO declared a jsonColumn. On read, the jsonColumns
// decode parses the overflow JSON text into an object FIRST, so the overflow-
// merge step sees an already-parsed object (not a raw string) and still folds
// its keys back onto the row.
async function testOverflowColumnListedInJsonColumns() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-ofjc-"));
  try {
    await setupTestDb(tmpDir, [{
      name: "docs", columns: { _id: "TEXT PRIMARY KEY", email: "TEXT", data: "TEXT" },
    }]);
    var docs = b.db.collection("docs", { overflow: "data", jsonColumns: ["data"] });
    docs.insert({ _id: "d1", email: "a@x.com", dept: "eng", tier: "gold" });
    var row = docs.findOne({ _id: "d1" });
    check("overflow-as-jsonColumn folds parsed-object keys back onto the row",
          row.dept === "eng" && row.tier === "gold");
    check("overflow-as-jsonColumn removes the overflow column from the row",
          row.data === undefined);
    check("overflow-as-jsonColumn preserves the real columns",
          row._id === "d1" && row.email === "a@x.com");
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
  await testSealedFieldValueRefusal();
  await testOverflowInsertAndDecode();
  await testOverflowBlobValueNotCorrupted();
  await testOverflowQueryOperators();
  await testOverflowUpdates();
  await testExplicitColumnsAndIntrospectionErrors();
  await testOverflowUpdateWithoutIdRefused();
  await testOverflowUnconditionalUpdateRefused();
  await testOverflowInvalidJsonPaths();
  await testIntrospectionErrorWrapped();
  await testOverflowColumnListedInJsonColumns();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
