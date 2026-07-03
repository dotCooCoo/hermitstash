// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.db.collection(name, opts) — schemaless-document extensions:
 *   - opts.overflow      — fold unknown fields into a JSON-text column
 *   - opts.jsonColumns   — auto-stringify on write, auto-parse on read
 *   - opts.sealedFields  — co-locate cryptoField sealing + derived hash
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
    _id:        "TEXT PRIMARY KEY",
    email:      "TEXT",
    emailHash:  "TEXT",
    age:        "INTEGER",
    roles:      "TEXT",
    metadata:   "TEXT",
    data:       "TEXT",
  },
  indexes: ["emailHash"],
}];

async function testOverflowInsertAndRead() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-overflow-"));
  try {
    await setupTestDb(tmpDir, SCHEMA);
    var users = b.db.collection("users", { overflow: "data" });

    users.insert({
      _id:    "u1",
      email:  "alice@x.com",
      age:    30,
      dept:   "eng",
      joined: "2026-01-01",
      tags:   ["admin", "ops"],
    });

    var row = users.findOne({ _id: "u1" });
    check("overflow: real columns round-trip",        row.email === "alice@x.com" && row.age === 30);
    check("overflow: dept folded + restored",         row.dept === "eng");
    check("overflow: joined folded + restored",       row.joined === "2026-01-01");
    check("overflow: array value round-trips",        Array.isArray(row.tags) && row.tags.length === 2 && row.tags[0] === "admin");
    check("overflow: data column hidden from output", row.data === undefined);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testOverflowQuery() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-overflow-q-"));
  try {
    await setupTestDb(tmpDir, SCHEMA);
    var users = b.db.collection("users", { overflow: "data" });
    users.insert({ _id: "u1", email: "a@x.com", dept: "eng",   region: "us-east" });
    users.insert({ _id: "u2", email: "b@x.com", dept: "ops",   region: "us-west" });
    users.insert({ _id: "u3", email: "c@x.com", dept: "eng",   region: "eu-west" });

    var engs = users.find({ dept: "eng" });
    check("overflow: where on virtual field via JSON_EXTRACT", engs.length === 2);
    check("overflow: virtual field $eq operator works",        users.find({ dept: { $eq: "ops" } }).length === 1);
    check("overflow: virtual field $ne",                       users.find({ dept: { $ne: "eng" } }).length === 1);
    check("overflow: virtual field $in",                       users.find({ region: { $in: ["us-east", "us-west"] } }).length === 2);
    check("overflow: count matches find",                      users.count({ dept: "eng" }) === 2);

    var threw = false;
    try { users.find({ dept: { $gt: "eng" } }); }
    catch (e) { threw = /supports \$eq \/ \$ne \/ \$in only/.test(e.message); }
    check("overflow: range operator refused on virtual field", threw);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testOverflowUpdate() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-overflow-u-"));
  try {
    await setupTestDb(tmpDir, SCHEMA);
    var users = b.db.collection("users", { overflow: "data" });
    users.insert({ _id: "u1", email: "a@x.com", dept: "eng", joined: "2026-01-01" });

    var changed = users.update({ _id: "u1" }, { $set: { dept: "ops", lastSeen: "2026-05-09" } });
    check("overflow: $set on virtual fields reports changed", changed === 1);

    var row = users.findOne({ _id: "u1" });
    check("overflow: updated dept",       row.dept === "ops");
    check("overflow: added lastSeen",     row.lastSeen === "2026-05-09");
    check("overflow: kept joined",        row.joined === "2026-01-01");

    users.update({ _id: "u1" }, { $unset: { lastSeen: 1 } });
    var row2 = users.findOne({ _id: "u1" });
    check("overflow: $unset removes overflow key", row2.lastSeen === undefined);

    var threw = false;
    try { users.update({ _id: "u1" }, { $inc: { dept: 1 } }); }
    catch (e) { threw = /\$inc on overflow field/.test(e.message); }
    check("overflow: $inc on virtual field refused", threw);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testJsonColumns() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-json-"));
  try {
    await setupTestDb(tmpDir, SCHEMA);
    var users = b.db.collection("users", { jsonColumns: ["roles", "metadata"] });
    users.insert({
      _id:      "u1",
      email:    "a@x.com",
      roles:    ["admin", "ops"],
      metadata: { team: "platform", level: 4 },
    });
    var row = users.findOne({ _id: "u1" });
    check("jsonColumns: array round-trips",          Array.isArray(row.roles) && row.roles[0] === "admin");
    check("jsonColumns: object round-trips",         row.metadata.team === "platform" && row.metadata.level === 4);

    users.update({ _id: "u1" }, { roles: ["readonly"] });
    var row2 = users.findOne({ _id: "u1" });
    check("jsonColumns: $set with object stringifies", row2.roles[0] === "readonly");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testJsonColumnsValidation() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-jsonv-"));
  try {
    await setupTestDb(tmpDir, SCHEMA);
    // Unknown jsonColumns must refuse on first introspection.
    var bad = b.db.collection("users", { jsonColumns: ["not_a_column"] });
    var threw = false;
    try { bad.insert({ _id: "u1" }); }
    catch (e) { threw = /jsonColumns reference unknown columns/.test(e.message); }
    check("jsonColumns: unknown column refused", threw);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testOverflowMissingColumn() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-overflow-m-"));
  try {
    await setupTestDb(tmpDir, SCHEMA);
    var bad = b.db.collection("users", { overflow: "no_such_column" });
    var threw = false;
    try { bad.insert({ _id: "u1" }); }
    catch (e) { threw = /overflow column 'no_such_column' not present/.test(e.message); }
    check("overflow: unknown column refused on first use", threw);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testSealedFieldsAutoTranslate() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "col-sealed-"));
  try {
    await setupTestDb(tmpDir, SCHEMA);
    // Declare email as sealed + emailHash as the derived hash on the
    // collection itself — no separate cryptoField.registerTable call.
    var users = b.db.collection("users", {
      sealedFields: { email: "emailHash" },
    });
    users.insert({ _id: "u1", email: "alice@x.com", age: 30 });
    users.insert({ _id: "u2", email: "bob@x.com",   age: 40 });

    var row = users.findOne({ email: "alice@x.com" });
    check("sealedFields: where on plaintext rewrites to hash lookup", row && row._id === "u1");
    check("sealedFields: unsealed email returned",                    row && row.email === "alice@x.com");

    var miss = users.findOne({ email: "nobody@x.com" });
    check("sealedFields: miss returns null",                          miss === null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testValidation() {
  var threw = false;
  try { b.db.collection("users", { overflow: "" }); }
  catch (e) { threw = /db-collection\/bad-overflow/.test(e.message) && e instanceof TypeError; }
  check("overflow: empty string refused", threw);

  threw = false;
  try { b.db.collection("users", { jsonColumns: ["valid", ""] }); }
  catch (e) { threw = /db-collection\/bad-json-columns/.test(e.message) && e instanceof TypeError; }
  check("jsonColumns: empty entry refused", threw);

  threw = false;
  try { b.db.collection("users", { sealedFields: { email: "" } }); }
  catch (e) { threw = /must be a hash-column name/.test(e.message); }
  check("sealedFields: empty hash column refused", threw);

  threw = false;
  try { b.db.collection("users", { sealedFields: ["email"] }); }
  catch (e) { threw = /db-collection\/bad-sealed-fields/.test(e.message) && e instanceof TypeError; }
  check("sealedFields: array shape refused", threw);
}

async function run() {
  await testOverflowInsertAndRead();
  await testOverflowQuery();
  await testOverflowUpdate();
  await testJsonColumns();
  await testJsonColumnsValidation();
  await testOverflowMissingColumn();
  await testSealedFieldsAutoTranslate();
  await testValidation();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message, e.stack); process.exit(1); }
  );
}
