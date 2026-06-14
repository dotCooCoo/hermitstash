"use strict";
// #141: a membership query on a SEALED column must work. db-query's sealed
// field → derived-hash rewrite handled "=" (single value → keyed hash, with a
// dual-read of the legacy digest across the v0.15.0 keyed-MAC flip) and "!=",
// but for "IN" it passed the WHOLE candidate array to cryptoField.lookupHash
// as if it were one plaintext — producing a single bogus hash, which the
// later array-shape check then rejected with "where IN requires a non-empty
// array". So b.db.from().whereIn("email", [...]) and
// b.db.collection().find({ email: { $in: [...] } }) on a sealed column were
// unusable: the documented derived-hash query path supported equality but not
// membership. The fix maps EACH array element through lookupHash and builds
// the combined IN-list (including each element's legacy digest for dual-read).
//
// RED on the buggy tree: whereIn / $in on a sealed field throws. GREEN after
// the fix: both consumer paths return the matching rows, including legacy-
// digested (un-migrated) rows.

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var fs   = require("fs");
var os   = require("os");
var path = require("path");
var { setupTestDb, teardownTestDb } = require("../helpers/db");

function _insertSealed(id, email, name) {
  var sealed = b.cryptoField.sealRow("users", { _id: id, email: email, name: name });
  b.db.prepare(
    'INSERT INTO "users" ("_id","email","emailHash","name") VALUES (?,?,?,?)'
  ).run(sealed._id, sealed.email, sealed.emailHash, sealed.name);
  return sealed;
}

async function run() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-sealed-in-"));
  try {
    await setupTestDb(dir);

    var alice = "alice@example.com";
    var bob   = "bob@example.com";
    var carol = "carol@example.com";
    _insertSealed("u-alice", alice, "Alice");
    _insertSealed("u-bob",   bob,   "Bob");
    _insertSealed("u-carol", carol, "Carol");

    // ---- equality still works (the path that was never broken) ----
    var eqRows = await b.db.from("users").where("email", alice).all();
    check("sealed equality query still finds the row",
          eqRows.length === 1 && eqRows[0]._id === "u-alice");

    // ---- #141: whereIn on a sealed column (the real consumer path) ----
    var inRows = await b.db.from("users").whereIn("email", [alice, bob]).all();
    var inIds = inRows.map(function (r) { return r._id; }).sort();
    check("#141 whereIn on a sealed column returns every matching row",
          inIds.length === 2 && inIds[0] === "u-alice" && inIds[1] === "u-bob");
    check("#141 whereIn on a sealed column excludes the non-listed row",
          inIds.indexOf("u-carol") === -1);

    // ---- #141: the collection $in consumer path (same root) ----
    var coll = b.db.collection("users");
    var collRows = coll.find({ email: { $in: [alice, carol] } });
    var collIds = collRows.map(function (r) { return r._id; }).sort();
    check("#141 collection.find $in on a sealed column returns every match",
          collIds.length === 2 && collIds[0] === "u-alice" && collIds[1] === "u-carol");

    // ---- #141: dual-read — a legacy-digested (un-migrated) row is found ----
    // Forge a row carrying the pre-v0.15.0 salted digest, like the dual-read
    // migrate test. whereIn must include the legacy digest per element.
    var dave = "dave@example.com";
    var lk = b.cryptoField.lookupHash("users", "email", dave);
    var sealedDave = b.cryptoField.sealRow("users", { _id: "u-dave", email: dave, name: "Dave" });
    sealedDave.emailHash = lk.legacyValue;   // pin the LEGACY digest
    b.db.prepare(
      'INSERT INTO "users" ("_id","email","emailHash","name") VALUES (?,?,?,?)'
    ).run(sealedDave._id, sealedDave.email, sealedDave.emailHash, sealedDave.name);
    var dualRows = await b.db.from("users").whereIn("email", [dave, bob]).all();
    var dualIds = dualRows.map(function (r) { return r._id; }).sort();
    check("#141 whereIn dual-reads the legacy digest (finds an un-migrated row)",
          dualIds.indexOf("u-dave") !== -1 && dualIds.indexOf("u-bob") !== -1);

    // ---- single-element membership ----
    var oneRows = await b.db.from("users").whereIn("email", [carol]).all();
    check("#141 single-element whereIn on a sealed column works",
          oneRows.length === 1 && oneRows[0]._id === "u-carol");

    // ---- regression: whereIn on a NON-sealed column is unchanged ----
    var idRows = await b.db.from("users").whereIn("_id", ["u-alice", "u-bob"]).all();
    check("non-sealed whereIn is unaffected",
          idRows.map(function (r) { return r._id; }).sort().join(",") === "u-alice,u-bob");

    console.log("OK — db-query sealed-field IN / $in tests");
  } finally {
    await teardownTestDb(dir);
  }
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.stderr.write(String(err && err.stack || err) + "\n"); process.exit(1); });
}
