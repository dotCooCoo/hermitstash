"use strict";

var fs = require("fs");
var path = require("path");
var os = require("os");
var helpers = require("../helpers");
var dbHelper = require("../helpers/db");
var b      = helpers.b;
var check  = helpers.check;

async function run() {
  check("db.declareWorm is fn",               typeof b.db.declareWorm === "function");
  check("db.declareRequireDualControl is fn", typeof b.db.declareRequireDualControl === "function");
  check("db.eraseHard is fn",                 typeof b.db.eraseHard === "function");

  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-db-worm-"));
  await dbHelper.setupTestDb(tmpDir, [
    {
      name: "orders",
      columns: {
        _id:      "TEXT PRIMARY KEY",
        userId:   "TEXT",
        amount:   "INTEGER",
        placedAt: "INTEGER",
      },
      indexes: ["userId"],
    },
  ]);

  // Insert a row before WORM declaration to exercise the trigger gate.
  b.db.from("orders").insertOne({ _id: "ord-1", userId: "u-1", amount: 100, placedAt: Date.now() });

  var dec = b.db.declareWorm({ tables: ["orders"], posture: "sec-17a-4" });
  check("declareWorm: returns tables",  Array.isArray(dec.tables) && dec.tables[0] === "orders");

  // Insert another row — INSERT must still succeed under WORM.
  var inserted = false;
  try {
    b.db.from("orders").insertOne({ _id: "ord-2", userId: "u-2", amount: 50, placedAt: Date.now() });
    inserted = true;
  } catch (_e) { inserted = false; }
  check("WORM: INSERT still permitted", inserted);

  // UPDATE must throw.
  var updateRefused = false;
  try {
    b.db.from("orders").where({ _id: "ord-1" }).updateOne({ amount: 999 });
  } catch (_e) { updateRefused = true; }
  check("WORM: UPDATE refused", updateRefused);

  // DELETE must throw.
  var deleteRefused = false;
  try {
    b.db.from("orders").where({ _id: "ord-1" }).deleteMany();
  } catch (_e) { deleteRefused = true; }
  check("WORM: DELETE refused", deleteRefused);

  // declareWorm refuses framework tables
  var rejectedReserved = false;
  try { b.db.declareWorm({ tables: ["audit_log"] }); }
  catch (_e) { rejectedReserved = true; }
  check("declareWorm: rejects audit_log", rejectedReserved);

  // declareRequireDualControl
  var dcDec = b.db.declareRequireDualControl({
    tables:  ["orders"],
    m:       2,
    n:       3,
    posture: "sox",
  });
  check("declareRequireDualControl: m=2",  dcDec.m === 2);
  check("declareRequireDualControl: n=3",  dcDec.n === 3);

  // eraseHard requires reason
  var noReasonRefused = false;
  try { await b.db.eraseHard("orders", "ord-1", {}); }
  catch (_e) { noReasonRefused = true; }
  check("eraseHard: no reason throws", noReasonRefused);

  // eraseHard with no grant under dual-control gate refuses
  var noGrantRefused = false;
  try { await b.db.eraseHard("orders", "ord-1", { reason: "test" }); }
  catch (e) { noGrantRefused = /dual-control/i.test(e.message); }
  check("eraseHard: dual-control gate refuses without grant", noGrantRefused);

  await dbHelper.teardownTestDb(tmpDir);
}

module.exports = { run: run };
