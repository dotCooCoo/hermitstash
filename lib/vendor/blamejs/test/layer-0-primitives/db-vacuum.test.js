"use strict";
/**
 * b.db.vacuumAfterErase — operator-callable VACUUM after large
 * erasures. Reclaims free pages so sealed-column ciphertext doesn't
 * survive on disk past the row-level erase.
 */

var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;
var setupTestDb = require("../helpers/db").setupTestDb;
var teardownTestDb = require("../helpers/db").teardownTestDb;

async function run() {
  var dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vacuum-"));
  var ctx = await setupTestDb(dataDir);
  try {
    // Bad mode rejected.
    var threw;
    try { b.db.vacuumAfterErase({ mode: "garbage" }); } catch (e) { threw = e; }
    check("vacuumAfterErase: bad mode throws",
      threw && threw.code === "db/bad-vacuum-mode");

    // incremental mode runs without error against a populated DB.
    var ok = (function () { try { b.db.vacuumAfterErase({ mode: "incremental" }); return true; } catch (_e) { return false; } })();
    check("vacuumAfterErase: incremental mode succeeds", ok === true);

    // Default mode is incremental.
    var okDefault = (function () { try { b.db.vacuumAfterErase(); return true; } catch (_e) { return false; } })();
    check("vacuumAfterErase: default mode succeeds", okDefault === true);
  } finally {
    await teardownTestDb(ctx);
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[db-vacuum] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
