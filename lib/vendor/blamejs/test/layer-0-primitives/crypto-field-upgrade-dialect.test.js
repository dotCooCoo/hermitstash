"use strict";
// #116: crypto-field's upgrade-on-read durable rewrite (re-hash a legacy
// salted-sha3 derived-hash column to the keyed MAC) hardcoded
// dialect: "sqlite" when building the UPDATE, ignoring the actual handle's
// dialect. The local b.db is sqlite, so it works there — but unsealRow accepts
// a caller-supplied dbHandle (db-query threads an external Postgres / MySQL
// handle through the read path). On a MySQL handle the sqlite-dialected UPDATE
// emits double-quoted identifiers ("users"), which MySQL parses as a string
// literal and rejects, so the durable re-hash is swallowed (try/catch) and the
// legacy digest stays on disk forever — the advertised keyed-MAC migration
// silently never happens off sqlite.
//
// RED on the buggy tree: the rewrite SQL is sqlite-quoted ("users") even when
// the handle declares dialect "mysql". GREEN after the fix: it is backtick-
// quoted (`users`) — the handle's dialect drives the builder.

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var fs   = require("fs");
var os   = require("os");
var path = require("path");
var { setupTestDb, teardownTestDb } = require("../helpers/db");

async function run() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cf-dialect-"));
  try {
    await setupTestDb(dir);

    var email = "Alice@Example.com";
    var keyed = b.cryptoField.lookupHash("users", "email", email);
    var legacyHash = keyed.legacyValue;

    // Forge a legacy-indexed row (the derived-hash column holds the salted
    // digest a pre-v0.15.0 row carries), mirroring crypto-field-dual-read.
    var sealed = b.cryptoField.sealRow("users", { _id: "u-mysql", email: email, name: "Alice" });
    sealed.emailHash = legacyHash;
    b.db.prepare(
      'INSERT INTO "users" ("_id","email","emailHash","name") VALUES (?,?,?,?)'
    ).run(sealed._id, sealed.email, sealed.emailHash, sealed.name);

    var rawRow = b.db.prepare('SELECT * FROM "users" WHERE _id = ?').get("u-mysql");

    // A caller-supplied handle that DECLARES the MySQL dialect (as an external
    // Postgres/MySQL handle does) and captures the durable-rewrite SQL. The
    // statement is a no-op runner — we only assert the dialect of the emitted
    // identifiers, not execute against a real MySQL.
    var capturedSql = null;
    var mysqlHandle = {
      dialect: "mysql",
      prepare: function (sqlText) {
        capturedSql = sqlText;
        return { run: function () { return { changes: 1 }; } };
      },
    };

    var unsealed = b.cryptoField.unsealRow("users", rawRow, "actor-1", mysqlHandle);
    check("unsealRow still decrypts the sealed email (handle independent of crypto)",
          unsealed.email === email);
    check("upgrade-on-read fired: a durable rewrite UPDATE was built", capturedSql !== null);
    check("#116 the rewrite UPDATE honors the handle's MySQL dialect (backtick-quoted)",
          capturedSql && capturedSql.indexOf("`users`") !== -1);
    check("#116 the rewrite UPDATE does NOT emit sqlite double-quoted identifiers on a MySQL handle",
          capturedSql && capturedSql.indexOf("\"users\"") === -1);

    console.log("OK — crypto-field upgrade-on-read dialect tests");
  } finally {
    await teardownTestDb(dir);
  }
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
