// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.db encryption-key AAD binding.
 *
 * The database encryption key (db.key.enc) is sealed with additional
 * authenticated data bound to its purpose, data directory, and key
 * path. That binding means a sealed key blob cannot be silently
 * relocated to a different deployment / path and unsealed there — the
 * AEAD authentication fails. A legacy plain-sealed key (pre-binding)
 * is transparently upgraded to the AAD-sealed format on next load.
 */

var helpers = require("../helpers");
var b              = helpers.b;
var check          = helpers.check;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var setupTestDb    = helpers.setupTestDb;

var DB_KEY_PURPOSE = "blamejs/db-encryption-key/v1";
var SCHEMA = [{
  name: "things",
  columns: { _id: "TEXT PRIMARY KEY", v: "TEXT" },
}];

function dbKeyAad(tmp, keyPath) {
  return b.vault.aad.buildContextAad({
    purpose: DB_KEY_PURPOSE,
    dataDir: path.resolve(tmp),
    keyPath: path.resolve(keyPath),
  });
}

async function reinitDbOnly(tmp) {
  helpers.setTestPassphraseEnv();
  b.db._resetForTest();
  await b.db.init({ dataDir: tmp, tmpDir: path.join(tmp, "tmpfs"), schema: SCHEMA });
}

async function run() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-dbkey-aad-"));
  // setupTestDb resets + inits vault and db; vault stays initialized
  // through every phase below (we only reset db between phases).
  await setupTestDb(tmp, SCHEMA);
  b.db.from("things").insertOne({ _id: "x", v: "secret" });

  var keyPath = path.join(tmp, "db.key.enc");
  var sealed = fs.readFileSync(keyPath, "utf8");

  // ---- on-disk key is AAD-sealed ----
  check("db.key.enc is AAD-sealed", b.vault.aad.isAadSealed(sealed) === true);

  // ---- correct AAD unseals to a non-empty key ----
  var b64 = b.vault.aad.unseal(sealed, dbKeyAad(tmp, keyPath));
  check("correct AAD unseals db key to non-empty base64", typeof b64 === "string" && b64.length > 0);

  // ---- binding: a different keyPath / dataDir fails to unseal ----
  var bindKeyPathThrew = false;
  try { b.vault.aad.unseal(sealed, dbKeyAad(tmp, path.join(tmp, "elsewhere.enc"))); }
  catch (_e) { bindKeyPathThrew = true; }
  check("db key won't unseal under a different keyPath", bindKeyPathThrew);

  var bindDirThrew = false;
  try {
    b.vault.aad.unseal(sealed, b.vault.aad.buildContextAad({
      purpose: DB_KEY_PURPOSE,
      dataDir: path.resolve(tmp, "..", "some-other-deployment"),
      keyPath: path.resolve(keyPath),
    }));
  } catch (_e) { bindDirThrew = true; }
  check("db key won't unseal under a different dataDir", bindDirThrew);

  // ---- round-trip: re-init at the same dir decrypts the row ----
  b.db.close();
  await reinitDbOnly(tmp);
  check("re-init at same dir decrypts row through AAD-sealed key",
    b.db.from("things").where({ _id: "x" }).first().v === "secret");

  // ---- legacy plain-sealed key is upgraded to AAD on next load ----
  b.db.close();
  fs.writeFileSync(keyPath, b.vault.seal(b64), { mode: 0o600 });
  check("legacy seed: db.key.enc is NOT AAD-sealed",
    b.vault.aad.isAadSealed(fs.readFileSync(keyPath, "utf8")) === false);
  await reinitDbOnly(tmp);
  check("legacy plain-sealed key upgraded to AAD on load",
    b.vault.aad.isAadSealed(fs.readFileSync(keyPath, "utf8")) === true);
  check("row still decrypts after legacy key upgrade",
    b.db.from("things").where({ _id: "x" }).first().v === "secret");

  b.db.close();
  b.audit._resetForTest();
  b.db._resetForTest();
  b.vault._resetForTest();
  b.cluster._resetForTest();
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_e) {}

  console.log("OK — db-key AAD tests");
}

module.exports = { run: run };
if (require.main === module) {
  // Rethrow on failure so Node surfaces the error and exits non-zero,
  // instead of logging the caught error object — a taint analyzer traces
  // a logged error back to the test passphrase fixture (a non-secret
  // constant) and raises a false clear-text-logging alert.
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
