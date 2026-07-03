// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.cryptoField — read-side AAD-downgrade refusal (#28).
 *
 * An aad:true (or per-row-key) table seals each cell AEAD-bound to
 * (table, row, column) so a ciphertext can't be relocated to another row or
 * column. A PLAIN `vault:` envelope carries no AAD and IS relocatable — so if
 * the read path accepted a plain cell on an aad table, a DB-write attacker
 * could copy a plain cell from anywhere under the same vault root into an aad
 * column and the read would silently surface it, defeating the cross-row /
 * cross-column copy-protection the AAD binding advertises.
 *
 * unsealRow now refuses a plain cell on an aad/per-row-key table (nulls the
 * field) unless the table opted into the documented pre-AAD migration window
 * with registerTable({ allowPlainMigration: true }).
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var fs   = require("fs");
var os   = require("os");
var path = require("path");

async function run() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cf-aaddt-"));
  await b.vault.init({ dataDir: tmp, mode: "plaintext" });

  // ---- aad:true table: plain cell refused on read ----
  b.cryptoField.registerTable("aaddt_secure", {
    aad: true, sealedFields: ["secret"], rowIdField: "id",
  });

  // A legitimately AAD-sealed row reads back.
  var sealed = b.cryptoField.sealRow("aaddt_secure", { id: "row1", secret: "legit-value" });
  var ok = b.cryptoField.unsealRow("aaddt_secure", Object.assign({}, sealed), { type: "system" });
  check("aad: a legitimately AAD-sealed cell reads back", ok.secret === "legit-value");

  // Forge a RELOCATED plain cell: a bare vault.seal envelope (no AAD) placed in
  // the aad column — exactly what a DB-write attacker would copy in from
  // elsewhere under the same vault root.
  var plainEnvelope = b.vault.seal("relocated-attacker-value");
  check("the forged cell is a plain vault: envelope (no AAD)",
    typeof plainEnvelope === "string" && plainEnvelope.indexOf("vault.aad:") !== 0 &&
    plainEnvelope.indexOf("vault:") === 0);

  var forged = b.cryptoField.unsealRow("aaddt_secure",
    { id: "row1", secret: plainEnvelope }, { type: "system" });
  check("aad-downgrade REFUSED: the relocated plain cell is NOT surfaced (field nulled)",
    forged.secret !== "relocated-attacker-value");
  check("aad-downgrade REFUSED: the field is null, not the attacker value",
    forged.secret === null);

  // ---- allowPlainMigration: the pre-AAD lazy-migration window accepts it ----
  b.cryptoField.registerTable("aaddt_migrating", {
    aad: true, sealedFields: ["secret"], rowIdField: "id", allowPlainMigration: true,
  });
  var migrated = b.cryptoField.unsealRow("aaddt_migrating",
    { id: "row1", secret: b.vault.seal("legacy-pre-aad-value") }, { type: "system" });
  check("allowPlainMigration: a plain pre-AAD cell still reads (documented migration window)",
    migrated.secret === "legacy-pre-aad-value");

  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }

  // ---- the REAL consumer path: db.init({ schema }) must forward allowPlainMigration ----
  // Applications register AAD tables declaratively through db.init, not a
  // direct cryptoField.registerTable call. The migration opt-in has to survive
  // that path — otherwise a schema declaring { aad: true, allowPlainMigration:
  // true } registers with the default (false) and legacy plain cells are nulled
  // despite the operator opting in.
  var tmp2 = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cf-apm-dbinit-"));
  helpers.setTestPassphraseEnv();
  await helpers.setupTestDb(tmp2, [{
    name:    "apm_via_schema",
    columns: { id: "TEXT PRIMARY KEY", secret: "TEXT" },
    aad:     true,
    sealedFields: ["secret"],
    rowIdField:   "id",
    allowPlainMigration: true,
  }]);
  var sch = b.cryptoField.getSchema("apm_via_schema");
  check("db.init schema path forwards allowPlainMigration to registerTable",
    !!sch && sch.allowPlainMigration === true);
  var viaSchema = b.cryptoField.unsealRow("apm_via_schema",
    { id: "row1", secret: b.vault.seal("legacy-via-db-init") }, { type: "system" });
  check("allowPlainMigration honored through the db.init schema consumer path",
    viaSchema.secret === "legacy-via-db-init");

  await helpers.teardownTestDb(tmp2);
}

// No standalone CLI runner: this test drives db.init with a test passphrase,
// and a `console.error(e.stack)` failure footer is a clear-text-logging sink
// CodeQL flags on the (test-fixture) passphrase. The smoke runner invokes
// run() directly — matching db-key-aad.test.js and the other db.init tests.
module.exports = { run: run };
