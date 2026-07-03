// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.cryptoField per-row key (K_row) crypto-shred substrate.
 *
 * declarePerRowKey opts a table into per-row keying. On INSERT the write
 * boundary materializes a fresh CSPRNG row-secret, derives K_row from it,
 * stores the SECRET (never K_row) AAD-sealed in _blamejs_per_row_keys, and
 * seals the row's sealed columns under K_row as vault.row: cells. Reads
 * fetch + unwrap the secret, re-derive K_row, and decrypt. Destroying the
 * wrapped secret (b.subject.eraseHard / b.retention) leaves WAL / replica
 * residual ciphertext mathematically undecryptable — the crypto-shred.
 *
 * Regression for the v0.14.25 critical class:
 *   - pre-fix K_row derived from the PLAINTEXT-on-disk derivedHash salt,
 *     so an attacker with disk access re-derived it and deleting the wrap
 *     shred NOTHING. The row-secret is now random.
 *   - pre-fix the wrap was sealed WITHOUT AAD despite a copy-protection
 *     claim. The wrap + the cells are now AAD-bound to (table, rowId,
 *     column, schemaVersion).
 *   - pre-fix materializePerRowKey was NEVER called on INSERT (dead
 *     surface). It is now wired at the db-query write boundary.
 *
 * Pins: materialize-rowId == destroy-rowId == _id; the residency-tag
 * column is NEVER K_row-sealed; a copied cell fails Poly1305; a vault
 * keypair rotation reseals the wrapped secret old-root -> new-root.
 */

var helpers = require("../helpers");
var b      = helpers.b;
var fs     = require("fs");
var os     = require("os");
var path   = require("path");
var check  = helpers.check;
var { setupTestDb, teardownTestDb } = require("../helpers/db");

var ROW_PREFIX = require("../../lib/constants").ROW_PREFIX;

// App table opted into per-row keying. `subjectId` is the plaintext
// subject column eraseHard matches on; `dataRegion` is the plaintext
// residency tag (declarePerRowResidency) that must NEVER be K_row-sealed;
// `ssn` / `note` are the sealed columns that become vault.row: cells.
var KEYED_SCHEMA = [{
  name: "pr_keyed",
  columns: {
    _id:        "TEXT PRIMARY KEY",
    subjectId:  "TEXT",
    dataRegion: "TEXT",
    ssn:        "TEXT",
    note:       "TEXT",
  },
  indexes: ["subjectId"],
  sealedFields: ["ssn", "note"],
  subjectField: "subjectId",
}];

function _perRowKeyCount(rowId) {
  var row = b.db.prepare(
    'SELECT COUNT(*) AS n FROM "_blamejs_per_row_keys" WHERE tableName = ? AND rowId = ?'
  ).get("pr_keyed", rowId);
  return row ? row.n : 0;
}

function _rawCell(rowId, col) {
  var row = b.db.prepare('SELECT "' + col + '" AS v FROM "pr_keyed" WHERE _id = ?').get(rowId);
  return row ? row.v : null;
}

async function run() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cf-prk-"));
  try {
    await setupTestDb(dir, KEYED_SCHEMA);
    b.cryptoField.clearResidencyForTest();
    b.cryptoField.declarePerRowKey("pr_keyed", { keySize: 32 });
    b.cryptoField.declarePerRowResidency("pr_keyed", {
      residencyColumn: "dataRegion",
      allowedTags:     ["eu", "us", "global"],
    });
    check("hasPerRowKey true after declare", b.cryptoField.hasPerRowKey("pr_keyed") === true);

    // ---- INSERT: materialize + K_row-seal at the write boundary ----
    var inserted = b.db.from("pr_keyed").insertOne({
      _id: "row-1", subjectId: "subj-A", dataRegion: "eu", ssn: "123-45-6789", note: "patient note one",
    });
    check("insertOne returns plaintext _id", inserted._id === "row-1");

    // A _blamejs_per_row_keys entry appears for this row's _id.
    check("per-row-keys registry row created for _id", _perRowKeyCount("row-1") === 1);

    // The stored wrapped secret is AAD-sealed (vault.aad: prefix).
    var wrapRow = b.db.prepare(
      'SELECT wrappedKey FROM "_blamejs_per_row_keys" WHERE tableName = ? AND rowId = ?'
    ).get("pr_keyed", "row-1");
    check("wrapped secret stored AAD-sealed (vault.aad:)",
      typeof wrapRow.wrappedKey === "string" && wrapRow.wrappedKey.indexOf("vault.aad:") === 0);

    // Sealed columns on disk carry the vault.row: prefix (K_row cells) —
    // asserted via the public b.cryptoField.isRowSealed primitive.
    check("ssn column is a vault.row: cell", b.cryptoField.isRowSealed(_rawCell("row-1", "ssn")));
    check("note column is a vault.row: cell", b.cryptoField.isRowSealed(_rawCell("row-1", "note")));
    check("ROW_PREFIX is the vault.row: envelope isRowSealed detects",
      String(_rawCell("row-1", "ssn")).indexOf(ROW_PREFIX) === 0);

    // PIN: the residency-tag column stays plaintext (never K_row-sealed);
    // isRowSealed is false for a plaintext cell.
    check("residency tag column stays plaintext", _rawCell("row-1", "dataRegion") === "eu");
    check("isRowSealed false for the plaintext residency tag",
      b.cryptoField.isRowSealed(_rawCell("row-1", "dataRegion")) === false);

    // ---- READ: round-trips to plaintext ----
    var got = b.db.from("pr_keyed").where({ _id: "row-1" }).first();
    check("read round-trips ssn", got.ssn === "123-45-6789");
    check("read round-trips note", got.note === "patient note one");
    check("read surfaces residency tag verbatim", got.dataRegion === "eu");

    // ---- Codex P1 regression: unsealRow with NO dbHandle (the
    // break-glass / clusterStorage read path) still decrypts a keyed row.
    // crypto-field resolves the local db itself for the wrapped-secret
    // lookup, so a direct caller doesn't null every K_row cell. ----
    var rawRow = b.db.prepare('SELECT * FROM "pr_keyed" WHERE _id = ?').get("row-1");
    check("raw row carries a vault.row: cell pre-unseal", b.cryptoField.isRowSealed(rawRow.ssn));
    var noHandle = b.cryptoField.unsealRow("pr_keyed", rawRow);   // 4th arg (dbHandle) omitted
    check("unsealRow without a dbHandle still decrypts ssn", noHandle.ssn === "123-45-6789");
    check("unsealRow without a dbHandle still decrypts note", noHandle.note === "patient note one");

    // all() path round-trips too.
    var all = b.db.from("pr_keyed").where({ subjectId: "subj-A" }).all();
    check("all() round-trips one keyed row", all.length === 1 && all[0].ssn === "123-45-6789");

    // ---- COPY-ROW ATTACK: paste another row's cell ----
    b.db.from("pr_keyed").insertOne({
      _id: "row-2", subjectId: "subj-B", dataRegion: "us", ssn: "999-88-7777", note: "patient note two",
    });
    var row2Ssn = _rawCell("row-2", "ssn");   // a valid vault.row: cell, but bound to row-2
    // Overwrite row-1's ssn cell with row-2's ciphertext via raw SQL (a
    // DB-write attacker). row-1's K_row + AAD differ, so Poly1305 fails.
    b.db.prepare('UPDATE "pr_keyed" SET "ssn" = ? WHERE _id = ?').run(row2Ssn, "row-1");
    var tampered = b.db.from("pr_keyed").where({ _id: "row-1" }).first();
    check("copied cell from another row fails to decrypt (null)", tampered.ssn === null);
    check("untouched cell on the same row still decrypts", tampered.note === "patient note one");
    // Restore a valid row-1 ssn cell for the erase/rotation phases.
    b.db.from("pr_keyed").where({ _id: "row-1" }).updateOne({ ssn: "123-45-6789" });
    check("re-seal under K_row round-trips after update",
      b.db.from("pr_keyed").where({ _id: "row-1" }).first().ssn === "123-45-6789");

    // ---- ERASE-HARD: crypto-shred ----
    var result = b.subject.eraseHard("subj-A", {
      reason: "test-crypto-shred",
      acknowledgements: ["no-litigation-hold", "no-statutory-retention-required"],
    });
    check("eraseHard destroyed 1 per-row key", result.perRowKeysDestroyed === 1);
    check("eraseHard deleted the row", result.perTable.pr_keyed === 1);
    check("per-row-keys registry row gone after shred", _perRowKeyCount("row-1") === 0);
    // The row itself was DELETEd by eraseHard; assert the wrapped secret
    // is gone (the residual-ciphertext shred). A post-shred re-insert of
    // the SAME _id would mint a NEW random secret — the old WAL cell would
    // never decrypt under it.
    check("subj-B row still present + decrypts (shred is row-scoped)",
      b.db.from("pr_keyed").where({ _id: "row-2" }).first().ssn === "999-88-7777");

    // ---- POST-DESTROY read-absent: a vault.row: cell with no wrap ----
    // Re-create a wrap-less keyed cell: insert, then destroy ONLY its
    // wrapped secret (simulating WAL residue after shred). The read must
    // null the field, not crash.
    b.db.from("pr_keyed").insertOne({
      _id: "row-3", subjectId: "subj-C", dataRegion: "global", ssn: "111-22-3333", note: "n3",
    });
    b.cryptoField.destroyPerRowKey("pr_keyed", "row-3", b.db);
    check("destroyPerRowKey removed the wrap", _perRowKeyCount("row-3") === 0);
    var shredded = b.db.from("pr_keyed").where({ _id: "row-3" }).first();
    check("shredded cell reads as absent (null), no crash", shredded.ssn === null && shredded.note === null);

    // ---- B3a: a SHREDDED read must NOT trip the unseal-failure rate cap ----
    // A crypto-shredded key is an EXPECTED absence (the wrap is gone — no oracle
    // to brute-force), not a forged-ciphertext attack. Bulk-reading erased rows
    // (GDPR eraseHard) must not accrue rate-cap failures, else the cap trips and
    // DoS's the live rows (self-DoS). Configure a low threshold and read the
    // shredded row many times for one (actor, table, column): none must throw
    // crypto-field/unseal-rate-exceeded.
    var rateAudits = [];
    b.cryptoField.configureUnsealRateCap({
      threshold: 2, windowMs: 60000, cooldownMs: 300000,
      onAudit: function (ev) { rateAudits.push(ev); },
    });
    var shredTrip = null;
    for (var sr = 0; sr < 8; sr++) {
      try {
        var srRow = b.db.prepare('SELECT * FROM "pr_keyed" WHERE _id = ?').get("row-3");
        b.cryptoField.unsealRow("pr_keyed", srRow, "shred-reader");
      } catch (e) { if (e.code === "crypto-field/unseal-rate-exceeded") shredTrip = e; }
    }
    check("8 shredded reads do NOT trip the rate cap (shred is exempt)", shredTrip === null);
    check("shredded reads emit no rate-exceeded audit",
      rateAudits.every(function (a) { return a.action !== "system.crypto.unseal_rate_exceeded"; }));
    // CONTROL: a genuine forged-ciphertext read on the same tuple still trips —
    // the exemption is specific to the shredded-key case, not a cap bypass.
    var FORGED_ROW = "vault.aad:Zm9yZ2VkLWdhcmJhZ2U=";
    var forgedTrip = null;
    for (var fr = 0; fr < 8; fr++) {
      try {
        b.cryptoField.unsealRow("pr_keyed", { _id: "row-3", ssn: FORGED_ROW }, "forge-reader");
      } catch (e) { if (e.code === "crypto-field/unseal-rate-exceeded") forgedTrip = e; }
    }
    check("forged-ciphertext reads STILL trip the rate cap (exemption is shred-specific)",
      forgedTrip !== null);
    b.cryptoField.clearRateCapForTest();

    // ---- FORENSIC RESIDUAL PROOF (the crypto-shred guarantee) ----
    // Advertised (crypto-field.js destroyPerRowKey): destroying the wrapped
    // row-secret makes residual ciphertext (WAL / replica / backup)
    // undecryptable EVEN WITH THE VAULT ROOT, because the random row-secret —
    // the only seed for K_row — is gone everywhere it lived. A read returning
    // null after shred proves only the read path; this proves the CIPHERTEXT
    // itself is unrecoverable while the vault root + machinery stay fully
    // functional (a sibling keyed row keeps decrypting throughout).
    var FNEEDLE = "SECRET-SSN-FORENSIC-7Q2";
    b.db.from("pr_keyed").insertOne({
      _id: "row-F", subjectId: "subj-F", dataRegion: "eu", ssn: FNEEDLE, note: "forensic note",
    });
    var residualCipher = _rawCell("row-F", "ssn");
    check("forensic: captured cell is a vault.row: residual envelope",
      b.cryptoField.isRowSealed(residualCipher));
    check("forensic: control — residual cell decrypts before shred",
      b.db.from("pr_keyed").where({ _id: "row-F" }).first().ssn === FNEEDLE);

    // Seal the working copy to durable db.enc, then scan every on-disk db
    // file (durable sealed copy + tmpfs working copy + WAL): the plaintext must
    // appear in NONE of them, while the sealed envelope DOES persist (a real
    // residual an attacker could lift from WAL / a replica / a backup).
    await b.db.flushToDisk();
    var plainNeedle = Buffer.from(FNEEDLE, "utf8");
    var envNeedle   = Buffer.from(residualCipher, "utf8");
    var scanned = 0, plaintextHits = 0, envelopeOnDisk = false;
    [dir, path.join(dir, "tmpfs")].forEach(function (d) {
      var entries;
      try { entries = fs.readdirSync(d); } catch (_e) { return; }
      entries.forEach(function (f) {
        var p = path.join(d, f), st;
        try { st = fs.statSync(p); } catch (_e) { return; }
        if (!st.isFile()) return;
        var buf;
        try { buf = fs.readFileSync(p); } catch (_e) { return; }
        scanned += 1;
        if (buf.indexOf(plainNeedle) !== -1) plaintextHits += 1;
        if (buf.indexOf(envNeedle)   !== -1) envelopeOnDisk = true;
      });
    });
    check("forensic: scanned on-disk db files (db.enc + working + wal)", scanned > 0);
    check("forensic: plaintext ssn appears in NO on-disk file (sealed at rest)", plaintextHits === 0);
    check("forensic: the sealed vault.row: envelope DOES persist on disk (real residual)", envelopeOnDisk);

    // Shred the wrapped secret ONLY — the row + its residual cell stay put.
    var fdestroy = b.cryptoField.destroyPerRowKey("pr_keyed", "row-F", b.db);
    check("forensic: destroyPerRowKey removed exactly the row-F wrap", fdestroy.destroyed === 1);
    check("forensic: wrapped secret gone from registry", _perRowKeyCount("row-F") === 0);
    check("forensic: residual cipher still physically on the row post-shred",
      _rawCell("row-F", "ssn") === residualCipher);
    // The vault root + crypto-field machinery are STILL fully functional: a
    // sibling keyed row (row-2, never shredded) decrypts normally.
    check("forensic: vault root intact — sibling keyed row still decrypts",
      b.db.from("pr_keyed").where({ _id: "row-2" }).first().ssn === "999-88-7777");
    // Yet the residual cell yields NO plaintext: the random row-secret that
    // seeded K_row is gone, and the vault root alone cannot reconstruct it.
    check("forensic: residual cell undecryptable after shred (root intact)",
      b.db.from("pr_keyed").where({ _id: "row-F" }).first().ssn === null);

    // Re-materializing the SAME _id mints a NEW random secret -> a DIFFERENT
    // K_row, so the captured residual (sealed under the destroyed K_row) is
    // STILL undecryptable. The shred is irreversible, not a key-reuse window.
    b.cryptoField.materializePerRowKey("pr_keyed", "row-F", b.db);
    check("forensic: a fresh wrap exists again for row-F", _perRowKeyCount("row-F") === 1);
    b.db.prepare('UPDATE "pr_keyed" SET "ssn" = ? WHERE _id = ?').run(residualCipher, "row-F");
    check("forensic: residual STILL undecryptable under a freshly-minted K_row",
      b.db.from("pr_keyed").where({ _id: "row-F" }).first().ssn === null);
    b.db.prepare('DELETE FROM "pr_keyed" WHERE _id = ?').run("row-F");
    b.cryptoField.destroyPerRowKey("pr_keyed", "row-F", b.db);

    await teardownTestDb(dir);

    // ---- ROTATION ROUND-TRIP ----
    await _rotationRoundTrip();

    // ---- B3b: crypto-shred under a CUSTOM tablePrefix ----
    await _customPrefixShredLifecycle();
  } finally {
    try { b.cryptoField.clearResidencyForTest(); } catch (_e) {}
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
  }
  console.log("OK — crypto-field per-row-key tests");
}

// The per-row-key registry is ALWAYS local (the crypto-shred substrate lives in
// the local sqlite even in cluster mode). A custom tablePrefix rewrites only the
// cluster-mode EXTERNAL names; the local table stays raw (_blamejs_per_row_keys).
// Regression: crypto-field resolved the registry name through the cluster-prefix
// resolver, so under a custom prefix it targeted a nonexistent <prefix>per_row_keys
// table — destroyPerRowKey deleted 0 rows and sealed cells stayed decryptable
// after eraseHard (a SILENT crypto-shred failure). Prove the full lifecycle
// (seal -> read -> shred -> read-absent) holds under a custom prefix.
async function _customPrefixShredLifecycle() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "prk-prefix-"));
  try {
    process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
    b.cluster._resetForTest(); b.audit._resetForTest(); b.vault._resetForTest(); b.db._resetForTest();
    helpers.setTestPassphraseEnv ? helpers.setTestPassphraseEnv() : (function () {
      process.env.BLAMEJS_VAULT_PASSPHRASE = "x".repeat(40);
      process.env.BLAMEJS_AUDIT_SIGNING_PASSPHRASE = "x".repeat(40);
    })();
    await b.vault.init({ dataDir: dir });
    await b.db.init({
      dataDir: dir, tmpDir: path.join(dir, "tmpfs"), allowNonTmpfsTmpDir: true,
      tablePrefix: "acme_",                                   // <-- CUSTOM PREFIX
      schema: KEYED_SCHEMA,
    });
    b.cryptoField.clearResidencyForTest();
    b.cryptoField.declarePerRowKey("pr_keyed", { keySize: 32 });
    b.cryptoField.declarePerRowResidency("pr_keyed", {
      residencyColumn: "dataRegion", allowedTags: ["eu", "us", "global"],
    });
    b.db.from("pr_keyed").insertOne({
      _id: "p1", subjectId: "subj-P", dataRegion: "eu", ssn: "123-45-6789", note: "n",
    });
    check("custom-prefix: keyed read round-trips before shred",
      b.db.from("pr_keyed").where({ _id: "p1" }).first().ssn === "123-45-6789");
    var res = b.cryptoField.destroyPerRowKey("pr_keyed", "p1", b.db);
    check("custom-prefix: destroyPerRowKey deletes the wrap (destroyed === 1)", res.destroyed === 1);
    check("custom-prefix: sealed cell is UNREADABLE after shred (crypto-shred holds)",
      b.db.from("pr_keyed").where({ _id: "p1" }).first().ssn === null);
    b.db.close();
  } finally {
    try { b.cryptoField.clearResidencyForTest(); } catch (_e) {}
    try { b.db._resetForTest(); } catch (_e) {}
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
  }
}

// A vault keypair rotation must reseal the wrapped row-secret in
// _blamejs_per_row_keys old-root -> new-root (registerTable({aad:true})
// wires rotate._rotateColumn). After the swap, the wrap unwraps under the
// new root, K_row re-derives, and a vault.row: data cell still decrypts.
async function _rotationRoundTrip() {
  var dirNew  = fs.mkdtempSync(path.join(os.tmpdir(), "prk-vr-new-"));
  var dirA    = fs.mkdtempSync(path.join(os.tmpdir(), "prk-vr-a-"));
  var staging = path.join(os.tmpdir(), "prk-vr-stg-" + process.pid + "-" + Date.now());

  async function _reset() {
    process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
    b.cluster._resetForTest();
    b.audit._resetForTest();
    b.vault._resetForTest();
    b.db._resetForTest();
  }

  try {
    // Fresh keypair to rotate INTO.
    await _reset();
    await b.vault.init({ dataDir: dirNew, mode: "plaintext" });
    var newKeys = JSON.parse(b.vault.getKeysJson());
    b.vault._resetForTest();

    // Live deployment with a per-row-key table + one keyed row.
    await _reset();
    await b.vault.init({ dataDir: dirA, mode: "plaintext" });
    var oldKeys = JSON.parse(b.vault.getKeysJson());
    check("rotation: old and new keypairs differ",
      JSON.stringify(oldKeys) !== JSON.stringify(newKeys));
    await b.db.init({
      dataDir: dirA, tmpDir: path.join(dirA, "tmpfs"), atRest: "encrypted",
      auditSigning: false, schema: KEYED_SCHEMA,
    });
    b.cryptoField.clearResidencyForTest();
    b.cryptoField.declarePerRowKey("pr_keyed", { keySize: 32 });
    b.cryptoField.declarePerRowResidency("pr_keyed", {
      residencyColumn: "dataRegion", allowedTags: ["eu", "us", "global"],
    });

    b.db.from("pr_keyed").insertOne({
      _id: "rot-1", subjectId: "s1", dataRegion: "eu", ssn: "555-44-3333", note: "rotate me",
    });
    check("rotation: keyed cell sealed as vault.row:",
      String(_rawCell("rot-1", "ssn")).indexOf(ROW_PREFIX) === 0);
    await b.db.flushToDisk();
    await b.db.close();

    // Rotate the keypair old -> new. externalAadResealed:true: this
    // deployment uses none of the operator-supplied external AAD stores.
    var rot = await b.vaultRotate.rotate({
      dataDir: dirA, stagingDir: staging, oldKeys: oldKeys, newKeys: newKeys,
      mode: "plaintext", externalAadResealed: true,
    });
    check("rotation: internal verify ok (AAD cells decrypt under new root)",
      !!rot.verifyResult && rot.verifyResult.ok === true);
    check("rotation: processed at least the wrapped-secret + the data cell",
      rot.totalRowsProcessed >= 1);

    // Swap staging -> dataDir, re-open under the NEW keypair.
    ["db.enc", "db.key.enc", "vault.key"].forEach(function (f) {
      var s = path.join(staging, f);
      if (fs.existsSync(s)) fs.copyFileSync(s, path.join(dirA, f));
    });
    try { fs.rmSync(path.join(dirA, "tmpfs"), { recursive: true, force: true }); } catch (_e) {}

    await _reset();
    await b.vault.init({ dataDir: dirA, mode: "plaintext" });
    check("rotation: vault now live under the NEW keypair",
      JSON.stringify(JSON.parse(b.vault.getKeysJson())) === JSON.stringify(newKeys));
    await b.db.init({
      dataDir: dirA, tmpDir: path.join(dirA, "tmpfs"), atRest: "encrypted",
      auditSigning: false, schema: KEYED_SCHEMA,
    });
    b.cryptoField.clearResidencyForTest();
    b.cryptoField.declarePerRowKey("pr_keyed", { keySize: 32 });
    b.cryptoField.declarePerRowResidency("pr_keyed", {
      residencyColumn: "dataRegion", allowedTags: ["eu", "us", "global"],
    });

    var got = b.db.from("pr_keyed").where({ _id: "rot-1" }).first();
    check("rotation: vault.row: cell decrypts after rotation under the new keypair",
      !!got && got.ssn === "555-44-3333" && got.note === "rotate me");
    await b.db.close();
  } finally {
    await _reset();
    try { b.cryptoField.clearResidencyForTest(); } catch (_e) {}
    [dirNew, dirA, staging].forEach(function (d) {
      try { fs.rmSync(d, { recursive: true, force: true }); } catch (_e) {}
    });
  }
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
