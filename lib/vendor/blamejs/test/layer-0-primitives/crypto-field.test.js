// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.cryptoField — sealed-column accessors + the seal / unseal seam.
 *
 * getSealedFields is the sealed-column accessor storage backends consult to
 * know which columns to wrap in vault.seal on write and vault.unseal on read.
 *
 * The seal/unseal seam tests drive the adversarial + defensive branches an
 * operator's data actually exercises: an empty-string sealed field (the three
 * envelope branches — plain / aad / K_row — must agree, never crash), the
 * type-fidelity codec (Buffer / object / array preserved through a sealed
 * column), the AAD cross-row / cross-column / cross-table copy-protection (a
 * relocated or tampered cell must be refused, not surfaced), and the
 * config-time refusals when the rowId term of the AAD binding is missing.
 *
 * Uses uniquely-named tables (no clearForTest) so the shared per-table schema
 * registry other smoke tests populate is left intact.
 *
 * Run standalone: `node test/layer-0-primitives/crypto-field.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var fs      = require("fs");
var os      = require("os");
var path    = require("path");
var { setupTestDb, teardownTestDb } = require("../helpers/db");

// Capture-or-value helper: returns { ok:true, value } when fn() returns, or
// { ok:false, err } when it throws — so a check can assert BOTH "did not throw"
// and "returned the right value" in one stable expression (a raw throw would
// otherwise abort the whole run before the assertion counts).
function _try(fn) {
  try { return { ok: true, value: fn() }; }
  catch (e) { return { ok: false, err: e }; }
}

// ---- getSealedFields accessor ----

function testReturnsDeclaredSealedFields() {
  b.cryptoField.registerTable("cf_getsealed_patients", {
    sealedFields: ["ssn", "diagnosis"],
    derivedHashes: {
      ssnHash: { from: "ssn", normalize: function (s) { return String(s).replace(/-/g, ""); } },
    },
  });
  var fields = b.cryptoField.getSealedFields("cf_getsealed_patients");
  check("getSealedFields returns an array", Array.isArray(fields));
  check("getSealedFields returns exactly the declared sealed columns",
    fields.length === 2 && fields[0] === "ssn" && fields[1] === "diagnosis");

  // Agrees with the fuller getSchema() record's sealedFields.
  var schema = b.cryptoField.getSchema("cf_getsealed_patients");
  check("getSealedFields agrees with getSchema().sealedFields",
    JSON.stringify(schema.sealedFields) === JSON.stringify(fields));
}

function testUnregisteredTableIsEmpty() {
  // A table that was never registered → empty array (not null/undefined),
  // so a backend can iterate the result unconditionally.
  var fields = b.cryptoField.getSealedFields("cf_getsealed_never_registered");
  check("getSealedFields returns [] for an unregistered table",
    Array.isArray(fields) && fields.length === 0);
}

function testTableWithNoSealedColumns() {
  // A registered table that seals nothing → empty array.
  b.cryptoField.registerTable("cf_getsealed_public", { sealedFields: [] });
  var fields = b.cryptoField.getSealedFields("cf_getsealed_public");
  check("getSealedFields returns [] for a table sealing no columns",
    Array.isArray(fields) && fields.length === 0);
}

function testPreservesDeclarationOrder() {
  // The accessor preserves the operator's declared column order, which the
  // seal/unseal call sites depend on for stable column mapping.
  b.cryptoField.registerTable("cf_getsealed_order", {
    sealedFields: ["zeta", "alpha", "mu"],
  });
  var fields = b.cryptoField.getSealedFields("cf_getsealed_order");
  check("getSealedFields preserves declared column order",
    fields.join(",") === "zeta,alpha,mu");
}

// ---- seal / unseal seam (vault-backed, no db) ----

async function testSealUnsealSeams() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cf-seam-"));
  try {
    try { b.vault._resetForTest(); } catch (_e) { /* fresh init below */ }
    await b.vault.init({ dataDir: tmp, mode: "plaintext" });
    b.cryptoField.clearRateCapForTest();

    // --- empty-string sealed field: sealed as a real envelope, tamper-evident ---
    // vault.aad.seal REFUSES empty plaintext, so a naive skip of "" would store a
    // bare plaintext empty string in the sealed column -- and unsealRow's falsy
    // skip would then accept a ciphertext a DB-write attacker downgraded to "" with
    // no AEAD failure. Instead _encodeTyped("") -> a non-empty typed marker, so a
    // sealed empty string is a real authenticated envelope that round-trips to ""
    // and detects a downgrade to "".
    b.cryptoField.registerTable("cf_seam_aad_empty", {
      aad: true, sealedFields: ["secret"], rowIdField: "id",
    });
    var aadSealedEmpty = b.cryptoField.sealRow("cf_seam_aad_empty", { id: "r1", secret: "" });
    check("aad table: empty-string sealed field is a non-empty envelope (not bare plaintext)",
      typeof aadSealedEmpty.secret === "string" && aadSealedEmpty.secret.length > 0);
    var aadEmpty = _try(function () {
      return b.cryptoField.unsealRow("cf_seam_aad_empty",
        Object.assign({}, aadSealedEmpty), "seam").secret;
    });
    check("aad table: empty-string sealed field round-trips to empty (no throw)",
      aadEmpty.ok === true && aadEmpty.value === "");
    // Downgrade tamper: a DB-write attacker replaces the ciphertext with "".
    // unsealRow must fail closed (null the cell), NOT accept "" as a valid value.
    var aadDowngrade = b.cryptoField.unsealRow("cf_seam_aad_empty",
      Object.assign({}, aadSealedEmpty, { secret: "" }), "seam");
    check("aad table: a ciphertext downgraded to empty fails closed (nulled, not accepted)",
      aadDowngrade.secret === null);

    // Plain + K_row branches agree on the same empty-string round-trip.
    b.cryptoField.registerTable("cf_seam_plain_empty", { sealedFields: ["secret"] });
    var plainEmpty = _try(function () {
      var sealedEmpty = b.cryptoField.sealRow("cf_seam_plain_empty", { secret: "" });
      return b.cryptoField.unsealRow("cf_seam_plain_empty", sealedEmpty, "seam").secret;
    });
    check("plain table: an empty-string sealed field round-trips to '' (no throw)",
      plainEmpty.ok === true && plainEmpty.value === "");

    // A null / undefined sealed field is still skipped (pre-existing contract).
    var nullField = b.cryptoField.sealRow("cf_seam_plain_empty", { secret: null });
    check("a null sealed field is left null (skipped, not sealed)", nullField.secret === null);

    // --- type-fidelity codec: Buffer / object / array / number / boolean ---
    b.cryptoField.registerTable("cf_seam_types", {
      sealedFields: ["blob", "obj", "arr", "num", "flag", "selfesc"],
    });
    var blob = Buffer.from([0, 1, 2, 250, 255]);   // non-ASCII bytes, no literals
    var sealedTypes = b.cryptoField.sealRow("cf_seam_types", {
      blob: blob,
      obj:  { a: 1, b: [2, 3], s: "x" },
      arr:  [1, "two", 3],
      num:  42,
      flag: false,
      selfesc: "\x00bjsv1:evil",   // a string that itself begins with the codec sentinel
    });
    check("a Buffer sealed field is stored as a vault: envelope",
      typeof sealedTypes.blob === "string" && sealedTypes.blob.indexOf("vault:") === 0);
    var readTypes = b.cryptoField.unsealRow("cf_seam_types", Object.assign({}, sealedTypes), "seam");
    check("a Buffer round-trips byte-for-byte through a sealed column",
      Buffer.isBuffer(readTypes.blob) && readTypes.blob.equals(blob));
    check("an object round-trips through a sealed column",
      readTypes.obj && JSON.stringify(readTypes.obj) === JSON.stringify({ a: 1, b: [2, 3], s: "x" }));
    check("an array round-trips through a sealed column",
      Array.isArray(readTypes.arr) && JSON.stringify(readTypes.arr) === JSON.stringify([1, "two", 3]));
    check("a number keeps the String() contract through a sealed column", readTypes.num === "42");
    check("a boolean keeps the String() contract through a sealed column", readTypes.flag === "false");
    check("a string that itself begins with the codec sentinel round-trips verbatim (self-escape)",
      readTypes.selfesc === "\x00bjsv1:evil");

    // --- AAD copy-protection: cross-row / cross-column / cross-table refusal ---
    // The confidentiality guarantee: a cell AEAD-bound to (table,row,column)
    // can NEVER be unsealed under a different context. A seam that surfaced a
    // relocated cell would be a copy-paste confidentiality break.
    b.cryptoField.registerTable("cf_seam_ctx", {
      aad: true, sealedFields: ["c1", "c2"], rowIdField: "id",
    });
    b.cryptoField.registerTable("cf_seam_ctx_other", {
      aad: true, sealedFields: ["c1"], rowIdField: "id",
    });
    var sealed = b.cryptoField.sealRow("cf_seam_ctx", { id: "rowA", c1: "secret-c1", c2: "secret-c2" });
    check("an aad cell is stored as a vault.aad: envelope",
      typeof sealed.c1 === "string" && sealed.c1.indexOf("vault.aad:") === 0);

    var okRead = b.cryptoField.unsealRow("cf_seam_ctx", Object.assign({}, sealed), "seam");
    check("the correct (table,row,column) context decrypts both cells",
      okRead.c1 === "secret-c1" && okRead.c2 === "secret-c2");

    // Relocate c1's ciphertext into column c2 (same row): AAD column term differs.
    var wrongCol = b.cryptoField.unsealRow("cf_seam_ctx", { id: "rowA", c2: sealed.c1 }, "seam");
    check("a cell relocated to a DIFFERENT column is refused (nulled, never surfaced)",
      wrongCol.c2 === null);

    // Relocate c1's ciphertext onto a different rowId: AAD rowId term differs.
    var wrongRow = b.cryptoField.unsealRow("cf_seam_ctx", { id: "rowB", c1: sealed.c1 }, "seam");
    check("a cell relocated to a DIFFERENT row is refused (nulled)", wrongRow.c1 === null);

    // Read the same cell through a DIFFERENT table: AAD table term differs.
    var wrongTable = b.cryptoField.unsealRow("cf_seam_ctx_other", { id: "rowA", c1: sealed.c1 }, "seam");
    check("a cell read through a DIFFERENT table is refused (nulled)", wrongTable.c1 === null);

    // --- tamper: a single flipped ciphertext char fails AEAD verification ---
    var tamperedCell = sealed.c1.slice(0, -1) + (sealed.c1.slice(-1) === "A" ? "B" : "A");
    var tampered = b.cryptoField.unsealRow("cf_seam_ctx",
      { id: "rowA", c1: tamperedCell, c2: sealed.c2 }, "seam");
    check("a tampered aad cell fails verification and is nulled (never surfaces plaintext)",
      tampered.c1 === null);
    check("an untampered sibling cell on the same row still decrypts",
      tampered.c2 === "secret-c2");

    // --- config-time refusals: the rowId term of the AAD binding is required ---
    var aadNoRowId = _try(function () {
      return b.cryptoField.sealRow("cf_seam_ctx", { c1: "x" });   // no id column
    });
    check("sealRow refuses an aad table when the rowId column is missing",
      aadNoRowId.ok === false && aadNoRowId.err &&
      aadNoRowId.err.code === "crypto-field/seal-row-aad-rowid-missing");

    var kRowNoRowId = _try(function () {
      // K_row seal with no rowId / _id — cannot build the (table,rowId,column) AAD.
      return b.cryptoField.sealRow("cf_seam_plain_empty", { secret: "v" }, { kRow: Buffer.alloc(32) });
    });
    check("sealRow refuses a K_row seal with no rowId",
      kRowNoRowId.ok === false && kRowNoRowId.err &&
      kRowNoRowId.err.code === "crypto-field/seal-row-krow-rowid-missing");

    b.cryptoField.clearRateCapForTest();
  } finally {
    try { b.vault._resetForTest(); } catch (_e) { /* leave vault state clean for siblings */ }
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

// ---- the REAL consumer path: b.db insert/read across envelope types ----

async function testConsumerPathEmptyAndKRow() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cf-seam-db-"));
  try {
    await setupTestDb(dir, [
      {
        name:    "cf_seam_aad_db",
        columns: { _id: "TEXT PRIMARY KEY", secret: "TEXT", note: "TEXT" },
        aad:     true,
        sealedFields: ["secret", "note"],
        rowIdField:   "_id",
      },
      {
        name:    "cf_seam_krow_db",
        columns: { _id: "TEXT PRIMARY KEY", subjectId: "TEXT", ssn: "TEXT" },
        sealedFields: ["ssn"],
        subjectField: "subjectId",
      },
    ]);
    b.cryptoField.clearResidencyForTest();
    b.cryptoField.declarePerRowKey("cf_seam_krow_db", { keySize: 32 });

    // aad table, real write boundary: an empty-string sealed field must not
    // crash the insert (the pre-fix vault.aad.seal("") throw surfaced here).
    var insAad = _try(function () {
      return b.db.from("cf_seam_aad_db").insertOne({ _id: "a1", secret: "", note: "present" });
    });
    check("b.db.insertOne on an aad table does NOT crash on an empty-string sealed field",
      insAad.ok === true);
    if (insAad.ok) {
      var gotA = b.db.from("cf_seam_aad_db").where({ _id: "a1" }).first();
      check("aad-table insert round-trips the empty sealed field to ''", gotA && gotA.secret === "");
      check("aad-table insert round-trips the non-empty sibling sealed field", gotA && gotA.note === "present");
    }

    // per-row-key table, real write boundary: empty-string field round-trips too.
    var insKRow = _try(function () {
      return b.db.from("cf_seam_krow_db").insertOne({ _id: "k1", subjectId: "s1", ssn: "" });
    });
    check("b.db.insertOne on a per-row-key table does NOT crash on an empty-string sealed field",
      insKRow.ok === true);
    if (insKRow.ok) {
      var gotK = b.db.from("cf_seam_krow_db").where({ _id: "k1" }).first();
      check("per-row-key insert round-trips the empty sealed field to ''", gotK && gotK.ssn === "");
    }

    // control: a non-empty aad value is stored as a vault.aad: envelope on disk
    // and round-trips — the empty-string fix does not weaken real sealing.
    b.db.from("cf_seam_aad_db").insertOne({ _id: "a2", secret: "top-secret", note: "n" });
    var rawA2 = b.db.prepare('SELECT "secret" AS s FROM "cf_seam_aad_db" WHERE _id = ?').get("a2");
    check("a non-empty aad sealed value is stored as a vault.aad: envelope on disk",
      rawA2 && typeof rawA2.s === "string" && rawA2.s.indexOf("vault.aad:") === 0);
    var gotA2 = b.db.from("cf_seam_aad_db").where({ _id: "a2" }).first();
    check("a non-empty aad sealed value round-trips through the real read path",
      gotA2 && gotA2.secret === "top-secret");
  } finally {
    try { b.cryptoField.clearResidencyForTest(); } catch (_e) { /* best-effort */ }
    await teardownTestDb(dir);
  }
}

// ---- accessor / guard branches (no vault needed) ----

function testAccessorAndGuardBranches() {
  // isRowSealed — the K_row-prefix router the read path uses to pick the
  // K_row decrypt over the vault-root unseal. A non-string or a plain
  // vault: cell must NOT be routed as row-keyed.
  check("isRowSealed true for a vault.row: cell", b.cryptoField.isRowSealed("vault.row:AAAA") === true);
  check("isRowSealed false for a plain vault: cell", b.cryptoField.isRowSealed("vault:AAAA") === false);
  check("isRowSealed false for null", b.cryptoField.isRowSealed(null) === false);
  check("isRowSealed false for a number", b.cryptoField.isRowSealed(42) === false);

  // getSchema returns null (not undefined) for an unregistered table so a
  // backend can branch on it directly.
  check("getSchema returns null for an unregistered table",
    b.cryptoField.getSchema("cf_cov_never_registered_schema") === null);

  // sealRow / unsealRow are no-ops when the row is falsy or the table was
  // never registered — the storage backend calls them unconditionally.
  check("sealRow(null) returns the falsy row unchanged", b.cryptoField.sealRow("cf_cov_x", null) === null);
  check("unsealRow(null) returns the falsy row unchanged", b.cryptoField.unsealRow("cf_cov_x", null) === null);
  var passthruIn = { a: 1, b: "vault:whatever" };
  var sealedPassthru = b.cryptoField.sealRow("cf_cov_unregistered_table_zzz", passthruIn);
  check("sealRow on an unregistered table returns the row unchanged",
    sealedPassthru === passthruIn);
  var unsealPassthru = b.cryptoField.unsealRow("cf_cov_unregistered_table_zzz", passthruIn);
  check("unsealRow on an unregistered table returns the row unchanged",
    unsealPassthru === passthruIn);

  // applyPosture is a defensive guard: empty / non-string returns null WITHOUT
  // recording a posture (so it can't accidentally arm the erase-vacuum cascade).
  check("applyPosture('') returns null (no-op)", b.cryptoField.applyPosture("") === null);
  check("applyPosture(non-string) returns null (no-op)", b.cryptoField.applyPosture(42) === null);
  var posture = b.cryptoField.getActivePosture();
  check("getActivePosture is read-only (null or a string)",
    posture === null || typeof posture === "string");

  // registerTable rejects an unknown derived-hash mode at config time so a
  // typo can't silently index under a malformed digest.
  var badMode = _try(function () {
    return b.cryptoField.registerTable("cf_cov_badmode", { derivedHashMode: "md5" });
  });
  check("registerTable throws on an unknown derivedHashMode",
    badMode.ok === false && badMode.err && badMode.err.code === "crypto-field/bad-derived-hash-mode");
  var badColMode = _try(function () {
    return b.cryptoField.registerTable("cf_cov_badcolmode", {
      derivedHashes: { h: { from: "x", mode: "sha1" } },
    });
  });
  check("registerTable throws on an unknown per-column derived-hash mode",
    badColMode.ok === false && badColMode.err &&
    badColMode.err.code === "crypto-field/bad-derived-hash-col-mode");
}

// ---- column-residency write gate (CWE-178 case-insensitivity) ----

function testColumnResidencyGate() {
  b.cryptoField.declareColumnResidency("cf_cov_res", {
    columnResidency: { addressLine1: "eu", name: "global" },
  });
  check("getColumnResidency returns the declared map",
    JSON.stringify(b.cryptoField.getColumnResidency("cf_cov_res")) ===
    JSON.stringify({ addressLine1: "eu", name: "global" }));
  check("getColumnResidency returns null for an undeclared table",
    b.cryptoField.getColumnResidency("cf_cov_res_none") === null);

  // A region-bound column on a mismatched backend is refused with the full
  // want/got refusal shape the storage backend wraps in its own error.
  var refuse = b.cryptoField.assertColumnResidency("cf_cov_res",
    { id: 1, addressLine1: "10 Rue de Rivoli" }, { backendTag: "us" });
  check("assertColumnResidency refuses an eu column landing on a us backend",
    refuse && refuse.error === "column-residency-mismatch" && refuse.column === "addressLine1" &&
    refuse.want === "eu" && refuse.got === "us");

  // The matching backend passes.
  check("assertColumnResidency passes an eu column on an eu backend",
    b.cryptoField.assertColumnResidency("cf_cov_res",
      { id: 1, addressLine1: "10 Rue de Rivoli" }, { backendTag: "eu" }) === null);

  // A "global" column and an "unrestricted" backend both pass any backend.
  check("assertColumnResidency passes a global column on any backend",
    b.cryptoField.assertColumnResidency("cf_cov_res",
      { id: 1, name: "Alice" }, { backendTag: "us" }) === null);
  check("assertColumnResidency passes an eu column on an unrestricted backend",
    b.cryptoField.assertColumnResidency("cf_cov_res",
      { id: 1, addressLine1: "x" }, { backendTag: "unrestricted" }) === null);

  // CWE-178: a raw-SQL-parsed row can differ in column case; the gate resolves
  // case-insensitively so a differently-cased column cannot skip the check.
  var refuseCase = b.cryptoField.assertColumnResidency("cf_cov_res",
    { id: 1, ADDRESSLINE1: "10 Rue de Rivoli" }, { backendTag: "us" });
  check("assertColumnResidency resolves the mapped column case-insensitively (CWE-178)",
    refuseCase && refuseCase.error === "column-residency-mismatch" && refuseCase.column === "addressLine1");

  // A null / absent cell is skipped (nothing to place).
  check("assertColumnResidency skips a null cell",
    b.cryptoField.assertColumnResidency("cf_cov_res",
      { id: 1, addressLine1: null }, { backendTag: "us" }) === null);
  check("assertColumnResidency returns null for an undeclared table",
    b.cryptoField.assertColumnResidency("cf_cov_res_none", { addressLine1: "x" }, { backendTag: "us" }) === null);

  // Config-time fail-loud on malformed declarations.
  check("declareColumnResidency throws on an empty table name",
    _try(function () { return b.cryptoField.declareColumnResidency("", { columnResidency: {} }); })
      .err.code === "crypto-field/residency-table-empty");
  check("declareColumnResidency throws when opts is not an object",
    _try(function () { return b.cryptoField.declareColumnResidency("cf_cov_res2", null); })
      .err.code === "crypto-field/residency-opts-not-object");
  check("declareColumnResidency throws when columnResidency is not an object",
    _try(function () { return b.cryptoField.declareColumnResidency("cf_cov_res2", { columnResidency: 5 }); })
      .err.code === "crypto-field/residency-map-not-object");
  check("declareColumnResidency throws on an empty residency tag",
    _try(function () { return b.cryptoField.declareColumnResidency("cf_cov_res2", { columnResidency: { c: "" } }); })
      .err.code === "crypto-field/residency-tag-empty");
}

// ---- per-row residency + per-row-key config guards, eraseRow tombstone ----

function testPerRowConfigGuardsAndErase() {
  // Per-row residency: the residency tag column must stay plaintext, so
  // declaring it on top of a sealed column is refused at config time.
  b.cryptoField.registerTable("cf_cov_prr", { sealedFields: ["region", "ssn"] });
  check("declarePerRowResidency refuses a sealed residency column",
    _try(function () {
      return b.cryptoField.declarePerRowResidency("cf_cov_prr", {
        residencyColumn: "region", allowedTags: ["eu", "global"],
      });
    }).err.code === "crypto-field/per-row-residency-sealed-conflict");
  check("declarePerRowResidency refuses an empty allowedTags array",
    _try(function () {
      return b.cryptoField.declarePerRowResidency("cf_cov_prr2", {
        residencyColumn: "dataRegion", allowedTags: [],
      });
    }).err.code === "crypto-field/per-row-residency-tags-invalid");

  var prrSpec = b.cryptoField.declarePerRowResidency("cf_cov_prr3", {
    residencyColumn: "dataRegion", allowedTags: ["eu-west-1", "global"],
  });
  check("declarePerRowResidency returns the declared spec",
    prrSpec.residencyColumn === "dataRegion" && prrSpec.allowedTags.length === 2);
  check("getPerRowResidency returns a copy of the spec",
    b.cryptoField.getPerRowResidency("cf_cov_prr3").residencyColumn === "dataRegion");
  check("getPerRowResidency returns null for an undeclared table",
    b.cryptoField.getPerRowResidency("cf_cov_prr_none") === null);
  var listed = b.cryptoField.listPerRowResidency();
  check("listPerRowResidency includes the declared table",
    Array.isArray(listed) && listed.some(function (e) {
      return e.table === "cf_cov_prr3" && e.residencyColumn === "dataRegion";
    }));

  // declarePerRowKey validation — config-time fail-loud on bad sizing.
  check("declarePerRowKey throws on an empty table name",
    _try(function () { return b.cryptoField.declarePerRowKey("", {}); })
      .err.code === "crypto-field/per-row-key-table-empty");
  check("declarePerRowKey throws on a keySize below the 16-byte minimum",
    _try(function () { return b.cryptoField.declarePerRowKey("cf_cov_pk", { keySize: 8 }); })
      .err.code === "crypto-field/per-row-key-bad-size");
  check("declarePerRowKey throws on a non-integer keySize",
    _try(function () { return b.cryptoField.declarePerRowKey("cf_cov_pk", { keySize: 16.5 }); })
      .err.code === "crypto-field/per-row-key-bad-size");
  check("declarePerRowKey throws on a non-numeric keySize",
    _try(function () { return b.cryptoField.declarePerRowKey("cf_cov_pk", { keySize: "32" }); })
      .err.code === "crypto-field/per-row-key-bad-size");
  check("declarePerRowKey throws on a non-string info label",
    _try(function () { return b.cryptoField.declarePerRowKey("cf_cov_pk", { info: 123 }); })
      .err.code === "crypto-field/per-row-key-info-empty");

  check("hasPerRowKey false before declaration", b.cryptoField.hasPerRowKey("cf_cov_pk_ok") === false);
  var pkSpec = b.cryptoField.declarePerRowKey("cf_cov_pk_ok");   // default keySize 32
  check("declarePerRowKey defaults keySize to 32", pkSpec.keySize === 32);
  check("declarePerRowKey defaults the info label to the table namespace",
    pkSpec.info === "blamejs-per-row-key:cf_cov_pk_ok");
  check("hasPerRowKey true after declaration", b.cryptoField.hasPerRowKey("cf_cov_pk_ok") === true);

  // materialize / destroy require a db handle — the guard branches throw or
  // no-op WITHOUT touching crypto when the table isn't keyed or no handle is
  // passed.
  check("materializePerRowKey returns null for a non-keyed table",
    b.cryptoField.materializePerRowKey("cf_cov_not_keyed", "r1", {}) === null);
  check("materializePerRowKey throws when no db handle is supplied",
    _try(function () { return b.cryptoField.materializePerRowKey("cf_cov_pk_ok", "r1"); })
      .err.code === "crypto-field/materialize-per-row-key-no-db");
  check("destroyPerRowKey no-ops (destroyed:0) for a non-keyed table",
    b.cryptoField.destroyPerRowKey("cf_cov_not_keyed", "r1", {}).destroyed === 0);
  check("destroyPerRowKey throws when no db handle is supplied",
    _try(function () { return b.cryptoField.destroyPerRowKey("cf_cov_pk_ok", "r1"); })
      .err.code === "crypto-field/destroy-per-row-key-no-db");

  // eraseRow tombstone: sealed columns + derived-hash mirrors NULLed, a
  // 1-day-bucketed __erasedAt stamped, non-sealed columns preserved.
  b.cryptoField.registerTable("cf_cov_erase", {
    sealedFields: ["ssn"], derivedHashes: { ssnHash: { from: "ssn" } },
  });
  check("eraseRow(null) returns the falsy row", b.cryptoField.eraseRow("cf_cov_erase", null) === null);
  var eraseInput = { id: 7, ssn: "vault:whatever", ssnHash: "deadbeef", keep: "retained" };
  var erased = b.cryptoField.eraseRow("cf_cov_erase", eraseInput);
  check("eraseRow NULLs the sealed column", erased.ssn === null);
  check("eraseRow NULLs the derived-hash mirror", erased.ssnHash === null);
  check("eraseRow preserves non-sealed columns", erased.keep === "retained");
  check("eraseRow stamps a numeric __erasedAt", typeof erased.__erasedAt === "number");
  check("eraseRow buckets __erasedAt to a 1-day floor (UTC ms)", erased.__erasedAt % (24 * 60 * 60 * 1000) === 0);
  check("eraseRow does not mutate the input row", eraseInput.ssn === "vault:whatever");
  check("eraseRow on an unregistered table returns the row unchanged",
    b.cryptoField.eraseRow("cf_cov_erase_none", eraseInput) === eraseInput);
}

// ---- malformed envelopes + Uint8Array type fidelity (vault-backed) ----

async function testMalformedEnvelopesFailClosed() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cf-malformed-"));
  try {
    try { b.vault._resetForTest(); } catch (_e) { /* fresh init below */ }
    await b.vault.init({ dataDir: tmp, mode: "plaintext" });
    b.cryptoField.clearRateCapForTest();

    // A DB-write attacker forges a garbage vault: payload into a sealed
    // column. unsealRow must fail closed (null the cell), never crash the
    // read and never surface the attacker-crafted string.
    b.cryptoField.registerTable("cf_cov_malformed", { sealedFields: ["x"] });
    var garbage = _try(function () {
      return b.cryptoField.unsealRow("cf_cov_malformed",
        { id: 1, x: "vault:not-valid-base64-@@@" }, "seam");
    });
    check("unsealRow does not throw on a malformed vault: envelope", garbage.ok === true);
    check("unsealRow nulls a malformed vault: envelope (fail closed, never surfaced)",
      garbage.value.x === null);

    // A malformed vault.aad: envelope on an aad table likewise fails closed.
    b.cryptoField.registerTable("cf_cov_malformed_aad", {
      aad: true, sealedFields: ["x"], rowIdField: "id",
    });
    var garbageAad = _try(function () {
      return b.cryptoField.unsealRow("cf_cov_malformed_aad",
        { id: "rowA", x: "vault.aad:garbage-not-a-real-envelope" }, "seam");
    });
    check("unsealRow does not throw on a malformed vault.aad: envelope", garbageAad.ok === true);
    check("unsealRow nulls a malformed vault.aad: envelope (fail closed)", garbageAad.value.x === null);

    // AAD-downgrade refusal: a plain (unbound) vault: cell on an aad table is a
    // relocatable-seal downgrade — refused (nulled), not surfaced. Build a real
    // plain vault: cell on a separate plain table, then read it through the aad
    // table's context.
    b.cryptoField.registerTable("cf_cov_plainsrc", { sealedFields: ["x"] });
    var plainCell = b.cryptoField.sealRow("cf_cov_plainsrc", { x: "leaked" }).x;
    check("control: the source plain cell is a vault: (unbound) envelope",
      typeof plainCell === "string" && plainCell.indexOf("vault:") === 0);
    var downgrade = b.cryptoField.unsealRow("cf_cov_malformed_aad",
      { id: "rowA", x: plainCell }, "seam");
    check("unsealRow refuses a plain vault: cell on an aad table (downgrade nulled)",
      downgrade.x === null);

    // Type fidelity: a plain Uint8Array (not a Buffer) round-trips as bytes —
    // the distinct _encodeTyped Uint8Array branch, separate from Buffer.
    b.cryptoField.registerTable("cf_cov_u8", { sealedFields: ["bytes"] });
    var u8 = new Uint8Array([0, 9, 250, 255, 1]);
    var sealedU8 = b.cryptoField.sealRow("cf_cov_u8", { bytes: u8 });
    check("a Uint8Array sealed field is stored as a vault: envelope",
      typeof sealedU8.bytes === "string" && sealedU8.bytes.indexOf("vault:") === 0);
    var readU8 = b.cryptoField.unsealRow("cf_cov_u8", Object.assign({}, sealedU8), "seam");
    check("a Uint8Array round-trips byte-for-byte (as a Buffer) through a sealed column",
      Buffer.isBuffer(readU8.bytes) && readU8.bytes.equals(Buffer.from(u8)));

    b.cryptoField.clearRateCapForTest();
  } finally {
    try { b.vault._resetForTest(); } catch (_e) { /* leave vault state clean for siblings */ }
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

async function run() {
  testReturnsDeclaredSealedFields();
  testUnregisteredTableIsEmpty();
  testTableWithNoSealedColumns();
  testPreservesDeclarationOrder();
  testAccessorAndGuardBranches();
  testColumnResidencyGate();
  testPerRowConfigGuardsAndErase();
  await testSealUnsealSeams();
  await testConsumerPathEmptyAndKRow();
  await testMalformedEnvelopesFailClosed();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("[crypto-field] OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
