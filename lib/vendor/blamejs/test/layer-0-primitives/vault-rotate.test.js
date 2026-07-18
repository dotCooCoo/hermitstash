// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.vaultRotate — error / adversarial / defensive / option-default branches.
 *
 * Covers the diagnostic surface (validateSchemaMatch / verify /
 * formatValidationResult) and the rotation pipeline's fail-closed guards
 * (missing keys / dataDir / stagingDir, bad mode, wrapped-without-passphrase,
 * the external-AAD detect-and-refuse gate) plus the plaintext + wrapped
 * key-write paths and a full plaintext keypair rotation end-to-end.
 *
 * The diagnostics run against an in-memory node:sqlite handle seeded with
 * vault-prefixed cells produced under two distinct hybrid keypairs — the
 * exact object shape an operator holds when running a pre/post-rotation
 * sweep on a decrypted DB. No real KMS: sealed cells come from
 * b.crypto.encrypt under keypairs from b.crypto.generateEncryptionKeyPair.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var fs      = helpers.fs;
var os      = helpers.os;
var path    = helpers.path;
var check   = helpers.check;

var { DatabaseSync } = require("node:sqlite");

var VAULT_PREFIX = b.constants.VAULT_PREFIX;

// Two distinct hybrid recipient keypairs. keyA is the "old" root, keyB the
// "new"/foreign root. Each doubles as publicKeys (encrypt) and privateKeys
// (decrypt), exactly as the rotation pipeline threads oldKeys/newKeys.
var keyA = b.crypto.generateEncryptionKeyPair();
var keyB = b.crypto.generateEncryptionKeyPair();

function _seal(plain, keys) {
  return VAULT_PREFIX + b.crypto.encrypt(plain, keys);
}

// Build an in-memory sqlite handle with one DDL + inserted rows. The handle
// is the real object validateSchemaMatch/verify consume; caller closes it.
function _memDb(ddl, inserts) {
  var db = new DatabaseSync(":memory:");
  db.prepare(ddl).run();
  for (var i = 0; i < (inserts || []).length; i++) {
    var ins = inserts[i];
    var stmt = db.prepare(ins.sql);
    stmt.run.apply(stmt, ins.params);
  }
  return db;
}

// ---------------------------------------------------------------------------
// verify — input-validation fail-closed branches
// ---------------------------------------------------------------------------
function testVerifyRequiresKeys() {
  var threw = null;
  try { b.vaultRotate.verify({}); } catch (e) { threw = e; }
  check("verify refuses when opts.keys absent",
    !!threw && threw.code === "vault-rotate/no-keys");
  // No-arg call exercises the `opts = opts || {}` default.
  var threw2 = null;
  try { b.vaultRotate.verify(); } catch (e) { threw2 = e; }
  check("verify with no arguments refuses (opts default)",
    !!threw2 && threw2.code === "vault-rotate/no-keys");
}

function testVerifyRequiresDb() {
  var threw = null;
  try { b.vaultRotate.verify({ keys: keyA }); } catch (e) { threw = e; }
  check("verify refuses when opts.db absent",
    !!threw && threw.code === "vault-rotate/no-db");
}

function testVerifyRejectsNonHandleDb() {
  var threw = null;
  // An object without a prepare() method is not a node:sqlite handle.
  try { b.vaultRotate.verify({ keys: keyA, db: { query: function () {} } }); }
  catch (e) { threw = e; }
  check("verify refuses a db without prepare()",
    !!threw && threw.code === "vault-rotate/no-db");
}

function testVerifyRejectsBadSampleMin() {
  var db = _memDb("CREATE TABLE t (_id TEXT PRIMARY KEY, secret TEXT)", []);
  try {
    var threw = null;
    try { b.vaultRotate.verify({ keys: keyA, db: db, sampleMin: -3 }); }
    catch (e) { threw = e; }
    check("verify refuses a negative sampleMin",
      !!threw && threw.code === "vault-rotate/bad-opt");
  } finally { db.close(); }
}

function testVerifyRejectsBadSamplePercent() {
  var db = _memDb("CREATE TABLE t (_id TEXT PRIMARY KEY, secret TEXT)", []);
  try {
    var bad = [0, -0.5, NaN, Infinity, "10%"];
    for (var i = 0; i < bad.length; i++) {
      var threw = null;
      try { b.vaultRotate.verify({ keys: keyA, db: db, samplePercent: bad[i] }); }
      catch (e) { threw = e; }
      check("verify refuses samplePercent=" + String(bad[i]),
        !!threw && threw.code === "vault-rotate/bad-opt");
    }
  } finally { db.close(); }
}

// ---------------------------------------------------------------------------
// verify — diagnostic behaviour
// ---------------------------------------------------------------------------
function _seedSecretsDb(sealedValue, extraCols) {
  b.cryptoField.clearForTest();
  b.cryptoField.registerTable("secrets", { sealedFields: ["secret"] });
  var ddl = "CREATE TABLE secrets (_id TEXT PRIMARY KEY, secret TEXT" +
    (extraCols ? ", " + extraCols : "") + ")";
  return _memDb(ddl, [{
    sql: "INSERT INTO secrets (_id, secret) VALUES (?, ?)",
    params: ["r1", sealedValue],
  }]);
}

function testVerifyPassesUnderMatchingKey() {
  var db = _seedSecretsDb(_seal("hello", keyA));
  try {
    // Explicit valid sampleMin + samplePercent exercise the option-present
    // ternaries (not the defaults).
    var res = b.vaultRotate.verify({ keys: keyA, db: db, sampleMin: 3, samplePercent: 0.5 });
    check("verify ok when the cell decrypts under keys", res.ok === true);
    check("verify records the verified table", res.passed.length === 1 &&
      res.passed[0].table === "secrets" && res.passed[0].verified === 1);
    check("verify reports no failures/regressions",
      res.failures.length === 0 && res.regressions.length === 0);
  } finally { db.close(); b.cryptoField.clearForTest(); }
}

function testVerifyFlagsDecryptFailure() {
  var db = _seedSecretsDb(_seal("hello", keyA));
  try {
    // Sealed under keyA, verified under keyB — decrypt must fail.
    var res = b.vaultRotate.verify({ keys: keyB, db: db });
    check("verify not ok when the cell fails to decrypt under keys", res.ok === false);
    check("verify records the decrypt failure",
      res.failures.length === 1 && res.failures[0].table === "secrets");
  } finally { db.close(); b.cryptoField.clearForTest(); }
}

function testVerifyFlagsRegressionWhenOldKeysStillDecrypt() {
  var db = _seedSecretsDb(_seal("hello", keyA));
  try {
    // keys==oldKeys==keyA: the cell decrypts under both, so the old root
    // "still decrypts" → rotation-did-not-take-effect regression.
    var res = b.vaultRotate.verify({ keys: keyA, db: db, oldKeys: keyA });
    check("verify not ok when old keys still decrypt", res.ok === false);
    check("verify records the regression",
      res.regressions.length === 1 &&
      /rotation did not take effect/.test(res.regressions[0].error));
  } finally { db.close(); b.cryptoField.clearForTest(); }
}

function testVerifyRotationEffectiveWithOldKeys() {
  var db = _seedSecretsDb(_seal("hello", keyB));
  try {
    // Sealed under the NEW root (keyB); old root (keyA) no longer decrypts,
    // so foundOldFail flips and no regression is recorded.
    var res = b.vaultRotate.verify({ keys: keyB, db: db, oldKeys: keyA });
    check("verify ok when new root decrypts and old root is rejected", res.ok === true);
    check("verify records no regression once old root fails", res.regressions.length === 0);
  } finally { db.close(); b.cryptoField.clearForTest(); }
}

function testVerifySkipsNonStringAndUnprefixedCells() {
  b.cryptoField.clearForTest();
  b.cryptoField.registerTable("secrets", { sealedFields: ["secret"] });
  var db = _memDb("CREATE TABLE secrets (_id TEXT PRIMARY KEY, secret TEXT)", [
    { sql: "INSERT INTO secrets (_id, secret) VALUES (?, ?)", params: ["nul", null] },
    { sql: "INSERT INTO secrets (_id, secret) VALUES (?, ?)", params: ["plain", "not-a-vault-value"] },
  ]);
  try {
    var res = b.vaultRotate.verify({ keys: keyA, db: db });
    check("verify skips NULL / non-vault-prefixed cells with no failure",
      res.ok === true && res.failures.length === 0);
    check("verify counts the sampled rows as verified", res.passed.length === 1 &&
      res.passed[0].verified === 2);
  } finally { db.close(); b.cryptoField.clearForTest(); }
}

function testVerifySkipsEmptyAndUnregisteredAndMissingTables() {
  b.cryptoField.clearForTest();
  b.cryptoField.registerTable("secrets", { sealedFields: ["secret"] });
  // 'secrets' registered but empty; 'plainrows' unregistered.
  var db = _memDb("CREATE TABLE secrets (_id TEXT PRIMARY KEY, secret TEXT)", []);
  db.prepare("CREATE TABLE plainrows (_id TEXT PRIMARY KEY, v TEXT)").run();
  db.prepare("INSERT INTO plainrows (_id, v) VALUES ('p1', 'x')").run();
  try {
    // opts.tables includes a table that does not exist in the DB → skipped.
    var res = b.vaultRotate.verify({ keys: keyA, db: db,
      tables: ["secrets", "plainrows", "ghost_table"] });
    check("verify skips empty + unregistered + missing tables → ok, nothing passed",
      res.ok === true && res.passed.length === 0);
  } finally { db.close(); b.cryptoField.clearForTest(); }
}

function testVerifyDecryptsAadCells() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "vr-aadverify-"));
  var db1 = null, db2 = null;
  return helpers.setupVaultOnly(dir).then(function () {
    b.cryptoField.clearForTest();
    b.cryptoField.registerTable("aadsecrets", { sealedFields: ["secret"], aad: true, rowIdField: "_id" });
    var sealedRow = b.cryptoField.sealRow("aadsecrets", { _id: "a1", secret: "aad-secret-value" });
    check("cryptoField.sealRow produced a vault.aad: cell",
      typeof sealedRow.secret === "string" && sealedRow.secret.indexOf("vault.aad:") === 0);
    var keys = JSON.parse(b.vault.getKeysJson());

    // DB1 — one good AAD cell: decrypts under the matching root, and with
    // oldKeys==keys the old root "still opens" it → regression.
    db1 = _memDb("CREATE TABLE aadsecrets (_id TEXT PRIMARY KEY, secret TEXT)", [
      { sql: "INSERT INTO aadsecrets (_id, secret) VALUES (?, ?)", params: ["a1", sealedRow.secret] },
    ]);
    var good = b.vaultRotate.verify({ keys: keys, db: db1 });
    check("verify decrypts an AAD cell under the matching root",
      good.ok === true && good.passed.length === 1 && good.passed[0].verified === 1);
    var regr = b.vaultRotate.verify({ keys: keys, db: db1, oldKeys: keys });
    check("verify flags an AAD regression when the old root still opens the cell",
      regr.ok === false && regr.regressions.length === 1);

    // DB2 — a corrupted AAD cell (prefix intact, tail mangled) fails to open.
    var corrupt = sealedRow.secret.slice(0, -8) + "AAAAAAAA";
    db2 = _memDb("CREATE TABLE aadsecrets (_id TEXT PRIMARY KEY, secret TEXT)", [
      { sql: "INSERT INTO aadsecrets (_id, secret) VALUES (?, ?)", params: ["a2", corrupt] },
    ]);
    var bad = b.vaultRotate.verify({ keys: keys, db: db2 });
    check("verify flags an AAD decrypt failure for a corrupted cell",
      bad.ok === false && bad.failures.length === 1);
  }).then(function () {
    if (db1) db1.close();
    if (db2) db2.close();
    b.cryptoField.clearForTest();
    helpers.teardownVaultOnly(dir);
  }, function (e) {
    if (db1) db1.close();
    if (db2) db2.close();
    b.cryptoField.clearForTest();
    helpers.teardownVaultOnly(dir);
    throw e;
  });
}

// ---------------------------------------------------------------------------
// validateSchemaMatch — option-default, defensive + warning/error branches
// ---------------------------------------------------------------------------
function testValidateRejectsBadDriftSampleLimit() {
  var db = _memDb("CREATE TABLE secrets (_id TEXT PRIMARY KEY, secret TEXT)", []);
  try {
    var threw = null;
    try { b.vaultRotate.validateSchemaMatch(db, { driftSampleLimit: 0 }); }
    catch (e) { threw = e; }
    check("validateSchemaMatch refuses a non-positive driftSampleLimit",
      !!threw && threw.code === "vault-rotate/bad-opt");
  } finally { db.close(); }
}

function testValidateCleanSchemaHasNoWarningsOrErrors() {
  b.cryptoField.clearForTest();
  b.cryptoField.registerTable("secrets", { sealedFields: ["secret"] });
  var db = _memDb("CREATE TABLE secrets (_id TEXT PRIMARY KEY, secret TEXT)", [
    { sql: "INSERT INTO secrets (_id, secret) VALUES (?, ?)", params: ["r1", _seal("x", keyA)] },
  ]);
  try {
    // secret is declared sealed; _id is the primary key (unknown column) but
    // holds no vault-prefixed value → no drift.
    var res = b.vaultRotate.validateSchemaMatch(db);
    check("validateSchemaMatch clean → no warnings", res.warnings.length === 0);
    check("validateSchemaMatch clean → no errors", res.errors.length === 0);
  } finally { db.close(); b.cryptoField.clearForTest(); }
}

function testValidateTreatsDerivedHashColumnsAsKnown() {
  b.cryptoField.clearForTest();
  // A derived-hash column (emailHash from email) + its source column are both
  // "known" to the drift detector even though neither is a sealedField.
  b.cryptoField.registerTable("people", {
    sealedFields:  ["email"],
    derivedHashes: { emailHash: { from: "email", normalize: function (v) { return String(v).toLowerCase(); } } },
  });
  // emailHash holds a hash (not vault-prefixed) and email holds a sealed cell;
  // a genuinely-undeclared 'rogue' column holds a vault-prefixed value.
  var db = _memDb(
    "CREATE TABLE people (_id TEXT PRIMARY KEY, email TEXT, emailHash TEXT, rogue TEXT)", [
      { sql: "INSERT INTO people (_id, email, emailHash, rogue) VALUES (?, ?, ?, ?)",
        params: ["p1", _seal("a@b.c", keyA), "deadbeef", _seal("leak", keyA)] },
    ]);
  try {
    var res = b.vaultRotate.validateSchemaMatch(db);
    // emailHash + email are known (no drift); only 'rogue' is flagged.
    check("validateSchemaMatch treats derivedHash + source columns as known",
      res.errors.length === 1 && res.errors[0].column === "rogue");
  } finally { db.close(); b.cryptoField.clearForTest(); }
}

function testValidateWarnsOnMissingTable() {
  b.cryptoField.clearForTest();
  var db = _memDb("CREATE TABLE secrets (_id TEXT PRIMARY KEY, secret TEXT)", []);
  try {
    var res = b.vaultRotate.validateSchemaMatch(db, { tables: ["ghost"] });
    check("validateSchemaMatch warns table_missing for a schema-only table",
      res.warnings.length === 1 && res.warnings[0].kind === "table_missing" &&
      res.warnings[0].table === "ghost");
    check("validateSchemaMatch missing table is non-fatal (no errors)", res.errors.length === 0);
  } finally { db.close(); b.cryptoField.clearForTest(); }
}

function testValidateWarnsOnMissingSealedColumn() {
  b.cryptoField.clearForTest();
  // Declare a sealed column ('ssn') the live table lacks.
  b.cryptoField.registerTable("secrets", { sealedFields: ["secret", "ssn"] });
  var db = _memDb("CREATE TABLE secrets (_id TEXT PRIMARY KEY, secret TEXT)", []);
  try {
    var res = b.vaultRotate.validateSchemaMatch(db, { tables: ["secrets"] });
    check("validateSchemaMatch warns sealed_col_missing for an absent sealed column",
      res.warnings.some(function (w) {
        return w.kind === "sealed_col_missing" && w.column === "ssn";
      }));
  } finally { db.close(); b.cryptoField.clearForTest(); }
}

function testValidateDetectsDriftInUndeclaredColumn() {
  b.cryptoField.clearForTest();
  b.cryptoField.registerTable("secrets", { sealedFields: ["secret"] });
  // 'rogue' is not declared sealed but holds a vault-prefixed value. Two
  // drifting rows exercise the "column already flagged" fast-path continue.
  var db = _memDb("CREATE TABLE secrets (_id TEXT PRIMARY KEY, secret TEXT, rogue TEXT)", [
    { sql: "INSERT INTO secrets (_id, secret, rogue) VALUES (?, ?, ?)",
      params: ["r1", _seal("x", keyA), _seal("leak", keyA)] },
    { sql: "INSERT INTO secrets (_id, secret, rogue) VALUES (?, ?, ?)",
      params: ["r2", _seal("y", keyA), _seal("leak2", keyA)] },
  ]);
  try {
    // A valid driftSampleLimit exercises the option-present ternary.
    var res = b.vaultRotate.validateSchemaMatch(db, { driftSampleLimit: 50 });
    check("validateSchemaMatch flags drift once per undeclared vault-prefixed column",
      res.errors.length === 1 && res.errors[0].kind === "drift" &&
      res.errors[0].column === "rogue");
  } finally { db.close(); b.cryptoField.clearForTest(); }
}

function testValidateInfraColumnsSuppressesDrift() {
  b.cryptoField.clearForTest();
  b.cryptoField.registerTable("secrets", { sealedFields: ["secret"] });
  var db = _memDb("CREATE TABLE secrets (_id TEXT PRIMARY KEY, secret TEXT, rogue TEXT)", [
    { sql: "INSERT INTO secrets (_id, secret, rogue) VALUES (?, ?, ?)",
      params: ["r1", _seal("x", keyA), _seal("leak", keyA)] },
  ]);
  try {
    // Operator declares 'rogue' as an intentionally-unsealed infra column.
    var res = b.vaultRotate.validateSchemaMatch(db, { infraColumns: ["rogue", "_id"] });
    check("validateSchemaMatch infraColumns allowlist suppresses the drift error",
      res.errors.length === 0);
  } finally { db.close(); b.cryptoField.clearForTest(); }
}

function testValidateIgnoresNonArrayInfraColumns() {
  b.cryptoField.clearForTest();
  b.cryptoField.registerTable("secrets", { sealedFields: ["secret"] });
  var db = _memDb("CREATE TABLE secrets (_id TEXT PRIMARY KEY, secret TEXT, rogue TEXT)", [
    { sql: "INSERT INTO secrets (_id, secret, rogue) VALUES (?, ?, ?)",
      params: ["r1", _seal("x", keyA), _seal("leak", keyA)] },
  ]);
  try {
    // A non-array infraColumns is coerced to [] (defensive) — drift still fires.
    var res = b.vaultRotate.validateSchemaMatch(db, { infraColumns: "rogue" });
    check("validateSchemaMatch coerces a non-array infraColumns to [] and still flags drift",
      res.errors.length === 1 && res.errors[0].column === "rogue");
  } finally { db.close(); b.cryptoField.clearForTest(); }
}

// ---------------------------------------------------------------------------
// formatValidationResult
// ---------------------------------------------------------------------------
function testFormatValidationResultRenders() {
  var okLine = b.vaultRotate.formatValidationResult({ warnings: [], errors: [] });
  check("formatValidationResult renders the OK line for a clean result",
    okLine === "[vault-rotate] schema match: OK");

  var warnOnly = b.vaultRotate.formatValidationResult({
    warnings: [{ message: "w1" }], errors: [],
  });
  check("formatValidationResult renders warnings-only",
    /schema warnings \(1/.test(warnOnly) && /- w1/.test(warnOnly));

  var withErrors = b.vaultRotate.formatValidationResult({
    warnings: [{ message: "w1" }], errors: [{ message: "e1" }],
  });
  check("formatValidationResult renders the FATAL error section",
    /FATAL/.test(withErrors) && /- e1/.test(withErrors));
}

// ---------------------------------------------------------------------------
// rotate — fail-closed guards (throw BEFORE any filesystem work)
// ---------------------------------------------------------------------------
async function _expectRotateThrow(label, opts, code) {
  var threw = null;
  try { await b.vaultRotate.rotate(opts); } catch (e) { threw = e; }
  check(label + " (code " + code + ")", !!threw && threw.code === code);
}

async function testRotateGuardsRequiredArgs() {
  var dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "vr-guard-"));
  try {
    // No-arg call exercises the `opts = opts || {}` default before the keys guard.
    var threwNoArg = null;
    try { await b.vaultRotate.rotate(); } catch (e) { threwNoArg = e; }
    check("rotate with no arguments refuses (opts default → no-keys)",
      !!threwNoArg && threwNoArg.code === "vault-rotate/no-keys");
    await _expectRotateThrow("rotate refuses missing keys",
      { dataDir: dataDir }, "vault-rotate/no-keys");
    await _expectRotateThrow("rotate refuses a non-existent dataDir",
      { oldKeys: keyA, newKeys: keyB, dataDir: path.join(dataDir, "nope") },
      "vault-rotate/no-datadir");
    await _expectRotateThrow("rotate refuses a missing stagingDir",
      { oldKeys: keyA, newKeys: keyB, dataDir: dataDir },
      "vault-rotate/no-staging");
    await _expectRotateThrow("rotate refuses a pre-existing stagingDir",
      { oldKeys: keyA, newKeys: keyB, dataDir: dataDir, stagingDir: dataDir },
      "vault-rotate/staging-exists");
    await _expectRotateThrow("rotate refuses an unknown mode",
      { oldKeys: keyA, newKeys: keyB, dataDir: dataDir,
        stagingDir: path.join(dataDir, "stg1"), mode: "sideways" },
      "vault-rotate/bad-mode");
    await _expectRotateThrow("rotate refuses wrapped mode without a passphrase Buffer",
      { oldKeys: keyA, newKeys: keyB, dataDir: dataDir,
        stagingDir: path.join(dataDir, "stg2"), mode: "wrapped" },
      "vault-rotate/no-passphrase");
  } finally {
    try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* cleanup */ }
  }
}

async function testRotateRefusesUnacknowledgedExternalAad() {
  var dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "vr-ext-"));
  var staging = path.join(os.tmpdir(), "vr-ext-stg-" + process.pid + "-" + Date.now());
  try {
    // This process can load the agent AAD modules, so the external-AAD gate
    // has tables to protect. Without acknowledgement rotate must refuse.
    var gated = b.vaultRotate._externalAadTables();
    check("external-AAD gate lists operator-supplied stores", gated.length > 0);
    await _expectRotateThrow("rotate refuses unacknowledged external-AAD stores",
      { oldKeys: keyA, newKeys: keyB, dataDir: dataDir, stagingDir: staging, mode: "plaintext" },
      "vault-rotate/external-aad-unresealed");
    check("external-AAD refusal left no staging dir behind", !fs.existsSync(staging));
  } finally {
    try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* cleanup */ }
    try { fs.rmSync(staging, { recursive: true, force: true }); } catch (_e) { /* cleanup */ }
  }
}

// ---------------------------------------------------------------------------
// rotate — key-write pipeline on a dataDir with no db.enc (plaintext + wrapped)
// ---------------------------------------------------------------------------
async function testRotatePlaintextKeyWriteNoDb() {
  var dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "vr-pt-"));
  var staging = path.join(os.tmpdir(), "vr-pt-stg-" + process.pid + "-" + Date.now());
  var phases = [];
  try {
    // Acknowledge via the explicit table array (exercises the array-ack branch)
    // and pass a progress callback that always throws to prove _emit swallows
    // callback errors.
    var result = await b.vaultRotate.rotate({
      oldKeys: keyA, newKeys: keyB, dataDir: dataDir, stagingDir: staging,
      mode: "plaintext",
      externalAadResealed: b.vaultRotate._externalAadTables(),
      progressCallback: function (ev) { phases.push(ev.phase); throw new Error("cb boom"); },
    });
    check("rotate with no db.enc processes zero tables", result.tablesProcessed === 0);
    check("rotate emitted the init + done progress phases despite throwing callback",
      phases.indexOf("init") !== -1 && phases.indexOf("done") !== -1);
    check("rotate wrote the plaintext vault.key into staging",
      fs.existsSync(path.join(staging, "vault.key")));
    check("rotate did not produce a verifyResult with no db.enc",
      result.verifyResult === null);
  } finally {
    try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* cleanup */ }
    try { fs.rmSync(staging, { recursive: true, force: true }); } catch (_e) { /* cleanup */ }
  }
}

async function testRotateWrappedKeyWriteNoDb() {
  var dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "vr-wr-"));
  var staging = path.join(os.tmpdir(), "vr-wr-stg-" + process.pid + "-" + Date.now());
  try {
    var result = await b.vaultRotate.rotate({
      oldKeys: keyA, newKeys: keyB, dataDir: dataDir, stagingDir: staging,
      mode: "wrapped", newPassphrase: Buffer.from("rotate-test-passphrase-not-secret"),
      externalAadResealed: true,
    });
    check("rotate wrapped mode writes vault.key.sealed into staging",
      fs.existsSync(path.join(staging, "vault.key.sealed")));
    var sealedBytes = fs.readFileSync(path.join(staging, "vault.key.sealed"), "utf8");
    check("rotate wrapped-mode key file is not the plaintext keypair JSON",
      sealedBytes.indexOf("privateKey") === -1);
    check("rotate wrapped mode processed zero tables", result.tablesProcessed === 0);
  } finally {
    try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* cleanup */ }
    try { fs.rmSync(staging, { recursive: true, force: true }); } catch (_e) { /* cleanup */ }
  }
}

// ---------------------------------------------------------------------------
// rotate — full plaintext keypair rotation of a live encrypted deployment
// with plain (non-AAD) sealed cells + an overflow `data` JSON column.
// ---------------------------------------------------------------------------
var PLAIN_SCHEMA = [
  {
    name:    "notes",
    columns: { _id: "TEXT PRIMARY KEY", title: "TEXT", subtitle: "TEXT", data: "TEXT" },
    // 'subtitle' is a real column left entirely NULL (a sealed column with
    // zero non-null rows → _rotateColumn short-circuits); 'phantom' is
    // declared sealed but is NOT a live column (skipped by the liveColSet gate).
    sealedFields: ["title", "subtitle", "phantom"],
  },
  {
    // AAD-bound table with a non-_id rowIdField exercises _rotateColumn's
    // AAD reseal path when rowIdField must be projected separately.
    name:          "secrets",
    columns:       { _id: "TEXT PRIMARY KEY", entityId: "TEXT", secret: "TEXT" },
    sealedFields:  ["secret"],
    aad:           true,
    rowIdField:    "entityId",
    schemaVersion: "1",
  },
  {
    // AAD-bound table keyed on _id (the common config) exercises the AAD
    // reseal path where the row-id IS the _id cursor (no separate projection).
    name:          "sessions",
    columns:       { _id: "TEXT PRIMARY KEY", token: "TEXT" },
    sealedFields:  ["token"],
    aad:           true,
    rowIdField:    "_id",
    schemaVersion: "1",
  },
];

async function _reset() {
  process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
  b.cluster._resetForTest();
  b.audit._resetForTest();
  b.vault._resetForTest();
  b.db._resetForTest();
}

async function testRotateFullPlaintextRotation() {
  var dirNew = fs.mkdtempSync(path.join(os.tmpdir(), "vr-full-new-"));
  var dirA   = fs.mkdtempSync(path.join(os.tmpdir(), "vr-full-a-"));
  var staging = path.join(os.tmpdir(), "vr-full-stg-" + process.pid + "-" + Date.now());
  try {
    // 1. Fresh keypair to rotate INTO.
    await _reset();
    await b.vault.init({ dataDir: dirNew, mode: "plaintext" });
    var newKeys = JSON.parse(b.vault.getKeysJson());
    b.vault._resetForTest();

    // 2. Live deployment under the OLD keypair: encrypted db + a plain sealed
    //    cell + an overflow `data` JSON blob carrying a vault-prefixed string.
    await _reset();
    await b.vault.init({ dataDir: dirA, mode: "plaintext" });
    var oldKeys = JSON.parse(b.vault.getKeysJson());
    check("full-rotation old and new keypairs differ",
      JSON.stringify(oldKeys) !== JSON.stringify(newKeys));
    await b.db.init({ dataDir: dirA, tmpDir: path.join(dirA, "tmpfs"), atRest: "encrypted",
      auditSigning: false, frameworkTables: false, schema: PLAIN_SCHEMA });

    var sealed = b.cryptoField.sealRow("notes", { _id: "n1", title: "confidential-title" });
    check("plain seal produced a vault: cell",
      typeof sealed.title === "string" && sealed.title.indexOf(VAULT_PREFIX) === 0);
    // Overflow `data` JSON exercises _rotateOverflow / _walkAndReSeal across
    // every node kind: a nested vault-prefixed string, an array of mixed
    // members, and primitives (number / bool / null) that pass through.
    sealed.data = JSON.stringify({
      note:  b.vault.seal("overflow-secret"),
      list:  [b.vault.seal("in-array"), "plain-elem", 7],
      plain: "kept",
      count: 5,
      flag:  true,
      nul:   null,
    });
    b.db.from("notes").insertOne(sealed);
    // A row whose sealed column is NULL (skipped by _rotateColumn) and whose
    // overflow `data` is malformed JSON (left unrotated with a warning).
    b.db.from("notes").insertOne({ _id: "n2", title: null, data: "{not valid json" });

    // AAD-bound row: sealed under a (table, rowId=entityId, column) tuple.
    var sealedAad = b.cryptoField.sealRow("secrets", { _id: "s1", entityId: "ent-1", secret: "aad-cell-value" });
    check("AAD seal produced a vault.aad: cell",
      typeof sealedAad.secret === "string" && sealedAad.secret.indexOf("vault.aad:") === 0);
    b.db.from("secrets").insertOne(sealedAad);
    var sealedSession = b.cryptoField.sealRow("sessions", { _id: "sess-1", token: "session-token-value" });
    b.db.from("sessions").insertOne(sealedSession);
    await b.db.flushToDisk();
    await b.db.close();

    // 3. Rotate old -> new. rowBatchSize forces the keyset cursor to page;
    //    opts.tables scopes the walk and includes a non-existent table that
    //    the tableExists gate skips.
    var result = await b.vaultRotate.rotate({
      dataDir: dirA, stagingDir: staging, oldKeys: oldKeys, newKeys: newKeys,
      mode: "plaintext", externalAadResealed: true, rowBatchSize: 1,
      tables: ["notes", "secrets", "sessions", "ghost_table"],
    });
    check("full rotation internal round-trip verify ok",
      !!result.verifyResult && result.verifyResult.ok === true);
    check("full rotation processed at least one row", result.totalRowsProcessed >= 1);
    check("full rotation warns about the malformed overflow JSON row",
      result.warnings.some(function (w) { return /malformed overflow JSON/.test(w); }));

    // 4. Swap staging -> dataDir and re-open under the NEW keypair.
    ["db.enc", "db.key.enc", "vault.key"].forEach(function (f) {
      var s = path.join(staging, f);
      if (fs.existsSync(s)) fs.copyFileSync(s, path.join(dirA, f));
    });
    try { fs.rmSync(path.join(dirA, "tmpfs"), { recursive: true, force: true }); } catch (_e) { /* fresh decrypt */ }

    await _reset();
    await b.vault.init({ dataDir: dirA, mode: "plaintext" });
    check("vault now live under the NEW keypair",
      JSON.stringify(JSON.parse(b.vault.getKeysJson())) === JSON.stringify(newKeys));
    await b.db.init({ dataDir: dirA, tmpDir: path.join(dirA, "tmpfs"), atRest: "encrypted",
      auditSigning: false, frameworkTables: false, schema: PLAIN_SCHEMA });

    var got = b.cryptoField.unsealRow("notes", b.db.from("notes").where({ _id: "n1" }).first());
    check("plain sealed cell decrypts after rotation under the new keypair",
      !!got && got.title === "confidential-title");
    var overflow = JSON.parse(got.data);
    check("overflow vault-prefixed value re-sealed and decrypts under the new keypair",
      b.vault.unseal(overflow.note) === "overflow-secret" && overflow.plain === "kept");
    check("overflow array member re-sealed and decrypts; primitives preserved",
      b.vault.unseal(overflow.list[0]) === "in-array" && overflow.list[1] === "plain-elem" &&
      overflow.list[2] === 7 && overflow.count === 5 && overflow.flag === true && overflow.nul === null);

    var gotAad = b.cryptoField.unsealRow("secrets", b.db.from("secrets").where({ _id: "s1" }).first());
    check("AAD-bound cell (entityId rowId) decrypts after rotation under the new keypair",
      !!gotAad && gotAad.secret === "aad-cell-value");
    var gotSess = b.cryptoField.unsealRow("sessions", b.db.from("sessions").where({ _id: "sess-1" }).first());
    check("AAD-bound cell (_id rowId) decrypts after rotation under the new keypair",
      !!gotSess && gotSess.token === "session-token-value");
    await b.db.close();
  } finally {
    await _reset();
    b.cryptoField.clearForTest();
    [dirNew, dirA, staging].forEach(function (d) {
      try { fs.rmSync(d, { recursive: true, force: true }); } catch (_e) { /* cleanup */ }
    });
  }
}

// ---------------------------------------------------------------------------
// rotate — auxiliary sealed / verbatim file rotation (legacy plain db.key.enc,
// additionalSealed, derived-hash salt + MAC, verbatim files + dirs). No db.enc,
// so the pipeline exercises only the file-reseal + copy surface.
// ---------------------------------------------------------------------------
function _b64Key() { return Buffer.from("0123456789abcdef0123456789abcdef").toString("base64"); }

async function testRotateAuxiliaryFilesRotation() {
  var dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "vr-aux-"));
  var staging = path.join(os.tmpdir(), "vr-aux-stg-" + process.pid + "-" + Date.now());
  try {
    // Legacy plain-sealed db.key.enc (pre-AAD `vault:` prefix), an operator
    // additionalSealed blob, the derived-hash salt (verbatim) + MAC (resealed),
    // and verbatim file/dir trees.
    fs.writeFileSync(path.join(dataDir, "db.key.enc"), _seal(_b64Key(), keyA));
    fs.writeFileSync(path.join(dataDir, "extra.sealed"), _seal("operator-secret-blob", keyA));
    // A nested additionalSealed forces the staging dest-dir ensureDir branch.
    fs.mkdirSync(path.join(dataDir, "nested"));
    fs.writeFileSync(path.join(dataDir, "nested", "deep.sealed"), _seal("deep-blob", keyA));
    fs.writeFileSync(path.join(dataDir, "vault.derived-hash-salt"), Buffer.from("salt-bytes-verbatim"));
    fs.writeFileSync(path.join(dataDir, "vault.derived-hash-mac.sealed"), _seal(_b64Key(), keyA));
    fs.writeFileSync(path.join(dataDir, "keep.txt"), "verbatim-contents");
    fs.mkdirSync(path.join(dataDir, "subdir"));
    fs.writeFileSync(path.join(dataDir, "subdir", "inner.txt"), "inner-verbatim");

    // mode omitted → defaults to "plaintext".
    var result = await b.vaultRotate.rotate({
      oldKeys: keyA, newKeys: keyB, dataDir: dataDir, stagingDir: staging,
      externalAadResealed: true,
      paths: {
        additionalSealed: [
          { relativePath: "extra.sealed", required: true },
          { relativePath: "nested/deep.sealed", required: true },
          { relativePath: "missing-optional.sealed", required: false },
        ],
        verbatimFiles: [
          { relativePath: "keep.txt" },
          { relativePath: "missing-optional.txt", required: false },
        ],
        verbatimDirs: [
          { relativePath: "subdir" },
          { relativePath: "missing-optional-dir", required: false },
        ],
      },
    });
    check("aux rotation processed zero DB tables (no db.enc)", result.tablesProcessed === 0);
    check("aux rotation wrote the plaintext vault.key", fs.existsSync(path.join(staging, "vault.key")));

    var stagedDbKey = fs.readFileSync(path.join(staging, "db.key.enc"), "utf8");
    check("legacy plain db.key.enc re-sealed under the new keypair",
      stagedDbKey.indexOf(VAULT_PREFIX) === 0 && stagedDbKey !== _seal(_b64Key(), keyA) &&
      b.crypto.decrypt(stagedDbKey.substring(VAULT_PREFIX.length), keyB) === _b64Key());

    var stagedExtra = fs.readFileSync(path.join(staging, "extra.sealed"), "utf8");
    check("additionalSealed blob re-sealed and decrypts under the new keypair",
      stagedExtra.indexOf(VAULT_PREFIX) === 0 &&
      b.crypto.decrypt(stagedExtra.substring(VAULT_PREFIX.length), keyB) === "operator-secret-blob");

    check("derived-hash salt copied verbatim",
      fs.existsSync(path.join(staging, "vault.derived-hash-salt")) &&
      fs.readFileSync(path.join(staging, "vault.derived-hash-salt"), "utf8") === "salt-bytes-verbatim");
    var stagedMac = fs.readFileSync(path.join(staging, "vault.derived-hash-mac.sealed"), "utf8");
    check("derived-hash MAC re-sealed under the new keypair",
      stagedMac.indexOf(VAULT_PREFIX) === 0 &&
      b.crypto.decrypt(stagedMac.substring(VAULT_PREFIX.length), keyB) === _b64Key());

    check("verbatim file copied into staging",
      fs.existsSync(path.join(staging, "keep.txt")) &&
      fs.readFileSync(path.join(staging, "keep.txt"), "utf8") === "verbatim-contents");
    check("verbatim dir copied recursively into staging",
      fs.existsSync(path.join(staging, "subdir", "inner.txt")));
    check("nested additionalSealed re-sealed into a created staging subdir",
      fs.existsSync(path.join(staging, "nested", "deep.sealed")) &&
      b.crypto.decrypt(fs.readFileSync(path.join(staging, "nested", "deep.sealed"), "utf8")
        .substring(VAULT_PREFIX.length), keyB) === "deep-blob");
  } finally {
    try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* cleanup */ }
    try { fs.rmSync(staging, { recursive: true, force: true }); } catch (_e) { /* cleanup */ }
  }
}

// rotate — fail-closed guards on missing/malformed auxiliary files.
async function testRotateAuxiliaryFileGuards() {
  async function withDataDir(build, opts, code, label) {
    var dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "vr-auxg-"));
    var staging = path.join(os.tmpdir(), "vr-auxg-stg-" + process.pid + "-" + Date.now() + "-" + Math.random().toString(36).slice(2));
    try {
      build(dataDir);
      var full = Object.assign({ oldKeys: keyA, newKeys: keyB, dataDir: dataDir,
        stagingDir: staging, mode: "plaintext", externalAadResealed: true }, opts);
      await _expectRotateThrow(label, full, code);
    } finally {
      try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* cleanup */ }
      try { fs.rmSync(staging, { recursive: true, force: true }); } catch (_e) { /* cleanup */ }
    }
  }

  await withDataDir(function () { /* no keep.txt */ },
    { paths: { verbatimFiles: [{ relativePath: "keep.txt", required: true }] } },
    "vault-rotate/missing-verbatim", "rotate refuses a missing required verbatim file");

  await withDataDir(function () { /* no subdir */ },
    { paths: { verbatimDirs: [{ relativePath: "subdir", required: true }] } },
    "vault-rotate/missing-verbatim-dir", "rotate refuses a missing required verbatim dir");

  await withDataDir(function () { /* no extra.sealed */ },
    { paths: { additionalSealed: [{ relativePath: "extra.sealed", required: true }] } },
    "vault-rotate/missing-sealed", "rotate refuses a missing required sealed file");

  await withDataDir(function (dir) { fs.writeFileSync(path.join(dir, "extra.sealed"), "not-vault-prefixed"); },
    { paths: { additionalSealed: [{ relativePath: "extra.sealed", required: true }] } },
    "vault-rotate/bad-sealed", "rotate refuses an additionalSealed file lacking the vault prefix");

  await withDataDir(function (dir) { fs.writeFileSync(path.join(dir, "db.key.enc"), "garbage-no-prefix"); },
    {}, "vault-rotate/bad-dbkey", "rotate refuses a db.key.enc without a vault prefix");
}

// rotate — round-trip verify fail-closed: rotating to the SAME keypair leaves
// every cell decryptable under the "old" root, which the internal verify flags
// as a non-effective rotation → the pipeline refuses rather than reporting ok.
async function testRotateVerifyFailedOnSameKeypair() {
  var dirA = fs.mkdtempSync(path.join(os.tmpdir(), "vr-vf-a-"));
  var staging = path.join(os.tmpdir(), "vr-vf-stg-" + process.pid + "-" + Date.now());
  try {
    await _reset();
    await b.vault.init({ dataDir: dirA, mode: "plaintext" });
    var liveKeys = JSON.parse(b.vault.getKeysJson());
    await b.db.init({ dataDir: dirA, tmpDir: path.join(dirA, "tmpfs"), atRest: "encrypted",
      auditSigning: false, frameworkTables: false, schema: [PLAIN_SCHEMA[0]] });
    b.db.from("notes").insertOne(b.cryptoField.sealRow("notes", { _id: "n1", title: "x" }));
    await b.db.flushToDisk();
    await b.db.close();

    // oldKeys === newKeys: the "old" root still decrypts every rotated cell.
    await _expectRotateThrow("rotate refuses when the round-trip verify detects a non-effective rotation",
      { dataDir: dirA, stagingDir: staging, oldKeys: liveKeys, newKeys: liveKeys,
        mode: "plaintext", externalAadResealed: true },
      "vault-rotate/verify-failed");
  } finally {
    await _reset();
    b.cryptoField.clearForTest();
    try { fs.rmSync(dirA, { recursive: true, force: true }); } catch (_e) { /* cleanup */ }
    try { fs.rmSync(staging, { recursive: true, force: true }); } catch (_e) { /* cleanup */ }
  }
}

// ---------------------------------------------------------------------------
// Exposed constants — referenced by their verbatim dotted form (the static
// gate has no method-invocation fallback for constants).
// ---------------------------------------------------------------------------
function testExposedConstants() {
  check("DEFAULT_DRIFT_SAMPLE_LIMIT exposed",
    b.vaultRotate.DEFAULT_DRIFT_SAMPLE_LIMIT === 100);
  check("DEFAULT_VERIFY_SAMPLE_MIN exposed",
    b.vaultRotate.DEFAULT_VERIFY_SAMPLE_MIN === 5);
  check("DEFAULT_VERIFY_SAMPLE_FRAC exposed",
    b.vaultRotate.DEFAULT_VERIFY_SAMPLE_FRAC === 0.01);
  check("ROW_BATCH_SIZE_DEFAULT exposed",
    b.vaultRotate.ROW_BATCH_SIZE_DEFAULT === 1000);
  check("VaultRotateError class exposed",
    typeof b.vaultRotate.VaultRotateError === "function");
}

async function run() {
  testVerifyRequiresKeys();
  testVerifyRequiresDb();
  testVerifyRejectsNonHandleDb();
  testVerifyRejectsBadSampleMin();
  testVerifyRejectsBadSamplePercent();

  testVerifyPassesUnderMatchingKey();
  testVerifyFlagsDecryptFailure();
  testVerifyFlagsRegressionWhenOldKeysStillDecrypt();
  testVerifyRotationEffectiveWithOldKeys();
  testVerifySkipsNonStringAndUnprefixedCells();
  testVerifySkipsEmptyAndUnregisteredAndMissingTables();
  await testVerifyDecryptsAadCells();

  testValidateRejectsBadDriftSampleLimit();
  testValidateCleanSchemaHasNoWarningsOrErrors();
  testValidateTreatsDerivedHashColumnsAsKnown();
  testValidateWarnsOnMissingTable();
  testValidateWarnsOnMissingSealedColumn();
  testValidateDetectsDriftInUndeclaredColumn();
  testValidateInfraColumnsSuppressesDrift();
  testValidateIgnoresNonArrayInfraColumns();

  testFormatValidationResultRenders();

  await testRotateGuardsRequiredArgs();
  await testRotateRefusesUnacknowledgedExternalAad();
  await testRotatePlaintextKeyWriteNoDb();
  await testRotateWrappedKeyWriteNoDb();
  await testRotateAuxiliaryFilesRotation();
  await testRotateAuxiliaryFileGuards();
  await testRotateFullPlaintextRotation();
  await testRotateVerifyFailedOnSameKeypair();

  testExposedConstants();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[vault-rotate] OK — " + helpers.getChecks() + " checks passed"); },
    // Rethrow rather than log the error: the fixtures seed vault passphrases,
    // and logging the error object trips CodeQL's clear-text-logging taint.
    function (e) { process.exitCode = 1; throw e; }
  );
}
