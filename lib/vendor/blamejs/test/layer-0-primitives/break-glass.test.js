"use strict";
/**
 * b.breakGlass — column-policy / row-enforcement step-up auth (v0.5.0).
 *
 * Covers: surface, policy CRUD, TOTP factor verification, grant
 * lifecycle (expiry / exhaustion / revoke), error codes, IP/session
 * pinning data flow, audit emission per row, sweep.
 *
 * Run standalone: `node test/layer-0-primitives/break-glass.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

var C = b.constants;

function _tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bg-")); }

// Build a test "patient" record table that mimics the operator-facing
// shape: a glass-locked column (ssn) sealed via cryptoField. We don't
// need a custom table schema — _blamejs_jobs has sealed columns we
// can repurpose for the unsealRow test (payload field is sealed). For
// the policy tests we use arbitrary table names since policy.set
// doesn't validate the table exists in the DB.

function _validTotp() {
  var secret = b.auth.totp.generateSecret();
  var code = b.auth.totp.generate(secret);
  return { secret: secret, code: code };
}

function _fakeReq(overrides) {
  var base = {
    user:    { id: "user-test-1" },
    session: { id: "sess-test-1" },
    socket:  { remoteAddress: "127.0.0.1" },
    headers: { "user-agent": "test-agent" },
    method:  "POST",
    url:     "/admin/break-glass",
  };
  return Object.assign(base, overrides || {});
}

// ---- Surface ----

function testSurface() {
  check("b.breakGlass namespace present",          typeof b.breakGlass === "object");
  check("breakGlass.init is fn",                   typeof b.breakGlass.init === "function");
  check("breakGlass.policy.set is fn",             typeof b.breakGlass.policy.set === "function");
  check("breakGlass.policy.get is fn",             typeof b.breakGlass.policy.get === "function");
  check("breakGlass.policy.list is fn",            typeof b.breakGlass.policy.list === "function");
  check("breakGlass.policy.delete is fn",          typeof b.breakGlass.policy.delete === "function");
  check("breakGlass.grant is fn",                  typeof b.breakGlass.grant === "function");
  check("breakGlass.unsealRow is fn",              typeof b.breakGlass.unsealRow === "function");
  check("breakGlass.revoke is fn",                 typeof b.breakGlass.revoke === "function");
  check("breakGlass.listActive is fn",             typeof b.breakGlass.listActive === "function");
  check("breakGlass.BreakGlassError is class",     typeof b.breakGlass.BreakGlassError === "function");
}

// ---- Policy CRUD ----

async function testPolicyCRUD() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();

    // No policy → null
    var p0 = await b.breakGlass.policy.get("patients");
    check("policy.get unset returns null", p0 === null);

    // Set
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn", "diagnosis"],
      factors: ["totp"],
    });
    var p1 = await b.breakGlass.policy.get("patients");
    check("policy.get returns the saved policy",
          p1 && p1.table === "patients");
    check("policy.set defaults maxRowsPerGrant = 1",
          p1 && p1.maxRowsPerGrant === 1);
    check("policy.set defaults grantTtl = 15 min",
          p1 && p1.grantTtl === C.TIME.minutes(15));
    check("policy.set defaults reasonRequired = true",
          p1 && p1.reasonRequired === true);
    check("policy.set defaults pinIp = true",
          p1 && p1.pinIp === true);
    check("policy.set defaults sessionPin = true",
          p1 && p1.sessionPin === true);
    check("policy.set defaults onLockedAccess = throw",
          p1 && p1.onLockedAccess === "throw");
    check("policy.set defaults auditReasonStorage = cleartext",
          p1 && p1.auditReasonStorage === "cleartext");
    check("policy.set columns round-trip",
          p1 && Array.isArray(p1.columns) && p1.columns[0] === "ssn" && p1.columns[1] === "diagnosis");

    // List
    var all = await b.breakGlass.policy.list();
    check("policy.list returns 1 entry",  all.length === 1 && all[0].table === "patients");

    // Update (UPSERT)
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"],
      factors: ["totp"],
      grantTtl: C.TIME.minutes(5),
      maxRowsPerGrant: 10,
      reasonMinLength: 20,
    });
    var p2 = await b.breakGlass.policy.get("patients");
    check("policy.set is idempotent UPSERT (columns updated)",
          p2.columns.length === 1 && p2.columns[0] === "ssn");
    check("policy.set updates grantTtl",      p2.grantTtl === C.TIME.minutes(5));
    check("policy.set updates maxRowsPerGrant", p2.maxRowsPerGrant === 10);
    check("policy.set updates reasonMinLength", p2.reasonMinLength === 20);

    // Delete
    await b.breakGlass.policy.delete("patients");
    var p3 = await b.breakGlass.policy.get("patients");
    check("policy.delete removes the policy",  p3 === null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Input validation (rejects bad opts at create time) ----

async function testPolicyValidation() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    function reject(label, table, opts, codeRe) {
      return b.breakGlass.policy.set(table, opts).then(
        function () { check("policy.validate: " + label + " (should throw)", false); },
        function (e) { check("policy.validate: " + label, codeRe.test(e.code || "")); }
      );
    }
    await reject("rejects bad table",          "", { columns: ["x"], factors: ["totp"] }, /breakglass\/bad-policy/);
    await reject("rejects missing columns",    "t", { factors: ["totp"] }, /breakglass\/bad-policy/);
    await reject("rejects empty columns",      "t", { columns: [], factors: ["totp"] }, /breakglass\/bad-policy/);
    await reject("rejects missing factors",    "t", { columns: ["x"] }, /breakglass\/bad-policy/);
    await reject("rejects unknown factor",     "t", { columns: ["x"], factors: ["sms"] }, /breakglass\/bad-policy/);
    await reject("rejects unknown factor 'sms'",   "t", { columns: ["x"], factors: ["sms"] }, /breakglass\/bad-policy/);
    await reject("rejects non-boolean cryptographic",
                                               "t", { columns: ["x"], factors: ["totp"], cryptographic: "yes" }, /breakglass\/bad-policy/);
    await reject("rejects bad onLockedAccess", "t", { columns: ["x"], factors: ["totp"], onLockedAccess: "panic" }, /breakglass\/bad-policy/);
    await reject("rejects bad maxRowsPerGrant","t", { columns: ["x"], factors: ["totp"], maxRowsPerGrant: 0 }, /breakglass\/bad-policy/);
    await reject("rejects negative grantTtl",  "t", { columns: ["x"], factors: ["totp"], grantTtl: -1 }, /breakglass\/bad-policy/);
    await reject("rejects bad auditReasonStorage",
                                               "t", { columns: ["x"], factors: ["totp"], auditReasonStorage: "raw" }, /breakglass\/bad-policy/);
    await reject("rejects serviceAccountBypass in 0.5.0",
                                               "t", { columns: ["x"], factors: ["totp"], serviceAccountBypass: { enabled: true } }, /breakglass\/bad-policy/);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Grant — happy path ----

async function testGrantHappyPath() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"],
      factors: ["totp"],
    });
    var totp = _validTotp();
    var grant = await b.breakGlass.grant({
      req:     _fakeReq(),
      table:   "patients",
      reason:  "investigating ticket #12345 for compliance review",
      factor:  { type: "totp", code: totp.code, secret: totp.secret },
    });
    check("grant: returns id",               typeof grant.id === "string" && grant.id.indexOf("bg-") === 0);
    check("grant: returns expiresAt",        typeof grant.expiresAt === "number" && grant.expiresAt > Date.now());
    check("grant: rowsRemaining = 1 (default)", grant.rowsRemaining === 1);
    check("grant: scopeTable echoed",        grant.scopeTable === "patients");
    check("grant: scopeColumns echoed",      grant.scopeColumns.length === 1 && grant.scopeColumns[0] === "ssn");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Grant — refused paths ----

async function testGrantRefusalPaths() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"],
      factors: ["totp"],
      reasonMinLength: 12,
    });

    function reject(label, opts, codeRe) {
      return b.breakGlass.grant(opts).then(
        function () { check("grant.refusal: " + label + " (should throw)", false); },
        function (e) { check("grant.refusal: " + label, codeRe.test(e.code || "")); }
      );
    }
    var totp = _validTotp();

    await reject("policy-not-set",
      { req: _fakeReq(), table: "no-such-table", reason: "x".repeat(12),
        factor: { type: "totp", code: totp.code, secret: totp.secret } },
      /breakglass\/policy-not-set/);

    await reject("missing-reason",
      { req: _fakeReq(), table: "patients", reason: "",
        factor: { type: "totp", code: totp.code, secret: totp.secret } },
      /breakglass\/missing-reason/);

    await reject("short-reason",
      { req: _fakeReq(), table: "patients", reason: "short",
        factor: { type: "totp", code: totp.code, secret: totp.secret } },
      /breakglass\/short-reason/);

    await reject("grant-column-mismatch",
      { req: _fakeReq(), table: "patients", reason: "this is a long enough reason",
        columns: ["nonexistent-column"],
        factor: { type: "totp", code: totp.code, secret: totp.secret } },
      /breakglass\/grant-column-mismatch/);

    await reject("bad-factor (wrong code)",
      { req: _fakeReq(), table: "patients", reason: "this is a long enough reason",
        factor: { type: "totp", code: "000000", secret: totp.secret } },
      /breakglass\/bad-factor/);

    await reject("unauthorized (no actor on req)",
      { req: { socket: { remoteAddress: "127.0.0.1" }, headers: {} },
        table: "patients", reason: "this is a long enough reason",
        factor: { type: "totp", code: totp.code, secret: totp.secret } },
      /breakglass\/unauthorized/);

    await reject("bad factor type",
      { req: _fakeReq(), table: "patients", reason: "this is a long enough reason",
        factor: { type: "magic-link" } },
      /breakglass\/bad-factor/);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Grant + unseal — full lifecycle on a real sealed table ----

async function testUnsealRowLifecycle() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    // Use _blamejs_jobs as the test target: payload is sealed by
    // cryptoField.sealRow per FRAMEWORK_SCHEMA.
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var jid = await b.queue.enqueue("test-q", { secret: "alice's diagnosis" });

    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns:         ["payload"],
      factors:         ["totp"],
      maxRowsPerGrant: 3,   // raise from default-1 so we can test exhaustion + a normal read
    });

    var totp = _validTotp();
    var grant = await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "_blamejs_jobs",
      reason: "diagnostic spot-check on queue payloads",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });
    check("grant: maxRowsPerGrant honored from policy", grant.rowsRemaining === 3);

    // Use grant once
    var unsealed = await b.breakGlass.unsealRow(grant, "_blamejs_jobs", jid.jobId);
    check("unsealRow: returns the row",                 unsealed && unsealed._id === jid.jobId);
    check("unsealRow: payload column is decrypted",
          unsealed.payload && unsealed.payload.indexOf("alice") !== -1);

    // listActive shows 2 remaining
    var active = await b.breakGlass.listActive({ req: _fakeReq() });
    check("listActive: 1 grant",                        active.length === 1);
    check("listActive: rowsRemaining decremented",      active[0].rowsRemaining === 2);

    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Exhaustion ----

async function testGrantExhaustion() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var jid = await b.queue.enqueue("ex-q", { kind: "row-1" });

    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns:         ["payload"],
      factors:         ["totp"],
      maxRowsPerGrant: 1,    // strict default
    });
    var totp = _validTotp();
    var grant = await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "_blamejs_jobs",
      reason: "compliance spot-check on queue row",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });
    await b.breakGlass.unsealRow(grant, "_blamejs_jobs", jid.jobId);

    var threw = null;
    try { await b.breakGlass.unsealRow(grant, "_blamejs_jobs", jid.jobId); }
    catch (e) { threw = e; }
    check("exhaustion: second use of 1-row grant rejects",
          threw && /breakglass\/grant-exhausted/.test(threw.code));

    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Revoke ----

async function testGrantRevoke() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var jid = await b.queue.enqueue("rv-q", { kind: "row-1" });

    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns: ["payload"], factors: ["totp"], maxRowsPerGrant: 5,
    });
    var totp = _validTotp();
    var grant = await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "_blamejs_jobs",
      reason: "compliance spot-check on queue row",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });
    await b.breakGlass.revoke(grant.id, { reason: "task complete" });
    var threw = null;
    try { await b.breakGlass.unsealRow(grant, "_blamejs_jobs", jid.jobId); }
    catch (e) { threw = e; }
    check("revoke: unseal after revoke rejects",
          threw && /breakglass\/grant-revoked/.test(threw.code));

    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Table mismatch ----

async function testTableMismatch() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", { columns: ["ssn"], factors: ["totp"] });
    var totp = _validTotp();
    var grant = await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "patients",
      reason: "investigating ticket #12345 for compliance review",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });
    var threw = null;
    try { await b.breakGlass.unsealRow(grant, "doctors", "doc-1"); }
    catch (e) { threw = e; }
    check("table-mismatch: unseal on wrong table rejects",
          threw && /breakglass\/grant-table-mismatch/.test(threw.code));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Sweep ----

async function testSweepExpiredGrants() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"], factors: ["totp"],
      grantTtl: 10,    // 10 ms — guaranteed expired by sweep time
    });
    var totp = _validTotp();
    await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "patients",
      reason: "soak-test with 10ms ttl for sweep coverage",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });
    await new Promise(function (r) { setTimeout(r, 50); });
    var swept = await b.breakGlass._sweepExpiredForTest();
    check("sweep: marks expired grants revoked", swept.expired >= 1);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- v0.5.1: Cryptographic mode (Model B) ----

async function testEncryptDecryptCellHappyPath() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns:       ["ssn"],
      factors:       ["totp"],
      cryptographic: true,
      maxRowsPerGrant: 5,
    });
    var ct = await b.breakGlass.encryptCell("123-45-6789",
      { table: "patients", rowId: "p-42", column: "ssn" });
    check("encryptCell: returns bgcell:1: prefix", typeof ct === "string" && ct.indexOf("bgcell:1:") === 0);
    var pt = await b.breakGlass.decryptCell(ct,
      { table: "patients", rowId: "p-42", column: "ssn" });
    check("decryptCell: round-trip recovers plaintext", pt === "123-45-6789");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testEncryptionContextBinding() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"], factors: ["totp"], cryptographic: true,
    });
    var ct = await b.breakGlass.encryptCell("123-45-6789",
      { table: "patients", rowId: "p-42", column: "ssn" });

    // Wrong rowId — decrypt must fail
    var threw = null;
    try {
      await b.breakGlass.decryptCell(ct, { table: "patients", rowId: "p-43", column: "ssn" });
    } catch (e) { threw = e; }
    check("aad-binding: wrong rowId fails decrypt", threw !== null);

    // Wrong column — fails
    threw = null;
    try {
      await b.breakGlass.decryptCell(ct, { table: "patients", rowId: "p-42", column: "diagnosis" });
    } catch (e) { threw = e; }
    check("aad-binding: wrong column fails decrypt", threw !== null);

    // Wrong table — fails
    threw = null;
    try {
      await b.breakGlass.decryptCell(ct, { table: "doctors", rowId: "p-42", column: "ssn" });
    } catch (e) { threw = e; }
    check("aad-binding: wrong table fails decrypt", threw !== null);

    // Correct context — works
    var pt = await b.breakGlass.decryptCell(ct,
      { table: "patients", rowId: "p-42", column: "ssn" });
    check("aad-binding: correct context decrypts", pt === "123-45-6789");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testEncryptCellRequiresCryptographicPolicy() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"], factors: ["totp"], cryptographic: false,
    });
    var threw = null;
    try {
      await b.breakGlass.encryptCell("x", { table: "patients", rowId: "1", column: "ssn" });
    } catch (e) { threw = e; }
    check("encryptCell: rejects Model A policy",
          threw && /breakglass\/policy-not-set/.test(threw.code));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testEncryptCellRejectsBadColumn() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"], factors: ["totp"], cryptographic: true,
    });
    var threw = null;
    try {
      await b.breakGlass.encryptCell("x", { table: "patients", rowId: "1", column: "phone" });
    } catch (e) { threw = e; }
    check("encryptCell: rejects non-glass-locked column",
          threw && /breakglass\/grant-column-mismatch/.test(threw.code));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testCryptographicUnsealRow() {
  // End-to-end Model B: write a Model-B-shaped row directly, issue
  // grant, unseal, verify cell decrypted via decryptCell with proper
  // context binding.
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var jid = await b.queue.enqueue("crypto-q", { sentinel: "outer-payload" });

    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns:         ["payload"],
      factors:         ["totp"],
      cryptographic:   true,
      maxRowsPerGrant: 3,
    });

    // Write a cryptographic-mode payload directly into the row.
    var bgPayload = await b.breakGlass.encryptCell("alice's diagnosis (Model B)",
      { table: "_blamejs_jobs", rowId: jid.jobId, column: "payload" });
    await b.clusterStorage.execute(
      "UPDATE _blamejs_jobs SET payload = ? WHERE _id = ?",
      [bgPayload, jid.jobId]
    );

    var totp = _validTotp();
    var grant = await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "_blamejs_jobs",
      reason: "Model B integration test for cryptographic unseal",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });
    var row = await b.breakGlass.unsealRow(grant, "_blamejs_jobs", jid.jobId);
    check("Model B unsealRow: decrypts cryptographic cell",
          row.payload === "alice's diagnosis (Model B)");

    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testMigrateModelAtoModelB() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    // Enqueue 3 jobs in Model A (vault-sealed payload).
    var j1 = await b.queue.enqueue("mig-q", { secret: "row-1-secret" });
    var j2 = await b.queue.enqueue("mig-q", { secret: "row-2-secret" });
    var j3 = await b.queue.enqueue("mig-q", { secret: "row-3-secret" });

    // Set cryptographic policy + run migrate.
    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns: ["payload"], factors: ["totp"], cryptographic: true,
      maxRowsPerGrant: 5,
    });
    var result = await b.breakGlass.migrate("_blamejs_jobs", { batchSize: 10 });
    check("migrate: returns total + migrated counts",
          result.totalRows >= 3 && result.migratedRows >= 3);

    // Idempotent — second run skips already-migrated rows.
    var result2 = await b.breakGlass.migrate("_blamejs_jobs", { batchSize: 10 });
    check("migrate: second run is idempotent",
          result2.skippedRows >= result2.migratedRows);

    // Read via grant — confirms the migrated rows decrypt.
    var totp = _validTotp();
    var grant = await b.breakGlass.grant({
      req:    _fakeReq(),
      table:  "_blamejs_jobs",
      reason: "post-migration verification of payload decrypt path",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });
    var row = await b.breakGlass.unsealRow(grant, "_blamejs_jobs", j1.jobId);
    check("migrate: row-1 reads as cryptographic-mode plaintext",
          row.payload && row.payload.indexOf("row-1-secret") !== -1);
    void j2; void j3;

    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- v0.5.2: passkey factor + service-account bypass + admin tools ----

function testV052Surface() {
  check("breakGlass.unsealRowAsService is fn",  typeof b.breakGlass.unsealRowAsService === "function");
  check("breakGlass.listActiveAll is fn",       typeof b.breakGlass.listActiveAll === "function");
  check("breakGlass.revokeAll is fn",           typeof b.breakGlass.revokeAll === "function");
}

async function testPasskeyAcceptedInPolicy() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"], factors: ["passkey"],
    });
    var p = await b.breakGlass.policy.get("patients");
    check("passkey factor accepted in policy",   p && p.factors[0] === "passkey");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testPasskeyFactorPath() {
  // We don't have a real WebAuthn fixture handy; verify the factor
  // dispatch + rejection of malformed assertions.
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("patients", {
      columns: ["ssn"], factors: ["passkey"],
    });
    var threw = null;
    try {
      await b.breakGlass.grant({
        req:    _fakeReq(),
        table:  "patients",
        reason: "investigating ticket #12345 for compliance review",
        factor: { type: "passkey" /* missing all the fields */ },
      });
    } catch (e) { threw = e; }
    check("passkey: malformed assertion rejected as bad-factor",
          threw && /breakglass\/bad-factor/.test(threw.code));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testServiceAccountBypassPolicyValidation() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    function reject(label, sab, codeRe) {
      return b.breakGlass.policy.set("t", {
        columns: ["x"], factors: ["totp"],
        serviceAccountBypass: sab,
      }).then(
        function () { check("sab.validate: " + label + " (should throw)", false); },
        function (e) { check("sab.validate: " + label, codeRe.test(e.code || "")); }
      );
    }
    await reject("rejects non-object",    "yes",                            /breakglass\/bad-policy/);
    await reject("rejects enabled false", { enabled: false, apiKeyIds: ["x"], requireRole: "y" }, /breakglass\/bad-policy/);
    await reject("rejects empty apiKeyIds", { enabled: true, apiKeyIds: [], requireRole: "y" }, /breakglass\/bad-policy/);
    await reject("rejects missing requireRole", { enabled: true, apiKeyIds: ["x"] }, /breakglass\/bad-policy/);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testServiceAccountBypassHappyPath() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var jid = await b.queue.enqueue("svc-q", { secret: "row-payload-svc" });

    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns: ["payload"], factors: ["totp"],
      serviceAccountBypass: {
        enabled:     true,
        apiKeyIds:   ["ak-svc-deidentify-job"],
        requireRole: "service:phi-reader",
      },
    });
    var serviceReq = {
      apiKey: {
        id:     "ak-svc-deidentify-job",
        scopes: ["service:phi-reader"],
      },
      socket:  { remoteAddress: "10.0.0.1" },
      headers: { "user-agent": "blamejs-svc" },
      method:  "GET",
      url:     "/cron/deid",
    };
    var row = await b.breakGlass.unsealRowAsService(serviceReq, "_blamejs_jobs", jid.jobId,
      { reason: "nightly de-identification run" });
    check("bypass: returns the row",
          row && typeof row.payload === "string" && row.payload.indexOf("row-payload-svc") !== -1);

    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testServiceAccountBypassRefusalPaths() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var jid = await b.queue.enqueue("svc-deny-q", { secret: "x" });

    // Policy WITHOUT serviceAccountBypass — bypass path must refuse.
    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns: ["payload"], factors: ["totp"],
    });
    var threw = null;
    try {
      await b.breakGlass.unsealRowAsService(
        { apiKey: { id: "ak-x", scopes: [] } }, "_blamejs_jobs", jid.jobId);
    } catch (e) { threw = e; }
    check("bypass: refuses when not configured",
          threw && /breakglass\/bypass-not-configured/.test(threw.code));

    // Now with bypass configured but apiKey not in allowlist
    await b.breakGlass.policy.set("_blamejs_jobs", {
      columns: ["payload"], factors: ["totp"],
      serviceAccountBypass: {
        enabled: true, apiKeyIds: ["ak-allowed"], requireRole: "service:reader",
      },
    });
    threw = null;
    try {
      await b.breakGlass.unsealRowAsService(
        { apiKey: { id: "ak-other", scopes: ["service:reader"] } },
        "_blamejs_jobs", jid.jobId);
    } catch (e) { threw = e; }
    check("bypass: refuses unknown apiKey id",
          threw && /breakglass\/bypass-unauthorized/.test(threw.code));

    // apiKey in allowlist but missing role
    threw = null;
    try {
      await b.breakGlass.unsealRowAsService(
        { apiKey: { id: "ak-allowed", scopes: ["service:other"] } },
        "_blamejs_jobs", jid.jobId);
    } catch (e) { threw = e; }
    check("bypass: refuses without required role",
          threw && /breakglass\/bypass-unauthorized/.test(threw.code));

    // No req.apiKey at all
    threw = null;
    try {
      await b.breakGlass.unsealRowAsService(_fakeReq(), "_blamejs_jobs", jid.jobId);
    } catch (e) { threw = e; }
    check("bypass: refuses when req has no apiKey",
          threw && /breakglass\/bypass-no-apikey/.test(threw.code));

    try { await b.queue.shutdown({ timeoutMs: 200 }); } catch (_e) {}
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testListActiveAllAndRevokeAll() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.breakGlass.init();
    await b.breakGlass.policy.set("t1", { columns: ["c"], factors: ["totp"], maxRowsPerGrant: 3 });
    await b.breakGlass.policy.set("t2", { columns: ["c"], factors: ["totp"], maxRowsPerGrant: 3 });

    var totp = _validTotp();
    var g1 = await b.breakGlass.grant({
      req: _fakeReq(), table: "t1",
      reason: "compliance review per ticket #1",
      factor: { type: "totp", code: totp.code, secret: totp.secret },
    });
    var totp2 = _validTotp();
    var g2 = await b.breakGlass.grant({
      req: _fakeReq(), table: "t2",
      reason: "compliance review per ticket #2",
      factor: { type: "totp", code: totp2.code, secret: totp2.secret },
    });
    void g1; void g2;

    var all = await b.breakGlass.listActiveAll();
    check("listActiveAll: returns both grants",  all.length === 2);

    var t1Only = await b.breakGlass.listActiveAll({ table: "t1" });
    check("listActiveAll: filters by table",     t1Only.length === 1 && t1Only[0].scopeTable === "t1");

    // revokeAll requires actor or table scope
    var threw = null;
    try { await b.breakGlass.revokeAll({}); } catch (e) { threw = e; }
    check("revokeAll: refuses unbounded",
          threw && /breakglass\/bad-revoke-criteria/.test(threw.code));

    var result = await b.breakGlass.revokeAll({ table: "t1", reason: "ir-test" });
    check("revokeAll: reports revokedCount",     result && result.revokedCount === 1);

    var afterRevoke = await b.breakGlass.listActiveAll();
    check("revokeAll: t1 grant gone",             afterRevoke.length === 1 && afterRevoke[0].scopeTable === "t2");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  testSurface();
  await testPolicyCRUD();
  await testPolicyValidation();
  await testGrantHappyPath();
  await testGrantRefusalPaths();
  await testUnsealRowLifecycle();
  await testGrantExhaustion();
  await testGrantRevoke();
  await testTableMismatch();
  await testSweepExpiredGrants();
  // v0.5.1 Model B
  await testEncryptDecryptCellHappyPath();
  await testEncryptionContextBinding();
  await testEncryptCellRequiresCryptographicPolicy();
  await testEncryptCellRejectsBadColumn();
  await testCryptographicUnsealRow();
  await testMigrateModelAtoModelB();
  // v0.5.2 passkey + bypass + admin
  testV052Surface();
  await testPasskeyAcceptedInPolicy();
  await testPasskeyFactorPath();
  await testServiceAccountBypassPolicyValidation();
  await testServiceAccountBypassHappyPath();
  await testServiceAccountBypassRefusalPaths();
  await testListActiveAllAndRevokeAll();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
