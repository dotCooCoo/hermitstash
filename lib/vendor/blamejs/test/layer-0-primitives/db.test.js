// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * db — error / defensive / adversarial branch coverage for
 * lib/db.js driven through the public b.db surface. Focus is the
 * non-happy-path: bad-init opts, reserved-table collisions,
 * personal-data-category validation, exportCsv / transaction / stream
 * / vacuum / worm / dual-control / eraseHard / purge validation
 * throws, the tmpfs storage-headroom write gate (fault-injected
 * statfs), the not-initialized guard across entry points, and the
 * close/idempotency + generation-counter seams.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var fs      = helpers.fs;
var os      = helpers.os;
var path    = helpers.path;

var C = b.constants;

// --- shared local fixtures ------------------------------------------------

function _mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

async function _freshVault(tmpDir) {
  process.env.BLAMEJS_SKIP_NTP_CHECK            = "1";
  process.env.BLAMEJS_VAULT_PASSPHRASE          = "test-passphrase-suite";
  process.env.BLAMEJS_AUDIT_SIGNING_PASSPHRASE  = "test-passphrase-suite";
  b.cluster._resetForTest();
  b.audit._resetForTest();
  b.vault._resetForTest();
  b.db._resetForTest();
  await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
}

// Plain-mode db (fast; no tmpfs, no encryption envelope). frameworkTables
// default ON unless the caller overrides via `extra`.
async function _plainInit(tmpDir, schema, extra) {
  await _freshVault(tmpDir);
  var opts = { dataDir: tmpDir, atRest: "plain", schema: schema || [] };
  if (extra) Object.assign(opts, extra);
  await b.db.init(opts);
}

function _teardownPlain(tmpDir) {
  try { b.db.close(); } catch (_e) { /* may already be closed */ }
  b.db._resetForTest();
  b.vault._resetForTest();
  b.cluster._resetForTest();
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
}

// Return the thrown error (or null) for a sync-or-async thunk.
async function _catch(thunk) {
  try { await thunk(); return null; }
  catch (e) { return e; }
}

// --- init() argument validation (no db opened) ----------------------------

async function testInitArgValidation() {
  // Ensure a clean not-initialized state so the `if (initialized) return`
  // early-out doesn't swallow these throws.
  b.cluster._resetForTest();
  b.audit._resetForTest();
  b.vault._resetForTest();
  b.db._resetForTest();
  var tmpDir = _mkTmp("db-cov-argv-");
  try {
    var e1 = await _catch(function () { return b.db.init(); });
    check("init() with no opts throws db/bad-init", e1 && e1.code === "db/bad-init");

    var e2 = await _catch(function () { return b.db.init({}); });
    check("init({}) missing dataDir throws db/bad-init", e2 && e2.code === "db/bad-init");

    var e3 = await _catch(function () { return b.db.init({ dataDir: tmpDir, schema: "notarray" }); });
    check("init non-array schema throws db/bad-init", e3 && e3.code === "db/bad-init");

    var e4 = await _catch(function () { return b.db.init({ dataDir: tmpDir, schema: [], atRest: "weird" }); });
    check("init bad atRest throws db/bad-at-rest", e4 && e4.code === "db/bad-at-rest");

    var e5 = await _catch(function () { return b.db.init({ dataDir: tmpDir, schema: [], atRest: "plain", streamLimit: -1 }); });
    check("init negative streamLimit throws", e5 !== null);

    var e6 = await _catch(function () { return b.db.init({ dataDir: tmpDir, schema: [], atRest: "plain", streamLimit: 1.5 }); });
    check("init non-integer streamLimit throws", e6 !== null);

    var e7 = await _catch(function () { return b.db.init({ dataDir: tmpDir, schema: [], atRest: "plain", columnGate: "bogus" }); });
    check("init bad columnGate throws db/bad-init", e7 && e7.code === "db/bad-init");

    // db was never opened by any of these — still not initialized.
    var e8 = await _catch(function () { return b.db.from("x"); });
    check("after failed inits, from() reports not-initialized", e8 && e8.code === "db/not-initialized");
  } finally {
    b.db._resetForTest();
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
  }
}

// --- not-initialized guard across the public entry points -----------------

async function testNotInitializedGuard() {
  b.db._resetForTest();
  var errs = {
    from:            await _catch(function () { return b.db.from("t"); }),
    prepare:         await _catch(function () { return b.db.prepare("SELECT 1"); }),
    stream:          await _catch(function () { return b.db.stream("SELECT 1"); }),
    transaction:     await _catch(function () { return b.db.transaction(function () {}); }),
    hashFor:         await _catch(function () { return b.db.hashFor("t", "f", "v"); }),
    snapshot:        await _catch(function () { return b.db.snapshot(); }),
    exportCsv:       await _catch(function () { return b.db.exportCsv({ table: "t" }); }),
    eraseHard:       await _catch(function () { return b.db.eraseHard("t", "r", { reason: "x" }); }),
    declareWorm:     await _catch(function () { return b.db.declareWorm({ tables: ["t"] }); }),
    integrityCheck:  await _catch(function () { return b.db.integrityCheck(); }),
    runSql:          await _catch(function () { return b.db.runSql("SELECT 1"); }),
  };
  Object.keys(errs).forEach(function (k) {
    check("not-initialized guard fires for " + k,
      errs[k] && errs[k].code === "db/not-initialized");
  });
  // Accessors are safe pre-init and read null-ish state.
  check("getMode() null before init", b.db.getMode() === null);
  check("getDbPath() null before init", b.db.getDbPath() === null);
  check("getDataResidency() null before init", b.db.getDataResidency() === null);
}

// --- reserved framework table-name collisions -----------------------------

async function testReservedTableNames() {
  var tmpDir = _mkTmp("db-cov-reserved-");
  try {
    var e1 = await _catch(function () {
      return _plainInit(tmpDir, [{ name: "audit_log", columns: { _id: "TEXT PRIMARY KEY" } }]);
    });
    check("schema colliding with audit_log throws db/reserved-table-name",
      e1 && e1.code === "db/reserved-table-name");
    b.db._resetForTest();

    var e2 = await _catch(function () {
      return _plainInit(tmpDir, [{ name: "_blamejs_custom", columns: { _id: "TEXT PRIMARY KEY" } }]);
    });
    check("schema with _blamejs_ prefix throws db/reserved-table-name",
      e2 && e2.code === "db/reserved-table-name");
    b.db._resetForTest();

    // Under frameworkTables:false the operator MAY own an audit_log.
    await _plainInit(tmpDir, [{ name: "audit_log", columns: { _id: "TEXT PRIMARY KEY" } }],
      { frameworkTables: false, auditSigning: false });
    check("frameworkTables:false lets operator name a table audit_log",
      typeof b.db.from === "function");
  } finally {
    _teardownPlain(tmpDir);
  }
}

// --- personalDataCategories validation ------------------------------------

async function testPersonalDataCategories() {
  var tmpDir = _mkTmp("db-cov-pdc-");
  try {
    var badShape = await _catch(function () {
      return _plainInit(tmpDir, [{
        name: "people", columns: { _id: "TEXT PRIMARY KEY", uid: "TEXT" },
        subjectField: "uid", personalDataCategories: "not-an-object",
      }]);
    });
    check("personalDataCategories non-object throws db/bad-personal-data-categories",
      badShape && badShape.code === "db/bad-personal-data-categories");
    b.db._resetForTest();

    var badVal = await _catch(function () {
      return _plainInit(tmpDir, [{
        name: "people", columns: { _id: "TEXT PRIMARY KEY", uid: "TEXT" },
        subjectField: "uid", personalDataCategories: { uid: 123 },
      }]);
    });
    check("personalDataCategories non-string value throws db/bad-personal-data-category",
      badVal && badVal.code === "db/bad-personal-data-category");
    b.db._resetForTest();

    // Known + unknown vocabulary both accepted; unknown emits a warning
    // audit (drop-silent) and init still succeeds.
    await _plainInit(tmpDir, [{
      name: "people", columns: { _id: "TEXT PRIMARY KEY", uid: "TEXT" },
      subjectField: "uid",
      personalDataCategories: { uid: "email", extra: "totally-unknown-category" },
    }]);
    check("init succeeds with a mix of known + unknown data categories",
      b.db.getTableMetadata("people").subjectField === "uid");
  } finally {
    _teardownPlain(tmpDir);
  }
}

// --- getTableMetadata dispatch + accessors --------------------------------

async function testMetadataAndAccessors() {
  var tmpDir = _mkTmp("db-cov-meta-");
  try {
    await helpers.setupTestDb(tmpDir, [{
      name: "orders",
      columns: { _id: "TEXT PRIMARY KEY", note: "TEXT", total: "INTEGER NOT NULL", totalHash: "TEXT" },
      sealedFields: ["note"],
      derivedHashes: { totalHash: { from: "total" } },
    }]);

    check("getMode() returns encrypted", b.db.getMode() === "encrypted");
    check("getDbPath() is a string path", typeof b.db.getDbPath() === "string");
    check("getStreamLimit() default is 1_000_000", b.db.getStreamLimit() === 1000000);
    check("getDataResidency() null when unset", b.db.getDataResidency() === null);

    check("getDeclaredColumns known table lists _id",
      b.db.getDeclaredColumns("orders").indexOf("_id") !== -1);
    check("getDeclaredColumns unknown table returns null",
      b.db.getDeclaredColumns("nope") === null);

    check("getTableMetadata() no-arg returns a snapshot object",
      typeof b.db.getTableMetadata() === "object" && !!b.db.getTableMetadata().orders);
    check("getTableMetadata(string) returns the table meta",
      b.db.getTableMetadata("orders").sealedFields.indexOf("note") !== -1);
    check("getTableMetadata(unknown-string) returns null",
      b.db.getTableMetadata("nope") === null);
    check("getTableMetadata(non-object non-string) returns null",
      b.db.getTableMetadata(123) === null);
    check("getTableMetadata({ table: unknown }) returns null",
      b.db.getTableMetadata({ table: "nope" }) === null);

    var badArg = await _catch(function () { return b.db.getTableMetadata({ table: "" }); });
    check("getTableMetadata({ table: '' }) throws db/bad-table-arg",
      badArg && badArg.code === "db/bad-table-arg");

    var badFmt = await _catch(function () {
      return b.db.getTableMetadata({ table: "orders", format: "yaml" });
    });
    check("getTableMetadata bad format throws db/bad-format",
      badFmt && badFmt.code === "db/bad-format");

    var js = b.db.getTableMetadata({ table: "orders", format: "json-schema-2020-12" });
    check("json-schema output carries the 2020-12 $schema", /2020-12/.test(js["$schema"]));
    check("json-schema marks NOT NULL column required", js.required.indexOf("total") !== -1);
    check("json-schema marks nullable column as anyOf union",
      Array.isArray(js.properties.note.anyOf));
    check("json-schema annotates sealed column",
      js.properties.note["x-blamejs-sealed"] === true);
    check("json-schema annotates derived-hash column",
      js.properties.totalHash["x-blamejs-derived-from"] === "total");
  } finally {
    await helpers.teardownTestDb(tmpDir);
  }
}

// --- transaction() --------------------------------------------------------

async function testTransaction() {
  var tmpDir = _mkTmp("db-cov-txn-");
  try {
    await _plainInit(tmpDir, [{ name: "ledger", columns: { _id: "TEXT PRIMARY KEY", bal: "INTEGER" } }],
      { frameworkTables: false, auditSigning: false });

    var badFn = await _catch(function () { return b.db.transaction("not-a-fn"); });
    check("transaction(non-fn) throws db/bad-transaction-fn",
      badFn && badFn.code === "db/bad-transaction-fn");

    var ret = b.db.transaction(function () {
      b.db.from("ledger").insertOne({ _id: "a", bal: 1 });
      return "committed";
    });
    check("transaction returns the fn's value", ret === "committed");
    check("committed row is present", b.db.from("ledger").where({ _id: "a" }).first().bal === 1);

    // A throw inside the body rolls back and re-propagates.
    var rolled = await _catch(function () {
      return b.db.transaction(function () {
        b.db.from("ledger").insertOne({ _id: "b", bal: 2 });
        throw new Error("boom-in-txn");
      });
    });
    check("transaction re-propagates the body error", rolled && /boom-in-txn/.test(rolled.message));
    check("rolled-back row is absent",
      !b.db.from("ledger").where({ _id: "b" }).first());
  } finally {
    _teardownPlain(tmpDir);
  }
}

// --- exportCsv validation + success ---------------------------------------

async function testExportCsv() {
  var tmpDir = _mkTmp("db-cov-csv-");
  try {
    await helpers.setupTestDb(tmpDir, [{
      name: "orders",
      columns: {
        _id: "TEXT PRIMARY KEY", note: "TEXT", total: "INTEGER NOT NULL",
        createdAt: "INTEGER NOT NULL", raw: "BLOB",
      },
      sealedFields: ["note"],
    }]);

    var noOpts = await _catch(function () { return b.db.exportCsv(); });
    check("exportCsv() no opts throws db/bad-export-opts",
      noOpts && noOpts.code === "db/bad-export-opts");

    var noTable = await _catch(function () { return b.db.exportCsv({}); });
    check("exportCsv missing table throws", noTable !== null);

    var unknown = await _catch(function () { return b.db.exportCsv({ table: "ghost" }); });
    check("exportCsv unknown table throws db/unknown-table",
      unknown && unknown.code === "db/unknown-table");

    var badCol = await _catch(function () {
      return b.db.exportCsv({ table: "orders", columns: ["_id", "not_a_col"] });
    });
    check("exportCsv unknown column throws db/bad-export-column",
      badCol && badCol.code === "db/bad-export-column");

    var badFmt = await _catch(function () {
      return b.db.exportCsv({ table: "orders", format: "tsv" });
    });
    check("exportCsv bad format throws db/bad-export-format",
      badFmt && badFmt.code === "db/bad-export-format");

    var badSigner = await _catch(function () {
      return b.db.exportCsv({ table: "orders", signWith: { sign: function () {} } });
    });
    check("exportCsv incomplete signer throws db/bad-signer",
      badSigner && badSigner.code === "db/bad-signer");

    var throwingSigner = await _catch(function () {
      return b.db.exportCsv({
        table: "orders",
        signWith: {
          sign:                    function () { throw new Error("hsm-down"); },
          getPublicKey:            function () { return ""; },
          getAlgorithm:            function () { return "x"; },
          getPublicKeyFingerprint: function () { return "y"; },
        },
      });
    });
    check("exportCsv signer that throws surfaces db/sign-failed",
      throwingSigner && throwingSigner.code === "db/sign-failed");

    // Success path: BOM + ISO timestamp cast + Buffer base64 + null → "".
    b.db.from("orders").insertOne({ _id: "o1", note: "hi", total: 100, createdAt: Date.now(), raw: Buffer.from("AB") });
    b.db.from("orders").insertOne({ _id: "o2", note: null, total: 200, createdAt: Date.now() });
    var out = b.db.exportCsv({
      table: "orders", bom: true, timestampFields: ["createdAt"], signWith: b.auditSign,
    });
    check("exportCsv success reports 2 rows", out.rowCount === 2);
    check("exportCsv emits a SHA3-512 (128 hex chars)", out.sha3_512.length === 128);
    check("exportCsv text carries the UTF-8 BOM", out.csv.charCodeAt(0) === 0xFEFF);
    check("exportCsv attaches a signature block", !!out.signature && typeof out.signature.value === "string");
  } finally {
    await helpers.teardownTestDb(tmpDir);
  }
}

// --- stream() error + limit branches --------------------------------------

async function testStream() {
  var tmpDir = _mkTmp("db-cov-stream-");
  try {
    await _plainInit(tmpDir, [{
      name: "events", columns: { _id: "TEXT PRIMARY KEY", payload: "TEXT" }, sealedFields: ["payload"],
    }], { frameworkTables: false, auditSigning: false });
    b.db.from("events").insertOne({ _id: "e1", payload: "one" });
    b.db.from("events").insertOne({ _id: "e2", payload: "two" });
    b.db.from("events").insertOne({ _id: "e3", payload: "three" });

    // prepare() throws on bad SQL → the returned Readable destroys w/ error.
    var badErr = await _drain(b.db.stream("SELECT * FROM missing_table"));
    check("stream over a missing table destroys with an error", badErr.error !== null);

    // bad per-call streamLimit throws synchronously at the call site.
    var badLimit = await _catch(function () { return b.db.stream("SELECT * FROM events", { streamLimit: 0 }); });
    check("stream bad streamLimit throws db/bad-stream-limit",
      badLimit && badLimit.code === "db/bad-stream-limit");

    // A limit strictly below the row count exceeds → destroyed with the typed error.
    var over = await _drain(b.db.stream("SELECT * FROM events", { streamLimit: 2 }));
    check("stream past the limit destroys with db/stream-limit-exceeded",
      over.error && over.error.code === "db/stream-limit-exceeded");

    // Sealed-column auto-unseal via opts.table + a positional param.
    var okRun = await _drain(b.db.stream("SELECT * FROM events WHERE _id != ?", "e_none", { table: "events" }));
    check("stream with opts.table + param yields unsealed rows", okRun.rows.length === 3);
    check("stream auto-unseals the sealed column",
      okRun.rows.every(function (r) { return typeof r.payload === "string" && r.payload.indexOf("vault") === -1; }));

    // A trailing positional (non-object) param with no opts object takes the
    // params-only branch (last arg is a SQL binding, not an options bag).
    var posOnly = await _drain(b.db.stream("SELECT * FROM events WHERE _id != ?", "e1"));
    check("stream with a positional param and no opts binds it as a parameter",
      posOnly.error === null && posOnly.rows.length === 2);
  } finally {
    _teardownPlain(tmpDir);
  }
}

// Drain a Readable to completion, capturing rows + any error.
function _drain(readable) {
  return new Promise(function (resolve) {
    var rows = [];
    readable.on("data", function (r) { rows.push(r); });
    readable.on("end", function () { resolve({ rows: rows, error: null }); });
    readable.on("error", function (e) { resolve({ rows: rows, error: e }); });
  });
}

// --- prepare() cache + LRU eviction ---------------------------------------

async function testPrepareCache() {
  var tmpDir = _mkTmp("db-cov-prep-");
  try {
    await _plainInit(tmpDir, [], { frameworkTables: false, auditSigning: false });

    var a = b.db.prepare("SELECT 1 AS one");
    var again = b.db.prepare("SELECT 1 AS one");
    check("prepare() returns the cached Statement for the same SQL", a === again);

    // Fill past the 256-entry cap so the first distinct SQL is evicted, then
    // re-prepare it — a fresh Statement means the LRU dropped it.
    var first = b.db.prepare("SELECT 0 AS n");
    for (var i = 1; i <= 300; i++) {
      b.db.prepare("SELECT " + i + " AS n");
    }
    var firstAgain = b.db.prepare("SELECT 0 AS n");
    check("prepare() LRU evicts the oldest entry past the cap", first !== firstAgain);
  } finally {
    _teardownPlain(tmpDir);
  }
}

// --- runSql / exec DDL audit branches -------------------------------------

async function testRunSql() {
  var tmpDir = _mkTmp("db-cov-runsql-");
  try {
    await _plainInit(tmpDir, [], { frameworkTables: false, auditSigning: false });

    b.db.runSql("CREATE TABLE scratch (id INTEGER PRIMARY KEY)");
    check("runSql executes a DDL CREATE",
      b.db.prepare("SELECT name FROM sqlite_master WHERE name='scratch'").get().name === "scratch");

    // exec alias exists and runs DDL too.
    b.db.exec("CREATE TABLE scratch2 (id INTEGER PRIMARY KEY)");
    check("db.exec alias runs DDL",
      b.db.prepare("SELECT name FROM sqlite_master WHERE name='scratch2'").get().name === "scratch2");

    // A malformed DDL exercises the failure-audit branch and re-throws.
    var ddlErr = await _catch(function () { return b.db.runSql("CREATE TABLE"); });
    check("runSql malformed DDL re-throws", ddlErr !== null);

    // Non-DDL raw statement runs through the non-audited path.
    b.db.runSql("INSERT INTO scratch (id) VALUES (7)");
    check("runSql non-DDL DML executes",
      b.db.prepare("SELECT id FROM scratch WHERE id=7").get().id === 7);
  } finally {
    _teardownPlain(tmpDir);
  }
}

// --- vacuumAfterErase -----------------------------------------------------

async function testVacuum() {
  var tmpDir = _mkTmp("db-cov-vac-");
  try {
    await _plainInit(tmpDir, [], { frameworkTables: false, auditSigning: false });

    var badMode = await _catch(function () { return b.db.vacuumAfterErase({ mode: "sideways" }); });
    check("vacuumAfterErase bad mode throws db/bad-vacuum-mode",
      badMode && badMode.code === "db/bad-vacuum-mode");

    var badPages = await _catch(function () { return b.db.vacuumAfterErase({ mode: "incremental", pages: -3 }); });
    check("vacuumAfterErase bad pages throws db/bad-vacuum-pages",
      badPages && badPages.code === "db/bad-vacuum-pages");

    b.db.vacuumAfterErase({ mode: "incremental", pages: 5 });
    b.db.vacuumAfterErase();                 // default incremental / 1000 pages
    b.db.vacuumAfterErase({ mode: "full" });
    check("vacuumAfterErase incremental + full succeed", true);

    b.db.close();
    var notInit = await _catch(function () { return b.db.vacuumAfterErase({ mode: "full" }); });
    check("vacuumAfterErase after close throws db/not-initialized",
      notInit && notInit.code === "db/not-initialized");
  } finally {
    _teardownPlain(tmpDir);
  }
}

// --- declareWorm ----------------------------------------------------------

async function testDeclareWorm() {
  var tmpDir = _mkTmp("db-cov-worm-");
  try {
    await helpers.setupTestDb(tmpDir, [
      { name: "blotter", columns: { _id: "TEXT PRIMARY KEY", sym: "TEXT" } },
    ]);

    var noTables = await _catch(function () { return b.db.declareWorm({}); });
    check("declareWorm missing tables throws", noTables !== null && noTables.name === "WormViolationError");

    var empty = await _catch(function () { return b.db.declareWorm({ tables: [] }); });
    check("declareWorm empty tables throws", empty !== null);

    var badId = await _catch(function () { return b.db.declareWorm({ tables: ["bad name!"] }); });
    check("declareWorm invalid identifier throws", badId !== null);

    var badPosture = await _catch(function () { return b.db.declareWorm({ tables: ["blotter"], posture: 5 }); });
    check("declareWorm non-string posture throws", badPosture !== null);

    var reserved = await _catch(function () { return b.db.declareWorm({ tables: ["audit_log"] }); });
    check("declareWorm on framework audit_log throws RESERVED",
      reserved && reserved.code === "RESERVED");

    var declared = b.db.declareWorm({ tables: ["blotter"], posture: "finra-4511" });
    check("declareWorm returns the declared table list", declared.tables[0] === "blotter");

    // The WORM trigger now blocks UPDATE + DELETE on the declared table.
    b.db.from("blotter").insertOne({ _id: "t1", sym: "AAPL" });
    var upd = await _catch(function () {
      return b.db.from("blotter").where({ _id: "t1" }).updateOne({ sym: "MSFT" });
    });
    check("WORM trigger blocks UPDATE on the declared table", upd !== null);
  } finally {
    await helpers.teardownTestDb(tmpDir);
  }
}

// --- declareRequireDualControl + _checkDualControlGate --------------------

async function testDualControl() {
  var tmpDir = _mkTmp("db-cov-dc-");
  try {
    await helpers.setupTestDb(tmpDir, [
      { name: "charts", columns: { _id: "TEXT PRIMARY KEY", body: "TEXT" } },
    ]);

    var noTables = await _catch(function () { return b.db.declareRequireDualControl({}); });
    check("declareRequireDualControl no tables throws db/dual-control-bad-tables",
      noTables && noTables.code === "db/dual-control-bad-tables");

    var badId = await _catch(function () { return b.db.declareRequireDualControl({ tables: ["bad;name"] }); });
    check("declareRequireDualControl bad identifier throws", badId !== null);

    var badQuorum = await _catch(function () { return b.db.declareRequireDualControl({ tables: ["charts"], m: 1 }); });
    check("declareRequireDualControl m<2 throws db/dual-control-bad-quorum",
      badQuorum && badQuorum.code === "db/dual-control-bad-quorum");

    var badPosture = await _catch(function () {
      return b.db.declareRequireDualControl({ tables: ["charts"], posture: 9 });
    });
    check("declareRequireDualControl non-string posture throws db/dual-control-bad-posture",
      badPosture && badPosture.code === "db/dual-control-bad-posture");

    check("_checkDualControlGate returns null for an undeclared table",
      b.db._checkDualControlGate("charts") === null);

    var gate = b.db.declareRequireDualControl({ tables: ["charts"], m: 2, n: 3, posture: "hipaa" });
    check("declareRequireDualControl returns quorum tuple", gate.m === 2 && gate.n === 3);

    var row = b.db._checkDualControlGate("charts");
    check("_checkDualControlGate returns the registered gate", row && row.m === 2 && row.n === 3);
  } finally {
    await helpers.teardownTestDb(tmpDir);
  }
}

// --- eraseHard ------------------------------------------------------------

async function testEraseHard() {
  var tmpDir = _mkTmp("db-cov-erase-");
  try {
    await helpers.setupTestDb(tmpDir, [
      { name: "gated",  columns: { _id: "TEXT PRIMARY KEY", ssn: "TEXT" }, sealedFields: ["ssn"] },
      { name: "plainrows", columns: { _id: "TEXT PRIMARY KEY", ssn: "TEXT" }, sealedFields: ["ssn"] },
    ]);

    var badRow = await _catch(function () { return b.db.eraseHard("gated", "", { reason: "x here now" }); });
    check("eraseHard empty rowId throws db/erase-hard-bad-row-id",
      badRow && badRow.code === "db/erase-hard-bad-row-id");

    var noReason = await _catch(function () { return b.db.eraseHard("plainrows", "r1", {}); });
    check("eraseHard missing reason throws db/erase-hard-no-reason",
      noReason && noReason.code === "db/erase-hard-no-reason");

    // Non-gated, non-WORM table: success.
    b.db.from("plainrows").insertOne({ _id: "r1", ssn: "111-11-1111" });
    var ok = b.db.eraseHard("plainrows", "r1", { reason: "gdpr art 17 erasure request" });
    check("eraseHard deletes the row (rowsDeleted === 1)", ok.rowsDeleted === 1);
    check("eraseHard reports a numeric durationMs", typeof ok.durationMs === "number");
    check("eraseHard actually removed the row",
      !b.db.from("plainrows").where({ _id: "r1" }).first());

    // Gated table: refused without a grant.
    b.db.declareRequireDualControl({ tables: ["gated"], m: 2, n: 3, posture: "hipaa" });
    b.db.from("gated").insertOne({ _id: "g1", ssn: "222-22-2222" });
    var denied = await _catch(function () { return b.db.eraseHard("gated", "g1", { reason: "erase please now" }); });
    check("eraseHard on a gated table without a grant is refused",
      denied && denied.code === "db/erase-hard-dual-control-required");

    var notReady = await _catch(function () {
      return b.db.eraseHard("gated", "g1", { reason: "erase please now", dualControlGrant: { ready: false } });
    });
    check("eraseHard with an unconsumed grant throws db/erase-hard-grant-not-ready",
      notReady && notReady.code === "db/erase-hard-grant-not-ready");

    var gatedOk = b.db.eraseHard("gated", "g1", { reason: "erase please now", dualControlGrant: { ready: true } });
    check("eraseHard with a ready grant succeeds", gatedOk.rowsDeleted === 1);
  } finally {
    await helpers.teardownTestDb(tmpDir);
  }
}

// --- purgeAuditChain ------------------------------------------------------

async function testPurgeAuditChain() {
  var tmpDir = _mkTmp("db-cov-purge-");
  try {
    await helpers.setupTestDb(tmpDir, [{ name: "t", columns: { _id: "TEXT PRIMARY KEY" } }]);

    var badCounter = await _catch(function () { return b.db.purgeAuditChain({ lastPurgedCounter: -1 }); });
    check("purgeAuditChain negative counter throws db/bad-purge-counter",
      badCounter && badCounter.code === "db/bad-purge-counter");

    var nanCounter = await _catch(function () { return b.db.purgeAuditChain({ lastPurgedCounter: "abc" }); });
    check("purgeAuditChain non-numeric counter throws db/bad-purge-counter",
      nanCounter && nanCounter.code === "db/bad-purge-counter");

    var res = await b.db.purgeAuditChain({ lastPurgedCounter: 0 });
    check("purgeAuditChain returns numeric rowsDeleted", typeof res.rowsDeleted === "number");
    check("purgeAuditChain returns numeric checkpointsDeleted", typeof res.checkpointsDeleted === "number");
  } finally {
    await helpers.teardownTestDb(tmpDir);
  }
}

// --- hashFor / hashCandidatesFor ------------------------------------------

async function testHashHelpers() {
  var tmpDir = _mkTmp("db-cov-hash-");
  try {
    await helpers.setupTestDb(tmpDir);   // default users table w/ email→emailHash
    var h = b.db.hashFor("users", "email", "alice@example.com");
    check("hashFor returns a string digest for a derived field", typeof h === "string" && h.length > 0);
    check("hashFor returns null for a field with no derived hash",
      b.db.hashFor("users", "name", "Alice") === null);

    var cands = b.db.hashCandidatesFor("users", "email", "alice@example.com");
    check("hashCandidatesFor returns { field, values } for a derived field",
      cands && cands.field === "emailHash" && Array.isArray(cands.values));
    check("hashCandidatesFor returns null for a non-derived field",
      b.db.hashCandidatesFor("users", "name", "Alice") === null);
  } finally {
    await helpers.teardownTestDb(tmpDir);
  }
}

// --- integrityCheck + integrityMonitor ------------------------------------

async function testIntegrity() {
  var tmpDir = _mkTmp("db-cov-integ-");
  try {
    await _plainInit(tmpDir, [], { frameworkTables: false, auditSigning: false });

    check("integrityCheck reports ok on a healthy db", b.db.integrityCheck() === "ok");

    var badInterval = await _catch(function () { return b.db.integrityMonitor({ intervalMs: -5 }); });
    check("integrityMonitor rejects a non-positive intervalMs", badInterval instanceof TypeError);

    var mon = b.db.integrityMonitor({ intervalMs: C.TIME.hours(24), audit: false });
    check("integrityMonitor returns a handle with stop()", typeof mon.stop === "function");
    mon.stop();
    mon.stop();   // idempotent second stop
    check("integrityMonitor stop() is idempotent", true);
  } finally {
    _teardownPlain(tmpDir);
  }
}

// --- applyPosture / getActivePosture --------------------------------------

async function testApplyPosture() {
  b.db._resetForTest();
  check("applyPosture('') returns null", b.db.applyPosture("") === null);
  check("applyPosture(non-string) returns null", b.db.applyPosture(123) === null);
  var res = b.db.applyPosture("pci-dss");
  check("applyPosture records posture + dbInitialized flag",
    res.posture === "pci-dss" && res.dbInitialized === false);
  check("getActivePosture reflects the last applied posture",
    b.db.getActivePosture() === "pci-dss");
}

// --- close idempotency + generation counter -------------------------------

async function testCloseAndGeneration() {
  var tmpDir = _mkTmp("db-cov-close-");
  try {
    await _plainInit(tmpDir, [{ name: "t", columns: { _id: "TEXT PRIMARY KEY" } }],
      { frameworkTables: false, auditSigning: false });

    var genBefore = b.db._dbGeneration();
    check("_dbGeneration is a number after init", typeof genBefore === "number");

    b.db.close();
    var genAfter = b.db._dbGeneration();
    check("_dbGeneration bumps on close", genAfter > genBefore);

    b.db.close();   // idempotent no-op after the first close
    check("close() after close is a no-op (generation unchanged)",
      b.db._dbGeneration() === genAfter);

    var guarded = await _catch(function () { return b.db.from("t"); });
    check("from() after close reports not-initialized", guarded && guarded.code === "db/not-initialized");
  } finally {
    _teardownPlain(tmpDir);
  }
}

// --- tmpfs storage-headroom write gate (fault-injected statfs) -------------

async function testStorageGuard() {
  var tmpDir = _mkTmp("db-cov-storage-");
  try {
    // One vault for the whole test — a second vault.init would rotate the
    // keypair and fail to unseal the db.key.enc written on the first attempt.
    await _freshVault(tmpDir);

    // Bad minFreeBytes surfaces at config time (encrypted branch, after the
    // key file is materialized — hence vault must be up first).
    var badMin = await _catch(function () {
      return b.db.init({
        dataDir: tmpDir, tmpDir: path.join(tmpDir, "tmpfs"), allowNonTmpfsTmpDir: true,
        frameworkTables: false, auditSigning: false, minFreeBytes: -5,
        schema: [{ name: "t", columns: { _id: "TEXT PRIMARY KEY" } }],
      });
    });
    check("init negative minFreeBytes throws db/bad-min-free-bytes",
      badMin && badMin.code === "db/bad-min-free-bytes");
    b.db._resetForTest();

    // Encrypted mode with an injectable free-space reader (reuses the vault
    // + key file from above).
    var freeBytes = C.BYTES.mib(100);
    await b.db.init({
      dataDir: tmpDir, tmpDir: path.join(tmpDir, "tmpfs"), allowNonTmpfsTmpDir: true,
      frameworkTables: false, auditSigning: false,
      minFreeBytes: C.BYTES.mib(16),
      _statfsForTest: function () { return { bavail: freeBytes, bsize: 1 }; },
      schema: [{ name: "t", columns: { _id: "TEXT PRIMARY KEY", v: "TEXT" } }],
    });

    var healthy = b.db._probeStorageForTest();
    check("storage probe: writes allowed when headroom is healthy", healthy.writesRefused === false);

    // Drop below the floor → growth writes refused.
    freeBytes = C.BYTES.kib(1);
    var low = b.db._probeStorageForTest();
    check("storage probe flips writesRefused when free space is low", low.writesRefused === true);

    var refused = await _catch(function () { return b.db.from("t").insertOne({ _id: "x", v: "1" }); });
    check("growth write is refused with db/storage-low under low headroom",
      refused && refused.code === "db/storage-low");

    // A writable-CTE (WITH ... INSERT) is also a growth write — the gate
    // classifies it by effective write syntax, not just the leading keyword.
    var refusedCte = await _catch(function () {
      var st = b.db.prepare("WITH c AS (SELECT 1) INSERT INTO t (_id, v) SELECT 'z', '9'");
      return st.run();
    });
    check("a WITH-prefixed writable-CTE growth write is refused under low headroom",
      refusedCte && refusedCte.code === "db/storage-low");

    // Reads keep serving even while writes are refused.
    var readOk = await _catch(function () { return b.db.from("t").all(); });
    check("reads still serve while writes are refused", readOk === null);

    // Recover headroom → writes re-enabled.
    freeBytes = C.BYTES.mib(100);
    var recovered = b.db._probeStorageForTest();
    check("storage probe clears writesRefused after recovery", recovered.writesRefused === false);

    b.db.from("t").insertOne({ _id: "y", v: "2" });
    check("growth write succeeds after headroom recovers",
      b.db.from("t").where({ _id: "y" }).first().v === "2");
  } finally {
    _teardownPlain(tmpDir);
  }
}

// --- tmpfs resolution: BLAMEJS_TMPDIR + fail-closed no-tmpfs -----------------

async function testTmpfsResolution() {
  var savedTmpEnv = process.env.BLAMEJS_TMPDIR;
  var tmpDir = _mkTmp("db-cov-tmpfs-");
  try {
    // No opts.tmpDir and no BLAMEJS_TMPDIR: encrypted mode (the default) must
    // resolve a tmpfs for the decrypted working copy. On a host without
    // /dev/shm the resolver returns null and boot fail-closes with
    // db/no-tmpfs; on a host WITH /dev/shm it resolves that mount and boots.
    delete process.env.BLAMEJS_TMPDIR;
    await _freshVault(tmpDir);
    var noTmp = await _catch(function () {
      return b.db.init({ dataDir: tmpDir, atRest: "encrypted", schema: [],
        frameworkTables: false, auditSigning: false, minFreeBytes: 0 });
    });
    if (noTmp) {
      check("encrypted init with no resolvable tmpfs fail-closes db/no-tmpfs",
        noTmp.code === "db/no-tmpfs");
    } else {
      check("encrypted init resolved a host tmpfs and booted",
        b.db.getMode() === "encrypted");
    }
    b.db._resetForTest();

    // BLAMEJS_TMPDIR supplies the working-copy mount when opts.tmpDir is
    // omitted. (The Linux-only tmpfs heuristic is skipped on non-Linux;
    // allowNonTmpfsTmpDir downgrades it to a warning where it does run.)
    var envTmpfs = path.join(tmpDir, "envtmpfs");
    fs.mkdirSync(envTmpfs, { recursive: true });
    process.env.BLAMEJS_TMPDIR = envTmpfs;
    await _freshVault(tmpDir);
    await b.db.init({ dataDir: tmpDir, atRest: "encrypted", schema: [],
      allowNonTmpfsTmpDir: true, frameworkTables: false, auditSigning: false, minFreeBytes: 0 });
    check("BLAMEJS_TMPDIR is honored as the encrypted-mode tmpfs mount",
      b.db.getMode() === "encrypted");
  } finally {
    if (savedTmpEnv === undefined) delete process.env.BLAMEJS_TMPDIR;
    else process.env.BLAMEJS_TMPDIR = savedTmpEnv;
    _teardownPlain(tmpDir);
  }
}

// --- tablePrefix passthrough + dataResidency accessor ----------------------

async function testTablePrefixAndResidency() {
  var tmpDir = _mkTmp("db-cov-prefix-");
  try {
    await _freshVault(tmpDir);
    // dataDir points at a not-yet-existent nested path so init creates it;
    // the explicit default tablePrefix drives the setTablePrefix passthrough;
    // dataResidency flows to the accessor; a string-form primaryKey exercises
    // the non-array normalize branch.
    var nestedDir = path.join(tmpDir, "nested", "data");
    check("nested dataDir does not exist before init", !fs.existsSync(nestedDir));
    await b.db.init({
      dataDir: nestedDir, atRest: "plain",
      schema: [{ name: "widgets", columns: { code: "TEXT NOT NULL", label: "TEXT" }, primaryKey: "code" }],
      frameworkTables: false, auditSigning: false,
      tablePrefix: "_blamejs_",
      dataResidency: { region: "eu-west-1", strict: true },
    });
    check("init creates a missing nested dataDir", fs.existsSync(nestedDir));
    check("init with an explicit tablePrefix boots normally",
      typeof b.db.from("widgets").all === "function");
    check("getDataResidency returns the declared region",
      b.db.getDataResidency().region === "eu-west-1");
    check("string-form primaryKey normalizes to a single-column array",
      JSON.stringify(b.db.getTableMetadata("widgets").primaryKey) === '["code"]');
  } finally {
    _teardownPlain(tmpDir);
  }
}

// --- encrypted round-trip: stale-tmpdb sweep, snapshot, decryptToTmp -------

async function testEncryptedRoundTrip() {
  var tmpDir = _mkTmp("db-cov-enc-");
  var tmpfs = path.join(tmpDir, "tmpfs");
  fs.mkdirSync(tmpfs, { recursive: true });
  // Seed a stale plaintext working copy from a "previous crashed process" so
  // init's cleanStaleTmpDbs sweep has an orphan to reclaim.
  fs.writeFileSync(path.join(tmpfs, "blamejs-staleorphan.db"), "orphan");
  var encOpts = {
    dataDir: tmpDir, tmpDir: tmpfs, allowNonTmpfsTmpDir: true, atRest: "encrypted",
    frameworkTables: false, auditSigning: false, minFreeBytes: 0,
    schema: [{ name: "vaultrows", columns: { _id: "TEXT PRIMARY KEY", v: "TEXT" } }],
  };
  try {
    await _freshVault(tmpDir);
    await b.db.init(encOpts);
    check("stale tmpfs working copy is swept at encrypted boot",
      !fs.existsSync(path.join(tmpfs, "blamejs-staleorphan.db")));

    b.db.from("vaultrows").insertOne({ _id: "a", v: "persisted" });

    // snapshot() in encrypted mode returns the sealed envelope Buffer.
    var snap = b.db.snapshot();
    check("encrypted snapshot returns a sealed envelope Buffer",
      Buffer.isBuffer(snap) && snap.length > 26);

    // flushToDisk re-encrypts the live tmpfs copy to db.enc.
    b.db.flushToDisk();
    b.db.close();
    check("close writes the encrypted-at-rest db.enc", fs.existsSync(path.join(tmpDir, "db.enc")));

    // Re-init against the SAME vault + dataDir decrypts db.enc back into a
    // fresh tmpfs working copy (decryptToTmp read + AEAD-verified decrypt).
    await b.db.init(encOpts);
    var row = b.db.from("vaultrows").where({ _id: "a" }).first();
    check("encrypted round-trip recovers the row through decryptToTmp",
      row && row.v === "persisted");
  } finally {
    _teardownPlain(tmpDir);
  }
}

// --- snapshot() in plain mode (raw bytes, no envelope) ---------------------

async function testSnapshotPlain() {
  var tmpDir = _mkTmp("db-cov-snap-");
  try {
    await _plainInit(tmpDir, [{ name: "t", columns: { _id: "TEXT PRIMARY KEY" } }],
      { frameworkTables: false, auditSigning: false });
    b.db.from("t").insertOne({ _id: "s1" });
    var snap = b.db.snapshot();
    check("plain-mode snapshot returns the raw SQLite bytes as a Buffer",
      Buffer.isBuffer(snap) && snap.length > 0);
    // A plain snapshot is an unencrypted SQLite file — the magic header is
    // the ASCII "SQLite format 3\0" string.
    check("plain snapshot carries the SQLite file header",
      snap.slice(0, 16).toString("latin1").indexOf("SQLite format 3") === 0);
  } finally {
    _teardownPlain(tmpDir);
  }
}

// --- file-based migrations (run-once) --------------------------------------

async function testMigrations() {
  var tmpDir = _mkTmp("db-cov-mig-");
  var migDir = path.join(tmpDir, "migrations");
  fs.mkdirSync(migDir, { recursive: true });
  fs.writeFileSync(path.join(migDir, "001-scratch.js"),
    "module.exports = { description: 'create mig_scratch', " +
    "up: function (db) { db.exec('CREATE TABLE mig_scratch (id INTEGER PRIMARY KEY)'); } };");
  try {
    await _plainInit(tmpDir, [], { frameworkTables: false, auditSigning: false, migrationDir: migDir });
    check("migrationDir applies the pending migration",
      b.db.prepare("SELECT name FROM sqlite_master WHERE name='mig_scratch'").get().name === "mig_scratch");

    // Re-running init against the same dataDir skips the already-applied
    // migration (run-once ledger).
    b.db.close();
    b.db._resetForTest();
    await b.db.init({ dataDir: tmpDir, atRest: "plain", schema: [],
      frameworkTables: false, auditSigning: false, migrationDir: migDir });
    check("a re-run leaves the already-applied migration in place",
      b.db.prepare("SELECT name FROM sqlite_master WHERE name='mig_scratch'").get().name === "mig_scratch");
  } finally {
    _teardownPlain(tmpDir);
  }
}

// --- WORM posture boot assertion -------------------------------------------

async function testWormPostureAssertion() {
  var tmpDir = _mkTmp("db-cov-wormposture-");
  try {
    await _freshVault(tmpDir);
    // Under a record-preservation posture (21 CFR Part 11) with framework
    // tables enabled, boot refuses unless at least one operator table has a
    // row-level WORM declaration.
    b.compliance.set("fda-21cfr11");
    var refused = await _catch(function () {
      return b.db.init({ dataDir: tmpDir, atRest: "plain",
        schema: [{ name: "records", columns: { _id: "TEXT PRIMARY KEY" } }] });
    });
    check("boot under a WORM posture with no declared table throws POSTURE_VIOLATION",
      refused && refused.code === "POSTURE_VIOLATION");
  } finally {
    b.compliance.clear();
    _teardownPlain(tmpDir);
  }
}

// --- eraseHard legal-hold consult ------------------------------------------

async function testEraseHardLegalHold() {
  var tmpDir = _mkTmp("db-cov-lh-");
  try {
    await helpers.setupTestDb(tmpDir, [
      { name: "held", columns: { _id: "TEXT PRIMARY KEY", ssn: "TEXT" }, sealedFields: ["ssn"] },
    ]);
    // Registering a legal-hold instance installs the framework singleton
    // eraseHard consults via _getSingleton().isHeld(subjectId).
    var holds = b.legalHold.create({ db: b.db, audit: b.audit });
    holds.place("subject-held", { reason: "litigation hold — matter 42" });

    b.db.from("held").insertOne({ _id: "r1", ssn: "111-11-1111" });
    var denied = await _catch(function () {
      return b.db.eraseHard("held", "r1", { reason: "erasure request now", subjectId: "subject-held" });
    });
    check("eraseHard refuses a row whose subject is on legal hold",
      denied && denied.code === "db/erase-hard-legal-hold");
    check("legally-held row is still present after the refusal",
      !!b.db.from("held").where({ _id: "r1" }).first());

    // A subject NOT on hold takes the pass-through branch and erases.
    b.db.from("held").insertOne({ _id: "r2", ssn: "222-22-2222" });
    var ok = b.db.eraseHard("held", "r2", { reason: "erasure request now", subjectId: "subject-free" });
    check("eraseHard proceeds when the subject is not on legal hold", ok.rowsDeleted === 1);
  } finally {
    b.legalHold._resetForTest();
    await helpers.teardownTestDb(tmpDir);
  }
}

// --- integrityMonitor periodic tick (OK path) ------------------------------

async function testIntegrityMonitorTick() {
  var tmpDir = _mkTmp("db-cov-montick-");
  var mon = null;
  var tapInstalled = false;
  try {
    await _plainInit(tmpDir, [], { frameworkTables: false, auditSigning: false });
    var seen = [];
    b.observability.setTap(function (name) {
      if (typeof name === "string" && name.indexOf("db.integrity_check") !== -1) seen.push(name);
    });
    tapInstalled = true;
    // Short interval so the periodic PRAGMA integrity_check tick actually
    // fires within the test; default audit:true drives the audit-emit branch.
    mon = b.db.integrityMonitor({ intervalMs: 40 });
    await helpers.waitUntil(function () { return seen.length >= 1; }, {
      timeoutMs: 5000, label: "integrityMonitor: first clean tick",
    });
    check("integrityMonitor tick emits the db.integrity_check_ok counter",
      seen.indexOf("db.integrity_check_ok") !== -1);
  } finally {
    if (mon) mon.stop();
    if (tapInstalled) b.observability.setTap(null);
    _teardownPlain(tmpDir);
  }
}

// --- getTableMetadata json-schema type mapping across DDL types ------------

async function testJsonSchemaTypeMapping() {
  var tmpDir = _mkTmp("db-cov-jsontypes-");
  try {
    await _plainInit(tmpDir, [{
      name: "typed",
      columns: {
        _id:    "TEXT PRIMARY KEY",
        n:      "INTEGER NOT NULL",
        amount: "REAL",
        active: "BOOLEAN",
        blobby: "BLOB",
        weird:  "GEOMETRY",
      },
    }], { frameworkTables: false, auditSigning: false });

    var js = b.db.getTableMetadata({ table: "typed", format: "json-schema-2020-12" });
    check("json-schema maps INTEGER → integer", js.properties.n.type === "integer");
    check("json-schema maps REAL → number (nullable union)",
      js.properties.amount.anyOf[0].type === "number");
    check("json-schema maps BOOLEAN → boolean",
      js.properties.active.anyOf[0].type === "boolean");
    check("json-schema maps BLOB → base64-encoded string",
      js.properties.blobby.anyOf[0].contentEncoding === "base64");
    check("json-schema falls back to string for an unrecognized type",
      js.properties.weird.anyOf[0].type === "string");
  } finally {
    _teardownPlain(tmpDir);
  }
}

// --- exportCsv WHERE filter + explicit column projection -------------------

async function testExportCsvWhereProjection() {
  var tmpDir = _mkTmp("db-cov-csv2-");
  try {
    await _plainInit(tmpDir, [{
      name: "sales",
      columns: { _id: "TEXT PRIMARY KEY", region: "TEXT", cents: "INTEGER NOT NULL" },
    }], { frameworkTables: false, auditSigning: false });
    b.db.from("sales").insertOne({ _id: "s1", region: "eu", cents: 100 });
    b.db.from("sales").insertOne({ _id: "s2", region: "us", cents: 200 });
    b.db.from("sales").insertOne({ _id: "s3", region: "eu", cents: 300 });

    var out = b.db.exportCsv({
      table: "sales", columns: ["_id", "cents"], where: { region: "eu" },
    });
    check("exportCsv WHERE filter narrows the row set", out.rowCount === 2);
    check("exportCsv column projection drops unlisted columns",
      out.csv.indexOf("region") === -1 && out.csv.indexOf("cents") !== -1);
  } finally {
    _teardownPlain(tmpDir);
  }
}

// --- legacy plain-sealed DB key → re-seal with deployment-path AAD ---------

async function testLegacyKeyReseal() {
  var tmpDir = _mkTmp("db-cov-legacykey-");
  var tmpfs = path.join(tmpDir, "tmpfs");
  fs.mkdirSync(tmpfs, { recursive: true });
  try {
    await _freshVault(tmpDir);
    // Pre-write a pre-AAD key file the way an older release sealed it —
    // classic vault.seal, no deployment-path binding. Boot must unseal it via
    // the legacy path and re-seal it in place with the AAD binding.
    var rawKeyB64 = Buffer.alloc(32, 7).toString("base64");
    var keyPath = path.join(tmpDir, "db.key.enc");
    fs.writeFileSync(keyPath, b.vault.seal(rawKeyB64));
    check("seeded key file is plain vault-sealed (pre-AAD)",
      fs.readFileSync(keyPath, "utf8").indexOf("vault:") === 0);

    await b.db.init({ dataDir: tmpDir, tmpDir: tmpfs, allowNonTmpfsTmpDir: true,
      atRest: "encrypted", frameworkTables: false, auditSigning: false, minFreeBytes: 0, schema: [] });
    check("encrypted boot accepts the legacy plain-sealed DB key",
      b.db.getMode() === "encrypted");
    check("boot re-seals the DB key in place with the deployment-path AAD",
      fs.readFileSync(keyPath, "utf8").indexOf("vault.aad:") === 0);
  } finally {
    _teardownPlain(tmpDir);
  }
}

// --- refuse-to-boot on audit / consent chain break -------------------------

async function testChainBreakDetection() {
  // A tampered audit_log row (its rowHash doesn't chain from the prior row)
  // must halt boot — tamper-evidence compromised is a hard fail-closed.
  var d1 = _mkTmp("db-cov-chain-a-");
  var opts1 = { dataDir: d1, atRest: "plain", schema: [], auditSigning: false };
  try {
    await _freshVault(d1);
    await b.db.init(opts1);
    // Append-only triggers permit INSERT (that's what audit.record does); a
    // raw insert with a non-chaining rowHash simulates row-level tampering.
    b.db.prepare("INSERT INTO audit_log (_id, recordedAt, monotonicCounter, action, " +
      "outcome, prevHash, rowHash, nonce) VALUES (?,?,?,?,?,?,?,?)")
      .run("tamper-a1", Date.now(), 999000, "tamper.injected", "success",
        "deadbeef", "not-a-valid-chain-hash", Buffer.from("nonce-bytes-16xx"));
    b.db.close();
    b.db._resetForTest();
    var auditBreak = await _catch(function () { return b.db.init(opts1); });
    check("boot refuses on a broken audit_log chain (db/audit-chain-break)",
      auditBreak && auditBreak.code === "db/audit-chain-break");
    try { b.db.close(); } catch (_e) { /* partially-initialized */ }
  } finally {
    _teardownPlain(d1);
  }

  // With the audit chain intact but the consent_log chain tampered, boot must
  // still refuse — the consent chain is verified independently.
  var d2 = _mkTmp("db-cov-chain-c-");
  var opts2 = { dataDir: d2, atRest: "plain", schema: [], auditSigning: false };
  try {
    await _freshVault(d2);
    await b.db.init(opts2);
    b.db.prepare("INSERT INTO consent_log (_id, recordedAt, monotonicCounter, subjectId, " +
      "subjectIdHash, purpose, lawfulBasis, action, channel, prevHash, rowHash, nonce) " +
      "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
      .run("tamper-c1", Date.now(), 999000, "subj", "subjhash", "marketing", "consent",
        "grant", "web", "deadbeef", "bad-chain-hash", Buffer.from("nonce-bytes-16xx"));
    b.db.close();
    b.db._resetForTest();
    var consentBreak = await _catch(function () { return b.db.init(opts2); });
    check("boot refuses on a broken consent_log chain (db/consent-chain-break)",
      consentBreak && consentBreak.code === "db/consent-chain-break");
    try { b.db.close(); } catch (_e) { /* partially-initialized */ }
  } finally {
    _teardownPlain(d2);
  }
}

// --- audit.tip rollback detection (OK / rollback / unreadable) --------------

async function testRollbackDetection() {
  var tmpDir = _mkTmp("db-cov-rollback-");
  var opts = { dataDir: tmpDir, atRest: "plain", schema: [], auditSigning: false };
  var tipPath = path.join(tmpDir, "audit.tip");
  try {
    await _freshVault(tmpDir);
    await b.db.init(opts);
    // A tip at or below the live MAX(monotonicCounter) is not a rollback.
    b.db._writeAuditTip({ atMonotonicCounter: 0, rowHash: "seed", signedAt: new Date().toISOString() });
    b.db.close();
    b.db._resetForTest();
    await b.db.init(opts);
    check("boot with an in-range audit.tip passes the rollback check",
      b.db.getMode() === "plain");

    // A tip recording a HIGHER counter than the live DB means the DB was
    // restored from an older snapshot (or rows were deleted) — refuse boot.
    b.db._writeAuditTip({ atMonotonicCounter: 999999, rowHash: "seed", signedAt: new Date().toISOString() });
    b.db.close();
    b.db._resetForTest();
    var rolled = await _catch(function () { return b.db.init(opts); });
    check("boot with a rollback-shaped audit.tip throws db/audit-rollback-detected",
      rolled && rolled.code === "db/audit-rollback-detected");
    try { b.db.close(); } catch (_e) { /* partially-initialized */ }
    b.db._resetForTest();

    // A corrupt / schema-invalid audit.tip fail-closes rather than silently
    // forfeiting rollback protection.
    fs.writeFileSync(tipPath, "{ not valid json at all ");
    var unreadable = await _catch(function () { return b.db.init(opts); });
    check("boot with an unreadable audit.tip throws db/audit-tip-unreadable",
      unreadable && unreadable.code === "db/audit-tip-unreadable");
  } finally {
    _teardownPlain(tmpDir);
  }
}

// --- json-schema type mapping across the remaining DDL heads ---------------
async function testJsonSchemaTypeAliases() {
  var tmpDir = _mkTmp("db-cov-jsontypes2-");
  try {
    await _plainInit(tmpDir, [{
      name: "aliased",
      columns: {
        _id:      "TEXT PRIMARY KEY",
        i1:       "INT",
        i2:       "BIGINT",
        f1:       "FLOAT",
        f2:       "DOUBLE",
        f3:       "NUMERIC",
        b1:       "BOOL",
        s1:       "VARCHAR",
        s2:       "CHAR",
        reqInt:   "INT NOT NULL",
      },
    }], { frameworkTables: false, auditSigning: false });

    var js = b.db.getTableMetadata({ table: "aliased", format: "json-schema-2020-12" });
    check("json-schema maps INT → integer", js.properties.i1.anyOf[0].type === "integer");
    check("json-schema maps BIGINT → integer", js.properties.i2.anyOf[0].type === "integer");
    check("json-schema maps FLOAT → number", js.properties.f1.anyOf[0].type === "number");
    check("json-schema maps DOUBLE → number", js.properties.f2.anyOf[0].type === "number");
    check("json-schema maps NUMERIC → number", js.properties.f3.anyOf[0].type === "number");
    check("json-schema maps BOOL → boolean", js.properties.b1.anyOf[0].type === "boolean");
    check("json-schema maps VARCHAR → string", js.properties.s1.anyOf[0].type === "string");
    check("json-schema maps CHAR → string", js.properties.s2.anyOf[0].type === "string");
    // A NOT NULL integer-alias column keeps the bare type (no null union) and
    // lands in `required`.
    check("json-schema NOT NULL INT is a bare integer", js.properties.reqInt.type === "integer");
    check("json-schema NOT NULL column is required", js.required.indexOf("reqInt") !== -1);
  } finally {
    _teardownPlain(tmpDir);
  }
}

// --- getTableMetadata explicit blamejs format + posture-after-init ----------
async function testMetadataBlamejsFormatAndPosture() {
  var tmpDir = _mkTmp("db-cov-blamejsfmt-");
  try {
    await _plainInit(tmpDir, [{
      name: "acct", columns: { _id: "TEXT PRIMARY KEY", note: "TEXT" }, sealedFields: ["note"],
    }], { frameworkTables: false, auditSigning: false });

    // Explicit format: "blamejs" takes the structuredClone snapshot branch
    // (distinct from the string-arg and json-schema branches).
    var meta = b.db.getTableMetadata({ table: "acct", format: "blamejs" });
    check("getTableMetadata({format:'blamejs'}) returns the native snapshot",
      meta && meta.sealedFields.indexOf("note") !== -1);

    // applyPosture WHILE the db is open reports dbInitialized:true (the other
    // suite exercises the pre-init false branch).
    var res = b.db.applyPosture("gdpr");
    check("applyPosture after init reports dbInitialized:true",
      res.posture === "gdpr" && res.dbInitialized === true);
    check("getActivePosture reflects the posture set after init",
      b.db.getActivePosture() === "gdpr");
  } finally {
    _teardownPlain(tmpDir);
  }
}

// --- exportCsv: qualified/quoted table + empty projection + out-of-range ts --
async function testExportCsvAdversarialInput() {
  var tmpDir = _mkTmp("db-cov-csvadv-");
  try {
    await _plainInit(tmpDir, [{
      name: "evts",
      columns: { _id: "TEXT PRIMARY KEY", region: "TEXT", when: "INTEGER" },
    }], { frameworkTables: false, auditSigning: false });

    // A schema-qualified / quote-bearing table name is rejected by the
    // identifier quoter BEFORE the registered-table lookup — refuses the
    // injection surface rather than passing it into SQL.
    var qualified = await _catch(function () { return b.db.exportCsv({ table: "main.evts" }); });
    check("exportCsv on a schema-qualified table name is refused",
      qualified && qualified.code === "sql/bad-shape");
    var quoted = await _catch(function () { return b.db.exportCsv({ table: 'ev"ts' }); });
    check("exportCsv on a quote-bearing table name is refused",
      quoted && quoted.code === "sql/bad-shape");

    b.db.from("evts").insertOne({ _id: "e1", region: "eu", when: Date.now() });
    // An empty explicit column projection falls back to the full declared set
    // (length-0 array is treated as "no projection", not "select nothing").
    var allOut = b.db.exportCsv({ table: "evts", columns: [] });
    check("exportCsv with an empty columns array projects all columns",
      allOut.csv.indexOf("region") !== -1 && allOut.csv.indexOf("when") !== -1);

    // A finite ms value outside JS Date's representable range (>8.64e15) makes
    // new Date(v).toISOString() throw RangeError. exportCsv must degrade to the
    // raw numeric string, not crash the whole export.
    b.db.from("evts").insertOne({ _id: "e2", region: "us", when: 9e15 });
    var crashed = null, tsOut = null;
    try { tsOut = b.db.exportCsv({ table: "evts", timestampFields: ["when"] }); }
    catch (e) { crashed = e; }
    check("exportCsv does not crash on an out-of-range timestamp value", crashed === null);
    check("exportCsv still returns every row past the bad timestamp",
      tsOut && tsOut.rowCount === 2);
    check("an out-of-range timestamp degrades to its raw numeric string",
      tsOut && tsOut.csv.indexOf("9000000000000000") !== -1);
  } finally {
    _teardownPlain(tmpDir);
  }
}

// --- declareWorm / dual-control empty-string posture rejection --------------
async function testDeclareEmptyPosture() {
  var tmpDir = _mkTmp("db-cov-emptyposture-");
  try {
    await helpers.setupTestDb(tmpDir, [
      { name: "book", columns: { _id: "TEXT PRIMARY KEY", sym: "TEXT" } },
    ]);

    // An empty-string posture is a distinct branch from a non-string posture:
    // typeof === "string" but length 0 must still be refused.
    var wormEmpty = await _catch(function () {
      return b.db.declareWorm({ tables: ["book"], posture: "" });
    });
    check("declareWorm empty-string posture is refused",
      wormEmpty && wormEmpty.name === "WormViolationError");

    var dcEmpty = await _catch(function () {
      return b.db.declareRequireDualControl({ tables: ["book"], m: 2, n: 3, posture: "" });
    });
    check("declareRequireDualControl empty-string posture throws db/dual-control-bad-posture",
      dcEmpty && dcEmpty.code === "db/dual-control-bad-posture");

    // A null posture is explicitly allowed (recorded as null) — the pass-through
    // branch of the same guard.
    var okNull = b.db.declareWorm({ tables: ["book"], posture: null });
    check("declareWorm accepts a null posture", okNull.posture === null);
  } finally {
    await helpers.teardownTestDb(tmpDir);
  }
}

// --- stream(): a Buffer positional binding is a param, not an opts bag -------
async function testStreamBufferParam() {
  var tmpDir = _mkTmp("db-cov-streambuf-");
  try {
    await _plainInit(tmpDir, [{
      name: "rows", columns: { _id: "TEXT PRIMARY KEY", blobcol: "BLOB" },
    }], { frameworkTables: false, auditSigning: false });
    b.db.from("rows").insertOne({ _id: "r1", blobcol: Buffer.from("AA") });
    b.db.from("rows").insertOne({ _id: "r2", blobcol: Buffer.from("BB") });

    // A trailing Buffer is a SQL binding, not an options object — the last-arg
    // opts sniff excludes Buffers, so this binds as a parameter.
    var res = await _drain(b.db.stream("SELECT * FROM rows WHERE blobcol = ?", Buffer.from("AA")));
    check("stream binds a trailing Buffer as a parameter (not opts)",
      res.error === null && res.rows.length === 1 && res.rows[0]._id === "r1");
  } finally {
    _teardownPlain(tmpDir);
  }
}

async function run() {
  await testJsonSchemaTypeAliases();
  await testMetadataBlamejsFormatAndPosture();
  await testExportCsvAdversarialInput();
  await testDeclareEmptyPosture();
  await testStreamBufferParam();
  await testInitArgValidation();
  await testNotInitializedGuard();
  await testReservedTableNames();
  await testPersonalDataCategories();
  await testMetadataAndAccessors();
  await testTransaction();
  await testExportCsv();
  await testStream();
  await testPrepareCache();
  await testRunSql();
  await testVacuum();
  await testDeclareWorm();
  await testDualControl();
  await testEraseHard();
  await testPurgeAuditChain();
  await testHashHelpers();
  await testIntegrity();
  await testApplyPosture();
  await testCloseAndGeneration();
  await testStorageGuard();
  await testTmpfsResolution();
  await testTablePrefixAndResidency();
  await testEncryptedRoundTrip();
  await testSnapshotPlain();
  await testMigrations();
  await testEraseHardLegalHold();
  await testIntegrityMonitorTick();
  await testJsonSchemaTypeMapping();
  await testExportCsvWhereProjection();
  await testLegacyKeyReseal();
  await testChainBreakDetection();
  await testRollbackDetection();
  await testWormPostureAssertion();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message, e.stack); process.exit(1); }
  );
}
