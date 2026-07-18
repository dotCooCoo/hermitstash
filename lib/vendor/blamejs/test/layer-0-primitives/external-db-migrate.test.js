// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.externalDb.migrate — migration runner for an externalDb backend.
 *
 * End-to-end test against a SQLite-backed fake externalDb driver.
 * Covers up()/down()/status(), idempotent re-apply, lock acquisition,
 * down() refusal when the migration has no down(), audit emissions.
 */

var fs    = require("fs");
var os    = require("os");
var path  = require("path");
var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var _makeSqliteDriver = helpers._makeSqliteDriver;

function _tempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix + "-"));
}

function _writeMigration(dir, name, body) {
  fs.writeFileSync(path.join(dir, name), body);
}

function _initWith(driver, dialect) {
  b.externalDb._resetForTest();
  b.externalDb.init({
    backends: {
      main: {
        connect: driver.connect,
        query:   driver.query,
        close:   driver.close,
        dialect: dialect || "postgres",
      },
    },
  });
}

async function _expectThrow(label, fn, codeRe) {
  var threw = null;
  try { await fn(); } catch (e) { threw = e; }
  check(label,
    threw !== null && (codeRe ? codeRe.test(threw.code || "") : true));
}

// Capture a thrown error so a test can assert on both its code and its
// operator-facing message.
async function _capture(fn) {
  try { await fn(); return null; } catch (e) { return e; }
}

// The lock table name is derived from the tracking-table name (the lock
// table is `<tracking>_lock`), so it tracks the configurable framework
// prefix without a dedicated export.
function _lockTableName() {
  return b.externalDb.migrate.TRACKING_TABLE + "_lock";
}

async function _seedLockRow(lockedAt, lockedBy) {
  await b.externalDb.query(
    "INSERT INTO " + _lockTableName() + " (scope, lockedAt, lockedBy) VALUES ($1, $2, $3)",
    ["lock", lockedAt, lockedBy]);
}

// A thin wrapper over the sqlite driver that lets a test inject a fault
// into exactly one of the migration-lock statements (the conflict-safe
// upsert or the holder-naming inspect SELECT) without disturbing any of
// the other SQL the runner emits. Injected stub only — no network.
function _wrapSqliteDriver(dbPath, hooks) {
  hooks = hooks || {};
  var base = _makeSqliteDriver(dbPath);
  return {
    connect: base.connect,
    close:   base.close,
    _close:  base._close,
    query: async function (client, sql, params) {
      var run = function () { return base.query(client, sql, params); };
      var isLockInsert = /^\s*INSERT INTO\s+"?_blamejs_externaldb_migrations_lock/i.test(sql);
      var isLockInspect = /^\s*SELECT/i.test(sql) && /lockedBy/i.test(sql);
      // The release DELETE keys on lockedBy; the stale-takeover DELETE keys
      // on lockedAt — matching lockedBy isolates the release path.
      var isLockRelease = /^\s*DELETE\s+FROM\s+"?_blamejs_externaldb_migrations_lock/i.test(sql) &&
                          /lockedBy/i.test(sql);
      if (isLockInsert && hooks.onLockUpsert) return hooks.onLockUpsert(run, client, base);
      if (isLockInspect && hooks.onLockInspect) return hooks.onLockInspect(run, client, base);
      if (isLockRelease && hooks.onLockRelease) return hooks.onLockRelease(run, client, base);
      return run();
    },
  };
}

// A minimal DDL up()/down() migration body — the framework tracking /
// history INSERTs are the only DML in the transaction.
function _ddlMigration(table, withDown) {
  return 'module.exports = {\n' +
    '  description: "create ' + table + '",\n' +
    '  up:   async function (xdb) { await xdb.query("CREATE TABLE ' + table + ' (id INTEGER PRIMARY KEY)", []); },\n' +
    (withDown
      ? '  down: async function (xdb) { await xdb.query("DROP TABLE ' + table + '", []); },\n'
      : '') +
    '};\n';
}

// ---------- _resolveBackendName error + explicit-backend paths ----------

async function _testResolveBackendErrors() {
  var migDir = _tempDir("blamejs-xmig-nobk-mig");
  try {
    _writeMigration(migDir, "0001-x.js", _ddlMigration("nobk_t", true));

    // No backends registered → status() surfaces the clear no-backends error.
    b.externalDb._resetForTest();
    var noBk = b.externalDb.migrate.create({ dir: migDir });
    var e1 = await _capture(function () { return noBk.status(); });
    check("status() on an externalDb with no backends throws no-backends",
      e1 !== null && /externaldb-migrate\/no-backends/.test(e1.code || ""));

    // Explicit backend opt selects that backend by name.
    var dataDir = _tempDir("blamejs-xmig-nobk-data");
    var driver = _makeSqliteDriver(path.join(dataDir, "db"));
    _initWith(driver, "postgres");
    try {
      var explicit = b.externalDb.migrate.create({ dir: migDir, backend: "main" });
      var r = await explicit.up();
      check("create({ backend }) resolves the named backend and applies",
        r.backend === "main" && r.applied.indexOf("0001-x.js") !== -1);
    } finally {
      driver._close();
      b.externalDb._resetForTest();
      fs.rmSync(dataDir, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(migDir, { recursive: true, force: true });
  }
}

// ---------- create() option defaults: custom introspect / ranBy /
// signHistory:false (unsigned history) / missing-description ----------

async function _testCreateOptionDefaults() {
  var dataDir = _tempDir("blamejs-xmig-opt-data");
  var migDir  = _tempDir("blamejs-xmig-opt-mig");
  var driver  = _makeSqliteDriver(path.join(dataDir, "db"));
  _initWith(driver, "postgres");
  try {
    // No `description` export → the runner records "" for it.
    _writeMigration(migDir, "0001-opt.js",
      'module.exports = {\n' +
      '  up:   async function (xdb) { await xdb.query("CREATE TABLE opt_thing (id INTEGER PRIMARY KEY)", []); },\n' +
      '  down: async function (xdb) { await xdb.query("DROP TABLE opt_thing", []); },\n' +
      '};\n');

    var introspectCalls = 0;
    var migrate = b.externalDb.migrate.create({
      dir:          migDir,
      ranBy:        "custom-actor",
      signHistory:  false,
      schemaIntrospect: async function () { introspectCalls += 1; return "fixed-introspect-hash"; },
    });

    var r = await migrate.up();
    check("up() applies with custom option set", r.applied.indexOf("0001-opt.js") !== -1);
    check("custom schemaIntrospect ran during up()", introspectCalls >= 1);

    var hist = await migrate.history();
    check("history() row carries the custom ranBy",
      hist.length === 1 && hist[0].ranBy === "custom-actor");
    check("history() row carries the custom introspection hash",
      hist[0].schemaIntrospectionHash === "fixed-introspect-hash");
    check("signHistory:false leaves the history row unsigned (row-unsigned)",
      hist[0].verified === false && hist[0].verifyReason === "row-unsigned");
  } finally {
    driver._close();
    b.externalDb._resetForTest();
    fs.rmSync(dataDir, { recursive: true, force: true });
    fs.rmSync(migDir,  { recursive: true, force: true });
  }
}

// ---------- _loadMigration: a migration file that fails to require ----

async function _testLoadFailed() {
  var dataDir = _tempDir("blamejs-xmig-load-data");
  var migDir  = _tempDir("blamejs-xmig-load-mig");
  var driver  = _makeSqliteDriver(path.join(dataDir, "db"));
  _initWith(driver, "postgres");
  try {
    // Syntactically broken module — require() throws, so the runner
    // surfaces the wrapped load-failed error rather than a raw SyntaxError.
    _writeMigration(migDir, "0001-broken.js",
      "module.exports = {\n  up: async function ( {\n");
    var migrate = b.externalDb.migrate.create({ dir: migDir });
    var e = await _capture(function () { return migrate.up(); });
    check("up() wraps a require-failing migration as load-failed",
      e !== null && /externaldb-migrate\/load-failed/.test(e.code || "") &&
      /0001-broken\.js/.test(e.message || ""));
  } finally {
    driver._close();
    b.externalDb._resetForTest();
    fs.rmSync(dataDir, { recursive: true, force: true });
    fs.rmSync(migDir,  { recursive: true, force: true });
  }
}

// ---------- up(): a migration whose up() throws → up-failed + audit ----

async function _testUpFailed() {
  var dataDir = _tempDir("blamejs-xmig-upfail-data");
  var migDir  = _tempDir("blamejs-xmig-upfail-mig");
  var driver  = _makeSqliteDriver(path.join(dataDir, "db"));
  _initWith(driver, "postgres");
  var auditEmits = [];
  var fakeAudit = { safeEmit: function (e) { auditEmits.push(e); } };
  try {
    _writeMigration(migDir, "0001-boom.js",
      'module.exports = {\n' +
      '  description: "boom",\n' +
      '  up: async function (xdb) { await xdb.query("THIS IS NOT VALID SQL", []); },\n' +
      '};\n');
    var migrate = b.externalDb.migrate.create({ dir: migDir, audit: fakeAudit });
    var e = await _capture(function () { return migrate.up(); });
    check("up() surfaces a failing migration as up-failed",
      e !== null && /externaldb-migrate\/up-failed/.test(e.code || "") &&
      /0001-boom\.js/.test(e.message || ""));
    check("up() emits an up failure audit for the failing migration",
      auditEmits.some(function (x) {
        return x.action === "externaldb.migrate.up" && x.outcome === "failure" &&
               x.metadata && x.metadata.migration === "0001-boom.js";
      }));
    // The lock is still released after the failure (finally path ran).
    check("up() releases the lock even after a migration failure",
      auditEmits.some(function (x) { return x.action === "externaldb.migrate.lock.released"; }));
  } finally {
    driver._close();
    b.externalDb._resetForTest();
    fs.rmSync(dataDir, { recursive: true, force: true });
    fs.rmSync(migDir,  { recursive: true, force: true });
  }
}

// ---------- down(): a failing down() → down-failed; default steps ----

async function _testDownFailedAndDefaultSteps() {
  var dataDir = _tempDir("blamejs-xmig-dnfail-data");
  var migDir  = _tempDir("blamejs-xmig-dnfail-mig");
  var driver  = _makeSqliteDriver(path.join(dataDir, "db"));
  _initWith(driver, "postgres");
  var auditEmits = [];
  var fakeAudit = { safeEmit: function (e) { auditEmits.push(e); } };
  try {
    // 0001 rolls back cleanly; 0002 has a down() that throws.
    _writeMigration(migDir, "0001-ok.js", _ddlMigration("dn_ok_t", true));
    _writeMigration(migDir, "0002-baddown.js",
      'module.exports = {\n' +
      '  description: "bad down",\n' +
      '  up:   async function (xdb) { await xdb.query("CREATE TABLE dn_bad_t (id INTEGER)", []); },\n' +
      '  down: async function (xdb) { await xdb.query("NOT VALID SQL EITHER", []); },\n' +
      '};\n');
    var migrate = b.externalDb.migrate.create({ dir: migDir, audit: fakeAudit });
    await migrate.up();

    // down() with no args defaults steps to 1 → most-recent migration only.
    var e = await _capture(function () { return migrate.down(); });
    check("down() (default steps) surfaces a failing rollback as down-failed",
      e !== null && /externaldb-migrate\/down-failed/.test(e.code || "") &&
      /0002-baddown\.js/.test(e.message || ""));
    check("down() emits a down failure audit for the failing migration",
      auditEmits.some(function (x) {
        return x.action === "externaldb.migrate.down" && x.outcome === "failure" &&
               x.metadata && x.metadata.migration === "0002-baddown.js";
      }));
  } finally {
    driver._close();
    b.externalDb._resetForTest();
    fs.rmSync(dataDir, { recursive: true, force: true });
    fs.rmSync(migDir,  { recursive: true, force: true });
  }
}

// ---------- _emit: a throwing audit sink must not crash the migration --

async function _testEmitAuditThrows() {
  var dataDir = _tempDir("blamejs-xmig-emit-data");
  var migDir  = _tempDir("blamejs-xmig-emit-mig");
  var driver  = _makeSqliteDriver(path.join(dataDir, "db"));
  _initWith(driver, "postgres");
  try {
    _writeMigration(migDir, "0001-emit.js", _ddlMigration("emit_t", true));
    var throwingAudit = { safeEmit: function () { throw new Error("audit sink is down"); } };
    var migrate = b.externalDb.migrate.create({ dir: migDir, audit: throwingAudit });
    var r = await migrate.up();
    check("up() succeeds even when audit.safeEmit throws (drop-silent)",
      r.applied.indexOf("0001-emit.js") !== -1);
  } finally {
    driver._close();
    b.externalDb._resetForTest();
    fs.rmSync(dataDir, { recursive: true, force: true });
    fs.rmSync(migDir,  { recursive: true, force: true });
  }
}

// ---------- Adversarial lock state: a held lock refuses the wave ------

async function _testLockHeldRefusal() {
  var dataDir = _tempDir("blamejs-xmig-held-data");
  var migDir  = _tempDir("blamejs-xmig-held-mig");
  var driver  = _makeSqliteDriver(path.join(dataDir, "db"));
  _initWith(driver, "postgres");
  try {
    _writeMigration(migDir, "0001-h.js", _ddlMigration("held_a", true));
    var migrate = b.externalDb.migrate.create({ dir: migDir });
    await migrate.up();  // creates the lock table + applies + releases

    // A competing process holds a FRESH lock. With no staleAfterMs the
    // wave must refuse rather than steal it.
    await _seedLockRow(Date.now(), "held-by-other@host@boot");
    _writeMigration(migDir, "0002-h.js", _ddlMigration("held_b", true));

    var e = await _capture(function () { return migrate.up(); });
    check("up() refuses when the lock is held by another live process (lock-held)",
      e !== null && /externaldb-migrate\/lock-held/.test(e.code || "") &&
      /held-by-other@host@boot/.test(e.message || ""));
    var st = await migrate.status();
    check("the held lock prevented the pending migration from applying",
      st.pending.indexOf("0002-h.js") !== -1);
  } finally {
    driver._close();
    b.externalDb._resetForTest();
    fs.rmSync(dataDir, { recursive: true, force: true });
    fs.rmSync(migDir,  { recursive: true, force: true });
  }
}

// ---------- Stale-lock takeover on both up() and down() --------------

async function _testStaleLockTakeover() {
  var dataDir = _tempDir("blamejs-xmig-stale-data");
  var migDir  = _tempDir("blamejs-xmig-stale-mig");
  var driver  = _makeSqliteDriver(path.join(dataDir, "db"));
  _initWith(driver, "postgres");
  var auditEmits = [];
  var fakeAudit = { safeEmit: function (e) { auditEmits.push(e); } };
  try {
    _writeMigration(migDir, "0001-s.js", _ddlMigration("stale_a", true));
    var migrate = b.externalDb.migrate.create({
      dir: migDir, staleAfterMs: 1000, audit: fakeAudit,
    });
    await migrate.up();  // clean apply, creates the lock table

    // An orphaned lock older than staleAfterMs → up() force-replaces it.
    await _seedLockRow(Date.now() - 100000, "stale-holder@host@boot");
    await migrate.up();  // 0001 already applied; the takeover still fires
    check("up() takes over a stale lock and emits a takeover audit",
      auditEmits.some(function (x) {
        return x.action === "externaldb.migrate.lock.takeover" && x.outcome === "success" &&
               x.metadata && x.metadata.takeoverFrom === "stale-holder@host@boot";
      }));

    // Now exercise the same stale-takeover branch through down().
    auditEmits.length = 0;
    await _seedLockRow(Date.now() - 100000, "stale-holder-2@host@boot");
    var d = await migrate.down({ steps: 1 });
    check("down() takes over a stale lock and reverts the migration",
      d.reverted.indexOf("0001-s.js") !== -1 &&
      auditEmits.some(function (x) {
        return x.action === "externaldb.migrate.lock.takeover" &&
               x.metadata && x.metadata.takeoverFrom === "stale-holder-2@host@boot";
      }));
  } finally {
    driver._close();
    b.externalDb._resetForTest();
    fs.rmSync(dataDir, { recursive: true, force: true });
    fs.rmSync(migDir,  { recursive: true, force: true });
  }
}

// ---------- Lock acquire: injected driver / inspect faults ------------

async function _testLockUpsertDriverFault() {
  var dataDir = _tempDir("blamejs-xmig-upsertf-data");
  var migDir  = _tempDir("blamejs-xmig-upsertf-mig");
  var driver  = _wrapSqliteDriver(path.join(dataDir, "db"), {
    onLockUpsert: function () { throw new Error("simulated lock upsert driver fault"); },
  });
  _initWith(driver, "postgres");
  try {
    _writeMigration(migDir, "0001-uf.js", _ddlMigration("uf_t", true));
    var migrate = b.externalDb.migrate.create({ dir: migDir });
    var e = await _capture(function () { return migrate.up(); });
    check("a driver fault on the lock upsert surfaces as lock-busy",
      e !== null && /externaldb-migrate\/lock-busy/.test(e.code || "") &&
      /simulated lock upsert driver fault/.test(e.message || ""));
  } finally {
    driver._close();
    b.externalDb._resetForTest();
    fs.rmSync(dataDir, { recursive: true, force: true });
    fs.rmSync(migDir,  { recursive: true, force: true });
  }
}

async function _testLockInspectFault() {
  var dataDir = _tempDir("blamejs-xmig-inspf-data");
  var migDir  = _tempDir("blamejs-xmig-inspf-mig");
  var driver  = _wrapSqliteDriver(path.join(dataDir, "db"), {
    onLockInspect: function () { throw new Error("simulated inspect fault"); },
  });
  _initWith(driver, "postgres");
  try {
    _writeMigration(migDir, "0001-if.js", _ddlMigration("if_t", true));
    var migrate = b.externalDb.migrate.create({ dir: migDir });
    await migrate.up();  // clean acquire (upsert wins, no inspect), applies

    // Seed a competing row so the next acquire hits the DO-NOTHING no-op
    // and must inspect the holder — where the driver fault fires.
    await _seedLockRow(Date.now(), "other@host@boot");
    _writeMigration(migDir, "0002-if.js", _ddlMigration("if_t2", true));
    var e = await _capture(function () { return migrate.up(); });
    check("a fault inspecting the lock holder surfaces as lock-held",
      e !== null && /externaldb-migrate\/lock-held/.test(e.code || "") &&
      /could not be inspected/.test(e.message || ""));
  } finally {
    driver._close();
    b.externalDb._resetForTest();
    fs.rmSync(dataDir, { recursive: true, force: true });
    fs.rmSync(migDir,  { recursive: true, force: true });
  }
}

async function _testLockVanishRetryWins() {
  var dataDir = _tempDir("blamejs-xmig-vwin-data");
  var migDir  = _tempDir("blamejs-xmig-vwin-mig");
  var lockTable = _lockTableName();
  var driver = _wrapSqliteDriver(path.join(dataDir, "db"), {
    // The lock row "vanishes" between our no-op insert and the inspect
    // (the holder released concurrently): drop it and report empty so the
    // runner's single retry insert wins the lock.
    onLockInspect: async function (_run, client, base) {
      await base.query(client, "DELETE FROM " + lockTable + " WHERE scope = 'lock'", []);
      return { rows: [], rowCount: 0 };
    },
  });
  _initWith(driver, "postgres");
  try {
    _writeMigration(migDir, "0001-vw.js", _ddlMigration("vw_t", true));
    var migrate = b.externalDb.migrate.create({ dir: migDir });
    await migrate.up();  // clean acquire — no inspect, so no vanish

    await _seedLockRow(Date.now(), "racing-holder@host@boot");
    _writeMigration(migDir, "0002-vw.js", _ddlMigration("vw_t2", true));
    var r = await migrate.up();
    check("up() recovers when the held lock vanishes mid-inspect (retry wins)",
      r.applied.indexOf("0002-vw.js") !== -1);
  } finally {
    driver._close();
    b.externalDb._resetForTest();
    fs.rmSync(dataDir, { recursive: true, force: true });
    fs.rmSync(migDir,  { recursive: true, force: true });
  }
}

async function _testLockVanishRetryLost() {
  var dataDir = _tempDir("blamejs-xmig-vlost-data");
  var migDir  = _tempDir("blamejs-xmig-vlost-mig");
  var driver = _wrapSqliteDriver(path.join(dataDir, "db"), {
    // The inspect reports empty (holder appears to have released) but the
    // row is NOT actually removed, so the retry insert still conflicts and
    // the runner reports the lock as re-acquired by another process.
    onLockInspect: function () { return { rows: [], rowCount: 0 }; },
  });
  _initWith(driver, "postgres");
  try {
    _writeMigration(migDir, "0001-vl.js", _ddlMigration("vl_t", true));
    var migrate = b.externalDb.migrate.create({ dir: migDir });
    await migrate.up();  // clean acquire

    await _seedLockRow(Date.now(), "racer@host@boot");
    _writeMigration(migDir, "0002-vl.js", _ddlMigration("vl_t2", true));
    var e = await _capture(function () { return migrate.up(); });
    check("up() refuses when the retry loses the acquire race (lock-held)",
      e !== null && /externaldb-migrate\/lock-held/.test(e.code || "") &&
      /re-acquired it during the acquire race/.test(e.message || ""));
  } finally {
    driver._close();
    b.externalDb._resetForTest();
    fs.rmSync(dataDir, { recursive: true, force: true });
    fs.rmSync(migDir,  { recursive: true, force: true });
  }
}

// ---------- _releaseLock: a faulting release DELETE is swallowed -----

async function _testReleaseSwallowsDeleteFault() {
  var dataDir = _tempDir("blamejs-xmig-rel-data");
  var migDir  = _tempDir("blamejs-xmig-rel-mig");
  var driver  = _wrapSqliteDriver(path.join(dataDir, "db"), {
    onLockRelease: function () { throw new Error("simulated release delete fault"); },
  });
  _initWith(driver, "postgres");
  var auditEmits = [];
  var fakeAudit = { safeEmit: function (e) { auditEmits.push(e); } };
  try {
    _writeMigration(migDir, "0001-rel.js", _ddlMigration("rel_t", true));
    var migrate = b.externalDb.migrate.create({ dir: migDir, audit: fakeAudit });
    var r = await migrate.up();
    check("up() completes even when the lock-release DELETE faults (swallowed)",
      r.applied.indexOf("0001-rel.js") !== -1);
    // _releaseLock swallows the DELETE error, so the release transaction
    // still commits and the outer emit reports a successful release.
    check("a faulting release DELETE is swallowed, not surfaced",
      auditEmits.some(function (x) {
        return x.action === "externaldb.migrate.lock.released" && x.outcome === "success";
      }));
  } finally {
    driver._close();
    b.externalDb._resetForTest();
    fs.rmSync(dataDir, { recursive: true, force: true });
    fs.rmSync(migDir,  { recursive: true, force: true });
  }
}

// ---------- history() signature verification + tamper detection ------
// Needs a live audit-signing key, so it runs under the full-framework
// fixture (setupTestDb bootstraps b.auditSign at b.db.init).

async function _testHistorySignedAndTamper() {
  var tmpDir = _tempDir("blamejs-xmig-hist-fw");
  await helpers.setupTestDb(tmpDir);
  var dataDir = _tempDir("blamejs-xmig-hist-data");
  var migDir  = _tempDir("blamejs-xmig-hist-mig");
  var driver  = _makeSqliteDriver(path.join(dataDir, "db"));
  _initWith(driver, "postgres");
  var auditEmits = [];
  var fakeAudit = { safeEmit: function (e) { auditEmits.push(e); } };
  try {
    _writeMigration(migDir, "0001-a.js", _ddlMigration("hist_a", true));
    _writeMigration(migDir, "0002-b.js", _ddlMigration("hist_b", true));
    var migrate = b.externalDb.migrate.create({ dir: migDir, audit: fakeAudit });
    await migrate.up();

    // Every history row is signed and verifies against the live key.
    var h1 = await migrate.history();
    check("history() verifies signed rows",
      h1.length === 2 && h1.every(function (r) { return r.verified === true && r.verifyReason === null; }));
    check("history() emits a verified-rows audit",
      auditEmits.some(function (x) { return x.action === "migrations.history.verified"; }));

    var histTable = b.externalDb.migrate.HISTORY_TABLE;

    // Tamper: swap the recorded public-key fingerprint on one row.
    await b.externalDb.query(
      "UPDATE " + histTable + " SET publicKeyFingerprint = $1 WHERE version = $2",
      ["deadbeefdeadbeef", "0002-b.js"]);
    auditEmits.length = 0;
    var h2 = await migrate.history();
    var row2 = h2.filter(function (r) { return r.version === "0002-b.js"; })[0];
    check("history() flags a fingerprint mismatch",
      row2 && row2.verified === false && row2.verifyReason === "public-key-fingerprint-mismatch");
    check("history() emits tamper_detected on the mismatching row",
      auditEmits.some(function (x) {
        return x.action === "migrations.history.tamper_detected" &&
               x.metadata && x.metadata.version === "0002-b.js";
      }));

    // Tamper: keep the fingerprint neutral (NULL) but corrupt the signature
    // bytes → the cryptographic verify fails (or throws), never verifies.
    await b.externalDb.query(
      "UPDATE " + histTable + " SET publicKeyFingerprint = $1, signature = $2 WHERE version = $3",
      [null, "AAAA", "0002-b.js"]);
    var h3 = await migrate.history();
    var row2b = h3.filter(function (r) { return r.version === "0002-b.js"; })[0];
    check("history() refuses a corrupted signature",
      row2b && row2b.verified === false &&
      (row2b.verifyReason === "signature-verify-failed" || /^verify-threw/.test(row2b.verifyReason || "")));
    // The untampered row still verifies.
    var row1 = h3.filter(function (r) { return r.version === "0001-a.js"; })[0];
    check("the untampered history row still verifies", row1 && row1.verified === true);
  } finally {
    driver._close();
    b.externalDb._resetForTest();
    fs.rmSync(dataDir, { recursive: true, force: true });
    fs.rmSync(migDir,  { recursive: true, force: true });
    await helpers.teardownTestDb(tmpDir);
  }
}

async function run() {
  // ---------- create() rejects bad opts ----------

  _expectThrow("create rejects missing dir",
    function () { b.externalDb.migrate.create({}); },
    /externaldb-migrate\/no-dir/);

  _expectThrow("create with no argument defaults opts to {} then rejects missing dir",
    function () { b.externalDb.migrate.create(); },
    /externaldb-migrate\/no-dir/);

  _expectThrow("create rejects unknown opt",
    function () { b.externalDb.migrate.create({ dir: ".", bogus: 1 }); });
    // validateOpts throws without a code attribute — just assert it throws.

  _expectThrow("create rejects bad audit",
    function () { b.externalDb.migrate.create({ dir: ".", audit: { nope: true } }); },
    /externaldb-migrate\/bad-audit/);

  _expectThrow("create rejects negative staleAfterMs",
    function () { b.externalDb.migrate.create({ dir: ".", staleAfterMs: -1 }); },
    /externaldb-migrate\/bad-stale/);

  // ---------- End-to-end: apply two migrations against a sqlite-backed driver ----------

  var dataDir = _tempDir("blamejs-xmig-data");
  var migDir  = _tempDir("blamejs-xmig-mig");
  var sqlitePath = path.join(dataDir, "fake-pg.db");
  var driver = _makeSqliteDriver(sqlitePath);
  _initWith(driver, "postgres");

  _writeMigration(migDir, "0001-make-thing.js",
    'module.exports = {\n' +
    '  description: "create thing",\n' +
    '  up:   async function (xdb) { await xdb.query("CREATE TABLE thing (id INTEGER PRIMARY KEY, name TEXT)", []); },\n' +
    '  down: async function (xdb) { await xdb.query("DROP TABLE thing", []); },\n' +
    '};\n');

  _writeMigration(migDir, "0002-add-row.js",
    'module.exports = {\n' +
    '  description: "seed thing",\n' +
    '  up:   async function (xdb) { await xdb.query("INSERT INTO thing (id, name) VALUES ($1, $2)", [1, "hello"]); },\n' +
    '  down: async function (xdb) { await xdb.query("DELETE FROM thing WHERE id = $1", [1]); },\n' +
    '};\n');

  // Fake audit captor — proves the migrate runner emits.
  var auditEmits = [];
  var fakeAudit = {
    safeEmit: function (event) { auditEmits.push(event); },
  };

  var migrate = b.externalDb.migrate.create({
    dir:    migDir,
    audit:  fakeAudit,
  });

  // Initial status — both pending
  var s0 = await migrate.status();
  check("status before apply: 2 pending",
    s0.pending.length === 2 && s0.applied.length === 0);

  // Apply
  var r1 = await migrate.up();
  check("up applied both migrations",
    r1.applied.length === 2 &&
    r1.applied.indexOf("0001-make-thing.js") !== -1 &&
    r1.applied.indexOf("0002-add-row.js") !== -1);

  // Status after — both applied
  var s1 = await migrate.status();
  check("status after apply: 2 applied, 0 pending",
    s1.applied.length === 2 && s1.pending.length === 0);

  // The migration's CREATE TABLE actually ran — query through externalDb.query
  var thingRes = await b.externalDb.query("SELECT * FROM thing WHERE id = $1", [1]);
  check("migration's up() ran (row exists)",
    thingRes.rows.length === 1 && thingRes.rows[0].name === "hello");

  // Re-apply — idempotent, both skipped
  var r2 = await migrate.up();
  check("re-apply: both skipped", r2.applied.length === 0 && r2.skipped.length === 2);

  // Audit fired
  check("audit captured up.success events",
    auditEmits.filter(function (e) { return e.action === "externaldb.migrate.up" && e.outcome === "success"; }).length === 2);
  check("audit captured lock acquired+released",
    auditEmits.some(function (e) { return e.action === "externaldb.migrate.lock.acquired"; }) &&
    auditEmits.some(function (e) { return e.action === "externaldb.migrate.lock.released"; }));

  // ---------- down(steps:1) ----------

  var d1 = await migrate.down({ steps: 1 });
  check("down(steps:1) reverted most recent migration",
    d1.reverted.length === 1 && d1.reverted[0] === "0002-add-row.js");

  var thingRes2 = await b.externalDb.query("SELECT * FROM thing WHERE id = $1", [1]);
  check("down() actually rolled back the row",
    thingRes2.rows.length === 0);

  var s2 = await migrate.status();
  check("status after partial rollback: 1 applied, 1 pending",
    s2.applied.length === 1 && s2.pending.length === 1);

  // ---------- down on a migration with no down() ----------

  // First re-apply 0002 so we can exercise no-down on a different migration
  await migrate.up();

  // Now write a 0003 without a down()
  _writeMigration(migDir, "0003-no-down.js",
    'module.exports = {\n' +
    '  description: "no down",\n' +
    '  up: async function (xdb) { await xdb.query("CREATE TABLE no_down_t (id INTEGER)", []); },\n' +
    '};\n');

  var r3 = await migrate.up();
  check("up applied 0003-no-down",
    r3.applied.length === 1 && r3.applied[0] === "0003-no-down.js");

  await _expectThrow("down() without a down() function throws clear error",
    async function () { await migrate.down({ steps: 1 }); },
    /externaldb-migrate\/no-down/);

  // ---------- rejects bad migration file ----------

  _writeMigration(migDir, "0004-bad.js",
    'module.exports = { description: "bad" };  // no up()\n');

  await _expectThrow("up() throws on migration missing up()",
    async function () { await migrate.up(); },
    /externaldb-migrate\/missing-up/);

  driver._close();
  b.externalDb._resetForTest();
  fs.rmSync(dataDir, { recursive: true, force: true });
  fs.rmSync(migDir,  { recursive: true, force: true });

  // ---------- Residency: framework tracking writes survive a
  // residency-tagged backend under a cross-border regulated posture ----
  // The migrate runner's own tracking / history / lock INSERTs are
  // region-neutral metadata and carry the "unrestricted" tag; without
  // that exemption the per-row residency write gate would refuse every
  // migration with RESIDENCY_GATE_REQUIRED on an eu-tagged backend
  // under gdpr.
  var resDataDir = _tempDir("blamejs-xmig-res-data");
  var resMigDir  = _tempDir("blamejs-xmig-res-mig");
  var resDriver  = _makeSqliteDriver(path.join(resDataDir, "fake-pg.db"));
  b.externalDb._resetForTest();
  b.externalDb.init({
    backends: {
      main: {
        connect: resDriver.connect, query: resDriver.query,
        close: resDriver.close, dialect: "postgres", residencyTag: "eu",
      },
    },
  });
  // DDL-only migration — the only DML in the transaction is the
  // framework's tracking + history INSERTs (operator DML would itself
  // be gated, which is correct, so the migration body stays DDL).
  _writeMigration(resMigDir, "0001-ddl-only.js",
    'module.exports = {\n' +
    '  description: "create widget",\n' +
    '  up:   async function (xdb) { await xdb.query("CREATE TABLE widget (id INTEGER PRIMARY KEY)", []); },\n' +
    '  down: async function (xdb) { await xdb.query("DROP TABLE widget", []); },\n' +
    '};\n');
  var resMigrate = b.externalDb.migrate.create({ dir: resMigDir });
  b.compliance.clear();
  b.compliance.set("gdpr");
  try {
    var resR = await resMigrate.up();
    check("migrate up() succeeds on eu backend under gdpr (framework writes exempt)",
      resR.applied.length === 1 && resR.applied[0] === "0001-ddl-only.js");
    // The tracking row landed — re-running is idempotent (proves the
    // framework INSERT into the tracking table actually committed).
    var resR2 = await resMigrate.up();
    check("migrate is idempotent after the tracked apply (tracking INSERT committed)",
      resR2.applied.length === 0 && resR2.skipped.length === 1);
  } finally {
    b.compliance.clear();
    resDriver._close();
    b.externalDb._resetForTest();
    fs.rmSync(resDataDir, { recursive: true, force: true });
    fs.rmSync(resMigDir,  { recursive: true, force: true });
  }

  // ---------- Error / adversarial / option-default branches ----------

  await _testResolveBackendErrors();
  await _testCreateOptionDefaults();
  await _testLoadFailed();
  await _testUpFailed();
  await _testDownFailedAndDefaultSteps();
  await _testEmitAuditThrows();
  await _testLockHeldRefusal();
  await _testStaleLockTakeover();
  await _testLockUpsertDriverFault();
  await _testLockInspectFault();
  await _testLockVanishRetryWins();
  await _testLockVanishRetryLost();
  await _testReleaseSwallowsDeleteFault();
  await _testHistorySignedAndTamper();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
