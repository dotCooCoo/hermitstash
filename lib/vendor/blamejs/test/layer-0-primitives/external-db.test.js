// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * external-db — error / defensive / adversarial branch coverage for
 * b.externalDb. Drives the PUBLIC API with in-memory fake drivers (no real
 * Postgres): init/config validation, backend-pick precedence, query retry +
 * connection-destroy paths, transaction (deadlock retry / rollback /
 * sessionGucs / non-atomic refusal), health checks, pool internals
 * (waiter/drain/destroy/reap), read-replica routing + health + config
 * residency, connectAs SET wiring, runAs role routing, and the internal SQL
 * classifiers.
 *
 * Fault injection covers every catch/else: a driver that throws a chosen
 * SQLSTATE on a matched statement, a connect() that throws, a ping() that
 * throws, and transaction bodies that throw transient (40P01/40001) vs
 * permanent errors.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// ---- shared fixtures -------------------------------------------------------

// In-memory driver. Records every SQL string on `seen`. Options:
//   connectThrows: <code>   → connect() rejects with err.code = <code>
//   pingThrows:    <code>   → adds a ping() that rejects
//   ping:          true     → adds a resolving ping()
//   failOn: { re, code, times } → query() throws err.code=<code> the first
//                                  <times> statements matching <re>
//   roles: [names]          → a pg_roles SELECT returns those rolname rows
function mkDriver(label, opts) {
  opts = opts || {};
  var seen = [];
  var roles = opts.roles || [];
  var failOn = opts.failOn ? { re: opts.failOn.re, code: opts.failOn.code, times: opts.failOn.times } : null;
  var d = {
    label: label,
    seen:  seen,
    connect: async function () {
      if (opts.connectThrows) {
        var ce = new Error(label + " connect fail");
        ce.code = opts.connectThrows;
        throw ce;
      }
      return { id: label };
    },
    query: async function (_client, sql, _params) {
      seen.push(sql);
      if (failOn && failOn.re.test(sql) && failOn.times > 0) {
        failOn.times -= 1;
        var e = new Error(label + " query fail");
        e.code = failOn.code;
        throw e;
      }
      if (/pg_roles/i.test(sql)) {
        return { rows: roles.map(function (n) { return { rolname: n }; }), rowCount: roles.length };
      }
      if (/^SELECT\s+1\b/i.test(sql)) return { rows: [{ n: 1 }], rowCount: 1 };
      if (/^(BEGIN|COMMIT|ROLLBACK|SET\b|SAVEPOINT|RELEASE)/i.test(sql)) return { rows: [], rowCount: 0 };
      if (/^(SELECT|SHOW|PRAGMA|DESC|VALUES|TABLE)\b/i.test(sql)) return { rows: [{ src: label }], rowCount: 1 };
      return { rows: [], rowCount: 1 };
    },
    close: async function () { /* no-op */ },
  };
  if (opts.pingThrows) {
    d.ping = async function () { var pe = new Error(label + " ping fail"); pe.code = opts.pingThrows; throw pe; };
  } else if (opts.ping) {
    d.ping = async function () { return true; };
  }
  return d;
}

function _saw(driver, re) {
  return driver.seen.some(function (s) { return re.test(s); });
}

function okBackend() {
  return {
    connect: async function () { return {}; },
    query:   async function () { return { rows: [], rowCount: 0 }; },
  };
}

async function expectThrow(label, fn, code) {
  var threw = null;
  try { await fn(); } catch (e) { threw = e; }
  check(label, threw !== null && (code === null || threw.code === code));
  return threw;
}

function expectThrowSync(label, fn, code) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, threw !== null && (code === null || threw.code === code));
  return threw;
}

function expectInitThrow(label, initOpts, code) {
  b.externalDb._resetForTest();
  var threw = null;
  try { b.externalDb.init(initOpts); } catch (e) { threw = e; }
  check(label, threw !== null && (code === null || threw.code === code));
  b.externalDb._resetForTest();
}

// ---- not-initialized guards ------------------------------------------------

async function testNotInitialized() {
  b.externalDb._resetForTest();
  await expectThrow("query before init → NOT_INITIALIZED",
    function () { return b.externalDb.query("SELECT 1"); }, "NOT_INITIALIZED");
  await expectThrow("transaction before init → NOT_INITIALIZED",
    function () { return b.externalDb.transaction(async function () {}); }, "NOT_INITIALIZED");
  await expectThrow("healthCheck before init → NOT_INITIALIZED",
    function () { return b.externalDb.healthCheck(); }, "NOT_INITIALIZED");
  await expectThrow("read.query before init → NOT_INITIALIZED",
    function () { return b.externalDb.read.query("SELECT 1"); }, "NOT_INITIALIZED");
  await expectThrow("assertRoleHardening before init → NOT_INITIALIZED",
    function () { return b.externalDb.assertRoleHardening({ declaredRoles: [] }); }, "NOT_INITIALIZED");
  expectThrowSync("configurePool before init → NOT_INITIALIZED",
    function () { b.externalDb.configurePool("main", { min: 1 }); }, "NOT_INITIALIZED");
  expectThrowSync("supportsTransactions before init → NOT_INITIALIZED",
    function () { b.externalDb.supportsTransactions(); }, "NOT_INITIALIZED");

  check("listBackends before init → []",
    Array.isArray(b.externalDb.listBackends()) && b.externalDb.listBackends().length === 0);
  await b.externalDb.shutdown();
  check("shutdown before init is a no-op", true);
}

// ---- init config validation ------------------------------------------------

function testInitValidation() {
  expectInitThrow("init(undefined) → throws", undefined, null);
  expectInitThrow("init missing backends → throws", {}, null);
  expectInitThrow("init backend missing connect → INVALID_CONFIG",
    { backends: { main: { query: async function () {} } } }, "INVALID_CONFIG");
  expectInitThrow("init backend missing query → INVALID_CONFIG",
    { backends: { main: { connect: async function () {} } } }, "INVALID_CONFIG");
  expectInitThrow("init unknown dialect → INVALID_CONFIG",
    { backends: { main: { connect: async function () {}, query: async function () {}, dialect: "oracle" } } },
    "INVALID_CONFIG");
  expectInitThrow("init applicationName empty string → INVALID_CONFIG",
    { backends: { main: { connect: async function () {}, query: async function () {}, applicationName: "" } } },
    "INVALID_CONFIG");
  expectInitThrow("init supportsTransactions non-boolean → INVALID_CONFIG",
    { backends: { main: { connect: async function () {}, query: async function () {}, supportsTransactions: "yes" } } },
    "INVALID_CONFIG");
  expectInitThrow("init batch non-function → INVALID_CONFIG",
    { backends: { main: { connect: async function () {}, query: async function () {}, batch: "nope" } } },
    "INVALID_CONFIG");

  // dbRoleBackends validation
  expectInitThrow("dbRoleBackends non-object → INVALID_CONFIG",
    { backends: { main: okBackend() }, dbRoleBackends: [] }, "INVALID_CONFIG");
  expectInitThrow("dbRoleBackends invalid role identifier → INVALID_CONFIG",
    { backends: { main: okBackend() }, dbRoleBackends: { "1bad": "main" } }, "INVALID_CONFIG");
  expectInitThrow("dbRoleBackends backend name non-string → INVALID_CONFIG",
    { backends: { main: okBackend() }, dbRoleBackends: { good_role: 123 } }, "INVALID_CONFIG");
  expectInitThrow("dbRoleBackends unknown backend → INVALID_CONFIG",
    { backends: { main: okBackend() }, dbRoleBackends: { good_role: "nope" } }, "INVALID_CONFIG");

  // replica config validation
  expectInitThrow("replicas non-array → INVALID_CONFIG",
    { backends: { main: { connect: async function () {}, query: async function () {}, replicas: "x" } } },
    "INVALID_CONFIG");
  expectInitThrow("replicas empty array → INVALID_CONFIG",
    { backends: { main: { connect: async function () {}, query: async function () {}, replicas: [] } } },
    "INVALID_CONFIG");
  expectInitThrow("replica missing connect → INVALID_CONFIG",
    { backends: { main: { connect: async function () {}, query: async function () {},
      replicas: [{ query: async function () {} }] } } }, "INVALID_CONFIG");
  expectInitThrow("replica missing query → INVALID_CONFIG",
    { backends: { main: { connect: async function () {}, query: async function () {},
      replicas: [{ connect: async function () {} }] } } }, "INVALID_CONFIG");
  expectInitThrow("replica weight non-positive → INVALID_CONFIG",
    { backends: { main: { connect: async function () {}, query: async function () {},
      replicas: [{ connect: async function () {}, query: async function () {}, weight: 0 }] } } },
    "INVALID_CONFIG");
  expectInitThrow("replica cross-border residency mismatch → RESIDENCY_MISMATCH",
    { backends: { main: { connect: async function () {}, query: async function () {}, residencyTag: "EU",
      replicas: [{ connect: async function () {}, query: async function () {}, residencyTag: "US" }] } } },
    "RESIDENCY_MISMATCH");
}

// ---- init idempotency ------------------------------------------------------

function testInitIdempotent() {
  b.externalDb._resetForTest();
  var idemD = mkDriver("idem");
  b.externalDb.init({ backends: { main: { connect: idemD.connect, query: idemD.query, close: idemD.close } } });
  b.externalDb.init({ backends: { other: okBackend() } });   // second init ignored
  var names = b.externalDb.listBackends().map(function (x) { return x.name; });
  check("init is idempotent — second init ignored", names.length === 1 && names[0] === "main");
  var row = b.externalDb.listBackends()[0];
  check("listBackends surfaces dialect/classifications/breaker/pool",
    row.dialect === "postgres" && Array.isArray(row.classifications) &&
    row.breakerState === "closed" && row.pool && typeof row.pool.idle === "number");
  b.externalDb._resetForTest();
}

// ---- backend-pick precedence ----------------------------------------------

async function testPickBackend() {
  b.externalDb._resetForTest();
  var persD = mkDriver("personal");
  var opsD  = mkDriver("ops");
  b.externalDb.init({ backends: {
    p: { connect: persD.connect, query: persD.query, close: persD.close, classifications: ["personal"] },
    o: { connect: opsD.connect,  query: opsD.query,  close: opsD.close,  classifications: ["operational"] },
  } });
  var cRes = await b.externalDb.query("SELECT id FROM t", [], { classification: "personal" });
  check("classification routes to serving backend", cRes.rows[0].src === "personal");
  await expectThrow("classification with no serving backend → NO_BACKEND_FOR_CLASSIFICATION",
    function () { return b.externalDb.query("SELECT 1", [], { classification: "secret" }); },
    "NO_BACKEND_FOR_CLASSIFICATION");
  await expectThrow("explicit backend not serving classification → CLASSIFICATION_MISMATCH",
    function () { return b.externalDb.query("SELECT 1", [], { backend: "p", classification: "operational" }); },
    "CLASSIFICATION_MISMATCH");
  await expectThrow("explicit unknown backend → UNKNOWN_BACKEND",
    function () { return b.externalDb.query("SELECT 1", [], { backend: "nope" }); }, "UNKNOWN_BACKEND");
  b.externalDb._resetForTest();
}

// defaultBackend must name a REGISTERED backend — a typo is refused at
// init() with a typed INVALID_CONFIG error rather than surfacing as an
// opaque TypeError when the first query dereferences a missing pool.
async function testDefaultBackendValidation() {
  expectInitThrow("init defaultBackend typo → INVALID_CONFIG",
    { backends: { main: okBackend() }, defaultBackend: "does_not_exist" }, "INVALID_CONFIG");
  expectInitThrow("init defaultBackend non-string → INVALID_CONFIG",
    { backends: { main: okBackend() }, defaultBackend: 123 }, "INVALID_CONFIG");
  expectInitThrow("init defaultBackend empty string → INVALID_CONFIG",
    { backends: { main: okBackend() }, defaultBackend: "" }, "INVALID_CONFIG");

  // valid defaultBackend routes the default (no opts.backend / classification
  // / role) query to the named backend — not the first-declared one.
  b.externalDb._resetForTest();
  var aD = mkDriver("A");
  var bD = mkDriver("B");
  b.externalDb.init({
    backends: {
      a: { connect: aD.connect, query: aD.query, close: aD.close },
      b: { connect: bD.connect, query: bD.query, close: bD.close },
    },
    defaultBackend: "b",
  });
  var dres = await b.externalDb.query("SELECT id FROM t");
  check("valid defaultBackend routes default query to the named backend", dres.rows[0].src === "B");
  b.externalDb._resetForTest();

  // omitted defaultBackend still falls back to the first declared backend
  b.externalDb._resetForTest();
  var cD = mkDriver("C");
  var dD = mkDriver("D");
  b.externalDb.init({
    backends: {
      c: { connect: cD.connect, query: cD.query, close: cD.close },
      d: { connect: dD.connect, query: dD.query, close: dD.close },
    },
  });
  var fres = await b.externalDb.query("SELECT id FROM t");
  check("omitted defaultBackend falls back to first declared backend", fres.rows[0].src === "C");
  b.externalDb._resetForTest();
}

// ---- query retry + error paths --------------------------------------------

async function testQueryPaths() {
  // transient ECONNRESET retried, then succeeds (connection-destroy path)
  b.externalDb._resetForTest();
  var qD = mkDriver("q", { failOn: { re: /RETRYME/, code: "ECONNRESET", times: 1 } });
  b.externalDb.init({ backends: { main: { connect: qD.connect, query: qD.query, close: qD.close,
    retry: { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 1, jitterFactor: 0 } } } });
  var qr = await b.externalDb.query("SELECT RETRYME FROM t");
  check("query retries transient ECONNRESET then succeeds", qr.rows[0].src === "q");
  check("query attempted twice (retry re-acquired)",
    qD.seen.filter(function (s) { return /RETRYME/.test(s); }).length === 2);

  // connection error exhausts retries and rethrows (destroy path each attempt)
  b.externalDb._resetForTest();
  var qD2 = mkDriver("q2", { failOn: { re: /SELECT/i, code: "ECONNRESET", times: 99 } });
  b.externalDb.init({ backends: { main: { connect: qD2.connect, query: qD2.query, close: qD2.close,
    retry: { maxAttempts: 2, baseDelayMs: 1, maxDelayMs: 1, jitterFactor: 0 } } } });
  await expectThrow("query connection error exhausts retries and rethrows",
    function () { return b.externalDb.query("SELECT id FROM t"); }, "ECONNRESET");

  // non-connection 42501 → release path + db.role.denied + auth audit
  b.externalDb._resetForTest();
  var qD3 = mkDriver("q3", { failOn: { re: /secret/i, code: "42501", times: 99 } });
  b.externalDb.init({ backends: { main: { connect: qD3.connect, query: qD3.query, close: qD3.close } } });
  await expectThrow("query 42501 surfaces (release path + auth audit)",
    function () { return b.externalDb.query("SELECT * FROM secret"); }, "42501");

  // 28P01 auth-failure path
  b.externalDb._resetForTest();
  var qD4 = mkDriver("q4", { failOn: { re: /login/i, code: "28P01", times: 99 } });
  b.externalDb.init({ backends: { main: { connect: qD4.connect, query: qD4.query, close: qD4.close } } });
  await expectThrow("query 28P01 surfaces + auth audit",
    function () { return b.externalDb.query("SELECT login FROM t"); }, "28P01");

  b.externalDb._resetForTest();
}

// ---- transaction validation + execution -----------------------------------

async function testTransactionValidation() {
  b.externalDb._resetForTest();
  var okD = mkDriver("txok");
  var noD = mkDriver("txno");
  b.externalDb.init({ backends: {
    ok: { connect: okD.connect, query: okD.query, close: okD.close },
    no: { connect: noD.connect, query: noD.query, close: noD.close, supportsTransactions: false },
  } });
  check("supportsTransactions default backend → true", b.externalDb.supportsTransactions() === true);
  check("supportsTransactions non-atomic backend → false", b.externalDb.supportsTransactions({ backend: "no" }) === false);

  await expectThrow("transaction fn not function → INVALID_FN",
    function () { return b.externalDb.transaction("notfn"); }, "INVALID_FN");
  await expectThrow("transaction on non-atomic backend → NON_ATOMIC_BACKEND",
    function () { return b.externalDb.transaction(async function () {}, { backend: "no" }); }, "NON_ATOMIC_BACKEND");
  check("non-atomic tx refused before BEGIN reached the wire",
    noD.seen.every(function (s) { return !/BEGIN/i.test(s); }));

  await expectThrow("deadlockRetries 2.5 → INVALID_OPT",
    function () { return b.externalDb.transaction(async function () {}, { deadlockRetries: 2.5 }); }, "INVALID_OPT");
  await expectThrow("deadlockRetries -1 → INVALID_OPT",
    function () { return b.externalDb.transaction(async function () {}, { deadlockRetries: -1 }); }, "INVALID_OPT");
  await expectThrow("deadlockRetries Infinity → INVALID_OPT",
    function () { return b.externalDb.transaction(async function () {}, { deadlockRetries: Infinity }); }, "INVALID_OPT");
  await expectThrow("deadlockRetries string → INVALID_OPT",
    function () { return b.externalDb.transaction(async function () {}, { deadlockRetries: "3" }); }, "INVALID_OPT");
  await expectThrow("tx rowResidencyTag empty → INVALID_OPT",
    function () { return b.externalDb.transaction(async function () {}, { rowResidencyTag: "" }); }, "INVALID_OPT");

  await expectThrow("sessionGucs non-object → INVALID_SESSION_GUCS",
    function () { return b.externalDb.transaction(async function () {}, { sessionGucs: "x" }); }, "INVALID_SESSION_GUCS");
  await expectThrow("sessionGucs null value → INVALID_SESSION_GUCS",
    function () { return b.externalDb.transaction(async function () {}, { sessionGucs: { "app.k": null } }); }, "INVALID_SESSION_GUCS");
  await expectThrow("sessionGucs object value → INVALID_SESSION_GUCS",
    function () { return b.externalDb.transaction(async function () {}, { sessionGucs: { "app.k": {} } }); }, "INVALID_SESSION_GUCS");
  await expectThrow("sessionGucs invalid identifier → INVALID_SESSION_GUCS",
    function () { return b.externalDb.transaction(async function () {}, { sessionGucs: { "1bad name": "v" } }); }, "INVALID_SESSION_GUCS");
  await expectThrow("sessionGucs oversized value → INVALID_SESSION_GUCS",
    function () { return b.externalDb.transaction(async function () {}, { sessionGucs: { "app.k": "x".repeat(5000) } }); }, "INVALID_SESSION_GUCS");

  b.externalDb._resetForTest();
}

async function testTransactionExec() {
  // deadlock retry then success
  b.externalDb._resetForTest();
  var txD = mkDriver("tx");
  b.externalDb.init({ backends: { main: { connect: txD.connect, query: txD.query, close: txD.close } } });
  var dlAttempts = 0;
  var dlResult = await b.externalDb.transaction(async function (tx) {
    dlAttempts += 1;
    if (dlAttempts === 1) { var e = new Error("deadlock"); e.code = "40P01"; throw e; }
    await tx.query("SELECT id FROM t");
    return "committed";
  }, { deadlockRetries: 3 });
  check("transaction retries transient 40P01 then commits", dlResult === "committed" && dlAttempts === 2);
  check("transaction retry issued ROLLBACK then COMMIT", _saw(txD, /^ROLLBACK\b/) && _saw(txD, /^COMMIT\b/));

  // deadlock exhausted → throws the transient code
  b.externalDb._resetForTest();
  var txD2 = mkDriver("tx2");
  b.externalDb.init({ backends: { main: { connect: txD2.connect, query: txD2.query, close: txD2.close } } });
  await expectThrow("transaction deadlock exhausted (0 retries) → throws 40001",
    function () {
      return b.externalDb.transaction(async function () { var e = new Error("dl"); e.code = "40001"; throw e; },
        { deadlockRetries: 0 });
    }, "40001");
  check("exhausted deadlock issued ROLLBACK", _saw(txD2, /^ROLLBACK\b/));

  // non-transient body throw rolls back and rethrows
  b.externalDb._resetForTest();
  var txD3 = mkDriver("tx3");
  b.externalDb.init({ backends: { main: { connect: txD3.connect, query: txD3.query, close: txD3.close } } });
  await expectThrow("transaction body throw rolls back and rethrows",
    function () { return b.externalDb.transaction(async function () { throw new Error("body boom"); }); }, null);
  check("non-transient tx failure issued ROLLBACK", _saw(txD3, /^ROLLBACK\b/));
  check("non-transient tx failure did not COMMIT", txD3.seen.every(function (s) { return !/^COMMIT\b/i.test(s); }));

  // commit success + sessionGucs (string/number/boolean) + timeouts
  b.externalDb._resetForTest();
  var txD4 = mkDriver("tx4");
  b.externalDb.init({ backends: { main: { connect: txD4.connect, query: txD4.query, close: txD4.close } } });
  var okVal = await b.externalDb.transaction(async function (tx) {
    var r = await tx.query("SELECT id FROM t");
    return r.rows[0].src;
  }, { sessionGucs: { "app.tenant_id": "acme", "app.flag": true, "app.n": 7 },
       statementTimeoutMs: 5000, idleInTransactionTimeoutMs: 3000 });
  check("transaction commits and returns body value", okVal === "tx4");
  check("transaction issued BEGIN + COMMIT", _saw(txD4, /^BEGIN\b/) && _saw(txD4, /^COMMIT\b/));
  check("transaction applied SET LOCAL statement_timeout", _saw(txD4, /^SET LOCAL statement_timeout = 5000$/));
  check("transaction applied SET LOCAL idle timeout", _saw(txD4, /^SET LOCAL idle_in_transaction_session_timeout = 3000$/));
  check("transaction applied sessionGucs string", _saw(txD4, /^SET LOCAL "app"\."tenant_id" = 'acme'$/));
  check("transaction applied sessionGucs boolean", _saw(txD4, /^SET LOCAL "app"\."flag" = true$/));
  check("transaction applied sessionGucs number", _saw(txD4, /^SET LOCAL "app"\."n" = 7$/));

  // write.query / write.transaction aliases route to primary
  var wRes = await b.externalDb.write.query("SELECT id FROM t");
  check("write.query routes to primary", wRes.rows[0].src === "tx4");
  var wtRes = await b.externalDb.write.transaction(async function (tx) { await tx.query("SELECT 1"); return 42; });
  check("write.transaction runs a transaction and returns", wtRes === 42);

  b.externalDb._resetForTest();
}

// ---- health check ----------------------------------------------------------

async function testHealthCheck() {
  b.externalDb._resetForTest();
  var hcD = mkDriver("hc", { ping: true });
  b.externalDb.init({ backends: { main: { connect: hcD.connect, query: hcD.query, close: hcD.close, ping: hcD.ping } } });
  var h1 = await b.externalDb.healthCheck("main");
  check("healthCheck(main) with ping hook → ok + breaker state + pool",
    h1.ok === true && h1.breakerState === "closed" && h1.pool && typeof h1.pool.idle === "number");
  var hAll = await b.externalDb.healthCheck();
  check("healthCheck() → map keyed by backend", hAll.main && hAll.main.ok === true);
  var hUnknown = await b.externalDb.healthCheck("nope");
  check("healthCheck(unknown) → ok:false unknown backend", hUnknown.ok === false && /unknown backend/.test(hUnknown.error));

  // no ping hook → falls back to SELECT 1
  b.externalDb._resetForTest();
  var hc2 = mkDriver("hc2");
  b.externalDb.init({ backends: { main: { connect: hc2.connect, query: hc2.query, close: hc2.close } } });
  var h2 = await b.externalDb.healthCheck("main");
  check("healthCheck without ping hook uses SELECT 1", h2.ok === true && _saw(hc2, /^SELECT 1$/));

  // ping throws → destroy client, ok:false
  b.externalDb._resetForTest();
  var hc3 = mkDriver("hc3", { pingThrows: "ETIMEDOUT" });
  b.externalDb.init({ backends: { main: { connect: hc3.connect, query: hc3.query, close: hc3.close, ping: hc3.ping } } });
  var h3 = await b.externalDb.healthCheck("main");
  check("healthCheck ping failure → ok:false with error", h3.ok === false && /ping fail/.test(h3.error));

  // connect throws → outer catch, ok:false
  b.externalDb._resetForTest();
  var hc4 = mkDriver("hc4", { connectThrows: "ECONNREFUSED" });
  b.externalDb.init({ backends: { main: { connect: hc4.connect, query: hc4.query, close: hc4.close } } });
  var h4 = await b.externalDb.healthCheck("main");
  check("healthCheck connect failure → ok:false", h4.ok === false && /connect fail/.test(h4.error));

  b.externalDb._resetForTest();
}

// ---- shutdown (with replicas) ---------------------------------------------

async function testShutdown() {
  b.externalDb._resetForTest();
  var sdP = mkDriver("sdP");
  var sdR = mkDriver("sdR");
  b.externalDb.init({ backends: { main: { connect: sdP.connect, query: sdP.query, close: sdP.close,
    replicas: [{ connect: sdR.connect, query: sdR.query, close: sdR.close }] } } });
  await b.externalDb.shutdown();
  check("shutdown drains and clears backends", b.externalDb.listBackends().length === 0);
  b.externalDb._resetForTest();
}

// ---- configurePool ---------------------------------------------------------

function testConfigurePool() {
  b.externalDb._resetForTest();
  var cpD = mkDriver("cp");
  b.externalDb.init({ backends: { main: { connect: cpD.connect, query: cpD.query, close: cpD.close } } });
  expectThrowSync("configurePool bad backendName type → INVALID_CONFIG",
    function () { b.externalDb.configurePool(123, { min: 1 }); }, "INVALID_CONFIG");
  expectThrowSync("configurePool unknown backend → UNKNOWN_BACKEND",
    function () { b.externalDb.configurePool("nope", { min: 1 }); }, "UNKNOWN_BACKEND");
  expectThrowSync("configurePool opts not object → INVALID_CONFIG",
    function () { b.externalDb.configurePool("main", null); }, "INVALID_CONFIG");
  expectThrowSync("configurePool unknown option → INVALID_CONFIG",
    function () { b.externalDb.configurePool("main", { bogus: 1 }); }, "INVALID_CONFIG");
  expectThrowSync("configurePool non-positive min → INVALID_CONFIG",
    function () { b.externalDb.configurePool("main", { min: 0 }); }, "INVALID_CONFIG");
  expectThrowSync("configurePool min > max → INVALID_CONFIG",
    function () { b.externalDb.configurePool("main", { min: 10, max: 2 }); }, "INVALID_CONFIG");
  var cpOk = true;
  try { b.externalDb.configurePool("main", { min: 2, max: 20, idleTimeoutMs: 120000 }); } catch (_e) { cpOk = false; }
  check("configurePool valid resize succeeds", cpOk);
  b.externalDb._resetForTest();
}

// ---- adapters.connectAs ----------------------------------------------------

async function testConnectAs() {
  var fn = function () { return {}; };
  expectThrowSync("connectAs opts not object → INVALID_CONFIG",
    function () { b.externalDb.adapters.connectAs(fn, null); }, "INVALID_CONFIG");
  expectThrowSync("connectAs missing query → INVALID_CONFIG",
    function () { b.externalDb.adapters.connectAs(fn, {}); }, "INVALID_CONFIG");
  expectThrowSync("connectAs connect not function → INVALID_CONFIG",
    function () { b.externalDb.adapters.connectAs(null, { query: fn }); }, "INVALID_CONFIG");
  expectThrowSync("connectAs unknown option → INVALID_CONFIG",
    function () { b.externalDb.adapters.connectAs(fn, { query: fn, bogus: 1 }); }, "INVALID_CONFIG");
  expectThrowSync("connectAs searchPath empty → INVALID_CONFIG",
    function () { b.externalDb.adapters.connectAs(fn, { query: fn, searchPath: [] }); }, "INVALID_CONFIG");
  expectThrowSync("connectAs applicationName non-string → INVALID_CONFIG",
    function () { b.externalDb.adapters.connectAs(fn, { query: fn, applicationName: 123 }); }, "INVALID_CONFIG");
  expectThrowSync("connectAs statementTimeoutMs non-positive → INVALID_CONFIG",
    function () { b.externalDb.adapters.connectAs(fn, { query: fn, statementTimeoutMs: 0 }); }, "INVALID_CONFIG");
  expectThrowSync("connectAs gucs not object → INVALID_CONFIG",
    function () { b.externalDb.adapters.connectAs(fn, { query: fn, gucs: "x" }); }, "INVALID_CONFIG");
  expectThrowSync("connectAs gucs non-finite number → INVALID_CONFIG",
    function () { b.externalDb.adapters.connectAs(fn, { query: fn, gucs: { work_mem: Infinity } }); }, "INVALID_CONFIG");
  expectThrowSync("connectAs gucs string with newline → INVALID_CONFIG",
    function () { b.externalDb.adapters.connectAs(fn, { query: fn, gucs: { search_path: "a\nb" } }); }, "INVALID_CONFIG");
  expectThrowSync("connectAs role invalid identifier → throws",
    function () { b.externalDb.adapters.connectAs(fn, { query: fn, role: "1bad" }); }, null);

  // valid connectAs wiring — every SET runs on the freshly-acquired client
  b.externalDb._resetForTest();
  var caD = mkDriver("ca");
  var wrapped = b.externalDb.adapters.connectAs(caD.connect, {
    query: caD.query,
    role: "analytics_user",
    searchPath: ["analytics", "public"],
    applicationName: "wiki:analytics",
    statementTimeoutMs: 30000,
    gucs: { idle_in_transaction_session_timeout: "60s", work_mem: 4096 },
  });
  b.externalDb.init({ backends: { main: { dialect: "postgres", connect: wrapped, query: caD.query, close: caD.close } } });
  await b.externalDb.query("SELECT id FROM t");
  check("connectAs issues SET ROLE", _saw(caD, /^SET ROLE "analytics_user"$/));
  check("connectAs issues SET search_path", _saw(caD, /^SET search_path TO "analytics", "public"$/));
  check("connectAs issues SET application_name", _saw(caD, /^SET application_name TO 'wiki:analytics'$/));
  check("connectAs issues SET statement_timeout", _saw(caD, /^SET statement_timeout TO 30000$/));
  check("connectAs issues numeric guc", _saw(caD, /^SET "work_mem" TO 4096$/));
  check("connectAs issues string guc", _saw(caD, /^SET "idle_in_transaction_session_timeout" TO '60s'$/));
  b.externalDb._resetForTest();
}

// ---- runAs / currentRole ---------------------------------------------------

async function testRunAs() {
  check("currentRole() outside runAs → null", b.externalDb.currentRole() === null);
  expectThrowSync("runAs fn not function → INVALID_FN",
    function () { b.externalDb.runAs("r", "notfn"); }, "INVALID_FN");
  expectThrowSync("runAs role not string → INVALID_ROLE",
    function () { b.externalDb.runAs(123, function () {}); }, "INVALID_ROLE");
  expectThrowSync("runAs role empty → INVALID_ROLE",
    function () { b.externalDb.runAs("", function () {}); }, "INVALID_ROLE");
  expectThrowSync("runAs role invalid identifier → throws",
    function () { b.externalDb.runAs("1bad", function () {}); }, null);

  b.externalDb._resetForTest();
  var mainD = mkDriver("main");
  var anaD  = mkDriver("analytics");
  b.externalDb.init({
    backends: {
      main:      { connect: mainD.connect, query: mainD.query, close: mainD.close },
      analytics: { connect: anaD.connect,  query: anaD.query,  close: anaD.close },
    },
    dbRoleBackends: { analytics_user: "analytics" },
  });
  var routedSrc = await b.externalDb.runAs("analytics_user", async function () {
    check("currentRole inside runAs", b.externalDb.currentRole() === "analytics_user");
    var r = await b.externalDb.query("SELECT id FROM t");
    return r.rows[0].src;
  });
  check("runAs routes query to role-mapped backend", routedSrc === "analytics");
  check("currentRole after runAs → null", b.externalDb.currentRole() === null);
  await b.externalDb.runAs(null, async function () {
    check("runAs(null) clears role", b.externalDb.currentRole() === null);
  });
  b.externalDb._resetForTest();
}

// ---- assertRoleHardening (uncovered branches) -----------------------------

async function testAssertRoleHardening() {
  b.externalDb._resetForTest();
  var arD = mkDriver("ar", { roles: ["app_user", "postgres", "pg_signal_backend"] });
  b.externalDb.init({ backends: { main: { connect: arD.connect, query: arD.query, close: arD.close } } });
  await expectThrow("assertRoleHardening opts missing → INVALID_CONFIG",
    function () { return b.externalDb.assertRoleHardening(); }, "INVALID_CONFIG");
  await expectThrow("assertRoleHardening mode invalid → INVALID_CONFIG",
    function () { return b.externalDb.assertRoleHardening({ declaredRoles: ["app_user"], mode: "bogus" }); }, "INVALID_CONFIG");
  await expectThrow("assertRoleHardening declaredRoles element not string → INVALID_CONFIG",
    function () { return b.externalDb.assertRoleHardening({ declaredRoles: [123] }); }, "INVALID_CONFIG");
  await expectThrow("assertRoleHardening unknown backend → UNKNOWN_BACKEND",
    function () { return b.externalDb.assertRoleHardening({ declaredRoles: ["x"], backend: "nope" }); }, "UNKNOWN_BACKEND");
  var arOk = await b.externalDb.assertRoleHardening({ declaredRoles: ["app_user"], mode: "audit" });
  check("assertRoleHardening ok path filters system roles",
    arOk.unrecognized.length === 0 && arOk.missing.length === 0 && arOk.observed.indexOf("postgres") === -1);

  // non-postgres dialect → skipped
  b.externalDb._resetForTest();
  var arSqlite = mkDriver("arsqlite");
  b.externalDb.init({ backends: { main: { dialect: "sqlite", connect: arSqlite.connect, query: arSqlite.query, close: arSqlite.close } } });
  var arSkip = await b.externalDb.assertRoleHardening({ declaredRoles: ["x"] });
  check("assertRoleHardening non-postgres → skipped with empty observed",
    arSkip.observed.length === 0 && arSkip.unrecognized.length === 0);

  // pg_roles unreadable → ROLE_HARDENING_UNREADABLE
  b.externalDb._resetForTest();
  var arFail = mkDriver("arfail", { failOn: { re: /pg_roles/i, code: "XX000", times: 99 } });
  b.externalDb.init({ backends: { main: { connect: arFail.connect, query: arFail.query, close: arFail.close } } });
  await expectThrow("assertRoleHardening pg_roles unreadable → ROLE_HARDENING_UNREADABLE",
    function () { return b.externalDb.assertRoleHardening({ declaredRoles: ["x"] }); }, "ROLE_HARDENING_UNREADABLE");

  b.externalDb._resetForTest();
}

// ---- statement classifiers -------------------------------------------------

function testStatementHelpers() {
  var srr = b.externalDb._statementReturnsRows;
  check("statementReturnsRows SELECT → true", srr("SELECT * FROM t") === true);
  check("statementReturnsRows INSERT → false", srr("INSERT INTO t (a) VALUES (1)") === false);
  check("statementReturnsRows INSERT RETURNING → true", srr("INSERT INTO t (a) VALUES (1) RETURNING id") === true);
  check("statementReturnsRows WITH CTE SELECT → true", srr("WITH x AS (SELECT 1) SELECT * FROM x") === true);
  check("statementReturnsRows SHOW → true", srr("SHOW TABLES") === true);
  check("statementReturnsRows empty → false", srr("") === false);
  check("statementReturnsRows non-string → false", srr(null) === false);
  check("statementReturnsRows UPDATE RETURNING → true", srr("UPDATE t SET a = 1 RETURNING *") === true);

  var xr = b.externalDb._extractTargetRelation;
  check("extractTargetRelation NUL in quoted identifier → null",
    xr('SELECT * FROM "a' + String.fromCharCode(0) + 'b"') === null);
  check("extractTargetRelation non-string → null", xr(null) === null);
}

// ---- residency advisory (unregulated posture) -----------------------------

async function testResidencyAdvisory() {
  b.compliance.clear();   // ensure no cross-border-regulated posture is pinned
  b.externalDb._resetForTest();
  var advD = mkDriver("adv");
  b.externalDb.init({ backends: { main: { connect: advD.connect, query: advD.query, close: advD.close, residencyTag: "eu" } } });
  await b.externalDb.query("INSERT INTO t (a) VALUES (1)", [], { rowResidencyTag: "eu" });
  check("unregulated posture + tag on write → advisory, statement reaches wire", _saw(advD, /INSERT INTO t/));
  var advRead = await b.externalDb.query("SELECT a FROM t", [], { rowResidencyTag: "eu" });
  check("unregulated posture + tag on read → passes (no advisory branch)", advRead.rows[0].src === "adv");
  b.externalDb._resetForTest();
}

// ---- read-replica routing + health ----------------------------------------

async function testReplicas() {
  // no replicas → read.query routes to primary
  b.externalDb._resetForTest();
  var np = mkDriver("noreprimary");
  b.externalDb.init({ backends: { main: { connect: np.connect, query: np.query, close: np.close } } });
  var nrRes = await b.externalDb.read.query("SELECT id FROM t");
  check("read.query without replicas routes to primary", nrRes.rows[0].src === "noreprimary");

  // healthy replica → read routes to replica, not primary
  b.externalDb._resetForTest();
  var primary = mkDriver("primary");
  var rep = mkDriver("replica");
  b.externalDb.init({ backends: { main: { connect: primary.connect, query: primary.query, close: primary.close,
    replicas: [{ connect: rep.connect, query: rep.query, close: rep.close }] } } });
  var rr = await b.externalDb.read.query("SELECT id FROM t");
  check("read.query routes to replica", rr.rows[0].src === "replica");
  check("read.query did not touch primary", primary.seen.length === 0);

  // replica connection error → fallback to primary
  b.externalDb._resetForTest();
  var primary2 = mkDriver("primary2");
  var rep2 = mkDriver("replica2", { failOn: { re: /SELECT/i, code: "ECONNRESET", times: 99 } });
  b.externalDb.init({ backends: { main: { connect: primary2.connect, query: primary2.query, close: primary2.close,
    replicas: [{ connect: rep2.connect, query: rep2.query, close: rep2.close }], replicaFallbackToPrimary: true } } });
  var rr2 = await b.externalDb.read.query("SELECT id FROM t");
  check("replica ECONNRESET falls back to primary", rr2.rows[0].src === "primary2");

  // all replicas unhealthy + fallback disabled → ALL_REPLICAS_UNHEALTHY
  b.externalDb._resetForTest();
  var primary3 = mkDriver("primary3");
  var rep3 = mkDriver("replica3", { failOn: { re: /SELECT/i, code: "ECONNRESET", times: 99 } });
  b.externalDb.init({ backends: { main: { connect: primary3.connect, query: primary3.query, close: primary3.close,
    replicas: [{ connect: rep3.connect, query: rep3.query, close: rep3.close }], replicaFallbackToPrimary: false } } });
  await expectThrow("replica read failure, fallback disabled → surfaces the error",
    function () { return b.externalDb.read.query("SELECT id FROM t"); }, "ECONNRESET");
  await expectThrow("all replicas unhealthy + fallback disabled → ALL_REPLICAS_UNHEALTHY",
    function () { return b.externalDb.read.query("SELECT id FROM t"); }, "ALL_REPLICAS_UNHEALTHY");

  // cross-border replica with allowCrossBorder:true → init accepts, read serves
  b.externalDb._resetForTest();
  var pX = mkDriver("pX");
  var rX = mkDriver("rX");
  b.externalDb.init({ backends: { main: { connect: pX.connect, query: pX.query, close: pX.close, residencyTag: "EU",
    replicas: [{ connect: rX.connect, query: rX.query, close: rX.close, residencyTag: "US", allowCrossBorder: true }] } } });
  var rX1 = await b.externalDb.read.query("SELECT id FROM t");
  check("cross-border replica with allowCrossBorder serves read", rX1.rows[0].src === "rX");

  b.externalDb._resetForTest();
}

// ---- Pool internals (waiter / drain / destroy / reap / connect-error) ------

async function testPoolInternals() {
  var Pool = b.externalDb.Pool;

  // waiter resolves on release
  var pA = new Pool("poolA", { connect: async function () { return { id: "a" }; }, close: async function () {}, pool: { max: 1 } });
  try {
    var a1 = await pA.acquire();
    var pendingA = pA.acquire();
    check("pool at max queues a waiter", pA.stats().waiters === 1);
    pA.release(a1);
    var a2 = await pendingA;
    check("pool waiter resolved on release with the released client", a2 === a1);
    check("pool stats after waiter resolve", pA.stats().active === 1 && pA.stats().waiters === 0);
    pA.release(a2);
    check("pool stats after final release", pA.stats().idle === 1 && pA.stats().active === 0);
  } finally { await pA.drain(); }

  // drain rejects queued waiter with POOL_DRAINED
  var pB = new Pool("poolB", { connect: async function () { return { id: "b" }; }, pool: { max: 1 } });
  await pB.acquire();
  var pendingB = pB.acquire();
  await pB.drain();
  var rejB = null;
  try { await pendingB; } catch (e) { rejB = e; }
  check("drain rejects queued waiter with POOL_DRAINED", rejB && rejB.code === "POOL_DRAINED");

  // destroy resolves a queued waiter via a fresh acquire
  var pC = new Pool("poolC", { connect: async function () { return { id: "c" + Math.random() }; }, close: async function () {}, pool: { max: 1 } });
  try {
    var c1 = await pC.acquire();
    var pendingC = pC.acquire();
    await pC.destroy(c1);
    var c2 = await pendingC;
    check("destroy resolves queued waiter via fresh acquire", !!c2);
    pC.release(c2);
  } finally { await pC.drain(); }

  // reaper removes expired idle clients (min:0 opts out of the warm floor)
  var pD = new Pool("poolD", { connect: async function () { return { id: "d" }; }, close: async function () {}, pool: { min: 0, max: 2, idleTimeoutMs: 1 } });
  try {
    var d1 = await pD.acquire();
    pD.release(d1);
    check("released client goes idle", pD.stats().idle === 1);
    pD.idle[0].lastUsedAt = Date.now() - 1000;   // backdate past idleTimeoutMs
    pD._reapIdle();
    check("reaper removes expired idle client", pD.stats().idle === 0);
  } finally { await pD.drain(); }

  // acquire surfaces a connect error and decrements active
  var pE = new Pool("poolE", { connect: async function () { var e = new Error("nope"); e.code = "ECONNREFUSED"; throw e; }, pool: { max: 2 } });
  try {
    var eThrew = null;
    try { await pE.acquire(); } catch (e) { eThrew = e; }
    check("pool acquire surfaces connect error and decrements active",
      eThrew && eThrew.code === "ECONNREFUSED" && pE.stats().active === 0);
  } finally { await pE.drain(); }
}

// ---- Pool min floor (reaper honors the idle-client floor) ------------------

// Pool `min` is documented as a floor on idle clients: the reaper must
// retain at least `min` warm idle clients even when they have all gone
// idle past idleTimeoutMs, so a warm connection survives quiet periods.
async function testPoolMinFloor() {
  var Pool = b.externalDb.Pool;

  // reaper honors min=1: with two idle clients both expired, one warm
  // client survives (the floor), and repeat reaps never drop below it.
  var pF = new Pool("poolF", { connect: async function () { return { id: "f" }; }, close: async function () {},
    pool: { min: 1, max: 3, idleTimeoutMs: 1 } });
  try {
    var f1 = await pF.acquire();
    var f2 = await pF.acquire();
    pF.release(f1);
    pF.release(f2);
    check("two clients idle before reap", pF.stats().idle === 2);
    pF.idle.forEach(function (e) { e.lastUsedAt = Date.now() - 1000; });   // backdate all past idleTimeoutMs
    pF._reapIdle();
    check("reaper keeps min=1 idle client as the floor (never drops below min)", pF.stats().idle === 1);
    pF.idle[0].lastUsedAt = Date.now() - 1000;
    pF._reapIdle();
    check("reaper holds the floor across repeat runs", pF.stats().idle === 1);
  } finally { await pF.drain(); }

  // reaper keeps every idle client when all are within the floor
  var pH = new Pool("poolH", { connect: async function () { return { id: "h" }; }, close: async function () {},
    pool: { min: 4, max: 4, idleTimeoutMs: 1 } });
  try {
    var h1 = await pH.acquire();
    var h2 = await pH.acquire();
    pH.release(h1);
    pH.release(h2);
    pH.idle.forEach(function (e) { e.lastUsedAt = Date.now() - 1000; });
    pH._reapIdle();
    check("idle count at/below min is fully retained by reaper", pH.stats().idle === 2);
  } finally { await pH.drain(); }

  // min=0 opts out of the floor — every expired idle client is reaped
  var pG = new Pool("poolG", { connect: async function () { return { id: "g" }; }, close: async function () {},
    pool: { min: 0, max: 2, idleTimeoutMs: 1 } });
  try {
    var g1 = await pG.acquire();
    pG.release(g1);
    pG.idle[0].lastUsedAt = Date.now() - 1000;
    pG._reapIdle();
    check("min=0 reaps every expired idle client", pG.stats().idle === 0);
  } finally { await pG.drain(); }
}

// ---- runner ----------------------------------------------------------------

async function run() {
  await testNotInitialized();
  testInitValidation();
  testInitIdempotent();
  await testPickBackend();
  await testDefaultBackendValidation();
  await testQueryPaths();
  await testTransactionValidation();
  await testTransactionExec();
  await testHealthCheck();
  await testShutdown();
  testConfigurePool();
  await testConnectAs();
  await testRunAs();
  await testAssertRoleHardening();
  testStatementHelpers();
  await testResidencyAdvisory();
  await testReplicas();
  await testPoolInternals();
  await testPoolMinFloor();

  // Leave the registry + compliance state clean for parallel smoke files.
  b.externalDb._resetForTest();
  b.compliance.clear();
}

if (require.main === module) {
  run().then(
    function () { process.stdout.write("OK — external-db: " + helpers.getChecks() + " checks passed\n"); process.exit(0); },
    function (err) { console.error(err && err.stack); process.exit(1); }
  );
}

module.exports = { run: run };
