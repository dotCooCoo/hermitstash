// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * external-db-residency — per-row residency write gate
 * (b.externalDb.query / transaction / read.query).
 *
 * Drives the cross-border DML write gate end-to-end against a fake
 * backend so the wire (the backend's query hook) is observed for every
 * enforcement-matrix cell:
 *
 *   - unregulated posture + residency-tagged backend → DML passes
 *   - regulated posture (gdpr) + untagged backend     → DML passes
 *   - gdpr + tagged backend + no rowResidencyTag       → RESIDENCY_GATE_REQUIRED (wire NOT reached)
 *   - gdpr + tagged backend + matching tag             → passes (statement reaches the wire)
 *   - gdpr + tagged backend + "global"                 → passes
 *   - gdpr + tagged backend + mismatched tag           → RESIDENCY_TAG_MISMATCH
 *   - empty-string rowResidencyTag                     → INVALID_OPT
 *   - SELECT under gdpr to a tagged backend            → passes (non-DML not gated)
 *   - transaction: tx-level + per-call override tags    → mismatch rolls back (no COMMIT)
 *   - read-replica residency incompatibility            → REPLICA_RESIDENCY_INCOMPATIBLE / allowCrossBorder bypass
 *
 * The gate reads the active posture from b.compliance.current(), so each
 * regulated-posture block flips the posture via b.compliance.set("gdpr")
 * and ALWAYS restores it in a finally so parallel smoke files aren't
 * poisoned.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// Tracking driver: records every SQL statement the backend's query hook
// sees so tests assert whether the wire was reached. Returns rowCount 1
// for DML, an empty result for SELECT, and a no-op for BEGIN / COMMIT /
// ROLLBACK so the transaction machinery completes.
function _trackingDriver(label) {
  var seen = [];
  return {
    label: label,
    seen:  seen,
    connect: async function () { return { id: label + "-client" }; },
    query:   async function (_client, sql, _params) {
      seen.push(sql);
      if (/^(BEGIN|COMMIT|ROLLBACK)\b/i.test(sql)) return { rows: [], rowCount: 0 };
      if (/^SELECT\b/i.test(sql)) return { rows: [{ from: label }], rowCount: 1 };
      return { rows: [], rowCount: 1 };
    },
    close: async function () { /* no-op */ },
    ping:  async function () { return true; },
  };
}

function _saw(driver, re) {
  return driver.seen.some(function (s) { return re.test(s); });
}

// Run fn() under the gdpr posture, restoring whatever posture (or none)
// was pinned before. clear()+set() because compliance.set refuses a
// runtime switch when a different posture is already pinned.
async function _underGdpr(fn) {
  var prior = b.compliance.current();
  b.compliance.clear();
  b.compliance.set("gdpr");
  try {
    await fn();
  } finally {
    b.compliance.clear();
    if (prior) b.compliance.set(prior);
  }
}

async function _expectThrow(label, fn, expectedCode) {
  var threw = null;
  try { await fn(); } catch (e) { threw = e; }
  check(label + ": threw " + expectedCode,
        threw !== null && threw.code === expectedCode);
}

async function run() {
  // Confirm the cross-border vocabulary is shared between the gate and
  // the compliance catalog (the gate consults isCrossBorderRegulated).
  check("compliance.isCrossBorderRegulated('gdpr') === true",
        b.compliance.isCrossBorderRegulated("gdpr") === true);
  check("compliance.isCrossBorderRegulated('soc2') === false",
        b.compliance.isCrossBorderRegulated("soc2") === false);
  check("CROSS_BORDER_REGULATED_POSTURES includes gdpr",
        Array.isArray(b.compliance.CROSS_BORDER_REGULATED_POSTURES) &&
        b.compliance.CROSS_BORDER_REGULATED_POSTURES.indexOf("gdpr") !== -1);

  // ---- unregulated posture + residency-tagged backend → DML passes ----
  // No posture pinned (default) → the gate does not engage even for a
  // residency-tagged backend, even without a rowResidencyTag.
  b.externalDb._resetForTest();
  var euDriver = _trackingDriver("eu");
  b.externalDb.init({
    backends: {
      main: {
        connect: euDriver.connect, query: euDriver.query,
        close: euDriver.close, residencyTag: "eu",
      },
    },
  });
  await b.externalDb.query("INSERT INTO orders (id) VALUES ($1)", ["o-1"]);
  check("unregulated + tagged backend + untagged DML → passes, wire reached",
        _saw(euDriver, /INSERT INTO orders/));

  // ---- gdpr + UNTAGGED (unrestricted) backend + untagged DML → passes ----
  b.externalDb._resetForTest();
  var freeDriver = _trackingDriver("free");
  b.externalDb.init({
    backends: {
      main: {
        connect: freeDriver.connect, query: freeDriver.query,
        close: freeDriver.close,   // no residencyTag → "unrestricted"
      },
    },
  });
  await _underGdpr(async function () {
    await b.externalDb.query("UPDATE orders SET total = $1 WHERE id = $2", [10, "o-1"]);
  });
  check("gdpr + unrestricted backend + untagged DML → passes, wire reached",
        _saw(freeDriver, /UPDATE orders/));

  // ---- gdpr + eu backend + DML without tag → RESIDENCY_GATE_REQUIRED ----
  b.externalDb._resetForTest();
  var gateDriver = _trackingDriver("gate");
  b.externalDb.init({
    backends: {
      main: {
        connect: gateDriver.connect, query: gateDriver.query,
        close: gateDriver.close, residencyTag: "eu",
      },
    },
  });
  await _underGdpr(async function () {
    await _expectThrow("gdpr + eu backend + untagged DML",
      function () {
        return b.externalDb.query("DELETE FROM orders WHERE id = $1", ["o-1"]);
      },
      "RESIDENCY_GATE_REQUIRED");
  });
  check("RESIDENCY_GATE_REQUIRED → wire NOT reached",
        gateDriver.seen.every(function (s) { return !/DELETE FROM orders/.test(s); }));

  // ---- gdpr + eu backend + matching tag "eu" → passes (success path) ----
  b.externalDb._resetForTest();
  var okDriver = _trackingDriver("ok");
  b.externalDb.init({
    backends: {
      main: {
        connect: okDriver.connect, query: okDriver.query,
        close: okDriver.close, residencyTag: "eu",
      },
    },
  });
  await _underGdpr(async function () {
    var res = await b.externalDb.query(
      "INSERT INTO orders (id, region) VALUES ($1, $2)",
      ["o-2", "eu"],
      { rowResidencyTag: "eu" });
    check("gdpr + eu backend + tag 'eu' → rowCount returned",
          res && res.rowCount === 1);
  });
  check("gdpr + eu backend + tag 'eu' → wire reached with the statement",
        _saw(okDriver, /INSERT INTO orders \(id, region\)/));

  // ---- gdpr + eu backend + tag "global" → passes ----
  b.externalDb._resetForTest();
  var globalDriver = _trackingDriver("global");
  b.externalDb.init({
    backends: {
      main: {
        connect: globalDriver.connect, query: globalDriver.query,
        close: globalDriver.close, residencyTag: "eu",
      },
    },
  });
  await _underGdpr(async function () {
    await b.externalDb.query(
      "UPDATE orders SET total = $1 WHERE id = $2",
      [99, "o-2"],
      { rowResidencyTag: "global" });
  });
  check("gdpr + eu backend + tag 'global' → passes, wire reached",
        _saw(globalDriver, /UPDATE orders/));

  // ---- gdpr + eu backend + tag "us" → RESIDENCY_TAG_MISMATCH ----
  b.externalDb._resetForTest();
  var mismatchDriver = _trackingDriver("mismatch");
  b.externalDb.init({
    backends: {
      main: {
        connect: mismatchDriver.connect, query: mismatchDriver.query,
        close: mismatchDriver.close, residencyTag: "eu",
      },
    },
  });
  await _underGdpr(async function () {
    await _expectThrow("gdpr + eu backend + tag 'us'",
      function () {
        return b.externalDb.query(
          "INSERT INTO orders (id) VALUES ($1)",
          ["o-3"],
          { rowResidencyTag: "us" });
      },
      "RESIDENCY_TAG_MISMATCH");
  });
  check("RESIDENCY_TAG_MISMATCH → wire NOT reached",
        mismatchDriver.seen.every(function (s) { return !/INSERT INTO orders/.test(s); }));

  // ---- rowResidencyTag present but empty string → INVALID_OPT ----
  // The empty-string guard runs ahead of posture / DML classification —
  // exercise it on a DML statement under gdpr so the path is realistic.
  b.externalDb._resetForTest();
  var emptyDriver = _trackingDriver("empty");
  b.externalDb.init({
    backends: {
      main: {
        connect: emptyDriver.connect, query: emptyDriver.query,
        close: emptyDriver.close, residencyTag: "eu",
      },
    },
  });
  await _underGdpr(async function () {
    await _expectThrow("empty-string rowResidencyTag",
      function () {
        return b.externalDb.query(
          "INSERT INTO orders (id) VALUES ($1)",
          ["o-4"],
          { rowResidencyTag: "" });
      },
      "INVALID_OPT");
  });
  check("INVALID_OPT → wire NOT reached",
        emptyDriver.seen.every(function (s) { return !/INSERT INTO orders/.test(s); }));

  // ---- multi-statement SQL hiding a trailing DML behind a SELECT
  // prefix → MULTI_STATEMENT_REFUSED (the classifier reads only the
  // leading keyword; a trailing INSERT must not slip the gate) ----
  b.externalDb._resetForTest();
  var multiDriver = _trackingDriver("multi");
  b.externalDb.init({
    backends: {
      main: {
        connect: multiDriver.connect, query: multiDriver.query,
        close: multiDriver.close, residencyTag: "eu",
      },
    },
  });
  await _underGdpr(async function () {
    await _expectThrow("multi-statement SELECT;INSERT refused",
      function () {
        return b.externalDb.query(
          "SELECT 1; INSERT INTO orders (id) VALUES ('o-x')", []);
      },
      "MULTI_STATEMENT_REFUSED");
  });
  check("MULTI_STATEMENT_REFUSED → wire NOT reached",
        multiDriver.seen.every(function (s) { return !/INSERT INTO orders/.test(s); }));
  // A single statement ending in a bare ; (no trailing statement) is fine.
  await _underGdpr(async function () {
    var ok = await b.externalDb.query(
      "INSERT INTO orders (id) VALUES ('o-semi');", [], { rowResidencyTag: "eu" });
    check("single statement with trailing ; passes", ok && ok.rowCount === 1);
  });

  // ---- transaction-level rowResidencyTag shape validated at entry ----
  b.externalDb._resetForTest();
  var txShapeDriver = _trackingDriver("txshape");
  b.externalDb.init({
    backends: {
      main: {
        connect: txShapeDriver.connect, query: txShapeDriver.query,
        close: txShapeDriver.close, residencyTag: "eu",
      },
    },
  });
  await _underGdpr(async function () {
    await _expectThrow("empty tx-level rowResidencyTag refused at entry",
      function () {
        return b.externalDb.transaction(async function (tx) {
          await tx.query("INSERT INTO orders (id) VALUES ('o-tx')", []);
        }, { rowResidencyTag: "" });
      },
      "INVALID_OPT");
  });
  check("tx-level shape refusal → no BEGIN reached the backend",
        txShapeDriver.seen.every(function (s) { return !/BEGIN/i.test(s); }));

  // ---- SELECT under gdpr to an eu backend without tag → passes (non-DML) ----
  b.externalDb._resetForTest();
  var selectDriver = _trackingDriver("select");
  b.externalDb.init({
    backends: {
      main: {
        connect: selectDriver.connect, query: selectDriver.query,
        close: selectDriver.close, residencyTag: "eu",
      },
    },
  });
  await _underGdpr(async function () {
    var res = await b.externalDb.query("SELECT id FROM orders WHERE id = $1", ["o-1"]);
    check("gdpr + eu backend + untagged SELECT → passes, rows returned",
          res && res.rowCount === 1);
  });
  check("gdpr + eu backend + untagged SELECT → wire reached (non-DML not gated)",
        _saw(selectDriver, /SELECT id FROM orders/));

  // ---- transaction: tx-level tag applies to tx.query; mismatch rolls back ----
  // A transaction-level rowResidencyTag of "us" against an "eu" backend
  // makes the first DML tx.query throw RESIDENCY_TAG_MISMATCH, which
  // rolls the transaction back: the fake backend sees BEGIN then
  // ROLLBACK, and NEVER COMMIT or the gated INSERT.
  b.externalDb._resetForTest();
  var txMismatchDriver = _trackingDriver("txmismatch");
  b.externalDb.init({
    backends: {
      main: {
        connect: txMismatchDriver.connect, query: txMismatchDriver.query,
        close: txMismatchDriver.close, residencyTag: "eu",
      },
    },
  });
  await _underGdpr(async function () {
    await _expectThrow("transaction: tx-level tag 'us' on eu backend",
      function () {
        return b.externalDb.transaction(async function (tx) {
          await tx.query("INSERT INTO orders (id) VALUES ($1)", ["tx-1"]);
        }, { rowResidencyTag: "us" });
      },
      "RESIDENCY_TAG_MISMATCH");
  });
  check("transaction mismatch: BEGIN issued",
        _saw(txMismatchDriver, /^BEGIN\b/));
  check("transaction mismatch: ROLLBACK issued (transaction rolled back)",
        _saw(txMismatchDriver, /^ROLLBACK\b/));
  check("transaction mismatch: COMMIT NOT reached",
        txMismatchDriver.seen.every(function (s) { return !/^COMMIT\b/i.test(s); }));
  check("transaction mismatch: gated INSERT NOT reached",
        txMismatchDriver.seen.every(function (s) { return !/INSERT INTO orders/.test(s); }));

  // tx-level matching tag "eu" → the statement commits end-to-end.
  b.externalDb._resetForTest();
  var txOkDriver = _trackingDriver("txok");
  b.externalDb.init({
    backends: {
      main: {
        connect: txOkDriver.connect, query: txOkDriver.query,
        close: txOkDriver.close, residencyTag: "eu",
      },
    },
  });
  await _underGdpr(async function () {
    await b.externalDb.transaction(async function (tx) {
      await tx.query("INSERT INTO orders (id) VALUES ($1)", ["tx-2"]);
    }, { rowResidencyTag: "eu" });
  });
  check("transaction tx-level tag 'eu': INSERT reached the wire",
        _saw(txOkDriver, /INSERT INTO orders/));
  check("transaction tx-level tag 'eu': COMMIT reached",
        _saw(txOkDriver, /^COMMIT\b/));

  // per-call third-arg override wins over the transaction-level tag.
  // Transaction-level tag "us" (would refuse), but the per-call override
  // "eu" replaces it for that statement → the DML reaches the wire and
  // the transaction commits.
  b.externalDb._resetForTest();
  var txOverrideDriver = _trackingDriver("txoverride");
  b.externalDb.init({
    backends: {
      main: {
        connect: txOverrideDriver.connect, query: txOverrideDriver.query,
        close: txOverrideDriver.close, residencyTag: "eu",
      },
    },
  });
  await _underGdpr(async function () {
    await b.externalDb.transaction(async function (tx) {
      await tx.query(
        "INSERT INTO orders (id) VALUES ($1)",
        ["tx-3"],
        { rowResidencyTag: "eu" });
    }, { rowResidencyTag: "us" });
  });
  check("transaction per-call override 'eu' beats tx-level 'us': INSERT reached",
        _saw(txOverrideDriver, /INSERT INTO orders/));
  check("transaction per-call override 'eu' beats tx-level 'us': COMMIT reached",
        _saw(txOverrideDriver, /^COMMIT\b/));

  // and the converse: per-call override "us" beats a benign tx-level
  // "eu" → that statement is refused and the transaction rolls back.
  b.externalDb._resetForTest();
  var txOverrideBadDriver = _trackingDriver("txoverridebad");
  b.externalDb.init({
    backends: {
      main: {
        connect: txOverrideBadDriver.connect, query: txOverrideBadDriver.query,
        close: txOverrideBadDriver.close, residencyTag: "eu",
      },
    },
  });
  await _underGdpr(async function () {
    await _expectThrow("transaction per-call override 'us' beats tx-level 'eu'",
      function () {
        return b.externalDb.transaction(async function (tx) {
          await tx.query(
            "INSERT INTO orders (id) VALUES ($1)",
            ["tx-4"],
            { rowResidencyTag: "us" });
        }, { rowResidencyTag: "eu" });
      },
      "RESIDENCY_TAG_MISMATCH");
  });
  check("transaction per-call override 'us': COMMIT NOT reached",
        txOverrideBadDriver.seen.every(function (s) { return !/^COMMIT\b/i.test(s); }));

  // ---- read-replica residency incompatibility ----
  // The replica-vs-row read gate is distinct from the replica-vs-primary
  // CONFIG gate. To reach the read gate with allowCrossBorder:false (init
  // would refuse a cross-border replica otherwise), the primary is left
  // "unrestricted" — so the "us" replica is config-compatible with the
  // primary and init accepts it — and the incompatibility is between the
  // ROW's tag ("eu") and the replica's tag ("us") at read time.
  b.externalDb._resetForTest();
  var roPrimary = _trackingDriver("ro-primary");
  var usReplica = _trackingDriver("us-replica");
  b.externalDb.init({
    backends: {
      main: {
        connect: roPrimary.connect, query: roPrimary.query,
        close: roPrimary.close,   // primary unrestricted
        replicas: [
          {
            connect: usReplica.connect, query: usReplica.query,
            close: usReplica.close, residencyTag: "us",
            allowCrossBorder: false,
          },
        ],
        replicaFallbackToPrimary: false,
      },
    },
  });
  await _underGdpr(async function () {
    await _expectThrow("read to us replica for eu row, allowCrossBorder false",
      function () {
        return b.externalDb.read.query(
          "SELECT id FROM orders WHERE id = $1",
          ["o-1"],
          { rowResidencyTag: "eu" });
      },
      "REPLICA_RESIDENCY_INCOMPATIBLE");
  });
  check("REPLICA_RESIDENCY_INCOMPATIBLE → replica wire NOT reached",
        usReplica.seen.every(function (s) { return !/SELECT id FROM orders/.test(s); }));

  // allowCrossBorder true on the replica → the cross-border read is
  // permitted (audited) and reaches the replica wire.
  b.externalDb._resetForTest();
  var roPrimary2 = _trackingDriver("ro-primary2");
  var usReplicaOk = _trackingDriver("us-replica-ok");
  b.externalDb.init({
    backends: {
      main: {
        connect: roPrimary2.connect, query: roPrimary2.query,
        close: roPrimary2.close,   // primary unrestricted
        replicas: [
          {
            connect: usReplicaOk.connect, query: usReplicaOk.query,
            close: usReplicaOk.close, residencyTag: "us",
            allowCrossBorder: true,
          },
        ],
        replicaFallbackToPrimary: false,
      },
    },
  });
  await _underGdpr(async function () {
    var res = await b.externalDb.read.query(
      "SELECT id FROM orders WHERE id = $1",
      ["o-1"],
      { rowResidencyTag: "eu" });
    check("read to us replica for eu row, allowCrossBorder true → rows returned",
          res && res.rowCount === 1);
  });
  check("allowCrossBorder replica read → replica wire reached",
        _saw(usReplicaOk, /SELECT id FROM orders/));

  // ---- read-replica residency gate: OMITTED rowResidencyTag must fail closed ----
  // Symmetric with the WRITE gate's RESIDENCY_GATE_REQUIRED. When the read gate
  // is skipped on an absent tag, a SELECT of EU-resident rows silently lands on
  // a tagged US replica — the fan-out drops the per-row residency tag. Under a
  // cross-border-regulated posture a tagged, non-cross-border replica must
  // refuse the untagged read rather than route it.
  b.externalDb._resetForTest();
  var roPrimaryOmit = _trackingDriver("ro-primary-omit");
  var usReplicaOmit  = _trackingDriver("us-replica-omit");
  b.externalDb.init({
    backends: {
      main: {
        connect: roPrimaryOmit.connect, query: roPrimaryOmit.query,
        close: roPrimaryOmit.close,   // primary unrestricted
        replicas: [
          {
            connect: usReplicaOmit.connect, query: usReplicaOmit.query,
            close: usReplicaOmit.close, residencyTag: "us",
            allowCrossBorder: false,
          },
        ],
        replicaFallbackToPrimary: false,
      },
    },
  });
  await _underGdpr(async function () {
    // No rowResidencyTag opt → the read gate must NOT silently pass.
    await _expectThrow("read with OMITTED rowResidencyTag under gdpr to a tagged replica fails closed",
      function () {
        return b.externalDb.read.query("SELECT id FROM orders WHERE id = $1", ["o-1"]);
      },
      "REPLICA_RESIDENCY_TAG_REQUIRED");
  });
  check("omitted-tag read → us-replica wire NOT reached (gate fail-closed)",
        usReplicaOmit.seen.every(function (s) { return !/SELECT id FROM orders/.test(s); }));

  // ---- read-replica gate must NOT over-reject an UNRESTRICTED replica ----
  // A replica with no residencyTag defaults to "unrestricted" (no residency
  // constraint — it may serve any region's rows). Under a cross-border-regulated
  // posture a read to it WITHOUT opts.rowResidencyTag must still pass: there is
  // no constraint to enforce. (Was: the fail-closed tag-required gate fired on
  // any truthy replica.residencyTag, and "unrestricted" is truthy → it refused
  // every regulated read to an untagged replica that omitted rowResidencyTag.)
  b.externalDb._resetForTest();
  var roPrimaryFree = _trackingDriver("ro-primary-free");
  var freeReplica   = _trackingDriver("free-replica");
  b.externalDb.init({
    backends: {
      main: {
        connect: roPrimaryFree.connect, query: roPrimaryFree.query,
        close: roPrimaryFree.close,   // primary unrestricted
        replicas: [
          {
            connect: freeReplica.connect, query: freeReplica.query,
            close: freeReplica.close,   // no residencyTag → "unrestricted"
            allowCrossBorder: false,
          },
        ],
        replicaFallbackToPrimary: false,
      },
    },
  });
  await _underGdpr(async function () {
    var res = await b.externalDb.read.query("SELECT id FROM orders WHERE id = $1", ["o-1"]);
    check("gdpr + unrestricted replica + omitted tag → passes (no over-reject)",
          res && res.rowCount === 1);
  });
  check("unrestricted-replica untagged read → replica wire reached",
        _saw(freeReplica, /SELECT id FROM orders/));

  // ---- write verbs that wear a harmless leading keyword must still be
  // gated: WITH (CTE) / COPY FROM / EXPLAIN ANALYZE / CALL / EXECUTE /
  // REPLACE / DO all PLACE rows, so under gdpr + eu backend they require
  // a tag; recognized pure reads (WITH...SELECT, COPY...TO, plain
  // EXPLAIN) pass untagged. One driver, exercised across the matrix. ----
  function _classDriver() { return _trackingDriver("class"); }

  async function _refusedUntagged(label, sql, code) {
    b.externalDb._resetForTest();
    var d = _classDriver();
    b.externalDb.init({ backends: { main: {
      connect: d.connect, query: d.query, close: d.close, residencyTag: "eu",
    } } });
    await _underGdpr(async function () {
      await _expectThrow(label, function () { return b.externalDb.query(sql, []); }, code);
    });
    check(label + " → wire NOT reached", d.seen.length === 0);
  }

  async function _passesUntagged(label, sql) {
    b.externalDb._resetForTest();
    var d = _classDriver();
    b.externalDb.init({ backends: { main: {
      connect: d.connect, query: d.query, close: d.close, residencyTag: "eu",
    } } });
    var err = null;
    await _underGdpr(async function () {
      try { await b.externalDb.query(sql, []); } catch (e) { err = e; }
    });
    check(label + " → passes untagged, wire reached", err === null && d.seen.length === 1);
  }

  async function _passesWithTag(label, sql) {
    b.externalDb._resetForTest();
    var d = _classDriver();
    b.externalDb.init({ backends: { main: {
      connect: d.connect, query: d.query, close: d.close, residencyTag: "eu",
    } } });
    var err = null;
    await _underGdpr(async function () {
      try { await b.externalDb.query(sql, [], { rowResidencyTag: "eu" }); }
      catch (e) { err = e; }
    });
    check(label + " → matching tag reaches the wire", err === null && d.seen.length === 1);
  }

  // CTE-wrapped DML (the Codex P1 shape) — write, gated.
  await _refusedUntagged("WITH ... INSERT (CTE write) untagged",
    "WITH src AS (SELECT 1 AS id) INSERT INTO eu_users (id) SELECT id FROM src",
    "RESIDENCY_GATE_REQUIRED");
  await _passesWithTag("WITH ... INSERT (CTE write) tag 'eu'",
    "WITH src AS (SELECT 1 AS id) INSERT INTO eu_users (id) SELECT id FROM src");
  // CTE-wrapped SELECT — read, passes untagged.
  await _passesUntagged("WITH ... SELECT (CTE read) untagged",
    "WITH src AS (SELECT 1 AS id) SELECT id FROM src");
  // RECURSIVE + MATERIALIZED keywords before the main verb don't confuse it.
  await _refusedUntagged("WITH RECURSIVE ... UPDATE untagged",
    "WITH RECURSIVE t AS (SELECT 1) UPDATE eu_users SET id = 2 WHERE id IN (SELECT * FROM t)",
    "RESIDENCY_GATE_REQUIRED");

  // COPY ... FROM loads rows (write); COPY ... TO exports (read).
  await _refusedUntagged("COPY ... FROM (bulk load) untagged",
    "COPY eu_users (id) FROM STDIN", "RESIDENCY_GATE_REQUIRED");
  await _passesUntagged("COPY (query) TO (export) untagged",
    "COPY (SELECT id FROM eu_users) TO STDOUT");

  // EXPLAIN ANALYZE EXECUTES the wrapped statement; plain EXPLAIN does not.
  await _refusedUntagged("EXPLAIN ANALYZE INSERT untagged",
    "EXPLAIN ANALYZE INSERT INTO eu_users (id) VALUES (1)", "RESIDENCY_GATE_REQUIRED");
  await _refusedUntagged("EXPLAIN (ANALYZE, FORMAT JSON) UPDATE untagged",
    "EXPLAIN (ANALYZE, FORMAT JSON) UPDATE eu_users SET id = 2 WHERE id = 1",
    "RESIDENCY_GATE_REQUIRED");
  await _passesUntagged("EXPLAIN (plan-only) INSERT untagged",
    "EXPLAIN INSERT INTO eu_users (id) VALUES (1)");
  await _passesUntagged("EXPLAIN SELECT untagged",
    "EXPLAIN SELECT id FROM eu_users");

  // Opaque-write verbs — CALL / EXECUTE / DO — gated (fail-closed).
  await _refusedUntagged("CALL stored-proc untagged",
    "CALL load_eu_rows('x')", "RESIDENCY_GATE_REQUIRED");
  await _refusedUntagged("EXECUTE prepared untagged",
    "EXECUTE ins_eu (1)", "RESIDENCY_GATE_REQUIRED");
  await _refusedUntagged("DO anonymous block untagged",
    "DO $$ BEGIN INSERT INTO eu_users (id) VALUES (1); END $$",
    "RESIDENCY_GATE_REQUIRED");

  // REPLACE INTO (mysql/sqlite) — delete-then-insert, a write.
  await _refusedUntagged("REPLACE INTO untagged",
    "REPLACE INTO eu_users (id) VALUES (1)", "RESIDENCY_GATE_REQUIRED");

  // A `;` inside a dollar-quoted body is DATA, not a statement
  // separator — must not false-positive as MULTI_STATEMENT_REFUSED; the
  // DO block is gated as the ROUTINE write it is.
  await _refusedUntagged("DO body with inner ; is one statement",
    "DO $$ BEGIN INSERT INTO eu_users (id) VALUES (1); INSERT INTO eu_users (id) VALUES (2); END $$",
    "RESIDENCY_GATE_REQUIRED");

  // An unresolvable WITH (no main verb past the CTE list) fails closed.
  await _refusedUntagged("unresolvable WITH refused",
    "WITH x AS (SELECT 1)", "STATEMENT_UNRESOLVED_REFUSED");

  // ---- Final clean ----
  b.externalDb._resetForTest();
  b.compliance.clear();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () {
    process.stdout.write("OK — external-db-residency: " + helpers.getChecks() + " checks passed\n");
  }, function (e) {
    process.stderr.write("FAIL: " + (e && e.stack || e) + "\n");
    process.exit(1);
  });
}
