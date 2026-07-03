// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// #343: externalDb.transaction (and the b.outbox built on it) silently
// non-atomic on a stateless / autocommit-per-statement adapter.
//
// transaction(fn) defaults its tx verbs to query(client,"BEGIN") /
// query(client,"COMMIT") when the adapter supplies no beginTx/commit/
// rollback. On a stateless adapter — connect() returns a sentinel and
// every query() is an independent round-trip (e.g. an HTTP bridge to
// Cloudflare D1) — BEGIN, the body statements, and COMMIT each land on a
// DIFFERENT session: no isolation, no rollback. Yet the call resolves, so
// the consumer believes the block was atomic. b.outbox is built entirely
// on this (enqueue requires the txClient), so its dual-write guarantee is
// void on such a backend.
//
// FIX: a backend declares supportsTransactions:false (the stateless
// declaration). transaction() and outbox.create() then REFUSE LOUDLY with
// a typed error (fail closed) instead of running BEGIN/COMMIT as separate
// no-ops and resolving.
//
// RED on the buggy tree: transaction(fn) runs (BEGIN/COMMIT as independent
// no-op round-trips) and RESOLVES; outbox.create() succeeds. GREEN after
// the fix: both throw NON_ATOMIC_BACKEND / outbox/non-atomic-backend.

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

// A faithful STATELESS adapter: connect() returns a fresh sentinel each
// call, every query() is an independent round-trip against a shared store,
// and there is NO beginTx/commit/rollback hook. BEGIN/COMMIT/ROLLBACK are
// accepted as harmless no-ops (exactly what an autocommit bridge does).
function _makeStatelessAdapter() {
  var store = {};
  var connectCount = 0;
  var sawBegin = false;
  return {
    sawBegin: function () { return sawBegin; },
    connect: async function () { connectCount += 1; return { sentinel: connectCount }; },
    query: async function (_client, sql, params) {
      if (/^\s*(BEGIN|COMMIT|ROLLBACK)/i.test(sql)) { sawBegin = true; return { rows: [], rowCount: 0 }; }
      if (/^INSERT INTO kv/i.test(sql)) { store[params[0]] = params[1]; return { rows: [], rowCount: 1 }; }
      if (/^SELECT/i.test(sql)) {
        var v = store[params && params[0]];
        return v === undefined ? { rows: [], rowCount: 0 } : { rows: [{ value: v }], rowCount: 1 };
      }
      return { rows: [], rowCount: 0 };
    },
    close: async function () {},
  };
}

async function run() {
  // ---- transaction() refuses a stateless backend ----
  b.externalDb._resetForTest();
  var stateless = _makeStatelessAdapter();
  b.externalDb.init({
    backends: {
      d1: {
        dialect:              "sqlite",
        connect:              stateless.connect,
        query:                stateless.query,
        close:                stateless.close,
        supportsTransactions: false,   // stateless / autocommit-per-statement declaration
      },
    },
  });

  var threw = null;
  var bodyRan = false;
  try {
    await b.externalDb.transaction(async function (tx) {
      bodyRan = true;
      await tx.query("INSERT INTO kv (id, value) VALUES ($1, $2)", ["k", "v"]);
    });
  } catch (e) { threw = e; }
  check("#343 transaction() refuses a stateless backend (typed NON_ATOMIC_BACKEND)",
        threw && /NON_ATOMIC_BACKEND/.test(threw.code || ""));
  check("#343 transaction() refuses BEFORE running the body / any BEGIN",
        bodyRan === false && stateless.sawBegin() === false);

  // write.transaction routes through transaction() — must refuse too.
  var threwWrite = null;
  try {
    await b.externalDb.write.transaction(async function (tx) { await tx.query("SELECT 1", []); });
  } catch (e) { threwWrite = e; }
  check("#343 write.transaction() also refuses a stateless backend",
        threwWrite && /NON_ATOMIC_BACKEND/.test(threwWrite.code || ""));

  // supportsTransactions probe reflects the declaration.
  check("#343 supportsTransactions() probe returns false for the stateless backend",
        b.externalDb.supportsTransactions() === false);

  // ---- outbox.create() refuses a stateless backend ----
  var outboxThrew = null;
  try {
    b.outbox.create({
      externalDb: b.externalDb,
      table:      "outbox_events",
      publisher:  async function () {},
      audit:      false,
    });
  } catch (e) { outboxThrew = e; }
  check("#343 outbox.create() refuses a stateless backend (typed error)",
        outboxThrew && /non-atomic-backend/.test(outboxThrew.code || ""));

  // A custom externalDb object that declares supportsTransactions:false is
  // refused identically (outbox accepts the namespace OR a faithful object).
  var customOutboxThrew = null;
  try {
    b.outbox.create({
      externalDb: {
        dialect:              "sqlite",
        query:                async function () { return { rows: [] }; },
        transaction:          async function (fn) { return fn({ query: async function () { return { rows: [] }; } }); },
        supportsTransactions: false,
      },
      table:     "outbox_events",
      publisher: async function () {},
      audit:     false,
    });
  } catch (e) { customOutboxThrew = e; }
  check("#343 outbox.create() refuses a custom externalDb declaring supportsTransactions:false",
        customOutboxThrew && /non-atomic-backend/.test(customOutboxThrew.code || ""));

  // ---- no regression: a STATEFUL backend (the historical default) still works ----
  b.externalDb._resetForTest();
  var stateful = helpers._makeFakeDriver();
  b.externalDb.init({
    backends: { main: { connect: stateful.connect, query: stateful.query, close: stateful.close, ping: stateful.ping } },
  });
  var statefulOk = false;
  var got = await b.externalDb.transaction(async function (tx) {
    await tx.query("INSERT INTO kv (id, value) VALUES ($1, $2)", ["a", "1"]);
    var r = await tx.query("SELECT id, value FROM kv WHERE id = $1", ["a"]);
    statefulOk = r.rowCount === 1;
    return r.rows[0];
  });
  check("#343 a stateful backend (no flag, no hooks) still runs transactions",
        statefulOk && got && got.value === "1");
  check("#343 supportsTransactions() probe returns true for a stateful backend",
        b.externalDb.supportsTransactions() === true);
  check("#343 outbox.create() succeeds on a stateful backend",
        (function () {
          try {
            b.outbox.create({ externalDb: b.externalDb, table: "outbox_events",
              publisher: async function () {}, audit: false });
            return true;
          } catch (_e) { return false; }
        })());

  // ---- an explicit supportsTransactions:true (stateful operator assertion) is permitted ----
  b.externalDb._resetForTest();
  var asserted = helpers._makeFakeDriver();
  b.externalDb.init({
    backends: {
      mainAsserted: {
        connect:              asserted.connect,
        query:                asserted.query,
        close:                asserted.close,
        ping:                 asserted.ping,
        supportsTransactions: true,   // operator asserts the default BEGIN/COMMIT runs on a stateful client
      },
    },
  });
  check("#343 supportsTransactions:true is honored (transaction not refused)",
        b.externalDb.supportsTransactions() === true);

  // ---- a stateless adapter declaring supportsTransactions:false is refused even WITH a batch hook ----
  // (batch is a separate static-statement atomic path; it cannot make an
  //  interactive transaction(fn) safe, so it does NOT flip the capability.)
  b.externalDb._resetForTest();
  var batchAdapter = _makeStatelessAdapter();
  b.externalDb.init({
    backends: {
      d1batch: {
        dialect:              "sqlite",
        connect:              batchAdapter.connect,
        query:                batchAdapter.query,
        close:                batchAdapter.close,
        supportsTransactions: false,
        batch:                async function () { return; },
      },
    },
  });
  var batchThrew = null;
  try {
    await b.externalDb.transaction(async function (tx) { await tx.query("SELECT 1", []); });
  } catch (e) { batchThrew = e; }
  check("#343 a stateless adapter with only a batch hook still refuses interactive transaction()",
        batchThrew && /NON_ATOMIC_BACKEND/.test(batchThrew.code || ""));

  b.externalDb._resetForTest();
  console.log("OK — externalDb non-atomic backend refusal (#343)");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.stderr.write(String(err && err.stack || err) + "\n"); process.exit(1); });
}
