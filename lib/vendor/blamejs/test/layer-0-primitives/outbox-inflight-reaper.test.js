// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// #128: the outbox must reclaim a row stranded 'in-flight' by a crashed
// publisher. A claim flips status pending → in-flight and stamps claimed_at;
// the claim path then only SELECTs status='pending', so if the process dies
// between the claim and _markPublished/_markRetry/_markDead, the row sits
// in-flight forever — silently dropped, violating the at-least-once delivery
// the module header advertises (b.queue has a sweepExpired reaper; outbox had
// none). The fix reaps any in-flight row whose claim is older than the lease
// (or predates the claimed_at column) back to 'pending' at the top of every
// poll.
//
// Driven against a REAL node:sqlite backend (a faithful externalDb), so the
// claim / reap / publish SQL actually executes. RED on the buggy tree: the
// stranded row is never published. GREEN after the fix: the reaper returns it
// to the pending pool and it publishes on the next poll.

var { DatabaseSync } = require("node:sqlite");
var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var C     = b.constants;

// Minimal faithful externalDb over an in-memory node:sqlite db: implements
// query(sql, params) + transaction(fn) + dialect, converting JS Date params
// to ISO strings the way the framework's real sqlite provider does.
function _sqliteExternalDb() {
  var db = new DatabaseSync(":memory:");
  function _bind(params) {
    return (params || []).map(function (v) {
      if (v instanceof Date) return v.toISOString();
      return v;
    });
  }
  function _query(sqlText, params) {
    var stmt = db.prepare(sqlText);
    var args = _bind(params);
    if (/^\s*select/i.test(sqlText)) {
      return { rows: stmt.all.apply(stmt, args) };
    }
    var info = stmt.run.apply(stmt, args);
    return { rows: [], changes: info.changes };
  }
  var xdb = {
    dialect: "sqlite",
    query: async function (s, p) { return _query(s, p); },
  };
  return {
    dialect: "sqlite",
    query: async function (s, p) { return _query(s, p); },
    transaction: async function (fn) {
      db.exec("BEGIN");
      try { var r = await fn(xdb); db.exec("COMMIT"); return r; }
      catch (e) { try { db.exec("ROLLBACK"); } catch (_e) {} throw e; }
    },
    _raw: db,
  };
}

async function run() {
  var xdb = _sqliteExternalDb();
  var published = [];
  var outbox = b.outbox.create({
    externalDb:     xdb,
    table:          "test_outbox",
    publisher:      async function (event) { published.push(event); },
    pollIntervalMs: C.TIME.seconds(1),
    claimReclaimMs: C.TIME.seconds(1),   // short lease so a 10s-old claim is stale
    audit:          false,
  });
  await outbox.declareSchema();

  // enqueue is transactional (the outbox pattern — written in the same txn as
  // the domain row); wrap each in a transaction and hand it the txClient.
  function _enqueue(event) {
    return xdb.transaction(async function (tx) { await outbox.enqueue(event, tx); });
  }

  // ---- the crash: a row claimed (in-flight) but never published ----
  await _enqueue({ topic: "orders", payload: { id: "o-1" } });
  check("#128 the enqueued row starts pending", (await outbox.pendingCount()) === 1);

  // Simulate a publisher that claimed the row then died: flip it to in-flight
  // with a claim timestamp older than the lease.
  var staleClaim = new Date(Date.now() - C.TIME.seconds(10)).toISOString();
  xdb._raw.prepare(
    "UPDATE \"test_outbox\" SET status = 'in-flight', claimed_at = ? WHERE topic = 'orders'"
  ).run(staleClaim);
  check("#128 the stranded row is no longer in the pending pool",
        (await outbox.pendingCount()) === 0);
  check("#128 nothing has been published yet", published.length === 0);

  // ---- one poll: the reaper must reclaim + the row must publish ----
  await outbox._processOnce();

  check("#128 the stranded in-flight row is reclaimed and published",
        published.length === 1 && published[0].topic === "orders");
  check("#128 no row is left stranded in-flight",
        Number(xdb._raw.prepare(
          "SELECT COUNT(*) AS n FROM \"test_outbox\" WHERE status = 'in-flight'").get().n) === 0);
  check("#128 the published row is marked published",
        Number(xdb._raw.prepare(
          "SELECT COUNT(*) AS n FROM \"test_outbox\" WHERE status = 'published'").get().n) === 1);
  check("#128 deadCount stays 0 (the row was delivered, not dead-lettered)",
        (await outbox.deadCount()) === 0);

  // ---- a FRESH in-flight claim (within the lease) must NOT be reclaimed ----
  await _enqueue({ topic: "fresh", payload: { id: "f-1" } });
  xdb._raw.prepare(
    "UPDATE \"test_outbox\" SET status = 'in-flight', claimed_at = ? WHERE topic = 'fresh'"
  ).run(new Date().toISOString());
  var publishedBefore = published.length;
  await outbox._processOnce();
  check("#128 a fresh in-flight claim (within the lease) is NOT reclaimed",
        Number(xdb._raw.prepare(
          "SELECT COUNT(*) AS n FROM \"test_outbox\" WHERE topic = 'fresh' AND status = 'in-flight'").get().n) === 1);
  check("#128 the fresh in-flight row was not re-published",
        published.length === publishedBefore);

  // ---- a legacy in-flight row (NULL claimed_at) is reclaimed ----
  await _enqueue({ topic: "legacy", payload: { id: "l-1" } });
  xdb._raw.prepare(
    "UPDATE \"test_outbox\" SET status = 'in-flight', claimed_at = NULL WHERE topic = 'legacy'"
  ).run();
  await outbox._processOnce();
  check("#128 a legacy in-flight row (NULL claimed_at) is reclaimed and published",
        published.some(function (e) { return e.topic === "legacy"; }));

  await outbox.stop();
  console.log("OK — outbox stale-in-flight reaper tests");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.stderr.write(String(err && err.stack || err) + "\n"); process.exit(1); });
}
