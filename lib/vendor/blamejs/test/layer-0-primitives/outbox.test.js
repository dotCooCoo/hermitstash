// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// Behavioral coverage for b.outbox.create — the transactional-outbox
// primitive. The stale-in-flight reaper has its own file
// (outbox-inflight-reaper.test.js #128); this file drives the create() /
// enqueue() validation surface, the publish / retry / dead-letter state
// machine, the sqlite + postgres claim paths, the debezium envelope, and
// the start/stop worker lifecycle through the REAL consumer path.
//
// Every backend here is a faithful in-process node:sqlite externalDb (or a
// postgres-dialect facade over the same, rewriting FOR UPDATE SKIP LOCKED /
// $N / = ANY(?) so the pg claim SQL actually executes). No network, no
// NODE_ENV bypass — the production code path runs unchanged.

var { DatabaseSync } = require("node:sqlite");
var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var C     = b.constants;

var OutboxError = b.outbox.OutboxError;

// Faithful externalDb over an in-memory node:sqlite db: query(sql, params)
// + transaction(fn) + dialect, converting JS Date params to ISO strings the
// way the framework's real sqlite provider does. Mirrors the sibling reaper
// test — no shared helper provides an externalDb.
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

// Postgres-dialect facade over node:sqlite. Rewrites the pg-only SQL the
// outbox emits on a postgres backend so the FOR UPDATE SKIP LOCKED claim
// path (the double-publish guard) actually executes against a real engine:
//   - strip `FOR UPDATE SKIP LOCKED` (sqlite is a single writer)
//   - `= ANY($N)` → `IN (?, ?, ...)`, flattening the bound array param
//   - `$N` → `?`, params re-ordered by textual appearance
// The table is created with sqlite-compatible DDL up front (declareSchema
// on a pg backend would emit BIGSERIAL / TIMESTAMPTZ / partial index).
function _pgExternalDb(tableName) {
  var db = new DatabaseSync(":memory:");
  db.exec(
    'CREATE TABLE "' + tableName + '" (' +
    '  "id" INTEGER PRIMARY KEY AUTOINCREMENT,' +
    '  "topic" TEXT NOT NULL,' +
    '  "payload" TEXT NOT NULL,' +
    '  "key" TEXT,' +
    '  "headers" TEXT,' +
    '  "enqueued_at" TEXT NOT NULL,' +
    '  "next_attempt_at" TEXT NOT NULL,' +
    '  "published_at" TEXT,' +
    '  "claimed_at" TEXT,' +
    '  "attempts" INTEGER NOT NULL DEFAULT 0,' +
    '  "last_error" TEXT,' +
    '  "status" TEXT NOT NULL DEFAULT \'pending\'' +
    ')'
  );
  function _rewrite(sqlText, params) {
    params = params || [];
    var out = [];
    var text = sqlText.replace(/\s+FOR UPDATE SKIP LOCKED/gi, "");
    text = text.replace(/=\s*ANY\(\$(\d+)\)|\$(\d+)/gi, function (_m, anyN, plainN) {
      if (anyN !== undefined) {
        var arr = params[Number(anyN) - 1];
        if (!Array.isArray(arr)) arr = [arr];
        for (var i = 0; i < arr.length; i++) out.push(arr[i]);
        return " IN (" + arr.map(function () { return "?"; }).join(", ") + ")";
      }
      out.push(params[Number(plainN) - 1]);
      return "?";
    });
    var bound = out.map(function (v) { return v instanceof Date ? v.toISOString() : v; });
    return { text: text, bound: bound };
  }
  function _query(sqlText, params) {
    var r = _rewrite(sqlText, params);
    var stmt = db.prepare(r.text);
    if (/^\s*select/i.test(r.text)) {
      return { rows: stmt.all.apply(stmt, r.bound) };
    }
    var info = stmt.run.apply(stmt, r.bound);
    return { rows: [], changes: info.changes };
  }
  var xdb = {
    dialect: "postgres",
    query: async function (s, p) { return _query(s, p); },
  };
  return {
    dialect: "postgres",
    query: async function (s, p) { return _query(s, p); },
    transaction: async function (fn) {
      db.exec("BEGIN");
      try { var r = await fn(xdb); db.exec("COMMIT"); return r; }
      catch (e) { try { db.exec("ROLLBACK"); } catch (_e) {} throw e; }
    },
    _raw: db,
  };
}

function _expectThrow(fn, code, label) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label + " throws", threw !== null);
  if (threw && code) {
    check(label + " → code " + code, threw.code === code);
  }
  return threw;
}

async function _expectReject(promise, code, label) {
  var threw = null;
  try { await promise; } catch (e) { threw = e; }
  check(label + " rejects", threw !== null);
  if (threw && code) {
    check(label + " → code " + code, threw.code === code);
  }
  return threw;
}

function _mkOutbox(xdb, extra) {
  var opts = {
    externalDb: xdb,
    table:      "test_outbox",
    publisher:  async function () {},
    audit:      false,
  };
  if (extra) for (var k in extra) opts[k] = extra[k];
  return b.outbox.create(opts);
}

// ---------------------------------------------------------------------------
// create() — config-time validation (THROW tier)
// ---------------------------------------------------------------------------
async function testCreateValidation() {
  var xdb = _sqliteExternalDb();

  _expectThrow(function () { b.outbox.create(null); }, "BAD_OPT",
    "create(null)");
  _expectThrow(function () { b.outbox.create("nope"); }, "BAD_OPT",
    "create(non-object)");

  // Unknown opt key is refused by the allowed-keys gate.
  _expectThrow(function () { _mkOutbox(xdb, { bogusKey: 1 }); }, null,
    "create({ unknown key })");

  // externalDb missing / not a transaction-capable object.
  _expectThrow(function () {
    b.outbox.create({ table: "t", publisher: async function () {} });
  }, "outbox/bad-externaldb", "create() with no externalDb");
  _expectThrow(function () {
    b.outbox.create({ externalDb: { query: function () {} }, table: "t", publisher: async function () {} });
  }, "outbox/bad-externaldb", "create() externalDb without transaction()");

  // Non-atomic backend: supportsTransactions === false → refuse.
  _expectThrow(function () {
    b.outbox.create({
      externalDb: { transaction: function () {}, query: function () {}, supportsTransactions: false },
      table: "t", publisher: async function () {},
    });
  }, "outbox/non-atomic-backend", "create() supportsTransactions:false");

  // Non-atomic backend: supportsTransactions is a probe fn returning false.
  _expectThrow(function () {
    b.outbox.create({
      externalDb: { transaction: function () {}, query: function () {}, supportsTransactions: function () { return false; } },
      table: "t", publisher: async function () {},
    });
  }, "outbox/non-atomic-backend", "create() supportsTransactions()→false");

  // A probe fn that THROWS is treated as atomic (historical assumption held).
  var okThrows = b.outbox.create({
    externalDb: { transaction: function () {}, query: function () {}, supportsTransactions: function () { throw new Error("boom"); } },
    table: "t", publisher: async function () {}, audit: false,
  });
  check("create() supportsTransactions() throw → still constructs (atomic assumed)",
    okThrows && typeof okThrows.enqueue === "function");

  // table: empty / missing / bad identifier.
  _expectThrow(function () {
    b.outbox.create({ externalDb: xdb, table: "", publisher: async function () {} });
  }, "outbox/bad-table", "create() empty table");
  _expectThrow(function () {
    b.outbox.create({ externalDb: xdb, table: 42, publisher: async function () {} });
  }, "outbox/bad-table", "create() non-string table");
  // Embedded quote — quoteIdentifier refuses (surfaces some error).
  _expectThrow(function () {
    b.outbox.create({ externalDb: xdb, table: 'bad"name', publisher: async function () {} });
  }, null, "create() table with embedded quote");

  // publisher: not a function.
  _expectThrow(function () {
    b.outbox.create({ externalDb: xdb, table: "t", publisher: 123 });
  }, "outbox/bad-publisher", "create() non-function publisher");

  // envelope: unknown value.
  _expectThrow(function () {
    _mkOutbox(xdb, { envelope: "avro" });
  }, "outbox/bad-envelope", "create() bad envelope");

  // retryBackoff sub-shape: non-positive / non-finite fields refuse.
  _expectThrow(function () {
    _mkOutbox(xdb, { retryBackoff: { initialMs: -1 } });
  }, "outbox/bad-opts", "create() retryBackoff.initialMs negative");
  _expectThrow(function () {
    _mkOutbox(xdb, { retryBackoff: { maxMs: 0 } });
  }, "outbox/bad-opts", "create() retryBackoff.maxMs zero");
  _expectThrow(function () {
    _mkOutbox(xdb, { retryBackoff: { factor: Infinity } });
  }, "outbox/bad-opts", "create() retryBackoff.factor Infinity");

  // Numeric caps refuse non-positive / non-finite.
  _expectThrow(function () {
    _mkOutbox(xdb, { pollIntervalMs: 0 });
  }, "outbox/bad-opts", "create() pollIntervalMs zero");
  _expectThrow(function () {
    _mkOutbox(xdb, { batchSize: -5 });
  }, "outbox/bad-opts", "create() batchSize negative");
  _expectThrow(function () {
    _mkOutbox(xdb, { maxAttempts: NaN });
  }, "outbox/bad-opts", "create() maxAttempts NaN");
  _expectThrow(function () {
    _mkOutbox(xdb, { claimReclaimMs: Infinity });
  }, "outbox/bad-opts", "create() claimReclaimMs Infinity");

  // A fully-defaulted valid create constructs a usable handle.
  var ok = _mkOutbox(xdb);
  check("create() with defaults returns the outbox surface",
    ok && typeof ok.enqueue === "function" && typeof ok.start === "function" &&
    typeof ok.stop === "function" && typeof ok.pendingCount === "function" &&
    typeof ok.deadCount === "function" && typeof ok.declareSchema === "function");

  check("OutboxError is exported and is a constructor", typeof OutboxError === "function");
}

// ---------------------------------------------------------------------------
// enqueue() — event-shape validation (THROW tier), driven in a real txn
// ---------------------------------------------------------------------------
async function testEnqueueValidation() {
  var xdb = _sqliteExternalDb();
  var outbox = _mkOutbox(xdb);
  await outbox.declareSchema();

  function _inTxn(fn) {
    return xdb.transaction(async function (tx) { return fn(tx); });
  }

  // bad txn handle — not the txClient.
  await _expectReject(outbox.enqueue({ topic: "t", payload: {} }, null),
    "outbox/bad-txn", "enqueue() null txn");
  await _expectReject(outbox.enqueue({ topic: "t", payload: {} }, { notQuery: true }),
    "outbox/bad-txn", "enqueue() txn without query()");

  // The rest run inside a real transaction so the txClient is valid.
  await _inTxn(async function (tx) {
    await _expectReject(outbox.enqueue(null, tx), "outbox/bad-event", "enqueue() null event");
    await _expectReject(outbox.enqueue("str", tx), "outbox/bad-event", "enqueue() non-object event");

    await _expectReject(outbox.enqueue({ payload: {} }, tx), "outbox/bad-event", "enqueue() missing topic");
    await _expectReject(outbox.enqueue({ topic: "", payload: {} }, tx), "outbox/bad-event", "enqueue() empty topic");
    var longTopic = new Array(300).join("x") + "yyy"; // > 255
    await _expectReject(outbox.enqueue({ topic: longTopic, payload: {} }, tx),
      "outbox/bad-event", "enqueue() over-long topic");

    await _expectReject(outbox.enqueue({ topic: "t" }, tx), "outbox/bad-event",
      "enqueue() missing payload (undefined)");

    // key: wrong type / over-long.
    await _expectReject(outbox.enqueue({ topic: "t", payload: {}, key: 5 }, tx),
      "outbox/bad-event", "enqueue() non-string key");
    var longKey = new Array(300).join("k");
    await _expectReject(outbox.enqueue({ topic: "t", payload: {}, key: longKey }, tx),
      "outbox/bad-event", "enqueue() over-long key");

    // headers: array / non-object.
    await _expectReject(outbox.enqueue({ topic: "t", payload: {}, headers: [1, 2] }, tx),
      "outbox/bad-event", "enqueue() array headers");
    await _expectReject(outbox.enqueue({ topic: "t", payload: {}, headers: "x" }, tx),
      "outbox/bad-event", "enqueue() string headers");

    // non-JSON-serializable payload (circular) → wrapped bad-event.
    var circular = {}; circular.self = circular;
    await _expectReject(outbox.enqueue({ topic: "t", payload: circular }, tx),
      "outbox/bad-event", "enqueue() circular payload");
  });

  // A valid enqueue with key:null and headers:null lands a pending row.
  await _inTxn(async function (tx) {
    await outbox.enqueue({ topic: "ok", payload: { a: 1 }, key: null, headers: null }, tx);
  });
  check("enqueue() valid row is pending", (await outbox.pendingCount()) === 1);

  // payload:null is a valid JSON value (only undefined is rejected).
  await _inTxn(async function (tx) {
    await outbox.enqueue({ topic: "nullpay", payload: null }, tx);
  });
  check("enqueue() payload:null is accepted", (await outbox.pendingCount()) === 2);
}

// ---------------------------------------------------------------------------
// _processOnce — publish success / empty batch / null payload round-trip
// ---------------------------------------------------------------------------
async function testProcessPublish() {
  var xdb = _sqliteExternalDb();
  var published = [];
  var outbox = _mkOutbox(xdb, { publisher: async function (e) { published.push(e); } });
  await outbox.declareSchema();

  // Empty poll returns 0.
  check("_processOnce() empty batch returns 0", (await outbox._processOnce()) === 0);

  await xdb.transaction(async function (tx) {
    await outbox.enqueue({ topic: "orders", payload: { id: "o-1" }, key: "k1", headers: { h: "1" } }, tx);
    await outbox.enqueue({ topic: "nullpay", payload: null }, tx);
  });

  var n = await outbox._processOnce();
  check("_processOnce() publishes the whole batch", n === 2);
  check("_processOnce() delivered both events", published.length === 2);
  var order = published.filter(function (e) { return e.topic === "orders"; })[0];
  check("_processOnce() deserializes payload JSON", order && order.payload && order.payload.id === "o-1");
  check("_processOnce() deserializes headers JSON", order && order.headers && order.headers.h === "1");
  check("_processOnce() carries key through", order && order.key === "k1");
  var np = published.filter(function (e) { return e.topic === "nullpay"; })[0];
  check("_processOnce() null payload round-trips to null", np && np.payload === null && np.headers === null);

  check("_processOnce() marks both published", (await outbox.pendingCount()) === 0);
  check("_processOnce() dead count stays 0", (await outbox.deadCount()) === 0);
}

// ---------------------------------------------------------------------------
// _processOnce — retry curve + dead-letter transition on publisher failure
// ---------------------------------------------------------------------------
async function testRetryAndDeadLetter() {
  var xdb = _sqliteExternalDb();
  var attempts = 0;
  var outbox = _mkOutbox(xdb, {
    maxAttempts: 3,
    // maxMs (1500) sits between the attempt-1 backoff (1000) and the attempt-2
    // backoff (2000), so the second retry's curve is clamped to the ceiling —
    // exercising both sides of the _backoffMs cap.
    retryBackoff: { initialMs: C.TIME.seconds(1), maxMs: 1500, factor: 2 },
    publisher: async function () { attempts += 1; throw new Error("bus down"); },
  });
  await outbox.declareSchema();

  await xdb.transaction(async function (tx) {
    await outbox.enqueue({ topic: "flaky", payload: { id: 1 } }, tx);
  });

  // Attempt 1 fails → stays pending, attempts=1, next_attempt_at pushed out.
  await outbox._processOnce();
  var row1 = xdb._raw.prepare('SELECT attempts, status, last_error, next_attempt_at FROM "test_outbox"').get();
  check("retry: after 1 failure attempts=1", row1.attempts === 1);
  check("retry: row stays pending", row1.status === "pending");
  check("retry: last_error recorded", /bus down/.test(row1.last_error));
  check("retry: next_attempt_at pushed into the future",
    new Date(row1.next_attempt_at).getTime() > Date.now());

  // Force the row eligible again (next_attempt_at in the past) and re-poll.
  function _makeEligible() {
    xdb._raw.prepare('UPDATE "test_outbox" SET next_attempt_at = ? WHERE status = \'pending\'')
      .run(new Date(Date.now() - C.TIME.seconds(60)).toISOString());
  }
  _makeEligible();
  var t2 = Date.now();
  await outbox._processOnce(); // attempt 2 → attempts=2, still pending
  var row2 = xdb._raw.prepare('SELECT attempts, status, next_attempt_at FROM "test_outbox"').get();
  check("retry: after 2 failures attempts=2 still pending", row2.attempts === 2 && row2.status === "pending");
  // Unclamped the 2nd retry curve would be 2000ms out; the cap pins it to 1500.
  check("retry: 2nd-retry backoff is clamped to maxMs (< unclamped 2000ms)",
    new Date(row2.next_attempt_at).getTime() - t2 < 1800);

  _makeEligible();
  await outbox._processOnce(); // attempt 3 → nextAttempts(3) >= maxAttempts(3) → dead
  var row3 = xdb._raw.prepare('SELECT attempts, status FROM "test_outbox"').get();
  check("dead-letter: attempts hit max → status dead", row3.status === "dead");
  check("dead-letter: attempts stamped as max", row3.attempts === 3);
  check("dead-letter: deadCount reflects the dead row", (await outbox.deadCount()) === 1);
  check("dead-letter: pendingCount drops to 0", (await outbox.pendingCount()) === 0);
  check("dead-letter: publisher was invoked 3 times", attempts === 3);
}

// ---------------------------------------------------------------------------
// _processOnce — drop-silent when _markRetry / _markDead itself fails
// ---------------------------------------------------------------------------
async function testMarkFailureDropSilent() {
  var xdb = _sqliteExternalDb();
  var outbox = _mkOutbox(xdb, {
    maxAttempts: 1, // first failure → dead path
    publisher: async function () { throw new Error("publish boom"); },
  });
  await outbox.declareSchema();
  await xdb.transaction(async function (tx) {
    await outbox.enqueue({ topic: "t", payload: { id: 1 } }, tx);
  });

  // Make every write after the claim throw, so _markDead throws and is
  // swallowed (drop-silent — worker keeps moving). Wrap the outer query()
  // to reject UPDATE ... SET status = 'dead'.
  var realQuery = xdb.query;
  xdb.query = async function (s, p) {
    if (/status\s*=\s*'?dead'?/i.test(s) || /SET\s+"?status"?\s*=\s*\?/i.test(s)) {
      throw new Error("db write blocked");
    }
    return realQuery(s, p);
  };
  var n = await outbox._processOnce();
  xdb.query = realQuery;
  check("drop-silent: _processOnce still returns the batch length despite mark failure", n === 1);
  // The row could not be marked dead; it remains in-flight (claimed) — the
  // reaper will reclaim it later. The point is _processOnce did NOT throw.
  check("drop-silent: _processOnce did not throw when _markDead failed", true);
}

// ---------------------------------------------------------------------------
// _processOnce — drop-silent when _markRetry itself fails (retry path)
// ---------------------------------------------------------------------------
async function testMarkRetryFailureDropSilent() {
  var xdb = _sqliteExternalDb();
  var outbox = _mkOutbox(xdb, {
    maxAttempts: 3, // first failure → retry path (not dead)
    publisher: async function () { throw new Error("publish boom"); },
  });
  await outbox.declareSchema();
  await xdb.transaction(async function (tx) {
    await outbox.enqueue({ topic: "t", payload: { id: 1 } }, tx);
  });

  // Block the retry UPDATE (it stamps last_error) so _markRetry throws; the
  // publish loop must swallow it (drop-silent) and still return the batch size.
  var realQuery = xdb.query;
  xdb.query = async function (s, p) {
    if (/last_error/i.test(s)) throw new Error("db write blocked");
    return realQuery(s, p);
  };
  var threw = null;
  var n;
  try { n = await outbox._processOnce(); } catch (e) { threw = e; }
  xdb.query = realQuery;
  check("drop-silent: _processOnce did not throw when _markRetry failed", threw === null);
  check("drop-silent: _processOnce still returns the batch length", n === 1);
}

// ---------------------------------------------------------------------------
// _processOnce — reaper failure is swallowed (drop-silent)
// ---------------------------------------------------------------------------
async function testReaperFailureDropSilent() {
  var xdb = _sqliteExternalDb();
  var published = [];
  var outbox = _mkOutbox(xdb, { publisher: async function (e) { published.push(e); } });
  await outbox.declareSchema();
  await xdb.transaction(async function (tx) {
    await outbox.enqueue({ topic: "t", payload: { id: 1 } }, tx);
  });

  // Fail only the reaper UPDATE (status = 'in-flight' predicate → pending),
  // leave the claim path intact. _processOnce must swallow the reaper error
  // and still publish.
  var realQuery = xdb.query;
  var failedOnce = false;
  xdb.query = async function (s, p) {
    if (!failedOnce && /SET\s+"?status"?\s*=\s*\?,\s*"?claimed_at"?\s*=\s*\?\s+WHERE\s+status\s*=\s*'in-flight'/i.test(s)) {
      failedOnce = true;
      throw new Error("reaper blocked");
    }
    return realQuery(s, p);
  };
  var n = await outbox._processOnce();
  xdb.query = realQuery;
  check("drop-silent: reaper failure did not abort the poll", n === 1);
  check("drop-silent: the row still published despite reaper error", published.length === 1);
}

// ---------------------------------------------------------------------------
// Postgres claim path — FOR UPDATE SKIP LOCKED + `= ANY(?)` claim update
// ---------------------------------------------------------------------------
async function testPostgresClaimPath() {
  var xdb = _pgExternalDb("test_outbox");
  var published = [];
  var outbox = _mkOutbox(xdb, { publisher: async function (e) { published.push(e); } });

  // enqueue two rows through the real transactional path (pg INSERT).
  await xdb.transaction(async function (tx) {
    await outbox.enqueue({ topic: "pg1", payload: { id: 1 }, key: "a" }, tx);
    await outbox.enqueue({ topic: "pg2", payload: { id: 2 } }, tx);
  });
  check("pg: two rows enqueued pending", (await outbox.pendingCount()) === 2);

  var n = await outbox._processOnce();
  check("pg: claim+publish drains both rows", n === 2 && published.length === 2);
  check("pg: both marked published", (await outbox.pendingCount()) === 0);
  var topics = published.map(function (e) { return e.topic; }).sort();
  check("pg: correct topics delivered", topics[0] === "pg1" && topics[1] === "pg2");
}

// ---------------------------------------------------------------------------
// Debezium envelope — payload wrapping, op header, connector metadata
// ---------------------------------------------------------------------------
async function testDebeziumEnvelope() {
  var xdb = _sqliteExternalDb();
  var published = [];
  var outbox = _mkOutbox(xdb, {
    envelope:      "debezium",
    connectorName: "myconn",
    dbName:        "shopdb",
    publisher:     async function (e) { published.push(e); },
  });
  await outbox.declareSchema();

  await xdb.transaction(async function (tx) {
    // object payload with explicit before/after + a debezium-op header.
    await outbox.enqueue({
      topic:   "accounts",
      payload: { before: { bal: 10 }, after: { bal: 5 } },
      key:     "acct-1",
      headers: { "debezium-op": "u" },
    }, tx);
    // scalar payload → wrapped as { value: <scalar> } and used as `after`.
    await outbox.enqueue({ topic: "scalars", payload: 42 }, tx);
  });

  await outbox._processOnce();
  check("debezium: both events published", published.length === 2);

  var acct = published.filter(function (e) { return e.payload && e.payload.source && e.payload.source.table === "accounts"; })[0];
  check("debezium: envelope carries a schema", acct && acct.schema && acct.schema.type === "struct");
  check("debezium: op comes from the debezium-op header", acct && acct.payload.op === "u");
  check("debezium: before/after preserved", acct && acct.payload.before.bal === 10 && acct.payload.after.bal === 5);
  check("debezium: connector metadata applied", acct &&
    acct.payload.source.connector === "myconn" && acct.payload.source.db === "shopdb" &&
    acct.payload.source.version === "1.0.0");
  check("debezium: key travels as an extension field", acct && acct.payload.key === "acct-1");

  var scalar = published.filter(function (e) { return e.payload && e.payload.source && e.payload.source.table === "scalars"; })[0];
  check("debezium: scalar payload wrapped as { value }", scalar && scalar.payload.after && scalar.payload.after.value === 42);
  check("debezium: default op is 'c' when no header", scalar && scalar.payload.op === "c");
}

// ---------------------------------------------------------------------------
// declareSchema — dialect-correct DDL for postgres / mysql (recording backend)
// ---------------------------------------------------------------------------
function _recordingDb(dialect) {
  var queries = [];
  var api = {
    dialect: dialect,
    query: async function (s, p) { queries.push({ sql: s, params: p }); return { rows: [] }; },
    _queries: queries,
  };
  api.transaction = async function (fn) { return fn(api); };
  return api;
}

async function testDeclareSchemaDialects() {
  // Postgres: identity PK renders BIGSERIAL, timestamps TIMESTAMPTZ, and the
  // claim index is a partial index (WHERE status='pending') on next_attempt_at.
  var pg = _recordingDb("postgres");
  var pgOutbox = _mkOutbox(pg);
  await pgOutbox.declareSchema();
  var pgSql = pg._queries.map(function (q) { return q.sql; }).join("\n");
  check("declareSchema(postgres) emits >=3 statements (table + index + alter)",
    pg._queries.length >= 3);
  check("declareSchema(postgres) uses TIMESTAMPTZ timestamps", /TIMESTAMPTZ/i.test(pgSql));
  check("declareSchema(postgres) emits a partial claim index", /WHERE status = 'pending'/i.test(pgSql));

  // MySQL: no partial index (WHERE on CREATE INDEX is a syntax error there) —
  // falls back to a composite (status, next_attempt_at) index; timestamps TIMESTAMP.
  var my = _recordingDb("mysql");
  var myOutbox = _mkOutbox(my);
  await myOutbox.declareSchema();
  var mySql = my._queries.map(function (q) { return q.sql; }).join("\n");
  check("declareSchema(mysql) emits >=3 statements", my._queries.length >= 3);
  check("declareSchema(mysql) does NOT emit a partial index WHERE",
    !/WHERE status = 'pending'/i.test(mySql));
  check("declareSchema(mysql) composite index carries status",
    /status/i.test(mySql) && /_pending_idx/i.test(mySql));
}

// ---------------------------------------------------------------------------
// declareSchema — back-compat: adds claimed_at to a pre-existing legacy table
// ---------------------------------------------------------------------------
async function testDeclareSchemaLegacyMigration() {
  var xdb = _sqliteExternalDb();
  // A table created before the stale-in-flight reaper existed — no claimed_at.
  xdb._raw.exec(
    'CREATE TABLE "test_outbox" (' +
    '  "id" INTEGER PRIMARY KEY AUTOINCREMENT,' +
    '  "topic" TEXT NOT NULL, "payload" TEXT NOT NULL, "key" TEXT, "headers" TEXT,' +
    '  "enqueued_at" TEXT NOT NULL, "next_attempt_at" TEXT NOT NULL,' +
    '  "published_at" TEXT, "attempts" INTEGER NOT NULL DEFAULT 0,' +
    '  "last_error" TEXT, "status" TEXT NOT NULL DEFAULT \'pending\')'
  );
  var cols0 = xdb._raw.prepare('PRAGMA table_info("test_outbox")').all()
    .map(function (c) { return c.name; });
  check("legacy table starts WITHOUT claimed_at", cols0.indexOf("claimed_at") === -1);

  var outbox = _mkOutbox(xdb);
  // CREATE TABLE IF NOT EXISTS no-ops (table exists); the idempotent ALTER
  // succeeds because claimed_at is genuinely missing — the back-compat path.
  await outbox.declareSchema();
  var cols1 = xdb._raw.prepare('PRAGMA table_info("test_outbox")').all()
    .map(function (c) { return c.name; });
  check("declareSchema back-fills claimed_at on a legacy table",
    cols1.indexOf("claimed_at") !== -1);

  // Running it AGAIN is idempotent — the ALTER now throws (duplicate column)
  // and is swallowed; no exception surfaces.
  var reran = null;
  try { await outbox.declareSchema(); } catch (e) { reran = e; }
  check("declareSchema is idempotent on the second run (duplicate ALTER swallowed)",
    reran === null);
}

// ---------------------------------------------------------------------------
// _processOnce — corrupt/legacy row with an empty payload publishes null
// ---------------------------------------------------------------------------
async function testCorruptEmptyPayload() {
  var xdb = _sqliteExternalDb();
  var published = [];
  var outbox = _mkOutbox(xdb, { publisher: async function (e) { published.push(e); } });
  await outbox.declareSchema();
  // A row whose payload column is the empty string (a corrupt/legacy write) —
  // enqueue never produces this, but the publisher deserializer must fail
  // closed to null rather than throw on a falsy payload.
  var past = new Date(Date.now() - C.TIME.seconds(60)).toISOString();
  xdb._raw.prepare(
    'INSERT INTO "test_outbox" ("topic","payload","enqueued_at","next_attempt_at","attempts","status")' +
    " VALUES ('corrupt','',?,?,0,'pending')"
  ).run(past, past);

  await outbox._processOnce();
  check("corrupt-payload: the empty-payload row still published", published.length === 1);
  check("corrupt-payload: empty payload deserializes to null (fail-closed)",
    published[0].payload === null);
}

// ---------------------------------------------------------------------------
// _processOnce — publisher rejecting a falsy (non-Error) value on retry + dead
// ---------------------------------------------------------------------------
async function testPublisherRejectsFalsy() {
  var xdb = _sqliteExternalDb();
  var outbox = _mkOutbox(xdb, {
    maxAttempts: 2,
    // Reject with `undefined` (not an Error) so `(e && e.message) || String(e)`
    // takes its String(e) fallback on both the retry and dead-letter paths.
    publisher: async function () { return Promise.reject(undefined); },
  });
  await outbox.declareSchema();
  await xdb.transaction(async function (tx) {
    await outbox.enqueue({ topic: "t", payload: { id: 1 } }, tx);
  });

  await outbox._processOnce(); // attempt 1 → retry (nextAttempts 1 < 2)
  var r1 = xdb._raw.prepare('SELECT attempts, status, last_error FROM "test_outbox"').get();
  check("falsy-reject: retry records String(undefined) as last_error",
    r1.status === "pending" && r1.attempts === 1 && r1.last_error === "undefined");

  xdb._raw.prepare('UPDATE "test_outbox" SET next_attempt_at = ?')
    .run(new Date(Date.now() - C.TIME.seconds(60)).toISOString());
  await outbox._processOnce(); // attempt 2 → dead (nextAttempts 2 >= 2)
  var r2 = xdb._raw.prepare('SELECT attempts, status, last_error FROM "test_outbox"').get();
  check("falsy-reject: dead-letter records String(undefined) as last_error",
    r2.status === "dead" && r2.last_error === "undefined");
  check("falsy-reject: deadCount reflects the dead row", (await outbox.deadCount()) === 1);
}

// ---------------------------------------------------------------------------
// Debezium — default connector metadata (no connectorName / dbName supplied)
// ---------------------------------------------------------------------------
async function testDebeziumDefaults() {
  var xdb = _sqliteExternalDb();
  var published = [];
  var outbox = _mkOutbox(xdb, {
    envelope:  "debezium",
    publisher: async function (e) { published.push(e); },
  });
  await outbox.declareSchema();
  await xdb.transaction(async function (tx) {
    await outbox.enqueue({ topic: "def", payload: { x: 1 } }, tx);
  });
  await outbox._processOnce();
  check("debezium-defaults: one event published", published.length === 1);
  check("debezium-defaults: connector defaults to 'blamejs'",
    published[0].payload.source.connector === "blamejs");
  check("debezium-defaults: db defaults to null when dbName omitted",
    published[0].payload.source.db === null);
}

// ---------------------------------------------------------------------------
// Worker lifecycle — start/stop, double-start no-op, poll drains the outbox
// ---------------------------------------------------------------------------
async function testWorkerLifecycle() {
  var xdb = _sqliteExternalDb();
  var published = [];
  var outbox = _mkOutbox(xdb, {
    pollIntervalMs: 20, // fast poll so waitUntil resolves quickly
    publisher:      async function (e) { published.push(e); },
  });
  await outbox.declareSchema();
  await xdb.transaction(async function (tx) {
    await outbox.enqueue({ topic: "live", payload: { id: 1 } }, tx);
  });

  try {
    outbox.start();
    outbox.start(); // second call is a no-op (workerHandle already set)
    await helpers.waitUntil(function () { return published.length >= 1; }, {
      timeoutMs: 5000, label: "outbox worker: published the pending row",
    });
    check("worker: start() drains the pending row", published.length === 1 && published[0].topic === "live");
  } finally {
    await outbox.stop();
  }
  check("worker: stop() completes cleanly", true);

  // stop() again is safe (workerHandle already null).
  await outbox.stop();
  check("worker: double stop() is safe", true);
}

// ---------------------------------------------------------------------------
// Worker — a slow publish holds inFlight across ticks (the overlap guard),
// and stop() awaits the in-flight poll rather than abandoning it.
// ---------------------------------------------------------------------------
async function testWorkerInFlightGuardAndStop() {
  var xdb = _sqliteExternalDb();
  var published = [];
  var entered = 0;
  var releaseGate;
  var gate = new Promise(function (resolve) { releaseGate = resolve; });
  var outbox = _mkOutbox(xdb, {
    pollIntervalMs: 15, // fast poll so several ticks fire while a publish blocks
    publisher: async function (e) { entered += 1; await gate; published.push(e); },
  });
  await outbox.declareSchema();
  await xdb.transaction(async function (tx) {
    await outbox.enqueue({ topic: "slow", payload: { id: 1 } }, tx);
  });

  var stopP = null;
  try {
    outbox.start();
    // First tick claims the row and enters the publisher, which then blocks on
    // the gate — inFlight is now a pending poll.
    await helpers.waitUntil(function () { return entered >= 1; }, {
      timeoutMs: 5000, label: "outbox worker: publisher entered (poll in-flight)",
    });
    // Let several more ticks fire while the publish is blocked; each must hit
    // the `if (stopping || inFlight) return` overlap guard and NOT re-enter the
    // publisher (no double-claim).
    await helpers.passiveObserve(120, "outbox worker: overlap guard holds while publish blocks");
    check("worker: overlap guard prevents re-entry while a publish is in-flight",
      entered === 1 && published.length === 0);

    // stop() while the poll is still in-flight: it must await the pending poll.
    stopP = outbox.stop();
    releaseGate();          // unblock the publisher so the in-flight poll finishes
    await stopP;            // stop() resolves only after the awaited poll completes
    check("worker: stop() awaited the in-flight poll to completion",
      published.length === 1 && published[0].topic === "slow");
  } finally {
    if (!stopP) { releaseGate(); await outbox.stop(); }
  }
}

async function run() {
  await testCreateValidation();
  await testEnqueueValidation();
  await testProcessPublish();
  await testRetryAndDeadLetter();
  await testMarkFailureDropSilent();
  await testMarkRetryFailureDropSilent();
  await testReaperFailureDropSilent();
  await testPostgresClaimPath();
  await testDeclareSchemaDialects();
  await testDeclareSchemaLegacyMigration();
  await testCorruptEmptyPayload();
  await testPublisherRejectsFalsy();
  await testDebeziumEnvelope();
  await testDebeziumDefaults();
  await testWorkerLifecycle();
  await testWorkerInFlightGuardAndStop();
  console.log("OK — outbox create/enqueue/publish/retry/dead-letter/debezium/lifecycle tests");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.stderr.write(String(err && err.stack || err) + "\n"); process.exit(1); });
}
