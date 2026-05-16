"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _fakeCursor(rows, batchSize) {
  var pos = 0;
  var closed = false;
  return {
    fetchBatch: async function (n) {
      var take = Math.min(n || batchSize, rows.length - pos);
      var batch = rows.slice(pos, pos + take);
      pos += take;
      return { rows: batch, done: pos >= rows.length };
    },
    close: async function () { closed = true; },
    lastSeenCursor: function () { return { pos: pos }; },
    _isClosed: function () { return closed; },
  };
}

function expectRejection(label, p, codeMatch) {
  return p.then(
    function () { check(label + " (did not reject)", false); },
    function (e) { check(label, (e && e.code || "").indexOf(codeMatch) !== -1); }
  );
}

function testSurface() {
  check("create is fn",      typeof b.agent.stream.create === "function");
  check("AgentStreamError",  typeof b.agent.stream.AgentStreamError === "function");
  check("guards.args",       b.agent.stream.guards.args === b.guardStreamArgs);
  var e = new b.agent.stream.AgentStreamError("agent-stream/test", "t");
  check("error carries code", e.code === "agent-stream/test");
}

async function testBasicIteration() {
  var cursor;
  var stream = b.agent.stream.create({
    openCursor: function () {
      cursor = _fakeCursor([{ id: 1 }, { id: 2 }, { id: 3 }], 10);
      return cursor;
    },
    batchSize: 10,
  });
  var collected = [];
  for await (var row of stream) collected.push(row);
  check("basic iteration: 3 rows",  collected.length === 3);
  check("basic iteration: order",    collected[0].id === 1 && collected[2].id === 3);
  check("basic iteration: cursor closed", cursor._isClosed() === true);
}

async function testMultipleBatches() {
  var fetchCount = 0;
  var rows = [];
  for (var i = 0; i < 25; i += 1) rows.push({ id: i });
  var stream = b.agent.stream.create({
    openCursor: function () {
      var c = _fakeCursor(rows, 10);
      var origFetch = c.fetchBatch;
      c.fetchBatch = async function (n) { fetchCount += 1; return origFetch(n); };
      return c;
    },
    batchSize: 10,
  });
  var collected = [];
  for await (var row of stream) collected.push(row);
  check("batches: 25 rows total",       collected.length === 25);
  check("batches: 3 fetch calls",        fetchCount === 3);
}

async function testConsumerBreakClosesCursor() {
  var cursor;
  var stream = b.agent.stream.create({
    openCursor: function () {
      cursor = _fakeCursor([{ id: 1 }, { id: 2 }, { id: 3 }, { id: 4 }, { id: 5 }], 10);
      return cursor;
    },
    batchSize: 10,
  });
  var count = 0;
  for await (var _row of stream) {
    count += 1;
    if (count === 2) break;        // early-break must close cursor
  }
  check("consumer break: cursor closed", cursor._isClosed() === true);
}

async function testConsumerThrowClosesCursor() {
  var cursor;
  var stream = b.agent.stream.create({
    openCursor: function () {
      cursor = _fakeCursor([{ id: 1 }, { id: 2 }, { id: 3 }], 10);
      return cursor;
    },
    batchSize: 10,
  });
  var threw = null;
  try {
    for await (var row of stream) {
      if (row.id === 2) throw new Error("test-abort");
    }
  } catch (e) { threw = e; }
  check("consumer throw: cursor closed",      cursor._isClosed() === true);
  check("consumer throw: error propagates",   threw && threw.message === "test-abort");
}

async function testDrainMarker() {
  var orch = b.agent.orchestrator.create({});
  var cursor;
  var stream = b.agent.stream.create({
    openCursor: function () {
      cursor = _fakeCursor([{ id: 1 }, { id: 2 }, { id: 3 }], 10);
      return cursor;
    },
    batchSize:    10,
    orchestrator: orch,
    actor:        { id: "u1" },
    kind:         "search",
  });
  // Drain BEFORE pulling — first iteration emits the drain marker.
  await orch.drain({});
  var collected = [];
  for await (var row of stream) collected.push(row);
  check("drain: drain marker emitted",
    collected.length === 1 && collected[0]._drainMarker === true && collected[0].reason === "drain");
  // lastSeenCursor is null when drain fires before any fetch (nothing
  // to resume from); object when drain fires mid-stream.
  check("drain: lastSeenCursor key present (null pre-fetch)",
    "lastSeenCursor" in collected[0] && collected[0].lastSeenCursor === null);
}

async function testStreamRegisteredWithOrchestrator() {
  var orch = b.agent.orchestrator.create({});
  var rows = [];
  for (var i = 0; i < 5; i += 1) rows.push({ id: i });
  var stream = b.agent.stream.create({
    openCursor:   function () { return _fakeCursor(rows, 2); },
    batchSize:    2,
    orchestrator: orch,
    actor:        { id: "u1" },
    kind:         "search",
  });
  // Start iteration; mid-stream check health for stream count.
  var iter = stream[Symbol.asyncIterator]();
  var first = await iter.next();
  check("registered: first row",          first.value.id === 0);
  var h = await orch.health();
  check("registered: orchestrator sees 1 open stream", h.streams === 1);
  // Drain the rest.
  while (!(await iter.next()).done) { /* noop */ }
  var h2 = await orch.health();
  check("registered: stream unregistered after exhaust", h2.streams === 0);
}

async function testRefusesBadCursor() {
  var stream = b.agent.stream.create({
    openCursor: function () { return { /* missing fetchBatch */ }; },
    batchSize:  10,
  });
  await expectRejection("refuses cursor without fetchBatch",
    (async function () {
      for await (var row of stream) { /* shouldn't get here */ }                                      // eslint-disable-line no-unused-vars
    })(),
    "agent-stream/bad-cursor");
}

async function testRefusesBadOpts() {
  var threw = null;
  try { b.agent.stream.create({}); } catch (e) { threw = e; }
  check("create refuses missing openCursor",
    threw && (threw.code || "").indexOf("agent-stream/bad-open-cursor") !== -1);

  var threw2 = null;
  try {
    b.agent.stream.create({ openCursor: function () {}, batchSize: 1.5 });
  } catch (e) { threw2 = e; }
  check("create refuses fractional batchSize",
    threw2 && (threw2.code || "").indexOf("stream-args/bad-batch-size") !== -1);
}

async function testBackpressure() {
  // Verify each `next()` call only pulls one batch's worth of rows
  // into memory at a time; the buffer drains BEFORE refetching.
  var fetchCount = 0;
  var stream = b.agent.stream.create({
    openCursor: function () {
      var rows = [];
      for (var i = 0; i < 6; i += 1) rows.push({ id: i });
      var c = _fakeCursor(rows, 3);
      var orig = c.fetchBatch;
      c.fetchBatch = async function (n) { fetchCount += 1; return orig(n); };
      return c;
    },
    batchSize: 3,
  });
  var iter = stream[Symbol.asyncIterator]();
  // First 3 rows from batch 1 — only 1 fetch so far.
  for (var i = 0; i < 3; i += 1) {
    var r = await iter.next();
    check("backpressure: row " + i, r.value.id === i);
  }
  check("backpressure: 1 fetch after 3 rows", fetchCount === 1);
  // Next row triggers batch 2 — 2 fetches now.
  await iter.next();
  check("backpressure: 2 fetches after 4th row", fetchCount === 2);
}

async function run() {
  testSurface();
  await testBasicIteration();
  await testMultipleBatches();
  await testConsumerBreakClosesCursor();
  await testConsumerThrowClosesCursor();
  await testDrainMarker();
  await testStreamRegisteredWithOrchestrator();
  await testRefusesBadCursor();
  await testRefusesBadOpts();
  await testBackpressure();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
