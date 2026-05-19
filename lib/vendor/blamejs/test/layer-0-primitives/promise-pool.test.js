"use strict";
/**
 * b.promisePool — bounded-concurrency promise pool.
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

function _sleep(ms) {
  return new Promise(function (r) { setTimeout(r, ms); });
}

async function testRunsConcurrent() {
  var pool = b.promisePool.create({ concurrency: 3 });
  var observed = 0;
  var peak = 0;
  var tasks = [];
  for (var i = 0; i < 12; i += 1) {
    tasks.push(pool.run(async function () {
      observed += 1;
      if (observed > peak) peak = observed;
      await _sleep(20);
      observed -= 1;
      return 1;
    }));
  }
  var results = await Promise.all(tasks);
  check("all 12 tasks completed",         results.length === 12);
  check("results all === 1",              results.every(function (v) { return v === 1; }));
  check("peak in-flight bounded by concurrency", peak <= 3);
  await pool.drain({ close: true });
  check("pool closed",                    pool.closed() === true);
}

async function testDrainWaitsForInFlight() {
  var pool = b.promisePool.create({ concurrency: 2 });
  var resolved = 0;
  for (var i = 0; i < 5; i += 1) {
    pool.run(async function () { await _sleep(15); resolved += 1; });
  }
  await pool.drain();
  check("drain waits for everything", resolved === 5);
}

async function testEnqueueOnClosedThrows() {
  var pool = b.promisePool.create({ concurrency: 1 });
  await pool.drain({ close: true });
  var threw = false;
  try { await pool.run(async function () { return 1; }); }
  catch (_e) { threw = true; }
  check("closed pool refuses enqueue", threw);
}

async function testQueueLimitRefuses() {
  var pool = b.promisePool.create({ concurrency: 1, queueLimit: 2 });
  pool.run(async function () { await _sleep(40); return 1; });
  pool.run(async function () { return 1; });
  pool.run(async function () { return 1; });
  var threw = false;
  try { pool.run(async function () { return 1; }); }
  catch (_e) { threw = true; }
  check("queueLimit refuses 4th enqueue", threw);
  await pool.drain({ close: true });
}

function testConcurrencyValidation() {
  var threw;
  threw = false; try { b.promisePool.create({ concurrency: 0 }); } catch (_e) { threw = true; }
  check("concurrency=0 throws", threw);

  threw = false; try { b.promisePool.create({ concurrency: 1.5 }); } catch (_e) { threw = true; }
  check("concurrency=1.5 throws", threw);

  threw = false; try { b.promisePool.create({ concurrency: 100000 }); } catch (_e) { threw = true; }
  check("concurrency>65536 throws", threw);

  // PromisePoolError class is reachable as a typed error.
  check("PromisePoolError exported", typeof b.promisePool.PromisePoolError === "function");
}

async function run() {
  await testRunsConcurrent();
  await testDrainWaitsForInFlight();
  await testEnqueueOnClosedThrows();
  await testQueueLimitRefuses();
  testConcurrencyValidation();
}

if (require.main === module) run().catch(function (e) { console.error(e); process.exit(1); });
module.exports = { run: run };
