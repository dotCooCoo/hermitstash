// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * dbSchema.runInTransaction / runInTransactionAsync — the BEGIN / COMMIT /
 * ROLLBACK wrappers that seeders, migrations, and vault-rotate route through
 * instead of hand-rolling the transaction skeleton. A fake handle records the
 * exact statement sequence so the commit-on-success / rollback-on-failure
 * contract — and, for the async form, that COMMIT waits for the awaited body —
 * is asserted directly, without standing up a real SQLite database.
 */

var helpers = require("../helpers");
var check = helpers.check;
var dbSchema = require("../../lib/db-schema");

// A handle exposing exec() — the shape runSqlOnHandle drives. It records every
// statement; an optional failOn set makes a named statement (e.g. ROLLBACK)
// throw so the onRollbackFail path is exercisable.
function _fakeDb(failOn) {
  var calls = [];
  return {
    _calls: calls,
    exec: function (sql) {
      calls.push(sql);
      if (failOn && failOn[sql]) throw new Error("exec failed: " + sql);
    },
  };
}

function testSyncCommitAndRollback() {
  var okDb = _fakeDb();
  var ret = dbSchema.runInTransaction(okDb, function () {
    okDb.exec("WORK");
    return 42;
  });
  check("runInTransaction returns the fn result", ret === 42);
  check("runInTransaction sequence is BEGIN, WORK, COMMIT",
    okDb._calls.join(",") === "BEGIN,WORK,COMMIT");

  var failDb = _fakeDb();
  var threw = null;
  try {
    dbSchema.runInTransaction(failDb, function () { throw new Error("boom"); });
  } catch (e) { threw = e; }
  check("runInTransaction re-throws the body error", threw && threw.message === "boom");
  check("runInTransaction rolls back (BEGIN, ROLLBACK — no COMMIT)",
    failDb._calls.join(",") === "BEGIN,ROLLBACK");

  // lockMode appends to BEGIN.
  var lockDb = _fakeDb();
  dbSchema.runInTransaction(lockDb, function () {}, { lockMode: "IMMEDIATE" });
  check("runInTransaction honours opts.lockMode", lockDb._calls[0] === "BEGIN IMMEDIATE");
}

async function testAsyncCommitWaitsForBody() {
  var okDb = _fakeDb();
  var ret = await dbSchema.runInTransactionAsync(okDb, async function () {
    // Yield to the event loop, THEN record work — proves COMMIT waits for the
    // awaited body rather than firing synchronously after fn() returns a promise.
    await Promise.resolve();
    okDb.exec("ASYNC-WORK");
    return "done";
  });
  check("runInTransactionAsync returns the awaited result", ret === "done");
  check("runInTransactionAsync commits AFTER the awaited body (BEGIN, ASYNC-WORK, COMMIT)",
    okDb._calls.join(",") === "BEGIN,ASYNC-WORK,COMMIT");
}

async function testAsyncRollbackOnReject() {
  var failDb = _fakeDb();
  var threw = null;
  try {
    await dbSchema.runInTransactionAsync(failDb, async function () {
      await Promise.resolve();
      throw new Error("async-boom");
    });
  } catch (e) { threw = e; }
  check("runInTransactionAsync re-throws the rejected body error",
    threw && threw.message === "async-boom");
  check("runInTransactionAsync rolls back on async reject (BEGIN, ROLLBACK)",
    failDb._calls.join(",") === "BEGIN,ROLLBACK");

  // onRollbackFail fires when ROLLBACK itself throws, and the ORIGINAL error
  // still surfaces (the rollback failure must not mask the body failure).
  var rbFailDb = _fakeDb({ ROLLBACK: true });
  var sawRollbackFail = false;
  var origErr = null;
  try {
    await dbSchema.runInTransactionAsync(rbFailDb, async function () {
      throw new Error("primary");
    }, { onRollbackFail: function () { sawRollbackFail = true; } });
  } catch (e) { origErr = e; }
  check("onRollbackFail invoked when ROLLBACK throws", sawRollbackFail === true);
  check("original body error still surfaces despite rollback failure",
    origErr && origErr.message === "primary");
}

async function run() {
  testSyncCommitAndRollback();
  await testAsyncCommitWaitsForBody();
  await testAsyncRollbackOnReject();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
