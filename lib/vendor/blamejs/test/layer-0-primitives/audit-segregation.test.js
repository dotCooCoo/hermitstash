"use strict";
/**
 * b.audit.bindActor / generateActorBindingTriggerSql / assertSegregation —
 * SOX §404 + SOC 2 CC1.3 segregation-of-duties primitives.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("audit.bindActor is a function",
        typeof b.audit.bindActor === "function");
  check("audit.assertSegregation is a function",
        typeof b.audit.assertSegregation === "function");
  check("audit.generateActorBindingTriggerSql is a function",
        typeof b.audit.generateActorBindingTriggerSql === "function");
  check("frameworkError.AuditSegregationError exposed",
        typeof b.frameworkError.AuditSegregationError === "function");
}

function testTriggerSqlShape() {
  var sql = b.audit.generateActorBindingTriggerSql();
  check("up SQL contains CREATE OR REPLACE FUNCTION",
        sql.up.indexOf("CREATE OR REPLACE FUNCTION") !== -1);
  check("up SQL contains BEFORE INSERT",
        sql.up.indexOf("BEFORE INSERT") !== -1);
  check("up SQL contains current_user check",
        sql.up.indexOf("current_user") !== -1);
  check("down SQL drops trigger + function",
        sql.down.indexOf("DROP TRIGGER") !== -1 &&
        sql.down.indexOf("DROP FUNCTION") !== -1);
  check("functionName + triggerName returned",
        typeof sql.functionName === "string" && typeof sql.triggerName === "string");
}

function testTriggerSqlAllowList() {
  var sql = b.audit.generateActorBindingTriggerSql({
    allowRoles: ["blamejs_service", "migration_runner"],
  });
  check("allowRoles included in up SQL",
        sql.up.indexOf("'blamejs_service'") !== -1 &&
        sql.up.indexOf("'migration_runner'") !== -1);
}

function testBindActorMissing() {
  var threw = null;
  try { b.audit.bindActor(""); } catch (e) { threw = e; }
  check("bindActor: empty actorId throws",
        threw && /bind-actor-missing/.test(threw.code || ""));
}

function testBindActorRecordMismatch() {
  var bound = b.audit.bindActor("alice");
  var threw = null;
  bound.record({
    action: "audit.read",
    outcome: "success",
    actor: { userId: "bob" },
  }).catch(function (e) { threw = e; });
  // record() returns a promise that should reject async; for synchronous
  // assertion just check that a record call with no actor mismatches:
  return new Promise(function (resolve) {
    setTimeout(function () {
      check("bound.record refuses mismatched actor",
            threw && /actor-binding-violation/.test(threw.code || ""));
      resolve();
    }, 20);
  });
}

function testAssertSegregationMissingDb() {
  var threw = null;
  b.audit.assertSegregation({}).catch(function (e) { threw = e; });
  return new Promise(function (resolve) {
    setTimeout(function () {
      check("assertSegregation without db throws",
            threw && /segregation-no-db/.test(threw.code || ""));
      resolve();
    }, 10);
  });
}

async function testAssertSegregationMissingTrigger() {
  var fakeDb = {
    query: async function () { return { rows: [] }; },
  };
  var threw = null;
  try { await b.audit.assertSegregation({ db: fakeDb }); } catch (e) { threw = e; }
  check("assertSegregation refuses when trigger absent",
        threw && /segregation-not-installed/.test(threw.code || ""));
}

async function testAssertSegregationOk() {
  var fakeDb = {
    query: async function () { return { rows: [{ ok: 1 }] }; },
  };
  var rv = await b.audit.assertSegregation({ db: fakeDb });
  check("assertSegregation returns ok=true when trigger present",
        rv && rv.ok === true);
}

async function run() {
  testSurface();
  testTriggerSqlShape();
  testTriggerSqlAllowList();
  testBindActorMissing();
  await testBindActorRecordMismatch();
  await testAssertSegregationMissingDb();
  await testAssertSegregationMissingTrigger();
  await testAssertSegregationOk();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
