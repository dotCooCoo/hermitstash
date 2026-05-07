"use strict";
/**
 * observability — combined metrics + tracing tap.
 *
 * Run standalone: `node test/layer-0-primitives/observability.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b               = helpers.b;
var check           = helpers.check;
var makeFakeOtelApi = helpers.makeFakeOtelApi;

function _resetRegistries() {
  b.metrics._resetForTest();
  b.tracing._resetForTest();
}

function testObservabilitySurface() {
  check("b.observability is exposed",          typeof b.observability === "object");
  check("observability.tap is a function",     typeof b.observability.tap === "function");
  check("observability.event is a function",   typeof b.observability.event === "function");
}

function testObservabilityTapRunsFnWithoutRegistries() {
  _resetRegistries();
  var ran = false;
  var ret = b.observability.tap("smoke.test", { x: 1 }, function (span) {
    ran = true;
    return span;
  });
  check("tap: fn ran without registries",  ran === true);
  check("tap: span arg is null pass-through", ret === null);
}

function testObservabilityTapReturnsValue() {
  _resetRegistries();
  var v = b.observability.tap("smoke.test", function () { return 42; });
  check("tap: return value preserved (no attrs)", v === 42);
  var w = b.observability.tap("smoke.test", { k: "v" }, function () { return "ok"; });
  check("tap: return value preserved (with attrs)", w === "ok");
}

async function testObservabilityTapAsyncReturn() {
  _resetRegistries();
  var v = await b.observability.tap("smoke.test", function () {
    return Promise.resolve("async-ok");
  });
  check("tap: async return value preserved", v === "async-ok");
}

function testObservabilityTapMetricsFiresOnSuccess() {
  _resetRegistries();
  var m = b.metrics.create();
  b.observability.tap("audit.record",
    { action: "test.action", outcome: "success" },
    function () { return "ok"; });
  var auditCounter = m.metrics.get("framework_audit_events_total");
  check("tap: metrics fired on success path",
        auditCounter.get({ action: "test.action", outcome: "success" }) === 1);
  m.deactivate();
}

function testObservabilityTapMetricsFiresOnFailure() {
  _resetRegistries();
  var m = b.metrics.create();
  var threw = null;
  try {
    b.observability.tap("audit.record",
      { action: "test.action", outcome: "failure" },
      function () { throw new Error("boom"); });
  } catch (e) { threw = e; }
  check("tap: throw propagates after metrics fire", threw && threw.message === "boom");
  var auditCounter = m.metrics.get("framework_audit_events_total");
  check("tap: metrics fired on sync-throw failure path",
        auditCounter.get({ action: "test.action", outcome: "failure" }) === 1);
  m.deactivate();
}

async function testObservabilityTapMetricsFiresOnAsyncRejection() {
  _resetRegistries();
  var m = b.metrics.create();
  var threw = null;
  try {
    await b.observability.tap("audit.record",
      { action: "test.action", outcome: "failure" },
      function () { return Promise.reject(new Error("async-boom")); });
  } catch (e) { threw = e; }
  check("tap: rejection propagates after metrics fire",
        threw && threw.message === "async-boom");
  var auditCounter = m.metrics.get("framework_audit_events_total");
  check("tap: metrics fired on async-reject failure path",
        auditCounter.get({ action: "test.action", outcome: "failure" }) === 1);
  m.deactivate();
}

function testObservabilityTapTracingProducesSpan() {
  _resetRegistries();
  var fake = makeFakeOtelApi();
  b.tracing._setOtelForTest(fake);
  var t = b.tracing.create();
  b.observability.tap("smoke.span",
    { foo: "bar" },
    function () { return 1; });
  check("tap: tracing produced 1 span",          fake._spans.length === 1);
  check("tap: span name matches tap name",       fake._spans[0]._name === "smoke.span");
  check("tap: span attrs include passed attrs",  fake._spans[0]._attrs.foo === "bar");
  t.deactivate();
}

function testObservabilityEventRoutesIntoMetricsOnly() {
  _resetRegistries();
  var m = b.metrics.create();
  b.observability.event("queue.enqueue", 1, { queueName: "outbox" });
  var counter = m.metrics.get("framework_queue_enqueue_total");
  check("event: metrics counter incremented",
        counter.get({ queueName: "outbox" }) === 1);
  m.deactivate();
}

function testObservabilityEventNoOpWhenNoRegistry() {
  _resetRegistries();
  var threw = null;
  try { b.observability.event("anything", 1, { a: 1 }); }
  catch (e) { threw = e; }
  check("event: no-op without registry — no throw", threw === null);
}

function testObservabilityTapRejectsBadFn() {
  _resetRegistries();
  var threw = null;
  try { b.observability.tap("smoke", "not-a-function"); }
  catch (e) { threw = e; }
  check("tap: rejects non-function fn", threw && /must be a function/.test(threw.message));
}

function testObservabilityTapRejectsBadName() {
  _resetRegistries();
  var threwUndef = null;
  try { b.observability.tap(undefined, function () {}); }
  catch (e) { threwUndef = e; }
  check("tap: rejects undefined name (throws)",
        threwUndef instanceof TypeError && /name must be/.test(threwUndef.message));
  var threwEmpty = null;
  try { b.observability.tap("", function () {}); }
  catch (e) { threwEmpty = e; }
  check("tap: rejects empty-string name", threwEmpty instanceof TypeError);
  var threwNumeric = null;
  try { b.observability.tap(42, function () {}); }
  catch (e) { threwNumeric = e; }
  check("tap: rejects number name", threwNumeric instanceof TypeError);
}

function testObservabilityEventDropsBadName() {
  _resetRegistries();
  var m = b.metrics.create();
  var threw = null;
  try {
    b.observability.event(undefined, 1, { x: 1 });
    b.observability.event("", 1);
    b.observability.event(null);
  } catch (e) { threw = e; }
  check("event: silently drops malformed name", threw === null);
  m.deactivate();
}

async function run() {
  testObservabilitySurface();
  testObservabilityTapRunsFnWithoutRegistries();
  testObservabilityTapReturnsValue();
  await testObservabilityTapAsyncReturn();
  testObservabilityTapMetricsFiresOnSuccess();
  testObservabilityTapMetricsFiresOnFailure();
  await testObservabilityTapMetricsFiresOnAsyncRejection();
  testObservabilityTapTracingProducesSpan();
  testObservabilityEventRoutesIntoMetricsOnly();
  testObservabilityEventNoOpWhenNoRegistry();
  testObservabilityTapRejectsBadFn();
  testObservabilityTapRejectsBadName();
  testObservabilityEventDropsBadName();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("observability tests passed"); process.exit(0); },
    function (e) { console.error(e); process.exit(1); }
  );
}
