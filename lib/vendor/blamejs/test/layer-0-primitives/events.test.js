"use strict";
/**
 * events — framework breach-detection signal bus.
 *
 * Run standalone: `node test/layer-0-primitives/events.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function testEventsSurface() {
  check("b.events namespace present",        typeof b.events === "object");
  check("b.events.on is a function",         typeof b.events.on === "function");
  check("b.events.off is a function",        typeof b.events.off === "function");
  check("b.events.once is a function",       typeof b.events.once === "function");
  check("b.events.emit is a function",       typeof b.events.emit === "function");
  check("b.events.listenerCount is a function", typeof b.events.listenerCount === "function");
  check("b.events.EVENTS is frozen object",  typeof b.events.EVENTS === "object" && Object.isFrozen(b.events.EVENTS));
  check("EVENTS.AUDIT_CHAIN_BREAK constant",      b.events.EVENTS.AUDIT_CHAIN_BREAK === "audit:chain-break");
  check("EVENTS.AUDIT_CHECKPOINT_BREAK constant", b.events.EVENTS.AUDIT_CHECKPOINT_BREAK === "audit:checkpoint-break");
  check("EVENTS.AUDIT_ROLLBACK_DETECTED constant", b.events.EVENTS.AUDIT_ROLLBACK_DETECTED === "audit:rollback-detected");
  check("EVENTS.NTP_DRIFT constant",         b.events.EVENTS.NTP_DRIFT === "audit:ntp-drift");
}

function testEventsListenerFires() {
  b.events._resetForTest();
  var got = null;
  b.events.on(b.events.EVENTS.AUDIT_CHAIN_BREAK, function (info) { got = info; });
  var hadListener = b.events.emit(b.events.EVENTS.AUDIT_CHAIN_BREAK, { table: "audit_log", reason: "test" });
  check("emit returns true when listener present",  hadListener === true);
  check("listener received the payload",            got && got.reason === "test");
}

function testEventsMultipleListeners() {
  b.events._resetForTest();
  var calls = 0;
  function l1() { calls++; }
  function l2() { calls++; }
  b.events.on(b.events.EVENTS.NTP_DRIFT, l1);
  b.events.on(b.events.EVENTS.NTP_DRIFT, l2);
  check("listenerCount tracks two listeners",       b.events.listenerCount(b.events.EVENTS.NTP_DRIFT) === 2);
  b.events.emit(b.events.EVENTS.NTP_DRIFT, { driftMs: 999 });
  check("both listeners fire",                      calls === 2);
}

function testEventsOffRemovesListener() {
  b.events._resetForTest();
  var calls = 0;
  function l() { calls++; }
  b.events.on(b.events.EVENTS.AUDIT_ROLLBACK_DETECTED, l);
  b.events.emit(b.events.EVENTS.AUDIT_ROLLBACK_DETECTED, {});
  b.events.off(b.events.EVENTS.AUDIT_ROLLBACK_DETECTED, l);
  b.events.emit(b.events.EVENTS.AUDIT_ROLLBACK_DETECTED, {});
  check("off() removes listener — second emit not received", calls === 1);
}

function testEventsOnceFiresOnceOnly() {
  b.events._resetForTest();
  var calls = 0;
  b.events.once(b.events.EVENTS.NTP_DRIFT, function () { calls++; });
  b.events.emit(b.events.EVENTS.NTP_DRIFT, {});
  b.events.emit(b.events.EVENTS.NTP_DRIFT, {});
  check("once() listener fires exactly once",       calls === 1);
}

function testEventsEmitSwallowsListenerThrows() {
  b.events._resetForTest();
  var secondCalled = false;
  b.events.on(b.events.EVENTS.AUDIT_CHAIN_BREAK, function () { throw new Error("boom"); });
  b.events.on(b.events.EVENTS.AUDIT_CHAIN_BREAK, function () { secondCalled = true; });
  // Should NOT throw — emit must be best-effort because callers fire it
  // immediately before process.exit on fail-fast paths.
  var threw = null;
  try { b.events.emit(b.events.EVENTS.AUDIT_CHAIN_BREAK, {}); } catch (e) { threw = e; }
  check("emit swallows per-listener throws",        threw === null);
  check("subsequent listener still fires after a thrower", secondCalled === true);
}

function testEventsEmitWithNoListenersIsNoop() {
  b.events._resetForTest();
  var hadListener = b.events.emit("audit:nonexistent", { x: 1 });
  check("emit with no listeners returns false",     hadListener === false);
}

async function run() {
  testEventsSurface();
  testEventsListenerFires();
  testEventsMultipleListeners();
  testEventsOffRemovesListener();
  testEventsOnceFiresOnceOnly();
  testEventsEmitSwallowsListenerThrows();
  testEventsEmitWithNoListenersIsNoop();
}

module.exports = { run: run };

// Standalone execution: node test/layer-0-primitives/events.test.js
if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
