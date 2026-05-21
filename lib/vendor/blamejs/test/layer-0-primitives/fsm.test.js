"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _orderFactory() {
  return b.fsm.define({
    name:    "order",
    initial: "placed",
    states: {
      placed:    {},
      paid:      { onEnter: function (ctx) { ctx.paidAt = "T0"; } },
      shipped:   {},
      delivered: {},
      canceled:  {},
    },
    transitions: [
      { from: "placed",  to: "paid",      on: "pay" },
      { from: "paid",    to: "shipped",   on: "ship",
        guard: function (ctx) { return ctx.address != null; } },
      { from: "shipped", to: "delivered", on: "deliver" },
      { from: "placed",  to: "canceled",  on: "cancel" },
      { from: "paid",    to: "canceled",  on: "cancel" },
    ],
  });
}

function testSurface() {
  check("define is fn",         typeof b.fsm.define === "function");
  check("FsmError ctor",        typeof b.fsm.FsmError === "function");
  var f = _orderFactory();
  check("factory.create fn",    typeof f.create === "function");
  check("factory.restore fn",   typeof f.restore === "function");
  check("factory.name",         f.name === "order");
  check("factory frozen",       Object.isFrozen(f));
}

function testCreateInitialState() {
  var f = _orderFactory();
  var i = f.create({ initialContext: { address: "addr" } });
  check("initial state",        i.state === "placed");
  check("context carried",      i.context.address === "addr");
  check("history empty",        i.history.length === 0);
  check("allowed lists pay+cancel",
    i.allowed().indexOf("pay") !== -1 && i.allowed().indexOf("cancel") !== -1);
}

async function testHappyTransition() {
  var f = _orderFactory();
  var i = f.create({ initialContext: { address: "addr" } });
  var r = await i.transition("pay");
  check("transition return shape", r.from === "placed" && r.to === "paid" && r.on === "pay");
  check("state advanced",       i.state === "paid");
  check("history appended",     i.history.length === 1);
  check("history entry shape",
    i.history[0].from === "placed" && i.history[0].to === "paid" &&
    i.history[0].on === "pay" && typeof i.history[0].at === "number");
  check("onEnter side-effect ran", i.context.paidAt === "T0");
}

async function testIllegalTransitionFromWrongState() {
  var f = _orderFactory();
  var i = f.create({ initialContext: { address: "addr" } });
  var threw = null;
  try { await i.transition("ship"); } catch (e) { threw = e; }
  check("illegal transition throws", threw && threw.code === "fsm/illegal-transition");
  check("state unchanged after refusal", i.state === "placed");
  check("history empty after refusal",   i.history.length === 0);
}

async function testUnknownTransitionName() {
  var f = _orderFactory();
  var i = f.create({ initialContext: { address: "addr" } });
  var threw = null;
  try { await i.transition("teleport"); } catch (e) { threw = e; }
  check("unknown transition name throws", threw && threw.code === "fsm/illegal-transition");
}

async function testGuardRefusal() {
  var f = _orderFactory();
  // No address — `ship` guard returns false.
  var i = f.create({ initialContext: {} });
  await i.transition("pay");
  var threw = null;
  try { await i.transition("ship"); } catch (e) { threw = e; }
  check("guard refusal code",   threw && threw.code === "fsm/guard-refused");
  check("state still paid",     i.state === "paid");
  // Set address; now the guard passes.
  i.context.address = "addr";
  await i.transition("ship");
  check("guard pass after fix", i.state === "shipped");
}

async function testGuardThrow() {
  var f = b.fsm.define({
    name: "guardthrow", initial: "a",
    states: { a: {}, b: {} },
    transitions: [
      { from: "a", to: "b", on: "go",
        guard: function () { throw new Error("guard boom"); } },
    ],
  });
  var i = f.create();
  var threw = null;
  try { await i.transition("go"); } catch (e) { threw = e; }
  check("guard-threw code",     threw && threw.code === "fsm/guard-threw");
}

async function testOnExitBeforeOnEnter() {
  var order = [];
  var f = b.fsm.define({
    name: "exitenter", initial: "a",
    states: {
      a: { onExit:  function () { order.push("exit-a"); } },
      b: { onEnter: function () { order.push("enter-b"); } },
    },
    transitions: [{ from: "a", to: "b", on: "go" }],
  });
  var i = f.create();
  await i.transition("go");
  check("onExit before onEnter",
    order.length === 2 && order[0] === "exit-a" && order[1] === "enter-b");
}

async function testAsyncOnEnterAwaited() {
  // Verify that a Promise-returning onEnter is awaited before
  // .transition() resolves. The onEnter resolves on the microtask
  // queue (no setTimeout) — the question is whether the primitive
  // awaits the returned promise, not whether wall-clock time passes.
  var landed = false;
  var resolveOnEnter;
  var enterPromise = new Promise(function (resolve) { resolveOnEnter = resolve; });
  var f = b.fsm.define({
    name: "asyncenter", initial: "a",
    states: {
      a: {},
      b: { onEnter: function () {
        return enterPromise.then(function () { landed = true; });
      } },
    },
    transitions: [{ from: "a", to: "b", on: "go" }],
  });
  var i = f.create();
  var transitionPromise = i.transition("go");
  // landed is false until we resolve enterPromise — proves the
  // transition is awaiting the onEnter result.
  check("async onEnter pending before resolve", landed === false);
  resolveOnEnter();
  await transitionPromise;
  check("async onEnter awaited", landed === true);
}

function testAllowedFromCurrent() {
  var f = _orderFactory();
  var i = f.create({ initialContext: { address: "addr" } });
  var fromPlaced = i.allowed();
  check("allowed from placed: pay+cancel",
    fromPlaced.length === 2 &&
    fromPlaced.indexOf("pay") !== -1 &&
    fromPlaced.indexOf("cancel") !== -1);
}

async function testCanConsidersGuard() {
  var f = _orderFactory();
  var iNoAddr = f.create({ initialContext: {} });
  await iNoAddr.transition("pay");
  // From paid we have ship (guarded, will refuse — no address) + cancel.
  check("can(ship) false without address", iNoAddr.can("ship") === false);
  check("can(cancel) true",                iNoAddr.can("cancel") === true);
  iNoAddr.context.address = "addr";
  check("can(ship) true with address",     iNoAddr.can("ship") === true);
  check("can(unknown) false",              iNoAddr.can("teleport") === false);
}

async function testToJsonRestoreRoundtrip() {
  var f = _orderFactory();
  var i = f.create({ initialContext: { address: "addr" } });
  await i.transition("pay");
  await i.transition("ship");
  var snap = i.toJSON();
  check("snapshot state",   snap.state === "shipped");
  check("snapshot history", snap.history.length === 2);
  check("snapshot context", snap.context.address === "addr" && snap.context.paidAt === "T0");
  var restored = f.restore(snap);
  check("restore state",    restored.state === "shipped");
  check("restore history",  restored.history.length === 2);
  check("restore context",  restored.context.address === "addr");
  // Restored instance is fully live — can continue transitioning.
  await restored.transition("deliver");
  check("restored advances", restored.state === "delivered");
  check("restored history grew", restored.history.length === 3);
  // Snapshot history is decoupled from the restored instance's
  // history (slice() copy at toJSON + at restore time).
  check("original snap history unchanged", snap.history.length === 2);
}

async function testConcurrentTransitionsSerialize() {
  // Five concurrent transitions; the FIRST valid one wins, the rest
  // either fire later (when state-machine permits) or are refused.
  // The lock guarantees ordering; no two onEnter callbacks interleave.
  var enterOrder = [];
  var f = b.fsm.define({
    name: "concurrent", initial: "s1",
    states: {
      s1: {},
      s2: { onEnter: function () { enterOrder.push("s2"); } },
      s3: { onEnter: function () { enterOrder.push("s3"); } },
    },
    transitions: [
      { from: "s1", to: "s2", on: "to2" },
      { from: "s2", to: "s3", on: "to3" },
    ],
  });
  var i = f.create();
  // Fire 5 concurrent transitions. The lock guarantees serial
  // execution; each transition sees the state the prior one left.
  //   p1 to2: s1→s2 (valid)
  //   p2 to3: s2→s3 (valid — runs after p1 commits)
  //   p3 to3: s3→? — illegal from s3 (will throw)
  //   p4 to2: s3→? — illegal from s3 (will throw)
  //   p5 to3: s3→? — illegal (will throw)
  var p1 = i.transition("to2");
  var p2 = i.transition("to3");
  var p3 = i.transition("to3");
  var p4 = i.transition("to2");
  var p5 = i.transition("to3");
  var results = await Promise.allSettled([p1, p2, p3, p4, p5]);
  check("concurrent: p1 fulfilled", results[0].status === "fulfilled");
  check("concurrent: p2 fulfilled", results[1].status === "fulfilled");
  check("concurrent: p3 rejected",  results[2].status === "rejected");
  check("concurrent: p4 rejected",  results[3].status === "rejected");
  check("concurrent: p5 rejected",  results[4].status === "rejected");
  check("concurrent: final state s3", i.state === "s3");
  // onEnter side-effects ran in order — no interleave.
  check("concurrent: enter order preserved",
    enterOrder.length === 2 && enterOrder[0] === "s2" && enterOrder[1] === "s3");
  check("concurrent: only 2 transitions in history", i.history.length === 2);
}

async function testAuditEmission() {
  // We can't easily mock the real lazy-required audit module from
  // here, but audit.safeEmit IS drop-silent by design and the lib's
  // emit is wrapped in its own try/catch. The behavioral contract
  // worth pinning: a transition completes successfully even when
  // the audit chain is in a broken state, AND the history entry
  // contains the actor/metadata from opts.
  var f = _orderFactory();
  var i = f.create({ initialContext: { address: "addr" } });
  await i.transition("pay", { actor: "user-42", metadata: { reason: "card-charged" } });
  check("history actor recorded",    i.history[0].actor === "user-42");
  check("history metadata recorded", i.history[0].metadata.reason === "card-charged");
  // Audit-sink failures are isolated — even if no audit handler is
  // active, the transition still returns its result.
  check("transition succeeded under best-effort audit", i.state === "paid");
}

function testDefineBadStateName() {
  var threw = null;
  try {
    b.fsm.define({
      name: "bad", initial: "ok",
      states: { ok: {}, "DROP TABLE users": {} },
      transitions: [{ from: "ok", to: "ok", on: "noop" }],
    });
  } catch (e) { threw = e; }
  check("bad state name refused", threw && threw.code === "fsm/bad-name");
}

function testDefineBadTransitionName() {
  var threw = null;
  try {
    b.fsm.define({
      name: "bad2", initial: "a",
      states: { a: {}, b: {} },
      transitions: [{ from: "a", to: "b", on: "go;DROP" }],
    });
  } catch (e) { threw = e; }
  check("bad transition name refused", threw && threw.code === "fsm/bad-name");
}

function testDefineMissingInitial() {
  var threw = null;
  try {
    b.fsm.define({
      name: "missinginit",
      states: { a: {}, b: {} },
      transitions: [{ from: "a", to: "b", on: "go" }],
    });
  } catch (e) { threw = e; }
  check("missing initial refused", threw && threw.code === "fsm/bad-input");
}

function testDefineInitialNotInStates() {
  var threw = null;
  try {
    b.fsm.define({
      name: "stray", initial: "ghost",
      states: { a: {} },
      transitions: [{ from: "a", to: "a", on: "noop" }],
    });
  } catch (e) { threw = e; }
  check("initial-not-in-states refused", threw && threw.code === "fsm/bad-input");
}

function testDefineTransitionUnknownState() {
  var threw = null;
  try {
    b.fsm.define({
      name: "stray2", initial: "a",
      states: { a: {} },
      transitions: [{ from: "a", to: "ghost", on: "noop" }],
    });
  } catch (e) { threw = e; }
  check("transition-to-unknown refused", threw && threw.code === "fsm/bad-input");
}

function testDefineDuplicateFromOnPair() {
  var threw = null;
  try {
    b.fsm.define({
      name: "dup", initial: "a",
      states: { a: {}, b: {}, c: {} },
      transitions: [
        { from: "a", to: "b", on: "go" },
        { from: "a", to: "c", on: "go" },
      ],
    });
  } catch (e) { threw = e; }
  check("duplicate (from,on) refused", threw && threw.code === "fsm/bad-input");
}

function testDefineBadDefinition() {
  var threw = null;
  try { b.fsm.define(null); } catch (e) { threw = e; }
  check("null definition refused", threw && threw.code === "fsm/bad-input");
}

function testRestoreBadSnapshot() {
  var f = _orderFactory();
  var threw = null;
  try { f.restore({ state: "ghost" }); } catch (e) { threw = e; }
  check("restore unknown-state refused", threw && threw.code === "fsm/bad-input");
}

async function run() {
  testSurface();
  testCreateInitialState();
  await testHappyTransition();
  await testIllegalTransitionFromWrongState();
  await testUnknownTransitionName();
  await testGuardRefusal();
  await testGuardThrow();
  await testOnExitBeforeOnEnter();
  await testAsyncOnEnterAwaited();
  testAllowedFromCurrent();
  await testCanConsidersGuard();
  await testToJsonRestoreRoundtrip();
  await testConcurrentTransitionsSerialize();
  await testAuditEmission();
  testDefineBadStateName();
  testDefineBadTransitionName();
  testDefineMissingInitial();
  testDefineInitialNotInStates();
  testDefineTransitionUnknownState();
  testDefineDuplicateFromOnPair();
  testDefineBadDefinition();
  testRestoreBadSnapshot();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
