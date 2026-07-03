// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.network.dns.resolver — per-query upstream timeout.
 *
 * A non-responsive / slow / stalling DoH endpoint (or a transport whose
 * lookup never resolves — the wire-level analogue of a server that sends
 * 200 headers then never ends the body) must not hold the await pending
 * forever. Every query() and every followCnames hop is bounded by the
 * create({ timeoutMs }) wall-clock deadline. RED on the pre-fix tree:
 * queryA() never settles and the test hangs until the harness kills it.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// A transport whose lookup never resolves — models a DoH endpoint that
// accepts the connection, sends headers, then stalls the body forever.
function _hangingTransport() {
  return {
    lookupCalls: 0,
    lookup: function () {
      this.lookupCalls += 1;
      return new Promise(function () { /* never settles */ });
    },
  };
}

// Bound a promise so a regressed (hanging) tree fails as a timeout instead of
// stalling the whole suite. Polls via helpers.waitUntil (not a fixed
// setTimeout sleep) for the promise to settle, then rethrows its rejection —
// a genuine hang surfaces as a waitUntil timeout rather than hanging forever.
function _within(promise, ms, label) {
  var state = { done: false, value: undefined, error: undefined };
  promise.then(
    function (v) { state.done = true; state.value = v; },
    function (e) { state.done = true; state.error = e; }
  );
  return helpers.waitUntil(function () { return state.done; }, { timeoutMs: ms, label: label })
    .then(function () { if (state.error) throw state.error; return state.value; });
}

async function testQueryTimesOutOnHangingTransport() {
  var transport = _hangingTransport();
  var r = b.network.dns.resolver.create({ transport: transport, timeoutMs: 80 });

  var threw = null;
  try {
    await _within(r.queryA("example.com"), 4000,
      "queryA against a hanging transport");
  } catch (e) {
    threw = e;
  }
  check("queryA rejects on a hanging transport (does not hang)", threw !== null);
  var msg = threw ? String(threw.message) : "";
  check("rejection is the resolver deadline, not the test backstop",
    /timed out/i.test(msg) && !/TEST-DEADLINE/.test(msg));
  check("transport.lookup was actually invoked", transport.lookupCalls === 1);
}

async function testFollowCnamesHopTimesOut() {
  // followCnames loops query() per hop; the first hop's transport stall
  // must bound the whole walk, not hang it.
  var transport = _hangingTransport();
  var r = b.network.dns.resolver.create({ transport: transport, timeoutMs: 80 });

  var threw = null;
  try {
    await _within(r.followCnames("alias.example.com", "A"), 4000,
      "followCnames against a hanging transport");
  } catch (e) {
    threw = e;
  }
  check("followCnames rejects when a hop's transport stalls", threw !== null);
  var msg2 = threw ? String(threw.message) : "";
  check("followCnames rejection is the resolver deadline",
    /timed out/i.test(msg2) && !/TEST-DEADLINE/.test(msg2));
}

async function testBadTimeoutRejectedAtCreate() {
  var cases = [0, -1, NaN, Infinity];
  for (var i = 0; i < cases.length; i += 1) {
    var threw = null;
    try {
      b.network.dns.resolver.create({ timeoutMs: cases[i] });
    } catch (e) {
      threw = e;
    }
    check("create rejects timeoutMs=" + cases[i],
      threw !== null && threw.code === "resolver/bad-input");
  }
}

async function testDefaultTimeoutAccepted() {
  // No timeoutMs supplied — create() must still build (uses the default)
  // and a fast fake transport resolves normally.
  var r = b.network.dns.resolver.create({
    transport: { lookup: function () { return Promise.reject(new Error("boom")); } },
  });
  var threw = null;
  try {
    await r.queryA("example.com");
  } catch (e) {
    threw = e;
  }
  // A transport error (not a timeout) surfaces as upstream-failed — proves
  // the default-timeout path doesn't swallow real fast failures.
  check("default timeout path surfaces fast transport errors",
    threw !== null && threw.code === "resolver/upstream-failed");
}

async function run() {
  await testQueryTimesOutOnHangingTransport();
  await testFollowCnamesHopTimesOut();
  await testBadTimeoutRejectedAtCreate();
  await testDefaultTimeoutAccepted();
}

module.exports = { run: run };

if (require.main === module) run().then(function () {
  process.stdout.write("PASS: network-dns-resolver-timeout\n");
}).catch(function (e) {
  process.stderr.write("FAIL: " + (e && e.stack || e) + "\n");
  process.exit(1);
});
