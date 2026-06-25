"use strict";
/**
 * b.webhook.verify — replay nonceStore is atomic, not check-then-set (#328).
 *
 * The Stripe-shape inbound verifier must consult its replay store via the
 * atomic { checkAndInsert(nonce, expireAt) → bool } contract — the SAME
 * contract b.nonceStore.create exposes and b.webhook.verifier already uses.
 * A non-atomic check-then-set ({ has, set }) races two concurrent
 * redeliveries of the same event: both observe "unseen", both proceed
 * (CWE-367 TOCTOU). These tests drive the real b.webhook.verify consumer
 * path with the framework's own b.nonceStore.create so the store drops in
 * with no adapter, and assert that of two byte-identical concurrent
 * deliveries exactly one is accepted.
 *
 * RED proof (old buggy non-atomic await-has → if-seen-throw → await-set):
 * two concurrent verifies of the same signature BOTH observe "unseen" and
 * BOTH resolve ok — "concurrent: exactly one accepted" would fail (2 ok,
 * 0 replay). The atomic checkAndInsert collapses that to 1 ok / 1 replay.
 *
 * Run standalone: `node test/layer-0-primitives/webhook-verify-nonce-atomic.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var STRIPE_ALG = "hmac-sha256-stripe";

// Build a valid Stripe-Signature header for (body, secret, ts) through the
// public round-trip companion — no dependence on another test file's helper.
function _header(body, secret, ts) {
  return b.webhook.sign({ alg: STRIPE_ALG, secret: secret, body: body, timestamp: ts });
}

// The framework's own replay store satisfies the verifier's contract with
// no adapter: a first delivery is accepted, a second (sequential) replay of
// the same signature is refused with the stable webhook/replay code.
async function testFrameworkStoreDropsIn() {
  var body   = '{"event":"checkout.completed","id":"evt_drop_in"}';
  var secret = "whsec_drop_in_secret";
  var ts     = Math.floor(Date.now() / 1000);
  var header = _header(body, secret, ts);
  var ns     = b.nonceStore.create({ backend: "memory" });

  var r1 = await b.webhook.verify({
    alg: STRIPE_ALG, secret: secret, header: header, body: body, nonceStore: ns,
  });
  check("framework store: first delivery accepted", r1.ok === true);
  check("framework store: scheme v1",               r1.scheme === "v1");
  check("framework store: timestamp echoed",        r1.timestamp === ts);

  var replayed = false;
  try {
    await b.webhook.verify({
      alg: STRIPE_ALG, secret: secret, header: header, body: body, nonceStore: ns,
    });
  } catch (e) {
    replayed = true;
    check("framework store: replay → webhook/replay", e.code === "webhook/replay");
  }
  check("framework store: sequential replay refused", replayed);

  if (ns.close) await ns.close();
}

// The core of #328: of two concurrent verifies of the SAME signature with a
// SHARED framework store, exactly one is accepted and the other is refused as
// a replay. A non-atomic check-then-set would let both through (the TOCTOU
// the atomic checkAndInsert closes).
async function testConcurrentExactlyOneAccepted() {
  var body   = '{"event":"invoice.paid","id":"evt_concurrent"}';
  var secret = "whsec_concurrent_secret";
  var ts     = Math.floor(Date.now() / 1000);
  var header = _header(body, secret, ts);
  var ns     = b.nonceStore.create({ backend: "memory" });

  var settled = await Promise.allSettled([
    b.webhook.verify({ alg: STRIPE_ALG, secret: secret, header: header, body: body, nonceStore: ns }),
    b.webhook.verify({ alg: STRIPE_ALG, secret: secret, header: header, body: body, nonceStore: ns }),
  ]);

  var accepted = settled.filter(function (s) {
    return s.status === "fulfilled" && s.value && s.value.ok === true;
  }).length;
  var replays = settled.filter(function (s) {
    return s.status === "rejected" && s.reason && s.reason.code === "webhook/replay";
  }).length;

  check("concurrent: exactly one accepted", accepted === 1);
  check("concurrent: exactly one replay",   replays === 1);

  if (ns.close) await ns.close();
}

// A higher-concurrency fan-out hardens the assertion: N byte-identical
// deliveries land at once and STILL exactly one is accepted — the atomic
// gate admits a single winner regardless of contention depth.
async function testConcurrentFanoutSingleWinner() {
  var body   = '{"event":"charge.refunded","id":"evt_fanout"}';
  var secret = "whsec_fanout_secret";
  var ts     = Math.floor(Date.now() / 1000);
  var header = _header(body, secret, ts);
  var ns     = b.nonceStore.create({ backend: "memory" });

  var N = 8;
  var calls = [];
  for (var i = 0; i < N; i += 1) {
    calls.push(b.webhook.verify({
      alg: STRIPE_ALG, secret: secret, header: header, body: body, nonceStore: ns,
    }));
  }
  var settled = await Promise.allSettled(calls);
  var accepted = settled.filter(function (s) {
    return s.status === "fulfilled" && s.value && s.value.ok === true;
  }).length;
  var replays = settled.filter(function (s) {
    return s.status === "rejected" && s.reason && s.reason.code === "webhook/replay";
  }).length;

  check("fanout: exactly one accepted of " + N,    accepted === 1);
  check("fanout: remaining N-1 refused as replay", replays === N - 1);

  if (ns.close) await ns.close();
}

// The contract migration: a store exposing only the legacy racy { has, set }
// shape (no checkAndInsert) is refused — the verifier fails closed on a
// store that cannot give it an atomic gate, rather than silently falling
// back to a check-then-set race.
async function testLegacyHasSetShapeRefused() {
  var body   = '{"event":"x","id":"evt_legacy"}';
  var secret = "whsec_legacy_shape";
  var ts     = Math.floor(Date.now() / 1000);
  var header = _header(body, secret, ts);
  var legacyStore = {
    has: function () { return Promise.resolve(false); },
    set: function () { return Promise.resolve(); },
  };

  var refused = false;
  try {
    await b.webhook.verify({
      alg: STRIPE_ALG, secret: secret, header: header, body: body, nonceStore: legacyStore,
    });
  } catch (e) {
    refused = true;
    check("legacy { has, set }: webhook/bad-nonce-store code", e.code === "webhook/bad-nonce-store");
  }
  check("legacy { has, set } store refused (no checkAndInsert)", refused);
}

async function run() {
  check("b.webhook.verify is a function",       typeof b.webhook.verify === "function");
  check("b.nonceStore.create is a function",    typeof b.nonceStore.create === "function");
  await testFrameworkStoreDropsIn();
  await testConcurrentExactlyOneAccepted();
  await testConcurrentFanoutSingleWinner();
  await testLegacyHasSetShapeRefused();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
