"use strict";
// b.middleware.dpop must REQUIRE a replayStore. The store IS the jti-replay
// defense: without it a captured DPoP proof can be replayed indefinitely — the
// exact attack proof-of-possession exists to stop (RFC 9449 §11.1). The doc has
// always listed replayStore as "required", but create() read it optionally and
// mounted a gate that performed no replay check when it was omitted. Mounting
// must fail closed at config time, never silently disable the defense.

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function expectThrow(label, fn, codeNeedle) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label + " — throws at create()", threw !== null);
  if (threw && codeNeedle) {
    check(label + " — error names the replay store",
          String((threw.code || threw.message) || "").toLowerCase().indexOf(codeNeedle) !== -1);
  }
}

function run() {
  // 1. Omitting replayStore must throw at create() — no silent replay-off mount.
  expectThrow("dpop middleware without replayStore", function () {
    b.middleware.dpop({ getAccessToken: function () { return null; } });
  }, "replay");

  // 2. A replayStore lacking checkAndInsert must throw at create() (fail fast on
  //    config, not at the first request).
  expectThrow("dpop middleware with a malformed replayStore", function () {
    b.middleware.dpop({ replayStore: { notCheckAndInsert: true } });
  }, "replay");

  // 3. A valid replayStore mounts cleanly (control — proves the gate is not
  //    over-tightened into refusing legitimate config).
  var mounted = null;
  try {
    mounted = b.middleware.dpop({ replayStore: b.nonceStore.create({ backend: "memory" }) });
  } catch (e) { mounted = e; }
  check("dpop middleware with a valid replayStore mounts", typeof mounted === "function");

  process.stdout.write("OK — dpop middleware replayStore-required tests\n");
}

module.exports = { run: run };
if (require.main === module) {
  // run() is synchronous here — wrap in Promise.resolve().then so the standalone
  // CLI path works whether run is sync or async (a bare run().catch throws
  // "Cannot read properties of undefined" on a sync run that returns undefined).
  Promise.resolve().then(run).catch(function (e) {
    process.stderr.write((e && e.stack ? e.stack : String(e)) + "\n"); process.exit(1);
  });
}
