"use strict";
/**
 * b.network.tls.pinsetDriftMonitor — periodic check that emits
 * audit + observability events when the trust-store fingerprint
 * set drifts from the captured baseline.
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

async function run() {
  var threw;
  try { b.network.tls.pinsetDriftMonitor({}); } catch (e) { threw = e; }
  check("network.tls.pinsetDriftMonitor: missing intervalMs throws",
    threw && threw.code === "tls/bad-interval");

  b.network.tls.captureBaselineFingerprints();
  var monitor = b.network.tls.pinsetDriftMonitor({
    intervalMs: 60_000,
    audit: false,
  });
  check("network.tls.pinsetDriftMonitor: returns stop handle",
    monitor && typeof monitor.stop === "function");
  monitor.stop();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[tls-pinset-drift] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
