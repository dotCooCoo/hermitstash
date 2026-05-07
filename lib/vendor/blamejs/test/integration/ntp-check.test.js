"use strict";
/**
 * Live SNTPv4 round-trip against the docker-compose chrony NTP fixture.
 *
 * Exercises lib/ntp-check.js querySingle / checkDrift / bootCheck against
 * a real NTP server that's syncing from public pools. Drift should be
 * tiny (sub-second) since the container's clock and the host's clock
 * both anchor to the same upstream sources within a few seconds.
 *
 * The fixture binds host port 12300 (privileged port 123 isn't allowed
 * to bind on Windows without admin), so tests pass `port: 12300` to
 * the framework.
 */
var helpers = require("../helpers");
var check = helpers.check;
var services = require("../helpers/services");
var b = require("../../");

async function run() {
  var svc = await services.requireService("ntp");
  if (!svc.ok) throw new Error("ntp unreachable: " + svc.reason);

  // ---- querySingle: raw SNTP query, expects a non-zero drift back ----
  var single = await b.ntpCheck.querySingle("127.0.0.1", { port: 12300, timeoutMs: 4000 });
  check("querySingle: returns server name",       single.server === "127.0.0.1");
  check("querySingle: returns finite drift ms",   typeof single.driftMs === "number" && isFinite(single.driftMs));
  check("querySingle: returns serverTimeMs",       typeof single.serverTimeMs === "number" &&
                                                   single.serverTimeMs > 1700000000000);
  check("querySingle: drift is sub-minute (server is in sync)",
        Math.abs(single.driftMs) < 60000);

  // ---- checkDrift: tries servers in order, returns first success ----
  var drift = await b.ntpCheck.checkDrift({
    servers: ["127.0.0.1"],
    port:     12300,
    timeoutMs: 4000,
  });
  check("checkDrift: returns drift object",  drift && typeof drift.driftMs === "number");
  check("checkDrift: drift is sub-minute",   Math.abs(drift.driftMs) < 60000);

  // ---- bootCheck: integrates with the framework's logging policy ----
  // Set thresholds tight to prove the policy logic works on real data.
  // 60 minute fatal so it never triggers on real drift; 5 minute warn.
  var boot = await b.ntpCheck.bootCheck({
    servers:       ["127.0.0.1"],
    port:          12300,
    timeoutMs:     4000,
    driftWarnMs:   60 * 60 * 1000,
    driftFatalMs:  60 * 60 * 1000,
  });
  check("bootCheck: ok=true on healthy NTP",   boot.ok === true);
  check("bootCheck: severity is info",          boot.severity === "info");
  check("bootCheck: server is the one we asked", boot.server === "127.0.0.1");
  check("bootCheck: message references drift",  /drift/.test(boot.message));

  // ---- IPv6 path — must work because the compose file dual-binds
  //      every host port onto [::1] and SNTPv4 is address-family agnostic.
  //      A failure here is a real coverage gap, not "expected drift".
  var v6 = await b.ntpCheck.querySingle("::1", { port: 12300, timeoutMs: 4000 });
  check("querySingle v6: returned an object",
        typeof v6 === "object" && v6 !== null);
  check("querySingle v6: drift is sub-minute (server in sync)",
        typeof v6.driftMs === "number" && Math.abs(v6.driftMs) < 60000);
  check("querySingle v6: serverTimeMs is realistic (post-2024)",
        typeof v6.serverTimeMs === "number" && v6.serverTimeMs > 1700000000000);

  // ---- bad host: must surface a clean error code, not a hang ----
  var badHost = await b.ntpCheck.querySingle("127.0.0.99", {
    port: 12300, timeoutMs: 1500,
  }).catch(function (e) { return { _err: e }; });
  check("querySingle: unreachable host throws ntp/timeout",
        badHost._err && badHost._err.code === "ntp/timeout");

  // ---- bad port: cleanly times out (no NTP server on this port) ----
  var badPort = await b.ntpCheck.querySingle("127.0.0.1", {
    port: 11999, timeoutMs: 1500,
  }).catch(function (e) { return { _err: e }; });
  check("querySingle: unbound port throws ntp/timeout",
        badPort._err && badPort._err.code === "ntp/timeout");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
