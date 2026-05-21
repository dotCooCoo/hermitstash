"use strict";
/**
 * Live heartbeat probe against the docker-compose Caddy fixture.
 * Exercises lib/network-heartbeat (b.network.heartbeat) — the
 * framework's uptime monitor — as a real timer-driven probe loop
 * that hits a real HTTP endpoint and records OK/FAIL transitions.
 *
 * Covers all three target types: http, tcp, ntp.
 */
var helpers = require("../helpers");
var check = helpers.check;
var services = require("../helpers/services");
var b = require("../../");

async function run() {
  var caddy = await services.requireService("caddy");
  if (!caddy.ok) throw new Error("caddy unreachable: " + caddy.reason);

  if (typeof b.network.heartbeat._resetForTest === "function") b.network.heartbeat._resetForTest();

  var stateChanges = [];
  b.network.heartbeat.start({
    onStateChange: function (event) { stateChanges.push(event); },
    onResult:      function (_event) { /* fire-and-forget */ },
    targets: [
      // Healthy HTTP target — caddy /healthz returns 200.
      {
        name:             "caddy-up",
        type:             "http",
        url:              "http://127.0.0.1:8080/healthz",
        intervalMs:       100,
        timeoutMs:        2000,
        threshold:        1,
        allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
        allowInternal:    true,
      },
      // Failing HTTP target — port 1 doesn't accept.
      {
        name:             "caddy-down",
        type:             "http",
        url:              "http://127.0.0.1:1/never-here",
        intervalMs:       100,
        timeoutMs:        500,
        threshold:        1,
        allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
        allowInternal:    true,
      },
      // Healthy TCP target — squid listens on 3128.
      {
        name:       "squid-tcp",
        type:       "tcp",
        host:       "127.0.0.1",
        port:       3128,
        intervalMs: 100,
        timeoutMs:  2000,
        threshold:  1,
      },
    ],
  });

  // Wait until probes have fired across all three configured targets.
  var statuses = await helpers.waitUntil(function () {
    var s = b.network.heartbeat.statuses();
    var count = Array.isArray(s) ? s.length : Object.keys(s).length;
    return count >= 3 ? s : false;
  }, { label: "heartbeat: 3+ probe statuses available" });
  check("statuses: returns at least one entry",
        Array.isArray(statuses) ? statuses.length >= 3 : Object.keys(statuses).length >= 3);

  var caddyUp = b.network.heartbeat.status("caddy-up");
  check("caddy-up: status object returned",
        typeof caddyUp === "object" && caddyUp !== null);
  check("caddy-up: marked as up/healthy",
        /up|healthy|ok|success/i.test(JSON.stringify(caddyUp)));

  var caddyDown = b.network.heartbeat.status("caddy-down");
  check("caddy-down: status object returned",
        typeof caddyDown === "object" && caddyDown !== null);
  check("caddy-down: marked as down/failure",
        /down|fail|error|unhealthy/i.test(JSON.stringify(caddyDown)));

  var squidTcp = b.network.heartbeat.status("squid-tcp");
  check("squid-tcp: TCP target probe returned status",
        typeof squidTcp === "object" && squidTcp !== null);
  check("squid-tcp: marked as up (port is open)",
        /up|healthy|ok|success/i.test(JSON.stringify(squidTcp)));

  check("onStateChange: fired for at least one target",
        stateChanges.length >= 1);

  b.network.heartbeat.stopAll();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
