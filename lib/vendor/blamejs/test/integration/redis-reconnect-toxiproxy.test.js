"use strict";
/**
 * Live reconnect / failover proof for lib/redis-client.js against a REAL
 * redis dropped mid-connection via toxiproxy.
 *
 * The framework redis client points at toxiproxy's proxied redis
 * (127.0.0.1:16379, upstream redis:6379). A working connection is
 * established (SET/GET round-trips), then the proxy is DISABLED through
 * the toxiproxy HTTP API (127.0.0.1:8474) so redis appears DOWN — every
 * established connection is closed and new dials are refused. The test
 * asserts:
 *
 *   1. An in-flight command issued during the outage REJECTS (with a
 *      transport / timeout error code) rather than hanging the caller
 *      forever — no caller wedge.
 *   2. The client schedules a reconnect (the _state() reconnect machinery
 *      advances) — the lost socket drives the reconnect loop.
 *   3. No reconnect storm: one outage schedules at most ONE pending timer
 *      at a time (the single-flight guard) — a socket failure surfacing
 *      as BOTH `error` and `close` must not stack two reconnects and burn
 *      the budget at 2x.
 *   4. Re-enabling the proxy RECOVERS the client: it reconnects on its own
 *      and a subsequent SET/GET round-trips, with the backoff counter +
 *      give-up latch reset.
 *
 * Recovery is polled with helpers.waitUntil — no fixed sleep. Fault is
 * injected over the toxiproxy HTTP control plane, not by killing the real
 * redis (which other workflows may share); the upstream redis is never
 * touched.
 *
 * Run:
 *   node scripts/test-integration.js --skip-service-check redis-reconnect-toxiproxy
 */
var http = require("node:http");
var helpers  = require("../helpers");
var check    = helpers.check;
var services = require("../helpers/services");
var redisClient = require("../../lib/redis-client");

// toxiproxy control plane. The proxy named "redis" listens on :16379 and
// forwards to upstream redis:6379; flipping its `enabled` flag is the
// outage switch (disabled = existing conns closed + new dials refused).
var TOXIPROXY_API  = services.URLS.toxiproxy;   // http://127.0.0.1:8474
var PROXY_NAME     = "redis";
var PROXIED_REDIS  = services.URLS.toxiproxyRedis; // redis://127.0.0.1:16379

// Minimal toxiproxy HTTP client over node:http — POST a JSON body to the
// proxy endpoint to flip `enabled`. Returns the parsed proxy object.
function _toxiproxyRequest(method, urlPath, bodyObj) {
  return new Promise(function (resolve, reject) {
    var u = new URL(TOXIPROXY_API + urlPath);
    var payload = bodyObj === undefined ? null : Buffer.from(JSON.stringify(bodyObj), "utf8");
    var req = http.request({
      host:   u.hostname,
      port:   u.port,
      path:   u.pathname + (u.search || ""),
      method: method,
      headers: payload
        ? { "content-type": "application/json", "content-length": payload.length }
        : {},
    }, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        var raw = Buffer.concat(chunks).toString("utf8");
        if (res.statusCode < 200 || res.statusCode >= 300) {
          return reject(new Error("toxiproxy " + method + " " + urlPath +
            " -> HTTP " + res.statusCode + ": " + raw));
        }
        var parsed = null;
        try { parsed = raw ? JSON.parse(raw) : null; } catch (_e) { parsed = raw; }
        resolve(parsed);
      });
    });
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function _setProxyEnabled(enabled) {
  return _toxiproxyRequest("POST", "/proxies/" + PROXY_NAME, { enabled: !!enabled });
}

async function run() {
  // Probe both the proxied-redis port AND the toxiproxy control plane —
  // either being down means we can't run the fault-injection proof.
  var svcProxy = await services.requireService("toxiproxyRedis");
  var svcApi   = await services.requireService("toxiproxy");
  if (!svcProxy.ok || !svcApi.ok) {
    console.log("  [redis-reconnect] toxiproxy unreachable — skipping " +
      "(" + (svcProxy.ok ? "" : svcProxy.reason + " ") + (svcApi.ok ? "" : svcApi.reason) + ")");
    console.log("  [redis-reconnect]   bring up: docker compose -f docker-compose.test.yml up -d --wait");
    return;
  }

  // Always leave the proxy enabled when we exit, even on a mid-test
  // failure — a left-disabled proxy would poison every later redis test.
  var restored = false;
  async function _restoreProxy() {
    if (restored) return;
    restored = true;
    try { await _setProxyEnabled(true); } catch (_e) { /* best-effort */ }
  }

  var c = null;
  try {
    // Start from a known-good proxy state.
    await _setProxyEnabled(true);

    // Client through the proxy. A generous reconnect budget (the outage
    // window spans several backoff steps) + short connect/command timeouts
    // so an in-flight op against a dead proxy settles fast instead of
    // sitting on the full default. db 15 isolates test data.
    c = redisClient.create({
      url:                  PROXIED_REDIS + "/15",
      connectTimeoutMs:     1000,
      commandTimeoutMs:     1500,
      maxReconnectAttempts: 50,
    });

    // ---- 1. working connection ----
    await c.connect();
    check("connect: established through toxiproxy", c.isOpen());

    var key = "blamejs:test:reconnect:" + Date.now();
    var setRv = await c.command("SET", key, "before-outage");
    check("pre-outage SET: returns OK",
          setRv === "OK" || (Buffer.isBuffer(setRv) && setRv.toString() === "OK"));
    var getRv = await c.command("GET", key);
    check("pre-outage GET: round-trips",
          Buffer.isBuffer(getRv) && getRv.toString() === "before-outage");

    var stateBefore = c._state();
    check("pre-outage _state: connected, no reconnect pending, attempt 0",
          stateBefore.connected === true &&
          stateBefore.reconnectPending === false &&
          stateBefore.reconnect === 0);

    // ---- 2. outage: disable the proxy. Existing conns are closed; new
    //         dials are refused. This drives _teardownSocket → drain
    //         pending + schedule reconnect. ----
    await _setProxyEnabled(false);

    // An in-flight op issued DURING the outage must reject, not wedge.
    // Whether the socket-drop reaches the client before or after this
    // write, the command settles with an error (drained pending, write
    // failure, queued-timeout, or command-timeout) — never an unsettled
    // await. Bound the whole thing well under any hang with waitUntil so
    // a regression that DOES wedge fails the gate as a timeout instead of
    // hanging the suite.
    var inflightErr = null;
    var inflightResolved = false;
    var inflightSettled = false;
    c.command("GET", key).then(
      function ()  { inflightResolved = true; inflightSettled = true; },
      function (e) { inflightErr = e;        inflightSettled = true; }
    );
    await helpers.waitUntil(function () { return inflightSettled; }, {
      timeoutMs: 8000,
      label:     "redis-reconnect: in-flight op settles during outage (no caller wedge)",
    });
    check("in-flight op during outage SETTLES (no wedge)", inflightSettled === true);
    check("in-flight op during outage REJECTS with a transport/timeout error",
          inflightResolved === false &&
          inflightErr !== null && typeof inflightErr.code === "string");

    // ---- 3. the lost socket scheduled a reconnect. The client is now
    //         disconnected and the reconnect machinery is engaged
    //         (a timer pending and/or attempts advancing). ----
    var reconnecting = await helpers.waitUntil(function () {
      var s = c._state();
      // Engaged = no longer connected AND (a backoff timer is pending OR a
      // dial is mid-flight OR at least one attempt has been counted).
      if (s.connected) return false;
      return (s.reconnectPending || s.connecting || s.reconnect > 0) ? s : false;
    }, {
      timeoutMs: 8000,
      label:     "redis-reconnect: client schedules a reconnect after the socket drop",
    });
    check("outage: client is disconnected", reconnecting.connected === false);
    check("outage: a reconnect is engaged (pending timer / dialing / attempt counted)",
          reconnecting.reconnectPending === true ||
          reconnecting.connecting === true ||
          reconnecting.reconnect > 0);
    check("outage: did NOT give up (budget not exhausted mid-outage)",
          reconnecting.gaveUp === false);

    // ---- 4. no reconnect storm. Single-flight means: at any instant at
    //         most ONE backoff timer is pending, and the attempt counter
    //         advances monotonically by the dial cadence — it must not
    //         leap by 2 from a single socket failure surfacing as both
    //         `error` and `close`. The first retry backoff is 100ms, so
    //         sampling at 20ms (provably below the minimum inter-dial gap)
    //         means at most ONE dial can complete per sample window; a
    //         per-sample attempt delta of 2 would prove two reconnects
    //         fired for one window — a storm / double-schedule. We sample
    //         across ~2.4s, which spans the early small-backoff steps
    //         (100/200/400/800ms) where stacking would show first. ----
    var maxDelta = 0;
    var prevAttempt = c._state().reconnect;
    var sawNonBoolPending = false;    // (structurally a boolean — timer
                                      // !== null — but assert it: a count
                                      // here would mean stacked timers)
    for (var i = 0; i < 120; i++) {
      var s = c._state();
      var delta = s.reconnect - prevAttempt;
      if (delta > maxDelta) maxDelta = delta;
      prevAttempt = s.reconnect;
      if (s.reconnectPending !== true && s.reconnectPending !== false) sawNonBoolPending = true;
      await helpers.passiveObserve(20, "redis-reconnect storm-watch sample " + i);
    }
    check("no reconnect storm: attempts advance by <= 1 per 20ms sample (single-flight, no double-schedule)",
          maxDelta <= 1);
    check("no reconnect storm: reconnectPending is always a single boolean (one timer max)",
          sawNonBoolPending === false);

    // ---- 5. recovery: re-enable the proxy. The next scheduled dial
    //         succeeds and the client reconnects on its own. ----
    await _setProxyEnabled(true);

    // Poll a SYNCHRONOUS predicate (_state().connected) for the reconnect.
    // Awaiting c.command() inside the predicate would backlog the command
    // behind the client's reconnect timer — and that timer is unref'd by
    // design (a backoff window must not by itself keep the loop alive), so
    // with no other ref'd handle the loop could drain mid-await and the
    // process would exit before the reconnect fires. waitUntil's own 25ms
    // poll timer IS ref'd, so a sync predicate keeps the loop alive on each
    // tick and lets the unref'd reconnect timer fire — the same role a
    // real app's listening server socket plays in production.
    var recovered = await helpers.waitUntil(function () {
      return c._state().connected ? c._state() : false;
    }, {
      timeoutMs: 20000,
      label:     "redis-reconnect: client reconnects on its own after proxy re-enabled",
    });
    check("recovery: client reconnected after outage", recovered.connected === true);
    check("recovery: client reports open again", c.isOpen());

    // Now that the socket is back, a fresh SET/GET must round-trip.
    var setAfter = await c.command("SET", key, "after-recovery");
    check("recovery: post-reconnect SET returns OK",
          setAfter === "OK" || (Buffer.isBuffer(setAfter) && setAfter.toString() === "OK"));

    var getAfter = await c.command("GET", key);
    check("recovery: GET round-trips the post-recovery value",
          Buffer.isBuffer(getAfter) && getAfter.toString() === "after-recovery");

    var stateAfter = c._state();
    check("recovery: reconnect counter reset to 0 on successful reconnect",
          stateAfter.reconnect === 0);
    check("recovery: give-up latch cleared", stateAfter.gaveUp === false);
    check("recovery: no reconnect timer left pending", stateAfter.reconnectPending === false);

    // ---- 6. the recovered connection survives a SECOND independent
    //         outage — proves the reconnect path is reusable, not a
    //         one-shot, and the budget genuinely reset. ----
    await _setProxyEnabled(false);
    await helpers.waitUntil(function () {
      var s = c._state();
      return (!s.connected && (s.reconnectPending || s.connecting || s.reconnect > 0)) ? s : false;
    }, {
      timeoutMs: 8000,
      label:     "redis-reconnect: second outage re-engages the reconnect loop",
    });
    check("second outage: reconnect loop re-engaged (path is reusable)", !c._state().connected);

    await _setProxyEnabled(true);
    // Sync predicate again (see the phase-5 note on unref'd reconnect timers).
    await helpers.waitUntil(function () {
      return c._state().connected ? c._state() : false;
    }, {
      timeoutMs: 20000,
      label:     "redis-reconnect: second recovery — client reconnects again",
    });
    check("second recovery: client reconnected", c.isOpen());
    var getAfter2 = await c.command("GET", key);
    check("second recovery: GET round-trips the prior value (path is reusable)",
          Buffer.isBuffer(getAfter2) && getAfter2.toString() === "after-recovery");

    // ---- cleanup ----
    await c.command("DEL", key);
  } finally {
    await _restoreProxy();
    if (c) { try { await c.close(); } catch (_e) {} }
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    // No process.exit(0) on success: an immediate exit after console.log
    // can drop the buffered banner when stdout is a pipe (the integration
    // runner pipes it). close() + unref'd timers let the loop drain on its
    // own, so the line flushes. The failure path still hard-exits 1.
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
