// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * network-dns: every lookup has an effective wall-clock deadline out of
 * the box, and a stalled upstream tears the socket down.
 *
 * Regression guard for the CWE-400 class: `lookupTimeoutMs` defaulted to
 * 0 (no deadline) and `_withTimeout` was a no-op at 0, so a
 * header-then-stall / accept-then-never-reply upstream hung the request
 * forever. The raw transport sockets also had no req.setTimeout /
 * socket.setTimeout, so even a rejected promise leaked the fd.
 *
 * Drives the real `b.network.dns.resolve(host, "SVCB", {transport:
 * "system"})` consumer path against a TCP black-hole responder — the
 * same raw-query code path (`_systemRawQuery`) an operator runs — and
 * confirms a stalled upstream is torn down within the deadline rather
 * than hanging forever.
 */

var net = require("node:net");

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

var C = require("../../lib/constants");

var dnsModule = b.network.dns;

// A TCP server that accepts the connection but never sends a reply (and
// never closes) — models a stalled upstream resolver. Returns the live
// sockets it accepted so the test can assert teardown.
function _startBlackHoleResponder() {
  return new Promise(function (resolve) {
    var accepted = [];
    var srv = net.createServer(function (sock) {
      accepted.push(sock);
      // Swallow the query; deliberately never reply, never end.
      sock.on("data", function () { /* black hole */ });
      sock.on("error", function () { /* fixture best-effort */ });
    });
    srv.unref();
    srv.listen(0, "127.0.0.1", function () {
      resolve({ srv: srv, port: srv.address().port, accepted: accepted });
    });
  });
}

async function _throwsAsync(fn, expectedCodeSubstr) {
  try { await fn(); return false; }
  catch (e) {
    if (!expectedCodeSubstr) return true;
    var hay = (e.code || "") + " " + (e.message || "");
    return hay.indexOf(expectedCodeSubstr) !== -1;
  }
}

async function run() {
  dnsModule._resetForTest();

  // ----------------------------------------------------------------
  // The default deadline is applied (not 0 = no-timeout).
  // ----------------------------------------------------------------
  check("default lookupTimeoutMs is a non-zero wall-clock deadline (10s)",
    dnsModule._stateForTest().lookupTimeoutMs === C.TIME.seconds(10));

  // ----------------------------------------------------------------
  // A stalled upstream tears the socket down within the deadline AND
  // rejects the consumer call — without any operator setLookupTimeoutMs.
  // We shorten the deadline to keep the test fast; the *mechanism* under
  // test (setTimeout teardown + non-zero default _withTimeout) is the
  // same one the 10s default arms. On the buggy tree this hangs forever.
  // ----------------------------------------------------------------
  var hole = await _startBlackHoleResponder();
  dnsModule.useSystemResolver();
  dnsModule.setServers(["127.0.0.1:" + hole.port]);
  dnsModule.setLookupTimeoutMs(500);

  var rejected = await _throwsAsync(function () {
    return dnsModule.resolve("stall.example.com", "SVCB", { transport: "system" });
  }, "dns/lookup-timeout");
  check("resolve(...,'SVCB',system) against a black-hole upstream rejects with dns/lookup-timeout (does not hang)",
    rejected);

  // The accepted socket(s) must be destroyed — the deadline teardown,
  // not just a promise-level reject leaving the fd alive.
  await helpers.waitUntil(function () {
    return hole.accepted.length > 0 &&
      hole.accepted.every(function (s) { return s.destroyed; });
  }, {
    timeoutMs: 5000,
    label:     "network-dns timeout: stalled upstream socket torn down",
  });
  check("stalled upstream socket is torn down (fd not leaked)",
    hole.accepted.length > 0 && hole.accepted.every(function (s) { return s.destroyed; }));

  hole.srv.close();
  dnsModule._resetForTest();

  // ----------------------------------------------------------------
  // Operator opt-out (0) still disables the deadline — the override path
  // survives the default change.
  // ----------------------------------------------------------------
  dnsModule.setLookupTimeoutMs(0);
  check("operator can disable the deadline (lookupTimeoutMs = 0)",
    dnsModule._stateForTest().lookupTimeoutMs === 0);
  dnsModule._resetForTest();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[network-dns-lookup-timeout-default] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error(e && e.stack || e); process.exit(1); }
  );
}
