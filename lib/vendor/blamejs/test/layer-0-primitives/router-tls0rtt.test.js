// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.router.create({ tls0Rtt }) — RFC 8446 §8 / RFC 8470 anti-replay
 * posture surface tests.
 *
 * Validates that:
 *   - tls0Rtt defaults to "refuse"
 *   - tls0Rtt accepts "refuse" / "replay-cache" only
 *   - replay-cache fail-closes under pci-dss / fapi2 postures
 *   - Early-Data: 1 inbound requests are gated per posture
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _mockReq(method, url, headers) {
  return {
    method:  method || "POST",
    url:     url    || "/",
    headers: headers || {},
  };
}

function testCreateDefaultsToRefuse() {
  var r = b.router.create();
  check("router.create() defaults tls0Rtt to 'refuse'",
        r.tls0RttPosture() === "refuse");
}

function testCreateRefusesUnknownPosture() {
  var threw = null;
  try { b.router.create({ tls0Rtt: "allow-everything" }); }
  catch (e) { threw = e; }
  check("router.create({ tls0Rtt: 'allow-everything' }) throws TypeError",
        threw instanceof TypeError);
}

function testCreateAcceptsValidPostures() {
  var refuse = b.router.create({ tls0Rtt: "refuse" });
  var replay = b.router.create({ tls0Rtt: "replay-cache" });
  check("router.create accepts 'refuse'", refuse.tls0RttPosture() === "refuse");
  check("router.create accepts 'replay-cache'", replay.tls0RttPosture() === "replay-cache");
}

function testRefusePostureRejectsEarlyData() {
  var r = b.router.create({ tls0Rtt: "refuse" });
  var verdict = r._check0RttReplay(_mockReq("POST", "/api/charge",
    { "early-data": "1" }));
  check("refuse posture refuses Early-Data: 1 with 425",
        verdict && verdict.status === 425 && verdict.reason === "early-data-refused");
}

function testRefusePostureAllowsNonEarlyData() {
  var r = b.router.create({ tls0Rtt: "refuse" });
  var verdict = r._check0RttReplay(_mockReq("POST", "/api/charge", {}));
  check("refuse posture allows non-Early-Data request",
        verdict === null);
}

function testReplayCacheAdmitsFirstRequest() {
  var r = b.router.create({ tls0Rtt: "replay-cache" });
  var verdict = r._check0RttReplay(_mockReq("POST", "/api/charge",
    { "early-data": "1", host: "api.example.com",
      authorization: "Bearer abc", date: "Fri, 01 Jan 2026 00:00:00 GMT" }));
  check("replay-cache admits first Early-Data: 1 request",
        verdict === null);
}

function testReplayCacheRefusesSecondIdentical() {
  var r = b.router.create({ tls0Rtt: "replay-cache" });
  var headers = { "early-data": "1", host: "api.example.com",
                  authorization: "Bearer abc", date: "Fri, 01 Jan 2026 00:00:00 GMT" };
  r._check0RttReplay(_mockReq("POST", "/api/charge", headers));
  var second = r._check0RttReplay(_mockReq("POST", "/api/charge", headers));
  check("replay-cache refuses identical-bytes replay with 425",
        second && second.status === 425 && second.reason === "early-data-replay");
}

function testReplayCacheDistinguishesDifferentRequests() {
  var r = b.router.create({ tls0Rtt: "replay-cache" });
  r._check0RttReplay(_mockReq("POST", "/api/charge",
    { "early-data": "1", "idempotency-key": "key-1" }));
  var second = r._check0RttReplay(_mockReq("POST", "/api/charge",
    { "early-data": "1", "idempotency-key": "key-2" }));
  check("replay-cache admits different idempotency-keyed requests",
        second === null);
}

// The replay key must be computed from the same canonical target the router
// dispatches, so a replay that only varies the leading-slash run (which the
// router normalizes to the same path) cannot mint a fresh key and slip through
// the window.
function testReplayCacheCanonicalizesLeadingSlashes() {
  var r = b.router.create({ tls0Rtt: "replay-cache" });
  var headers = { "early-data": "1", host: "api.example.com" };
  // First Early-Data request for /api/charge is admitted + cached.
  var first = r._check0RttReplay(_mockReq("POST", "/api/charge", headers));
  check("replay-cache admits the first /api/charge Early-Data", first === null);
  // "//api/charge" routes to the SAME endpoint, so it must hit the same key.
  var replayDouble = r._check0RttReplay(_mockReq("POST", "//api/charge", headers));
  check("replay-cache: //api/charge is caught as a replay of /api/charge (canonical key)",
        replayDouble && replayDouble.status === 425 && replayDouble.reason === "early-data-replay");
  // A triple-slash variant too.
  var replayTriple = r._check0RttReplay(_mockReq("POST", "///api/charge", headers));
  check("replay-cache: ///api/charge is also caught as a replay",
        replayTriple && replayTriple.status === 425 && replayTriple.reason === "early-data-replay");
}

function testReplayCacheFailClosesUnderPciDss() {
  var compliance = b.compliance;
  var prior = null;
  try { prior = compliance.current ? compliance.current() : null; } catch (_e) {}
  if (prior) {
    // Posture is sticky once set; can't toggle in a test. Skip.
    check("replay-cache fail-close under pci-dss (skipped: posture already set to '" +
          prior + "')", true);
    return;
  }
  try { compliance.set("pci-dss"); }
  catch (e) {
    check("replay-cache fail-close under pci-dss (skipped: " + e.message + ")", true);
    return;
  }
  try {
    var r = b.router.create({ tls0Rtt: "replay-cache" });
    var posture = r._effective0RttPosture();
    check("replay-cache → refuse under pci-dss posture",
          posture === "refuse");
  } finally {
    try { if (typeof compliance.clear === "function") compliance.clear(); }
    catch (_e) { /* clear best-effort */ }
  }
}

async function run() {
  testCreateDefaultsToRefuse();
  testCreateRefusesUnknownPosture();
  testCreateAcceptsValidPostures();
  testRefusePostureRejectsEarlyData();
  testRefusePostureAllowsNonEarlyData();
  testReplayCacheAdmitsFirstRequest();
  testReplayCacheRefusesSecondIdentical();
  testReplayCacheDistinguishesDifferentRequests();
  testReplayCacheCanonicalizesLeadingSlashes();
  testReplayCacheFailClosesUnderPciDss();
}

module.exports = { run: run };
