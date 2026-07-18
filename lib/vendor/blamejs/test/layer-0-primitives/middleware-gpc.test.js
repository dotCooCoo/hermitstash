// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.middleware.gpc — Sec-GPC (Global Privacy Control) handler.
 *
 * Drives the advertised contract: reads Sec-GPC: 1, sets
 * req.gpcOptOut, echoes Sec-GPC-Status, records purpose withdrawal
 * through an optional b.consent integration, and always calls next().
 *
 * Run standalone: `node test/layer-0-primitives/middleware-gpc.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers   = require("../helpers");
var b         = helpers.b;
var check     = helpers.check;
var _mockReq  = helpers._mockReq;
var _mockRes  = helpers._mockRes;

function testOptOutHonored() {
  var mw = b.middleware.gpc({ mode: "enforce" });
  var req = _mockReq({ headers: { "sec-gpc": "1" } });
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("gpc: Sec-GPC:1 sets req.gpcOptOut = true", req.gpcOptOut === true);
  check("gpc: honored acknowledgement header echoed",
    res._captured().headers["sec-gpc-status"] === "honored");
  check("gpc: middleware always delegates via next()", nextCalled === true);
}

function testNoSignalIsNotOptOut() {
  var mw = b.middleware.gpc({ mode: "enforce" });
  var req = _mockReq({ headers: {} });
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("gpc: absent Sec-GPC leaves req.gpcOptOut = false", req.gpcOptOut === false);
  check("gpc: no acknowledgement header without the signal",
    res._captured().headers["sec-gpc-status"] === undefined);
  check("gpc: passes through", nextCalled === true);
}

function testNonOneValueIsNotOptOut() {
  // Only the exact "1" token is the opt-out per the IETF draft.
  var mw = b.middleware.gpc({});
  var req = _mockReq({ headers: { "sec-gpc": "0" } });
  mw(req, _mockRes(), function () {});
  check("gpc: Sec-GPC:0 is not an opt-out", req.gpcOptOut === false);
}

function testAuditOnlyModeStatus() {
  var mw = b.middleware.gpc({ mode: "audit-only" });
  var req = _mockReq({ headers: { "sec-gpc": "1" } });
  var res = _mockRes();
  mw(req, res, function () {});
  check("gpc: audit-only still records the opt-out", req.gpcOptOut === true);
  check("gpc: audit-only acknowledgement header reflects the mode",
    res._captured().headers["sec-gpc-status"] === "audit-only");
}

function testStatusHeaderSuppressible() {
  var mw = b.middleware.gpc({ statusHeader: false });
  var req = _mockReq({ headers: { "sec-gpc": "1" } });
  var res = _mockRes();
  mw(req, res, function () {});
  check("gpc: statusHeader:false suppresses the acknowledgement header",
    res._captured().headers["sec-gpc-status"] === undefined);
  check("gpc: opt-out still recorded even with the header suppressed",
    req.gpcOptOut === true);
}

function testConsentIntegrationRecordsPurposes() {
  var recorded = null;
  var fakeConsent = {
    recordOptOut: function (o) { recorded = o; },
  };
  var mw = b.middleware.gpc({ consent: fakeConsent });
  var req = _mockReq({ headers: { "sec-gpc": "1" } });
  mw(req, _mockRes(), function () {});
  check("gpc: consent integration invoked with source sec-gpc",
    recorded !== null && recorded.source === "sec-gpc");
  check("gpc: the CCPA/CPRA opt-out purposes are withdrawn",
    recorded.purposes.indexOf("sale") !== -1 &&
    recorded.purposes.indexOf("share") !== -1 &&
    recorded.purposes.indexOf("targeted-ads") !== -1 &&
    recorded.purposes.indexOf("profiling") !== -1);
}

function testConsentErrorDoesNotCrashRequest() {
  // A throwing consent integration must be swallowed (drop-silent) so
  // the request that carried the GPC signal still completes.
  var mw = b.middleware.gpc({
    consent: { recordOptOut: function () { throw new Error("consent store down"); } },
  });
  var req = _mockReq({ headers: { "sec-gpc": "1" } });
  var nextCalled = false;
  mw(req, _mockRes(), function () { nextCalled = true; });
  check("gpc: a throwing consent store does not crash the request",
    nextCalled === true && req.gpcOptOut === true);
}

function run() {
  testOptOutHonored();
  testNoSignalIsNotOptOut();
  testNonOneValueIsNotOptOut();
  testAuditOnlyModeStatus();
  testStatusHeaderSuppressible();
  testConsentIntegrationRecordsPurposes();
  testConsentErrorDoesNotCrashRequest();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.message); process.exit(1); }
  );
}
