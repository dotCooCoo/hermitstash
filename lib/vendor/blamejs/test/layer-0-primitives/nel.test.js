// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * nel — W3C Network Error Logging emitter middleware.
 *
 * Run standalone: `node test/layer-0-primitives/nel.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b        = helpers.b;
var check    = helpers.check;
var _mockReq = helpers._mockReq;
var _mockRes = helpers._mockRes;

function testNelSurface() {
  check("b.middleware.nel is a function",        typeof b.middleware.nel === "function");
  var raw = b.middleware._modules.nel;
  check("nel.create exposed via _modules",       typeof raw.create === "function");
  check("DEFAULT_REPORT_GROUP exposed",          raw.DEFAULT_REPORT_GROUP === "default");
  check("DEFAULT_MAX_AGE exposed (24h)",         raw.DEFAULT_MAX_AGE === 86400);
  check("DEFAULT_SUCCESS_FRACTION default 0",    raw.DEFAULT_SUCCESS_FRACTION === 0);
  check("DEFAULT_FAILURE_FRACTION default 1",    raw.DEFAULT_FAILURE_FRACTION === 1);
}

function testNelRequiresCollectorUrl() {
  var threw;
  threw = null;
  try { b.middleware.nel({}); } catch (e) { threw = e; }
  check("missing collectorUrl throws",
        threw && /collectorUrl is required/.test(threw.message));

  threw = null;
  try { b.middleware.nel({ collectorUrl: "" }); } catch (e) { threw = e; }
  check("empty collectorUrl throws",
        threw && /collectorUrl is required/.test(threw.message));

  threw = null;
  try { b.middleware.nel({ collectorUrl: "http://insecure.example.com/c" }); } catch (e) { threw = e; }
  check("http:// collectorUrl rejected (browsers ignore non-secure NEL)",
        threw && /https:\/\//.test(threw.message));
}

function testNelRefusesHeaderInjection() {
  var threw;
  threw = null;
  try { b.middleware.nel({ collectorUrl: "https://collector.example.com/c\r\nX-Inject: 1" }); }
  catch (e) { threw = e; }
  check("CR/LF in collectorUrl refused as header-injection vector",
        threw && /header-injection/.test(threw.message));

  threw = null;
  try {
    b.middleware.nel({
      collectorUrl: "https://collector.example.com/c",
      reportTo:     "evil\rSet-Cookie: x=1",
    });
  } catch (e) { threw = e; }
  check("CR in reportTo refused",
        threw && /header-injection/.test(threw.message));

  threw = null;
  try {
    b.middleware.nel({
      collectorUrl: "https://collector.example.com/c\0nul",
    });
  } catch (e) { threw = e; }
  check("NUL in collectorUrl refused",
        threw && /header-injection/.test(threw.message));
}

function testNelValidatesNumericRanges() {
  var threw;
  threw = null;
  try {
    b.middleware.nel({
      collectorUrl: "https://collector.example.com/c",
      maxAge:       -1,
    });
  } catch (e) { threw = e; }
  check("negative maxAge throws",
        threw && /maxAge/.test(threw.message));

  threw = null;
  try {
    b.middleware.nel({
      collectorUrl:    "https://collector.example.com/c",
      successFraction: 1.5,
    });
  } catch (e) { threw = e; }
  check("successFraction > 1 throws",
        threw && /successFraction/.test(threw.message));

  threw = null;
  try {
    b.middleware.nel({
      collectorUrl:    "https://collector.example.com/c",
      failureFraction: -0.1,
    });
  } catch (e) { threw = e; }
  check("failureFraction < 0 throws",
        threw && /failureFraction/.test(threw.message));
}

function testNelRejectsUnknownOpts() {
  var threw = null;
  try {
    b.middleware.nel({
      collectorUrl: "https://collector.example.com/c",
      unknownKey:   "smell",
    });
  } catch (e) { threw = e; }
  check("unknown opt key rejected at config-time", threw !== null);
}

function _drive(mw, req, res) {
  return new Promise(function (resolve) {
    mw(req, res, function () { resolve(); });
  });
}

async function testNelEmitsHeaders() {
  var mw = b.middleware.nel({
    collectorUrl: "https://collector.example.com/nel",
  });
  var req = _mockReq();
  var res = _mockRes();
  await _drive(mw, req, res);
  var captured = res._captured();
  var reportTo = captured.headers["report-to"];
  var nel = captured.headers["nel"];
  check("Report-To header set",     typeof reportTo === "string" && reportTo.length > 0);
  check("NEL header set",           typeof nel === "string" && nel.length > 0);

  var reportToParsed = JSON.parse(reportTo);
  check("Report-To group=default",  reportToParsed.group === "default");
  check("Report-To max_age=86400",  reportToParsed.max_age === 86400);
  check("Report-To endpoints[0].url is the collector",
        Array.isArray(reportToParsed.endpoints) &&
        reportToParsed.endpoints[0].url === "https://collector.example.com/nel");

  var nelParsed = JSON.parse(nel);
  check("NEL report_to=default",          nelParsed.report_to === "default");
  check("NEL max_age=86400",              nelParsed.max_age === 86400);
  check("NEL include_subdomains=false",   nelParsed.include_subdomains === false);
  check("NEL success_fraction=0 (default)", nelParsed.success_fraction === 0);
  check("NEL failure_fraction=1 (default)", nelParsed.failure_fraction === 1);
}

async function testNelHonorsCustomOpts() {
  var mw = b.middleware.nel({
    collectorUrl:      "https://c.example.com/nel",
    reportTo:          "main",
    maxAge:            3600,
    includeSubdomains: true,
    successFraction:   0.05,
    failureFraction:   0.5,
  });
  var req = _mockReq();
  var res = _mockRes();
  await _drive(mw, req, res);
  var captured = res._captured();
  var reportToParsed = JSON.parse(captured.headers["report-to"]);
  var nelParsed = JSON.parse(captured.headers["nel"]);
  check("custom report group propagates",         reportToParsed.group === "main");
  check("custom maxAge propagates",                reportToParsed.max_age === 3600);
  check("includeSubdomains=true propagates",       nelParsed.include_subdomains === true);
  check("successFraction=0.05 propagates",         nelParsed.success_fraction === 0.05);
  check("failureFraction=0.5 propagates",          nelParsed.failure_fraction === 0.5);
}

async function testNelCallsNext() {
  var mw = b.middleware.nel({ collectorUrl: "https://c.example.com/nel" });
  var req = _mockReq();
  var res = _mockRes();
  var nextCalled = false;
  await new Promise(function (resolve) {
    mw(req, res, function () { nextCalled = true; resolve(); });
  });
  check("middleware calls next() unconditionally", nextCalled === true);
}

async function run() {
  testNelSurface();
  testNelRequiresCollectorUrl();
  testNelRefusesHeaderInjection();
  testNelValidatesNumericRanges();
  testNelRejectsUnknownOpts();
  await testNelEmitsHeaders();
  await testNelHonorsCustomOpts();
  await testNelCallsNext();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
