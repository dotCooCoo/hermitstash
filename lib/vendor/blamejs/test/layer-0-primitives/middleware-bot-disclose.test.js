// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.middleware.botDisclose — California SB 1001 bot-disclosure.
 *
 * Drives the load-bearing disclosure surfaces: the X-Bot-Disclosure
 * header on every in-scope request, banner injection into text/html
 * responses, res.locals for JSON handlers, and mountPaths scoping.
 *
 * Run standalone: `node test/layer-0-primitives/middleware-bot-disclose.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers   = require("../helpers");
var b         = helpers.b;
var check     = helpers.check;
var _mockReq  = helpers._mockReq;
var _mockRes  = helpers._mockRes;

function testHeaderSetOnEveryRequest() {
  var mw = b.middleware.botDisclose({ mountPaths: ["/chat"] });
  var req = _mockReq({ method: "GET", url: "/chat" });
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  res.end("{}");
  check("botDisclose: X-Bot-Disclosure header set for API consumers",
    res._captured().headers["x-bot-disclosure"] === "automated-assistant");
  check("botDisclose: delegates to the handler via next()", nextCalled === true);
}

function testBannerInjectedIntoHtml() {
  var mw = b.middleware.botDisclose({
    mountPaths: ["/chat"],
    bannerHtml: '<div id="BOT-BANNER">automated</div>',
  });
  var req = _mockReq({ method: "GET", url: "/chat" });
  var res = _mockRes();
  mw(req, res, function () {});
  // Operator handler renders HTML — the middleware patched res.end.
  res.setHeader("content-type", "text/html; charset=utf-8");
  res.end("<html><body><h1>hi</h1></body></html>");
  var body = res._captured().body;
  check("botDisclose: banner injected into the HTML response",
    body.indexOf('<div id="BOT-BANNER">automated</div>') !== -1);
  check("botDisclose: banner injected AFTER the <body> open tag",
    body.indexOf("<body>") < body.indexOf("BOT-BANNER") &&
    body.indexOf("BOT-BANNER") < body.indexOf("<h1>"));
}

function testNonHtmlResponseNotRewritten() {
  var mw = b.middleware.botDisclose({ mountPaths: ["/api/chat"] });
  var req = _mockReq({ method: "POST", url: "/api/chat" });
  var res = _mockRes();
  mw(req, res, function () {});
  res.setHeader("content-type", "application/json");
  res.end('{"reply":"hi"}');
  check("botDisclose: JSON body left byte-for-byte intact (header carries the disclosure)",
    res._captured().body === '{"reply":"hi"}');
}

function testJsonDisclosureOnLocals() {
  var mw = b.middleware.botDisclose({
    mountPaths: ["/chat"],
    bannerJson: { _bot: true, disclosure: "automated-assistant" },
  });
  var req = _mockReq({ method: "GET", url: "/chat" });
  var res = _mockRes();
  res.locals = {};
  mw(req, res, function () {});
  check("botDisclose: bannerJson exposed on res.locals for JSON handlers",
    res.locals.botDisclosure && res.locals.botDisclosure._bot === true);
}

function testMountPathScoping() {
  var mw = b.middleware.botDisclose({ mountPaths: ["/chat"] });
  var req = _mockReq({ method: "GET", url: "/dashboard" });
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("botDisclose: request outside mountPaths passes through untouched", nextCalled === true);
  check("botDisclose: no header on out-of-scope route",
    res._captured().headers["x-bot-disclosure"] === undefined);
}

function testNullMountPathsAppliesEverywhere() {
  // null mountPaths = apply to every route.
  var mw = b.middleware.botDisclose({});
  var req = _mockReq({ method: "GET", url: "/anything/at/all" });
  var res = _mockRes();
  mw(req, res, function () {});
  check("botDisclose: null mountPaths applies the header to every route",
    res._captured().headers["x-bot-disclosure"] === "automated-assistant");
}

function testCustomHeaderName() {
  var mw = b.middleware.botDisclose({ headerName: "X-Automated-Agent" });
  var req = _mockReq({ method: "GET", url: "/x" });
  var res = _mockRes();
  mw(req, res, function () {});
  check("botDisclose: custom headerName honored",
    res._captured().headers["x-automated-agent"] === "automated-assistant");
}

function run() {
  testHeaderSetOnEveryRequest();
  testBannerInjectedIntoHtml();
  testNonHtmlResponseNotRewritten();
  testJsonDisclosureOnLocals();
  testMountPathScoping();
  testNullMountPathsAppliesEverywhere();
  testCustomHeaderName();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.message); process.exit(1); }
  );
}
