"use strict";
/**
 * b.aiPref — AIPREF Content-Usage + Cloudflare Content Signals.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  check("middleware is fn",      typeof b.aiPref.middleware === "function");
  check("serializeHeader is fn", typeof b.aiPref.serializeHeader === "function");
  check("parseHeader is fn",     typeof b.aiPref.parseHeader === "function");
  check("robotsBlock is fn",     typeof b.aiPref.robotsBlock === "function");
  check("refusePaidCrawl is fn", typeof b.aiPref.refusePaidCrawl === "function");
  check("AiPrefError is fn",     typeof b.aiPref.AiPrefError === "function");

  // serializeHeader
  var h = b.aiPref.serializeHeader({ train: "deny", infer: "allow", snippet: "allow" });
  check("serializeHeader basic", h === "train=deny, infer=allow, snippet=allow");

  var hp = b.aiPref.serializeHeader({
    train: "paid", infer: "allow", snippet: "allow",
    price: { amountUsd: 0.005, perTokens: 1000 },
  });
  check("serializeHeader paid + price",
        hp.indexOf("train=paid") !== -1 && hp.indexOf("price-usd=0.005000") !== -1 &&
        hp.indexOf("per-tokens=1000") !== -1);

  // parseHeader round-trip
  var p = b.aiPref.parseHeader(h);
  check("parseHeader round-trip",
        p.train === "deny" && p.infer === "allow" && p.snippet === "allow");

  // robotsBlock
  var rb = b.aiPref.robotsBlock({ train: "deny", infer: "allow", snippet: "allow", userAgent: "GPTBot" });
  check("robotsBlock for GPTBot",
        rb.indexOf("User-agent: GPTBot") !== -1 &&
        rb.indexOf("Content-Usage: train=deny") !== -1);

  // middleware sets headers
  var mw = b.aiPref.middleware({ train: "deny", infer: "allow", snippet: "allow" });
  var headers = {};
  var fakeRes = {
    setHeader: function (k, v) { headers[k] = v; },
  };
  var nextCalled = false;
  mw({ headers: {} }, fakeRes, function () { nextCalled = true; });
  check("middleware sets Content-Usage", typeof headers["Content-Usage"] === "string");
  check("middleware sets CF-Content-Signals", typeof headers["CF-Content-Signals"] === "string");
  check("middleware called next", nextCalled === true);

  // refusePaidCrawl emits 402
  var status = 0, body = "";
  var fakeRes2 = {
    setHeader: function () {},
    set statusCode(n) { status = n; },
    end: function (s) { body = s; },
  };
  b.aiPref.refusePaidCrawl({ headers: { "user-agent": "GPTBot" }, socket: { remoteAddress: "1.2.3.4" } },
    fakeRes2, { price: { amountUsd: 0.01 }, contact: "billing@example.com" });
  check("refusePaidCrawl status 402", status === 402);
  check("refusePaidCrawl body json",  body.indexOf('"pricingModel"') !== -1);

  // Validation
  function rejects(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && threw.code === code);
  }
  rejects("refuses bad train",  function () { b.aiPref.serializeHeader({ train: "maybe" }); }, "BAD_TRAIN");
  rejects("refuses paid without price",
    function () { b.aiPref.serializeHeader({ train: "paid", infer: "allow", snippet: "allow" }); }, "BAD_PRICE");
}

module.exports = { run: run };
