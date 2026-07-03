// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.middleware.noCache — RFC 9111 §5.2.2.5 Cache-Control: no-store middleware.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _mockReq(url) {
  return { method: "GET", url: url || "/", headers: {} };
}

function _mockRes() {
  var headers = {};
  return {
    setHeader: function (k, v) { headers[k.toLowerCase()] = v; },
    getHeader: function (k) { return headers[k.toLowerCase()]; },
    _headers: function () { return headers; },
  };
}

function testSurface() {
  check("middleware.noCache is fn", typeof b.middleware.noCache === "function");
}

function testDefaultHeaders() {
  var mw = b.middleware.noCache();
  var req = _mockReq();
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("noCache: next() called",            nextCalled);
  check("noCache: Cache-Control no-store",   res._headers()["cache-control"] === "no-store");
  check("noCache: Pragma no-cache",          res._headers()["pragma"] === "no-cache");
  check("noCache: Vary Cookie+Auth",         res._headers()["vary"] === "Cookie, Authorization");
}

function testWhenPredicate() {
  var mw = b.middleware.noCache({
    when: function (req) { return req.url.indexOf("/api/private/") === 0; },
  });
  var req1 = _mockReq("/api/public/foo");
  var res1 = _mockRes();
  mw(req1, res1, function () {});
  check("noCache when=false: no headers set", !res1._headers()["cache-control"]);

  var req2 = _mockReq("/api/private/bar");
  var res2 = _mockRes();
  mw(req2, res2, function () {});
  check("noCache when=true: headers set", res2._headers()["cache-control"] === "no-store");
}

function testCustomCacheControlAndVary() {
  var mw = b.middleware.noCache({
    cacheControl: "no-store, private",
    vary:         "Cookie",
  });
  var res = _mockRes();
  mw(_mockReq(), res, function () {});
  check("noCache: custom cacheControl", res._headers()["cache-control"] === "no-store, private");
  check("noCache: custom vary",         res._headers()["vary"] === "Cookie");
}

function testSkipExisting() {
  var mw = b.middleware.noCache({ skipExisting: true });
  var res = _mockRes();
  res.setHeader("Cache-Control", "public, max-age=600");
  var nextCalled = false;
  mw(_mockReq(), res, function () { nextCalled = true; });
  check("noCache skipExisting: pre-set header preserved",
        res._headers()["cache-control"] === "public, max-age=600");
  check("noCache skipExisting: next still called", nextCalled);
}

function testBadOpts() {
  var threw = null;
  try { b.middleware.noCache({ when: "not a fn" }); }
  catch (e) { threw = e; }
  check("noCache: bad when refused",
        threw && /no-cache\/bad-when/.test(threw.code || ""));
}

async function run() {
  testSurface();
  testDefaultHeaders();
  testWhenPredicate();
  testCustomCacheControlAndVary();
  testSkipExisting();
  testBadOpts();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
