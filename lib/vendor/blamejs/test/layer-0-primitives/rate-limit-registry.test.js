// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.middleware._modules.rateLimit.instances() / resetAll() — module-level
 * registry of every rate-limit middleware in the running process; used
 * by incident-response scripts that need to flush every limiter at
 * once without threading references through the app.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  var rateLimitMod = b.middleware._modules.rateLimit;

  check("instances() is fn",       typeof rateLimitMod.instances === "function");
  check("resetAll() is fn",        typeof rateLimitMod.resetAll  === "function");

  // Snapshot any pre-existing instances (other tests sharing the
  // module). We only assert on the deltas this test creates.
  var preCount = rateLimitMod.instances().length;

  var mwA = b.middleware.rateLimit({
    backend: "memory", burst: 10, refillPerSecond: 1,
  });
  var mwB = b.middleware.rateLimit({
    backend: "memory", max: 5, windowMs: 1000,
  });

  var afterAdd = rateLimitMod.instances();
  check("instances() reflects new middlewares",
        afterAdd.length === preCount + 2);
  check("instances() includes mwA", afterAdd.indexOf(mwA) !== -1);
  check("instances() includes mwB", afterAdd.indexOf(mwB) !== -1);
  check("instances() entries are middleware fns",
        typeof afterAdd[afterAdd.length - 1] === "function");
  check("instances() entries expose .resetAll",
        typeof mwA.resetAll === "function");

  // headerPrefix: the X-RateLimit-* response header names are configurable
  // (default "X-RateLimit-", or e.g. the unprefixed IETF-draft "RateLimit-").
  function _mkRes() {
    var h = {};
    return { _h: h, setHeader: function (k, v) { h[k] = v; }, writeHead: function () {}, end: function () {} };
  }
  function _runRl(mw, key) {
    return new Promise(function (resolve) {
      var res = _mkRes();
      mw({ headers: {}, url: "/", method: "GET", socket: { remoteAddress: "127.0.0.1" } },
         res, function () { resolve(res); });
    });
  }
  var rlDefault = b.middleware.rateLimit({
    backend: "memory", burst: 5, refillPerSecond: 1, keyFn: function () { return "hp-d"; },
  });
  var rlDefaultRes = await _runRl(rlDefault);
  check("rateLimit default emits X-RateLimit-Limit",
        rlDefaultRes._h["X-RateLimit-Limit"] !== undefined);
  var rlCustom = b.middleware.rateLimit({
    backend: "memory", burst: 5, refillPerSecond: 1, headerPrefix: "RateLimit-",
    keyFn: function () { return "hp-c"; },
  });
  var rlCustomRes = await _runRl(rlCustom);
  check("rateLimit custom headerPrefix on limit",
        rlCustomRes._h["RateLimit-Limit"] !== undefined);
  check("rateLimit custom headerPrefix on remaining",
        rlCustomRes._h["RateLimit-Remaining"] !== undefined);
  check("rateLimit custom headerPrefix replaces default",
        rlCustomRes._h["X-RateLimit-Limit"] === undefined);
  // Deregister so the registry-count assertions below stay exact.
  rlDefault.close();
  rlCustom.close();

  // Seed each backend so resetAll has observable state to flush.
  // Drive .take() through the middleware function via a fake req/res.
  var fakeReq = { socket: { remoteAddress: "1.2.3.4" }, method: "GET", url: "/" };
  var fakeRes = { setHeader: function () {}, writeHead: function () {}, end: function () {} };
  function _drive(mw) {
    return new Promise(function (resolve) { mw(fakeReq, fakeRes, resolve); });
  }
  await _drive(mwA);
  await _drive(mwB);

  // Top-level resetAll() walks every registered instance.
  var n = rateLimitMod.resetAll();
  check("resetAll() returned count of flushed instances",
        typeof n === "number" && n >= 2);

  // close() removes from the registry.
  mwA.close();
  var afterClose = rateLimitMod.instances();
  check("close() deregisters from instances()",
        afterClose.indexOf(mwA) === -1);
  check("instances() still includes mwB after mwA closed",
        afterClose.indexOf(mwB) !== -1);

  mwB.close();
  check("instances() back to pre-existing count after both closed",
        rateLimitMod.instances().length === preCount);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
