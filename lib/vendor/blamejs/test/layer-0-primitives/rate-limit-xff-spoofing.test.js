// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.middleware.rateLimit — X-Forwarded-For spoofing of the rate-limit key
 * (CWE-290/348). A bare trustProxy honored a forgeable header, so a caller
 * could rotate X-Forwarded-For to evade their own limit, or set a victim's
 * IP to exhaust the victim's bucket (targeted DoS). The key is now peer-
 * gated: trustProxy without trustedProxies/clientIpResolver/keyFn is refused
 * at construction, and a declared proxy CIDR gates the header.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function _runMw(mw, req) {
  return new Promise(function (resolve) {
    var res = { setHeader: function () {}, writeHead: function () {}, end: function () {}, statusCode: 200 };
    var next = false;
    var maybe = mw(req, res, function () { next = true; });
    Promise.resolve(maybe).then(function () {
      setImmediate(function () { resolve({ next: next }); });
    });
  });
}
function _req(sock, xff) {
  return { url: "/x", pathname: "/x", method: "GET",
    socket: { remoteAddress: sock },
    headers: xff ? { "x-forwarded-for": xff } : {}, requestId: "r" };
}

async function run() {
  // Construction fails closed: bare trustProxy with the default IP key.
  var threwBare = null;
  try { b.middleware.rateLimit({ backend: "memory", burst: 1, refillPerSecond: 0.001, trustProxy: true }); }
  catch (e) { threwBare = e; }
  check("create: bare trustProxy refused (spoofable IP key)", threwBare !== null);

  // Allowed: bare trustProxy when the operator owns the key (not IP-derived).
  var okKeyFn = true;
  try { b.middleware.rateLimit({ backend: "memory", burst: 1, refillPerSecond: 0.001, trustProxy: true, keyFn: function () { return "k"; } }); }
  catch (_e) { okKeyFn = false; }
  check("create: trustProxy + keyFn allowed (key not IP)", okKeyFn === true);

  // Malformed trustedProxies CIDR refused.
  var threwCidr = null;
  try { b.middleware.rateLimit({ backend: "memory", burst: 1, refillPerSecond: 0.001, trustedProxies: ["nope"] }); }
  catch (e) { threwCidr = e; }
  check("create: malformed trustedProxies CIDR refused", threwCidr !== null);

  // Peer-gated: a direct attacker cannot evade by rotating X-Forwarded-For —
  // the key is the socket address, so both requests hit the same bucket.
  var atkMw = b.middleware.rateLimit({ backend: "memory", burst: 1, refillPerSecond: 0.001, trustedProxies: ["10.0.0.0/8"] });
  var a1 = await _runMw(atkMw, _req("198.51.100.66", "1.1.1.1"));
  var a2 = await _runMw(atkMw, _req("198.51.100.66", "2.2.2.2"));
  check("attacker first request allowed",                 a1.next === true);
  check("attacker cannot evade by rotating XFF (blocked)", a2.next === false);

  // Behind a trusted proxy, distinct real clients get distinct buckets.
  var proxMw = b.middleware.rateLimit({ backend: "memory", burst: 1, refillPerSecond: 0.001, trustedProxies: ["10.0.0.0/8"] });
  var c1 = await _runMw(proxMw, _req("10.0.0.9", "203.0.113.1"));
  var c2 = await _runMw(proxMw, _req("10.0.0.9", "203.0.113.2"));
  check("trusted proxy: client A allowed", c1.next === true);
  check("trusted proxy: client B (distinct bucket) allowed", c2.next === true);

  // Same real client via the proxy shares a bucket (limit enforced per-client).
  var c2again = await _runMw(proxMw, _req("10.0.0.9", "203.0.113.1"));
  check("trusted proxy: client A second request blocked", c2again.next === false);

  // #352 — ipKeyMode "prefix64": an IPv6 end-site owns a whole /64 and can
  // rotate the low 64 bits freely. Under the default exact key each rotated
  // address is a fresh bucket (the bypass); under prefix64 they share the
  // /64 bucket, so the per-IP limit actually binds. IPv4 stays exact.
  var v6a = "2001:db8:1:2:dead:beef:0:1";
  var v6b = "2001:db8:1:2:ffff:ffff:ffff:ffff";   // same /64, rotated low bits
  var v6c = "2001:db8:1:3::1";                      // different /64

  // Baseline (exact): rotating the low 64 bits evades the limit.
  var exactMw = b.middleware.rateLimit({ backend: "memory", burst: 1, refillPerSecond: 0.001 });
  var e1 = await _runMw(exactMw, _req(v6a));
  var e2 = await _runMw(exactMw, _req(v6b));
  check("exact key: low-64 rotation mints a fresh bucket (the bypass)",
        e1.next === true && e2.next === true);

  // prefix64: the rotated address shares the /64 bucket → second blocked.
  var p64Mw = b.middleware.rateLimit({ backend: "memory", burst: 1, refillPerSecond: 0.001, ipKeyMode: "prefix64" });
  var f1 = await _runMw(p64Mw, _req(v6a));
  var f2 = await _runMw(p64Mw, _req(v6b));
  var f3 = await _runMw(p64Mw, _req(v6c));
  check("prefix64: first /64 request allowed", f1.next === true);
  check("prefix64: low-64 rotation hits the SAME /64 bucket (blocked)", f2.next === false);
  check("prefix64: a different /64 gets its own bucket (allowed)", f3.next === true);

  // prefix64 keeps IPv4 exact — two distinct IPv4 hosts are distinct buckets.
  var p64v4 = b.middleware.rateLimit({ backend: "memory", burst: 1, refillPerSecond: 0.001, ipKeyMode: "prefix64" });
  var g1 = await _runMw(p64v4, _req("198.51.100.10"));
  var g2 = await _runMw(p64v4, _req("198.51.100.11"));
  check("prefix64: distinct IPv4 hosts stay distinct (v4 exact)", g1.next === true && g2.next === true);

  // Bad ipKeyMode refused at construction.
  var threwMode = null;
  try { b.middleware.rateLimit({ backend: "memory", burst: 1, refillPerSecond: 0.001, ipKeyMode: "bogus" }); }
  catch (e) { threwMode = e; }
  check("create: bad ipKeyMode refused", threwMode !== null && /ipKeyMode/.test(threwMode.message));

  // scope:"per-route" must key on the route PATH only — never the query
  // string. When req.pathname is absent (a raw http.IncomingMessage handed
  // to the middleware directly, before b.router populates pathname) the key
  // used req.url verbatim, so rotating a throwaway query param minted a fresh
  // per-route bucket per request and defeated the limit — the same bucket-
  // rotation evasion class as the XFF / low-64 cases above. Every sibling
  // guard (request-log / require-auth / network-allowlist) already strips the
  // query with `(req.url||"").split("?")[0]`; rate-limit must too.
  function _rawReq(url) {
    // No pathname — the shape a bare Node req has before the router runs.
    return { url: url, method: "POST",
      socket: { remoteAddress: "198.51.100.7" }, headers: {}, requestId: "r" };
  }
  var routeMw = b.middleware.rateLimit({
    backend: "memory", algorithm: "fixed-window", max: 1,
    windowMs: b.constants.TIME.hours(1), scope: "per-route",
  });
  var q1 = await _runMw(routeMw, _rawReq("/api/pay?nonce=1"));
  var q2 = await _runMw(routeMw, _rawReq("/api/pay?nonce=2"));
  var q3 = await _runMw(routeMw, _rawReq("/api/pay?nonce=3"));
  check("per-route: first request to the route allowed", q1.next === true);
  check("per-route: query-string rotation hits the SAME route bucket (blocked)",
        q2.next === false && q3.next === false);

  // The fix strips the query, not the path: distinct route paths stay distinct.
  var routeMw2 = b.middleware.rateLimit({
    backend: "memory", algorithm: "fixed-window", max: 1,
    windowMs: b.constants.TIME.hours(1), scope: "per-route",
  });
  var r1 = await _runMw(routeMw2, _rawReq("/api/pay"));
  var r2 = await _runMw(routeMw2, _rawReq("/api/refund"));
  check("per-route: distinct route paths keep distinct buckets",
        r1.next === true && r2.next === true);

  console.log("[rate-limit-xff-spoofing] OK — " + helpers.getChecks() + " checks passed");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () {}, function (e) { console.error("FAIL: " + helpers.formatErr(e)); process.exit(1); });
}
