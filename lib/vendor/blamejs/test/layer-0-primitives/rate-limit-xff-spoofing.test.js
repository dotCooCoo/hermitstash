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

  console.log("[rate-limit-xff-spoofing] OK — " + helpers.getChecks() + " checks passed");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () {}, function (e) { console.error("FAIL: " + helpers.formatErr(e)); process.exit(1); });
}
