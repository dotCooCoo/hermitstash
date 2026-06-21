"use strict";

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;
var _mockReq = helpers._mockReq;
var _mockRes = helpers._mockRes;

async function run() {
  check("middleware.networkAllowlist is fn",  typeof b.middleware.networkAllowlist === "function");

  // ---- Validation ----
  var threwNoPaths = null;
  try { b.middleware.networkAllowlist({ allowedCidrs: ["127.0.0.0/8"] }); }
  catch (e) { threwNoPaths = e; }
  check("create: rejects missing paths",      threwNoPaths !== null);

  var threwNoCidrs = null;
  try { b.middleware.networkAllowlist({ paths: ["/admin"] }); }
  catch (e) { threwNoCidrs = e; }
  check("create: rejects missing allowedCidrs", threwNoCidrs !== null);

  var threwBadCidr = null;
  try { b.middleware.networkAllowlist({ paths: ["/admin"], allowedCidrs: ["nope"] }); }
  catch (e) { threwBadCidr = e; }
  check("create: rejects malformed CIDR",     threwBadCidr !== null);

  var threwBadPath = null;
  try { b.middleware.networkAllowlist({ paths: ["admin"], allowedCidrs: ["10.0.0.0/8"] }); }
  catch (e) { threwBadPath = e; }
  check("create: rejects path missing leading /", threwBadPath !== null);

  // ---- Behaviour ----
  var fence = b.middleware.networkAllowlist({
    paths:        ["/admin", "/healthz/internal"],
    allowedCidrs: ["10.0.0.0/8", "127.0.0.0/8"],
    audit:        b.audit,
  });

  function _runMw(mw, req) {
    return new Promise(function (resolve) {
      var res = _mockRes();
      var nextCalled = false;
      var maybe = mw(req, res, function () { nextCalled = true; resolve({ res: res, next: true }); });
      if (maybe && typeof maybe.then === "function") maybe.then(function () {
        // synchronous path may have already resolved
      });
      // Allow microtask flush so async middleware completes.
      setImmediate(function () {
        if (nextCalled) return;
        resolve({ res: res, next: false });
      });
    });
  }

  // Request from allowed CIDR (127.0.0.1) to admin path → next() called
  var req1 = _mockReq({ url: "/admin/dashboard", method: "GET" });
  req1.pathname = "/admin/dashboard";
  req1.socket = { remoteAddress: "127.0.0.1" };
  var r1 = await _runMw(fence, req1);
  check("allowed IP + gated path → next()",     r1.next === true);

  // Request from disallowed CIDR (192.168.x.x) to admin → 404 (default denyStatus)
  var req2 = _mockReq({ url: "/admin/dashboard", method: "GET" });
  req2.pathname = "/admin/dashboard";
  req2.socket = { remoteAddress: "192.168.1.50" };
  var r2 = await _runMw(fence, req2);
  check("disallowed IP + gated path → blocked",   r2.next === false);
  check("disallowed IP + gated path → 404",       r2.res._captured().status === 404);

  // Request to NON-gated path passes regardless of IP
  var req3 = _mockReq({ url: "/public", method: "GET" });
  req3.pathname = "/public";
  req3.socket = { remoteAddress: "192.168.1.50" };
  var r3 = await _runMw(fence, req3);
  check("non-gated path → next() regardless of IP", r3.next === true);

  // Boundary check — /administer must NOT match /admin
  var req4 = _mockReq({ url: "/administer", method: "GET" });
  req4.pathname = "/administer";
  req4.socket = { remoteAddress: "192.168.1.50" };
  var r4 = await _runMw(fence, req4);
  check("/administer not gated by /admin prefix",  r4.next === true);

  // Custom denyStatus / denyBody
  var fence403 = b.middleware.networkAllowlist({
    paths:        ["/admin"],
    allowedCidrs: ["10.0.0.0/8"],
    denyStatus:   403,
    denyBody:     "Forbidden",
  });
  var req5 = _mockReq({ url: "/admin", method: "GET" });
  req5.pathname = "/admin";
  req5.socket = { remoteAddress: "192.168.1.1" };
  var r5 = await _runMw(fence403, req5);
  check("custom denyStatus = 403",                  r5.res._captured().status === 403);

  // ---- X-Forwarded-For spoofing (CWE-290/348) ----
  // A bare trustProxy honored the leftmost XFF hop, which a direct caller
  // fully controls — forging an allowed IP walked through the gate. The gate
  // now refuses that spoofable config at construction and peer-gates XFF.

  // Construction fails closed: trustProxy without trustedProxies/resolver.
  var threwBareTrust = null;
  try { b.middleware.networkAllowlist({ paths: ["/admin"], allowedCidrs: ["203.0.113.0/24"], trustProxy: true }); }
  catch (e) { threwBareTrust = e; }
  check("create: bare trustProxy refused (spoofable gate)", threwBareTrust !== null);
  var threwBareNum = null;
  try { b.middleware.networkAllowlist({ paths: ["/admin"], allowedCidrs: ["203.0.113.0/24"], trustProxy: 1 }); }
  catch (e) { threwBareNum = e; }
  check("create: bare trustProxy:N refused too",            threwBareNum !== null);
  var threwBadResolver = null;
  try { b.middleware.networkAllowlist({ paths: ["/admin"], allowedCidrs: ["203.0.113.0/24"], clientIpResolver: 123 }); }
  catch (e) { threwBadResolver = e; }
  check("create: non-function clientIpResolver refused",    threwBadResolver !== null);

  function _xffReq(sock, xff) {
    var rq = _mockReq({ url: "/admin/x", method: "GET" });
    rq.pathname = "/admin/x";
    rq.socket = { remoteAddress: sock };
    rq.headers["x-forwarded-for"] = xff;
    return rq;
  }

  // Peer-gated via trustedProxies.
  var pgFence = b.middleware.networkAllowlist({
    paths:          ["/admin"],
    allowedCidrs:   ["203.0.113.0/24"],
    trustedProxies: ["10.0.0.0/8"],
  });
  // Direct attacker (untrusted peer) forging an allowed IP → DENIED.
  var rSpoof = await _runMw(pgFence, _xffReq("198.51.100.66", "203.0.113.7"));
  check("spoofed XFF from untrusted peer → blocked",    rSpoof.next === false);
  // Trusted proxy forwarding a real allowed client → allowed.
  var rTrusted = await _runMw(pgFence, _xffReq("10.0.0.9", "203.0.113.7"));
  check("trusted proxy + allowed client → next()",      rTrusted.next === true);
  // Trusted proxy forwarding a non-allowed client → blocked (real IP honored).
  var rTrustedBad = await _runMw(pgFence, _xffReq("10.0.0.9", "198.51.100.66"));
  check("trusted proxy + non-allowed client → blocked", rTrustedBad.next === false);

  // clientIpResolver: operator owns resolution entirely.
  var resFence = b.middleware.networkAllowlist({
    paths:            ["/admin"],
    allowedCidrs:     ["203.0.113.0/24"],
    clientIpResolver: function (rq) { return rq.headers["true-client-ip"]; },
  });
  var resReq = _mockReq({ url: "/admin/x", method: "GET" });
  resReq.pathname = "/admin/x";
  resReq.socket = { remoteAddress: "1.2.3.4" };
  resReq.headers["true-client-ip"] = "203.0.113.50";
  var rRes = await _runMw(resFence, resReq);
  check("clientIpResolver resolves allowed client → next()", rRes.next === true);

  // Default (no trust config): socket address governs, forged XFF ignored.
  var defFence = b.middleware.networkAllowlist({ paths: ["/admin"], allowedCidrs: ["203.0.113.0/24"] });
  var rDefSpoof = await _runMw(defFence, _xffReq("198.51.100.66", "203.0.113.7"));
  check("default: forged XFF ignored, attacker socket blocked", rDefSpoof.next === false);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[network-allowlist] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
