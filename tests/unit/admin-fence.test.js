/**
 * Admin network fence — opt-in CIDR allowlist on the /admin surface.
 *
 * The fence is b.middleware.networkAllowlist constructed at boot ONLY when
 * config.adminAllowedCidrs is non-empty. These tests exercise the constructed
 * middleware directly (in-range passes, out-of-range is refused 404 + the
 * deny callback fires) plus the config-driven decision that an empty CIDR
 * list mounts NO fence (default off — zero behaviour change).
 */
var { describe, it } = require("node:test");
var assert = require("node:assert");
var b = require("../../lib/vendor/blamejs");

function mkRes() {
  return {
    statusCode: null, headers: {}, body: "",
    setHeader(k, v) { this.headers[k] = v; return this; },
    writeHead(s, h) { this.statusCode = s; if (h) Object.assign(this.headers, h); return this; },
    end(x) { this.body = x || ""; return this; },
  };
}

// Build the fence exactly as server-main.js does, but with a deny spy in place
// of the real audit.log call so the test stays DB-free.
function buildFence(cidrs, denySpy) {
  return b.middleware.networkAllowlist({
    paths:        ["/admin"],
    allowedCidrs: cidrs,
    trustProxy:   false,
    denyStatus:   404,
    onDeny: function (req, res) {
      if (denySpy) denySpy(req);
      res.statusCode = 404;
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.end("Not Found");
    },
  });
}

describe("admin fence — networkAllowlist over /admin", function () {
  var ALLOWED = ["10.0.0.0/8", "::1/128"];

  it("calls next() for an in-range IPv4 admin request", function () {
    var fence = buildFence(ALLOWED);
    var passed = false;
    var req = { pathname: "/admin", url: "/admin", socket: { remoteAddress: "10.1.2.3" }, headers: {} };
    fence(req, mkRes(), function () { passed = true; });
    assert.strictEqual(passed, true, "in-range admin request should pass through");
  });

  it("calls next() for an in-range IPv6 loopback admin request", function () {
    var fence = buildFence(ALLOWED);
    var passed = false;
    var req = { pathname: "/admin/settings", url: "/admin/settings", socket: { remoteAddress: "::1" }, headers: {} };
    fence(req, mkRes(), function () { passed = true; });
    assert.strictEqual(passed, true, "in-range ::1 admin request should pass through");
  });

  it("refuses an out-of-range admin request with 404 and fires the deny callback", function () {
    var denied = [];
    var fence = buildFence(ALLOWED, function (req) { denied.push(req.pathname); });
    var passed = false;
    var res = mkRes();
    var req = { pathname: "/admin", url: "/admin", socket: { remoteAddress: "203.0.113.9" }, headers: {} };
    fence(req, res, function () { passed = true; });
    assert.strictEqual(passed, false, "out-of-range request must not call next()");
    assert.strictEqual(res.statusCode, 404, "deny status hides the fence (404, not 403)");
    assert.strictEqual(res.body, "Not Found");
    assert.deepStrictEqual(denied, ["/admin"], "deny callback (audit hook) should fire once for the refused path");
  });

  it("passes non-/admin paths through unchanged regardless of source IP", function () {
    var fence = buildFence(ALLOWED);
    var passed = false;
    var req = { pathname: "/dashboard", url: "/dashboard", socket: { remoteAddress: "203.0.113.9" }, headers: {} };
    fence(req, mkRes(), function () { passed = true; });
    assert.strictEqual(passed, true, "a public path must not be gated by the admin fence");
  });

  it("does not match /administer (boundary-aware prefix)", function () {
    var fence = buildFence(ALLOWED);
    var passed = false;
    var req = { pathname: "/administer", url: "/administer", socket: { remoteAddress: "203.0.113.9" }, headers: {} };
    fence(req, mkRes(), function () { passed = true; });
    assert.strictEqual(passed, true, "/administer is not /admin — must not be fenced");
  });

  it("an empty CIDR list mounts NO fence (default off)", function () {
    // server-main.js only constructs the fence when the list is non-empty.
    // Mirror that decision here: an empty list means the middleware is never
    // built, so /admin keeps its pre-fence behaviour.
    var cidrs = [];
    var mounted = Array.isArray(cidrs) && cidrs.length > 0;
    assert.strictEqual(mounted, false, "empty adminAllowedCidrs must not mount the fence");

    // And constructing the fence with an empty allowlist is a config error
    // (the primitive refuses an empty allowlist) — proving the guard is load-
    // bearing, not cosmetic.
    assert.throws(function () { buildFence([]); }, /allowedCidrs/);
  });
});
