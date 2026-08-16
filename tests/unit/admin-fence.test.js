/**
 * Admin network fence — opt-in CIDR allowlist on the /admin surface.
 *
 * These exercise app/security/admin-fence.js, which is what server-main.js
 * mounts. The previous version of this file built b.middleware.networkAllowlist
 * and called it "the fence exactly as server-main.js does" — server-main.js had
 * stopped using that primitive, precisely because it resolves the client IP
 * itself with no trusted-peer gate. So the header-spoofing case below, the one
 * the hand-written fence exists to defeat, was the one thing not being checked.
 *
 * The fence audits a refusal, so these need the database the audit log writes
 * to and the vault key its sealed columns derive from.
 */

var os = require("node:os");
var path = require("node:path");
var fs = require("node:fs");

var dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "hs-admin-fence-"));
process.env.HERMITSTASH_DATA_DIR = dataDir;

require("../helpers/test-env");

var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");

var vault = require("../../lib/vault");
var config = require("../../lib/config");
var adminFence = require("../../app/security/admin-fence");

var ALLOWED = ["10.0.0.0/8", "::1/128"];

function mkRes() {
  return {
    statusCode: null, headers: {}, body: "", ended: false,
    setHeader(k, v) { this.headers[k] = v; return this; },
    writeHead(s, h) { this.statusCode = s; if (h) Object.assign(this.headers, h); return this; },
    end(x) { this.body = x || ""; this.ended = true; return this; },
  };
}

// A request as the router hands it to middleware: pathname already decoded,
// socket peer separate from any forwarding header.
function mkReq(pathname, peerIp, headers) {
  return {
    pathname: pathname,
    url: pathname,
    method: "GET",
    headers: headers || {},
    socket: { remoteAddress: peerIp },
  };
}

// Run the fence and report which way it went.
function run(fence, req) {
  var res = mkRes();
  var passed = false;
  fence(req, res, function () { passed = true; });
  return { passed: passed, res: res };
}

describe("admin fence", function () {
  before(async function () { await vault.init(); });
  after(function () {
    try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
  });

  describe("who gets through", function () {
    it("passes an in-range IPv4 admin request", function () {
      var out = run(adminFence.create(ALLOWED), mkReq("/admin", "10.1.2.3"));
      assert.strictEqual(out.passed, true, "an in-range operator must reach /admin");
    });

    it("passes an in-range IPv6 loopback admin request", function () {
      var out = run(adminFence.create(ALLOWED), mkReq("/admin", "::1"));
      assert.strictEqual(out.passed, true);
    });

    it("passes an in-range operator arriving as IPv4-mapped IPv6", function () {
      // A dual-stack listener reports 10.1.2.3 as ::ffff:10.1.2.3. Refusing that
      // locks out the operator whose address is in the allowlist.
      var out = run(adminFence.create(ALLOWED), mkReq("/admin", "::ffff:10.1.2.3"));
      assert.strictEqual(out.passed, true, "an IPv4-mapped in-range address must not be refused");
    });

    it("refuses an out-of-range admin request with 404, not 403", function () {
      // 404 so a probe cannot tell the fence — or the admin surface — is there.
      var out = run(adminFence.create(ALLOWED), mkReq("/admin", "203.0.113.5"));
      assert.strictEqual(out.passed, false, "an out-of-range request must not reach the route");
      assert.strictEqual(out.res.statusCode, 404);
      assert.strictEqual(out.res.body, "Not Found");
    });

    it("refuses when the peer address is missing entirely", function () {
      var out = run(adminFence.create(ALLOWED), mkReq("/admin", undefined));
      assert.strictEqual(out.passed, false, "no resolvable client IP must fail closed");
      assert.strictEqual(out.res.statusCode, 404);
    });
  });

  describe("a forwarding header cannot open the fence", function () {
    // The reason this fence does not use the framework's networkAllowlist. The
    // client IP is only taken from X-Forwarded-For when the socket peer is a
    // configured trusted proxy; off-proxy the header is attacker-supplied.
    it("ignores X-Forwarded-For naming an in-range address from an untrusted peer", function () {
      var out = run(adminFence.create(ALLOWED),
        mkReq("/admin", "203.0.113.5", { "x-forwarded-for": "10.1.2.3" }));
      assert.strictEqual(out.passed, false,
        "a forged X-Forwarded-For must not put an outside client inside the fence");
      assert.strictEqual(out.res.statusCode, 404);
    });

    it("ignores a multi-hop X-Forwarded-For from an untrusted peer", function () {
      var out = run(adminFence.create(ALLOWED),
        mkReq("/admin", "203.0.113.5", { "x-forwarded-for": "10.1.2.3, 10.9.9.9" }));
      assert.strictEqual(out.passed, false);
      assert.strictEqual(out.res.statusCode, 404);
    });
  });

  describe("what counts as the admin surface", function () {
    it("lets a non-admin path through from any address", function () {
      var out = run(adminFence.create(ALLOWED), mkReq("/drop", "203.0.113.5"));
      assert.strictEqual(out.passed, true, "the fence covers /admin only");
    });

    it("does not fence a path that merely starts with the same letters", function () {
      assert.strictEqual(adminFence.isAdminPath("/administer"), false);
      assert.strictEqual(adminFence.isAdminPath("/admin-tools"), false);
      var out = run(adminFence.create(ALLOWED), mkReq("/administer", "203.0.113.5"));
      assert.strictEqual(out.passed, true);
    });

    it("covers /admin and everything under it", function () {
      assert.strictEqual(adminFence.isAdminPath("/admin"), true);
      assert.strictEqual(adminFence.isAdminPath("/admin/"), true);
      assert.strictEqual(adminFence.isAdminPath("/admin/settings"), true);
      assert.strictEqual(adminFence.isAdminPath("/admin/api/mtls-ca/regenerate"), true);
    });

    it("fails closed when the router did not supply a pathname", function () {
      // Treated as admin-scoped rather than waved through, so a request the
      // fence cannot classify is refused rather than exempted.
      var req = mkReq("/admin", "203.0.113.5");
      delete req.pathname;
      var out = run(adminFence.create(ALLOWED), req);
      assert.strictEqual(out.passed, false, "an unclassifiable request must be fenced, not exempted");
      assert.strictEqual(out.res.statusCode, 404);
    });
  });

  describe("the operator's CIDR list", function () {
    it("refuses to build on a malformed entry instead of dropping it", function () {
      // Silently discarding the bad entry leaves a hole in a fence the operator
      // believes is closed.
      assert.throws(function () { adminFence.create(["10.0.0.0/8", "not-a-cidr"]); },
        /malformed entry/i);
      assert.throws(function () { adminFence.create(["10.0.0.0/99"]); },
        /malformed entry/i);
    });

    it("names the offending entry so it can be found", function () {
      try {
        adminFence.create(["10.0.0.0/8", "banana"]);
        assert.fail("should have thrown");
      } catch (e) {
        assert.match(e.message, /"banana"/, "the error must quote the bad entry: " + e.message);
      }
    });

    it("accepts a bare address by treating it as a single host", function () {
      // Written without a mask it used to match nothing at all, not even itself.
      var fence = adminFence.create(["10.1.2.3"]);
      assert.strictEqual(run(fence, mkReq("/admin", "10.1.2.3")).passed, true,
        "a bare address must at least match itself");
      assert.strictEqual(run(fence, mkReq("/admin", "10.1.2.4")).passed, false);
    });

    it("is off by default — an empty list is never mounted", function () {
      // server-main.js only builds the fence when the list is non-empty, so an
      // empty list must not compile to something that refuses everything.
      assert.deepStrictEqual(adminFence.compile([]), []);
      assert.ok(!Array.isArray(config.adminAllowedCidrs) || config.adminAllowedCidrs.length === 0,
        "the default deployment ships no admin fence");
    });
  });
});
