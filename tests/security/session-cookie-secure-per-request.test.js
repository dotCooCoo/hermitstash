// The session cookie's Secure attribute must follow the REQUEST's own scheme,
// not a configured origin.
//
// The failure this pins is quiet and looks like a login loop rather than a bug.
// RP_ORIGIN has to be https for passkeys to work at all, and the flag used to be
// derived from it: `config.rpOrigin.startsWith("https") ? "; Secure" : ""`. A
// visitor arriving over plain HTTP — a LAN hostname, a second origin, an
// umbrel-style proxy that does not terminate TLS — was then sent a Secure
// cookie, which the browser silently declines to store. The next request carries
// no cookie, so it arrives unauthenticated, and nothing anywhere reports an
// error. Every CSRF and session assertion still passes while sign-in is broken.
//
// So RP_ORIGIN is pinned to an https value in EVERY case below. That is the
// trap: a test that also lowers RP_ORIGIN would pass against the old code.
//
// The second half is peer-gating. X-Forwarded-Proto is forgeable, so honoring it
// from an untrusted caller would let anyone mark their own cookie Secure. It is
// read only when the immediate peer is a declared trusted proxy — the same
// trusted-proxy list that resolves the client IP, deliberately shared so the two
// cannot drift apart.

require("../helpers/isolate-db");
const { describe, it, before } = require("node:test");
const assert = require("node:assert");
var http = require("http");

// The session store is its own database with a shared default name, and the
// runner runs files in parallel — set before lib/session is required, which is
// when the path resolves.
process.env.HERMITSTASH_SESSION_DB = "test-session-secure-"
  + require("crypto").randomBytes(4).toString("hex") + ".db";

// Pinned high so the assertions below cannot pass by accident: if the flag were
// still origin-derived, every case here would carry Secure.
process.env.RP_ORIGIN = "https://files.example.com";
process.env.TRUST_PROXY = "10.0.0.0/8";

var { Router } = require("../../lib/vendor/blamejs").router;
var { sessionMiddleware } = require("../../lib/session");
var clientIp = require("../../lib/client-ip");
var vault = require("../../lib/vault");

// Pull the hs_sid cookie out of a response, or null when none was set.
function sessionCookie(res) {
  var all = res.headers["set-cookie"] || [];
  return all.filter(function (c) { return c.startsWith("hs_sid="); })[0] || null;
}

// One request through the real middleware chain, with arbitrary headers.
function request(headers, cb) {
  var app = new Router();
  app.use(sessionMiddleware);
  app.get("/t", function (req, res) { res.json({ ok: true }); });
  var server = app.listen(0, function () {
    http.get({
      hostname: "127.0.0.1", port: server.address().port, path: "/t", headers: headers || {},
    }, function (res) {
      res.resume();
      var cookie = sessionCookie(res);
      server.close(function () { cb(cookie); });
    });
  });
}

describe("session cookie Secure flag follows the request, not the configured origin", function () {
  before(async function () {
    await vault.init();
  });

  it("omits Secure on a plain-HTTP request even though RP_ORIGIN is https", function (_, done) {
    request({}, function (cookie) {
      assert.ok(cookie, "a session cookie should still be set");
      assert.ok(
        !/;\s*Secure/i.test(cookie),
        "plain HTTP must not get Secure — the browser would discard the cookie and the "
        + "next request would arrive unauthenticated. Got: " + cookie);
      done();
    });
  });

  it("still sets the other hardening attributes when Secure is absent", function (_, done) {
    request({}, function (cookie) {
      // Dropping Secure must not quietly drop the rest with it.
      assert.match(cookie, /;\s*HttpOnly/i, "HttpOnly missing: " + cookie);
      assert.match(cookie, /;\s*SameSite=Lax/i, "SameSite missing: " + cookie);
      assert.match(cookie, /;\s*Path=\//, "Path missing: " + cookie);
      done();
    });
  });

  // The peer-gated cases are asserted against the resolver directly, because an
  // HTTP server bound to loopback cannot present any other peer address — and
  // loopback is a trusted forwarder by default. Driving them through the server
  // would test that default rather than the gate, and the "untrusted" case would
  // silently assert the opposite of what it claims.
  it("ignores X-Forwarded-Proto from an untrusted peer", function () {
    // The request really did arrive in the clear; a caller claiming otherwise
    // must not be able to choose its own cookie attributes.
    var forged = {
      headers: { "x-forwarded-proto": "https" },
      socket: { encrypted: false, remoteAddress: "203.0.113.9" },
    };
    assert.strictEqual(clientIp.isSecureRequest(forged), false,
      "a forged X-Forwarded-Proto from an untrusted peer must not mark the cookie Secure");
  });

  it("honors X-Forwarded-Proto from a declared trusted proxy", function () {
    var viaProxy = {
      headers: { "x-forwarded-proto": "https" },
      socket: { encrypted: false, remoteAddress: "10.0.0.5" },
    };
    assert.strictEqual(clientIp.isSecureRequest(viaProxy), true,
      "a trusted proxy's forwarded scheme should be believed");
  });

  it("believes a direct TLS socket with no forwarded header", function () {
    var direct = { headers: {}, socket: { encrypted: true, remoteAddress: "203.0.113.9" } };
    assert.strictEqual(clientIp.isSecureRequest(direct), true);
  });

  it("does not treat an absent request as secure", function () {
    // Fail closed: no request means no evidence of TLS.
    assert.strictEqual(clientIp.isSecureRequest(null), false);
    assert.strictEqual(clientIp.isSecureRequest(undefined), false);
  });
});
