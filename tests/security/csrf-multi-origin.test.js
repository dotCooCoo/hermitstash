// The CSRF origin gate accepts a declared SET of origins, not one.
//
// A deployment reachable on more than one hostname — a LAN name alongside a
// tailnet MagicDNS name — had every state-changing request from the second one
// refused with a 403, because the gate compared the browser's Origin against
// config.rpOrigin alone. CORS_ORIGINS did not help: it governs who may READ a
// response, and the CSRF gate is a separate refusal further along.
//
// The risk in widening it is obvious, so the test that matters most here is the
// negative one: an origin the operator did NOT declare must still be rejected.
// A gate that accepts everything passes every positive case in this file.

require("../helpers/isolate-db");
const { describe, it } = require("node:test");
const assert = require("node:assert");

process.env.HERMITSTASH_SESSION_DB = "test-csrf-multiorigin-"
  + require("crypto").randomBytes(4).toString("hex") + ".db";

process.env.RP_ORIGIN = "https://files.example.com";
process.env.ADDITIONAL_ORIGINS =
  "http://umbrel.local:3081, https://box.tail1a2b3c.ts.net";

var originPolicy = require("../../app/security/origin-policy");
var { csrfMiddleware } = require("../../app/security/csrf-policy");
var config = require("../../lib/config");

// Drive the REAL middleware. Re-implementing its comparison here is what would
// let this test pass while the shipped gate did something else — the exact
// failure mode a security regression test exists to prevent. The route is a
// JSON POST, the branch where the Origin check is the primary CSRF defense.
function accepts(origin) {
  var passed = false;
  var status = null;
  var req = {
    method: "POST",
    pathname: "/admin/settings",          // not exempt; a real state-changing path
    headers: { "content-type": "application/json", origin: origin },
    session: {},
  };
  var res = {
    statusCode: 200,
    headersSent: false,
    setHeader: function () {},
    getHeader: function () { return null; },
    writeHead: function (s) { status = s; return res; },
    end: function () { return res; },
    json: function (body) { status = status || res.statusCode; return body; },
    status: function (s) { status = s; return res; },
  };
  csrfMiddleware(req, res, function () { passed = true; });
  // Reaching next() is the decision under test: a rejected request never does,
  // and emits a 403 through the error responder instead. `status` is captured
  // only to keep a failure message informative.
  void status;
  return passed;
}

describe("CSRF origin gate — multi-origin acceptance", function () {

  it("accepts the canonical origin", function () {
    assert.strictEqual(accepts("https://files.example.com"), true);
  });

  it("accepts a declared additional origin", function () {
    assert.strictEqual(accepts("http://umbrel.local:3081"), true,
      "the LAN hostname the operator declared should be able to change state");
    assert.strictEqual(accepts("https://box.tail1a2b3c.ts.net"), true,
      "the tailnet MagicDNS name the operator declared should too");
  });

  // The one that matters. Everything above passes on a gate that accepts all.
  it("still rejects an origin nobody declared", function () {
    assert.strictEqual(accepts("https://evil.example.net"), false);
    assert.strictEqual(accepts("http://evil.example.net"), false);
  });

  it("rejects a near-miss on scheme, port or host", function () {
    // Same host, wrong scheme — a plain-HTTP forger must not inherit the
    // HTTPS origin's acceptance.
    assert.strictEqual(accepts("http://files.example.com"), false);
    // Same host, wrong port.
    assert.strictEqual(accepts("http://umbrel.local:9999"), false);
    // Declared host as a prefix of an attacker's.
    assert.strictEqual(accepts("https://files.example.com.evil.net"), false);
    // Declared host as a subdomain target — no implicit subdomain trust.
    assert.strictEqual(accepts("https://sub.files.example.com"), false);
  });

  it("rejects a malformed or non-http Origin", function () {
    // Each canonicalizes to "", which is filtered out of the accepted set, so
    // "" can never match "" and let a garbage Origin through.
    assert.strictEqual(accepts("javascript:alert(1)"), false);
    assert.strictEqual(accepts("not a url"), false);
    assert.strictEqual(accepts("file:///etc/passwd"), false);
    assert.strictEqual(accepts("://"), false);
  });

  it("canonicalizes both sides — case, trailing dot and trailing slash match", function () {
    assert.strictEqual(accepts("https://FILES.EXAMPLE.COM"), true, "case");
    assert.strictEqual(accepts("https://files.example.com."), true, "trailing dot");
    assert.strictEqual(accepts("https://files.example.com/"), true, "trailing slash");
    assert.strictEqual(accepts("https://files.example.com:443"), true, "explicit default port");
  });

  it("keeps getOrigin() single-valued", function () {
    // Pinned deliberately. absoluteUrl, share links, verification emails and the
    // sitemap each need exactly one origin; a later refactor that made this
    // multi-valued would make those URLs depend on list order.
    var one = originPolicy.getOrigin();
    assert.strictEqual(typeof one, "string");
    assert.strictEqual(one, "https://files.example.com");
    assert.ok(!Array.isArray(one));
  });

  it("includes the canonical origin first in the accepted set", function () {
    var set = originPolicy.acceptedOrigins();
    assert.ok(Array.isArray(set));
    assert.strictEqual(set[0], originPolicy.getOrigin());
    assert.strictEqual(set.length, 3);
  });
});

describe("CSRF origin gate — with no additional origins declared", function () {
  // Behavior must be identical to the single-origin gate for every deployment
  // that does not set the new option, which is nearly all of them. The accepted
  // set is then exactly one entry, and the gate is what it always was.
  it("collapses to the canonical origin alone", function () {
    var saved = config.additionalOrigins;
    config.additionalOrigins = [];
    try {
      var set = originPolicy.acceptedOrigins();
      assert.deepStrictEqual(set, ["https://files.example.com"],
        "with nothing declared the accepted set is just rpOrigin");
      assert.strictEqual(accepts("https://files.example.com"), true);
      assert.strictEqual(accepts("http://umbrel.local:3081"), false,
        "an origin is not accepted merely because another deployment declared it");
      assert.strictEqual(accepts("https://evil.example.net"), false);
    } finally {
      config.additionalOrigins = saved;
    }
  });

  it("survives the setting being absent entirely, not just empty", function () {
    var saved = config.additionalOrigins;
    delete config.additionalOrigins;
    try {
      assert.deepStrictEqual(originPolicy.acceptedOrigins(), ["https://files.example.com"]);
      assert.strictEqual(accepts("https://evil.example.net"), false);
    } finally {
      config.additionalOrigins = saved;
    }
  });
});
