require("../helpers/isolate-db"); // must precede every HermitStash require
const { describe, it } = require("node:test");
const assert = require("node:assert");

// _safeCspSource validates each admin-supplied analytics host before it is
// concatenated into the CSP header. A CSP source-expression is a single token,
// so a value containing the directive separator `;` or whitespace would splice
// a new directive/source into the policy (CSP injection — A5-2). Valid hosts
// must survive; anything that could break out of a source token must be dropped.
var { _safeCspSource } = require("../../middleware/security-headers");
var securityHeaders = require("../../middleware/security-headers");
var b = require("../../lib/vendor/blamejs");

describe("security-headers _safeCspSource (A5-2 CSP injection guard)", function () {
  it("drops a value carrying a directive separator (;)", function () {
    assert.strictEqual(_safeCspSource("evil.com; script-src https://attacker.example"), null);
  });

  it("drops a value carrying whitespace", function () {
    assert.strictEqual(_safeCspSource("evil.com script-src"), null);
  });

  it("drops a value carrying quotes or angle brackets", function () {
    assert.strictEqual(_safeCspSource('a"b.com'), null);
    assert.strictEqual(_safeCspSource("a<b.com"), null);
  });

  it("drops a bare keyword with no host (no dot)", function () {
    assert.strictEqual(_safeCspSource("javascript"), null);
    assert.strictEqual(_safeCspSource(""), null);
    assert.strictEqual(_safeCspSource(null), null);
  });

  it("keeps a valid host and normalizes to an https origin", function () {
    assert.strictEqual(_safeCspSource("cdn.example.com"), "https://cdn.example.com");
    assert.strictEqual(_safeCspSource(" analytics.example.com "), "https://analytics.example.com");
  });

  it("preserves an explicit scheme, port, path, and wildcard host", function () {
    assert.strictEqual(_safeCspSource("https://a.example.com:8443/path"), "https://a.example.com:8443/path");
    assert.strictEqual(_safeCspSource("*.example.com"), "https://*.example.com");
    assert.strictEqual(_safeCspSource("http://plausible.example.com"), "http://plausible.example.com");
  });
});

describe("security-headers relies on the b.requestHelpers.appendVary contract", function () {
  function mockRes(initial) {
    var headers = {};
    Object.keys(initial).forEach(function (k) { headers[k.toLowerCase()] = initial[k]; });
    return {
      setHeader: function (k, v) { headers[String(k).toLowerCase()] = v; },
      getHeader: function (k) { return headers[String(k).toLowerCase()]; },
      removeHeader: function (k) { delete headers[String(k).toLowerCase()]; },
      writeHead: function () { return this; },
    };
  }
  function respond(initial, pathname) {
    var req = { method: "GET", url: pathname, pathname: pathname, headers: { host: "localhost" },
      socket: { remoteAddress: "127.0.0.1" } };
    var res = mockRes(initial);
    securityHeaders(req, res, function () {});
    res.writeHead(200);
    return res;
  }

  it("appendVary adds a token once and keeps the tokens already there", function () {
    var res = mockRes({ Vary: "Origin" });
    b.requestHelpers.appendVary(res, "Cookie");
    b.requestHelpers.appendVary(res, "cookie");
    assert.strictEqual(res.getHeader("Vary"), "Origin, Cookie");
  });

  it("appendVary leaves a lone * in place", function () {
    var res = mockRes({ Vary: "*" });
    b.requestHelpers.appendVary(res, "Cookie");
    assert.strictEqual(res.getHeader("Vary"), "*");
  });

  it("a no-store response carries Vary: Cookie after a Vary another layer set", function () {
    var res = respond({ Vary: "Origin" }, "/dashboard");
    assert.strictEqual(res.getHeader("Cache-Control"), "no-store, no-cache, must-revalidate, private");
    assert.strictEqual(res.getHeader("Vary"), "Origin, Cookie");
  });

  it("a response whose route set Cache-Control gets no Vary from this middleware", function () {
    var res = respond({ "Cache-Control": "public, max-age=60" }, "/x");
    assert.strictEqual(res.getHeader("Vary"), undefined);
  });
});
