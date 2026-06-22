const { describe, it } = require("node:test");
const assert = require("node:assert");

// _safeCspSource validates each admin-supplied analytics host before it is
// concatenated into the CSP header. A CSP source-expression is a single token,
// so a value containing the directive separator `;` or whitespace would splice
// a new directive/source into the policy (CSP injection — A5-2). Valid hosts
// must survive; anything that could break out of a source token must be dropped.
var { _safeCspSource } = require("../../middleware/security-headers");

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
