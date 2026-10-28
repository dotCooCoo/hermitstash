/**
 * admin.validator safeLogoUrl (the stash logo URL check in routes/stash.js):
 * an admin-supplied logo URL is a same-origin path or an https:// URL, decided
 * on the URL a browser resolves.
 */
var { describe, it } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var safeLogoUrl = require(path.join(__dirname, "..", "..", "app", "http", "validators", "admin.validator")).safeLogoUrl;
var BACKSLASH = String.fromCharCode(92);

describe("safeLogoUrl", function () {
  it("keeps a same-origin path and an https URL", function () {
    assert.strictEqual(safeLogoUrl("/logos/acme.png"), "/logos/acme.png");
    assert.strictEqual(safeLogoUrl("/logos/acme.png?v=2"), "/logos/acme.png?v=2");
    assert.strictEqual(safeLogoUrl("https://cdn.example.com/a.png"), "https://cdn.example.com/a.png");
  });

  it("refuses every spelling a browser resolves to another origin", function () {
    [
      "//evil.com/x.png",
      "/" + BACKSLASH + "evil.com/x.png",
      "/\t/evil.com/x.png",
      "/\n/evil.com/x.png",
      "/\r/evil.com/x.png",
      "/" + BACKSLASH + "/evil.com",
      BACKSLASH + BACKSLASH + "evil.com/x.png",
    ].forEach(function (u) {
      assert.strictEqual(safeLogoUrl(u), "", JSON.stringify(u) + " is refused");
      // the browser's own reading of the same value, to show what it would load
      var resolved = new URL(u.replace(/^\s+|\s+$/g, ""), "https://hs.example/stash/x");
      if (u !== "//evil.com/x.png" && !u.startsWith(BACKSLASH)) {
        assert.strictEqual(resolved.host, "evil.com", "the probe resolves " + JSON.stringify(u) + " off-origin");
      }
    });
  });

  it("refuses other schemes and control characters", function () {
    ["javascript:alert(1)", "data:image/png;base64,AAAA", "http://example.com/a.png", "/a\u0000.png", "/a\u007f.png"]
      .forEach(function (u) { assert.strictEqual(safeLogoUrl(u), "", JSON.stringify(u)); });
  });

  it("normalizes dot segments in a local path", function () {
    assert.strictEqual(safeLogoUrl("/logos/../logos/a.png"), "/logos/a.png");
  });

  it("refuses a path whose normalized form would start with //", function () {
    ["/a/..//evil.example/logo.png", "/./..//evil.example/x", "/a/%2e%2e//evil.example/x"].forEach(function (u) {
      assert.strictEqual(safeLogoUrl(u), "", JSON.stringify(u));
    });
  });
});
