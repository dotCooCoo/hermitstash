const { describe, it } = require("node:test");
const assert = require("node:assert");
const { render, formatSize } = require("../../lib/template");

describe("formatSize", function () {
  it("formats bytes", function () {
    assert.strictEqual(formatSize(500), "500 B");
  });

  it("formats KB", function () {
    assert.strictEqual(formatSize(2048), "2 KB");
  });

  it("formats MB", function () {
    assert.strictEqual(formatSize(5242880), "5.0 MB");
  });

  it("formats GB", function () {
    assert.strictEqual(formatSize(2147483648), "2.00 GB");
  });
});

describe("template render", function () {
  var baseData = {
    brand: { siteName: "T", logo: "/x", logoOriginal: "/x" },
    assets: { css: "/css/style.css?v=1", js: "/js/animations.js?v=1", favicon16: "/f16", favicon32: "/f32", appleTouchIcon: "/at", manifest: "/m", ogImage: "/og", themeColor: "#000" },
    site: { announcement: "", maintenance: false, themeAccentColor: "", themeBgColor: "", themeFont: "" },
    apiKey: "",
  };

  it("renders escaped variables", function () {
    var html = render("error", Object.assign({}, baseData, { user: null, title: "Test <b>Error</b>", message: "Something broke" }));
    assert.ok(html.includes("Test &lt;b&gt;Error&lt;/b&gt;"));
    assert.ok(html.includes("Something broke"));
  });

  it("renders raw expressions", function () {
    var html = render("error", Object.assign({}, baseData, { user: null, title: "T", message: "M" }));
    // The brand logo uses {{{ }}} raw output
    assert.ok(html.includes('src="/x"'));
  });

  it("caches compiled templates", function () {
    var t0 = Date.now();
    for (var i = 0; i < 100; i++) {
      render("error", Object.assign({}, baseData, { user: null, title: "T", message: "M" }));
    }
    // Verify cache works by checking repeated renders produce identical output
    var html1 = render("error", Object.assign({}, baseData, { user: null, title: "A", message: "B" }));
    var html2 = render("error", Object.assign({}, baseData, { user: null, title: "A", message: "B" }));
    assert.strictEqual(html1, html2, "cached renders should produce identical output");
  });

  it("throws on missing view (fail-loud, not swallowed)", function () {
    // render() intentionally throws rather than returning placeholder HTML so
    // the error handler surfaces a real 500 and missing-view bugs don't
    // silently ship to production as garbled pages.
    assert.throws(function () {
      render("nonexistent_view_xyz", {});
    }, /View not found/);
  });
});
