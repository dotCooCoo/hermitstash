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
    // Versioned asset URLs use {{{ }}} raw output (trusted, server-built paths).
    // (The brand logo moved to escaped {{ }} — see the A5 hardening suite below.)
    assert.ok(html.includes('href="/css/style.css?v=1"'));
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

describe("template XSS hardening (A5)", function () {
  var base = {
    brand: { siteName: "T", logo: "/x", logoDark: "/d", logoColor: "/c", version: "1", github: { stars: null, behindLatest: false, latestVersion: "", repoUrl: "#", releaseUrl: "#" } },
    assets: { css: "/css/s.css?v=1", js: "/js/a.js?v=1", apiJs: "/a.js", vaultPq: "/v.js", helpers: "/h.js", webauthn: "/w.js", favicon16: "/f", favicon32: "/f", appleTouchIcon: "/a", manifest: "/m", ogImage: "/o", themeColor: "#000" },
    site: { origin: "https://ok.example", announcement: "", maintenance: false, themeAccentColor: "", themeBgColor: "", themeFont: "", showMaintainerSupport: false, analyticsScript: "" },
    user: null, csrfToken: "x", nonce: "n", apiKey: "",
    maxSize: 1, maxBundleSize: 1, maxFiles: 1, uploadConcurrency: 1, uploadRetries: 1, uploadTimeout: 1,
    dropTitle: "t", dropSubtitle: "s", vaultEnabled: false, allowedExtensions: ["pdf"], vaultPublicKey: null,
  };
  function pub(extra) { return Object.assign({}, base, extra); }

  it("script-context JSON escapes </script> so an admin allowedExtensions can't DOM-XSS the public page", function () {
    var html = render("public-upload", pub({ allowedExtensions: ["pdf", "</script><img src=x onerror=alert(1)>"] }));
    assert.ok(!html.includes("</script><img src=x onerror=alert(1)>"), "raw breakout must not appear");
    assert.ok(html.includes("\\u003c/script\\u003e"), "the < must be unicode-escaped inside the inline script");
  });

  it("escapes an admin logo path in the img src attribute (attribute XSS)", function () {
    var html = render("public-upload", pub({ brand: Object.assign({}, base.brand, { logoColor: 'x" onerror="alert(1)' }) }));
    assert.ok(!/src="x" onerror="alert\(1\)"/.test(html), "must not break out of the src attribute");
  });

  it("drops a non-color theme accent (CSS-context injection)", function () {
    var html = render("public-upload", pub({ site: Object.assign({}, base.site, { themeAccentColor: "red;}body{visibility:hidden" }) }));
    assert.ok(!/--main-color:\s*red;\}body/.test(html), "malicious CSS must be dropped by the color guard");
  });

  it("renders a valid hex theme accent unchanged", function () {
    var html = render("public-upload", pub({ site: Object.assign({}, base.site, { themeAccentColor: "#8B5CF6" }) }));
    assert.ok(/--main-color:\s*#8B5CF6/.test(html), "a valid hex color must render");
  });

  it("escapes an admin rpOrigin in the canonical/og:url attributes", function () {
    var html = render("public-upload", pub({ site: Object.assign({}, base.site, { origin: 'https://x" onerror=alert(1)' }) }));
    assert.ok(!/content="https:\/\/x" onerror=alert\(1\)>/.test(html), "rpOrigin must not break out of the attribute");
  });

  it("emits the session apiKey through the script-context serializer (JSON-quoted, </script> escaped)", function () {
    var html = render("public-upload", pub({ apiKey: 'k</script><img src=x onerror=alert(1)>' }));
    assert.ok(!html.includes("k</script><img src=x onerror=alert(1)>"), "raw breakout must not appear in the inline script");
    assert.ok(html.includes("\\u003c/script\\u003e"), "the </script> must be unicode-escaped inside window.__ak");
    // The serializer emits its own JSON quotes — assignment is bare, not "{{apiKey}}".
    assert.ok(/window\.__ak="k\\u003c\/script\\u003e/.test(html), "window.__ak is assigned the JSON string directly");
  });

  it("round-trips a normal base64url apiKey unchanged through __scriptJson", function () {
    var key = "abcXYZ_-0123456789";
    var html = render("public-upload", pub({ apiKey: key }));
    assert.ok(html.includes('window.__ak="' + key + '"'), "a base64url key renders as window.__ak=\"<key>\"");
  });
});
