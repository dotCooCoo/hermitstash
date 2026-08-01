var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var projectRoot = testServer.projectRoot;
var client;
var config;

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());
  config = require(path.join(projectRoot, "lib", "config"));
});

after(function () { return testServer.stop(); });

// G-1: the /privacy /terms /cookies pages render admin-authored policy bodies
// raw (unescaped) to every public visitor. An admin who pasted policy markup
// containing <script> got stored XSS executed in every browser. The three
// policy fields are now sanitized (balanced HTML profile) before render —
// legitimate formatting survives, active markup does not.
describe("legal policy pages — stored-XSS sanitization (G-1)", function () {
  it("neutralizes <script> in a privacy policy while preserving safe formatting", async function () {
    var orig = config.privacyPolicy;
    config.privacyPolicy = "<h2>Privacy</h2><p>Body <strong>bold</strong></p><script>alert('xss')</script>";
    try {
      var res = await client.get("/privacy");
      assert.strictEqual(res.status, 200);
      // Assert on the injected payload specifically — the page's own head/foot
      // chrome legitimately carries <script> tags, so a bare "<script" search
      // would be a false positive. The sanitizer drops a <script> tag AND its
      // body, so the executable marker must be gone entirely.
      assert.ok(res.text.indexOf("alert('xss')") === -1, "injected script body dropped");
      assert.ok(res.text.indexOf("<script>alert") === -1, "injected script tag not rendered");
      assert.ok(res.text.indexOf("<h2>Privacy</h2>") !== -1, "heading preserved");
      assert.ok(res.text.indexOf("<strong>bold</strong>") !== -1, "inline formatting preserved");
    } finally {
      config.privacyPolicy = orig;
    }
  });

  it("strips an event-handler attribute from a terms policy", async function () {
    var orig = config.termsOfService;
    config.termsOfService = '<p onclick="steal()">Terms text</p>';
    try {
      var res = await client.get("/terms");
      assert.strictEqual(res.status, 200);
      // Target the injected handler body — the page chrome may carry its own
      // on*-attributes, so assert the pasted handler payload is gone rather than
      // the generic "onclick" token.
      assert.ok(res.text.indexOf("steal()") === -1, "event-handler payload stripped");
      assert.ok(res.text.indexOf('onclick="steal') === -1, "event-handler attribute stripped");
      assert.ok(res.text.indexOf("Terms text") !== -1, "text content preserved");
    } finally {
      config.termsOfService = orig;
    }
  });

  it("strips a javascript: href from a cookie policy link", async function () {
    var orig = config.cookiePolicy;
    config.cookiePolicy = '<p><a href="javascript:alert(1)">click</a></p>';
    try {
      var res = await client.get("/cookies");
      assert.strictEqual(res.status, 200);
      assert.ok(res.text.indexOf("javascript:") === -1, "dangerous URL scheme stripped");
      assert.ok(res.text.indexOf("click") !== -1, "link text preserved");
    } finally {
      config.cookiePolicy = orig;
    }
  });

  it("falls back to the built-in default page when no policy is configured", async function () {
    var orig = config.cookiePolicy;
    config.cookiePolicy = "";
    try {
      var res = await client.get("/cookies");
      assert.strictEqual(res.status, 200);
      assert.ok(res.text.indexOf("hs_sid") !== -1, "default cookie page renders when policy empty");
    } finally {
      config.cookiePolicy = orig;
    }
  });
});
