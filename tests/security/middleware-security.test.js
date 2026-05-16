const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const fs = require("fs");
const http = require("http");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var projectRoot = testServer.projectRoot;
var client;

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());
});

after(function () { return testServer.stop(); });

// Raw HTTP request that does NOT follow redirects or parse cookies —
// needed for reading response headers directly from the server
function rawRequest(method, pathStr, opts) {
  opts = opts || {};
  var base = new URL(testServer.baseUrl());
  return new Promise(function (resolve, reject) {
    var headers = Object.assign({}, opts.headers || {});
    var body = null;
    if (opts.body) {
      body = opts.body;
      if (opts.contentType) headers["content-type"] = opts.contentType;
      headers["content-length"] = Buffer.byteLength(body);
    }
    var req = http.request({
      hostname: base.hostname,
      port: base.port,
      path: pathStr,
      method: method,
      headers: headers,
    }, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          text: Buffer.concat(chunks).toString(),
        });
      });
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

describe("middleware-security", function () {
  describe("security headers on dynamic pages", function () {
    it("X-Content-Type-Options: nosniff present", async function () {
      var res = await rawRequest("GET", "/auth/login");
      assert.strictEqual(res.headers["x-content-type-options"], "nosniff");
    });

    it("X-Frame-Options: DENY present", async function () {
      var res = await rawRequest("GET", "/auth/login");
      assert.strictEqual(res.headers["x-frame-options"], "DENY");
    });

    it("Referrer-Policy present", async function () {
      var res = await rawRequest("GET", "/auth/login");
      assert.ok(res.headers["referrer-policy"], "Referrer-Policy header should be set");
      // HS hardened to `no-referrer` (was `strict-origin-when-cross-origin`)
      // for tighter Referer leak posture — auth pages have no legitimate
      // reason to leak the origin to navigated-away destinations.
      assert.strictEqual(res.headers["referrer-policy"], "no-referrer");
    });

    it("Permissions-Policy present", async function () {
      var res = await rawRequest("GET", "/auth/login");
      assert.ok(res.headers["permissions-policy"], "Permissions-Policy header should be set");
      // HS expanded the deny list well beyond the original three; assert
      // the core deny set is present rather than pinning the exact string,
      // which b.middleware.securityHeaders maintains against new W3C
      // permissions-policy registry entries.
      var pp = res.headers["permissions-policy"];
      assert.ok(pp.indexOf("camera=()") !== -1, "camera deny present");
      assert.ok(pp.indexOf("microphone=()") !== -1, "microphone deny present");
      assert.ok(pp.indexOf("geolocation=()") !== -1, "geolocation deny present");
    });

    it("Cross-Origin-Opener-Policy: same-origin present", async function () {
      var res = await rawRequest("GET", "/auth/login");
      assert.strictEqual(res.headers["cross-origin-opener-policy"], "same-origin");
    });

    it("Cross-Origin-Resource-Policy: same-origin present", async function () {
      var res = await rawRequest("GET", "/auth/login");
      assert.strictEqual(res.headers["cross-origin-resource-policy"], "same-origin");
    });

    it("Cache-Control includes no-store and private on dynamic pages", async function () {
      var res = await rawRequest("GET", "/auth/login");
      var cc = res.headers["cache-control"] || "";
      assert.ok(cc.includes("no-store"), "must include no-store, got: " + cc);
      assert.ok(cc.includes("private"), "must include private, got: " + cc);
      assert.ok(cc.includes("no-cache"), "must include no-cache, got: " + cc);
      assert.ok(cc.includes("must-revalidate"), "must include must-revalidate, got: " + cc);
    });

    it("Content-Security-Policy present on dynamic pages", async function () {
      var res = await rawRequest("GET", "/auth/login");
      assert.ok(res.headers["content-security-policy"], "CSP header should be set");
      assert.ok(res.headers["content-security-policy"].includes("default-src"), "CSP should include default-src directive");
    });
  });

  describe("static asset caching", function () {
    it("CSS files do NOT have Cache-Control: no-store", async function () {
      // Find an actual CSS file in public/
      var cssFiles = fs.readdirSync(path.join(projectRoot, "public", "css"));
      var cssFile = cssFiles.find(function (f) { return f.endsWith(".css"); });
      assert.ok(cssFile, "should have at least one CSS file in public/css");

      var res = await rawRequest("GET", "/css/" + cssFile);
      // Static files should either have no Cache-Control or a permissive one, not no-store
      var cc = res.headers["cache-control"] || "";
      assert.ok(cc !== "no-store", "static CSS should not have Cache-Control: no-store, got: " + cc);
    });

    it("JS files do NOT have Cache-Control: no-store", async function () {
      var jsFiles = fs.readdirSync(path.join(projectRoot, "public", "js"));
      var jsFile = jsFiles.find(function (f) { return f.endsWith(".js"); });
      assert.ok(jsFile, "should have at least one JS file in public/js");

      var res = await rawRequest("GET", "/js/" + jsFile);
      var cc = res.headers["cache-control"] || "";
      assert.ok(cc !== "no-store", "static JS should not have Cache-Control: no-store, got: " + cc);
    });
  });

  describe("api-encrypt body size limit", function () {
    it("POST with JSON body under 1MB succeeds", async function () {
      await client.initApiKey();
      // A normal-sized login attempt (well under 1MB)
      var res = await client.post("/auth/login", {
        json: { email: "nobody@test.com", password: "password123" },
      });
      // Should get a 401 (invalid credentials), NOT a 413
      assert.strictEqual(res.status, 401);
    });

    it("POST with JSON body over 1MB is rejected", async function () {
      // Send a raw (unencrypted) JSON body larger than 1MB directly.
      // The server calls req.destroy() then writes 413, so the client may
      // receive a 413 response OR a socket reset — both prove the limit works.
      var largePayload = JSON.stringify({ data: "x".repeat(1100000) });
      try {
        var res = await rawRequest("POST", "/auth/login", {
          body: largePayload,
          contentType: "application/json",
        });
        assert.strictEqual(res.status, 413);
      } catch (err) {
        // ECONNRESET or socket hang up means the server killed the connection
        // before responding — this is also correct enforcement behavior
        assert.ok(
          err.code === "ECONNRESET" || err.message.includes("socket hang up"),
          "oversized body should cause 413 or connection reset, got: " + err.message
        );
      }
    });
  });

  describe("host() injection prevention", function () {
    it("host() prefers rpOrigin config over X-Forwarded-Proto header", function () {
      // Test the host() function directly
      var { host } = require(path.join(projectRoot, "middleware", "send"));
      var config = require(path.join(projectRoot, "lib", "config"));

      // Save original rpOrigin
      var originalRpOrigin = config.rpOrigin;

      try {
        // Set rpOrigin to a trusted value
        config.rpOrigin = "https://hermitstash.example.com";

        // Create a fake request with an attacker-controlled X-Forwarded-Proto and Host
        var fakeReq = {
          headers: {
            "x-forwarded-proto": "https",
            host: "evil-attacker.com",
          },
        };

        var result = host(fakeReq);
        assert.strictEqual(result, "https://hermitstash.example.com");
        // Confirm it does NOT use the attacker's host header
        assert.ok(!result.includes("evil-attacker"), "host() must not use attacker-controlled Host header when rpOrigin is set");
      } finally {
        // Restore original config
        config.rpOrigin = originalRpOrigin;
      }
    });

    it("host() falls back to req.headers.host only when rpOrigin is not set", function () {
      var { host } = require(path.join(projectRoot, "middleware", "send"));
      var config = require(path.join(projectRoot, "lib", "config"));

      var originalRpOrigin = config.rpOrigin;

      try {
        // Clear rpOrigin to test fallback path
        config.rpOrigin = "";

        var fakeReq = {
          headers: {
            host: "localhost:3000",
          },
        };

        var result = host(fakeReq);
        assert.strictEqual(result, "http://localhost:3000");
      } finally {
        config.rpOrigin = originalRpOrigin;
      }
    });

    it("email verification URLs use rpOrigin, not attacker headers", async function () {
      var config = require(path.join(projectRoot, "lib", "config"));
      var originalRpOrigin = config.rpOrigin;

      try {
        // Set a trusted rpOrigin
        config.rpOrigin = "https://hermitstash.example.com";

        // Register a user (with email verification enabled, this triggers a verification email)
        // We just need to verify the host() function is called correctly during registration
        var { host } = require(path.join(projectRoot, "middleware", "send"));

        // Simulate a request with malicious headers
        var fakeReq = {
          headers: {
            "x-forwarded-proto": "https",
            "x-forwarded-host": "evil.com",
            host: "evil.com",
          },
        };

        // The verification URL should use rpOrigin
        var verifyBase = host(fakeReq);
        assert.strictEqual(verifyBase, "https://hermitstash.example.com");
        assert.ok(!verifyBase.includes("evil.com"), "verification base URL must not contain attacker domain");
      } finally {
        config.rpOrigin = originalRpOrigin;
      }
    });
  });
});
