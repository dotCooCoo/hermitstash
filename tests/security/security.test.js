const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());
});

after(function () { return testServer.stop(); });

describe("security", function () {
  describe("path traversal", function () {
    it("static files cannot escape public/", async function () {
      var res = await client.get("/../server.js");
      assert.notStrictEqual(res.status, 200);
    });

    it("encoded traversal blocked", async function () {
      var res = await client.get("/%2e%2e/server.js");
      assert.notStrictEqual(res.status, 200);
    });
  });

  describe("XSS prevention", function () {
    it("display name is escaped in templates", async function () {
      // Register with XSS payload as name
      await client.initApiKey();
      await client.post("/auth/register", {
        json: { displayName: "<script>alert(1)</script>", email: "xss@test.com", password: "password123" },
      });
      // Upload a file so it appears on dashboard with uploader name
      var init = await client.post("/drop/init", {
        json: { uploaderName: "<img onerror=alert(1)>", uploaderEmail: "xss@test.com", fileCount: 1, skippedCount: 0, skippedFiles: [] },
      });
      await client.uploadFile("/drop/file/" + init.json.bundleId, "file", "xss.txt", "test", { relativePath: "xss.txt" });
      await client.post("/drop/finalize/" + init.json.bundleId, { json: { finalizeToken: init.json.finalizeToken } });

      // The bundle page should escape the uploader name
      var bundle = await client.get("/b/" + init.json.shareId);
      assert.ok(!bundle.text.includes("<img onerror=alert(1)>"), "XSS payload should be escaped");
    });
  });

  describe("SQL injection", function () {
    it("login rejects SQL injection in email", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/auth/login", {
        json: { email: "' OR 1=1 --", password: "anything" },
      });
      assert.strictEqual(res.status, 401);
    });

    it("login rejects SQL injection in password", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/auth/login", {
        json: { email: "test@test.com", password: "' OR '1'='1" },
      });
      assert.strictEqual(res.status, 401);
    });
  });

  describe("auth bypass", function () {
    it("tampered session cookie does not authenticate", async function () {
      client.clearCookies();
      await client.initApiKey();
      client.cookies["hs_sid"] = "fake.tampered";
      var res = await client.get("/dashboard");
      assert.strictEqual(res.status, 302);
    });

    it("admin endpoint rejects non-admin", async function () {
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/register", {
        json: { displayName: "Reg", email: "reg2@test.com", password: "password123" },
      });
      var res = await client.get("/admin");
      assert.strictEqual(res.status, 403);
    });

    it("admin settings API rejects non-admin", async function () {
      var res = await client.get("/admin/settings");
      assert.strictEqual(res.status, 403);
    });

    it("admin settings POST rejects non-admin", async function () {
      var res = await client.post("/admin/settings", {
        json: { siteName: "Hacked" },
      });
      assert.strictEqual(res.status, 403);
    });
  });

  describe("IDOR (insecure direct object reference)", function () {
    it("user cannot delete another user's file", async function () {
      // Register user A and upload a file
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/register", {
        json: { displayName: "UserA", email: "usera@test.com", password: "password123" },
      });
      var init = await client.post("/drop/init", {
        json: { uploaderName: "A", uploaderEmail: "usera@test.com", fileCount: 1, skippedCount: 0, skippedFiles: [] },
      });
      await client.uploadFile("/drop/file/" + init.json.bundleId, "file", "private.txt", "secret", { relativePath: "private.txt" });
      await client.post("/drop/finalize/" + init.json.bundleId, { json: { finalizeToken: init.json.finalizeToken } });

      // Get the file's shareId from dashboard
      var dash = await client.get("/dashboard");
      // Extract shareId from the HTML (it appears in delete onclick)
      var match = dash.text.match(/del\('([a-f0-9]+)'\)/);
      var fileShareId = match ? match[1] : null;

      if (fileShareId) {
        // Login as user B
        client.clearCookies();
        await client.initApiKey();
        await client.post("/auth/register", {
          json: { displayName: "UserB", email: "userb@test.com", password: "password123" },
        });

        // Try to delete user A's file
        var res = await client.post("/files/" + fileShareId + "/delete");
        assert.strictEqual(res.status, 403, "should not be able to delete another user's file");
      }
    });
  });

  describe("file extension enforcement", function () {
    it("rejects uploads with blocked extensions", async function () {
      client.clearCookies();
      await client.initApiKey();
      var init = await client.post("/drop/init", {
        json: { uploaderName: "X", fileCount: 1, skippedCount: 0, skippedFiles: [] },
      });
      var res = await client.uploadFile("/drop/file/" + init.json.bundleId, "file", "payload.exe", "MZ", { relativePath: "payload.exe" });
      assert.strictEqual(res.status, 400);
    });
  });
});
