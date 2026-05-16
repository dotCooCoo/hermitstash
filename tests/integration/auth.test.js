const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());

  // Initialize transaction helper
  var txHelper = require(path.join(testServer.projectRoot, "app", "data", "db", "transaction"));
  try { txHelper.init(require(path.join(testServer.projectRoot, "lib", "db")).getDb()); } catch (_e) {}
});

after(function () { return testServer.stop(); });

describe("auth integration", function () {
  describe("registration", function () {
    it("registers a new user with sealed PII", async function () {
      await client.initApiKey();
      var res = await client.post("/auth/register", {
        json: { displayName: "Test User", email: "test@test.com", password: "password123" },
      });
      assert.strictEqual(res.json.success, true);
      assert.strictEqual(res.json.redirect, "/dashboard");

      // Verify PII is sealed in DB (use .raw() to bypass auto-unseal)
      var vault = require(path.join(testServer.projectRoot, "lib", "vault"));
      var { users } = require(path.join(testServer.projectRoot, "lib", "db"));
      var { hashEmail } = require(path.join(testServer.projectRoot, "lib", "crypto"));
      var user = users.raw().findOne({ emailHash: hashEmail("test@test.com") });
      assert.ok(user, "user should exist");
      assert.ok(user.email.startsWith("vault:"), "email should be sealed in DB");
      assert.ok(user.displayName.startsWith("vault:"), "displayName should be sealed in DB");
      assert.strictEqual(vault.unseal(user.email), "test@test.com");
    });

    it("rejects duplicate email", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/auth/register", {
        json: { displayName: "Dupe", email: "test@test.com", password: "password123" },
      });
      assert.ok(res.status === 400 || res.status === 409, "should reject duplicate with 400 or 409, got " + res.status);
      assert.ok(res.json.error.includes("already registered"));
    });

    it("rejects short password", async function () {
      var res = await client.post("/auth/register", {
        json: { displayName: "Short", email: "short@test.com", password: "123" },
      });
      assert.strictEqual(res.status, 400);
      assert.ok(res.json.error.includes("8"));
    });

    it("rejects missing fields", async function () {
      var res = await client.post("/auth/register", {
        json: { displayName: "", email: "", password: "" },
      });
      assert.strictEqual(res.status, 400);
    });
  });

  describe("login", function () {
    it("logs in with correct credentials via emailHash lookup", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/auth/login", {
        json: { email: "test@test.com", password: "password123" },
      });
      assert.strictEqual(res.json.success, true);
    });

    it("rejects wrong password", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/auth/login", {
        json: { email: "test@test.com", password: "wrongpassword" },
      });
      assert.strictEqual(res.status, 401);
    });

    it("rejects nonexistent email", async function () {
      await client.initApiKey();
      var res = await client.post("/auth/login", {
        json: { email: "nobody@test.com", password: "password123" },
      });
      assert.strictEqual(res.status, 401);
    });
  });

  describe("email verification", function () {
    it("blocks pending users from login when verification enabled", async function () {
      // Enable verification for this test
      var config = require(path.join(testServer.projectRoot, "lib", "config"));
      var origVal = config.emailVerification;
      config.emailVerification = true;

      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/auth/register", {
        json: { displayName: "Pending User", email: "pending@test.com", password: "password123" },
      });
      assert.ok(res.json.pending, "should be pending");
      assert.ok(res.json.redirect.includes("/auth/pending"), "should redirect to pending page");

      // Try to login — should be blocked
      client.clearCookies();
      await client.initApiKey();
      var loginRes = await client.post("/auth/login", {
        json: { email: "pending@test.com", password: "password123" },
      });
      assert.strictEqual(loginRes.status, 403);
      assert.ok(loginRes.json.pending, "should indicate pending status");

      config.emailVerification = origVal;
    });

    it("verification pending page renders", async function () {
      var res = await client.get("/auth/pending");
      assert.strictEqual(res.status, 200);
      assert.ok(res.text.includes("Check your"), "should show verification message");
    });
  });

  describe("session", function () {
    it("dashboard accessible after login", async function () {
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/login", {
        json: { email: "test@test.com", password: "password123" },
      });
      var res = await client.get("/dashboard");
      assert.strictEqual(res.status, 200);
    });

    it("dashboard redirects without login", async function () {
      client.clearCookies();
      var res = await client.get("/dashboard");
      assert.strictEqual(res.status, 302);
      assert.ok(res.location.includes("/auth/login"));
    });

    it("logout clears session", async function () {
      // Logout is POST-only with CSRF validation (not GET). Extract the
      // CSRF token by directly querying the in-memory session store — more
      // robust than HTML-scraping, which depends on template details.
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/login", {
        json: { email: "test@test.com", password: "password123" },
      });
      // Confirm login actually created a session
      var dash = await client.get("/dashboard");
      assert.strictEqual(dash.status, 200, "dashboard should be 200 after login");

      // Extract CSRF token directly from the server's session store. The
      // hs_sid cookie is the framework-emitted vault:-prefixed token
      // verbatim; getSessionData accepts the URL-decoded value as-is.
      var sessions = require(path.join(testServer.projectRoot, "lib", "session"));
      var token = decodeURIComponent(client.cookies.hs_sid || "");
      assert.ok(token, "hs_sid cookie should be present after login");
      var sessData = await sessions.getSessionData(token);
      assert.ok(sessData && sessData._csrf, "session data should include _csrf token");
      var csrf = sessData._csrf;

      // POST /auth/logout with form-encoded CSRF token
      var logoutRes = await client.post("/auth/logout", {
        body: "_csrf=" + encodeURIComponent(csrf),
        contentType: "application/x-www-form-urlencoded",
      });
      assert.ok(
        logoutRes.status === 302 || logoutRes.status === 200,
        "logout should succeed, got " + logoutRes.status + " " + logoutRes.text
      );
      // Dashboard should now redirect (session cleared)
      var res = await client.get("/dashboard");
      assert.strictEqual(res.status, 302, "dashboard should redirect when logged out");
    });

    it("session cookie is ML-KEM-768 encrypted (large)", async function () {
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/login", {
        json: { email: "test@test.com", password: "password123" },
      });
      var cookieVal = client.cookies.hs_sid || "";
      var decoded = decodeURIComponent(cookieVal);
      assert.ok(decoded.length > 500, "cookie should be large (ML-KEM ciphertext), got: " + decoded.length);
    });
  });

  describe("admin guard", function () {
    it("first user is admin", async function () {
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/login", {
        json: { email: "test@test.com", password: "password123" },
      });
      var res = await client.get("/admin");
      assert.strictEqual(res.status, 200);
    });

    it("non-admin gets 403", async function () {
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/register", {
        json: { displayName: "Regular", email: "reg@test.com", password: "password123" },
      });
      var res = await client.get("/admin");
      assert.strictEqual(res.status, 403);
    });
  });

  describe("passkey endpoints", function () {
    it("login options endpoint returns challenge", async function () {
      await client.initApiKey();
      var res = await client.post("/passkey/login/options", { json: {} });
      assert.ok(res.json.challenge, "should return challenge");
      assert.strictEqual(res.json.rpId, "localhost");
    });

    it("register options requires auth", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/passkey/register/options", { json: {} });
      // Should redirect to login (requireAuth)
      assert.strictEqual(res.status, 302);
    });

    it("passkey list requires auth", async function () {
      client.clearCookies();
      var res = await client.get("/passkey/list");
      assert.strictEqual(res.status, 302);
    });

    it("authenticated user can list passkeys", async function () {
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/login", { json: { email: "test@test.com", password: "password123" } });
      var res = await client.get("/passkey/list");
      assert.ok(res.json.passkeys !== undefined, "should return passkeys array");
      assert.strictEqual(res.json.passkeyEnabled, true);
    });
  });
});
