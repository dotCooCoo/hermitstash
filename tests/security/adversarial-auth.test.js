var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;

before(async function () { await testServer.start(); client = new TestClient(testServer.baseUrl()); });
after(function () { return testServer.stop(); });

// ---------------------------------------------------------------
// Seed users: first registered user is admin, second is regular
// ---------------------------------------------------------------
var testId = Date.now().toString(36);
var adminEmail = "admin-adv-" + testId + "@test.com";
var regularEmail = "regular-adv-" + testId + "@test.com";
var strongPassword = "Str0ng!Pass_" + testId;

describe("adversarial auth and authorization", function () {

  // Pre-seed admin + regular user for later tests
  before(async function () {
    // First user becomes admin
    client.clearCookies();
    await client.initApiKey();
    await client.post("/auth/register", {
      json: { displayName: "Admin User", email: adminEmail, password: strongPassword },
    });
    client.clearCookies();
    await client.initApiKey();

    // Second user is regular
    await client.post("/auth/register", {
      json: { displayName: "Regular User", email: regularEmail, password: strongPassword },
    });
    client.clearCookies();
    await client.initApiKey();
  });

  // =============================================================
  // SESSION ATTACKS
  // =============================================================
  describe("session attacks", function () {

    // 1. Tampered session cookie
    it("tampered session cookie 'fake.tampered' redirects from dashboard", async function () {
      client.clearCookies();
      await client.initApiKey();
      client.cookies["hs_sid"] = "fake.tampered";
      var res = await client.get("/dashboard");
      assert.strictEqual(res.status, 302, "tampered cookie must yield redirect");
      assert.strictEqual(res.location, "/auth/login");
    });

    // 2. Very long cookie value (100KB) - server or Node HTTP parser may
    //    reject oversized headers with a connection reset, but the server
    //    must not crash (i.e. it stays up and serves the next request).
    it("100KB cookie value does not crash the server", async function () {
      client.clearCookies();
      await client.initApiKey();
      var longVal = "a".repeat(100 * 1024);
      client.cookies["hs_sid"] = longVal;
      var errorThrown = false;
      try {
        var res = await client.get("/dashboard");
        // If the request completes, it should not be a 500
        assert.notStrictEqual(res.status, 500, "must not return 500");
      } catch (e) {
        // Connection reset is acceptable — Node's HTTP parser rejects
        // headers exceeding the default 16KB limit before our code runs.
        errorThrown = true;
        assert.strictEqual(e.code, "ECONNRESET", "expected ECONNRESET from oversized header");
      }

      // Verify the server is still alive by making a normal request
      client.clearCookies();
      await client.initApiKey();
      var healthCheck = await client.get("/drop");
      assert.strictEqual(healthCheck.status, 200, "server must still respond after oversized cookie");
    });

    // 3. Session persists across requests with valid cookie
    it("valid session persists across multiple requests", async function () {
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/login", {
        json: { email: adminEmail, password: strongPassword },
      });
      var res1 = await client.get("/dashboard");
      assert.strictEqual(res1.status, 200, "first dashboard hit must succeed");
      var res2 = await client.get("/dashboard");
      assert.strictEqual(res2.status, 200, "second dashboard hit must succeed");
    });

    // 4. Session invalidated after logout
    it("session is invalidated after logout", async function () {
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/login", {
        json: { email: adminEmail, password: strongPassword },
      });
      var dashBefore = await client.get("/dashboard");
      assert.strictEqual(dashBefore.status, 200, "dashboard accessible before logout");

      // HS hardened /auth/logout to POST-only with CSRF token validation;
      // GET no longer logs the user out. Fetch the session's _csrf token
      // (cookies are URL-encoded in TestClient.cookies, decode before
      // passing to b.session.verify via lib/session.getSessionData) and
      // submit the form-encoded logout per the documented pattern.
      var sessions = require(path.join(testServer.projectRoot, "lib", "session"));
      var hsSidCookie = client.cookies && client.cookies["hs_sid"];
      var token = hsSidCookie ? decodeURIComponent(hsSidCookie) : null;
      var sessData = token ? await sessions.getSessionData(token) : null;
      var csrf = sessData && sessData._csrf;
      assert.ok(csrf, "session should carry a _csrf token");
      await client.post("/auth/logout", {
        body: "_csrf=" + encodeURIComponent(csrf),
        contentType: "application/x-www-form-urlencoded",
      });

      var dashAfter = await client.get("/dashboard");
      assert.strictEqual(dashAfter.status, 302, "dashboard must redirect after logout");
    });

    // 5. Session ID rotates on login (fixation prevention)
    it("session ID rotates on login", async function () {
      client.clearCookies();
      await client.initApiKey();

      // Hit any page to get a pre-login session cookie
      var prePage = await client.get("/auth/login");
      var preLoginCookie = client.cookies["hs_sid"];
      assert.ok(preLoginCookie, "should have a session cookie before login");

      // Login
      await client.post("/auth/login", {
        json: { email: adminEmail, password: strongPassword },
      });
      var postLoginCookie = client.cookies["hs_sid"];
      assert.ok(postLoginCookie, "should have a session cookie after login");
      assert.notStrictEqual(postLoginCookie, preLoginCookie, "session cookie must change after login");

      client.clearCookies();
      await client.initApiKey();
    });

    // 6. Empty cookie value for hs_sid
    it("empty hs_sid cookie does not crash, creates new session", async function () {
      client.clearCookies();
      await client.initApiKey();
      client.cookies["hs_sid"] = "";
      var res = await client.get("/dashboard");
      assert.strictEqual(res.status, 302, "should redirect unauthenticated user");
      assert.notStrictEqual(res.status, 500, "must not crash");
    });
  });

  // =============================================================
  // AUTH BYPASS
  // =============================================================
  describe("auth bypass", function () {

    // 7. /admin without login
    it("GET /admin without login redirects", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.get("/admin");
      // requireAdmin renders a 403 error page when no user, so it can be 302 or 403
      // From the code: requireAdmin checks !req.user || req.user.role !== "admin"
      // When no user is set, it returns 403 with error page
      assert.strictEqual(res.status, 403, "admin without login returns 403");
    });

    // 8. /dashboard without login
    it("GET /dashboard without login redirects", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.get("/dashboard");
      assert.strictEqual(res.status, 302, "dashboard without login must redirect");
      assert.strictEqual(res.location, "/auth/login");
    });

    // 9. POST /files/:shareId/delete without login
    // CSRF policy fires before the auth-redirect path for unauthenticated
    // POSTs without a valid token — 403 is the documented outcome. The
    // legacy permissive-CSRF posture returned 302; either gate is
    // acceptable as "refuses unauthenticated mutating request".
    it("POST /files/:shareId/delete without login is refused", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/files/fakeshare/delete");
      assert.ok(res.status === 302 || res.status === 403,
        "file delete without login must redirect (302) or be CSRF-refused (403), got " + res.status);
    });

    // 10. GET /admin/settings without login
    it("GET /admin/settings without login is blocked", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.get("/admin/settings");
      assert.strictEqual(res.status, 403, "admin settings without login returns 403");
    });
  });

  // =============================================================
  // PRIVILEGE ESCALATION
  // =============================================================
  describe("privilege escalation", function () {

    before(async function () {
      // Login as regular user for all priv-esc tests
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/login", {
        json: { email: regularEmail, password: strongPassword },
      });
    });

    // 11. Regular user POST /admin/users/:id/role
    it("regular user cannot POST /admin/users/:id/role", async function () {
      var res = await client.post("/admin/users/someid/role");
      assert.strictEqual(res.status, 403, "role toggle must be admin-only");
    });

    // 12. Regular user POST /admin/settings
    it("regular user cannot POST /admin/settings", async function () {
      var res = await client.post("/admin/settings", {
        json: { siteName: "Hacked" },
      });
      assert.strictEqual(res.status, 403, "settings update must be admin-only");
    });

    // 13. Regular user GET /admin
    it("regular user cannot GET /admin", async function () {
      var res = await client.get("/admin");
      assert.strictEqual(res.status, 403, "admin page must be admin-only");
    });

    // 14. Regular user POST /admin/files/:shareId/delete
    it("regular user cannot POST /admin/files/:shareId/delete", async function () {
      var res = await client.post("/admin/files/fakeshare/delete");
      assert.strictEqual(res.status, 403, "admin file delete must be admin-only");
    });

    // 15. Regular user POST /admin/bundles/:shareId/delete
    it("regular user cannot POST /admin/bundles/:shareId/delete", async function () {
      var res = await client.post("/admin/bundles/fakeshare/delete");
      assert.strictEqual(res.status, 403, "admin bundle delete must be admin-only");
    });
  });

  // =============================================================
  // REGISTRATION EDGE CASES
  // =============================================================
  describe("registration edge cases", function () {

    // 16. Uppercase email registration, then lowercase login
    it("email is case-insensitive (register uppercase, login lowercase)", async function () {
      client.clearCookies();
      await client.initApiKey();
      var upperEmail = "CASEUPPER" + testId + "@TEST.COM";
      var lowerEmail = upperEmail.toLowerCase();
      var res = await client.post("/auth/register", {
        json: { displayName: "CaseTest", email: upperEmail, password: strongPassword },
      });
      assert.strictEqual(res.json.success, true, "registration with uppercase email must succeed");

      // Logout and login with lowercase
      client.clearCookies();
      await client.initApiKey();
      var loginRes = await client.post("/auth/login", {
        json: { email: lowerEmail, password: strongPassword },
      });
      assert.strictEqual(loginRes.json.success, true, "login with lowercase email must succeed");
    });

    // 17. Email with leading/trailing whitespace
    it("email with whitespace is handled correctly", async function () {
      client.clearCookies();
      await client.initApiKey();
      var baseEmail = "spaced" + testId + "@test.com";
      // Register with clean email first
      var regRes = await client.post("/auth/register", {
        json: { displayName: "Spacer", email: baseEmail, password: strongPassword },
      });
      assert.strictEqual(regRes.json.success, true, "registration must succeed");

      // Try to register again with whitespace-padded version
      client.clearCookies();
      await client.initApiKey();
      var dupeRes = await client.post("/auth/register", {
        json: { displayName: "Spacer2", email: "  " + baseEmail + "  ", password: strongPassword },
      });
      // The system lowercases but may not trim; either it rejects as dupe
      // or it creates a new account. Either way it must not crash.
      assert.notStrictEqual(dupeRes.status, 500, "whitespace email must not crash");
    });

    // 18. Password exactly 8 characters (boundary)
    it("password of exactly 8 characters is accepted", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/auth/register", {
        json: { displayName: "Boundary", email: "pw8-" + testId + "@test.com", password: "12345678" },
      });
      assert.strictEqual(res.json.success, true, "8-char password must be accepted");
    });

    // 19. Password of 7 characters is rejected
    it("password of 7 characters is rejected", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/auth/register", {
        json: { displayName: "Short", email: "pw7-" + testId + "@test.com", password: "1234567" },
      });
      assert.strictEqual(res.status, 400, "7-char password must be rejected");
      assert.ok(res.json.detail.includes("8"), "error must mention minimum length");
    });

    // 20. Empty displayName
    it("empty displayName is rejected", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/auth/register", {
        json: { displayName: "", email: "noname-" + testId + "@test.com", password: strongPassword },
      });
      assert.strictEqual(res.status, 400, "empty displayName must be rejected");
    });

    // 21. Duplicate email
    it("duplicate email is rejected with 'already registered'", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/auth/register", {
        json: { displayName: "Dupe", email: adminEmail, password: strongPassword },
      });
      assert.ok(res.status === 400 || res.status === 409, "duplicate email must be rejected with 400 or 409, got " + res.status);
      assert.ok(res.json.detail.includes("already registered"), "error must say 'already registered'");
    });
  });

  // =============================================================
  // LOGIN EDGE CASES
  // =============================================================
  describe("login edge cases", function () {

    // 22. Missing email field
    it("login with missing email field returns 400", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/auth/login", {
        json: { password: strongPassword },
      });
      assert.strictEqual(res.status, 400, "missing email must yield 400");
      assert.strictEqual(res.json.detail, "Email and password required.");
    });

    // 23. Missing password field
    it("login with missing password field returns 400", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/auth/login", {
        json: { email: adminEmail },
      });
      assert.strictEqual(res.status, 400, "missing password must yield 400");
      assert.strictEqual(res.json.detail, "Email and password required.");
    });

    // 24. Email as number instead of string — the server coerces via
    //     String(), so the number becomes "12345", lookup fails, and
    //     it returns 401. The server must not crash.
    it("login with numeric email does not crash", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/auth/login", {
        json: { email: 12345, password: "password123" },
      });
      assert.strictEqual(res.status, 401, "numeric email coerced to string, user not found");
      assert.strictEqual(res.json.detail, "Invalid email or password.");
    });

    // 25. Null body — CSRF blocks before body-parse path; HS rejects
    // unauthenticated POST without csrf token at the security middleware
    // layer, not at the body validator. Either response is acceptable
    // (the request never reaches the route handler with an empty body).
    it("login with null body returns 400 or 403", async function () {
      client.clearCookies();
      await client.initApiKey();
      // Send empty string as body with JSON content-type
      var res = await client.post("/auth/login", {
        body: "",
        contentType: "application/json",
      });
      assert.ok(res.status === 400 || res.status === 403,
        "null/empty body must yield 400 (validator) or 403 (CSRF), got " + res.status);
    });
  });

  // =============================================================
  // IDOR (Insecure Direct Object Reference)
  // =============================================================
  describe("IDOR", function () {
    var victimFileShareId;

    // 26 & 27: Set up a file owned by user A, then test cross-user access
    before(async function () {
      // Login as admin (user A) and create a file via drop
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/login", {
        json: { email: adminEmail, password: strongPassword },
      });
      var init = await client.post("/drop/init", {
        json: {
          uploaderName: "Admin",
          uploaderEmail: adminEmail,
          fileCount: 1,
          skippedCount: 0,
          skippedFiles: [],
        },
      });
      await client.uploadFile(
        "/drop/file/" + init.json.bundleId,
        "file", "idor-test.txt", "idor-content",
        { relativePath: "idor-test.txt" }
      );
      await client.post("/drop/finalize/" + init.json.bundleId, { json: { finalizeToken: init.json.finalizeToken } });

      // Get the file shareId from DB (shareId and bundleShareId are sealed; use hash lookup)
      var projectRoot = testServer.projectRoot;
      var vault = require(path.join(projectRoot, "lib", "vault"));
      var { sha3Hash } = require(path.join(projectRoot, "lib", "crypto"));
      var { files } = require(path.join(projectRoot, "lib", "db"));
      var allFiles = files.find({ bundleShareIdHash: sha3Hash("hs-share:" + init.json.shareId) });
      victimFileShareId = allFiles.length > 0 ? vault.unseal(allFiles[0].shareId) : null;

      client.clearCookies();
      await client.initApiKey();
    });

    // 26. User B cannot delete User A's file
    it("user B cannot delete user A's file", async function () {
      assert.ok(victimFileShareId, "test setup must have produced a file shareId");

      // Login as regular user (user B)
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/login", {
        json: { email: regularEmail, password: strongPassword },
      });

      // POST with JSON body so the request routes through the session-
      // encrypted JSON path (no CSRF token needed — session encryption
      // is the protection on that path). Form POSTs require a _csrf
      // token, JSON POSTs do not.
      var res = await client.post("/files/" + victimFileShareId + "/delete", {
        json: {},
      });
      assert.strictEqual(res.status, 403, "user B must get 403 deleting user A's file");
      assert.strictEqual(res.json.detail || res.json.error, "Not authorized.");
    });

    // 27. User A (admin) can delete their own file
    it("user A can delete their own file", async function () {
      assert.ok(victimFileShareId, "test setup must have produced a file shareId");

      // Login as admin (user A / owner)
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/login", {
        json: { email: adminEmail, password: strongPassword },
      });

      // JSON body routes through session-encrypted JSON path; CSRF
      // token not needed.
      var res = await client.post("/files/" + victimFileShareId + "/delete", {
        json: {},
      });
      assert.strictEqual(res.status, 200, "owner must be able to delete own file");
      assert.strictEqual(res.json.success, true);
    });
  });
});
