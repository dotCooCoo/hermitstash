var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var crypto = require("crypto");
var b = require("../../lib/vendor/blamejs");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());

  // Seed admin user directly via db (with sealed PII)
  var b = require(path.join(testServer.projectRoot, "lib", "vendor", "blamejs"));
  var hashPassword = function (p) { return b.auth.password.hash(String(p)); };
  var vault = require(path.join(testServer.projectRoot, "lib", "vault"));
  var { hashEmail } = require(path.join(testServer.projectRoot, "lib", "crypto"));
  var { users } = require(path.join(testServer.projectRoot, "lib", "db"));
  var hash = await hashPassword("adminpass123");
  users.insert({
    email: vault.seal("admin@test.com"),
    emailHash: hashEmail("admin@test.com"),
    displayName: vault.seal("Admin"),
    passwordHash: hash,
    authType: "local",
    role: "admin",
    status: "active",
    createdAt: new Date().toISOString(),
    lastLogin: new Date().toISOString(),
  });

  // Initialize transaction helper
  var txHelper = require(path.join(testServer.projectRoot, "app", "data", "db", "transaction"));
  try { txHelper.init(require(path.join(testServer.projectRoot, "lib", "db")).getDb()); } catch (_e) {}
});

after(function () { return testServer.stop(); });

// ── Helper: log in as admin and return client with session ──
async function loginAsAdmin() {
  client.clearCookies();
  await client.initApiKey();
  var res = await client.post("/auth/login", {
    json: { email: "admin@test.com", password: "adminpass123" },
  });
  assert.strictEqual(res.json.success, true);
  return client;
}

// ── Helper: reset rate limits (call when needed between many registrations) ──
function resetRateLimits() {
  testServer.resetAllRateLimits();
}

describe("user management integration", function () {

  // ═══════════════════════════════════════════════════
  // ADMIN USER CRUD
  // ═══════════════════════════════════════════════════
  describe("admin user CRUD", function () {

    // 1. Create alice via public registration (the main test user)
    it("creates alice via registration", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/auth/register", {
        json: { displayName: "Alice", email: "alice@test.com", password: "password123" },
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);
    });

    // 2. Duplicate email rejected at registration
    it("rejects duplicate email", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/auth/register", {
        json: { displayName: "Alice Dupe", email: "alice@test.com", password: "password123" },
      });
      // 409 Conflict is the accurate status for "already exists"; 400 was the
      // old response before the error-handler migration. Accept either so the
      // test is forward-compatible with the more-correct status.
      assert.ok(res.status === 400 || res.status === 409, "duplicate email should be 400 or 409, got " + res.status);
      assert.ok(/already registered/i.test(res.json.detail || res.json.error), "error should mention already registered, got: " + (res.json.detail || res.json.error));
    });

    // 3. Short password rejected at registration
    it("rejects short password", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/auth/register", {
        json: { displayName: "Short", email: "short@test.com", password: "abc" },
      });
      assert.strictEqual(res.status, 400);
      assert.ok((res.json.detail || res.json.error || "").includes("8"));
    });

    // 4. Missing fields rejected at registration
    it("rejects missing fields", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/auth/register", {
        json: { displayName: "", email: "", password: "" },
      });
      assert.strictEqual(res.status, 400);
      assert.ok((res.json.detail || res.json.error || "").includes("required"));
    });

    // 5. List users via /admin/users/api
    it("lists users via API with total and email field", async function () {
      await loginAsAdmin();
      var res = await client.get("/admin/users/api");
      assert.strictEqual(res.status, 200);
      assert.ok(res.json.total >= 2);
      assert.ok(Array.isArray(res.json.users));
      // Every user object must have an email field
      for (var i = 0; i < res.json.users.length; i++) {
        assert.ok(typeof res.json.users[i].email === "string");
      }
    });

    // 6. Search users via /admin/users/api?q=searchterm
    it("searches users by query string", async function () {
      await loginAsAdmin();
      var res = await client.get("/admin/users/api?q=alice");
      assert.strictEqual(res.status, 200);
      assert.ok(res.json.total >= 1);
      // All returned users must match the search term in email or displayName
      for (var i = 0; i < res.json.users.length; i++) {
        var u = res.json.users[i];
        var matchesEmail = u.email.toLowerCase().includes("alice");
        var matchesName = u.displayName.toLowerCase().includes("alice");
        assert.ok(matchesEmail || matchesName);
      }
    });

    // 7. Filter by role via /admin/users/api?role=admin
    it("filters users by role", async function () {
      await loginAsAdmin();
      var res = await client.get("/admin/users/api?role=admin");
      assert.strictEqual(res.status, 200);
      assert.ok(res.json.total >= 1);
      for (var i = 0; i < res.json.users.length; i++) {
        assert.strictEqual(res.json.users[i].role, "admin");
      }
    });

    // 8. Filter by status via /admin/users/api?status=active
    it("filters users by status", async function () {
      await loginAsAdmin();
      var res = await client.get("/admin/users/api?status=active");
      assert.strictEqual(res.status, 200);
      assert.ok(res.json.total >= 1);
      for (var i = 0; i < res.json.users.length; i++) {
        assert.strictEqual(res.json.users[i].status, "active");
      }
    });

    // 9. Suspend user
    it("suspends a user and verifies status via API", async function () {
      await loginAsAdmin();
      // Find Alice's ID
      var list = await client.get("/admin/users/api?q=alice");
      var aliceId = list.json.users[0]._id;

      var res = await client.post("/admin/users/" + aliceId + "/suspend", {
        json: {},
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);

      // Verify status is suspended via API
      var check = await client.get("/admin/users/api?q=alice");
      var alice = check.json.users.find(function (u) { return u._id === aliceId; });
      assert.strictEqual(alice.status, "suspended");
    });

    // 10. Suspended user cannot log in
    it("suspended user cannot log in", async function () {
      client.clearCookies();
      await client.initApiKey();
      // Suspended user login returns 403
      var res = await client.post("/auth/login", {
        json: { email: "alice@test.com", password: "password123" },
      });
      assert.strictEqual(res.status, 403);
    });

    // 11. Unsuspend user
    it("unsuspends a user and they can log in again", async function () {
      await loginAsAdmin();
      var list = await client.get("/admin/users/api?q=alice");
      var aliceId = list.json.users[0]._id;

      var res = await client.post("/admin/users/" + aliceId + "/unsuspend", {
        json: {},
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);

      // Alice can now log in and access dashboard
      client.clearCookies();
      await client.initApiKey();
      var login = await client.post("/auth/login", {
        json: { email: "alice@test.com", password: "password123" },
      });
      assert.strictEqual(login.json.success, true);
      var dash = await client.get("/dashboard");
      assert.strictEqual(dash.status, 200);
    });

    // 12. Delete user (create a throwaway via registration, then delete via admin)
    it("deletes a user and they no longer appear in API", async function () {
      // Create a throwaway user via registration
      client.clearCookies();
      await client.initApiKey();
      resetRateLimits();
      await client.post("/auth/register", {
        json: { displayName: "ToDelete", email: "todelete@test.com", password: "password123" },
      });

      // Admin deletes the user
      await loginAsAdmin();
      var list = await client.get("/admin/users/api?q=todelete");
      assert.strictEqual(list.json.total, 1);
      var userId = list.json.users[0]._id;

      var res = await client.post("/admin/users/" + userId + "/delete", {
        json: {},
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);

      // Verify user no longer appears
      var check = await client.get("/admin/users/api?q=todelete");
      assert.strictEqual(check.json.total, 0);
    });

    // 13. Delete user reassigns files
    it("deleting a user reassigns their files to deleted", async function () {
      // Create user via registration
      client.clearCookies();
      await client.initApiKey();
      resetRateLimits();
      await client.post("/auth/register", {
        json: { displayName: "FileOwner", email: "fileowner@test.com", password: "password123" },
      });

      // Look up user ID via admin API
      await loginAsAdmin();
      var list = await client.get("/admin/users/api?q=fileowner");
      var ownerId = list.json.users[0]._id;

      // Insert a file record directly via db, owned by this user
      var { files } = require(path.join(testServer.projectRoot, "lib", "db"));
      var vault = require(path.join(testServer.projectRoot, "lib", "vault"));
      var { hashEmail } = require(path.join(testServer.projectRoot, "lib", "crypto"));
      var fileShareId = b.crypto.generateToken(4);
      files.insert({
        shareId: fileShareId,
        originalName: "testfile.pdf",
        storagePath: "",
        mimeType: "application/pdf",
        size: 1024,
        uploadedBy: ownerId,
        uploaderEmail: vault.seal("fileowner@test.com"),
        emailHash: hashEmail("fileowner@test.com"),
        downloads: 0,
        status: "complete",
        createdAt: new Date().toISOString(),
      });

      // Delete the user
      var res = await client.post("/admin/users/" + ownerId + "/delete", {
        json: {},
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);
      assert.ok(res.json.filesReassigned >= 1);

      // Verify file still exists with uploadedBy "deleted"
      var fileDoc = files.findOne({ shareId: fileShareId });
      assert.ok(fileDoc !== null);
      assert.strictEqual(fileDoc.uploadedBy, "deleted");
      var unsealed = vault.unseal(fileDoc.uploaderName) || fileDoc.uploaderName;
      assert.ok(unsealed.includes("(deleted)"), "uploaderName should contain (deleted), got: " + unsealed);
    });
  });

  // ═══════════════════════════════════════════════════
  // LAST ADMIN PROTECTION
  // ═══════════════════════════════════════════════════
  describe("last admin protection", function () {

    // 14. Cannot demote last admin
    it("cannot demote the last admin", async function () {
      await loginAsAdmin();
      // Find the admin user
      var list = await client.get("/admin/users/api?role=admin");
      var adminId = list.json.users[0]._id;

      var res = await client.post("/admin/users/" + adminId + "/role", {
        json: {},
      });
      assert.strictEqual(res.status, 400);
      assert.ok((res.json.detail || res.json.error).includes("Cannot remove the last admin"));
    });

    // 15. Cannot suspend last admin
    it("cannot suspend the last admin", async function () {
      await loginAsAdmin();
      var list = await client.get("/admin/users/api?role=admin");
      var adminId = list.json.users[0]._id;

      var res = await client.post("/admin/users/" + adminId + "/suspend", {
        json: {},
      });
      assert.strictEqual(res.status, 400);
      assert.ok((res.json.detail || res.json.error).includes("Cannot suspend the last admin"));
    });

    // 16. Cannot delete last admin
    it("cannot delete the last admin", async function () {
      await loginAsAdmin();
      var list = await client.get("/admin/users/api?role=admin");
      var adminId = list.json.users[0]._id;

      var res = await client.post("/admin/users/" + adminId + "/delete", {
        json: {},
      });
      assert.strictEqual(res.status, 400);
      assert.ok((res.json.detail || res.json.error).includes("Cannot delete the last admin"));
    });

    // 17. With 2 admins, CAN demote one
    it("with two admins, can demote one", async function () {
      // Create a second admin via direct DB insert
      var { users } = require(path.join(testServer.projectRoot, "lib", "db"));
      var b = require(path.join(testServer.projectRoot, "lib", "vendor", "blamejs"));
  var hashPassword = function (p) { return b.auth.password.hash(String(p)); };
      var vault = require(path.join(testServer.projectRoot, "lib", "vault"));
      var { hashEmail } = require(path.join(testServer.projectRoot, "lib", "crypto"));
      var hash = await hashPassword("password123");
      var admin2 = users.insert({
        email: vault.seal("admin2@test.com"),
        emailHash: hashEmail("admin2@test.com"),
        displayName: vault.seal("Admin2"),
        passwordHash: hash,
        authType: "local",
        role: "admin",
        status: "active",
        createdAt: new Date().toISOString(),
        lastLogin: new Date().toISOString(),
      });

      await loginAsAdmin();
      var admin2Id = admin2._id;

      // Demote admin2
      var res = await client.post("/admin/users/" + admin2Id + "/role", {
        json: {},
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);
      assert.strictEqual(res.json.newRole, "user");

      // Clean up: delete admin2
      await client.post("/admin/users/" + admin2Id + "/delete", { json: {} });
    });
  });

  // ═══════════════════════════════════════════════════
  // PROFILE SELF-SERVICE
  // ═══════════════════════════════════════════════════
  describe("profile self-service", function () {

    // 18. User can view own profile
    it("user can view own profile", async function () {
      // Log in as Alice
      client.clearCookies();
      await client.initApiKey();
      resetRateLimits();
      await client.post("/auth/login", {
        json: { email: "alice@test.com", password: "password123" },
      });
      var res = await client.get("/profile");
      assert.strictEqual(res.status, 200);
    });

    // 19. User can update display name
    it("user can update display name", async function () {
      client.clearCookies();
      await client.initApiKey();
      resetRateLimits();
      await client.post("/auth/login", {
        json: { email: "alice@test.com", password: "password123" },
      });
      var res = await client.post("/profile/update", {
        json: { displayName: "Alice Updated" },
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);

      // Verify via profile page (should contain new name)
      var profile = await client.get("/profile");
      assert.strictEqual(profile.status, 200);
      assert.ok(profile.text.includes("Alice Updated"));
    });

    // 20. User can change password (and change it back to keep later tests working)
    it("user can change password and login with new password", async function () {
      client.clearCookies();
      await client.initApiKey();
      resetRateLimits();
      await client.post("/auth/login", {
        json: { email: "alice@test.com", password: "password123" },
      });
      var res = await client.post("/profile/password", {
        json: { currentPassword: "password123", newPassword: "newpassword456" },
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);

      // Log out and log in with new password
      client.clearCookies();
      await client.initApiKey();
      resetRateLimits();
      var login = await client.post("/auth/login", {
        json: { email: "alice@test.com", password: "newpassword456" },
      });
      assert.strictEqual(login.json.success, true);

      // Change password BACK so subsequent tests keep working with password123
      var revert = await client.post("/profile/password", {
        json: { currentPassword: "newpassword456", newPassword: "password123" },
      });
      assert.strictEqual(revert.status, 200);
      assert.strictEqual(revert.json.success, true);
    });

    // 21. Wrong current password rejected
    it("rejects wrong current password", async function () {
      client.clearCookies();
      await client.initApiKey();
      resetRateLimits();
      await client.post("/auth/login", {
        json: { email: "alice@test.com", password: "password123" },
      });
      var res = await client.post("/profile/password", {
        json: { currentPassword: "totallyWrong", newPassword: "something123" },
      });
      assert.strictEqual(res.status, 401);
      assert.ok((res.json.detail || res.json.error || "").includes("Current password is incorrect"));
    });

    // 22. New password too short
    it("rejects new password that is too short", async function () {
      client.clearCookies();
      await client.initApiKey();
      resetRateLimits();
      await client.post("/auth/login", {
        json: { email: "alice@test.com", password: "password123" },
      });
      var res = await client.post("/profile/password", {
        json: { currentPassword: "password123", newPassword: "short" },
      });
      assert.strictEqual(res.status, 400);
      assert.ok((res.json.detail || res.json.error || "").includes("8"));
    });

    // 23. Google OAuth user cannot change password
    it("google OAuth user cannot change password", async function () {
      // Insert a Google-authed user directly into the DB
      var { users } = require(path.join(testServer.projectRoot, "lib", "db"));
      var b = require(path.join(testServer.projectRoot, "lib", "vendor", "blamejs"));
  var hashPassword = function (p) { return b.auth.password.hash(String(p)); };
      var hash = await hashPassword("placeholder123");
      var vault = require(path.join(testServer.projectRoot, "lib", "vault"));
      var { hashEmail } = require(path.join(testServer.projectRoot, "lib", "crypto"));
      var googleUser = users.insert({
        email: vault.seal("googleuser@test.com"),
        emailHash: hashEmail("googleuser@test.com"),
        displayName: vault.seal("Google User"),
        passwordHash: hash,
        authType: "google",
        googleId: vault.seal("google-fake-id-12345"),
        role: "user",
        status: "active",
        createdAt: new Date().toISOString(),
        lastLogin: new Date().toISOString(),
      });

      // Log in via local auth (password hash exists), then hit the endpoint.
      client.clearCookies();
      await client.initApiKey();
      resetRateLimits();
      var login = await client.post("/auth/login", {
        json: { email: "googleuser@test.com", password: "placeholder123" },
      });
      assert.strictEqual(login.json.success, true);

      var res = await client.post("/profile/password", {
        json: { currentPassword: "placeholder123", newPassword: "newgooglepass123" },
      });
      assert.strictEqual(res.status, 400);
      assert.ok((res.json.detail || res.json.error || "").includes("local accounts"));

      // Clean up
      users.remove({ _id: googleUser._id });
    });

    // 24. User can delete own account
    it("user can delete own account", async function () {
      // Create a disposable user via registration
      client.clearCookies();
      await client.initApiKey();
      resetRateLimits();
      await client.post("/auth/register", {
        json: { displayName: "SelfDelete", email: "selfdelete@test.com", password: "password123" },
      });

      var res = await client.post("/profile/delete", {
        json: { confirm: "DELETE" },
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);
      assert.strictEqual(res.json.redirect, "/");

      // Login should fail now
      client.clearCookies();
      await client.initApiKey();
      resetRateLimits();
      var login = await client.post("/auth/login", {
        json: { email: "selfdelete@test.com", password: "password123" },
      });
      assert.strictEqual(login.status, 401);
    });
  });

  // ═══════════════════════════════════════════════════
  // PREVENTING BAD BEHAVIOR
  // ═══════════════════════════════════════════════════
  describe("preventing bad behavior", function () {

    // 25. Regular user cannot access /admin/users
    it("regular user cannot access /admin/users", async function () {
      client.clearCookies();
      await client.initApiKey();
      resetRateLimits();
      // Register a regular user
      await client.post("/auth/register", {
        json: { displayName: "RegUser", email: "reguser@test.com", password: "password123" },
      });
      var res = await client.get("/admin/users");
      assert.strictEqual(res.status, 403);
    });

    // 26. Regular user cannot access /admin/users/api
    it("regular user cannot access /admin/users/api", async function () {
      client.clearCookies();
      await client.initApiKey();
      resetRateLimits();
      await client.post("/auth/login", {
        json: { email: "reguser@test.com", password: "password123" },
      });
      var res = await client.get("/admin/users/api");
      assert.strictEqual(res.status, 403);
    });

    // 27. Regular user cannot invite users
    it("regular user cannot invite users", async function () {
      client.clearCookies();
      await client.initApiKey();
      resetRateLimits();
      await client.post("/auth/login", {
        json: { email: "reguser@test.com", password: "password123" },
      });
      var res = await client.post("/admin/users/invite", {
        json: { email: "hacker@test.com", role: "user" },
      });
      assert.strictEqual(res.status, 403);
    });

    // 28. Regular user cannot suspend users
    it("regular user cannot suspend users", async function () {
      client.clearCookies();
      await client.initApiKey();
      resetRateLimits();
      await client.post("/auth/login", {
        json: { email: "reguser@test.com", password: "password123" },
      });
      // Use alice's ID (look up via admin API from within the test setup)
      var { users } = require(path.join(testServer.projectRoot, "lib", "db"));
      var { hashEmail } = require(path.join(testServer.projectRoot, "lib", "crypto"));
      var alice = users.findOne({ emailHash: hashEmail("alice@test.com") });
      assert.ok(alice, "alice must exist for this test");
      var res = await client.post("/admin/users/" + alice._id + "/suspend", {
        json: {},
      });
      assert.strictEqual(res.status, 403);
    });

    // 29. Regular user cannot delete other users via admin route
    it("regular user cannot delete other users via admin route", async function () {
      client.clearCookies();
      await client.initApiKey();
      resetRateLimits();
      await client.post("/auth/login", {
        json: { email: "reguser@test.com", password: "password123" },
      });
      var { users } = require(path.join(testServer.projectRoot, "lib", "db"));
      var { hashEmail } = require(path.join(testServer.projectRoot, "lib", "crypto"));
      var alice = users.findOne({ emailHash: hashEmail("alice@test.com") });
      assert.ok(alice, "alice must exist for this test");
      var res = await client.post("/admin/users/" + alice._id + "/delete", {
        json: {},
      });
      assert.strictEqual(res.status, 403);
    });

    // 30. Regular user cannot change another user's role
    it("regular user cannot change another user's role", async function () {
      client.clearCookies();
      await client.initApiKey();
      resetRateLimits();
      await client.post("/auth/login", {
        json: { email: "reguser@test.com", password: "password123" },
      });
      var { users } = require(path.join(testServer.projectRoot, "lib", "db"));
      var { hashEmail } = require(path.join(testServer.projectRoot, "lib", "crypto"));
      var alice = users.findOne({ emailHash: hashEmail("alice@test.com") });
      assert.ok(alice, "alice must exist for this test");
      var res = await client.post("/admin/users/" + alice._id + "/role", {
        json: {},
      });
      assert.strictEqual(res.status, 403);
    });

    // 31. User cannot delete own account without typing DELETE
    it("user cannot delete own account without typing DELETE", async function () {
      client.clearCookies();
      await client.initApiKey();
      resetRateLimits();
      await client.post("/auth/login", {
        json: { email: "reguser@test.com", password: "password123" },
      });
      var res = await client.post("/profile/delete", {
        json: { confirm: "nope" },
      });
      assert.strictEqual(res.status, 400);
      assert.ok((res.json.detail || res.json.error || "").includes("DELETE"));
    });

    // 32. User profile update with empty name
    it("rejects profile update with empty display name", async function () {
      client.clearCookies();
      await client.initApiKey();
      resetRateLimits();
      await client.post("/auth/login", {
        json: { email: "reguser@test.com", password: "password123" },
      });
      var res = await client.post("/profile/update", {
        json: { displayName: "" },
      });
      assert.strictEqual(res.status, 400);
      assert.ok((res.json.detail || res.json.error || "").includes("required"));
    });

    // 33. Suspended user's session is cleared
    it("suspended user's old cookie no longer works", async function () {
      // Create and log in a user to get their session cookie
      client.clearCookies();
      await client.initApiKey();
      resetRateLimits();
      await client.post("/auth/register", {
        json: { displayName: "SuspendMe", email: "suspendme@test.com", password: "password123" },
      });
      // Verify they can access dashboard
      var dash = await client.get("/dashboard");
      assert.strictEqual(dash.status, 200);

      // Save the cookie state
      var savedCookies = Object.assign({}, client.cookies);

      // Admin suspends the user
      await loginAsAdmin();
      var { users } = require(path.join(testServer.projectRoot, "lib", "db"));
      var { hashEmail } = require(path.join(testServer.projectRoot, "lib", "crypto"));
      var target = users.findOne({ emailHash: hashEmail("suspendme@test.com") });
      var suspendRes = await client.post("/admin/users/" + target._id + "/suspend", {
        json: {},
      });
      assert.strictEqual(suspendRes.json.success, true);

      // Restore the suspended user's old cookies and try to access a page
      client.clearCookies();
      await client.initApiKey();
      client.cookies = savedCookies;
      var res = await client.get("/dashboard");
      assert.strictEqual(res.status, 302);

      // Clean up: unsuspend the user
      await loginAsAdmin();
      await client.post("/admin/users/" + target._id + "/unsuspend", { json: {} });
    });

    // 34. User cannot access profile without login
    it("user cannot access profile without login", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.get("/profile");
      assert.strictEqual(res.status, 302);
    });
  });
});
