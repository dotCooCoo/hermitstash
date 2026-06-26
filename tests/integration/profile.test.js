var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());
});

after(function () { return testServer.stop(); });

// Helper: register and login, return client ready to use
async function registerAndLogin(name, email, password) {
  client.clearCookies();
  await client.initApiKey();
  await client.post("/auth/register", {
    json: { displayName: name, email: email, password: password },
  });
  return client;
}

async function loginAs(email, password) {
  client.clearCookies();
  await client.initApiKey();
  await client.post("/auth/login", {
    json: { email: email, password: password },
  });
  return client;
}

describe("profile integration", function () {
  // Create the first user (admin) used across tests
  before(async function () {
    await registerAndLogin("Profile Admin", "admin@profile.test", "password123");
  });

  describe("GET /profile", function () {
    it("requires authentication (redirect to login)", async function () {
      client.clearCookies();
      var res = await client.get("/profile");
      assert.strictEqual(res.status, 302);
      assert.ok(res.location.includes("/auth/login"));
    });

    it("renders profile page for authenticated user", async function () {
      await loginAs("admin@profile.test", "password123");
      var res = await client.get("/profile");
      assert.strictEqual(res.status, 200);
      assert.ok(res.text.includes("profile") || res.text.includes("Profile"), "should contain profile content");
    });
  });

  describe("POST /profile/update (display name)", function () {
    it("updates display name successfully", async function () {
      await loginAs("admin@profile.test", "password123");
      var res = await client.post("/profile/update", {
        json: { displayName: "New Admin Name" },
      });
      assert.strictEqual(res.json.success, true);
    });

    it("rejects empty display name", async function () {
      await loginAs("admin@profile.test", "password123");
      var res = await client.post("/profile/update", {
        json: { displayName: "" },
      });
      assert.strictEqual(res.status, 400);
      assert.ok((res.json.detail || res.json.error || "").includes("required"));
    });

    it("requires authentication", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/profile/update", {
        json: { displayName: "Hacker" },
      });
      assert.strictEqual(res.status, 302);
    });
  });

  describe("POST /profile/password", function () {
    it("changes password with correct current password", async function () {
      await loginAs("admin@profile.test", "password123");
      var res = await client.post("/profile/password", {
        json: { currentPassword: "password123", newPassword: "newpassword456" },
      });
      assert.strictEqual(res.json.success, true);

      // Verify new password works by logging in
      await loginAs("admin@profile.test", "newpassword456");
      var dashRes = await client.get("/dashboard");
      assert.strictEqual(dashRes.status, 200);

      // Change it back for subsequent tests
      var restoreRes = await client.post("/profile/password", {
        json: { currentPassword: "newpassword456", newPassword: "password123" },
      });
      assert.strictEqual(restoreRes.json.success, true);
    });

    it("rejects wrong current password with 401", async function () {
      await loginAs("admin@profile.test", "password123");
      var res = await client.post("/profile/password", {
        json: { currentPassword: "wrongpassword", newPassword: "newpassword456" },
      });
      assert.strictEqual(res.status, 401);
      assert.ok((res.json.detail || res.json.error || "").includes("incorrect"));
    });

    it("rejects short new password with 400", async function () {
      await loginAs("admin@profile.test", "password123");
      var res = await client.post("/profile/password", {
        json: { currentPassword: "password123", newPassword: "short" },
      });
      assert.strictEqual(res.status, 400);
      assert.ok((res.json.detail || res.json.error || "").includes("8"));
    });

    it("rejects non-local auth users with 400", async function () {
      // Simulate a Google OAuth user by directly inserting one
      var { users } = require(path.join(testServer.projectRoot, "lib", "db"));
      var googleUser = users.insert({
        email: "google@profile.test",
        displayName: "Google User",
        authType: "google",
        googleId: "g-" + Date.now(),
        role: "user",
        status: "active",
        createdAt: new Date().toISOString(),
        lastLogin: new Date().toISOString(),
      });

      // Login as admin and then manually set session to google user
      // Instead, we need to create a local user, log in, then change their authType
      // Or we can just register a local user and patch them
      await registerAndLogin("Local Turned Google", "localgoogle@profile.test", "password123");
      users.update({ email: "localgoogle@profile.test" }, { $set: { authType: "google" } });

      // Re-login to pick up changed authType — but wait, login checks passwordHash
      // The user still has a passwordHash, so login works but profile/password checks authType
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/login", {
        json: { email: "localgoogle@profile.test", password: "password123" },
      });

      var res = await client.post("/profile/password", {
        json: { currentPassword: "password123", newPassword: "newpassword456" },
      });
      assert.strictEqual(res.status, 400);
      assert.ok((res.json.detail || res.json.error || "").includes("local"));

      // Restore for cleanup
      users.update({ email: "localgoogle@profile.test" }, { $set: { authType: "local" } });
    });
  });

  describe("POST /profile/email", function () {
    it("changes email with valid password", async function () {
      await loginAs("admin@profile.test", "password123");
      var res = await client.post("/profile/email", {
        json: { newEmail: "admin-new@profile.test", password: "password123" },
      });
      assert.strictEqual(res.json.success, true);

      // Change it back for subsequent tests
      await loginAs("admin-new@profile.test", "password123");
      var restoreRes = await client.post("/profile/email", {
        json: { newEmail: "admin@profile.test", password: "password123" },
      });
      assert.strictEqual(restoreRes.json.success, true);
    });

    it("rejects wrong password with 401", async function () {
      await loginAs("admin@profile.test", "password123");
      var res = await client.post("/profile/email", {
        json: { newEmail: "newemail@profile.test", password: "wrongpassword" },
      });
      assert.strictEqual(res.status, 401);
      assert.ok((res.json.detail || res.json.error || "").includes("incorrect"));
    });

    it("rejects duplicate email with 400", async function () {
      // Register a second user
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/register", {
        json: { displayName: "Second User", email: "second@profile.test", password: "password123" },
      });

      // Login as admin and try to change to the second user's email
      await loginAs("admin@profile.test", "password123");
      var res = await client.post("/profile/email", {
        json: { newEmail: "second@profile.test", password: "password123" },
      });
      assert.strictEqual(res.status, 400);
      assert.ok((res.json.detail || res.json.error || "").includes("already"));
    });

    it("stages an email change behind verification, keeping the old email authoritative until confirmed", async function () {
      var config = require(path.join(testServer.projectRoot, "lib", "config"));
      var dbmod = require(path.join(testServer.projectRoot, "lib", "db"));
      var verification = require(path.join(testServer.projectRoot, "routes", "verification"));
      var rl = require(path.join(testServer.projectRoot, "lib", "rate-limit"));
      var orig = config.emailVerification;

      // Dedicated active account (registered while verification is still off).
      client.clearCookies(); await client.initApiKey(); rl.resetAllInstances();
      await client.post("/auth/register", { json: { displayName: "Stager", email: "stage-old@profile.test", password: "password123" } });
      var idRow = dbmod.users.findOne({ email: "stage-old@profile.test" });
      assert.ok(idRow, "dedicated account registered");

      config.emailVerification = true;
      try {
        await loginAs("stage-old@profile.test", "password123");
        var res = await client.post("/profile/email", { json: { newEmail: "stage-new@profile.test", password: "password123" } });
        assert.strictEqual(res.json.success, true);
        assert.ok(res.json.pending, "the change is staged pending verification of the new address");

        // The OLD address is still the authoritative login identity.
        client.clearCookies(); await client.initApiKey(); rl.resetAllInstances();
        var oldLogin = await client.post("/auth/login", { json: { email: "stage-old@profile.test", password: "password123" } });
        assert.strictEqual(oldLogin.json.success, true, "old email still logs in while the change is pending (no lockout)");

        // The NEW address is NOT the identity until the change is confirmed.
        client.clearCookies(); await client.initApiKey(); rl.resetAllInstances();
        var newEarly = await client.post("/auth/login", { json: { email: "stage-new@profile.test", password: "password123" } });
        assert.notStrictEqual(newEarly.status, 200, "new email must not log in before confirmation");

        // Prove control of the new address — commits pendingEmail -> email.
        var token = verification.createVerificationToken(idRow._id);
        await client.post("/auth/verify/" + token, { json: {} });

        // After commit: the NEW address is the identity; the OLD one is not.
        client.clearCookies(); await client.initApiKey(); rl.resetAllInstances();
        var newLogin = await client.post("/auth/login", { json: { email: "stage-new@profile.test", password: "password123" } });
        assert.strictEqual(newLogin.json.success, true, "new email logs in after confirmation");
        client.clearCookies(); await client.initApiKey(); rl.resetAllInstances();
        var oldAfter = await client.post("/auth/login", { json: { email: "stage-old@profile.test", password: "password123" } });
        assert.notStrictEqual(oldAfter.status, 200, "old email no longer logs in after the change is committed");
      } finally {
        config.emailVerification = orig;
      }
    });
  });

  describe("POST /profile/delete", function () {
    it("rejects deletion without DELETE confirmation", async function () {
      // Create a throwaway user for deletion tests
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/register", {
        json: { displayName: "No Confirm", email: "noconfirm@profile.test", password: "password123" },
      });
      var res = await client.post("/profile/delete", {
        json: { confirm: "nope" },
      });
      assert.strictEqual(res.status, 400);
      assert.ok((res.json.detail || res.json.error || "").includes("DELETE"));
    });

    it("last admin cannot delete themselves", async function () {
      await loginAs("admin@profile.test", "password123");
      var res = await client.post("/profile/delete", {
        json: { confirm: "DELETE" },
      });
      assert.strictEqual(res.status, 400);
      assert.ok((res.json.detail || res.json.error || "").includes("last admin"));
    });

    it("deletes own account with correct confirmation", async function () {
      // Register a disposable user
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/register", {
        json: { displayName: "Delete Me", email: "deleteme@profile.test", password: "password123" },
      });
      var res = await client.post("/profile/delete", {
        json: { confirm: "DELETE" },
      });
      assert.strictEqual(res.json.success, true);
      assert.strictEqual(res.json.redirect, "/");

      // Verify user can no longer login
      client.clearCookies();
      await client.initApiKey();
      var loginRes = await client.post("/auth/login", {
        json: { email: "deleteme@profile.test", password: "password123" },
      });
      assert.strictEqual(loginRes.status, 401);
    });
  });
});
