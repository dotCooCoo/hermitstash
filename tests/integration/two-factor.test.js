var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var crypto = require("crypto");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;

var users;

// totp.js only depends on crypto — safe to import at top level
var totp = require(path.join(testServer.projectRoot, "lib", "totp"));

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());
  users = require(path.join(testServer.projectRoot, "lib", "db")).users;
});

after(function () { return testServer.stop(); });

// Compute the current TOTP code via lib/totp's SHA-512 path so the test
// uses the same algorithm + secret format the server stamps on new
// enrollments. A SHA1-against-20-byte-base32 hand-roll would silently
// fall out of sync because the server defaults to SHA-512 + 128-byte
// secrets.
function getCurrentCode(secret) {
  return totp.computeCode(secret, Math.floor(Date.now() / 30000));
}

// Clear the TOTP replay prevention step so the same code can be reused across tests
function clearTotpLastStep(email) {
  var user = users.findOne({ email: email });
  if (user) users.update({ _id: user._id }, { $set: { totpLastStep: null } });
}

async function registerAndLogin(name, email, password) {
  client.clearCookies();
  await client.initApiKey();
  await client.post("/auth/register", {
    json: { displayName: name, email: email, password: password },
  });
  return client;
}

// Login and complete 2FA if required. Returns login response.
async function fullLoginAs(email, password, secret) {
  client.clearCookies();
  await client.initApiKey();
  var res = await client.post("/auth/login", {
    json: { email: email, password: password },
  });
  if (res.json && res.json.requires2fa && secret) {
    clearTotpLastStep(email);
    testServer.resetAllRateLimits();
    var code = getCurrentCode(secret);
    var verifyRes = await client.post("/2fa/verify", { json: { code: code } });
    return verifyRes;
  }
  return res;
}

describe("two-factor integration", function () {
  var totpSecret;
  var backupCodes;

  // Create the test user (first user = admin)
  before(async function () {
    await registerAndLogin("2FA User", "2fa@test.com", "password123");
  });

  describe("GET /2fa/status", function () {
    it("requires authentication", async function () {
      client.clearCookies();
      var res = await client.get("/2fa/status");
      assert.strictEqual(res.status, 302);
      assert.ok(res.location.includes("/auth/login"));
    });

    it("shows 2FA disabled initially", async function () {
      testServer.resetAllRateLimits();
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/login", {
        json: { email: "2fa@test.com", password: "password123" },
      });
      var res = await client.get("/2fa/status");
      assert.strictEqual(res.json.enabled, false);
      assert.strictEqual(res.json.backupCodesRemaining, 0);
    });
  });

  describe("POST /2fa/setup", function () {
    it("requires authentication", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/2fa/setup", { json: {} });
      assert.strictEqual(res.status, 302);
    });

    it("returns secret and QR URI", async function () {
      testServer.resetAllRateLimits();
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/login", {
        json: { email: "2fa@test.com", password: "password123" },
      });
      var res = await client.post("/2fa/setup", { json: {} });
      assert.ok(res.json.secret, "should return TOTP secret");
      assert.ok(res.json.uri, "should return otpauth URI");
      assert.ok(res.json.uri.startsWith("otpauth://totp/"), "URI should be otpauth format");
      assert.ok(res.json.uri.includes(res.json.secret), "URI should contain the secret");
      totpSecret = res.json.secret;
    });
  });

  describe("POST /2fa/confirm", function () {
    it("requires authentication", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/2fa/confirm", { json: { code: "123456" } });
      assert.strictEqual(res.status, 302);
    });

    it("rejects invalid code", async function () {
      testServer.resetAllRateLimits();
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/login", {
        json: { email: "2fa@test.com", password: "password123" },
      });
      // Setup to get pending secret in session
      var setupRes = await client.post("/2fa/setup", { json: {} });
      totpSecret = setupRes.json.secret;

      var res = await client.post("/2fa/confirm", { json: { code: "000000" } });
      assert.strictEqual(res.status, 400);
      assert.ok(res.json.error.includes("Invalid"));
    });

    it("rejects without pending setup", async function () {
      testServer.resetAllRateLimits();
      // Fresh login — no setup was called in this session
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/login", {
        json: { email: "2fa@test.com", password: "password123" },
      });
      var res = await client.post("/2fa/confirm", { json: { code: "123456" } });
      assert.strictEqual(res.status, 400);
      assert.ok(res.json.error.includes("pending") || res.json.error.includes("Start again"));
    });

    it("confirms with valid TOTP code and returns backup codes", async function () {
      testServer.resetAllRateLimits();
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/login", {
        json: { email: "2fa@test.com", password: "password123" },
      });
      // Setup first
      var setupRes = await client.post("/2fa/setup", { json: {} });
      totpSecret = setupRes.json.secret;

      // Compute the valid TOTP code
      var code = getCurrentCode(totpSecret);
      var res = await client.post("/2fa/confirm", { json: { code: code } });
      assert.strictEqual(res.json.success, true);
      assert.ok(res.json.backupCodes, "should return backup codes");
      assert.strictEqual(res.json.backupCodes.length, 10, "should return 10 backup codes");
      backupCodes = res.json.backupCodes;
    });

    it("2FA status shows enabled after confirmation", async function () {
      // After 2FA is enabled, must complete full 2FA login to check status
      testServer.resetAllRateLimits();
      clearTotpLastStep("2fa@test.com");
      var res = await fullLoginAs("2fa@test.com", "password123", totpSecret);
      assert.strictEqual(res.json.success, true);

      var statusRes = await client.get("/2fa/status");
      assert.strictEqual(statusRes.json.enabled, true);
      assert.strictEqual(statusRes.json.backupCodesRemaining, 10);
    });
  });

  describe("POST /2fa/verify (login flow)", function () {
    it("login returns requires2fa flag when 2FA is enabled", async function () {
      testServer.resetAllRateLimits();
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/auth/login", {
        json: { email: "2fa@test.com", password: "password123" },
      });
      assert.strictEqual(res.json.requires2fa, true);
      assert.strictEqual(res.json.success, undefined, "should not grant full access yet");
    });

    it("verify with correct TOTP code completes login", async function () {
      testServer.resetAllRateLimits();
      clearTotpLastStep("2fa@test.com");
      client.clearCookies();
      await client.initApiKey();
      var loginRes = await client.post("/auth/login", {
        json: { email: "2fa@test.com", password: "password123" },
      });
      assert.strictEqual(loginRes.json.requires2fa, true);

      // Compute and submit valid code
      var code = getCurrentCode(totpSecret);
      var res = await client.post("/2fa/verify", { json: { code: code } });
      assert.strictEqual(res.json.success, true);
      assert.strictEqual(res.json.redirect, "/dashboard");

      // Verify we can access the dashboard now
      var dashRes = await client.get("/dashboard");
      assert.strictEqual(dashRes.status, 200);
    });

    it("verify with wrong code returns 401", async function () {
      testServer.resetAllRateLimits();
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/login", {
        json: { email: "2fa@test.com", password: "password123" },
      });
      var res = await client.post("/2fa/verify", { json: { code: "000000" } });
      assert.strictEqual(res.status, 401);
      assert.ok(res.json.error.includes("Invalid"));
    });

    it("verify without pending userId returns 400", async function () {
      // Fresh session with no login attempt
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/2fa/verify", { json: { code: "123456" } });
      assert.strictEqual(res.status, 400);
      assert.ok(res.json.error.includes("pending"));
    });

    it("verify with backup code completes login", async function () {
      testServer.resetAllRateLimits();
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/login", {
        json: { email: "2fa@test.com", password: "password123" },
      });
      // Use the first backup code
      var code = backupCodes[0];
      var res = await client.post("/2fa/verify", { json: { code: code } });
      assert.strictEqual(res.json.success, true);
      assert.strictEqual(res.json.redirect, "/dashboard");
    });

    it("backup code is single-use (cannot reuse)", async function () {
      testServer.resetAllRateLimits();
      client.clearCookies();
      await client.initApiKey();
      await client.post("/auth/login", {
        json: { email: "2fa@test.com", password: "password123" },
      });
      // Try the same backup code again (already consumed above)
      var code = backupCodes[0];
      var res = await client.post("/2fa/verify", { json: { code: code } });
      assert.strictEqual(res.status, 401);
    });

    it("backup code count decrements after use", async function () {
      // Login fully with TOTP to check status
      testServer.resetAllRateLimits();
      clearTotpLastStep("2fa@test.com");
      var res = await fullLoginAs("2fa@test.com", "password123", totpSecret);
      assert.strictEqual(res.json.success, true);

      var statusRes = await client.get("/2fa/status");
      assert.strictEqual(statusRes.json.enabled, true);
      assert.strictEqual(statusRes.json.backupCodesRemaining, 9, "should have 9 backup codes after using 1");
    });
  });

  describe("POST /2fa/disable", function () {
    it("requires authentication", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/2fa/disable", { json: { code: "123456" } });
      assert.strictEqual(res.status, 302);
    });

    it("rejects invalid code", async function () {
      // Login fully (with 2FA)
      testServer.resetAllRateLimits();
      clearTotpLastStep("2fa@test.com");
      await fullLoginAs("2fa@test.com", "password123", totpSecret);

      var res = await client.post("/2fa/disable", { json: { code: "000000" } });
      assert.strictEqual(res.status, 400);
      assert.ok(res.json.error.includes("Invalid"));
    });

    it("disables 2FA with valid code", async function () {
      testServer.resetAllRateLimits();
      clearTotpLastStep("2fa@test.com");
      await fullLoginAs("2fa@test.com", "password123", totpSecret);

      // Disable with a valid code (clear replay step so current code works)
      clearTotpLastStep("2fa@test.com");
      var disableCode = getCurrentCode(totpSecret);
      var res = await client.post("/2fa/disable", { json: { code: disableCode } });
      assert.strictEqual(res.json.success, true);
    });

    it("2FA status shows disabled after disabling", async function () {
      // Login normally (should not require 2FA anymore)
      testServer.resetAllRateLimits();
      client.clearCookies();
      await client.initApiKey();
      var loginRes = await client.post("/auth/login", {
        json: { email: "2fa@test.com", password: "password123" },
      });
      assert.strictEqual(loginRes.json.success, true, "login should succeed without 2FA");

      var res = await client.get("/2fa/status");
      assert.strictEqual(res.json.enabled, false);
      assert.strictEqual(res.json.backupCodesRemaining, 0);
    });

    it("login no longer requires 2FA after disabling", async function () {
      testServer.resetAllRateLimits();
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/auth/login", {
        json: { email: "2fa@test.com", password: "password123" },
      });
      assert.strictEqual(res.json.success, true);
      assert.strictEqual(res.json.requires2fa, undefined);
    });
  });
});
