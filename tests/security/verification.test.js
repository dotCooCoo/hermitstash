const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const crypto = require("crypto");
const b = require("../../lib/vendor/blamejs");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var projectRoot = testServer.projectRoot;
var client;

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());
});

after(function () {
  return testServer.stop();
});

describe("email verification flow", function () {
  var pendingUserId;

  it("register with emailVerification enabled creates pending user", async function () {
    // Seed an admin user first so the next registration is NOT auto-admin.
    // The first registered user is always admin and skips verification.
    var vault = require(path.join(projectRoot, "lib", "vault"));
    var { hashEmail } = require(path.join(projectRoot, "lib", "crypto"));
    var { users } = require(path.join(projectRoot, "lib", "db"));
    // b.auth.password.hash (Argon2id PHC) — lib/crypto.js never had hashPassword.
    var hash = await b.auth.password.hash("adminpass123");
    users.insert({
      email: vault.seal("seedadmin@test.com"), emailHash: hashEmail("seedadmin@test.com"),
      displayName: vault.seal("Seed Admin"), passwordHash: hash,
      authType: "local", role: "admin", status: "active",
      createdAt: new Date().toISOString(),
    });

    var config = require(path.join(projectRoot, "lib", "config"));
    config.emailVerification = true;

    client.clearCookies();
    await client.initApiKey();
    var rateLimit = require(path.join(projectRoot, "lib", "rate-limit"));
    rateLimit.reset("register", "127.0.0.1");
    rateLimit.reset("register", "::1");
    rateLimit.reset("register", "::ffff:127.0.0.1");

    var res = await client.post("/auth/register", {
      json: { displayName: "Pending User", email: "verify@test.com", password: "password123" },
    });
    assert.ok(res.json.pending, "response should indicate pending status");
    assert.ok(res.json.redirect.includes("/auth/pending"), "should redirect to pending page");

    // Verify user is pending in DB
    var user = users.findOne({ emailHash: hashEmail("verify@test.com") });
    assert.ok(user, "user should exist in DB");
    assert.strictEqual(user.status, "pending", "user status should be pending");
    pendingUserId = user._id;

    config.emailVerification = false;
  });

  it("createVerificationToken creates token and POST /auth/verify/:token activates user", async function () {
    // Use the exported createVerificationToken to get the raw token
    var { createVerificationToken } = require(path.join(projectRoot, "routes", "verification"));
    var rawToken = createVerificationToken(pendingUserId);
    assert.ok(rawToken, "should return a raw token string");
    assert.strictEqual(rawToken.length, 64, "token should be 64 hex chars (32 bytes)");

    // Verify token is in DB (hashed)
    var { verificationTokens } = require(path.join(projectRoot, "lib", "db"));
    var { sha3Hash } = require(path.join(projectRoot, "lib", "crypto"));
    var record = verificationTokens.findOne({ token: sha3Hash(rawToken) });
    assert.ok(record, "hashed token should exist in DB");
    assert.strictEqual(record.userId, pendingUserId);
    assert.strictEqual(record.type, "email");

    // GET now shows a confirmation page (auto-submitting form) instead of activating directly
    client.clearCookies();
    var getRes = await client.get("/auth/verify/" + rawToken);
    assert.strictEqual(getRes.status, 200);
    assert.ok(getRes.text.includes("form") || getRes.text.includes("verify"), "GET should show confirmation page");

    // POST actually activates the user (simulates the form submission)
    var res = await client.post("/auth/verify/" + rawToken, { json: {} });
    assert.strictEqual(res.status, 200);

    // Verify user is now active
    var { users } = require(path.join(projectRoot, "lib", "db"));
    var user = users.findOne({ _id: pendingUserId });
    assert.strictEqual(user.status, "active", "user status should be active after verification");

    // Token should be consumed (removed from DB)
    var consumed = verificationTokens.findOne({ token: sha3Hash(rawToken) });
    assert.strictEqual(consumed, null, "token should be removed after verification");
  });

  it("GET /auth/verify/:token with invalid token returns error page", async function () {
    client.clearCookies();
    var res = await client.get("/auth/verify/0000000000000000000000000000000000000000000000000000000000000000");
    assert.strictEqual(res.status, 400);
    assert.ok(res.text.includes("Invalid") || res.text.includes("invalid"), "page should show invalid link message");
  });

  it("GET /auth/verify/:token with expired token returns error page", async function () {
    // Create a pending user for this test
    var { users, verificationTokens } = require(path.join(projectRoot, "lib", "db"));
    // b.auth.password.hash — lib/crypto.js never exported hashPassword.
    var vault = require(path.join(projectRoot, "lib", "vault"));
    var { hashEmail, sha3Hash } = require(path.join(projectRoot, "lib", "crypto"));
    var hash = await b.auth.password.hash("password123");
    var expUser = users.insert({
      email: vault.seal("expired@test.com"), emailHash: hashEmail("expired@test.com"),
      displayName: vault.seal("Expired User"), passwordHash: hash,
      authType: "local", role: "user", status: "pending",
      createdAt: new Date().toISOString(),
    });

    // Insert token with expired date
    var rawToken = b.crypto.generateToken(32);
    verificationTokens.insert({
      userId: expUser._id,
      token: sha3Hash(rawToken),
      type: "email",
      expiresAt: new Date(Date.now() - 86400000).toISOString(), // 24 hours ago
      createdAt: new Date().toISOString(),
    });

    client.clearCookies();
    var res = await client.get("/auth/verify/" + rawToken);
    assert.strictEqual(res.status, 400);
    assert.ok(res.text.includes("Expired") || res.text.includes("expired"), "page should show expired link message");

    // Expired token should be cleaned up
    var record = verificationTokens.findOne({ token: sha3Hash(rawToken) });
    assert.strictEqual(record, null, "expired token should be removed from DB after attempt");
  });
});

describe("resend verification", function () {
  it("POST /auth/resend-verification with valid pending email returns 200", async function () {
    // Create a pending user
    var { users } = require(path.join(projectRoot, "lib", "db"));
    // b.auth.password.hash — lib/crypto.js never exported hashPassword.
    var vault = require(path.join(projectRoot, "lib", "vault"));
    var { hashEmail } = require(path.join(projectRoot, "lib", "crypto"));
    var hash = await b.auth.password.hash("password123");
    users.insert({
      email: vault.seal("resend@test.com"), emailHash: hashEmail("resend@test.com"),
      displayName: vault.seal("Resend User"), passwordHash: hash,
      authType: "local", role: "user", status: "pending",
      createdAt: new Date().toISOString(),
    });

    client.clearCookies();
    await client.initApiKey();
    var res = await client.post("/auth/resend-verification", {
      json: { email: "resend@test.com" },
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.json.success, true);
    assert.ok(res.json.message.includes("verification"), "response should mention verification");
  });

  it("POST /auth/resend-verification with non-existent email returns 200 (no enumeration)", async function () {
    await client.initApiKey();
    var res = await client.post("/auth/resend-verification", {
      json: { email: "nobody@nowhere.com" },
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.json.success, true, "should return success even for non-existent email");
    assert.ok(res.json.message.includes("verification"), "response message should be identical to valid case");
  });

  it("POST /auth/resend-verification with missing email returns 400", async function () {
    await client.initApiKey();
    var res = await client.post("/auth/resend-verification", {
      json: { email: "" },
    });
    assert.strictEqual(res.status, 400);
    assert.ok(res.json.error.includes("Email") || res.json.error.includes("email"), "error should mention email required");
  });
});
