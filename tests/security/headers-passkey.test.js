var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client, config;

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());

  config = require(path.join(testServer.projectRoot, "lib", "config"));

  // Seed an admin user
  var b = require(path.join(testServer.projectRoot, "lib", "vendor", "blamejs"));
  var vault = require(path.join(testServer.projectRoot, "lib", "vault"));
  var { hashEmail } = require(path.join(testServer.projectRoot, "lib", "crypto"));
  var { users } = require(path.join(testServer.projectRoot, "lib", "db"));
  // Password hashing — b.auth.password.hash (Argon2id PHC). lib/crypto.js
  // never exported hashPassword.
  var hash = await b.auth.password.hash("adminpass123");
  users.insert({
    email: vault.seal("hpadmin@test.com"), emailHash: hashEmail("hpadmin@test.com"),
    displayName: vault.seal("HP Admin"), passwordHash: hash,
    authType: "local", role: "admin", status: "active",
    createdAt: new Date().toISOString(),
  });
});

after(function () { return testServer.stop(); });

// ---------------------------------------------------------------------------
// Security headers
// ---------------------------------------------------------------------------
describe("security headers", function () {
  it("response includes X-Content-Type-Options: nosniff", async function () {
    var res = await client.get("/auth/login");
    assert.strictEqual(res.headers["x-content-type-options"], "nosniff");
  });

  it("response includes X-Frame-Options: DENY", async function () {
    var res = await client.get("/auth/login");
    assert.strictEqual(res.headers["x-frame-options"], "DENY");
  });

  it("response includes Content-Security-Policy", async function () {
    var res = await client.get("/auth/login");
    var csp = res.headers["content-security-policy"];
    assert.ok(csp, "Content-Security-Policy header should be present");
    assert.ok(csp.includes("default-src"), "CSP should contain default-src directive");
    assert.ok(csp.includes("frame-ancestors 'none'"), "CSP should block framing via frame-ancestors");
  });

  it("response includes Referrer-Policy: no-referrer", async function () {
    var res = await client.get("/auth/login");
    // HS hardened to `no-referrer` for tighter Referer leak posture on
    // auth pages — was `strict-origin-when-cross-origin` pre-security-
    // headers-rebuild.
    assert.strictEqual(res.headers["referrer-policy"], "no-referrer");
  });

  it("response includes Permissions-Policy", async function () {
    var res = await client.get("/auth/login");
    var pp = res.headers["permissions-policy"];
    assert.ok(pp, "Permissions-Policy header should be present");
    assert.ok(pp.includes("camera=()"), "should restrict camera");
    assert.ok(pp.includes("microphone=()"), "should restrict microphone");
    assert.ok(pp.includes("geolocation=()"), "should restrict geolocation");
  });
});

// ---------------------------------------------------------------------------
// Passkey error paths (passkeyEnabled = true)
// ---------------------------------------------------------------------------
describe("passkey error paths", function () {
  it("POST /passkey/register/verify without pending challenge returns 400", async function () {
    client.clearCookies();
    await client.initApiKey();
    await client.post("/auth/login", {
      json: { email: "hpadmin@test.com", password: "adminpass123" },
    });
    var res = await client.post("/passkey/register/verify", {
      json: { id: "fake", rawId: "fake", response: {}, type: "public-key" },
    });
    assert.strictEqual(res.status, 400);
    assert.ok((res.json.detail || res.json.error || "").includes("No pending"), "should mention no pending challenge");
  });

  it("POST /passkey/login/verify without pending challenge returns 400", async function () {
    client.clearCookies();
    await client.initApiKey();
    // Make a request to establish a session, but do NOT call /passkey/login/options
    await client.get("/auth/login");
    var res = await client.post("/passkey/login/verify", {
      json: { id: "fake", rawId: "fake", response: {}, type: "public-key" },
    });
    assert.strictEqual(res.status, 400);
    assert.ok((res.json.detail || res.json.error || "").includes("No pending"), "should mention no pending challenge");
  });

  it("POST /passkey/remove without auth redirects to login", async function () {
    client.clearCookies();
    await client.initApiKey();
    var res = await client.post("/passkey/remove", {
      json: { credentialId: "anything" },
    });
    assert.strictEqual(res.status, 302);
    assert.ok(res.location.includes("/auth/login"), "should redirect to login");
  });

  it("POST /passkey/remove with auth but missing credentialId returns 400", async function () {
    client.clearCookies();
    await client.initApiKey();
    await client.post("/auth/login", {
      json: { email: "hpadmin@test.com", password: "adminpass123" },
    });
    var res = await client.post("/passkey/remove", {
      json: {},
    });
    assert.strictEqual(res.status, 400);
    assert.ok((res.json.detail || res.json.error || "").includes("Credential ID"), "should mention credential ID required");
  });

  it("POST /passkey/remove with auth but wrong credentialId returns 404", async function () {
    client.clearCookies();
    await client.initApiKey();
    await client.post("/auth/login", {
      json: { email: "hpadmin@test.com", password: "adminpass123" },
    });
    var res = await client.post("/passkey/remove", {
      json: { credentialId: "nonexistent-cred-id-12345" },
    });
    assert.strictEqual(res.status, 404);
    assert.ok((res.json.detail || res.json.error || "").includes("not found"), "should mention passkey not found");
  });
});

// ---------------------------------------------------------------------------
// Passkey disabled (passkeyEnabled = false)
// ---------------------------------------------------------------------------
describe("passkey disabled", function () {
  var origPasskeyEnabled;

  before(function () {
    origPasskeyEnabled = config.passkeyEnabled;
    config.passkeyEnabled = false;
  });

  after(function () {
    config.passkeyEnabled = origPasskeyEnabled;
  });

  it("POST /passkey/login/options returns 403 when disabled", async function () {
    client.clearCookies();
    await client.initApiKey();
    var res = await client.post("/passkey/login/options", { json: {} });
    assert.strictEqual(res.status, 403);
    assert.ok((res.json.detail || res.json.error || "").includes("disabled"), "should mention passkeys are disabled");
  });

  it("POST /passkey/register/options returns 403 when disabled", async function () {
    client.clearCookies();
    await client.initApiKey();
    await client.post("/auth/login", {
      json: { email: "hpadmin@test.com", password: "adminpass123" },
    });
    var res = await client.post("/passkey/register/options", { json: {} });
    assert.strictEqual(res.status, 403);
    assert.ok((res.json.detail || res.json.error || "").includes("disabled"), "should mention passkeys are disabled");
  });

  it("POST /passkey/register/verify returns 403 when disabled", async function () {
    var res = await client.post("/passkey/register/verify", {
      json: { id: "fake", rawId: "fake", response: {}, type: "public-key" },
    });
    assert.strictEqual(res.status, 403);
    assert.ok((res.json.detail || res.json.error || "").includes("disabled"), "should mention passkeys are disabled");
  });

  it("POST /passkey/login/verify returns 403 when disabled", async function () {
    client.clearCookies();
    await client.initApiKey();
    var res = await client.post("/passkey/login/verify", {
      json: { id: "fake", rawId: "fake", response: {}, type: "public-key" },
    });
    assert.strictEqual(res.status, 403);
    assert.ok((res.json.detail || res.json.error || "").includes("disabled"), "should mention passkeys are disabled");
  });
});
