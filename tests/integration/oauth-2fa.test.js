/**
 * OAuth (Google) login must honor the 2FA gate.
 *
 * The Google callback routes its successful-credential outcome through the
 * same sessionService.completeLogin chokepoint the local-password path uses.
 * A totpEnabled account reachable via SSO must be held in the pending-2FA
 * state and redirected to the TOTP step, never handed a full session by the
 * OAuth entry point. This mirrors the local-path assertion in
 * tests/integration/two-factor.test.js, redirect-based because the callback
 * is a browser navigation.
 *
 * Google's discovery, JWKS and token endpoints are served by the mock
 * provider in tests/helpers/mock-oidc-provider.js through a b.httpClient.request
 * stub, so the test is offline. The login runs the real chain: GET
 * /auth/google writes the pending state, the mock records the consent, and the
 * callback verifies a signed id_token.
 */
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var mockOp = require("../helpers/mock-oidc-provider");

// b + rateLimit are resolved AFTER testServer.start() so they reference the
// same post-cache-clear module instances the running server uses.
var b;
var rateLimit;
var users;
var op;
var restoreStub;

async function driveGoogleCallback(client, claims) {
  rateLimit.resetAllInstances();
  var start = await client.get("/auth/google");
  assert.strictEqual(start.status, 302, "GET /auth/google redirects to Google");
  var cb = op.authorize(start.location, { claims: claims });
  return client.get(cb.path);
}

before(async function () {
  await testServer.start({
    env: {
      GOOGLE_CLIENT_ID: "test-client-id",
      GOOGLE_CLIENT_SECRET: "test-client-secret",
      GOOGLE_CALLBACK_URL: "http://localhost/auth/google/callback",
    },
  });
  b = require(path.join(testServer.projectRoot, "lib", "vendor", "blamejs"));
  rateLimit = require(path.join(testServer.projectRoot, "lib", "rate-limit"));
  users = require(path.join(testServer.projectRoot, "lib", "db")).users;
  op = mockOp.create({ issuer: "https://accounts.google.com", clientId: "test-client-id", clientSecret: "test-client-secret" });
  restoreStub = op.installHttpStub(b);
});

after(function () {
  if (restoreStub) restoreStub();
  return testServer.stop();
});

describe("OAuth 2FA enforcement", function () {
  it("totpEnabled Google account is redirected to /2fa, not granted a session", async function () {
    var client = new TestClient(testServer.baseUrl());

    // Pre-seed a google-authType user with 2FA enabled. The callback's
    // resolveGoogleUser looks up by email and returns this existing row.
    var email = "twofa.google@test.com";
    users.insert({
      googleId: "g-twofa-1",
      email: email,
      displayName: "TwoFA Google",
      authType: "google",
      role: "user",
      status: "active",
      totpEnabled: "true",
      totpSecret: b.crypto.generateBytes(64).toString("base64"),
      totpAlgorithm: "SHA-512",
      createdAt: new Date().toISOString(),
    });

    var res = await driveGoogleCallback(client, { sub: "g-twofa-1", email: email, name: "TwoFA Google" });

    assert.strictEqual(res.status, 302, "callback should redirect");
    assert.strictEqual(res.location, "/2fa", "2FA account must be sent to the TOTP step, not /dashboard");

    // No full session was established. The pending-2FA state is anonymous, so
    // an auth-gated page bounces back to the login redirect rather than 200.
    var dash = await client.get("/dashboard");
    assert.strictEqual(dash.status, 302, "auth gate redirects the unauthenticated pending session");
    assert.strictEqual(dash.location, "/auth/login", "redirected to login, not granted access");
  });

  it("Google account without 2FA still gets a full session at /dashboard", async function () {
    var client = new TestClient(testServer.baseUrl());

    var email = "no2fa.google@test.com";
    users.insert({
      googleId: "g-no2fa-1",
      email: email,
      displayName: "No2FA Google",
      authType: "google",
      role: "user",
      status: "active",
      createdAt: new Date().toISOString(),
    });

    var res = await driveGoogleCallback(client, { sub: "g-no2fa-1", email: email, name: "No2FA Google" });

    assert.strictEqual(res.status, 302, "callback should redirect");
    assert.strictEqual(res.location, "/dashboard", "non-2FA account gets a full session");

    var dash = await client.get("/dashboard");
    assert.strictEqual(dash.status, 200, "non-2FA account is fully authenticated");
  });
});
