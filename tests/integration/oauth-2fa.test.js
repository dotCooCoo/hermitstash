/**
 * OAuth (Google) login must honor the 2FA gate.
 *
 * The Google callback routes its successful-credential outcome through the
 * same sessionService.completeLogin chokepoint the local-password path uses.
 * A totpEnabled account reachable via SSO must be held in the pending-2FA
 * state and redirected to the TOTP step — never handed a full session by the
 * OAuth entry point. This mirrors the local-path assertion in
 * tests/integration/two-factor.test.js, redirect-based because the callback
 * is a browser navigation.
 *
 * The Google token + userinfo HTTP calls (b.httpClient.request) are stubbed so
 * the test is deterministic and offline. The server runs in-process, so the
 * stub lands on the same b.httpClient the server's lib/google-auth uses.
 */
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");

// b + rateLimit are resolved AFTER testServer.start() so they reference the
// same post-cache-clear module instances the running server uses (the harness
// clears the HS require cache during boot — a pre-start require would yield a
// stale instance with an uninitialized session store and an unstubbed
// httpClient).
var b;
var rateLimit;
var users;
var realHttpRequest;
var stubProfile = null;

// Stub the Google token + userinfo round-trip. lib/google-auth posts to the
// token URL then gets the userinfo URL; both go through b.httpClient.request
// and read res.body as JSON. Return whichever shape the URL asks for.
function installGoogleStub() {
  realHttpRequest = b.httpClient.request;
  b.httpClient.request = function (opts) {
    var url = String(opts && opts.url || "");
    var payload;
    if (url.indexOf("oauth2.googleapis.com/token") !== -1) {
      payload = { access_token: "stub-access-token", token_type: "Bearer" };
    } else if (url.indexOf("openidconnect.googleapis.com/v1/userinfo") !== -1) {
      payload = {
        sub: stubProfile.googleId,
        email: stubProfile.email,
        email_verified: true,
        name: stubProfile.displayName,
        picture: "",
      };
    } else {
      return realHttpRequest.call(b.httpClient, opts);
    }
    return Promise.resolve({ status: 200, headers: {}, body: Buffer.from(JSON.stringify(payload)) });
  };
}

function restoreGoogleStub() {
  if (realHttpRequest) b.httpClient.request = realHttpRequest;
}

// Drive the real OAuth callback. The /auth/google step (cross-origin redirect
// to accounts.google.com) isn't reachable through the test router, so seed
// req.session.oauthState directly into the live session the same shape
// /auth/google writes — the hs_sid cookie value IS the framework session
// token — then GET the callback with the matching state. The stub supplies
// the Google profile. The CSRF state check still runs for real.
var COOKIE_NAME = "hs_sid";
async function driveGoogleCallback(client, profile) {
  rateLimit.resetAllInstances();
  stubProfile = profile;

  // Establish a session (issues the hs_sid cookie).
  await client.get("/auth/login");
  var rawCookie = client.cookies[COOKIE_NAME];
  assert.ok(rawCookie, "expected an hs_sid session cookie");
  var token = decodeURIComponent(rawCookie);

  // Seed the OAuth state exactly as /auth/google would.
  var state = b.crypto.generateBytes(32).toString("base64url");
  await b.session.updateData(token, { oauthState: { value: state, ts: Date.now() } });

  return client.get("/auth/google/callback?code=stub-code&state=" + encodeURIComponent(state));
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
  installGoogleStub();
});

after(function () {
  restoreGoogleStub();
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

    var res = await driveGoogleCallback(client, { googleId: "g-twofa-1", email: email, displayName: "TwoFA Google" });

    assert.strictEqual(res.status, 302, "callback should redirect");
    assert.strictEqual(res.location, "/2fa", "2FA account must be sent to the TOTP step, not /dashboard");
    assert.notStrictEqual(res.location, "/dashboard", "must not grant a full session past 2FA");

    // No full session was established — the pending-2FA state is anonymous, so
    // an auth-gated page bounces back to the login redirect rather than 200.
    var dash = await client.get("/dashboard");
    assert.notStrictEqual(dash.status, 200, "2FA-pending account must not reach the dashboard");
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

    var res = await driveGoogleCallback(client, { googleId: "g-no2fa-1", email: email, displayName: "No2FA Google" });

    assert.strictEqual(res.status, 302, "callback should redirect");
    assert.strictEqual(res.location, "/dashboard", "non-2FA account gets a full session");

    // Full session — the auth-gated dashboard renders.
    var dash = await client.get("/dashboard");
    assert.strictEqual(dash.status, 200, "non-2FA account is fully authenticated");
  });
});
