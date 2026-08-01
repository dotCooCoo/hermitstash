var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var b = require("../../lib/vendor/blamejs");
var projectRoot = testServer.projectRoot;
var client;
var emailMod;

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());
  emailMod = require(path.join(projectRoot, "lib", "email"));
});

after(function () { return testServer.stop(); });

async function seedUser(email, displayName, status) {
  var vault = require(path.join(projectRoot, "lib", "vault"));
  var { hashEmail } = require(path.join(projectRoot, "lib", "crypto"));
  var { users } = require(path.join(projectRoot, "lib", "db"));
  var hash = await b.auth.password.hash("password123");
  users.insert({
    email: vault.seal(email), emailHash: hashEmail(email),
    displayName: vault.seal(displayName), passwordHash: hash,
    authType: "local", role: "user", status: status,
    createdAt: new Date().toISOString(),
  });
}

// F-2: /auth/forgot-password and /auth/resend-verification both return an
// identical generic body regardless of account existence, but the account-EXISTS
// branch awaited the email send while the non-existent branch returned
// immediately — making response latency an account-enumeration oracle. The send
// is now fire-and-forget on both routes, so the response returns without waiting
// on the SMTP round-trip.
//
// Test construction: the email send is stubbed with a promise that NEVER settles.
// If the handler awaited it (the pre-fix behavior) the HTTP response would never
// arrive and the request would hang until the per-test timeout. Fire-and-forget
// lets the response return while the send is still in flight.

describe("password reset — email send is not awaited before the response (F-2)", function () {
  it("returns success on the account-exists branch without awaiting the send", { timeout: 8000 }, async function () {
    await seedUser("reset-timing@test.com", "Reset Timing", "active");

    var called = false;
    var orig = emailMod.sendPasswordResetEmail;
    emailMod.sendPasswordResetEmail = function () {
      called = true;
      return new Promise(function () {});   // never settles
    };

    client.clearCookies();
    await client.initApiKey();
    try {
      var res = await client.post("/auth/forgot-password", { json: { email: "reset-timing@test.com" } });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);
      assert.strictEqual(called, true, "the reset email send was kicked off");
    } finally {
      emailMod.sendPasswordResetEmail = orig;
    }
  });
});

describe("verification resend — email send is not awaited before the response (F-2)", function () {
  it("returns success on the pending-account branch without awaiting the send", { timeout: 8000 }, async function () {
    await seedUser("resend-timing@test.com", "Resend Timing", "pending");

    var called = false;
    var orig = emailMod.sendVerificationEmail;
    emailMod.sendVerificationEmail = function () {
      called = true;
      return new Promise(function () {});   // never settles
    };

    client.clearCookies();
    await client.initApiKey();
    try {
      var res = await client.post("/auth/resend-verification", { json: { email: "resend-timing@test.com" } });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);
      assert.strictEqual(called, true, "the verification email send was kicked off");
    } finally {
      emailMod.sendVerificationEmail = orig;
    }
  });
});
