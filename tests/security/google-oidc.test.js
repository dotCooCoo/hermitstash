/**
 * Google sign-in on b.auth.oauth: regression coverage.
 *
 * Google moved from a hand-written flow that trusted the userinfo endpoint to
 * a verified id_token with a nonce and mandatory PKCE. These tests pin the
 * behavior existing deployments depend on (googleId equals the id_token sub,
 * auto-provisioning, allowedDomains) and the refusals the move added. Google's
 * endpoints are served by the mock provider through a b.httpClient.request
 * stub. OpenID Connect is left unconfigured here, which also covers the
 * not-configured /auth/oidc response.
 */
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var mockOp = require("../helpers/mock-oidc-provider");

var GOOGLE_CLIENT = "google-client-id.apps.googleusercontent.com";
var b;
var db;
var config;
var rateLimit;
var op;
var restoreStub;
var n = 0;
function uniq(p) { n += 1; return p + "-" + Date.now().toString(36) + "-" + n; }

async function startGoogle(client) {
  rateLimit.resetAllInstances();
  var start = await client.get("/auth/google");
  assert.strictEqual(start.status, 302, "GET /auth/google redirects (got " + start.status + ")");
  return start.location;
}

async function googleLogin(client, aopts) {
  var url = await startGoogle(client);
  var cb = op.authorize(url, aopts);
  return client.get(cb.path);
}

before(async function () {
  await testServer.start({
    env: {
      GOOGLE_CLIENT_ID: GOOGLE_CLIENT,
      GOOGLE_CLIENT_SECRET: "google-secret",
      OIDC_ENABLED: "false",
    },
  });
  b = require(path.join(testServer.projectRoot, "lib", "vendor", "blamejs"));
  db = require(path.join(testServer.projectRoot, "lib", "db"));
  config = require(path.join(testServer.projectRoot, "lib", "config"));
  rateLimit = require(path.join(testServer.projectRoot, "lib", "rate-limit"));
  op = mockOp.create({ issuer: "https://accounts.google.com", clientId: GOOGLE_CLIENT, clientSecret: "google-secret" });
  restoreStub = op.installHttpStub(b);
});

after(function () {
  if (restoreStub) restoreStub();
  return testServer.stop();
});

describe("Google sign-in", function () {
  it("sends PKCE S256, a nonce, state and prompt=select_account", async function () {
    var url = new URL(await startGoogle(new TestClient(testServer.baseUrl())));
    assert.strictEqual(url.origin, "https://accounts.google.com");
    assert.strictEqual(url.searchParams.get("code_challenge_method"), "S256");
    assert.ok(url.searchParams.get("code_challenge"), "a PKCE challenge is sent");
    assert.ok(url.searchParams.get("nonce"), "a nonce is sent");
    assert.ok(url.searchParams.get("state"), "a state is sent");
    assert.strictEqual(url.searchParams.get("prompt"), "select_account");
    assert.strictEqual(url.searchParams.get("redirect_uri"), "http://localhost/auth/google/callback");
  });

  it("signs in an existing account whose googleId equals the id_token sub", async function () {
    var email = uniq("existing") + "@gmail.test";
    var gid = uniq("gid");
    var row = db.users.insert({ email: email, googleId: gid, displayName: "Existing", authType: "google", role: "user", status: "active", createdAt: new Date().toISOString() });
    var client = new TestClient(testServer.baseUrl());
    var res = await googleLogin(client, { claims: { sub: gid, email: email } });
    assert.strictEqual(res.location, "/dashboard");
    assert.strictEqual((await client.get("/dashboard")).status, 200);
    assert.strictEqual(db.users.find({}).filter(function (u) { return u.email === email; }).length, 1);
    assert.strictEqual(db.users.findOne({ _id: row._id }).googleId, gid, "googleId is unchanged");
  });

  it("refuses an existing account when the id_token sub differs from googleId", async function () {
    var email = uniq("recycled") + "@gmail.test";
    db.users.insert({ email: email, googleId: uniq("gid-orig"), displayName: "Orig", authType: "google", role: "user", status: "active", createdAt: new Date().toISOString() });
    var res = await googleLogin(new TestClient(testServer.baseUrl()), { claims: { sub: uniq("gid-new"), email: email } });
    assert.strictEqual(res.location, "/auth/failed");
  });

  it("still auto-provisions a new Google account", async function () {
    var email = uniq("fresh") + "@gmail.test";
    var gid = uniq("gid-fresh");
    var res = await googleLogin(new TestClient(testServer.baseUrl()), { claims: { sub: gid, email: email, name: "Fresh" } });
    assert.strictEqual(res.location, "/dashboard");
    var u = db.users.find({}).filter(function (x) { return x.email === email; })[0];
    assert.ok(u, "the account was created");
    assert.strictEqual(u.authType, "google");
    assert.strictEqual(u.googleId, gid, "googleId is the id_token sub");
  });

  it("refuses a local account with the same email (no cross-provider takeover)", async function () {
    var email = uniq("local") + "@gmail.test";
    db.users.insert({ email: email, displayName: "Local", authType: "local", passwordHash: "$argon2id$placeholder", role: "user", status: "active", createdAt: new Date().toISOString() });
    var res = await googleLogin(new TestClient(testServer.baseUrl()), { claims: { sub: uniq("gid"), email: email } });
    assert.strictEqual(res.location, "/auth/failed");
  });

  it("enforces allowedDomains", async function () {
    config.updateSettings({ allowedDomains: "allowed.test" });
    try {
      var res = await googleLogin(new TestClient(testServer.baseUrl()), { claims: { sub: uniq("gid"), email: uniq("x") + "@other.test" } });
      assert.strictEqual(res.location, "/auth/failed");
    } finally {
      config.updateSettings({ allowedDomains: "" });
    }
  });

  [
    ["email_verified as the string \"true\"", { claims: { email_verified: "true" } }],
    ["email_verified false", { claims: { email_verified: false } }],
    ["a bad id_token signature", { token: "bad-signature" }],
    ["a missing id_token", { token: "no-id-token" }],
    ["a wrong nonce", { claims: { nonce: "wrong" } }],
    ["a wrong audience", { claims: { aud: "another-client" } }],
    ["a state that does not match", { state: "forged" }],
  ].forEach(function (c) {
    it("refuses " + c[0], async function () {
      var email = uniq("refused") + "@gmail.test";
      var aopts = Object.assign({}, c[1]);
      aopts.claims = Object.assign({ sub: uniq("gid"), email: email }, c[1].claims || {});
      var res = await googleLogin(new TestClient(testServer.baseUrl()), aopts);
      assert.strictEqual(res.location, "/auth/failed", c[0] + " is refused");
      assert.strictEqual(db.users.find({}).filter(function (x) { return x.email === email; }).length, 0, "no account is created");
    });
  });

  it("refuses a callback with no code after consuming the state", async function () {
    var client = new TestClient(testServer.baseUrl());
    var url = new URL(await startGoogle(client));
    var res = await client.get("/auth/google/callback?state=" + encodeURIComponent(url.searchParams.get("state")));
    assert.strictEqual(res.location, "/auth/failed");
  });
});

describe("OpenID Connect when not configured", function () {
  it("answers /auth/oidc with 500, no redirect and no pending state", async function () {
    var client = new TestClient(testServer.baseUrl());
    var res = await client.get("/auth/oidc");
    assert.strictEqual(res.status, 500);
    assert.ok(!res.location, "no redirect is sent");
    var token = client.cookies.hs_sid ? decodeURIComponent(client.cookies.hs_sid) : null;
    if (token) {
      var sess = await b.session.verify(token).catch(function () { return null; });
      var data = sess && sess.data;
      assert.ok(!data || !data.oidcState, "no oidcState was written");
    }
  });

  it("does not show the SSO button", async function () {
    var res = await new TestClient(testServer.baseUrl()).get("/auth/login");
    assert.strictEqual(String(res.text).indexOf('href="/auth/oidc"'), -1);
  });
});
