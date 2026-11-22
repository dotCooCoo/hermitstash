/**
 * Generic OpenID Connect sign-in, end to end against an in-process provider.
 *
 * The provider (tests/helpers/mock-oidc-provider.js) listens on 127.0.0.1 and
 * signs id_tokens with RS256. The server reaches it over plain http because
 * OIDC_ALLOW_INTERNAL names 127.0.0.1/32; that is ordinary configuration, not
 * a test mode. Every login walks the real chain: GET /auth/oidc writes the
 * pending state and redirects to the provider, the mock records the consent,
 * and the test follows the redirect back to /auth/oidc/callback with the same
 * cookie jar.
 */
var { describe, it, before, after, beforeEach } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var mockOp = require("../helpers/mock-oidc-provider");

var op;
var b;
var db;
var config;
var oidc;
var rateLimit;
var CLIENT_ID = "hs-oidc-client";
var CLIENT_SECRET = "hs-oidc-secret-value";
var counter = 0;

function uniq(prefix) { counter += 1; return prefix + "-" + Date.now().toString(36) + "-" + counter; }

async function startLogin(client) {
  var res = await client.get("/auth/oidc");
  assert.strictEqual(res.status, 302, "GET /auth/oidc redirects to the provider (got " + res.status + ")");
  assert.ok(res.location.indexOf(op.issuer + "/authorize?") === 0, "redirect goes to the provider's authorization endpoint");
  return res.location;
}

// Full login. Returns the callback response.
async function login(client, aopts) {
  rateLimit.resetAllInstances();
  var authUrl = await startLogin(client);
  var cb = op.authorize(authUrl, aopts);
  return client.get(cb.path);
}

function usersBySubject(sub) {
  return db.users.find({ oidcSubject: op.issuer + "|" + sub });
}

// `action` is sealed, so rows are unsealed and filtered here.
function auditActions(action) {
  return db.auditLog.find({}).filter(function (r) { return r.action === action; });
}

function insertUser(fields) {
  return db.users.insert(Object.assign({
    role: "user",
    status: "active",
    createdAt: new Date().toISOString(),
  }, fields));
}

async function expectFailed(res, msg) {
  assert.strictEqual(res.status, 302, msg + " (status " + res.status + ")");
  assert.strictEqual(res.location, "/auth/failed", msg);
}

before(async function () {
  op = mockOp.create({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });
  await op.listen();
  await testServer.start({
    env: {
      OIDC_ENABLED: "true",
      OIDC_ISSUER: op.issuer,
      OIDC_CLIENT_ID: CLIENT_ID,
      OIDC_CLIENT_SECRET: CLIENT_SECRET,
      OIDC_ALLOW_INTERNAL: "127.0.0.1/32",
      OIDC_AUTO_PROVISION: "true",
      OIDC_ALLOWLIST: "new.user@corp.test, race@corp.test, userinfo@corp.test, ui-noverified@corp.test, ui-falseverified@corp.test",
    },
  });
  b = require(path.join(testServer.projectRoot, "lib", "vendor", "blamejs"));
  db = require(path.join(testServer.projectRoot, "lib", "db"));
  config = require(path.join(testServer.projectRoot, "lib", "config"));
  oidc = require(path.join(testServer.projectRoot, "lib", "oidc"));
  rateLimit = require(path.join(testServer.projectRoot, "lib", "rate-limit"));
});

after(async function () {
  await testServer.stop();
  await op.close();
});

beforeEach(function () {
  op.discoveryOverrides = {};
});

describe("OIDC sign-in: provisioning and returning users", function () {
  it("provisions an allowlisted user and binds the issuer-scoped subject", async function () {
    var client = new TestClient(testServer.baseUrl());
    var sub = uniq("sub-new");
    var res = await login(client, { claims: { sub: sub, email: "new.user@corp.test", name: "New User" } });
    assert.strictEqual(res.status, 302);
    assert.strictEqual(res.location, "/dashboard");
    var rows = usersBySubject(sub);
    assert.strictEqual(rows.length, 1, "exactly one account bound to the subject");
    assert.strictEqual(rows[0].authType, "oidc");
    assert.strictEqual(rows[0].email, "new.user@corp.test");
    assert.strictEqual(rows[0].role, "user", "OIDC never applies the first-user-admin rule");
    var dash = await client.get("/dashboard");
    assert.strictEqual(dash.status, 200, "the session is fully authenticated");

    // Returning login with the same subject resolves the same account.
    var again = await login(new TestClient(testServer.baseUrl()), { claims: { sub: sub, email: "new.user@corp.test" } });
    assert.strictEqual(again.location, "/dashboard");
    assert.strictEqual(usersBySubject(sub).length, 1, "no duplicate account on re-login");
  });

  it("refuses to provision a user who is not on the allowlist", async function () {
    var sub = uniq("sub-stranger");
    var before = auditActions("oidc_provision_denied").length;
    var res = await login(new TestClient(testServer.baseUrl()), { claims: { sub: sub, email: "stranger@corp.test" } });
    await expectFailed(res, "provisioning outside the allowlist is refused");
    assert.strictEqual(usersBySubject(sub).length, 0);
    assert.strictEqual(auditActions("oidc_provision_denied").length, before + 1, "the refusal is audited");
  });

  it("keeps one account when two callbacks for a new subject race", async function () {
    var sub = uniq("sub-race");
    var c1 = new TestClient(testServer.baseUrl());
    var c2 = new TestClient(testServer.baseUrl());
    rateLimit.resetAllInstances();
    var u1 = await startLogin(c1);
    var u2 = await startLogin(c2);
    var cb1 = op.authorize(u1, { claims: { sub: sub, email: "race@corp.test" } });
    var cb2 = op.authorize(u2, { claims: { sub: sub, email: "race@corp.test" } });
    var results = await Promise.all([c1.get(cb1.path), c2.get(cb2.path)]);
    results.forEach(function (r) { assert.strictEqual(r.status, 302); });
    assert.strictEqual(usersBySubject(sub).length, 1, "the race leaves a single account");
  });

  it("sends a TOTP-enabled account to /2fa without a full session", async function () {
    var sub = uniq("sub-totp");
    var email = uniq("totp") + "@corp.test";
    insertUser({
      email: email, displayName: "TOTP", authType: "oidc", oidcSubject: op.issuer + "|" + sub,
      totpEnabled: "true", totpSecret: b.crypto.generateBytes(64).toString("base64"), totpAlgorithm: "SHA-512",
    });
    var client = new TestClient(testServer.baseUrl());
    var res = await login(client, { claims: { sub: sub, email: email } });
    assert.strictEqual(res.location, "/2fa");
    var dash = await client.get("/dashboard");
    assert.strictEqual(dash.status, 302, "no full session before TOTP");
  });
});

describe("OIDC sign-in: state, PKCE and callback refusals", function () {
  it("refuses a callback whose state does not match", async function () {
    var res = await login(new TestClient(testServer.baseUrl()), { state: "forged-state", claims: { sub: uniq("s") } });
    await expectFailed(res, "state mismatch is refused");
  });

  it("refuses a replayed callback (state is single-use)", async function () {
    var client = new TestClient(testServer.baseUrl());
    rateLimit.resetAllInstances();
    var sub = uniq("sub-replay");
    var email = uniq("replay") + "@corp.test";
    insertUser({ email: email, displayName: "Replay", authType: "oidc", oidcSubject: op.issuer + "|" + sub });
    var authUrl = await startLogin(client);
    var cb = op.authorize(authUrl, { claims: { sub: sub, email: email } });
    var first = await client.get(cb.path);
    assert.strictEqual(first.location, "/dashboard", "the first use succeeds");
    var second = await new TestClient(testServer.baseUrl()).get(cb.path);
    await expectFailed(second, "the callback URL replayed from another browser is refused");
    var third = await client.get(cb.path);
    await expectFailed(third, "the same callback cannot be used twice in the same browser");
  });

  it("refuses a callback after the state has expired", async function () {
    var client = new TestClient(testServer.baseUrl());
    rateLimit.resetAllInstances();
    var authUrl = await startLogin(client);
    var params = new URL(authUrl).searchParams;
    var token = decodeURIComponent(client.cookies.hs_sid);
    await b.session.updateData(token, { oidcState: { value: params.get("state"), nonce: params.get("nonce"), verifier: "x", ts: Date.now() - 6 * 60 * 1000, gen: 0 } });
    var cb = op.authorize(authUrl, { claims: { sub: uniq("s") } });
    await expectFailed(await client.get(cb.path), "an expired state is refused");
  });

  it("refuses a callback with no pending state", async function () {
    var client = new TestClient(testServer.baseUrl());
    rateLimit.resetAllInstances();
    await client.get("/auth/login");
    await expectFailed(await client.get("/auth/oidc/callback?code=abc&state=def"), "a callback without a started login is refused");
  });

  it("refuses a repeated callback parameter", async function () {
    var res = await login(new TestClient(testServer.baseUrl()), { extraQuery: ["code", "second"], claims: { sub: uniq("s") } });
    await expectFailed(res, "a duplicated code parameter is refused");
  });

  it("refuses an RFC 9207 iss parameter naming another issuer", async function () {
    var res = await login(new TestClient(testServer.baseUrl()), { iss: "https://evil.example", claims: { sub: uniq("s") } });
    await expectFailed(res, "an iss mix-up is refused");
  });

  it("refuses a provider error response without echoing its description", async function () {
    var client = new TestClient(testServer.baseUrl());
    rateLimit.resetAllInstances();
    var authUrl = await startLogin(client);
    var state = new URL(authUrl).searchParams.get("state");
    var res = await client.get("/auth/oidc/callback?error=access_denied&error_description=" + encodeURIComponent("secret-description-text") + "&state=" + state);
    await expectFailed(res, "a provider error fails the login");
    var rows = auditActions("auth_failed_page").filter(function (r) { return String(r.details || "").indexOf("secret-description-text") !== -1; });
    assert.strictEqual(rows.length, 0, "error_description never reaches the audit log");
  });

  it("rate-limits the callback at 10 per minute", async function () {
    rateLimit.resetAllInstances();
    var client = new TestClient(testServer.baseUrl());
    var last = null;
    for (var i = 0; i < 11; i++) last = await client.get("/auth/oidc/callback?code=x&state=y");
    assert.strictEqual(last.status, 429, "the 11th callback in a minute is refused");
    rateLimit.resetAllInstances();
  });
});

describe("OIDC sign-in: id_token refusals", function () {
  var cases = [
    ["alg none", { token: "alg-none" }],
    ["HS256 signed with the client secret", { token: "hs256" }],
    ["an unknown kid", { token: "unknown-kid" }],
    ["a bad signature", { token: "bad-signature" }],
    ["a missing id_token", { token: "no-id-token" }],
    ["a wrong nonce", { claims: { nonce: "not-the-nonce" } }],
    ["a missing nonce", { claims: { nonce: undefined } }],
    ["a wrong issuer", { claims: { iss: "https://other-issuer.example" } }],
    ["a wrong audience", { claims: { aud: "someone-else" } }],
    ["several audiences without azp", { claims: { aud: [CLIENT_ID, "someone-else"] } }],
    ["an expired token", { claims: { exp: Math.floor(Date.now() / 1000) - 3600, iat: Math.floor(Date.now() / 1000) - 7200 } }],
  ];
  cases.forEach(function (c) {
    it("refuses " + c[0], async function () {
      var sub = uniq("sub-bad");
      var aopts = Object.assign({}, c[1]);
      aopts.claims = Object.assign({ sub: sub, email: "new.user@corp.test" }, c[1].claims || {});
      var res = await login(new TestClient(testServer.baseUrl()), aopts);
      await expectFailed(res, c[0] + " is refused");
      assert.strictEqual(usersBySubject(sub).length, 0, "no account is created");
    });
  });

  [["false", false], ["the string \"true\"", "true"], ["missing", undefined]].forEach(function (c) {
    it("does not treat email_verified " + c[0] + " as verified", async function () {
      var sub = uniq("sub-unverified");
      var res = await login(new TestClient(testServer.baseUrl()), { claims: { sub: sub, email: "new.user@corp.test", email_verified: c[1] } });
      await expectFailed(res, "an unverified email cannot provision");
      assert.strictEqual(usersBySubject(sub).length, 0);
    });
  });

  it("does not link an existing account on an unverified email", async function () {
    var email = uniq("unverified-link") + "@corp.test";
    var row = insertUser({ email: email, displayName: "Local", authType: "local", passwordHash: "$argon2id$placeholder" });
    var res = await login(new TestClient(testServer.baseUrl()), { claims: { sub: uniq("s"), email: email, email_verified: false } });
    await expectFailed(res, "unverified email does not link");
    assert.ok(!db.users.findOne({ _id: row._id }).oidcSubject, "the account stays unlinked");
  });

  it("reads a verified email from userinfo when the id_token has none", async function () {
    var sub = uniq("sub-userinfo");
    var res = await login(new TestClient(testServer.baseUrl()), {
      claims: { sub: sub, email: undefined, email_verified: undefined },
      userinfo: { sub: sub, email: "userinfo@corp.test", email_verified: true },
    });
    assert.strictEqual(res.location, "/dashboard", "userinfo supplied the verified email");
    assert.strictEqual(usersBySubject(sub)[0].email, "userinfo@corp.test");
  });

  it("refuses userinfo whose sub differs from the id_token", async function () {
    var sub = uniq("sub-uimismatch");
    var res = await login(new TestClient(testServer.baseUrl()), {
      claims: { sub: sub, email: undefined, email_verified: undefined },
      userinfo: { sub: "someone-else", email: "new.user@corp.test", email_verified: true },
    });
    await expectFailed(res, "a userinfo sub mismatch leaves no verified email");
    assert.strictEqual(usersBySubject(sub).length, 0);
  });

  it("reads a verified email from userinfo when the id_token email has no email_verified", async function () {
    var sub = uniq("sub-ui-noverified");
    var res = await login(new TestClient(testServer.baseUrl()), {
      claims: { sub: sub, email: "ui-noverified@corp.test", email_verified: undefined },
      userinfo: { sub: sub, email: "ui-noverified@corp.test", email_verified: true },
    });
    assert.strictEqual(res.location, "/dashboard", "userinfo supplied the verified email");
    assert.strictEqual(usersBySubject(sub)[0].email, "ui-noverified@corp.test");
  });

  it("reads a verified email from userinfo when the id_token says email_verified false", async function () {
    var sub = uniq("sub-ui-falseverified");
    var res = await login(new TestClient(testServer.baseUrl()), {
      claims: { sub: sub, email: "ui-falseverified@corp.test", email_verified: false },
      userinfo: { sub: sub, email: "ui-falseverified@corp.test", email_verified: true },
    });
    assert.strictEqual(res.location, "/dashboard", "userinfo supplied the verified email");
    assert.strictEqual(usersBySubject(sub)[0].email, "ui-falseverified@corp.test");
  });

  it("links an existing account on an email that only userinfo marks verified", async function () {
    var sub = uniq("sub-ui-link");
    var email = uniq("ui-link") + "@corp.test";
    var row = insertUser({ email: email, displayName: "Local", authType: "local", passwordHash: "$argon2id$placeholder" });
    var res = await login(new TestClient(testServer.baseUrl()), {
      claims: { sub: sub, email: email, email_verified: false },
      userinfo: { sub: sub, email: email, email_verified: true },
    });
    assert.strictEqual(res.location, "/dashboard", "the verified userinfo email links the account");
    assert.strictEqual(db.users.findOne({ _id: row._id }).oidcSubject, op.issuer + "|" + sub);
  });

  it("refuses when neither the id_token nor userinfo marks the email verified", async function () {
    var sub = uniq("sub-ui-unverified");
    function noVerifiedEmailRows() {
      return auditActions("auth_failed_page").filter(function (r) { return String(r.details || "").indexOf("no-verified-email") !== -1; }).length;
    }
    var before = noVerifiedEmailRows();
    var res = await login(new TestClient(testServer.baseUrl()), {
      claims: { sub: sub, email: "new.user@corp.test", email_verified: false },
      userinfo: { sub: sub, email: "new.user@corp.test", email_verified: false },
    });
    await expectFailed(res, "an email unverified in both sources cannot provision");
    assert.strictEqual(usersBySubject(sub).length, 0);
    assert.strictEqual(noVerifiedEmailRows(), before + 1, "refused with the reason an unverified id_token email gets");
  });

  it("refuses a userinfo sub mismatch when the id_token email is unverified", async function () {
    var sub = uniq("sub-ui-mismatch-unverified");
    var res = await login(new TestClient(testServer.baseUrl()), {
      claims: { sub: sub, email: "new.user@corp.test", email_verified: false },
      userinfo: { sub: "someone-else", email: "new.user@corp.test", email_verified: true },
    });
    await expectFailed(res, "a userinfo sub mismatch leaves no verified email");
    assert.strictEqual(usersBySubject(sub).length, 0);
  });
});

describe("OIDC sign-in: discovery refusals", function () {
  it("refuses a discovery document whose issuer differs", async function () {
    op.discoveryOverrides = { issuer: "https://not-the-issuer.example" };
    oidc.reset();
    var res = await new TestClient(testServer.baseUrl()).get("/auth/oidc");
    assert.strictEqual(res.status, 502, "the login does not start");
    assert.ok(!res.location, "no redirect is sent");
    op.discoveryOverrides = {};
    oidc.reset();
  });

  it("refuses a discovery document that drops S256", async function () {
    op.discoveryOverrides = { code_challenge_methods_supported: ["plain"] };
    oidc.reset();
    var res = await new TestClient(testServer.baseUrl()).get("/auth/oidc");
    assert.strictEqual(res.status, 502, "a PKCE downgrade does not start a login");
    op.discoveryOverrides = {};
    oidc.reset();
  });

  it("fails a login that started before the client was rebuilt", async function () {
    var client = new TestClient(testServer.baseUrl());
    rateLimit.resetAllInstances();
    var authUrl = await startLogin(client);
    oidc.reset();
    var cb = op.authorize(authUrl, { claims: { sub: uniq("s"), email: "new.user@corp.test" } });
    await expectFailed(await client.get(cb.path), "a state from an earlier client generation is refused");
  });
});

describe("OIDC sign-in: account linking", function () {
  it("links an existing local account on a verified email and audits it", async function () {
    var email = uniq("link-local") + "@corp.test";
    var row = insertUser({ email: email, displayName: "Local User", authType: "local", passwordHash: "$argon2id$placeholder" });
    var sub = uniq("sub-link");
    var before = auditActions("oidc_account_linked").length;
    var res = await login(new TestClient(testServer.baseUrl()), { claims: { sub: sub, email: email, name: "IdP Name" } });
    assert.strictEqual(res.location, "/dashboard");
    var fresh = db.users.findOne({ _id: row._id });
    assert.strictEqual(fresh.oidcSubject, op.issuer + "|" + sub, "the subject is bound to the existing account");
    assert.strictEqual(fresh.authType, "local", "the account keeps its own sign-in method");
    assert.strictEqual(fresh.displayName, "Local User", "a linked non-OIDC account keeps its display name");
    assert.strictEqual(auditActions("oidc_account_linked").length, before + 1);
  });

  it("links an existing Google account on a verified email", async function () {
    var email = uniq("link-google") + "@corp.test";
    var row = insertUser({ email: email, displayName: "G", authType: "google", googleId: uniq("gid") });
    var res = await login(new TestClient(testServer.baseUrl()), { claims: { sub: uniq("sub"), email: email } });
    assert.strictEqual(res.location, "/dashboard");
    assert.ok(db.users.findOne({ _id: row._id }).oidcSubject);
  });

  it("refuses an account already bound to a different subject", async function () {
    var email = uniq("bound") + "@corp.test";
    var row = insertUser({ email: email, displayName: "Bound", authType: "oidc", oidcSubject: op.issuer + "|original-sub" });
    var res = await login(new TestClient(testServer.baseUrl()), { claims: { sub: uniq("other-sub"), email: email } });
    await expectFailed(res, "same email with a different subject is refused");
    assert.strictEqual(db.users.findOne({ _id: row._id }).oidcSubject, op.issuer + "|original-sub");
  });

  it("refuses to link a pending account", async function () {
    var email = uniq("pending") + "@corp.test";
    var row = insertUser({ email: email, displayName: "Pending", authType: "local", status: "pending", passwordHash: "$argon2id$placeholder" });
    var res = await login(new TestClient(testServer.baseUrl()), { claims: { sub: uniq("sub"), email: email } });
    await expectFailed(res, "a pending account is not linked");
    assert.ok(!db.users.findOne({ _id: row._id }).oidcSubject);
  });

  it("refuses a suspended account", async function () {
    var sub = uniq("sub-susp");
    var email = uniq("susp") + "@corp.test";
    insertUser({ email: email, displayName: "S", authType: "oidc", oidcSubject: op.issuer + "|" + sub, status: "suspended" });
    await expectFailed(await login(new TestClient(testServer.baseUrl()), { claims: { sub: sub, email: email } }), "a suspended account cannot sign in");
  });
});

describe("OIDC sign-in: groups and roles", function () {
  after(function () {
    config.updateSettings({ oidcRequiredGroup: "", oidcAdminGroup: "" });
  });

  it("revokes sessions and refuses sign-in when the required group is removed", async function () {
    var sub = uniq("sub-group");
    var email = uniq("group") + "@corp.test";
    insertUser({ email: email, displayName: "Grouped", authType: "oidc", oidcSubject: op.issuer + "|" + sub });
    config.updateSettings({ oidcRequiredGroup: "hs-users" });

    var first = new TestClient(testServer.baseUrl());
    var ok = await login(first, { claims: { sub: sub, email: email, groups: ["hs-users"] } });
    assert.strictEqual(ok.location, "/dashboard");
    assert.strictEqual((await first.get("/dashboard")).status, 200);

    var before = auditActions("oidc_group_denied").length;
    var denied = await login(new TestClient(testServer.baseUrl()), { claims: { sub: sub, email: email, groups: ["other"] } });
    await expectFailed(denied, "a user removed from the required group is refused");
    assert.strictEqual(auditActions("oidc_group_denied").length, before + 1);
    assert.strictEqual((await first.get("/dashboard")).status, 302, "the earlier session was revoked");
  });

  it("refuses when the required group is set and the provider supplies no groups", async function () {
    var sub = uniq("sub-nogroups");
    var email = uniq("nogroups") + "@corp.test";
    insertUser({ email: email, displayName: "N", authType: "oidc", oidcSubject: op.issuer + "|" + sub });
    config.updateSettings({ oidcRequiredGroup: "hs-users" });
    var res = await login(new TestClient(testServer.baseUrl()), { claims: { sub: sub, email: email }, userinfo: null });
    await expectFailed(res, "unknown groups fail closed for the required group");
    config.updateSettings({ oidcRequiredGroup: "" });
  });

  it("reads groups from a dotted claim path", async function () {
    var sub = uniq("sub-dotted");
    var email = uniq("dotted") + "@corp.test";
    insertUser({ email: email, displayName: "D", authType: "oidc", oidcSubject: op.issuer + "|" + sub });
    config.updateSettings({ oidcRequiredGroup: "hs-users", oidcGroupsClaim: "realm_access.roles" });
    var res = await login(new TestClient(testServer.baseUrl()), { claims: { sub: sub, email: email, realm_access: { roles: ["hs-users"] } } });
    assert.strictEqual(res.location, "/dashboard");
    config.updateSettings({ oidcRequiredGroup: "", oidcGroupsClaim: "groups" });
  });

  it("promotes on the admin group and demotes on removal, revoking sessions", async function () {
    config.updateSettings({ oidcAdminGroup: "hs-admins" });
    // A second active admin so the demotion is not blocked by the last-admin guard.
    insertUser({ email: uniq("other-admin") + "@corp.test", displayName: "Other Admin", authType: "local", role: "admin" });
    var sub = uniq("sub-admin");
    var email = uniq("admin") + "@corp.test";
    var row = insertUser({ email: email, displayName: "A", authType: "oidc", oidcSubject: op.issuer + "|" + sub });

    var c1 = new TestClient(testServer.baseUrl());
    var up = await login(c1, { claims: { sub: sub, email: email, groups: ["hs-admins"] } });
    assert.strictEqual(up.location, "/dashboard");
    assert.strictEqual(db.users.findOne({ _id: row._id }).role, "admin", "promoted by the admin group");
    assert.strictEqual((await c1.get("/dashboard")).status, 200);

    var c2 = new TestClient(testServer.baseUrl());
    var down = await login(c2, { claims: { sub: sub, email: email, groups: [] } });
    assert.strictEqual(down.location, "/dashboard", "a demoted user still signs in");
    assert.strictEqual(db.users.findOne({ _id: row._id }).role, "user", "demoted when removed from the admin group");
    assert.strictEqual((await c1.get("/dashboard")).status, 302, "the session from before the demotion was revoked");
    assert.strictEqual((await c2.get("/dashboard")).status, 200, "the new session works");
  });

  it("leaves the role alone when the provider supplies no groups", async function () {
    config.updateSettings({ oidcAdminGroup: "hs-admins" });
    var sub = uniq("sub-keep");
    var email = uniq("keep") + "@corp.test";
    var row = insertUser({ email: email, displayName: "K", authType: "oidc", oidcSubject: op.issuer + "|" + sub, role: "admin" });
    var res = await login(new TestClient(testServer.baseUrl()), { claims: { sub: sub, email: email }, userinfo: null });
    assert.strictEqual(res.location, "/dashboard");
    assert.strictEqual(db.users.findOne({ _id: row._id }).role, "admin", "a failed userinfo read does not demote");
  });

  it("never demotes the last active admin", async function () {
    config.updateSettings({ oidcAdminGroup: "hs-admins" });
    var admins = db.users.find({ role: "admin", status: "active" });
    // Leave exactly one active admin: the account under test.
    admins.forEach(function (a) { db.users.update({ _id: a._id }, { $set: { role: "user" } }); });
    var sub = uniq("sub-last");
    var email = uniq("last") + "@corp.test";
    var row = insertUser({ email: email, displayName: "Last", authType: "oidc", oidcSubject: op.issuer + "|" + sub, role: "admin" });
    var before = auditActions("oidc_role_sync_refused").length;
    var res = await login(new TestClient(testServer.baseUrl()), { claims: { sub: sub, email: email, groups: [] } });
    assert.strictEqual(res.location, "/dashboard");
    assert.strictEqual(db.users.findOne({ _id: row._id }).role, "admin", "the last admin keeps admin");
    assert.strictEqual(auditActions("oidc_role_sync_refused").length, before + 1);
    admins.forEach(function (a) { db.users.update({ _id: a._id }, { $set: { role: "admin" } }); });
  });
});

describe("OIDC settings", function () {
  it("refuses auto-provision with neither an allowlist nor a required group", function () {
    assert.throws(function () { config.updateSettings({ oidcAllowlist: "" }); }, /OIDC_AUTO_PROVISION/);
  });

  it("refuses an http issuer outside the allowed internal ranges", function () {
    assert.throws(function () { config.updateSettings({ oidcAllowInternal: "10.9.9.9/32" }); }, /OIDC_ISSUER must use https/);
  });

  it("allows passwords to be disabled while OIDC is a working sign-in method", function () {
    var saved = { localAuth: config.localAuth, passkeyEnabled: config.passkeyEnabled };
    try {
      config.updateSettings({ localAuth: "false", passkeyEnabled: "false" });
      assert.strictEqual(config.localAuth, false);
    } finally {
      config.updateSettings({ localAuth: String(saved.localAuth), passkeyEnabled: String(saved.passkeyEnabled) });
    }
  });

  it("counts a linked OIDC identity in the lockout warning only while OIDC is on", function () {
    var saved = { localAuth: config.localAuth, passkeyEnabled: config.passkeyEnabled };
    var email = uniq("lockout") + "@corp.test";
    insertUser({ email: email, displayName: "Lockout", authType: "local", passwordHash: "x", oidcSubject: op.issuer + "|" + uniq("sub-lock") });
    try {
      var on = config.updateSettings({ localAuth: "false", passkeyEnabled: "true" });
      assert.ok(on.warnings.join(" ").indexOf(email) === -1, "a linked account is not reported while OIDC is on");
      config.updateSettings({ localAuth: "true" });
      config.updateSettings({ oidcEnabled: "false" });
      var off = config.updateSettings({ localAuth: "false" });
      assert.ok(off.warnings.join(" ").indexOf(email) !== -1, "a linked account is reported once OIDC is off");
    } finally {
      config.updateSettings({ localAuth: String(saved.localAuth), passkeyEnabled: String(saved.passkeyEnabled), oidcEnabled: "true" });
    }
  });

  it("refuses to turn OIDC off when it is the only sign-in method left", function () {
    var saved = { localAuth: config.localAuth, passkeyEnabled: config.passkeyEnabled, google: config.google.clientID };
    try {
      config.updateSettings({ localAuth: "false", passkeyEnabled: "false", googleClientID: "" });
      assert.throws(function () { config.updateSettings({ oidcEnabled: "false" }); }, /Cannot disable password authentication/);
      assert.strictEqual(config.oidc.enabled, true);
    } finally {
      config.updateSettings({ localAuth: String(saved.localAuth), passkeyEnabled: String(saved.passkeyEnabled), googleClientID: saved.google || "" });
    }
  });

  it("shows the login button with the configured label", async function () {
    var res = await new TestClient(testServer.baseUrl()).get("/auth/login");
    assert.strictEqual(res.status, 200);
    assert.ok(String(res.text).indexOf('href="/auth/oidc"') !== -1, "the login page links to /auth/oidc");
    assert.ok(String(res.text).indexOf("Sign in with SSO") !== -1, "the default label is shown");
  });

  it("masks the client secret in the settings view", function () {
    var s = config.getSettings();
    assert.ok(/^•+$/.test(s.oidcClientSecret), "the secret is masked");
  });
});
