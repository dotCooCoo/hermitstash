/**
 * Linking and unlinking an OpenID Connect identity from the profile page and
 * from the admin user list, end to end against the in-process provider in
 * tests/helpers/mock-oidc-provider.js.
 *
 * A link starts at POST /profile/oidc/link, which returns the provider URL.
 * The test plays the provider's consent step and follows the redirect back to
 * /auth/oidc/callback with the same cookie jar; the callback reports the
 * outcome as /profile?sso=<code>.
 */
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var mockOp = require("../helpers/mock-oidc-provider");

var op;
var b;
var db;
var rateLimit;
var csrfPolicy;
var CLIENT_ID = "hs-oidc-link-client";
var CLIENT_SECRET = "hs-oidc-link-secret";
var PASSWORD = "password123";
var counter = 0;
var passwordHash;

function uniq(prefix) { counter += 1; return prefix + "-" + Date.now().toString(36) + "-" + counter; }

function auditActions(action) {
  return db.auditLog.find({}).filter(function (r) { return r.action === action; });
}

function insertUser(fields) {
  return db.users.insert(Object.assign({
    role: "user",
    status: "active",
    authType: "local",
    createdAt: new Date().toISOString(),
  }, fields));
}

// Read the per-session payload key from a page the signed-in client can load.
async function refreshKey(client) {
  var page = await client.get("/profile");
  var m = String(page.text || "").match(/__ak="([^"]+)"/);
  if (m) client._apiKey = m[1];
}

async function passwordLogin(email) {
  rateLimit.resetAllInstances();
  var c = new TestClient(testServer.baseUrl());
  await c.initApiKey();
  var r = await c.post("/auth/login", { json: { email: email, password: PASSWORD } });
  assert.strictEqual(r.json && r.json.success, true, "password sign-in for " + email);
  await refreshKey(c);
  return c;
}

async function oidcLogin(sub, email, client) {
  rateLimit.resetAllInstances();
  var c = client || new TestClient(testServer.baseUrl());
  var start = await c.get("/auth/oidc");
  assert.strictEqual(start.status, 302);
  var cb = op.authorize(start.location, { claims: { sub: sub, email: email } });
  var res = await c.get(cb.path);
  return { client: c, res: res };
}

// Start a link from the profile page and return the provider URL.
async function startLink(client, body) {
  rateLimit.resetAllInstances();
  return client.post("/profile/oidc/link", { json: body || { currentPassword: PASSWORD } });
}

// Finish a started link at the provider and return the callback response.
async function finishLink(client, authUrl, claims) {
  var cb = op.authorize(authUrl, { claims: claims });
  return client.get(cb.path);
}

async function setSession(client, data) {
  var token = decodeURIComponent(client.cookies.hs_sid);
  await b.session.updateData(token, data, { merge: true });
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
    },
  });
  b = require(path.join(testServer.projectRoot, "lib", "vendor", "blamejs"));
  db = require(path.join(testServer.projectRoot, "lib", "db"));
  rateLimit = require(path.join(testServer.projectRoot, "lib", "rate-limit"));
  csrfPolicy = require(path.join(testServer.projectRoot, "app", "security", "csrf-policy"));
  passwordHash = await b.auth.password.hash(PASSWORD);
});

after(async function () {
  await testServer.stop();
  await op.close();
});

describe("POST /profile/oidc/link", function () {
  it("is not exempt from CSRF protection", function () {
    assert.strictEqual(csrfPolicy.isExempt("/profile/oidc/link"), false);
    assert.strictEqual(csrfPolicy.isExempt("/profile/oidc/unlink"), false);
  });

  it("requires the current password from an account that has one", async function () {
    var email = uniq("pw") + "@corp.test";
    insertUser({ email: email, displayName: "Pw", passwordHash: passwordHash });
    var c = await passwordLogin(email);
    var missing = await startLink(c, {});
    assert.strictEqual(missing.status, 400);
    var wrong = await startLink(c, { currentPassword: "not-the-password" });
    assert.strictEqual(wrong.status, 400);
    assert.ok(/incorrect/.test(wrong.json.detail || ""), JSON.stringify(wrong.json));
  });

  it("asks for a fresh sign-in at the provider", async function () {
    var email = uniq("prompt") + "@corp.test";
    insertUser({ email: email, displayName: "Prompt", passwordHash: passwordHash });
    var c = await passwordLogin(email);
    var r = await startLink(c);
    assert.strictEqual(r.status, 200, JSON.stringify(r.json));
    var params = new URL(r.json.redirect).searchParams;
    assert.strictEqual(params.get("prompt"), "login");
    assert.strictEqual(params.get("max_age"), "0");
  });

  it("links the identity, ends the other sessions and audits the link", async function () {
    var email = uniq("link") + "@corp.test";
    var row = insertUser({ email: email, displayName: "Linker", passwordHash: passwordHash });
    var other = await passwordLogin(email);
    var c = await passwordLogin(email);
    var before = auditActions("oidc_account_linked").length;
    var r = await startLink(c);
    var sub = uniq("sub-link");
    var providerEmail = uniq("work") + "@idp.test";
    var cb = await finishLink(c, r.json.redirect, { sub: sub, email: providerEmail });
    assert.strictEqual(cb.status, 302);
    assert.strictEqual(cb.location, "/profile?sso=linked");
    var fresh = db.users.findOne({ _id: row._id });
    assert.strictEqual(fresh.oidcSubject, op.issuer + "|" + sub);
    assert.strictEqual(fresh.oidcLabel, providerEmail, "the provider address is kept as a label");
    assert.notStrictEqual(fresh.emailConfirmedVia, "oidc", "a different provider address confirms nothing");
    assert.strictEqual((await c.get("/dashboard")).status, 200, "the linking browser stays signed in");
    assert.strictEqual((await other.get("/dashboard")).status, 302, "other sessions were ended");
    var rows = auditActions("oidc_account_linked");
    assert.strictEqual(rows.length, before + 1);
    assert.ok(/method: explicit, provider email matches account: no/.test(rows[rows.length - 1].details));

    // The linked identity now signs in to the same account.
    var again = await oidcLogin(sub, providerEmail);
    assert.strictEqual(again.res.location, "/dashboard");

    // A second link attempt is refused before it reaches the provider.
    await refreshKey(c);
    var dup = await startLink(c);
    assert.strictEqual(dup.status, 409);
  });

  it("records a confirmation when the provider address matches the account", async function () {
    var email = uniq("match") + "@corp.test";
    var row = insertUser({ email: email, displayName: "Match", passwordHash: passwordHash });
    var c = await passwordLogin(email);
    var r = await startLink(c);
    var cb = await finishLink(c, r.json.redirect, { sub: uniq("sub-match"), email: email });
    assert.strictEqual(cb.location, "/profile?sso=linked");
    assert.strictEqual(db.users.findOne({ _id: row._id }).emailConfirmedVia, "oidc");
    var rows = auditActions("oidc_account_linked");
    assert.ok(/provider email matches account: yes/.test(rows[rows.length - 1].details));
  });

  it("refuses a subject that another account holds", async function () {
    var sub = uniq("sub-held");
    insertUser({ email: uniq("holder") + "@corp.test", displayName: "Holder", authType: "oidc", oidcSubject: op.issuer + "|" + sub });
    var email = uniq("taker") + "@corp.test";
    var row = insertUser({ email: email, displayName: "Taker", passwordHash: passwordHash });
    var c = await passwordLogin(email);
    var before = auditActions("oidc_link_refused").length;
    var r = await startLink(c);
    var cb = await finishLink(c, r.json.redirect, { sub: sub, email: uniq("x") + "@idp.test" });
    assert.strictEqual(cb.location, "/profile?sso=subject-in-use");
    assert.ok(!db.users.findOne({ _id: row._id }).oidcSubject);
    assert.strictEqual(auditActions("oidc_link_refused").length, before + 1);
    assert.strictEqual((await c.get("/dashboard")).status, 200, "a refused link keeps the session");
  });

  it("refuses a provider address that belongs to another account", async function () {
    var theirs = uniq("theirs") + "@corp.test";
    insertUser({ email: theirs, displayName: "Theirs", passwordHash: passwordHash });
    var email = uniq("mine") + "@corp.test";
    insertUser({ email: email, displayName: "Mine", passwordHash: passwordHash });
    var c = await passwordLogin(email);
    var r = await startLink(c);
    var cb = await finishLink(c, r.json.redirect, { sub: uniq("sub-theirs"), email: theirs });
    assert.strictEqual(cb.location, "/profile?sso=email-other-account");
  });

  it("refuses a provider sign-in older than the link request", async function () {
    var email = uniq("stale") + "@corp.test";
    var row = insertUser({ email: email, displayName: "Stale", passwordHash: passwordHash });
    var c = await passwordLogin(email);
    var r = await startLink(c);
    var cb = await finishLink(c, r.json.redirect, { sub: uniq("sub-stale"), email: uniq("s") + "@idp.test", auth_time: Math.floor(Date.now() / 1000) - 3600 });
    assert.strictEqual(cb.location, "/profile?sso=stale-auth");
    assert.ok(!db.users.findOne({ _id: row._id }).oidcSubject);
  });

  it("refuses when the browser signed in as someone else before the callback", async function () {
    var a = uniq("first") + "@corp.test";
    var bEmail = uniq("second") + "@corp.test";
    var rowA = insertUser({ email: a, displayName: "A", passwordHash: passwordHash });
    var rowB = insertUser({ email: bEmail, displayName: "B", passwordHash: passwordHash });
    var c = await passwordLogin(a);
    var r = await startLink(c);
    rateLimit.resetAllInstances();
    var li = await c.post("/auth/login", { json: { email: bEmail, password: PASSWORD } });
    assert.strictEqual(li.json.success, true);
    var cb = await finishLink(c, r.json.redirect, { sub: uniq("sub-switch"), email: uniq("sw") + "@idp.test" });
    assert.ok(cb.location === "/profile?sso=session-changed" || cb.location === "/auth/failed", cb.location);
    assert.ok(!db.users.findOne({ _id: rowA._id }).oidcSubject);
    assert.ok(!db.users.findOne({ _id: rowB._id }).oidcSubject);
  });

  it("asks for a fresh sign-in before an unlink once 10 minutes have passed", async function () {
    var sub = uniq("sub-nopw");
    var email = uniq("nopw") + "@corp.test";
    insertUser({ email: email, displayName: "NoPw", authType: "oidc", oidcSubject: op.issuer + "|" + sub });
    var s = await oidcLogin(sub, email);
    assert.strictEqual(s.res.location, "/dashboard");
    await refreshKey(s.client);
    await setSession(s.client, { authAt: Date.now() - 11 * 60 * 1000 }); // eleven minutes, past the window
    rateLimit.resetAllInstances();
    var r = await s.client.post("/profile/oidc/unlink", { json: {} });
    assert.strictEqual(r.status, 400);
    assert.strictEqual(r.json.reauth, true);
    assert.ok(/then unlink single sign-on within 10 minutes/.test(r.json.detail || ""), JSON.stringify(r.json));
  });

  it("lists the account's API keys and client certificates before a link", async function () {
    var email = uniq("keys") + "@corp.test";
    var row = insertUser({ email: email, displayName: "Keys", passwordHash: passwordHash });
    var c = await passwordLogin(email);
    var page = await c.get("/profile");
    assert.ok(!/API key/.test(String(page.text)), "no keys, no entry");
    ["Key one", "Browser: cn-one"].forEach(function (name) {
      db.apiKeys.insert({ name: name, keyHash: b.crypto.sha3Hash(uniq("k")), prefix: "hs_test", permissions: "upload", userId: row._id, createdAt: new Date().toISOString() });
    });
    page = await c.get("/profile");
    assert.ok(/2 API keys or client certificates/.test(String(page.text)), "the count is listed");
  });
});

describe("POST /profile/oidc/unlink", function () {
  it("refuses when single sign-on is the only way into the account", async function () {
    var sub = uniq("sub-only");
    var email = uniq("only") + "@corp.test";
    insertUser({ email: email, displayName: "Only", authType: "oidc", oidcSubject: op.issuer + "|" + sub });
    var s = await oidcLogin(sub, email);
    await refreshKey(s.client);
    rateLimit.resetAllInstances();
    var r = await s.client.post("/profile/oidc/unlink", { json: {} });
    assert.strictEqual(r.status, 400);
    assert.ok(/password or a passkey/.test(r.json.detail || ""), JSON.stringify(r.json));
  });

  it("unlinks, blocks the next automatic link and allows an explicit one", async function () {
    var sub = uniq("sub-unlink");
    var email = uniq("unlink") + "@corp.test";
    var row = insertUser({ email: email, displayName: "Unlink", passwordHash: passwordHash, emailConfirmedVia: "verification", emailConfirmedAt: new Date().toISOString(), oidcSubject: op.issuer + "|" + sub });
    var other = await passwordLogin(email);
    var c = await passwordLogin(email);
    var before = auditActions("oidc_account_unlinked").length;
    rateLimit.resetAllInstances();
    var r = await c.post("/profile/oidc/unlink", { json: {} });
    assert.strictEqual(r.status, 200, JSON.stringify(r.json));
    var fresh = db.users.findOne({ _id: row._id });
    assert.ok(!fresh.oidcSubject);
    assert.ok(fresh.oidcAutoLinkBlockedAt);
    assert.strictEqual((await other.get("/dashboard")).status, 302, "other sessions were ended");
    assert.strictEqual((await c.get("/dashboard")).status, 200, "this session continues");
    var rows = auditActions("oidc_account_unlinked");
    assert.strictEqual(rows.length, before + 1);
    assert.ok(/method: self/.test(rows[rows.length - 1].details));

    var auto = await oidcLogin(sub, email);
    assert.strictEqual(auto.res.location, "/auth/failed", "the confirmed address no longer links by itself");
    assert.ok(!db.users.findOne({ _id: row._id }).oidcSubject);

    await refreshKey(c);
    var start = await startLink(c);
    var cb = await finishLink(c, start.json.redirect, { sub: sub, email: email });
    assert.strictEqual(cb.location, "/profile?sso=linked");
    var relinked = db.users.findOne({ _id: row._id });
    assert.strictEqual(relinked.oidcSubject, op.issuer + "|" + sub);
    assert.ok(!relinked.oidcAutoLinkBlockedAt, "an explicit link clears the block");
  });
});

describe("admin user list and admin unlink", function () {
  var admin;
  var adminEmail;

  before(async function () {
    adminEmail = uniq("admin") + "@corp.test";
    insertUser({ email: adminEmail, displayName: "Admin", role: "admin", passwordHash: passwordHash });
    admin = await passwordLogin(adminEmail);
  });

  it("reports sign-in methods as flags and never the identifiers", async function () {
    var sub = uniq("sub-list");
    var email = uniq("listed") + "@corp.test";
    var row = insertUser({ email: email, displayName: "Listed", passwordHash: passwordHash, googleId: uniq("gid"), oidcSubject: op.issuer + "|" + sub, oidcLabel: "label@idp.test", emailConfirmedVia: "invite", emailConfirmedAt: new Date().toISOString() });
    rateLimit.resetAllInstances();
    var r = await admin.get("/admin/users/api?q=" + encodeURIComponent(email));
    assert.strictEqual(r.status, 200);
    var u = r.json.users.filter(function (x) { return x._id === row._id; })[0];
    assert.ok(u, "the account is listed");
    ["googleId", "tailscaleId", "tailscaleIdHash", "oidcSubject", "oidcSubjectHash", "passwordHash"].forEach(function (k) {
      assert.strictEqual(u[k], undefined, k + " is not reported");
    });
    assert.strictEqual(u.googleLinked, true);
    assert.strictEqual(u.tailscaleLinked, false);
    assert.strictEqual(u.oidcLinked, true);
    assert.strictEqual(u.oidcLabel, "label@idp.test");
    assert.strictEqual(u.emailConfirmed, true);
    assert.strictEqual(u.emailConfirmedVia, "invite");
  });

  it("unlinks an account that keeps another method and ends its sessions", async function () {
    var sub = uniq("sub-adm");
    var email = uniq("adm-target") + "@corp.test";
    var row = insertUser({ email: email, displayName: "Target", passwordHash: passwordHash, oidcSubject: op.issuer + "|" + sub });
    var victim = await passwordLogin(email);
    var before = auditActions("oidc_account_unlinked").length;
    rateLimit.resetAllInstances();
    var r = await admin.post("/admin/users/" + row._id + "/oidc/unlink", { json: {} });
    assert.strictEqual(r.status, 200, JSON.stringify(r.json));
    var fresh = db.users.findOne({ _id: row._id });
    assert.ok(!fresh.oidcSubject);
    assert.ok(fresh.oidcAutoLinkBlockedAt);
    assert.strictEqual((await victim.get("/dashboard")).status, 302, "the account's sessions were ended");
    var rows = auditActions("oidc_account_unlinked");
    assert.strictEqual(rows.length, before + 1);
    assert.ok(/method: admin/.test(rows[rows.length - 1].details));
  });

  it("refuses to unlink an account with no other method or no link", async function () {
    var row = insertUser({ email: uniq("adm-only") + "@corp.test", displayName: "OnlySso", authType: "oidc", oidcSubject: op.issuer + "|" + uniq("sub-ao") });
    rateLimit.resetAllInstances();
    var r = await admin.post("/admin/users/" + row._id + "/oidc/unlink", { json: {} });
    assert.strictEqual(r.status, 400);
    assert.ok(db.users.findOne({ _id: row._id }).oidcSubject);
    var plain = insertUser({ email: uniq("adm-plain") + "@corp.test", displayName: "Plain", passwordHash: passwordHash });
    var r2 = await admin.post("/admin/users/" + plain._id + "/oidc/unlink", { json: {} });
    assert.strictEqual(r2.status, 400);
  });

  it("is refused to a non-admin", async function () {
    var email = uniq("nonadmin") + "@corp.test";
    insertUser({ email: email, displayName: "User", passwordHash: passwordHash });
    var target = insertUser({ email: uniq("t") + "@corp.test", displayName: "T", passwordHash: passwordHash, oidcSubject: op.issuer + "|" + uniq("sub-t") });
    var c = await passwordLogin(email);
    rateLimit.resetAllInstances();
    var r = await c.post("/admin/users/" + target._id + "/oidc/unlink", { json: {} });
    assert.notStrictEqual(r.status, 200);
    assert.ok(db.users.findOne({ _id: target._id }).oidcSubject);
  });
});
