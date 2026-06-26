const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;

var memberId, stashId;
var STASH_SLUG = "acme-co";

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());

  var b = require(path.join(testServer.projectRoot, "lib", "vendor", "blamejs"));
  var vault = require(path.join(testServer.projectRoot, "lib", "vault"));
  var { hashEmail } = require(path.join(testServer.projectRoot, "lib", "crypto"));
  var { users } = require(path.join(testServer.projectRoot, "lib", "db"));
  async function seed(email, name, role, pw) {
    var u = users.insert({
      email: vault.seal(email), emailHash: hashEmail(email), displayName: vault.seal(name),
      passwordHash: await b.auth.password.hash(pw), authType: "local", role: role, status: "active",
      createdAt: new Date().toISOString(),
    });
    return u._id;
  }
  await seed("smadmin@test.com", "SM Admin", "admin", "adminpass123");
  memberId = await seed("smmember@test.com", "Stash Member", "user", "memberpass123");
  await seed("smoutsider@test.com", "Outsider", "user", "outsiderpass123");
});

after(function () { return testServer.stop(); });

async function login(email, pw) {
  client.clearCookies();
  await client.initApiKey();
  testServer.resetAllRateLimits();
  var r = await client.post("/auth/login", { json: { email: email, password: pw } });
  assert.strictEqual(r.json.success, true, email + " login should succeed");
}

describe("customer stash members", function () {
  it("admin creates a stash", async function () {
    await login("smadmin@test.com", "adminpass123");
    var res = await client.post("/admin/stash/create", { json: { name: "Acme Co", slug: STASH_SLUG } });
    assert.ok(res.json.success, "stash created");
    var stashRepo = require(path.join(testServer.projectRoot, "app", "data", "repositories", "stash.repo"));
    var s = stashRepo.findBySlug(STASH_SLUG);
    assert.ok(s, "stash row exists");
    stashId = s._id;
  });

  it("seeds a completed upload into the stash", function () {
    var bundlesRepo = require(path.join(testServer.projectRoot, "app", "data", "repositories", "bundles.repo"));
    var bundle = bundlesRepo.create({
      shareId: "smbundle1", bundleName: "Q4 Report", uploaderName: "Visitor",
      stashId: stashId, status: "complete", receivedFiles: 2, totalSize: 2048,
      createdAt: new Date().toISOString(),
    });
    assert.ok(bundle && bundle._id);
  });

  it("admin adds a user to the stash by email", async function () {
    await login("smadmin@test.com", "adminpass123");
    var res = await client.post("/admin/stash/" + stashId + "/members/add", { json: { email: "smmember@test.com" } });
    assert.strictEqual(res.json.success, true, "member added");
    var list = await client.get("/admin/stash/" + stashId + "/members");
    assert.strictEqual(list.json.total, 1, "one member listed");
    assert.strictEqual(list.json.members[0].userId, memberId);
  });

  it("adding the same user again is idempotent (no duplicate)", async function () {
    await login("smadmin@test.com", "adminpass123");
    await client.post("/admin/stash/" + stashId + "/members/add", { json: { email: "smmember@test.com" } });
    var list = await client.get("/admin/stash/" + stashId + "/members");
    assert.strictEqual(list.json.total, 1, "still exactly one member");
  });

  it("rejects adding an email with no account (404)", async function () {
    await login("smadmin@test.com", "adminpass123");
    var res = await client.post("/admin/stash/" + stashId + "/members/add", { json: { email: "nobody@nowhere.test" } });
    assert.strictEqual(res.status, 404);
  });

  it("rejects a malformed email with 400 (format guard fires before lookup)", async function () {
    await login("smadmin@test.com", "adminpass123");
    var res = await client.post("/admin/stash/" + stashId + "/members/add", { json: { email: "not-an-email" } });
    assert.strictEqual(res.status, 400);
  });

  it("a non-admin cannot add members", async function () {
    await login("smoutsider@test.com", "outsiderpass123");
    var res = await client.post("/admin/stash/" + stashId + "/members/add", { json: { email: "smoutsider@test.com" } });
    assert.ok(res.status === 403 || res.status === 302, "non-admin blocked, got " + res.status);
  });

  it("the member sees the stash and its upload under Shared with me", async function () {
    await login("smmember@test.com", "memberpass123");
    var res = await client.get("/dashboard");
    assert.strictEqual(res.status, 200);
    assert.ok(res.text.includes("Shared with me"), "Shared-with-me panel present");
    assert.ok(res.text.includes("Acme Co"), "stash name shown");
    assert.ok(res.text.includes("smbundle1"), "the stash's upload is listed (download link)");
  });

  it("a non-member does NOT see the stash (cross-tenant isolation)", async function () {
    await login("smoutsider@test.com", "outsiderpass123");
    var res = await client.get("/dashboard");
    assert.strictEqual(res.status, 200);
    assert.ok(!res.text.includes("Acme Co"), "a non-member must not see another customer's stash");
  });

  it("admin removes the member; access disappears", async function () {
    await login("smadmin@test.com", "adminpass123");
    var res = await client.post("/admin/stash/" + stashId + "/members/remove", { json: { userId: memberId } });
    assert.strictEqual(res.json.success, true);
    var list = await client.get("/admin/stash/" + stashId + "/members");
    assert.strictEqual(list.json.total, 0, "member removed");

    await login("smmember@test.com", "memberpass123");
    var dash = await client.get("/dashboard");
    assert.ok(!dash.text.includes("Acme Co"), "removed member no longer sees the stash");
  });
});
