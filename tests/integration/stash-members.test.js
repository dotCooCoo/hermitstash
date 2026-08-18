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

  it("the member list names who is on it, not just how many", async function () {
    // The list is what an admin acts on — revoking the wrong person is the cost
    // of a row that carries only an id.
    await login("smadmin@test.com", "adminpass123");
    var list = await client.get("/admin/stash/" + stashId + "/members");
    assert.strictEqual(list.status, 200);
    assert.strictEqual(list.json.total, 1);
    var m = list.json.members[0];
    assert.strictEqual(m.userId, memberId);
    assert.strictEqual(m.email, "smmember@test.com", "the email must be unsealed for display");
    assert.strictEqual(m.displayName, "Stash Member");
    assert.strictEqual(m.missing, false, "the account exists");
    assert.ok(m.addedAt, "and the row says when access was granted");
  });

  it("a member whose account was deleted is shown as missing, not dropped", async function () {
    // Deleting a user does not remove their stash grants. If the row vanished
    // from this list the grant would still be in the table with nothing in the
    // UI to revoke, so it is listed and flagged instead.
    var { users } = require(path.join(testServer.projectRoot, "lib", "db"));
    var stashRepo = require(path.join(testServer.projectRoot, "app", "data", "repositories", "stash.repo"));
    var ghostId = users.insert({
      email: require(path.join(testServer.projectRoot, "lib", "vault")).seal("smghost@test.com"),
      emailHash: require(path.join(testServer.projectRoot, "lib", "crypto")).hashEmail("smghost@test.com"),
      authType: "local", role: "user", status: "active", createdAt: new Date().toISOString(),
    })._id;
    stashRepo.addMember(stashId, ghostId);
    users.remove({ _id: ghostId });

    await login("smadmin@test.com", "adminpass123");
    var list = await client.get("/admin/stash/" + stashId + "/members");
    var ghost = list.json.members.filter(function (m) { return m.userId === ghostId; })[0];
    assert.ok(ghost, "the grant must still be listed so it can be revoked");
    assert.strictEqual(ghost.missing, true, "and flagged as having no account behind it");
    assert.strictEqual(ghost.email, null, "with no email to show");

    // Clean up so the counts below are about the real member.
    await client.post("/admin/stash/" + stashId + "/members/remove", { json: { userId: ghostId } });
  });

  it("refuses to list, add to, or remove from a stash that does not exist", async function () {
    // Each of the three has its own lookup. A 404 rather than an empty list is
    // what keeps a mistyped id from reading as "this stash has no members".
    await login("smadmin@test.com", "adminpass123");
    var missingId = "no-such-stash-id";
    var list = await client.get("/admin/stash/" + missingId + "/members");
    assert.strictEqual(list.status, 404, "listing a missing stash is not an empty list");
    var add = await client.post("/admin/stash/" + missingId + "/members/add", { json: { email: "smmember@test.com" } });
    assert.strictEqual(add.status, 404);
    var rem = await client.post("/admin/stash/" + missingId + "/members/remove", { json: { userId: memberId } });
    assert.strictEqual(rem.status, 404);
  });

  it("refuses a remove with no userId rather than removing nothing quietly", async function () {
    await login("smadmin@test.com", "adminpass123");
    var res = await client.post("/admin/stash/" + stashId + "/members/remove", { json: {} });
    assert.strictEqual(res.status, 400);
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
