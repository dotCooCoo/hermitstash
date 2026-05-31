const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;

// IDs populated during tests
var adminUserId, memberUserId, teamId;

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());

  // Seed admin user directly in DB
  var b = require(path.join(testServer.projectRoot, "lib", "vendor", "blamejs"));
  var hashPassword = function (p) { return b.auth.password.hash(String(p)); };
  var vault = require(path.join(testServer.projectRoot, "lib", "vault"));
  var { hashEmail } = require(path.join(testServer.projectRoot, "lib", "crypto"));
  var { users } = require(path.join(testServer.projectRoot, "lib", "db"));
  var hash = await hashPassword("adminpass123");
  var admin = users.insert({
    email: vault.seal("teamadmin@test.com"), emailHash: hashEmail("teamadmin@test.com"),
    displayName: vault.seal("Team Admin"), passwordHash: hash,
    authType: "local", role: "admin", status: "active",
    createdAt: new Date().toISOString(),
  });
  adminUserId = admin._id;

  // Seed a second (non-admin) user for member tests
  var hash2 = await hashPassword("memberpass123");
  var member = users.insert({
    email: vault.seal("teammember@test.com"), emailHash: hashEmail("teammember@test.com"),
    displayName: vault.seal("Team Member"), passwordHash: hash2,
    authType: "local", role: "user", status: "active",
    createdAt: new Date().toISOString(),
  });
  memberUserId = member._id;
});

after(function () { return testServer.stop(); });

// Helper: login as admin
async function loginAdmin() {
  client.clearCookies();
  await client.initApiKey();
  testServer.resetAllRateLimits();
  var res = await client.post("/auth/login", {
    json: { email: "teamadmin@test.com", password: "adminpass123" },
  });
  assert.strictEqual(res.json.success, true, "admin login should succeed");
}

// Helper: login as member
async function loginMember() {
  client.clearCookies();
  await client.initApiKey();
  testServer.resetAllRateLimits();
  var res = await client.post("/auth/login", {
    json: { email: "teammember@test.com", password: "memberpass123" },
  });
  assert.strictEqual(res.json.success, true, "member login should succeed");
}

describe("teams integration", function () {
  describe("POST /teams/create", function () {
    it("creates team successfully and returns teamId", async function () {
      await loginAdmin();
      var res = await client.post("/teams/create", { json: { name: "Test Team Alpha" } });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);
      assert.ok(res.json.teamId, "should return teamId");
      teamId = res.json.teamId;
    });

    it("empty name returns 400", async function () {
      await loginAdmin();
      var res = await client.post("/teams/create", { json: { name: "" } });
      assert.strictEqual(res.status, 400);
      assert.ok((res.json.detail || res.json.error).includes("required"), "error should mention name required");
    });
  });

  describe("GET /teams/api", function () {
    it("lists user's teams", async function () {
      await loginAdmin();
      var res = await client.get("/teams/api");
      assert.strictEqual(res.status, 200);
      assert.ok(Array.isArray(res.json.teams), "should return teams array");
      var found = res.json.teams.find(function (t) { return t._id === teamId; });
      assert.ok(found, "admin should see the created team");
      assert.strictEqual(found.name, "Test Team Alpha");
      assert.strictEqual(found.role, "admin");
      assert.strictEqual(found.memberCount, 1);
    });
  });

  describe("POST /teams/:teamId/members/add", function () {
    it("adds member as team admin", async function () {
      await loginAdmin();
      var res = await client.post("/teams/" + teamId + "/members/add", {
        json: { userId: memberUserId },
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);
    });

    it("non-admin rejected with 403", async function () {
      await loginMember();
      var res = await client.post("/teams/" + teamId + "/members/add", {
        json: { userId: "someRandomUserId" },
      });
      assert.strictEqual(res.status, 403);
      assert.ok((res.json.detail || res.json.error).includes("admin"), "error should mention admin");
    });

    it("user not found returns 404", async function () {
      await loginAdmin();
      var res = await client.post("/teams/" + teamId + "/members/add", {
        json: { userId: "nonexistent000000000000" },
      });
      assert.strictEqual(res.status, 404);
      assert.ok((res.json.detail || res.json.error).includes("not found"), "error should mention user not found");
    });

    it("already a member returns 400", async function () {
      await loginAdmin();
      var res = await client.post("/teams/" + teamId + "/members/add", {
        json: { userId: memberUserId },
      });
      assert.strictEqual(res.status, 400);
      assert.ok((res.json.detail || res.json.error).toLowerCase().includes("already"), "error should mention already a member");
    });
  });

  describe("GET /teams/:teamId/members", function () {
    it("lists members for team member", async function () {
      await loginMember();
      var res = await client.get("/teams/" + teamId + "/members");
      assert.strictEqual(res.status, 200);
      assert.ok(Array.isArray(res.json.members), "should return members array");
      assert.strictEqual(res.json.members.length, 2, "should have admin + member");
      var adminEntry = res.json.members.find(function (m) { return m.userId === adminUserId; });
      var memberEntry = res.json.members.find(function (m) { return m.userId === memberUserId; });
      assert.ok(adminEntry, "admin should be listed");
      assert.ok(memberEntry, "member should be listed");
      assert.strictEqual(adminEntry.role, "admin");
      assert.strictEqual(memberEntry.role, "member");
    });

    it("non-member rejected with 403", async function () {
      // Register a third user who is NOT a member
      client.clearCookies();
      await client.initApiKey();
      testServer.resetAllRateLimits();
      await client.post("/auth/register", {
        json: { displayName: "Outsider", email: "outsider@test.com", password: "password123" },
      });
      var res = await client.get("/teams/" + teamId + "/members");
      assert.strictEqual(res.status, 403);
      assert.ok((res.json.detail || res.json.error).includes("Not a member"), "error should mention not a member");
    });
  });

  describe("GET /teams/:teamId/files", function () {
    it("member can see files (empty list)", async function () {
      await loginMember();
      var res = await client.get("/teams/" + teamId + "/files");
      assert.strictEqual(res.status, 200);
      assert.ok(Array.isArray(res.json.files), "should return files array");
    });

    it("non-member rejected with 403", async function () {
      // Login as the outsider registered above
      client.clearCookies();
      await client.initApiKey();
      testServer.resetAllRateLimits();
      await client.post("/auth/login", {
        json: { email: "outsider@test.com", password: "password123" },
      });
      var res = await client.get("/teams/" + teamId + "/files");
      assert.strictEqual(res.status, 403);
    });
  });

  describe("POST /teams/:teamId/members/remove", function () {
    it("removes member as team admin", async function () {
      await loginAdmin();
      var res = await client.post("/teams/" + teamId + "/members/remove", {
        json: { userId: memberUserId },
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);

      // Verify member is removed
      var members = await client.get("/teams/" + teamId + "/members");
      var found = members.json.members.find(function (m) { return m.userId === memberUserId; });
      assert.strictEqual(found, undefined, "member should no longer be listed");
    });
  });

  describe("POST /teams/:teamId/delete", function () {
    it("non-admin rejected with 403", async function () {
      // Re-add member first so they're in the team
      await loginAdmin();
      await client.post("/teams/" + teamId + "/members/add", {
        json: { userId: memberUserId },
      });

      await loginMember();
      var res = await client.post("/teams/" + teamId + "/delete", { json: {} });
      assert.strictEqual(res.status, 403);
      assert.ok((res.json.detail || res.json.error).includes("admin"), "error should mention admin");
    });

    it("deletes team as team admin", async function () {
      await loginAdmin();
      var res = await client.post("/teams/" + teamId + "/delete", { json: {} });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);

      // Verify team is gone
      var list = await client.get("/teams/api");
      var found = list.json.teams.find(function (t) { return t._id === teamId; });
      assert.strictEqual(found, undefined, "team should no longer exist");
    });
  });
});
