const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var adminClient, memberClient, outsiderClient, siteAdminClient;

// IDs populated during tests
var adminUserId, memberUserId, outsiderUserId, siteAdminId;
var teamId, secondTeamId;

before(async function () {
  await testServer.start();
  adminClient = new TestClient(testServer.baseUrl());
  memberClient = new TestClient(testServer.baseUrl());
  outsiderClient = new TestClient(testServer.baseUrl());
  siteAdminClient = new TestClient(testServer.baseUrl());

  // Seed users directly in DB
  var b = require(path.join(testServer.projectRoot, "lib", "vendor", "blamejs"));
  var hashPassword = function (p) { return b.auth.password.hash(String(p)); };
  var vault = require(path.join(testServer.projectRoot, "lib", "vault"));
  var { hashEmail } = require(path.join(testServer.projectRoot, "lib", "crypto"));
  var { users } = require(path.join(testServer.projectRoot, "lib", "db"));

  // Site admin — first user, has role:admin and can override membership checks
  var h1 = await hashPassword("siteadmin123");
  var sa = users.insert({
    email: vault.seal("siteadmin@test.com"), emailHash: hashEmail("siteadmin@test.com"),
    displayName: vault.seal("Site Admin"), passwordHash: h1,
    authType: "local", role: "admin", status: "active",
    createdAt: new Date().toISOString(),
  });
  siteAdminId = sa._id;

  // Team admin (regular user who will create teams)
  var h2 = await hashPassword("teamadmin123");
  var ta = users.insert({
    email: vault.seal("teamadmin@test.com"), emailHash: hashEmail("teamadmin@test.com"),
    displayName: vault.seal("Team Admin"), passwordHash: h2,
    authType: "local", role: "user", status: "active",
    createdAt: new Date().toISOString(),
  });
  adminUserId = ta._id;

  // Regular team member
  var h3 = await hashPassword("member123");
  var tm = users.insert({
    email: vault.seal("member@test.com"), emailHash: hashEmail("member@test.com"),
    displayName: vault.seal("Team Member"), passwordHash: h3,
    authType: "local", role: "user", status: "active",
    createdAt: new Date().toISOString(),
  });
  memberUserId = tm._id;

  // Outsider — not part of any team
  var h4 = await hashPassword("outsider123");
  var ou = users.insert({
    email: vault.seal("outsider@test.com"), emailHash: hashEmail("outsider@test.com"),
    displayName: vault.seal("Outsider"), passwordHash: h4,
    authType: "local", role: "user", status: "active",
    createdAt: new Date().toISOString(),
  });
  outsiderUserId = ou._id;
});

after(function () { return testServer.stop(); });

function resetRateLimits() {
  var rateLimit = require(path.join(testServer.projectRoot, "lib", "rate-limit"));
  // Flush every b.middleware.rateLimit instance so repeated logins across
  // cases don't share the login limiter's 15/5min budget.
  rateLimit.resetAllInstances();
}

async function loginAs(c, email, password) {
  c.clearCookies();
  await c.initApiKey();
  resetRateLimits();
  var res = await c.post("/auth/login", { json: { email: email, password: password } });
  assert.strictEqual(res.json.success, true, email + " login should succeed");
}

async function loginTeamAdmin() { await loginAs(adminClient, "teamadmin@test.com", "teamadmin123"); }
async function loginMember() { await loginAs(memberClient, "member@test.com", "member123"); }
async function loginOutsider() { await loginAs(outsiderClient, "outsider@test.com", "outsider123"); }
async function loginSiteAdmin() { await loginAs(siteAdminClient, "siteadmin@test.com", "siteadmin123"); }

describe("teams extended integration", function () {
  describe("authentication required", function () {
    it("GET /teams/api redirects when not logged in", async function () {
      adminClient.clearCookies();
      var res = await adminClient.get("/teams/api");
      assert.strictEqual(res.status, 302);
      assert.ok(res.location.includes("/auth/login"), "should redirect to login");
    });

    it("POST /teams/create redirects when not logged in", async function () {
      adminClient.clearCookies();
      await adminClient.initApiKey();
      var res = await adminClient.post("/teams/create", { json: { name: "Nope" } });
      assert.strictEqual(res.status, 302);
      assert.ok(res.location.includes("/auth/login"), "should redirect to login");
    });
  });

  describe("POST /teams/create", function () {
    it("creates team and creator becomes admin", async function () {
      await loginTeamAdmin();
      var res = await adminClient.post("/teams/create", { json: { name: "Alpha Squad" } });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);
      assert.ok(res.json.teamId, "should return teamId");
      teamId = res.json.teamId;
    });

    it("team appears in creator team list with admin role", async function () {
      await loginTeamAdmin();
      var res = await adminClient.get("/teams/api");
      assert.strictEqual(res.status, 200);
      var found = res.json.teams.find(function (t) { return t._id === teamId; });
      assert.ok(found, "team should appear in list");
      assert.strictEqual(found.name, "Alpha Squad");
      assert.strictEqual(found.role, "admin");
      assert.strictEqual(found.memberCount, 1);
    });

    it("rejects empty team name", async function () {
      await loginTeamAdmin();
      var res = await adminClient.post("/teams/create", { json: { name: "" } });
      assert.strictEqual(res.status, 400);
      assert.ok(res.json.error.includes("required"), "error should mention name required");
    });

    it("rejects whitespace-only team name", async function () {
      await loginTeamAdmin();
      var res = await adminClient.post("/teams/create", { json: { name: "   " } });
      assert.strictEqual(res.status, 400);
      assert.ok(res.json.error.includes("required"), "error should mention name required");
    });

    it("truncates overly long team name to 100 chars", async function () {
      await loginTeamAdmin();
      var longName = "A".repeat(150);
      var res = await adminClient.post("/teams/create", { json: { name: longName } });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);
      secondTeamId = res.json.teamId;

      // Verify the stored name was truncated
      var list = await adminClient.get("/teams/api");
      var found = list.json.teams.find(function (t) { return t._id === secondTeamId; });
      assert.strictEqual(found.name.length, 100, "name should be truncated to 100 chars");
    });

    it("team does not appear in other user team list", async function () {
      await loginOutsider();
      var res = await outsiderClient.get("/teams/api");
      var found = res.json.teams.find(function (t) { return t._id === teamId; });
      assert.strictEqual(found, undefined, "outsider should not see the team");
    });
  });

  describe("POST /teams/:teamId/members/add", function () {
    it("team admin can add member", async function () {
      await loginTeamAdmin();
      var res = await adminClient.post("/teams/" + teamId + "/members/add", {
        json: { userId: memberUserId },
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);
    });

    it("added member appears in team list", async function () {
      await loginMember();
      var res = await memberClient.get("/teams/api");
      var found = res.json.teams.find(function (t) { return t._id === teamId; });
      assert.ok(found, "member should now see the team");
      assert.strictEqual(found.role, "member");
      assert.strictEqual(found.memberCount, 2);
    });

    it("rejects adding non-existent user", async function () {
      await loginTeamAdmin();
      var res = await adminClient.post("/teams/" + teamId + "/members/add", {
        json: { userId: "nonexistent000000000000" },
      });
      assert.strictEqual(res.status, 404);
      assert.ok(res.json.error.includes("not found"), "error should mention user not found");
    });

    it("rejects adding duplicate member", async function () {
      await loginTeamAdmin();
      var res = await adminClient.post("/teams/" + teamId + "/members/add", {
        json: { userId: memberUserId },
      });
      assert.strictEqual(res.status, 400);
      assert.ok(/already/i.test(res.json.error), "error should mention already a member, got: " + res.json.error);
    });

    it("rejects missing userId", async function () {
      await loginTeamAdmin();
      var res = await adminClient.post("/teams/" + teamId + "/members/add", {
        json: {},
      });
      assert.strictEqual(res.status, 400);
      assert.ok(res.json.error.includes("User ID required"), "error should mention user ID required");
    });

    it("non-admin member cannot add users", async function () {
      await loginMember();
      var res = await memberClient.post("/teams/" + teamId + "/members/add", {
        json: { userId: outsiderUserId },
      });
      assert.strictEqual(res.status, 403);
      assert.ok(res.json.error.includes("admin"), "error should mention admin requirement");
    });

    it("site admin can add members to any team", async function () {
      await loginSiteAdmin();
      var res = await siteAdminClient.post("/teams/" + teamId + "/members/add", {
        json: { userId: outsiderUserId },
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);
    });
  });

  describe("GET /teams/:teamId/members", function () {
    it("lists correct members with roles", async function () {
      await loginTeamAdmin();
      var res = await adminClient.get("/teams/" + teamId + "/members");
      assert.strictEqual(res.status, 200);
      assert.ok(Array.isArray(res.json.members), "should return members array");
      assert.strictEqual(res.json.members.length, 3, "should have admin + member + outsider");

      var adminEntry = res.json.members.find(function (m) { return m.userId === adminUserId; });
      var memberEntry = res.json.members.find(function (m) { return m.userId === memberUserId; });
      var outsiderEntry = res.json.members.find(function (m) { return m.userId === outsiderUserId; });
      assert.ok(adminEntry, "team admin should be listed");
      assert.ok(memberEntry, "member should be listed");
      assert.ok(outsiderEntry, "outsider (just added) should be listed");
      assert.strictEqual(adminEntry.role, "admin");
      assert.strictEqual(memberEntry.role, "member");
    });

    it("member entries include display info", async function () {
      await loginTeamAdmin();
      var res = await adminClient.get("/teams/" + teamId + "/members");
      var memberEntry = res.json.members.find(function (m) { return m.userId === memberUserId; });
      assert.ok(memberEntry.email, "member entry should include email");
      assert.ok(memberEntry.displayName, "member entry should include displayName");
      assert.ok(memberEntry.joinedAt, "member entry should include joinedAt");
    });

    it("non-member gets 403", async function () {
      // Remove outsider first so they are no longer a member, then test access
      await loginSiteAdmin();
      await siteAdminClient.post("/teams/" + teamId + "/members/remove", {
        json: { userId: outsiderUserId },
      });

      await loginOutsider();
      var res = await outsiderClient.get("/teams/" + teamId + "/members");
      assert.strictEqual(res.status, 403);
      assert.ok(res.json.error.includes("Not a member"), "error should mention not a member");
    });

    it("site admin can view any team members (overrides membership check)", async function () {
      await loginSiteAdmin();
      var res = await siteAdminClient.get("/teams/" + teamId + "/members");
      assert.strictEqual(res.status, 200);
      assert.ok(Array.isArray(res.json.members), "site admin should see members");
      assert.strictEqual(res.json.members.length, 2, "should list exactly 2 members (admin + added member)");
    });
  });

  describe("GET /teams/:teamId/files", function () {
    it("member can list files (empty)", async function () {
      await loginMember();
      var res = await memberClient.get("/teams/" + teamId + "/files");
      assert.strictEqual(res.status, 200);
      assert.ok(Array.isArray(res.json.files), "should return files array");
      assert.strictEqual(res.json.files.length, 0, "no files uploaded yet");
    });

    it("non-member gets 403", async function () {
      await loginOutsider();
      var res = await outsiderClient.get("/teams/" + teamId + "/files");
      assert.strictEqual(res.status, 403);
    });

    it("site admin can view any team files", async function () {
      await loginSiteAdmin();
      var res = await siteAdminClient.get("/teams/" + teamId + "/files");
      assert.strictEqual(res.status, 200);
      assert.ok(Array.isArray(res.json.files), "site admin should see files list");
    });

    it("files scoped to team — does not leak files from other teams", async function () {
      // Insert a file assigned to secondTeamId directly in DB
      var { files } = require(path.join(testServer.projectRoot, "lib", "db"));
      files.insert({
        shareId: "team2-file-ext",
        originalName: "other-team-doc.pdf",
        relativePath: "other-team-doc.pdf",
        storagePath: "uploads/other-team-doc.pdf",
        mimeType: "application/pdf",
        size: 1024,
        uploadedBy: adminUserId,
        teamId: secondTeamId,
        downloads: 0,
        status: "complete",
        createdAt: new Date().toISOString(),
      });

      // Now list files for the primary team — should NOT include secondTeam files
      await loginTeamAdmin();
      var res = await adminClient.get("/teams/" + teamId + "/files");
      assert.strictEqual(res.status, 200);
      var leaked = res.json.files.find(function (f) { return f.shareId === "team2-file-ext"; });
      assert.strictEqual(leaked, undefined, "files from other teams should not appear");

      // Verify the file DOES appear under the correct team
      var res2 = await adminClient.get("/teams/" + secondTeamId + "/files");
      assert.strictEqual(res2.status, 200);
      var found = res2.json.files.find(function (f) { return f.shareId === "team2-file-ext"; });
      assert.ok(found, "file should appear under its assigned team");
      assert.strictEqual(found.originalName, "other-team-doc.pdf");
    });
  });

  describe("POST /teams/:teamId/members/remove", function () {
    it("team admin can remove member", async function () {
      await loginTeamAdmin();
      var res = await adminClient.post("/teams/" + teamId + "/members/remove", {
        json: { userId: memberUserId },
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);

      // Verify member is removed from list
      var members = await adminClient.get("/teams/" + teamId + "/members");
      var found = members.json.members.find(function (m) { return m.userId === memberUserId; });
      assert.strictEqual(found, undefined, "member should no longer be listed");
    });

    it("removed member loses access to team files", async function () {
      await loginMember();
      var res = await memberClient.get("/teams/" + teamId + "/files");
      assert.strictEqual(res.status, 403);
    });

    it("removed member loses access to team members list", async function () {
      await loginMember();
      var res = await memberClient.get("/teams/" + teamId + "/members");
      assert.strictEqual(res.status, 403);
    });

    it("cannot remove the last team admin", async function () {
      // teamId has only one admin (adminUserId) — removing them should fail
      await loginTeamAdmin();
      var res = await adminClient.post("/teams/" + teamId + "/members/remove", {
        json: { userId: adminUserId },
      });
      assert.strictEqual(res.status, 400);
      assert.ok(res.json.error.includes("last team admin"), "error should mention last team admin");
    });

    it("can remove admin when another admin exists", async function () {
      // Add member back as admin
      await loginTeamAdmin();
      await adminClient.post("/teams/" + teamId + "/members/add", {
        json: { userId: memberUserId, role: "admin" },
      });

      // Verify both are admin
      var members = await adminClient.get("/teams/" + teamId + "/members");
      var admins = members.json.members.filter(function (m) { return m.role === "admin"; });
      assert.strictEqual(admins.length, 2, "should have exactly 2 admins now");

      // Now removing one admin should succeed
      var res = await adminClient.post("/teams/" + teamId + "/members/remove", {
        json: { userId: memberUserId },
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);
    });

    it("non-admin member cannot remove users", async function () {
      // Re-add member as regular member
      await loginTeamAdmin();
      await adminClient.post("/teams/" + teamId + "/members/add", {
        json: { userId: memberUserId },
      });

      await loginMember();
      var res = await memberClient.post("/teams/" + teamId + "/members/remove", {
        json: { userId: adminUserId },
      });
      assert.strictEqual(res.status, 403);
      assert.ok(res.json.error.includes("admin"), "error should mention admin requirement");
    });
  });

  describe("POST /teams/:teamId/delete", function () {
    it("non-admin member cannot delete team", async function () {
      await loginMember();
      var res = await memberClient.post("/teams/" + teamId + "/delete", { json: {} });
      assert.strictEqual(res.status, 403);
      assert.ok(res.json.error.includes("admin"), "error should mention admin requirement");
    });

    it("outsider cannot delete team", async function () {
      await loginOutsider();
      var res = await outsiderClient.post("/teams/" + teamId + "/delete", { json: {} });
      assert.strictEqual(res.status, 403);
    });

    it("site admin can delete any team (overrides membership)", async function () {
      // Delete secondTeamId using site admin
      await loginSiteAdmin();
      var res = await siteAdminClient.post("/teams/" + secondTeamId + "/delete", { json: {} });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);

      // Verify team is gone from admin's list
      await loginTeamAdmin();
      var list = await adminClient.get("/teams/api");
      var found = list.json.teams.find(function (t) { return t._id === secondTeamId; });
      assert.strictEqual(found, undefined, "deleted team should not appear in list");
    });

    it("team admin can delete their team", async function () {
      await loginTeamAdmin();
      var res = await adminClient.post("/teams/" + teamId + "/delete", { json: {} });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);
    });

    it("deleted team gone from all user lists", async function () {
      await loginTeamAdmin();
      var adminList = await adminClient.get("/teams/api");
      var found1 = adminList.json.teams.find(function (t) { return t._id === teamId; });
      assert.strictEqual(found1, undefined, "deleted team should not appear in admin list");

      await loginMember();
      var memberList = await memberClient.get("/teams/api");
      var found2 = memberList.json.teams.find(function (t) { return t._id === teamId; });
      assert.strictEqual(found2, undefined, "deleted team should not appear in member list");
    });

    it("team files unassigned after deletion (not deleted)", async function () {
      // Create a fresh team with a file, then delete and verify the file still exists
      await loginTeamAdmin();
      var createRes = await adminClient.post("/teams/create", { json: { name: "Ephemeral Team" } });
      var ephemeralTeamId = createRes.json.teamId;

      var { files } = require(path.join(testServer.projectRoot, "lib", "db"));
      files.insert({
        shareId: "ephemeral-file-ext",
        originalName: "ephemeral.txt",
        relativePath: "ephemeral.txt",
        storagePath: "uploads/ephemeral.txt",
        mimeType: "text/plain",
        size: 100,
        uploadedBy: adminUserId,
        teamId: ephemeralTeamId,
        downloads: 0,
        status: "complete",
        createdAt: new Date().toISOString(),
      });

      // Delete the team
      var delRes = await adminClient.post("/teams/" + ephemeralTeamId + "/delete", { json: {} });
      assert.strictEqual(delRes.json.success, true);

      // File should still exist but with teamId cleared (null or undefined in SQLite)
      var doc = files.findOne({ shareId: "ephemeral-file-ext" });
      assert.ok(doc, "file should still exist after team deletion");
      assert.ok(!doc.teamId, "file teamId should be cleared after team deletion");
    });
  });

  describe("concurrent team operations", function () {
    it("multiple teams can be created by same user", async function () {
      await loginTeamAdmin();
      var res1 = await adminClient.post("/teams/create", { json: { name: "Team One" } });
      var res2 = await adminClient.post("/teams/create", { json: { name: "Team Two" } });
      var res3 = await adminClient.post("/teams/create", { json: { name: "Team Three" } });
      assert.strictEqual(res1.json.success, true);
      assert.strictEqual(res2.json.success, true);
      assert.strictEqual(res3.json.success, true);

      // All three should appear in list
      var list = await adminClient.get("/teams/api");
      var names = list.json.teams.map(function (t) { return t.name; });
      assert.ok(names.includes("Team One"), "Team One should appear");
      assert.ok(names.includes("Team Two"), "Team Two should appear");
      assert.ok(names.includes("Team Three"), "Team Three should appear");
    });

    it("user sees only teams they belong to", async function () {
      // Member and outsider should see no teams (none created by them, not added to any)
      await loginOutsider();
      var res = await outsiderClient.get("/teams/api");
      assert.strictEqual(res.json.teams.length, 0, "outsider should have zero teams");
    });
  });
});
