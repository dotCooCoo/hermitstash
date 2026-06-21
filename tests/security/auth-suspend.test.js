const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var adminClient, userClient;

before(async function () {
  await testServer.start();
  adminClient = new TestClient(testServer.baseUrl());
  userClient = new TestClient(testServer.baseUrl());
});

after(function () { return testServer.stop(); });

describe("auth-suspend", function () {
  var adminUserId;
  var targetUserId;

  // Register admin (first user = admin) and a regular user
  before(async function () {
    // Register admin (first user is always admin)
    await adminClient.initApiKey();
    var adminReg = await adminClient.post("/auth/register", {
      json: { displayName: "Admin", email: "admin@suspend-test.com", password: "password123" },
    });
    assert.strictEqual(adminReg.json.success, true);

    // Get admin user ID from the users API
    var usersRes = await adminClient.get("/admin/users/api");
    var adminUser = usersRes.json.users.find(function (u) { return u.email === "admin@suspend-test.com"; });
    adminUserId = adminUser._id;

    // Register target user (second user = regular user)
    await userClient.initApiKey();
    var userReg = await userClient.post("/auth/register", {
      json: { displayName: "Target", email: "target@suspend-test.com", password: "password123" },
    });
    assert.strictEqual(userReg.json.success, true);

    // Get target user ID
    var usersRes2 = await adminClient.get("/admin/users/api");
    var targetUser = usersRes2.json.users.find(function (u) { return u.email === "target@suspend-test.com"; });
    targetUserId = targetUser._id;
  });

  describe("suspended user local login blocked", function () {
    before(async function () {
      // Admin suspends the target user
      var suspendRes = await adminClient.post("/admin/users/" + targetUserId + "/suspend", { json: {} });
      assert.strictEqual(suspendRes.json.success, true);
    });

    it("suspended user login returns 403 with Account suspended", async function () {
      userClient.clearCookies();
      await userClient.initApiKey();
      var res = await userClient.post("/auth/login", {
        json: { email: "target@suspend-test.com", password: "password123" },
      });
      assert.strictEqual(res.status, 403);
      assert.strictEqual(res.json.detail, "Account suspended.");
    });

    it("suspended user cannot access dashboard", async function () {
      // Try to access dashboard — the session was cleared by suspension,
      // and even if they had a session, attach-user clears it for non-active users
      var res = await userClient.get("/dashboard");
      // Should redirect to login (302) since attach-user nullifies suspended sessions
      assert.strictEqual(res.status, 302);
    });

    it("active user can still log in after another user is suspended", async function () {
      // Admin should still be able to log in fine
      adminClient.clearCookies();
      await adminClient.initApiKey();
      var res = await adminClient.post("/auth/login", {
        json: { email: "admin@suspend-test.com", password: "password123" },
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);
    });
  });

  describe("unsuspend restores login", function () {
    before(async function () {
      // Admin unsuspends the target user
      var unsuspendRes = await adminClient.post("/admin/users/" + targetUserId + "/unsuspend", { json: {} });
      assert.strictEqual(unsuspendRes.json.success, true);
    });

    it("re-activated user can log in again", async function () {
      userClient.clearCookies();
      await userClient.initApiKey();
      var res = await userClient.post("/auth/login", {
        json: { email: "target@suspend-test.com", password: "password123" },
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);
    });

    it("re-activated user can access dashboard", async function () {
      var res = await userClient.get("/dashboard");
      assert.strictEqual(res.status, 200);
    });
  });

  describe("account deletion revokes sessions without 500 (C1-1 / blamejs#340 regression guard)", function () {
    var delClient, delUserId;
    before(async function () {
      delClient = new TestClient(testServer.baseUrl());
      await delClient.initApiKey();
      var reg = await delClient.post("/auth/register", {
        json: { displayName: "Deletable", email: "deletable@suspend-test.com", password: "password123" },
      });
      assert.strictEqual(reg.json.success, true);
      var usersRes = await adminClient.get("/admin/users/api");
      var u = usersRes.json.users.find(function (x) { return x.email === "deletable@suspend-test.com"; });
      delUserId = u._id;
    });

    it("admin delete succeeds and clears the user's sessions (no MISCONFIGURED 500)", async function () {
      // delete → clearSessionsForUser → b.session.destroyAllForUser, whose
      // post-DELETE stateless valid-from bump throws MISCONFIGURED on HS's
      // store-only model (no b.db.init). A 500 here means the swallow stopped
      // matching the framework's re-wrapped error after a vendor bump.
      var res = await adminClient.post("/admin/users/" + delUserId + "/delete", { json: {} });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);
    });

    it("deleted user can no longer log in", async function () {
      delClient.clearCookies();
      await delClient.initApiKey();
      var res = await delClient.post("/auth/login", {
        json: { email: "deletable@suspend-test.com", password: "password123" },
      });
      assert.notStrictEqual(res.status, 200);
    });
  });
});
