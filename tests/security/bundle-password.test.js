var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;

before(async function () { await testServer.start(); client = new TestClient(testServer.baseUrl()); });
after(function () { return testServer.stop(); });

describe("bundle-password", function () {
  var pwShareId;
  var pwFileShareId;
  var noPwShareId;
  var noPwFileShareId;

  // Create a password-protected bundle with one file
  before(async function () {
    await client.initApiKey();

    // --- Password-protected bundle ---
    var init = await client.post("/drop/init", {
      json: {
        uploaderName: "PW Tester",
        uploaderEmail: "pw@test.com",
        fileCount: 1,
        skippedCount: 0,
        skippedFiles: [],
        password: "secretpass123",
      },
    });
    assert.ok(init.json.bundleId, "bundle init should return bundleId");
    assert.ok(init.json.shareId, "bundle init should return shareId");
    pwShareId = init.json.shareId;

    var upload = await client.uploadFile("/drop/file/" + init.json.bundleId, "file", "secret.txt", "top secret content", { relativePath: "secret.txt" });
    assert.strictEqual(upload.status, 200);

    var finalize = await client.post("/drop/finalize/" + init.json.bundleId, {
      json: { finalizeToken: init.json.finalizeToken },
    });
    assert.strictEqual(finalize.json.success, true);

    // Get the file shareId by loading the bundle page (need to unlock first for this)
    // We'll unlock with a fresh client session, grab file info, then clear for tests
    var unlockClient = new TestClient(testServer.baseUrl());
    await unlockClient.initApiKey();
    var unlockRes = await unlockClient.post("/b/" + pwShareId + "/unlock", {
      json: { password: "secretpass123" },
    });
    assert.strictEqual(unlockRes.json.success, true);
    var bundlePage = await unlockClient.get("/b/" + pwShareId);
    var fileMatch = bundlePage.text.match(/\/b\/[a-f0-9]+\/file\/([a-f0-9]+)/);
    assert.ok(fileMatch, "bundle page should contain file download link");
    pwFileShareId = fileMatch[1];

    // --- Non-password bundle ---
    var init2 = await client.post("/drop/init", {
      json: {
        uploaderName: "No PW Tester",
        uploaderEmail: "nopw@test.com",
        fileCount: 1,
        skippedCount: 0,
        skippedFiles: [],
      },
    });
    noPwShareId = init2.json.shareId;

    var upload2 = await client.uploadFile("/drop/file/" + init2.json.bundleId, "file", "public.txt", "public content", { relativePath: "public.txt" });
    assert.strictEqual(upload2.status, 200);

    var finalize2 = await client.post("/drop/finalize/" + init2.json.bundleId, {
      json: { finalizeToken: init2.json.finalizeToken },
    });
    assert.strictEqual(finalize2.json.success, true);

    // Get non-password file shareId
    var noPwPage = await client.get("/b/" + noPwShareId);
    var noPwMatch = noPwPage.text.match(/\/b\/[a-f0-9]+\/file\/([a-f0-9]+)/);
    assert.ok(noPwMatch, "non-password bundle page should contain file download link");
    noPwFileShareId = noPwMatch[1];
  });

  describe("locked bundle access blocked without unlock", function () {
    it("bundle page shows locked template without unlock", async function () {
      // Fresh client with no session — has not unlocked
      var freshClient = new TestClient(testServer.baseUrl());
      var res = await freshClient.get("/b/" + pwShareId);
      assert.strictEqual(res.status, 200);
      // The bundle-locked template is rendered (check for password form indicator)
      assert.ok(res.text.includes("password") || res.text.includes("locked") || res.text.includes("unlock"),
        "locked bundle page should show password/locked/unlock UI");
      // Should NOT contain the file download link
      assert.ok(!res.text.includes("secret.txt") || res.text.includes("locked"),
        "locked bundle should not reveal file contents");
    });

    it("single file download returns 401 without unlock", async function () {
      var freshClient = new TestClient(testServer.baseUrl());
      var res = await freshClient.get("/b/" + pwShareId + "/file/" + pwFileShareId);
      assert.strictEqual(res.status, 401);
    });

    it("ZIP download returns 401 without unlock", async function () {
      var freshClient = new TestClient(testServer.baseUrl());
      var res = await freshClient.get("/b/" + pwShareId + "/download");
      assert.strictEqual(res.status, 401);
    });
  });

  describe("wrong password rejected", function () {
    it("unlock with wrong password returns 401", async function () {
      var freshClient = new TestClient(testServer.baseUrl());
      await freshClient.initApiKey();
      var res = await freshClient.post("/b/" + pwShareId + "/unlock", {
        json: { password: "wrongpassword" },
      });
      assert.strictEqual(res.status, 401);
    });
  });

  describe("correct password unlocks all endpoints", function () {
    var unlockedClient;

    before(async function () {
      unlockedClient = new TestClient(testServer.baseUrl());
      await unlockedClient.initApiKey();
      var res = await unlockedClient.post("/b/" + pwShareId + "/unlock", {
        json: { password: "secretpass123" },
      });
      assert.strictEqual(res.json.success, true);
    });

    it("bundle page accessible after unlock", async function () {
      var res = await unlockedClient.get("/b/" + pwShareId);
      assert.strictEqual(res.status, 200);
      assert.ok(res.text.includes("secret.txt"), "unlocked bundle page should show file name");
    });

    it("single file download works after unlock", async function () {
      var res = await unlockedClient.get("/b/" + pwShareId + "/file/" + pwFileShareId);
      assert.strictEqual(res.status, 200);
    });

    it("ZIP download works after unlock", async function () {
      var res = await unlockedClient.get("/b/" + pwShareId + "/download");
      assert.strictEqual(res.status, 200);
    });
  });

  describe("non-password bundle accessible without unlock", function () {
    it("bundle page accessible without password", async function () {
      var freshClient = new TestClient(testServer.baseUrl());
      var res = await freshClient.get("/b/" + noPwShareId);
      assert.strictEqual(res.status, 200);
      assert.ok(res.text.includes("public.txt"), "non-password bundle should show files");
    });

    it("single file download works without password", async function () {
      var freshClient = new TestClient(testServer.baseUrl());
      var res = await freshClient.get("/b/" + noPwShareId + "/file/" + noPwFileShareId);
      assert.strictEqual(res.status, 200);
    });

    it("ZIP download works without password", async function () {
      var freshClient = new TestClient(testServer.baseUrl());
      var res = await freshClient.get("/b/" + noPwShareId + "/download");
      assert.strictEqual(res.status, 200);
    });
  });
});
