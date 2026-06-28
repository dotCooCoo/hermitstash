const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");
var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;
var audit, config;

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());
  var root = testServer.projectRoot;
  audit = require(path.join(root, "lib", "audit"));
  config = require(path.join(root, "lib", "config"));

  config.auditChainEnabled = true;
  config.auditArchivePassphrase = "route-archive-pass-9999";
  // Low threshold so a manual run (keep = threshold) actually archives the overflow.
  config.auditArchiveThresholdRows = 5;

  var b = require(path.join(root, "lib", "vendor", "blamejs"));
  var vault = require(path.join(root, "lib", "vault"));
  var { hashEmail } = require(path.join(root, "lib", "crypto"));
  var { users } = require(path.join(root, "lib", "db"));
  async function seed(email, name, role, pw) {
    var u = users.insert({
      email: vault.seal(email), emailHash: hashEmail(email), displayName: vault.seal(name),
      passwordHash: await b.auth.password.hash(pw), authType: "local", role: role, status: "active",
      createdAt: new Date().toISOString(),
    });
    return u._id;
  }
  await seed("arcadmin@test.com", "Arc Admin", "admin", "adminpass123");
  await seed("arcuser@test.com", "Arc User", "user", "userpass123");

  function r(over) { return Object.assign({ method: "POST", pathname: "/x", headers: {}, user: { _id: "u", email: "e@t.com" }, socket: { remoteAddress: "203.0.113.9" } }, over || {}); }
  for (var i = 0; i < 12; i++) audit.log("file_downloaded", { targetId: "rt-" + i, details: "evt " + i, req: r() });
  await audit.drainChain();
});
after(function () { config.auditChainEnabled = false; return testServer.stop(); });

async function login(email, pw) {
  client.clearCookies();
  await client.initApiKey();
  testServer.resetAllRateLimits();
  var res = await client.post("/auth/login", { json: { email: email, password: pw } });
  assert.strictEqual(res.json.success, true, email + " login");
}

describe("audit archive routes", function () {
  var archiveId;

  it("runs an archive via POST /admin/audit/archives/run", async function () {
    await login("arcadmin@test.com", "adminpass123");
    var res = await client.post("/admin/audit/archives/run", { json: { all: false } });
    assert.strictEqual(res.json.success, true, "archive ran: " + JSON.stringify(res.json));
    assert.ok(res.json.archived >= 1, "archived some");
    assert.ok(res.json.id, "id returned");
    archiveId = res.json.id;
  });

  it("lists archives via GET /admin/audit/archives", async function () {
    await login("arcadmin@test.com", "adminpass123");
    var res = await client.get("/admin/audit/archives");
    assert.ok(Array.isArray(res.json.archives) && res.json.archives.length >= 1, "archives listed");
    assert.strictEqual(res.json.enabled !== undefined, true, "enabled flag present");
    assert.ok(res.json.archives[0].id && res.json.archives[0].count >= 1, "archive metadata");
  });

  it("verifies a bundle via POST /admin/audit/archives/verify", async function () {
    await login("arcadmin@test.com", "adminpass123");
    var res = await client.post("/admin/audit/archives/verify", { json: { id: archiveId } });
    assert.strictEqual(res.json.ok, true, "bundle verifies: " + JSON.stringify(res.json));
    assert.ok(res.json.rowsVerified >= 1, "rows verified");
  });

  it("a wrong passphrase fails verification cleanly", async function () {
    await login("arcadmin@test.com", "adminpass123");
    var res = await client.post("/admin/audit/archives/verify", { json: { id: archiveId, passphrase: "nope" } });
    assert.strictEqual(res.json.ok, false, "wrong passphrase → not ok");
  });

  it("exports a decrypted archive via GET /admin/audit/archives/export", async function () {
    await login("arcadmin@test.com", "adminpass123");
    var res = await client.get("/admin/audit/archives/export?id=" + encodeURIComponent(archiveId) + "&format=json");
    assert.strictEqual(res.status, 200);
    assert.ok(/attachment; filename="audit-archive-/.test(res.headers["content-disposition"] || ""), "download header");
    assert.ok(Array.isArray(res.json.entries) && res.json.entries.length >= 1, "decrypted entries");
    assert.strictEqual(res.json.entries[0].action, "file_downloaded", "rows decrypted/unsealed");
  });

  it("blocks a non-admin from every archive route", async function () {
    await login("arcuser@test.com", "userpass123");
    var run = await client.post("/admin/audit/archives/run", { json: {} });
    var list = await client.get("/admin/audit/archives");
    var exp = await client.get("/admin/audit/archives/export?id=" + encodeURIComponent(archiveId) + "&format=json");
    [run, list, exp].forEach(function (res) { assert.ok(res.status === 403 || res.status === 302, "blocked, got " + res.status); });
  });
});
