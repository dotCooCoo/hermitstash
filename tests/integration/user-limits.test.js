const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;

var targetId;

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
  await seed("limadmin@test.com", "Lim Admin", "admin", "adminpass123");
  targetId = await seed("limtarget@test.com", "Lim Target", "user", "targetpass123");
  await seed("limoutsider@test.com", "Lim Outsider", "user", "outsiderpass123");
});

after(function () { return testServer.stop(); });

async function login(email, pw) {
  client.clearCookies();
  await client.initApiKey();
  testServer.resetAllRateLimits();
  var r = await client.post("/auth/login", { json: { email: email, password: pw } });
  assert.strictEqual(r.json.success, true, email + " login should succeed");
}

function reloadTarget() {
  var usersRepo = require(path.join(testServer.projectRoot, "app", "data", "repositories", "users.repo"));
  return usersRepo.findById(targetId);
}
function resolve(stash, user) {
  var handler = require(path.join(testServer.projectRoot, "app", "domain", "uploads", "upload.handler"));
  return handler.resolveUploadConfig(stash, user);
}

describe("per-user upload limits", function () {
  it("a user starts with no overrides (off by default)", function () {
    var u = reloadTarget();
    assert.ok(!Number(u.quotaBytes), "quotaBytes unset");
    assert.ok(!Number(u.maxFileSize), "maxFileSize unset");
    assert.ok(!u.allowedExtensions, "allowedExtensions unset");
  });

  it("admin sets per-user limits; numeric fields persist raw", async function () {
    await login("limadmin@test.com", "adminpass123");
    var res = await client.post("/admin/users/" + targetId + "/limits", { json: {
      quotaBytes: 10485760, maxFileSize: 2097152, maxFiles: 5, maxBundleSize: 5242880,
      allowedExtensions: "PDF, .png ,Zip",
    } });
    assert.strictEqual(res.json.success, true, "limits saved");
    var u = reloadTarget();
    assert.strictEqual(Number(u.quotaBytes), 10485760);
    assert.strictEqual(Number(u.maxFileSize), 2097152);
    assert.strictEqual(Number(u.maxFiles), 5);
    assert.strictEqual(Number(u.maxBundleSize), 5242880);
  });

  it("normalizes the extension allowlist (lowercase, dot-prefixed)", function () {
    assert.strictEqual(reloadTarget().allowedExtensions, ".pdf,.png,.zip");
  });

  it("resolveUploadConfig applies the per-user overrides to the owner's own upload", function () {
    var cfg = resolve(null, reloadTarget());
    assert.strictEqual(cfg.maxFileSize, 2097152, "per-user maxFileSize wins");
    assert.strictEqual(cfg.maxFiles, 5, "per-user maxFiles wins");
    assert.strictEqual(cfg.maxBundleSize, 5242880, "per-user maxBundleSize wins");
    assert.deepStrictEqual(cfg.allowedExtensions, [".pdf", ".png", ".zip"]);
  });

  it("a stash upload ignores per-user overrides (stash keeps its own config)", function () {
    var cfg = resolve({ maxFileSize: 999, maxFiles: 9, maxBundleSize: 9999 }, reloadTarget());
    assert.strictEqual(cfg.maxFileSize, 999, "stash config wins over per-user");
    assert.strictEqual(cfg.maxFiles, 9);
  });

  it("an anonymous upload (no user) uses the global config", function () {
    var config = require(path.join(testServer.projectRoot, "lib", "config"));
    var cfg = resolve(null, null);
    assert.strictEqual(cfg.maxFileSize, config.maxFileSize, "global maxFileSize for anonymous");
  });

  it("clearing the fields (blank/0) reverts to global defaults", async function () {
    await login("limadmin@test.com", "adminpass123");
    var res = await client.post("/admin/users/" + targetId + "/limits", { json: {
      quotaBytes: 0, maxFileSize: 0, maxFiles: 0, maxBundleSize: 0, allowedExtensions: "",
    } });
    assert.strictEqual(res.json.success, true);
    var u = reloadTarget();
    assert.ok(!Number(u.quotaBytes) && !Number(u.maxFileSize), "numeric overrides cleared");
    assert.ok(!u.allowedExtensions, "extensions cleared");
    var config = require(path.join(testServer.projectRoot, "lib", "config"));
    assert.strictEqual(resolve(null, u).maxFileSize, config.maxFileSize, "falls back to global");
  });

  it("rejects a negative value by treating it as unset (0)", async function () {
    await login("limadmin@test.com", "adminpass123");
    var res = await client.post("/admin/users/" + targetId + "/limits", { json: { quotaBytes: -500, maxFiles: -1 } });
    assert.strictEqual(res.json.success, true);
    var u = reloadTarget();
    assert.strictEqual(Number(u.quotaBytes), 0, "negative coerced to 0");
    assert.strictEqual(Number(u.maxFiles), 0);
  });

  it("rejects a nonexistent user (404)", async function () {
    await login("limadmin@test.com", "adminpass123");
    var res = await client.post("/admin/users/does-not-exist/limits", { json: { quotaBytes: 100 } });
    assert.strictEqual(res.status, 404);
  });

  it("a non-admin cannot set limits", async function () {
    await login("limoutsider@test.com", "outsiderpass123");
    var res = await client.post("/admin/users/" + targetId + "/limits", { json: { quotaBytes: 100 } });
    assert.ok(res.status === 403 || res.status === 302, "non-admin blocked, got " + res.status);
    assert.strictEqual(Number(reloadTarget().quotaBytes), 0, "value unchanged by blocked write");
  });
});
