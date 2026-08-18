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

  it("a stash with No-limit fields (-1 / \"*\") resolves to no caps", function () {
    var cfg = resolve({ maxFileSize: -1, maxFiles: -1, maxBundleSize: -1, allowedExtensions: "*" }, null);
    assert.strictEqual(cfg.maxFileSize, 0);
    assert.strictEqual(cfg.maxFiles, 0);
    assert.strictEqual(cfg.maxBundleSize, 0);
    assert.deepStrictEqual(cfg.allowedExtensions, []);
  });

  it("a stash with an explicit cap wins; a blank stash field falls back to global", function () {
    var config = require(path.join(testServer.projectRoot, "lib", "config"));
    var cfg = resolve({ maxFileSize: 4096, maxFiles: 0, maxBundleSize: 0, allowedExtensions: "" }, null);
    assert.strictEqual(cfg.maxFileSize, 4096, "explicit stash cap honored");
    assert.strictEqual(cfg.maxFiles, config.publicMaxFiles, "blank stash field uses global");
    assert.strictEqual(cfg.maxBundleSize, config.publicMaxBundleSize, "blank stash field uses global");
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

  it("treats an arbitrary negative (not -1) as unset (0)", async function () {
    await login("limadmin@test.com", "adminpass123");
    var res = await client.post("/admin/users/" + targetId + "/limits", { json: { quotaBytes: -500, maxFiles: -42 } });
    assert.strictEqual(res.json.success, true);
    var u = reloadTarget();
    assert.strictEqual(Number(u.quotaBytes), 0, "arbitrary negative coerced to 0");
    assert.strictEqual(Number(u.maxFiles), 0);
  });

  it("admin sets every field to No limit (-1 / \"*\"); sentinels persist", async function () {
    await login("limadmin@test.com", "adminpass123");
    var res = await client.post("/admin/users/" + targetId + "/limits", { json: {
      quotaBytes: -1, maxFileSize: -1, maxFiles: -1, maxBundleSize: -1, allowedExtensions: "*",
    } });
    assert.strictEqual(res.json.success, true);
    var u = reloadTarget();
    assert.strictEqual(Number(u.quotaBytes), -1);
    assert.strictEqual(Number(u.maxFileSize), -1);
    assert.strictEqual(Number(u.maxFiles), -1);
    assert.strictEqual(Number(u.maxBundleSize), -1);
    assert.strictEqual(u.allowedExtensions, "*");
  });

  it("resolveUploadConfig lifts every cap when No limit is set", function () {
    var cfg = resolve(null, reloadTarget());
    assert.strictEqual(cfg.maxFileSize, 0, "0 = no policy cap (validators treat 0 as unbounded)");
    assert.strictEqual(cfg.maxFiles, 0);
    assert.strictEqual(cfg.maxBundleSize, 0);
    assert.deepStrictEqual(cfg.allowedExtensions, [], "empty list = allow any extension");
  });

  it("a No-limit quota bypasses even a configured global PER_USER_QUOTA", async function () {
    var config = require(path.join(testServer.projectRoot, "lib", "config"));
    var handler = require(path.join(testServer.projectRoot, "app", "domain", "uploads", "upload.handler"));
    var prev = config.perUserQuotaBytes;
    config.perUserQuotaBytes = 1048576; // global 1 MB cap in force
    try {
      // _perUserQuotaCap sees the owner's -1 and returns "no cap", winning over the
      // global; an upload far above the 1 MB global is therefore allowed.
      var r = await handler.checkAllQuotas(5242880, { ownerId: targetId }, { headers: {}, ip: "127.0.0.1" });
      assert.strictEqual(r.allowed, true, "No-limit quota owner is not capped by the global PER_USER_QUOTA");
    } finally {
      config.perUserQuotaBytes = prev;
    }
  });

  it("the No-limit multipart ceiling is a positive finite byte count", function () {
    var C = require(path.join(testServer.projectRoot, "lib", "constants"));
    assert.ok(C.UPLOAD.NO_LIMIT_CEILING_BYTES > 0 && isFinite(C.UPLOAD.NO_LIMIT_CEILING_BYTES));
  });

  it("rejects a nonexistent user (404)", async function () {
    await login("limadmin@test.com", "adminpass123");
    var res = await client.post("/admin/users/does-not-exist/limits", { json: { quotaBytes: 100 } });
    assert.strictEqual(res.status, 404);
  });

  it("a non-admin cannot set limits", async function () {
    var before = Number(reloadTarget().quotaBytes);
    await login("limoutsider@test.com", "outsiderpass123");
    var res = await client.post("/admin/users/" + targetId + "/limits", { json: { quotaBytes: 100 } });
    assert.ok(res.status === 403 || res.status === 302, "non-admin blocked, got " + res.status);
    assert.strictEqual(Number(reloadTarget().quotaBytes), before, "value unchanged by blocked write");
  });
});

// Which cap applies to a given upload, and whether the one that applies is
// actually enforced. The precedence has three levels — a per-user override, the
// instance-wide PER_USER_QUOTA, and no cap at all — and getting it wrong in
// either direction is a real outcome: a user silently granted unlimited
// storage, or one refused an upload they are entitled to make.
describe("per-user quota precedence and enforcement", function () {
  var handler, config, usersRepo, filesRepo;
  var savedGlobal, savedQuota;

  before(function () {
    handler = require(path.join(testServer.projectRoot, "app", "domain", "uploads", "upload.handler"));
    config = require(path.join(testServer.projectRoot, "lib", "config"));
    usersRepo = require(path.join(testServer.projectRoot, "app", "data", "repositories", "users.repo"));
    filesRepo = require(path.join(testServer.projectRoot, "app", "data", "repositories", "files.repo"));
    savedGlobal = config.perUserQuotaBytes;
    savedQuota = reloadTarget().quotaBytes;
  });
  after(function () {
    config.perUserQuotaBytes = savedGlobal;
    usersRepo.update(targetId, { $set: { quotaBytes: savedQuota } });
  });

  // $set, not a bare object: the repositories forward `ops` straight to the DB
  // layer, which acts only on $set/$push. A bare object used to write nothing
  // and say nothing — it now throws, and the case below holds that.
  function setOwnerQuota(v) { usersRepo.update(targetId, { $set: { quotaBytes: v } }); }
  function check(size, ownerId) {
    // No IP quota configured in these cases, so req is only along for the ride.
    return handler.checkAllQuotas(size, { ownerId: ownerId }, { headers: {}, ip: "127.0.0.1" });
  }

  it("applies no per-user cap to an anonymous upload", async function () {
    // The per-user quota is keyed on an owner. Applying the global to an upload
    // with no owner would cap every anonymous visitor against one shared total.
    config.perUserQuotaBytes = 1024;
    var r = await check(1048576, null);
    assert.strictEqual(r.allowed, true, "an ownerless upload is not subject to a per-user cap");
  });

  it("falls back to the instance default when the owner has no override", async function () {
    setOwnerQuota(0);
    config.perUserQuotaBytes = 1048576;
    assert.strictEqual((await check(512, targetId)).allowed, true, "under the global cap");
    var over = await check(2097152, targetId);
    assert.strictEqual(over.allowed, false, "over the global cap must be refused");
    assert.match(over.error, /Personal storage quota exceeded/);
    assert.strictEqual(over.reason, "per-user quota exceeded");
  });

  it("lets an explicit override win over the instance default, in both directions", async function () {
    config.perUserQuotaBytes = 1048576;   // global 1 MB

    setOwnerQuota(4194304);               // this user may use 4 MB
    assert.strictEqual((await check(2097152, targetId)).allowed, true,
      "an override above the global raises this user's ceiling");

    setOwnerQuota(1024);                  // this user is held to 1 KB
    assert.strictEqual((await check(4096, targetId)).allowed, false,
      "an override below the global lowers it, and is enforced");
  });

  it("treats a missing owner record as no override rather than as no cap", async function () {
    // A grant can outlive the account it was written for. Reading the absent
    // user as "unlimited" would turn a deleted account into a bypass.
    config.perUserQuotaBytes = 1024;
    var r = await check(1048576, "no-such-user-id");
    assert.strictEqual(r.allowed, false, "an unknown owner falls back to the global cap, not to no cap");
  });

  it("counts what the owner already stores, not just the new file", async function () {
    // The cap is on the total. Checking the incoming size alone would let a
    // user at their limit keep uploading forever.
    config.perUserQuotaBytes = 0;
    setOwnerQuota(10000);
    var f = filesRepo.create({
      bundleId: "quota-bundle", originalName: "big.bin", storedName: "big.bin",
      size: 9000, uploadedBy: targetId, createdAt: new Date().toISOString(),
    });
    try {
      assert.strictEqual((await check(500, targetId)).allowed, true, "9000 + 500 is under 10000");
      var over = await check(2000, targetId);
      assert.strictEqual(over.allowed, false, "9000 + 2000 is over 10000 and must be refused");
    } finally {
      if (f && f._id) filesRepo.remove(f._id);
    }
  });

  it("is off entirely when neither an override nor an instance default is set", async function () {
    config.perUserQuotaBytes = 0;
    setOwnerQuota(0);
    assert.strictEqual((await check(1073741824, targetId)).allowed, true,
      "quotas are opt-in; with none configured a large upload is allowed");
  });

  it("refuses an update that would write nothing rather than accepting it", function () {
    // How this was found: setting the quota with a bare object left it at 0, and
    // three enforcement cases "passed" against a cap that had never been
    // written. The repositories take (id, ops) and hand ops straight to the DB
    // layer, which acts only on $set/$push, so the mistake looks exactly like a
    // correct call and reports nothing.
    assert.throws(function () { usersRepo.update(targetId, { quotaBytes: 4096 }); },
      /needs \$set or \$push/,
      "a bare object must be refused, not silently ignored");
    assert.strictEqual(Number(reloadTarget().quotaBytes), 0, "and must not have written anything");

    // The correct form still works.
    usersRepo.update(targetId, { $set: { quotaBytes: 4096 } });
    assert.strictEqual(Number(reloadTarget().quotaBytes), 4096);
    usersRepo.update(targetId, { $set: { quotaBytes: 0 } });
  });
});
