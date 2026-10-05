require("../helpers/isolate-db"); // must precede every HermitStash require
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var TIME = require("../../lib/vendor/blamejs").constants.TIME;
var argon2Probe = require("../helpers/argon2-probe");
var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");

argon2Probe.install();

var root = testServer.projectRoot;
var BUSY = "Too many password checks are in progress. Try again in a few seconds.";
var FILLER_PW = "filler-password-1";
var CASE = { timeout: TIME.seconds(60) };
var b, C, gate, db, usersRepo, tokensRepo, fillerHash, admitted;

before(async function () {
  await testServer.start();
  // Required after start(), so these are the copies the mounted routes use.
  b = require(path.join(root, "lib", "vendor", "blamejs"));
  C = require(path.join(root, "lib", "constants"));
  gate = require(path.join(root, "lib", "password-gate"));
  db = require(path.join(root, "lib", "db"));
  usersRepo = require(path.join(root, "app", "data", "repositories", "users.repo"));
  tokensRepo = require(path.join(root, "app", "data", "repositories", "verificationTokens.repo"));
  admitted = C.PASSWORD_HASH.MAX_CONCURRENT + C.PASSWORD_HASH.MAX_QUEUED;
  // A 1 MiB stored hash keeps each filler check short; verify reads its cost
  // from the stored hash.
  fillerHash = await b.auth.password.hash(FILLER_PW, { memoryCost: C.BYTES.kib(1), timeCost: 1, parallelism: 1 });
});

after(async function () {
  argon2Probe.uninstall();
  await testServer.stop();
});

async function seedUser(email, password, extra) {
  return usersRepo.create(Object.assign({
    email: email, displayName: "Gate Test", passwordHash: await gate.hash(password),
    authType: "local", role: "user", status: "active", createdAt: new Date().toISOString(),
  }, extra || {}));
}

async function newClient() {
  var client = new TestClient(testServer.baseUrl());
  await client.initApiKey();
  return client;
}

function login(client, email, password) {
  return client.post("/auth/login", { json: { email: email, password: password } });
}

async function until(predicate, label) {
  var deadline = Date.now() + TIME.seconds(10);
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error("timed out waiting for " + label);
    await new Promise(function (resolve) { setImmediate(resolve); });
  }
}

// Fills every running and queued slot. The running check is held before it
// reaches node:crypto, and the others wait in the queue behind it.
function fillGate() {
  argon2Probe.hold();
  var fillers = [];
  for (var i = 0; i < admitted; i++) fillers.push(gate.verify(fillerHash, FILLER_PW));
  return fillers;
}

async function drain(fillers) {
  argon2Probe.release();
  var results = await Promise.all(fillers);
  assert.ok(results.every(function (r) { return r === true; }), "every queued filler check completed");
}

describe("password checks through the mounted routes", function () {
  it("runs one Argon2id check at a time and completes every queued login", CASE, async function () {
    await seedUser("gate-a@test.com", "right-password-a1");
    testServer.resetAllRateLimits();
    var clients = [];
    for (var i = 0; i < 6; i++) clients.push(await newClient());
    argon2Probe.reset();
    argon2Probe.hold();
    var pending = clients.map(function (c) { return login(c, "gate-a@test.com", "wrong-password-a1"); });
    try {
      await until(function () { var s = gate.stats(); return s.running + s.queued === 6; }, "six admitted checks");
      assert.strictEqual(argon2Probe.stats().running, C.PASSWORD_HASH.MAX_CONCURRENT);
    } finally {
      argon2Probe.release();
    }
    var responses = await Promise.all(pending);
    responses.forEach(function (r) { assert.strictEqual(r.status, 401); });
    assert.strictEqual(argon2Probe.stats().maxRunning, C.PASSWORD_HASH.MAX_CONCURRENT);
    assert.strictEqual(argon2Probe.stats().calls, 6);
  });

  it("refuses a login with 503, Retry-After and the busy detail while the queue is full", CASE, async function () {
    await seedUser("gate-b@test.com", "right-password-b1");
    testServer.resetAllRateLimits();
    var client = await newClient();
    var fillers = fillGate();
    try {
      var res = await login(client, "gate-b@test.com", "right-password-b1");
      assert.strictEqual(res.status, 503);
      assert.strictEqual(res.headers["retry-after"], String(C.PASSWORD_HASH.RETRY_AFTER_SECONDS));
      assert.strictEqual(res.json.type, "https://hermitstash.com/problems/service-unavailable");
      assert.strictEqual(res.json.detail, BUSY);
      assert.strictEqual(res.json.retryAfter, C.PASSWORD_HASH.RETRY_AFTER_SECONDS);
    } finally {
      await drain(fillers);
    }
    assert.ok(!(usersRepo.findByEmail("gate-b@test.com").failedLoginAttempts > 0), "a refused check is not a failed attempt");
    var ok = await login(client, "gate-b@test.com", "right-password-b1");
    assert.strictEqual(ok.json.success, true);
  });

  it("answers a locked account with the same 503 while the queue is full", CASE, async function () {
    await seedUser("gate-c@test.com", "right-password-c1", { lockedUntil: new Date(Date.now() + TIME.minutes(30)).toISOString() });
    testServer.resetAllRateLimits();
    var client = await newClient();
    var fillers = fillGate();
    try {
      var res = await login(client, "gate-c@test.com", "right-password-c1");
      assert.strictEqual(res.status, 503);
      assert.strictEqual(res.json.detail, BUSY);
    } finally {
      await drain(fillers);
    }
    var locked = await login(client, "gate-c@test.com", "right-password-c1");
    assert.strictEqual(locked.status, 401);
  });

  it("refuses a share-link unlock with 503 and records no failed attempt", CASE, async function () {
    testServer.resetAllRateLimits();
    var owner = await newClient();
    var init = await owner.post("/drop/init", { json: { uploaderName: "Gate", uploaderEmail: "gate-owner@test.com", fileCount: 1, skippedCount: 0, skippedFiles: [], password: "bundle-pass-123" } });
    assert.ok(init.json.bundleId, "bundle created");
    var upload = await owner.uploadFile("/drop/file/" + init.json.bundleId, "file", "gate.txt", "gate content", { relativePath: "gate.txt" });
    assert.strictEqual(upload.status, 200);
    var fin = await owner.post("/drop/finalize/" + init.json.bundleId, { json: { finalizeToken: init.json.finalizeToken } });
    assert.strictEqual(fin.json.success, true);

    var visitor = await newClient();
    var fillers = fillGate();
    try {
      var res = await visitor.post("/b/" + init.json.shareId + "/unlock", { json: { password: "bundle-pass-123" } });
      assert.strictEqual(res.status, 503);
      assert.strictEqual(res.json.detail, BUSY);
    } finally {
      await drain(fillers);
    }
    assert.strictEqual(db.bundleAccessLockouts.count({}), 0, "a refused check is not a failed unlock attempt");
    var ok = await visitor.post("/b/" + init.json.shareId + "/unlock", { json: { password: "bundle-pass-123" } });
    assert.strictEqual(ok.json.success, true);
  });

  it("refuses a password-protected /drop/init with 503 and does not replay the refusal", CASE, async function () {
    testServer.resetAllRateLimits();
    var client = await newClient();
    var body = { uploaderName: "Gate", fileCount: 1, skippedCount: 0, skippedFiles: [], password: "bundle-pass-456" };
    var headers = { "Idempotency-Key": "gate-init-" + b.crypto.generateToken(16) };
    var fillers = fillGate();
    try {
      var refused = await client.post("/drop/init", { json: body, headers: headers });
      assert.strictEqual(refused.status, 503);
      assert.strictEqual(refused.headers["retry-after"], String(C.PASSWORD_HASH.RETRY_AFTER_SECONDS));
    } finally {
      await drain(fillers);
    }
    var retried = await client.post("/drop/init", { json: body, headers: headers });
    assert.strictEqual(retried.status, 200);
    assert.ok(retried.json.bundleId, "the retry ran the handler");
    var replayed = await client.post("/drop/init", { json: body, headers: headers });
    assert.strictEqual(replayed.json.bundleId, retried.json.bundleId, "the 200 is cached and replayed");
  });

  it("leaves the reset link usable when the new-password hash is refused", CASE, async function () {
    var user = await seedUser("gate-d@test.com", "old-password-d1");
    var raw = b.crypto.generateToken();
    tokensRepo.create({
      userId: user._id, token: b.crypto.sha3Hash(raw), type: "password_reset",
      expiresAt: new Date(Date.now() + TIME.hours(1)).toISOString(), createdAt: new Date().toISOString(),
    });
    testServer.resetAllRateLimits();
    var client = await newClient();
    var fillers = fillGate();
    try {
      var refused = await client.post("/auth/reset-password/" + raw, { json: { password: "new-password-d2" } });
      assert.strictEqual(refused.status, 503);
    } finally {
      await drain(fillers);
    }
    var done = await client.post("/auth/reset-password/" + raw, { json: { password: "new-password-d2" } });
    assert.strictEqual(done.json.success, true, JSON.stringify(done.json));
  });
});
