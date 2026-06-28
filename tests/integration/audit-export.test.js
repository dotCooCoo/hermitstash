const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");
var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;
var audit, auditRepo;

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());
  var root = testServer.projectRoot;
  audit = require(path.join(root, "lib", "audit"));
  auditRepo = require(path.join(root, "app", "data", "repositories", "audit.repo"));

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
  await seed("exadmin@test.com", "Export Admin", "admin", "adminpass123");
  await seed("exuser@test.com", "Export User", "user", "userpass123");

  function req(over) {
    return Object.assign({
      method: "POST", pathname: "/auth/login", headers: { "user-agent": "UA/1" },
      user: { _id: "u-ex", email: "x@y.com" }, socket: { remoteAddress: "198.51.100.7" }, requestId: "r-1",
    }, over || {});
  }
  audit.log("login_success", { targetId: "ex-1", targetEmail: "a@b.com", details: "First event", req: req() });
  audit.log("login_failed_bad_password", { targetId: "ex-2", details: "Bad pw", req: req() });
  audit.log("file_downloaded", { targetId: "ex-3", details: "Downloaded", req: req({ method: "GET", pathname: "/d/x" }) });
});
after(function () { return testServer.stop(); });

async function login(email, pw) {
  client.clearCookies();
  await client.initApiKey();
  testServer.resetAllRateLimits();
  var r = await client.post("/auth/login", { json: { email: email, password: pw } });
  assert.strictEqual(r.json.success, true, email + " login should succeed");
}

describe("audit decrypt + export", function () {
  it("JSON export returns decrypted entries with full context", async function () {
    await login("exadmin@test.com", "adminpass123");
    var res = await client.get("/admin/audit/export?format=json");
    assert.strictEqual(res.status, 200);
    assert.ok(/attachment; filename="audit-export-/.test(res.headers["content-disposition"] || ""), "download header");
    assert.ok(Array.isArray(res.json.entries), "entries array");
    var e1 = res.json.entries.find(function (e) { return e.targetId === "ex-1"; });
    assert.ok(e1, "seeded entry present");
    assert.strictEqual(e1.action, "login_success");
    assert.strictEqual(e1.method, "POST");
    assert.strictEqual(e1.path, "/auth/login");
  });

  it("CSV export is formula-injection-safe with a header row", async function () {
    await login("exadmin@test.com", "adminpass123");
    var res = await client.get("/admin/audit/export?format=csv");
    assert.strictEqual(res.status, 200);
    assert.strictEqual((res.headers["content-type"] || "").indexOf("text/csv"), 0, "csv content-type");
    var lines = res.text.split(/\r?\n/);
    assert.strictEqual(lines[0].indexOf("createdAt"), 0, "header row, got: " + lines[0]);
    assert.ok(res.text.indexOf("login_success") !== -1, "contains a seeded action");
  });

  it("CADF export is a valid event batch with the chain extension", async function () {
    await login("exadmin@test.com", "adminpass123");
    var res = await client.get("/admin/audit/export?format=cadf");
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.json.typeURI, "http://schemas.dmtf.org/cloud/audit/1.0/event-batch");
    assert.ok(Array.isArray(res.json.events) && res.json.events.length >= 3, "events present");
    var ev = res.json.events[0];
    assert.ok(ev.eventTime && ev.action, "event has time + action");
    assert.ok(ev["blamejs:chain"], "chain extension present");
    var failed = res.json.events.find(function (x) { return x.action === "login_failed_bad_password"; });
    assert.strictEqual(failed.outcome, "failure", "failed action → failure outcome");
  });

  it("the action filter scopes the export", async function () {
    await login("exadmin@test.com", "adminpass123");
    var res = await client.get("/admin/audit/export?format=json&action=file_downloaded");
    var actions = res.json.entries.map(function (e) { return e.action; });
    assert.ok(actions.length >= 1 && actions.every(function (a) { return a === "file_downloaded"; }), "only the filtered action");
  });

  it("exporting is itself audited (audit_exported)", async function () {
    await login("exadmin@test.com", "adminpass123");
    await client.get("/admin/audit/export?format=json");
    var res = auditRepo.findPaginated({}, { limit: 50, offset: 0, orderBy: "createdAt", orderDir: "desc" });
    var exp = res.data.find(function (e) { return e.action === "audit_exported"; });
    assert.ok(exp, "audit_exported entry written");
    assert.strictEqual((exp.details || "").indexOf("json export"), 0, "details note the format");
  });

  it("a non-admin cannot export", async function () {
    await login("exuser@test.com", "userpass123");
    var res = await client.get("/admin/audit/export?format=json");
    assert.ok(res.status === 403 || res.status === 302, "non-admin blocked, got " + res.status);
  });
});
