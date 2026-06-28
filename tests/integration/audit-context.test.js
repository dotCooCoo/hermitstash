const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");
var testServer = require("../helpers/test-server");

var audit, auditRepo, config, db;

before(async function () {
  await testServer.start();
  var root = testServer.projectRoot;
  audit = require(path.join(root, "lib", "audit"));
  auditRepo = require(path.join(root, "app", "data", "repositories", "audit.repo"));
  config = require(path.join(root, "lib", "config"));
  db = require(path.join(root, "lib", "db"));
});
after(function () { return testServer.stop(); });

function fakeReq(over) {
  return Object.assign({
    method: "POST",
    pathname: "/audit/test",
    headers: { "user-agent": "TestUA/9.9" },
    user: { _id: "u-tester", email: "tester@test.com" },
    socket: { remoteAddress: "203.0.113.42" },
    connection: { remoteAddress: "203.0.113.42" },
    requestId: "req-abc123",
  }, over || {});
}

function findByTarget(targetId) {
  var res = auditRepo.findPaginated({}, { limit: 500, offset: 0, orderBy: "createdAt", orderDir: "desc" });
  return res.data.find(function (e) { return e.targetId === targetId; });
}

describe("audit richer context capture", function () {
  it("captures method / path / authType / requestId / performer from req", function () {
    audit.log("file_downloaded", { targetId: "t-ctx-1", req: fakeReq() });
    var e = findByTarget("t-ctx-1");
    assert.ok(e, "entry written");
    assert.strictEqual(e.method, "POST");
    assert.strictEqual(e.path, "/audit/test");
    assert.strictEqual(e.authType, "session");
    assert.strictEqual(e.requestId, "req-abc123");
    assert.strictEqual(e.performedBy, "u-tester");
  });

  it("authType reflects apikey and anonymous callers", function () {
    audit.log("file_downloaded", { targetId: "t-ctx-key", req: fakeReq({ user: null, apiKey: { _id: "k1" } }) });
    audit.log("file_downloaded", { targetId: "t-ctx-anon", req: fakeReq({ user: null }) });
    assert.strictEqual(findByTarget("t-ctx-key").authType, "apikey");
    assert.strictEqual(findByTarget("t-ctx-anon").authType, "anonymous");
  });

  it("strips the query string from the recorded path (no token leak)", function () {
    audit.log("file_downloaded", { targetId: "t-q", req: fakeReq({ pathname: null, url: "/d/x?token=secret123" }) });
    var e = findByTarget("t-q");
    assert.strictEqual(e.path, "/d/x");
    assert.ok(e.path.indexOf("secret123") === -1, "query string dropped");
  });

  it("records a one-way IP hash by default (operator cannot recover the address)", function () {
    config.auditIpFull = false;
    audit.log("file_downloaded", { targetId: "t-ip-hash", req: fakeReq() });
    var e = findByTarget("t-ip-hash");
    assert.ok(/^[0-9a-f]{16}$/.test(e.ip || ""), "ip stored as 16-hex hash, got " + e.ip);
    assert.ok((e.ip || "").indexOf("203.0.113") === -1, "raw IP absent");
  });

  it("records the full IP when auditIpFull is enabled (investigation mode)", function () {
    config.auditIpFull = true;
    try {
      audit.log("file_downloaded", { targetId: "t-ip-full", req: fakeReq() });
      assert.strictEqual(findByTarget("t-ip-full").ip, "203.0.113.42");
    } finally { config.auditIpFull = false; }
  });

  it("captures user-agent only when enabled", function () {
    config.auditCaptureUserAgent = false;
    audit.log("file_downloaded", { targetId: "t-ua-off", req: fakeReq() });
    assert.ok(!findByTarget("t-ua-off").userAgent, "UA not captured by default");
    config.auditCaptureUserAgent = true;
    try {
      audit.log("file_downloaded", { targetId: "t-ua-on", req: fakeReq() });
      assert.strictEqual(findByTarget("t-ua-on").userAgent, "TestUA/9.9");
    } finally { config.auditCaptureUserAgent = false; }
  });

  it("seals path + userAgent at rest; method stays raw", function () {
    config.auditCaptureUserAgent = true;
    try {
      audit.log("file_downloaded", { targetId: "t-seal", req: fakeReq() });
      var e = findByTarget("t-seal");
      assert.strictEqual(e.path, "/audit/test", "path unsealed on read");
      var raw = db.rawGet("SELECT path, userAgent, method, authType FROM audit_log WHERE _id = ?", e._id);
      assert.notStrictEqual(raw.path, "/audit/test", "path is ciphertext at rest");
      assert.notStrictEqual(raw.userAgent, "TestUA/9.9", "userAgent is ciphertext at rest");
      assert.strictEqual(raw.method, "POST", "method stored raw (enum)");
      assert.strictEqual(raw.authType, "session", "authType stored raw (enum)");
    } finally { config.auditCaptureUserAgent = false; }
  });

  it("a system event (no req) leaves context columns null", function () {
    audit.log("server_started", { targetId: "t-sys", performedBy: "system" });
    var e = findByTarget("t-sys");
    assert.ok(e, "entry written");
    assert.ok(!e.method && !e.path && !e.ip && !e.authType, "no request context for a system event");
  });
});

describe("audit tamper-chain with the widened schema", function () {
  var auditService;
  before(function () {
    auditService = require(path.join(testServer.projectRoot, "app", "domain", "admin", "audit.service"));
    config.auditChainEnabled = true;
  });
  after(function () { config.auditChainEnabled = false; });

  it("chained rows hash the new columns and verifyChain stays clean", async function () {
    audit.log("file_downloaded", { targetId: "t-chain-1", req: fakeReq() });
    audit.log("user_role_changed", { targetId: "t-chain-2", req: fakeReq({ method: "GET", pathname: "/admin/x" }) });
    audit.log("server_started", { performedBy: "system", targetId: "t-chain-3" });
    await audit.drainChain();

    var e = findByTarget("t-chain-2");
    assert.strictEqual(e.method, "GET", "chained row carries the new context");
    assert.strictEqual(e.path, "/admin/x");

    var result = await auditService.verifyAuditChain();
    assert.strictEqual(result.ok, true, "chain verifies clean: " + JSON.stringify(result));
    assert.ok(result.rowsVerified >= 3, "verified the chained rows, got " + result.rowsVerified);
  });
});
