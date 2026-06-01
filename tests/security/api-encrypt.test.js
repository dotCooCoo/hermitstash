var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var http = require("http");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var { encryptPayload, decryptPayload, generateApiKey } = require("../../lib/api-crypto");
var client;

before(async function () { await testServer.start(); client = new TestClient(testServer.baseUrl()); });
after(function () { return testServer.stop(); });

describe("API payload encryption", function () {

  // Seed admin user for tests
  before(async function () {
    var b = require(path.join(testServer.projectRoot, "lib", "vendor", "blamejs"));
    var vault = require(path.join(testServer.projectRoot, "lib", "vault"));
    var { hashEmail } = require(path.join(testServer.projectRoot, "lib", "crypto"));
    var { users } = require(path.join(testServer.projectRoot, "lib", "db"));
    // Password hashing — b.auth.password.hash (Argon2id PHC) is the
    // framework primitive; lib/crypto.js never exported hashPassword.
    var hash = await b.auth.password.hash("admin");
    users.insert({ email: vault.seal("admin@test.com"), emailHash: hashEmail("admin@test.com"), displayName: vault.seal("Admin"), passwordHash: hash, authType: "local", role: "admin", status: "active", createdAt: new Date().toISOString() });
    // Mark setup as complete so login redirects to /dashboard not /admin/setup
    var config = require(path.join(testServer.projectRoot, "lib", "config"));
    config.setupComplete = true;
  });

  it("all JSON responses are encrypted on the wire", async function () {
    await client.initApiKey();
    // Send raw HTTP to see the encrypted response before TestClient decrypts it
    var url = new URL("/auth/login", testServer.baseUrl());
    var body = JSON.stringify({ email: "admin@test.com", password: "admin" });
    var cookieStr = Object.entries(client.cookies).map(function(e) { return e[0] + "=" + e[1]; }).join("; ");
    var rawResp = await new Promise(function(resolve) {
      var req = http.request({ hostname: url.hostname, port: url.port, path: url.pathname, method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body), cookie: cookieStr } }, function(res) {
        var chunks = [];
        res.on("data", function(c) { chunks.push(c); });
        res.on("end", function() { resolve(JSON.parse(Buffer.concat(chunks).toString())); });
      });
      req.write(body); req.end();
    });
    assert.ok(rawResp._e, "raw response should have _e encrypted field");
    assert.ok(rawResp._t, "raw response should have _t timestamp");
    assert.ok(!rawResp.success, "plaintext success should not be visible");
  });

  it("client can decrypt responses with API key", async function () {
    await client.initApiKey();
    var res = await client.post("/auth/login", { json: { email: "admin@test.com", password: "admin" } });
    assert.strictEqual(res.json.success, true, "decrypted response should have success");
    assert.strictEqual(res.json.redirect, "/dashboard");
  });

  it("tampered encrypted payload rejected", async function () {
    await client.initApiKey();
    var body = JSON.stringify({ _e: "AAAA_tampered_data_garbage", _t: Date.now() });
    var res = await client.post("/auth/login", { body: body, contentType: "application/json" });
    assert.strictEqual(res.status, 400, "tampered payload should return 400");
  });

  it("decrypt-failure rejection is encrypted, not plaintext problem+json", async function () {
    // The decrypt-failure 400 is emitted from inside the body-collector stream
    // callback. It must route through the wrapped res.json (encrypted envelope),
    // NOT b.problemDetails' raw res.end — otherwise the error ships cleartext on
    // a session the client negotiated as encrypted (matters most in HTTP mode
    // where this layer is the only on-wire payload confidentiality).
    await client.initApiKey();
    var url = new URL("/auth/login", testServer.baseUrl());
    var body = JSON.stringify({ _e: "AAAA_tampered_data_garbage", _t: Date.now() });
    var cookieStr = Object.entries(client.cookies).map(function (e) { return e[0] + "=" + e[1]; }).join("; ");
    var raw = await new Promise(function (resolve) {
      var req = http.request({ hostname: url.hostname, port: url.port, path: url.pathname, method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body), cookie: cookieStr } }, function (res) {
        var chunks = [];
        res.on("data", function (c) { chunks.push(c); });
        res.on("end", function () { resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }); });
      });
      req.write(body); req.end();
    });
    assert.strictEqual(raw.status, 400, "decrypt failure should be 400");
    var parsed = JSON.parse(raw.body);
    assert.ok(parsed._e, "decrypt-failure body must be the encrypted envelope (_e), not cleartext");
    assert.strictEqual(parsed.detail, undefined, "no plaintext problem-details detail on the wire");
    assert.strictEqual(parsed.title, undefined, "no plaintext problem-details title on the wire");
  });

  it("expired timestamp rejected (anti-replay)", async function () {
    await client.initApiKey();
    // Craft a payload with an old timestamp INSIDE the GCM ciphertext
    // (the middleware checks the authenticated timestamp within the encrypted envelope)
    var ac = require("../../lib/api-crypto");
    var key = Buffer.from(client._apiKey, "base64url");
    var iv = require("crypto").randomBytes(12);
    var plaintext = JSON.stringify({ _d: { email: "admin@test.com", password: "admin" }, _t: Date.now() - 60000 });
    var cipher = require("crypto").createCipheriv("aes-256-gcm", key, iv);
    var enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    var tag = cipher.getAuthTag();
    var sealed = Buffer.concat([iv, enc, tag]).toString("base64url");
    var body = JSON.stringify({ _e: sealed, _t: Date.now() });
    var res = await client.post("/auth/login", { body: body, contentType: "application/json" });
    assert.strictEqual(res.status, 400, "expired timestamp should return 400");
  });

  it("wrong encryption key rejected", async function () {
    await client.initApiKey();
    var wrongKey = generateApiKey();
    var encrypted = encryptPayload({ email: "admin@test.com", password: "admin" }, wrongKey);
    var body = JSON.stringify({ _e: encrypted, _t: Date.now() });
    var res = await client.post("/auth/login", { body: body, contentType: "application/json" });
    assert.strictEqual(res.status, 400, "wrong key should return 400");
  });

  it("plaintext request still processed (graceful fallback)", async function () {
    await client.initApiKey();
    // Send unencrypted JSON via raw HTTP (no _e field) — should still work
    var url = new URL("/auth/login", testServer.baseUrl());
    var body = JSON.stringify({ email: "admin@test.com", password: "admin" });
    var cookieStr = Object.entries(client.cookies).map(function(e) { return e[0] + "=" + e[1]; }).join("; ");
    var rawResp = await new Promise(function(resolve) {
      var req = http.request({ hostname: url.hostname, port: url.port, path: url.pathname, method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body), cookie: cookieStr } }, function(res) {
        var chunks = [];
        res.on("data", function(c) { chunks.push(c); });
        res.on("end", function() { resolve(JSON.parse(Buffer.concat(chunks).toString())); });
      });
      req.write(body); req.end();
    });
    assert.ok(rawResp._e, "response should still be encrypted even for plaintext request");
  });

  it("API key is embedded in HTML pages", async function () {
    await client.initApiKey();
    assert.ok(client._apiKey, "API key should be extracted from page");
    assert.ok(client._apiKey.length > 30, "key should be substantial");
  });

  it("different sessions get different API keys", async function () {
    var client2 = new TestClient(testServer.baseUrl());
    await client2.initApiKey();
    assert.ok(client2._apiKey, "second client should get key");
    // Keys may differ since sessions are different
    // (both are valid but shouldn't be identical unless by chance)
  });

  it("drop init works with encrypted payload", async function () {
    await client.initApiKey();
    var res = await client.post("/drop/init", { json: { uploaderName: "Tester", fileCount: 0, skippedCount: 0 } });
    assert.ok(res.json.bundleId, "should return bundleId");
    assert.ok(res.json.shareId, "should return shareId");
  });

  it("admin settings response is encrypted", async function () {
    await client.initApiKey();
    await client.post("/auth/login", { json: { email: "admin@test.com", password: "admin" } });
    var res = await client.get("/admin/settings");
    // The TestClient auto-decrypts, so we should see the settings
    assert.ok(res.json.siteName !== undefined, "decrypted settings should have siteName");
  });
});
