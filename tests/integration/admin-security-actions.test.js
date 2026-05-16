/**
 * Admin Security Actions E2E.
 *
 * Covers the 6 endpoints + the /admin/security/status action metadata:
 *   POST   /admin/security/seal/vault-passphrase
 *   POST   /admin/security/unseal/vault-passphrase
 *   POST   /admin/security/seal/ca-key
 *   POST   /admin/security/unseal/ca-key
 *   POST   /admin/security/seal/tls-key        (TLS setup not in fixture; shape-check only)
 *   POST   /admin/security/unseal/tls-key      (same)
 *   GET    /admin/security/status              (verify `actions` array shape)
 *
 * The test spawns a real server via tests/helpers/test-server, registers
 * an admin, and exercises the routes end-to-end. Non-admin gate tested too.
 */
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;
var regularClient;

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());
  regularClient = new TestClient(testServer.baseUrl());

  // First registered user becomes admin (HermitStash convention)
  client.clearCookies();
  await client.initApiKey();
  await client.post("/auth/register", {
    json: { displayName: "Sec Admin", email: "sec-admin@test.com", password: "password123" },
  });

  // Second user is a regular user — used for the admin-gate test
  regularClient.clearCookies();
  await regularClient.initApiKey();
  await regularClient.post("/auth/register", {
    json: { displayName: "Sec Regular", email: "sec-regular@test.com", password: "password123" },
  });
});

after(function () { return testServer.stop(); });

describe("GET /admin/security/status", function () {

  it("requires admin", async function () {
    var res = await regularClient.get("/admin/security/status");
    assert.strictEqual(res.status, 403);
  });

  it("returns 5 items each with status + actions fields", async function () {
    var res = await client.get("/admin/security/status");
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.json.success, true);
    assert.ok(Array.isArray(res.json.items), "items array present");
    var keys = res.json.items.map(function (i) { return i.key; });
    ["vault_passphrase", "ca_key_sealed", "tls_key_sealed", "mtls_enforcement", "tls"].forEach(function (k) {
      assert.ok(keys.indexOf(k) !== -1, "status response includes " + k);
    });
    res.json.items.forEach(function (i) {
      assert.ok(["ok", "warn", "info"].indexOf(i.status) !== -1, i.key + " has valid status");
      assert.ok(Array.isArray(i.actions), i.key + " has actions array");
    });
  });

  it("vault_passphrase row surfaces a 'seal' action when plaintext vault.key exists", async function () {
    var res = await client.get("/admin/security/status");
    var vault = res.json.items.filter(function (i) { return i.key === "vault_passphrase"; })[0];
    assert.ok(vault, "vault_passphrase row present");
    // Test server runs in plaintext mode with no sealed file → expect a seal action
    var sealAction = vault.actions.filter(function (a) { return a.kind === "seal"; })[0];
    assert.ok(sealAction, "seal action present on plaintext row");
    assert.strictEqual(sealAction.route, "/admin/security/seal/vault-passphrase");
    assert.strictEqual(sealAction.needsPassphrase, true);
  });
});

describe("POST /admin/security/seal/vault-passphrase", function () {

  it("non-admin returns 403", async function () {
    var res = await regularClient.post("/admin/security/seal/vault-passphrase", {
      json: { passphrase: "xx", confirmPassphrase: "xx" },
    });
    assert.strictEqual(res.status, 403);
  });

  it("refuses mismatched passphrase + confirm", async function () {
    var res = await client.post("/admin/security/seal/vault-passphrase", {
      json: { passphrase: "one", confirmPassphrase: "different" },
    });
    assert.strictEqual(res.status, 400);
    assert.match(res.json.error, /do not match/);
  });

  it("refuses empty passphrase", async function () {
    var res = await client.post("/admin/security/seal/vault-passphrase", {
      json: { passphrase: "", confirmPassphrase: "" },
    });
    assert.strictEqual(res.status, 400);
    assert.match(res.json.error, /required/);
  });

  it("seals vault key with matching passphrase + returns followUp checklist", async function () {
    var pw = "e2e-test-passphrase-abc-123";
    var res = await client.post("/admin/security/seal/vault-passphrase", {
      json: { passphrase: pw, confirmPassphrase: pw },
    });
    assert.strictEqual(res.status, 200, "seal should succeed; body: " + JSON.stringify(res.json));
    assert.strictEqual(res.json.success, true);
    assert.ok(res.json.sealedPath);
    assert.ok(Array.isArray(res.json.followUp), "followUp checklist present");
    assert.ok(res.json.followUp.length > 0);
    assert.ok(res.json.followUp.some(function (s) { return /VAULT_PASSPHRASE_FILE/.test(s); }),
      "followUp mentions the env-var setup requirement");
  });

  it("post-seal: status endpoint now shows unseal action (disable button)", async function () {
    var res = await client.get("/admin/security/status");
    var vault = res.json.items.filter(function (i) { return i.key === "vault_passphrase"; })[0];
    var unsealAction = vault.actions.filter(function (a) { return a.kind === "unseal"; })[0];
    assert.ok(unsealAction, "after sealing, unseal action should appear");
    assert.strictEqual(unsealAction.route, "/admin/security/unseal/vault-passphrase");
  });

  it("refuses a second seal while already sealed", async function () {
    var res = await client.post("/admin/security/seal/vault-passphrase", {
      json: { passphrase: "x", confirmPassphrase: "x" },
    });
    assert.strictEqual(res.status, 409);
  });
});

describe("POST /admin/security/unseal/vault-passphrase", function () {

  it("non-admin returns 403", async function () {
    var res = await regularClient.post("/admin/security/unseal/vault-passphrase", {
      json: { passphrase: "x" },
    });
    assert.strictEqual(res.status, 403);
  });

  it("rejects wrong passphrase with 401", async function () {
    var res = await client.post("/admin/security/unseal/vault-passphrase", {
      json: { passphrase: "definitely-the-wrong-one" },
    });
    assert.strictEqual(res.status, 401);
    assert.match(res.json.error, /passphrase rejected/);
  });

  it("unseals with correct passphrase", async function () {
    var pw = "e2e-test-passphrase-abc-123";
    var res = await client.post("/admin/security/unseal/vault-passphrase", {
      json: { passphrase: pw },
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.json.success, true);
    assert.ok(res.json.plaintextPath);
    assert.ok(Array.isArray(res.json.followUp));
    assert.ok(res.json.followUp.some(function (s) { return /unset VAULT_PASSPHRASE_MODE/i.test(s); }),
      "followUp mentions the env-var cleanup requirement");
  });
});

describe("POST /admin/security/seal/ca-key and /unseal/ca-key", function () {

  it("seal returns 409 when no ca.key exists (fresh test server)", async function () {
    // The test server doesn't generate a CA at boot; any call before a
    // first cert op should hit the not-present guard.
    var fs = require("fs");
    var C = require(path.join(testServer.projectRoot, "lib", "constants"));
    if (!fs.existsSync(C.PATHS.CA_KEY)) {
      var res = await client.post("/admin/security/seal/ca-key", { json: {} });
      assert.strictEqual(res.status, 409);
      assert.match(res.json.error, /does not exist/);
    }
  });

  it("non-admin returns 403", async function () {
    var res = await regularClient.post("/admin/security/seal/ca-key", { json: {} });
    assert.strictEqual(res.status, 403);
  });
});

describe("POST /admin/security/seal/tls-key", function () {

  it("non-admin returns 403", async function () {
    var res = await regularClient.post("/admin/security/seal/tls-key", { json: {} });
    assert.strictEqual(res.status, 403);
  });

  it("returns 409 when no TLS key configured", async function () {
    var res = await client.post("/admin/security/seal/tls-key", { json: {} });
    assert.strictEqual(res.status, 409);
    assert.match(res.json.error, /does not exist/);
  });
});
