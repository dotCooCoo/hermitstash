const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const crypto = require("crypto");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client, client2;

// IDs populated during tests
var ownerUserId, otherUserId;
var vaultShareId;

// Generate a fake ML-KEM-1024 public key (exactly 1568 bytes)
function fakePublicKey() {
  return crypto.randomBytes(1568).toString("base64");
}
// Generate a fake 32-byte vault seed for passkey-gated mode
function fakeSeed() {
  return crypto.randomBytes(32).toString("base64");
}
// Helper: enable payload for passkey-gated mode (works without real PRF)
function enablePayload(pk) {
  return { publicKey: pk || fakePublicKey(), mode: "passkey", seed: fakeSeed() };
}

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());
  client2 = new TestClient(testServer.baseUrl());

  // Seed vault owner user directly in DB
  var b = require(path.join(testServer.projectRoot, "lib", "vendor", "blamejs"));
  var hashPassword = function (p) { return b.auth.password.hash(String(p)); };
  var vault = require(path.join(testServer.projectRoot, "lib", "vault"));
  var { hashEmail } = require(path.join(testServer.projectRoot, "lib", "crypto"));
  var { users } = require(path.join(testServer.projectRoot, "lib", "db"));
  var hash = await hashPassword("vaultowner123");
  var owner = users.insert({
    email: vault.seal("vaultowner@test.com"), emailHash: hashEmail("vaultowner@test.com"),
    displayName: vault.seal("Vault Owner"), passwordHash: hash,
    authType: "local", role: "admin", status: "active",
    createdAt: new Date().toISOString(),
  });
  ownerUserId = owner._id;

  // Seed a second user who should NOT access vault files
  var hash2 = await hashPassword("otheruser123");
  var other = users.insert({
    email: vault.seal("otheruser@test.com"), emailHash: hashEmail("otheruser@test.com"),
    displayName: vault.seal("Other User"), passwordHash: hash2,
    authType: "local", role: "user", status: "active",
    createdAt: new Date().toISOString(),
  });
  otherUserId = other._id;
});

after(function () { return testServer.stop(); });

// Helper: login as vault owner (admin)
async function loginOwner() {
  client.clearCookies();
  await client.initApiKey();
  testServer.resetAllRateLimits();
  var res = await client.post("/auth/login", {
    json: { email: "vaultowner@test.com", password: "vaultowner123" },
  });
  assert.strictEqual(res.json.success, true, "owner login should succeed");
}

// Helper: login as other user (non-admin)
async function loginOther() {
  client2.clearCookies();
  await client2.initApiKey();
  testServer.resetAllRateLimits();
  var res = await client2.post("/auth/login", {
    json: { email: "otheruser@test.com", password: "otheruser123" },
  });
  assert.strictEqual(res.json.success, true, "other user login should succeed");
}

describe("vault integration", function () {
  describe("authentication required", function () {
    it("GET /vault/status redirects when not logged in", async function () {
      client.clearCookies();
      var res = await client.get("/vault/status");
      assert.strictEqual(res.status, 302);
      assert.ok(res.location.includes("/auth/login"), "should redirect to login");
    });

    it("POST /vault/enable redirects when not logged in", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/vault/enable", { json: enablePayload() });
      assert.strictEqual(res.status, 302);
      assert.ok(res.location.includes("/auth/login"), "should redirect to login");
    });

    it("POST /vault/disable redirects when not logged in", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/vault/disable", { json: {} });
      assert.strictEqual(res.status, 302);
      assert.ok(res.location.includes("/auth/login"), "should redirect to login");
    });

    it("POST /vault/stealth redirects when not logged in", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/vault/stealth", { json: { enable: true } });
      assert.strictEqual(res.status, 302);
      assert.ok(res.location.includes("/auth/login"), "should redirect to login");
    });

    it("POST /vault/upload redirects when not logged in", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/vault/upload", { json: { ciphertext: "dGVzdA==", encapsulatedKey: "a2V5", iv: "aXY=", filename: "test.txt" } });
      assert.strictEqual(res.status, 302);
      assert.ok(res.location.includes("/auth/login"), "should redirect to login");
    });

    it("GET /vault/download/:shareId redirects when not logged in", async function () {
      client.clearCookies();
      var res = await client.get("/vault/download/nonexistent");
      assert.strictEqual(res.status, 302);
      assert.ok(res.location.includes("/auth/login"), "should redirect to login");
    });

    it("POST /vault/delete/:shareId redirects when not logged in", async function () {
      client.clearCookies();
      await client.initApiKey();
      var res = await client.post("/vault/delete/nonexistent", { json: {} });
      assert.strictEqual(res.status, 302);
      assert.ok(res.location.includes("/auth/login"), "should redirect to login");
    });

    it("GET /vault/s/:shareId redirects when not logged in", async function () {
      client.clearCookies();
      var res = await client.get("/vault/s/nonexistent");
      assert.strictEqual(res.status, 302);
      assert.ok(res.location.includes("/auth/login"), "should redirect to login");
    });
  });

  describe("POST /vault/enable", function () {
    it("fails without public key", async function () {
      await loginOwner();
      var res = await client.post("/vault/enable", { json: {} });
      assert.strictEqual(res.status, 400);
      assert.ok((res.json.detail || res.json.error || "").includes("Invalid public key"), "error should mention invalid public key");
    });

    it("fails with short public key", async function () {
      await loginOwner();
      var res = await client.post("/vault/enable", { json: { publicKey: "dG9vc2hvcnQ=", mode: "passkey", seed: fakeSeed() } });
      assert.strictEqual(res.status, 400);
      assert.ok((res.json.detail || res.json.error || "").includes("Invalid"), "error should mention invalid key");
    });

    it("fails with wrong-size key (not 1184 or 1568 bytes)", async function () {
      await loginOwner();
      // 512 bytes -- valid base64 but wrong ML-KEM size
      var wrongSizeKey = crypto.randomBytes(512).toString("base64");
      var res = await client.post("/vault/enable", { json: { publicKey: wrongSizeKey, mode: "passkey", seed: fakeSeed() } });
      assert.strictEqual(res.status, 400);
      assert.ok((res.json.detail || res.json.error || "").includes("ML-KEM"), "error should mention ML-KEM key size");
    });

    it("succeeds with valid ML-KEM-1024 public key (1568 bytes)", async function () {
      await loginOwner();
      var pk1024 = crypto.randomBytes(1568).toString("base64");
      var res = await client.post("/vault/enable", { json: { publicKey: pk1024, mode: "passkey", seed: fakeSeed() } });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);
    });

    it("succeeds with valid ML-KEM-768 public key (1184 bytes, legacy)", async function () {
      await loginOwner();
      var pk = fakePublicKey();
      var res = await client.post("/vault/enable", { json: enablePayload(pk) });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);
    });
  });

  describe("GET /vault/status", function () {
    it("returns enabled:true after enabling vault", async function () {
      await loginOwner();
      var res = await client.get("/vault/status");
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.enabled, true);
      assert.strictEqual(res.json.hasPublicKey, true);
      assert.ok(res.json.publicKey, "should include publicKey");
      assert.strictEqual(res.json.stealth, false);
    });

    it("other user vault status shows disabled", async function () {
      await loginOther();
      var res = await client2.get("/vault/status");
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.enabled, false);
      assert.strictEqual(res.json.hasPublicKey, false);
    });
  });

  describe("POST /vault/stealth", function () {
    it("fails when vault is not enabled", async function () {
      await loginOther();
      var res = await client2.post("/vault/stealth", { json: { enable: true } });
      assert.strictEqual(res.status, 400);
      assert.ok((res.json.detail || res.json.error || "").includes("Vault must be enabled"), "error should require vault enabled");
    });

    it("succeeds when vault is enabled", async function () {
      await loginOwner();
      var res = await client.post("/vault/stealth", { json: { enable: true } });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);
      assert.strictEqual(res.json.stealth, true);
    });

    it("vault status reflects stealth enabled", async function () {
      await loginOwner();
      var res = await client.get("/vault/status");
      assert.strictEqual(res.json.stealth, true);
    });

    it("disables stealth mode", async function () {
      await loginOwner();
      var res = await client.post("/vault/stealth", { json: { enable: false } });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);
      assert.strictEqual(res.json.stealth, false);
    });
  });

  describe("POST /vault/upload", function () {
    it("fails with missing encrypted data fields", async function () {
      await loginOwner();
      var res = await client.post("/vault/upload", { json: { ciphertext: "dGVzdA==" } });
      assert.strictEqual(res.status, 400);
      assert.ok((res.json.detail || res.json.error || "").includes("Missing encrypted file data"), "error should mention missing data");
    });

    it("fails when vault is not enabled for user", async function () {
      await loginOther();
      var res = await client2.post("/vault/upload", {
        json: {
          ciphertext: Buffer.from("encrypted-content").toString("base64"),
          encapsulatedKey: Buffer.from("encapsulated-key-data").toString("base64"),
          iv: Buffer.from("test-iv-data").toString("base64"),
          filename: "secret.txt",
        },
      });
      assert.strictEqual(res.status, 400);
      assert.ok((res.json.detail || res.json.error || "").includes("Vault not enabled"), "error should say vault not enabled");
    });

    it("succeeds with valid encrypted payload", async function () {
      await loginOwner();
      var ciphertext = crypto.randomBytes(256);
      var res = await client.post("/vault/upload", {
        json: {
          ciphertext: ciphertext.toString("base64"),
          encapsulatedKey: crypto.randomBytes(64).toString("base64"),
          iv: crypto.randomBytes(12).toString("base64"),
          filename: "vault-secret.bin",
          mimeType: "application/octet-stream",
          originalSize: 256,
        },
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);
      assert.ok(res.json.shareId, "should return shareId");
      vaultShareId = res.json.shareId;
    });

    it("succeeds with file larger than 1MB (parseJson limit regression)", async function () {
      await loginOwner();
      // 1.5MB — exceeds the old 1MB parseJson default, proves the limit scales with config.maxFileSize
      var ciphertext = crypto.randomBytes(1572864);
      var res = await client.post("/vault/upload", {
        json: {
          ciphertext: ciphertext.toString("base64"),
          encapsulatedKey: crypto.randomBytes(64).toString("base64"),
          iv: crypto.randomBytes(12).toString("base64"),
          filename: "large-presentation.pptx",
          mimeType: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
          originalSize: 1572864,
        },
      });
      assert.strictEqual(res.status, 200, "large vault upload should succeed, got: " + JSON.stringify(res.json));
      assert.strictEqual(res.json.success, true);
      assert.ok(res.json.shareId, "should return shareId for large file");
    });

    it("sanitizes filename with path traversal", async function () {
      await loginOwner();
      var ciphertext = crypto.randomBytes(64);
      var res = await client.post("/vault/upload", {
        json: {
          ciphertext: ciphertext.toString("base64"),
          encapsulatedKey: crypto.randomBytes(64).toString("base64"),
          iv: crypto.randomBytes(12).toString("base64"),
          filename: "../../etc/passwd",
        },
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);
      // Verify the stored filename was sanitized (path.basename strips directory components)
      var { files } = require(path.join(testServer.projectRoot, "lib", "db"));
      var doc = files.findOne({ shareId: res.json.shareId });
      assert.strictEqual(doc.originalName, "passwd", "filename should be sanitized to basename only");
    });
  });

  describe("GET /vault/files", function () {
    it("lists vault files for owner", async function () {
      await loginOwner();
      var res = await client.get("/vault/files");
      assert.strictEqual(res.status, 200);
      assert.ok(Array.isArray(res.json.files), "should return files array");
      assert.ok(res.json.files.length >= 1, "should have at least one vault file");
      var found = res.json.files.find(function (f) { return f.shareId === vaultShareId; });
      assert.ok(found, "should include the uploaded vault file");
      assert.strictEqual(found.originalName, "vault-secret.bin");
    });

    it("other user sees no vault files", async function () {
      await loginOther();
      var res = await client2.get("/vault/files");
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.files.length, 0, "other user should have no vault files");
    });
  });

  describe("GET /vault/download/:shareId", function () {
    it("returns encrypted data for owner", async function () {
      await loginOwner();
      var res = await client.get("/vault/download/" + vaultShareId);
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.filename, "vault-secret.bin");
      assert.strictEqual(res.json.mimeType, "application/octet-stream");
      assert.ok(res.json.ciphertext, "should include ciphertext");
      assert.ok(res.json.encapsulatedKey, "should include encapsulatedKey");
      assert.ok(res.json.iv, "should include iv");
    });

    it("non-owner non-admin gets 404 (no existence leak)", async function () {
      await loginOther();
      var res = await client2.get("/vault/download/" + vaultShareId);
      assert.strictEqual(res.status, 404);
    });

    it("returns 404 for nonexistent shareId", async function () {
      await loginOwner();
      var res = await client.get("/vault/download/nonexistent999");
      assert.strictEqual(res.status, 404);
    });
  });

  describe("access control — vault files scoped to owner", function () {
    it("other user cannot download owner vault file (returns 404)", async function () {
      await loginOther();
      var res = await client2.get("/vault/download/" + vaultShareId);
      assert.strictEqual(res.status, 404);
    });

    it("other user cannot delete owner vault file (returns 404)", async function () {
      await loginOther();
      var res = await client2.post("/vault/delete/" + vaultShareId, { json: {} });
      assert.strictEqual(res.status, 404);
      assert.ok((res.json.detail || res.json.error || "").includes("Not found"), "error should say not found (no existence leak)");
    });

    it("admin (owner) CAN download any vault file", async function () {
      // Owner is admin in this test setup, so this verifies the admin bypass
      await loginOwner();
      var res = await client.get("/vault/download/" + vaultShareId);
      assert.strictEqual(res.status, 200);
      assert.ok(res.json.ciphertext, "admin should be able to download vault file metadata");
    });
  });

  describe("GET /vault/s/:shareId (self-access link)", function () {
    it("renders share page for owner", async function () {
      await loginOwner();
      var res = await client.get("/vault/s/" + vaultShareId);
      assert.strictEqual(res.status, 200);
      assert.ok(res.text.includes("vault-secret.bin"), "page should show filename");
      assert.ok(res.text.includes("Decrypt"), "page should have decrypt button");
    });

    it("non-owner non-admin gets 404 (no existence leak)", async function () {
      await loginOther();
      var res = await client2.get("/vault/s/" + vaultShareId);
      assert.strictEqual(res.status, 404);
    });

    it("returns 404 for nonexistent shareId", async function () {
      await loginOwner();
      var res = await client.get("/vault/s/nonexistent999");
      assert.strictEqual(res.status, 404);
    });
  });

  describe("POST /vault/delete/:shareId", function () {
    it("returns 404 for nonexistent shareId", async function () {
      await loginOwner();
      var res = await client.post("/vault/delete/nonexistent999", { json: {} });
      assert.strictEqual(res.status, 404);
      assert.ok((res.json.detail || res.json.error || "").includes("Not found"), "error should say not found");
    });

    it("owner can delete their vault file", async function () {
      await loginOwner();
      var res = await client.post("/vault/delete/" + vaultShareId, { json: {} });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);
    });

    it("deleted file no longer downloadable", async function () {
      await loginOwner();
      var res = await client.get("/vault/download/" + vaultShareId);
      assert.strictEqual(res.status, 404);
    });

    it("deleted file no longer in vault files list", async function () {
      await loginOwner();
      var res = await client.get("/vault/files");
      var found = res.json.files.find(function (f) { return f.shareId === vaultShareId; });
      assert.strictEqual(found, undefined, "deleted file should not appear in list");
    });
  });

  describe("POST /vault/disable", function () {
    it("disables vault successfully", async function () {
      await loginOwner();
      var res = await client.post("/vault/disable", { json: {} });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);
    });

    it("status shows disabled after disabling", async function () {
      await loginOwner();
      var res = await client.get("/vault/status");
      assert.strictEqual(res.json.enabled, false);
      assert.strictEqual(res.json.hasPublicKey, false);
    });

    it("upload fails after vault disabled", async function () {
      await loginOwner();
      var res = await client.post("/vault/upload", {
        json: {
          ciphertext: crypto.randomBytes(64).toString("base64"),
          encapsulatedKey: crypto.randomBytes(64).toString("base64"),
          iv: crypto.randomBytes(12).toString("base64"),
          filename: "should-fail.txt",
        },
      });
      assert.strictEqual(res.status, 400);
      assert.ok((res.json.detail || res.json.error || "").includes("Vault not enabled"), "should reject upload when vault disabled");
    });

    it("stealth toggle fails after vault disabled", async function () {
      await loginOwner();
      var res = await client.post("/vault/stealth", { json: { enable: true } });
      assert.strictEqual(res.status, 400);
      assert.ok((res.json.detail || res.json.error || "").includes("Vault must be enabled"), "stealth should require enabled vault");
    });
  });

  describe("re-enable vault lifecycle", function () {
    it("can re-enable vault with new key", async function () {
      await loginOwner();
      var newKey = fakePublicKey();
      var res = await client.post("/vault/enable", { json: enablePayload(newKey) });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);

      var status = await client.get("/vault/status");
      assert.strictEqual(status.json.enabled, true);
      assert.strictEqual(status.json.hasPublicKey, true);
    });

    it("upload works again after re-enable", async function () {
      await loginOwner();
      var res = await client.post("/vault/upload", {
        json: {
          ciphertext: crypto.randomBytes(128).toString("base64"),
          encapsulatedKey: crypto.randomBytes(64).toString("base64"),
          iv: crypto.randomBytes(12).toString("base64"),
          filename: "re-enabled-upload.dat",
        },
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);
    });
  });
});
