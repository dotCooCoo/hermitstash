const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var { isSealed, unsealField } = require("../helpers/seal-assert");
var client;

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());
});

after(function () { return testServer.stop(); });

describe("drop integration", function () {
  var bundleId, bundleShareId, bundleFinalizeToken;

  it("GET /drop returns 200", async function () {
    var res = await client.get("/drop");
    assert.strictEqual(res.status, 200);
  });

  it("POST /drop/init creates a bundle with sealed PII", async function () {
    await client.initApiKey();
    var res = await client.post("/drop/init", {
      json: { uploaderName: "Tester", uploaderEmail: "tester@test.com", fileCount: 2, skippedCount: 0, skippedFiles: [] },
    });
    assert.strictEqual(res.status, 200);
    assert.ok(res.json.bundleId);
    assert.ok(res.json.shareId);
    bundleId = res.json.bundleId;
    bundleShareId = res.json.shareId;
    bundleFinalizeToken = res.json.finalizeToken;

    // Verify PII is sealed in DB (use .raw() to bypass auto-unseal)
    var vault = require(path.join(testServer.projectRoot, "lib", "vault"));
    var { bundles } = require(path.join(testServer.projectRoot, "lib", "db"));
    var bundle = bundles.raw().findOne({ _id: bundleId });
    assert.ok(isSealed(bundle.uploaderName), "uploaderName should be sealed");
    assert.ok(isSealed(bundle.uploaderEmail), "uploaderEmail should be sealed");
    assert.ok(bundle.emailHash, "emailHash should exist");
    assert.ok(bundle.emailHash.length > 50, "emailHash should be SHA3 hash");
    assert.strictEqual(unsealField("bundles", bundle._id, "uploaderName", bundle.uploaderName), "Tester");
    assert.strictEqual(unsealField("bundles", bundle._id, "uploaderEmail", bundle.uploaderEmail), "tester@test.com");
  });

  it("POST /drop/file uploads a file with sealed metadata", async function () {
    var res = await client.uploadFile(
      "/drop/file/" + bundleId, "file", "test.txt",
      "Hello world content", { relativePath: "folder/test.txt" }
    );
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.json.success, true);
    assert.strictEqual(res.json.received, 1);

    // Verify file metadata is sealed in DB. Resolve the row by bundleShareId
    // (field-crypto translates that to the keyed blind index), then read it raw
    // to bypass auto-unseal for the sealing assertions.
    var { files } = require(path.join(testServer.projectRoot, "lib", "db"));
    var unsealed = files.find({ bundleShareId: bundleShareId });
    assert.ok(unsealed.length >= 1);
    var f = files.raw().findOne({ _id: unsealed[0]._id });
    assert.ok(isSealed(f.originalName), "originalName should be sealed");
    assert.ok(isSealed(f.relativePath), "relativePath should be sealed");
    assert.ok(isSealed(f.storagePath), "storagePath should be sealed");
    assert.ok(isSealed(f.mimeType), "mimeType should be sealed");
    assert.ok(isSealed(f.uploaderEmail), "uploaderEmail should be sealed");
    assert.strictEqual(unsealField("files", f._id, "originalName", f.originalName), "test.txt");
    assert.strictEqual(unsealField("files", f._id, "relativePath", f.relativePath), "folder/test.txt");
  });

  it("POST /drop/file uploads a second file", async function () {
    var res = await client.uploadFile(
      "/drop/file/" + bundleId, "file", "readme.txt",
      "README contents", { relativePath: "readme.txt" }
    );
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.json.received, 2);
  });

  it("rejects blocked extension", async function () {
    var res = await client.uploadFile(
      "/drop/file/" + bundleId, "file", "virus.exe",
      "bad content", { relativePath: "virus.exe" }
    );
    assert.strictEqual(res.status, 400);
    assert.ok((res.json.detail || res.json.error || "").includes("not allowed"));
  });

  it("POST /drop/finalize completes the bundle", async function () {
    var res = await client.post("/drop/finalize/" + bundleId, { json: { finalizeToken: bundleFinalizeToken } });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.json.success, true);
    assert.ok(res.json.shareUrl.includes("/b/"));
  });

  it("GET /b/:shareId shows bundle page with unsealed names", async function () {
    var res = await client.get("/b/" + bundleShareId);
    assert.strictEqual(res.status, 200);
    // File names should be unsealed for display
    assert.ok(res.text.includes("test.txt"), "unsealed file name should appear");
    assert.ok(res.text.includes("readme.txt"), "unsealed file name should appear");
  });

  it("GET /b/:shareId/download returns ZIP", async function () {
    var res = await client.get("/b/" + bundleShareId + "/download");
    assert.strictEqual(res.status, 200);
    assert.ok(res.headers["content-type"].includes("zip"));
  });

  it("returns error page for nonexistent bundle", async function () {
    var res = await client.get("/b/nonexistent");
    assert.strictEqual(res.status, 404);
  });
});

describe("drop integration — Bearer + blamejs apiEncrypt", function () {
  // Mirrors the production sync-client wire format. Without this case
  // the integration suite would only exercise legacy api-encrypt; a
  // class of browser-upload regressions can slip through when
  // tests/helpers/test-server.js wires only the legacy middleware and
  // no client here produces the blamejs envelope. Keep this case alive
  // — if it stops exercising the blamejs gate, the divergence has
  // re-emerged.
  it("POST /drop/init with Bearer auth goes through blamejs apiEncrypt", async function () {
    var b = require(path.join(testServer.projectRoot, "lib", "vendor", "blamejs"));
    var apiKeysRepo = require(path.join(testServer.projectRoot, "app", "data", "repositories", "apiKeys.repo"));
    var usersRepo = require(path.join(testServer.projectRoot, "app", "data", "repositories", "users.repo"));
    // api-auth only sets req.apiKey when the key resolves to an active
    // user (middleware/api-auth.js). Mirror the production-shape sync
    // setup: user → user-bound API key with upload scope.
    var user = usersRepo.create({
      email:       "bearer-owner@test.com",
      displayName: "Bearer Owner",
      authType:    "local",
      status:      "active",
      role:        "user",
      createdAt:   new Date().toISOString(),
    });
    var rawKey = "hs_" + b.crypto.generateToken(32);
    apiKeysRepo.create({
      name:        "test-bearer",
      keyHash:     b.crypto.sha3Hash(rawKey),
      prefix:      rawKey.substring(0, 7),
      permissions: "upload",
      userId:      user._id,
      createdAt:   new Date().toISOString(),
    });

    var bearerClient = await new TestClient(testServer.baseUrl()).bearer(rawKey);
    var res = await bearerClient.post("/drop/init", {
      json: { uploaderName: "BearerTester", uploaderEmail: "bearer@test.com", fileCount: 1, skippedCount: 0, skippedFiles: [] },
    });
    assert.strictEqual(res.status, 200, "blamejs envelope accepted, got " + res.status + " body=" + res.text);
    assert.ok(res.json && res.json.bundleId, "decrypted blamejs response carries bundleId");
    assert.ok(res.json.shareId, "decrypted blamejs response carries shareId");
    assert.ok(res.json.finalizeToken, "decrypted blamejs response carries finalizeToken");
  });
});

describe("drop + claim flow", function () {
  it("files claimed on registration via emailHash", async function () {
    await client.initApiKey();
    var init = await client.post("/drop/init", {
      json: { uploaderName: "Claimer", uploaderEmail: "claimer@test.com", fileCount: 1, skippedCount: 0, skippedFiles: [] },
    });
    await client.uploadFile("/drop/file/" + init.json.bundleId, "file", "claim.txt", "claim content", { relativePath: "claim.txt" });
    await client.post("/drop/finalize/" + init.json.bundleId, { json: { finalizeToken: init.json.finalizeToken } });

    // Register with that email — files should be claimed via emailHash
    client.clearCookies();
    await client.initApiKey();
    var reg = await client.post("/auth/register", {
      json: { displayName: "Claimer", email: "claimer@test.com", password: "password123" },
    });
    assert.strictEqual(reg.json.success, true);
    assert.ok(reg.json.claimed >= 1, "should claim at least 1 file via emailHash");
  });
});
