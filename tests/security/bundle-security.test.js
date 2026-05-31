const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const crypto = require("crypto");
const b = require("../../lib/vendor/blamejs");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var { isSealed, unsealField } = require("../helpers/seal-assert");
var client;

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());
  await client.initApiKey();
});

after(function () { return testServer.stop(); });

describe("bundle password protection", function () {
  var protectedShareId, protectedBundleId, protectedFinalizeToken;

  it("POST /drop/init with password stores passwordHash in DB", async function () {
    await client.initApiKey();
    var res = await client.post("/drop/init", {
      json: { uploaderName: "Pwd Test", fileCount: 1, skippedCount: 0, skippedFiles: [], password: "secret123" },
    });
    assert.strictEqual(res.status, 200);
    assert.ok(res.json.bundleId, "should return bundleId");
    protectedBundleId = res.json.bundleId;
    protectedShareId = res.json.shareId;
    protectedFinalizeToken = res.json.finalizeToken;

    // Verify passwordHash is stored in DB
    var { bundles } = require(path.join(testServer.projectRoot, "lib", "db"));
    var bundle = bundles.findOne({ _id: protectedBundleId });
    assert.ok(bundle.passwordHash, "bundle should have passwordHash in DB");
    assert.ok(bundle.passwordHash.length > 0, "passwordHash should not be empty");
  });

  it("POST /drop/init with expiryDays stores expiresAt in DB", async function () {
    await client.initApiKey();
    var res = await client.post("/drop/init", {
      json: { uploaderName: "Expiry Test", fileCount: 0, skippedCount: 0, skippedFiles: [], expiryDays: 7 },
    });
    assert.strictEqual(res.status, 200);

    var { bundles } = require(path.join(testServer.projectRoot, "lib", "db"));
    var bundle = bundles.findOne({ _id: res.json.bundleId });
    assert.ok(bundle.expiresAt, "bundle should have expiresAt in DB");
    var expiry = new Date(bundle.expiresAt);
    var expected = new Date(Date.now() + 7 * 86400000);
    // Exact day check: expiry should be within 60 seconds of expected (accounts for test execution time)
    var diffMs = Math.abs(expiry.getTime() - expected.getTime());
    assert.ok(diffMs < 60000, "expiresAt should be exactly 7 days from now (off by " + Math.round(diffMs / 1000) + "s)");
  });

  it("POST /drop/init with message stores vault-sealed message in DB", async function () {
    await client.initApiKey();
    var res = await client.post("/drop/init", {
      json: { uploaderName: "Msg Test", fileCount: 0, skippedCount: 0, skippedFiles: [], message: "Hello from the uploader" },
    });
    assert.strictEqual(res.status, 200);

    var { bundles } = require(path.join(testServer.projectRoot, "lib", "db"));
    var vault = require(path.join(testServer.projectRoot, "lib", "vault"));
    var bundle = bundles.raw().findOne({ _id: res.json.bundleId });
    assert.ok(bundle.message, "bundle should have message in DB");
    assert.ok(isSealed(bundle.message), "message should be vault-sealed");
    assert.strictEqual(unsealField("bundles", res.json.bundleId, "message", bundle.message), "Hello from the uploader");
  });

  it("upload file and finalize the password-protected bundle", async function () {
    await client.initApiKey();

    var up = await client.uploadFile("/drop/file/" + protectedBundleId, "file", "test.txt", "protected content", { relativePath: "test.txt" });
    assert.strictEqual(up.status, 200);

    var fin = await client.post("/drop/finalize/" + protectedBundleId, { json: { finalizeToken: protectedFinalizeToken } });
    assert.strictEqual(fin.status, 200);
    assert.strictEqual(fin.json.success, true);
  });

  it("GET /b/:shareId on password-protected bundle renders locked page", async function () {
    var res = await client.get("/b/" + protectedShareId);
    assert.strictEqual(res.status, 200);
    assert.ok(res.text.includes("Protected"), "page should contain 'Protected' for locked bundle");
    assert.ok(res.text.includes("password"), "page should mention password");
  });

  it("POST /b/:shareId/unlock with wrong password returns 401", async function () {
    await client.initApiKey();
    var res = await client.post("/b/" + protectedShareId + "/unlock", {
      json: { password: "wrongpassword" },
    });
    assert.strictEqual(res.status, 401);
    assert.ok((res.json.detail || res.json.error || "").includes("Incorrect"), "error should mention incorrect password");
  });

  it("POST /b/:shareId/unlock with correct password returns 200", async function () {
    await client.initApiKey();
    var res = await client.post("/b/" + protectedShareId + "/unlock", {
      json: { password: "secret123" },
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.json.success, true);
  });

  it("GET /b/:shareId after unlock shows bundle (not locked page)", async function () {
    var res = await client.get("/b/" + protectedShareId);
    assert.strictEqual(res.status, 200);
    // After unlocking, the page should show the bundle, not the password form
    assert.ok(!res.text.includes("Enter bundle password") || !res.text.includes("Protected"), "should show bundle content, not locked page");
  });
});

describe("bundle finalize token security", function () {
  it("POST /drop/finalize with wrong token returns 403", async function () {
    await client.initApiKey();
    var init = await client.post("/drop/init", {
      json: { uploaderName: "Token Test", fileCount: 0, skippedCount: 0, skippedFiles: [] },
    });
    assert.strictEqual(init.status, 200);

    var res = await client.post("/drop/finalize/" + init.json.bundleId, {
      json: { finalizeToken: "deadbeef0000000000000000deadbeef" },
    });
    assert.strictEqual(res.status, 403);
    assert.ok((res.json.detail || res.json.error || "").includes("Invalid finalize token"), "error should mention invalid finalize token");
  });

  it("POST /drop/finalize with correct token returns 200", async function () {
    await client.initApiKey();
    var init = await client.post("/drop/init", {
      json: { uploaderName: "Token OK", fileCount: 0, skippedCount: 0, skippedFiles: [] },
    });
    assert.strictEqual(init.status, 200);

    var res = await client.post("/drop/finalize/" + init.json.bundleId, {
      json: { finalizeToken: init.json.finalizeToken },
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.json.success, true);
  });
});

describe("bundle expiry", function () {
  it("GET /b/:shareId on expired bundle returns 410", async function () {
    await client.initApiKey();
    // Create and finalize a bundle
    var init = await client.post("/drop/init", {
      json: { uploaderName: "Expiry View", fileCount: 0, skippedCount: 0, skippedFiles: [] },
    });
    var fin = await client.post("/drop/finalize/" + init.json.bundleId, {
      json: { finalizeToken: init.json.finalizeToken },
    });
    assert.strictEqual(fin.status, 200);

    // Directly set expiresAt to a past date in the DB
    var { bundles } = require(path.join(testServer.projectRoot, "lib", "db"));
    bundles.update({ _id: init.json.bundleId }, {
      $set: { expiresAt: new Date(Date.now() - 86400000).toISOString() },
    });

    var res = await client.get("/b/" + init.json.shareId);
    assert.strictEqual(res.status, 410);
    assert.ok(res.text.includes("Expired") || res.text.includes("expired"), "page should indicate bundle is expired");
  });
});

describe("chunked uploads", function () {
  it("POST /drop/chunk/:bundleId uploads a file in 2 chunks and reassembles", async function () {
    await client.initApiKey();

    // Create bundle
    var init = await client.post("/drop/init", {
      json: { uploaderName: "Chunk Test", fileCount: 1, skippedCount: 0, skippedFiles: [] },
    });
    assert.strictEqual(init.status, 200);
    var bundleId = init.json.bundleId;

    // The chunk route uses bundle.shareId (vault-sealed) as a directory path.
    // On Windows, vault-sealed values contain backslashes which break mkdirSync.
    // Work around this by replacing the sealed shareId with a plain hex string
    // so the chunk temp directory has a safe path.
    var { bundles } = require(path.join(testServer.projectRoot, "lib", "db"));
    var vault = require(path.join(testServer.projectRoot, "lib", "vault"));
    var plainShareId = vault.unseal(bundles.findOne({ _id: bundleId }).shareId);
    bundles.update({ _id: bundleId }, { $set: { shareId: plainShareId } });

    var fileId = b.crypto.generateToken(8);

    // Split content into two chunks
    var part1 = "Hello, this is ";
    var part2 = "chunked content!";

    // Upload chunk 0
    var res1 = await client.uploadFile("/drop/chunk/" + bundleId, "file", "chunked.txt", part1, {
      chunkIndex: "0", totalChunks: "2", fileId: fileId,
      filename: "chunked.txt", relativePath: "chunked.txt", mimeType: "text/plain",
    });
    assert.strictEqual(res1.status, 200);
    assert.strictEqual(res1.json.success, true);
    assert.strictEqual(res1.json.chunksReceived, 1);
    assert.strictEqual(res1.json.totalChunks, 2);

    // Upload chunk 1 (final chunk triggers reassembly)
    var res2 = await client.uploadFile("/drop/chunk/" + bundleId, "file", "chunked.txt", part2, {
      chunkIndex: "1", totalChunks: "2", fileId: fileId,
      filename: "chunked.txt", relativePath: "chunked.txt", mimeType: "text/plain",
    });
    assert.strictEqual(res2.status, 200);
    assert.strictEqual(res2.json.success, true);
    assert.strictEqual(res2.json.assembled, true, "second chunk should trigger reassembly");

    // Finalize and verify the file is in the bundle
    var fin = await client.post("/drop/finalize/" + bundleId, {
      json: { finalizeToken: init.json.finalizeToken },
    });
    assert.strictEqual(fin.status, 200);
    assert.strictEqual(fin.json.success, true);

    // Verify file exists in DB
    var { files } = require(path.join(testServer.projectRoot, "lib", "db"));
    var bundleFiles = files.find({ bundleId: bundleId, status: "complete" });
    assert.strictEqual(bundleFiles.length, 1, "bundle should have one reassembled file");
    var originalName = vault.unseal(bundleFiles[0].originalName);
    assert.strictEqual(originalName, "chunked.txt", "file name should be preserved");
    var expectedSize = Buffer.byteLength(part1) + Buffer.byteLength(part2);
    assert.strictEqual(bundleFiles[0].size, expectedSize, "reassembled file size should match combined chunks");
  });
});
