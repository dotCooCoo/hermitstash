"use strict";

/**
 * Two ways the bundle surface can hand out a file it should not.
 *
 * A file row can outlive its bundle. Access protection — the password, the
 * email gate, the expiry — all live on the PARENT, so a file whose parent is
 * gone has nothing left to evaluate. The single-file route used to read
 * `parentBundle && isBundleLocked(...)`, which short-circuits to false when the
 * parent is missing and serves the file with no protection at all. It now
 * refuses, and this holds that.
 *
 * The same page also answers JSON for API and sync clients. That branch returns
 * the whole manifest — every filename, size and per-file share id — so it has
 * to sit behind the same locks the HTML does. A client that asks for JSON must
 * not get a listing the browser is refused.
 */

var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;

var openShareId, openFileShareId, openBundleId;
var lockedShareId;

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());
  await client.initApiKey();

  // An open bundle with one file.
  var init = await client.post("/drop/init", {
    json: { uploaderName: "Orphan Tester", fileCount: 1, skippedCount: 0, skippedFiles: [] },
  });
  openShareId = init.json.shareId;
  openBundleId = init.json.bundleId;
  await client.uploadFile("/drop/file/" + openBundleId, "file", "keep.txt", "kept bytes", { relativePath: "keep.txt" });
  await client.post("/drop/finalize/" + openBundleId, { json: { finalizeToken: init.json.finalizeToken } });
  var page = await client.get("/b/" + openShareId);
  openFileShareId = page.text.match(/\/b\/[a-f0-9]+\/file\/([a-f0-9]+)/)[1];

  // A password-locked bundle with one file.
  var init2 = await client.post("/drop/init", {
    json: { uploaderName: "Locked Tester", fileCount: 1, skippedCount: 0, skippedFiles: [], password: "lockedpass123" },
  });
  lockedShareId = init2.json.shareId;
  await client.uploadFile("/drop/file/" + init2.json.bundleId, "file", "secret.txt", "secret bytes", { relativePath: "secret.txt" });
  await client.post("/drop/finalize/" + init2.json.bundleId, { json: { finalizeToken: init2.json.finalizeToken } });
});

after(function () { return testServer.stop(); });

describe("a file whose bundle is gone is not served", function () {
  it("refuses the file once its parent bundle has been removed", async function () {
    // Serve it once to prove the route works, then remove only the parent — the
    // file row stays, which is the state an orphan is in.
    var before = await client.get("/b/" + openShareId + "/file/" + openFileShareId);
    assert.strictEqual(before.status, 200, "precondition: the file serves while its bundle exists");

    var bundlesRepo = require(path.join(testServer.projectRoot, "app", "data", "repositories", "bundles.repo"));
    var filesRepo = require(path.join(testServer.projectRoot, "app", "data", "repositories", "files.repo"));
    bundlesRepo.remove(openBundleId);
    assert.ok(filesRepo.findCompleteByShareId(openFileShareId),
      "precondition: the file row outlives the bundle — that is what makes it an orphan");

    var after = await client.get("/b/" + openShareId + "/file/" + openFileShareId);
    assert.strictEqual(after.status, 404,
      "with no parent there is no protection to evaluate, so it must be refused rather than served");
    assert.ok(!/kept bytes/.test(after.text || ""), "and none of the content may come back");
  });
});

describe("the JSON view is behind the same locks as the page", function () {
  it("gives a locked bundle no manifest, whatever the client asks for", async function () {
    // The JSON branch returns every filename, size and per-file share id. A
    // client that asks for JSON must not receive a listing the browser is
    // refused — the per-file share ids alone are enough to fetch the contents.
    var res = await client.get("/b/" + lockedShareId, { headers: { Accept: "application/json" } });
    var body = res.text || "";
    assert.ok(!/secret\.txt/.test(body), "a locked bundle must not name its files: " + body.slice(0, 200));
    if (res.json && res.json.files) {
      assert.fail("a locked bundle returned a file manifest over JSON");
    }
  });

  it("gives an open bundle the manifest an API client needs", async function () {
    // The other half: the negotiation has to actually work, or a sync client
    // silently falls back to scraping HTML.
    var init = await client.post("/drop/init", {
      json: { uploaderName: "JSON Tester", fileCount: 1, skippedCount: 0, skippedFiles: [] },
    });
    await client.uploadFile("/drop/file/" + init.json.bundleId, "file", "open.txt", "open bytes", { relativePath: "open.txt" });
    await client.post("/drop/finalize/" + init.json.bundleId, { json: { finalizeToken: init.json.finalizeToken } });

    var res = await client.get("/b/" + init.json.shareId, { headers: { Accept: "application/json" } });
    assert.strictEqual(res.status, 200);
    assert.ok(res.json && Array.isArray(res.json.files), "an open bundle answers JSON with a file list");
    assert.strictEqual(res.json.fileCount, 1);
    assert.strictEqual(res.json.files[0].name, "open.txt");
    assert.ok(res.json.files[0].shareId, "each entry carries the id a client fetches with");
    assert.strictEqual(res.json.accessMode, "open");
  });
});
