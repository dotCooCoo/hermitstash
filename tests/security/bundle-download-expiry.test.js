"use strict";

/**
 * Expired content stops being downloadable.
 *
 * A time-limited share is the product's promise: the sender picks a window and
 * the link stops working after it. Three separate checks enforce that on the
 * download path — the file's own expiry, the parent bundle's expiry on a
 * single-file download, and the bundle's expiry on the whole-bundle download —
 * and none of them had a test. An expiry that quietly stopped being enforced
 * would look exactly like an expiry that works, right up until someone opened
 * an old link.
 *
 * Expiry is set directly on the stored rows rather than by waiting: the
 * comparison is against a timestamp, so a row stamped in the past is the same
 * input the passage of time produces, and the test does not have to sleep.
 *
 * Each case has a live control alongside it. A download path that refused
 * everything would satisfy the expiry assertions on its own.
 */

var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;
var db;

var live = {};      // an unexpired bundle + file, used as the control
var expiring = {};  // the one whose rows get stamped into the past

async function makeBundle(name) {
  var init = await client.post("/drop/init", {
    json: { uploaderName: name, fileCount: 1, skippedCount: 0, skippedFiles: [] },
  });
  await client.uploadFile("/drop/file/" + init.json.bundleId, "file", name + ".txt",
    name + " bytes", { relativePath: name + ".txt" });
  await client.post("/drop/finalize/" + init.json.bundleId, { json: { finalizeToken: init.json.finalizeToken } });
  var page = await client.get("/b/" + init.json.shareId);
  var m = page.text.match(/\/b\/[a-f0-9]+\/file\/([a-f0-9]+)/);
  assert.ok(m, "the bundle page must list its file so the download URL is known");
  return { shareId: init.json.shareId, bundleId: init.json.bundleId, fileShareId: m[1] };
}

var PAST = "2020-01-01T00:00:00.000Z";
var FUTURE = "2999-01-01T00:00:00.000Z";

function setBundleExpiry(shareId, when) {
  var row = db.bundles.findOne({ shareId: shareId });
  assert.ok(row, "bundle row must exist");
  db.bundles.update({ _id: row._id }, { $set: { expiresAt: when } });
}
function setFileExpiry(fileShareId, when) {
  var row = db.files.findOne({ shareId: fileShareId });
  assert.ok(row, "file row must exist");
  db.files.update({ _id: row._id }, { $set: { expiresAt: when } });
}

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());
  await client.initApiKey();
  db = require(path.join(testServer.projectRoot, "lib", "db"));

  live = await makeBundle("live");
  expiring = await makeBundle("expiring");
});
after(function () { return testServer.stop(); });

describe("a live share is downloadable", function () {
  it("serves the single file and the whole bundle", async function () {
    // The control. Every refusal below is only meaningful against this.
    var file = await client.get("/b/" + live.shareId + "/file/" + live.fileShareId);
    assert.strictEqual(file.status, 200, "an unexpired file must download");

    var all = await client.get("/b/" + live.shareId + "/download");
    assert.strictEqual(all.status, 200, "an unexpired bundle must download");
  });

  it("stays downloadable with an expiry set in the future", async function () {
    setBundleExpiry(live.shareId, FUTURE);
    setFileExpiry(live.fileShareId, FUTURE);
    assert.strictEqual((await client.get("/b/" + live.shareId + "/file/" + live.fileShareId)).status, 200);
    assert.strictEqual((await client.get("/b/" + live.shareId + "/download")).status, 200);
  });
});

describe("a file past its own expiry is gone", function () {
  it("answers 410 rather than serving the bytes", async function () {
    setFileExpiry(expiring.fileShareId, PAST);
    var res = await client.get("/b/" + expiring.shareId + "/file/" + expiring.fileShareId);
    assert.strictEqual(res.status, 410, "an expired file is gone, not merely forbidden");
    assert.match(String(res.text || ""), /expired/i);
    assert.strictEqual(/expiring bytes/.test(String(res.text || "")), false,
      "and none of the content may come back with the refusal");
  });

  it("the sibling live bundle is unaffected", async function () {
    assert.strictEqual((await client.get("/b/" + live.shareId + "/file/" + live.fileShareId)).status, 200,
      "one share expiring must not take another with it");
  });
});

describe("a file whose parent bundle expired is gone", function () {
  it("answers 410 on the single-file route even when the file itself has no expiry", async function () {
    // The window belongs to the bundle; a file row carrying no expiry of its own
    // must still stop being served when its parent's window closes.
    var b2 = await makeBundle("parentexpiry");
    setFileExpiry(b2.fileShareId, null);
    setBundleExpiry(b2.shareId, PAST);

    var res = await client.get("/b/" + b2.shareId + "/file/" + b2.fileShareId);
    assert.strictEqual(res.status, 410);
    assert.match(String(res.text || ""), /expired/i);
  });
});

describe("an expired bundle serves no archive", function () {
  it("answers 410 on the whole-bundle download", async function () {
    var b3 = await makeBundle("archiveexpiry");
    setBundleExpiry(b3.shareId, PAST);

    var res = await client.get("/b/" + b3.shareId + "/download");
    assert.strictEqual(res.status, 410, "the archive route enforces the same window");
    assert.match(String(res.text || ""), /expired/i);
  });

  it("and the file inside it is not reachable by its own URL either", async function () {
    // The archive route and the single-file route are separate handlers; closing
    // one is not closing the other.
    var b4 = await makeBundle("bothroutes");
    setBundleExpiry(b4.shareId, PAST);
    assert.strictEqual((await client.get("/b/" + b4.shareId + "/download")).status, 410);
    assert.strictEqual((await client.get("/b/" + b4.shareId + "/file/" + b4.fileShareId)).status, 410);
  });
});

describe("every route that serves a bundle closes on the same expiry", function () {
  // The gate is one function called from four handlers, which is what makes
  // this worth asserting as a set: the module comment says the policy must not
  // drift per-route, and a handler that lost its call would still leave the
  // other three passing.
  it("the browse page, the archive, a single file and a folder all refuse", async function () {
    var b5 = await makeBundle("everyroute");
    setBundleExpiry(b5.shareId, PAST);

    var page = await client.get("/b/" + b5.shareId);
    assert.strictEqual(page.status, 410, "the browse page");
    assert.match(String(page.text || ""), /expired/i);

    assert.strictEqual((await client.get("/b/" + b5.shareId + "/download")).status, 410, "the archive");
    assert.strictEqual((await client.get("/b/" + b5.shareId + "/file/" + b5.fileShareId)).status, 410,
      "a single file");
    assert.strictEqual((await client.get("/b/" + b5.shareId + "/folder?path=sub")).status, 410,
      "a folder archive");
  });

  it("and all four serve a bundle that has not expired", async function () {
    // The control for the set. Four routes refusing everything would satisfy
    // the case above on its own.
    assert.strictEqual((await client.get("/b/" + live.shareId)).status, 200, "the browse page");
    assert.strictEqual((await client.get("/b/" + live.shareId + "/download")).status, 200, "the archive");
    assert.strictEqual((await client.get("/b/" + live.shareId + "/file/" + live.fileShareId)).status, 200,
      "a single file");
    var folder = await client.get("/b/" + live.shareId + "/folder?path=sub");
    assert.notStrictEqual(folder.status, 410,
      "a folder request on a live bundle must not be refused as expired, whatever else it answers");
  });
});
