/**
 * Regression tests for the /sync/ws change-feed cluster of findings.
 *
 * Covered here:
 *   - Finding 8 — revoking an API key tears down its live /sync/ws sockets.
 *     The revoke route closes every socket in the shared sync registry that
 *     is bound to the revoked keyId (close 4401), so a hard-deleted credential
 *     can't keep receiving the bundle change-feed.
 *   - Finding 10 — the catch-up change-feed is PAGED. filesRepo
 *     .findBundleChangesSince(bundleId, since, limit) filters/orders/limits in
 *     SQL on the raw bundleId/seq columns and returns at most `limit` rows, so
 *     an attacker-controlled since=0 can't force the server to materialize +
 *     field-crypto-decrypt the whole bundle. Sealed columns (relativePath)
 *     come back decrypted.
 *
 * The /sync/ws upgrade handler itself lives in server-main.js (not mounted by
 * the route-level test harness), so finding 8 is exercised at its root cause —
 * the revoke route's registry teardown — by planting a fake socket in the
 * shared registry the production handler also writes to.
 */
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");

var client;
var db;
var filesRepo;
var syncRegistry;

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());
  db = require(path.join(testServer.projectRoot, "lib", "db"));
  filesRepo = require(path.join(testServer.projectRoot, "app", "data", "repositories", "files.repo"));
  syncRegistry = require(path.join(testServer.projectRoot, "lib", "sync-registry"));
});

after(function () { return testServer.stop(); });

async function registerAndLogin(name, email, password) {
  var rateLimit = require(path.join(testServer.projectRoot, "lib", "rate-limit"));
  rateLimit.resetAllInstances();
  client.clearCookies();
  await client.initApiKey();
  await client.post("/auth/register", { json: { displayName: name, email: email, password: password } });
  return client;
}

async function loginAs(email, password) {
  var rateLimit = require(path.join(testServer.projectRoot, "lib", "rate-limit"));
  rateLimit.resetAllInstances();
  client.clearCookies();
  await client.initApiKey();
  await client.post("/auth/login", { json: { email: email, password: password } });
  return client;
}

describe("sync ws change-feed cluster", function () {
  before(async function () {
    // First registered user is the admin.
    await registerAndLogin("Sync Admin", "syncadmin@test.com", "password123");
  });

  describe("finding 8 — revoke closes live sync sockets", function () {
    it("closes every registry socket bound to the revoked key with 4401", async function () {
      await loginAs("syncadmin@test.com", "password123");

      // Create a sync-scoped key.
      var createRes = await client.post("/admin/apikeys/create", {
        json: { name: "ws-revoke-key", permissions: "sync" },
      });
      assert.strictEqual(createRes.json.success, true, "key should be created");
      var prefix = createRes.json.prefix;

      // Resolve its _id from the admin listing.
      var listRes = await client.get("/admin/apikeys/api");
      var row = listRes.json.keys.find(function (k) { return k.prefix === prefix; });
      assert.ok(row, "created key should appear in the listing");
      var keyId = row._id;

      // Plant two fake live sockets in the shared registry the production
      // upgrade handler also writes to — one bound to this key, one to a
      // different key (the second must be left untouched).
      var closedThis = [];
      var otherClosed = false;
      var thisWs = { readyState: "open", close: function (code, reason) { closedThis.push({ code: code, reason: reason }); } };
      var otherWs = { readyState: "open", close: function () { otherClosed = true; } };

      var bundleId = "bundle-revoke-test";
      syncRegistry.syncConnections.set(bundleId, new Set([
        { ws: thisWs, apiKeyId: keyId },
        { ws: otherWs, apiKeyId: "some-other-key-id" },
      ]));

      try {
        var revokeRes = await client.post("/admin/apikeys/" + keyId + "/revoke", { json: {} });
        assert.strictEqual(revokeRes.json.success, true, "revoke should succeed");

        assert.strictEqual(closedThis.length, 1, "the revoked key's socket should be closed exactly once");
        assert.strictEqual(closedThis[0].code, 4401, "close code should be 4401");
        assert.strictEqual(otherClosed, false, "an unrelated key's socket must NOT be closed");

        // The key row must be gone (hard delete) AND the registry entry torn down.
        assert.strictEqual(db.apiKeys.findOne({ _id: keyId }), null, "revoked key row should be deleted");
      } finally {
        syncRegistry.syncConnections.delete(bundleId);
      }
    });
  });

  describe("finding 10 — catch-up is paged + bounded", function () {
    it("findBundleChangesSince caps the page, orders by seq, and unseals sealed columns", function () {
      var bundleId = "paged-bundle-" + Date.now();
      var total = 25;
      // Insert files out of seq order so we can prove SQL ordering, not insert order.
      var order = [];
      for (var i = total; i >= 1; i--) order.push(i);
      for (var j = 0; j < order.length; j++) {
        var seq = order[j];
        db.files.insert({
          bundleId: bundleId,
          shareId: "share-" + bundleId + "-" + seq,
          originalName: "f" + seq + ".txt",
          relativePath: "dir/f" + seq + ".txt",   // sealed column
          checksum: "sum-" + seq,                  // sealed column
          status: "complete",
          size: 10,
          seq: seq,
          createdAt: new Date().toISOString(),
        });
      }

      // since=0 with a small page must return only the page, not the whole bundle.
      var page = 10;
      var firstPage = filesRepo.findBundleChangesSince(bundleId, 0, page);
      assert.strictEqual(firstPage.length, page, "must return exactly one page, not every file");
      for (var p = 0; p < firstPage.length; p++) {
        assert.strictEqual(firstPage[p].seq, p + 1, "page must be ordered ascending by seq");
        // Sealed column round-trips through field-crypto on read.
        assert.strictEqual(firstPage[p].relativePath, "dir/f" + (p + 1) + ".txt", "sealed relativePath should be decrypted");
      }

      // Paging: advance `since` to the last seq seen → next page continues.
      var lastSeq = firstPage[firstPage.length - 1].seq;
      var secondPage = filesRepo.findBundleChangesSince(bundleId, lastSeq, page);
      assert.ok(secondPage.length > 0, "second page should have rows");
      assert.strictEqual(secondPage[0].seq, lastSeq + 1, "second page resumes strictly after `since`");
      for (var q = 0; q < secondPage.length; q++) {
        assert.ok(secondPage[q].seq > lastSeq, "every second-page row must have seq > since");
      }

      // A since at/above the max yields nothing (no over-read).
      var none = filesRepo.findBundleChangesSince(bundleId, total, page);
      assert.strictEqual(none.length, 0, "since >= max seq returns no rows");
    });
  });
});
