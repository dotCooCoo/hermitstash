"use strict";

/**
 * Finalizing somebody else's bundle.
 *
 * POST /drop/finalize/:bundleId takes a bundle id from the path and a token
 * from the body, and it is reachable without signing in — that is the point of
 * the public drop portal. Two checks keep one uploader out of another's bundle:
 * a bundle with an owner may only be finalized by that owner, and a bundle that
 * belongs to a stash must go through the stash's own endpoint, where the stash's
 * gate applies.
 *
 * Finalizing is not a read. It closes the bundle, sends the uploader
 * confirmation, and fires the webhooks — so reaching it on someone else's
 * bundle publishes their upload and notifies their recipients, on their behalf.
 *
 * The ownership check had no test.
 */

var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var owner, other, anon;
var db;

// Each client is its own session, which is what makes "a different user" real
// rather than simulated.
async function newClient() {
  var c = new TestClient(testServer.baseUrl());
  c.clearCookies();
  await c.initApiKey();
  return c;
}

async function startBundle(client, name) {
  var init = await client.post("/drop/init", {
    json: { uploaderName: name, fileCount: 1, skippedCount: 0, skippedFiles: [] },
  });
  assert.strictEqual(init.status, 200, "precondition: the bundle starts");
  await client.uploadFile("/drop/file/" + init.json.bundleId, "file", name + ".txt",
    name + " bytes", { relativePath: name + ".txt" });
  return init.json;   // { bundleId, shareId, finalizeToken }
}

before(async function () {
  await testServer.start();
  db = require(path.join(testServer.projectRoot, "lib", "db"));

  owner = await newClient();
  await owner.post("/auth/register", {
    json: { displayName: "Bundle Owner", email: "dropowner@test.com", password: "password123" },
  });

  other = await newClient();
  await other.post("/auth/register", {
    json: { displayName: "Someone Else", email: "dropother@test.com", password: "password123" },
  });

  anon = await newClient();
});
after(function () { return testServer.stop(); });

describe("finalizing a bundle that belongs to somebody", function () {
  it("refuses a different signed-in user, even with the right token", async function () {
    // The token is not the authorisation. Holding it — from a shared link, a
    // log, a leaked response — must not be enough to close another account's
    // bundle and notify their recipients.
    var b = await startBundle(owner, "owned");
    var res = await other.post("/drop/finalize/" + b.bundleId, {
      json: { finalizeToken: b.finalizeToken },
    });
    assert.strictEqual(res.status, 403);
    assert.match(String(res.json.detail || res.json.error || ""), /forbidden/i);
  });

  it("refuses an anonymous caller", async function () {
    var b = await startBundle(owner, "owned2");
    var res = await anon.post("/drop/finalize/" + b.bundleId, {
      json: { finalizeToken: b.finalizeToken },
    });
    assert.strictEqual(res.status, 403);
  });

  it("lets the owner finalize their own", async function () {
    // The control. Refusing everyone would satisfy both cases above.
    var b = await startBundle(owner, "owned3");
    var res = await owner.post("/drop/finalize/" + b.bundleId, {
      json: { finalizeToken: b.finalizeToken },
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.json.success, true);
  });
});

describe("finalizing an unowned bundle", function () {
  it("is allowed for the anonymous uploader who started it", async function () {
    // A public drop has no owner; the token is what proves you started it.
    var b = await startBundle(anon, "anonymous");
    var res = await anon.post("/drop/finalize/" + b.bundleId, {
      json: { finalizeToken: b.finalizeToken },
    });
    assert.strictEqual(res.status, 200);
  });

  it("still refuses a wrong token", async function () {
    var b = await startBundle(anon, "anonymous2");
    var res = await anon.post("/drop/finalize/" + b.bundleId, {
      json: { finalizeToken: "not-the-token" },
    });
    assert.notStrictEqual(res.status, 200, "the token still has to match");
  });
});

describe("finalizing a stash bundle through the public route", function () {
  it("is refused and points at the stash endpoint", async function () {
    // A stash bundle carries the stash's own gate — password, email allow-list,
    // expiry. Closing it through the public route would step around all of it.
    var b = await startBundle(anon, "stashbound");
    var row = db.bundles.findOne({ _id: b.bundleId });
    assert.ok(row, "precondition: the bundle row exists");
    db.bundles.update({ _id: row._id }, { $set: { stashId: "some-stash-id" } });

    var res = await anon.post("/drop/finalize/" + b.bundleId, {
      json: { finalizeToken: b.finalizeToken },
    });
    assert.strictEqual(res.status, 403);
    assert.match(String(res.json.detail || res.json.error || ""), /stash endpoint/i);
  });
});

describe("finalizing a bundle that is already complete", function () {
  it("returns the share link only to a caller that sends the finalize token", async function () {
    // A bundle ID is written to audit events and to sync connection log lines,
    // so the bundle ID alone must not return the share link.
    var b = await startBundle(anon, "repeat");
    var first = await anon.post("/drop/finalize/" + b.bundleId, {
      json: { finalizeToken: b.finalizeToken },
    });
    assert.strictEqual(first.status, 200, "precondition: the first finalize succeeds");

    var withoutToken = await other.post("/drop/finalize/" + b.bundleId, { json: {} });
    assert.strictEqual(withoutToken.status, 404);
    assert.strictEqual((withoutToken.json || {}).shareId, undefined, "the refusal carries no share ID");
    var unknown = await other.post("/drop/finalize/" + "a".repeat(64), { json: {} });
    assert.strictEqual(unknown.status, 404, "precondition: an unknown bundle is a 404");
    assert.strictEqual(withoutToken.json.type, unknown.json.type, "the refusal has the problem type of an unknown bundle");
    assert.strictEqual(withoutToken.json.title, unknown.json.title, "the refusal has the title of an unknown bundle");

    var wrongToken = await other.post("/drop/finalize/" + b.bundleId, {
      json: { finalizeToken: "f".repeat(64) },
    });
    assert.strictEqual(wrongToken.status, 404);

    var retry = await anon.post("/drop/finalize/" + b.bundleId, {
      json: { finalizeToken: b.finalizeToken },
    });
    assert.strictEqual(retry.status, 200, "a retry with the finalize token still gets the link");
    assert.strictEqual(retry.json.shareId, b.shareId);
  });
});

describe("an API key bound to a stash on the drop routes", function () {
  // A stash sync key carries the userId of the admin who issued it. On the drop
  // routes it reaches only bundles of its own stash, not the admin's own.
  var keyClient;
  var syncBundleId;
  var snapshot;

  before(async function () {
    var created = await owner.post("/admin/stash/create", { json: { slug: "dropbind", name: "Drop Bind", title: "Drop Bind" } });
    assert.strictEqual(created.status, 200, "precondition: the stash is created: " + created.text);
    var stashId = created.json.stash._id;
    var issued = await owner.post("/admin/stash/" + stashId + "/sync-token", { json: {} });
    assert.strictEqual(issued.status, 200, "precondition: the sync token is issued: " + issued.text);
    var record = db.enrollmentCodes.find({}).filter(function (r) { return r.stashId === stashId; })[0];
    assert.ok(record && record.apiKey, "precondition: the enrollment record holds the key");
    keyClient = new TestClient(testServer.baseUrl());
    await keyClient.bearer(record.apiKey);

    var syncInit = await owner.post("/drop/init", {
      json: { uploaderName: "bind", bundleType: "sync", fileCount: 0, skippedCount: 0, skippedFiles: [] },
    });
    assert.strictEqual(syncInit.status, 200, "precondition: the admin's sync bundle starts");
    syncBundleId = syncInit.json.bundleId;
    snapshot = await startBundle(owner, "bind-snapshot");
    var fin = await owner.post("/drop/finalize/" + snapshot.bundleId, { json: { finalizeToken: snapshot.finalizeToken } });
    assert.strictEqual(fin.status, 200, "precondition: the admin's snapshot is finalized");
  });

  it("starts no bundle on POST /drop/init", async function () {
    var res = await keyClient.post("/drop/init", {
      json: { uploaderName: "bind-key", fileCount: 1, skippedCount: 0, skippedFiles: [] },
    });
    assert.strictEqual(res.status, 403);
  });

  it("cannot upload into the issuing admin's own sync bundle", async function () {
    var res = await keyClient.uploadFile("/drop/file/" + syncBundleId, "file", "notes.txt",
      "from the stash key", { relativePath: "notes.txt" });
    assert.strictEqual(res.status, 403);
  });

  it("cannot send a chunk to the issuing admin's own sync bundle", async function () {
    var res = await keyClient.post("/drop/chunk/" + syncBundleId, { json: {} });
    assert.strictEqual(res.status, 403);
  });

  it("does not get the share link of the issuing admin's completed bundle", async function () {
    var res = await keyClient.post("/drop/finalize/" + snapshot.bundleId, { json: {} });
    assert.strictEqual(res.status, 403);
    assert.strictEqual((res.json || {}).shareId, undefined, "the refusal carries no share ID");
  });
});

describe("sync bundles without an owner", function () {
  it("cannot be started by an anonymous caller", async function () {
    var res = await anon.post("/drop/init", {
      json: { uploaderName: "anon-sync", bundleType: "sync", fileCount: 1, skippedCount: 0, skippedFiles: [] },
    });
    assert.strictEqual(res.status, 403);
  });

  it("accept no writes when one already exists", async function () {
    var b = await startBundle(anon, "ownerless-sync");
    db.bundles.update({ _id: b.bundleId }, { $set: { bundleType: "sync", status: "complete" } });
    var res = await anon.uploadFile("/drop/file/" + b.bundleId, "file", "replaced.txt",
      "replaced bytes", { relativePath: "ownerless-sync.txt" });
    assert.strictEqual(res.status, 404);
  });

  it("still accept writes from the owner of an owned sync bundle", async function () {
    // The control: the check applies only to a sync bundle with no owner.
    var b = await startBundle(owner, "owned-sync");
    db.bundles.update({ _id: b.bundleId }, { $set: { bundleType: "sync", status: "complete" } });
    var res = await owner.uploadFile("/drop/file/" + b.bundleId, "file", "owned-sync.txt",
      "updated bytes", { relativePath: "owned-sync.txt" });
    assert.strictEqual(res.status, 200);
  });
});
