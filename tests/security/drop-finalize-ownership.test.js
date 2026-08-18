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
