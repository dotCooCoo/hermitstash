"use strict";

/**
 * The confirmation standing between an admin session and a factory reset.
 *
 * POST /admin/purge/database deletes every file from storage, every user but the
 * one making the request, and the contents of eleven tables. One check decides
 * whether that happens: the body must carry the exact string PURGE. Everything
 * after it is unconditional.
 *
 * Only the confirmed path had a test. A refusal is worth far more here, and it
 * has to be asserted on the DATA rather than on the status code — a 400 with the
 * deletion loop already run is the failure this is written to catch, and it
 * looks identical from the response.
 *
 * The other property is that the reset keeps the operator who asked for it. A
 * factory reset that removed the acting admin would leave an installation with
 * no way back in.
 */

var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;
var db;

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());
  db = require(path.join(testServer.projectRoot, "lib", "db"));
  var txHelper = require(path.join(testServer.projectRoot, "app", "data", "db", "transaction"));
  try { txHelper.init(db.getDb()); } catch (_e) { /* transactions unused by these cases */ }
});
after(function () { return testServer.stop(); });

async function registerAndLogin(name, email, password) {
  client.clearCookies();
  await client.initApiKey();
  await client.post("/auth/register", { json: { displayName: name, email: email, password: password } });
}

// Something the purge would visibly destroy.
function seed(tag) {
  db.bundles.insert({ shareId: "keep-" + tag, createdAt: new Date().toISOString() });
  db.files.insert({
    shareId: "keep-file-" + tag, originalName: tag + ".bin", size: 1,
    bundleShareId: "keep-" + tag, createdAt: new Date().toISOString(),
  });
}
function counts() {
  return { bundles: db.bundles.find({}).length, files: db.files.find({}).length };
}

describe("a database purge without the exact confirmation destroys nothing", function () {
  before(async function () {
    // First registered user is the admin.
    await registerAndLogin("Purge Admin", "purgeadmin@test.com", "password123");
  });

  // Each is a plausible thing to send, and none of them is the confirmation.
  var NOT_CONFIRMED = [
    ["an empty body", {}],
    ["a lowercase spelling", { confirm: "purge" }],
    ["mixed case", { confirm: "Purge" }],
    ["trailing whitespace", { confirm: "PURGE " }],
    ["a different word", { confirm: "YES" }],
    ["a boolean", { confirm: true }],
    ["a null", { confirm: null }],
    ["the word inside a sentence", { confirm: "I want to PURGE everything" }],
  ];

  NOT_CONFIRMED.forEach(function (pair, i) {
    it("case " + (i + 1) + " — " + pair[0] + " — is refused and leaves the data", async function () {
      seed("c" + i);
      var before_ = counts();
      assert.ok(before_.bundles > 0 && before_.files > 0, "precondition: there is something to lose");

      var res = await client.post("/admin/purge/database", { json: pair[1] });
      assert.strictEqual(res.status, 400, "the request must be refused");
      assert.match(String(res.json.detail || res.json.error || ""), /PURGE/,
        "and the refusal must say what to type");

      var after_ = counts();
      assert.strictEqual(after_.bundles, before_.bundles,
        "a refused purge must not have deleted bundles on its way to the 400");
      assert.strictEqual(after_.files, before_.files,
        "nor files");
    });
  });

  it("is refused for a signed-in non-admin, whatever they type", async function () {
    // The confirmation is not the only gate, and must not be reachable without
    // the role.
    await registerAndLogin("Ordinary", "ordinary-purge@test.com", "password123");
    seed("nonadmin");
    var before_ = counts();
    var res = await client.post("/admin/purge/database", { json: { confirm: "PURGE" } });
    assert.strictEqual(res.status, 403);
    assert.deepStrictEqual(counts(), before_, "and nothing was destroyed");
  });
});

describe("a confirmed purge keeps the operator who asked for it", function () {
  it("removes the data and leaves the acting admin able to sign in", async function () {
    // A factory reset that deleted the acting admin would leave the
    // installation with no way back in. Asserted last, because it is the case
    // that actually destroys the fixture data.
    client.clearCookies();
    await client.initApiKey();
    await client.post("/auth/login", { json: { email: "purgeadmin@test.com", password: "password123" } });

    seed("confirmed");
    assert.ok(counts().bundles > 0, "precondition: there is something to purge");

    var res = await client.post("/admin/purge/database", { json: { confirm: "PURGE" } });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.json.success, true);
    assert.strictEqual(counts().bundles, 0, "bundles are gone");
    assert.strictEqual(counts().files, 0, "files are gone");

    // The purge revokes every session including this one, so signing in again is
    // the check that the account survived.
    client.clearCookies();
    await client.initApiKey();
    var login = await client.post("/auth/login", {
      json: { email: "purgeadmin@test.com", password: "password123" },
    });
    assert.strictEqual(login.status, 200,
      "the admin who ran the reset must still be able to sign in");
  });
});
