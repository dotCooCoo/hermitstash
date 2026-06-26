/**
 * API-key scope enforcement on mutate routes.
 *
 * Every API key is admin-minted, so api-auth attaches the admin creator as
 * req.user. Before this gate a key the operator labelled "upload" or "read"
 * for least privilege silently inherited the creator's blanket admin
 * ownership override and could rename/delete ANY user's files and bundles.
 *
 * Two layers are asserted here:
 *   1. requireScope("upload") on the mutate routes — a key without a mutate
 *      scope (e.g. "read") is rejected with 403 at the route boundary.
 *   2. canEditOwned no longer honors the admin ownership override for a
 *      non-admin-scoped API-key principal — an "upload" key may only act on
 *      resources IT owns, not on a victim user's resources via admin bypass.
 *      An interactive admin SESSION (no req.apiKey) keeps the override; an
 *      admin-SCOPED key keeps it too.
 *
 * Also asserts "webhook" is no longer a mintable scope (it was never enforced
 * anywhere — all /admin/webhooks routes are requireAdmin-gated).
 */
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var projectRoot = testServer.projectRoot;

var client;

before(async function () { await testServer.start(); client = new TestClient(testServer.baseUrl()); });
after(function () { return testServer.stop(); });

var testId = Date.now().toString(36);
var adminEmail = "admin-scope-" + testId + "@test.com";
var victimEmail = "victim-scope-" + testId + "@test.com";
var strongPassword = "Str0ng!Pass_" + testId;

function rateLimit() { return require(path.join(projectRoot, "lib", "rate-limit")); }

// Mint an API key with the given comma-separated permissions via the admin
// route. Returns the raw key string (shown once at creation).
async function mintKey(c, name, permissions) {
  var res = await c.post("/admin/apikeys/create", { json: { name: name, permissions: permissions } });
  assert.strictEqual(res.status, 200, "mint '" + permissions + "' key should succeed: " + res.text);
  assert.ok(res.json && res.json.key, "mint should return a raw key");
  return res.json.key;
}

describe("API-key scope enforcement on mutate routes", function () {
  var victimUserId;
  var adminUploadKey;   // upload-only key (admin-minted)
  var adminReadKey;     // read-only key (admin-minted)
  var adminScopedKey;   // admin-scoped key (admin-minted)

  before(async function () {
    var { users } = require(path.join(projectRoot, "lib", "db"));

    // First registered user becomes admin.
    client.clearCookies();
    await client.initApiKey();
    await client.post("/auth/register", { json: { displayName: "Admin", email: adminEmail, password: strongPassword } });

    // A distinct victim user who owns the target resources.
    var victim = users.insert({
      email: victimEmail, displayName: "Victim", passwordHash: "x",
      authType: "local", role: "user", status: "active",
      createdAt: new Date().toISOString(),
    });
    victimUserId = victim._id;

    // Login as admin and mint the three keys.
    rateLimit().resetAllInstances();
    client.clearCookies();
    await client.initApiKey();
    await client.post("/auth/login", { json: { email: adminEmail, password: strongPassword } });

    adminUploadKey = await mintKey(client, "upload-key-" + testId, "upload");
    adminReadKey = await mintKey(client, "read-key-" + testId, "read");
    adminScopedKey = await mintKey(client, "admin-key-" + testId, "admin");
  });

  // Insert a fresh bundle + file owned by the victim, returning their shareIds.
  function seedVictimBundle() {
    var bundlesRepo = require(path.join(projectRoot, "app", "data", "repositories", "bundles.repo"));
    var filesRepo = require(path.join(projectRoot, "app", "data", "repositories", "files.repo"));
    var b = require(path.join(projectRoot, "lib", "vendor", "blamejs"));
    var bundleShareId = "bsc" + b.crypto.generateToken(8);
    var fileShareId = "fsc" + b.crypto.generateToken(8);
    bundlesRepo.create({
      shareId: bundleShareId, ownerId: victimUserId, uploaderName: "Victim",
      bundleName: "victim-bundle", status: "complete", bundleType: "snapshot",
      totalSize: 0, createdAt: new Date().toISOString(),
    });
    filesRepo.create({
      shareId: fileShareId, bundleShareId: bundleShareId, uploadedBy: victimUserId,
      originalName: "victim.txt", status: "complete", size: 1,
      storagePath: "nonexistent/" + fileShareId, createdAt: new Date().toISOString(),
    });
    return { bundleShareId: bundleShareId, fileShareId: fileShareId };
  }

  it("read-only key is rejected (403) on bundle delete by requireScope", async function () {
    var seed = seedVictimBundle();
    var c = new TestClient(testServer.baseUrl());
    await c.bearer(adminReadKey);
    var res = await c.post("/bundles/" + seed.bundleShareId + "/delete", { json: {} });
    assert.strictEqual(res.status, 403, "read-only key must not delete a bundle: " + res.text);

    // The bundle is still present — the delete was refused before any work.
    var bundlesRepo = require(path.join(projectRoot, "app", "data", "repositories", "bundles.repo"));
    assert.ok(bundlesRepo.findByShareId(seed.bundleShareId), "bundle must survive a refused delete");
  });

  it("read-only key is rejected (403) on file delete by requireScope", async function () {
    var seed = seedVictimBundle();
    var c = new TestClient(testServer.baseUrl());
    await c.bearer(adminReadKey);
    var res = await c.post("/files/" + seed.fileShareId + "/delete", { json: {} });
    assert.strictEqual(res.status, 403, "read-only key must not delete a file: " + res.text);
  });

  it("read-only key is rejected (403) on bundle rename by requireScope", async function () {
    var seed = seedVictimBundle();
    var c = new TestClient(testServer.baseUrl());
    await c.bearer(adminReadKey);
    var res = await c.post("/bundles/" + seed.bundleShareId + "/rename", { json: { name: "hijacked" } });
    assert.strictEqual(res.status, 403, "read-only key must not rename a bundle: " + res.text);
  });

  it("upload-only key cannot delete a victim's bundle (admin override suppressed)", async function () {
    var seed = seedVictimBundle();
    var c = new TestClient(testServer.baseUrl());
    await c.bearer(adminUploadKey);
    // Passes requireScope("upload") but canEditOwned must NOT grant the
    // admin ownership override to a non-admin-scoped API-key principal.
    var res = await c.post("/bundles/" + seed.bundleShareId + "/delete", { json: {} });
    assert.strictEqual(res.status, 403, "upload key must not delete another user's bundle: " + res.text);

    var bundlesRepo = require(path.join(projectRoot, "app", "data", "repositories", "bundles.repo"));
    assert.ok(bundlesRepo.findByShareId(seed.bundleShareId), "victim bundle must survive");
  });

  it("upload-only key cannot rename a victim's file (admin override suppressed)", async function () {
    var seed = seedVictimBundle();
    var c = new TestClient(testServer.baseUrl());
    await c.bearer(adminUploadKey);
    var res = await c.post("/files/" + seed.fileShareId + "/rename", { json: { name: "hijacked.txt" } });
    assert.strictEqual(res.status, 403, "upload key must not rename another user's file: " + res.text);
  });

  it("admin-scoped key keeps the ownership override (can delete a victim's bundle)", async function () {
    var seed = seedVictimBundle();
    var c = new TestClient(testServer.baseUrl());
    await c.bearer(adminScopedKey);
    var res = await c.post("/bundles/" + seed.bundleShareId + "/delete", { json: {} });
    assert.strictEqual(res.status, 200, "admin-scoped key may delete via override: " + res.text);

    var bundlesRepo = require(path.join(projectRoot, "app", "data", "repositories", "bundles.repo"));
    assert.strictEqual(bundlesRepo.findByShareId(seed.bundleShareId), null, "admin key deletes the bundle");
  });

  it("interactive admin SESSION keeps the ownership override (can delete a victim's bundle)", async function () {
    var seed = seedVictimBundle();
    rateLimit().resetAllInstances();
    var c = new TestClient(testServer.baseUrl());
    await c.initApiKey();
    await c.post("/auth/login", { json: { email: adminEmail, password: strongPassword } });
    var res = await c.post("/bundles/" + seed.bundleShareId + "/delete", { json: {} });
    assert.strictEqual(res.status, 200, "interactive admin session keeps the override: " + res.text);

    var bundlesRepo = require(path.join(projectRoot, "app", "data", "repositories", "bundles.repo"));
    assert.strictEqual(bundlesRepo.findByShareId(seed.bundleShareId), null, "admin session deletes the bundle");
  });

  it("'webhook' is no longer a mintable scope", async function () {
    rateLimit().resetAllInstances();
    client.clearCookies();
    await client.initApiKey();
    await client.post("/auth/login", { json: { email: adminEmail, password: strongPassword } });
    var res = await client.post("/admin/apikeys/create", { json: { name: "wh-" + testId, permissions: "webhook" } });
    assert.strictEqual(res.status, 400, "minting a webhook-scoped key must be rejected: " + res.text);
    var detail = (res.json && (res.json.detail || res.json.error)) || res.text || "";
    assert.ok(/webhook/i.test(detail), "rejection should name the unknown scope: " + detail);

    // And the constant itself no longer carries it.
    var { VALID_SCOPES } = require(path.join(projectRoot, "app", "security", "scope-policy"));
    assert.strictEqual(VALID_SCOPES.indexOf("webhook"), -1, "VALID_SCOPES must not contain 'webhook'");
  });
});
