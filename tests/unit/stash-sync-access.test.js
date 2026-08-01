/**
 * E-2 regression: a public sync stash must not let an anonymous browser visitor
 * overwrite an owner-synced file, and E-6-stash: the email access-code request
 * must not leak allow-list membership through response latency.
 *
 * E-2. A sync-enabled stash exposes a browser drop portal AND a shared,
 * owner-facing persistent sync bundle. The upload handler treats a matching
 * relativePath on a sync bundle as a REPLACE that deletes the old blob and emits
 * a file_replaced event, which propagates to the owner's connected sync clients
 * (they write it to the owner's disk). Previously POST /stash/:slug/init handed
 * the shared sync bundle to ANY visitor who cleared the stash gate, and POST
 * /stash/:slug/file/:bundleId accepted uploads to it gated only by the stash
 * lock — so an anonymous visitor could overwrite any synced file by guessing its
 * relativePath. The fix routes anonymous browser uploads into a per-visitor
 * SNAPSHOT bundle and refuses the shared sync bundle to any principal not bound
 * to the stash's sync key. A legitimate sync client (bearer + boundStashId +
 * sync scope) still gets the shared sync bundle.
 *
 * E-6. The email access-code request awaited the send on the allowed-address
 * branch while the non-allowed branch returned immediately — a timing oracle for
 * allow-list membership. The send is now fire-and-forget; the response is
 * synchronous on both branches.
 *
 * The route handlers are driven directly against a captured router with the
 * repositories/services stubbed, so no server, network, or api-encrypt layer is
 * involved.
 */
const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const fs = require("fs");
const b = require("../../lib/vendor/blamejs");

var testId = b.crypto.generateToken(4);
var testDbPath = path.join(__dirname, "..", "..", "data", "test-stash-sync-" + testId + ".db");
process.env.HERMITSTASH_DB_PATH = testDbPath;

Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

var vault = require("../../lib/vault");
var stashRepo, bundlesRepo, bundleService, audit, accessCodeService, blamejs;
var routes = {};
var orig = {};

var SYNC_STASH = {
  _id: "stash-sync-" + testId, slug: "syncstash", enabled: "true",
  accessMode: "open", passwordHash: null, allowedEmails: null,
  syncEnabled: "true", syncBundleId: "syncbundle-" + testId,
  name: "Sync Stash", title: "Sync Stash", teamId: null, defaultExpiry: 0,
};
var SYNC_BUNDLE = {
  _id: SYNC_STASH.syncBundleId, shareId: "syncshare-" + testId,
  bundleType: "sync", stashId: SYNC_STASH._id, status: "uploading",
};
var EMAIL_STASH = {
  _id: "stash-email-" + testId, slug: "emailstash", enabled: "true",
  accessMode: "email", passwordHash: null, allowedEmails: "allowed@example.com",
  syncEnabled: "false", syncBundleId: null,
  name: "Email Stash", title: "Email Stash", teamId: null, defaultExpiry: 0,
};

var initCall; // records the initBundle args on the snapshot path

function mockRes() {
  return {
    statusCalled: null,
    body: null,
    status: function (c) { this.statusCalled = c; return this; },
    json: function (o) { this.body = o; return this; },
  };
}

var SYNC_KEY = { boundStashId: SYNC_STASH._id, permissions: "sync,upload", userId: "admin-1" };

before(async function () {
  await vault.init();
  stashRepo = require("../../app/data/repositories/stash.repo");
  bundlesRepo = require("../../app/data/repositories/bundles.repo");
  bundleService = require("../../app/domain/uploads/bundle.service");
  audit = require("../../lib/audit");
  accessCodeService = require("../../app/domain/access-code.service");
  blamejs = require("../../lib/vendor/blamejs");
  var registerStashRoutes = require("../../routes/stash");

  var app = {
    get: function () {},
    post: function (routePath) { routes["POST " + routePath] = arguments[arguments.length - 1]; },
    getReservedSlugs: function () { return new Set(); },
  };
  registerStashRoutes(app);

  // ---- Stubs (namespace-method monkey patches; restored in after) ----
  orig.findBySlug = stashRepo.findBySlug;
  stashRepo.findBySlug = function (slug) {
    if (slug === SYNC_STASH.slug) return SYNC_STASH;
    if (slug === EMAIL_STASH.slug) return EMAIL_STASH;
    return null;
  };
  orig.findById = bundlesRepo.findById;
  bundlesRepo.findById = function (id) { return id === SYNC_BUNDLE._id ? SYNC_BUNDLE : null; };
  orig.bundleUpdate = bundlesRepo.update;
  bundlesRepo.update = function () {};
  orig.stashUpdate = stashRepo.update;
  stashRepo.update = function () {};
  orig.initBundle = bundleService.initBundle;
  bundleService.initBundle = async function (opts) {
    initCall = opts;
    return { bundleId: "snapshot-" + testId, shareId: "snapshotshare-" + testId, finalizeToken: "tok-" + testId };
  };
  orig.auditLog = audit.log;
  audit.log = function () {};
  orig.requestCode = accessCodeService.requestCode;
  accessCodeService.requestCode = async function () { return { sent: true }; };
  orig.parsersJson = blamejs.parsers.json;
  blamejs.parsers.json = async function () { return {}; };
});

after(function () {
  if (stashRepo) { stashRepo.findBySlug = orig.findBySlug; stashRepo.update = orig.stashUpdate; }
  if (bundlesRepo) { bundlesRepo.findById = orig.findById; bundlesRepo.update = orig.bundleUpdate; }
  if (bundleService) bundleService.initBundle = orig.initBundle;
  if (audit) audit.log = orig.auditLog;
  if (accessCodeService) accessCodeService.requestCode = orig.requestCode;
  if (blamejs) blamejs.parsers.json = orig.parsersJson;

  try { fs.unlinkSync(testDbPath); } catch {}
  try { fs.unlinkSync(testDbPath + "-shm"); } catch {}
  try { fs.unlinkSync(testDbPath + "-wal"); } catch {}
  try { fs.unlinkSync(testDbPath + ".enc"); } catch {}
});

describe("stash sync-bundle access (E-2)", function () {

  it("anonymous browser init gets a per-visitor snapshot bundle, NOT the shared sync bundle", async function () {
    initCall = null;
    var req = { params: { slug: SYNC_STASH.slug }, session: {}, headers: {} }; // no apiKey
    var res = mockRes();
    await routes["POST /stash/:slug/init"](req, res);

    assert.ok(res.body, "handler responded");
    assert.strictEqual(res.body.syncMode, false, "anonymous init must NOT be sync mode");
    assert.notStrictEqual(res.body.bundleId, SYNC_STASH.syncBundleId,
      "anonymous init must NOT return the shared sync bundle id");
    assert.ok(initCall, "a fresh bundle is created for the anonymous visitor");
    assert.strictEqual(initCall.bundleType, "snapshot",
      "the anonymous browser upload is a snapshot, never the shared sync bundle");
  });

  it("the stash sync client init still receives the shared sync bundle", async function () {
    initCall = null;
    var req = { params: { slug: SYNC_STASH.slug }, session: {}, headers: {}, apiKey: SYNC_KEY };
    var res = mockRes();
    await routes["POST /stash/:slug/init"](req, res);

    assert.ok(res.body, "handler responded");
    assert.strictEqual(res.body.syncMode, true, "sync client init IS sync mode");
    assert.strictEqual(res.body.bundleId, SYNC_STASH.syncBundleId,
      "sync client gets the shared persistent sync bundle");
    assert.strictEqual(initCall, null, "no snapshot bundle is created for the sync client (early return)");
  });

  it("anonymous upload to the shared sync bundle is refused (no cross-user replace)", async function () {
    var req = { params: { slug: SYNC_STASH.slug, bundleId: SYNC_BUNDLE._id }, session: {}, headers: {} };
    var res = mockRes();
    await assert.rejects(
      routes["POST /stash/:slug/file/:bundleId"](req, res),
      function (e) { return e && e.statusCode === 404; },
      "anonymous upload to the shared sync bundle must be refused as not-found"
    );
  });

  it("the stash sync client passes the sync-bundle guard (fails downstream, not as not-found)", async function () {
    var req = { params: { slug: SYNC_STASH.slug, bundleId: SYNC_BUNDLE._id }, session: {}, headers: {}, apiKey: SYNC_KEY };
    var res = mockRes();
    // The guard is scoped to non-sync principals. For the sync client it must NOT
    // fire; the handler proceeds to parseMultipart, which rejects on this mock
    // request and is wrapped as a 500 — a non-404 outcome proves the guard passed.
    await assert.rejects(
      routes["POST /stash/:slug/file/:bundleId"](req, res),
      function (e) { return e && e.statusCode !== 404; },
      "sync client must pass the sync-bundle guard (must not be refused as not-found)"
    );
  });
});

describe("stash email access-code request (E-6)", function () {

  it("responds without awaiting the send (no allow-list timing oracle)", { timeout: 5000 }, async function () {
    // A controllable send that stays pending until we resolve it below. With
    // fire-and-forget, the handler returns as soon as it calls res.json — it does
    // NOT await the send — so awaiting the handler resolves while the send is
    // still pending. A regression that awaited the send would deadlock here (the
    // send only resolves afterward) and trip the test timeout.
    var kicked = false;
    var resolveSend;
    accessCodeService.requestCode = function () { kicked = true; return new Promise(function (resolve) { resolveSend = resolve; }); };
    blamejs.parsers.json = async function () { return { email: "allowed@example.com" }; };

    var req = { params: { slug: EMAIL_STASH.slug }, session: {}, headers: {} };
    var res = mockRes();

    await routes["POST /stash/:slug/request-code"](req, res);

    assert.ok(res.body && res.body.success === true, "responds success synchronously on the allowed branch");
    assert.strictEqual(kicked, true, "the send is still kicked off (fire-and-forget)");

    // Let the still-pending send settle so its handler-attached .then/.catch run.
    if (resolveSend) resolveSend({ sent: false });
    await Promise.resolve();

    // Restore the fast stubs for any later tests.
    accessCodeService.requestCode = async function () { return { sent: true }; };
    blamejs.parsers.json = async function () { return {}; };
  });
});
