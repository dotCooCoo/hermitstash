"use strict";

/**
 * Limited-download (burn-after-read) bundles over HTTP.
 *
 * A download is spent only by the click-through POST, with a valid CSRF token,
 * after the bundle's expiry and access gates pass. GET, HEAD, previews and the
 * ZIP routes never spend one. Once the last download of the last file is used,
 * the share answers 410 with the same page as an expired bundle.
 *
 * Every refusal is checked against the stash count, read with
 * storage.peekEphemeral, so a route that silently spent a download fails.
 */

var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var fs = require("fs");
var os = require("os");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");
var client;
var db;
var storage;
var C;

var PAST = "2020-01-01T00:00:00.000Z";
var tick = require("node:timers/promises").setTimeout;

// The download is counted just after the response ends, so a client can see
// the end of the body a moment before the count changes. Poll for it.
// On Windows, reading an entry while a download rewrites or removes its
// sidecar can throw EPERM, or EINTEGRITY from the store's name check
// (blamejs/stash#95), so on Windows a poll retries those codes.
var TRANSIENT_WIN = process.platform === "win32" ? ["EPERM", "EACCES", "EBUSY", "EINTEGRITY"] : [];
async function creditsBecome(storagePath, n) {
  var deadline = Date.now() + 10000;
  for (;;) {
    var left;
    try {
      left = await storage.peekEphemeral(storagePath);
    } catch (e) {
      if (!e || TRANSIENT_WIN.indexOf(e.code) === -1 || Date.now() > deadline) throw e;
      await tick(5);
      continue;
    }
    if (left === n) return left;
    if (Date.now() > deadline) return left;
    await tick(5);
  }
}

async function makeBurnBundle(name, readLimit, extra) {
  testServer.resetAllRateLimits();
  var body = Object.assign({ uploaderName: name, fileCount: 1, skippedCount: 0, skippedFiles: [], expiryDays: 1, readLimit: readLimit }, extra || {});
  var init = await client.post("/drop/init", { json: body });
  assert.strictEqual(init.status, 200, "init: " + init.text);
  var content = name + " secret bytes " + "x".repeat(2000);
  var up = await client.uploadFile("/drop/file/" + init.json.bundleId, "file", name + ".txt", content, { relativePath: name + ".txt" });
  assert.strictEqual(up.status, 200, "upload: " + up.text);
  var fin = await client.post("/drop/finalize/" + init.json.bundleId, { json: { finalizeToken: init.json.finalizeToken } });
  assert.strictEqual(fin.status, 200, "finalize: " + fin.text);
  var bundleRow = db.bundles.findOne({ _id: init.json.bundleId });
  var fileRow = db.files.find({}).filter(function (f) { return f.bundleId === init.json.bundleId; })[0];
  assert.ok(fileRow, "the file row exists");
  return { shareId: bundleRow.shareId, bundleId: init.json.bundleId, fileShareId: fileRow.shareId, storagePath: fileRow.storagePath, content: content, finalizeToken: init.json.finalizeToken };
}

function fileUrl(b) { return "/b/" + b.shareId + "/file/" + b.fileShareId; }

async function csrfFrom(b) {
  var page = await client.get(fileUrl(b));
  assert.strictEqual(page.status, 200, "the click-through page renders: " + page.status);
  var m = page.text.match(/name="_csrf" value="([^"]+)"/);
  assert.ok(m, "the click-through page carries a CSRF token");
  return m[1];
}

function postDownload(b, token, headers) {
  return client.post(fileUrl(b), {
    body: "_csrf=" + encodeURIComponent(token || ""),
    contentType: "application/x-www-form-urlencoded",
    headers: headers || {},
  });
}

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());
  await client.initApiKey();
  db = require(path.join(testServer.projectRoot, "lib", "db"));
  storage = require(path.join(testServer.projectRoot, "lib", "storage"));
  C = require(path.join(testServer.projectRoot, "lib", "constants"));
});
after(async function () {
  await storage.closeEphemeral();
  return testServer.stop();
});

describe("sender input", function () {
  it("stores limited-download files under the data directory, outside UPLOAD_DIR", async function () {
    var b = await makeBurnBundle("where", 1);
    assert.ok(storage.isStashPath(b.storagePath), "the file row points at the stash store");
    assert.ok(C.PATHS.STASH_DIR.startsWith(testServer.testDataDir), "the stash root is under the data dir");
    assert.ok(!C.PATHS.STASH_DIR.startsWith(storage.uploadDir + path.sep), "and not under UPLOAD_DIR");
  });

  it("refuses an out-of-range or malformed readLimit", async function () {
    var max = C.UPLOAD.MAX_BURN_READS_DEFAULT;
    var bad = [max + 1, -1, "abc", 1.5];
    for (var i = 0; i < bad.length; i++) {
      var r = await client.post("/drop/init", { json: { uploaderName: "x", fileCount: 1, skippedCount: 0, skippedFiles: [], expiryDays: 1, readLimit: bad[i] } });
      assert.strictEqual(r.status, 400, "readLimit " + JSON.stringify(bad[i]) + " is refused");
    }
  });

  it("refuses a limited-download bundle with no expiry", async function () {
    var r = await client.post("/drop/init", { json: { uploaderName: "x", fileCount: 1, skippedCount: 0, skippedFiles: [], expiryDays: 0, readLimit: 1 } });
    assert.strictEqual(r.status, 400);
  });

  it("the upload page renders one download-limit select, and the script reads it by that id", async function () {
    testServer.resetAllRateLimits();
    var page = await client.get("/drop");
    assert.strictEqual(page.status, 200, "the drop page renders: " + page.status);
    var ids = page.text.match(/id="bundleReadLimit"/g) || [];
    assert.strictEqual(ids.length, 1, "exactly one element carries id=bundleReadLimit");
    var select = page.text.match(/<select id="bundleReadLimit"[\s\S]*?<\/select>/);
    assert.ok(select, "the element is the visible select");
    var values = (select[0].match(/<option value="(\d+)"/g) || []).map(function (o) { return Number(o.match(/\d+/)[0]); });
    assert.strictEqual(values[0], 0, "the first choice is no limit");
    assert.ok(values.indexOf(1) !== -1 && values.length > 1, "limit choices are offered");
    assert.match(page.text, /getElementById\('bundleReadLimit'\)/);
    assert.match(page.text, /readLimit:readLimit/, "the init body sends the selected value");
  });
});

describe("requests that must not spend a download", function () {
  var b;
  before(async function () { b = await makeBurnBundle("nospend", 2); });

  it("the bundle page lists the downloads left and spends nothing", async function () {
    var page = await client.get("/b/" + b.shareId);
    assert.strictEqual(page.status, 200);
    assert.match(page.text, /2 downloads left/);
    assert.strictEqual(page.text.indexOf("/download\""), -1, "no ZIP link is offered");
    assert.strictEqual(await storage.peekEphemeral(b.storagePath), 2);
  });

  it("GET of the file shows the click-through page, not the file", async function () {
    var page = await client.get(fileUrl(b));
    assert.strictEqual(page.status, 200);
    assert.strictEqual(page.text.indexOf("secret bytes"), -1, "the content is not in the page");
    assert.match(page.text, /method="POST"/);
    assert.strictEqual(await storage.peekEphemeral(b.storagePath), 2);
  });

  it("HEAD answers 405", async function () {
    var r = await client.request("HEAD", fileUrl(b));
    assert.strictEqual(r.status, 405);
    assert.strictEqual(await storage.peekEphemeral(b.storagePath), 2);
  });

  it("preview answers 404 and the /s routes redirect to the click-through", async function () {
    assert.strictEqual((await client.get("/s/" + b.fileShareId + "/preview")).status, 404);
    var dl = await client.get("/s/" + b.fileShareId + "/download");
    assert.strictEqual(dl.status, 303);
    assert.strictEqual(dl.location, fileUrl(b));
    assert.strictEqual((await client.get("/s/" + b.fileShareId)).status, 303);
    assert.strictEqual(await storage.peekEphemeral(b.storagePath), 2);
  });

  it("ZIP-all and folder ZIP are refused", async function () {
    assert.strictEqual((await client.get("/b/" + b.shareId + "/download")).status, 409);
    assert.strictEqual((await client.get("/b/" + b.shareId + "/folder?path=x")).status, 409);
    assert.strictEqual(await storage.peekEphemeral(b.storagePath), 2);
  });

  it("a POST without a valid CSRF token is refused", async function () {
    var r = await postDownload(b, "not-the-token");
    assert.strictEqual(r.status, 403);
    var r2 = await postDownload(b, "");
    assert.strictEqual(r2.status, 403);
    assert.strictEqual(await storage.peekEphemeral(b.storagePath), 2);
  });

  it("getFileStream refuses the stash path instead of spending a download", async function () {
    await assert.rejects(storage.getFileStream(b.storagePath, "AAAA"), /consumeEphemeral/);
    assert.strictEqual(await storage.peekEphemeral(b.storagePath), 2);
  });
});

describe("the click-through download", function () {
  it("sends the whole file, ignores Range, spends one download per POST, then answers 410", async function () {
    var b = await makeBurnBundle("spend", 2);
    var token = await csrfFrom(b);
    var r1 = await postDownload(b, token, { range: "bytes=0-9" });
    assert.strictEqual(r1.status, 200, "Range is ignored: no 206");
    assert.strictEqual(r1.text, b.content, "the whole file comes back");
    assert.strictEqual(r1.headers["cache-control"], "no-store");
    assert.strictEqual(await creditsBecome(b.storagePath, 1), 1);

    // The first download's claim is released just after its count is written;
    // until then a second download answers 409.
    var r2 = await postDownload(b, token);
    var retryUntil = Date.now() + 10000;
    while (r2.status === 409 && Date.now() < retryUntil) { await tick(5); r2 = await postDownload(b, token); }
    assert.strictEqual(r2.status, 200);
    assert.strictEqual(r2.text, b.content);
    assert.strictEqual(await creditsBecome(b.storagePath, null), null, "the last download destroys the entry");
    // The route records the read and marks the bundle burned after the commit.
    var deadline = Date.now() + 10000;
    while (db.bundles.findOne({ _id: b.bundleId }).status !== "burned" && Date.now() < deadline) await tick(5);

    var expiredPage = await client.get("/b/" + b.shareId);
    assert.strictEqual(expiredPage.status, 410, "a used-up bundle answers 410");
    assert.match(expiredPage.text, /This bundle has expired/, "with the expired page");
    assert.strictEqual((await client.get(fileUrl(b))).status, 410);
    assert.strictEqual((await postDownload(b, token)).status, 410);
    var row = db.bundles.findOne({ _id: b.bundleId });
    assert.strictEqual(row.status, "burned", "the bundle row stays, marked burned");
  });

  it("a burned bundle accepts no uploads and cannot be finalized again", async function () {
    var b = await makeBurnBundle("reopen", 1);
    var token = await csrfFrom(b);
    assert.strictEqual((await postDownload(b, token)).status, 200);
    var deadline = Date.now() + 10000;
    while (db.bundles.findOne({ _id: b.bundleId }).status !== "burned" && Date.now() < deadline) await tick(5);
    assert.strictEqual(db.bundles.findOne({ _id: b.bundleId }).status, "burned");
    var filesBefore = db.files.find({}).filter(function (f) { return f.bundleId === b.bundleId; }).length;

    testServer.resetAllRateLimits();
    var up = await client.uploadFile("/drop/file/" + b.bundleId, "file", "late.txt", "late " + "y".repeat(100), { relativePath: "late.txt" });
    assert.strictEqual(up.status, 404, "single-file upload to a burned bundle: " + up.status);
    var chunk = await client.uploadFile("/drop/chunk/" + b.bundleId, "chunk", "late.txt", "late " + "y".repeat(100),
      { fileId: "late-1", chunkIndex: "0", totalChunks: "1", filename: "late.txt", relativePath: "late.txt" });
    assert.strictEqual(chunk.status, 404, "chunk upload to a burned bundle: " + chunk.status);
    var fin = await client.post("/drop/finalize/" + b.bundleId, { json: { finalizeToken: b.finalizeToken } });
    assert.strictEqual(fin.status, 404, "re-finalize of a burned bundle: " + fin.status);

    var bundleService = require(path.join(testServer.projectRoot, "app", "domain", "uploads", "bundle.service"));
    assert.throws(function () { bundleService.finalizeBundle(b.bundleId, b.finalizeToken); }, function (e) { return e.statusCode === 404; });

    assert.strictEqual(db.bundles.findOne({ _id: b.bundleId }).status, "burned", "the bundle stays burned");
    assert.strictEqual(db.files.find({}).filter(function (f) { return f.bundleId === b.bundleId; }).length, filesBefore, "no file row was added");
    assert.strictEqual((await client.get("/b/" + b.shareId)).status, 410, "the share link still answers 410");
  });

  it("never writes the stash ref to the audit log", async function () {
    var b = await makeBurnBundle("auditref", 1);
    var token = await csrfFrom(b);
    assert.strictEqual((await postDownload(b, token)).status, 200);
    var ref = b.storagePath.slice("stash:".length);
    await creditsBecome(b.storagePath, null);
    var rows, reads;
    var until = Date.now() + 10000;
    do {
      rows = db.auditLog.find({});
      reads = rows.filter(function (r) { return r.action === "bundle_burn_read" && String(r.details).indexOf(b.shareId) !== -1; });
      if (reads.length > 0) break;
      await tick(5);
    } while (Date.now() < until);
    assert.ok(reads.length > 0, "the download was audited");
    rows.forEach(function (r) {
      assert.strictEqual(JSON.stringify(r).indexOf(ref), -1, "audit row " + r.action + " does not carry the ref");
    });
  });

  it("concurrent downloads of the last credit: exactly one succeeds", async function () {
    var b = await makeBurnBundle("race", 1);
    var token = await csrfFrom(b);
    var results = await Promise.all([0, 1, 2, 3].map(function () { return postDownload(b, token); }));
    var statuses = results.map(function (r) { return r.status; });
    assert.strictEqual(statuses.filter(function (s) { return s === 200; }).length, 1, "one download: " + statuses.join(","));
    statuses.forEach(function (s) { assert.ok(s === 200 || s === 409 || s === 410, "losers get 409 or 410: " + s); });
  });
});

describe("access gates run before the stash is touched", function () {
  it("a password-protected bundle spends nothing before unlock", async function () {
    var b = await makeBurnBundle("locked", 1, { password: "correct horse battery staple 9" });
    var other = new TestClient(testServer.baseUrl());
    await other.initApiKey();
    var page = await other.get(fileUrl(b));
    assert.strictEqual(page.status, 401);
    assert.strictEqual(await storage.peekEphemeral(b.storagePath), 1);
  });

  it("a bundle that has not been finalized serves nothing", async function () {
    var init = await client.post("/drop/init", { json: { uploaderName: "unfinal", fileCount: 2, skippedCount: 0, skippedFiles: [], expiryDays: 1, readLimit: 1 } });
    assert.strictEqual(init.status, 200, "init: " + init.text);
    var up = await client.uploadFile("/drop/file/" + init.json.bundleId, "file", "unfinal.txt", "unfinal secret bytes", { relativePath: "unfinal.txt" });
    assert.strictEqual(up.status, 200, "upload: " + up.text);
    var bundleRow = db.bundles.findOne({ _id: init.json.bundleId });
    assert.strictEqual(bundleRow.status, "uploading");
    var fileRow = db.files.find({}).filter(function (f) { return f.bundleId === init.json.bundleId; })[0];
    var b = { shareId: bundleRow.shareId, fileShareId: fileRow.shareId };
    assert.strictEqual((await client.get(fileUrl(b))).status, 404);
    // The token comes from a finalized bundle's page; the session is shared.
    var token = await csrfFrom(await makeBurnBundle("unfinaltoken", 1));
    assert.strictEqual((await postDownload(b, token)).status, 404);
    assert.strictEqual(await storage.peekEphemeral(fileRow.storagePath), 1);
  });
});

// Registers a route module against a stub app and returns the handler chain
// for one method and path, so a route can be driven without its transport
// (the sync API needs an mTLS client certificate; admin routes need a session).
function routeChain(modulePath, method, routePath) {
  var chains = {};
  var stub = {};
  ["get", "post", "put", "delete", "head", "patch", "use", "all"].forEach(function (m) {
    stub[m] = function (p) { chains[m + " " + p] = Array.prototype.slice.call(arguments, 1); };
  });
  require(path.join(testServer.projectRoot, modulePath))(stub);
  var chain = chains[method + " " + routePath];
  assert.ok(chain, "route " + method + " " + routePath + " is registered");
  return chain;
}

function stubRes() {
  var res = { statusCode: 200, body: null, headers: {} };
  res.status = function (c) { res.statusCode = c; return res; };
  res.json = function (o) { res.body = o; return res; };
  res.writeHead = function (c) { res.statusCode = c; return res; };
  res.setHeader = function (k, v) { res.headers[k] = v; };
  res.end = function () { return res; };
  return res;
}

describe("other routes that hold a limited-download file", function () {
  it("the sync download answers 403 and spends nothing", async function () {
    var b = await makeBurnBundle("syncdl", 2);
    db.bundles.update({ _id: b.bundleId }, { $set: { ownerId: "sync-owner" } });
    var chain = routeChain(path.join("routes", "files"), "get", "/files/:fileId/download");
    var handler = chain[chain.length - 1];
    var req = { params: { fileId: b.fileShareId }, apiKey: { userId: "sync-owner", permissions: "sync" }, on: function () {} };
    await assert.rejects(handler(req, stubRes()), function (err) { return err && err.statusCode === 403; });
    assert.strictEqual(await storage.peekEphemeral(b.storagePath), 2);
  });

  it("admin file and bundle deletes destroy the entry and audit bundle_burn_destroyed", async function () {
    var admin = { _id: "burn-admin", role: "admin", status: "active", email: "burn-admin@test.com" };
    var one = await makeBurnBundle("admindelfile", 2);
    var delFile = routeChain(path.join("routes", "admin"), "post", "/admin/files/:shareId/delete");
    var res1 = stubRes();
    await delFile[delFile.length - 1]({ params: { shareId: one.fileShareId }, user: admin, headers: {}, on: function () {} }, res1);
    assert.deepStrictEqual(res1.body, { success: true });
    assert.strictEqual(await storage.peekEphemeral(one.storagePath), null, "the stash entry is gone");

    var two = await makeBurnBundle("admindelbundle", 2);
    var delBundle = routeChain(path.join("routes", "admin"), "post", "/admin/bundles/:shareId/delete");
    var res2 = stubRes();
    await delBundle[delBundle.length - 1]({ params: { shareId: two.shareId }, user: admin, headers: {}, on: function () {} }, res2);
    assert.deepStrictEqual(res2.body, { success: true });
    assert.strictEqual(await storage.peekEphemeral(two.storagePath), null);

    var destroyed = db.auditLog.find({}).filter(function (r) { return r.action === "bundle_burn_destroyed"; });
    assert.ok(destroyed.some(function (r) { return String(r.details).indexOf(one.shareId) !== -1; }), "the file delete is audited");
    assert.ok(destroyed.some(function (r) { return String(r.details).indexOf(two.shareId) !== -1; }), "the bundle delete is audited");
  });
});

describe("the maxBurnReads setting", function () {
  it("the admin validator refuses values outside 1..100, and a saved value caps readLimit", async function () {
    var adminValidator = require(path.join(testServer.projectRoot, "app", "http", "validators", "admin.validator"));
    assert.ok(adminValidator.validateSettingsInput({ maxBurnReads: 101 }).error, "101 is refused");
    assert.ok(adminValidator.validateSettingsInput({ maxBurnReads: "0" }).error, "0 is refused");
    assert.ok(!adminValidator.validateSettingsInput({ maxBurnReads: 3 }).error, "3 is accepted");

    var settingsService = require(path.join(testServer.projectRoot, "app", "domain", "admin", "settings.service"));
    var config = require(path.join(testServer.projectRoot, "lib", "config"));
    var before = config.maxBurnReads;
    settingsService.updateSettings({ maxBurnReads: "3" });
    testServer.resetAllRateLimits();
    try {
      assert.strictEqual(config.maxBurnReads, 3);
      var base = { uploaderName: "cap", fileCount: 1, skippedCount: 0, skippedFiles: [], expiryDays: 1 };
      var over = await client.post("/drop/init", { json: Object.assign({}, base, { readLimit: 4 }) });
      assert.strictEqual(over.status, 400, "a readLimit above the setting is refused");
      var at = await client.post("/drop/init", { json: Object.assign({}, base, { readLimit: 3 }) });
      assert.strictEqual(at.status, 200, "a readLimit at the setting is accepted: " + at.text);
    } finally {
      settingsService.updateSettings({ maxBurnReads: String(before) });
    }
  });
});

describe("storage quotas charge the stored size", function () {
  function rowOf(b) { return db.files.findOne({ shareId: b.fileShareId }); }

  it("refuses tiny limited-download files once their stored size crosses the storage quota", async function () {
    var config = require(path.join(testServer.projectRoot, "lib", "config"));
    var prior = config.storageQuotaBytes;
    var tiny = "q".repeat(100);
    var stored = storage.storedSizeOf(tiny.length, true);
    assert.ok(stored > storage.BURN_HOLD_BYTES, "a tiny burn file occupies more than the hold region");
    testServer.resetAllRateLimits();
    var init = await client.post("/drop/init", { json: { uploaderName: "quota", fileCount: 5, skippedCount: 0, skippedFiles: [], expiryDays: 1, readLimit: 1 } });
    assert.strictEqual(init.status, 200, "init: " + init.text);
    // Room for three stored files and half of a fourth. Their plaintext, 400
    // bytes in all, is far below the quota.
    config.storageQuotaBytes = db.getTotalStorageUsed() + 3 * stored + Math.floor(stored / 2);
    try {
      var statuses = [];
      for (var i = 0; i < 4; i++) {
        var up = await client.uploadFile("/drop/file/" + init.json.bundleId, "file", "q" + i + ".txt", tiny, { relativePath: "q" + i + ".txt" });
        statuses.push({ status: up.status, text: JSON.stringify(up.json) });
      }
      for (var j = 0; j < 3; j++) assert.strictEqual(statuses[j].status, 200, "file " + j + " fits: " + statuses[j].text);
      assert.notStrictEqual(statuses[3].status, 200, "the fourth file is refused");
      assert.match(statuses[3].text, /Storage quota exceeded/);
      var rows = db.files.find({}).filter(function (f) { return f.bundleId === init.json.bundleId; });
      assert.strictEqual(rows.length, 3, "the refused file left no row");
      rows.forEach(function (r) { assert.strictEqual(Number(r.storedSize), stored, "each row records its stored size"); assert.strictEqual(Number(r.size), tiny.length, "size stays the plaintext length"); });
    } finally {
      config.storageQuotaBytes = prior;
    }
  });

  it("usage returns to its prior value after limited-download files are spent, deleted and expired", async function () {
    var expiryJob = require(path.join(testServer.projectRoot, "app", "jobs", "expiry-cleanup.job"));
    var admin = { _id: "quota-admin", role: "admin", status: "active", email: "quota-admin@test.com" };
    var u0 = db.getTotalStorageUsed();

    var spent = await makeBurnBundle("qspent", 1);
    var deleted = await makeBurnBundle("qdeleted", 2);
    var expired = await makeBurnBundle("qexpired", 2);
    var vanished = await makeBurnBundle("qvanished", 2);
    var all = [spent, deleted, expired, vanished];
    var added = 0;
    all.forEach(function (b) {
      var r = rowOf(b);
      assert.strictEqual(Number(r.storedSize), storage.storedSizeOf(b.content.length, true));
      added += Number(r.storedSize);
    });
    assert.strictEqual(db.getTotalStorageUsed(), u0 + added, "usage rose by the stored sizes");

    // Spent: the last download removes the row.
    var token = await csrfFrom(spent);
    assert.strictEqual((await postDownload(spent, token)).status, 200);
    var deadline = Date.now() + 10000;
    while (rowOf(spent) && Date.now() < deadline) await tick(5);
    assert.strictEqual(rowOf(spent), null, "the spent file's row is gone");

    // Deleted by an admin.
    var delFile = routeChain(path.join("routes", "admin"), "post", "/admin/files/:shareId/delete");
    await delFile[delFile.length - 1]({ params: { shareId: deleted.fileShareId }, user: admin, headers: {}, on: function () {} }, stubRes());
    assert.strictEqual(rowOf(deleted), null);

    // Expired file row.
    db.files.update({ _id: rowOf(expired)._id }, { $set: { expiresAt: PAST } });
    await expiryJob.cleanupExpiredFiles();
    assert.strictEqual(rowOf(expired), null);

    // Stash entry gone (pruned or dropped): the burn cleanup removes the row.
    await storage.dropEphemeral(vanished.storagePath);
    await expiryJob.cleanupBurnStore();
    assert.strictEqual(rowOf(vanished), null);

    assert.strictEqual(db.getTotalStorageUsed(), u0, "usage is back to its prior value");
  });
});

describe("background jobs", function () {
  it("the orphan scan does not report limited-download rows as dangling", async function () {
    var b = await makeBurnBundle("orphan", 1);
    var orphanJob = require(path.join(testServer.projectRoot, "app", "jobs", "orphan-cleanup.job"));
    var dangling = await orphanJob.scanDanglingRecords();
    assert.strictEqual(dangling.filter(function (d) { return d.storagePath === b.storagePath; }).length, 0);
  });

  it("the burn cleanup keeps a burned bundle until its expiry, then removes it", async function () {
    var expiryJob = require(path.join(testServer.projectRoot, "app", "jobs", "expiry-cleanup.job"));
    var b = await makeBurnBundle("cleanup", 1);
    var token = await csrfFrom(b);
    assert.strictEqual((await postDownload(b, token)).status, 200);
    await expiryJob.cleanupBurnStore();
    assert.ok(db.bundles.findOne({ _id: b.bundleId }), "kept while its expiry is in the future");
    assert.strictEqual((await client.get("/b/" + b.shareId)).status, 410);

    var row = db.bundles.findOne({ _id: b.bundleId });
    db.bundles.update({ _id: row._id }, { $set: { expiresAt: PAST } });
    var res = await expiryJob.cleanupBurnStore();
    assert.ok(res.burnedRemoved >= 1);
    assert.strictEqual(db.bundles.findOne({ _id: b.bundleId }), null, "removed once expired");
  });

  it("the burn cleanup removes the row of a file whose stash entry is gone", async function () {
    var expiryJob = require(path.join(testServer.projectRoot, "app", "jobs", "expiry-cleanup.job"));
    var b = await makeBurnBundle("reconcile", 3);
    await storage.dropEphemeral(b.storagePath);
    var res = await expiryJob.cleanupBurnStore();
    assert.ok(res.reconciled >= 1);
    assert.strictEqual(db.files.findOne({ shareId: b.fileShareId }), null);
    assert.strictEqual(db.bundles.findOne({ _id: b.bundleId }).status, "burned");
  });

  it("the expiry job does not tombstone an expired stash entry", async function () {
    var expiryJob = require(path.join(testServer.projectRoot, "app", "jobs", "expiry-cleanup.job"));
    var b = await makeBurnBundle("expired", 2);
    var row = db.files.findOne({ shareId: b.fileShareId });
    db.files.update({ _id: row._id }, { $set: { expiresAt: PAST } });
    await expiryJob.cleanupExpiredFiles();
    assert.strictEqual(db.files.findOne({ shareId: b.fileShareId }), null, "the expired row is removed");
    assert.strictEqual(await storage.peekEphemeral(b.storagePath), 2, "the stash entry is left for prune, not dropped");
  });

  it("the backup walk skips the stash directory when it sits inside the upload tree", async function () {
    var walk = require(path.join(testServer.projectRoot, "lib", "backup-walk"));
    var root = fs.mkdtempSync(path.join(os.tmpdir(), "hs-walk-"));
    try {
      fs.mkdirSync(path.join(root, "bundles", "a"), { recursive: true });
      fs.mkdirSync(path.join(root, "burn-stash", "blobs"), { recursive: true });
      fs.mkdirSync(path.join(root, "chunks"), { recursive: true });
      fs.writeFileSync(path.join(root, "bundles", "a", "f.bin"), "x");
      fs.writeFileSync(path.join(root, "burn-stash", "blobs", "v1_x"), "y");
      fs.writeFileSync(path.join(root, "chunks", "0"), "z");
      var files = await walk.walkUploads(root, [path.join(root, "chunks"), path.join(root, "burn-stash")]);
      var rel = files.map(function (f) { return path.relative(root, f).replace(/\\/g, "/"); });
      assert.deepStrictEqual(rel, ["bundles/a/f.bin"]);
      // UPLOAD_DIR set to the store itself, or to a directory inside it.
      assert.deepStrictEqual(await walk.walkUploads(path.join(root, "burn-stash"), [path.join(root, "burn-stash")]), []);
      assert.deepStrictEqual(await walk.walkUploads(path.join(root, "burn-stash", "blobs"), [path.join(root, "burn-stash")]), []);
      // A sibling whose name starts with the store's name is still walked.
      fs.mkdirSync(path.join(root, "burn-stash-other"));
      fs.writeFileSync(path.join(root, "burn-stash-other", "g.bin"), "w");
      assert.strictEqual((await walk.walkUploads(path.join(root, "burn-stash-other"), [path.join(root, "burn-stash")])).length, 1);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it("the dashboard disk figure counts each burn-store byte once, nested or not, including entries with no row", async function () {
    var admin = require(path.join(testServer.projectRoot, "routes", "admin"));
    var spent = await makeBurnBundle("walk-spent", 1);
    var dl = await postDownload(spent, await csrfFrom(spent));
    assert.strictEqual(dl.status, 200);
    assert.strictEqual(await creditsBecome(spent.storagePath, null), null, "the spent entry has no credits left");
    await makeBurnBundle("walk-live", 2);
    var stashDir = path.resolve(C.PATHS.STASH_DIR);
    function sumAll(dir) {
      if (!fs.existsSync(dir)) return 0;
      var total = 0;
      fs.readdirSync(dir, { withFileTypes: true }).forEach(function (e) {
        var full = path.join(dir, e.name);
        if (e.isDirectory()) total += sumAll(full);
        else if (e.isFile()) total += fs.statSync(full).size;
      });
      return total;
    }
    assert.ok(sumAll(stashDir) > 0, "the stash directory holds bytes");
    // Nested: the store sits inside the walked tree.
    var parent = path.dirname(stashDir);
    assert.strictEqual(admin.diskFootprint(parent), sumAll(parent));
    // Separate: the store is outside the walked tree and is still added.
    var other = fs.mkdtempSync(path.join(os.tmpdir(), "hs-up-"));
    try {
      fs.writeFileSync(path.join(other, "f.bin"), "abc");
      assert.strictEqual(admin.diskFootprint(other), 3 + sumAll(stashDir));
    } finally {
      fs.rmSync(other, { recursive: true, force: true });
    }
  });

  it("the backup passes the stash directory to the worker as an exclusion", function () {
    var src = fs.readFileSync(path.join(testServer.projectRoot, "lib", "backup.js"), "utf8");
    assert.match(src, /stashDir:\s*C\.PATHS\.STASH_DIR/);
    var worker = fs.readFileSync(path.join(testServer.projectRoot, "lib", "backup-worker.js"), "utf8");
    assert.match(worker, /walkUploads\(uploadDir,\s*\[chunkScratchAbs,\s*stashAbs\]\)/);
  });
});
