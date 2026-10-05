/**
 * Request fields that an anonymous visitor or a signed-in user can store in a
 * database row or an audit row are held to fixed limits, and a request inside
 * those limits is stored unchanged.
 */
var { describe, it, before, after, beforeEach } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var crypto = require("crypto");

var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");

var client;
var root, db, b, bundlesRepo, filesRepo, usersRepo, credentialsRepo, sanitizeFilename;

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());
  root = testServer.projectRoot;
  db = require(path.join(root, "lib", "db"));
  b = require(path.join(root, "lib", "vendor", "blamejs"));
  bundlesRepo = require(path.join(root, "app", "data", "repositories", "bundles.repo"));
  filesRepo = require(path.join(root, "app", "data", "repositories", "files.repo"));
  usersRepo = require(path.join(root, "app", "data", "repositories", "users.repo"));
  credentialsRepo = require(path.join(root, "app", "data", "repositories", "credentials.repo"));
  sanitizeFilename = require(path.join(root, "app", "shared", "sanitize-filename")).sanitizeFilename;
});

after(function () { return testServer.stop(); });

beforeEach(function () { testServer.resetAllRateLimits(); });

function detail(res) { return res.json && (res.json.detail || res.json.error); }

function auditRows(action, targetId) {
  return db.auditLog.find({}).filter(function (e) {
    return e.action === action && (!targetId || e.targetId === targetId);
  });
}

function bytes64(n) { return crypto.randomBytes(n).toString("base64"); }

async function anonymous() {
  client.clearCookies();
  await client.initApiKey();
}

async function signUp(email) {
  client.clearCookies();
  await client.initApiKey();
  var res = await client.post("/auth/register", { json: { displayName: "Caps", email: email, password: "password123" } });
  assert.strictEqual(res.status, 200, "register " + email + ": " + JSON.stringify(res.json));
  return usersRepo.findByEmail(email);
}

function dropInit(json) { return client.post("/drop/init", { json: json }); }

describe("bundle init fields", function () {
  it("refuses a fileCount that is not a whole number", async function () {
    await anonymous();
    var res = await dropInit({ uploaderName: "C", fileCount: "x".repeat(200000), skippedCount: 0, skippedFiles: [] });
    assert.strictEqual(res.status, 400);
    assert.strictEqual(detail(res), "fileCount must be a whole number.");
  });

  it("refuses a skippedCount that is not a whole number", async function () {
    await anonymous();
    var res = await dropInit({ uploaderName: "C", fileCount: 1, skippedCount: { nested: "y".repeat(50000) }, skippedFiles: [] });
    assert.strictEqual(res.status, 400);
    assert.strictEqual(detail(res), "skippedCount must be a whole number.");
  });

  it("stores the counts as integers and audits the validated fileCount", async function () {
    await anonymous();
    var res = await dropInit({ uploaderName: "C", fileCount: "7", skippedCount: 3000, skippedFiles: [] });
    assert.strictEqual(res.status, 200);
    var row = db.rawGet("SELECT typeof(expectedFiles) AS t1, expectedFiles AS v1, typeof(skippedCount) AS t2, skippedCount AS v2 FROM bundles WHERE _id = ?", res.json.bundleId);
    assert.deepStrictEqual(Object.assign({}, row), { t1: "integer", v1: 7, t2: "integer", v2: 3000 });
    assert.strictEqual(auditRows("bundle_initialized", res.json.bundleId)[0].details, "expected: 7");
  });

  it("refuses a skippedFiles value that is not a list", async function () {
    await anonymous();
    var res = await dropInit({ uploaderName: "C", fileCount: 1, skippedCount: 0, skippedFiles: "q".repeat(100000) });
    assert.strictEqual(res.status, 400);
    assert.strictEqual(detail(res), "skippedFiles must be a list.");
  });

  it("refuses a skipped entry without a path", async function () {
    await anonymous();
    var res = await dropInit({ uploaderName: "C", fileCount: 1, skippedCount: 1, skippedFiles: [{ reason: "no path" }] });
    assert.strictEqual(res.status, 400);
    assert.strictEqual(detail(res), "Each skipped file needs a path.");
  });

  it("keeps the first 50 skipped entries and cuts each one to its limits", async function () {
    await anonymous();
    var sent = [];
    for (var i = 0; i < 200; i++) sent.push({ path: "dir/" + "p".repeat(600) + i, reason: "r".repeat(150) });
    var res = await dropInit({ uploaderName: "C", fileCount: 0, skippedCount: 200, skippedFiles: sent });
    assert.strictEqual(res.status, 200);
    var stored = bundlesRepo.findById(res.json.bundleId).skippedFiles;
    assert.strictEqual(stored.length, 50);
    stored.forEach(function (e, idx) {
      assert.strictEqual(e.path, sent[idx].path.slice(0, 500));
      assert.strictEqual(e.reason, "r".repeat(100));
    });
  });

  it("stores a skipped list at the limits unchanged", async function () {
    await anonymous();
    var sent = [];
    for (var i = 0; i < 50; i++) sent.push({ path: "p".repeat(497) + String(i).padStart(3, "0"), reason: "r".repeat(100) });
    var res = await dropInit({ uploaderName: "C", fileCount: 0, skippedCount: 50, skippedFiles: sent });
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(bundlesRepo.findById(res.json.bundleId).skippedFiles, sent);
  });
});

describe("allowed emails", function () {
  function addresses(n) {
    var out = [];
    for (var i = 0; i < n; i++) out.push("person" + i + "@example.com");
    return out;
  }

  it("stores 100 addresses", async function () {
    await anonymous();
    var res = await dropInit({ uploaderName: "C", fileCount: 1, allowedEmails: addresses(100).join(", ") });
    assert.strictEqual(res.status, 200);
    var bundle = bundlesRepo.findById(res.json.bundleId);
    assert.strictEqual(bundle.allowedEmails.split(",").length, 100);
    assert.strictEqual(bundle.accessMode, "email");
  });

  it("refuses 101 addresses", async function () {
    await anonymous();
    var res = await dropInit({ uploaderName: "C", fileCount: 1, allowedEmails: addresses(101).join(",") });
    assert.strictEqual(res.status, 400);
    assert.strictEqual(detail(res), "At most 100 email addresses can be allowed.");
  });

  it("refuses an invalid address instead of dropping it from the list", async function () {
    await anonymous();
    var res = await dropInit({ uploaderName: "C", fileCount: 1, allowedEmails: "alice@example.com, not-an-email" });
    assert.strictEqual(res.status, 400);
    assert.strictEqual(detail(res), "Allowed email 2 is not a valid address.");
  });

  it("refuses a list whose only address is invalid instead of creating an open bundle", async function () {
    await anonymous();
    var res = await dropInit({ uploaderName: "C", fileCount: 1, allowedEmails: "alice@example" });
    assert.strictEqual(res.status, 400);
    assert.strictEqual(detail(res), "Allowed email 1 is not a valid address.");
  });
});

describe("stash init fields", function () {
  var slug = "caps-stash";

  before(async function () {
    var vault = require(path.join(root, "lib", "vault"));
    var { hashEmail } = require(path.join(root, "lib", "crypto"));
    db.users.insert({
      email: vault.seal("capsadmin@test.com"), emailHash: hashEmail("capsadmin@test.com"),
      displayName: vault.seal("Caps Admin"), passwordHash: await b.auth.password.hash("adminpass123"),
      authType: "local", role: "admin", status: "active", createdAt: new Date().toISOString(),
    });
    client.clearCookies();
    await client.initApiKey();
    testServer.resetAllRateLimits();
    var login = await client.post("/auth/login", { json: { email: "capsadmin@test.com", password: "adminpass123" } });
    assert.strictEqual(login.json.success, true, "admin login should succeed");
    var created = await client.post("/admin/stash/create", { json: { name: "Caps", slug: slug } });
    assert.strictEqual(created.status, 200, JSON.stringify(created.json));
  });

  it("refuses a fileCount that is not a whole number", async function () {
    await anonymous();
    var res = await client.post("/stash/" + slug + "/init", { json: { fileCount: "x".repeat(100000), skippedCount: 0, skippedFiles: [] } });
    assert.strictEqual(res.status, 400);
    assert.strictEqual(detail(res), "fileCount must be a whole number.");
  });

  it("keeps the first 50 skipped entries", async function () {
    await anonymous();
    var sent = [];
    for (var i = 0; i < 200; i++) sent.push({ path: "f" + i + ".exe", reason: ".exe not allowed" });
    var res = await client.post("/stash/" + slug + "/init", { json: { fileCount: 1, skippedCount: 200, skippedFiles: sent } });
    assert.strictEqual(res.status, 200, JSON.stringify(res.json));
    assert.deepStrictEqual(bundlesRepo.findById(res.json.bundleId).skippedFiles, sent.slice(0, 50));
  });
});

describe("login email", function () {
  var memberEmail = "caps-member@test.com";

  before(async function () { await signUp(memberEmail); });

  it("answers an overlong or malformed email exactly like a wrong password", async function () {
    await anonymous();
    var wrong = await client.post("/auth/login", { json: { email: memberEmail, password: "wrong-password" } });
    assert.strictEqual(wrong.status, 401);
    var emails = [
      "a".repeat(243) + "@example.com",
      "a".repeat(200000) + "@example.com",
      "user\r\n@example.com",
    ];
    for (var i = 0; i < emails.length; i++) {
      var res = await client.post("/auth/login", { json: { email: emails[i], password: "wrong-password" } });
      assert.strictEqual(res.status, wrong.status, "status for email " + i);
      assert.deepStrictEqual(res.json, wrong.json, "body for email " + i);
    }
  });

  it("writes no address longer than 254 characters into the audit log", async function () {
    await anonymous();
    var longEmail = "b".repeat(200000) + "@example.com";
    var res = await client.post("/auth/login", { json: { email: longEmail, password: "wrong-password" } });
    assert.strictEqual(res.status, 401);
    var rows = auditRows("login_failed_no_account");
    rows.forEach(function (e) {
      assert.ok(!e.targetEmail || e.targetEmail.length <= 254, "targetEmail of " + (e.targetEmail || "").length + " characters");
    });
    var row = rows.filter(function (e) { return e.details === "Unusable email (" + longEmail.length + " characters)"; })[0];
    assert.ok(row, "the attempt is audited with the length of the address");
    assert.strictEqual(row.targetEmail, undefined);
  });

  it("runs the same password check for an unusable email as for an unknown one", async function () {
    await anonymous();
    var original = b.auth.password.verify;
    var calls = 0;
    b.auth.password.verify = function () { calls++; return original.apply(this, arguments); };
    try {
      await client.post("/auth/login", { json: { email: "nobody-here@example.com", password: "wrong-password" } });
      var unknownCalls = calls;
      calls = 0;
      await client.post("/auth/login", { json: { email: "c".repeat(300) + "@example.com", password: "wrong-password" } });
      assert.strictEqual(unknownCalls, 1);
      assert.strictEqual(calls, unknownCalls);
    } finally {
      b.auth.password.verify = original;
    }
  });

  it("signs in with a 254-character address", async function () {
    var longest = "d".repeat(242) + "@example.com";
    assert.strictEqual(longest.length, 254);
    await signUp(longest);
    client.clearCookies();
    await client.initApiKey();
    var res = await client.post("/auth/login", { json: { email: longest, password: "password123" } });
    assert.strictEqual(res.status, 200, JSON.stringify(res.json));
    assert.strictEqual(res.json.success, true);
  });
});

describe("uploaded file name", function () {
  function uploadedAudit(bundleId) {
    var row = auditRows("bundle_file_uploaded", bundleId)[0];
    assert.ok(row, "the upload is audited");
    return JSON.parse(row.details).file;
  }

  // The multipart parser cuts a part's file name to 255 characters, but it
  // keeps < > and ', which sanitizeFilename removes from a stored name.
  it("a single-file upload audits the sanitized name the file row stores", async function () {
    await anonymous();
    var init = await dropInit({ uploaderName: "C", fileCount: 1 });
    assert.strictEqual(init.status, 200);
    var name = "<report>'s.txt";
    var res = await client.uploadFile("/drop/file/" + init.json.bundleId, "file", name, "hello file", { relativePath: "x.txt" });
    assert.strictEqual(res.status, 200, JSON.stringify(res.json));
    var logged = uploadedAudit(init.json.bundleId);
    assert.strictEqual(logged, "reports.txt");
    assert.strictEqual(filesRepo.findAll({ bundleId: init.json.bundleId })[0].originalName, logged);
  });

  // The chunked path reads the file name from a form field of up to 1 MiB.
  it("a chunked upload audits the sanitized name the file row stores", async function () {
    var longName = "A".repeat(3000) + ".txt";
    await anonymous();
    var init = await dropInit({ uploaderName: "C", fileCount: 1 });
    assert.strictEqual(init.status, 200);
    var res = await client.uploadFile("/drop/chunk/" + init.json.bundleId, "file", "blob", "hello chunk", {
      chunkIndex: "0", totalChunks: "1", fileId: "capschunk1", filename: longName, relativePath: "x.txt", mimeType: "text/plain",
    });
    assert.strictEqual(res.status, 200, JSON.stringify(res.json));
    var logged = uploadedAudit(init.json.bundleId);
    assert.strictEqual(logged, sanitizeFilename(longName));
    assert.ok(logged.length <= 255);
    assert.strictEqual(filesRepo.findAll({ bundleId: init.json.bundleId })[0].originalName, logged);
  });
});

describe("upload notification emails", function () {
  it("receive a numeric skipped count and a list for a bundle row that holds text", async function () {
    await anonymous();
    var bundleService = require(path.join(root, "app", "domain", "uploads", "bundle.service"));
    var emailService = require(path.join(root, "app", "domain", "integrations", "email.service"));
    // initBundle stores the values it is given. A bundle row written before the
    // init routes validated these fields can hold the same values.
    var made = await bundleService.initBundle({
      uploaderName: "C", uploaderEmail: "uploader@example.com", fileCount: 1,
      skippedCount: "<a href=\"https://attacker.example/\">Review</a>", skippedFiles: "not a list",
    });
    var up = await client.uploadFile("/drop/file/" + made.bundleId, "file", "a.txt", "hello", { relativePath: "a.txt" });
    assert.strictEqual(up.status, 200, JSON.stringify(up.json));

    var seen = [];
    var originalConfirmation = emailService.sendUploaderConfirmation;
    var originalNotification = emailService.sendAdminNotification;
    emailService.sendUploaderConfirmation = function (data) { seen.push(data); return Promise.resolve(false); };
    emailService.sendAdminNotification = function (data) { seen.push(data); return Promise.resolve(false); };
    try {
      var fin = await client.post("/drop/finalize/" + made.bundleId, { json: { finalizeToken: made.finalizeToken } });
      assert.strictEqual(fin.status, 200, JSON.stringify(fin.json));
    } finally {
      emailService.sendUploaderConfirmation = originalConfirmation;
      emailService.sendAdminNotification = originalNotification;
    }
    assert.ok(seen.length > 0, "the finalize composed at least one email");
    seen.forEach(function (data) {
      assert.strictEqual(data.skippedCount, 0);
      assert.deepStrictEqual(data.skippedFiles, []);
    });
  });
});

describe("sync rename path", function () {
  var shareId = "capsrenameshare0001";

  before(async function () {
    var owner = await signUp("caps-rename@test.com");
    var bundle = bundlesRepo.create({ shareId: shareId, ownerId: owner._id, bundleType: "sync", status: "complete", createdAt: new Date().toISOString() });
    filesRepo.create({
      bundleId: bundle._id, bundleShareId: shareId, shareId: "capsrenamefile0001",
      originalName: "a.txt", relativePath: "a.txt", status: "complete", size: 1, createdAt: new Date().toISOString(),
    });
  });

  function rename(oldPath, newPath) {
    return client.post("/bundles/" + shareId + "/file/rename", { json: { oldRelativePath: oldPath, newRelativePath: newPath } });
  }

  it("refuses a new path longer than 500 characters", async function () {
    var res = await rename("a.txt", "a".repeat(250) + "/" + "b".repeat(246) + ".txt");
    assert.strictEqual(res.status, 400);
    assert.strictEqual(detail(res), "The new path is longer than 500 characters.");
  });

  it("refuses a raw path longer than 2000 characters before sanitizing it", async function () {
    var res = await rename("a.txt", "seg/".repeat(600));
    assert.strictEqual(res.status, 400);
    assert.strictEqual(detail(res), "The new path is longer than 500 characters.");
  });

  it("stores a 500-character path", async function () {
    var target = "a".repeat(249) + "/" + "b".repeat(246) + ".txt";
    assert.strictEqual(target.length, 500);
    var res = await rename("a.txt", target);
    assert.strictEqual(res.status, 200, JSON.stringify(res.json));
    assert.strictEqual(res.json.relativePath, target);
    var row = filesRepo.findAll({ bundleId: bundlesRepo.findByShareId(shareId)._id })[0];
    assert.strictEqual(row.relativePath, target);
  });
});

describe("vault fields", function () {
  function upload(over) {
    return client.post("/vault/upload", { json: Object.assign({
      ciphertext: bytes64(64), encapsulatedKey: bytes64(1568), iv: bytes64(24), filename: "caps.bin",
    }, over) });
  }

  before(async function () { await signUp("caps-vault@test.com"); });

  it("refuses a public key padded with text outside the base64 alphabet", async function () {
    var key = bytes64(1568);
    var res = await client.post("/vault/enable", { json: { publicKey: key.slice(0, 4) + "!".repeat(1000) + key.slice(4), mode: "passkey", seed: bytes64(64) } });
    assert.strictEqual(res.status, 400);
    assert.strictEqual(detail(res), "Invalid public key.");
  });

  it("refuses a seed padded with whitespace", async function () {
    var res = await client.post("/vault/enable", { json: { publicKey: bytes64(1568), mode: "passkey", seed: bytes64(64) + " ".repeat(1000) } });
    assert.strictEqual(res.status, 400);
    assert.strictEqual(detail(res), "The vault seed must be base64.");
  });

  it("stores a canonical public key unchanged", async function () {
    var key = bytes64(1568);
    var res = await client.post("/vault/enable", { json: { publicKey: key, mode: "passkey", seed: bytes64(64) } });
    assert.strictEqual(res.status, 200);
    var stored = usersRepo.findByEmail("caps-vault@test.com").vaultPublicKey;
    assert.strictEqual(stored, key);
    assert.strictEqual(b.safeBuffer.isCanonicalBase64(stored), true);
  });

  it("refuses an encapsulated key that is not 1568 bytes", async function () {
    var res = await upload({ encapsulatedKey: bytes64(64) });
    assert.strictEqual(res.status, 400);
    assert.strictEqual(detail(res), "The encapsulated key must be 1568 bytes of base64.");
  });

  it("refuses an IV that is not 24 bytes", async function () {
    var res = await upload({ iv: bytes64(12) });
    assert.strictEqual(res.status, 400);
    assert.strictEqual(detail(res), "The IV must be 24 bytes of base64.");
  });

  it("refuses a batch ID longer than 64 characters", async function () {
    var res = await upload({ batchId: "b".repeat(65) });
    assert.strictEqual(res.status, 400);
    assert.strictEqual(detail(res), "The batch ID must be 1 to 64 letters, digits, hyphens or underscores.");
  });

  it("stores an unusable MIME type as application/octet-stream", async function () {
    var res = await upload({ mimeType: "m".repeat(300) });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(filesRepo.findByShareId(res.json.shareId).mimeType, "application/octet-stream");
  });

  it("stores a browser upload at the limits unchanged", async function () {
    var key = bytes64(1568);
    var iv = bytes64(24);
    var batch = crypto.randomUUID();
    var mime = "application/vnd.openxmlformats-officedocument.presentationml.presentation";
    var res = await upload({ encapsulatedKey: key, iv: iv, batchId: batch, mimeType: mime });
    assert.strictEqual(res.status, 200);
    var row = filesRepo.findByShareId(res.json.shareId);
    assert.strictEqual(row.vaultEncapsulatedKey, key);
    assert.strictEqual(row.vaultIv, iv);
    assert.strictEqual(row.vaultBatchId, batch);
    assert.strictEqual(row.mimeType, mime);
  });

  it("refuses a rotation whose new key or re-encrypted data has the wrong format", async function () {
    var list = await client.get("/vault/files");
    var files = list.json.files.map(function (f) {
      return { shareId: f.shareId, ciphertext: bytes64(64), encapsulatedKey: bytes64(1568), iv: bytes64(24) };
    });
    assert.ok(files.length > 0, "the vault holds a file to rotate");
    var padded = bytes64(1568);
    var badKey = await client.post("/vault/rotate", { json: {
      newPublicKey: padded.slice(0, 4) + "!".repeat(1000) + padded.slice(4), newMode: "passkey", newSeed: bytes64(64), files: files,
    } });
    assert.strictEqual(badKey.status, 400);
    assert.strictEqual(detail(badKey), "Invalid new public key.");
    files[0].encapsulatedKey = bytes64(64);
    var badFile = await client.post("/vault/rotate", { json: { newPublicKey: bytes64(1568), newMode: "passkey", newSeed: bytes64(64), files: files } });
    assert.strictEqual(badFile.status, 400);
    assert.match(detail(badFile), /has the wrong format\.$/);
  });
});

describe("passkey transports", function () {
  var original;

  before(function () {
    original = b.auth.passkey.verifyRegistration;
    b.auth.passkey.verifyRegistration = async function () {
      return { verified: true, registrationInfo: {
        credential: { id: crypto.randomBytes(16).toString("base64url"), publicKey: new Uint8Array(77), counter: 0 },
        credentialDeviceType: "singleDevice", credentialBackedUp: false,
      } };
    };
  });

  after(function () { b.auth.passkey.verifyRegistration = original; });

  async function register(transports) {
    var user = await signUp("caps-passkey-" + crypto.randomBytes(4).toString("hex") + "@test.com");
    var opts = await client.post("/passkey/register/options", { json: {} });
    assert.strictEqual(opts.status, 200, JSON.stringify(opts.json));
    var res = await client.post("/passkey/register/verify", { json: { id: "x", response: { transports: transports } } });
    assert.strictEqual(res.status, 200, JSON.stringify(res.json));
    return credentialsRepo.findByUser(user._id)[0].transports;
  }

  it("keeps the distinct transport hints and drops everything else", async function () {
    var stored = await register(["usb", "internal", "usb", "x".repeat(100000), 5, "HYBRID"].concat(new Array(50).fill("nfc")));
    assert.strictEqual(stored, JSON.stringify(["usb", "internal", "nfc"]));
  });

  it("stores the browser's transport list unchanged", async function () {
    var stored = await register(["ble", "hybrid", "internal", "nfc", "smart-card", "usb"]);
    assert.strictEqual(stored, JSON.stringify(["ble", "hybrid", "internal", "nfc", "smart-card", "usb"]));
  });
});
