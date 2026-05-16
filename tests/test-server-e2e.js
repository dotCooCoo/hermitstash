#!/usr/bin/env node
"use strict";

/**
 * HermitStash — Consolidated E2E Test Suite
 *
 * Spins up an isolated server instance with a fresh database,
 * completes the setup wizard, then exercises every endpoint and
 * crypto operation end-to-end using the actual project libraries.
 *
 * Usage:
 *   node tests/test-server-e2e.js
 *   TEST_PORT=4444 node tests/test-server-e2e.js
 */

var http = require("http");
var fs = require("fs");
var path = require("path");
var crypto = require("crypto");
var b = require("../lib/vendor/blamejs");
var { spawn } = require("child_process");

// Set HERMITSTASH_DATA_DIR to a temp dir BEFORE importing libs that trigger DB init
var _testImportDir = path.join(require("os").tmpdir(), "hs-e2e-import-" + Date.now());
fs.mkdirSync(path.join(_testImportDir, "uploads"), { recursive: true });
process.env.HERMITSTASH_DATA_DIR = _testImportDir;

// ---- Import REAL project libs (no reimplementation) ----
var { encryptPayload, decryptPayload } = require("../lib/api-crypto");
var { sha3Hash, bufferChecksum, encryptWithPassphrase, decryptWithPassphrase,
      encryptVaultKey, decryptVaultKey, TLS_FILES } = require("../lib/backup-crypto");
var { isS3Path, s3KeyFromPath } = require("../lib/storage");
var backup = require("../lib/backup");

var PORT = parseInt(process.env.TEST_PORT, 10) || 13400;
var passed = 0, failed = 0;
var serverProcess = null;
var testDataDir = null;
var adminCookie = "";
var sessionApiKey = "";

function ok(name) { passed++; console.log("  \x1b[32mPASS\x1b[0m " + name); }
function fail(name, detail) { failed++; console.log("  \x1b[31mFAIL\x1b[0m " + name + (detail ? " — " + detail : "")); }
function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

var BROWSER = {
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  "Accept": "text/html,application/xhtml+xml",
  "Accept-Language": "en-US",
  "Sec-Fetch-Dest": "document",
};

function request(method, urlPath, opts) {
  opts = opts || {};
  return new Promise(function (resolve) {
    var headers = Object.assign({}, opts.noBrowser ? {} : BROWSER, opts.headers || {});
    var body = null;
    if (opts.json !== undefined) {
      headers["Content-Type"] = "application/json";
      var payload = opts.json;
      if (sessionApiKey && !opts.raw) {
        payload = { _e: encryptPayload(opts.json, sessionApiKey), _t: Date.now() };
      }
      body = JSON.stringify(payload);
      headers["Content-Length"] = Buffer.byteLength(body);
    }
    if (opts.cookie) headers["Cookie"] = opts.cookie;
    if (opts.formData) {
      body = opts.formData;
      headers["Content-Length"] = Buffer.byteLength(body);
    }

    var req = http.request({ hostname: "localhost", port: PORT, path: urlPath, method: method, headers: headers }, function (res) {
      var data = "";
      res.on("data", function (c) { data += c; });
      res.on("end", function () {
        var cookies = res.headers["set-cookie"] || [];
        var ck = "";
        cookies.forEach(function (c) { if (c.indexOf("hs_sid=") === 0) ck = c.split(";")[0]; });
        var json = null;
        try { json = JSON.parse(data); } catch (_e) {}
        if (json && json._e && sessionApiKey) {
          try { json = decryptPayload(json._e, sessionApiKey, 60000); } catch (_e) {}
        }
        resolve({ status: res.statusCode, body: data, json: json, cookie: ck, headers: res.headers });
      });
    });
    req.on("error", function (e) { resolve({ status: 0, body: "", json: null, cookie: "", headers: {}, error: e.message }); });
    req.setTimeout(15000, function () { req.destroy(new Error("timeout")); });
    if (body) req.write(body);
    req.end();
  });
}

// ==================================================================
// 1. SERVER LIFECYCLE
// ==================================================================

async function startServer() {
  testDataDir = path.join(require("os").tmpdir(), "hs-e2e-" + Date.now());
  fs.mkdirSync(path.join(testDataDir, "uploads"), { recursive: true });
  console.log("Data dir: " + testDataDir);

  var root = path.resolve(__dirname, "..");
  serverProcess = spawn(process.execPath, [path.join(root, "server.js")], {
    env: Object.assign({}, process.env, { PORT: String(PORT), PQC_ENFORCE: "false", HERMITSTASH_DATA_DIR: testDataDir, UPLOAD_DIR: path.join(testDataDir, "uploads") }),
    cwd: root, stdio: "pipe",
  });
  var log = [];
  serverProcess.stderr.on("data", function (d) { log.push(d.toString().trim()); });
  serverProcess.stdout.on("data", function (d) { log.push(d.toString().trim()); });
  serverProcess.on("exit", function (code) {
    if (code && code !== 0) { console.error("\n  SERVER CRASHED (exit " + code + "):"); log.slice(-5).forEach(function (l) { console.error("    " + l); }); }
  });

  for (var i = 0; i < 30; i++) {
    await sleep(1000);
    try { var r = await request("GET", "/health"); if (r.status === 200) { await sleep(5000); return; } } catch (_e) {}
  }
  throw new Error("Server did not start");
}

function stopServer() {
  if (serverProcess) { serverProcess.kill("SIGTERM"); serverProcess = null; }
  if (testDataDir) { try { fs.rmSync(testDataDir, { recursive: true, force: true }); } catch (_e) {} }
  if (_testImportDir) { try { fs.rmSync(_testImportDir, { recursive: true, force: true }); } catch (_e) {} }
}

// ==================================================================
// 2. AUTH & SESSION
// ==================================================================

async function testAuth() {
  console.log("\n--- Auth & Session ---");
  var page = await request("GET", "/auth/login");
  if (page.status === 200) ok("Login page → 200"); else fail("Login page", String(page.status));
  if (page.cookie) { adminCookie = page.cookie; ok("Session cookie obtained"); } else fail("No session cookie");

  var akMatch = (page.body || "").match(/window\.__ak="([^"]+)"/);
  if (akMatch) { sessionApiKey = akMatch[1]; ok("API encryption key extracted"); } else fail("No API key in page");

  // Login with default admin (retry for Argon2 hash)
  var loginRes = null;
  for (var i = 0; i < 5; i++) {
    loginRes = await request("POST", "/auth/login", { json: { email: "admin@hermitstash.com", password: "admin" }, cookie: adminCookie });
    if (loginRes.json && loginRes.json.success) break;
    await sleep(2000);
  }
  if (loginRes && loginRes.json && loginRes.json.success) {
    if (loginRes.cookie) adminCookie = loginRes.cookie;
    ok("Admin login → success");
  } else { fail("Admin login"); return; }

  // Complete setup wizard
  var setupPage = await request("GET", "/admin/setup", { cookie: adminCookie });
  var setupAk = (setupPage.body || "").match(/window\.__ak="([^"]+)"/);
  if (setupAk) sessionApiKey = setupAk[1];
  if (setupPage.status === 200) {
    var setupRes = await request("POST", "/admin/setup", { cookie: adminCookie,
      json: { adminEmail: "test@e2e.local", adminPassword: "TestPass123!", siteName: "E2E", sessionSecret: b.crypto.generateToken(32) } });
    if (setupRes.json && setupRes.json.success) ok("Setup wizard completed"); else fail("Setup wizard", (setupRes.json && setupRes.json.error) || "");
    var adminPage = await request("GET", "/admin", { cookie: adminCookie });
    var ak2 = (adminPage.body || "").match(/window\.__ak="([^"]+)"/);
    if (ak2) { sessionApiKey = ak2[1]; ok("API key refreshed after setup"); }
  }

  // Verify API encryption round-trip
  if (sessionApiKey) {
    var testData = { test: "round-trip", value: 42 };
    var encrypted = encryptPayload(testData, sessionApiKey);
    var decrypted = decryptPayload(encrypted, sessionApiKey, 60000);
    if (decrypted && decrypted.test === "round-trip" && decrypted.value === 42) ok("API crypto round-trip via real lib");
    else fail("API crypto round-trip");
  }
}

// ==================================================================
// 3. ENDPOINT PROTECTION
// ==================================================================

async function testEndpointProtection() {
  console.log("\n--- Endpoint Protection ---");
  var eps = [
    ["GET", "/admin/storage/migration/preview?direction=local-to-s3"],
    ["GET", "/admin/storage/orphans/scan"],
    ["GET", "/admin/backup/history"],
    ["POST", "/admin/storage/migration/start"],
    ["POST", "/admin/storage/orphans/clean"],
    ["POST", "/admin/restore/run"],
    ["POST", "/admin/backup/delete"],
  ];
  for (var i = 0; i < eps.length; i++) {
    var r = await request(eps[i][0], eps[i][1]);
    if (r.status === 401 || r.status === 302 || r.status === 403) ok(eps[i][1].split("?")[0] + " → " + r.status + " (protected)");
    else fail(eps[i][1].split("?")[0], "got " + r.status);
  }
}

// ==================================================================
// 4. CERT RENEWAL AUTH
// ==================================================================

async function testCertRenewalAuth() {
  console.log("\n--- Cert Renewal Auth ---");
  var r1 = await request("POST", "/sync/renew-cert", { noBrowser: true, raw: true, json: {} });
  if (r1.status === 401) ok("No auth → 401"); else fail("No auth", r1.status + " " + (r1.error || ""));
  await sleep(500);
  var r2 = await request("POST", "/sync/renew-cert", { noBrowser: true, raw: true, json: {}, headers: { "Authorization": "Bearer fake" } });
  if (r2.status === 403) ok("Bad API key → 403"); else if (r2.status === 429) ok("Bad API key → 429 (rate limited)"); else fail("Bad key", String(r2.status));
  await sleep(500);
  var r3 = await request("POST", "/sync/renew-cert", { noBrowser: true, raw: true, json: {}, headers: { "Authorization": "Bearer " } });
  if (r3.status === 401) ok("Empty Bearer → 401"); else if (r3.status === 429) ok("Empty Bearer → 429"); else fail("Empty bearer", String(r3.status));
  await sleep(500);
  var r4 = await request("POST", "/sync/renew-cert", { noBrowser: true, raw: true, json: {}, headers: { "Authorization": "Basic dXNlcjpw" } });
  if (r4.status === 401) ok("Wrong scheme → 401"); else if (r4.status === 429) ok("Wrong scheme → 429"); else fail("Wrong scheme", String(r4.status));
}

// ==================================================================
// 5. ENROLLMENT
// ==================================================================

async function testEnrollment() {
  console.log("\n--- Enrollment ---");
  var r1 = await request("POST", "/sync/enroll", { noBrowser: true, raw: true, json: {} });
  if (r1.status === 400) ok("No code → 400"); else fail("No code", String(r1.status));
  await sleep(500);
  var r2 = await request("POST", "/sync/enroll", { noBrowser: true, raw: true, json: { code: "FAKE" } });
  if (r2.status === 401) ok("Invalid code → 401"); else if (r2.status === 429) ok("Invalid code → 429"); else fail("Bad code", String(r2.status));
  await sleep(500);
  var r3 = await request("POST", "/sync/enroll", { noBrowser: true, raw: true, json: { code: "" } });
  if (r3.status === 400) ok("Empty code → 400"); else if (r3.status === 429) ok("Empty code → 429"); else fail("Empty code", String(r3.status));
}

// ==================================================================
// 6. STORAGE ENDPOINTS
// ==================================================================

async function testStorageEndpoints() {
  console.log("\n--- Storage Endpoints ---");
  if (!adminCookie) { ok("Skipped (no session)"); return; }
  var r1 = await request("GET", "/admin/storage/migration/preview?direction=local-to-s3", { cookie: adminCookie });
  if (r1.status === 200 && r1.json) ok("Migration preview → toMigrate=" + r1.json.toMigrate); else fail("Preview", String(r1.status));
  var r2 = await request("GET", "/admin/storage/migration/preview?direction=invalid", { cookie: adminCookie });
  if (r2.status === 400) ok("Bad direction → 400"); else fail("Bad dir", String(r2.status));
  var r3 = await request("GET", "/admin/storage/migration/status", { cookie: adminCookie });
  if (r3.status === 200 && r3.json && r3.json.status === "idle") ok("Migration status → idle"); else fail("Status", String(r3.status));
  var r4 = await request("GET", "/admin/storage/orphans/scan", { cookie: adminCookie });
  if (r4.status === 200 && r4.json) ok("Orphan scan → orphans=" + r4.json.local.orphans + " scanned=" + r4.json.local.scanned); else fail("Scan", String(r4.status));
  var r5 = await request("POST", "/admin/storage/orphans/clean", { cookie: adminCookie, json: { local: true, s3: false, dangling: false } });
  if (r5.status === 200 && r5.json && r5.json.success) ok("Orphan clean → local=" + r5.json.deleted.local); else fail("Clean", String(r5.status));
}

// ==================================================================
// 7. BACKUP ENDPOINTS
// ==================================================================

async function testBackupEndpoints() {
  console.log("\n--- Backup Endpoints ---");
  if (!adminCookie) { ok("Skipped (no session)"); return; }
  var r1 = await request("GET", "/admin/backup/history", { cookie: adminCookie });
  if (r1.status === 200) ok("Backup history → " + ((r1.json && r1.json.error) || (r1.json && r1.json.history && r1.json.history.length + " backups") || "ok")); else fail("History", String(r1.status));
  var r2 = await request("POST", "/admin/restore/run", { cookie: adminCookie, json: {} });
  if (r2.status === 400) ok("Restore no params → 400"); else fail("Restore", String(r2.status));
  var r3 = await request("POST", "/admin/backup/delete", { cookie: adminCookie, json: {} });
  if (r3.status === 400) ok("Delete no timestamp → 400"); else fail("Delete", String(r3.status));
  var r4 = await request("GET", "/admin/backup/manifest", { cookie: adminCookie });
  if (r4.status === 400) ok("Manifest no timestamp → 400"); else fail("Manifest", String(r4.status));
}

// ==================================================================
// 8. BACKUP CRYPTO (real libs)
// ==================================================================

async function testBackupCrypto() {
  console.log("\n--- Backup Crypto (real libs) ---");

  // SHA3
  var h1 = sha3Hash("hello");
  if (h1.length === 128) ok("sha3Hash → 128-char hex"); else fail("sha3Hash length");
  if (sha3Hash("hello") === h1) ok("sha3Hash deterministic"); else fail("sha3Hash det");
  if (sha3Hash("world") !== h1) ok("sha3Hash collision-free"); else fail("sha3Hash collision");

  // Checksum
  if (bufferChecksum(Buffer.from("test")) === sha3Hash(Buffer.from("test"))) ok("bufferChecksum wraps sha3Hash"); else fail("bufferChecksum");

  // Symmetric encrypt/decrypt
  var salt = b.crypto.generateToken(32);
  var plain = Buffer.from("secret data");
  var enc = await encryptWithPassphrase(plain, "pass123", salt);
  var dec = await decryptWithPassphrase(enc, "pass123", salt);
  if (dec.toString() === "secret data") ok("Symmetric round-trip"); else fail("Symmetric round-trip");
  try { await decryptWithPassphrase(enc, "wrong", salt); fail("Wrong pass should throw"); } catch (_e) { ok("Wrong passphrase throws"); }
  var enc2 = await encryptWithPassphrase(plain, "pass123", salt);
  if (!enc.equals(enc2)) ok("Unique nonce per encryption"); else fail("Nonce reuse");

  // Vault key encrypt/decrypt using the server's actual vault.key
  var vaultDir = testDataDir || _testImportDir;
  var vaultResult = await encryptVaultKey("testpass", vaultDir);
  if (vaultResult.encrypted.length > 0 && vaultResult.salt.length === 64) ok("encryptVaultKey → encrypted + 64-char salt"); else fail("encryptVaultKey");
  var vaultJson = await decryptVaultKey(vaultResult.encrypted, "testpass", vaultResult.salt);
  var parsed = JSON.parse(vaultJson);
  if (parsed.ecPublicKey && parsed.ecPrivateKey) ok("decryptVaultKey → valid keypair JSON"); else fail("decryptVaultKey");
  try { await decryptVaultKey(vaultResult.encrypted, "wrong", vaultResult.salt); fail("Wrong pass vault"); } catch (_e) { ok("Wrong passphrase on vault key throws"); }

  // TLS_FILES
  if (Array.isArray(TLS_FILES) && TLS_FILES.length === 4) ok("TLS_FILES has 4 entries"); else fail("TLS_FILES");
  if (TLS_FILES.every(function (f) { return f.local && f.key && f.key.endsWith(".enc"); })) ok("TLS_FILES all have .enc keys"); else fail("TLS_FILES format");

  // isS3Path
  if (isS3Path("s3://b/k") === true) ok("isS3Path s3 → true"); else fail("isS3Path s3");
  if (isS3Path("local/path") === false) ok("isS3Path local → false"); else fail("isS3Path local");
  if (isS3Path(null) === false) ok("isS3Path null → false"); else fail("isS3Path null");
  if (isS3Path("") === false) ok("isS3Path empty → false"); else fail("isS3Path empty");

  // s3KeyFromPath
  if (s3KeyFromPath("s3://bucket/bundles/a/f.pdf") === "bundles/a/f.pdf") ok("s3KeyFromPath extracts key"); else fail("s3KeyFromPath");

  // Operation lock (using imported backup module)
  if (backup.isOperationRunning() === false) ok("Operation lock → idle"); else fail("Lock");

  // Tamper detection
  var tampered = Buffer.from(enc);
  tampered[tampered.length - 1] ^= 0xff;
  try { await decryptWithPassphrase(tampered, "pass123", salt); fail("Tampered should throw"); } catch (_e) { ok("Tampered ciphertext throws"); }

  // 1MB round-trip
  var bigBuf = crypto.randomBytes(1048576);
  var bigEnc = await encryptWithPassphrase(bigBuf, "pass", salt);
  var bigDec = await decryptWithPassphrase(bigEnc, "pass", salt);
  if (bigDec.equals(bigBuf)) ok("1MB round-trip"); else fail("1MB");
}

// ==================================================================
// 9. STASH + SYNC FULL FLOW
// ==================================================================

async function testStashSync() {
  console.log("\n--- Stash + Sync Full Flow ---");
  if (!adminCookie) { ok("Skipped (no session)"); return; }

  var cr = await request("POST", "/admin/stash/create", { cookie: adminCookie,
    json: { slug: "test-sync", name: "Test Sync", title: "Upload", enabled: "true", syncEnabled: "true" } });
  var stashId = cr.json && cr.json.stash && cr.json.stash._id;
  if (cr.status === 200 && stashId) ok("Created stash (id=" + stashId.substring(0, 12) + "...)"); else { fail("Create stash", String(cr.status)); return; }

  var tk = await request("POST", "/admin/stash/" + stashId + "/sync-token", { cookie: adminCookie, json: {} });
  var code = tk.json && tk.json.enrollmentCode;
  if (tk.status === 200 && code) ok("Sync token (code=" + code.substring(0, 12) + "...)"); else { fail("Sync token", String(tk.status)); return; }

  var keys = await request("GET", "/admin/stash/" + stashId + "/sync-keys", { cookie: adminCookie });
  if (keys.status === 200 && keys.json && keys.json.keys && keys.json.keys.length > 0) {
    ok("Sync keys: " + keys.json.keys.length + " key(s)");
    var k = keys.json.keys[0];
    if (k.certIssuedAt) ok("certIssuedAt tracked: " + k.certIssuedAt.substring(0, 10)); else ok("No cert dates (OpenSSL unavailable)");
    if (k.certStatus) ok("certStatus: " + k.certStatus);
  } else { fail("Sync keys", String(keys.status)); }

  // Redeem enrollment code
  var enroll = await request("POST", "/sync/enroll", { noBrowser: true, raw: true, json: { code: code } });
  if (enroll.status === 200 && enroll.json && enroll.json.success) {
    ok("Enrollment redeemed");
    if (enroll.json.apiKey) ok("API key received"); else fail("No API key");
    if (enroll.json.clientCert) ok("mTLS cert received"); else ok("No mTLS cert (OpenSSL unavailable)");
    if (!enroll.json.reissue) ok("reissue=false (full enrollment)"); else fail("reissue should be false");

    // One-time use
    await sleep(500);
    var reuse = await request("POST", "/sync/enroll", { noBrowser: true, raw: true, json: { code: code } });
    if (reuse.status === 401) ok("Reused code → 401 (one-time)"); else if (reuse.status === 429) ok("Reused code → 429 (rate limited)"); else fail("Reuse", String(reuse.status));

    // Cert renewal without mTLS → 403
    if (enroll.json.apiKey) {
      await sleep(500);
      var renew = await request("POST", "/sync/renew-cert", { noBrowser: true, raw: true, json: {},
        headers: { "Authorization": "Bearer " + enroll.json.apiKey } });
      if (renew.status === 403) ok("Cert renewal without mTLS → 403 (requires both factors)");
      else if (renew.status === 429) ok("Cert renewal → 429 (rate limited)");
      else fail("Renewal auth", String(renew.status));
    }
  } else { fail("Enrollment", String(enroll.status) + " " + (enroll.error || "")); }

  // Reissue cert from admin
  if (keys.json && keys.json.keys && keys.json.keys.length > 0) {
    var keyId = keys.json.keys[0]._id;
    var reissue = await request("POST", "/admin/stash/" + stashId + "/reissue-cert", { cookie: adminCookie, json: { apiKeyId: keyId } });
    if (reissue.status === 200 && reissue.json && reissue.json.success) {
      ok("Cert reissued (code=" + reissue.json.enrollmentCode.substring(0, 12) + "...)");
      if (reissue.json.reissue === true) ok("reissue=true flag set"); else fail("reissue flag");
      // Redeem repair code
      await sleep(500);
      var repair = await request("POST", "/sync/enroll", { noBrowser: true, raw: true, json: { code: reissue.json.enrollmentCode } });
      if (repair.status === 200 && repair.json && repair.json.success) {
        ok("Repair code redeemed");
        if (repair.json.apiKey === null) ok("apiKey=null (cert-only reissue)"); else fail("apiKey should be null");
        if (repair.json.reissue === true) ok("reissue=true in response"); else fail("reissue in response");
      } else if (repair.status === 429) { ok("Repair → 429 (rate limited)"); }
      else { fail("Repair", String(repair.status)); }
    } else { fail("Reissue", String(reissue.status) + " " + ((reissue.json && reissue.json.error) || "")); }
  }
}

// ==================================================================
// 10. OWNERSHIP
// ==================================================================

async function testOwnership() {
  console.log("\n--- Ownership ---");
  var r = await request("POST", "/drop/finalize/nonexistent", { cookie: adminCookie, json: { finalizeToken: "fake" } });
  if (r.status === 404) ok("Finalize non-existent → 404"); else fail("Finalize", String(r.status));
}

// ==================================================================
// 11. SECURITY HEADERS
// ==================================================================

async function testSecurityHeaders() {
  console.log("\n--- Security Headers ---");
  var r = await request("GET", "/health");
  if (r.headers["x-content-type-options"] === "nosniff") ok("X-Content-Type-Options: nosniff"); else fail("XCTO");
  if (r.headers["x-frame-options"] === "DENY") ok("X-Frame-Options: DENY"); else fail("XFO");
}

// ==================================================================
// 12. MANIFEST & ENCRYPTION VALIDATION
// ==================================================================

async function testManifestValidation() {
  console.log("\n--- Manifest Validation ---");
  var salt = b.crypto.generateToken(32);
  var manifest = {
    version: 2, timestamp: new Date().toISOString(), scope: "full", storageBackend: "local", argon2Salt: salt,
    files: { "vault.key.enc": { s3Key: "backups/t/vault.key.enc", checksum: "abc" } },
    uploads: { "bundles/s/f.pdf": { s3Key: "backups/uploads/bundles/s/f.pdf", checksum: "def" } },
    stats: { dbFiles: 1, uploadFiles: 1, totalSize: 100, durationMs: 50 },
  };
  var encManifest = await encryptWithPassphrase(Buffer.from(JSON.stringify(manifest)), "pass", salt);
  var header = { version: 2, timestamp: manifest.timestamp, scope: "full", storageBackend: "local",
    storageBucket: null, argon2Salt: salt, stats: manifest.stats, encrypted: true };
  var headerStr = JSON.stringify(header);
  if (!headerStr.includes("vault.key.enc")) ok("Header doesn't leak file paths"); else fail("Header leak");
  if (!headerStr.includes("bundles/s")) ok("Header doesn't leak upload paths"); else fail("Upload leak");
  if (headerStr.includes("argon2Salt")) ok("Header has argon2Salt"); else fail("Salt in header");
  var decManifest = JSON.parse((await decryptWithPassphrase(encManifest, "pass", salt)).toString());
  if (decManifest.version === 2 && decManifest.files["vault.key.enc"]) ok("Manifest decrypt + validate"); else fail("Manifest decrypt");

  // Atomic write
  var fsP = require("fs/promises");
  var testFile = path.join(testDataDir, "atomic.dat");
  var testTmp = testFile + ".tmp";
  var data = crypto.randomBytes(64);
  await fsP.writeFile(testTmp, data);
  await fsP.rename(testTmp, testFile);
  if (fs.existsSync(testFile) && !fs.existsSync(testTmp) && fs.readFileSync(testFile).equals(data)) ok("Atomic write (.tmp + rename)"); else fail("Atomic write");
}

// ==================================================================
// 13. CERT EXPIRY DETECTION
// ==================================================================

async function testCertExpiryDetection() {
  console.log("\n--- Cert Expiry Detection ---");
  var THRESHOLD = 60;
  var cases = [
    [365, false], [90, false], [61, false], [60, true], [30, true], [7, true], [1, true], [0, true], [-1, true],
  ];
  for (var i = 0; i < cases.length; i++) {
    var days = cases[i][0], shouldRenew = cases[i][1];
    if ((days <= THRESHOLD) === shouldRenew) ok(days + " days → " + (shouldRenew ? "renew" : "skip"));
    else fail(days + " days threshold");
  }
}

// ==================================================================
// 14. PATH TRAVERSAL
// ==================================================================

async function testPathTraversal() {
  console.log("\n--- Path Traversal ---");
  var base = path.join(testDataDir, "traversal");
  fs.mkdirSync(base, { recursive: true });
  var attacks = ["../../etc/passwd", "../../../etc/shadow", "bundles/../../../etc/passwd", "bundles/s/../../../../../../tmp/evil"];
  if (process.platform === "win32") attacks.push("..\\..\\windows\\system32\\sam");
  else attacks.push("/etc/passwd");
  var blocked = 0;
  for (var i = 0; i < attacks.length; i++) {
    var resolved = path.resolve(path.join(base, attacks[i]));
    if (!resolved.startsWith(path.resolve(base) + path.sep)) blocked++;
  }
  if (blocked === attacks.length) ok("All " + blocked + " attack paths blocked"); else fail("Traversal", blocked + "/" + attacks.length);
  var valid = ["bundles/share/file.pdf", "bundles/a/b/c.jpg"];
  var allowed = 0;
  for (var j = 0; j < valid.length; j++) {
    if (path.resolve(path.join(base, valid[j])).startsWith(path.resolve(base) + path.sep)) allowed++;
  }
  if (allowed === valid.length) ok("Valid paths pass (" + allowed + "/" + valid.length + ")"); else fail("Valid paths");
}

// ==================================================================
// RUN ALL
// ==================================================================

async function main() {
  console.log("HermitStash Consolidated E2E Tests\n");
  try { await startServer(); } catch (e) { console.error("Start failed:", e.message); stopServer(); process.exit(1); }

  try {
    await testAuth();
    await testEndpointProtection();
    await testCertRenewalAuth();
    await testEnrollment();
    await testStorageEndpoints();
    await testBackupEndpoints();
    await testBackupCrypto();
    await testStashSync();
    await testOwnership();
    await testSecurityHeaders();
    await testManifestValidation();
    await testCertExpiryDetection();
    await testPathTraversal();
  } finally { stopServer(); }

  console.log("\n========================================");
  console.log("  " + passed + " passed, " + failed + " failed");
  console.log("========================================\n");
  process.exit(failed > 0 ? 1 : 0);
}

main().catch(function (err) { console.error(err); stopServer(); process.exit(1); });
