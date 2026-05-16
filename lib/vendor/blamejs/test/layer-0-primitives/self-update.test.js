"use strict";
/**
 * b.selfUpdate — poll / verify / swap / rollback tests.
 *
 * Run standalone: `node test/layer-0-primitives/self-update.test.js`
 * Or via smoke:   `node test/smoke.js`
 *
 * The poll() path runs against a local http.Server fixture (no live
 * GitHub interaction). The releasesUrl is http://127.0.0.1:<port> so
 * we pass allowedProtocols + allowInternal through to the framework
 * SSRF guard. Production callers default to https-only with no
 * internal addresses.
 *
 * verify() / swap() / rollback() exercise the full atomic-swap +
 * rollback flow against on-disk artifacts under os.tmpdir().
 */

var fs = require("fs");
var os = require("os");
var http = require("http");
var path = require("path");
var nodeCrypto = require("node:crypto");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _tmp(name) {
  return path.join(os.tmpdir(), "blamejs-selfupdate-" + Date.now() + "-" +
    Math.random().toString(36).slice(2, 8) + "-" + name);
}

function _newSigningKeys() {
  return nodeCrypto.generateKeyPairSync("ed25519");
}

function _detachedSign(privateKey, bytes) {
  return nodeCrypto.sign(null, bytes, privateKey);
}

function testSurface() {
  check("b.selfUpdate namespace present",      typeof b.selfUpdate === "object");
  check("b.selfUpdate.poll is a function",     typeof b.selfUpdate.poll === "function");
  check("b.selfUpdate.verify is a function",   typeof b.selfUpdate.verify === "function");
  check("b.selfUpdate.swap is a function",     typeof b.selfUpdate.swap === "function");
  check("b.selfUpdate.rollback is a function", typeof b.selfUpdate.rollback === "function");
  check("SelfUpdateError class exposed",       typeof b.selfUpdate.SelfUpdateError === "function");
  check("DEFAULT_HASH_ALG = sha3-512",         b.selfUpdate.DEFAULT_HASH_ALG === "sha3-512");
}

function testPollRejectsBadOpts() {
  return Promise.resolve()
    .then(function () { return b.selfUpdate.poll(); })
    .then(function () { check("poll() with no opts should throw", false); },
          function (e) { check("poll: rejects empty",
            e && /selfupdate\/bad-opts/.test(e.code || "")); })
    .then(function () { return b.selfUpdate.poll({ releasesUrl: "ftp://x", currentVersion: "1.0.0" }); })
    .then(function () { check("poll() ftp:// should throw", false); },
          function (e) { check("poll: rejects ftp protocol",
            e && /selfupdate\/bad-releases-url/.test(e.code || "")); });
}

function testCompareTags() {
  var cmp = b.selfUpdate.compareTags;
  check("compareTags: public surface exposed",  typeof cmp === "function");
  check("compareTags: identical to internal",   cmp === b.selfUpdate._compareTags);
  check("compareTags: v0.7.30 < v0.7.31",       cmp("v0.7.30", "v0.7.31") === -1);
  check("compareTags: v0.7.31 > v0.7.30",       cmp("v0.7.31", "v0.7.30") === 1);
  check("compareTags: v0.7.31 == 0.7.31",       cmp("v0.7.31", "0.7.31") === 0);
  check("compareTags: v0.8.0 > v0.7.99",        cmp("v0.8.0", "v0.7.99") === 1);
  check("compareTags: v1.0.0 > v0.99.0",        cmp("v1.0.0", "v0.99.0") === 1);
  check("compareTags: case-insensitive leading v", cmp("V1.0.0", "1.0.0") === 0);
  check("compareTags: missing components treated as 0", cmp("1.0", "1.0.0") === 0);
  check("compareTags: non-numeric falls back to lex", cmp("1.0.0-rc.1", "1.0.0-rc.2") === -1);
  check("compareTags: bad input (non-string) safe",   cmp(null, "1.0.0") === -1);
  check("compareTags: bad input both safe",           cmp(null, undefined) === 0);
}

function _serveJson(payload) {
  var server = http.createServer(function (req, res) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(payload));
  });
  return server;
}

async function testPollAvailableAndUpToDate() {
  // Newer release available.
  var s1 = _serveJson({
    tag_name: "v2.0.0",
    assets: [
      { name: "blamejs-2.0.0.tar.gz",     browser_download_url: "https://example.invalid/asset.tgz", size: 1024 },
      { name: "blamejs-2.0.0.tar.gz.sig", browser_download_url: "https://example.invalid/asset.sig", size: 64 },
    ],
  });
  var port1 = await b.testing.listenOnRandomPort(s1);
  try {
    var r1 = await b.selfUpdate.poll({
      releasesUrl:      "http://127.0.0.1:" + port1 + "/releases/latest",
      currentVersion:   "v1.0.0",
      allowedProtocols: ["http:"],
      allowInternal:    true,
    });
    check("poll: available=true",                 r1.available === true);
    check("poll: latestTag=v2.0.0",               r1.latestTag === "v2.0.0");
    check("poll: asset selected",                 r1.asset && r1.asset.name === "blamejs-2.0.0.tar.gz");
    check("poll: signature selected",             r1.signature && r1.signature.name === "blamejs-2.0.0.tar.gz.sig");
  } finally { s1.close(); }

  // Up-to-date — no newer tag.
  var s2 = _serveJson({ tag_name: "v1.0.0", assets: [] });
  var port2 = await b.testing.listenOnRandomPort(s2);
  try {
    var r2 = await b.selfUpdate.poll({
      releasesUrl:      "http://127.0.0.1:" + port2 + "/releases/latest",
      currentVersion:   "v1.0.0",
      allowedProtocols: ["http:"],
      allowInternal:    true,
    });
    check("poll: up-to-date available=false",     r2.available === false);
    check("poll: up-to-date latestTag=v1.0.0",    r2.latestTag === "v1.0.0");
  } finally { s2.close(); }
}

async function testPollArrayShape() {
  var s = _serveJson([
    { tag_name: "v1.0.0", assets: [] },
    { tag_name: "v2.0.0", assets: [{ name: "x.tar.gz", browser_download_url: "https://example.invalid/x.tgz" }] },
    { tag_name: "v1.5.0", assets: [] },
  ]);
  var port = await b.testing.listenOnRandomPort(s);
  try {
    var r = await b.selfUpdate.poll({
      releasesUrl:      "http://127.0.0.1:" + port + "/releases",
      currentVersion:   "v0.5.0",
      allowedProtocols: ["http:"],
      allowInternal:    true,
    });
    check("poll: array picks max tag",            r.latestTag === "v2.0.0");
  } finally { s.close(); }
}

async function testPollNon2xxRefused() {
  var s = http.createServer(function (req, res) { res.writeHead(503); res.end(""); });
  var port = await b.testing.listenOnRandomPort(s);
  var threw = null;
  try {
    await b.selfUpdate.poll({
      releasesUrl:      "http://127.0.0.1:" + port + "/releases",
      currentVersion:   "v1.0.0",
      allowedProtocols: ["http:"],
      allowInternal:    true,
    });
  } catch (e) { threw = e; }
  s.close();
  check("poll: 503 raises selfupdate error",
        threw && /selfupdate\/poll-non-2xx|selfupdate\/poll-failed/.test(threw.code || ""));
}

async function testVerifyPassFail() {
  var keys = _newSigningKeys();
  var pubPem = keys.publicKey.export({ type: "spki", format: "pem" });
  var assetBytes = Buffer.from("hello blamejs payload");
  var sigBytes   = _detachedSign(keys.privateKey, assetBytes);

  var assetPath = _tmp("asset.bin");
  var sigPath   = _tmp("asset.sig");
  fs.writeFileSync(assetPath, assetBytes);
  fs.writeFileSync(sigPath,   sigBytes);

  try {
    var ok = await b.selfUpdate.verify({
      assetPath:     assetPath,
      signaturePath: sigPath,
      pubkeyPem:     pubPem,
    });
    check("verify: passed",                       ok.verified === true);
    check("verify: hash returned",                typeof ok.hash === "string" && ok.hash.length > 0);
    check("verify: alg = sha3-512",               ok.alg === "sha3-512");

    // Tamper the signature — verify must throw.
    var badSig = Buffer.from(sigBytes);
    badSig[0] ^= 0xFF;
    fs.writeFileSync(sigPath, badSig);
    var threw = null;
    try {
      await b.selfUpdate.verify({
        assetPath:     assetPath,
        signaturePath: sigPath,
        pubkeyPem:     pubPem,
      });
    } catch (e) { threw = e; }
    check("verify: tampered sig is refused",
          threw && /selfupdate\/(signature-mismatch|verify-failed)/.test(threw.code || ""));
  } finally {
    try { fs.unlinkSync(assetPath); } catch (_e) { /* best-effort */ }
    try { fs.unlinkSync(sigPath);   } catch (_e) { /* best-effort */ }
  }
}

async function testSwapAndRollback() {
  var dir = _tmp("dir");
  fs.mkdirSync(dir, { recursive: true });
  var to       = path.join(dir, "blamejs.bin");
  var backupTo = path.join(dir, "blamejs.bin.bak");
  var newPath  = path.join(dir, "blamejs.bin.new");

  fs.writeFileSync(to,      Buffer.from("OLD-BINARY"));
  fs.writeFileSync(newPath, Buffer.from("NEW-BINARY"));

  var rs = await b.selfUpdate.swap({ from: newPath, to: to, backupTo: backupTo });
  check("swap: ok=true",                           rs.ok === true);
  check("swap: to has new bytes",                  fs.readFileSync(to, "utf8") === "NEW-BINARY");
  check("swap: backup has old bytes",              fs.readFileSync(backupTo, "utf8") === "OLD-BINARY");
  check("swap: from removed (renamed)",            !fs.existsSync(newPath));

  var rr = await b.selfUpdate.rollback({ to: to, backupTo: backupTo });
  check("rollback: ok=true",                       rr.ok === true);
  check("rollback: to has old bytes again",        fs.readFileSync(to, "utf8") === "OLD-BINARY");

  // Cleanup.
  try { fs.unlinkSync(to);       } catch (_e) { /* best-effort */ }
  try { fs.unlinkSync(backupTo); } catch (_e) { /* best-effort */ }
  try { fs.rmdirSync(dir);       } catch (_e) { /* best-effort */ }
}

async function testSwapMissingFromRefused() {
  var dir = _tmp("dir2");
  fs.mkdirSync(dir, { recursive: true });
  var threw = null;
  try {
    await b.selfUpdate.swap({
      from:     path.join(dir, "absent.bin"),
      to:       path.join(dir, "to.bin"),
      backupTo: path.join(dir, "to.bin.bak"),
    });
  } catch (e) { threw = e; }
  check("swap: missing-from refused",
        threw && /selfupdate\/missing-from/.test(threw.code || ""));
  try { fs.rmdirSync(dir); } catch (_e) { /* best-effort */ }
}

async function testRollbackMissingBackupRefused() {
  var dir = _tmp("dir3");
  fs.mkdirSync(dir, { recursive: true });
  var threw = null;
  try {
    await b.selfUpdate.rollback({
      to:       path.join(dir, "to.bin"),
      backupTo: path.join(dir, "absent.bak"),
    });
  } catch (e) { threw = e; }
  check("rollback: missing backup refused",
        threw && /selfupdate\/missing-backup/.test(threw.code || ""));
  try { fs.rmdirSync(dir); } catch (_e) { /* best-effort */ }
}

async function run() {
  testSurface();
  testCompareTags();
  await testPollRejectsBadOpts();
  await testPollAvailableAndUpToDate();
  await testPollArrayShape();
  await testPollNon2xxRefused();
  await testVerifyPassFail();
  await testSwapAndRollback();
  await testSwapMissingFromRefused();
  await testRollbackMissingBackupRefused();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e.message); process.exit(1); }
  );
}
