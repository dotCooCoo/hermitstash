// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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

var _tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-selfupdate-"));
function _tmp(name) {
  return path.join(_tmpBase, Date.now() + "-" +
    Math.random().toString(36).slice(2, 8) + "-" + name);
}

function _newSigningKeys() {
  return nodeCrypto.generateKeyPairSync("ed25519");
}

function _newEcP384Keys() {
  return nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-384" });
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
  check("b.selfUpdate.beginProbation is a function", typeof b.selfUpdate.beginProbation === "function");
  check("b.selfUpdate.confirmHealthy is a function", typeof b.selfUpdate.confirmHealthy === "function");
  check("b.selfUpdate.evaluateOnBoot is a function", typeof b.selfUpdate.evaluateOnBoot === "function");
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

function testPollRejectsUnsafeAssetPattern() {
  // A wrapped nested quantifier is catastrophic-backtracking (ReDoS)
  // shaped; it must be refused at config-time, before any request runs.
  // The releasesUrl is well-formed so the assetPattern screen is what
  // fails — and the refusal happens before any .test() so nothing ever
  // backtracks.
  return Promise.resolve()
    .then(function () {
      return b.selfUpdate.poll({
        releasesUrl:    "https://example.invalid/releases",
        currentVersion: "1.0.0",
        assetPattern:   /((a)+)+$/,
      });
    })
    .then(function () { check("poll() ReDoS assetPattern should throw", false); },
          function (e) { check("poll: rejects ReDoS-shaped assetPattern",
            e && /selfupdate\/unsafe-asset-pattern/.test(e.code || "")); });
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
  // SemVer 2.0.0 §11 strict precedence — the lex-only ordering would
  // sort "10" < "9" as strings, allowing an attacker pivot of
  // publishing `1.0.0-alpha.10` to leapfrog `1.0.0-alpha.9`. The
  // strict implementation forces numeric compare per §11.4.1.
  check("compareTags §11.4.1: alpha.9 < alpha.10 (numeric, not lex)",
        cmp("1.0.0-alpha.9", "1.0.0-alpha.10") === -1);
  check("compareTags §11.4.1: alpha.10 > alpha.9",
        cmp("1.0.0-alpha.10", "1.0.0-alpha.9") === 1);
  // §11.4.2 — alphanumeric identifiers compare lexicographically.
  check("compareTags §11.4.2: alpha < beta (lex)",
        cmp("1.0.0-alpha", "1.0.0-beta") === -1);
  // §11.4.3 — numeric identifier < alphanumeric.
  check("compareTags §11.4.3: 1 < alpha (numeric < alphanum)",
        cmp("1.0.0-1", "1.0.0-alpha") === -1);
  // §11.3 — version WITHOUT pre-release > version WITH one.
  check("compareTags §11.3: 1.0.0-rc.1 < 1.0.0 (release > pre-release)",
        cmp("1.0.0-rc.1", "1.0.0") === -1);
  check("compareTags §11.3: 1.0.0 > 1.0.0-rc.1",
        cmp("1.0.0", "1.0.0-rc.1") === 1);
  // §11.4.4 — longer pre-release list > shorter when prefix matches.
  check("compareTags §11.4.4: alpha < alpha.1 (shorter < longer)",
        cmp("1.0.0-alpha", "1.0.0-alpha.1") === -1);
  // §10 — build metadata ignored.
  check("compareTags §10: 1.0.0+sha-abc = 1.0.0+sha-def (build ignored)",
        cmp("1.0.0+sha-abc", "1.0.0+sha-def") === 0);
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

  var newHash = nodeCrypto.createHash("sha3-512").update(Buffer.from("NEW-BINARY")).digest("hex");
  var rs = await b.selfUpdate.swap({ from: newPath, to: to, backupTo: backupTo, expectedHash: newHash });
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
      from:         path.join(dir, "absent.bin"),
      to:           path.join(dir, "to.bin"),
      backupTo:     path.join(dir, "to.bin.bak"),
      expectedHash: "00",   // present so validation passes; the existsSync(from) check fires first
    });
  } catch (e) { threw = e; }
  check("swap: missing-from refused",
        threw && /selfupdate\/missing-from/.test(threw.code || ""));
  try { fs.rmdirSync(dir); } catch (_e) { /* best-effort */ }
}

async function testSwapHashMismatchRefused() {
  // RED before the fix: swap() renamed `from` into place with no re-check, so an
  // attacker who swapped `from` after selfUpdate.verify passed (or pointed verify
  // at a different inode via a symlink) installed unverified bytes. swap() now
  // re-hashes `from` against expectedHash (verify's hash) immediately before the
  // install and refuses a mismatch.
  var dir = _tmp("dir-tamper");
  fs.mkdirSync(dir, { recursive: true });
  var to       = path.join(dir, "blamejs.bin");
  var backupTo = path.join(dir, "blamejs.bin.bak");
  var newPath  = path.join(dir, "blamejs.bin.new");
  fs.writeFileSync(to, Buffer.from("OLD-BINARY"));
  // verify() checked these bytes...
  var verifiedHash = nodeCrypto.createHash("sha3-512").update(Buffer.from("GOOD-BINARY")).digest("hex");
  // ...but `from` was swapped to different bytes after verify.
  fs.writeFileSync(newPath, Buffer.from("TAMPERED-BINARY"));
  var threw = null;
  try {
    await b.selfUpdate.swap({ from: newPath, to: to, backupTo: backupTo, expectedHash: verifiedHash });
  } catch (e) { threw = e; }
  check("swap: from tampered after verify is refused (hash mismatch)",
        threw && /selfupdate\/swap-hash-mismatch/.test(threw.code || ""));
  check("swap: tampered bytes NOT installed", fs.readFileSync(to, "utf8") === "OLD-BINARY");
  try { fs.unlinkSync(to);      } catch (_e) { /* best-effort */ }
  try { fs.unlinkSync(newPath); } catch (_e) { /* best-effort */ }
  try { fs.rmdirSync(dir);      } catch (_e) { /* best-effort */ }
}

async function testSwapSymlinkedFromRefused() {
  // A symlinked `from` must be refused at read (O_NOFOLLOW): hashing the link
  // TARGET while installing the link itself would let an attacker point the link
  // at verified bytes, pass expectedHash, then repoint the installed link at
  // unverified bytes. POSIX-only — Windows symlink creation needs privileges.
  var dir = _tmp("dir-symlink");
  fs.mkdirSync(dir, { recursive: true });
  var real = path.join(dir, "real.bin");
  var link = path.join(dir, "link.bin");
  var to   = path.join(dir, "to.bin");
  fs.writeFileSync(real, Buffer.from("REAL-BYTES"));
  var madeLink = false;
  try { fs.symlinkSync(real, link); madeLink = true; } catch (_e) { /* no symlink privilege */ }
  if (!madeLink) {
    check("swap: symlinked-from test skipped (no symlink privilege)", true);
    try { fs.unlinkSync(real); fs.rmdirSync(dir); } catch (_e) { /* best-effort */ }
    return;
  }
  var realHash = nodeCrypto.createHash("sha3-512").update(Buffer.from("REAL-BYTES")).digest("hex");
  var threw = null;
  try {
    await b.selfUpdate.swap({ from: link, to: to, backupTo: path.join(dir, "to.bin.bak"), expectedHash: realHash });
  } catch (e) { threw = e; }
  check("swap: a symlinked from is refused (read with O_NOFOLLOW)",
        threw && /selfupdate\/swap-read-failed/.test(threw.code || ""));
  check("swap: symlinked from did not install", !fs.existsSync(to));
  try { fs.unlinkSync(link); fs.unlinkSync(real); fs.rmdirSync(dir); } catch (_e) { /* best-effort */ }
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

// ---- Additional coverage: poll / verify / swap / rollback error,
// adversarial, and option-default branches ----

function _serveStatus(status, body, headers, onReq) {
  return http.createServer(function (req, res) {
    if (onReq) onReq(req);
    res.writeHead(status, headers || {});
    res.end(body == null ? "" : body);
  });
}

async function _pollLocal(port, extra) {
  return b.selfUpdate.poll(Object.assign({
    releasesUrl:      "http://127.0.0.1:" + port + "/releases",
    currentVersion:   "v1.0.0",
    allowedProtocols: ["http:"],
    allowInternal:    true,
  }, extra || {}));
}

async function testPoll304FastPath() {
  // RED before the fix: httpClient.request rejects EVERY non-2xx (304
  // included) as HTTP_ERROR, so poll() never reached its own
  // statusCode===304 branch — the documented If-None-Match "fast no-update"
  // path was dead code and a conditional poll that correctly received a 304
  // threw selfupdate/poll-failed instead of reporting "no update". poll() now
  // passes responseMode:"always-resolve" so it owns status handling.
  var etag = "W/\"cafe-f00d\"";
  var seenHeader = null;
  var s = _serveStatus(304, "", { ETag: etag }, function (req) {
    seenHeader = req.headers["if-none-match"];
  });
  var port = await b.testing.listenOnRandomPort(s);
  try {
    var r = await _pollLocal(port, { etag: etag });
    check("poll 304: If-None-Match header was sent",   seenHeader === etag);
    check("poll 304: fast-path returns (no throw)",    r && r.available === false);
    check("poll 304: statusCode surfaced",             r.statusCode === 304);
    check("poll 304: etag echoed back",                r.etag === etag);
    check("poll 304: latestTag null on 304",           r.latestTag === null);
  } finally { s.close(); }
}

async function testPollNon2xxSurfacesTypedCode() {
  // With poll owning status handling, a real non-2xx surfaces the intended
  // typed selfupdate/poll-non-2xx branch rather than the generic
  // request-failed catch (also previously dead behind httpClient's throw).
  var s = _serveStatus(503, "busy");
  var port = await b.testing.listenOnRandomPort(s);
  var threw = null;
  try { await _pollLocal(port); } catch (e) { threw = e; }
  s.close();
  check("poll: 503 surfaces selfupdate/poll-non-2xx",
        threw && /selfupdate\/poll-non-2xx/.test(threw.code || ""));
}

async function testPollEmptyArrayFeed() {
  var s = _serveJson([]);
  var port = await b.testing.listenOnRandomPort(s);
  try {
    var r = await _pollLocal(port);
    check("poll: empty-array feed available=false", r.available === false);
    check("poll: empty-array latestTag null",       r.latestTag === null);
  } finally { s.close(); }
}

async function testPollMalformedBodies() {
  // Malformed JSON body.
  var s1 = _serveStatus(200, "{ not json", { "Content-Type": "application/json" });
  var p1 = await b.testing.listenOnRandomPort(s1);
  var t1 = null;
  try { await _pollLocal(p1); } catch (e) { t1 = e; }
  s1.close();
  check("poll: malformed JSON -> selfupdate/bad-json",
        t1 && /selfupdate\/bad-json/.test(t1.code || ""));

  // Valid JSON but a bare primitive — neither object nor array.
  var s2 = _serveStatus(200, "42", { "Content-Type": "application/json" });
  var p2 = await b.testing.listenOnRandomPort(s2);
  var t2 = null;
  try { await _pollLocal(p2); } catch (e) { t2 = e; }
  s2.close();
  check("poll: JSON primitive -> selfupdate/bad-shape",
        t2 && /selfupdate\/bad-shape/.test(t2.code || ""));

  // Object with no tag_name.
  var s3 = _serveJson({ assets: [] });
  var p3 = await b.testing.listenOnRandomPort(s3);
  var t3 = null;
  try { await _pollLocal(p3); } catch (e) { t3 = e; }
  s3.close();
  check("poll: object missing tag_name -> selfupdate/bad-shape",
        t3 && /selfupdate\/bad-shape/.test(t3.code || ""));
}

async function testPollAvailableNoAssetMatch() {
  // Newer tag but nothing matches the well-known asset/signature shapes.
  var s = _serveJson({
    tag_name: "v2.0.0",
    assets: [{ name: "NOTES.md", browser_download_url: "https://example.invalid/notes" }],
  });
  var port = await b.testing.listenOnRandomPort(s);
  try {
    var r = await _pollLocal(port);
    check("poll: newer tag with no matching asset -> available=true", r.available === true);
    check("poll: no matching asset -> asset null",     r.asset === null);
    check("poll: no matching signature -> signature null", r.signature === null);
  } finally { s.close(); }
}

async function testPollDigestPassthrough() {
  var s = _serveJson({
    tag_name: "v2.0.0",
    assets: [
      { name: "blamejs.tar.gz",     browser_download_url: "https://example.invalid/a.tgz", size: 100, digest: "sha256:abc123" },
      { name: "blamejs.tar.gz.sig", browser_download_url: "https://example.invalid/a.sig", size: 64,  digest: "sha256:sigdig" },
    ],
  });
  var port = await b.testing.listenOnRandomPort(s);
  try {
    var r = await _pollLocal(port);
    check("poll: asset digest passed through verbatim",     r.asset && r.asset.digest === "sha256:abc123");
    check("poll: signature digest passed through verbatim", r.signature && r.signature.digest === "sha256:sigdig");
    check("poll: asset size surfaced",                      r.asset && r.asset.size === 100);
  } finally { s.close(); }
}

async function testPollStringPatterns() {
  // assetPattern / signaturePattern as substrings — matched via indexOf,
  // never compiled, so no ReDoS surface.
  var s = _serveJson({
    tag_name: "v2.0.0",
    assets: [
      { name: "custom-runtime.pkg",     browser_download_url: "https://example.invalid/rt" },
      { name: "custom-runtime.pkg.sig", browser_download_url: "https://example.invalid/rt.sig" },
    ],
  });
  var port = await b.testing.listenOnRandomPort(s);
  try {
    var r = await _pollLocal(port, { assetPattern: ".pkg", signaturePattern: ".pkg.sig" });
    check("poll: string signaturePattern selects the sig", r.signature && r.signature.name === "custom-runtime.pkg.sig");
    check("poll: string assetPattern selects the asset",   r.asset && r.asset.name === "custom-runtime.pkg");
  } finally { s.close(); }
}

async function testPollSignaturePairsWithAsset() {
  // #497 — the returned signature MUST be the detached sig OF the returned asset,
  // not a first-match-wins sig that may belong to a different sidecar. Order an
  // ML-DSA sidecar BEFORE the real .sig so a first-match-wins selection returns
  // the wrong one; the derived-name pairing (asset.name + ".sig") returns the
  // sig that actually signs the selected asset.
  var s = _serveJson({
    tag_name: "v2.0.0",
    assets: [
      { name: "blamejs-linux.tar.gz",           browser_download_url: "https://example.invalid/a.tgz", size: 4096 },
      { name: "blamejs-linux.tar.gz.mldsa.sig",  browser_download_url: "https://example.invalid/a.mldsa.sig", size: 4700 },
      { name: "blamejs-linux.tar.gz.sig",        browser_download_url: "https://example.invalid/a.sig", size: 96 },
    ],
  });
  var port = await b.testing.listenOnRandomPort(s);
  try {
    var r = await _pollLocal(port);
    check("poll pairing: asset selected",          r.asset && r.asset.name === "blamejs-linux.tar.gz");
    check("poll pairing: signature is the detached sig OF the asset",
          r.signature && r.signature.name === r.asset.name + ".sig");
  } finally { s.close(); }
}

async function testPollSignaturePairingEdgeCases() {
  // A lone signature-shaped asset (not asset+suffix) is accepted as THE sig
  // (single-sig release) — keeps the common one-asset-one-sig case green.
  var s1 = _serveJson({
    tag_name: "v2.0.0",
    assets: [
      { name: "runtime.tar.gz",       browser_download_url: "https://example.invalid/rt.tgz" },
      { name: "runtime.detached.sig", browser_download_url: "https://example.invalid/rt.sig" },
    ],
  });
  var p1 = await b.testing.listenOnRandomPort(s1);
  try {
    var r1 = await _pollLocal(p1);
    check("poll pairing: lone signature-shaped asset accepted",
          r1.signature && r1.signature.name === "runtime.detached.sig");
  } finally { s1.close(); }

  // Two unrelated sigs, neither derived from the asset name — ambiguous, so the
  // signature is null (fail closed) rather than guessing one that may not sign
  // the asset.
  var s2 = _serveJson({
    tag_name: "v2.0.0",
    assets: [
      { name: "runtime.tar.gz", browser_download_url: "https://example.invalid/rt.tgz" },
      { name: "other-a.sig",    browser_download_url: "https://example.invalid/a.sig" },
      { name: "other-b.sig",    browser_download_url: "https://example.invalid/b.sig" },
    ],
  });
  var p2 = await b.testing.listenOnRandomPort(s2);
  try {
    var r2 = await _pollLocal(p2);
    check("poll pairing: ambiguous unrelated sigs → signature null (fail closed)",
          r2.asset && r2.asset.name === "runtime.tar.gz" && r2.signature === null);
  } finally { s2.close(); }

  // An operator signaturePattern that matches a sig NOT belonging to the asset
  // stem must not be paired to the asset (fail closed).
  var s3 = _serveJson({
    tag_name: "v2.0.0",
    assets: [
      { name: "app.tar.gz",       browser_download_url: "https://example.invalid/app.tgz" },
      { name: "unrelated.sig.bin", browser_download_url: "https://example.invalid/u.sig.bin" },
    ],
  });
  var p3 = await b.testing.listenOnRandomPort(s3);
  try {
    var r3 = await _pollLocal(p3, { signaturePattern: ".sig.bin" });
    check("poll pairing: operator sig pattern not matching asset stem → null",
          r3.asset && r3.asset.name === "app.tar.gz" && r3.signature === null);
  } finally { s3.close(); }
}

function testPollOptValidation() {
  // Config-time refusals — each throws before any request is issued.
  var cases = [
    [{ currentVersion: "1.0.0" },                                                       "bad-releases-url",      "missing releasesUrl"],
    [{ releasesUrl: "https://x/r" },                                                    "bad-current-version",   "missing currentVersion"],
    [{ releasesUrl: "::::not a url", currentVersion: "1.0.0" },                         "bad-releases-url",      "unparseable releasesUrl"],
    [{ releasesUrl: "https://x/r", currentVersion: "1.0.0", maxBytes: -1 },             "bad-max-bytes",         "negative maxBytes"],
    [{ releasesUrl: "https://x/r", currentVersion: "1.0.0", maxBytes: Infinity },       "bad-max-bytes",         "Infinity maxBytes"],
    [{ releasesUrl: "https://x/r", currentVersion: "1.0.0", timeoutMs: 0 },             "bad-timeout",           "zero timeoutMs"],
    [{ releasesUrl: "https://x/r", currentVersion: "1.0.0", headers: [] },              "bad-headers",           "array headers"],
    [{ releasesUrl: "https://x/r", currentVersion: "1.0.0", etag: 123 },                "bad-etag",              "numeric etag"],
    [{ releasesUrl: "http://x/r",  currentVersion: "1.0.0", allowedProtocols: ["http:", 1] }, "bad-allowed-protocols", "non-string protocol element"],
    [{ releasesUrl: "https://x/r", currentVersion: "1.0.0", assetPattern: 5 },          "bad-asset-pattern",     "numeric assetPattern"],
    [{ releasesUrl: "https://x/r", currentVersion: "1.0.0", signaturePattern: 5 },      "bad-sig-pattern",       "numeric signaturePattern"],
    [{ releasesUrl: "https://x/r", currentVersion: "1.0.0", signaturePattern: /((a)+)+$/ }, "unsafe-sig-pattern", "ReDoS signaturePattern"],
    [{ releasesUrl: "https://x/r", currentVersion: "1.0.0", bogusOpt: 1 },              "bad-opts",              "unknown opt"],
  ];
  return cases.reduce(function (chain, c) {
    return chain.then(function () {
      return b.selfUpdate.poll(c[0]).then(
        function () { check("poll validation (" + c[2] + ") should throw", false); },
        function (e) {
          check("poll validation: " + c[2] + " -> selfupdate/" + c[1],
                e && new RegExp("selfupdate/" + c[1]).test(e.code || ""));
        });
    });
  }, Promise.resolve());
}

async function testVerifyErrorPaths() {
  // Missing asset file -> read-failed.
  var t1 = null;
  try {
    await b.selfUpdate.verify({
      assetPath:     _tmp("absent-asset.bin"),
      signaturePath: _tmp("absent.sig"),
      pubkeyPem:     "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n",
    });
  } catch (e) { t1 = e; }
  check("verify: missing asset file -> selfupdate/read-failed",
        t1 && /selfupdate\/read-failed/.test(t1.code || ""));

  var keys  = _newSigningKeys();
  var pubPem = keys.publicKey.export({ type: "spki", format: "pem" });
  var asset = Buffer.from("verify-error-path payload");
  var sig   = _detachedSign(keys.privateKey, asset);
  var aPath = _tmp("verr-asset.bin");
  var sPath = _tmp("verr-asset.sig");
  fs.writeFileSync(aPath, asset);
  fs.writeFileSync(sPath, sig);
  try {
    // Garbage PEM makes crypto.verify throw -> verify-failed (typed).
    var t2 = null;
    try {
      await b.selfUpdate.verify({ assetPath: aPath, signaturePath: sPath, pubkeyPem: "not a valid pem" });
    } catch (e) { t2 = e; }
    check("verify: garbage pubkey -> selfupdate/verify-failed",
          t2 && /selfupdate\/verify-failed/.test(t2.code || ""));

    // Unsupported digest algorithm -> config-time bad-hash-algo.
    var t3 = null;
    try {
      await b.selfUpdate.verify({ assetPath: aPath, signaturePath: sPath, pubkeyPem: pubPem, hashAlgo: "md5" });
    } catch (e) { t3 = e; }
    check("verify: unsupported hashAlgo -> selfupdate/bad-hash-algo",
          t3 && /selfupdate\/bad-hash-algo/.test(t3.code || ""));

    // Missing required pubkeyPem -> bad-pubkey.
    var t4 = null;
    try {
      await b.selfUpdate.verify({ assetPath: aPath, signaturePath: sPath });
    } catch (e) { t4 = e; }
    check("verify: missing pubkeyPem -> selfupdate/bad-pubkey",
          t4 && /selfupdate\/bad-pubkey/.test(t4.code || ""));

    // A valid non-default digest algorithm is honored end-to-end.
    var vv = await b.selfUpdate.verify({ assetPath: aPath, signaturePath: sPath, pubkeyPem: pubPem, hashAlgo: "sha-256" });
    check("verify: custom hashAlgo verified",       vv.verified === true);
    check("verify: custom hashAlgo reported back",  vv.alg === "sha-256");
    check("verify: sha-256 digest is 64 lc hex",    /^[0-9a-f]{64}$/.test(vv.hash));
  } finally {
    try { fs.unlinkSync(aPath); } catch (_e) { /* best-effort */ }
    try { fs.unlinkSync(sPath); } catch (_e) { /* best-effort */ }
  }
}

async function testSwapFreshInstall() {
  // No pre-existing `to` — hadOriginal=false, so no backup is written and the
  // verified bytes are installed from memory.
  var dir = _tmp("dir-fresh");
  fs.mkdirSync(dir, { recursive: true });
  var to       = path.join(dir, "app.bin");
  var backupTo = path.join(dir, "app.bin.bak");
  var from     = path.join(dir, "app.bin.new");
  var bytes    = Buffer.from("FRESH-INSTALL-BYTES");
  fs.writeFileSync(from, bytes);
  var hash = nodeCrypto.createHash("sha3-512").update(bytes).digest("hex");
  var rs = await b.selfUpdate.swap({ from: from, to: to, backupTo: backupTo, expectedHash: hash });
  check("swap fresh: ok=true",             rs.ok === true);
  check("swap fresh: installed bytes",     fs.readFileSync(to, "utf8") === "FRESH-INSTALL-BYTES");
  check("swap fresh: no backup written",   !fs.existsSync(backupTo));
  check("swap fresh: from consumed",       !fs.existsSync(from));
  try { fs.unlinkSync(to); } catch (_e) { /* best-effort */ }
  try { fs.rmdirSync(dir); } catch (_e) { /* best-effort */ }
}

async function testSwapCustomHashAlgoRoundTrip() {
  var dir = _tmp("dir-algo");
  fs.mkdirSync(dir, { recursive: true });
  var to    = path.join(dir, "bin");
  var from  = path.join(dir, "bin.new");
  var bytes = Buffer.from("ALGO-ROUNDTRIP");
  fs.writeFileSync(to, Buffer.from("OLD"));
  fs.writeFileSync(from, bytes);
  var h256 = nodeCrypto.createHash("sha-256").update(bytes).digest("hex");
  var rs = await b.selfUpdate.swap({ from: from, to: to, backupTo: path.join(dir, "bin.bak"),
    expectedHash: h256, hashAlgo: "sha-256" });
  check("swap sha-256: ok=true",     rs.ok === true);
  check("swap sha-256: installed",   fs.readFileSync(to, "utf8") === "ALGO-ROUNDTRIP");

  // A sha-256 expectedHash checked against swap's default sha3-512 re-hash
  // fails closed (algo divergence must never install).
  fs.writeFileSync(to, Buffer.from("OLD2"));
  fs.writeFileSync(from, bytes);
  var t2 = null;
  try {
    await b.selfUpdate.swap({ from: from, to: to, backupTo: path.join(dir, "bin.bak"), expectedHash: h256 });
  } catch (e) { t2 = e; }
  check("swap: algo-divergent expectedHash refused",
        t2 && /selfupdate\/swap-hash-mismatch/.test(t2.code || ""));
  check("swap: algo-divergence left original intact", fs.readFileSync(to, "utf8") === "OLD2");
  try { fs.unlinkSync(to);   } catch (_e) { /* best-effort */ }
  try { fs.unlinkSync(from); } catch (_e) { /* best-effort */ }
  try { fs.rmdirSync(dir);   } catch (_e) { /* best-effort */ }
}

async function testSwapRollbackOptValidation() {
  var dir = _tmp("dir-optval");
  fs.mkdirSync(dir, { recursive: true });
  var from = path.join(dir, "src.bin");
  fs.writeFileSync(from, Buffer.from("X"));

  // The verify->swap integrity binding is mandatory: omitting expectedHash
  // is refused at config-time (never an opt-in security check).
  var t1 = null;
  try {
    await b.selfUpdate.swap({ from: from, to: path.join(dir, "to.bin"), backupTo: path.join(dir, "to.bak") });
  } catch (e) { t1 = e; }
  check("swap: missing expectedHash -> selfupdate/bad-expected-hash",
        t1 && /selfupdate\/bad-expected-hash/.test(t1.code || ""));

  var t2 = null;
  try {
    await b.selfUpdate.swap({ from: from, to: path.join(dir, "to.bin"),
      backupTo: path.join(dir, "to.bak"), expectedHash: "00", hashAlgo: "md5" });
  } catch (e) { t2 = e; }
  check("swap: unsupported hashAlgo -> selfupdate/bad-hash-algo",
        t2 && /selfupdate\/bad-hash-algo/.test(t2.code || ""));

  var t3 = null;
  try {
    await b.selfUpdate.swap({ from: from, to: path.join(dir, "to.bin"),
      backupTo: path.join(dir, "to.bak"), expectedHash: "00", bogus: 1 });
  } catch (e) { t3 = e; }
  check("swap: unknown opt -> selfupdate/bad-opts",
        t3 && /selfupdate\/bad-opts/.test(t3.code || ""));

  // maxBytes is a DECLARED swap opt (the body re-reads the from-bytes under it,
  // matching what selfUpdate.verify accepted): a bad value is refused with the
  // specific bad-max-bytes code, not the generic unknown-opt bad-opts.
  var t3b = null;
  try {
    await b.selfUpdate.swap({ from: from, to: path.join(dir, "to.bin"),
      backupTo: path.join(dir, "to.bak"), expectedHash: "00", maxBytes: -1 });
  } catch (e) { t3b = e; }
  check("swap: bad maxBytes -> selfupdate/bad-max-bytes (declared opt, matches verify)",
        t3b && /selfupdate\/bad-max-bytes/.test(t3b.code || ""));

  // maxBytes is NOT a rollback opt (rollback re-reads nothing), so it stays
  // unknown there — the declaration is swap-only.
  var t3c = null;
  try {
    await b.selfUpdate.rollback({ to: path.join(dir, "to.bin"),
      backupTo: path.join(dir, "to.bak"), maxBytes: 999 });
  } catch (e) { t3c = e; }
  check("rollback: maxBytes is not a rollback opt -> selfupdate/bad-opts",
        t3c && /selfupdate\/bad-opts/.test(t3c.code || ""));

  var t4 = null;
  try {
    await b.selfUpdate.rollback({ backupTo: path.join(dir, "to.bak") });
  } catch (e) { t4 = e; }
  check("rollback: missing to -> selfupdate/bad-to",
        t4 && /selfupdate\/bad-to/.test(t4.code || ""));

  try { fs.unlinkSync(from); } catch (_e) { /* best-effort */ }
  try { fs.rmdirSync(dir);   } catch (_e) { /* best-effort */ }
}

// ---- compareTags SemVer §11 precedence — remaining branch coverage.
// Each pair pins the strict-§11 ordering the poll upgrade decision relies
// on; a lexicographic fallback would misorder several of these and offer a
// downgrade / skip an upgrade. ----
function testCompareTagsFullPrecedence() {
  var cmp = b.selfUpdate.compareTags;
  // Numeric core, a-side LONGER than b-side (b's missing component is "0").
  check("compareTags: 1.0.0 == 1.0 (a longer core, missing→0)", cmp("1.0.0", "1.0") === 0);
  // Non-numeric core component — deterministic ASCII fallback, a > b.
  check("compareTags: non-numeric core a>b (1.z > 1.a)",        cmp("1.z", "1.a") === 1);
  // §11.4.4 — a's pre-release list is LONGER with a common prefix → a > b.
  check("compareTags §11.4.4: alpha.1 > alpha (longer > shorter)", cmp("1.0.0-alpha.1", "1.0.0-alpha") === 1);
  // §11.4.1 — equal leading numeric identifier then numeric compare (9 < 10).
  check("compareTags §11.4.1: 1.9 < 1.10 (numeric, equal prefix)", cmp("1.0.0-1.9", "1.0.0-1.10") === -1);
  // §11.4.3 — alphanumeric identifier OUTRANKS a numeric one (a=alpha, b=1).
  check("compareTags §11.4.3: alpha > 1 (alphanum > numeric)",   cmp("1.0.0-alpha", "1.0.0-1") === 1);
  // §11.4.2 — both alphanumeric, ASCII compare, a > b.
  check("compareTags §11.4.2: beta > alpha (lex)",               cmp("1.0.0-beta", "1.0.0-alpha") === 1);
  // Fully-equal pre-release lists → 0 (final fall-through).
  check("compareTags: alpha.1 == alpha.1 (equal pre-release)",   cmp("1.0.0-alpha.1", "1.0.0-alpha.1") === 0);
  // An empty pre-release identifier (malformed input) is treated as
  // alphanumeric (non-numeric) and stays deterministic rather than throwing.
  check("compareTags: empty pre-release segment is deterministic", cmp("1.0.0-alpha.", "1.0.0-alpha.0") === 1);
}

// A body larger than `bodyBytes` streamed on a 200 — used to prove poll's
// maxBytes cap refuses an oversized releases feed (no unbounded buffering).
function _serveOversized(bodyBytes) {
  return http.createServer(function (req, res) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end("[" + '"' + "x".repeat(bodyBytes) + '"' + "]");
  });
}

async function testPollDowngradeRefusedWithEtag() {
  // A feed advertising an OLDER tag than currentVersion must never report an
  // upgrade. Also exercises the maxBytes / timeoutMs numeric-opt branches and
  // the available=false etag pass-through from the response headers.
  var etag = 'W/"downgrade-guard"';
  var s = _serveStatus(200, JSON.stringify({ tag_name: "v1.0.0", assets: [] }),
    { "Content-Type": "application/json", ETag: etag });
  var port = await b.testing.listenOnRandomPort(s);
  try {
    var r = await _pollLocal(port, { currentVersion: "v2.0.0", maxBytes: 2000000, timeoutMs: 5000 });
    check("poll: older-than-current tag → available=false (no downgrade)", r.available === false);
    check("poll: downgrade path reports the older latestTag",             r.latestTag === "v1.0.0");
    check("poll: available=false surfaces the response etag",             r.etag === etag);
  } finally { s.close(); }
}

async function testPollOversizedFeedRefused() {
  // The releases JSON is capped by opts.maxBytes; an oversized response is
  // rejected by the framework downloader and surfaces as poll-failed rather
  // than buffering unboundedly (DoS bound on a hostile feed).
  var s = _serveOversized(4000);
  var port = await b.testing.listenOnRandomPort(s);
  var threw = null;
  try { await _pollLocal(port, { maxBytes: 512 }); } catch (e) { threw = e; }
  s.close();
  check("poll: oversized feed over maxBytes → selfupdate/poll-failed",
        threw && /selfupdate\/poll-failed/.test(threw.code || ""));
}

async function testPollNonArrayAssetsAndMalformedEntries() {
  // Newer tag but `assets` is not an array — asset/signature resolve to null
  // without throwing (defensive normalization).
  var s1 = _serveJson({ tag_name: "v2.0.0", assets: "not-an-array" });
  var p1 = await b.testing.listenOnRandomPort(s1);
  try {
    var r1 = await _pollLocal(p1);
    check("poll: non-array assets → available=true", r1.available === true);
    check("poll: non-array assets → asset null",     r1.asset === null);
    check("poll: non-array assets → signature null", r1.signature === null);
  } finally { s1.close(); }

  // A null asset entry and a name-less entry are both skipped; the well-formed
  // entry is selected.
  var s2 = _serveJson({
    tag_name: "v2.0.0",
    assets: [
      null,
      { browser_download_url: "https://example.invalid/no-name" },   // missing name → skipped
      { name: "app-2.0.0.tar.gz", browser_download_url: "https://example.invalid/app.tgz" },
      { name: "no-url.tar.gz" },                                     // missing url → skipped
    ],
  });
  var p2 = await b.testing.listenOnRandomPort(s2);
  try {
    var r2 = await _pollLocal(p2);
    check("poll: malformed entries skipped, valid asset selected",
          r2.asset && r2.asset.name === "app-2.0.0.tar.gz");
  } finally { s2.close(); }
}

async function testPollRegexpPatterns() {
  // RegExp asset / signature patterns reach _matchAsset's RegExp branch
  // (the string form is covered separately via indexOf). Both are ReDoS-safe
  // anchored shapes so they pass the config-time guardRegex screen.
  var s = _serveJson({
    tag_name: "v2.0.0",
    assets: [
      { name: "blamejs-runtime.pkg",     browser_download_url: "https://example.invalid/rt" },
      { name: "blamejs-runtime.pkg.sig", browser_download_url: "https://example.invalid/rt.sig" },
    ],
  });
  var port = await b.testing.listenOnRandomPort(s);
  try {
    var r = await _pollLocal(port, { assetPattern: /-runtime\.pkg$/, signaturePattern: /\.pkg\.sig$/ });
    check("poll: RegExp signaturePattern selects the sig", r.signature && r.signature.name === "blamejs-runtime.pkg.sig");
    check("poll: RegExp assetPattern selects the asset",   r.asset && r.asset.name === "blamejs-runtime.pkg");
  } finally { s.close(); }
}

async function testVerifyWrongKeyAndMalformedSig() {
  // A valid signature produced by a DIFFERENT keypair must NOT verify against
  // the operator's pinned key — this is the wrong-key fail-closed guarantee.
  var kSign = _newSigningKeys();
  var kOther = _newSigningKeys();
  var asset  = Buffer.from("wrong-key adversarial payload");
  var goodSig = _detachedSign(kSign.privateKey, asset);
  var otherPub = kOther.publicKey.export({ type: "spki", format: "pem" });

  var aPath = _tmp("wk-asset.bin");
  var sPath = _tmp("wk-asset.sig");
  fs.writeFileSync(aPath, asset);
  fs.writeFileSync(sPath, goodSig);
  try {
    var t1 = null;
    try {
      await b.selfUpdate.verify({ assetPath: aPath, signaturePath: sPath, pubkeyPem: otherPub });
    } catch (e) { t1 = e; }
    check("verify: valid sig under WRONG key is refused",
          t1 && /selfupdate\/signature-mismatch/.test(t1.code || ""));

    // A truncated signature must be refused (never silently accepted).
    fs.writeFileSync(sPath, goodSig.slice(0, 32));
    var signerPub = kSign.publicKey.export({ type: "spki", format: "pem" });
    var t2 = null;
    try {
      await b.selfUpdate.verify({ assetPath: aPath, signaturePath: sPath, pubkeyPem: signerPub });
    } catch (e) { t2 = e; }
    check("verify: truncated signature is refused",
          t2 && /selfupdate\/(signature-mismatch|verify-failed)/.test(t2.code || ""));

    // An empty signature file must be refused.
    fs.writeFileSync(sPath, Buffer.alloc(0));
    var t3 = null;
    try {
      await b.selfUpdate.verify({ assetPath: aPath, signaturePath: sPath, pubkeyPem: signerPub });
    } catch (e) { t3 = e; }
    check("verify: empty signature is refused",
          t3 && /selfupdate\/(signature-mismatch|verify-failed)/.test(t3.code || ""));
  } finally {
    try { fs.unlinkSync(aPath); } catch (_e) { /* best-effort */ }
    try { fs.unlinkSync(sPath); } catch (_e) { /* best-effort */ }
  }
}

async function testVerifyEcdsaP384DigestCommitment() {
  // #496 — verify() commits to a SHA3-512 signing digest (matching the framework
  // signer + standaloneVerifier). A SHA3-512-digest DER P-384 sidecar verifies;
  // a signature over a DIFFERENT digest (the curve-default SHA-384 that
  // nodeCrypto.sign(null, …) / b.crypto.sign produce for an EC key) is refused —
  // the digest, not just the key, is part of the accept contract. Pre-fix, verify
  // routed through b.crypto.verify (SHA-384 + DER-only), which INVERTED this:
  // it accepted the SHA-384 sig and rejected the framework's SHA3-512 sidecar.
  var keys    = _newEcP384Keys();
  var pubPem  = keys.publicKey.export({ type: "spki", format: "pem" });
  var privPem = keys.privateKey.export({ type: "pkcs8", format: "pem" });
  var asset   = Buffer.from("ecdsa-p384 asset bytes");
  // SHA3-512 digest-then-sign, DER (default) encoding — the framework's shape.
  var derSig  = nodeCrypto.createSign("sha3-512").update(asset).sign(keys.privateKey);

  var aPath = _tmp("ec-asset.bin");
  var sPath = _tmp("ec-asset.sig");
  fs.writeFileSync(aPath, asset);
  fs.writeFileSync(sPath, derSig);
  try {
    var v = await b.selfUpdate.verify({ assetPath: aPath, signaturePath: sPath, pubkeyPem: pubPem });
    check("verify: SHA3-512 + DER P-384 detached signature verifies", v.verified === true);

    // A wrong-digest signature (curve-default SHA-384) must be refused.
    var sha384Sig = b.crypto.sign(asset, privPem);
    fs.writeFileSync(sPath, sha384Sig);
    var t1 = null;
    try {
      await b.selfUpdate.verify({ assetPath: aPath, signaturePath: sPath, pubkeyPem: pubPem });
    } catch (e) { t1 = e; }
    check("verify: wrong-digest (SHA-384) ECDSA signature is refused",
          t1 && /selfupdate\/(signature-mismatch|verify-failed)/.test(t1.code || ""));
  } finally {
    try { fs.unlinkSync(aPath); } catch (_e) { /* best-effort */ }
    try { fs.unlinkSync(sPath); } catch (_e) { /* best-effort */ }
  }
}

async function testVerifyEcdsaP384Sha3P1363Accepted() {
  // #496 — b.selfUpdate.verify must accept exactly the signature set the
  // framework's own standaloneVerifier accepts: a SHA3-512-digest-then-sign
  // detached signature with a raw IEEE-P1363 (r||s) encoding over an EC P-384
  // key. Before the fix, verify() routed through b.crypto.verify →
  // nodeCrypto.verify(null, ...), which uses the curve-default SHA-384 digest
  // and DER-only, so a SHA3-512 + raw-P1363 release sidecar verified ONLY under
  // standaloneVerifier and was rejected by verify() — a disjoint accept set.
  var keys   = _newEcP384Keys();
  var pubPem = keys.publicKey.export({ type: "spki", format: "pem" });
  var asset  = Buffer.from("ecdsa-p384 sha3-512 ieee-p1363 release sidecar");
  // SHA3-512 digest-then-sign, raw r||s (mirrors ...ecdsa-encoding.test.js:189).
  var sig = nodeCrypto.createSign("sha3-512").update(asset)
    .sign({ key: keys.privateKey, dsaEncoding: "ieee-p1363" });

  var aPath = _tmp("p1363-asset.bin");
  var sPath = _tmp("p1363-asset.sig");
  fs.writeFileSync(aPath, asset);
  fs.writeFileSync(sPath, sig);
  try {
    var v = await b.selfUpdate.verify({ assetPath: aPath, signaturePath: sPath, pubkeyPem: pubPem });
    check("verify: SHA3-512 + IEEE-P1363 P-384 sidecar verifies", v.verified === true);
    check("verify: reports the default sha3-512 digest alg",      v.alg === "sha3-512");
    check("verify: reports the asset byte count",                 v.bytes === asset.length);

    // Equivalence: the exact triple the standaloneVerifier accepts, verify() accepts.
    var sv = b.selfUpdate.standaloneVerifier.verify(aPath, sPath, pubPem);
    check("verify/standaloneVerifier accept the same triple",
          sv.ok === true && v.verified === true && v.hash === sv.sha3_512);
  } finally {
    try { fs.unlinkSync(aPath); } catch (_e) { /* best-effort */ }
    try { fs.unlinkSync(sPath); } catch (_e) { /* best-effort */ }
  }
}

async function testVerifyMaxBytesBound() {
  // verify's maxBytes caps the asset read (v0.16.18 download-bounds class): an
  // asset larger than the cap is refused BEFORE it is buffered/hashed, and the
  // cap is tight (size == maxBytes passes, size == maxBytes+1 refuses).
  var keys   = _newSigningKeys();
  var pubPem = keys.publicKey.export({ type: "spki", format: "pem" });
  var asset  = Buffer.alloc(2000, 7);
  var sig    = _detachedSign(keys.privateKey, asset);
  var aPath = _tmp("cap-asset.bin");
  var sPath = _tmp("cap-asset.sig");
  fs.writeFileSync(aPath, asset);
  fs.writeFileSync(sPath, sig);
  try {
    var t1 = null;
    try {
      await b.selfUpdate.verify({ assetPath: aPath, signaturePath: sPath, pubkeyPem: pubPem, maxBytes: 1000 });
    } catch (e) { t1 = e; }
    check("verify: asset over maxBytes → selfupdate/read-failed",
          t1 && /selfupdate\/read-failed/.test(t1.code || ""));

    var t2 = null;
    try {
      await b.selfUpdate.verify({ assetPath: aPath, signaturePath: sPath, pubkeyPem: pubPem, maxBytes: 1999 });
    } catch (e) { t2 = e; }
    check("verify: asset over maxBytes by one byte → read-failed (tight bound)",
          t2 && /selfupdate\/read-failed/.test(t2.code || ""));

    var v = await b.selfUpdate.verify({ assetPath: aPath, signaturePath: sPath, pubkeyPem: pubPem, maxBytes: 2000 });
    check("verify: asset exactly at maxBytes verifies", v.verified === true);

    // The detached signature read is independently capped (64 KiB); an
    // oversized signature file is refused at read.
    fs.writeFileSync(sPath, Buffer.alloc(70000, 1));
    var t3 = null;
    try {
      await b.selfUpdate.verify({ assetPath: aPath, signaturePath: sPath, pubkeyPem: pubPem, maxBytes: 2000 });
    } catch (e) { t3 = e; }
    check("verify: oversized signature file → read-failed",
          t3 && /selfupdate\/read-failed/.test(t3.code || ""));
  } finally {
    try { fs.unlinkSync(aPath); } catch (_e) { /* best-effort */ }
    try { fs.unlinkSync(sPath); } catch (_e) { /* best-effort */ }
  }
}

async function testSwapMaxBytesBound() {
  // swap re-reads `from` under maxBytes to re-hash it; a from larger than the
  // cap is refused (swap-read-failed) and NOTHING is installed. A valid cap
  // installs normally.
  var dir = _tmp("dir-swap-cap");
  fs.mkdirSync(dir, { recursive: true });
  var to    = path.join(dir, "bin");
  var from  = path.join(dir, "bin.new");
  var bytes = Buffer.alloc(3000, 9);
  var hash  = nodeCrypto.createHash("sha3-512").update(bytes).digest("hex");
  fs.writeFileSync(from, bytes);

  var t1 = null;
  try {
    await b.selfUpdate.swap({ from: from, to: to, backupTo: path.join(dir, "bin.bak"),
      expectedHash: hash, maxBytes: 1000 });
  } catch (e) { t1 = e; }
  check("swap: from over maxBytes → selfupdate/swap-read-failed",
        t1 && /selfupdate\/swap-read-failed/.test(t1.code || ""));
  check("swap: over-cap from was NOT installed", !fs.existsSync(to));

  if (!fs.existsSync(from)) fs.writeFileSync(from, bytes);
  var rs = await b.selfUpdate.swap({ from: from, to: to, backupTo: path.join(dir, "bin.bak"),
    expectedHash: hash, maxBytes: 3000 });
  check("swap: valid maxBytes installs", rs.ok === true && fs.readFileSync(to).length === 3000);

  try { fs.unlinkSync(to);   } catch (_e) { /* best-effort */ }
  try { fs.rmdirSync(dir);   } catch (_e) { /* best-effort */ }
}

async function testSwapBackupFailureLeavesOriginal() {
  // The backup step must fail closed: when the backup destination cannot be
  // written (here backupTo is an existing directory), swap refuses with
  // backup-failed and the original `to` is left untouched.
  var dir = _tmp("dir-backupfail");
  fs.mkdirSync(dir, { recursive: true });
  var to    = path.join(dir, "app.bin");
  var from  = path.join(dir, "app.bin.new");
  var bytes = Buffer.from("NEW-VERIFIED");
  fs.writeFileSync(to, Buffer.from("ORIGINAL-BINARY"));
  fs.writeFileSync(from, bytes);
  var hash  = nodeCrypto.createHash("sha3-512").update(bytes).digest("hex");
  var backupDir = path.join(dir, "backup-is-a-directory");
  fs.mkdirSync(backupDir);

  var threw = null;
  try {
    await b.selfUpdate.swap({ from: from, to: to, backupTo: backupDir, expectedHash: hash });
  } catch (e) { threw = e; }
  check("swap: unwritable backup dest → selfupdate/backup-failed",
        threw && /selfupdate\/backup-failed/.test(threw.code || ""));
  check("swap: backup failure leaves original intact", fs.readFileSync(to, "utf8") === "ORIGINAL-BINARY");

  try { fs.unlinkSync(to);   } catch (_e) { /* best-effort */ }
  try { fs.unlinkSync(from); } catch (_e) { /* best-effort */ }
}

async function testSwapSeparateBackupDir() {
  // backupTo in a DIFFERENT directory than `to` exercises the second
  // directory-fsync branch (both parents are synced for durability).
  var toDir  = _tmp("dir-to");
  var bkDir  = _tmp("dir-backup");
  fs.mkdirSync(toDir, { recursive: true });
  fs.mkdirSync(bkDir, { recursive: true });
  var to       = path.join(toDir, "app.bin");
  var backupTo = path.join(bkDir, "app.bak");
  var from     = path.join(toDir, "app.bin.new");
  var bytes    = Buffer.from("SEPARATE-DIR-BYTES");
  fs.writeFileSync(to, Buffer.from("OLD"));
  fs.writeFileSync(from, bytes);
  var hash = nodeCrypto.createHash("sha3-512").update(bytes).digest("hex");

  var rs = await b.selfUpdate.swap({ from: from, to: to, backupTo: backupTo, expectedHash: hash });
  check("swap (separate backup dir): ok=true",          rs.ok === true);
  check("swap (separate backup dir): installed bytes",  fs.readFileSync(to, "utf8") === "SEPARATE-DIR-BYTES");
  check("swap (separate backup dir): backup in other dir", fs.readFileSync(backupTo, "utf8") === "OLD");

  try { fs.unlinkSync(to);       } catch (_e) { /* best-effort */ }
  try { fs.unlinkSync(backupTo); } catch (_e) { /* best-effort */ }
}

async function testSwapWriteFailureNoOriginal() {
  // A fresh install (no pre-existing `to`) whose install write cannot complete
  // must surface swap-failed — with no backup to roll back from, the source is
  // left for the operator. An unwritable target path (embedded NUL) forces the
  // atomic write to fail deterministically on every platform.
  var dir = _tmp("dir-writefail");
  fs.mkdirSync(dir, { recursive: true });
  var from  = path.join(dir, "src.bin");
  var bytes = Buffer.from("FRESH-BYTES");
  fs.writeFileSync(from, bytes);
  var hash  = nodeCrypto.createHash("sha3-512").update(bytes).digest("hex");
  var badTo = path.join(dir, "bad" + String.fromCharCode(0) + "name.bin");   // embedded NUL — never openable

  var threw = null;
  try {
    await b.selfUpdate.swap({ from: from, to: badTo, backupTo: path.join(dir, "bad.bak"), expectedHash: hash });
  } catch (e) { threw = e; }
  check("swap: install write failure (no original) → selfupdate/swap-failed",
        threw && /selfupdate\/swap-failed/.test(threw.code || ""));

  try { fs.unlinkSync(from); } catch (_e) { /* best-effort */ }
  try { fs.rmdirSync(dir);   } catch (_e) { /* best-effort */ }
}

async function testSwapReplacesLockedTargetWin32() {
  // #494 — installing over a running Windows image must succeed. Windows locks a
  // mapped / running executable against an in-place REPLACE (write-temp-then-
  // rename ONTO it) but allows a RENAME / move of the file. swap now moves the
  // outgoing `to` ASIDE to backupTo (a rename = lock-safe AND the backup) and
  // writes the new bytes to the freed path (a create, not a replace). The
  // read-only attribute (chmodSync 0o400) reproduces the replace-onto-locked
  // failure the old rename-onto-`to` path hit; rename-away sidesteps it.
  // Windows-only: POSIX rename ignores the target file mode, so the replace
  // failure can't be forced there without privileged setup.
  if (process.platform !== "win32") {
    check("swap: locked-target replace test skipped (non-win32)", true);
    return;
  }
  var dir = _tmp("dir-locked");
  var bkDir = _tmp("dir-locked-bak");
  fs.mkdirSync(dir, { recursive: true });
  fs.mkdirSync(bkDir, { recursive: true });
  var to       = path.join(dir, "app.bin");
  var backupTo = path.join(bkDir, "app.bak");
  var from     = path.join(dir, "app.bin.new");
  var bytes    = Buffer.from("NEW-VERIFIED-BYTES");
  fs.writeFileSync(from, bytes);
  fs.writeFileSync(to, Buffer.from("ORIGINAL-BYTES"));
  fs.chmodSync(to, 0o400);   // read-only → in-place replace onto `to` fails; rename-away does not
  var hash = nodeCrypto.createHash("sha3-512").update(bytes).digest("hex");

  var rs = await b.selfUpdate.swap({ from: from, to: to, backupTo: backupTo, expectedHash: hash });
  check("swap: locked target still installs (rename-away)", rs && rs.ok === true);
  check("swap: new bytes installed at target",  fs.readFileSync(to, "utf8") === "NEW-VERIFIED-BYTES");
  check("swap: old bytes preserved in backup",  fs.readFileSync(backupTo, "utf8") === "ORIGINAL-BYTES");
  check("swap: from consumed",                  !fs.existsSync(from));

  try { fs.chmodSync(to, 0o600); fs.unlinkSync(to); } catch (_e) { /* best-effort */ }
  try { fs.chmodSync(backupTo, 0o600); fs.unlinkSync(backupTo); } catch (_e) { /* best-effort */ }
  try { fs.unlinkSync(from); } catch (_e) { /* best-effort */ }
}

async function testRollbackCopyFailure() {
  // rollback fails closed when the restore copy cannot be written — here `to`
  // is an existing directory, so the atomic write of the restored bytes fails
  // and rollback surfaces selfupdate/rollback-failed.
  var dir = _tmp("dir-rbcopyfail");
  fs.mkdirSync(dir, { recursive: true });
  var backupTo = path.join(dir, "app.bak");
  fs.writeFileSync(backupTo, Buffer.from("BACKUP-BYTES"));
  var toDir = path.join(dir, "to-is-a-directory");
  fs.mkdirSync(toDir);

  var threw = null;
  try {
    await b.selfUpdate.rollback({ to: toDir, backupTo: backupTo });
  } catch (e) { threw = e; }
  check("rollback: unwritable restore target → selfupdate/rollback-failed",
        threw && /selfupdate\/rollback-failed/.test(threw.code || ""));

  try { fs.unlinkSync(backupTo); } catch (_e) { /* best-effort */ }
}

// ---- #495 — probation / rollback orchestration. Real on-disk markers under
// os.tmpdir(); the wall clock is injected via evaluateOnBoot({ now }) so the
// window edges are exercised deterministically (no sleeping). ----

function _sha3(bytes) { return nodeCrypto.createHash("sha3-512").update(bytes).digest("hex"); }

async function testProbationExpiredRollsBack() {
  // Edge 1 — the probation window elapses with no confirmHealthy (the new binary
  // ran but never reported healthy) → rollback restores the known-good backup.
  var dir = _tmp("dir-prob-exp");
  fs.mkdirSync(dir, { recursive: true });
  var to       = path.join(dir, "app.bin");
  var backupTo = path.join(dir, "app.bin.bak");
  var newBytes = Buffer.from("NEW-PROBATIONARY-BINARY");
  fs.writeFileSync(to, newBytes);                         // probationary binary installed at `to`
  fs.writeFileSync(backupTo, Buffer.from("OLD-KNOWN-GOOD"));
  var begun = await b.selfUpdate.beginProbation({
    to: to, backupTo: backupTo, expectedHash: _sha3(newBytes), windowMs: 60000,
  });
  check("beginProbation: returns a markerPath",  typeof begun.markerPath === "string");
  check("beginProbation: marker written to disk", fs.existsSync(begun.markerPath));

  var r = await b.selfUpdate.evaluateOnBoot({ to: to, now: begun.expiresAt + 1 });
  check("evaluateOnBoot: expired + unconfirmed → rollback", r.action === "rollback");
  check("evaluateOnBoot: restored the known-good backup",   fs.readFileSync(to, "utf8") === "OLD-KNOWN-GOOD");
  check("evaluateOnBoot: marker cleared after rollback",    !fs.existsSync(begun.markerPath));

  try { fs.unlinkSync(to); fs.unlinkSync(backupTo); } catch (_e) { /* best-effort */ }
}

async function testProbationCleanStopWithinWindowKeeps() {
  // Edge 2 — a clean stop / restart INSIDE the window must not be misread as a
  // crash: keep the new binary and leave the marker for the window to run out.
  var dir = _tmp("dir-prob-win");
  fs.mkdirSync(dir, { recursive: true });
  var to       = path.join(dir, "app.bin");
  var backupTo = path.join(dir, "app.bin.bak");
  var newBytes = Buffer.from("NEW-BINARY-IN-PROBATION");
  fs.writeFileSync(to, newBytes);
  fs.writeFileSync(backupTo, Buffer.from("OLD-BINARY"));
  var begun = await b.selfUpdate.beginProbation({
    to: to, backupTo: backupTo, expectedHash: _sha3(newBytes), windowMs: 60000,
  });
  var r = await b.selfUpdate.evaluateOnBoot({ to: to, now: begun.installedAt + 1 });
  check("evaluateOnBoot: within-window → keep",              r.action === "keep");
  check("evaluateOnBoot: within-window keeps the new binary", fs.readFileSync(to, "utf8") === "NEW-BINARY-IN-PROBATION");
  check("evaluateOnBoot: within-window keeps the marker",     fs.existsSync(begun.markerPath));

  try { fs.unlinkSync(begun.markerPath); } catch (_e) { /* best-effort */ }
  try { fs.unlinkSync(to); fs.unlinkSync(backupTo); } catch (_e) { /* best-effort */ }
}

async function testProbationConfirmAndFailedSwapNoPhantom() {
  // Edge 3a — confirmHealthy clears the marker (a clean/healthy signal): a later
  // boot finds no marker and keeps, never rolling back a healthy binary.
  var dir = _tmp("dir-prob-confirm");
  fs.mkdirSync(dir, { recursive: true });
  var to       = path.join(dir, "app.bin");
  var backupTo = path.join(dir, "app.bin.bak");
  var newBytes = Buffer.from("NEW-CONFIRMED-HEALTHY");
  fs.writeFileSync(to, newBytes);
  fs.writeFileSync(backupTo, Buffer.from("OLD-BINARY"));
  var begun = await b.selfUpdate.beginProbation({
    to: to, backupTo: backupTo, expectedHash: _sha3(newBytes), windowMs: 60000,
  });
  var conf = await b.selfUpdate.confirmHealthy({ to: to });
  check("confirmHealthy: clears the marker", conf.cleared === true && !fs.existsSync(begun.markerPath));
  var r = await b.selfUpdate.evaluateOnBoot({ to: to, now: begun.expiresAt + 1 });
  check("evaluateOnBoot: confirmed → keep (no marker)",  r.action === "keep");
  check("evaluateOnBoot: confirmed keeps the new binary", fs.readFileSync(to, "utf8") === "NEW-CONFIRMED-HEALTHY");

  // Edge 3b — a marker that SURVIVED a FAILED swap (recorded expectedHash of a
  // new binary that was never installed; `to` still holds the OLD binary) must
  // NOT phantom-rollback: the probationary binary isn't the one installed.
  var dir2 = _tmp("dir-prob-failswap");
  fs.mkdirSync(dir2, { recursive: true });
  var to2       = path.join(dir2, "app.bin");
  var backupTo2 = path.join(dir2, "app.bin.bak");
  fs.writeFileSync(to2, Buffer.from("OLD-BINARY-STILL-HERE"));        // swap failed — new never installed
  fs.writeFileSync(backupTo2, Buffer.from("OLD-BINARY-STILL-HERE"));
  var neverInstalled = _sha3(Buffer.from("NEW-BINARY-THAT-FAILED-TO-INSTALL"));
  var begun2 = await b.selfUpdate.beginProbation({
    to: to2, backupTo: backupTo2, expectedHash: neverInstalled, windowMs: 60000,
  });
  var r2 = await b.selfUpdate.evaluateOnBoot({ to: to2, now: begun2.expiresAt + 1 });
  check("evaluateOnBoot: failed-swap marker → no phantom rollback", r2.action === "keep");
  check("evaluateOnBoot: failed-swap `to` untouched", fs.readFileSync(to2, "utf8") === "OLD-BINARY-STILL-HERE");

  try { fs.unlinkSync(to); fs.unlinkSync(backupTo); } catch (_e) { /* best-effort */ }
  try { fs.unlinkSync(to2); fs.unlinkSync(backupTo2); fs.unlinkSync(begun2.markerPath); } catch (_e) { /* best-effort */ }
}

async function testProbationMarkerRecoverableAfterSpawnFailure() {
  // Edge 4 — the successor (new binary) fails to spawn / confirm. The marker
  // beginProbation wrote must be a complete, re-readable record the NEXT boot's
  // evaluateOnBoot recovers from (rollback), never a half-written / lost marker.
  var dir = _tmp("dir-prob-spawn");
  fs.mkdirSync(dir, { recursive: true });
  var to       = path.join(dir, "app.bin");
  var backupTo = path.join(dir, "app.bin.bak");
  var newBytes = Buffer.from("SUCCESSOR-THAT-DIED");
  fs.writeFileSync(to, newBytes);
  fs.writeFileSync(backupTo, Buffer.from("PRIOR-GOOD"));
  var begun = await b.selfUpdate.beginProbation({
    to: to, backupTo: backupTo, expectedHash: _sha3(newBytes), windowMs: 60000,
  });
  // Marker is a complete JSON record (recoverable — not lost by the spawn failure).
  var marker = JSON.parse(fs.readFileSync(begun.markerPath, "utf8"));
  check("probation marker is a complete record",
        marker.to === to && marker.backupTo === backupTo &&
        marker.expectedHash === _sha3(newBytes) && typeof marker.expiresAt === "number");
  check("probation marker records a generation", typeof marker.generation === "number");

  var r = await b.selfUpdate.evaluateOnBoot({ to: to, now: begun.expiresAt + 1 });
  check("evaluateOnBoot: recovers from spawn failure → rollback", r.action === "rollback");
  check("evaluateOnBoot: restored the prior-good binary", fs.readFileSync(to, "utf8") === "PRIOR-GOOD");

  try { fs.unlinkSync(to); fs.unlinkSync(backupTo); } catch (_e) { /* best-effort */ }
}

async function testProbationOptValidation() {
  // beginProbation requires to / backupTo / expectedHash; evaluateOnBoot requires to.
  var dir = _tmp("dir-prob-val");
  fs.mkdirSync(dir, { recursive: true });
  var t1 = null;
  try { await b.selfUpdate.beginProbation({ backupTo: "/x", expectedHash: "00" }); }
  catch (e) { t1 = e; }
  check("beginProbation: missing to → selfupdate/bad-to", t1 && /selfupdate\/bad-to/.test(t1.code || ""));

  var t2 = null;
  try { await b.selfUpdate.beginProbation({ to: "/x", backupTo: "/y" }); }
  catch (e) { t2 = e; }
  check("beginProbation: missing expectedHash → selfupdate/bad-expected-hash",
        t2 && /selfupdate\/bad-expected-hash/.test(t2.code || ""));

  var t3 = null;
  try { await b.selfUpdate.beginProbation({ to: "/x", backupTo: "/y", expectedHash: "00", windowMs: -1 }); }
  catch (e) { t3 = e; }
  check("beginProbation: bad windowMs → selfupdate/bad-window", t3 && /selfupdate\/bad-window/.test(t3.code || ""));

  var t4 = null;
  try { await b.selfUpdate.evaluateOnBoot({ backupTo: "/y" }); }
  catch (e) { t4 = e; }
  check("evaluateOnBoot: missing to → selfupdate/bad-to", t4 && /selfupdate\/bad-to/.test(t4.code || ""));

  // no-marker → keep(no-probation-active), never a rollback.
  var r = await b.selfUpdate.evaluateOnBoot({ to: path.join(dir, "absent.bin") });
  check("evaluateOnBoot: no marker → keep(no-probation-active)",
        r.action === "keep" && r.reason === "no-probation-active");

  try { fs.rmdirSync(dir); } catch (_e) { /* best-effort */ }
}

// selfUpdate.poll dials the releases endpoint through the shared httpClient
// keep-alive transport pool; a cached client socket finalizes its destroy on a
// later event-loop turn, past the forked worker's grace window. Reset the pool,
// then poll until every TCP handle (client sockets + any fixture-server accept
// socket) has actually drained so none outlives run().
async function _drainTcpHandles() {
  b.httpClient._resetForTest();
  if (typeof process.getActiveResourcesInfo !== "function") return;
  await helpers.waitUntil(function () {
    return process.getActiveResourcesInfo().filter(function (t) {
      return t === "TCPSocketWrap" || t === "TCPServerWrap";
    }).length === 0;
  }, { timeoutMs: 5000, label: "self-update: TCP handle drain after _resetForTest" });
}

async function run() {
  try {
    testSurface();
    testCompareTags();
    testCompareTagsFullPrecedence();
    await testPollRejectsBadOpts();
    await testPollRejectsUnsafeAssetPattern();
    await testPollAvailableAndUpToDate();
    await testPollArrayShape();
    await testPollNon2xxRefused();
    await testPoll304FastPath();
    await testPollNon2xxSurfacesTypedCode();
    await testPollEmptyArrayFeed();
    await testPollMalformedBodies();
    await testPollAvailableNoAssetMatch();
    await testPollDigestPassthrough();
    await testPollStringPatterns();
    await testPollRegexpPatterns();
    await testPollDowngradeRefusedWithEtag();
    await testPollOversizedFeedRefused();
    await testPollNonArrayAssetsAndMalformedEntries();
    await testPollSignaturePairsWithAsset();
    await testPollSignaturePairingEdgeCases();
    await testPollOptValidation();
    await testVerifyPassFail();
    await testVerifyErrorPaths();
    await testVerifyWrongKeyAndMalformedSig();
    await testVerifyEcdsaP384DigestCommitment();
    await testVerifyEcdsaP384Sha3P1363Accepted();
    await testVerifyMaxBytesBound();
    await testSwapAndRollback();
    await testSwapMissingFromRefused();
    await testSwapHashMismatchRefused();
    await testSwapSymlinkedFromRefused();
    await testSwapFreshInstall();
    await testSwapCustomHashAlgoRoundTrip();
    await testSwapMaxBytesBound();
    await testSwapBackupFailureLeavesOriginal();
    await testSwapSeparateBackupDir();
    await testSwapWriteFailureNoOriginal();
    await testSwapReplacesLockedTargetWin32();
    await testSwapRollbackOptValidation();
    await testRollbackMissingBackupRefused();
    await testRollbackCopyFailure();
    await testProbationExpiredRollsBack();
    await testProbationCleanStopWithinWindowKeeps();
    await testProbationConfirmAndFailedSwapNoPhantom();
    await testProbationMarkerRecoverableAfterSpawnFailure();
    await testProbationOptValidation();
  } finally {
    await _drainTcpHandles();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e.message); process.exit(1); }
  );
}
