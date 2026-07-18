// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * static — forceAttachmentForNonText defense for stored-XSS via
 * user-upload directories, plus the mountType typing that drives its
 * default (v0.15.0: "user-content" mounts force-download by default;
 * "curated" mounts keep inline render).
 *
 * Run standalone: `node test/layer-0-primitives/static.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var http = require("node:http");
var crypto = require("node:crypto");
var helpers = require("../helpers");
var b      = helpers.b;
var fs     = helpers.fs;
var os     = helpers.os;
var path   = helpers.path;
var check  = helpers.check;
var listenOnRandomPort = helpers.listenOnRandomPort;

function _writeFile(root, rel, content) {
  var abs = path.join(root, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content);
}

async function _server() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-fa-"));
  return {
    dir: dir,
    start: async function (opts) {
      b.staticServe._resetCacheForTest();
      var fn = b.staticServe.create(Object.assign({ root: dir }, opts || {}));
      var server = http.createServer(function (req, res) {
        fn(req, res, function () { res.writeHead(404); res.end("nf"); });
      });
      var port = await listenOnRandomPort(server);
      return {
        server: server, port: port,
        close: function () { server.close(); },
      };
    },
    cleanup: function () { fs.rmSync(dir, { recursive: true, force: true }); },
  };
}

function _get(port, urlPath, headers) {
  return new Promise(function (resolve, reject) {
    var req = http.request({
      hostname: "127.0.0.1", port: port, path: urlPath, method: "GET",
      headers: headers || undefined,
    }, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        resolve({ statusCode: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) });
      });
      res.on("error", reject);
    });
    req.on("error", reject);
    req.end();
  });
}

async function testForceAttachmentDefaultOff() {
  var ctx = await _server();
  _writeFile(ctx.dir, "evil.html", "<script>alert(1)</script>");
  var srv = await ctx.start({ contentSafety: null });
  try {
    var r = await _get(srv.port, "/evil.html");
    check("default OFF: html served inline (no forced attachment)",
          r.statusCode === 200 && !r.headers["content-disposition"]);
    check("default OFF: no nosniff added",
          r.headers["x-content-type-options"] === undefined);
  } finally {
    srv.close();
    ctx.cleanup();
  }
}

async function testForceAttachmentOnHtml() {
  var ctx = await _server();
  _writeFile(ctx.dir, "evil.html", "<script>alert(1)</script>");
  var srv = await ctx.start({
    contentSafety:             null,
    forceAttachmentForNonText: true,
  });
  try {
    var r = await _get(srv.port, "/evil.html");
    check("forceAttachment: html served with attachment",
          r.statusCode === 200 &&
          /^attachment;/.test(r.headers["content-disposition"] || ""));
    check("forceAttachment: html served with nosniff",
          r.headers["x-content-type-options"] === "nosniff");
    check("forceAttachment: filename in disposition",
          /filename="evil\.html"/.test(r.headers["content-disposition"] || ""));
  } finally {
    srv.close();
    ctx.cleanup();
  }
}

async function testForceAttachmentOnJs() {
  var ctx = await _server();
  _writeFile(ctx.dir, "evil.js", "alert('xss')");
  var srv = await ctx.start({
    contentSafety:             null,
    forceAttachmentForNonText: true,
  });
  try {
    var r = await _get(srv.port, "/evil.js");
    check("forceAttachment: js forced to attachment",
          /^attachment;/.test(r.headers["content-disposition"] || ""));
    check("forceAttachment: js gets nosniff",
          r.headers["x-content-type-options"] === "nosniff");
  } finally {
    srv.close();
    ctx.cleanup();
  }
}

async function testForceAttachmentTextStillInline() {
  var ctx = await _server();
  _writeFile(ctx.dir, "readme.txt", "plain text");
  var srv = await ctx.start({
    contentSafety:             null,
    forceAttachmentForNonText: true,
  });
  try {
    var r = await _get(srv.port, "/readme.txt");
    check("forceAttachment: text/plain still inline",
          r.statusCode === 200 && !r.headers["content-disposition"]);
    check("forceAttachment: text/plain no nosniff (irrelevant)",
          r.headers["x-content-type-options"] === undefined);
  } finally {
    srv.close();
    ctx.cleanup();
  }
}

async function testForceAttachmentRasterStillInline() {
  var ctx = await _server();
  // Minimal PNG (8-byte signature + 4-byte IHDR len + IHDR magic) is enough
  // for the Content-Type table, which keys off the .png extension.
  _writeFile(ctx.dir, "logo.png", Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  var srv = await ctx.start({
    contentSafety:             null,
    forceAttachmentForNonText: true,
  });
  try {
    var r = await _get(srv.port, "/logo.png");
    check("forceAttachment: image/png stays inline",
          r.statusCode === 200 && !r.headers["content-disposition"]);
  } finally {
    srv.close();
    ctx.cleanup();
  }
}

async function testForceAttachmentSvgWithoutSanitizer() {
  var ctx = await _server();
  _writeFile(ctx.dir, "evil.svg",
    "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>");
  // Disable contentSafety entirely so no SVG sanitizer is wired.
  var srv = await ctx.start({
    contentSafety:             null,
    forceAttachmentForNonText: true,
  });
  try {
    var r = await _get(srv.port, "/evil.svg");
    check("forceAttachment: svg without sanitizer forced to attachment",
          /^attachment;/.test(r.headers["content-disposition"] || ""));
    check("forceAttachment: svg gets nosniff",
          r.headers["x-content-type-options"] === "nosniff");
  } finally {
    srv.close();
    ctx.cleanup();
  }
}

async function testForceAttachmentSvgWithSanitizerInlineAllowed() {
  var ctx = await _server();
  _writeFile(ctx.dir, "logo.svg",
    "<svg xmlns=\"http://www.w3.org/2000/svg\"><circle cx=\"50\" cy=\"50\" r=\"10\"/></svg>");
  // Wire a fake SVG sanitizer gate that always passes — the gate's
  // presence in contentSafety is what unlocks inline render.
  var fakeGate = {
    check: async function (_args) { return { ok: true, action: "serve" }; },
  };
  var srv = await ctx.start({
    contentSafety:             { ".svg": fakeGate },
    forceAttachmentForNonText: true,
  });
  try {
    var r = await _get(srv.port, "/logo.svg");
    check("forceAttachment: svg with sanitizer gate stays inline",
          r.statusCode === 200 && !r.headers["content-disposition"]);
  } finally {
    srv.close();
    ctx.cleanup();
  }
}

async function testForceAttachmentPdfDefaultDownload() {
  var ctx = await _server();
  _writeFile(ctx.dir, "doc.pdf", "%PDF-1.4\n%%EOF\n");
  var srv = await ctx.start({
    contentSafety:             null,
    forceAttachmentForNonText: true,
  });
  try {
    var r = await _get(srv.port, "/doc.pdf");
    check("forceAttachment: pdf forced to attachment by default",
          /^attachment;/.test(r.headers["content-disposition"] || ""));
  } finally {
    srv.close();
    ctx.cleanup();
  }
}

async function testForceAttachmentPdfOptInInline() {
  var ctx = await _server();
  _writeFile(ctx.dir, "doc.pdf", "%PDF-1.4\n%%EOF\n");
  var srv = await ctx.start({
    contentSafety:             null,
    forceAttachmentForNonText: true,
    safeRenderPdf:             true,
  });
  try {
    var r = await _get(srv.port, "/doc.pdf");
    check("forceAttachment + safeRenderPdf: pdf stays inline",
          r.statusCode === 200 && !r.headers["content-disposition"]);
  } finally {
    srv.close();
    ctx.cleanup();
  }
}

// mountType drives the forceAttachmentForNonText default (v0.15.0).
// A mount TYPED "user-content" forces risky inline MIMEs to download with
// NO explicit forceAttachmentForNonText (the new default-on behavior); a
// "curated" mount (or unset) keeps inline render (the opt-out preserved).
async function testMountTypeUserContentForcesDownloadByDefault() {
  var ctx = await _server();
  _writeFile(ctx.dir, "evil.html", "<script>alert(1)</script>");
  // No forceAttachmentForNonText passed — the default comes from mountType.
  var srv = await ctx.start({ contentSafety: null, mountType: "user-content" });
  try {
    var r = await _get(srv.port, "/evil.html");
    check("mountType user-content: html forced to attachment by default",
          r.statusCode === 200 &&
          /^attachment;/.test(r.headers["content-disposition"] || ""));
    check("mountType user-content: nosniff added by default",
          r.headers["x-content-type-options"] === "nosniff");
  } finally {
    srv.close();
    ctx.cleanup();
  }
}

async function testMountTypeCuratedKeepsInline() {
  var ctx = await _server();
  _writeFile(ctx.dir, "evil.html", "<script>alert(1)</script>");
  // Explicit "curated" is the documented opt-out — inline render preserved.
  var srv = await ctx.start({ contentSafety: null, mountType: "curated" });
  try {
    var r = await _get(srv.port, "/evil.html");
    check("mountType curated: html served inline (opt-out preserved)",
          r.statusCode === 200 && !r.headers["content-disposition"]);
  } finally {
    srv.close();
    ctx.cleanup();
  }
}

async function testMountTypeExplicitOverrideWins() {
  var ctx = await _server();
  _writeFile(ctx.dir, "evil.html", "<script>alert(1)</script>");
  // An explicit forceAttachmentForNonText:false overrides the
  // user-content-derived default either way.
  var srv = await ctx.start({
    contentSafety: null, mountType: "user-content",
    forceAttachmentForNonText: false,
  });
  try {
    var r = await _get(srv.port, "/evil.html");
    check("explicit forceAttachmentForNonText:false overrides user-content default",
          r.statusCode === 200 && !r.headers["content-disposition"]);
  } finally {
    srv.close();
    ctx.cleanup();
  }
}

function testMountTypeBadValueThrows() {
  var threw = null;
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-mt-"));
  try {
    b.staticServe.create({ root: dir, mountType: "uploads" });
  } catch (e) { threw = e; }
  finally { fs.rmSync(dir, { recursive: true, force: true }); }
  check("bad mountType value throws at config time",
        threw && /mountType must be 'curated'/.test(threw.message));
}

function testRejectsUnknownOpts() {
  var threw = null;
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-fa-"));
  try {
    b.staticServe.create({ root: dir, unknownKey: "smell" });
  } catch (e) { threw = e; }
  check("unknown opt rejected at create()", threw !== null);
  fs.rmSync(dir, { recursive: true, force: true });
}

// hashedPathPattern is .test()'d against the attacker-controlled request
// path on every download; a catastrophic-backtracking (ReDoS) pattern is a
// per-request DoS. The screen runs at create() time, so a nested-quantifier
// pattern (`((a)+)+$` — WRAPPED nested quantifier) must be refused up front.
// The matched input stays trivial so the test never actually backtracks.
function testHashedPathPatternReDoSRefused() {
  var threw = null;
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-redos-"));
  try {
    b.staticServe.create({ root: dir, hashedPathPattern: /((a)+)+$/ });
  } catch (e) { threw = e; }
  finally { fs.rmSync(dir, { recursive: true, force: true }); }
  check("hashedPathPattern ReDoS shape refused at config time",
        threw && threw.code === "static/unsafe-pattern" &&
        /pattern rejected as unsafe/.test(threw.message));

  // The screen must ACCEPT the framework's own exported default when a caller
  // pins it explicitly — its `{8,}` open-ended repeat is a single linear
  // counted repeat, not catastrophic backtracking. (Rejecting it would break
  // configs that passed b.staticServe.DEFAULT_HASHED_PATTERN.)
  var okThrew = null;
  var dir2 = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-okpat-"));
  try {
    b.staticServe.create({ root: dir2, hashedPathPattern: b.staticServe.DEFAULT_HASHED_PATTERN });
  } catch (e) { okThrew = e; }
  finally { fs.rmSync(dir2, { recursive: true, force: true }); }
  check("hashedPathPattern accepts the exported DEFAULT_HASHED_PATTERN (bounded repeat is linear)",
        okThrew === null);
}

// onError mirrors onServe on the refusal paths. A denying permissions
// gate forces a 403, which previously fired no operator callback.
async function testOnErrorFiresOnRefusal() {
  var ctx = await _server();
  _writeFile(ctx.dir, "secret.txt", "classified");
  var seen = [];
  var denyPerms = { check: async function () { return false; } };
  var srv = await ctx.start({
    contentSafety: null,
    permissions:   denyPerms,
    onError:       function (info) { seen.push(info); },
  });
  try {
    var r = await _get(srv.port, "/secret.txt");
    check("onError: refusal returns 403",            r.statusCode === 403);
    check("onError: hook fired once on the refusal", seen.length === 1);
    check("onError: hook carries status + code + urlPath",
          seen[0].status === 403 && seen[0].code === "permission_denied" &&
          seen[0].urlPath === "/secret.txt");
  } finally {
    srv.close();
    ctx.cleanup();
  }
}

// onError is observability-only: a throwing hook must not corrupt the
// refusal response already on the wire.
async function testOnErrorThrowDoesNotCorruptResponse() {
  var ctx = await _server();
  _writeFile(ctx.dir, "secret.txt", "classified");
  var denyPerms = { check: async function () { return false; } };
  var srv = await ctx.start({
    contentSafety: null,
    permissions:   denyPerms,
    onError:       function () { throw new Error("sink broke"); },
  });
  try {
    var r = await _get(srv.port, "/secret.txt");
    check("onError: throwing hook still yields the 403",
          r.statusCode === 403 && /Forbidden/.test(r.body.toString("utf8")));
  } finally {
    srv.close();
    ctx.cleanup();
  }
}

function testOnErrorRejectsNonFunction() {
  var threw = null;
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-fa-"));
  try {
    b.staticServe.create({ root: dir, onError: "nope" });
  } catch (e) { threw = e; }
  check("onError non-function rejected at create()", threw !== null);
  fs.rmSync(dir, { recursive: true, force: true });
}

// Send a raw (un-normalized-by-node) request path. http.request normalizes
// "/../" on the client side, so build the request line by hand over a raw
// socket to deliver the traversal bytes verbatim to the server.
function _getRaw(port, rawPath) {
  var net = require("node:net");
  return new Promise(function (resolve, reject) {
    var sock = net.connect(port, "127.0.0.1", function () {
      sock.write("GET " + rawPath + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    });
    var chunks = [];
    sock.on("data", function (c) { chunks.push(c); });
    sock.on("end", function () {
      var raw = Buffer.concat(chunks).toString("utf8");
      var statusLine = raw.split("\r\n")[0] || "";
      var m = /^HTTP\/1\.\d (\d{3})/.exec(statusLine);
      var sep = raw.indexOf("\r\n\r\n");
      var body = sep === -1 ? "" : raw.slice(sep + 4);
      resolve({ statusCode: m ? parseInt(m[1], 10) : 0, body: body, raw: raw });
    });
    sock.on("error", reject);
  });
}

// Path-traversal refusal — a file OUTSIDE the served root must never be
// reachable via `../` escapes, percent-encoded escapes, or NUL injection.
// The secret is written to the parent of `root` so any successful escape
// would disclose it.
async function testPathTraversalRefused() {
  var ctx = await _server();
  // Sibling secret one level above the served root.
  var parent = path.dirname(ctx.dir);
  var secretName = "blamejs-static-secret-" + process.pid + ".txt";
  var secretAbs = path.join(parent, secretName);
  var secretBody = "TOP-SECRET-" + Date.now();
  fs.writeFileSync(secretAbs, secretBody);
  // A legit in-root file to prove the server is otherwise functional.
  _writeFile(ctx.dir, "ok.txt", "in-root");
  var srv = await ctx.start({ contentSafety: null });
  try {
    // Raw `../` traversal (delivered verbatim over a raw socket).
    var rawTrav = await _getRaw(srv.port, "/../" + secretName);
    check("traversal: raw ../ does not disclose the sibling secret",
          rawTrav.body.indexOf(secretBody) === -1);
    check("traversal: raw ../ refused (not 200-with-secret)",
          rawTrav.statusCode !== 200 || rawTrav.body.indexOf(secretBody) === -1);

    // Deeper raw traversal.
    var rawDeep = await _getRaw(srv.port, "/sub/../../" + secretName);
    check("traversal: nested raw ../../ does not disclose the secret",
          rawDeep.body.indexOf(secretBody) === -1);

    // Percent-encoded `..%2f` traversal (the server decodes, then must
    // still refuse).
    var encTrav = await _get(srv.port, "/%2e%2e%2f" + secretName);
    check("traversal: percent-encoded %2e%2e%2f refused (404/next)",
          encTrav.statusCode === 404);
    check("traversal: percent-encoded escape does not disclose the secret",
          encTrav.body.toString("utf8").indexOf(secretBody) === -1);

    // Double percent-encoded dot-dot.
    var encTrav2 = await _get(srv.port, "/%2e%2e/%2e%2e/" + secretName);
    check("traversal: %2e%2e/%2e%2e/ does not disclose the secret",
          encTrav2.body.toString("utf8").indexOf(secretBody) === -1);

    // NUL-byte injection — refused before any fs op.
    var nul = await _get(srv.port, "/ok.txt%00.png");
    check("traversal: NUL-byte path refused (404/next)",
          nul.statusCode === 404);

    // Sanity: the legit in-root file still serves.
    var ok = await _get(srv.port, "/ok.txt");
    check("traversal: in-root file still serves after refusals",
          ok.statusCode === 200 && ok.body.toString("utf8") === "in-root");
  } finally {
    srv.close();
    fs.rmSync(secretAbs, { force: true });
    ctx.cleanup();
  }
}

// Success path — a legitimately nested file under root is served with its
// bytes intact. Confirms the confinement barrier does not over-refuse.
async function testNestedFileServed() {
  var ctx = await _server();
  _writeFile(ctx.dir, "assets/css/site.css", "body{color:#000}");
  var srv = await ctx.start({ contentSafety: null });
  try {
    var r = await _get(srv.port, "/assets/css/site.css");
    check("nested: deep in-root file serves 200",
          r.statusCode === 200);
    check("nested: bytes intact",
          r.body.toString("utf8") === "body{color:#000}");
    check("nested: correct content-type",
          /text\/css/.test(r.headers["content-type"] || ""));
  } finally {
    srv.close();
    ctx.cleanup();
  }
}

// A directory-index request resolves to the index file inside root and
// serves it — exercises the re-confinement after the index-file join.
async function testDirectoryIndexServed() {
  var ctx = await _server();
  _writeFile(ctx.dir, "docs/index.html", "<h1>docs</h1>");
  var srv = await ctx.start({ contentSafety: null });
  try {
    var r = await _get(srv.port, "/docs/");
    check("dir-index: index.html served for a directory request",
          r.statusCode === 200 && /docs/.test(r.body.toString("utf8")));
  } finally {
    srv.close();
    ctx.cleanup();
  }
}

// RFC 7232 §3.3/§6: If-None-Match takes precedence over If-Modified-Since,
// and If-Match takes precedence over If-Unmodified-Since. When the strong
// entity-tag precondition is present, the recipient MUST ignore the
// date-based one — otherwise a changed resource is falsely reported 304, or
// an unchanged resource falsely 412'd.
async function testConditionalEntityTagPrecedence() {
  var ctx = await _server();
  _writeFile(ctx.dir, "doc.txt", "hello conditional");
  var srv = await ctx.start({ contentSafety: null });
  try {
    var base = await _get(srv.port, "/doc.txt");
    check("conditional: baseline serves 200 with ETag",
          base.statusCode === 200 && typeof base.headers.etag === "string");
    var future = new Date(Date.now() + 86400000).toUTCString();
    var past   = new Date(Date.now() - 86400000).toUTCString();

    // If-None-Match present + non-matching → resource changed; the
    // If-Modified-Since (future → would 304) must be ignored, serve 200.
    var r1 = await _get(srv.port, "/doc.txt", {
      "If-None-Match":     '"stale-does-not-match"',
      "If-Modified-Since": future,
    });
    check("If-None-Match (stale) overrides If-Modified-Since → 200, not 304",
          r1.statusCode === 200);

    // If-Match: * (matches) + If-Unmodified-Since (past → would 412) must
    // be ignored because If-Match is present and satisfied, serve 200.
    var r2 = await _get(srv.port, "/doc.txt", {
      "If-Match":            "*",
      "If-Unmodified-Since": past,
    });
    check("If-Match (*) overrides If-Unmodified-Since → 200, not 412",
          r2.statusCode === 200);
  } finally {
    srv.close();
    ctx.cleanup();
  }
}

// ---------------------------------------------------------------------------
// Shared fixture for the error / adversarial / defensive-branch coverage below.
// _ctx writes the fixture files, resets the module meta-cache, builds a real
// staticServe handle behind a localhost http server, and exposes the handle
// (fn) so revoke / stats / invalidateMeta can be driven through the operator
// surface. close() tears down the server AND the temp dir.
// ---------------------------------------------------------------------------
async function _ctx(opts, files) {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-cov-"));
  if (files) {
    Object.keys(files).forEach(function (rel) { _writeFile(dir, rel, files[rel]); });
  }
  b.staticServe._resetCacheForTest();
  var fn = b.staticServe.create(Object.assign({ root: dir }, opts || {}));
  var server = http.createServer(function (req, res) {
    fn(req, res, function () { res.writeHead(404); res.end("nf"); });
  });
  var port = await listenOnRandomPort(server);
  return {
    dir: dir, fn: fn, port: port, server: server,
    close: function () {
      server.close();
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

// Method-parametrized request driver (the module _get is GET-only).
function _req(port, method, urlPath, headers) {
  return new Promise(function (resolve, reject) {
    var req = http.request({
      hostname: "127.0.0.1", port: port, path: urlPath, method: method,
      headers: headers || undefined,
    }, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        resolve({ statusCode: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) });
      });
      res.on("error", reject);
    });
    req.on("error", reject);
    req.end();
  });
}

// --- Range requests (RFC 7233 single-range) ------------------------------

async function testRangeSingle() {
  var ctx = await _ctx({ contentSafety: null }, { "data.txt": "0123456789" });
  try {
    var r = await _get(ctx.port, "/data.txt", { "Range": "bytes=2-5" });
    check("range: single satisfiable range → 206",
          r.statusCode === 206);
    check("range: Content-Range reflects the served slice",
          r.headers["content-range"] === "bytes 2-5/10");
    check("range: Content-Length is the slice length",
          r.headers["content-length"] === "4");
    check("range: Accept-Ranges advertised", r.headers["accept-ranges"] === "bytes");
    check("range: body is exactly the requested bytes",
          r.body.toString("utf8") === "2345");
  } finally { ctx.close(); }
}

async function testRangeSuffixAndOpenEnded() {
  var ctx = await _ctx({ contentSafety: null }, { "data.txt": "0123456789" });
  try {
    var suffix = await _get(ctx.port, "/data.txt", { "Range": "bytes=-3" });
    check("range: suffix bytes=-3 serves the last 3 bytes → 206",
          suffix.statusCode === 206 && suffix.body.toString("utf8") === "789");
    check("range: suffix Content-Range",
          suffix.headers["content-range"] === "bytes 7-9/10");

    var open = await _get(ctx.port, "/data.txt", { "Range": "bytes=6-" });
    check("range: open-ended bytes=6- serves to EOF → 206",
          open.statusCode === 206 && open.body.toString("utf8") === "6789");

    // Suffix larger than the file clamps to the whole file (parser branch).
    var bigSuffix = await _get(ctx.port, "/data.txt", { "Range": "bytes=-99" });
    check("range: over-long suffix clamps to the full file → 206 whole body",
          bigSuffix.statusCode === 206 && bigSuffix.body.toString("utf8") === "0123456789");

    // End past EOF clamps to size-1 (parser branch).
    var clampEnd = await _get(ctx.port, "/data.txt", { "Range": "bytes=4-99" });
    check("range: end past EOF clamps to last byte → 206",
          clampEnd.statusCode === 206 && clampEnd.body.toString("utf8") === "456789");
  } finally { ctx.close(); }
}

async function testRangeMalformedAndMulti() {
  var ctx = await _ctx({ contentSafety: null }, { "data.txt": "0123456789" });
  try {
    var cases = [
      ["bytes=abc",   "no dash"],
      ["bytes=foo-bar", "non-numeric bounds"],
      ["items=0-1",   "wrong unit"],
      ["bytes=",      "empty spec"],
      ["bytes=5-2",   "end before start"],
      ["bytes=-0",    "zero-length suffix"],
    ];
    for (var i = 0; i < cases.length; i++) {
      var r = await _get(ctx.port, "/data.txt", { "Range": cases[i][0] });
      check("range: malformed (" + cases[i][1] + ") → 416",
            r.statusCode === 416 &&
            r.headers["content-range"] === "bytes */10");
    }
    var multi = await _get(ctx.port, "/data.txt", { "Range": "bytes=0-1,4-5" });
    check("range: multi-range refused → 416 (v1 ships single-range only)",
          multi.statusCode === 416 && multi.headers["content-range"] === "bytes */10");
  } finally { ctx.close(); }
}

async function testRangeUnsatisfiableAndTooLarge() {
  var ctx = await _ctx({ contentSafety: null }, { "data.txt": "0123456789" });
  try {
    var unsat = await _get(ctx.port, "/data.txt", { "Range": "bytes=50-60" });
    check("range: start past EOF is unsatisfiable → 416",
          unsat.statusCode === 416 && unsat.headers["content-range"] === "bytes */10");
  } finally { ctx.close(); }

  // maxRangeBytes caps a single Range (slowloris-range defense).
  var capped = await _ctx({ contentSafety: null, maxRangeBytes: 4 },
                          { "data.txt": "0123456789" });
  try {
    var tooBig = await _get(capped.port, "/data.txt", { "Range": "bytes=0-8" });
    check("range: length over maxRangeBytes → 416 range_too_large",
          tooBig.statusCode === 416 && tooBig.headers["content-range"] === "bytes */10");
    // A range within the cap still serves.
    var okRange = await _get(capped.port, "/data.txt", { "Range": "bytes=0-3" });
    check("range: within maxRangeBytes still serves → 206",
          okRange.statusCode === 206 && okRange.body.toString("utf8") === "0123");
  } finally { capped.close(); }
}

// acceptRanges:false disables the whole Range machinery — a Range header is
// ignored and the full body is served 200.
async function testAcceptRangesDisabled() {
  var ctx = await _ctx({ contentSafety: null, acceptRanges: false },
                       { "data.txt": "0123456789" });
  try {
    var r = await _get(ctx.port, "/data.txt", { "Range": "bytes=0-3" });
    check("acceptRanges:false: Range ignored, full body 200",
          r.statusCode === 200 && r.body.toString("utf8") === "0123456789");
    check("acceptRanges:false: no Accept-Ranges header",
          r.headers["accept-ranges"] === undefined);
  } finally { ctx.close(); }
}

// --- Conditional requests (RFC 7232) -------------------------------------

async function testConditionalHits() {
  var ctx = await _ctx({ contentSafety: null }, { "doc.txt": "conditional body" });
  try {
    var base = await _get(ctx.port, "/doc.txt");
    var etag = base.headers.etag;
    var lastMod = base.headers["last-modified"];
    check("conditional: baseline 200 exposes ETag + Last-Modified",
          base.statusCode === 200 && typeof etag === "string" && typeof lastMod === "string");

    // If-None-Match matching → 304, empty body.
    var inm = await _get(ctx.port, "/doc.txt", { "If-None-Match": etag });
    check("If-None-Match (matching) → 304 with empty body",
          inm.statusCode === 304 && inm.body.length === 0);
    check("304 carries the validator headers",
          inm.headers.etag === etag && typeof inm.headers["cache-control"] === "string");

    // If-Match non-matching → 412.
    var ifm = await _get(ctx.port, "/doc.txt", { "If-Match": '"not-the-etag"' });
    check("If-Match (non-matching strong validator) → 412", ifm.statusCode === 412);

    // If-Modified-Since in the future (no If-None-Match) → 304.
    var future = new Date(Date.now() + 86400000).toUTCString();
    var ims = await _get(ctx.port, "/doc.txt", { "If-Modified-Since": future });
    check("If-Modified-Since (future) → 304", ims.statusCode === 304);

    // If-Unmodified-Since in the past (no If-Match) → 412.
    var past = new Date(Date.now() - 86400000).toUTCString();
    var ius = await _get(ctx.port, "/doc.txt", { "If-Unmodified-Since": past });
    check("If-Unmodified-Since (past) → 412", ius.statusCode === 412);
  } finally { ctx.close(); }
}

// --- HEAD -----------------------------------------------------------------

async function testHeadRequest() {
  var ctx = await _ctx({ contentSafety: null }, { "page.html": "<h1>hi</h1>" });
  try {
    var r = await _req(ctx.port, "HEAD", "/page.html");
    check("HEAD: 200 with headers, no body",
          r.statusCode === 200 && r.body.length === 0);
    check("HEAD: Content-Length reflects the file size",
          r.headers["content-length"] === String(Buffer.byteLength("<h1>hi</h1>")));
    check("HEAD: ETag + X-Integrity present",
          typeof r.headers.etag === "string" &&
          /^sha384-/.test(r.headers["x-integrity"] || ""));
  } finally { ctx.close(); }
}

// --- safeAttachmentForRiskyMimes (distinct from forceAttachmentForNonText) --

async function testSafeAttachmentRiskyMime() {
  var ctx = await _ctx({ contentSafety: null, safeAttachmentForRiskyMimes: true },
                       { "page.html": "<h1>hi</h1>" });
  try {
    var r = await _get(ctx.port, "/page.html");
    check("safeAttachmentForRiskyMimes: risky text/html forced to attachment",
          r.statusCode === 200 &&
          /^attachment;/.test(r.headers["content-disposition"] || ""));
    check("safeAttachmentForRiskyMimes: filename encoded in disposition",
          /filename="page\.html"/.test(r.headers["content-disposition"] || ""));
  } finally { ctx.close(); }
}

// --- onServe hook ---------------------------------------------------------

async function testOnServeMutatesHeaders() {
  var seen = [];
  var ctx = await _ctx({
    contentSafety: null,
    onServe: function (info) {
      seen.push(info);
      info.headers["X-Custom-Serve"] = "yes";
    },
  }, { "a.txt": "abc" });
  try {
    var r = await _get(ctx.port, "/a.txt");
    check("onServe: fires on the success path and can mutate headers",
          r.statusCode === 200 && r.headers["x-custom-serve"] === "yes");
    check("onServe: receives the serve context",
          seen.length === 1 && seen[0].urlPath === "/a.txt" && seen[0].size === 3);
  } finally { ctx.close(); }
}

async function testOnServeThrows() {
  var ctx = await _ctx({
    contentSafety: null,
    onServe: function () { throw new Error("hook boom"); },
  }, { "a.txt": "abc" });
  try {
    var r = await _get(ctx.port, "/a.txt");
    check("onServe: a throwing hook fails closed with 500 (never partial 200)",
          r.statusCode === 500 && /Internal Server Error/.test(r.body.toString("utf8")));
  } finally { ctx.close(); }
}

// --- content-safety gate branches ----------------------------------------

async function testContentSafetyRefuse() {
  var gate = { check: async function () { return { ok: false, action: "refuse", issues: [] }; } };
  var ctx = await _ctx({ contentSafety: { ".csv": gate } }, { "rows.csv": "a,b\n1,2" });
  try {
    var r = await _get(ctx.port, "/rows.csv");
    check("content-safety: gate refuse → 415 opaque", r.statusCode === 415);
  } finally { ctx.close(); }
}

async function testContentSafetySanitize() {
  var gate = {
    check: async function () {
      return { ok: true, action: "sanitize", sanitized: Buffer.from("SAFE-BYTES") };
    },
  };
  var ctx = await _ctx({ contentSafety: { ".csv": gate } }, { "rows.csv": "a,b\n1,2" });
  try {
    var r = await _get(ctx.port, "/rows.csv");
    check("content-safety: sanitize serves the replacement bytes → 200",
          r.statusCode === 200 && r.body.toString("utf8") === "SAFE-BYTES");
    check("content-safety: sanitized Content-Length matches the override",
          r.headers["content-length"] === "10");
    check("content-safety: sanitized override drops Content-Range",
          r.headers["content-range"] === undefined);
  } finally { ctx.close(); }
}

async function testContentSafetySanitizeIntegrityHeaders() {
  // When the content-safety gate REPLACES the served bytes (sanitize), the
  // strong ETag and the SRI X-Integrity header must describe the bytes
  // ACTUALLY DELIVERED — not the on-disk original the meta cache hashed.
  // Otherwise a consumer verifying the served body against the advertised
  // X-Integrity fails, and a strong-validator / If-None-Match cache is keyed
  // to a representation the client never receives (RFC 7232 §2.3 strong
  // validator; W3C SRI).
  var sanitized = Buffer.from("SAFE-BYTES");
  var gate = {
    check: async function () {
      return { ok: true, action: "sanitize", sanitized: sanitized };
    },
  };
  var ctx = await _ctx({ contentSafety: { ".csv": gate } },
    { "rows.csv": "a,b\n1,2,ORIGINAL-BYTES-THAT-DIFFER-FROM-SANITIZED" });
  try {
    var r = await _get(ctx.port, "/rows.csv");
    var expectEtag = '"' +
      crypto.createHash("sha3-512").update(sanitized).digest("hex").slice(0, 32) + '"';
    var expectSri = "sha384-" +
      crypto.createHash("sha384").update(sanitized).digest("base64");
    check("content-safety: sanitized ETag hashes the DELIVERED bytes, not the original",
          r.headers["etag"] === expectEtag);
    check("content-safety: sanitized X-Integrity (SRI) hashes the DELIVERED bytes",
          r.headers["x-integrity"] === expectSri);
    // A consumer that verifies the served body against the advertised
    // X-Integrity must succeed.
    var deliveredSri = "sha384-" +
      crypto.createHash("sha384").update(r.body).digest("base64");
    check("content-safety: served body verifies against its advertised X-Integrity",
          deliveredSri === r.headers["x-integrity"]);
    // Conditional revalidation with the advertised ETag round-trips to 304
    // (the strong validator names the representation that is actually served).
    var r304 = await _get(ctx.port, "/rows.csv", { "If-None-Match": r.headers["etag"] });
    check("content-safety: If-None-Match with the advertised (sanitized) ETag → 304",
          r304.statusCode === 304);
  } finally { ctx.close(); }
}

async function testContentSafetyThrows() {
  var gate = { check: async function () { throw new Error("gate exploded"); } };
  var ctx = await _ctx({ contentSafety: { ".csv": gate } }, { "rows.csv": "a,b\n1,2" });
  try {
    var r = await _get(ctx.port, "/rows.csv");
    check("content-safety: a throwing gate fails closed → 500", r.statusCode === 500);
  } finally { ctx.close(); }
}

async function testContentSafetyTooLarge() {
  // A gated file over the 16 MiB inspection cap is refused before the gate
  // buffers it (request-reachable OOM defense) — the gate's check is never
  // invoked.
  var gateCalled = false;
  var gate = { check: async function () { gateCalled = true; return { ok: true, action: "serve" }; } };
  var big = Buffer.alloc(16 * 1024 * 1024 + 1);
  var ctx = await _ctx({ contentSafety: { ".bin": gate } }, { "huge.bin": big });
  try {
    var r = await _get(ctx.port, "/huge.bin");
    check("content-safety: file over the inspection cap → 415 (not buffered)",
          r.statusCode === 415);
    check("content-safety: oversize file never reaches the gate", gateCalled === false);
  } finally { ctx.close(); }
}

// --- MIME allowlist (magic-byte sniff via b.fileType) ---------------------

async function testMimeAllowlistSuccess() {
  var png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0]);
  var ctx = await _ctx({
    contentSafety: null, fileType: b.fileType, allowedFileTypes: ["image/png"],
  }, { "logo.png": png });
  try {
    var r = await _get(ctx.port, "/logo.png");
    check("mime-allowlist: sniffed image/png in the allowlist → 200", r.statusCode === 200);
  } finally { ctx.close(); }
}

async function testMimeAllowlistRejections() {
  var png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0]);
  var notAllowed = await _ctx({
    contentSafety: null, fileType: b.fileType, allowedFileTypes: ["image/jpeg"],
  }, { "logo.png": png });
  try {
    var r = await _get(notAllowed.port, "/logo.png");
    check("mime-allowlist: sniffed MIME not in the allowlist → 415", r.statusCode === 415);
  } finally { notAllowed.close(); }

  // A file whose magic bytes are indeterminate (plain text) is also refused
  // when an allowlist is active.
  var indet = await _ctx({
    contentSafety: null, fileType: b.fileType, allowedFileTypes: ["image/png"],
  }, { "notes.png": "this is really just text, not a png" });
  try {
    var r2 = await _get(indet.port, "/notes.png");
    check("mime-allowlist: indeterminate magic bytes → 415", r2.statusCode === 415);
  } finally { indet.close(); }
}

// --- Force-revoke (404, opaque) ------------------------------------------

async function testRevokeLocal() {
  var ctx = await _ctx({ contentSafety: null }, { "secret.txt": "classified" });
  try {
    var before = await _get(ctx.port, "/secret.txt");
    check("revoke: file serves before revocation", before.statusCode === 200);
    await ctx.fn.revoke(path.join(ctx.dir, "secret.txt"));
    var after = await _get(ctx.port, "/secret.txt");
    check("revoke: revoked file → 404 (opaque to clients)", after.statusCode === 404);
    await ctx.fn.unrevoke(path.join(ctx.dir, "secret.txt"));
    var restored = await _get(ctx.port, "/secret.txt");
    check("revoke: unrevoke restores serving", restored.statusCode === 200);
  } finally { ctx.close(); }
}

async function testRevokeStore() {
  var revoked = true;
  var calls = { revoke: 0, unrevoke: 0 };
  var revokeStore = {
    isRevoked: async function () { return revoked; },
    revoke:    async function () { calls.revoke += 1; revoked = true; },
    unrevoke:  async function () { calls.unrevoke += 1; revoked = false; },
  };
  var ctx = await _ctx({ contentSafety: null, revokeStore: revokeStore },
                       { "f.txt": "body" });
  try {
    var r = await _get(ctx.port, "/f.txt");
    check("revokeStore: isRevoked(true) → 404", r.statusCode === 404);
    var res = await ctx.fn.revoke("k");
    check("revokeStore: fn.revoke routes to the store", calls.revoke === 1 && res.ok === true);
    var res2 = await ctx.fn.unrevoke("k");
    check("revokeStore: fn.unrevoke routes to the store", calls.unrevoke === 1 && res2.ok === true);
    var r2 = await _get(ctx.port, "/f.txt");
    check("revokeStore: after unrevoke the file serves again", r2.statusCode === 200);
  } finally { ctx.close(); }
}

// --- Compliance retention (451) ------------------------------------------

async function testRetentionBlocked() {
  var retention = { isServable: async function () { return false; } };
  var ctx = await _ctx({ contentSafety: null, retention: retention },
                       { "record.txt": "phi" });
  try {
    var r = await _get(ctx.port, "/record.txt");
    check("retention: non-servable file → 451 Unavailable For Legal Reasons",
          r.statusCode === 451);
  } finally { ctx.close(); }

  // A retention check that throws fails closed (also 451).
  var throwing = { isServable: async function () { throw new Error("retention backend down"); } };
  var ctx2 = await _ctx({ contentSafety: null, retention: throwing },
                        { "record.txt": "phi" });
  try {
    var r2 = await _get(ctx2.port, "/record.txt");
    check("retention: a throwing check fails closed → 451", r2.statusCode === 451);
  } finally { ctx2.close(); }
}

// --- Bandwidth / concurrency quotas (429, cluster-shared via b.cache) ------

async function testConcurrencyCapRejected() {
  var cache = b.cache.create({ namespace: "static-conc-" + process.pid, backend: "memory" });
  var ctx = await _ctx({
    contentSafety: null, cache: cache, maxConcurrentDownloadsPerActor: 1,
  }, { "f.txt": "body" });
  try {
    // Seed the per-actor concurrency counter above the cap for every plausible
    // localhost actor key so the gate rejects deterministically (no request race).
    var ipCands = ["127.0.0.1", "::1", "::ffff:127.0.0.1"];
    for (var i = 0; i < ipCands.length; i++) {
      await cache.set("static:conc:ip:" + ipCands[i], 5);
    }
    var r = await _get(ctx.port, "/f.txt");
    check("concurrency-cap: actor at the cap → 429", r.statusCode === 429);
    check("concurrency-cap: Retry-After advertised", r.headers["retry-after"] === "5");
  } finally {
    ctx.close();
    if (typeof cache.close === "function") await cache.close();
  }
}

async function testBandwidthCapRejected() {
  var cache = b.cache.create({ namespace: "static-bw-" + process.pid, backend: "memory" });
  var ctx = await _ctx({
    contentSafety: null, cache: cache, maxBytesAllActorsPerWindowMs: 4,
  }, { "f.txt": "0123456789" });
  try {
    // Pre-charge the global bandwidth window above the cap.
    await cache.set("static:bw:global", 1000);
    var r = await _get(ctx.port, "/f.txt");
    check("bandwidth-cap: global window over cap → 429", r.statusCode === 429);
    check("bandwidth-cap: Retry-After advertised",
          typeof r.headers["retry-after"] === "string");
  } finally {
    ctx.close();
    if (typeof cache.close === "function") await cache.close();
  }
}

async function testQuotaSuccessConsumesAndReleases() {
  var cache = b.cache.create({ namespace: "static-ok-" + process.pid, backend: "memory" });
  var ctx = await _ctx({
    contentSafety: null, cache: cache,
    maxBytesPerActorPerWindowMs:  1000000,
    maxBytesAllActorsPerWindowMs: 1000000,
    maxConcurrentDownloadsPerActor: 4,
  }, { "f.txt": "0123456789" });
  try {
    var r = await _get(ctx.port, "/f.txt");
    check("quota-success: under-cap request serves 200 with full body",
          r.statusCode === 200 && r.body.toString("utf8") === "0123456789");
    // Bandwidth is charged on stream end (fire-and-forget) — poll for it.
    await helpers.waitUntil(async function () {
      return ((await cache.get("static:bw:global")) || 0) >= 10;
    }, { timeoutMs: 5000, label: "static quota: global bandwidth counter charged after serve" });
    check("quota-success: served bytes charged to the global window",
          ((await cache.get("static:bw:global")) || 0) >= 10);
    // Concurrency slot released back to 0 after the stream ends.
    await helpers.waitUntil(async function () {
      var ip = ["127.0.0.1", "::1", "::ffff:127.0.0.1"];
      for (var i = 0; i < ip.length; i++) {
        if (((await cache.get("static:conc:ip:" + ip[i])) || 0) > 0) return false;
      }
      return true;
    }, { timeoutMs: 5000, label: "static quota: concurrency slot released after serve" });
    check("quota-success: concurrency slot released after the stream ends", true);
  } finally {
    ctx.close();
    if (typeof cache.close === "function") await cache.close();
  }
}

// --- create() config-time validation (throw tier) -------------------------

function testCreateValidationThrows() {
  function throwsOn(opts, label) {
    var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-val-"));
    var threw = null;
    try { b.staticServe.create(Object.assign({ root: dir }, opts)); }
    catch (e) { threw = e; }
    finally { fs.rmSync(dir, { recursive: true, force: true }); }
    check("validation: " + label + " throws at create()", threw !== null);
    return threw;
  }

  // root does not exist
  var noRoot = null;
  try { b.staticServe.create({ root: path.join(os.tmpdir(), "blamejs-does-not-exist-" + process.pid) }); }
  catch (e) { noRoot = e; }
  check("validation: non-existent root throws",
        noRoot && /root does not exist/.test(noRoot.message));

  throwsOn({ allowedFileTypes: ["image/png"] }, "allowedFileTypes without fileType");
  throwsOn({ maxBytesPerActorPerWindowMs: 100 }, "bandwidth quota without cache");
  throwsOn({ maxConcurrentDownloadsPerActor: 2, cache: { get: function () {} } },
           "quota cache lacking atomic update()");
  throwsOn({ maxRangeBytes: -1 }, "negative maxRangeBytes");
  throwsOn({ hashedPathPattern: "not-a-regexp" }, "non-RegExp hashedPathPattern");
  throwsOn({ contentSafety: { ".csv": { notAGate: true } } }, "contentSafety value missing check()");
  throwsOn({ mountPath: 123 }, "non-string mountPath");

  // mountPath:"" is the documented "no mount" sentinel — must NOT throw.
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-val-"));
  var okThrew = null;
  try { b.staticServe.create({ root: dir, mountPath: "", contentSafety: null }); }
  catch (e) { okThrew = e; }
  finally { fs.rmSync(dir, { recursive: true, force: true }); }
  check("validation: empty-string mountPath is accepted (no mount)", okThrew === null);
}

// --- integrity() module helper (SRI) --------------------------------------

async function testIntegrityHelper() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-sri-"));
  var abs = path.join(dir, "asset.js");
  fs.writeFileSync(abs, "console.log(1)");
  try {
    var sri = await b.staticServe.integrity(abs);
    check("integrity: returns an sha384- SRI digest for a real file",
          typeof sri === "string" && /^sha384-[A-Za-z0-9+/=]+$/.test(sri));

    var emptyThrew = null;
    try { await b.staticServe.integrity(""); } catch (e) { emptyThrew = e; }
    check("integrity: empty path throws BAD_OPT",
          emptyThrew && emptyThrew.code === "BAD_OPT");

    var missingThrew = null;
    try { await b.staticServe.integrity(path.join(dir, "nope.js")); }
    catch (e) { missingThrew = e; }
    check("integrity: missing file throws NOT_FOUND",
          missingThrew && missingThrew.code === "NOT_FOUND");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// --- fn handle surface: stats() + invalidateMeta() ------------------------

async function testStatsAndInvalidateMeta() {
  var ctx = await _ctx({ contentSafety: null }, { "a.txt": "abc", "b.txt": "defgh" });
  try {
    await _get(ctx.port, "/a.txt");
    var etagHit = await _get(ctx.port, "/a.txt");
    // Second identical request with the ETag → counts an etag hit.
    var base = await _get(ctx.port, "/b.txt");
    await _get(ctx.port, "/b.txt", { "If-None-Match": base.headers.etag });
    var s = ctx.fn.stats();
    check("stats: requestsServed accumulates", s.requestsServed >= 2);
    check("stats: bytesServed accumulates", s.bytesServed >= 3);
    check("stats: etagHits counted for a matching conditional", s.etagHits >= 1);
    check("stats: returns a copy (mutating it does not corrupt internal state)",
          (function () { s.requestsServed = -999; return ctx.fn.stats().requestsServed !== -999; })());
    void etagHit;

    var inv = ctx.fn.invalidateMeta(path.join(ctx.dir, "a.txt"));
    check("invalidateMeta: returns ok for the evicted key",
          inv.ok === true && inv.key === path.join(ctx.dir, "a.txt"));
  } finally { ctx.close(); }
}

// --- contentSafety:null audit emission ------------------------------------

async function testContentSafetyDisabledAudit() {
  var rows = [];
  var audit = { safeEmit: function (row) { rows.push(row); } };
  var ctx = await _ctx({
    contentSafety: null, audit: audit,
    contentSafetyDisabledReason: "trusted-curated-assets",
  }, { "a.txt": "abc" });
  try {
    var disabledRow = rows.filter(function (r) {
      return r.action === "staticServe.contentSafety.disabled";
    })[0];
    check("contentSafety:null emits an audit row recording the opt-out",
          !!disabledRow && disabledRow.metadata.reason === "trusted-curated-assets");
  } finally { ctx.close(); }
}

// --- hashed-asset immutable Cache-Control ---------------------------------

async function testHashedImmutableCacheControl() {
  var ctx = await _ctx({ contentSafety: null }, { "app.abcdef12.js": "x=1" });
  try {
    var r = await _get(ctx.port, "/app.abcdef12.js");
    check("hashed asset: immutable long-max-age Cache-Control",
          r.statusCode === 200 && /immutable/.test(r.headers["cache-control"] || ""));
    var plain = await _ctx({ contentSafety: null }, { "app.js": "x=1" });
    try {
      var r2 = await _get(plain.port, "/app.js");
      check("non-hashed asset: short-max-age Cache-Control (no immutable)",
            !/immutable/.test(r2.headers["cache-control"] || ""));
    } finally { plain.close(); }
  } finally { ctx.close(); }
}

// --- mountPath stripping --------------------------------------------------

async function testMountPathStrip() {
  var ctx = await _ctx({ contentSafety: null, mountPath: "/static" },
                       { "site.css": "body{}" });
  try {
    var r = await _get(ctx.port, "/static/site.css");
    check("mountPath: prefix stripped, file served from root",
          r.statusCode === 200 && r.body.toString("utf8") === "body{}");
  } finally { ctx.close(); }
}

// --- indexFile:null disables directory-index serving ----------------------

async function testIndexFileDisabled() {
  var ctx = await _ctx({ contentSafety: null, indexFile: null },
                       { "docs/index.html": "<h1>x</h1>" });
  try {
    var r = await _get(ctx.port, "/docs/");
    check("indexFile:null: directory request falls through → 404",
          r.statusCode === 404);
  } finally { ctx.close(); }
}

// --- _shouldForceAttachment extension-fallback branches -------------------

async function testForceAttachmentExtFallback() {
  // A .zip served as the generic octet-stream, forced download (final
  // catch-all return true).
  var zip = await _ctx({ contentSafety: null, forceAttachmentForNonText: true },
                       { "bundle.zip": "PKstuff" });
  try {
    var r = await _get(zip.port, "/bundle.zip");
    check("force-attachment: octet-stream .zip forced to download",
          /^attachment;/.test(r.headers["content-disposition"] || ""));
  } finally { zip.close(); }

  // A .svg mislabeled as octet-stream but backed by a sanitizer gate renders
  // inline via the extension-fallback safe-render allowance.
  var svgGate = { check: async function () { return { ok: true, action: "serve" }; } };
  var svg = await _ctx({
    forceAttachmentForNonText: true,
    contentTypes:  { ".svg": "application/octet-stream" },
    contentSafety: { ".svg": svgGate },
  }, { "icon.svg": "<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>" });
  try {
    var r2 = await _get(svg.port, "/icon.svg");
    check("force-attachment: octet-stream .svg with a sanitizer gate renders inline",
          r2.statusCode === 200 && !r2.headers["content-disposition"]);
  } finally { svg.close(); }
}

// Per-actor bandwidth window (distinct scope from the global window).
async function testBandwidthPerActorCapRejected() {
  var cache = b.cache.create({ namespace: "static-bwa-" + process.pid, backend: "memory" });
  var ctx = await _ctx({
    contentSafety: null, cache: cache, maxBytesPerActorPerWindowMs: 4,
  }, { "f.txt": "0123456789" });
  try {
    var ipCands = ["127.0.0.1", "::1", "::ffff:127.0.0.1"];
    for (var i = 0; i < ipCands.length; i++) {
      await cache.set("static:bw:actor:ip:" + ipCands[i], 1000);
    }
    var r = await _get(ctx.port, "/f.txt");
    check("bandwidth-cap: per-actor window over cap → 429", r.statusCode === 429);
  } finally {
    ctx.close();
    if (typeof cache.close === "function") await cache.close();
  }
}

// The atomic counter retries the whole read-modify-write when the cache
// signals UPDATE_CONTENTION (cluster CAS lost the race); a stub cache that
// throws contention once then delegates proves the retry recovers.
async function testCounterRetriesOnContention() {
  var real = b.cache.create({ namespace: "static-cas-" + process.pid, backend: "memory" });
  var threwOnce = false;
  var stub = {
    get: function (k) { return real.get(k); },
    set: function (k, v, o) { return real.set(k, v, o); },
    update: async function (k, fn, o) {
      if (!threwOnce) {
        threwOnce = true;
        var e = new Error("cluster CAS lost the race");
        e.code = "UPDATE_CONTENTION";
        throw e;
      }
      return real.update(k, fn, o);
    },
  };
  var ctx = await _ctx({
    contentSafety: null, cache: stub, maxConcurrentDownloadsPerActor: 4,
  }, { "f.txt": "body" });
  try {
    var r = await _get(ctx.port, "/f.txt");
    check("counter-contention: serve recovers after an UPDATE_CONTENTION retry → 200",
          r.statusCode === 200 && r.body.toString("utf8") === "body");
    check("counter-contention: the contention path was actually exercised",
          threwOnce === true);
  } finally {
    ctx.close();
    if (typeof real.close === "function") await real.close();
  }
}

// A malformed percent-encoding makes decodeURIComponent throw; the middleware
// falls through to next() (404) rather than surfacing the decode error.
async function testMalformedPercentEncoding() {
  var ctx = await _ctx({ contentSafety: null }, { "ok.txt": "ok" });
  try {
    var r = await _get(ctx.port, "/%zz");
    check("decode: malformed %-escape falls through to 404", r.statusCode === 404);
  } finally { ctx.close(); }
}

// A request whose path equals the mount prefix exactly resolves to root "/".
async function testMountPathExactMatch() {
  var ctx = await _ctx({ contentSafety: null, mountPath: "/static" },
                       { "index.html": "<h1>root index</h1>" });
  try {
    var r = await _get(ctx.port, "/static");
    check("mountPath: request equal to the mount prefix resolves to the root index",
          r.statusCode === 200 && /root index/.test(r.body.toString("utf8")));
  } finally { ctx.close(); }
}

// safeRenderSvg:false forces an SVG to download even with a sanitizer wired.
async function testSafeRenderSvgDisabled() {
  var svgGate = { check: async function () { return { ok: true, action: "serve" }; } };
  var ctx = await _ctx({
    forceAttachmentForNonText: true, safeRenderSvg: false,
    contentSafety: { ".svg": svgGate },
  }, { "icon.svg": "<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>" });
  try {
    var r = await _get(ctx.port, "/icon.svg");
    check("safeRenderSvg:false forces SVG to download even with a sanitizer gate",
          /^attachment;/.test(r.headers["content-disposition"] || ""));
  } finally { ctx.close(); }
}

// contentSafety:null with an audit sink but no explicit reason records the
// default opt-out reason.
async function testContentSafetyDisabledDefaultReason() {
  var rows = [];
  var audit = { safeEmit: function (row) { rows.push(row); } };
  var ctx = await _ctx({ contentSafety: null, audit: audit }, { "a.txt": "abc" });
  try {
    var row = rows.filter(function (r) {
      return r.action === "staticServe.contentSafety.disabled";
    })[0];
    check("contentSafety:null without a reason records the default opt-out reason",
          !!row && row.metadata.reason === "operator-explicit-opt-out");
  } finally { ctx.close(); }
}

// A revokeStore whose isRevoked() throws fails open on the revocation check
// (the file still serves) — a revoke-store outage must not 404 every asset.
async function testRevokeStoreIsRevokedThrows() {
  var revokeStore = {
    isRevoked: async function () { throw new Error("revoke backend down"); },
    revoke:    async function () {},
  };
  var ctx = await _ctx({ contentSafety: null, revokeStore: revokeStore },
                       { "f.txt": "body" });
  try {
    var r = await _get(ctx.port, "/f.txt");
    check("revokeStore: a throwing isRevoked() does not block serving (200)",
          r.statusCode === 200 && r.body.toString("utf8") === "body");
  } finally { ctx.close(); }
}

// create() with no argument still runs the required-opt validation (opts||{}).
function testCreateNoArgThrows() {
  var threw = null;
  try { b.staticServe.create(); } catch (e) { threw = e; }
  check("create() with no opts throws (root is required)",
        threw && /root/.test(threw.message));
}

// The _get helper drives each fixture server with a default-agent http.request
// (keep-alive), and srv.close() runs fire-and-forget. The kept-alive client
// sockets, the servers' accept sockets, and any in-flight static-file read
// (FSReqCallback) finalize their teardown on a later event-loop turn — past the
// forked worker's grace window. Destroy the global-agent socket pool, then poll
// until every TCP/fs handle has drained so none outlives run().
async function _drainTcpHandles() {
  http.globalAgent.destroy();
  if (typeof process.getActiveResourcesInfo !== "function") return;
  await helpers.waitUntil(function () {
    return process.getActiveResourcesInfo().filter(function (t) {
      return t === "TCPSocketWrap" || t === "TCPServerWrap" || t === "FSReqCallback";
    }).length === 0;
  }, { timeoutMs: 5000, label: "static: TCP/fs handle drain after globalAgent.destroy" });
}

async function run() {
  try {
    await testConditionalEntityTagPrecedence();
    await testForceAttachmentDefaultOff();
    await testForceAttachmentOnHtml();
    await testForceAttachmentOnJs();
    await testForceAttachmentTextStillInline();
    await testForceAttachmentRasterStillInline();
    await testForceAttachmentSvgWithoutSanitizer();
    await testForceAttachmentSvgWithSanitizerInlineAllowed();
    await testForceAttachmentPdfDefaultDownload();
    await testForceAttachmentPdfOptInInline();
    await testMountTypeUserContentForcesDownloadByDefault();
    await testMountTypeCuratedKeepsInline();
    await testMountTypeExplicitOverrideWins();
    testMountTypeBadValueThrows();
    testRejectsUnknownOpts();
    testHashedPathPatternReDoSRefused();
    await testOnErrorFiresOnRefusal();
    await testOnErrorThrowDoesNotCorruptResponse();
    testOnErrorRejectsNonFunction();
    await testPathTraversalRefused();
    await testNestedFileServed();
    await testDirectoryIndexServed();
    // Error / adversarial / defensive-branch coverage.
    await testRangeSingle();
    await testRangeSuffixAndOpenEnded();
    await testRangeMalformedAndMulti();
    await testRangeUnsatisfiableAndTooLarge();
    await testAcceptRangesDisabled();
    await testConditionalHits();
    await testHeadRequest();
    await testSafeAttachmentRiskyMime();
    await testOnServeMutatesHeaders();
    await testOnServeThrows();
    await testContentSafetyRefuse();
    await testContentSafetySanitize();
    await testContentSafetySanitizeIntegrityHeaders();
    await testContentSafetyThrows();
    await testContentSafetyTooLarge();
    await testMimeAllowlistSuccess();
    await testMimeAllowlistRejections();
    await testRevokeLocal();
    await testRevokeStore();
    await testRetentionBlocked();
    await testConcurrencyCapRejected();
    await testBandwidthCapRejected();
    await testQuotaSuccessConsumesAndReleases();
    testCreateValidationThrows();
    await testIntegrityHelper();
    await testStatsAndInvalidateMeta();
    await testContentSafetyDisabledAudit();
    await testHashedImmutableCacheControl();
    await testMountPathStrip();
    await testIndexFileDisabled();
    await testForceAttachmentExtFallback();
    await testBandwidthPerActorCapRejected();
    await testCounterRetriesOnContention();
    await testMalformedPercentEncoding();
    await testMountPathExactMatch();
    await testSafeRenderSvgDisabled();
    await testContentSafetyDisabledDefaultReason();
    await testRevokeStoreIsRevokedThrows();
    testCreateNoArgThrows();
  } finally {
    await _drainTcpHandles();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
