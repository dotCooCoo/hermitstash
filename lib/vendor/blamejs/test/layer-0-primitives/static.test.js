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
