"use strict";
/**
 * static — forceAttachmentForNonText opt-in defense for stored-XSS via
 * user-upload directories.
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

function _get(port, urlPath) {
  return new Promise(function (resolve, reject) {
    var req = http.request({
      hostname: "127.0.0.1", port: port, path: urlPath, method: "GET",
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

function testRejectsUnknownOpts() {
  var threw = null;
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-static-fa-"));
  try {
    b.staticServe.create({ root: dir, unknownKey: "smell" });
  } catch (e) { threw = e; }
  check("unknown opt rejected at create()", threw !== null);
  fs.rmSync(dir, { recursive: true, force: true });
}

async function run() {
  await testForceAttachmentDefaultOff();
  await testForceAttachmentOnHtml();
  await testForceAttachmentOnJs();
  await testForceAttachmentTextStillInline();
  await testForceAttachmentRasterStillInline();
  await testForceAttachmentSvgWithoutSanitizer();
  await testForceAttachmentSvgWithSanitizerInlineAllowed();
  await testForceAttachmentPdfDefaultDownload();
  await testForceAttachmentPdfOptInInline();
  testRejectsUnknownOpts();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
