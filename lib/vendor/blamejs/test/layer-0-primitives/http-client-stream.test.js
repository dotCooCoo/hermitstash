"use strict";
/**
 * b.httpClient.downloadStream + b.httpClient.uploadMultipartStream.
 *
 * Coverage:
 *   - downloadStream success + hash returned even without expected
 *   - downloadStream hash-match path (atomic rename, dest written, tmp gone)
 *   - downloadStream hash-mismatch refuses, deletes tmp, throws
 *     httpclient/hash-mismatch, audits .refused
 *   - downloadStream HTTP error surfaces without dest write
 *   - downloadStream stages into an exclusive, no-follow temp file: the
 *     happy path round-trips and a symlink at the dest is replaced (not
 *     followed) so the victim it pointed at is left untouched
 *   - uploadMultipartStream POSTs file body via multipart/form-data,
 *     server receives the bytes + the operator-supplied field
 *   - uploadMultipartStream missing-file refuses at config time
 *
 * No live network — local http.Server on a random port via
 * b.testing.listenOnRandomPort.
 */

var fs   = require("fs");
var http = require("http");
var path = require("path");
var nodeCrypto = require("crypto");

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var FIXTURE_PATH  = path.join(__dirname, "..", "fixtures", "http-client-stream-payload.txt");
var FIXTURE_BYTES = fs.readFileSync(FIXTURE_PATH);
var FIXTURE_SHA3  = nodeCrypto.createHash("sha3-512").update(FIXTURE_BYTES).digest("hex");

function _mkAuditCapture() {
  var events = [];
  return {
    events: events,
    safeEmit: function (e) { events.push(e); },
  };
}

function _tmpFile(name) {
  var dir = b.testing.tempDir("httpclient-stream");
  return path.join(dir.path, name);
}

async function _withServer(handler, fn) {
  var server = http.createServer(handler);
  var port = await b.testing.listenOnRandomPort(server, "127.0.0.1");
  try {
    return await fn("http://127.0.0.1:" + port);
  } finally {
    await new Promise(function (resolve) { server.close(function () { resolve(); }); });
  }
}

async function testDownloadHappyPath() {
  await _withServer(function (req, res) {
    res.writeHead(200, { "Content-Type": "application/octet-stream", "Content-Length": String(FIXTURE_BYTES.length) });
    res.end(FIXTURE_BYTES);
  }, async function (baseUrl) {
    var dest = _tmpFile("happy.bin");
    var audit = _mkAuditCapture();
    var result = await b.httpClient.downloadStream({
      url:              baseUrl + "/payload",
      dest:             dest,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:    true,
      audit:            audit,
    });
    check("downloadStream: returns statusCode 200",
          result.statusCode === 200);
    check("downloadStream: bytesWritten matches fixture size",
          result.bytesWritten === FIXTURE_BYTES.length);
    check("downloadStream: hash returned (sha3-512 default)",
          typeof result.hash === "string" && result.hash === FIXTURE_SHA3);
    check("downloadStream: dest file exists at final path",
          fs.existsSync(dest));
    check("downloadStream: dest file content matches fixture",
          fs.readFileSync(dest).equals(FIXTURE_BYTES));
    var completed = audit.events.find(function (e) {
      return e.action === "system.httpclient.download_stream.completed";
    });
    check("downloadStream: audited completed event",
          completed != null && completed.outcome === "allowed" &&
          completed.metadata.bytesWritten === FIXTURE_BYTES.length);
  });
}

async function testDownloadExpectedHashMatch() {
  await _withServer(function (req, res) {
    res.writeHead(200, { "Content-Type": "application/octet-stream" });
    res.end(FIXTURE_BYTES);
  }, async function (baseUrl) {
    var dest = _tmpFile("expected-match.bin");
    var result = await b.httpClient.downloadStream({
      url:              baseUrl + "/payload",
      dest:             dest,
      hash:             "sha3-512",
      expected:         FIXTURE_SHA3,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:    true,
    });
    check("downloadStream(expected match): success", result.hash === FIXTURE_SHA3);
    check("downloadStream(expected match): dest written",
          fs.existsSync(dest) && fs.readFileSync(dest).equals(FIXTURE_BYTES));
  });
}

async function testDownloadHashMismatch() {
  await _withServer(function (req, res) {
    res.writeHead(200, { "Content-Type": "application/octet-stream" });
    res.end(FIXTURE_BYTES);
  }, async function (baseUrl) {
    var dest = _tmpFile("mismatch.bin");
    var audit = _mkAuditCapture();
    var thrown = null;
    try {
      await b.httpClient.downloadStream({
        url:              baseUrl + "/payload",
        dest:             dest,
        hash:             "sha3-512",
        expected:         "0".repeat(128),  // wrong hex digest
        allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
        allowInternal:    true,
        audit:            audit,
      });
    } catch (e) { thrown = e; }
    check("downloadStream(hash mismatch): threw HttpClientError",
          thrown != null && thrown.code === "httpclient/hash-mismatch");
    check("downloadStream(hash mismatch): dest NOT written",
          !fs.existsSync(dest));
    // No tmp file left behind anywhere in the parent dir
    var parent = path.dirname(dest);
    var leftovers = fs.readdirSync(parent).filter(function (n) {
      return n.indexOf("mismatch.bin.tmp-") === 0;
    });
    check("downloadStream(hash mismatch): tmp file cleaned up",
          leftovers.length === 0);
    var refused = audit.events.find(function (e) {
      return e.action === "system.httpclient.download_stream.refused" &&
             e.metadata.reason === "hash-mismatch";
    });
    check("downloadStream(hash mismatch): audited refused event",
          refused != null && refused.outcome === "denied");
  });
}

async function testDownloadHttpError() {
  await _withServer(function (req, res) {
    res.writeHead(503, { "Content-Type": "text/plain" });
    res.end("upstream down");
  }, async function (baseUrl) {
    var dest = _tmpFile("http-error.bin");
    var thrown = null;
    try {
      await b.httpClient.downloadStream({
        url:              baseUrl + "/down",
        dest:             dest,
        allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
        allowInternal:    true,
      });
    } catch (e) { thrown = e; }
    check("downloadStream(503): threw error", thrown != null);
    check("downloadStream(503): dest NOT written", !fs.existsSync(dest));
  });
}

async function testStreamErrorBodyPreserved() {
  // A streamed (responseMode "stream") non-2xx must surface a bounded prefix
  // of the error body on the thrown error instead of draining it to nothing,
  // so the caller can read the problem+json / encrypted error detail.
  await _withServer(function (req, res) {
    res.writeHead(403, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "forbidden", detail: "stream-error-detail" }));
  }, async function (baseUrl) {
    var thrown = null;
    try {
      await b.httpClient.request({
        url:              baseUrl + "/x",
        method:           "GET",
        responseMode:     "stream",
        allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
        allowInternal:    true,
      });
    } catch (e) { thrown = e; }
    check("stream non-2xx: threw HTTP_ERROR",       thrown != null && thrown.code === "HTTP_ERROR");
    check("stream non-2xx: message names the status", thrown && /403/.test(thrown.message));
    check("stream non-2xx: err.body is a Buffer",   thrown && Buffer.isBuffer(thrown.body));
    check("stream non-2xx: err.body carries detail",
          thrown && thrown.body && /stream-error-detail/.test(thrown.body.toString("utf8")));
  });

  // A large (> cap) error body must reject promptly with a bounded prefix —
  // it must NOT leave the request promise pending until the whole body
  // drains to close (if it did, this test would hang past the file timeout).
  var BODY_LEN = 50003;
  await _withServer(function (req, res) {
    res.writeHead(500, { "Content-Type": "text/plain" });
    res.end("E".repeat(BODY_LEN) + "TAIL-MARKER");
  }, async function (baseUrl) {
    var thrown = null;
    try {
      await b.httpClient.request({
        url:              baseUrl + "/big",
        method:           "GET",
        responseMode:     "stream",
        allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
        allowInternal:    true,
      });
    } catch (e) { thrown = e; }
    check("stream large-error: threw HTTP_ERROR (did not hang)",
          thrown != null && thrown.code === "HTTP_ERROR");
    check("stream large-error: body bounded well below sent size",
          thrown && thrown.body && thrown.body.length > 0 && thrown.body.length < BODY_LEN);
    check("stream large-error: tail beyond cap was dropped",
          thrown && thrown.body && thrown.body.toString("utf8").indexOf("TAIL-MARKER") === -1);
  });
}

async function testDownloadTempCreateIsExclusiveNoFollow() {
  // CWE-377 / CWE-59: downloadStream stages the body into a sibling temp
  // file created with O_EXCL | O_NOFOLLOW before the atomic rename. Two
  // properties to assert through the public API:
  //   (a) the happy path still round-trips (the exclusive create didn't
  //       break the streaming/rename contract);
  //   (b) a symlink planted at the DESTINATION is replaced by the rename,
  //       not followed — the victim the symlink pointed at stays untouched.
  await _withServer(function (req, res) {
    res.writeHead(200, { "Content-Type": "application/octet-stream" });
    res.end(FIXTURE_BYTES);
  }, async function (baseUrl) {
    // (a) round-trip into a fresh dest, confirm exactly one final file and
    //     no leaked temp.
    var dir  = b.testing.tempDir("httpclient-stream-excl");
    try {
      var dest = path.join(dir.path, "release.bin");
      var result = await b.httpClient.downloadStream({
        url:              baseUrl + "/payload",
        dest:             dest,
        allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
        allowInternal:    true,
      });
      check("downloadStream(excl): round-trips bytes",
            result.bytesWritten === FIXTURE_BYTES.length &&
            fs.readFileSync(dest).equals(FIXTURE_BYTES));
      var leftovers = fs.readdirSync(dir.path).filter(function (n) {
        return n.indexOf("release.bin.tmp-") === 0;
      });
      check("downloadStream(excl): no temp file leaked on success",
            leftovers.length === 0);

      // (b) symlink-at-destination — replaced by the rename, victim safe.
      var victim = path.join(dir.path, "victim.bin");
      fs.writeFileSync(victim, "DO NOT OVERWRITE", { mode: 0o600 });
      var linkDest = path.join(dir.path, "link-dest.bin");
      var symlinkOk = true;
      try { fs.symlinkSync(victim, linkDest); }
      catch (_e) { symlinkOk = false; }  // Windows w/o symlink privilege

      if (symlinkOk) {
        await b.httpClient.downloadStream({
          url:              baseUrl + "/payload",
          dest:             linkDest,
          allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
          allowInternal:    true,
        });
        // Open ONE no-follow fd and take both the type check (fstat) and
        // the byte read from that same descriptor — no lstat-then-read
        // against the path, which would be a check-then-use file-system
        // race (CWE-367). O_NOFOLLOW makes the open fail if linkDest were
        // still a symlink, so a successful open already proves the rename
        // replaced the link with a regular file.
        var linkFd = fs.openSync(linkDest, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
        try {
          var linkStat = fs.fstatSync(linkFd);
          check("downloadStream(excl): symlink dest replaced by regular file",
                linkStat.isFile() && !linkStat.isSymbolicLink());
          var linkBytes = Buffer.alloc(linkStat.size);
          var linkGot = 0;
          while (linkGot < linkStat.size) {
            var ln = fs.readSync(linkFd, linkBytes, linkGot, linkStat.size - linkGot, null);
            if (ln === 0) break;
            linkGot += ln;
          }
          check("downloadStream(excl): symlink dest holds downloaded bytes",
                linkGot === FIXTURE_BYTES.length && linkBytes.equals(FIXTURE_BYTES));
        } finally {
          fs.closeSync(linkFd);
        }
        check("downloadStream(excl): symlink target (victim) untouched",
              fs.readFileSync(victim, "utf8") === "DO NOT OVERWRITE");
      } else {
        check("downloadStream(excl): symlink-dest case skipped (no privilege)", true);
      }
    } finally {
      dir.cleanup();
    }
  });
}

async function testDownloadBadOpts() {
  var thrown = null;
  try {
    await b.httpClient.downloadStream({ url: "https://x.example", dest: "/tmp/x", hash: "md5" });
  } catch (e) { thrown = e; }
  check("downloadStream(bad hash alg): rejects at config time",
        thrown != null && thrown.code === "httpclient/bad-opts");

  thrown = null;
  try {
    await b.httpClient.downloadStream({ url: "", dest: "/tmp/x" });
  } catch (e) { thrown = e; }
  check("downloadStream(empty url): rejects at config time",
        thrown != null && thrown.code === "httpclient/bad-opts");
}

async function testUploadHappyPath() {
  var receivedBody = null;
  var receivedContentType = null;
  await _withServer(function (req, res) {
    receivedContentType = req.headers["content-type"];
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      receivedBody = Buffer.concat(chunks);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, bytes: receivedBody.length }));
    });
  }, async function (baseUrl) {
    var audit = _mkAuditCapture();
    var result = await b.httpClient.uploadMultipartStream({
      url:              baseUrl + "/upload",
      fields:           { title: "fixture", tag: "test" },
      file: {
        path:        FIXTURE_PATH,
        fieldName:   "payload",
        filename:    "payload.txt",
        contentType: "text/plain",
      },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:    true,
      audit:            audit,
    });
    check("uploadMultipartStream: 200 OK",
          result.statusCode === 200);
    check("uploadMultipartStream: server saw multipart Content-Type",
          /^multipart\/form-data;\s*boundary=/i.test(receivedContentType || ""));
    check("uploadMultipartStream: body contains fixture bytes",
          receivedBody != null && receivedBody.indexOf(FIXTURE_BYTES) !== -1);
    check("uploadMultipartStream: body contains operator field",
          receivedBody != null && receivedBody.toString("utf8").indexOf('name="title"') !== -1 &&
          receivedBody.toString("utf8").indexOf("fixture") !== -1);
    check("uploadMultipartStream: body contains operator file fieldName",
          receivedBody != null && receivedBody.toString("utf8").indexOf('name="payload"') !== -1);
    var completed = audit.events.find(function (e) {
      return e.action === "system.httpclient.upload_stream.completed";
    });
    check("uploadMultipartStream: audited completed event",
          completed != null && completed.outcome === "allowed" &&
          completed.metadata.fieldName === "payload");
  });
}

async function testUploadMissingFile() {
  var thrown = null;
  try {
    await b.httpClient.uploadMultipartStream({
      url:  "http://127.0.0.1:1/never",
      file: { path: "/nonexistent/path/no-such-file.bin", fieldName: "f" },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:    true,
    });
  } catch (e) { thrown = e; }
  check("uploadMultipartStream(missing file): refuses with httpclient/missing-file",
        thrown != null && thrown.code === "httpclient/missing-file");
}

async function testUploadBadOpts() {
  var thrown = null;
  try {
    await b.httpClient.uploadMultipartStream({ url: "https://x.example" });
  } catch (e) { thrown = e; }
  check("uploadMultipartStream(no file): rejects at config time",
        thrown != null && thrown.code === "httpclient/bad-opts");
}

function testSurface() {
  check("httpClient.downloadStream is a function",
        typeof b.httpClient.downloadStream === "function");
  check("httpClient.uploadMultipartStream is a function",
        typeof b.httpClient.uploadMultipartStream === "function");
  check("httpClient.ALLOWED_DOWNLOAD_HASH_ALGS includes sha3-512",
        Array.isArray(b.httpClient.ALLOWED_DOWNLOAD_HASH_ALGS) &&
        b.httpClient.ALLOWED_DOWNLOAD_HASH_ALGS.indexOf("sha3-512") !== -1);
}

async function run() {
  testSurface();
  await testDownloadHappyPath();
  await testDownloadExpectedHashMatch();
  await testDownloadHashMismatch();
  await testDownloadHttpError();
  await testStreamErrorBodyPreserved();
  await testDownloadTempCreateIsExclusiveNoFollow();
  await testDownloadBadOpts();
  await testUploadHappyPath();
  await testUploadMissingFile();
  await testUploadBadOpts();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
