"use strict";
/**
 * b.httpClient — download/upload transform correctness outside stream mode.
 *
 *   - A downloadTransform must apply in the default "buffer" responseMode, not
 *     only when responseMode is "stream": the buffered body is the transformed
 *     bytes.
 *   - A size-changing uploadTransform on a Buffer body must NOT leave a stale
 *     Content-Length: the request is framed (chunked) on the transformed bytes
 *     so the server receives the whole body, not a truncated prefix.
 *
 * No live network — a local http.Server on a random port.
 */

var http        = require("http");
var nodeStream  = require("stream");

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

async function _withServer(handler, fn) {
  var server = http.createServer(handler);
  var port = await b.testing.listenOnRandomPort(server, "127.0.0.1");
  try { return await fn("http://127.0.0.1:" + port); }
  finally { await new Promise(function (resolve) { server.close(function () { resolve(); }); }); }
}

function _upperTransform() {
  return new nodeStream.Transform({
    transform: function (chunk, _enc, cb) { cb(null, Buffer.from(chunk.toString("utf8").toUpperCase())); },
  });
}

// Appends a fixed suffix on flush — the transformed body is strictly larger
// than the source, so a stale Content-Length would truncate it.
function _appendTransform() {
  return new nodeStream.Transform({
    transform: function (chunk, _enc, cb) { cb(null, chunk); },
    flush:     function (cb) { this.push(Buffer.from("-XFORM")); cb(); },
  });
}

async function testDownloadTransformAppliesInBufferMode() {
  await _withServer(function (req, res) {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("hello world");
  }, async function (base) {
    var r = await b.httpClient.request({
      url: base + "/", allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
      downloadTransform: _upperTransform,                 // default responseMode = "buffer"
    });
    check("buffer-mode downloadTransform applied to the buffered body",
      r.body.toString("utf8") === "HELLO WORLD");
  });
}

async function testUploadTransformSizeChangeNotTruncated() {
  var received = null;
  await _withServer(function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      received = Buffer.concat(chunks).toString("utf8");
      res.writeHead(200); res.end("ok");
    });
  }, async function (base) {
    await b.httpClient.request({
      url: base + "/", method: "POST", body: Buffer.from("payload"),
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
      uploadTransform: _appendTransform,                  // grows the body past the Buffer length
    });
    check("size-changing uploadTransform delivers the whole transformed body",
      received === "payload-XFORM");
  });
}

async function run() {
  await testDownloadTransformAppliesInBufferMode();
  await testUploadTransformSizeChangeNotTruncated();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK http-client-throttle-transform — " + helpers.getChecks() + " checks"); })
       .catch(function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); });
}
