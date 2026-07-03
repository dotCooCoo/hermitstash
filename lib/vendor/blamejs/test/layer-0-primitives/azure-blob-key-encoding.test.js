// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * azure-blob — blob key percent-encoding.
 *
 * Blob names are interpolated into the request URL path. A key with
 * reserved characters (`?` / `#` / space) MUST be percent-encoded, or
 * the `?` starts the query string / `#` starts the fragment (truncating
 * the path → wrong object or container root) and spaces / control bytes
 * corrupt the request line (CWE-20). `/` separators are preserved
 * (blob names are hierarchical virtual directories). A null byte is
 * refused. We assert the on-the-wire request line by recording the URL
 * the production adapter actually sends to a mock HTTP server.
 */
var http = require("node:http");
var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
var azure = require("../../lib/object-store/azure-blob");

function listenRecording() {
  return new Promise(function (resolve) {
    var requests = [];
    var server = http.createServer(function (req, res) {
      requests.push({ method: req.method, url: req.url });
      res.statusCode = 200;
      res.setHeader("etag", "\"mock-etag\"");
      res.end();
    });
    server.listen(0, "127.0.0.1", function () {
      resolve({
        port:     server.address().port,
        requests: requests,
        close:    function () { return new Promise(function (r) { server.close(r); }); },
      });
    });
  });
}

function _client(port) {
  var key = Buffer.from("test-shared-key-32-bytes-padded__", "utf8").toString("base64");
  return azure.create({
    accountName:      "blamejstest",
    accountKey:       key,
    container:        "cont",
    endpoint:         "http://127.0.0.1:" + port,
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    allowInternal:    true,
    timeoutMs:        5000,
  });
}

// The azure adapter issues requests through the shared b.httpClient
// keep-alive agent, whose cached client socket (and the mock server it
// keeps open) would otherwise outlive run() and hold the forked worker's
// event loop open. Tear the pool down and poll until the TCP handles have
// actually closed — agent.destroy() schedules the teardown asynchronously,
// so polling drives the event-loop turns needed to complete it inside run().
async function _drainTcpHandles() {
  b.httpClient._resetForTest();
  if (typeof process.getActiveResourcesInfo !== "function") return;
  await helpers.waitUntil(function () {
    return process.getActiveResourcesInfo().filter(function (t) {
      return t === "TCPSocketWrap" || t === "TCPServerWrap";
    }).length === 0;
  }, { timeoutMs: 5000, label: "azure-blob-key-encoding: TCP handle drain after _resetForTest" });
}

async function run() {
  try { await _runTests(); }
  finally { await _drainTcpHandles(); }
}

async function _runTests() {
  var srv = await listenRecording();
  try {
    var c = _client(srv.port);

    // Each tuple: [rawKey, expectedRequestPath]. The mock records req.url
    // (path + query). The container is "cont".
    var cases = [
      ["a b.txt",            "/cont/a%20b.txt"],
      ["with?q.txt",         "/cont/with%3Fq.txt"],
      ["with#h.txt",         "/cont/with%23h.txt"],
      ["dir/sub dir/f.txt",  "/cont/dir/sub%20dir/f.txt"],
      ["a+b&c.txt",          "/cont/a%2Bb%26c.txt"],
      ["plain.txt",          "/cont/plain.txt"],
    ];

    for (var i = 0; i < cases.length; i++) {
      var raw = cases[i][0];
      var expected = cases[i][1];
      srv.requests.length = 0;
      await c.put(raw, Buffer.from("body", "utf8"), { contentType: "text/plain" });
      var sent = srv.requests.length === 1 ? srv.requests[0].url : "(no request)";
      check("put key " + JSON.stringify(raw) + " → encoded path " + JSON.stringify(expected),
            sent === expected);
    }

    // get() must encode the same way (the path is what the server matches).
    srv.requests.length = 0;
    await c.get("with?q.txt");
    check("get key with '?' uses the encoded path",
          srv.requests.length === 1 && srv.requests[0].url === "/cont/with%3Fq.txt");

    // A reserved char must NOT leak into the query string — the `?` is
    // encoded, so the recorded URL has no real query separator.
    srv.requests.length = 0;
    await c.head("q?inject=1.txt");
    check("reserved '?' does not start a query string",
          srv.requests.length === 1 &&
          srv.requests[0].url === "/cont/q%3Finject%3D1.txt" &&
          srv.requests[0].url.indexOf("?") === -1);

    // Null byte refused (CWE-20 hostile key) before any request.
    srv.requests.length = 0;
    var threwNull = false;
    try { await c.put("bad" + String.fromCharCode(0) + "key.txt", Buffer.from("x", "utf8")); }
    catch (e) { threwNull = e && e.code === "INVALID_KEY"; }
    check("null-byte key refused with INVALID_KEY", threwNull);
    check("null-byte key sends no request", srv.requests.length === 0);

    // Presigned URL encodes the key in the PATH while the SAS signature
    // is computed over the raw resource — the returned URL must carry the
    // encoded path AND the SAS query params.
    var pre = c.presignedDownloadUrl({ key: "a b?c.txt", expiresIn: 300 });
    check("presigned URL encodes the key path",
          pre.url.indexOf("/cont/a%20b%3Fc.txt") !== -1);
    check("presigned URL still carries the SAS signature",
          pre.url.indexOf("sig=") !== -1 && pre.url.indexOf("se=") !== -1);
  } finally {
    await srv.close();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
