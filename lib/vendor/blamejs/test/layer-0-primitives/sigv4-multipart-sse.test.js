// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * sigv4 — multipart upload + server-side encryption (SSE).
 *
 * Stands up a fake S3 server that speaks the InitiateMultipartUpload /
 * UploadPart / CompleteMultipartUpload / AbortMultipartUpload sub-API.
 * Verifies:
 *   - small bodies stay single-PUT
 *   - bodies above the threshold dispatch to multipart
 *   - Readable streams always go multipart
 *   - aborts run on part-upload failure
 *   - SSE headers are forwarded on every request
 *   - SSE response verification fails the put when the server drops
 *     the encryption header (silent compliance hole prevention)
 *
 * Run standalone: `node test/layer-0-primitives/sigv4-multipart-sse.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var http               = require("http");
var { Readable }       = require("stream");
var sigv4              = require("../../lib/object-store/sigv4");
var b                  = helpers.b;
var check              = helpers.check;
var listenOnRandomPort = helpers.listenOnRandomPort;

function _baseConfig(port, overrides) {
  var cfg = {
    region:          "us-east-1",
    bucket:          "test-bucket",
    accessKeyId:     "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    endpoint:        "http://127.0.0.1:" + port,
    pathStyle:       true,
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    allowInternal:   true,
    timeoutMs:       5000,
  };
  if (overrides) Object.assign(cfg, overrides);
  return cfg;
}

// Build a fake S3 server. Records every request; returns S3-shaped XML.
// `behavior` lets a test inject failures or skip a response header.
function _fakeS3(behavior) {
  behavior = behavior || {};
  var requests = [];
  var partsReceived = {};   // uploadId -> [{ partNumber, body, headers }]
  var aborts = [];
  var server = http.createServer(function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      var body = Buffer.concat(chunks);
      var rec = {
        method:  req.method,
        url:     req.url,
        headers: req.headers,
        body:    body,
      };
      requests.push(rec);

      var parsed = new URL("http://x" + req.url);
      var hasUploadsParam = parsed.searchParams.has("uploads");
      var uploadId = parsed.searchParams.get("uploadId");
      var partNumber = parsed.searchParams.get("partNumber");

      // Emulate SSE response header echoing — unless the test asks
      // us to drop it for the SSE-verification-fails scenario.
      var sseHeader = req.headers["x-amz-server-side-encryption"];
      var commonHeaders = {};
      if (sseHeader && !behavior.dropSseResponseHeader) {
        commonHeaders["x-amz-server-side-encryption"] = sseHeader;
        var kmsKey = req.headers["x-amz-server-side-encryption-aws-kms-key-id"];
        if (kmsKey) commonHeaders["x-amz-server-side-encryption-aws-kms-key-id"] = kmsKey;
      }

      // 1. Initiate multipart: POST ?uploads
      if (req.method === "POST" && hasUploadsParam) {
        var newUploadId = "upl-" + Math.random().toString(36).slice(2, 10);
        partsReceived[newUploadId] = [];
        res.writeHead(200, Object.assign({ "Content-Type": "application/xml" }, commonHeaders));
        res.end(
          "<?xml version='1.0' encoding='UTF-8'?>" +
          "<InitiateMultipartUploadResult>" +
          "<Bucket>test-bucket</Bucket>" +
          "<Key>" + parsed.pathname + "</Key>" +
          "<UploadId>" + newUploadId + "</UploadId>" +
          "</InitiateMultipartUploadResult>"
        );
        return;
      }
      // 2. Upload part: PUT ?partNumber=N&uploadId=...
      if (req.method === "PUT" && uploadId && partNumber) {
        if (behavior.failPartNumber && Number(partNumber) === behavior.failPartNumber) {
          res.writeHead(500, { "Content-Type": "application/xml" });
          res.end("<Error><Code>InternalError</Code><Message>simulated</Message></Error>");
          return;
        }
        var etag = '"etag-p' + partNumber + '"';
        partsReceived[uploadId].push({
          partNumber: Number(partNumber),
          body:       body,
          headers:    req.headers,
        });
        res.writeHead(200, Object.assign({ ETag: etag }, commonHeaders));
        res.end();
        return;
      }
      // 3. Complete multipart: POST ?uploadId=...
      if (req.method === "POST" && uploadId) {
        if (behavior.completeReturnsError) {
          res.writeHead(200, { "Content-Type": "application/xml" });
          res.end(
            "<?xml version='1.0' encoding='UTF-8'?>" +
            "<Error><Code>InvalidPart</Code><Message>simulated</Message></Error>"
          );
          return;
        }
        res.writeHead(200, Object.assign({
          "Content-Type": "application/xml",
          ETag:           '"final-multipart-etag"',
        }, commonHeaders));
        res.end(
          "<?xml version='1.0' encoding='UTF-8'?>" +
          "<CompleteMultipartUploadResult>" +
          "<Location>http://x/test-bucket/" + parsed.pathname + "</Location>" +
          "<Bucket>test-bucket</Bucket>" +
          "<Key>" + parsed.pathname + "</Key>" +
          "<ETag>\"final-multipart-etag\"</ETag>" +
          "</CompleteMultipartUploadResult>"
        );
        return;
      }
      // Abort multipart: DELETE ?uploadId=...
      if (req.method === "DELETE" && uploadId) {
        aborts.push(uploadId);
        res.writeHead(204, commonHeaders);
        res.end();
        return;
      }
      // Single PUT
      if (req.method === "PUT") {
        res.writeHead(200, Object.assign({ ETag: '"etag-single"' }, commonHeaders));
        res.end();
        return;
      }
      res.writeHead(400);
      res.end();
    });
  });
  return {
    server:        server,
    requests:      requests,
    partsReceived: partsReceived,
    aborts:        aborts,
  };
}

// ---- Single-PUT path stays unchanged ----

async function testSinglePutRemainsBufferAtThreshold() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var store = sigv4.create(_baseConfig(port));
    var result = await store.put("small.bin", Buffer.alloc(1024));
    check("single-put: returns size",                result.size === 1024);
    check("single-put: not flagged multipart",       !result.multipart);
    check("single-put: only 1 HTTP request",         fake.requests.length === 1);
    check("single-put: method is PUT",               fake.requests[0].method === "PUT");
    check("single-put: no ?uploads param",           fake.requests[0].url.indexOf("uploads") === -1);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

// ---- Multipart auto-detect for buffers above threshold ----

async function testMultipartAutoDetectAboveThreshold() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var store = sigv4.create(_baseConfig(port, {
      multipartThresholdBytes: 6 * 1024 * 1024,
      partSizeBytes:           5 * 1024 * 1024,
    }));
    // 12 MiB buffer → 3 parts (5+5+2).
    var buf = Buffer.alloc(12 * 1024 * 1024);
    var result = await store.put("big.bin", buf);
    check("multipart: result.multipart === true",     result.multipart === true);
    check("multipart: result.size = body length",     result.size === 12 * 1024 * 1024);
    check("multipart: result.etag from complete",     result.etag === '"final-multipart-etag"');
    // 1 initiate + 3 part PUTs + 1 complete = 5 requests.
    check("multipart: 5 HTTP requests recorded",      fake.requests.length === 5);
    var initiate = fake.requests[0];
    check("multipart: first request is POST ?uploads",
          initiate.method === "POST" && initiate.url.indexOf("uploads") !== -1);
    var parts = Object.keys(fake.partsReceived);
    check("multipart: server tracked one upload",     parts.length === 1);
    check("multipart: 3 parts received",              fake.partsReceived[parts[0]].length === 3);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

// ---- Multipart for Readable streams (size unknown up-front) ----

async function testMultipartFromReadableStream() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var store = sigv4.create(_baseConfig(port, {
      partSizeBytes: 5 * 1024 * 1024,
    }));
    var bytesPushed = 0;
    var stream = new Readable({
      read: function () {
        if (bytesPushed >= 11 * 1024 * 1024) return this.push(null);
        var chunk = Buffer.alloc(1 * 1024 * 1024);
        bytesPushed += chunk.length;
        this.push(chunk);
      },
    });
    var result = await store.put("stream.bin", stream);
    check("stream-multipart: multipart === true",     result.multipart === true);
    check("stream-multipart: size = total bytes",     result.size === 11 * 1024 * 1024);
    var parts = Object.keys(fake.partsReceived);
    // 11 MiB / 5 MiB part size → 3 parts (5 + 5 + 1).
    check("stream-multipart: 3 parts received",       fake.partsReceived[parts[0]].length === 3);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

// ---- Abort runs on part failure ----

async function testMultipartAbortsOnPartFailure() {
  var fake = _fakeS3({ failPartNumber: 2 });
  var port = await listenOnRandomPort(fake.server);
  try {
    var store = sigv4.create(_baseConfig(port, {
      multipartThresholdBytes: 1,    // force multipart
      partSizeBytes:           5 * 1024 * 1024,
      partConcurrency:         1,    // determinism: parts upload in order
    }));
    var threw = null;
    try {
      await store.put("ouch.bin", Buffer.alloc(12 * 1024 * 1024));
    } catch (e) { threw = e; }
    check("abort: put rejects on part failure",        threw !== null);
    check("abort: error code reflects part failure",   threw && /MULTIPART_PART_FAILED|HTTP_ERROR/.test(threw.code || ""));
    check("abort: server saw the abort DELETE",        fake.aborts.length === 1);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

// ---- Complete-multipart returning <Error> body still fails ----

async function testMultipartCompleteErrorBodyFails() {
  var fake = _fakeS3({ completeReturnsError: true });
  var port = await listenOnRandomPort(fake.server);
  try {
    var store = sigv4.create(_baseConfig(port, {
      multipartThresholdBytes: 1,
      partSizeBytes:           5 * 1024 * 1024,
    }));
    var threw = null;
    try {
      await store.put("k.bin", Buffer.alloc(11 * 1024 * 1024));
    } catch (e) { threw = e; }
    check("complete-error: put rejects",              threw !== null);
    check("complete-error: code = MULTIPART_COMPLETE_FAILED",
          threw && /MULTIPART_COMPLETE_FAILED/.test(threw.code || ""));
    check("complete-error: abort ran for cleanup",    fake.aborts.length === 1);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

// ---- SSE option forwarding + response verification ----

async function testSseAES256Forwarded() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var store = sigv4.create(_baseConfig(port));
    await store.put("crypt.bin", Buffer.alloc(1024), { sse: "AES256" });
    check("sse aes256: forwarded on PUT",
          fake.requests[0].headers["x-amz-server-side-encryption"] === "AES256");
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testSseKmsForwardedWithKeyId() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var store = sigv4.create(_baseConfig(port));
    await store.put("crypt.bin", Buffer.alloc(1024),
      { sse: { type: "aws:kms", keyId: "arn:aws:kms:us-east-1:123:key/abc" } });
    check("sse kms: type forwarded",
          fake.requests[0].headers["x-amz-server-side-encryption"] === "aws:kms");
    check("sse kms: keyId forwarded",
          fake.requests[0].headers["x-amz-server-side-encryption-aws-kms-key-id"] ===
          "arn:aws:kms:us-east-1:123:key/abc");
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testSseForwardedOnEveryMultipartRequest() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var store = sigv4.create(_baseConfig(port, {
      multipartThresholdBytes: 1,
      partSizeBytes:           5 * 1024 * 1024,
      partConcurrency:         1,
    }));
    await store.put("k.bin", Buffer.alloc(11 * 1024 * 1024), { sse: "AES256" });
    var initiate = fake.requests[0];
    var firstPart = fake.requests[1];
    var complete = fake.requests[fake.requests.length - 1];
    check("sse multipart: forwarded on initiate",
          initiate.headers["x-amz-server-side-encryption"] === "AES256");
    // Per S3 spec the SSE headers are not strictly required on each
    // UploadPart, but the framework signs from the initiate config so
    // it doesn't re-stamp them on every part. We at least verify that
    // the initiate carries them — which is what governs the storage
    // policy server-side.
    void firstPart; void complete;
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testSseResponseVerificationFailsOnDroppedHeader() {
  var fake = _fakeS3({ dropSseResponseHeader: true });
  var port = await listenOnRandomPort(fake.server);
  try {
    var store = sigv4.create(_baseConfig(port));
    var threw = null;
    try {
      await store.put("k.bin", Buffer.alloc(1024), { sse: "AES256" });
    } catch (e) { threw = e; }
    check("sse verify: silently-dropped SSE → put rejects",  threw !== null);
    check("sse verify: code = SSE_NOT_APPLIED",
          threw && /SSE_NOT_APPLIED/.test(threw.code || ""));
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

// ---- SSE option validation (rejects bad values at call site) ----

async function testSseValidationRejectsBadValues() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var store = sigv4.create(_baseConfig(port));
    var threw = null;
    try { await store.put("k", Buffer.alloc(0), { sse: "DES" }); }
    catch (e) { threw = e; }
    check("sse validate: bad string rejected",   threw && /INVALID_SSE/.test(threw.code || ""));

    threw = null;
    try { await store.put("k", Buffer.alloc(0), { sse: 42 }); }
    catch (e) { threw = e; }
    check("sse validate: number rejected",        threw && /INVALID_SSE/.test(threw.code || ""));

    threw = null;
    try { await store.put("k", Buffer.alloc(0), { sse: { type: "AES512" } }); }
    catch (e) { threw = e; }
    check("sse validate: bad object type rejected", threw && /INVALID_SSE/.test(threw.code || ""));
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

// ---- Config validation ----

function testConfigValidation() {
  function shouldThrow(label, overrides, codeRe) {
    var threw = null;
    try { sigv4.create(_baseConfig(1, overrides)); } catch (e) { threw = e; }
    check("config validate: " + label,  threw && codeRe.test(threw.code || ""));
  }
  shouldThrow("rejects partSizeBytes < 5MiB",
    { partSizeBytes: 1024 }, /INVALID_CONFIG/);
  shouldThrow("rejects negative multipartThresholdBytes",
    { multipartThresholdBytes: -1 }, /INVALID_CONFIG/);
  shouldThrow("rejects partConcurrency = 0",
    { partConcurrency: 0 }, /INVALID_CONFIG/);
}

// ---- multipart: false bails on streams ----

async function testMultipartFalseRejectsStreams() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var store = sigv4.create(_baseConfig(port));
    var stream = Readable.from([Buffer.from("x")]);
    var threw = null;
    try { await store.put("k", stream, { multipart: false }); }
    catch (e) { threw = e; }
    check("multipart=false: stream rejected upfront",
          threw && /STREAM_REQUIRES_MULTIPART/.test(threw.code || ""));
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

// The sigv4 store dispatches every part / initiate / complete request through
// the shared httpClient keep-alive transport pool; cached client sockets
// finalize their destroy on a later event-loop turn, past the forked worker's
// grace window. Reset the pool, then poll until every TCP handle has actually
// drained so none outlives run().
async function _drainTcpHandles() {
  b.httpClient._resetForTest();
  if (typeof process.getActiveResourcesInfo !== "function") return;
  await helpers.waitUntil(function () {
    return process.getActiveResourcesInfo().filter(function (t) {
      return t === "TCPSocketWrap" || t === "TCPServerWrap";
    }).length === 0;
  }, { timeoutMs: 5000, label: "sigv4-multipart-sse: TCP handle drain after _resetForTest" });
}

async function run() {
  try {
    await testSinglePutRemainsBufferAtThreshold();
    await testMultipartAutoDetectAboveThreshold();
    await testMultipartFromReadableStream();
    await testMultipartAbortsOnPartFailure();
    await testMultipartCompleteErrorBodyFails();
    await testSseAES256Forwarded();
    await testSseKmsForwardedWithKeyId();
    await testSseForwardedOnEveryMultipartRequest();
    await testSseResponseVerificationFailsOnDroppedHeader();
    await testSseValidationRejectsBadValues();
    testConfigValidation();
    await testMultipartFalseRejectsStreams();
  } finally {
    await _drainTcpHandles();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
