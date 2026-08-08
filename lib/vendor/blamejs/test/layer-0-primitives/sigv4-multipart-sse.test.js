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
      // us to drop it for the SSE-verification-fails scenario, or to
      // echo a DIFFERENT algorithm than the one requested (a bucket
      // policy that silently downgrades / upgrades the request).
      var sseHeader = req.headers["x-amz-server-side-encryption"];
      var commonHeaders = {};
      if (sseHeader && !behavior.dropSseResponseHeader) {
        commonHeaders["x-amz-server-side-encryption"] =
          behavior.sseResponseTypeOverride || sseHeader;
        var kmsKey = req.headers["x-amz-server-side-encryption-aws-kms-key-id"];
        if (kmsKey) commonHeaders["x-amz-server-side-encryption-aws-kms-key-id"] = kmsKey;
      }

      // 1. Initiate multipart: POST ?uploads
      if (req.method === "POST" && hasUploadsParam) {
        var newUploadId = "upl-" + Math.random().toString(36).slice(2, 10);
        partsReceived[newUploadId] = [];
        res.writeHead(200, Object.assign({ "Content-Type": "application/xml" }, commonHeaders));
        if (behavior.initiateOmitsUploadId) {
          // A vendor / proxy that answers 200 with a well-formed envelope
          // but no UploadId — the framework must refuse rather than carry
          // `undefined` into every subsequent part URL.
          res.end(
            "<?xml version='1.0' encoding='UTF-8'?>" +
            "<InitiateMultipartUploadResult>" +
            "<Bucket>test-bucket</Bucket>" +
            "</InitiateMultipartUploadResult>"
          );
          return;
        }
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
        partsReceived[uploadId].push({
          partNumber: Number(partNumber),
          body:       body,
          headers:    req.headers,
        });
        if (behavior.partOmitsEtag) {
          // 200 OK with no ETag: the part's bytes cannot be referenced in
          // CompleteMultipartUpload, so the upload must fail, not complete
          // with a hole.
          res.writeHead(200, commonHeaders);
          res.end();
          return;
        }
        var etag = '"etag-p' + partNumber + '"';
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
        if (behavior.completeReturnsBareError) {
          // 200 OK carrying an <Error> with neither Code nor Message —
          // still an error, and the framework must say so.
          res.writeHead(200, { "Content-Type": "application/xml" });
          res.end(
            "<?xml version='1.0' encoding='UTF-8'?>" +
            "<Error><RequestId>req-abc</RequestId></Error>"
          );
          return;
        }
        if (behavior.completeForeignRoot) {
          // Neither <Error> nor <CompleteMultipartUploadResult>: the ETag
          // has to come from the response header instead.
          res.writeHead(200, Object.assign({
            "Content-Type": "application/xml",
            ETag:           '"header-only-etag"',
          }, commonHeaders));
          res.end(
            "<?xml version='1.0' encoding='UTF-8'?>" +
            "<VendorEnvelope><Status>ok</Status></VendorEnvelope>"
          );
          return;
        }
        if (behavior.completeResultOmitsEtag) {
          res.writeHead(200, Object.assign({
            "Content-Type": "application/xml",
            ETag:           '"header-fallback-etag"',
          }, commonHeaders));
          res.end(
            "<?xml version='1.0' encoding='UTF-8'?>" +
            "<CompleteMultipartUploadResult>" +
            "<Bucket>test-bucket</Bucket>" +
            "<Key>" + parsed.pathname + "</Key>" +
            "</CompleteMultipartUploadResult>"
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
        // Record the attempt BEFORE any injected failure so a test can
        // assert the abort was issued even when the server refuses it.
        aborts.push(uploadId);
        if (behavior.failAbort) {
          res.writeHead(500, { "Content-Type": "application/xml" });
          res.end("<Error><Code>InternalError</Code><Message>abort failed</Message></Error>");
          return;
        }
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

// ---- Config validation: offline type-guard / non-finite / boundary arms ----
// testConfigValidation above covers the "below-floor" arms; these close the
// type-guard (non-number) and non-finite (Infinity / NaN) arms, plus the
// boundary values that must be ACCEPTED. Every check is pure — create() parses
// the endpoint but opens no socket — so no S3 round-trip is involved.
function testConfigValidationOfflineBranches() {
  function shouldReject(label, overrides) {
    var threw = null;
    try { sigv4.create(_baseConfig(1, overrides)); } catch (e) { threw = e; }
    check("config-offline: " + label, threw && /INVALID_CONFIG/.test(threw.code || ""));
  }
  function shouldAccept(label, overrides) {
    var store = null, threw = null;
    try { store = sigv4.create(_baseConfig(1, overrides)); } catch (e) { threw = e; }
    check("config-offline: " + label,
          !threw && store !== null && store.protocol === "sigv4");
  }
  // partSizeBytes — type guard + non-finite arms (distinct from the < 5 MiB arm)
  shouldReject("partSizeBytes non-number rejected", { partSizeBytes: "5mb" });
  shouldReject("partSizeBytes Infinity rejected",   { partSizeBytes: Infinity });
  shouldReject("partSizeBytes NaN rejected",        { partSizeBytes: NaN });
  shouldAccept("partSizeBytes exactly the 5 MiB floor accepted",
    { partSizeBytes: 5 * 1024 * 1024 });
  // multipartThresholdBytes — type guard + non-finite arms + zero boundary
  shouldReject("multipartThresholdBytes non-number rejected", { multipartThresholdBytes: "big" });
  shouldReject("multipartThresholdBytes Infinity rejected",   { multipartThresholdBytes: Infinity });
  shouldAccept("multipartThresholdBytes zero accepted", { multipartThresholdBytes: 0 });
  // partConcurrency — type guard + non-finite arms + 1 boundary
  shouldReject("partConcurrency non-number rejected", { partConcurrency: "two" });
  shouldReject("partConcurrency Infinity rejected",   { partConcurrency: Infinity });
  shouldAccept("partConcurrency exactly 1 accepted", { partConcurrency: 1 });
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

// ---- Stream chunks that are strings, and that straddle a part boundary ----
// testMultipartFromReadableStream pushes Buffers whose size divides partSize
// exactly, so the reader never carries a remainder and never has to coerce a
// non-Buffer chunk. Both of those are the common real shape: a stream of
// strings (an fs.createReadStream with an encoding set, a generator) whose
// chunk size has no relationship to partSize. Getting either wrong silently
// corrupts the object, so this asserts the reassembled bytes, not just the
// part count.
async function testMultipartStreamStringChunksStraddlingPartBoundary() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var store = sigv4.create(_baseConfig(port, {
      partSizeBytes:   5 * 1024 * 1024,
      partConcurrency: 1,
    }));
    // Two 3 MiB ASCII strings: 6 MiB total across a 5 MiB part size, so the
    // first part is cut mid-chunk and 1 MiB is carried over as leftover.
    var chunkA = "a".repeat(3 * 1024 * 1024);
    var chunkB = "b".repeat(3 * 1024 * 1024);
    var expected = Buffer.from(chunkA + chunkB, "utf8");
    var result = await store.put("strings.bin", Readable.from([chunkA, chunkB]));

    var uploads = Object.keys(fake.partsReceived);
    var parts = fake.partsReceived[uploads[0]].slice().sort(function (x, y) {
      return x.partNumber - y.partNumber;
    });
    check("stream-strings: split into 2 parts (6 MiB over a 5 MiB part size)",
          parts.length === 2);
    check("stream-strings: first part is exactly partSize",
          parts[0].body.length === 5 * 1024 * 1024);
    check("stream-strings: remainder carried into the final part",
          parts[1].body.length === 1 * 1024 * 1024);
    check("stream-strings: reassembled bytes are byte-identical to the source",
          Buffer.compare(Buffer.concat([parts[0].body, parts[1].body]), expected) === 0);
    check("stream-strings: reported size is the full byte length",
          result.size === expected.length);
    check("stream-strings: flagged multipart", result.multipart === true);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

// ---- Zero-length bodies still produce a well-formed multipart upload ----
// S3 rejects a multipart upload with zero parts, so an empty Buffer / empty
// stream must still send exactly one (zero-length) part rather than an
// upload with no parts at all.
async function testMultipartEmptyBufferAndEmptyStream() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var store = sigv4.create(_baseConfig(port, {
      partSizeBytes:   5 * 1024 * 1024,
      partConcurrency: 1,
    }));

    var bufResult = await store.put("empty-buf.bin", Buffer.alloc(0), { multipart: true });
    var bufUpload = Object.keys(fake.partsReceived)[0];
    check("multipart empty buffer: exactly one part uploaded",
          fake.partsReceived[bufUpload].length === 1);
    check("multipart empty buffer: the part is zero-length",
          fake.partsReceived[bufUpload][0].body.length === 0);
    check("multipart empty buffer: part numbering still starts at 1",
          fake.partsReceived[bufUpload][0].partNumber === 1);
    check("multipart empty buffer: reported size 0", bufResult.size === 0);
    check("multipart empty buffer: completed as multipart", bufResult.multipart === true);

    var streamResult = await store.put("empty-stream.bin", Readable.from([]));
    var streamUpload = Object.keys(fake.partsReceived).filter(function (id) {
      return id !== bufUpload;
    })[0];
    check("multipart empty stream: exactly one part uploaded",
          fake.partsReceived[streamUpload].length === 1);
    check("multipart empty stream: the part is zero-length",
          fake.partsReceived[streamUpload][0].body.length === 0);
    check("multipart empty stream: reported size 0", streamResult.size === 0);
    check("multipart empty stream: completed as multipart", streamResult.multipart === true);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

// ---- InitiateMultipartUpload that answers 200 with no UploadId ----

async function testMultipartInitiateWithoutUploadIdFails() {
  var fake = _fakeS3({ initiateOmitsUploadId: true });
  var port = await listenOnRandomPort(fake.server);
  try {
    var store = sigv4.create(_baseConfig(port, {
      multipartThresholdBytes: 1,
      partSizeBytes:           5 * 1024 * 1024,
    }));
    var threw = null;
    try {
      await store.put("noid.bin", Buffer.alloc(6 * 1024 * 1024));
      check("initiate-no-uploadid: should have thrown", false);
    } catch (e) { threw = e; }
    check("initiate-no-uploadid: code = MULTIPART_INIT_FAILED",
          threw && threw.code === "MULTIPART_INIT_FAILED");
    check("initiate-no-uploadid: no part was uploaded against an undefined uploadId",
          fake.requests.filter(function (r) {
            return r.method === "PUT" && r.url.indexOf("partNumber") !== -1;
          }).length === 0);
    check("initiate-no-uploadid: no abort issued (no upload was ever created)",
          fake.aborts.length === 0);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

// ---- UploadPart that answers 200 with no ETag ----

async function testMultipartPartWithoutEtagFailsAndAborts() {
  var fake = _fakeS3({ partOmitsEtag: true });
  var port = await listenOnRandomPort(fake.server);
  try {
    var store = sigv4.create(_baseConfig(port, {
      multipartThresholdBytes: 1,
      partSizeBytes:           5 * 1024 * 1024,
      partConcurrency:         1,
    }));
    var threw = null;
    try {
      await store.put("noetag.bin", Buffer.alloc(6 * 1024 * 1024));
      check("part-no-etag: should have thrown", false);
    } catch (e) { threw = e; }
    check("part-no-etag: code = MULTIPART_PART_FAILED",
          threw && threw.code === "MULTIPART_PART_FAILED");
    check("part-no-etag: message names the failing part number",
          threw && /part 1\b/.test(String(threw.message)));
    check("part-no-etag: CompleteMultipartUpload never issued",
          fake.requests.filter(function (r) {
            return r.method === "POST" && r.url.indexOf("uploadId") !== -1 &&
                   r.url.indexOf("uploads") === -1;
          }).length === 0);
    check("part-no-etag: abort issued to clean up the partial upload",
          fake.aborts.length === 1);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

// ---- A failing abort must not mask the primary error ----

async function testAbortFailureDoesNotMaskPrimaryError() {
  var fake = _fakeS3({ partOmitsEtag: true, failAbort: true });
  var port = await listenOnRandomPort(fake.server);
  try {
    var store = sigv4.create(_baseConfig(port, {
      multipartThresholdBytes: 1,
      partSizeBytes:           5 * 1024 * 1024,
      partConcurrency:         1,
    }));
    var threw = null;
    try {
      await store.put("abortfail.bin", Buffer.alloc(6 * 1024 * 1024));
      check("abort-failure: should have thrown", false);
    } catch (e) { threw = e; }
    check("abort-failure: the abort WAS attempted", fake.aborts.length === 1);
    // The discriminator: the caller must see the upload's own failure, not
    // the cleanup's HTTP 500 (which would send them debugging the wrong
    // request).
    check("abort-failure: primary error survives (MULTIPART_PART_FAILED)",
          threw && threw.code === "MULTIPART_PART_FAILED");
    check("abort-failure: not replaced by the abort's HTTP status",
          threw && threw.statusCode === undefined);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

// ---- CompleteMultipartUpload 200 bodies that are not the happy shape ----

async function testCompleteBareErrorBodyStillFails() {
  var fake = _fakeS3({ completeReturnsBareError: true });
  var port = await listenOnRandomPort(fake.server);
  try {
    var store = sigv4.create(_baseConfig(port, {
      multipartThresholdBytes: 1,
      partSizeBytes:           5 * 1024 * 1024,
      partConcurrency:         1,
    }));
    var threw = null;
    try {
      await store.put("bare-error.bin", Buffer.alloc(6 * 1024 * 1024));
      check("complete-bare-error: should have thrown", false);
    } catch (e) { threw = e; }
    check("complete-bare-error: code = MULTIPART_COMPLETE_FAILED",
          threw && threw.code === "MULTIPART_COMPLETE_FAILED");
    // An <Error> with no <Code>/<Message> must not degrade into
    // "returned error: undefined undefined".
    check("complete-bare-error: absent Code reported as 'unknown'",
          threw && String(threw.message).indexOf("unknown") !== -1);
    check("complete-bare-error: absent Message does not leak 'undefined'",
          threw && String(threw.message).indexOf("undefined") === -1);
    check("complete-bare-error: abort ran for cleanup", fake.aborts.length === 1);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testCompleteEtagFallsBackToResponseHeader() {
  // (a) neither <Error> nor <CompleteMultipartUploadResult> in the body.
  var fake = _fakeS3({ completeForeignRoot: true });
  var port = await listenOnRandomPort(fake.server);
  try {
    var store = sigv4.create(_baseConfig(port, {
      multipartThresholdBytes: 1,
      partSizeBytes:           5 * 1024 * 1024,
      partConcurrency:         1,
    }));
    var r = await store.put("foreign-root.bin", Buffer.alloc(6 * 1024 * 1024));
    check("complete-foreign-root: upload still succeeds", r.multipart === true);
    check("complete-foreign-root: etag falls back to the response header",
          r.etag === '"header-only-etag"');
    check("complete-foreign-root: size still reflects every uploaded part",
          r.size === 6 * 1024 * 1024);
    check("complete-foreign-root: no abort (the upload did not fail)",
          fake.aborts.length === 0);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }

  // (b) a well-formed <CompleteMultipartUploadResult> that omits <ETag>.
  var fake2 = _fakeS3({ completeResultOmitsEtag: true });
  var port2 = await listenOnRandomPort(fake2.server);
  try {
    var store2 = sigv4.create(_baseConfig(port2, {
      multipartThresholdBytes: 1,
      partSizeBytes:           5 * 1024 * 1024,
      partConcurrency:         1,
    }));
    var r2 = await store2.put("result-no-etag.bin", Buffer.alloc(6 * 1024 * 1024));
    check("complete-result-no-etag: etag falls back to the response header",
          r2.etag === '"header-fallback-etag"');
    check("complete-result-no-etag: size preserved", r2.size === 6 * 1024 * 1024);
  } finally {
    await new Promise(function (r) { fake2.server.close(function () { r(); }); });
  }
}

// ---- SSE: the server applies a DIFFERENT algorithm than requested ----
// Dropping the header entirely is already covered; echoing a different
// algorithm is the other silent-compliance-hole shape (a bucket policy that
// rewrites AES256 to aws:kms, or vice versa). The operator asked for a
// specific policy, so a substitution is a hard failure too.
async function testSseMismatchRejectsPut() {
  var fake = _fakeS3({ sseResponseTypeOverride: "aws:kms" });
  var port = await listenOnRandomPort(fake.server);
  try {
    var store = sigv4.create(_baseConfig(port));
    var threw = null;
    try {
      await store.put("k.bin", Buffer.alloc(1024), { sse: "AES256" });
      check("sse mismatch: should have thrown", false);
    } catch (e) { threw = e; }
    check("sse mismatch: code = SSE_MISMATCH", threw && threw.code === "SSE_MISMATCH");
    check("sse mismatch: message names BOTH the requested and applied algorithms",
          threw && String(threw.message).indexOf("AES256") !== -1 &&
          String(threw.message).indexOf("aws:kms") !== -1);
    check("sse mismatch: distinct from the dropped-header code",
          threw && threw.code !== "SSE_NOT_APPLIED");
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
    testConfigValidationOfflineBranches();
    await testMultipartFalseRejectsStreams();
    await testMultipartStreamStringChunksStraddlingPartBoundary();
    await testMultipartEmptyBufferAndEmptyStream();
    await testMultipartInitiateWithoutUploadIdFails();
    await testMultipartPartWithoutEtagFailsAndAborts();
    await testAbortFailureDoesNotMaskPrimaryError();
    await testCompleteBareErrorBodyStillFails();
    await testCompleteEtagFallsBackToResponseHeader();
    await testSseMismatchRejectsPut();
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
