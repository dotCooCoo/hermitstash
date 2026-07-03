// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * AWS SQS queue adapter — wire-shape + lifecycle tests against an HTTP
 * mock that records every signed request the framework sends to SQS.
 * Covers SendMessage / ReceiveMessage / ChangeMessageVisibility /
 * DeleteMessage / GetQueueAttributes / PurgeQueue plus the operator-
 * facing enqueue → lease → complete round-trip.
 */
var http = require("node:http");
var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
var sqs = require("../../lib/queue-sqs");

function _mockSqs(routes) {
  return new Promise(function (resolve) {
    var captured = [];
    var server = http.createServer(function (req, res) {
      var chunks = [];
      req.on("data", function (c) { chunks.push(c); });
      req.on("end", function () {
        var bodyBuf = Buffer.concat(chunks);
        var bodyJson;
        try { bodyJson = bodyBuf.length > 0 ? JSON.parse(bodyBuf.toString("utf8")) : null; }
        catch (_e) { bodyJson = null; }
        var entry = {
          method:  req.method,
          url:     req.url,
          headers: req.headers,
          body:    bodyBuf,
          bodyJson: bodyJson,
        };
        captured.push(entry);
        var reply = routes(entry);
        res.statusCode = reply.status || 200;
        res.setHeader("content-type", "application/x-amz-json-1.0");
        res.end(typeof reply.body === "string" ? reply.body : JSON.stringify(reply.body || {}));
      });
    });
    server.listen(0, "127.0.0.1", function () {
      resolve({
        port:     server.address().port,
        captured: captured,
        close:    function () { return new Promise(function (r) { server.close(r); }); },
      });
    });
  });
}

function _baseConfig(port) {
  return {
    region:           "us-east-1",
    accessKeyId:      "AKIATEST",
    secretAccessKey:  "test-secret-access-key",
    accountId:        "123456789012",
    endpoint:         "http://127.0.0.1:" + port + "/",
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    allowInternal:    true,
    timeoutMs:        5000,
  };
}

async function testFactoryValidation() {
  function shouldThrow(label, opts, codeRe) {
    var threw = null;
    try { sqs.create(opts); } catch (e) { threw = e; }
    check("factory: " + label,  threw && codeRe.test(threw.code || ""));
  }
  shouldThrow("rejects missing region",
    { accessKeyId: "x", secretAccessKey: "y", accountId: "0" }, /INVALID_CONFIG/);
  shouldThrow("rejects missing accessKeyId",
    { region: "us-east-1", secretAccessKey: "y", accountId: "0" }, /INVALID_CONFIG/);
  shouldThrow("rejects missing secretAccessKey",
    { region: "us-east-1", accessKeyId: "x", accountId: "0" }, /INVALID_CONFIG/);
  shouldThrow("rejects missing accountId without queueUrlByName",
    { region: "us-east-1", accessKeyId: "x", secretAccessKey: "y" }, /INVALID_CONFIG/);
  // queueUrlByName lets cross-account / VPCE setups skip accountId.
  var ok = null;
  try {
    ok = sqs.create({
      region: "us-east-1", accessKeyId: "x", secretAccessKey: "y",
      queueUrlByName: function (n) { return "https://example.test/" + n; },
    });
  } catch (e) { ok = e; }
  check("queueUrlByName satisfies the url-resolver requirement",
        ok && typeof ok.enqueue === "function");
}

async function testEnqueueWireShape() {
  var srv = await _mockSqs(function (entry) {
    if (entry.headers["x-amz-target"] === "AmazonSQS.SendMessage") {
      return { body: { MessageId: "msg-id-1", MD5OfMessageBody: "abc" } };
    }
    return { status: 400, body: { error: "unexpected target" } };
  });
  try {
    var q = sqs.create(_baseConfig(srv.port));
    var jobId = await q.enqueue("orders", { sku: "SKU-1" });
    check("enqueue returns SQS MessageId or generated jobId",
          typeof jobId === "string" && jobId.length > 0);
    check("POST issued",                        srv.captured.length === 1);
    var req = srv.captured[0];
    check("Content-Type: application/x-amz-json-1.0",
          req.headers["content-type"] === "application/x-amz-json-1.0");
    check("X-Amz-Target: AmazonSQS.SendMessage",
          req.headers["x-amz-target"] === "AmazonSQS.SendMessage");
    check("Authorization is AWS4-HMAC-SHA256",
          /^AWS4-HMAC-SHA256/.test(req.headers["authorization"] || ""));
    check("Authorization carries Credential=AKIATEST/.../sqs/aws4_request",
          /Credential=AKIATEST\/[0-9]{8}\/us-east-1\/sqs\/aws4_request/.test(
            req.headers["authorization"] || ""));
    check("body has QueueUrl",
          typeof req.bodyJson.QueueUrl === "string");
    check("QueueUrl built from accountId + queueName",
          /\/123456789012\/orders$/.test(req.bodyJson.QueueUrl));
    check("body has MessageBody (string-encoded sealed envelope)",
          typeof req.bodyJson.MessageBody === "string");
    var sealed = JSON.parse(req.bodyJson.MessageBody);
    check("MessageBody parses as JSON object",   typeof sealed === "object");
    check("MessageBody carries _id (jobId)",     typeof sealed._id === "string");
    check("MessageBody carries queueName",       sealed.queueName === "orders");
  } finally { await srv.close(); }
}

async function testDelaySecondsClampedAt900() {
  var srv = await _mockSqs(function (entry) {
    if (entry.headers["x-amz-target"] === "AmazonSQS.SendMessage") {
      return { body: { MessageId: "m" } };
    }
    return { status: 400 };
  });
  try {
    var q = sqs.create(_baseConfig(srv.port));
    await q.enqueue("orders", { x: 1 }, { delaySeconds: 9999 });
    check("DelaySeconds clamped at SQS hard cap (900s)",
          srv.captured[0].bodyJson.DelaySeconds === 900);
  } finally { await srv.close(); }
}

async function testLeaseRoundTrip() {
  var srv = await _mockSqs(function (entry) {
    if (entry.headers["x-amz-target"] !== "AmazonSQS.ReceiveMessage") {
      return { status: 400 };
    }
    // Echo back a single message — sealed-envelope shape that
    // queue-sqs.lease() should round-trip through cryptoField.unseal.
    return { body: {
      Messages: [
        {
          MessageId:     "msg-1",
          ReceiptHandle: "rh-aaa",
          Body: JSON.stringify({
            _id:          "job-1",
            queueName:    "orders",
            payload:      JSON.stringify({ sku: "SKU-2" }),
            enqueuedAt:   Date.now(),
            attempts:     0,
          }),
        },
      ],
    }};
  });
  try {
    var q = sqs.create(_baseConfig(srv.port));
    var jobs = await q.lease("orders", { maxRows: 5, visibilityTimeoutSec: 60 });
    check("lease returns one job",  jobs.length === 1);
    check("job has jobId",          jobs[0].jobId === "job-1");
    check("job has queueName",      jobs[0].queueName === "orders");
    check("job payload deserialized", jobs[0].payload && jobs[0].payload.sku === "SKU-2");
    check("job carries receiptHandle for delete/extend",
          jobs[0].receiptHandle === "rh-aaa");
    check("job leaseExpiresAt set",  typeof jobs[0].leaseExpiresAt === "number");
    var req = srv.captured[0];
    check("ReceiveMessage MaxNumberOfMessages clamped to 10",
          req.bodyJson.MaxNumberOfMessages <= 10);
    check("ReceiveMessage VisibilityTimeout = 60",
          req.bodyJson.VisibilityTimeout === 60);
  } finally { await srv.close(); }
}

async function testCompleteDeletes() {
  var srv = await _mockSqs(function () { return { body: {} }; });
  try {
    var q = sqs.create(_baseConfig(srv.port));
    var rv = await q.complete("orders", "job-1", { receiptHandle: "rh-aaa" });
    check("complete returns true",  rv === true);
    var req = srv.captured[0];
    check("X-Amz-Target: DeleteMessage",
          req.headers["x-amz-target"] === "AmazonSQS.DeleteMessage");
    check("body.ReceiptHandle = rh-aaa",
          req.bodyJson.ReceiptHandle === "rh-aaa");

    var threw = null;
    try { await q.complete("orders", "job-1"); }
    catch (e) { threw = e; }
    check("complete without receiptHandle throws MISSING_RECEIPT",
          threw && threw.code === "MISSING_RECEIPT");
  } finally { await srv.close(); }
}

async function testExtendLease() {
  var srv = await _mockSqs(function () { return { body: {} }; });
  try {
    var q = sqs.create(_baseConfig(srv.port));
    var rv = await q.extendLease("orders", "job-1",
                                 { receiptHandle: "rh-aaa", visibilityTimeoutSec: 120 });
    check("extendLease returns true",  rv === true);
    var req = srv.captured[0];
    check("X-Amz-Target: ChangeMessageVisibility",
          req.headers["x-amz-target"] === "AmazonSQS.ChangeMessageVisibility");
    check("VisibilityTimeout = 120",  req.bodyJson.VisibilityTimeout === 120);
  } finally { await srv.close(); }
}

async function testFailMakesVisible() {
  var srv = await _mockSqs(function () { return { body: {} }; });
  try {
    var q = sqs.create(_baseConfig(srv.port));
    await q.fail("orders", "job-1", { receiptHandle: "rh-aaa" });
    var req = srv.captured[0];
    check("fail issues ChangeMessageVisibility",
          req.headers["x-amz-target"] === "AmazonSQS.ChangeMessageVisibility");
    check("VisibilityTimeout = 0 → re-deliver immediately",
          req.bodyJson.VisibilityTimeout === 0);
  } finally { await srv.close(); }
}

async function testSizeAndPurge() {
  var srv = await _mockSqs(function (entry) {
    if (entry.headers["x-amz-target"] === "AmazonSQS.GetQueueAttributes") {
      return { body: { Attributes: { ApproximateNumberOfMessages: "42" } } };
    }
    return { body: {} };
  });
  try {
    var q = sqs.create(_baseConfig(srv.port));
    var n = await q.size("orders");
    check("size returns ApproximateNumberOfMessages as Number",  n === 42);
    var attrReq = srv.captured[0];
    check("size requests AttributeNames including ApproximateNumberOfMessages",
          Array.isArray(attrReq.bodyJson.AttributeNames) &&
          attrReq.bodyJson.AttributeNames.indexOf("ApproximateNumberOfMessages") !== -1);

    var rv = await q.purge("orders");
    check("purge returns 0 (SQS doesn't return a count)",  rv === 0);
    var purgeReq = srv.captured[1];
    check("purge issues PurgeQueue",
          purgeReq.headers["x-amz-target"] === "AmazonSQS.PurgeQueue");
  } finally { await srv.close(); }
}

async function testCustomQueueUrlResolver() {
  var srv = await _mockSqs(function () { return { body: { MessageId: "x" } }; });
  try {
    var q = sqs.create(Object.assign({}, _baseConfig(srv.port), {
      accountId:      undefined,   // not provided
      queueUrlByName: function (n) {
        return "https://example.test/cross-account/" + n;
      },
    }));
    await q.enqueue("orders", { x: 1 });
    check("operator-supplied queueUrlByName wins over default builder",
          srv.captured[0].bodyJson.QueueUrl ===
          "https://example.test/cross-account/orders");
  } finally { await srv.close(); }
}

async function testSessionTokenHeader() {
  var srv = await _mockSqs(function () { return { body: { MessageId: "x" } }; });
  try {
    var q = sqs.create(Object.assign({}, _baseConfig(srv.port), {
      sessionToken: "FAKE-STS-SESSION-TOKEN",
    }));
    await q.enqueue("orders", { x: 1 });
    check("STS session token surfaces as x-amz-security-token header",
          srv.captured[0].headers["x-amz-security-token"] === "FAKE-STS-SESSION-TOKEN");
  } finally { await srv.close(); }
}

async function testNumericConfigValidation() {
  // visibilityTimeoutSec / waitTimeSec are config-time numeric knobs.
  // A typo (NaN-coercing string / negative / fractional) must THROW at
  // create rather than silently coercing to the default and shipping a
  // mis-tuned lease loop.
  function shouldThrow(label, overrides, codeRe) {
    var threw = null;
    try {
      sqs.create(Object.assign({}, _baseConfig(9999), overrides));
    } catch (e) { threw = e; }
    check("numeric-config: " + label, threw && codeRe.test(threw.code || ""));
  }
  function shouldPass(label, overrides) {
    var ok = null;
    try {
      ok = sqs.create(Object.assign({}, _baseConfig(9999), overrides));
    } catch (e) { ok = e; }
    check("numeric-config: " + label, ok && typeof ok.enqueue === "function");
  }

  // Present-but-bad visibilityTimeoutSec throws.
  shouldThrow("rejects NaN-coercing visibilityTimeoutSec",
    { visibilityTimeoutSec: "30s" }, /INVALID_CONFIG/);
  shouldThrow("rejects negative visibilityTimeoutSec",
    { visibilityTimeoutSec: -1 }, /INVALID_CONFIG/);
  shouldThrow("rejects fractional visibilityTimeoutSec",
    { visibilityTimeoutSec: 1.5 }, /INVALID_CONFIG/);
  shouldThrow("rejects zero visibilityTimeoutSec (not a positive int)",
    { visibilityTimeoutSec: 0 }, /INVALID_CONFIG/);

  // Present-but-bad waitTimeSec throws — but 0 (short-poll) stays valid.
  shouldThrow("rejects NaN-coercing waitTimeSec",
    { waitTimeSec: "10s" }, /INVALID_CONFIG/);
  shouldThrow("rejects negative waitTimeSec",
    { waitTimeSec: -1 }, /INVALID_CONFIG/);
  shouldThrow("rejects fractional waitTimeSec",
    { waitTimeSec: 2.5 }, /INVALID_CONFIG/);

  // Absent keeps the default (create succeeds, returns a live adapter).
  shouldPass("absent numeric knobs keep defaults", {});
  // Valid values flow through.
  shouldPass("accepts valid visibilityTimeoutSec", { visibilityTimeoutSec: 60 });
  shouldPass("accepts valid waitTimeSec", { waitTimeSec: 20 });
  // waitTimeSec=0 is the valid SQS short-poll sentinel — must NOT throw.
  shouldPass("accepts waitTimeSec=0 (short-poll sentinel)", { waitTimeSec: 0 });
}

// sqs.create issues its signed requests through the shared b.httpClient
// keep-alive agent, whose cached client sockets (and the mock servers they
// keep open) would otherwise outlive run() and hold the forked worker's
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
  }, { timeoutMs: 5000, label: "queue-sqs: TCP handle drain after _resetForTest" });
}

async function run() {
  try {
    await testFactoryValidation();
    await testNumericConfigValidation();
    await testEnqueueWireShape();
    await testDelaySecondsClampedAt900();
    await testLeaseRoundTrip();
    await testCompleteDeletes();
    await testExtendLease();
    await testFailMakesVisible();
    await testSizeAndPurge();
    await testCustomQueueUrlResolver();
    await testSessionTokenHeader();
  } finally {
    await _drainTcpHandles();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[queue-sqs] OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
