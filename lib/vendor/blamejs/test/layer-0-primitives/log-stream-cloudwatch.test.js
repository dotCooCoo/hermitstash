// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var http = require("node:http");
var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
var cw = require("../../lib/log-stream-cloudwatch");

function _mockCloudWatch(opts) {
  opts = opts || {};
  var received = [];
  var responder = opts.responder || function (_req, res) {
    res.statusCode = 200;
    res.setHeader("content-type", "application/x-amz-json-1.1");
    res.end("{}");
  };
  var server = http.createServer(function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      try {
        var body = Buffer.concat(chunks);
        received.push({
          url:     req.url,
          method:  req.method,
          headers: req.headers,
          body:    body,
          bodyJson: body.length > 0 ? JSON.parse(body.toString("utf8")) : null,
        });
      } catch (e) {
        received.push({ error: e.message });
      }
      responder(req, res);
    });
  });
  return new Promise(function (resolve) {
    server.listen(0, "127.0.0.1", function () {
      var port = server.address().port;
      resolve({
        url:      "http://127.0.0.1:" + port,
        received: received,
        close:    function () { return new Promise(function (r) { server.close(r); }); },
      });
    });
  });
}

async function run() {
  // ---- Endpoint resolution ----
  check("_resolveEndpoint: derives from region",
    cw._resolveEndpoint({ region: "us-east-1" }) ===
    "https://logs.us-east-1.amazonaws.com/");
  check("_resolveEndpoint: honors explicit endpoint + strips trailing slash",
    cw._resolveEndpoint({ endpoint: "https://logs.eu-west-1.amazonaws.com/" }) ===
    "https://logs.eu-west-1.amazonaws.com/");

  // ---- Event size accounting ----
  check("_eventByteSize: includes 26-byte AWS overhead",
    cw._eventByteSize("hello") === 5 + 26);

  // ---- Batch serialization sorts ascending + carries sequence token ----
  var ser = cw._serializeBatch(
    [
      { timestamp: 3000, message: "third" },
      { timestamp: 1000, message: "first" },
      { timestamp: 2000, message: "second" },
    ],
    { logGroupName: "g", logStreamName: "s" },
    "seq-123"
  );
  var serObj = JSON.parse(ser.toString("utf8"));
  check("_serializeBatch: sorts ascending by timestamp",
    serObj.logEvents[0].timestamp === 1000 &&
    serObj.logEvents[2].timestamp === 3000);
  check("_serializeBatch: includes logGroup/logStream",
    serObj.logGroupName === "g" && serObj.logStreamName === "s");
  check("_serializeBatch: includes sequenceToken when provided",
    serObj.sequenceToken === "seq-123");

  // ---- Permanent error classifier ----
  check("_isPermanentAwsError: ResourceNotFoundException → true",
    cw._isPermanentAwsError(new Error("ResourceNotFoundException: log group missing")));
  check("_isPermanentAwsError: AccessDeniedException → true",
    cw._isPermanentAwsError(new Error("AccessDeniedException")));
  check("_isPermanentAwsError: ThrottlingException → false (transient)",
    !cw._isPermanentAwsError(new Error("ThrottlingException: slow down")));
  check("_isPermanentAwsError: 503 → false (transient)",
    !cw._isPermanentAwsError(new Error("503 Service Unavailable")));

  // ---- Validation ----
  var threwRegion = null;
  try { cw.create({}); } catch (e) { threwRegion = e; }
  check("create rejects missing region",
    threwRegion && threwRegion.code === "BAD_OPT" && /region/.test(threwRegion.message));
  var threwCreds = null;
  try { cw.create({ region: "us-east-1" }); } catch (e) { threwCreds = e; }
  check("create rejects missing credentials",
    threwCreds && /accessKeyId/.test(threwCreds.message));
  var threwGroup = null;
  try {
    cw.create({ region: "us-east-1", accessKeyId: "AKIA", secretAccessKey: "x" });
  } catch (e) { threwGroup = e; }
  check("create rejects missing logGroup/logStream",
    threwGroup && /logGroupName/.test(threwGroup.message));

  // ---- Round-trip via mock CloudWatch ----
  var mock1 = await _mockCloudWatch();
  try {
    var sink = cw.create({
      region:          "us-east-1",
      accessKeyId:     "AKIATEST",
      secretAccessKey: "secret-test-key",
      logGroupName:    "test-group",
      logStreamName:   "test-stream",
      endpoint:        mock1.url,
      batchSize:       2,
      maxBatchAgeMs:   200,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:   true,
    });
    await sink.emit({ ts: 1700000000000, level: "info",  message: "msg1" });
    await sink.emit({ ts: 1700000000001, level: "error", message: "msg2" });
    await helpers.waitUntil(function () { return mock1.received.length >= 1; }, {
      label: "cloudwatch: mock received PutLogEvents POST",
    });
    check("CloudWatch received POST /", mock1.received.length === 1 && mock1.received[0].url === "/");
    check("X-Amz-Target = Logs_20140328.PutLogEvents",
      mock1.received[0].headers["x-amz-target"] === "Logs_20140328.PutLogEvents");
    check("Content-Type = application/x-amz-json-1.1",
      mock1.received[0].headers["content-type"] === "application/x-amz-json-1.1");
    check("Authorization header is SigV4",
      /^AWS4-HMAC-SHA256/.test(mock1.received[0].headers["authorization"]));
    var body = mock1.received[0].bodyJson;
    check("body.logGroupName = test-group",  body.logGroupName === "test-group");
    check("body.logStreamName = test-stream", body.logStreamName === "test-stream");
    check("body.logEvents length = 2",  body.logEvents.length === 2);
    check("logEvents[0].timestamp = 1700000000000", body.logEvents[0].timestamp === 1700000000000);
    check("logEvents[1].message = msg2", body.logEvents[1].message === "msg2");
    await sink.close();
  } finally {
    await mock1.close();
  }

  // ---- STS sessionToken propagates as X-Amz-Security-Token ----
  var mock2 = await _mockCloudWatch();
  try {
    var sink2 = cw.create({
      region:          "us-east-1",
      accessKeyId:     "ASIATEST",                  // STS-style key
      secretAccessKey: "secret",
      sessionToken:    "FQoGZXIvYXdzEDM=",
      logGroupName:    "g",
      logStreamName:   "s",
      endpoint:        mock2.url,
      batchSize:       1,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:   true,
    });
    await sink2.emit({ ts: Date.now(), level: "info", message: "sts-test" });
    await helpers.waitUntil(function () { return mock2.received.length >= 1; }, {
      label: "cloudwatch: STS sink delivered to mock",
    });
    check("STS session token propagates as X-Amz-Security-Token",
      mock2.received[0].headers["x-amz-security-token"] === "FQoGZXIvYXdzEDM=");
    await sink2.close();
  } finally {
    await mock2.close();
  }

  // ---- ResourceNotFoundException → permanent drop, NO retry ----
  var rnfCallCount = 0;
  var mock3 = await _mockCloudWatch({
    responder: function (_req, res) {
      rnfCallCount++;
      res.statusCode = 400;
      res.setHeader("content-type", "application/x-amz-json-1.1");
      res.end(JSON.stringify({
        __type:  "ResourceNotFoundException",
        message: "The specified log group does not exist.",
      }));
    },
  });
  try {
    var dropEvents = [];
    var sink3 = cw.create({
      region:          "us-east-1",
      accessKeyId:     "AKIA",
      secretAccessKey: "secret",
      logGroupName:    "nonexistent",
      logStreamName:   "nonexistent",
      endpoint:        mock3.url,
      batchSize:       1,
      retry:           { maxAttempts: 5, baseDelayMs: 5, maxDelayMs: 10 },
      onDrop:          function (d) { dropEvents.push(d); },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:   true,
    });
    await sink3.emit({ ts: Date.now(), level: "info", message: "lost" });
    await helpers.waitUntil(function () { return dropEvents.length >= 1; }, {
      label: "cloudwatch: ResourceNotFound drop event fired",
    });
    check("ResourceNotFound: NOT retried (1 attempt only)", rnfCallCount === 1);
    check("ResourceNotFound: dropped via onDrop with retry-exhausted",
      dropEvents.length === 1 && dropEvents[0].reason === "retry-exhausted");
    await sink3.close();
  } finally {
    await mock3.close();
  }

  // ---- 256 KiB per-event hard cap ----
  var mock4 = await _mockCloudWatch();
  try {
    var oversizeDrops = [];
    var sink4 = cw.create({
      region:          "us-east-1",
      accessKeyId:     "AKIA",
      secretAccessKey: "secret",
      logGroupName:    "g",
      logStreamName:   "s",
      endpoint:        mock4.url,
      batchSize:       1,
      onDrop:          function (d) { oversizeDrops.push(d); },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:   true,
    });
    var bigMessage = "X".repeat(257 * 1024);
    var result = await sink4.emit({ ts: Date.now(), level: "info", message: bigMessage });
    check("Oversize emit returns accepted: false", result.accepted === false);
    check("Oversize emit fires onDrop with reason event-too-large",
      oversizeDrops.length === 1 && oversizeDrops[0].reason === "event-too-large");
    check("Oversize drop carries truncated message in event-too-large drop",
      oversizeDrops[0].batch[0].message.length < bigMessage.length);
    check("CloudWatch received NO POST for oversize", mock4.received.length === 0);
    await sink4.close();
  } finally {
    await mock4.close();
  }

  // ---- Dispatcher integration via b.logStream ----
  var mock5 = await _mockCloudWatch();
  try {
    b.logStream._resetForTest();
    b.logStream.init({
      sinks: {
        primary: {
          protocol:        "cloudwatch",
          region:          "us-east-1",
          accessKeyId:     "AKIATEST",
          secretAccessKey: "secret",
          logGroupName:    "integration-group",
          logStreamName:   "integration-stream",
          endpoint:        mock5.url,
          batchSize:       1,
          maxBatchAgeMs:   50,
          allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
          allowInternal:   true,
        },
      },
      minLevel: "debug",
    });
    b.logStream.info("dispatcher-test", { kind: "regression" });
    await helpers.waitUntil(function () { return mock5.received.length >= 1; }, {
      label: "cloudwatch dispatcher: sink received the log",
    });
    check("dispatcher: CloudWatch sink received the log",
      mock5.received.length === 1 &&
      mock5.received[0].bodyJson.logGroupName === "integration-group");
    check("dispatcher: cloudwatch removed from DEFERRED_PROTOCOLS",
      b.logStream.DEFERRED_PROTOCOLS.indexOf("cloudwatch") === -1);
    check("dispatcher: cloudwatch listed in PROTOCOLS",
      b.logStream.PROTOCOLS.indexOf("cloudwatch") !== -1);
    await b.logStream.shutdown();
  } finally {
    await mock5.close();
  }

  // ---- autoCreate: true wires CreateLogGroup + CreateLogStream before PutLogEvents ----
  var seenTargets = [];
  var mockAC = await _mockCloudWatch({
    responder: function (req, res) {
      seenTargets.push(req.headers["x-amz-target"]);
      res.statusCode = 200;
      res.setHeader("content-type", "application/x-amz-json-1.1");
      res.end("{}");
    },
  });
  try {
    var sinkAC = cw.create({
      region:          "us-east-1",
      accessKeyId:     "AKIA",
      secretAccessKey: "secret",
      logGroupName:    "auto-group",
      logStreamName:   "auto-stream",
      endpoint:        mockAC.url,
      autoCreate:      true,
      batchSize:       1,
      maxBatchAgeMs:   50,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:   true,
    });
    sinkAC.emit({ ts: Date.now(), level: "info", message: "auto-create" });
    await helpers.waitUntil(function () {
      return seenTargets.indexOf("Logs_20140328.PutLogEvents") !== -1;
    }, { label: "cloudwatch autoCreate: PutLogEvents issued after CreateLogGroup + CreateLogStream" });
    check("autoCreate: CreateLogGroup issued",
      seenTargets.indexOf("Logs_20140328.CreateLogGroup") !== -1);
    check("autoCreate: CreateLogStream issued",
      seenTargets.indexOf("Logs_20140328.CreateLogStream") !== -1);
    check("autoCreate: PutLogEvents issued AFTER both Create calls",
      seenTargets.indexOf("Logs_20140328.PutLogEvents") >
        seenTargets.indexOf("Logs_20140328.CreateLogStream"));
    await sinkAC.close();
  } finally {
    await mockAC.close();
  }

  // ---- autoCreate: ResourceAlreadyExistsException is treated as success ----
  var seenTargetsAE = [];
  var mockAE = await _mockCloudWatch({
    responder: function (req, res) {
      var t = req.headers["x-amz-target"];
      seenTargetsAE.push(t);
      if (/CreateLogGroup|CreateLogStream/.test(t)) {
        res.statusCode = 400;
        res.setHeader("content-type", "application/x-amz-json-1.1");
        res.end(JSON.stringify({
          __type:  "ResourceAlreadyExistsException",
          message: "The specified log group already exists",
        }));
        return;
      }
      res.statusCode = 200;
      res.setHeader("content-type", "application/x-amz-json-1.1");
      res.end("{}");
    },
  });
  try {
    var sinkAE = cw.create({
      region:          "us-east-1",
      accessKeyId:     "AKIA",
      secretAccessKey: "secret",
      logGroupName:    "exists-group",
      logStreamName:   "exists-stream",
      endpoint:        mockAE.url,
      autoCreate:      true,
      batchSize:       1,
      maxBatchAgeMs:   50,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:   true,
    });
    sinkAE.emit({ ts: Date.now(), level: "info", message: "exists" });
    await helpers.waitUntil(function () {
      return seenTargetsAE.indexOf("Logs_20140328.PutLogEvents") !== -1;
    }, { label: "cloudwatch autoCreate: PutLogEvents after AlreadyExists" });
    check("autoCreate: ResourceAlreadyExists on group does not abort PutLogEvents",
      seenTargetsAE.indexOf("Logs_20140328.PutLogEvents") !== -1);
    await sinkAE.close();
  } finally {
    await mockAE.close();
  }

  // ---- autoCreate: hard CreateLogGroup failure drops events with reason ----
  var seenAFTargets = [];
  var droppedAF = [];
  var mockAF = await _mockCloudWatch({
    responder: function (req, res) {
      var t = req.headers["x-amz-target"];
      seenAFTargets.push(t);
      if (t === "Logs_20140328.CreateLogGroup") {
        res.statusCode = 500;
        res.setHeader("content-type", "application/x-amz-json-1.1");
        res.end(JSON.stringify({ __type: "InternalServerError", message: "boom" }));
        return;
      }
      res.statusCode = 200;
      res.setHeader("content-type", "application/x-amz-json-1.1");
      res.end("{}");
    },
  });
  try {
    var sinkAF = cw.create({
      region:          "us-east-1",
      accessKeyId:     "AKIA",
      secretAccessKey: "secret",
      logGroupName:    "fail-group",
      logStreamName:   "fail-stream",
      endpoint:        mockAF.url,
      autoCreate:      true,
      batchSize:       1,
      maxBatchAgeMs:   50,
      onDrop:          function (d) { droppedAF.push(d); },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:   true,
    });
    sinkAF.emit({ ts: Date.now(), level: "info", message: "doomed" });
    await helpers.waitUntil(function () { return droppedAF.length >= 1; }, {
      label: "cloudwatch autoCreate: hard-fail drop fired",
    });
    check("autoCreate: hard CreateLogGroup failure drops the buffered batch",
      droppedAF.length >= 1 && droppedAF[0].reason === "autocreate-failed");
    check("autoCreate: PutLogEvents NOT issued when autoCreate fails",
      seenAFTargets.indexOf("Logs_20140328.PutLogEvents") === -1);
    await sinkAF.close();
  } finally {
    await mockAF.close();
  }

  // ---- autoCreate: false (default) skips Create calls entirely ----
  var seenDefTargets = [];
  var mockDef = await _mockCloudWatch({
    responder: function (req, res) {
      seenDefTargets.push(req.headers["x-amz-target"]);
      res.statusCode = 200;
      res.setHeader("content-type", "application/x-amz-json-1.1");
      res.end("{}");
    },
  });
  try {
    var sinkDef = cw.create({
      region:          "us-east-1",
      accessKeyId:     "AKIA",
      secretAccessKey: "secret",
      logGroupName:    "pre-existing-group",
      logStreamName:   "pre-existing-stream",
      endpoint:        mockDef.url,
      // autoCreate omitted — defaults false
      batchSize:       1,
      maxBatchAgeMs:   50,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:   true,
    });
    sinkDef.emit({ ts: Date.now(), level: "info", message: "no-create" });
    await helpers.waitUntil(function () { return seenDefTargets.length >= 1; }, {
      label: "cloudwatch autoCreate-default: PutLogEvents reached mock",
    });
    check("autoCreate default false: no Create calls issued",
      seenDefTargets.every(function (t) {
        return t === "Logs_20140328.PutLogEvents";
      }));
    await sinkDef.close();
  } finally {
    await mockDef.close();
  }

  // ---- Batch splitting on size cap ----
  // Build 5 events that fit batchSize but bust the 1-MiB cap. Each is
  // ~250 KiB; 5 of them = 1.25 MiB — should be split into 4 + 1.
  var mock6 = await _mockCloudWatch();
  try {
    var sink6 = cw.create({
      region:          "us-east-1",
      accessKeyId:     "AKIA",
      secretAccessKey: "secret",
      logGroupName:    "g",
      logStreamName:   "s",
      endpoint:        mock6.url,
      batchSize:       100,                          // not the limiter
      maxBatchAgeMs:   100,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:   true,
    });
    var bigChunk = "Y".repeat(250 * 1024);
    for (var i = 0; i < 5; i++) {
      sink6.emit({ ts: Date.now() + i, level: "info", message: bigChunk });
    }
    await helpers.waitUntil(function () { return mock6.received.length >= 2; }, {
      timeoutMs: 5000,
      label:     "log-stream-cloudwatch: mock6 received both split batches",
    });
    check("batch splitter: 5 quarter-MB events POST as 2 calls (4 + 1)",
      mock6.received.length === 2);
    check("batch splitter: first call has 4 events",
      mock6.received[0].bodyJson.logEvents.length === 4);
    check("batch splitter: second call has 1 event",
      mock6.received[1].bodyJson.logEvents.length === 1);
    await sink6.close();
  } finally {
    await mock6.close();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[log-stream-cloudwatch] OK"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
