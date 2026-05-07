"use strict";

var http = require("node:http");
var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
var otlp = require("../../lib/log-stream-otlp");

function _mockCollector(opts) {
  opts = opts || {};
  var received = [];
  var responder = opts.responder || function (_req, res) {
    res.statusCode = 200;
    res.setHeader("content-type", "application/json");
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
        received.push({ url: req.url, error: e.message });
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

async function _sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

async function run() {
  // ---- URL resolution ----
  check("_resolveUrl: appends /v1/logs to bare host",
    otlp._resolveUrl("https://col:4318") === "https://col:4318/v1/logs");
  check("_resolveUrl: preserves explicit /v1/logs",
    otlp._resolveUrl("https://col:4318/v1/logs") === "https://col:4318/v1/logs");
  check("_resolveUrl: strips trailing slash",
    otlp._resolveUrl("https://col:4318/") === "https://col:4318/v1/logs");
  check("_resolveUrl: preserves /v1/logs with trailing slash",
    otlp._resolveUrl("https://col:4318/v1/logs/") === "https://col:4318/v1/logs");

  // ---- Attribute encoding ----
  var attrs = otlp._encodeAttrs({
    str:   "value",
    n:     42,
    f:     3.14,
    bool:  true,
    arr:   [1, "two"],
    nest:  { inner: "v" },
  });
  var byKey = {};
  attrs.forEach(function (a) { byKey[a.key] = a.value; });
  check("attr str → stringValue",  byKey.str.stringValue === "value");
  check("attr int → intValue (string-encoded)",  byKey.n.intValue === "42");
  check("attr float → doubleValue", byKey.f.doubleValue === 3.14);
  check("attr bool → boolValue",   byKey.bool.boolValue === true);
  check("attr array → arrayValue.values length",
    byKey.arr.arrayValue && byKey.arr.arrayValue.values.length === 2);
  check("attr nested object → kvlistValue",
    byKey.nest.kvlistValue && byKey.nest.kvlistValue.values.length === 1);

  // ---- Log record marshalling ----
  var rec = otlp._toLogRecord({ ts: 1700000000123, level: "warn", message: "hi", meta: { k: "v" } });
  check("logRecord: timeUnixNano = ms*1_000_000 as string",
    rec.timeUnixNano === "1700000000123000000");
  check("logRecord: severityNumber = 13 for warn",  rec.severityNumber === 13);
  check("logRecord: severityText = WARN",  rec.severityText === "WARN");
  check("logRecord: body.stringValue carries message",
    rec.body.stringValue === "hi");
  check("logRecord: attributes length === 1",  rec.attributes.length === 1);

  // ---- Round-trip via mock collector ----
  var col1 = await _mockCollector();
  try {
    var sink = otlp.create({
      url:           col1.url,
      serviceName:   "blamejs-test",
      serviceVersion: "1.2.3",
      resourceAttributes: { env: "test" },
      batchSize:     2,        // small to force flush after 2 emits
      maxBatchAgeMs: 200,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:    true,
    });
    await sink.emit({ ts: 1700000000000, level: "info",  message: "msg1" });
    await sink.emit({ ts: 1700000000001, level: "error", message: "msg2", meta: { code: "E1" } });
    // Wait for flush
    await _sleep(300);
    check("collector received POST", col1.received.length === 1);
    check("collector POST hit /v1/logs", col1.received[0].url === "/v1/logs");
    check("collector POST has Content-Type application/json",
      col1.received[0].headers["content-type"] === "application/json");
    var env = col1.received[0].bodyJson;
    check("envelope: resourceLogs[0].resource exists",
      env && env.resourceLogs && env.resourceLogs[0].resource);
    var resAttrsByKey = {};
    env.resourceLogs[0].resource.attributes.forEach(function (a) {
      resAttrsByKey[a.key] = a.value.stringValue;
    });
    check("resource: service.name = blamejs-test",
      resAttrsByKey["service.name"] === "blamejs-test");
    check("resource: service.version = 1.2.3",
      resAttrsByKey["service.version"] === "1.2.3");
    check("resource: env = test (custom resourceAttributes)",
      resAttrsByKey["env"] === "test");
    check("scopeLogs[0].scope.name = blamejs",
      env.resourceLogs[0].scopeLogs[0].scope.name === "blamejs");
    check("logRecords length = 2",
      env.resourceLogs[0].scopeLogs[0].logRecords.length === 2);
    check("logRecord[0] severity = INFO",
      env.resourceLogs[0].scopeLogs[0].logRecords[0].severityText === "INFO");
    check("logRecord[1] severity = ERROR",
      env.resourceLogs[0].scopeLogs[0].logRecords[1].severityText === "ERROR");
    await sink.close();
  } finally {
    await col1.close();
  }

  // ---- Auth header pass-through ----
  var col2 = await _mockCollector();
  try {
    var sink2 = otlp.create({
      url:    col2.url,
      auth:   "bearer",
      token:  "secret-token-123",
      batchSize: 1,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:    true,
    });
    await sink2.emit({ ts: Date.now(), level: "info", message: "auth-test" });
    await _sleep(100);
    check("collector received auth POST", col2.received.length === 1);
    check("Authorization: Bearer header present",
      col2.received[0].headers["authorization"] === "Bearer secret-token-123");
    await sink2.close();
  } finally {
    await col2.close();
  }

  // ---- Retry on 5xx + drop on retry-exhaustion ----
  var failCount = 0;
  var col3 = await _mockCollector({
    responder: function (_req, res) {
      failCount++;
      res.statusCode = 503;
      res.setHeader("content-type", "application/json");
      res.end('{"err":"unavailable"}');
    },
  });
  try {
    var dropEvents = [];
    var sink3 = otlp.create({
      url:    col3.url,
      batchSize: 1,
      retry:  { maxAttempts: 2, baseDelayMs: 5, maxDelayMs: 10 },
      onDrop: function (d) { dropEvents.push(d); },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:    true,
    });
    await sink3.emit({ ts: Date.now(), level: "info", message: "will-drop" });
    await _sleep(200);
    check("collector saw retries (>=2)", failCount >= 2);
    check("onDrop invoked with reason 'retry-exhausted'",
      dropEvents.length === 1 && dropEvents[0].reason === "retry-exhausted");
    check("dropped batch contained the rejected record",
      dropEvents[0].batch.length === 1 && dropEvents[0].batch[0].message === "will-drop");
    var s3stats = sink3.stats();
    check("stats.dropped reflects drop count", s3stats.dropped === 1);
    await sink3.close();
  } finally {
    await col3.close();
  }

  // ---- Buffer overflow drops oldest + emits onDrop ----
  var col4 = await _mockCollector({
    responder: function (_req, res) {
      // Hang the response so the in-flight batch never completes;
      // subsequent emits queue up, eventually overflowing.
      // (Test calls close() to release.)
      setTimeout(function () { res.statusCode = 200; res.end("{}"); }, 5000);
    },
  });
  try {
    var dropEvents4 = [];
    var sink4 = otlp.create({
      url:         col4.url,
      batchSize:   2,
      bufferLimit: 3,
      maxBatchAgeMs: 50,
      onDrop:      function (d) { dropEvents4.push(d); },
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:    true,
    });
    // Emit enough to trigger flush + buffer overflow
    for (var i = 0; i < 8; i++) {
      sink4.emit({ ts: Date.now(), level: "info", message: "m-" + i });
    }
    await _sleep(150);
    var overflowDrops = dropEvents4.filter(function (d) { return d.reason === "overflow"; });
    check("overflow drops fired (oldest evicted)", overflowDrops.length > 0);
    // Don't await close — the hanging response keeps it alive
    sink4.close().catch(function () {});
  } finally {
    await col4.close();
  }

  // ---- Surface integration: logStream wires otlp via dispatcher ----
  // Verify that opts.protocol = "otlp" reaches log-stream-otlp.create
  // through the dispatcher; otlp is no longer in DEFERRED_PROTOCOLS.
  var col5 = await _mockCollector();
  try {
    b.logStream._resetForTest();
    b.logStream.init({
      sinks: {
        primary: {
          protocol:    "otlp",
          url:         col5.url,
          serviceName: "integration",
          batchSize:   1,
          maxBatchAgeMs: 50,
          allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
          allowInternal:    true,
        },
      },
      minLevel: "debug",
    });
    b.logStream.info("hello", { who: "world" });
    await _sleep(150);
    check("dispatcher: otlp sink received the log",
      col5.received.length === 1 &&
      col5.received[0].bodyJson.resourceLogs[0].scopeLogs[0].logRecords[0].body.stringValue === "hello");
    check("dispatcher: otlp removed from DEFERRED_PROTOCOLS",
      b.logStream.DEFERRED_PROTOCOLS.indexOf("otlp") === -1);
    check("dispatcher: otlp listed in PROTOCOLS",
      b.logStream.PROTOCOLS.indexOf("otlp") !== -1);
    await b.logStream.shutdown();
  } finally {
    await col5.close();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[log-stream-otlp] OK"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
