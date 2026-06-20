"use strict";
/**
 * OTLP gRPC log sink — wire encoding + mock HTTP/2 server roundtrip.
 *
 * The framework's gRPC client speaks HTTP/2 + hand-encoded protobuf
 * directly to a stock OTel collector. Tests cover both layers:
 *
 *   - Wire encoding: deterministic byte sequences for a known
 *     ExportLogsServiceRequest, asserted against a hand-computed
 *     reference where the protobuf field numbers + wire types are
 *     small enough to verify.
 *   - HTTP/2 dance: a mock h2c (HTTP/2 cleartext) server accepts the
 *     POST, parses the gRPC framing, and returns grpc-status:0 in
 *     trailers.
 */
var http2 = require("node:http2");
var helpers = require("../helpers");
var check = helpers.check;
var grpc = require("../../lib/log-stream-otlp-grpc");

function _h2cServer(handler) {
  return new Promise(function (resolve) {
    var captured = [];
    var server = http2.createServer();
    server.on("stream", function (stream, headers) {
      var chunks = [];
      stream.on("data", function (c) { chunks.push(c); });
      stream.on("end", function () {
        var body = Buffer.concat(chunks);
        captured.push({ headers: headers, body: body });
        handler(stream, headers, body, captured);
      });
    });
    server.listen(0, "127.0.0.1", function () {
      resolve({
        port:    server.address().port,
        captured: captured,
        close:    function () { return new Promise(function (r) { server.close(r); }); },
      });
    });
  });
}

function _baseConfig(port, overrides) {
  return Object.assign({
    url:           "http://127.0.0.1:" + port,
    serviceName:   "test-service",
    serviceVersion: "1.0.0",
    batchSize:     5,
    maxBatchAgeMs: 50,
    timeoutMs:     5000,
    allowedProtocols: ["http:", "https:"],
    allowInsecure: true,
  }, overrides || {});
}

async function testFramingShape() {
  // gRPC frame: 1-byte compression flag + 4-byte BE length + body.
  var sink = grpc.create(_baseConfig(0));
  var body = Buffer.from([1, 2, 3]);
  var framed = sink._frameForTest(body);
  check("frame length = 5 (header) + body.length",  framed.length === 5 + body.length);
  check("compression flag is 0",                    framed[0] === 0);
  check("length is BE-encoded",                     framed.readUInt32BE(1) === body.length);
  check("payload follows header verbatim",
        Buffer.compare(framed.slice(5), body) === 0);
}

async function testEncodeLogRecord() {
  // Encode a single record and verify it has the expected fields.
  // We don't decode — instead we look for known byte patterns.
  var sink = grpc.create(_baseConfig(0));
  var body = sink._encodeForTest([{
    ts:      1735689600000,   // 2025-01-01T00:00:00Z
    level:   "info",
    message: "hello",
    meta:    { traceId: "abc-123" },
  }]);
  check("encoded body is non-empty", body.length > 0);
  // String "hello" in body — UTF-8 bytes 68 65 6c 6c 6f.
  check("encoded body contains 'hello' as UTF-8",
        body.indexOf(Buffer.from("hello", "utf8")) !== -1);
  // service.name attribute -> "test-service" UTF-8.
  check("encoded body contains 'test-service'",
        body.indexOf(Buffer.from("test-service", "utf8")) !== -1);
  // severity_text = "INFO"
  check("encoded body contains 'INFO'",
        body.indexOf(Buffer.from("INFO", "utf8")) !== -1);
}

async function testEncodeAttributeTypes() {
  var any = grpc._encodeAnyValue;
  // string -> field 1 (length-delimited)
  check("string AnyValue starts with tag 0x0a",  any("x")[0] === 0x0a);
  // bool true -> field 2 (varint), tag 0x10, body 0x01
  check("bool true -> 10 01",
        any(true).toString("hex") === "1001");
  // int (non-negative) -> field 3 (varint)
  check("int 5 starts with tag 0x18",  any(5)[0] === 0x18);
  // double -> field 4 (64-bit)
  check("double 1.5 starts with tag 0x21",  any(1.5)[0] === 0x21);
  // bytes -> field 7 (length-delimited)
  check("Buffer -> tag 0x3a",  any(Buffer.from([1])).readUInt8(0) === 0x3a);
}

async function testGrpcRoundTrip() {
  var srv = await _h2cServer(function (stream) {
    stream.respond({
      ":status":      200,
      "content-type": "application/grpc+proto",
    }, { waitForTrailers: true });
    stream.on("wantTrailers", function () {
      stream.sendTrailers({ "grpc-status": "0" });
    });
    // gRPC empty response: 1 byte (0) + 4 bytes (0) + 0 body.
    stream.write(Buffer.from([0, 0, 0, 0, 0]));
    stream.end();
  });
  try {
    var sink = grpc.create(_baseConfig(srv.port, {
      batchSize: 1,        // flush each record
      maxBatchAgeMs: 20,
    }));
    await sink.emit({ ts: Date.now(), level: "info", message: "wire-test" });
    // Wait for the gRPC export to land at the mock collector.
    await helpers.waitUntil(function () { return srv.captured.length >= 1; }, {
      label: "otlp-grpc: mock collector received Export request",
    });
    await sink.close();
    check("server received exactly one request",  srv.captured.length === 1);
    var req = srv.captured[0];
    check("path is OTLP Logs Export",
          req.headers[":path"] ===
          "/opentelemetry.proto.collector.logs.v1.LogsService/Export");
    check("content-type is application/grpc+proto",
          /^application\/grpc\+proto/.test(req.headers["content-type"] || ""));
    check("te trailers header set",
          req.headers["te"] === "trailers");
    // Body: 1-byte compress + 4-byte BE length + protobuf message.
    check("body length >= 5 (header + nonzero message)",
          req.body.length > 5);
    check("body header compression flag = 0",  req.body[0] === 0);
    var msgLen = req.body.readUInt32BE(1);
    check("body header length matches body.length-5",
          msgLen === req.body.length - 5);
    var protoBody = req.body.slice(5);
    check("protobuf body contains 'wire-test' UTF-8",
          protoBody.indexOf(Buffer.from("wire-test", "utf8")) !== -1);
  } finally { await srv.close(); }
}

async function testGrpcServerErrorTrailer() {
  var srv = await _h2cServer(function (stream) {
    stream.respond({ ":status": 200, "content-type": "application/grpc" },
                   { waitForTrailers: true });
    stream.on("wantTrailers", function () {
      stream.sendTrailers({ "grpc-status": "13", "grpc-message": "internal error" });
    });
    stream.end();
  });
  var dropped = [];
  try {
    var sink = grpc.create(_baseConfig(srv.port, {
      batchSize: 1,
      onDrop:    function (d) { dropped.push(d); },
    }));
    await sink.emit({ ts: Date.now(), level: "error", message: "doomed" });
    await helpers.waitUntil(function () { return dropped.length >= 1; }, {
      label: "otlp-grpc: server-error trailer fires onDrop",
    });
    await sink.close();
    check("server-side gRPC error fires onDrop",  dropped.length >= 1);
    check("drop reason = 'send-failed'",
          dropped[0].reason === "send-failed");
    check("drop error mentions grpc-status 13",
          dropped[0].error && /grpc-status 13/.test(dropped[0].error.message || ""));
    check("drop error mentions 'internal error'",
          dropped[0].error && /internal error/.test(dropped[0].error.message || ""));
  } finally { await srv.close(); }
}

async function testValidationRejectsBadUrl() {
  var threw = null;
  try { grpc.create({}); } catch (e) { threw = e; }
  check("missing url throws",  threw && threw.code === "BAD_OPT");
}

// The insecure-TLS audit must only fire on an actual TLS session. An h2c
// endpoint (http://, cleartext HTTP/2) creates no TLS session, so allowInsecure
// there skips no certificate and must NOT emit tls.insecure_skip_verify — a
// false security/compliance event. https:// + allowInsecure still emits it.
async function testInsecureTlsAuditGatedToHttps() {
  var observability = require("../../lib/observability");
  function capture(cfg) {
    var events = [];
    observability.setTap(function (name) { if (name === "tls.insecure_skip_verify") events.push(name); });
    var session;
    try { session = grpc._makeClient(cfg); }
    finally { observability.setTap(null); }
    if (session) {
      session.on("error", function () { /* dead address — expected */ });
      try { session.destroy(); } catch (_e) { /* best-effort */ }
    }
    return events.length;
  }

  var h2c = capture({ url: "http://127.0.0.1:1", allowInsecure: true, allowedProtocols: ["http:", "https:"] });
  check("h2c (cleartext) endpoint with allowInsecure emits NO insecure-TLS audit", h2c === 0);

  var tls = capture({ url: "https://127.0.0.1:1", allowInsecure: true, allowedProtocols: ["http:", "https:"] });
  check("https endpoint with allowInsecure DOES emit the insecure-TLS audit", tls === 1);
}

async function run() {
  await testFramingShape();
  await testEncodeLogRecord();
  await testEncodeAttributeTypes();
  await testGrpcRoundTrip();
  await testGrpcServerErrorTrailer();
  await testValidationRejectsBadUrl();
  await testInsecureTlsAuditGatedToHttps();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () {
      console.log("[log-stream-otlp-grpc] OK — " + helpers.getChecks() + " checks passed");
      process.exit(0);
    },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
