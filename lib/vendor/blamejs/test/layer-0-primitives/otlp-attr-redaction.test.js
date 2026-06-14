"use strict";
// The OTLP span exporter must run every attribute VALUE through the telemetry
// redactor before serialization. Telemetry is a first-class EGRESS sink — a
// span attribute holding a bearer token, password, or API key would otherwise
// be shipped verbatim onto the OTLP wire (CWE-532: insertion of sensitive
// information into an externally-shipped sink), reaching whatever collector the
// operator points at.
//
// Drives the real consumer path: create() an exporter with a capturing
// fetchImpl, queue a span (and a span EVENT) carrying sensitive attributes,
// flush, and inspect the outgoing body — for BOTH json and protobuf encodings.
// The default redactor (b.redact.redact) scrubs by sensitive field name.

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

var otlp        = require("../../lib/observability-otlp-exporter");
var otlpLog     = require("../../lib/log-stream-otlp");
var otlpLogGrpc = require("../../lib/log-stream-otlp-grpc");

var SECRET_TOKEN = "Bearer eyJSECRETtokenABCdef.ghi.jkl";
var SECRET_PW    = "hunter2-PLAINTEXT-PASSWORD";
var SECRET_API   = "sk_live_PLAINTEXT_APIKEY_0001";
var CONTROL_VAL  = "GET-control-value-keep-me";

function makeSpan() {
  return {
    traceId:           "0123456789abcdef0123456789abcdef",
    spanId:            "0123456789abcdef",
    parentSpanId:      "",
    name:              "GET /x",
    kind:              "server",
    startTimeUnixNano: "1700000000000000000",
    endTimeUnixNano:   "1700000000100000000",
    attributes: {
      "http.method":   CONTROL_VAL,        // non-sensitive control — must survive
      "authorization": SECRET_TOKEN,
      "password":      SECRET_PW,
      "api_key":       SECRET_API,
    },
    events: [
      { timeUnixNano: "1700000000050000000", name: "log",
        attributes: { "password": SECRET_PW } },
    ],
    status:   { code: 1, message: "" },
    resource: { "service.name": "svc" },
  };
}

async function captureBody(encoding) {
  var captured = [];
  var ex = otlp.create({
    endpoint:  "https://collector.invalid/v1/traces",
    encoding:  encoding,
    batchSize: 100,            // don't auto-flush; flush explicitly
    audit:     false,
    fetchImpl: async function (url, init) {
      captured.push(init && init.body);
      return { ok: true, status: 200, text: async function () { return ""; } };
    },
  });
  ex.queue(makeSpan());
  await ex.flush();
  await ex.shutdown();
  var body = captured[0];
  return Buffer.isBuffer(body) ? body.toString("latin1") : String(body);
}

async function run() {
  b.observability.setRedactor(null);   // default redactor active

  // The shared primitive both exporters route through — assert it directly so
  // the redaction contract is covered at the seam, not only end-to-end.
  var ra = b.observability.redactAttrs({
    "http.method": CONTROL_VAL, authorization: SECRET_TOKEN, password: SECRET_PW,
  });
  check("redactAttrs scrubs sensitive keys", ra.authorization === "[REDACTED]" && ra.password === "[REDACTED]");
  check("redactAttrs keeps non-sensitive keys", ra["http.method"] === CONTROL_VAL);

  var jsonWire = await captureBody("json");
  check("json: bearer token redacted on the OTLP wire", jsonWire.indexOf(SECRET_TOKEN) === -1);
  check("json: password redacted on the OTLP wire",     jsonWire.indexOf(SECRET_PW) === -1);
  check("json: api key redacted on the OTLP wire",      jsonWire.indexOf(SECRET_API) === -1);
  check("json: span-EVENT attribute password redacted", jsonWire.split(SECRET_PW).length === 1);
  check("json: non-sensitive control attribute survives", jsonWire.indexOf(CONTROL_VAL) !== -1);

  var protoWire = await captureBody("protobuf");
  check("protobuf: bearer token redacted on the OTLP wire", protoWire.indexOf(SECRET_TOKEN) === -1);
  check("protobuf: password redacted on the OTLP wire",     protoWire.indexOf(SECRET_PW) === -1);
  check("protobuf: api key redacted on the OTLP wire",      protoWire.indexOf(SECRET_API) === -1);
  check("protobuf: non-sensitive control attribute survives", protoWire.indexOf(CONTROL_VAL) !== -1);

  // ---- OTLP LOG sinks are EGRESS too: record-meta + resource attrs must redact ----
  // The span/metric exporters redact; the log sinks (HTTP-JSON + gRPC) shipped
  // the same attribute maps to the collector UNREDACTED — a log line carrying a
  // bearer token / password in its meta or a credential in a resource attribute
  // reached the wire verbatim (CWE-532). Drive the serialization seam of both.
  var logRec = otlpLog._toLogRecord({
    ts: 1700000000000, level: "error", message: "boom",
    meta: { "http.method": CONTROL_VAL, authorization: SECRET_TOKEN, password: SECRET_PW },
  });
  var logRecWire = JSON.stringify(logRec);
  check("otlp-log json: record-meta bearer token redacted", logRecWire.indexOf(SECRET_TOKEN) === -1);
  check("otlp-log json: record-meta password redacted",     logRecWire.indexOf(SECRET_PW) === -1);
  check("otlp-log json: non-sensitive record-meta survives", logRecWire.indexOf(CONTROL_VAL) !== -1);

  var logBatchWire = otlpLog._serializeBatch(
    [{ ts: 1700000000000, level: "info", message: "m", meta: { api_key: SECRET_API } }],
    { serviceName: "svc", resourceAttributes: { authorization: SECRET_TOKEN, region: CONTROL_VAL } },
    "1.0.0"
  ).toString("utf8");
  check("otlp-log json: resource-attr bearer token redacted", logBatchWire.indexOf(SECRET_TOKEN) === -1);
  check("otlp-log json: record-meta api key redacted",        logBatchWire.indexOf(SECRET_API) === -1);
  check("otlp-log json: non-sensitive resource attr survives", logBatchWire.indexOf(CONTROL_VAL) !== -1);

  var grpcRec = otlpLogGrpc._encodeLogRecord({
    ts: 1700000000000, level: "error", message: "boom",
    meta: { authorization: SECRET_TOKEN, password: SECRET_PW },
  }).toString("latin1");
  check("otlp-log grpc: record-meta bearer token redacted", grpcRec.indexOf(SECRET_TOKEN) === -1);
  check("otlp-log grpc: record-meta password redacted",     grpcRec.indexOf(SECRET_PW) === -1);

  var grpcReq = otlpLogGrpc._encodeExportRequest(
    [{ ts: 1700000000000, level: "info", message: "m", meta: { api_key: SECRET_API } }],
    { serviceName: "svc", resourceAttributes: { authorization: SECRET_TOKEN } }
  ).toString("latin1");
  check("otlp-log grpc: resource-attr bearer token redacted", grpcReq.indexOf(SECRET_TOKEN) === -1);
  check("otlp-log grpc: record-meta api key redacted",        grpcReq.indexOf(SECRET_API) === -1);

  b.observability.setRedactor(null);   // restore default for other tests
  process.stdout.write("OK — otlp attribute redaction tests\n");
}

run().then(function () {
  process.exit(0);
}).catch(function (e) {
  process.stderr.write((e && e.stack ? e.stack : String(e)) + "\n");
  process.exit(1);
});
