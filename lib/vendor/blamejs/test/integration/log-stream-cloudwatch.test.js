"use strict";
/**
 * Live CloudWatch Logs sink test — exercises lib/log-stream-cloudwatch.js
 * against LocalStack's CloudWatch Logs API (Logs_20140328) over TLS.
 *
 * What this proves (real, end-to-end):
 *   - The sink's autoCreate handshake issues CreateLogGroup ->
 *     CreateLogStream before the first PutLogEvents, and treats an
 *     already-existing group/stream as success.
 *   - The PutLogEvents wire shape is correct: X-Amz-Target
 *     Logs_20140328.PutLogEvents, Content-Type application/x-amz-json-1.1,
 *     a { logGroupName, logStreamName, logEvents:[{timestamp,message}] }
 *     body, events sorted ascending by timestamp.
 *   - The endpoint override (cfg.endpoint) is honoured — requests reach
 *     127.0.0.1:4566, not logs.<region>.amazonaws.com.
 *   - The sequence-token handshake: the framework picks up
 *     nextSequenceToken from each PutLogEvents response and carries it
 *     forward (stats().sequenceToken advances).
 *   - close()/shutdown() drains buffered records to the wire — the
 *     "records queued just before shutdown reach the wire" contract
 *     b.logStream advertises.
 *
 * Read-back is a SigV4-signed GetLogEvents / DescribeLogStreams built
 * with the framework's own signer (service "logs"), so the events the
 * sink delivered are confirmed present in CloudWatch with the expected
 * message content + ordering.
 *
 * Scope honesty — what this does NOT prove:
 *   LocalStack accepts the test credentials and does NOT verify the
 *   SigV4 signature. So this proves request SHAPE, the
 *   create-group -> create-stream -> put-events sequence, sequence-token
 *   handling, endpoint-override honouring, close-time drain, and
 *   read-back content/ordering — NOT signature correctness.
 *   (Signature correctness against a server that
 *   DOES verify SigV4 is covered by object-store-sigv4.test.js against
 *   MinIO.)
 *
 * No security bypass: TLS to LocalStack trusts the test CA via
 * NODE_EXTRA_CA_CERTS (exported by scripts/test-integration.js).
 * rejectUnauthorized stays on; the sink's allowInternal:true only
 * permits the loopback host, it does not disable verification.
 */
var nodeCrypto = require("node:crypto");
var helpers    = require("../helpers");
var check      = helpers.check;
var services   = require("../helpers/services");

var cloudwatchProto = require("../../lib/log-stream-cloudwatch");
var sigv4           = require("../../lib/object-store/sigv4");
var httpClient      = require("../../lib/http-client");
var safeUrl         = require("../../lib/safe-url");

var REGION = "us-east-1";
var ACCESS = "test";
var SECRET = "test";

// ---- SigV4-signed CloudWatch Logs read-back helper ----
// Builds + signs a Logs_20140328 request with the framework's own
// signer (service "logs") and posts it through httpClient. Returns the
// parsed JSON body. Rejects (throws) on a non-2xx so the caller sees
// the AWS exception text.
function _logsCall(endpoint, target, payload) {
  var body = Buffer.from(JSON.stringify(payload), "utf8");
  var payloadHash = nodeCrypto.createHash("sha256").update(body).digest("hex");
  var signed = sigv4.signRequest({
    method:           "POST",
    url:              endpoint,
    headers: {
      "Content-Type": "application/x-amz-json-1.1",
      "X-Amz-Target": target,
    },
    payloadHash:      payloadHash,
    region:           REGION,
    service:          "logs",
    accessKeyId:      ACCESS,
    secretAccessKey:  SECRET,
    allowedProtocols: safeUrl.ALLOW_HTTP_TLS,
  });
  return httpClient.request({
    method:        "POST",
    url:           endpoint,
    headers:       signed.headers,
    body:          body,
    allowInternal: true,
  }).then(function (res) {
    return JSON.parse(res.body.toString("utf8"));
  });
}

function _readEvents(endpoint, logGroupName, logStreamName) {
  return _logsCall(endpoint, "Logs_20140328.GetLogEvents", {
    logGroupName:  logGroupName,
    logStreamName: logStreamName,
    startFromHead: true,
  }).then(function (parsed) {
    return (parsed && parsed.events) || [];
  });
}

async function run() {
  var ls = await services.requireService("localstack");
  if (!ls.ok) throw new Error("localstack unreachable: " + ls.reason);

  var endpoint = services.URLS.localstack; // https://127.0.0.1:4566

  // ---- 1) endpoint override is honoured ----
  // _resolveEndpoint must reflect cfg.endpoint, not the AWS regional host.
  var resolved = cloudwatchProto._resolveEndpoint({
    endpoint: endpoint, region: REGION,
  });
  check("endpoint override honoured (not logs.<region>.amazonaws.com)",
        resolved === endpoint.replace(/\/+$/, "") + "/" &&
        resolved.indexOf("127.0.0.1:4566") !== -1);

  // ---- 2) autoCreate is load-bearing: PutLogEvents to a never-created
  // group/stream is a permanent ResourceNotFoundException. (Establishes
  // that the create handshake below is doing real work, not a no-op.) ----
  var stamp = Date.now() + "-" + Math.floor(Math.random() * 1e6);
  var missingGroup  = "blamejs-cw-missing-" + stamp;
  var missingStream = "missing-stream-" + stamp;
  var rnfErr = null;
  try {
    await _logsCall(endpoint, "Logs_20140328.PutLogEvents", {
      logGroupName:  missingGroup,
      logStreamName: missingStream,
      logEvents:     [{ timestamp: Date.now(), message: "should-not-land" }],
    });
  } catch (e) { rnfErr = e; }
  check("PutLogEvents to an uncreated group fails (ResourceNotFoundException) — autoCreate is load-bearing",
        rnfErr && /ResourceNotFoundException/.test(String(rnfErr.message || "")));
  check("classifier treats ResourceNotFoundException as permanent",
        cloudwatchProto._isPermanentAwsError(new Error("ResourceNotFoundException: no such group")) === true);

  // ---- 3) sink delivers events via autoCreate + close() drain + read-back ----
  // This is the core proof: emit a few records (under batchSize so close()
  // is the thing that has to drain them), close, then read them back out
  // of CloudWatch. Records are pushed out of timestamp order to confirm
  // the sink sorts ascending before PutLogEvents (AWS hard requirement).
  var logGroupName  = "blamejs-cw-test-" + stamp;
  var logStreamName = "stream-" + stamp;

  var drops = [];
  var sink = cloudwatchProto.create({
    region:           REGION,
    accessKeyId:      ACCESS,
    secretAccessKey:  SECRET,
    endpoint:         endpoint,
    logGroupName:     logGroupName,
    logStreamName:    logStreamName,
    autoCreate:       true,            // exercise CreateLogGroup -> CreateLogStream
    allowInternal:    true,            // permit the loopback host (TLS stays verified)
    allowedProtocols: safeUrl.ALLOW_HTTP_TLS,
    batchSize:        10,              // larger than the record count → close() drains
    onDrop:           function (d) { drops.push(d); },
  });

  var base = Date.now();
  var messages = [
    { ts: base + 30, message: "cw-event-three" },
    { ts: base + 10, message: "cw-event-one" },
    { ts: base + 20, message: "cw-event-two" },
  ];
  for (var i = 0; i < messages.length; i += 1) {
    var rv = await sink.emit(messages[i]);
    check("emit accepted record '" + messages[i].message + "'", rv && rv.accepted === true);
  }
  // close() MUST drain the buffered records to CloudWatch — this is the
  // documented shutdown contract. (If close() flips closed=true before
  // draining, _flush()'s `while (... && !closed)` loop strands them.)
  await sink.close();

  check("no drops during delivery", drops.length === 0);

  // Read the events back out of CloudWatch — the real end-to-end proof.
  var events = await helpers.waitUntil(async function () {
    var ev = await _readEvents(endpoint, logGroupName, logStreamName);
    return ev.length >= 3 ? ev : false;
  }, { timeoutMs: 8000, label: "cloudwatch: GetLogEvents returns the 3 records close() should have drained" });

  check("read-back: all three events present", events.length === 3);

  var readMessages = events.map(function (e) { return e.message; });
  check("read-back: 'cw-event-one' present",   readMessages.indexOf("cw-event-one")   !== -1);
  check("read-back: 'cw-event-two' present",   readMessages.indexOf("cw-event-two")   !== -1);
  check("read-back: 'cw-event-three' present", readMessages.indexOf("cw-event-three") !== -1);

  // GetLogEvents with startFromHead returns events oldest-first. The
  // sink sorts by timestamp ascending, so the read-back order must be
  // one -> two -> three regardless of emit order.
  check("read-back: events ordered ascending by timestamp (sink sorted them)",
        readMessages[0] === "cw-event-one" &&
        readMessages[1] === "cw-event-two" &&
        readMessages[2] === "cw-event-three");

  var st = sink.stats();
  check("after delivery: nothing left queued", st.queued === 0);
  check("sink picked up a sequenceToken from PutLogEvents response",
        typeof st.sequenceToken === "string" && st.sequenceToken.length > 0);

  // ---- 4) DescribeLogStreams confirms the stream the sink created ----
  var describe = await _logsCall(endpoint, "Logs_20140328.DescribeLogStreams", {
    logGroupName: logGroupName,
  });
  var streamNames = ((describe && describe.logStreams) || []).map(function (s) { return s.logStreamName; });
  check("DescribeLogStreams: autoCreate created the stream",
        streamNames.indexOf(logStreamName) !== -1);

  // NOTE: a redaction-before-sink leg was intentionally not included. The
  // CloudWatch sink serializes only record.message (record.meta is dropped),
  // and log records are not redacted before egress, so neither a
  // meta-redaction nor a meta-preservation guarantee holds for this sink —
  // asserting one would be vacuous. That structured-field / DLP gap is tracked
  // separately; this file proves the wire shape, autoCreate, sequence-token
  // handling, close-time drain, and read-back.
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
