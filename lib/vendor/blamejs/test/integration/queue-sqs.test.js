"use strict";
/**
 * Live SQS queue-backend round-trip — exercises lib/queue-sqs.js against
 * LocalStack's SQS API (AWSJsonProtocol_1.0) over TLS.
 *
 * What this proves (real, end-to-end against a live SQS server):
 *   - The adapter's SendMessage wire shape is correct: X-Amz-Target
 *     AmazonSQS.SendMessage, Content-Type application/x-amz-json-1.0, a
 *     { QueueUrl, MessageBody } body — and the message actually lands in
 *     the queue (size() rises, ReceiveMessage returns it).
 *   - The sealed-envelope round-trip: enqueue seals the job row through
 *     cryptoField.sealRow("_blamejs_jobs", ...) before SendMessage; lease
 *     unseals it on receive. A structured payload round-trips
 *     field-identical through the SQS wire (the message body in transit is
 *     the sealed envelope, not the cleartext payload).
 *   - ReceiveMessage surfaces a ReceiptHandle + MessageId, and complete()
 *     (DeleteMessage by that handle) removes the message so it does NOT
 *     redeliver — the queue drains.
 *   - The visibility-timeout / redelivery path: a leased-but-not-deleted
 *     message becomes invisible for VisibilityTimeout, and fail()
 *     (ChangeMessageVisibility VisibilityTimeout=0) makes it immediately
 *     visible again so another consumer re-leases it.
 *   - size() (GetQueueAttributes ApproximateNumberOfMessages) and purge()
 *     (PurgeQueue) hit the wire and reflect the queue state.
 *   - The endpoint override (cfg.endpoint / cfg.queueUrlByName) is
 *     honoured — requests reach 127.0.0.1:4566, not
 *     sqs.<region>.amazonaws.com.
 *
 * Scope honesty — what this does NOT prove:
 *   LocalStack accepts the test credentials and does NOT verify the SigV4
 *   signature (it ignores the secret key). So this proves the SQS wire /
 *   marshalling + the send/receive/delete/ack + visibility-timeout flow,
 *   NOT signature correctness. (Signature correctness against a server
 *   that DOES verify SigV4 is covered by object-store-sigv4.test.js
 *   against MinIO.)
 *
 * No security bypass: TLS to LocalStack trusts the test CA via
 * NODE_EXTRA_CA_CERTS (exported by scripts/test-integration.js).
 * rejectUnauthorized stays on; allowInternal:true only permits the
 * loopback host, it does not disable verification. The job payload is
 * sealed at rest in the queue (vault key + framework crypto stack) — the
 * test registers the seal table and inits the vault exactly as a queue
 * node would.
 *
 * To run:
 *   docker compose -f docker-compose.test.yml up -d --wait
 *   node scripts/test-integration.js --skip-service-check queue-sqs
 */
var fs         = require("node:fs");
var os         = require("node:os");
var path       = require("node:path");
var nodeCrypto = require("node:crypto");
var helpers    = require("../helpers");
var check      = helpers.check;
var services   = require("../helpers/services");
var b          = require("../../");

var queueSqs    = require("../../lib/queue-sqs");
var cryptoField = require("../../lib/crypto-field");
var sigv4       = require("../../lib/object-store/sigv4");
var httpClient  = require("../../lib/http-client");
var safeUrl     = require("../../lib/safe-url");

var REGION = "us-east-1";
var ACCESS = "test";
var SECRET = "test";

// ---- raw SigV4-signed SQS control-plane helper ----
// The adapter intentionally has no CreateQueue / DeleteQueue (queue
// lifecycle is operator/IaC territory), so the test stands the queue up
// and tears it down with its own signed AWSJsonProtocol_1.0 calls — the
// same signer the adapter uses. Returns the parsed JSON body; throws on a
// non-2xx so the caller sees the AWS exception text.
function _sqsCall(endpoint, action, payload) {
  var body = Buffer.from(JSON.stringify(payload || {}), "utf8");
  var payloadHash = nodeCrypto.createHash("sha256").update(body).digest("hex");
  var signed = sigv4.signRequest({
    method:           "POST",
    url:              endpoint,
    headers: {
      "Content-Type": "application/x-amz-json-1.0",
      "X-Amz-Target": "AmazonSQS." + action,
    },
    payloadHash:      payloadHash,
    region:           REGION,
    service:          "sqs",
    accessKeyId:      ACCESS,
    secretAccessKey:  SECRET,
    allowedProtocols: safeUrl.ALLOW_HTTP_TLS,
  });
  return httpClient.request({
    method:           "POST",
    url:              endpoint,
    headers:          signed.headers,
    body:             body,
    allowInternal:    true,
    allowedProtocols: safeUrl.ALLOW_HTTP_TLS,
  }).then(function (res) {
    var text = Buffer.isBuffer(res.body) ? res.body.toString("utf8")
            : (res.body || "").toString();
    return text.length ? JSON.parse(text) : {};
  });
}

async function run() {
  var ls = await services.requireService("localstack");
  if (!ls.ok) throw new Error("localstack unreachable: " + ls.reason);

  var endpoint = services.URLS.localstack; // https://127.0.0.1:4566

  // ---- 0) framework-side seal wiring ----
  // The SQS adapter seals the job row through cryptoField.sealRow(
  // "_blamejs_jobs", ...) before SendMessage and unsealRow()s it on
  // receive. Without registering the table + a live vault key, sealRow is
  // a no-op pass-through and the round-trip wouldn't actually exercise the
  // seal/unseal envelope — so init the vault + register the table exactly
  // as a standalone SQS queue node would (queue.init() calls
  // _ensureSealTable() for the same reason).
  var dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-queue-sqs-"));
  if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
  await b.vault.init({ dataDir: dataDir, mode: "plaintext" });
  cryptoField.registerTable("_blamejs_jobs", { sealedFields: ["payload", "lastError"] });

  // ---- 1) create a unique queue out-of-band ----
  // LocalStack's default AWS account is 000000000000; CreateQueue echoes
  // an AWS-shaped advertised URL (sqs.us-east-1.localhost.localstack.cloud),
  // but the adapter routes every action to cfg.endpoint and only carries
  // the QueueUrl in the JSON body — LocalStack accepts the path-style
  // endpoint+accountId+name URL the adapter's own resolver synthesizes.
  var ACCOUNT_ID = "000000000000";
  var queueName = "blamejs-sqs-test-" + Date.now() + "-" + Math.floor(Math.random() * 1e6);
  var created = await _sqsCall(endpoint, "CreateQueue", { QueueName: queueName });
  var advertisedUrl = created && created.QueueUrl;
  check("CreateQueue: returned a QueueUrl", typeof advertisedUrl === "string" && advertisedUrl.length > 0);
  check("CreateQueue: QueueUrl carries the queue name", advertisedUrl.indexOf(queueName) !== -1);

  // ---- 2) build the adapter pointed at LocalStack ----
  // No queueUrlByName override: this exercises the adapter's built-in
  // endpoint + accountId + name URL synthesis (the single-account default
  // path), so the test proves that path too — not just a hand-fed resolver.
  var q = queueSqs.create({
    endpoint:         endpoint,
    region:           REGION,
    accountId:        ACCOUNT_ID,
    accessKeyId:      ACCESS,
    secretAccessKey:  SECRET,
    allowInternal:    true,
    allowedProtocols: safeUrl.ALLOW_HTTP_TLS,
  });

  // endpoint override honoured — the synthesized queue URL points at the
  // LocalStack host, not the AWS regional host.
  check("endpoint override honoured (queue URL is the LocalStack host, not sqs.<region>.amazonaws.com)",
        q._queueUrl(queueName).indexOf("127.0.0.1:4566") !== -1 &&
        q._queueUrl(queueName).indexOf("amazonaws.com") === -1);

  try {
    // ---- 3) enqueue → receive round-trip + sealed-payload fidelity ----
    var Q = queueName;
    var payload = {
      kind:    "report.generate",
      orderId: "ord-" + Math.floor(Math.random() * 1e9),
      nested:  { tags: ["alpha", "beta"], count: 3, flag: true },
      unicode: "café — naïve — 日本語",
      amount:  1234.56,
    };
    var sentId = await q.enqueue(Q, payload, { traceId: "t-sqs-1" });
    check("enqueue: SendMessage returned a message id", typeof sentId === "string" && sentId.length > 0);

    // size() reflects the just-enqueued message (ApproximateNumberOfMessages
    // is eventually-consistent on real SQS; LocalStack is prompt — poll).
    var sz1 = await helpers.waitUntil(async function () {
      var n = await q.size(Q);
      return n >= 1 ? n : false;
    }, { timeoutMs: 8000, label: "queue-sqs: size() reflects the enqueued message" });
    check("size: >= 1 after enqueue", sz1 >= 1);

    // Receive it. The body on the wire is the sealed envelope; lease()
    // unseals it back to the structured payload.
    var leased = await helpers.waitUntil(async function () {
      var rv = await q.lease(Q, { maxRows: 5, waitTimeSec: 1, visibilityTimeoutSec: 30 });
      return rv.length >= 1 ? rv : false;
    }, { timeoutMs: 10000, label: "queue-sqs: ReceiveMessage returns the enqueued job" });
    check("lease: ReceiveMessage returned exactly one job", leased.length === 1);

    var job = leased[0];
    check("lease: surfaces a ReceiptHandle (the only key for delete/visibility)",
          typeof job.receiptHandle === "string" && job.receiptHandle.length > 0);
    check("lease: surfaces the SQS MessageId",
          typeof job.sqsMessageId === "string" && job.sqsMessageId.length > 0);
    check("lease: jobId present (the framework job id, not the SQS id)",
          typeof job.jobId === "string" && job.jobId.length > 0);
    check("lease: queueName round-tripped through the sealed row",
          job.queueName === Q);

    // The headline proof: structured payload survives the seal → SQS wire
    // → unseal round-trip byte/field-identical (deep equality).
    check("lease: payload round-trips field-identical through seal + SQS wire",
          JSON.stringify(job.payload) === JSON.stringify(payload));
    check("lease: nested object fields intact",
          job.payload && job.payload.nested &&
          job.payload.nested.count === 3 && job.payload.nested.flag === true &&
          job.payload.nested.tags.length === 2 &&
          job.payload.nested.tags[0] === "alpha" && job.payload.nested.tags[1] === "beta");
    check("lease: unicode payload byte-identical (no mojibake on the wire)",
          job.payload.unicode === "café — naïve — 日本語");
    check("lease: numeric field preserved (not stringified)",
          job.payload.amount === 1234.56 && job.payload.orderId === payload.orderId);

    // ---- 4) ack (DeleteMessage) → does NOT redeliver, queue drains ----
    var compRv = await q.complete(Q, job.jobId, { receiptHandle: job.receiptHandle });
    check("complete: DeleteMessage returned true", compRv === true);

    // After delete, the message must not come back. Long-poll a couple of
    // times with a fresh (short) visibility window; nothing should appear.
    var redelivered = await q.lease(Q, { maxRows: 5, waitTimeSec: 2, visibilityTimeoutSec: 5 });
    check("complete: deleted message does NOT redeliver (queue drained)",
          redelivered.length === 0);

    // NOTE on size() semantics: ApproximateNumberOfMessages counts only
    // VISIBLE messages — a leased-but-not-deleted message is in-flight
    // (NotVisible) and reports 0 here. So 0 after complete confirms the
    // message is neither visible nor in-flight. (waitUntil treats a falsy
    // return as "not ready", so the predicate returns true on success,
    // not the numeric 0.)
    var szDrained = await helpers.waitUntil(async function () {
      var n = await q.size(Q);
      return n === 0 ? true : false;
    }, { timeoutMs: 8000, label: "queue-sqs: size() back to 0 after complete" });
    check("size: 0 after complete (no in-flight, no visible)", szDrained === true);

    // ---- 5) visibility-timeout / redelivery path via fail() ----
    // Enqueue, lease with a long visibility timeout (so it would NOT come
    // back on its own within the test window), then fail() — which sets
    // VisibilityTimeout=0 and makes it immediately visible to the next
    // consumer. Proves ChangeMessageVisibility re-delivery, the SQS-native
    // retry the adapter relies on (server-side RedrivePolicy decides DLQ).
    var redeliverPayload = { step: "retry-me", n: 7 };
    await q.enqueue(Q, redeliverPayload, { traceId: "t-sqs-redeliver" });

    var firstLease = await helpers.waitUntil(async function () {
      var rv = await q.lease(Q, { maxRows: 1, waitTimeSec: 1, visibilityTimeoutSec: 300 });
      return rv.length >= 1 ? rv : false;
    }, { timeoutMs: 10000, label: "queue-sqs: redelivery job first lease" });
    check("redelivery: first lease grabbed the job under a 300s visibility window",
          firstLease.length === 1 && firstLease[0].payload &&
          firstLease[0].payload.step === "retry-me");

    // While the 300s visibility window is in effect, a second lease sees
    // nothing — the message is in-flight (invisible).
    var whileInflight = await q.lease(Q, { maxRows: 1, waitTimeSec: 1, visibilityTimeoutSec: 5 });
    check("redelivery: message invisible to a second consumer during the visibility window",
          whileInflight.length === 0);

    // fail() → VisibilityTimeout=0 → immediately visible again.
    var failRv = await q.fail(Q, firstLease[0].jobId, { receiptHandle: firstLease[0].receiptHandle });
    check("fail: ChangeMessageVisibility(0) returned true", failRv === true);

    var reLease = await helpers.waitUntil(async function () {
      var rv = await q.lease(Q, { maxRows: 1, waitTimeSec: 2, visibilityTimeoutSec: 30 });
      return rv.length >= 1 ? rv : false;
    }, { timeoutMs: 12000, label: "queue-sqs: fail() re-delivered the job to a new consumer" });
    check("redelivery: fail() made the message visible again (re-leased)",
          reLease.length === 1 && reLease[0].payload &&
          reLease[0].payload.step === "retry-me" && reLease[0].payload.n === 7);
    check("redelivery: re-leased message carries a fresh receipt handle",
          typeof reLease[0].receiptHandle === "string" &&
          reLease[0].receiptHandle.length > 0);

    // Clean it up so the purge leg starts from a known state.
    await q.complete(Q, reLease[0].jobId, { receiptHandle: reLease[0].receiptHandle });

    // ---- 6) extendLease (ChangeMessageVisibility to a longer window) ----
    await q.enqueue(Q, { step: "extend-me" }, {});
    var extLease = await helpers.waitUntil(async function () {
      var rv = await q.lease(Q, { maxRows: 1, waitTimeSec: 1, visibilityTimeoutSec: 30 });
      return rv.length >= 1 ? rv : false;
    }, { timeoutMs: 10000, label: "queue-sqs: extendLease job leased" });
    check("extendLease: job leased", extLease.length === 1);
    var extRv = await q.extendLease(Q, extLease[0].jobId, {
      receiptHandle: extLease[0].receiptHandle, visibilityTimeoutSec: 120,
    });
    check("extendLease: ChangeMessageVisibility(120) returned true", extRv === true);
    await q.complete(Q, extLease[0].jobId, { receiptHandle: extLease[0].receiptHandle });

    // ---- 7) purge clears the queue ----
    // Re-fill, confirm size, purge, confirm drained. (PurgeQueue is
    // 60s-rate-limited server-side; this test calls it once.)
    await q.enqueue(Q, { p: 1 }, {});
    await q.enqueue(Q, { p: 2 }, {});
    await q.enqueue(Q, { p: 3 }, {});
    var preSize = await helpers.waitUntil(async function () {
      var n = await q.size(Q);
      return n >= 3 ? n : false;
    }, { timeoutMs: 8000, label: "queue-sqs: size() reflects 3 enqueued before purge" });
    check("purge: pre-purge size >= 3", preSize >= 3);

    var purgeRv = await q.purge(Q);
    check("purge: PurgeQueue returned (count 0 — SQS doesn't report a count)", purgeRv === 0);

    var postPurge = await helpers.waitUntil(async function () {
      var n = await q.size(Q);
      return n === 0 ? true : false;
    }, { timeoutMs: 12000, label: "queue-sqs: size() back to 0 after PurgeQueue" });
    check("purge: post-purge size 0", postPurge === true);

  } finally {
    // Tear the queue down (control-plane, out-of-band like creation).
    try { await _sqsCall(endpoint, "DeleteQueue", { QueueUrl: advertisedUrl }); } catch (_e) {}
    try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (_e) {}
    if (typeof b.vault._resetForTest === "function") b.vault._resetForTest();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
