"use strict";
/**
 * AWS SQS queue adapter — backs `b.queue` with Amazon SQS so multi-replica
 * apps share a managed queue without each needing to be cluster leader.
 *
 * Wire protocol — AWSJsonProtocol_1.0 over HTTPS, SigV4-signed via
 * `lib/object-store/sigv4.js`'s service-agnostic `signRequest` helper:
 *
 *   POST https://sqs.{region}.amazonaws.com/
 *   Content-Type: application/x-amz-json-1.0
 *   X-Amz-Target: AmazonSQS.<Action>
 *   Authorization: AWS4-HMAC-SHA256 ...
 *
 *   Action          → SQS API
 *   enqueue         → SendMessage
 *   lease           → ReceiveMessage (long-poll up to WaitTimeSeconds)
 *   extendLease     → ChangeMessageVisibility
 *   complete        → DeleteMessage
 *   fail            → ChangeMessageVisibility (VisibilityTimeout=0 → re-deliver
 *                     immediately) — DLQ routing happens server-side via the
 *                     queue's RedrivePolicy attribute, configured at queue
 *                     creation time outside the framework
 *   size            → GetQueueAttributes(ApproximateNumberOfMessages)
 *   purge           → PurgeQueue
 *
 * Queue-name → URL: SQS queues live at
 *   https://sqs.{region}.amazonaws.com/{accountId}/{queueName}
 * Operators pass `accountId` + `region` and the adapter constructs URLs
 * from the framework's logical queue names. Operators with cross-account
 * queues / FIFO queues / VPCE endpoints pass an explicit
 * `queueUrlByName(name) → url` resolver instead.
 *
 * What this adapter does NOT support (operator wiring required):
 *
 *   - DLQ inspection (dlqList / dlqRetry / dlqSize) — SQS DLQs are
 *     separate queues; operators using one wire it as a second framework
 *     backend and inspect via that backend's `lease()`.
 *   - Flow / cron / parent-child dependencies — SQS has no native flow
 *     primitives; those stay on queue-local or queue-redis.
 *   - sweepExpired — SQS handles visibility-timeout expiry server-side.
 *
 * Sealing: payloads pass through `cryptoField.sealRow("_blamejs_jobs",
 * row)` before SendMessage so the SQS message body is a sealed envelope
 * (operator's vault-key + framework crypto stack), same posture as the
 * local + redis backends.
 */
var sigv4 = require("./object-store/sigv4");
var C = require("./constants");
var httpClient = require("./http-client");
var cryptoField = require("./crypto-field");
var safeJson = require("./safe-json");
var safeUrl = require("./safe-url");
var validateOpts = require("./validate-opts");
var { generateToken } = require("./crypto");
var { QueueError } = require("./framework-error");

var _err = QueueError.factory;

var DEFAULT_VISIBILITY_TIMEOUT_SEC = 30;
var DEFAULT_WAIT_TIME_SEC          = 0;       // SQS supports up to 20s
var DEFAULT_MAX_MESSAGES_PER_LEASE = 10;       // SQS hard cap

function _resolveEndpoint(opts) {
  if (opts.endpoint) return opts.endpoint.replace(/\/+$/, "") + "/";
  return "https://sqs." + opts.region + ".amazonaws.com/";
}

function _payloadHash(buf) {
  // Empty body's payload hash is the SHA256 of the empty string —
  // sigv4 requires the actual hash, not "UNSIGNED-PAYLOAD".
  var nodeCrypto = require("node:crypto");
  return nodeCrypto.createHash("sha256").update(buf || Buffer.alloc(0)).digest("hex");
}

function create(opts) {
  opts = opts || {};
  if (typeof opts.region !== "string" || opts.region.length === 0) {
    throw _err("INVALID_CONFIG", "queue-sqs: opts.region is required", true);
  }
  if (typeof opts.accessKeyId !== "string" || opts.accessKeyId.length === 0) {
    throw _err("INVALID_CONFIG", "queue-sqs: opts.accessKeyId is required", true);
  }
  if (typeof opts.secretAccessKey !== "string" || opts.secretAccessKey.length === 0) {
    throw _err("INVALID_CONFIG", "queue-sqs: opts.secretAccessKey is required", true);
  }
  if (!opts.queueUrlByName && (!opts.accountId ||
      (typeof opts.accountId !== "string" && typeof opts.accountId !== "number"))) {
    throw _err("INVALID_CONFIG",
      "queue-sqs: opts.accountId is required (12-digit AWS account ID) " +
      "or pass opts.queueUrlByName(name) → url for cross-account / VPCE queues", true);
  }

  var region          = opts.region;
  var endpoint        = _resolveEndpoint(opts);
  var allowedProtocols = opts.allowedProtocols || safeUrl.ALLOW_HTTP_TLS;
  var endpointUrl     = safeUrl.parse(endpoint, {
    errorClass:       QueueError,
    allowedProtocols: allowedProtocols,
  });
  var accessKeyId     = opts.accessKeyId;
  var secretAccessKey = opts.secretAccessKey;
  var sessionToken    = opts.sessionToken || null;
  var accountId       = opts.accountId ? String(opts.accountId) : null;
  var timeoutMs       = opts.timeoutMs;
  var allowInternal   = opts.allowInternal != null ? opts.allowInternal : null;
  // Config-time: a typo (NaN-coercing string / negative / fractional)
  // must surface at create, not silently fall back to the default and ship
  // a mis-tuned lease loop. THROW on present-but-bad; absent keeps default.
  validateOpts.optionalPositiveInt(opts.visibilityTimeoutSec,
    "queue-sqs: visibilityTimeoutSec", QueueError, "INVALID_CONFIG");
  // waitTimeSec=0 is the valid SQS short-poll sentinel (the default), so a
  // positive-int check would wrongly reject it — allow non-negative integers.
  if (opts.waitTimeSec !== undefined &&
      (typeof opts.waitTimeSec !== "number" || !isFinite(opts.waitTimeSec) ||
       opts.waitTimeSec < 0 || Math.floor(opts.waitTimeSec) !== opts.waitTimeSec)) {
    throw _err("INVALID_CONFIG",
      "queue-sqs: waitTimeSec must be a non-negative integer (0 = short-poll), got " +
      (typeof opts.waitTimeSec === "number" ? String(opts.waitTimeSec) : typeof opts.waitTimeSec),
      true);
  }
  var visibilityTimeoutSec = opts.visibilityTimeoutSec !== undefined
    ? opts.visibilityTimeoutSec : DEFAULT_VISIBILITY_TIMEOUT_SEC;
  var waitTimeSec = opts.waitTimeSec !== undefined
    ? opts.waitTimeSec : DEFAULT_WAIT_TIME_SEC;

  var queueUrlResolver = typeof opts.queueUrlByName === "function"
    ? opts.queueUrlByName
    : function (name) {
        return endpoint + accountId + "/" + name;
      };

  function _post(action, body) {
    var bodyBuf = Buffer.from(JSON.stringify(body || {}), "utf8");
    var headers = {
      "Content-Type":  "application/x-amz-json-1.0",
      "X-Amz-Target":  "AmazonSQS." + action,
      "Content-Length": String(bodyBuf.length),
    };
    var signed = sigv4.signRequest({
      method:           "POST",
      url:              endpointUrl,
      headers:          headers,
      payloadHash:      _payloadHash(bodyBuf),
      region:           region,
      service:          "sqs",
      accessKeyId:      accessKeyId,
      secretAccessKey:  secretAccessKey,
      sessionToken:     sessionToken,
      allowedProtocols: allowedProtocols,
    });
    var reqOpts = {
      method:           "POST",
      url:              endpointUrl,
      headers:          signed.headers,
      body:             bodyBuf,
      timeoutMs:        timeoutMs,
      idleTimeoutMs:    timeoutMs,
      allowedProtocols: allowedProtocols,
      errorClass:       QueueError,
    };
    if (allowInternal !== null) reqOpts.allowInternal = allowInternal;
    return httpClient.request(reqOpts).then(function (res) {
      var text = Buffer.isBuffer(res.body) ? res.body.toString("utf8")
              : (res.body || "").toString();
      if (text.length === 0) return null;
      try { return safeJson.parse(text); }
      catch (_e) {
        throw _err("BAD_RESPONSE", "queue-sqs: " + action +
          " returned non-JSON body: " + text.slice(0, 500));
      }
    });
  }

  // ---- enqueue ----
  async function enqueue(queueName, payload, enqueueOpts) {
    enqueueOpts = enqueueOpts || {};
    var queueUrl = queueUrlResolver(queueName);
    var jobId = generateToken(C.BYTES.bytes(16));
    // The cryptoField seal-table registry KEY (matches db.js's registerTable
    // literal), not a SQL table name; this SQS adapter holds no SQL
    // (AWSJsonProtocol over HTTPS). Keep it byte-identical so the sealed
    // message body unseals under the same schema on receive.
    // allow:hand-rolled-sql — cryptoField seal-table registry KEY, not SQL.
    var sealed = cryptoField.sealRow("_blamejs_jobs", {
      _id:           jobId,
      queueName:     queueName,
      payload:       JSON.stringify(payload == null ? null : payload),
      enqueuedAt:    Date.now(),
      attempts:      0,
    });
    // SQS message body: serialize the sealed row as JSON. Receive
    // replays the same shape — sealed.payload stays sealed in transit.
    var bodyJson = JSON.stringify(sealed);
    var sqsBody = {
      QueueUrl:    queueUrl,
      MessageBody: bodyJson,
    };
    var delaySeconds = enqueueOpts.delaySeconds;
    if (typeof delaySeconds === "number" && delaySeconds > 0) {
      // SQS hard cap is 900s (15 min).
      sqsBody.DelaySeconds = Math.min(C.TIME.minutes(15) / C.TIME.seconds(1), Math.floor(delaySeconds));
    }
    var rv = await _post("SendMessage", sqsBody);
    return rv && (rv.MessageId || jobId);
  }

  // ---- lease ----
  async function lease(queueName, leaseOpts) {
    leaseOpts = leaseOpts || {};
    var queueUrl = queueUrlResolver(queueName);
    var maxMessages = Math.min(
      DEFAULT_MAX_MESSAGES_PER_LEASE,
      Math.max(1, Number(leaseOpts.maxRows) || 1)
    );
    var visTimeout = Number(leaseOpts.visibilityTimeoutSec) || visibilityTimeoutSec;
    var waitSec    = Number(leaseOpts.waitTimeSec) ||
                     (waitTimeSec > 0 ? waitTimeSec : DEFAULT_WAIT_TIME_SEC);
    var rv = await _post("ReceiveMessage", {
      QueueUrl:               queueUrl,
      MaxNumberOfMessages:    maxMessages,
      VisibilityTimeout:      visTimeout,
      WaitTimeSeconds:        waitSec,
    });
    var messages = (rv && rv.Messages) || [];
    var out = [];
    for (var i = 0; i < messages.length; i++) {
      var m = messages[i];
      var sealed;
      try { sealed = safeJson.parse(m.Body); }
      catch (_e) { continue; }
      // allow:hand-rolled-sql — cryptoField seal-table registry KEY, not SQL.
      var unsealed = cryptoField.unsealRow("_blamejs_jobs", sealed);
      var payload;
      try {
        payload = unsealed.payload != null
          ? safeJson.parse(unsealed.payload, { maxBytes: C.BYTES.mib(64) }) : null;
      } catch (_e) { payload = unsealed.payload; }
      out.push({
        jobId:         unsealed._id,
        queueName:     unsealed.queueName || queueName,
        payload:       payload,
        attempts:      Number(unsealed.attempts) || 0,
        enqueuedAt:    Number(unsealed.enqueuedAt) || null,
        leaseExpiresAt: Date.now() + C.TIME.seconds(visTimeout),
        // SQS-specific: receipt handle is the only way to delete /
        // change visibility / extend — surface it for the framework
        // wrapper.
        receiptHandle: m.ReceiptHandle,
        sqsMessageId:  m.MessageId,
      });
    }
    return out;
  }

  // ---- extendLease ----
  async function extendLease(queueName, jobId, extendOpts) {
    extendOpts = extendOpts || {};
    if (!extendOpts.receiptHandle) {
      throw _err("MISSING_RECEIPT",
        "queue-sqs: extendLease requires opts.receiptHandle (returned by lease())", true);
    }
    var queueUrl = queueUrlResolver(queueName);
    var visTimeout = Number(extendOpts.visibilityTimeoutSec) || visibilityTimeoutSec;
    await _post("ChangeMessageVisibility", {
      QueueUrl:          queueUrl,
      ReceiptHandle:     extendOpts.receiptHandle,
      VisibilityTimeout: visTimeout,
    });
    return true;
  }

  // ---- complete ----
  async function complete(queueName, jobId, completeOpts) {
    completeOpts = completeOpts || {};
    if (!completeOpts.receiptHandle) {
      throw _err("MISSING_RECEIPT",
        "queue-sqs: complete requires opts.receiptHandle", true);
    }
    var queueUrl = queueUrlResolver(queueName);
    await _post("DeleteMessage", {
      QueueUrl:      queueUrl,
      ReceiptHandle: completeOpts.receiptHandle,
    });
    return true;
  }

  // ---- fail (request re-delivery; SQS server-side DLQ routing decides
  //          if it goes back to the main queue or to the DLQ) ----
  async function fail(queueName, jobId, failOpts) {
    failOpts = failOpts || {};
    if (!failOpts.receiptHandle) {
      throw _err("MISSING_RECEIPT",
        "queue-sqs: fail requires opts.receiptHandle", true);
    }
    var queueUrl = queueUrlResolver(queueName);
    // VisibilityTimeout=0 → message becomes visible to other consumers
    // immediately. SQS's RedrivePolicy on the queue (configured at
    // queue creation) tracks ApproximateReceiveCount and routes to
    // the DLQ once maxReceiveCount is exceeded.
    await _post("ChangeMessageVisibility", {
      QueueUrl:          queueUrl,
      ReceiptHandle:     failOpts.receiptHandle,
      VisibilityTimeout: 0,
    });
    return true;
  }

  // ---- size (visible messages only — in-flight and delayed are
  //           reported separately by GetQueueAttributes) ----
  async function size(queueName) {
    var queueUrl = queueUrlResolver(queueName);
    var rv = await _post("GetQueueAttributes", {
      QueueUrl:        queueUrl,
      AttributeNames:  ["ApproximateNumberOfMessages"],
    });
    var attrs = (rv && rv.Attributes) || {};
    return Number(attrs.ApproximateNumberOfMessages) || 0;
  }

  // ---- purge (60s server-side rate-limited; SQS rejects a second
  //            purge within the cooldown window) ----
  async function purge(queueName) {
    var queueUrl = queueUrlResolver(queueName);
    await _post("PurgeQueue", { QueueUrl: queueUrl });
    return 0;   // SQS doesn't return a count
  }

  return {
    enqueue:       enqueue,
    lease:         lease,
    extendLease:   extendLease,
    complete:      complete,
    fail:          fail,
    size:          size,
    purge:         purge,
    // Test hook — exposes the signed-request builder for assertion-
    // only verification of wire shape without standing up a mock SQS
    // server.
    _post:         _post,
    _queueUrl:     queueUrlResolver,
  };
}

module.exports = { create: create };
