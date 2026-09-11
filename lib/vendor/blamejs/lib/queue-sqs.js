// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var sigv4 = require("./object-store/sigv4");
var C = require("./constants");
var codepointClass = require("./codepoint-class");
var httpClient = require("./http-client");
var cryptoField = require("./crypto-field");
var safeJson = require("./safe-json");
var safeUrl = require("./safe-url");
var validateOpts = require("./validate-opts");
var { generateToken } = require("./crypto");
var { QueueError } = require("./framework-error");

var _err = QueueError.factory;

var DEFAULT_VISIBILITY_TIMEOUT_SEC = 30;
var DEFAULT_WAIT_TIME_SEC          = 0;
var DEFAULT_MAX_MESSAGES_PER_LEASE = 10;

function _resolveEndpoint(opts) {
  if (opts.endpoint) return codepointClass.trimTrailingChars(opts.endpoint, "/") + "/";
  return "https://sqs." + opts.region + ".amazonaws.com/";
}

function _payloadHash(buf) {
  var nodeCrypto = require("node:crypto");
  return nodeCrypto.createHash("sha256").update(buf || Buffer.alloc(0)).digest("hex");
}

function create(opts) {
  opts = opts || {};
  if (typeof opts.region !== "string" || opts.region.length === 0) {
    throw _err("queue-sqs/invalid-config", "queue-sqs: opts.region is required", true);
  }
  if (typeof opts.accessKeyId !== "string" || opts.accessKeyId.length === 0) {
    throw _err("queue-sqs/invalid-config", "queue-sqs: opts.accessKeyId is required", true);
  }
  if (typeof opts.secretAccessKey !== "string" || opts.secretAccessKey.length === 0) {
    throw _err("queue-sqs/invalid-config", "queue-sqs: opts.secretAccessKey is required", true);
  }
  if (!opts.queueUrlByName && (!opts.accountId ||
      (typeof opts.accountId !== "string" && typeof opts.accountId !== "number"))) {
    throw _err("queue-sqs/invalid-config",
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
  validateOpts.optionalPositiveInt(opts.visibilityTimeoutSec,
    "queue-sqs: visibilityTimeoutSec", QueueError, "queue-sqs/invalid-config");
  if (opts.waitTimeSec !== undefined &&
      (typeof opts.waitTimeSec !== "number" || !isFinite(opts.waitTimeSec) ||
       opts.waitTimeSec < 0 || Math.floor(opts.waitTimeSec) !== opts.waitTimeSec)) {
    throw _err("queue-sqs/invalid-config",
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
        throw _err("queue-sqs/bad-response", "queue-sqs: " + action +
          " returned non-JSON body: " + text.slice(0, 500));
      }
    });
  }

  async function enqueue(queueName, payload, enqueueOpts) {
    enqueueOpts = enqueueOpts || {};
    var queueUrl = queueUrlResolver(queueName);
    var jobId = generateToken(C.BYTES.bytes(16));
    // allow:hand-rolled-sql — cryptoField seal-table registry KEY, not SQL.
    var sealed = cryptoField.sealRow("_blamejs_jobs", {
      _id:           jobId,
      queueName:     queueName,
      payload:       JSON.stringify(payload == null ? null : payload),
      enqueuedAt:    Date.now(),
      attempts:      0,
    });
    var bodyJson = JSON.stringify(sealed);
    var sqsBody = {
      QueueUrl:    queueUrl,
      MessageBody: bodyJson,
    };
    var delaySeconds = enqueueOpts.delaySeconds;
    if (typeof delaySeconds === "number" && delaySeconds > 0) {
      sqsBody.DelaySeconds = Math.min(C.TIME.minutes(15) / C.TIME.seconds(1), Math.floor(delaySeconds));
    }
    var rv = await _post("SendMessage", sqsBody);
    return rv && (rv.MessageId || jobId);
  }

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
        receiptHandle: m.ReceiptHandle,
        sqsMessageId:  m.MessageId,
      });
    }
    return out;
  }

  async function extendLease(queueName, jobId, extendOpts) {
    extendOpts = extendOpts || {};
    if (!extendOpts.receiptHandle) {
      throw _err("queue-sqs/missing-receipt",
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

  async function complete(queueName, jobId, completeOpts) {
    completeOpts = completeOpts || {};
    if (!completeOpts.receiptHandle) {
      throw _err("queue-sqs/missing-receipt",
        "queue-sqs: complete requires opts.receiptHandle", true);
    }
    var queueUrl = queueUrlResolver(queueName);
    await _post("DeleteMessage", {
      QueueUrl:      queueUrl,
      ReceiptHandle: completeOpts.receiptHandle,
    });
    return true;
  }

  async function fail(queueName, jobId, failOpts) {
    failOpts = failOpts || {};
    if (!failOpts.receiptHandle) {
      throw _err("queue-sqs/missing-receipt",
        "queue-sqs: fail requires opts.receiptHandle", true);
    }
    var queueUrl = queueUrlResolver(queueName);
    await _post("ChangeMessageVisibility", {
      QueueUrl:          queueUrl,
      ReceiptHandle:     failOpts.receiptHandle,
      VisibilityTimeout: 0,
    });
    return true;
  }

  async function size(queueName) {
    var queueUrl = queueUrlResolver(queueName);
    var rv = await _post("GetQueueAttributes", {
      QueueUrl:        queueUrl,
      AttributeNames:  ["ApproximateNumberOfMessages"],
    });
    var attrs = (rv && rv.Attributes) || {};
    return Number(attrs.ApproximateNumberOfMessages) || 0;
  }

  async function purge(queueName) {
    var queueUrl = queueUrlResolver(queueName);
    await _post("PurgeQueue", { QueueUrl: queueUrl });
    return 0;
  }

  return {
    enqueue:       enqueue,
    lease:         lease,
    extendLease:   extendLease,
    complete:      complete,
    fail:          fail,
    size:          size,
    purge:         purge,
    _post:         _post,
    _queueUrl:     queueUrlResolver,
  };
}

module.exports = { create: create };
