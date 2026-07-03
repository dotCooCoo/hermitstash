// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * AWS CloudWatch Logs sink — PutLogEvents over HTTPS with SigV4.
 *
 * Operator config:
 *
 *   {
 *     region:           "us-east-1"
 *     accessKeyId:      env("AWS_ACCESS_KEY_ID")
 *     secretAccessKey:  env("AWS_SECRET_ACCESS_KEY")
 *     sessionToken:     env("AWS_SESSION_TOKEN")    // optional, STS creds
 *     logGroupName:     "my-app-logs"               // operator pre-creates
 *     logStreamName:    "instance-1"                // operator pre-creates
 *     endpoint:         "https://logs.us-east-1.amazonaws.com"   // optional
 *     batchSize:        100                          // CW caps at 10K events / 1 MiB per call
 *     maxBatchAgeMs:    C.TIME.seconds(5)
 *     timeoutMs:        C.TIME.seconds(30)
 *     retry:            { maxAttempts, baseDelayMs, ... }
 *     bufferLimit:      10000
 *     onDrop:           function ({ reason, batch, error }) { ... }
 *   }
 *
 * Wire format (Logs_20140328 PutLogEvents — JSON-1.1 over HTTPS):
 *
 *   POST /
 *   X-Amz-Target: Logs_20140328.PutLogEvents
 *   Content-Type: application/x-amz-json-1.1
 *   Authorization: AWS4-HMAC-SHA256 Credential=... SignedHeaders=... Signature=...
 *   Body: { logGroupName, logStreamName, logEvents: [{ timestamp, message }, ...] }
 *
 * AWS quirks the framework handles:
 *   - Events MUST be sorted by timestamp ascending — sink sorts before send.
 *   - Per-batch caps: 10,000 events AND <= 1 MiB total payload. Operator
 *     batchSize is enforced; the framework also splits batches when the
 *     1 MiB ceiling is reached mid-build.
 *   - Per-event 256 KiB hard cap. Oversized events are dropped at emit-time
 *     with onDrop fired.
 *   - sequenceToken is optional in modern CloudWatch (post-2023). If a
 *     legacy account requires it, CloudWatch returns
 *     InvalidSequenceTokenException with the expected token; the
 *     framework retries with that token transparently.
 *   - ResourceNotFoundException -> permanent error (operator forgot to
 *     create the log group or stream); surfaced via onDrop with a
 *     clear error.
 *
 * SigV4 signing reuses lib/object-store/sigv4.js with service: "logs".
 */
var C = require("./constants");
var nodeCrypto = require("node:crypto");
var safeAsync = require("./safe-async");
var safeJson = require("./safe-json");
var sigv4 = require("./object-store/sigv4");
var retryHelper = require("./retry");
var { LogStreamError } = require("./framework-error");
var httpClient = require("./http-client");

var MAX_RESPONSE_BYTES = C.BYTES.mib(1);
// AWS PutLogEvents hard limit: 10K events per batch (Logs_20140328 docs).
var CW_MAX_EVENTS_PER_BATCH = C.BYTES.bytes(10000);
var CW_MAX_BATCH_BYTES      = C.BYTES.mib(1);
var CW_MAX_EVENT_BYTES      = C.BYTES.kib(256);
var CW_EVENT_OVERHEAD_BYTES = C.BYTES.bytes(26);
// Truncated-message preview embedded in onDrop callbacks for oversize
// events — short enough to fit in a single log line so operators can
// spot the producer that emitted the over-cap record.
var DROP_PREVIEW_BYTES = C.BYTES.bytes(200);

var DEFAULTS = {
  batchSize:     100,
  maxBatchAgeMs: C.TIME.seconds(5),
  timeoutMs:     C.TIME.seconds(30),
  // Ring-buffer cap (event count, not bytes); routed through C.BYTES
  // identity passthrough so the file's literal arithmetic has a single
  // source of truth.
  bufferLimit:   C.BYTES.bytes(10000),
};

var _err = LogStreamError.factory;

function _resolveEndpoint(cfg) {
  if (cfg.endpoint) return cfg.endpoint.replace(/\/+$/, "") + "/";
  return "https://logs." + cfg.region + ".amazonaws.com/";
}

function _eventByteSize(message) {
  return Buffer.byteLength(message, "utf8") + CW_EVENT_OVERHEAD_BYTES;
}

function _serializeBatch(events, cfg, sequenceToken) {
  events.sort(function (a, b) { return a.timestamp - b.timestamp; });
  var body = {
    logGroupName:  cfg.logGroupName,
    logStreamName: cfg.logStreamName,
    logEvents:     events,
  };
  if (sequenceToken) body.sequenceToken = sequenceToken;
  return Buffer.from(JSON.stringify(body), "utf8");
}

function _signedHeaders(cfg, body, target) {
  target = target || "Logs_20140328.PutLogEvents";
  var url = _resolveEndpoint(cfg);
  var payloadHash = nodeCrypto.createHash("sha256").update(body).digest("hex");
  var unsigned = {
    "Content-Type": "application/x-amz-json-1.1",
    "X-Amz-Target": target,
  };
  var signed = sigv4.signRequest({
    method:           "POST",
    url:              url,
    headers:          unsigned,
    payloadHash:      payloadHash,
    region:           cfg.region,
    service:          "logs",
    accessKeyId:      cfg.accessKeyId,
    secretAccessKey:  cfg.secretAccessKey,
    sessionToken:     cfg.sessionToken || null,
    allowedProtocols: cfg.allowedProtocols,
  });
  return signed.headers;
}

// CloudWatch CreateLogGroup / CreateLogStream wrappers. Operator opts in
// via cfg.autoCreate = true; default stays "operator pre-creates via
// Terraform / CDK / aws cli" so the framework doesn't paper over an
// IAM-misconfigured deployment with surprising side effects.
async function _ensureLogGroupAndStream(cfg) {
  // CreateLogGroup — idempotent on the wire (we treat
  // ResourceAlreadyExistsException as success).
  var groupBody = Buffer.from(JSON.stringify({ logGroupName: cfg.logGroupName }), "utf8");
  var groupHeaders = _signedHeaders(cfg, groupBody, "Logs_20140328.CreateLogGroup");
  try {
    await _post(cfg, groupBody, groupHeaders);
  } catch (e) {
    var msg = (e && e.message) || "";
    if (!/ResourceAlreadyExistsException/.test(msg)) {
      throw _err("AUTOCREATE_FAILED",
        "log-stream cloudwatch autoCreate: CreateLogGroup failed: " + msg);
    }
  }
  // CreateLogStream — same idempotency treatment.
  var streamBody = Buffer.from(JSON.stringify({
    logGroupName:  cfg.logGroupName,
    logStreamName: cfg.logStreamName,
  }), "utf8");
  var streamHeaders = _signedHeaders(cfg, streamBody, "Logs_20140328.CreateLogStream");
  try {
    await _post(cfg, streamBody, streamHeaders);
  } catch (e) {
    var msg2 = (e && e.message) || "";
    if (!/ResourceAlreadyExistsException/.test(msg2)) {
      throw _err("AUTOCREATE_FAILED",
        "log-stream cloudwatch autoCreate: CreateLogStream failed: " + msg2);
    }
  }
}

function _post(cfg, body, headers) {
  return httpClient.request({
    method:           "POST",
    url:              _resolveEndpoint(cfg),
    headers:          headers,
    body:             body,
    timeoutMs:        cfg.timeoutMs,
    idleTimeoutMs:    cfg.timeoutMs,
    maxResponseBytes: MAX_RESPONSE_BYTES,
    errorClass:       LogStreamError,
    allowedProtocols: cfg.allowedProtocols,
    allowInternal:    cfg.allowInternal,
  });
}

function _isPermanentAwsError(err) {
  if (!err) return false;
  var msg = err.message || "";
  if (/ResourceNotFoundException/.test(msg)) return true;
  if (/InvalidParameterException/.test(msg)) return true;
  if (/UnrecognizedClientException/.test(msg)) return true;
  if (/AccessDeniedException/.test(msg)) return true;
  if (/SerializationException/.test(msg)) return true;
  return false;
}

function create(config) {
  if (!config || !config.region) {
    throw _err("BAD_OPT", "log-stream cloudwatch requires { region }");
  }
  if (!config.accessKeyId || !config.secretAccessKey) {
    throw _err("BAD_OPT",
      "log-stream cloudwatch requires { accessKeyId, secretAccessKey } " +
      "(IAM role or env-supplied STS credentials)");
  }
  if (!config.logGroupName || !config.logStreamName) {
    throw _err("BAD_OPT",
      "log-stream cloudwatch requires { logGroupName, logStreamName }. " +
      "Operator pre-creates both via aws / CDK / Terraform by default; " +
      "pass { autoCreate: true } to have the framework issue " +
      "CreateLogGroup + CreateLogStream on first emit (idempotent — " +
      "ResourceAlreadyExistsException treated as success).");
  }
  var cfg = Object.assign({}, DEFAULTS, config);
  var sequenceToken = null;

  function _takeBatch(buffer) {
    var batch = [];
    var totalBytes = 0;
    while (buffer.length > 0) {
      var nextEvent = buffer[0];
      var size = _eventByteSize(nextEvent.message);
      if (batch.length > 0 &&
          (batch.length >= cfg.batchSize ||
           batch.length >= CW_MAX_EVENTS_PER_BATCH ||
           totalBytes + size > CW_MAX_BATCH_BYTES)) {
        break;
      }
      batch.push(buffer.shift());
      totalBytes += size;
    }
    return batch;
  }

  // autoCreate handshake — runs once per process before the first
  // PutLogEvents. Promise cached so concurrent emits don't fire
  // duplicate CreateLogGroup / CreateLogStream calls.
  var autoCreatePromise = null;
  function _ensureAutoCreated() {
    if (!cfg.autoCreate) return Promise.resolve();
    if (!autoCreatePromise) autoCreatePromise = _ensureLogGroupAndStream(cfg);
    return autoCreatePromise;
  }

  // CloudWatch rejects any single event above its 256 KiB hard cap — drop it
  // (with a truncated preview) before it can poison a batch; otherwise build
  // the { timestamp, message } event the API expects.
  function _prepareRecord(record) {
    var message = typeof record.message === "string" ? record.message : JSON.stringify(record);
    var size = _eventByteSize(message);
    if (size > CW_MAX_EVENT_BYTES) {
      return {
        rejected: true,
        reason:   "event too large",
        dropKind: "event-too-large",
        drop: [{
          timestamp: record.ts || Date.now(),
          message:   message.slice(0, DROP_PREVIEW_BYTES) + "...[truncated for drop event]",
        }],
        error: new Error("event exceeds 256 KiB CloudWatch hard cap (was " + size + " bytes)"),
      };
    }
    return { entry: { timestamp: record.ts || Date.now(), message: message } };
  }

  async function _send(batch) {
    var body = _serializeBatch(batch, cfg, sequenceToken);
    var headers = _signedHeaders(cfg, body);
    var res;
    try {
      res = await _post(cfg, body, headers);
    } catch (e) {
      var match = /expected sequenceToken is:\s*(\S+)/.exec(e.message || "");
      if (match) {
        sequenceToken = match[1];
        var retryBody = _serializeBatch(batch, cfg, sequenceToken);
        var retryHeaders = _signedHeaders(cfg, retryBody);
        res = await _post(cfg, retryBody, retryHeaders);
      } else {
        throw e;
      }
    }
    if (res && res.body) {
      try {
        var parsed = safeJson.parse(res.body.toString("utf8"), { maxBytes: MAX_RESPONSE_BYTES });
        if (parsed && parsed.nextSequenceToken) sequenceToken = parsed.nextSequenceToken;
      } catch (_e) { /* response body not JSON; modern CW returns empty */ }
    }
    return res;
  }

  // beforeDrain runs the autoCreate handshake once; its failure is permanent
  // (every batch would hit the same error) so the whole buffer is dropped under
  // "autocreate-failed". takeBatch enforces CloudWatch's per-batch byte + count
  // caps; sendBatch wraps the signed PutLogEvents in retry, treating throttling
  // / sequence-token errors per _isPermanentAwsError.
  var sink = safeAsync.makeBatchingSink({
    batchSize:           cfg.batchSize,
    bufferLimit:         cfg.bufferLimit,
    maxBatchAgeMs:       cfg.maxBatchAgeMs,
    onDrop:              cfg.onDrop,
    prepareRecord:       _prepareRecord,
    takeBatch:           _takeBatch,
    beforeDrain:         _ensureAutoCreated,
    beforeDrainDropKind: "autocreate-failed",
    sendBatch:           function (batch) {
      return retryHelper.withRetry(function () {
        return _send(batch);
      }, Object.assign({ isPermanent: _isPermanentAwsError }, cfg.retry || {}));
    },
  });

  return {
    protocol: "cloudwatch",
    emit:     sink.emit,
    close:    sink.close,
    stats:    function () { return sink.stats({ sequenceToken: sequenceToken, endpoint: _resolveEndpoint(cfg) }); },
    flush:    sink.flush,
  };
}

module.exports = {
  create:                create,
  _resolveEndpoint:      _resolveEndpoint,
  _eventByteSize:        _eventByteSize,
  _serializeBatch:       _serializeBatch,
  _isPermanentAwsError:  _isPermanentAwsError,
  CW_MAX_EVENTS_PER_BATCH: CW_MAX_EVENTS_PER_BATCH,
  CW_MAX_BATCH_BYTES:    CW_MAX_BATCH_BYTES,
  CW_MAX_EVENT_BYTES:    CW_MAX_EVENT_BYTES,
};
