// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var C = require("./constants");
var nodeCrypto = require("node:crypto");
var codepointClass = require("./codepoint-class");
var safeAsync = require("./safe-async");
var safeJson = require("./safe-json");
var sigv4 = require("./object-store/sigv4");
var retryHelper = require("./retry");
var { LogStreamError } = require("./framework-error");
var httpClient = require("./http-client");

var MAX_RESPONSE_BYTES = C.BYTES.mib(1);
var CW_MAX_EVENTS_PER_BATCH = C.BYTES.bytes(10000);
var CW_MAX_BATCH_BYTES      = C.BYTES.mib(1);
var CW_MAX_EVENT_BYTES      = C.BYTES.kib(256);
var CW_EVENT_OVERHEAD_BYTES = C.BYTES.bytes(26);
var DROP_PREVIEW_BYTES = C.BYTES.bytes(200);

var DEFAULTS = {
  batchSize:     100,
  maxBatchAgeMs: C.TIME.seconds(5),
  timeoutMs:     C.TIME.seconds(30),
  bufferLimit:   C.BYTES.bytes(10000),
};

var _err = LogStreamError.factory;

function _resolveEndpoint(cfg) {
  if (cfg.endpoint) return codepointClass.trimTrailingChars(cfg.endpoint, "/") + "/";
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

async function _ensureLogGroupAndStream(cfg) {
  var groupBody = Buffer.from(JSON.stringify({ logGroupName: cfg.logGroupName }), "utf8");
  var groupHeaders = _signedHeaders(cfg, groupBody, "Logs_20140328.CreateLogGroup");
  try {
    await _post(cfg, groupBody, groupHeaders);
  } catch (e) {
    var msg = (e && e.message) || "";
    if (!/ResourceAlreadyExistsException/.test(msg)) {
      throw _err("log-stream-cloudwatch/autocreate-failed",
        "log-stream cloudwatch autoCreate: CreateLogGroup failed: " + msg);
    }
  }
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
      throw _err("log-stream-cloudwatch/autocreate-failed",
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
    throw _err("log-stream-cloudwatch/bad-opt", "log-stream cloudwatch requires { region }");
  }
  if (!config.accessKeyId || !config.secretAccessKey) {
    throw _err("log-stream-cloudwatch/bad-opt",
      "log-stream cloudwatch requires { accessKeyId, secretAccessKey } " +
      "(IAM role or env-supplied STS credentials)");
  }
  if (!config.logGroupName || !config.logStreamName) {
    throw _err("log-stream-cloudwatch/bad-opt",
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

  var autoCreatePromise = null;
  function _ensureAutoCreated() {
    if (!cfg.autoCreate) return Promise.resolve();
    if (!autoCreatePromise) autoCreatePromise = _ensureLogGroupAndStream(cfg);
    return autoCreatePromise;
  }

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
