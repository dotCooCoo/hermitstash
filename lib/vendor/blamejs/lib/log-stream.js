"use strict";
/**
 * Log streaming dispatcher — operational logs to one or many sinks with
 * redaction and bidirectional command channel.
 *
 * Same dispatcher pattern: backends configured per-name with a protocol
 * + protocol-specific options. Built-in protocols:
 *
 *   local    — append-only file with rotation
 *   webhook  — generic HTTP POST; covers Splunk HEC, Datadog, Sumo
 *              Logic, Loki, custom collectors that ingest JSON
 *   otlp     — OpenTelemetry Protocol over HTTP/JSON; ResourceLogs
 *              envelope with severity mapping per OTel Logs Data
 *              Model. Operators with an OTel collector running
 *              (k8s, cloud) get standard log forwarding without a
 *              vendor-specific adapter.
 *   otlp-grpc — same OTel Logs Data Model but over gRPC (HTTP/2 +
 *              hand-encoded protobuf). Higher-throughput than the
 *              JSON variant; preferred for production deployments
 *              pushing >100K logs/s straight to a remote OTel
 *              collector. No protobuf parser ships in the bundle —
 *              the encoder is the framework's own (lib/protobuf-encoder.js).
 *   cloudwatch — AWS CloudWatch Logs (PutLogEvents) over HTTPS with
 *              SigV4. Pass { autoCreate: true } to have the framework
 *              issue CreateLogGroup + CreateLogStream on first emit
 *              (idempotent — ResourceAlreadyExistsException treated as
 *              success). Honors IAM role + STS session tokens. Respects
 *              the 10K-event / 1 MiB / 256 KiB-per-event AWS caps.
 *   syslog   — RFC 5424 with octet-counting framing over UDP / TCP /
 *              TLS. UDP is best-effort; TCP/TLS buffer during socket
 *              reconnect and replay on connect. Default ports 514
 *              (UDP/TCP) and 6514 (TLS).
 *
 * Every emit goes through lib/redact.js BEFORE any sink sees it. PHI/PCI
 * never reaches operational logs even on a misconfigured field name —
 * pattern detectors catch credit-card-shaped values, JWTs, PEM blocks,
 * AWS access keys, vault-sealed strings, SSN-shaped values, etc.
 *
 * Bidirectional command channel:
 *   logStream.onIncoming(handler) registers a handler for inbound events.
 *   Operators wire their HTTP route (or other transport — webhook receiver,
 *   SSE, message-queue subscriber) to call logStream.deliverIncoming(payload)
 *   which invokes registered handlers. The framework doesn't prescribe the
 *   transport — it provides the dispatch.
 *
 * Public API:
 *   logStream.init({ sinks: { name: { protocol, ... } }, classification? })
 *   logStream.emit(level, message, meta?)         (sync — non-blocking)
 *   logStream.info(msg, meta?) / .warn / .error / .debug
 *   logStream.onIncoming(handler)                 (handler returns Promise)
 *   logStream.deliverIncoming(payload, opts?)
 *   logStream.shutdown()
 *   logStream.listSinks()                         → [{ name, protocol, stats }]
 */
var localProto      = require("./log-stream-local");
var webhookProto    = require("./log-stream-webhook");
var otlpProto       = require("./log-stream-otlp");
var otlpGrpcProto   = require("./log-stream-otlp-grpc");
var cloudwatchProto = require("./log-stream-cloudwatch");
var syslogProto     = require("./log-stream-syslog");
var { boot }        = require("./log");
var redactor        = require("./redact");
var lazyRequire     = require("./lazy-require");
var protocolDispatcher = require("./protocol-dispatcher");
var { LogStreamError } = require("./framework-error");

var _log = boot("log-stream");

var dispatcher = protocolDispatcher.create({
  name:       "log-stream",
  errorClass: LogStreamError,
  protocols:  {
    "local":      localProto,
    "webhook":    webhookProto,
    "otlp":       otlpProto,
    "otlp-grpc":  otlpGrpcProto,
    "cloudwatch": cloudwatchProto,
    "syslog":     syslogProto,
  },
  deferred:   {},
  fallbackProtocol: "local",
});

var LEVELS = ["debug", "info", "warn", "error"];
// Ordinal priority — higher = more severe. Values are spaced (1..4)
// only so future intermediate levels (e.g. 'notice' between info/warn)
// could slot in without renumbering the existing four.
var LEVEL_PRIORITY = { debug: 1, info: 2, warn: 3, error: 4 };

var _err = LogStreamError.factory;

var audit = lazyRequire(function () { return require("./audit"); });

var initialized = false;
var sinks = {};
// Pending emit promises, tracked so shutdown can drain them before
// closing sink fds. Without this, fire-and-forget emits queued just
// before shutdown raced with close() and silently dropped records.
var _inflight = new Set();
var minLevel = "info";
var incomingHandlers = [];

function init(opts) {
  if (initialized) return;
  if (!opts || !opts.sinks) throw new Error("logStream.init({ sinks }) is required");

  sinks = {};
  for (var name in opts.sinks) {
    var cfg = opts.sinks[name];
    var proto = dispatcher.resolve(cfg.protocol);
    sinks[name] = {
      name:     name,
      protocol: cfg.protocol,
      raw:      proto.create(cfg),
      levelFilter: cfg.minLevel || null,
    };
  }

  minLevel = (opts.minLevel || "info").toLowerCase();
  initialized = true;
}

function _shouldEmit(level, sinkLevelFilter) {
  var threshold = sinkLevelFilter ? LEVEL_PRIORITY[sinkLevelFilter] : LEVEL_PRIORITY[minLevel];
  return LEVEL_PRIORITY[level] >= threshold;
}

function emit(level, message, meta) {
  if (!initialized) return;
  if (LEVELS.indexOf(level) === -1) {
    throw _err("INVALID_LEVEL", "log level must be one of " + LEVELS.join(", "), true);
  }
  // Build the record. Redact metadata BEFORE distribution to any sink.
  var record = {
    ts:      Date.now(),
    level:   level,
    message: message == null ? null : String(message),
  };
  if (meta) {
    record.meta = redactor.redact(meta);
  }

  // Fire-and-forget to all sinks. Sink errors don't bubble — they're
  // captured by audit (system.log.sink-failure) so an external sink
  // outage doesn't take down the app's request handlers. Pending
  // emits are tracked in _inflight so shutdown() can drain them
  // before closing fds (otherwise records queued just before
  // shutdown would be lost when close() ran ahead of the microtask).
  Object.keys(sinks).forEach(function (name) {
    var sink = sinks[name];
    if (!_shouldEmit(level, sink.levelFilter)) return;
    var p = Promise.resolve()
      .then(function () { return sink.raw.emit(record); })
      .catch(function (e) {
        audit().safeEmit({
          action:   "system.log.sink_failure",
          outcome:  "failure",
          reason:   (e && e.message) || String(e),
          metadata: { sink: name, level: level },
        });
      });
    _inflight.add(p);
    p.then(function () { _inflight.delete(p); }, function () { _inflight.delete(p); });
  });
}

function debug(message, meta) { emit("debug", message, meta); }
function info(message, meta)  { emit("info",  message, meta); }
function warn(message, meta)  { emit("warn",  message, meta); }
function error(message, meta) { emit("error", message, meta); }

// ---- Bidirectional incoming command channel ----

function onIncoming(handler) {
  if (typeof handler !== "function") {
    throw _err("INVALID_HANDLER", "onIncoming requires a function handler", true);
  }
  incomingHandlers.push(handler);
  return function () {
    var idx = incomingHandlers.indexOf(handler);
    if (idx >= 0) incomingHandlers.splice(idx, 1);
  };
}

async function deliverIncoming(payload, opts) {
  opts = opts || {};
  var redacted = redactor.redact(payload);
  // Audit-log the inbound command BEFORE invoking handlers — even handler
  // exceptions don't lose the receipt.
  audit().safeEmit({
    actor:    opts.actor || {},
    action:   "system.log.incoming",
    metadata: { payload: redacted, source: opts.source || null },
  });

  var results = [];
  for (var i = 0; i < incomingHandlers.length; i++) {
    try {
      results.push({ ok: true, value: await incomingHandlers[i](payload, opts) });
    } catch (e) {
      results.push({ ok: false, error: (e && e.message) || String(e) });
    }
  }
  return results;
}

async function shutdown() {
  if (!initialized) return;
  // Drain any in-flight emits before closing sink fds so records
  // queued just before shutdown actually reach disk / the wire.
  if (_inflight.size > 0) {
    try { await Promise.all(Array.from(_inflight)); }
    catch (_e) { /* sink errors already audited via the catch above */ }
  }
  for (var name in sinks) {
    try {
      if (typeof sinks[name].raw.close === "function") await sinks[name].raw.close();
    } catch (_e) { /* best effort on shutdown */ }
  }
  sinks = {};
  incomingHandlers = [];
  initialized = false;
}

function listSinks() {
  if (!initialized) return [];
  return Object.keys(sinks).map(function (name) {
    var s = sinks[name];
    var stats = (typeof s.raw.stats === "function") ? s.raw.stats() : null;
    return { name: name, protocol: s.protocol, stats: stats };
  });
}

// ---- bootFromEnv ----
//
// Operator-friendly env-driven init that mirrors b.network.bootFromEnv.
// Reads BLAMEJS_LOG_STREAM_* env vars and constructs a single-sink
// configuration matching the operator's choice. Skipped silently when
// BLAMEJS_LOG_STREAM_PROTOCOL isn't set (operators using the in-code
// init() path keep their existing wiring).
//
// Recognised env vars:
//   BLAMEJS_LOG_STREAM_PROTOCOL    "local" | "webhook" | "otlp" | "cloudwatch"
//   BLAMEJS_LOG_STREAM_MIN_LEVEL   "debug" | "info" | "warn" | "error"
//
//   webhook + otlp shared:
//     BLAMEJS_LOG_STREAM_URL
//     BLAMEJS_LOG_STREAM_TOKEN              (auth: bearer)
//   otlp-only:
//     BLAMEJS_LOG_STREAM_SERVICE_NAME
//     BLAMEJS_LOG_STREAM_SERVICE_VERSION
//   cloudwatch-only (AWS_* are standard):
//     AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
//     BLAMEJS_LOG_STREAM_CLOUDWATCH_LOG_GROUP
//     BLAMEJS_LOG_STREAM_CLOUDWATCH_LOG_STREAM
//   local-only:
//     BLAMEJS_LOG_STREAM_PATH
function bootFromEnv(opts) {
  opts = opts || {};
  var env = opts.env || process.env;
  var proto = env.BLAMEJS_LOG_STREAM_PROTOCOL;
  if (!proto) return false;
  var sink = { protocol: proto };
  if (proto === "webhook") {
    sink.url = env.BLAMEJS_LOG_STREAM_URL;
    if (env.BLAMEJS_LOG_STREAM_TOKEN) {
      sink.auth  = "bearer";
      sink.token = env.BLAMEJS_LOG_STREAM_TOKEN;
    }
  } else if (proto === "otlp") {
    sink.url            = env.BLAMEJS_LOG_STREAM_URL;
    sink.serviceName    = env.BLAMEJS_LOG_STREAM_SERVICE_NAME    || "blamejs";
    sink.serviceVersion = env.BLAMEJS_LOG_STREAM_SERVICE_VERSION || null;
    if (env.BLAMEJS_LOG_STREAM_TOKEN) {
      sink.auth  = "bearer";
      sink.token = env.BLAMEJS_LOG_STREAM_TOKEN;
    }
  } else if (proto === "cloudwatch") {
    sink.region          = env.AWS_REGION;
    sink.accessKeyId     = env.AWS_ACCESS_KEY_ID;
    sink.secretAccessKey = env.AWS_SECRET_ACCESS_KEY;
    sink.sessionToken    = env.AWS_SESSION_TOKEN || null;
    sink.logGroupName    = env.BLAMEJS_LOG_STREAM_CLOUDWATCH_LOG_GROUP;
    sink.logStreamName   = env.BLAMEJS_LOG_STREAM_CLOUDWATCH_LOG_STREAM;
  } else if (proto === "local") {
    sink.path = env.BLAMEJS_LOG_STREAM_PATH;
  } else {
    throw _err("BAD_OPT",
      "BLAMEJS_LOG_STREAM_PROTOCOL='" + proto + "' is not one of " +
      "local | webhook | otlp | cloudwatch (or a custom backend wired via init())");
  }
  init({
    sinks:    { primary: sink },
    minLevel: env.BLAMEJS_LOG_STREAM_MIN_LEVEL || undefined,
  });
  return true;
}

function _resetForTest() {
  Object.keys(sinks).forEach(function (n) {
    try { if (sinks[n].raw.close) sinks[n].raw.close(); }
    catch (e) {
      // Test-reset path; best-effort — surface for diagnosability via
      // the framework's boot logger so flaky teardown doesn't go silent.
      _log.debug("reset-close-failed: " + (e && e.message || e));
    }
  });
  sinks = {};
  incomingHandlers = [];
  initialized = false;
  audit.reset();
}

module.exports = {
  init:               init,
  bootFromEnv:        bootFromEnv,
  emit:               emit,
  debug:              debug,
  info:               info,
  warn:               warn,
  error:              error,
  onIncoming:         onIncoming,
  deliverIncoming:    deliverIncoming,
  shutdown:           shutdown,
  listSinks:          listSinks,
  LEVELS:             LEVELS,
  PROTOCOLS:          dispatcher.protocols,
  DEFERRED_PROTOCOLS: dispatcher.deferred,
  _resetForTest:      _resetForTest,
};
