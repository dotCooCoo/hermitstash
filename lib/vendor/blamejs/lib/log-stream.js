// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.logStream
 * @nav    Observability
 * @title  Log Stream
 *
 * @intro
 *   Pluggable structured-log dispatcher — fire-and-forget JSON records
 *   from request hot paths to one or many sinks (local file with
 *   rotation, generic webhook, OTLP HTTP/JSON, OTLP gRPC, AWS
 *   CloudWatch Logs, RFC 5424 syslog over UDP/TCP/TLS). Each sink
 *   keeps its own connection / fd / batch buffer, so a slow remote
 *   collector backpressures only its own queue — never the request
 *   thread that called `emit()`.
 *
 *   Every record passes through `b.redact` BEFORE any sink sees it.
 *   PHI / PCI / JWTs / PEM blocks / AWS access keys / vault-sealed
 *   strings / credit-card-shaped digits / SSN-shaped values are
 *   stripped on the framework side, not delegated to the operator's
 *   sink config — a misnamed field cannot leak sensitive data into
 *   operational logs.
 *
 *   Sink failures are drop-silent on the hot path: a captured Promise
 *   reroutes the error into `audit.system.log.sink_failure` so a
 *   downed collector never crashes the request that emitted the log
 *   line. Pending emits are tracked and drained on `shutdown()` so
 *   records queued just before close still reach disk / the wire.
 *
 *   Bidirectional command channel: `onIncoming(handler)` registers a
 *   handler for inbound events; the operator wires their preferred
 *   transport (HTTP route, webhook receiver, SSE subscription,
 *   message-queue consumer) to call `deliverIncoming(payload)`, which
 *   redacts, audits, and dispatches to every registered handler. The
 *   framework provides the dispatch; the operator provides the wire.
 *
 *   Built-in protocols:
 *     local      — append-only file with size + age rotation
 *     webhook    — generic HTTP POST (Splunk HEC, Datadog, Loki,
 *                  Sumo Logic, custom JSON collectors)
 *     otlp       — OpenTelemetry Protocol over HTTP/JSON
 *     otlp-grpc  — same Logs Data Model over gRPC (higher throughput;
 *                  hand-encoded protobuf, no parser dependency)
 *     cloudwatch — PutLogEvents over HTTPS with SigV4; honours the
 *                  10K-event / 1 MiB / 256 KiB-per-event AWS caps
 *     syslog     — RFC 5424 octet-counting framing over UDP / TCP /
 *                  TLS (default ports 514 / 6514)
 *
 * @card
 *   Pluggable structured-log dispatcher — fire-and-forget JSON records from request hot paths to one or many sinks (local file with rotation, generic webhook, OTLP HTTP/JSON, OTLP gRPC, AWS CloudWatch Logs, RFC 5424 syslog over UDP/TCP/TLS).
 */
var localProto      = require("./log-stream-local");
var webhookProto    = require("./log-stream-webhook");
var otlpProto       = require("./log-stream-otlp");
var otlpGrpcProto   = require("./log-stream-otlp-grpc");
var cloudwatchProto = require("./log-stream-cloudwatch");
var syslogProto     = require("./log-stream-syslog");
var { boot }        = require("./log");
var redact          = require("./redact");
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

/**
 * @primitive b.logStream.init
 * @signature b.logStream.init(opts)
 * @since     0.0.13
 * @related   b.logStream.bootFromEnv, b.logStream.shutdown, b.logStream.listSinks
 *
 * Configure the dispatcher. Call once at boot; subsequent calls are
 * no-ops while the dispatcher is initialized (call `shutdown()` first
 * to reconfigure). Every named sink resolves a built-in protocol
 * (`local` / `webhook` / `otlp` / `otlp-grpc` / `cloudwatch` /
 * `syslog`) and constructs a per-sink instance from its own typed
 * config block.
 *
 * Records below `minLevel` (or a sink's per-sink `minLevel` override)
 * are dropped before redaction — debug / info chatter on a
 * production deployment costs nothing past the dispatcher.
 *
 * @opts
 *   sinks:    { [name]: { protocol, minLevel?, ...protocolOpts } },
 *   minLevel: "debug" | "info" | "warn" | "error",   // default "info"
 *
 * @example
 *   b.logStream.init({
 *     minLevel: "info",
 *     sinks: {
 *       file:   { protocol: "local",   path: "/var/log/app.log" },
 *       remote: { protocol: "otlp",
 *                 url:         "https://collector.internal:4318/v1/logs",
 *                 serviceName: "checkout",
 *                 minLevel:    "warn" },
 *     },
 *   });
 */
function init(opts) {
  if (initialized) return;
  if (!opts || !opts.sinks) throw new Error("logStream.init({ sinks }) is required");

  // Validate top-level minLevel at config time so a typo (`"infos"`)
  // doesn't silently produce `LEVEL_PRIORITY["infos"] === undefined`
  // and drop every record at runtime (an `X >= undefined` compare
  // is always false). Throw rather than fall back to a default —
  // operators want a loud failure at boot, not silent log loss.
  if (opts.minLevel !== undefined && opts.minLevel !== null) {
    var topLevel = String(opts.minLevel).toLowerCase();
    if (LEVELS.indexOf(topLevel) === -1) {
      throw _err("INVALID_LEVEL",
        "logStream.init: opts.minLevel '" + opts.minLevel +
        "' must be one of " + LEVELS.join(", "), true);
    }
  }

  sinks = {};
  for (var name in opts.sinks) {
    var cfg = opts.sinks[name];
    var proto = dispatcher.resolve(cfg.protocol);
    // Same gate per-sink so a misconfigured filter doesn't silently
    // drop records from a single sink while every other sink works.
    if (cfg.minLevel !== undefined && cfg.minLevel !== null) {
      var sinkLvl = String(cfg.minLevel).toLowerCase();
      if (LEVELS.indexOf(sinkLvl) === -1) {
        throw _err("INVALID_LEVEL",
          "logStream.init: sink '" + name + "' minLevel '" + cfg.minLevel +
          "' must be one of " + LEVELS.join(", "), true);
      }
    }
    sinks[name] = {
      name:     name,
      protocol: cfg.protocol,
      raw:      proto.create(cfg),
      levelFilter: cfg.minLevel ? String(cfg.minLevel).toLowerCase() : null,
    };
  }

  minLevel = (opts.minLevel || "info").toLowerCase();
  initialized = true;
}

function _shouldEmit(level, sinkLevelFilter) {
  var threshold = sinkLevelFilter ? LEVEL_PRIORITY[sinkLevelFilter] : LEVEL_PRIORITY[minLevel];
  return LEVEL_PRIORITY[level] >= threshold;
}

/**
 * @primitive b.logStream.emit
 * @signature b.logStream.emit(level, message, meta?)
 * @since     0.0.13
 * @related   b.logStream.info, b.logStream.warn, b.logStream.error, b.logStream.debug, b.redact.redact
 *
 * Synchronous, fire-and-forget emit to every registered sink whose
 * level filter accepts `level`. The record is `{ ts, level, message,
 * meta }`; `meta` is run through `b.redact.redact` BEFORE distribution
 * so PHI / credentials / vault-sealed values never reach a sink even
 * on a misnamed field. Sink errors are captured, audited
 * (`system.log.sink_failure`), and discarded — a downed collector
 * cannot crash the caller. Throws only on an unknown level (config
 * typo at the call site).
 *
 * @example
 *   // Structured event with sensitive metadata — `apiKey` and
 *   // `cardNumber` are redacted by pattern before any sink sees them.
 *   b.logStream.emit("warn", "checkout retry", {
 *     orderId:    "ord_01HXYZ",
 *     attempt:    3,
 *     apiKey:     "<sk-live-placeholder>",
 *     cardNumber: "<pan-placeholder>",
 *   });
 */
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
    record.meta = redact.redact(meta);
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

/**
 * @primitive b.logStream.debug
 * @signature b.logStream.debug(message, meta?)
 * @since     0.0.13
 * @related   b.logStream.emit, b.logStream.info, b.logStream.warn, b.logStream.error
 *
 * Convenience wrapper for `emit("debug", ...)`. Records drop below
 * `minLevel` (default `"info"`) without serialization cost, so leaving
 * `debug()` calls in production code is cheap.
 *
 * @example
 *   b.logStream.debug("cache lookup", { key: "user:42", hit: false });
 */
function debug(message, meta) { emit("debug", message, meta); }

/**
 * @primitive b.logStream.info
 * @signature b.logStream.info(message, meta?)
 * @since     0.0.13
 * @related   b.logStream.emit, b.logStream.debug, b.logStream.warn, b.logStream.error
 *
 * Convenience wrapper for `emit("info", ...)`. Use for routine
 * lifecycle events worth keeping in the operational log under default
 * filtering.
 *
 * @example
 *   b.logStream.info("worker ready", { pid: process.pid, queue: "checkout" });
 */
function info(message, meta)  { emit("info",  message, meta); }

/**
 * @primitive b.logStream.warn
 * @signature b.logStream.warn(message, meta?)
 * @since     0.0.13
 * @related   b.logStream.emit, b.logStream.debug, b.logStream.info, b.logStream.error
 *
 * Convenience wrapper for `emit("warn", ...)`. Use for recoverable
 * anomalies the operator should notice but that don't fail the
 * request — retry exhaustion below the cap, degraded-mode entry,
 * cache misses on a hot key.
 *
 * @example
 *   b.logStream.warn("retry succeeded after backoff", {
 *     route: "POST /checkout", attempts: 4, totalMs: 1820,
 *   });
 */
function warn(message, meta)  { emit("warn",  message, meta); }

/**
 * @primitive b.logStream.error
 * @signature b.logStream.error(message, meta?)
 * @since     0.0.13
 * @related   b.logStream.emit, b.logStream.debug, b.logStream.info, b.logStream.warn
 *
 * Convenience wrapper for `emit("error", ...)`. Use for the failed-
 * request / unhandled-exception class. `b.audit` remains the
 * authoritative tamper-evident record for privileged actions; the
 * log stream is operational telemetry.
 *
 * @example
 *   b.logStream.error("dispatcher failure", {
 *     route: "POST /checkout", err: "ECONNRESET", upstream: "payments",
 *   });
 */
function error(message, meta) { emit("error", message, meta); }

// ---- Bidirectional incoming command channel ----

/**
 * @primitive b.logStream.onIncoming
 * @signature b.logStream.onIncoming(handler)
 * @since     0.0.13
 * @related   b.logStream.deliverIncoming
 *
 * Register a handler for inbound command-channel events. Returns an
 * unsubscribe function. Handlers may be `async` and may return a
 * value; `deliverIncoming` collects every handler's result and reports
 * per-handler success / failure. Throws on a non-function argument.
 *
 * @example
 *   var off = b.logStream.onIncoming(async function (payload) {
 *     if (payload.command === "raise-log-level") return { applied: true };
 *     return { applied: false };
 *   });
 *   // Later, when teardown is needed:
 *   off();
 */
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

/**
 * @primitive b.logStream.deliverIncoming
 * @signature b.logStream.deliverIncoming(payload, opts?)
 * @since     0.0.13
 * @related   b.logStream.onIncoming, b.audit.safeEmit
 *
 * Dispatch an inbound command-channel payload to every registered
 * handler. The payload is redacted before audit and before handlers
 * run, so even a noisy webhook receiver cannot smuggle secrets into
 * the audit chain. Audit-logs the receipt under
 * `system.log.incoming` BEFORE invoking handlers — handler exceptions
 * never erase the receipt. Returns a per-handler `[{ ok, value? |
 * error? }]` array; one handler throwing does not abort the rest.
 *
 * @opts
 *   actor:  { userId?, sessionId?, ip?, userAgent? },   // audit context
 *   source: string,                                     // transport name
 *
 * @example
 *   var results = await b.logStream.deliverIncoming(
 *     { command: "rotate-sink", sink: "file" },
 *     { actor: { userId: "ops-42" }, source: "webhook" }
 *   );
 *   // → [{ ok: true, value: { applied: false } }]
 */
async function deliverIncoming(payload, opts) {
  opts = opts || {};
  var redacted = redact.redact(payload);
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

/**
 * @primitive b.logStream.shutdown
 * @signature b.logStream.shutdown()
 * @since     0.0.13
 * @related   b.logStream.init, b.appShutdown.create
 *
 * Drain pending fire-and-forget emits, close every sink (file fds,
 * webhook keep-alive sockets, syslog connections, OTLP gRPC streams),
 * and clear registered incoming handlers. Idempotent — safe to call
 * twice. Records queued just before shutdown reach disk / the wire
 * because in-flight Promises are tracked and awaited before close.
 *
 * @example
 *   process.on("SIGTERM", async function () {
 *     await b.logStream.shutdown();
 *     process.exit(0);
 *   });
 */
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

/**
 * @primitive b.logStream.listSinks
 * @signature b.logStream.listSinks()
 * @since     0.0.13
 * @related   b.logStream.init
 *
 * Return one descriptor per configured sink: `{ name, protocol, stats
 * }`. Sinks that expose a `stats()` method (file rotation counters,
 * webhook batch metrics, OTLP queue depth) report through it; those
 * that don't return `null`. Returns `[]` before `init()` runs, so
 * health endpoints can call it unconditionally.
 *
 * @example
 *   var snapshot = b.logStream.listSinks();
 *   // → [{ name: "file", protocol: "local",
 *   //      stats: { rotations: 2, bytesWritten: 4194304 } }]
 */
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
/**
 * @primitive b.logStream.bootFromEnv
 * @signature b.logStream.bootFromEnv(opts?)
 * @since     0.6.25
 * @related   b.logStream.init, b.network.bootFromEnv
 *
 * Operator-friendly env-driven init. Reads `BLAMEJS_LOG_STREAM_*` (and
 * standard `AWS_*`) variables and constructs a single-sink
 * configuration. Returns `false` and skips silently when
 * `BLAMEJS_LOG_STREAM_PROTOCOL` is unset, so deployments that wire
 * sinks through `init()` keep their existing config. Throws on an
 * unknown protocol value.
 *
 * Recognised variables: `BLAMEJS_LOG_STREAM_PROTOCOL` (`local` |
 * `webhook` | `otlp` | `cloudwatch`), `BLAMEJS_LOG_STREAM_MIN_LEVEL`,
 * `BLAMEJS_LOG_STREAM_URL`, `BLAMEJS_LOG_STREAM_TOKEN`,
 * `BLAMEJS_LOG_STREAM_SERVICE_NAME`, `BLAMEJS_LOG_STREAM_PATH`,
 * `BLAMEJS_LOG_STREAM_CLOUDWATCH_LOG_GROUP`, plus `AWS_REGION` /
 * `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`.
 *
 * @opts
 *   env: object,   // override process.env (testing / fixtures)
 *
 * @example
 *   // Operator sets BLAMEJS_LOG_STREAM_PROTOCOL=otlp and the URL in
 *   // the deployment manifest; the framework wires the sink at boot.
 *   var wired = b.logStream.bootFromEnv({
 *     env: {
 *       BLAMEJS_LOG_STREAM_PROTOCOL:     "otlp",
 *       BLAMEJS_LOG_STREAM_URL:          "https://collector.internal:4318/v1/logs",
 *       BLAMEJS_LOG_STREAM_SERVICE_NAME: "checkout",
 *       BLAMEJS_LOG_STREAM_MIN_LEVEL:    "info",
 *     },
 *   });
 *   // → true   (false when BLAMEJS_LOG_STREAM_PROTOCOL is unset)
 */
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
    // The local sink is directory-based (writes <dir>/<prefix>.log);
    // BLAMEJS_LOG_STREAM_PATH names that directory and maps to `dir`.
    sink.dir = env.BLAMEJS_LOG_STREAM_PATH;
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
