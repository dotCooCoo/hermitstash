"use strict";
/**
 * Queue dispatcher — pluggable job queue with retry, lease semantics, and
 * graceful shutdown.
 *
 * Same dispatcher pattern as object-store: backends are configured per-name,
 * each with a protocol + protocol-specific options. The built-in 'local'
 * protocol is SQLite-backed (baked into the framework's main DB).
 * External protocols (redis, sqs, amqp, nats) are listed as deferred and
 * surface a clear error when selected.
 *
 * Public API:
 *   queue.init({ backends: { name: { protocol: 'local' } }, defaultBackend? })
 *   queue.enqueue(queueName, payload, opts?)
 *                                       → { jobId, queueName, ... }
 *   queue.consume(queueName, handler, opts?)
 *                                       → consumer handle (with cancel())
 *   queue.size(queueName, opts?)        → number (pending + inflight)
 *   queue.purge(queueName, opts?)       → number deleted
 *   queue.shutdown(opts?)               → drain handlers gracefully
 *   queue.listBackends()                → [{ name, protocol }]
 *
 * Job lifecycle:
 *   enqueued (status='pending')
 *     ↓ availableAt reached + consumer leases
 *   inflight (status='inflight', lease expires after leaseDurationMs)
 *     ↓ handler returns                 ↓ handler throws
 *   done (status='done')              if attempts < maxAttempts:
 *                                       pending (with backoff)
 *                                     else:
 *                                       failed (status='failed')
 */
var C = require("./constants");
var clusterStorage = require("./cluster-storage");
var crypto = require("./crypto");
var lazyRequire = require("./lazy-require");
var { boot } = require("./log");
var numericChecks = require("./numeric-checks");
var observability = require("./observability");
var protocolDispatcher = require("./protocol-dispatcher");
var localProto = require("./queue-local");
var redisProto = require("./queue-redis");
var sqsProto   = require("./queue-sqs");
var retryHelper = require("./retry");
var safeAsync = require("./safe-async");
var { QueueError } = require("./framework-error");

var log = boot("queue");

var dispatcher = protocolDispatcher.create({
  name:       "queue",
  errorClass: QueueError,
  protocols:  { "local": localProto, "redis": redisProto, "sqs": sqsProto },
  deferred:   {
    "amqp":   { description: "AMQP 0-9-1 (RabbitMQ etc.)" },
    "nats":   { description: "NATS JetStream" },
  },
  fallbackProtocol: "local",
});

var _err = QueueError.factory;

var audit = lazyRequire(function () { return require("./audit"); });

var initialized = false;
var backends = {};
var defaultBackend = null;
var consumers = [];   // [{ queueName, backendName, cancel(), running, inFlight: Set }]
var sweepTimer = null;

function init(opts) {
  if (initialized) return;
  if (!opts || !opts.backends) {
    throw _err("INVALID_CONFIG", "queue.init({ backends }) is required", true);
  }

  backends = {};
  // IIFE per-iteration so each backend's wrappers close over its own
  // raw / breaker / cfg. With `var` (function-scoped) those bindings
  // would otherwise be shared across iterations and every wrapper
  // would end up using the LAST backend's breaker + retry config —
  // multi-backend isolation broken without a single error surfacing.
  Object.keys(opts.backends).forEach(function (name) {
    var cfg = opts.backends[name];
    var proto = dispatcher.resolve(cfg.protocol);
    var raw = proto.create(cfg);
    var breaker = new retryHelper.CircuitBreaker(
      "queue:" + name,
      cfg.breaker
    );

    // Wrap mutating ops with retry + breaker (idempotent only — enqueue and
    // complete are safe to retry; lease isn't because partial-double-lease
    // is dangerous, so it goes through the breaker but not retry).
    function wrapWithRetry(fn) {
      return function () {
        var args = Array.prototype.slice.call(arguments);
        return retryHelper.withRetry(function () {
          return breaker.wrap(function () { return fn.apply(raw, args); });
        }, cfg.retry);
      };
    }
    function wrapBreakerOnly(fn) {
      return function () {
        var args = Array.prototype.slice.call(arguments);
        return breaker.wrap(function () { return fn.apply(raw, args); });
      };
    }

    backends[name] = {
      name:          name,
      protocol:      cfg.protocol,
      breaker:       breaker,
      raw:           raw,
      enqueue:       wrapWithRetry(raw.enqueue),
      lease:         wrapBreakerOnly(raw.lease),
      extendLease:   raw.extendLease ? wrapWithRetry(raw.extendLease) : null,
      complete:      wrapWithRetry(raw.complete),
      fail:          wrapWithRetry(raw.fail),
      sweepExpired:  raw.sweepExpired ? wrapBreakerOnly(raw.sweepExpired) : null,
      size:          wrapWithRetry(raw.size),
      purge:         wrapWithRetry(raw.purge),
      dlqList:       raw.dlqList ? wrapWithRetry(raw.dlqList) : null,
      dlqRetry:      raw.dlqRetry ? wrapWithRetry(raw.dlqRetry) : null,
      dlqSize:       raw.dlqSize ? wrapWithRetry(raw.dlqSize) : null,
    };
  });

  defaultBackend = opts.defaultBackend || Object.keys(backends)[0];

  // Sweep expired leases periodically (every 30s) so crashed-handler jobs
  // get re-pended.
  sweepTimer = safeAsync.repeating(function () {
    Object.keys(backends).forEach(function (n) {
      if (backends[n].sweepExpired) {
        backends[n].sweepExpired().catch(function () { /* best effort */ });
      }
    });
  }, C.TIME.seconds(30), { name: "queue-sweep" });

  initialized = true;
}

function _backendFor(opts) {
  opts = opts || {};
  var name = opts.backend || defaultBackend;
  var b = backends[name];
  if (!b) throw _err("UNKNOWN_BACKEND", "no backend named '" + name + "'", true);
  return b;
}

// ---- Public API ----

function enqueue(queueName, payload, opts) {
  _requireInit();
  if (!queueName) throw _err("MISSING_QUEUE", "enqueue requires queueName", true);
  opts = opts || {};
  var b = _backendFor(opts);
  return observability.tap("queue.enqueue",
    { queueName: queueName, backend: b.name },
    function () {
      return b.enqueue(queueName, payload, opts).then(function (result) {
        _emit("system.queue.enqueue", {
          metadata: {
            queue:          queueName,
            backend:        b.name,
            jobId:          result.jobId,
            classification: result.classification,
            traceId:        opts.traceId,
            delaySeconds:   opts.delaySeconds || 0,
          },
        });
        return result;
      });
    }
  );
}

function consume(queueName, handler, opts) {
  _requireInit();
  if (!queueName) throw _err("MISSING_QUEUE", "consume requires queueName", true);
  if (typeof handler !== "function") throw _err("INVALID_HANDLER", "handler must be a function", true);
  opts = opts || {};
  var b = _backendFor(opts);
  var concurrency      = opts.concurrency      || 1;
  var leaseDurationMs  = opts.leaseDurationMs  || C.TIME.seconds(30);
  var pollIntervalMs   = opts.pollIntervalMs   || C.TIME.seconds(1);
  var fastPollMs       = opts.fastPollMs       || 50;

  // Rate-limit: { max, perSeconds } caps how many handler INVOCATIONS
  // start within any rolling perSeconds window. Token-bucket-style
  // accounting keeps it cheap (just a sliding deque of timestamps).
  var rateLimit = null;
  if (opts.rateLimit) {
    var rlMax = opts.rateLimit.max;
    var rlPer = opts.rateLimit.perSeconds;
    // NaN, Infinity, 0, negatives, fractional max all produce undefined
    // throttling math (NaN deque comparisons, perma-locked queues,
    // perma-open windows). Reject at config time.
    if (!numericChecks.isPositiveInt(rlMax) || !numericChecks.isPositiveFinite(rlPer)) {
      throw _err("BAD_RATE_LIMIT",
        "consume({ rateLimit }): expected { max: positive integer, perSeconds: positive finite number }, got " +
        JSON.stringify(opts.rateLimit), true);
    }
    rateLimit = {
      max:        rlMax,
      windowMs:   C.TIME.seconds(rlPer),
      timestamps: [],
    };
  }
  function _rateLimitWaitMs() {
    if (!rateLimit) return 0;
    var now = Date.now();
    var cutoff = now - rateLimit.windowMs;
    while (rateLimit.timestamps.length > 0 && rateLimit.timestamps[0] <= cutoff) {
      rateLimit.timestamps.shift();
    }
    if (rateLimit.timestamps.length < rateLimit.max) return 0;
    return rateLimit.timestamps[0] + rateLimit.windowMs - now + 1;
  }
  function _rateLimitConsume() {
    if (rateLimit) rateLimit.timestamps.push(Date.now());
  }

  // Progress audit-emit rate-limit — protect the audit chain from a
  // chatty handler that calls progress() every loop iteration.
  var PROGRESS_MIN_INTERVAL_MS = 250;

  // Each consumer has its own AbortController so cancel() unblocks any
  // in-flight poll-sleep immediately rather than waiting up to
  // pollIntervalMs (default 1s) for the next while-loop iteration.
  var abortCtrl = new AbortController();
  var state = {
    queueName:    queueName,
    backendName:  b.name,
    cancelled:    false,
    inFlight:     new Set(),
    abortCtrl:    abortCtrl,
    cancel:       function () {
      state.cancelled = true;
      try { abortCtrl.abort(); }
      catch (e) { log.debug("cancel-cleanup-failed", { op: "abortCtrl.abort", error: e.message }); }
    },
  };
  consumers.push(state);

  (async function loop() {
    // Helper — sleep with cancellation. On abort, returns instead of
    // rejecting so the next while-iteration sees `state.cancelled` and
    // exits cleanly.
    async function _pollSleep(ms) {
      try { await safeAsync.sleep(ms, { signal: abortCtrl.signal }); }
      catch (_e) { /* aborted — loop condition will catch it */ }
    }
    while (!state.cancelled) {
      // Don't lease more than (concurrency - inFlight) at a time
      var slots = concurrency - state.inFlight.size;
      if (slots <= 0) {
        await _pollSleep(fastPollMs);
        continue;
      }
      // If rate-limited and we'd exceed the budget, sleep until the
      // next slot opens. We lease at most `max - currentTokens` jobs to
      // stay under the cap.
      if (rateLimit) {
        var wait = _rateLimitWaitMs();
        if (wait > 0) {
          await _pollSleep(Math.min(wait, pollIntervalMs));
          continue;
        }
        var remainingTokens = rateLimit.max - rateLimit.timestamps.length;
        if (remainingTokens < slots) slots = Math.max(1, remainingTokens);
      }
      var jobs;
      try { jobs = await b.lease(queueName, leaseDurationMs, slots); }
      catch {
        // Backend down (breaker open, etc.) — back off
        await _pollSleep(pollIntervalMs);
        continue;
      }
      if (!jobs || jobs.length === 0) {
        await _pollSleep(pollIntervalMs);
        continue;
      }
      for (var i = 0; i < jobs.length; i++) {
        observability.event("queue.lease", 1, { queueName: queueName });
        (function (job) {
          state.inFlight.add(job.jobId);
          _emit("system.queue.consume.start", {
            metadata: { queue: queueName, backend: b.name, jobId: job.jobId, attempt: job.attempts, traceId: job.traceId },
          });
          // Consume a rate-limit slot at handler-start so the budget
          // tracks invocation rate, not lease rate (a single lease that
          // splits work across many sub-units doesn't double-count).
          _rateLimitConsume();

          // Handler context — second arg to handler. Carries
          // ctx.extendLease(ms) for long-running handlers and
          // ctx.progress(0..100) for surfacing job progress to the
          // audit chain (rate-limited so chatty handlers don't drown it).
          var lastProgressEmitAt = 0;
          var lastProgressValue = -1;
          var ctx = {
            extendLease: function (additionalMs) {
              if (typeof b.extendLease !== "function") {
                throw _err("EXTEND_LEASE_UNSUPPORTED",
                  "queue backend '" + b.name + "' does not support extendLease",
                  true);
              }
              return b.extendLease(job.jobId, additionalMs).then(function (ok) {
                if (ok) {
                  _emit("system.queue.lease.extended", {
                    metadata: { queue: queueName, backend: b.name, jobId: job.jobId, additionalMs: additionalMs },
                  });
                }
                return ok;
              });
            },
            progress: function (pct) {
              if (typeof pct !== "number" || !isFinite(pct)) return;
              var clamped = Math.max(0, Math.min(100, Math.floor(pct)));
              var now = Date.now();
              // Always emit 0 and 100 (start/done markers); throttle the rest.
              var isMarker = clamped === 0 || clamped === 100;
              if (!isMarker && (now - lastProgressEmitAt) < PROGRESS_MIN_INTERVAL_MS) return;
              if (clamped === lastProgressValue && !isMarker) return;
              lastProgressEmitAt = now;
              lastProgressValue = clamped;
              observability.event("queue.progress", clamped, { queueName: queueName });
              _emit("system.queue.progress", {
                metadata: {
                  queue: queueName, backend: b.name, jobId: job.jobId,
                  attempt: job.attempts, traceId: job.traceId,
                  percent: clamped,
                },
              });
            },
          };
          observability.tap("queue.consume",
            { queueName: queueName, backend: b.name, jobId: job.jobId, attempt: job.attempts },
            function () {
              return Promise.resolve()
                .then(function () { return handler(job, ctx); })
                .then(function () {
                  return b.complete(job.jobId).then(function () {
                    _emit("system.queue.consume.success", {
                      metadata: { queue: queueName, backend: b.name, jobId: job.jobId, attempt: job.attempts, traceId: job.traceId },
                    });
                    observability.event("queue.complete", 1, { queueName: queueName });
                  });
                }, function (err) {
              var msg = (err && err.message) || String(err);
              var willRetry = job.attempts < job.maxAttempts;
              return b.fail(job.jobId, msg, { retryDelayMs: _backoffDelay(job.attempts) })
                .then(function () {
                  observability.event("queue.fail", 1, { queueName: queueName, willRetry: willRetry });
                  _emit("system.queue.consume.failure", {
                    metadata: {
                      queue:    queueName, backend: b.name, jobId: job.jobId,
                      attempt:  job.attempts, traceId: job.traceId,
                      maxAttempts: job.maxAttempts, willRetry: willRetry,
                    },
                    reason:   msg,
                    outcome:  "failure",
                  });
                  // DLQ-write event when the job has exhausted its retries.
                  // Operators wire this to their alerting / dashboards
                  // — failed-after-retries is "needs human review" not
                  // "in the normal flow." Audit chain captures the
                  // final state for forensics.
                  if (!willRetry) {
                    _emit("system.queue.dlq.write", {
                      metadata: {
                        queue: queueName, backend: b.name, jobId: job.jobId,
                        attempts: job.attempts, traceId: job.traceId,
                      },
                      reason:  msg,
                      outcome: "failure",
                    });
                  }
                });
            })
            .catch(function (_e) { /* lifecycle errors swallowed — operator sees via audit */ })
            .then(function () { state.inFlight.delete(job.jobId); });
            }
          );
        })(jobs[i]);
      }
      await _pollSleep(fastPollMs);
    }
  })();

  return state;
}

var _QUEUE_BACKOFF_OPTS = {
  baseDelayMs:  C.TIME.seconds(1),
  maxDelayMs:   C.TIME.minutes(5),
  jitterFactor: 0,                    // queue uses deterministic backoff (no jitter) for predictability
};
function _backoffDelay(attempt) {
  return retryHelper.backoffDelay(attempt, _QUEUE_BACKOFF_OPTS);
}

function size(queueName, opts) {
  _requireInit();
  return _backendFor(opts).size(queueName);
}

function purge(queueName, opts) {
  _requireInit();
  var b = _backendFor(opts);
  return b.purge(queueName).then(function (n) {
    _emit("system.queue.purge", {
      metadata: { queue: queueName, backend: b.name, deleted: n },
    });
    return n;
  });
}

// ---- Dead-letter queue ----
//
// `dlqList` returns failed-after-retries jobs for operator review;
// `dlqRetry` resets a single job back to 'pending' so it gets picked
// up by consumers again (operator-driven — never automatic).

function dlqList(queueName, opts) {
  _requireInit();
  var b = _backendFor(opts);
  if (typeof b.dlqList !== "function") {
    return Promise.reject(_err("DLQ_UNSUPPORTED",
      "queue backend '" + b.name + "' does not support dlqList", true));
  }
  return b.dlqList(queueName, opts);
}

function dlqRetry(jobId, opts) {
  _requireInit();
  var b = _backendFor(opts);
  if (typeof b.dlqRetry !== "function") {
    return Promise.reject(_err("DLQ_UNSUPPORTED",
      "queue backend '" + b.name + "' does not support dlqRetry", true));
  }
  return b.dlqRetry(jobId).then(function (ok) {
    if (ok) {
      _emit("system.queue.dlq.retry", {
        metadata: { jobId: jobId, backend: b.name },
      });
    }
    return ok;
  });
}

function dlqSize(queueName, opts) {
  _requireInit();
  var b = _backendFor(opts);
  if (typeof b.dlqSize !== "function") {
    return Promise.reject(_err("DLQ_UNSUPPORTED",
      "queue backend '" + b.name + "' does not support dlqSize", true));
  }
  return b.dlqSize(queueName);
}

async function shutdown(opts) {
  if (!initialized) return;
  opts = opts || {};
  var timeoutMs = opts.timeoutMs != null ? opts.timeoutMs : C.TIME.seconds(30);
  // Signal all consumers to stop
  consumers.forEach(function (c) { c.cancel(); });
  // Wait for in-flight handlers to complete
  var deadline = Date.now() + timeoutMs;
  while (consumers.some(function (c) { return c.inFlight.size > 0; })) {
    if (Date.now() > deadline) break;
    await safeAsync.sleep(50);
  }
  consumers = [];
  if (sweepTimer) { sweepTimer.stop(); sweepTimer = null; }
}

function listBackends() {
  _requireInit();
  return Object.keys(backends).map(function (name) {
    return { name: name, protocol: backends[name].protocol, breakerState: backends[name].breaker.getState() };
  });
}

function _emit(action, info) {
  audit().safeEmit({ action: action, ...(info || {}) });
}

function _requireInit() {
  if (!initialized) throw _err("NOT_INITIALIZED", "queue.init() must be called first", true);
}

function _resetForTest() {
  if (sweepTimer) { sweepTimer.stop(); sweepTimer = null; }
  consumers.forEach(function (c) { c.cancel(); });
  consumers = [];
  backends = {};
  defaultBackend = null;
  initialized = false;
  audit.reset();
}

// enqueueFlow — atomic registration of a parent-child job graph.
//
//   await b.queue.enqueueFlow({
//     queueName: "ingest",
//     children: [
//       { name: "fetch",      payload: { url } },
//       { name: "transform",  payload: { ... }, dependsOn: ["fetch"] },
//       { name: "publish",    payload: { ... }, dependsOn: ["transform"] },
//     ],
//   });
//
// Cycle detection runs at registration (throws at call site). Each child enters
// the queue with availableAt = MAX_SAFE_INTEGER until parent completion
// bumps it. Returns { flowId, jobs: [{ name, jobId }, ...] }.
function enqueueFlow(spec) {
  _requireInit();
  if (!spec || typeof spec !== "object") {
    return Promise.reject(_err("BAD_FLOW", "enqueueFlow requires an opts object", true));
  }
  if (typeof spec.queueName !== "string" || !spec.queueName) {
    return Promise.reject(_err("BAD_FLOW", "enqueueFlow requires queueName", true));
  }
  if (!Array.isArray(spec.children) || spec.children.length === 0) {
    return Promise.reject(_err("BAD_FLOW", "enqueueFlow requires children: [...]", true));
  }
  // Validate each child's shape.
  var byName = {};
  for (var i = 0; i < spec.children.length; i++) {
    var c = spec.children[i];
    if (!c || typeof c !== "object") {
      return Promise.reject(_err("BAD_FLOW", "children[" + i + "] must be an object", true));
    }
    if (typeof c.name !== "string" || !c.name) {
      return Promise.reject(_err("BAD_FLOW", "children[" + i + "].name must be a non-empty string", true));
    }
    if (byName[c.name]) {
      return Promise.reject(_err("BAD_FLOW", "duplicate child name '" + c.name + "'", true));
    }
    byName[c.name] = c;
    if (c.dependsOn !== undefined) {
      if (!Array.isArray(c.dependsOn)) {
        return Promise.reject(_err("BAD_FLOW",
          "children[" + i + "].dependsOn must be an array of names", true));
      }
      for (var di = 0; di < c.dependsOn.length; di++) {
        if (typeof c.dependsOn[di] !== "string") {
          return Promise.reject(_err("BAD_FLOW",
            "children[" + i + "].dependsOn[" + di + "] must be a string name", true));
        }
      }
    }
  }
  // Cycle detection — depth-first traversal with visited set.
  function _visit(name, stack) {
    if (stack.indexOf(name) !== -1) {
      throw _err("FLOW_CYCLE", "flow cycle detected: " +
        stack.concat([name]).join(" → "), true);
    }
    var child = byName[name];
    if (!child || !child.dependsOn) return;
    var nextStack = stack.concat([name]);
    for (var k = 0; k < child.dependsOn.length; k++) {
      var dep = child.dependsOn[k];
      if (!byName[dep]) {
        throw _err("FLOW_UNKNOWN_DEP",
          "child '" + name + "' dependsOn unknown name '" + dep + "'", true);
      }
      _visit(dep, nextStack);
    }
  }
  try {
    var names = Object.keys(byName);
    for (var n = 0; n < names.length; n++) _visit(names[n], []);
  } catch (e) {
    return Promise.reject(e);
  }

  var flowId = "flow-" + crypto.generateToken(C.BYTES.bytes(8));

  return observability.tap("queue.enqueueFlow",
    { queueName: spec.queueName, flowId: flowId, childCount: spec.children.length },
    async function () {
      var jobs = [];
      // Two-pass insert: first pass enqueues all children with their
      // names attached so the second pass can write dependsOn jobIds
      // resolved by name. Children with deps land at MAX_SAFE_INTEGER
      // availableAt automatically (see queue-local enqueue logic).
      var nameToJobId = {};
      for (var p = 0; p < spec.children.length; p++) {
        var ch = spec.children[p];
        // Hold off setting dependsOn until we know all sibling jobIds.
        var enqOpts = {
          flowId:        flowId,
          flowChildName: ch.name,
          priority:      ch.priority || 0,
          classification: ch.classification || null,
          traceId:       ch.traceId || null,
          maxAttempts:   ch.maxAttempts,
          // dependsOn intentionally omitted on first pass — will be patched
          // in via direct UPDATE after all jobIds are known. This means
          // root children (no deps) are immediately leaseable; deps-bearing
          // children get patched to MAX_SAFE_INTEGER via second pass.
        };
        var result = await enqueue(spec.queueName, ch.payload, enqOpts);
        nameToJobId[ch.name] = result.jobId;
        jobs.push({ name: ch.name, jobId: result.jobId, dependsOn: ch.dependsOn || [] });
      }
      // Second pass: write dependsOn (translated to jobIds) for children
      // that need it, and parking-lot their availableAt to MAX_SAFE_INTEGER.
      for (var q = 0; q < jobs.length; q++) {
        var j = jobs[q];
        if (j.dependsOn.length === 0) continue;
        var depIds = j.dependsOn.map(function (n2) { return nameToJobId[n2]; });
        await clusterStorage.execute(
          "UPDATE _blamejs_jobs SET dependsOn = ?, availableAt = ? WHERE _id = ?",
          [JSON.stringify(depIds), Number.MAX_SAFE_INTEGER, j.jobId]
        );
      }
      _emit("system.queue.flow.enqueue", {
        metadata: {
          queue:      spec.queueName,
          flowId:     flowId,
          childCount: spec.children.length,
        },
      });
      return { flowId: flowId, jobs: jobs.map(function (j) { return { name: j.name, jobId: j.jobId }; }) };
    }
  );
}

// bootFromEnv — env-driven init mirroring b.network.bootFromEnv and
// b.logStream.bootFromEnv. Reads the BLAMEJS_QUEUE_* env vars and
// calls queue.init({ backends }) accordingly. Operators get a working
// queue backend without writing build-app code.
//
//   BLAMEJS_QUEUE_PROTOCOL          local | redis              (default: local)
//   BLAMEJS_QUEUE_REDIS_URL         redis://host:port/db       (required when protocol=redis)
//   BLAMEJS_QUEUE_REDIS_PASSWORD    auth password
//   BLAMEJS_QUEUE_REDIS_USERNAME    ACL username (optional)
//   BLAMEJS_QUEUE_REDIS_TLS         "1"/"true" forces TLS (else inferred from rediss://)
//   BLAMEJS_QUEUE_REDIS_KEY_PREFIX  key prefix (default "blamejs:queue")
function bootFromEnv(opts) {
  opts = opts || {};
  var env = opts.env || process.env;
  if (initialized) return;
  var protocol = env.BLAMEJS_QUEUE_PROTOCOL || "local";
  var backendCfg;
  if (protocol === "local") {
    backendCfg = { protocol: "local" };
  } else if (protocol === "redis") {
    var url = env.BLAMEJS_QUEUE_REDIS_URL;
    if (!url) {
      throw _err("INVALID_CONFIG",
        "queue.bootFromEnv: BLAMEJS_QUEUE_REDIS_URL is required when BLAMEJS_QUEUE_PROTOCOL=redis",
        true);
    }
    var tlsRaw = env.BLAMEJS_QUEUE_REDIS_TLS;
    var tls = tlsRaw === "1" || tlsRaw === "true";
    backendCfg = {
      protocol:  "redis",
      url:       url,
      password:  env.BLAMEJS_QUEUE_REDIS_PASSWORD || null,
      username:  env.BLAMEJS_QUEUE_REDIS_USERNAME || null,
      tls:       tlsRaw !== undefined ? tls : undefined,  // undefined → inferred from rediss://
      keyPrefix: env.BLAMEJS_QUEUE_REDIS_KEY_PREFIX || undefined,
    };
  } else {
    throw _err("INVALID_CONFIG",
      "queue.bootFromEnv: BLAMEJS_QUEUE_PROTOCOL must be 'local' or 'redis', got '" + protocol + "'",
      true);
  }
  init({ backends: { default: backendCfg }, defaultBackend: "default" });
}

module.exports = {
  init:               init,
  bootFromEnv:        bootFromEnv,
  enqueue:            enqueue,
  enqueueFlow:        enqueueFlow,
  consume:            consume,
  size:               size,
  purge:              purge,
  shutdown:           shutdown,
  listBackends:       listBackends,
  dlqList:            dlqList,
  dlqRetry:           dlqRetry,
  dlqSize:            dlqSize,
  PROTOCOLS:          dispatcher.protocols,
  DEFERRED_PROTOCOLS: dispatcher.deferred,
  _resetForTest:      _resetForTest,
};
