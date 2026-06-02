"use strict";
/**
 * @module b.queue
 * @nav    Data
 * @title  Queue
 *
 * @intro
 *   Durable, pluggable job queue with priority-aware leasing, retry +
 *   deterministic backoff, graceful shutdown, parent/child flows, and
 *   a dead-letter surface for jobs that exhaust their retries.
 *
 *   Same dispatcher shape as `b.objectStore`: every operator-named
 *   backend declares a `protocol` plus protocol-specific options. The
 *   built-in `local` protocol is SQLite-backed (rows live in the
 *   framework's main DB so persistence survives crashes / restarts
 *   without external infrastructure), and can be pointed at an
 *   operator's own database handle, table, and schema via the `local`
 *   config (`db` / `table` / `schema`). `redis` and `sqs` ship; `amqp`
 *   and `nats` are listed as deferred and surface a clear error if
 *   selected.
 *
 *   `local` and `redis` are driven by the generic `b.queue.consume`
 *   loop and the lifecycle below (framework-side leasing, deterministic
 *   backoff, DLQ, and the sweep timer). `sqs` is an SQS-native adapter
 *   with a different model: `complete` / `fail` delete or re-deliver by
 *   the message's `receiptHandle` (returned by `lease()`, threaded back
 *   by the caller), and DLQ + visibility-expiry are handled server-side
 *   by the SQS queue's RedrivePolicy — so `sqs` is driven directly
 *   (lease → handle → complete/fail), not by `b.queue.consume`, and it
 *   does not use the framework DLQ / sweep described below. See
 *   `lib/queue-sqs.js` for its action map and the features that require
 *   operator wiring.
 *
 *   Job lifecycle:
 *     enqueued (status='pending', availableAt set by delaySeconds)
 *       ↓ availableAt reached + consumer leases
 *     inflight (status='inflight', lease expires after leaseDurationMs)
 *       ↓ handler returns                 ↓ handler throws
 *     done   (status='done')           attempts < maxAttempts:
 *                                        pending (with deterministic backoff)
 *                                      else:
 *                                        failed → DLQ row written
 *
 *   A 30-second sweep timer re-pends inflight rows whose lease expired
 *   without completion (crashed handlers, OOM kills) so no job is
 *   abandoned. Within a single millisecond, higher `priority` jobs
 *   lease before lower-priority ones (deterministic — see
 *   `b.queue.enqueue` opts).
 *
 *   Dead-letter handling: jobs that exhaust `maxAttempts` write a
 *   `system.queue.dlq.write` audit event and stay queryable via
 *   `b.queue.dlqList`. Operator decides whether to retry
 *   (`b.queue.dlqRetry`) — never automatic.
 *
 * @card
 *   Durable, pluggable job queue with priority-aware leasing, retry + deterministic backoff, graceful shutdown, parent/child flows, and a dead-letter surface for jobs that exhaust their retries.
 */
var C = require("./constants");
var bCrypto = require("./crypto");
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

/**
 * @primitive b.queue.init
 * @signature b.queue.init(opts)
 * @since     0.4.0
 * @status    stable
 * @related   b.queue.bootFromEnv, b.queue.shutdown, b.queue.listBackends
 *
 * One-time initialization. Wires every named backend through the
 * protocol dispatcher, wraps mutating ops with the retry helper +
 * circuit breaker, and starts the 30-second expired-lease sweep.
 * Idempotent — calling `init` after the queue is already initialized
 * is a no-op (boot order doesn't have to be exact).
 *
 * Throws when `opts.backends` is missing — operators catch the typo
 * at boot rather than discovering it on first enqueue.
 *
 * The `local` protocol defaults to the framework's own database (the
 * main SQLite in single-node mode, the operator-supplied external DB in
 * cluster mode) and the `_blamejs_jobs` table. An operator who wants the
 * queue rows to live in their own database, table, or schema supplies
 * `db` / `table` / `schema` in the `local` backend config. The `db`
 * handle must expose the same `execute` / `executeOne` / `executeAll`
 * surface as `b.clusterStorage`; `table` / `schema` are validated as SQL
 * identifiers and quoted through `b.safeSql` (an identifier that isn't a
 * safe name is refused at `init` time, not interpolated into SQL).
 * Sealed columns (`payload`, `lastError`) stay sealed regardless of
 * where the rows land.
 *
 * @opts
 *   backends: {
 *     [name: string]: {
 *       protocol:  "local" | "redis" | "sqs",
 *       breaker?:  { ... },   // see b.retry.CircuitBreaker opts
 *       retry?:    { ... },   // see b.retry.withRetry opts
 *       // local protocol — bring-your-own database (all optional):
 *       db?:       object,    // store handle (execute/executeOne/executeAll); default cluster-storage
 *       table?:    string,    // table name (validated + quoted); default "_blamejs_jobs"
 *       schema?:   string,    // schema/namespace qualifier (validated + quoted)
 *       // ...other protocol-specific opts (e.g. redis url, sqs queueUrl)
 *     },
 *   },
 *   defaultBackend?: string,  // name to use when enqueue/consume omit { backend }
 *
 * @example
 *   b.queue.init({
 *     backends: {
 *       primary: { protocol: "local" },
 *       app:     { protocol: "local", table: "app_jobs", schema: "work" },
 *     },
 *     defaultBackend: "primary",
 *   });
 *   b.queue.listBackends();
 *   // → [{ name: "primary", protocol: "local", breakerState: "closed" }, ...]
 */
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
      patchFlowDeps: raw.patchFlowDeps ? wrapWithRetry(raw.patchFlowDeps) : null,
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

/**
 * @primitive b.queue.enqueue
 * @signature b.queue.enqueue(queueName, payload, opts)
 * @since     0.4.0
 * @status    stable
 * @related   b.queue.consume, b.queue.enqueueFlow, b.queue.size
 *
 * Persists a single job to the named queue and returns a promise that
 * resolves with the assigned `jobId`. The job's `payload` is stored
 * verbatim by the backend (the `local` protocol JSON-encodes; redis
 * and sqs follow their wire formats). Resolves before any consumer
 * actually leases the job — `enqueue` is durable handoff, not
 * synchronous execution.
 *
 * Higher `priority` jobs lease ahead of lower ones within the same
 * `availableAt` window. `delaySeconds` parks the job until the
 * timestamp arrives. `maxAttempts` overrides the queue default; on
 * the final attempt the job moves to the dead-letter view rather
 * than retrying again.
 *
 * @opts
 *   backend?:        string,   // backend name; defaults to defaultBackend
 *   priority?:       number,   // higher leases first (default 0)
 *   delaySeconds?:   number,   // park before becoming leaseable
 *   maxAttempts?:    number,   // retries before DLQ (backend default applies)
 *   classification?: string,   // operator metadata, surfaced in audit
 *   traceId?:        string,   // cross-request correlation id
 *
 * @example
 *   var result = await b.queue.enqueue("ingest", { url: "https://example.com" }, {
 *     priority:     5,
 *     maxAttempts:  3,
 *   });
 *   result.jobId;
 *   // → "job-7c2f8e1a..."
 */
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

/**
 * @primitive b.queue.consume
 * @signature b.queue.consume(queueName, handler, opts)
 * @since     0.4.0
 * @status    stable
 * @related   b.queue.enqueue, b.queue.shutdown, b.queue.dlqRetry
 *
 * Starts a long-running consumer that leases jobs and runs them
 * through `handler(job, ctx)`. Handler resolution marks the job
 * `done`; rejection bumps the attempt counter and either re-pends
 * with deterministic exponential backoff (1s base, 5min cap, no
 * jitter) or routes to the DLQ when `attempts >= maxAttempts`. This
 * loop drives the `local` and `redis` backends; the `sqs` backend uses
 * SQS-native receipt-handle complete/fail and server-side redrive and
 * is driven directly rather than by this consumer (see the module
 * intro).
 *
 * Returns a consumer state handle whose `.cancel()` aborts the poll
 * loop immediately (without waiting for the next `pollIntervalMs`
 * tick) and stops leasing new work. In-flight handlers complete on
 * their own; `b.queue.shutdown` waits for them with a deadline.
 *
 * `ctx` carries `extendLease(additionalMs)` for long-running
 * handlers about to overrun their lease, and `progress(0..100)` for
 * audit-chain progress markers (rate-limited so a chatty handler
 * can't flood the chain).
 *
 * @opts
 *   backend?:         string,   // backend name; defaults to defaultBackend
 *   concurrency?:     number,   // max in-flight handlers (default 1)
 *   leaseDurationMs?: number,   // lease window before sweep re-pends (default 30s)
 *   pollIntervalMs?:  number,   // idle backoff between empty leases (default 1s)
 *   fastPollMs?:      number,   // delay between non-empty lease batches (default 50ms)
 *   rateLimit?: {
 *     max:        number,       // positive integer
 *     perSeconds: number,       // positive finite seconds
 *   },
 *
 * @example
 *   var consumer = b.queue.consume("ingest", async function (job, ctx) {
 *     ctx.progress(10);
 *     // ...do work...
 *     ctx.progress(100);
 *   }, { concurrency: 4 });
 *
 *   // Later, on shutdown signal:
 *   consumer.cancel();
 */
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
      catch (e) {
        // Backend down (breaker open, etc.) — log + back off so a flapping
        // backend that hasn't yet tripped the breaker is still visible.
        log.debug("lease-failed", { op: "b.lease", queue: queueName, error: e.message });
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

/**
 * @primitive b.queue.size
 * @signature b.queue.size(queueName, opts)
 * @since     0.4.0
 * @status    stable
 * @related   b.queue.dlqSize, b.queue.purge
 *
 * Resolves with the number of pending + inflight jobs in the queue —
 * the live backlog. Excludes `done` and `failed` rows. Operators wire
 * this to dashboards and autoscalers.
 *
 * @opts
 *   backend?: string,   // backend name; defaults to defaultBackend
 *
 * @example
 *   var pending = await b.queue.size("ingest");
 *   // → 42
 */
function size(queueName, opts) {
  _requireInit();
  return _backendFor(opts).size(queueName);
}

/**
 * @primitive b.queue.purge
 * @signature b.queue.purge(queueName, opts)
 * @since     0.4.0
 * @status    stable
 * @related   b.queue.size, b.queue.dlqList
 *
 * Deletes every job in the named queue and resolves with the deleted
 * count. Emits a `system.queue.purge` audit event for forensic
 * traceability. Use during operator-driven cleanups; never in normal
 * traffic — purged jobs are not recoverable.
 *
 * @opts
 *   backend?: string,   // backend name; defaults to defaultBackend
 *
 * @example
 *   var deleted = await b.queue.purge("ingest");
 *   // → 42
 */
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

/**
 * @primitive b.queue.dlqList
 * @signature b.queue.dlqList(queueName, opts)
 * @since     0.4.0
 * @status    stable
 * @related   b.queue.dlqRetry, b.queue.dlqSize
 *
 * Resolves with an array of dead-letter rows — jobs that exhausted
 * their retries and were parked for human review. Each row carries
 * the original payload, attempt count, last failure reason, and
 * trace correlation id. Rejects with `DLQ_UNSUPPORTED` when the
 * configured backend does not implement a dead-letter view.
 *
 * @opts
 *   backend?: string,   // backend name; defaults to defaultBackend
 *   limit?:   number,   // backend-specific paging cap
 *
 * @example
 *   var dead = await b.queue.dlqList("ingest", { limit: 50 });
 *   dead.length;
 *   // → 3
 */
function dlqList(queueName, opts) {
  _requireInit();
  var b = _backendFor(opts);
  if (typeof b.dlqList !== "function") {
    return Promise.reject(_err("DLQ_UNSUPPORTED",
      "queue backend '" + b.name + "' does not support dlqList", true));
  }
  return b.dlqList(queueName, opts);
}

/**
 * @primitive b.queue.dlqRetry
 * @signature b.queue.dlqRetry(jobId, opts)
 * @since     0.4.0
 * @status    stable
 * @related   b.queue.dlqList, b.queue.dlqSize
 *
 * Resets a single dead-letter row back to `pending` so consumers
 * pick it up again. Operator-driven only — the framework never
 * auto-retries failed-after-retries jobs because the failure mode
 * usually requires human investigation. Resolves with `true` when
 * the row was found and reset, `false` otherwise.
 *
 * @opts
 *   backend?: string,   // backend name; defaults to defaultBackend
 *
 * @example
 *   var ok = await b.queue.dlqRetry("job-7c2f8e1a");
 *   // → true
 */
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

/**
 * @primitive b.queue.dlqSize
 * @signature b.queue.dlqSize(queueName, opts)
 * @since     0.4.0
 * @status    stable
 * @related   b.queue.dlqList, b.queue.dlqRetry
 *
 * Resolves with the number of dead-letter rows for the named queue —
 * jobs that exhausted their retries and were parked for human review.
 * Operators wire this to dashboards / alerting so a growing DLQ
 * surfaces before it becomes a backlog. Rejects with `DLQ_UNSUPPORTED`
 * when the configured backend does not implement a dead-letter view.
 *
 * @opts
 *   backend?: string,   // backend name; defaults to defaultBackend
 *
 * @example
 *   var stuck = await b.queue.dlqSize("ingest");
 *   // → 3
 */
function dlqSize(queueName, opts) {
  _requireInit();
  var b = _backendFor(opts);
  if (typeof b.dlqSize !== "function") {
    return Promise.reject(_err("DLQ_UNSUPPORTED",
      "queue backend '" + b.name + "' does not support dlqSize", true));
  }
  return b.dlqSize(queueName);
}

/**
 * @primitive b.queue.shutdown
 * @signature b.queue.shutdown(opts)
 * @since     0.4.0
 * @status    stable
 * @related   b.queue.consume, b.queue.init
 *
 * Cancels every active consumer and waits for in-flight handlers to
 * drain, then stops the expired-lease sweep timer. Honors a deadline
 * — handlers that exceed `timeoutMs` are abandoned (their leases
 * expire and the sweep re-pends them on the next process). Idempotent
 * — calling `shutdown` before `init` is a no-op so SIGTERM handlers
 * can be wired unconditionally.
 *
 * @opts
 *   timeoutMs?: number,   // drain deadline in ms (default 30000)
 *
 * @example
 *   process.on("SIGTERM", async function () {
 *     await b.queue.shutdown({ timeoutMs: 15000 });
 *   });
 */
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

/**
 * @primitive b.queue.listBackends
 * @signature b.queue.listBackends()
 * @since     0.4.0
 * @status    stable
 * @related   b.queue.init, b.queue.bootFromEnv
 *
 * Returns an array of `{ name, protocol, breakerState }` rows — one
 * per configured backend. `breakerState` is `"closed"` / `"open"` /
 * `"half-open"` from the per-backend circuit breaker. Operators wire
 * this to a `/health/queue` endpoint or readiness probe so a tripped
 * breaker surfaces in the orchestrator before silent backlog growth.
 *
 * @example
 *   var status = b.queue.listBackends();
 *   // → [{ name: "primary", protocol: "local", breakerState: "closed" }]
 */
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

/**
 * @primitive b.queue.enqueueFlow
 * @signature b.queue.enqueueFlow(spec)
 * @since     0.4.0
 * @status    stable
 * @related   b.queue.enqueue, b.queue.consume
 *
 * Atomically registers a parent-child job graph. Each child enqueues
 * with a parking-lot `availableAt = MAX_SAFE_INTEGER` until every
 * `dependsOn` row reaches `done`, at which point the dependent's
 * availableAt drops to "now" and consumers pick it up. Cycle detection
 * runs at registration time — bad graphs reject with `FLOW_CYCLE` /
 * `FLOW_UNKNOWN_DEP` before any row lands.
 *
 * Resolves with `{ flowId, jobs: [{ name, jobId }, ...] }`. The
 * returned `jobId` array is in declaration order, not topological
 * order — callers that need a specific child's id look it up by
 * `name`.
 *
 * @opts
 *   queueName: string,
 *   children: [
 *     {
 *       name:            string,           // unique within the flow
 *       payload:         any,
 *       dependsOn?:      string[],         // sibling names this child waits on
 *       priority?:       number,
 *       maxAttempts?:    number,
 *       classification?: string,
 *       traceId?:        string,
 *     },
 *     ...
 *   ],
 *
 * @example
 *   var flow = await b.queue.enqueueFlow({
 *     queueName: "ingest",
 *     children: [
 *       { name: "fetch",     payload: { url: "https://example.com" } },
 *       { name: "transform", payload: { stage: 1 }, dependsOn: ["fetch"] },
 *       { name: "publish",   payload: { topic: "out" }, dependsOn: ["transform"] },
 *     ],
 *   });
 *   flow.jobs.length;
 *   // → 3
 */
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

  var flowId = "flow-" + bCrypto.generateToken(C.BYTES.bytes(8));

  // Resolve the backend up front so the second-pass dependsOn patch
  // targets the SAME backend (and its configured store + table) that the
  // first-pass enqueue wrote to. A backend pointed at a bring-your-own
  // table must receive the flow graph through its own writer, not a
  // dispatcher-level write to the default jobs table.
  var flowBackend = _backendFor(spec);
  if (typeof flowBackend.patchFlowDeps !== "function") {
    return Promise.reject(_err("FLOW_UNSUPPORTED",
      "queue backend '" + flowBackend.name + "' does not support enqueueFlow", true));
  }

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
          backend:       flowBackend.name,
          flowId:        flowId,
          flowChildName: ch.name,
          priority:      ch.priority || 0,
          classification: ch.classification || null,
          traceId:       ch.traceId || null,
          maxAttempts:   ch.maxAttempts,
          // dependsOn intentionally omitted on first pass — will be patched
          // in via the backend's patchFlowDeps after all jobIds are known.
          // Root children (no deps) are immediately leaseable; deps-bearing
          // children get parked at MAX_SAFE_INTEGER via the second pass.
        };
        var result = await enqueue(spec.queueName, ch.payload, enqOpts);
        nameToJobId[ch.name] = result.jobId;
        jobs.push({ name: ch.name, jobId: result.jobId, dependsOn: ch.dependsOn || [] });
      }
      // Second pass: write dependsOn (translated to jobIds) for children
      // that need it, and parking-lot their availableAt to MAX_SAFE_INTEGER.
      // Routed through the backend's writer so it lands in the backend's
      // configured store + table (bring-your-own DB safe).
      for (var q = 0; q < jobs.length; q++) {
        var j = jobs[q];
        if (j.dependsOn.length === 0) continue;
        var depIds = j.dependsOn.map(function (n2) { return nameToJobId[n2]; });
        await flowBackend.patchFlowDeps(j.jobId, depIds);
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

/**
 * @primitive b.queue.bootFromEnv
 * @signature b.queue.bootFromEnv(opts)
 * @since     0.4.0
 * @status    stable
 * @related   b.queue.init, b.queue.listBackends
 *
 * Env-driven `init` mirroring `b.network.bootFromEnv` and
 * `b.logStream.bootFromEnv`. Reads `BLAMEJS_QUEUE_*` and calls
 * `queue.init({ backends: { default: ... } })` so operators get a
 * working queue without writing build-app code. Idempotent — a
 * second call after `init` already ran is a no-op.
 *
 * Recognized env vars:
 *   BLAMEJS_QUEUE_PROTOCOL          "local" | "redis"  (default "local")
 *   BLAMEJS_QUEUE_REDIS_URL         redis://host:port/db (required when protocol=redis)
 *   BLAMEJS_QUEUE_REDIS_PASSWORD    auth password
 *   BLAMEJS_QUEUE_REDIS_USERNAME    ACL username
 *   BLAMEJS_QUEUE_REDIS_TLS         "1" / "true" forces TLS (else inferred from rediss://)
 *   BLAMEJS_QUEUE_REDIS_KEY_PREFIX  key prefix (default "blamejs:queue")
 *
 * Throws `INVALID_CONFIG` when `BLAMEJS_QUEUE_PROTOCOL` is unknown
 * or when `redis` is selected without `BLAMEJS_QUEUE_REDIS_URL` —
 * operators catch the typo at boot rather than first enqueue.
 *
 * @opts
 *   env?: object,   // override process.env for testing / fixtures
 *
 * @example
 *   process.env.BLAMEJS_QUEUE_PROTOCOL = "local";
 *   b.queue.bootFromEnv();
 *   b.queue.listBackends().length;
 *   // → 1
 */
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
