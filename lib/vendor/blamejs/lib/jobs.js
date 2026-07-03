// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * jobs — name → handler registry on top of lib/queue.
 *
 * lib/queue handles dispatch (queue backend + lease + retry + breaker
 * + audit emit). lib/jobs is the application-level pattern most apps
 * actually use: register a handler ahead of time, enqueue by name,
 * the framework runs the right code without per-call wiring.
 *
 *   var jobs = b.jobs.create();
 *   jobs.define("send-welcome", async function ({ userId }) { … });
 *   jobs.define("rebuild-index", async function () { … });
 *
 *   await jobs.enqueue("send-welcome", { userId: "u-1" });
 *
 *   await jobs.start();      // consumers running
 *   …
 *   await jobs.shutdown();   // drain in-flight + stop consuming
 *
 * Each defined name maps to one queue (queue named after the job
 * name) with one consumer per jobs instance. Operators wanting
 * higher concurrency for a specific job pass concurrency in the
 * define options.
 *
 * Built on b.queue, which must be initialized first:
 *
 *   b.queue.init({ backends: { primary: { protocol: "local" } } });
 *   var jobs = b.jobs.create();
 *   jobs.define(...);
 *   await jobs.start();
 *
 * createApp wires this for you when opts.jobs is a function — the
 * factory boots queue with the default 'local' backend, instantiates
 * a jobs registry, calls opts.jobs(jobs) so the operator defines
 * handlers, and starts consumption before listen().
 *
 * Public API:
 *
 *   jobs.create(opts?)            → instance
 *     opts.queueBackend           — backend name to dispatch through
 *                                   (default 'primary' — the convention
 *                                    queue.init uses when given a
 *                                    single-backend config)
 *     opts.consumerDefaults       — defaults forwarded to queue.consume
 *                                   ({ concurrency, leaseDurationMs,
 *                                      pollIntervalMs, fastPollMs })
 *     opts.allowUnregisteredEnqueue  default false. When true, jobs.enqueue
 *                                   accepts names not yet defined
 *                                   (useful in test fixtures or for
 *                                    apps that expect lazy handler
 *                                    registration).
 *
 *   jobs.define(name, handler, defineOpts?)
 *     handler signature: async function (job) { … } where job =
 *     { jobId, queueName, payload, attempts, maxAttempts, traceId,
 *       classification, enqueuedAt, leaseExpiresAt }.
 *     defineOpts is forwarded to queue.consume — concurrency etc.
 *     Throws if name is already defined.
 *
 *   await jobs.enqueue(name, payload, enqueueOpts?)
 *     enqueueOpts is forwarded to queue.enqueue — delaySeconds,
 *     maxAttempts, traceId, classification.
 *     Returns { jobId, queueName, enqueuedAt, ... } from queue.enqueue.
 *
 *   await jobs.start()
 *     Begins consuming each defined queue. Idempotent — a second
 *     start() is a no-op once consumers are already running.
 *
 *   await jobs.shutdown(opts?)
 *     Stops consumers, drains in-flight via queue.shutdown.
 *     opts.timeoutMs forwards to queue.shutdown.
 *
 *   jobs.stats()
 *     → { defined: [string], started: boolean }
 */
var { boot } = require("./log");
var queue = require("./queue");
var validateOpts = require("./validate-opts");
var { JobsError } = require("./framework-error");
var boundedMap = require("./bounded-map");

var log = boot("jobs");

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "queueBackend", "consumerDefaults", "allowUnregisteredEnqueue",
  ], "b.jobs");
  var queueBackend     = opts.queueBackend || "primary";
  var consumerDefaults = opts.consumerDefaults || {};
  var allowUnregistered = !!opts.allowUnregisteredEnqueue;

  // name → { handler, defineOpts, consumerHandle (after start) }
  var registry = new Map();
  var started = false;

  var _err = JobsError.factory;

  function define(name, handler, defineOpts) {
    if (typeof name !== "string" || name.length === 0) {
      throw _err("INVALID_NAME", "jobs.define: name must be a non-empty string", true);
    }
    if (typeof handler !== "function") {
      throw _err("INVALID_HANDLER", "jobs.define: handler must be a function", true);
    }
    boundedMap.requireAbsent(registry, name, function () {
      throw _err("DUPLICATE_NAME",
        "jobs.define: '" + name + "' is already defined", true);
    });
    if (started) {
      // Defining after start would mean the new handler doesn't run
      // until the next start cycle. Reject loudly so operators don't
      // wonder why their newly-defined handler is silent.
      throw _err("ALREADY_STARTED",
        "jobs.define: cannot register '" + name + "' after start() — " +
        "define all handlers before calling start()", true);
    }
    registry.set(name, {
      handler:    handler,
      defineOpts: defineOpts || {},
    });
  }

  async function enqueue(name, payload, enqueueOpts) {
    if (typeof name !== "string" || name.length === 0) {
      throw _err("INVALID_NAME", "jobs.enqueue: name must be a non-empty string", true);
    }
    if (!allowUnregistered && !registry.has(name)) {
      throw _err("UNDEFINED_NAME",
        "jobs.enqueue: '" + name + "' has no registered handler. " +
        "Either define(name, handler) first, or pass " +
        "{ allowUnregisteredEnqueue: true } to jobs.create.", true);
    }
    return await queue.enqueue(name, payload, Object.assign(
      { backend: queueBackend },
      enqueueOpts || {}
    ));
  }

  async function start() {
    if (started) return;
    var consumerOpts = Object.assign({ backend: queueBackend }, consumerDefaults);
    registry.forEach(function (entry, name) {
      var perJobOpts = Object.assign({}, consumerOpts, entry.defineOpts);
      entry.consumerHandle = queue.consume(name, entry.handler, perJobOpts);
    });
    started = true;
  }

  async function shutdown(shutdownOpts) {
    if (!started) {
      // Even when not started, queue.shutdown handles its own state.
      try { await queue.shutdown(shutdownOpts); }
      catch (e) { log.debug("shutdown-failed", { op: "queue.shutdown", error: e.message }); }
      return;
    }
    started = false;
    await queue.shutdown(shutdownOpts);
    // Don't clear the registry — operators inspecting stats() after
    // shutdown should still see what was defined; only the running
    // state changes.
  }

  function stats() {
    return {
      defined:  Array.from(registry.keys()),
      started:  started,
    };
  }

  function _resetForTest() {
    registry.clear();
    started = false;
  }

  return {
    define:        define,
    enqueue:       enqueue,
    start:         start,
    shutdown:      shutdown,
    stats:         stats,
    _resetForTest: _resetForTest,
  };
}

module.exports = { create: create };
