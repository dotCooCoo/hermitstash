// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.jobs
 * @nav    Production
 * @title  Jobs
 * @slug   jobs
 *
 * @intro
 *   Named background work: register a handler for a job name, enqueue work
 *   under that name, and start the consumers. It sits on
 *   <code>b.queue</code> and adds the registry, so the name a producer
 *   writes and the handler a consumer runs are checked against each other
 *   rather than agreeing by convention.
 *
 *   Enqueuing a name no handler is registered for is refused, because that
 *   work would sit in the queue and never run while the enqueue call
 *   reported success. A deployment that produces on one node and consumes
 *   on another opens that case deliberately with
 *   <code>allowUnregisteredEnqueue</code>.
 *
 *   Handlers are registered before <code>start()</code> and refused after
 *   it, so the set of consumers a process runs is fixed at the point it
 *   starts running them.
 *
 * @card
 *   Register named background jobs and their handlers, enqueue work against
 *   the names, and run the consumers. An unregistered name is refused
 *   rather than queued for nobody.
 */

var { boot } = require("./log");
var queue = require("./queue");
var validateOpts = require("./validate-opts");
var { JobsError } = require("./framework-error");
var boundedMap = require("./bounded-map");

var log = boot("jobs");

/**
 * @primitive b.jobs.create
 * @signature b.jobs.create(opts?)
 * @since     0.1.66
 * @status    stable
 * @compliance soc2
 * @related   b.queue.enqueue, b.outbox.create
 *
 * Open a job registry and answer the handle to work it. The handle carries
 * `define(name, handler, opts?)`, `enqueue(name, payload, opts?)`,
 * `start()`, `shutdown(opts?)` and `stats()`.
 *
 * `define` refuses a duplicate name and refuses to run after `start()`.
 * `enqueue` refuses a name nothing handles unless
 * `allowUnregisteredEnqueue` is set, which is for the deployment that
 * enqueues on a node that does not consume. `start()` subscribes every
 * registered name and is safe to call twice. `stats()` answers the defined
 * names and whether the consumers are running.
 *
 * Per-job options given to `define` override `consumerDefaults` for that
 * job alone, so one slow job takes a longer timeout without widening it
 * for the rest.
 *
 * @opts
 *   queueBackend:             string,   // b.queue backend name; default "primary"
 *   consumerDefaults:         object,   // consumer options every job starts from
 *   allowUnregisteredEnqueue: boolean,  // default false — enqueue a name nothing handles
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var jobs = b.jobs.create({ consumerDefaults: { concurrency: 4 } });
 *   jobs.define("email.send", async function (payload) {
 *     await b.mail.create().send(payload);
 *   });
 *   await jobs.start();
 *   await jobs.enqueue("email.send", { to: "a@b.test" });
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "queueBackend", "consumerDefaults", "allowUnregisteredEnqueue",
  ], "b.jobs");
  var queueBackend     = opts.queueBackend || "primary";
  var consumerDefaults = opts.consumerDefaults || {};
  validateOpts.optionalBoolean(opts.allowUnregisteredEnqueue,
    "jobs.create: opts.allowUnregisteredEnqueue (whether a job name no handler is registered " +
    "for may be enqueued; anything other than a boolean was read as its truthiness, so the " +
    "string \"false\" admitted them exactly as true does)",
    JobsError, "jobs/bad-opt");
  var allowUnregistered = !!opts.allowUnregisteredEnqueue;

  var registry = new Map();
  var started = false;

  var _err = JobsError.factory;

  function define(name, handler, defineOpts) {
    if (typeof name !== "string" || name.length === 0) {
      throw _err("jobs/invalid-name", "jobs.define: name must be a non-empty string", true);
    }
    if (typeof handler !== "function") {
      throw _err("jobs/invalid-handler", "jobs.define: handler must be a function", true);
    }
    boundedMap.requireAbsent(registry, name, function () {
      throw _err("jobs/duplicate-name",
        "jobs.define: '" + name + "' is already defined", true);
    });
    if (started) {
      throw _err("jobs/already-started",
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
      throw _err("jobs/invalid-name", "jobs.enqueue: name must be a non-empty string", true);
    }
    if (!allowUnregistered && !registry.has(name)) {
      throw _err("jobs/undefined-name",
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
      try { await queue.shutdown(shutdownOpts); }
      catch (e) { log.debug("shutdown-failed", { op: "queue.shutdown", error: e.message }); }
      return;
    }
    started = false;
    await queue.shutdown(shutdownOpts);
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
