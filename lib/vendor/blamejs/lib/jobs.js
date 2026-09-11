// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
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
