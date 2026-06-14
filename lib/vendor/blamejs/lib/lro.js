"use strict";
/**
 * @module b.lro
 * @nav    HTTP
 * @title  Long-Running Operations
 * @order  178
 *
 * @intro
 *   Google API Improvement Proposals AIP-151 (Long-Running Operations)
 *   — a uniform shape for async APIs where the response can't be
 *   computed within the request lifetime. The operator's POST
 *   endpoint returns an Operation resource (`name` / `done` /
 *   `metadata` / `response` | `error`) which the client polls at
 *   `/operations/<name>` until `done: true`. Composes existing
 *   `b.queue` / `b.jobs` for the actual work; this module just
 *   ships the wire-shape + status-poll endpoint helpers.
 *
 *   `b.lro.create(opts)` returns `{ submit, status, list, cancel }`
 *   wired to operator-supplied storage (in-memory by default for
 *   single-process; ops with multiple workers wire `b.cache` /
 *   `b.db` storage via `opts.store`).
 *
 * @card
 *   AIP-151 Long-Running Operations — uniform Operation resource shape + submit / status / cancel endpoints. Composes b.queue / b.jobs for the actual work.
 */

var validateOpts = require("./validate-opts");
var numericBounds = require("./numeric-bounds");
var bCrypto      = require("./crypto");
var C            = require("./constants");
var { defineClass } = require("./framework-error");

var LroError = defineClass("LroError", { alwaysPermanent: true });

/**
 * @primitive b.lro.create
 * @signature b.lro.create(opts?)
 * @since     0.10.16
 * @status    stable
 *
 * Create an LRO registry. Returns `{ submit, status, list, cancel }`.
 * Operations are tracked in `opts.store` (a Map-shaped object) or an
 * in-memory Map when omitted. `submit({ work, metadata?, name? })`
 * runs `work` async + returns the initial Operation resource;
 * `status(name)` returns the current Operation (with `done: true`
 * + `response` or `error` set when finished); `cancel(name)`
 * surfaces cancellation back to the work function via the supplied
 * AbortSignal.
 *
 * @opts
 *   store:        Map-like { get, set, delete, keys },
 *   namePrefix:   string, // default "operations/"
 *   maxConcurrent: number, // soft cap; overflow refuses with lro/too-many
 *
 * @example
 *   var lro = b.lro.create();
 *   var op = await lro.submit({
 *     work: async function (signal) { return await heavyJob(signal); },
 *   });
 *   res.statusCode = 202;
 *   res.end(JSON.stringify(op));
 *
 *   // Later, on GET /operations/<name>:
 *   res.end(JSON.stringify(lro.status(op.name)));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, ["store", "namePrefix", "maxConcurrent"],
    "lro.create");
  var store = opts.store || new Map();
  var prefix = opts.namePrefix || "operations/";
  numericBounds.requirePositiveFiniteIntIfPresent(opts.maxConcurrent, "maxConcurrent",
    LroError, "lro/bad-max-concurrent");
  var maxConcurrent = typeof opts.maxConcurrent === "number" ? opts.maxConcurrent : 1024;             // default in-flight cap

  function _newName() { return prefix + bCrypto.generateToken(32); }                                  // 32-char name token

  function submit(submitOpts) {
    submitOpts = validateOpts.requireObject(submitOpts, "lro.submit",
      LroError, "lro/bad-opts");
    if (typeof submitOpts.work !== "function") {
      throw new LroError("lro/no-work",
        "submit: opts.work must be a function (signal) => Promise<result>");
    }
    var inFlight = 0;
    var keys = store.keys ? Array.from(store.keys()) : [];
    for (var i = 0; i < keys.length; i += 1) {
      var op = store.get(keys[i]);
      if (op && !op.done) inFlight += 1;
    }
    if (inFlight >= maxConcurrent) {
      throw new LroError("lro/too-many",
        "submit: " + inFlight + " operations in flight (cap " + maxConcurrent + ")");
    }
    var name = submitOpts.name || _newName();
    var controller = (typeof AbortController === "function") ? new AbortController() : null;
    var operation = {
      name:     name,
      done:     false,
      metadata: submitOpts.metadata || {},
      createdAt: new Date().toISOString(),
    };
    store.set(name, operation);
    // Kick off the work async. Operator-supplied function MUST accept
    // an AbortSignal (or ignore it). Errors land on operation.error;
    // successful results land on operation.response per AIP-151 shape.
    Promise.resolve()
      .then(function () { return submitOpts.work(controller ? controller.signal : null); })
      .then(function (response) {
        var stored = store.get(name);
        if (!stored) return;
        // Cancellation precedes resolve — if `cancel()` flipped the
        // operation to CANCELLED first AND the work function ignored
        // the AbortSignal, do NOT overwrite the cancelled terminal
        // state. AIP-151 §6.x: once an operation is `done: true`, it
        // stays done with the first terminal state it landed in.
        if (stored.done) return;
        stored.done = true;
        stored.response = (response === undefined) ? null : response;
        stored.completedAt = new Date().toISOString();
      }, function (err) {
        var stored = store.get(name);
        if (!stored) return;
        // Same guard as the resolve path — once terminal, stay terminal.
        if (stored.done) return;
        stored.done = true;
        // AIP-151 error: { code, message, details? } shape.
        var msg = (err && err.message) || String(err);
        stored.error = { code: 13, message: msg };                                                    // google.rpc.Code.INTERNAL = 13
        if (err && err.code) stored.error.errorCode = err.code;
        stored.completedAt = new Date().toISOString();
      });
    // Store the controller against the operation (off-resource, so
    // serialisation doesn't accidentally export it).
    operation._controller = controller;
    return _stripPrivate(operation);
  }

  function status(name) {
    if (typeof name !== "string" || name.length === 0) {
      throw new LroError("lro/bad-name", "status: name must be a non-empty string");
    }
    var op = store.get(name);
    if (!op) {
      throw new LroError("lro/not-found", "status: no operation named '" + name + "'");
    }
    return _stripPrivate(op);
  }

  function list(filter) {
    filter = filter || {};
    var out = [];
    var keys = store.keys ? Array.from(store.keys()) : [];
    for (var i = 0; i < keys.length; i += 1) {
      var op = store.get(keys[i]);
      if (!op) continue;
      if (filter.doneOnly && !op.done) continue;
      if (filter.pendingOnly && op.done) continue;
      out.push(_stripPrivate(op));
    }
    return out;
  }

  function cancel(name) {
    if (typeof name !== "string" || name.length === 0) {
      throw new LroError("lro/bad-name", "cancel: name must be a non-empty string");
    }
    var op = store.get(name);
    if (!op) {
      throw new LroError("lro/not-found", "cancel: no operation named '" + name + "'");
    }
    if (op.done) return _stripPrivate(op);
    if (op._controller) {
      try { op._controller.abort(); } catch (_e) { /* best-effort */ }
    }
    // Mark cancelled per AIP-151 — error.code 1 = CANCELLED.
    op.done = true;
    op.error = { code: 1, message: "operation cancelled" };                                           // google.rpc.Code.CANCELLED = 1
    op.completedAt = new Date().toISOString();
    return _stripPrivate(op);
  }

  void C;
  return { submit: submit, status: status, list: list, cancel: cancel };
}

function _stripPrivate(op) {
  var keys = Object.keys(op);
  var priv = [];
  for (var i = 0; i < keys.length; i += 1) {
    if (keys[i].charAt(0) === "_") priv.push(keys[i]);
  }
  return validateOpts.assignOwnEnumerable({}, op, priv);
}

module.exports = {
  create:    create,
  LroError:  LroError,
};
