// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * @module b.resourceAccessLock
 * @nav    Production
 * @title  Resource Access Lock
 * @slug   resource-access-lock
 *
 * @intro
 *   A switch in front of a resource with three positions: <code>open</code>
 *   allows everything, <code>read-only</code> allows the actions that read,
 *   and <code>locked</code> allows nothing. An incident responder flips it
 *   without a deploy, and every flip and every refusal is audited.
 *
 *   The read set is fixed: <code>read</code>, <code>list</code>,
 *   <code>get</code>, <code>query</code> and <code>read-only</code>. An
 *   action outside it is a write as far as the lock is concerned, so a
 *   name the caller invents is refused under <code>read-only</code> rather
 *   than allowed by a rule that never heard of it.
 *
 * @card
 *   Put a resource into open, read-only or locked without a deploy, and
 *   refuse the actions the current mode does not allow. Every flip and
 *   every refusal is audited.
 */

var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

var ResourceAccessLockError = defineClass("ResourceAccessLockError",
  { alwaysPermanent: true });

var VALID_MODES = Object.freeze({ open: 1, "read-only": 1, locked: 1 });
var READ_ACTIONS = Object.freeze({ read: 1, list: 1, get: 1, query: 1, "read-only": 1 });

/**
 * @primitive b.resourceAccessLock.create
 * @signature b.resourceAccessLock.create(opts)
 * @since     0.8.41
 * @status    stable
 * @compliance soc2, sox-404
 * @related   b.breakGlass.policy.set, b.dualControl.create
 *
 * Open a lock over one named resource. The handle carries `resource`,
 * `mode()`, `set(mode, ctx?)`, `permits(action)` and
 * `assertPermits(action, ctx?)`.
 *
 * `permits` answers the question; `assertPermits` answers it and throws
 * `resource-access-lock/refused` when the answer is no, so a caller that
 * forgets to read the boolean still stops. Both take the action by name,
 * and only `read`, `list`, `get`, `query` and `read-only` count as reads.
 *
 * `set` audits the move with the actor and reason the caller passes, and
 * `assertPermits` audits each refusal, so a timeline shows who narrowed a
 * resource and what was turned away while it was narrowed.
 *
 * Opening the lock throws `resource-access-lock/no-resource` when
 * `resource` is absent or empty, and `resource-access-lock/bad-start-mode`
 * when `startMode` is not one of the three modes above.
 *
 * @opts
 *   resource:  string,   // what the lock is over; required, non-empty
 *   startMode: string,   // "open" (default), "read-only" or "locked"
 *   audit:     boolean,  // default true
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var lock = b.resourceAccessLock.create({ resource: "payouts" });
 *   lock.set("read-only", { actor: "soc-on-call", reason: "IR-2026-0042" });
 *   lock.permits("list");      // → true
 *   lock.permits("transfer");  // → false
 *   lock.assertPermits("transfer");
 *   // throws ResourceAccessLockError "resource-access-lock/refused"
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, ["resource", "startMode", "audit"], "resourceAccessLock.create");
  validateOpts.requireNonEmptyString(opts.resource, "resource",
    ResourceAccessLockError, "resource-access-lock/no-resource");
  var startMode = opts.startMode || "open";
  if (!Object.prototype.hasOwnProperty.call(VALID_MODES, startMode)) {
    throw new ResourceAccessLockError(
      "resource-access-lock/bad-start-mode",
      "startMode must be one of: " + Object.keys(VALID_MODES).join(" / "));
  }
  var auditOn = opts.audit !== false;
  var resource = opts.resource;
  var mode = startMode;

  function _emit(action, outcome, meta) {
    if (!auditOn) return;
    try {
      audit().safeEmit({
        action: action, outcome: outcome,
        metadata: Object.assign({ resource: resource }, meta || {}),
      });
    } catch (_e) { /* audit best-effort */ }
  }

  function permits(action) {
    if (mode === "open") return true;
    if (mode === "locked") return false;
    return !!Object.prototype.hasOwnProperty.call(READ_ACTIONS, action);
  }

  function set(newMode, ctx) {
    ctx = ctx || {};
    if (!Object.prototype.hasOwnProperty.call(VALID_MODES, newMode)) {
      throw new ResourceAccessLockError(
        "resource-access-lock/bad-mode",
        "set: mode must be one of: " + Object.keys(VALID_MODES).join(" / "));
    }
    var prev = mode;
    mode = newMode;
    _emit("resourceaccesslock.mode_changed", "success", {
      from: prev, to: newMode,
      actor: ctx.actor || null, reason: ctx.reason || null,
    });
  }

  function assertPermits(action, ctx) {
    if (permits(action)) return;
    _emit("resourceaccesslock.refused", "failure", {
      action: action, mode: mode,
      actor: (ctx && ctx.actor) || null,
    });
    throw new ResourceAccessLockError(
      "resource-access-lock/refused",
      resource + " refuses '" + action + "': lock mode is '" + mode + "'");
  }

  return {
    resource:      resource,
    mode:          function () { return mode; },
    set:           set,
    permits:       permits,
    assertPermits: assertPermits,
  };
}

module.exports = {
  create:                   create,
  VALID_MODES:              Object.freeze(Object.keys(VALID_MODES)),
  ResourceAccessLockError:  ResourceAccessLockError,
};
