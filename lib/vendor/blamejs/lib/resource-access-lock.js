"use strict";
/**
 * b.resourceAccessLock — three-mode access-lock for arbitrary
 * resources (data exports, scheduled jobs, file paths, queue
 * partitions). Different from b.auth.accessLock — that one gates
 * HTTP request flow; this one gates non-HTTP-shaped operator
 * actions. Both share the open / read-only / locked vocabulary.
 *
 *   var exportLock = b.resourceAccessLock.create({
 *     resource:     "data-export-jobs",
 *     startMode:    "open",
 *     audit:        b.audit,
 *   });
 *
 *   if (!exportLock.permits("write")) {
 *     throw new b.resourceAccessLock.ResourceAccessLockError(
 *       "resource-access-lock/refused",
 *       "data export refused: lock mode is " + exportLock.mode());
 *   }
 *   await runExportJob();
 *
 *   exportLock.set("locked", { actor: "alice", reason: "incident-42 freeze" });
 *
 * Mode semantics:
 *   open       — every action permitted
 *   read-only  — actions tagged "read" permitted; "write" refused
 *   locked     — every action refused
 *
 * Audit shape:
 *   resourceaccesslock.mode_changed — {resource, from, to, actor, reason}
 *   resourceaccesslock.refused      — {resource, action, mode, actor}
 */

var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

var ResourceAccessLockError = defineClass("ResourceAccessLockError",
  { alwaysPermanent: true });

var VALID_MODES = Object.freeze({ open: 1, "read-only": 1, locked: 1 });
var READ_ACTIONS = Object.freeze({ read: 1, list: 1, get: 1, query: 1, "read-only": 1 });

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
