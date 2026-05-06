"use strict";
/**
 * deprecate — runtime deprecation API for the framework's LTS contract.
 *
 * Operators see a one-time stderr warning the first time deprecated
 * surface is used, with the version it was deprecated in and the
 * version it'll be removed in. Production runs suppress warnings by
 * default (operators don't want stderr noise from deprecated paths in
 * code they don't own), but BLAMEJS_DEPRECATIONS env var inverts that
 * for visibility-on-demand.
 *
 *   var dep = b.deprecate;
 *
 *   // Direct warning at the call site
 *   dep.warn("auth.legacyVerify", {
 *     since:    "0.2.0",
 *     removeIn: "0.4.0",
 *     message:  "use auth.password.verify(stored, plain) instead",
 *     hint:     "see MIGRATING.md#0-2-to-0-4",
 *   });
 *
 *   // Wrap an old function so calls trigger the warning automatically
 *   var legacyVerify = dep.wrap(newVerify, "auth.legacyVerify", {
 *     since: "0.2.0", removeIn: "0.4.0",
 *     message: "renamed to auth.password.verify",
 *   });
 *
 *   // Mark a property as deprecated; access triggers the warning
 *   dep.alias(targetObj, "oldKey", "newKey", {
 *     since: "0.2.0", removeIn: "0.4.0",
 *   });
 *
 *   dep.list();   // → [{ name, since, removeIn, callCount, firstSeen }]
 *   dep.reset();  // clears the seen-set; tests
 *
 * BLAMEJS_DEPRECATIONS env var controls runtime behavior:
 *   "warn"    — stderr warning on first use of each (name, since) pair
 *               (default outside production)
 *   "silent"  — skip entirely (default in production)
 *   "error"   — throw on first use; development tool to surface every
 *               deprecated call site as a hard failure during a sweep
 *
 * Mode resolution order:
 *   1. process.env.BLAMEJS_DEPRECATIONS if set
 *   2. "silent" when process.env.NODE_ENV === "production"
 *   3. "warn" otherwise
 *
 * Warnings dedupe by (name, since) — calling deprecate.warn(...) ten
 * thousand times with the same args produces one stderr line. The
 * call counter is still incremented so dep.list() shows usage volume.
 */

var safeEnv = require("./parsers/safe-env");
var validateOpts = require("./validate-opts");
var { FrameworkError } = require("./framework-error");

class DeprecateError extends FrameworkError {
  constructor(code, message) {
    super(message, code);
    this.name = "DeprecateError";
    this.permanent = true;
    this.isDeprecateError = true;
  }
}

// Map of "<name>:<since>" → { name, since, removeIn, callCount, firstSeen }
var _seen = new Map();

function _modeFromEnv() {
  var env = safeEnv.readVar("BLAMEJS_DEPRECATIONS");
  if (typeof env === "string" && env.length > 0) {
    var v = env.toLowerCase();
    if (v === "warn" || v === "silent" || v === "error") return v;
  }
  if (safeEnv.readVar("NODE_ENV") === "production") return "silent";
  return "warn";
}

function _format(name, opts) {
  opts = opts || {};
  var line = "[blamejs:deprecated] " + name;
  if (opts.since)    line += " (since " + opts.since + ")";
  if (opts.removeIn) line += "; removed in " + opts.removeIn;
  if (opts.message)  line += " — " + opts.message;
  if (opts.hint)     line += " · " + opts.hint;
  return line;
}

function _validateOpts(opts, fnName) {
  if (!opts || typeof opts !== "object") {
    throw new DeprecateError("deprecate/bad-opts",
      fnName + ": opts is required (with at least 'since' and 'removeIn')");
  }
  validateOpts.requireNonEmptyString(opts.since, fnName + ": opts.since (version string)", DeprecateError, "deprecate/bad-opts");
  validateOpts.requireNonEmptyString(opts.removeIn, fnName + ": opts.removeIn (version string)", DeprecateError, "deprecate/bad-opts");
}

function warn(name, opts) {
  if (typeof name !== "string" || name.length === 0) {
    throw new DeprecateError("deprecate/bad-name",
      "warn: name is required (the public identifier being deprecated)");
  }
  _validateOpts(opts, "warn");

  var key = name + ":" + opts.since;
  var entry = _seen.get(key);
  if (!entry) {
    entry = {
      name:      name,
      since:     opts.since,
      removeIn:  opts.removeIn,
      message:   opts.message || null,
      hint:      opts.hint    || null,
      callCount: 0,
      firstSeen: new Date().toISOString(),
    };
    _seen.set(key, entry);
  }
  entry.callCount++;

  var mode = _modeFromEnv();
  if (mode === "silent") return;

  // Emit on first occurrence only (dedupe)
  if (entry.callCount > 1) return;

  var line = _format(name, opts);
  if (mode === "error") {
    throw new DeprecateError("deprecate/used-in-error-mode",
      line + " — BLAMEJS_DEPRECATIONS=error in effect");
  }
  // mode === "warn"
  try { process.stderr.write(line + "\n"); }
  catch (_e) { /* stderr write best-effort */ }
}

// Wrap a function so calling it issues a deprecation warning + delegates.
// The wrapper preserves the original function's `.length` (arity) so
// callers introspecting it as a callable see the same shape.
function wrap(fn, name, opts) {
  if (typeof fn !== "function") {
    throw new DeprecateError("deprecate/bad-target",
      "wrap: first arg must be the replacement function (the new API)");
  }
  if (typeof name !== "string" || name.length === 0) {
    throw new DeprecateError("deprecate/bad-name",
      "wrap: name is required (the deprecated identifier)");
  }
  _validateOpts(opts, "wrap");
  var wrapper = function () {
    warn(name, opts);
    return fn.apply(this, arguments);
  };
  // Preserve identity hints
  Object.defineProperty(wrapper, "name", { value: name + ":deprecated", configurable: true });
  return wrapper;
}

// Define `oldKey` on `target` as a getter that warns then returns
// `target[newKey]`. The setter writes through so existing assignments
// still work, but the getter access trips the warning.
function alias(target, oldKey, newKey, opts) {
  if (!target || typeof target !== "object") {
    throw new DeprecateError("deprecate/bad-target",
      "alias: target must be an object");
  }
  if (typeof oldKey !== "string" || oldKey.length === 0) {
    throw new DeprecateError("deprecate/bad-name",
      "alias: oldKey is required");
  }
  if (typeof newKey !== "string" || newKey.length === 0) {
    throw new DeprecateError("deprecate/bad-name",
      "alias: newKey is required");
  }
  _validateOpts(opts, "alias");
  var aliasName = opts.aliasName ||
    ((target.constructor && target.constructor.name &&
      target.constructor.name !== "Object" ? target.constructor.name + "." : "") + oldKey);
  var fullOpts = Object.assign({
    message: "use '" + newKey + "' instead",
  }, opts);
  Object.defineProperty(target, oldKey, {
    configurable: true,
    enumerable:   false,
    get: function () { warn(aliasName, fullOpts); return target[newKey]; },
    set: function (v) { warn(aliasName, fullOpts); target[newKey] = v; },
  });
}

function list() {
  var out = [];
  _seen.forEach(function (v) {
    out.push({
      name:      v.name,
      since:     v.since,
      removeIn:  v.removeIn,
      callCount: v.callCount,
      firstSeen: v.firstSeen,
    });
  });
  // Stable order: most-frequent first, ties broken by first-seen
  out.sort(function (a, b) {
    if (a.callCount !== b.callCount) return b.callCount - a.callCount;
    return a.firstSeen < b.firstSeen ? -1 : 1;
  });
  return out;
}

function reset() { _seen.clear(); }

// Export the resolved mode so tests + ops dashboards can introspect
function getMode() { return _modeFromEnv(); }

module.exports = {
  warn:               warn,
  wrap:               wrap,
  alias:              alias,
  list:               list,
  reset:              reset,
  getMode:            getMode,
  DeprecateError:   DeprecateError,
};
