// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.deprecate
 * @nav    Production
 * @title  Deprecate
 *
 * @intro
 *   Runtime deprecation-warning system for the framework's LTS
 *   contract. Operators see a one-time stderr warning the first time
 *   deprecated surface is used, naming the version it was deprecated
 *   in and the version it will be removed in — so behavior changes
 *   ship visible at least one minor before the breakage lands in a
 *   major.
 *
 *   Three usage shapes:
 *
 *     - `warn(name, opts)` — emit a warning at the call site of an
 *       inline deprecated path.
 *     - `wrap(fn, name, opts)` — return a wrapper around the
 *       replacement function so calls to the old name auto-warn and
 *       delegate.
 *     - `alias(target, oldKey, newKey, opts)` — define `oldKey` on
 *       `target` as a getter/setter that warns on access and reads
 *       through to `newKey`.
 *
 *   Warnings dedupe by `(name, since)` — calling `warn` ten thousand
 *   times with the same args emits a single stderr line; the per-name
 *   call counter is still incremented so `list()` reflects real usage
 *   volume for ops dashboards.
 *
 *   `BLAMEJS_DEPRECATIONS` env var controls runtime behavior:
 *
 *     - `"warn"`   — stderr warning on first use (default outside
 *                    production).
 *     - `"silent"` — skip entirely (default in production; operators
 *                    do not want stderr noise from deprecated paths
 *                    in code they do not own).
 *     - `"error"`  — throw on first use; development tool to surface
 *                    every deprecated call site as a hard failure
 *                    during a sweep.
 *
 *   Mode resolution: explicit env var first, then `"silent"` when
 *   `NODE_ENV=production`, otherwise `"warn"`.
 *
 * @card
 *   Runtime deprecation-warning system for the framework's LTS contract.
 */

var safeEnv = require("./parsers/safe-env");
var validateOpts = require("./validate-opts");
var boundedMap = require("./bounded-map");
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

/**
 * @primitive b.deprecate.warn
 * @signature b.deprecate.warn(name, opts)
 * @since     0.1.90
 * @status    stable
 * @related   b.deprecate.wrap, b.deprecate.alias, b.deprecate.list
 *
 * Emit a deprecation warning for an inline call site. First call for a
 * given `(name, since)` pair writes a single line to stderr in `"warn"`
 * mode, throws `DeprecateError` in `"error"` mode, and is suppressed
 * in `"silent"` mode. Subsequent calls dedupe but still increment the
 * per-name call counter so `list()` reports real usage volume. Throws
 * `DeprecateError` (`deprecate/bad-name`) on missing `name` and
 * (`deprecate/bad-opts`) when `since` or `removeIn` are missing or
 * empty.
 *
 * @opts
 *   since:     string,   // required; semver this surface was deprecated in
 *   removeIn:  string,   // required; semver of planned removal
 *   message:   string,   // optional human-readable replacement guidance
 *   hint:      string,   // optional cross-reference (MIGRATING.md anchor)
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.deprecate.warn("auth.legacyVerify", {
 *     since:    "0.2.0",
 *     removeIn: "0.4.0",
 *     message:  "use auth.password.verify(stored, plain) instead",
 *     hint:     "see MIGRATING.md#0-2-to-0-4",
 *   });
 *   // → undefined  (stderr: [blamejs:deprecated] auth.legacyVerify (since 0.2.0); removed in 0.4.0 — ...)
 */
function warn(name, opts) {
  if (typeof name !== "string" || name.length === 0) {
    throw new DeprecateError("deprecate/bad-name",
      "warn: name is required (the public identifier being deprecated)");
  }
  _validateOpts(opts, "warn");

  var key = name + ":" + opts.since;
  var entry = boundedMap.getOrInsert(_seen, key, function () {
    return {
      name:      name,
      since:     opts.since,
      removeIn:  opts.removeIn,
      message:   opts.message || null,
      hint:      opts.hint    || null,
      callCount: 0,
      firstSeen: new Date().toISOString(),
    };
  });
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
/**
 * @primitive b.deprecate.wrap
 * @signature b.deprecate.wrap(fn, name, opts)
 * @since     0.1.90
 * @status    stable
 * @related   b.deprecate.warn, b.deprecate.alias
 *
 * Return a function that warns on first invocation then delegates to
 * `fn` with the same `this` and arguments. Use to keep the old export
 * name working through one minor version after rename. The wrapper's
 * `.name` is set to `<name>:deprecated` for stack-trace clarity. Same
 * dedupe + mode rules as `warn`. Throws `DeprecateError`
 * (`deprecate/bad-target`) when `fn` is not a function and
 * (`deprecate/bad-name`) on missing `name`.
 *
 * @opts
 *   since:     string,   // required; semver this surface was deprecated in
 *   removeIn:  string,   // required; semver of planned removal
 *   message:   string,   // optional human-readable replacement guidance
 *   hint:      string,   // optional cross-reference (MIGRATING.md anchor)
 *
 * @example
 *   var b = require("@blamejs/core");
 *   function passwordVerify(stored, plain) { return stored === plain; }
 *   var legacyVerify = b.deprecate.wrap(passwordVerify, "auth.legacyVerify", {
 *     since:    "0.2.0",
 *     removeIn: "0.4.0",
 *     message:  "renamed to auth.password.verify",
 *   });
 *   var ok = legacyVerify("stored", "plain");
 *   // → false  (stderr warns once on first call)
 */
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
/**
 * @primitive b.deprecate.alias
 * @signature b.deprecate.alias(target, oldKey, newKey, opts)
 * @since     0.1.90
 * @status    stable
 * @related   b.deprecate.wrap, b.deprecate.warn
 *
 * Define a getter/setter on `target.oldKey` that warns on access and
 * reads/writes through to `target.newKey`. Use to keep a renamed
 * property accessible for one minor without losing visibility into
 * who still reads the old name. The aliased property is non-
 * enumerable (so it does not leak into `Object.keys` / JSON
 * serialization) but configurable so tests can redefine it. Throws
 * `DeprecateError` (`deprecate/bad-target`) when `target` is not an
 * object and (`deprecate/bad-name`) on missing `oldKey` / `newKey`.
 *
 * @opts
 *   since:     string,   // required; semver this surface was deprecated in
 *   removeIn:  string,   // required; semver of planned removal
 *   message:   string,   // optional override; defaults to "use 'newKey' instead"
 *   hint:      string,   // optional cross-reference (MIGRATING.md anchor)
 *   aliasName: string,   // optional override for the warned identifier
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var settings = { timeout: 5000 };
 *   b.deprecate.alias(settings, "timeoutMs", "timeout", {
 *     since:    "0.3.0",
 *     removeIn: "0.5.0",
 *   });
 *   var v = settings.timeoutMs;
 *   // → 5000  (stderr warns once on first read)
 */
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

/**
 * @primitive b.deprecate.list
 * @signature b.deprecate.list()
 * @since     0.1.90
 * @status    stable
 * @related   b.deprecate.warn, b.deprecate.reset, b.deprecate.getMode
 *
 * Return an array of every deprecated identifier hit during this
 * process's lifetime — `{ name, since, removeIn, callCount,
 * firstSeen }`. Sorted most-frequent first, ties broken by earliest
 * `firstSeen`. Use from an ops dashboard or boot diagnostic to surface
 * which deprecated paths the running deployment still exercises so
 * the team can prioritize migrations before the `removeIn` major
 * lands.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.deprecate.warn("auth.legacyVerify", { since: "0.2.0", removeIn: "0.4.0" });
 *   var rows = b.deprecate.list();
 *   // → [{ name: "auth.legacyVerify", since: "0.2.0", removeIn: "0.4.0",
 *   //      callCount: 1, firstSeen: "2026-05-09T12:00:00.000Z" }]
 */
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

/**
 * @primitive b.deprecate.reset
 * @signature b.deprecate.reset()
 * @since     0.1.90
 * @status    stable
 * @related   b.deprecate.list, b.deprecate.warn
 *
 * Clear the seen-set so subsequent `warn` / `wrap` / `alias` calls
 * re-emit their first-use warnings. Used by tests that exercise the
 * deprecation path repeatedly; not meant for production code, where
 * the dedupe is intentional.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.deprecate.warn("auth.legacyVerify", { since: "0.2.0", removeIn: "0.4.0" });
 *   b.deprecate.reset();
 *   var seen = b.deprecate.list();
 *   // → []
 */
function reset() { _seen.clear(); }

// Export the resolved mode so tests + ops dashboards can introspect
/**
 * @primitive b.deprecate.getMode
 * @signature b.deprecate.getMode()
 * @since     0.1.90
 * @status    stable
 * @related   b.deprecate.warn, b.deprecate.list
 *
 * Return the resolved deprecation mode for the current process —
 * `"warn"`, `"silent"`, or `"error"`. Resolution order: explicit
 * `BLAMEJS_DEPRECATIONS` env var, then `"silent"` when
 * `NODE_ENV=production`, otherwise `"warn"`. Use from boot diagnostics
 * or test setup to confirm the active posture before exercising
 * deprecated paths.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var mode = b.deprecate.getMode();
 *   // → "warn"     (development default)
 *   // → "silent"   (NODE_ENV=production)
 *   // → "error"    (BLAMEJS_DEPRECATIONS=error)
 */
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
