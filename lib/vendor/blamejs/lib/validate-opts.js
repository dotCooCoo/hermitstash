"use strict";
/**
 * validate-opts — shared call-site helper for primitive create() functions
 * that throws on unknown / bad-shape opts at config time.
 *
 * Catches silent operator typos: `cors({ allowedOrigins: [] })` (wrong
 * key name) currently looks like config but does nothing — the primitive
 * sees opts.origins as undefined and falls back to defaults. With this
 * helper the create() throws at boot with a clear message instead of
 * the typo silently weakening the operator's setup.
 *
 *   var validateOpts = require("./validate-opts");
 *
 *   function create(opts) {
 *     opts = opts || {};
 *     validateOpts(opts, [
 *       "origins", "siteOrigin", "methods", "headers",
 *       "exposeHeaders", "credentials", "maxAgeSeconds", "refuseUnknown",
 *     ], "middleware.cors");
 *     ...
 *   }
 *
 * The exported `optional(...)` form lets a primitive accept a
 * sparsely-populated opts object and only validate keys that ARE present.
 *
 * Throws a plain Error with a code-shaped message — primitives that want
 * a typed error wrap the call.
 */

function _format(primitive, unknownKey, allowedKeys) {
  return primitive + ": unknown option '" + unknownKey + "'. " +
    "Allowed keys: " + allowedKeys.slice().sort().join(", ") + ".";
}

function check(opts, allowedKeys, primitive) {
  if (opts == null) return;
  if (typeof opts !== "object") {
    throw new Error(primitive + ": opts must be an object (got " + typeof opts + ")");
  }
  if (!Array.isArray(allowedKeys) || allowedKeys.length === 0) {
    throw new Error("validate-opts: allowedKeys must be a non-empty array");
  }
  if (typeof primitive !== "string" || primitive.length === 0) {
    throw new Error("validate-opts: primitive name must be a non-empty string");
  }
  var allowSet = Object.create(null);
  for (var i = 0; i < allowedKeys.length; i++) allowSet[allowedKeys[i]] = true;
  var keys = Object.keys(opts);
  for (var j = 0; j < keys.length; j++) {
    if (!allowSet[keys[j]]) {
      throw new Error(_format(primitive, keys[j], allowedKeys));
    }
  }
}

// auditShape — operator-supplied `opts.audit` must expose a
// `safeEmit` function. 10+ primitive create() functions previously
// inlined the same shape check + throw. Centralized here so every
// consumer has one validation contract.
function auditShape(audit, callerLabel, errorClass, code) {
  if (audit === undefined || audit === null) return audit;
  if (typeof audit !== "object" || typeof audit.safeEmit !== "function") {
    var msg = (callerLabel || "audit") +
      ": audit must be a b.audit-shaped object (safeEmit fn)";
    if (errorClass && errorClass.factory) {
      throw errorClass.factory(code || "BAD_OPT", msg);
    }
    if (typeof errorClass === "function") {
      throw new errorClass(code || "audit/bad-shape", msg);
    }
    throw new Error(msg);
  }
  return audit;
}

// _throw — shared error-emission for the optional* validators. Routes
// through the caller's framework-error class when supplied, falls back
// to plain Error so this helper itself stays decoupled from any one
// error hierarchy.
function _throw(errorClass, code, msg, defaultCode) {
  if (errorClass && errorClass.factory) {
    throw errorClass.factory(code || "BAD_OPT", msg);
  }
  if (typeof errorClass === "function") {
    throw new errorClass(code || defaultCode, msg);
  }
  throw new Error(msg);
}

// optionalBoolean / optionalPositiveInt / optionalFiniteNonNegative /
// optionalPositiveFinite / optionalFunction — opt-time type assertions
// for fields that may be omitted. Each returns the value unchanged when
// undefined or null (preserving the caller's "absent → use default"
// semantics) and throws on any other shape.
//
// 10+ primitive create() functions previously rolled identical
// `if (opts.X !== undefined && typeof opts.X !== "Y") throw`
// sequences. Centralizing the throw here keeps the operator-facing
// message format consistent and gives the codebase-pattern catalog one
// place to point new authors at.

function optionalBoolean(value, label, errorClass, code) {
  if (value === undefined || value === null) return value;
  if (typeof value !== "boolean") {
    _throw(errorClass, code, (label || "opt") + " must be a boolean, got " + typeof value,
           "validate-opts/bad-boolean");
  }
  return value;
}

function optionalPositiveInt(value, label, errorClass, code) {
  if (value === undefined || value === null) return value;
  if (typeof value !== "number" || !isFinite(value) || value < 1 || Math.floor(value) !== value) {
    _throw(errorClass, code, (label || "opt") +
           " must be a positive integer (>= 1, finite), got " +
           (typeof value === "number" ? String(value) : typeof value),
           "validate-opts/bad-positive-int");
  }
  return value;
}

function optionalFiniteNonNegative(value, label, errorClass, code) {
  if (value === undefined || value === null) return value;
  if (typeof value !== "number" || !isFinite(value) || value < 0) {
    _throw(errorClass, code, (label || "opt") +
           " must be a non-negative finite number, got " +
           (typeof value === "number" ? String(value) : typeof value),
           "validate-opts/bad-non-negative-finite");
  }
  return value;
}

function optionalPositiveFinite(value, label, errorClass, code) {
  if (value === undefined || value === null) return value;
  if (typeof value !== "number" || !isFinite(value) || value <= 0) {
    _throw(errorClass, code, (label || "opt") +
           " must be a positive finite number (> 0), got " +
           (typeof value === "number" ? String(value) : typeof value),
           "validate-opts/bad-positive-finite");
  }
  return value;
}

function optionalFunction(value, label, errorClass, code) {
  if (value === undefined || value === null) return value;
  if (typeof value !== "function") {
    _throw(errorClass, code, (label || "opt") + " must be a function, got " + typeof value,
           "validate-opts/bad-function");
  }
  return value;
}

// applyDefaults — resolve every key in DEFAULTS against opts. For each
// key, the operator's value (if not undefined) wins; otherwise the
// default is used. Returns a new plain object — NOT a frozen one, so
// the create() function can layer additional resolved fields if it
// needs them. 5+ primitives previously rolled their own
// `var X = (opts.X === undefined) ? DEFAULTS.X : opts.X;` cascade
// across 5–10 lines per call site; this collapses them all to one.
//
// Operator-supplied keys that aren't in DEFAULTS are dropped — use
// validateOpts(opts, ALLOWED_KEYS, label) at the boundary FIRST to
// reject typos before this resolves. Pass-through behavior would let
// `{ ttllMs: 5000 }` silently apply the default ttlMs without warning.
function applyDefaults(opts, defaults) {
  if (defaults === null || typeof defaults !== "object") {
    throw new Error("validate-opts.applyDefaults: defaults must be an object");
  }
  opts = opts || {};
  var out = {};
  var keys = Object.keys(defaults);
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    out[k] = (opts[k] === undefined) ? defaults[k] : opts[k];
  }
  return out;
}

// requireObject — every primitive's `_validate*Opts(opts)` function
// previously started with the same `if (!opts || typeof opts !== "object")
// throw _err(...)` prelude. Centralized here so the contract is one
// definition. Throws on null / undefined / non-object; returns opts on
// success.
function requireObject(opts, callerLabel, errorClass, code) {
  if (!opts || typeof opts !== "object") {
    var msg = (callerLabel || "opts") + ": opts must be an object, got " +
      (opts === null ? "null" : typeof opts);
    _throw(errorClass, code, msg, "validate-opts/bad-object");
  }
  return opts;
}

function optionalNonEmptyString(value, label, errorClass, code) {
  if (value === undefined || value === null) return value;
  if (typeof value !== "string" || value.length === 0) {
    _throw(errorClass, code, (label || "opt") +
           " must be a non-empty string, got " +
           (typeof value === "string" ? "empty string" : typeof value),
           "validate-opts/bad-non-empty-string");
  }
  return value;
}

// requireNonEmptyString — required-field counterpart to
// optionalNonEmptyString. Throws on undefined / null / empty / non-
// string. The dozens of `if (typeof opts.X !== "string" ||
// opts.X.length === 0) throw` sites every primitive's create() rolled
// at the top of validation collapse to one call here.
function requireNonEmptyString(value, label, errorClass, code) {
  if (typeof value !== "string" || value.length === 0) {
    var got = value === undefined ? "undefined"
            : value === null      ? "null"
            : typeof value === "string" ? "empty string"
            : typeof value;
    _throw(errorClass, code, (label || "opt") +
           " must be a non-empty string, got " + got,
           "validate-opts/missing-non-empty-string");
  }
  return value;
}

// optionalNonEmptyStringArray — required-shape validator for optional
// array-of-non-empty-strings opts (scopes / allowedFileTypes / dependsOn /
// rtlLanguages / eagerLocales / etc.). Replaces the recurring four-line
// cascade `if (opts.X !== undefined) { if (!Array.isArray) throw; for
// (i...) if (typeof !== "string" || === "") throw }` that 5+ primitives
// previously rolled by hand.
//
// undefined / null → returns the value unchanged (caller can default).
// non-array → throws via errorClass with the provided code.
// any non-string or empty-string element → throws with index-pointing message.
function optionalNonEmptyStringArray(value, label, errorClass, code) {
  if (value === undefined || value === null) return value;
  if (!Array.isArray(value)) {
    _throw(errorClass, code, (label || "opt") +
           " must be an array of non-empty strings, got " + typeof value,
           "validate-opts/bad-string-array");
  }
  for (var i = 0; i < value.length; i += 1) {
    if (typeof value[i] !== "string" || value[i].length === 0) {
      _throw(errorClass, code, (label || "opt") +
             "[" + i + "] must be a non-empty string",
             "validate-opts/bad-string-array-element");
    }
  }
  return value;
}

// optionalObjectWithMethod — required-shape validator for optional opts
// that accept a "duck-typed handle": an object that exposes a specific
// method. Replaces the recurring `if (opts.X !== undefined && opts.X !==
// null) { if (typeof opts.X !== "object" || typeof opts.X.method !==
// "function") throw ... }` cascade shared by file-upload (permissions),
// notify (queue), seeders (db), webhook (nonceStore), and others.
//
// undefined / null → returns the value unchanged (caller can default).
// non-object OR missing method → throws via errorClass with the operator-
// facing description (e.g. "must be a b.permissions instance (check fn)").
function optionalObjectWithMethod(value, method, label, errorClass, code, description) {
  if (value === undefined || value === null) return value;
  if (typeof value !== "object" || typeof value[method] !== "function") {
    _throw(errorClass, code, (label || "opt") + " " +
           (description || ("must expose " + method + "() method")),
           "validate-opts/bad-shaped-handle");
  }
  return value;
}

// optionalPlainObject — required-shape validator for optional opts that
// accept a plain object (not array, not null when undefined-meaning-absent
// is intended). Replaces the recurring `if (X !== undefined && X !== null)
// { if (typeof X !== "object" || Array.isArray(X)) throw }` cascade
// shared by api-key (metadata), db-declare-view, db-declare-row-policy,
// and static.js (contentSafety).
//
// undefined / null → returns the value unchanged (caller can default).
// non-object OR array → throws via errorClass with the operator-facing
// description (e.g. "metadata must be a plain object or null").
function optionalPlainObject(value, label, errorClass, code, description) {
  if (value === undefined || value === null) return value;
  if (typeof value !== "object" || Array.isArray(value)) {
    _throw(errorClass, code, (label || "opt") + " " +
           (description || "must be a plain object or null"),
           "validate-opts/bad-plain-object");
  }
  return value;
}

// makeAuditEmitter — closure factory parallel to safeAsync.makeDropCallback.
// Replaces the per-file `function _emit(action, info) { if (!audit) return;
// try { audit.safeEmit(Object.assign({ action: action }, info || {})); }
// catch (_e) { /* audit best-effort */ } }` boilerplate that 5 primitives
// previously rolled by hand (api-key / cache / notify / permissions /
// sigv4-bucket-ops).
//
// audit may be null/undefined — returns a no-op emitter in that case so
// callers don't need to null-check at every call site.
//
//   var _emit = validateOpts.makeAuditEmitter(opts.audit);
//   _emit("apikey.create", { actor: ..., resource: ..., outcome: "success" });
function makeAuditEmitter(audit) {
  if (!audit || typeof audit.safeEmit !== "function") {
    return function _noopEmit() {};
  }
  return function _emit(action, info) {
    try { audit.safeEmit(Object.assign({ action: action }, info || {})); }
    catch (_e) { /* audit best-effort — never break the caller */ }
  };
}

// observabilityShape — operator-supplied `opts.observability` must
// expose an `event` function. Parallel to auditShape; the n=1 catalog
// tracks both inline-shape regexes.
function observabilityShape(observability, callerLabel, errorClass, code) {
  if (observability === undefined || observability === null) return observability;
  if (typeof observability !== "object" || typeof observability.event !== "function") {
    var msg = (callerLabel || "observability") +
      ": observability must be a b.observability-shaped object (event fn)";
    _throw(errorClass, code, msg, "observability/bad-shape");
  }
  return observability;
}

module.exports = check;
module.exports.check = check;
module.exports.auditShape = auditShape;
module.exports.optionalBoolean = optionalBoolean;
module.exports.optionalPositiveInt = optionalPositiveInt;
module.exports.optionalFiniteNonNegative = optionalFiniteNonNegative;
module.exports.optionalPositiveFinite = optionalPositiveFinite;
module.exports.optionalFunction = optionalFunction;
module.exports.optionalNonEmptyString = optionalNonEmptyString;
module.exports.optionalNonEmptyStringArray = optionalNonEmptyStringArray;
module.exports.optionalObjectWithMethod = optionalObjectWithMethod;
module.exports.optionalPlainObject = optionalPlainObject;
module.exports.requireNonEmptyString = requireNonEmptyString;
module.exports.observabilityShape = observabilityShape;
module.exports.requireObject = requireObject;
module.exports.applyDefaults = applyDefaults;
module.exports.makeAuditEmitter = makeAuditEmitter;
