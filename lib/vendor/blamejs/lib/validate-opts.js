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

var numericBounds = require("./numeric-bounds");
var pick = require("./pick");

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
// error hierarchy. `permanent` (optional) is forwarded as the framework
// error's third constructor argument so callers whose config-time failure
// is non-retryable (a misconfigured dependency never becomes valid on
// retry) keep that flag when they route through these validators instead
// of hand-throwing; omitted → undefined → the class default (false), so
// existing callers are unaffected.
function _throw(errorClass, code, msg, defaultCode, permanent) {
  if (errorClass && errorClass.factory) {
    throw errorClass.factory(code || "BAD_OPT", msg, permanent);
  }
  if (typeof errorClass === "function") {
    throw new errorClass(code || defaultCode, msg, permanent);
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

function optionalDate(value, label, errorClass, code) {
  if (value === undefined || value === null) return value;
  if (!(value instanceof Date) || !isFinite(value.getTime())) {
    _throw(errorClass, code, (label || "opt") + " must be a valid Date",
           "validate-opts/bad-date");
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

// optionalPort — a TCP/UDP port number must be an integer in the wire-valid
// range (RFC 6335 §6). Outbound-connect sites require [1,65535]; pass
// { allowZero: true } for a listen-bind site where port 0 is the legitimate
// ephemeral-bind sentinel the OS replaces with a kernel-assigned port. Uses
// numericBounds.shape() in the message so Infinity / NaN / "443" stay visible.
function optionalPort(value, label, errorClass, code, opts) {
  if (value === undefined || value === null) return value;
  opts = opts || {};
  var ok = opts.allowZero
    ? (numericBounds.isNonNegativeFiniteInt(value) && value <= 65535)
    : (numericBounds.isPositiveFiniteInt(value) && value <= 65535);
  if (!ok) {
    _throw(errorClass, code, (label || "opt") + " must be " +
           (opts.allowZero ? "0 (ephemeral) or " : "") +
           "an integer in [" + (opts.allowZero ? 0 : 1) + ",65535], got " + numericBounds.shape(value),
           "validate-opts/bad-port");
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

// requireMethods — validate an injected dependency exposes the named
// methods. Collapses the repeated `if (!obj || typeof obj.fn !==
// "function" || ...) throw` injected-store / exporter / backend guards
// (b.agent.*.reseal stores, b.dsr / b.outbox create() backends, etc.)
// into one definition. Throws on null / non-object / any missing-or-
// non-function method; returns obj on success.
//
// `permanent` (optional) forwards to the framework error's permanent flag
// — pass true for a config-time dependency check whose failure is not
// retryable (a backend/store/vault missing its contract never becomes
// valid on retry). Omitted → the error class default (false), matching
// the historical bare `new Err(code, msg)` shape, so existing callers are
// unchanged.
function requireMethods(obj, methods, callerLabel, errorClass, code, permanent) {
  var label = callerLabel || "dependency";
  if (!obj || typeof obj !== "object") {
    _throw(errorClass, code, label + " must be an object exposing { " +
           methods.join(", ") + " }, got " + (obj === null ? "null" : typeof obj),
           "validate-opts/bad-methods-object", permanent);
  }
  for (var i = 0; i < methods.length; i += 1) {
    if (typeof obj[methods[i]] !== "function") {
      _throw(errorClass, code, label + " must expose a " + methods[i] +
             "() method (requires { " + methods.join(", ") + " })",
             "validate-opts/missing-method", permanent);
    }
  }
  return obj;
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

// _SHAPE_RULES — rule-token → validator dispatch table for `shape`. Each
// validator has the uniform (value, label, errorClass, code) signature, so the
// table drives them all from a declarative schema.
var _SHAPE_RULES = {
  "required-string":          requireNonEmptyString,
  "optional-string":          optionalNonEmptyString,
  "optional-string-array":    optionalNonEmptyStringArray,
  "optional-boolean":         optionalBoolean,
  "optional-positive-int":    optionalPositiveInt,
  "optional-positive-finite": optionalPositiveFinite,
  "optional-non-negative":    optionalFiniteNonNegative,
  "optional-date":            optionalDate,
  "optional-function":        optionalFunction,
  "optional-plain-object":    optionalPlainObject,
  "optional-port":            optionalPort,
  // numeric-bounds finite-int family (rejects Infinity/NaN, unlike the
  // optional-positive-int sugar) — so byte/count caps declare in the shape
  // rather than a separate numericBounds call outside it.
  "optional-positive-finite-int":     numericBounds.requirePositiveFiniteIntIfPresent,
  "optional-non-negative-finite-int": numericBounds.requireNonNegativeFiniteIntIfPresent,
  "required-positive-finite-int":     numericBounds.requirePositiveFiniteInt,
};

// shape — declarative opts validator. Collapses the `requireObject(opts) +
// requireNonEmptyString(opts.a) + optionalPositiveFinite(opts.b) + ...` preamble
// that every create()/build() factory re-rolls into one schema-driven call.
// The schema is expressive enough that a factory never has to contort its
// validation to fit a fixed vocabulary — each opt's rule is ANY of:
//
//   - a rule TOKEN (see _SHAPE_RULES) — sugar for the common per-field checks,
//     using the call-wide `code`;
//   - a per-field DESCRIPTOR `{ rule: "<token>", code?, label? }` — keeps a
//     DISTINCT per-field code (BAD_THIRD_PARTY vs BAD_CONSUMER_REF) or a custom
//     label, so behavior a per-field test asserts is preserved;
//   - an injected-DEPENDENCY `{ methods: [...], optional?, code?, label? }` —
//     validated via requireMethods;
//   - a NESTED `{ shape: {...}, optional?, code?, label? }` — recurses into a
//     sub-object field (e.g. opts.authServer.{issuer,jwksUri});
//   - an arbitrary VALIDATOR FUNCTION `(value, label, errorClass, code, opts)
//     => void` that throws on invalid — the universal hatch for a bespoke check.
//     It receives the whole `opts` as the 5th arg, so CROSS-FIELD logic ("field
//     B required when opts.a === X", a custom message, a numeric-bounds call)
//     lives IN the shape rather than as a hand-rolled check outside it.
//
// Validates `opts` is an object, then dispatches each declared field; returns
// opts. An unknown rule token throws at call time — a schema typo is the
// author's bug, surfaced loudly rather than silently skipping a field.
//
// The schema is ALWAYS the authoritative, exhaustive opts contract — there is
// no opt-in: any key present on `opts` that the schema does not declare (nor
// list in `options.allow`) is rejected. This is mandatory by design, so the
// "future code adds an opt but forgets to validate it" gap cannot reopen — an
// undeclared opt can't be silently consumed, because it is refused here;
// adding it forces declaring its rule in the schema, where it is validated.
// (A field declared in the schema is always validated; exhaustiveness adds the
// converse — nothing reaches the body unvalidated.) `options.allow` is the only
// escape: an explicit list of keys a factory forwards to a sub-component rather
// than validating locally — there is no "skip the contract" mode.
function shape(opts, schema, callerLabel, errorClass, code, options) {
  requireObject(opts, callerLabel, errorClass, code);
  var fields = Object.keys(schema);
  for (var i = 0; i < fields.length; i += 1) {
    var field = fields[i];
    var rule = schema[field];
    var fieldCode = code;
    var label = (callerLabel || "opts") + ": " + field;
    var value = opts[field];
    // Arbitrary validator function — the universal hatch. Receives the whole
    // `opts` as a 5th arg so a rule can do CROSS-FIELD validation (e.g. "field B
    // is required when opts.a === 'material'") without dropping back to inline
    // checks outside the shape.
    if (typeof rule === "function") { rule(value, label, errorClass, fieldCode, opts); continue; }
    if (rule && typeof rule === "object") {
      if (Array.isArray(rule.methods)) {
        if (rule.optional && (value === undefined || value === null)) continue;
        requireMethods(value, rule.methods, rule.label || label, errorClass, rule.code || code, rule.permanent);
        continue;
      }
      // Nested sub-object: validate it is an object, then recurse.
      if (rule.shape && typeof rule.shape === "object") {
        if (rule.optional && (value === undefined || value === null)) continue;
        requireObject(value, rule.label || label, errorClass, rule.code || code);
        shape(value, rule.shape, rule.label || label, errorClass, rule.code || code);
        continue;
      }
      // Per-field descriptor: { rule, code?, label? }.
      if (typeof rule.rule === "string") {
        if (typeof rule.code === "string") fieldCode = rule.code;
        if (typeof rule.label === "string") label = rule.label;
        rule = rule.rule;
      } else {
        _throw(errorClass, code, (callerLabel || "opts") +
               ": unsupported shape rule object for field " + field,
               "validate-opts/bad-shape-rule");
      }
    }
    if (rule === "required-object") { requireObject(value, label, errorClass, fieldCode); continue; }
    var fn = _SHAPE_RULES[rule];
    if (typeof fn !== "function") {
      _throw(errorClass, code, (callerLabel || "opts") +
             ": unknown shape rule " + JSON.stringify(rule) + " for field " + field,
             "validate-opts/bad-shape-rule");
    }
    fn(value, label, errorClass, fieldCode);
  }
  // Exhaustive contract enforcement — always on (the schema is complete).
  var declared = Object.create(null);
  for (var d = 0; d < fields.length; d += 1) declared[fields[d]] = true;
  var allowList = (options && options.allow) || [];
  for (var a = 0; a < allowList.length; a += 1) declared[allowList[a]] = true;
  var present = Object.keys(opts);
  for (var p = 0; p < present.length; p += 1) {
    if (!declared[present[p]]) {
      _throw(errorClass, code, (callerLabel || "opts") +
             ": unknown opt " + JSON.stringify(present[p]) +
             " (not in the validated shape; add it to the schema or pass options.allow)",
             "validate-opts/unknown-opt");
    }
  }
  return opts;
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

// makeNamespacedEmitters — collapses the per-primitive
//   function _emitAudit(action, outcome, metadata) { audit.safeEmit({...}) }
//   function _emitMetric(verb)                    { observability.safeEvent(...) }
// boilerplate into one helper. Every primitive that emits both audit
// events AND observability metrics under a fixed prefix shares the
// same shape; pre-v0.8.62 this was inlined in 13+ lib/auth files.
//
//   var emit = validateOpts.makeNamespacedEmitters("auth.ciba", { audit, observability });
//   emit.audit("token_received", "success", { hash: ... });
//   emit.metric("token-received");
//
// The audit/observability arguments are lazyRequire-resolved at the
// call site so the helper itself adds no module-load coupling.
function makeNamespacedEmitters(prefix, deps) {
  if (typeof prefix !== "string" || prefix.length === 0) {
    throw new Error("makeNamespacedEmitters: prefix must be a non-empty string");
  }
  deps = deps || {};
  function audit(action, outcome, metadata) {
    var auditMod = deps.audit;
    if (typeof auditMod === "function") auditMod = auditMod();
    if (!auditMod || typeof auditMod.safeEmit !== "function") return;
    try {
      auditMod.safeEmit({
        action:   prefix + "." + action,
        outcome:  outcome,
        metadata: metadata || {},
      });
    } catch (_e) { /* audit best-effort */ }
  }
  function metric(verb, value, attrs) {
    var obsMod = deps.observability;
    if (typeof obsMod === "function") obsMod = obsMod();
    if (!obsMod || typeof obsMod.safeEvent !== "function") return;
    try { obsMod.safeEvent(prefix + "." + verb, value || 1, attrs || {}); }
    catch (_e) { /* observability best-effort */ }
  }
  return { audit: audit, metric: metric };
}

// assignOwnEnumerable — copy a source object's own enumerable keys onto a
// target, skipping the prototype-pollution sentinels (__proto__ /
// constructor / prototype) and any caller-named reserved keys. Several
// primitives that merge operator-supplied free-form fields onto a
// spec-built object (JOSE claim sets, JWS protected headers, attestation
// extra-claims) previously open-coded the identical
// `for (k of Object.keys(src)) { if (sentinel) continue; if (reserved)
// continue; dst[k] = src[k]; }` loop. Centralizing the proto-safe walk
// keeps the merge contract in one place. Reserved keys win — they are NOT
// overwritten — so the caller's spec-built fields can never be shadowed by
// a same-named operator key. Returns the target.
function assignOwnEnumerable(target, source, reservedKeys) {
  if (!source || typeof source !== "object") return target;
  var reserved = Object.create(null);
  if (reservedKeys) for (var r = 0; r < reservedKeys.length; r += 1) reserved[reservedKeys[r]] = true;
  var keys = Object.keys(source);
  var entries = [];
  for (var i = 0; i < keys.length; i += 1) {
    var k = keys[i];
    if (pick.isPoisonedKey(k)) continue;
    if (reserved[k]) continue;
    entries.push([k, source[k]]);
  }
  // Staged through entries + Object.assign so the copy contains no
  // computed-name property write at all: Object.fromEntries creates own
  // data properties (it cannot walk the prototype chain), and the
  // sentinel skip above means the staging object carries no
  // __proto__/constructor/prototype key for Object.assign's [[Set]] to
  // trip over. Same observable result as a key-by-key copy, with the
  // arbitrary-property-write shape removed instead of merely guarded.
  return Object.assign(target, Object.fromEntries(entries));
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
module.exports.optionalDate = optionalDate;
module.exports.optionalPositiveFinite = optionalPositiveFinite;
module.exports.optionalPort = optionalPort;
module.exports.optionalFunction = optionalFunction;
module.exports.optionalNonEmptyString = optionalNonEmptyString;
module.exports.optionalNonEmptyStringArray = optionalNonEmptyStringArray;
module.exports.optionalObjectWithMethod = optionalObjectWithMethod;
module.exports.optionalPlainObject = optionalPlainObject;
module.exports.requireNonEmptyString = requireNonEmptyString;
module.exports.observabilityShape = observabilityShape;
module.exports.requireObject = requireObject;
module.exports.requireMethods = requireMethods;
module.exports.shape = shape;
module.exports.applyDefaults = applyDefaults;
module.exports.makeAuditEmitter = makeAuditEmitter;
module.exports.makeNamespacedEmitters = makeNamespacedEmitters;
module.exports.assignOwnEnumerable = assignOwnEnumerable;
