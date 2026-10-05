// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * @module b.validateOpts
 * @nav    Validation
 * @title  Validate Opts
 * @slug   validate-opts
 *
 * @intro
 *   Refuse an option nothing reads. Every primitive in the framework
 *   declares the keys its <code>opts</code> accepts, and a key outside
 *   that list throws, naming the one it did not recognize and listing the
 *   ones it does.
 *
 *   An ignored option looks exactly like an option that worked.
 *   <code>{ maxBytes: 1024 }</code> passed to a primitive that reads
 *   <code>maxSize</code> is a cap the operator believes is set and is not,
 *   and nothing about the running system says otherwise. Refusing at the
 *   call is the point at which the typo is still cheap.
 *
 *   The helpers are the per-value checks those primitives share. Each takes
 *   the caller's own error class and code, so a refusal arrives as that
 *   primitive's error rather than as a bare <code>TypeError</code> from
 *   somewhere the caller has never heard of.
 *
 *   Every helper whose name starts with <code>optional</code> accepts
 *   <code>undefined</code> and <code>null</code> as "not supplied", so a
 *   caller may pass an absent option straight through without testing it
 *   first.
 *
 * @card
 *   Refuse an option the primitive does not read, naming the key and
 *   listing the ones it accepts, plus the per-value checks primitives share
 *   for durations, ports, strings, functions and shapes.
 */

var nodeTypes = require("node:util").types;
var numericBounds = require("./numeric-bounds");
var pick = require("./pick");

function _format(primitive, unknownKey, allowedKeys) {
  return primitive + ": unknown option '" + unknownKey + "'. " +
    "Allowed keys: " + allowedKeys.slice().sort().join(", ") + ".";
}

/**
 * @primitive b.validateOpts
 * @signature b.validateOpts(opts, allowedKeys, primitive)
 * @since     0.3.16
 * @status    stable
 * @related   b.validateOpts.checkOrThrow, b.pick
 *
 * Throw when `opts` carries a key not in `allowedKeys`. The message names
 * the unrecognized key and lists the accepted ones sorted, so the reader
 * sees the name they meant next to the one they typed. `primitive` is the
 * name the message opens with, which is how an operator tells which call
 * refused.
 *
 * A null or undefined `opts` passes, since a primitive called with no
 * options takes its defaults. An `opts` that is not an object throws, and
 * so does an empty `allowedKeys` or a missing `primitive`, which are
 * mistakes in the primitive rather than in the call.
 *
 * It checks the key names and nothing else. The values are the helpers'
 * job, and it throws a plain `Error`; `b.validateOpts.checkOrThrow` is the
 * same check raising the caller's own error class instead.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.validateOpts({ maxSize: 1024 }, ["maxSize", "timeoutMs"], "myThing.create");
 *   // returns: every key is allowed
 *
 *   try {
 *     b.validateOpts({ maxBytes: 1 }, ["maxSize", "timeoutMs"], "myThing.create");
 *   } catch (e) {
 *     e.message;
 *     // → "myThing.create: unknown option 'maxBytes'. Allowed keys: maxSize, timeoutMs."
 *   }
 */
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

/**
 * @primitive b.validateOpts.check
 * @signature b.validateOpts.check(opts, allowedKeys, primitive)
 * @since     0.7.0
 * @status    stable
 * @related   b.validateOpts, b.validateOpts.checkOrThrow
 *
 * The same function the namespace itself is, under its own name.
 * `b.validateOpts(...)` and `b.validateOpts.check(...)` are one function,
 * so a caller that destructures `{ check }` and one that calls the module
 * get the same behavior.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.validateOpts.check === b.validateOpts;   // → true
 */

/**
 * @primitive b.validateOpts.auditShape
 * @signature b.validateOpts.auditShape(audit, callerLabel, errorClass, code)
 * @since     0.7.0
 * @status    stable
 * @related   b.validateOpts.makeAuditEmitter, b.audit.safeEmit
 *
 * Refuse an `audit` option that is not an audit sink. A sink is an object
 * carrying a `safeEmit` function, which is the shape `b.audit` has.
 *
 * `undefined` and `null` pass, meaning no sink was supplied. A boolean does
 * not: `audit: true` is the flag a primitive uses to turn its own auditing
 * on, and passing it where a sink belongs would emit nothing while looking
 * like it had been configured.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.validateOpts.auditShape(b.audit, "myThing.create", MyError, "my/bad-opt");
 *   // returns the sink
 *
 *   b.validateOpts.auditShape(true, "myThing.create", MyError, "my/bad-opt");
 *   // throws: audit must be a b.audit-shaped object (safeEmit fn)
 */
function auditShape(audit, callerLabel, errorClass, code) {
  if (audit === undefined || audit === null) return audit;
  if (typeof audit !== "object" || typeof audit.safeEmit !== "function") {
    var msg = (callerLabel || "audit") +
      ": audit must be a b.audit-shaped object (safeEmit fn)";
    if (errorClass && errorClass.factory) {
      throw errorClass.factory(code || "audit/bad-shape", msg);
    }
    if (typeof errorClass === "function") {
      throw new errorClass(code || "audit/bad-shape", msg);
    }
    throw new Error(msg);
  }
  return audit;
}

function _throw(errorClass, code, msg, defaultCode, permanent) {
  var resolved = code || defaultCode || "validate-opts/bad-opt";
  if (errorClass && errorClass.factory) {
    throw errorClass.factory(resolved, msg, permanent);
  }
  if (typeof errorClass === "function") {
    throw new errorClass(resolved, msg, permanent);
  }
  throw new Error(msg);
}

/**
 * @primitive b.validateOpts.optionalBoolean
 * @signature b.validateOpts.optionalBoolean(value, label, errorClass, code)
 * @since     0.7.0
 * @status    stable
 * @related   b.validateOpts, b.validateOpts.optionalFunction
 *
 * Refuse a value that is neither a boolean nor absent, and answer it
 * otherwise. `undefined` and `null` pass as "not supplied".
 *
 * A string is refused, which is the point: `"false"` is truthy, so a flag
 * read from an environment variable without conversion turns a feature on
 * while the operator reads their config as turning it off.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.validateOpts.optionalBoolean(false, "myThing: opts.strict", MyError, "my/bad-opt");
 *   // → false
 *
 *   b.validateOpts.optionalBoolean("false", "myThing: opts.strict", MyError, "my/bad-opt");
 *   // throws: must be a boolean, got string
 */
function optionalBoolean(value, label, errorClass, code) {
  if (value === undefined || value === null) return value;
  if (typeof value !== "boolean") {
    _throw(errorClass, code, (label || "opt") + " must be a boolean, got " + typeof value,
           "validate-opts/bad-boolean");
  }
  return value;
}

/**
 * @primitive b.validateOpts.optionalPositiveInt
 * @signature b.validateOpts.optionalPositiveInt(value, label, errorClass, code)
 * @since     0.7.0
 * @status    stable
 * @related   b.validateOpts.optionalPositiveFinite, b.validateOpts.optionalFiniteNonNegative
 *
 * Refuse anything that is not a whole number of at least 1, and answer it
 * otherwise. `undefined` and `null` pass as "not supplied".
 *
 * This is the check for a count: retries, workers, batch size. Zero is
 * refused because a count of zero is almost always a mistake rather than a
 * request to do nothing, and a fraction is refused because there is no
 * half a worker. `Infinity` is refused, so an unbounded count cannot be
 * asked for by accident.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.validateOpts.optionalPositiveInt(4, "myThing: opts.workers", MyError, "my/bad-opt");
 *   // → 4
 *
 *   b.validateOpts.optionalPositiveInt(0, "myThing: opts.workers", MyError, "my/bad-opt");
 *   // throws: must be a positive integer (>= 1, finite), got 0
 */
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

/**
 * @primitive b.validateOpts.optionalFiniteNonNegative
 * @signature b.validateOpts.optionalFiniteNonNegative(value, label, errorClass, code)
 * @since     0.7.0
 * @status    stable
 * @related   b.validateOpts.optionalPositiveFinite, b.validateOpts.optionalPositiveInt
 *
 * Refuse anything that is not a finite number of at least 0, and answer it
 * otherwise. `undefined` and `null` pass as "not supplied". A fraction is
 * allowed.
 *
 * This is the check for a quantity where zero means something: a delay of
 * none, a threshold of none. `Infinity` and `NaN` are refused, so a value
 * that arrived from arithmetic on a missing input does not become a timer
 * that never fires.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.validateOpts.optionalFiniteNonNegative(0, "myThing: opts.delayMs", MyError, "my/bad-opt");
 *   // → 0
 *
 *   b.validateOpts.optionalFiniteNonNegative(Infinity, "myThing: opts.delayMs", MyError, "my/bad-opt");
 *   // throws: must be a non-negative finite number, got Infinity
 */
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

/**
 * @primitive b.validateOpts.optionalDate
 * @signature b.validateOpts.optionalDate(value, label, errorClass, code)
 * @since     0.15.13
 * @status    stable
 * @related   b.validateOpts.optionalFiniteNonNegative, b.constants
 *
 * Refuse anything that is not a Date carrying a real time, and answer it
 * otherwise. `undefined` and `null` pass as "not supplied".
 *
 * `new Date("nope")` is a Date whose time is `NaN`, and every comparison
 * against it is false, so it would read as a deadline that is neither
 * past nor future. It is refused here rather than at whatever compares it.
 *
 * A number is refused: epoch milliseconds are not a Date, and the two are
 * easy to pass to the wrong parameter.
 *
 * The check reads the value's internal slot, so a Date built in another
 * realm, by a `node:vm` context for instance, is a Date here too.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.validateOpts.optionalDate(new Date(), "myThing: opts.notAfter", MyError, "my/bad-opt");
 *   // → the Date
 *
 *   b.validateOpts.optionalDate(new Date("nope"), "myThing: opts.notAfter", MyError, "my/bad-opt");
 *   // throws: must be a valid Date
 */
function optionalDate(value, label, errorClass, code) {
  if (value === undefined || value === null) return value;
  if (!nodeTypes.isDate(value) || !isFinite(value.getTime())) {
    _throw(errorClass, code, (label || "opt") + " must be a valid Date",
           "validate-opts/bad-date");
  }
  return value;
}

/**
 * @primitive b.validateOpts.optionalPositiveFinite
 * @signature b.validateOpts.optionalPositiveFinite(value, label, errorClass, code)
 * @since     0.7.0
 * @status    stable
 * @related   b.validateOpts.optionalFiniteNonNegative, b.validateOpts.optionalPositiveInt
 *
 * Refuse anything that is not a finite number above 0, and answer it
 * otherwise. `undefined` and `null` pass as "not supplied". A fraction is
 * allowed.
 *
 * This is the check for a duration or a size that has to be something: a
 * timeout of zero is not a short timeout, it is no timeout, and a cap of
 * zero admits nothing. Both are refused so the mistake surfaces at the
 * call rather than as behavior nobody asked for.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.validateOpts.optionalPositiveFinite(1500, "myThing: opts.timeoutMs", MyError, "my/bad-opt");
 *   // → 1500
 *
 *   b.validateOpts.optionalPositiveFinite(0, "myThing: opts.timeoutMs", MyError, "my/bad-opt");
 *   // throws: must be a positive finite number (> 0), got 0
 */
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

/**
 * @primitive b.validateOpts.optionalFunction
 * @signature b.validateOpts.optionalFunction(value, label, errorClass, code)
 * @since     0.7.0
 * @status    stable
 * @related   b.validateOpts.definedFunction, b.validateOpts.optionalObjectWithMethod
 *
 * Refuse a value that is neither a function nor absent, and answer it
 * otherwise. `undefined` and `null` pass as "not supplied".
 *
 * A hook that is not callable is never called, and a primitive that guards
 * every call site with `typeof` would skip it silently. Refusing here means
 * the operator hears about it at the call that configured it.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.validateOpts.optionalFunction(onError, "myThing: opts.onError", MyError, "my/bad-opt");
 *   // → the function
 *
 *   b.validateOpts.optionalFunction("onError", "myThing: opts.onError", MyError, "my/bad-opt");
 *   // throws: must be a function, got string
 */
function optionalFunction(value, label, errorClass, code) {
  if (value === undefined || value === null) return value;
  if (typeof value !== "function") {
    _throw(errorClass, code, (label || "opt") + " must be a function, got " + typeof value,
           "validate-opts/bad-function");
  }
  return value;
}

/**
 * @primitive b.validateOpts.definedFunctionMessage
 * @signature b.validateOpts.definedFunctionMessage(value, label)
 * @since     0.18.58
 * @status    stable
 * @related   b.validateOpts.definedFunction
 *
 * Answer the complaint about `value`, or null when there is none. It is
 * the message `b.validateOpts.definedFunction` throws, without throwing,
 * for a caller that gathers several complaints before reporting them
 * together.
 *
 * Null means no complaint: a function has none, and neither does
 * `undefined`, which stands for "not supplied". Anything else answers a
 * sentence naming what arrived.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.validateOpts.definedFunctionMessage(function () {}, "onError");   // → null
 *   b.validateOpts.definedFunctionMessage(undefined, "onError");        // → null
 *   b.validateOpts.definedFunctionMessage(42, "onError");
 *   // → a sentence beginning "onError must be a function, got number"
 */
function definedFunctionMessage(value, label) {
  if (value === undefined || typeof value === "function") return null;
  return (label || "opt") + " must be a function, got " +
    (value === null ? "null" : typeof value) +
    " — a value that cannot be called would silently skip the check it requests";
}

/**
 * @primitive b.validateOpts.definedFunction
 * @signature b.validateOpts.definedFunction(value, label, errorClass, code)
 * @since     0.18.58
 * @status    stable
 * @related   b.validateOpts.optionalFunction, b.validateOpts.definedFunctionMessage
 *
 * Refuse a value that was supplied and is not a function. `undefined`
 * passes, meaning nothing was supplied.
 *
 * `null` does not pass, which is the difference from
 * `b.validateOpts.optionalFunction`. Writing `null` is a decision to
 * supply something, and what was supplied cannot be called, so it is the
 * shape of a hook that was meant to be there and is not.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.validateOpts.definedFunction(undefined, "onError", MyError, "my/bad-opt");
 *   // → undefined: nothing was supplied
 *
 *   b.validateOpts.definedFunction(null, "onError", MyError, "my/bad-opt");
 *   // throws: onError must be a function, got null
 */
function definedFunction(value, label, errorClass, code) {
  var msg = definedFunctionMessage(value, label);
  if (msg) _throw(errorClass, code, msg, "validate-opts/bad-function");
  return value;
}

/**
 * @primitive b.validateOpts.optionalPort
 * @signature b.validateOpts.optionalPort(value, label, errorClass, code, opts?)
 * @since     0.14.16
 * @status    stable
 * @related   b.validateOpts.optionalPositiveInt
 *
 * Refuse anything that is not a TCP or UDP port number, and answer it
 * otherwise. A port is a whole number in [1, 65535]. `undefined` and
 * `null` pass as "not supplied".
 *
 * Zero is refused. To the operating system it means "any free port", which
 * is useful in a test and almost never what an operator meant to write in
 * a configuration file, where it reads as a port that was never filled in.
 *
 * @opts
 *   allowZero: boolean,   // accept 0, meaning any free port
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.validateOpts.optionalPort(8443, "myThing: opts.port", MyError, "my/bad-opt");
 *   // → 8443
 *
 *   b.validateOpts.optionalPort(70000, "myThing: opts.port", MyError, "my/bad-opt");
 *   // throws: must be an integer in [1,65535], got number 70000
 */
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

/**
 * @primitive b.validateOpts.applyDefaults
 * @signature b.validateOpts.applyDefaults(opts, defaults)
 * @since     0.7.0
 * @status    stable
 * @related   b.validateOpts, b.validateOpts.assignOwnEnumerable
 *
 * Answer a new object holding `defaults` with `opts` over the top. Neither
 * argument is modified, and a null or undefined `opts` answers the
 * defaults.
 *
 * A key whose value is `undefined` takes the default rather than
 * overriding it with nothing, so building an options object from variables
 * that may be unset does not blank out the defaults for the ones that are.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.validateOpts.applyDefaults({ retries: 5 }, { retries: 3, timeoutMs: 1000 });
 *   // → { retries: 5, timeoutMs: 1000 }
 *
 *   b.validateOpts.applyDefaults({ retries: undefined }, { retries: 3 });
 *   // → { retries: 3 }
 */
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

/**
 * @primitive b.validateOpts.requireObject
 * @signature b.validateOpts.requireObject(opts, callerLabel, errorClass, code)
 * @since     0.7.0
 * @status    stable
 * @related   b.validateOpts.optionalPlainObject, b.validateOpts.requireMethods
 *
 * Refuse anything that is not a non-null object, and answer it otherwise.
 * This is for a primitive whose options are required rather than optional,
 * so `undefined` and `null` are both refused.
 *
 * It asks only whether there is an object there. An array satisfies it;
 * `b.validateOpts.optionalPlainObject` is the check that does not.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.validateOpts.requireObject({ url: "x" }, "myThing.create", MyError, "my/bad-opt");
 *   // → the object
 *
 *   b.validateOpts.requireObject(null, "myThing.create", MyError, "my/bad-opt");
 *   // throws
 */
function requireObject(opts, callerLabel, errorClass, code) {
  if (!opts || typeof opts !== "object") {
    var msg = (callerLabel || "opts") + ": opts must be an object, got " +
      (opts === null ? "null" : typeof opts);
    _throw(errorClass, code, msg, "validate-opts/bad-object");
  }
  return opts;
}

/**
 * @primitive b.validateOpts.requireMethods
 * @signature b.validateOpts.requireMethods(obj, methods, callerLabel, errorClass, code, permanent?)
 * @since     0.14.12
 * @status    stable
 * @related   b.validateOpts.optionalObjectWithMethod, b.validateOpts.requireObject
 *
 * Refuse an object that does not carry every named method as a function,
 * and answer it otherwise. This is how a primitive states what it needs
 * from a dependency an operator supplies: a cache, a store, a transport.
 *
 * The message names the first method that is missing and lists all the
 * ones required, so the reader sees the whole contract rather than
 * discovering it one call at a time.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.validateOpts.requireMethods(store, ["get", "set"], "myThing.create", MyError, "my/bad-opt");
 *   // → store
 *
 *   b.validateOpts.requireMethods({}, ["get", "set"], "myThing.create", MyError, "my/bad-opt");
 *   // throws: myThing.create must expose a get() method (requires { get, set })
 */
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

/**
 * @primitive b.validateOpts.optionalNonEmptyString
 * @signature b.validateOpts.optionalNonEmptyString(value, label, errorClass, code)
 * @since     0.7.0
 * @status    stable
 * @related   b.validateOpts.requireNonEmptyString, b.validateOpts.optionalNonEmptyStringArray
 *
 * Refuse anything that is not a string with something in it, and answer it
 * otherwise. `undefined` and `null` pass as "not supplied".
 *
 * The empty string is refused rather than treated as absent, because the
 * two mean different things and only one of them is a mistake: a name, a
 * namespace or a prefix that came out empty is a value that was built and
 * lost, not a value nobody supplied.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.validateOpts.optionalNonEmptyString("orders", "myThing: opts.namespace", MyError, "my/bad-opt");
 *   // → "orders"
 *
 *   b.validateOpts.optionalNonEmptyString("", "myThing: opts.namespace", MyError, "my/bad-opt");
 *   // throws
 */
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

/**
 * @primitive b.validateOpts.requireNonEmptyString
 * @signature b.validateOpts.requireNonEmptyString(value, label, errorClass, code)
 * @since     0.7.0
 * @status    stable
 * @related   b.validateOpts.optionalNonEmptyString
 *
 * Refuse anything that is not a string with something in it, and answer it
 * otherwise. Unlike the optional form, `undefined` and `null` are refused
 * too: this is for a value the primitive cannot run without.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.validateOpts.requireNonEmptyString("orders", "myThing.create: name", MyError, "my/bad-opt");
 *   // → "orders"
 *
 *   b.validateOpts.requireNonEmptyString(undefined, "myThing.create: name", MyError, "my/bad-opt");
 *   // throws: must be a non-empty string, got undefined
 */
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

/**
 * @primitive b.validateOpts.optionalNonEmptyStringArray
 * @signature b.validateOpts.optionalNonEmptyStringArray(value, label, errorClass, code)
 * @since     0.7.2
 * @status    stable
 * @related   b.validateOpts.optionalNonEmptyString
 *
 * Refuse anything that is not an array whose every entry is a non-empty
 * string, and answer it otherwise. `undefined` and `null` pass as "not
 * supplied".
 *
 * An empty array passes: a list of no allowed hosts, or no scopes, is a
 * list the caller wrote and meant. What is refused is an entry that is not
 * a string, since a list of names holding a number or an object is a list
 * assembled from the wrong thing.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.validateOpts.optionalNonEmptyStringArray(["read", "write"], "myThing: opts.scopes", MyError, "my/bad-opt");
 *   // → ["read", "write"]
 *
 *   b.validateOpts.optionalNonEmptyStringArray([1], "myThing: opts.scopes", MyError, "my/bad-opt");
 *   // throws
 */
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

/**
 * @primitive b.validateOpts.optionalObjectWithMethod
 * @signature b.validateOpts.optionalObjectWithMethod(value, method, label, errorClass, code, description?)
 * @since     0.7.2
 * @status    stable
 * @related   b.validateOpts.requireMethods, b.validateOpts.optionalFunction
 *
 * Refuse a supplied value that is not an object carrying `method` as a
 * function, and answer it otherwise. `undefined` and `null` pass as "not
 * supplied".
 *
 * This is `b.validateOpts.requireMethods` for the single-method case, on an
 * option that may be omitted. `description` names the shape in the message,
 * so the reader is told what kind of thing was wanted rather than only
 * which method was missing.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.validateOpts.optionalObjectWithMethod(signer, "sign", "myThing: opts.signWith",
 *                                           MyError, "my/bad-opt", "a b.auditSign-shaped object");
 *   // → signer
 *
 *   b.validateOpts.optionalObjectWithMethod({}, "sign", "myThing: opts.signWith",
 *                                           MyError, "my/bad-opt", "a b.auditSign-shaped object");
 *   // throws
 */
function optionalObjectWithMethod(value, method, label, errorClass, code, description) {
  if (value === undefined || value === null) return value;
  if (typeof value !== "object" || typeof value[method] !== "function") {
    _throw(errorClass, code, (label || "opt") + " " +
           (description || ("must expose " + method + "() method")),
           "validate-opts/bad-shaped-handle");
  }
  return value;
}

/**
 * @primitive b.validateOpts.optionalPlainObject
 * @signature b.validateOpts.optionalPlainObject(value, label, errorClass, code, description?)
 * @since     0.7.5
 * @status    stable
 * @related   b.validateOpts.requireObject, b.pick
 *
 * Refuse a supplied value that is not a plain object, and answer it
 * otherwise. `undefined` and `null` pass as "not supplied".
 *
 * An array is refused, which is the difference from
 * `b.validateOpts.requireObject`. This is the check for an option that is a
 * bag of named values, headers or labels or metadata, where an array would
 * be read for its numeric keys and quietly contribute nothing.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.validateOpts.optionalPlainObject({ region: "eu" }, "myThing: opts.labels", MyError, "my/bad-opt");
 *   // → { region: "eu" }
 *
 *   b.validateOpts.optionalPlainObject(["eu"], "myThing: opts.labels", MyError, "my/bad-opt");
 *   // throws
 */
function optionalPlainObject(value, label, errorClass, code, description) {
  if (value === undefined || value === null) return value;
  if (typeof value !== "object" || Array.isArray(value)) {
    _throw(errorClass, code, (label || "opt") + " " +
           (description || "must be a plain object or null"),
           "validate-opts/bad-plain-object");
  }
  return value;
}

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
  "optional-positive-finite-int":     numericBounds.requirePositiveFiniteIntIfPresent,
  "optional-non-negative-finite-int": numericBounds.requireNonNegativeFiniteIntIfPresent,
  "required-positive-finite-int":     numericBounds.requirePositiveFiniteInt,
};

/**
 * @primitive b.validateOpts.shape
 * @signature b.validateOpts.shape(opts, schema, callerLabel, errorClass, code, options?)
 * @since     0.15.13
 * @status    stable
 * @related   b.validateOpts, b.safeSchema.object
 *
 * Check a whole options object against a schema in one call, and answer it.
 * The schema maps each key to a rule name or to a function that checks the
 * value itself.
 *
 * The rule names are `required-string`, `optional-string`,
 * `optional-string-array`, `optional-boolean`, `optional-positive-int`,
 * `optional-positive-finite`, `optional-non-negative`, `optional-date`,
 * `optional-function`, `optional-plain-object`, `optional-port`,
 * `optional-positive-finite-int`, `optional-non-negative-finite-int`,
 * `required-positive-finite-int` and `required-object`. Each runs the
 * helper of the same shape.
 *
 * A name outside that list is refused, naming the rule and the field,
 * because a misspelled rule would otherwise check nothing while reading as
 * a check.
 *
 * `opts` must be an object; there is no optional form, since a schema
 * describes options the primitive is going to read.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.validateOpts.shape({ name: "orders", retries: 3 }, {
 *     name:    "required-string",
 *     retries: "optional-positive-int",
 *   }, "myThing.create", MyError, "my/bad-opt");
 *   // → the opts object
 */
function shape(opts, schema, callerLabel, errorClass, code, options) {
  requireObject(opts, callerLabel, errorClass, code);
  var fields = Object.keys(schema);
  for (var i = 0; i < fields.length; i += 1) {
    var field = fields[i];
    var rule = schema[field];
    var fieldCode = code;
    var label = (callerLabel || "opts") + ": " + field;
    var value = opts[field];
    if (typeof rule === "function") { rule(value, label, errorClass, fieldCode, opts); continue; }
    if (rule && typeof rule === "object") {
      if (Array.isArray(rule.methods)) {
        if (rule.optional && (value === undefined || value === null)) continue;
        requireMethods(value, rule.methods, rule.label || label, errorClass, rule.code || code, rule.permanent);
        continue;
      }
      if (rule.shape && typeof rule.shape === "object") {
        if (rule.optional && (value === undefined || value === null)) continue;
        requireObject(value, rule.label || label, errorClass, rule.code || code);
        shape(value, rule.shape, rule.label || label, errorClass, rule.code || code);
        continue;
      }
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

/**
 * @primitive b.validateOpts.makeAuditEmitter
 * @signature b.validateOpts.makeAuditEmitter(audit)
 * @since     0.7.0
 * @status    stable
 * @related   b.validateOpts.auditShape, b.validateOpts.makeNamespacedEmitters
 *
 * Answer a function that emits to `audit`, or one that does nothing when
 * no sink was supplied. The caller emits unconditionally and never tests
 * whether auditing is configured.
 *
 * The emitter never throws. An audit sink is not the caller's reason for
 * running, so a sink that fails must not take the request with it.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var emit = b.validateOpts.makeAuditEmitter(b.audit);
 *   emit({ action: "thing.done", outcome: "success" });
 */
function makeAuditEmitter(audit) {
  if (!audit || typeof audit.safeEmit !== "function") {
    return function _noopEmit() {};
  }
  return function _emit(action, info) {
    try { audit.safeEmit(Object.assign({ action: action }, info || {})); }
    catch (_e) { /* audit best-effort — never break the caller */ }
  };
}

/**
 * @primitive b.validateOpts.makeNamespacedEmitters
 * @signature b.validateOpts.makeNamespacedEmitters(prefix, deps)
 * @since     0.8.62
 * @status    stable
 * @related   b.validateOpts.makeAuditEmitter, b.observability.safeEvent
 *
 * Answer `{ audit, metric }`, two emitters that put `prefix` in front of
 * every name they send. A primitive builds them once and emits without
 * repeating its own name at each call site, so the names it reports cannot
 * drift apart from one another.
 *
 * Both are drop-safe: neither an audit sink nor a metrics sink is the
 * caller's reason for running.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var emit = b.validateOpts.makeNamespacedEmitters("myThing", { audit: b.audit });
 *   emit.audit("started", "success", { region: "eu" });
 *   emit.metric("queue.depth", 12);
 */
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

/**
 * @primitive b.validateOpts.assignOwnEnumerable
 * @signature b.validateOpts.assignOwnEnumerable(target, source, reservedKeys?)
 * @since     0.14.22
 * @status    stable
 * @related   b.pick, b.validateOpts.applyDefaults
 *
 * Copy `source`'s own enumerable keys onto `target` and answer `target`,
 * skipping anything named in `reservedKeys`.
 *
 * It is `Object.assign` with two differences that matter when the source
 * came from outside: nothing inherited is copied, and the keys the caller
 * reserves for its own use cannot be overwritten by the source. A caller
 * merging operator input onto a record uses this so a field the record
 * owns, an id or a tenant, stays the record's.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.validateOpts.assignOwnEnumerable({}, { name: "ada", tenantId: "evil" }, ["tenantId"]);
 *   // → { name: "ada" }
 */
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
  return Object.assign(target, Object.fromEntries(entries));
}

/**
 * @primitive b.validateOpts.outboundHttpOpts
 * @signature b.validateOpts.outboundHttpOpts(value, callerLabel, errorClass, codePrefix)
 * @since     0.18.18
 * @status    stable
 * @related   b.httpClient.request, b.ssrfGuard.classify
 *
 * Check the options a primitive takes for making outbound HTTP requests,
 * and answer them resolved as `{ client, allowedHosts }`, both null when
 * nothing was supplied.
 *
 * Every primitive that calls out to a URL takes the same two: a replacement
 * HTTP client, which is what a test supplies instead of a socket, and the
 * hosts it may reach. Checking them in one place means a primitive that
 * adds an outbound call gets the host restriction rather than reinventing
 * it or leaving it out.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.validateOpts.outboundHttpOpts({ allowedHosts: ["api.example"] },
 *                                   "myThing.create", MyError, "my");
 *   // → { client: null, allowedHosts: ["api.example"] }
 */
function outboundHttpOpts(value, callerLabel, errorClass, codePrefix) {
  var label  = callerLabel || "opts";
  var prefix = codePrefix || "validate-opts";
  if (value === undefined || value === null) return { client: null, allowedHosts: null };
  optionalPlainObject(value, label + ": http", errorClass, prefix + "/bad-http",
                      "must be a plain object of { client, allowedHosts }");
  var known = { client: true, allowedHosts: true };
  var keys  = Object.keys(value);
  for (var i = 0; i < keys.length; i += 1) {
    if (!Object.prototype.hasOwnProperty.call(known, keys[i])) {
      _throw(errorClass, prefix + "/bad-http",
             label + ": http has unknown option '" + keys[i] +
             "' — expected client, allowedHosts",
             "validate-opts/bad-http");
    }
  }
  optionalObjectWithMethod(value.client, "request", label + ": http.client",
                           errorClass, prefix + "/bad-http-client",
                           "must be a b.httpClient-shaped object (request fn)");
  optionalNonEmptyStringArray(value.allowedHosts, label + ": http.allowedHosts",
                              errorClass, prefix + "/bad-http-allowed-hosts");
  if (value.allowedHosts !== undefined && value.allowedHosts !== null &&
      value.allowedHosts.length === 0) {
    _throw(errorClass, prefix + "/bad-http-allowed-hosts",
           label + ": http.allowedHosts must name at least one host",
           "validate-opts/bad-http-allowed-hosts");
  }
  return {
    client:       value.client || null,
    allowedHosts: (value.allowedHosts && value.allowedHosts.length)
                    ? value.allowedHosts.slice() : null,
  };
}

/**
 * @primitive b.validateOpts.observabilityShape
 * @signature b.validateOpts.observabilityShape(observability, callerLabel, errorClass, code)
 * @since     0.7.0
 * @status    stable
 * @related   b.validateOpts.auditShape, b.observability.event
 *
 * Refuse an `observability` option that is not a metrics sink, and answer
 * it otherwise. A sink is an object carrying an `event` function, which is
 * the shape `b.observability` has. `undefined` and `null` pass as "not
 * supplied".
 *
 * An object carrying only `safeEvent` is refused: that is the drop-silent
 * wrapper rather than the namespace, and a primitive handed it would find
 * the call it expected missing.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.validateOpts.observabilityShape(b.observability, "myThing.create", MyError, "my/bad-opt");
 *   // → the sink
 *
 *   b.validateOpts.observabilityShape({}, "myThing.create", MyError, "my/bad-opt");
 *   // throws: observability must be a b.observability-shaped object (event fn)
 */
function observabilityShape(observability, callerLabel, errorClass, code) {
  if (observability === undefined || observability === null) return observability;
  if (typeof observability !== "object" || typeof observability.event !== "function") {
    var msg = (callerLabel || "observability") +
      ": observability must be a b.observability-shaped object (event fn)";
    _throw(errorClass, code, msg, "observability/bad-shape");
  }
  return observability;
}

/**
 * @primitive b.validateOpts.checkOrThrow
 * @signature b.validateOpts.checkOrThrow(opts, allowedKeys, primitive, ErrorClass, code)
 * @since     0.18.61
 * @status    stable
 * @related   b.validateOpts, b.validateOpts.shape
 *
 * The unknown-key check of `b.validateOpts`, raising the caller's own error
 * class and code instead of a plain `Error`.
 *
 * The message is the same. What changes is what a caller catches: a
 * primitive whose every other refusal is its own error type reports a
 * misspelled option the same way, so an operator matches on one class
 * rather than on that class and `Error`.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   try {
 *     b.validateOpts.checkOrThrow({ maxBytes: 1 }, ["maxSize"], "myThing.create",
 *                                 MyError, "my/bad-opt");
 *   } catch (e) {
 *     e.code;   // → "my/bad-opt"
 *   }
 */
function checkOrThrow(opts, allowedKeys, primitive, ErrorClass, code) {
  try { check(opts, allowedKeys, primitive); }
  catch (e) { throw new ErrorClass(code, (e && e.message) || "unknown option"); }
}

module.exports = check;
module.exports.check = check;
module.exports.checkOrThrow = checkOrThrow;
module.exports.auditShape = auditShape;
module.exports.optionalBoolean = optionalBoolean;
module.exports.optionalPositiveInt = optionalPositiveInt;
module.exports.optionalFiniteNonNegative = optionalFiniteNonNegative;
module.exports.optionalDate = optionalDate;
module.exports.optionalPositiveFinite = optionalPositiveFinite;
module.exports.optionalPort = optionalPort;
module.exports.optionalFunction = optionalFunction;
module.exports.definedFunction = definedFunction;
module.exports.definedFunctionMessage = definedFunctionMessage;
module.exports.optionalNonEmptyString = optionalNonEmptyString;
module.exports.optionalNonEmptyStringArray = optionalNonEmptyStringArray;
module.exports.optionalObjectWithMethod = optionalObjectWithMethod;
module.exports.optionalPlainObject = optionalPlainObject;
module.exports.outboundHttpOpts = outboundHttpOpts;
module.exports.requireNonEmptyString = requireNonEmptyString;
module.exports.observabilityShape = observabilityShape;
module.exports.requireObject = requireObject;
module.exports.requireMethods = requireMethods;
module.exports.shape = shape;
module.exports.applyDefaults = applyDefaults;
module.exports.makeAuditEmitter = makeAuditEmitter;
module.exports.makeNamespacedEmitters = makeNamespacedEmitters;
module.exports.assignOwnEnumerable = assignOwnEnumerable;
