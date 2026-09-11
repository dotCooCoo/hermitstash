// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

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

function definedFunctionMessage(value, label) {
  if (value === undefined || typeof value === "function") return null;
  return (label || "opt") + " must be a function, got " +
    (value === null ? "null" : typeof value) +
    " — a value that cannot be called would silently skip the check it requests";
}

function definedFunction(value, label, errorClass, code) {
  var msg = definedFunctionMessage(value, label);
  if (msg) _throw(errorClass, code, msg, "validate-opts/bad-function");
  return value;
}

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

function requireObject(opts, callerLabel, errorClass, code) {
  if (!opts || typeof opts !== "object") {
    var msg = (callerLabel || "opts") + ": opts must be an object, got " +
      (opts === null ? "null" : typeof opts);
    _throw(errorClass, code, msg, "validate-opts/bad-object");
  }
  return opts;
}

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

function optionalObjectWithMethod(value, method, label, errorClass, code, description) {
  if (value === undefined || value === null) return value;
  if (typeof value !== "object" || typeof value[method] !== "function") {
    _throw(errorClass, code, (label || "opt") + " " +
           (description || ("must expose " + method + "() method")),
           "validate-opts/bad-shaped-handle");
  }
  return value;
}

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

function makeAuditEmitter(audit) {
  if (!audit || typeof audit.safeEmit !== "function") {
    return function _noopEmit() {};
  }
  return function _emit(action, info) {
    try { audit.safeEmit(Object.assign({ action: action }, info || {})); }
    catch (_e) { /* audit best-effort — never break the caller */ }
  };
}

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

function observabilityShape(observability, callerLabel, errorClass, code) {
  if (observability === undefined || observability === null) return observability;
  if (typeof observability !== "object" || typeof observability.event !== "function") {
    var msg = (callerLabel || "observability") +
      ": observability must be a b.observability-shaped object (event fn)";
    _throw(errorClass, code, msg, "observability/bad-shape");
  }
  return observability;
}

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
