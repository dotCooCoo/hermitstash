// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

function shape(value) {
  if (typeof value === "string") {
    return "string " + JSON.stringify(value);
  }
  return (typeof value) + " " + String(value);
}

function _throwInt(errorClass, code, message, errorOpts) {
  if (errorClass && typeof errorClass.factory === "function") {
    throw errorClass.factory(code, message,
      errorOpts ? errorOpts.permanent : undefined,
      errorOpts ? errorOpts.statusCode : undefined);
  }
  if (errorOpts) throw new errorClass(code, message, errorOpts.permanent, errorOpts.statusCode);
  throw new errorClass(code, message);
}

function isPositiveFiniteInt(value) {
  return typeof value === "number" && Number.isFinite(value) &&
         Number.isInteger(value) && value > 0;
}

function isNonNegativeFiniteInt(value) {
  return typeof value === "number" && Number.isFinite(value) &&
         Number.isInteger(value) && value >= 0;
}

function isNonNegativeSafeInt(value) {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isIncrementableSafeInt(value) {
  return isNonNegativeSafeInt(value) && value < Number.MAX_SAFE_INTEGER;
}

function isFiniteInt(value) {
  return typeof value === "number" && Number.isFinite(value) && Number.isInteger(value);
}

function isPositiveFiniteNumber(value) {
  return typeof value === "number" && Number.isFinite(value) && value > 0;
}

function requirePositiveFiniteNumberIfPresent(value, label, errorClass, code) {
  if (value === undefined) return value;
  if (!isPositiveFiniteNumber(value)) {
    _throwInt(errorClass, code,
      (label || "value") + " must be a positive finite number; got " + shape(value));
  }
  return value;
}

function requirePositiveFiniteIntIfPresent(value, label, errorClass, code, errorOpts) {
  if (value === undefined) return value;
  if (!isPositiveFiniteInt(value)) {
    _throwInt(errorClass, code,
      (label || "value") + " must be a positive finite integer; got " + shape(value), errorOpts);
  }
  return value;
}

function requireNonNegativeFiniteIntIfPresent(value, label, errorClass, code) {
  if (value === undefined) return value;
  if (!isNonNegativeFiniteInt(value)) {
    _throwInt(errorClass, code,
      (label || "value") + " must be a non-negative finite integer; got " + shape(value));
  }
  return value;
}

function _rangeSuffix(range) {
  if (!range) return "";
  if (range.min != null && range.max != null) return " in [" + range.min + ", " + range.max + "]";
  if (range.max != null) return " <= " + range.max;
  if (range.min != null) return " >= " + range.min;
  return "";
}
function requirePositiveFiniteInt(value, label, errorClass, code, range, errorOpts) {
  var inRange = !range ||
    ((range.min == null || value >= range.min) && (range.max == null || value <= range.max));
  if (!isPositiveFiniteInt(value) || !inRange) {
    _throwInt(errorClass, code,
      (label || "value") + " must be a positive finite integer" +
      _rangeSuffix(range) + "; got " + shape(value), errorOpts);
  }
  return value;
}

function requireAllPositiveFiniteIntIfPresent(opts, names, labelPrefix, errorClass, code, errorOpts) {
  if (!opts || !Array.isArray(names)) return;
  for (var i = 0; i < names.length; i += 1) {
    var n = names[i];
    requirePositiveFiniteIntIfPresent(opts[n],
      (labelPrefix || "") + ": " + n, errorClass, code, errorOpts);
  }
}

function isFiniteNumericDate(value) {
  return typeof value === "number" && Number.isFinite(value);
}

function requireFiniteNumericDate(value, label, errorClass, code, errorOpts) {
  if (!isFiniteNumericDate(value)) {
    _throwInt(errorClass, code,
      (label || "value") + " must be a finite number (RFC 7519 NumericDate); got " + shape(value), errorOpts);
  }
  return value;
}

function finiteTimestamp(value) {
  var n = Number(value);
  return isFinite(n) ? n : -Infinity;
}

module.exports = {
  shape:                                  shape,
  finiteTimestamp:                        finiteTimestamp,
  isFiniteNumericDate:                    isFiniteNumericDate,
  requireFiniteNumericDate:               requireFiniteNumericDate,
  isPositiveFiniteInt:                    isPositiveFiniteInt,
  isNonNegativeFiniteInt:                 isNonNegativeFiniteInt,
  isNonNegativeSafeInt:                   isNonNegativeSafeInt,
  isIncrementableSafeInt:                 isIncrementableSafeInt,
  isFiniteInt:                            isFiniteInt,
  isPositiveFiniteNumber:                 isPositiveFiniteNumber,
  requirePositiveFiniteNumberIfPresent:   requirePositiveFiniteNumberIfPresent,
  requirePositiveFiniteInt:               requirePositiveFiniteInt,
  requirePositiveFiniteIntIfPresent:      requirePositiveFiniteIntIfPresent,
  requireNonNegativeFiniteIntIfPresent:   requireNonNegativeFiniteIntIfPresent,
  requireAllPositiveFiniteIntIfPresent:   requireAllPositiveFiniteIntIfPresent,
};
