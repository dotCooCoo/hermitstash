"use strict";
/**
 * numeric-bounds — shared validators for operator-tunable numeric opts.
 *
 * Replaces the recurring `typeof opts.X === "number" && opts.X > 0`
 * pattern that ships across the framework. Pre-v0.6.69 each site had
 * its own slightly-different inline check; the bug they all shared was
 * accepting `Infinity` (silently bypassing OOM caps, body size limits,
 * URL caps, depth limits) and `NaN` (also bypassing because every
 * comparison with NaN is false). v0.6.57 fixed boundedChunkCollector,
 * v0.6.68 fixed atomicFile, v0.6.69 sweeps the rest.
 *
 *   var nb = require("./numeric-bounds");
 *
 *   if (!nb.isPositiveFiniteInt(opts.maxBytes)) {
 *     throw new CsvError("csv/bad-opt",
 *       "csv.parse: maxBytes must be a positive finite integer; got " +
 *       nb.shape(opts.maxBytes));
 *   }
 *
 * The helper returns a predicate + a shape-formatter rather than
 * throwing itself, because the framework's error classes use two
 * different constructor conventions:
 *
 *   AtomicFileError, SafeBufferError, SafeUrlError       (message, code)
 *   defineClass(...)-built (CsvError, MailBounceError…)  (code, message, permanent[, statusCode])
 *
 * Each call site throws its own class, with whatever ctor shape that
 * class wants. The helper just owns the validation rule + the consistent
 * shape format ("number Infinity" / "number NaN" / "string \"100\"") so
 * the typo / coercion is visible in the error message — `JSON.stringify`
 * collapses Infinity / NaN to "null" which obscures what went wrong.
 */

// Shape formatter — typeof + String preserves "number Infinity" /
// "number NaN" / "string foo". Strings get JSON-quoted so trailing
// whitespace / control chars are visible.
function shape(value) {
  if (typeof value === "string") {
    return "string " + JSON.stringify(value);
  }
  return (typeof value) + " " + String(value);
}

// _throwInt — construct + throw a code-first defineClass error. When no
// errorOpts is supplied the call is the historical bare `new ErrorClass(
// code, message)` (byte-identical for every existing caller); pass
// errorOpts { permanent, statusCode } to forward the framework error's
// non-retryable flag / HTTP status (a config opt that's wrong on retry
// stays wrong; a request-shaped opt carries its 4xx). Message-FIRST
// classes (AtomicFileError / SafeBufferError / SafeUrlError) must NOT use
// the require* throwers — they use the isPositiveFiniteInt predicate + their
// own throw (see the module header) so code/message don't swap.
function _throwInt(errorClass, code, message, errorOpts) {
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

// Any-sign finite integer (no sign bound) — for callers that only require
// integrality (e.g. a CloudEvents 32-bit signed-integer extension, a DNS
// algorithm/digest-type code) and reject only non-numbers / floats / Infinity /
// NaN. Distinct from isNonNegativeFiniteInt (which also forbids negatives).
function isFiniteInt(value) {
  return typeof value === "number" && Number.isFinite(value) && Number.isInteger(value);
}

// requirePositiveFiniteIntIfPresent / requireNonNegativeFiniteIntIfPresent —
// optional-shape gates that throw via the caller's framework-error class
// when the value is present but invalid. Replaces the per-file
// `if (opts.X !== undefined) { if (!nb.isYFiniteInt(opts.X)) throw new
// XError(...); }` cascade that app-shutdown / bundler / dev /
// http-client-cookie-jar / external-db-migrate / restore-rollback
// previously rolled by hand.
//
//   var nb = require("./numeric-bounds");
//   nb.requirePositiveFiniteIntIfPresent(opts.graceMs,
//     "app-shutdown.create: opts.graceMs", AppShutdownError,
//     "app-shutdown/bad-grace-ms");
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
    throw new errorClass(code,
      (label || "value") + " must be a non-negative finite integer; got " + shape(value));
  }
  return value;
}

// requirePositiveFiniteInt — REQUIRED-shape gate (the non-optional sibling
// of requirePositiveFiniteIntIfPresent): throws when the value is absent OR
// not a positive finite integer, and — when range bounds are supplied —
// when it falls outside them. Replaces the per-file
// `if (!nb.isPositiveFiniteInt(opts.X) || opts.X < MIN || opts.X > MAX) throw`
// cascade that bundler / mail-scan / safe-decompress rolled by hand for
// REQUIRED numeric opts (the IfPresent helper can't be used there — it
// skips when undefined, so a missing required opt would pass).
//
//   nb.requirePositiveFiniteInt(opts.maxOutputBytes,
//     "safeDecompress: maxOutputBytes", SafeDecompressError, "safe-decompress/bad-arg");
//   nb.requirePositiveFiniteInt(opts.hashLen, "bundler.create: opts.hashLen",
//     BundlerError, "bundler/bad-hash-len", { min: MIN_HASH_LEN, max: MAX_HASH_LEN });
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

// requireAllPositiveFiniteIntIfPresent — batch validator. Walk each
// opt-name in the list; for any that is present in opts, require it to
// be a positive finite integer (otherwise throw via errorClass with the
// shared code). Used by primitives whose entry points have a 3-6
// numeric opts that all share the same shape constraint, so the inline
// call sequence doesn't repeat per primitive.
//
//   nb.requireAllPositiveFiniteIntIfPresent(opts,
//     ["maxBytes", "maxAttrValueBytes", "maxTagDepth", "maxAttrsPerTag"],
//     "guardHtml.validate", GuardHtmlError, "html.bad-opt");
function requireAllPositiveFiniteIntIfPresent(opts, names, labelPrefix, errorClass, code, errorOpts) {
  if (!opts || !Array.isArray(names)) return;
  for (var i = 0; i < names.length; i += 1) {
    var n = names[i];
    requirePositiveFiniteIntIfPresent(opts[n],
      (labelPrefix || "") + ": " + n, errorClass, code, errorOpts);
  }
}

module.exports = {
  shape:                                  shape,
  isPositiveFiniteInt:                    isPositiveFiniteInt,
  isNonNegativeFiniteInt:                 isNonNegativeFiniteInt,
  isFiniteInt:                            isFiniteInt,
  requirePositiveFiniteInt:               requirePositiveFiniteInt,
  requirePositiveFiniteIntIfPresent:      requirePositiveFiniteIntIfPresent,
  requireNonNegativeFiniteIntIfPresent:   requireNonNegativeFiniteIntIfPresent,
  requireAllPositiveFiniteIntIfPresent:   requireAllPositiveFiniteIntIfPresent,
};
