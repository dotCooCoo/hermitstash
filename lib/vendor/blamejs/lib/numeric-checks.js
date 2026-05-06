"use strict";
/**
 * numeric-checks — predicate helpers for opts / arg validation.
 *
 * Existed previously as private `_isPositiveInt` / `_isFiniteNonNegative`
 * / `_isNonNegFinite` copies inside api-key, cache, notify, retry, slug,
 * testing, webhook, and (new in v0.6.12) inline checks in queue and
 * restore. Same shape, different file — that's the repeat-means-primitive
 * rule. Everything routes through here now so adding (e.g.) NaN-or-
 * Infinity-string handling is a one-file change.
 *
 * Predicates only — callers throw with their own framework-error class.
 *
 *   isPositiveInt(n)        n is a finite integer >= 1
 *   isFiniteNonNegative(n)  n is a finite number >= 0
 *   isPositiveFinite(n)     n is a finite number > 0
 *
 * All return false for non-numbers, NaN, Infinity, -Infinity, null,
 * undefined, strings, etc. — operators get one consistent gate against
 * the silent-NaN-cap class of bug regardless of which primitive they're
 * configuring.
 */

function isPositiveInt(n) {
  return typeof n === "number" && isFinite(n) && n >= 1 && Math.floor(n) === n;
}

function isFiniteNonNegative(n) {
  return typeof n === "number" && isFinite(n) && n >= 0;
}

function isPositiveFinite(n) {
  return typeof n === "number" && isFinite(n) && n > 0;
}

module.exports = {
  isPositiveInt:        isPositiveInt,
  isFiniteNonNegative:  isFiniteNonNegative,
  isPositiveFinite:     isPositiveFinite,
};
