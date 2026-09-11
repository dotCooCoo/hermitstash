// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var numericBounds = require("./numeric-bounds");
var safeAsync = require("./safe-async");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var BoundedMapError = defineClass("BoundedMapError");

/**
 * @param {object} opts
 * @param {number} opts.maxEntries    - hard ceiling; throws if not a positive finite int
 * @param {string} [opts.policy]      - "evict-oldest" (default) | "reject"
 * @param {function} [opts.onEvict]   - (key, value) called on eviction under "evict-oldest"
 * @returns Map-like facade: get/has/set/delete/clear, size getter, keys/values/entries/forEach, [Symbol.iterator]
 */
function boundedMap(opts) {
  opts = opts || {};
  if (!numericBounds.isPositiveFiniteInt(opts.maxEntries)) {
    throw new BoundedMapError("bounded-map/bad-max-entries",
      "boundedMap: opts.maxEntries must be a positive finite integer, got " + JSON.stringify(opts.maxEntries));
  }
  var maxEntries = opts.maxEntries;
  var policy = opts.policy || "evict-oldest";
  if (policy !== "evict-oldest" && policy !== "reject") {
    throw new BoundedMapError("bounded-map/bad-policy",
      "boundedMap: opts.policy must be 'evict-oldest' | 'reject', got " + JSON.stringify(policy));
  }
  var onEvict = typeof opts.onEvict === "function" ? opts.onEvict : null;
  var inner = new Map();

  function set(key, value) {
    if (inner.has(key)) { inner.set(key, value); return true; }
    if (inner.size >= maxEntries) {
      if (policy === "reject") return false;
      var oldest = inner.keys().next().value;
      if (oldest !== undefined || inner.has(oldest)) {
        var evictedVal = inner.get(oldest);
        inner.delete(oldest);
        safeAsync.safeApply(onEvict, [oldest, evictedVal]);
      }
    }
    inner.set(key, value);
    return true;
  }

  return {
    get:    function (k) { return inner.get(k); },
    has:    function (k) { return inner.has(k); },
    set:    set,
    delete: function (k) { return inner.delete(k); },
    clear:  function () { inner.clear(); },
    keys:   function () { return inner.keys(); },
    values: function () { return inner.values(); },
    entries: function () { return inner.entries(); },
    forEach: function (fn, thisArg) { return inner.forEach(fn, thisArg); },
    get size() { return inner.size; },
    get maxEntries() { return maxEntries; },
    get policy() { return policy; },
    [Symbol.iterator]: function () { return inner[Symbol.iterator](); },
  };
}

function _assertMapLike(map, fnName) {
  validateOpts.requireMethods(map, ["has", "get", "set"],
    fnName + ": map (Map-like)", BoundedMapError, "bounded-map/bad-map");
}

function getOrInsert(map, key, factory, opts) {
  _assertMapLike(map, "getOrInsert");
  if (typeof factory !== "function") {
    throw new BoundedMapError("bounded-map/bad-factory",
      "getOrInsert: factory must be a function, got " + (typeof factory));
  }
  if (map.has(key)) return map.get(key);
  if (opts && opts.maxSize !== undefined) {
    numericBounds.requirePositiveFiniteIntIfPresent(opts.maxSize,
      "getOrInsert: opts.maxSize", BoundedMapError, "bounded-map/bad-max-size");
    validateOpts.optionalFunction(opts.onFull,
      "getOrInsert: opts.onFull", BoundedMapError, "bounded-map/bad-on-full");
    if (map.size >= opts.maxSize) {
      return opts.onFull ? opts.onFull(key) : undefined;
    }
  }
  var value = factory(key);
  map.set(key, value);
  return value;
}

function requireAbsent(map, key, onConflict) {
  _assertMapLike(map, "requireAbsent");
  if (typeof onConflict !== "function") {
    throw new BoundedMapError("bounded-map/bad-on-conflict",
      "requireAbsent: onConflict must be a function, got " + (typeof onConflict));
  }
  if (map.has(key)) return onConflict(key, map.get(key));
  return undefined;
}

function requirePresent(map, key, onMissing) {
  _assertMapLike(map, "requirePresent");
  if (typeof onMissing !== "function") {
    throw new BoundedMapError("bounded-map/bad-on-missing",
      "requirePresent: onMissing must be a function, got " + (typeof onMissing));
  }
  if (!map.has(key)) return onMissing(key);
  return map.get(key);
}

function requireAbsentMember(set, key, onConflict) {
  if (!set || typeof set.has !== "function") {
    throw new BoundedMapError("bounded-map/bad-set",
      "requireAbsentMember: set must be a Set-like { has }");
  }
  if (typeof onConflict !== "function") {
    throw new BoundedMapError("bounded-map/bad-on-conflict",
      "requireAbsentMember: onConflict must be a function, got " + (typeof onConflict));
  }
  if (set.has(key)) return onConflict(key);
  return undefined;
}

module.exports = {
  boundedMap:          boundedMap,
  BoundedMapError:     BoundedMapError,
  getOrInsert:         getOrInsert,
  requireAbsent:       requireAbsent,
  requirePresent:      requirePresent,
  requireAbsentMember: requireAbsentMember,
};
