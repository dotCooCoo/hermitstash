"use strict";
/**
 * bounded-map — a Map facade that caps its entry count.
 *
 * Defends the unbounded-in-bounded resource-exhaustion class: an in-memory
 * store keyed on request-derived input (a locale, a hostname, an
 * idempotency key, a replay nonce) grows without limit between sweeps
 * unless something enforces a ceiling. A periodic TTL sweep alone does not
 * bound peak memory — a flood of unique keys arrives faster than the sweep
 * interval. This adds the missing ceiling.
 *
 * Two policies for what happens on `set` when already at `maxEntries`:
 *
 *   "evict-oldest" (default) — drop the oldest entry (insertion order)
 *     to make room, then store the new one. For caches whose entries are
 *     re-derivable on demand (Intl formatters, DNS results, idempotency
 *     records) eviction is cheap — the worst case is a recomputed value or
 *     a missed dedup under active flood, never a correctness or security
 *     hole. `set` always stores and returns true.
 *
 *   "reject" — refuse the new entry (do NOT evict a live one) and return
 *     false. For stores where evicting an unexpired entry would be unsafe:
 *     a replay-protection nonce store must not drop a live nonce to admit a
 *     new one, because that reopens a replay window for the dropped nonce.
 *     The caller fails closed on a false return (treats the request as
 *     un-recordable → reject it). Callers should purge expired entries
 *     before relying on this so the ceiling is hit only under genuine flood.
 *
 * This is deliberately NOT `b.cache` — that is an operator-facing primitive
 * with TTL, LRU-touch, observability, and pluggable backends. This is the
 * minimal internal ceiling the framework's own request-keyed Maps need, and
 * leaves TTL/expiry semantics to the caller (which already owns them).
 *
 * `onEvict(key, value)` (optional) fires when an entry is dropped to make
 * room under "evict-oldest" — for an observability counter, say. It never
 * fires under "reject" (nothing is evicted; the new entry is dropped).
 */

var numericBounds = require("./numeric-bounds");
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
    // Updating an existing key never grows the map — always allowed.
    if (inner.has(key)) { inner.set(key, value); return true; }
    if (inner.size >= maxEntries) {
      if (policy === "reject") return false;
      // evict-oldest: the first key in insertion order is the oldest.
      var oldest = inner.keys().next().value;
      if (oldest !== undefined || inner.has(oldest)) {
        var evictedVal = inner.get(oldest);
        inner.delete(oldest);
        if (onEvict) { try { onEvict(oldest, evictedVal); } catch (_e) { /* obs hook — drop-silent */ } }
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
    // Iterable like a Map, so `for (var e of bmap)` yields [key, value]
    // entries — callers that iterate a plain Map keep working unchanged.
    [Symbol.iterator]: function () { return inner[Symbol.iterator](); },
  };
}

// getOrInsert(map, key, factory, opts?) — Map.prototype.getOrInsertComputed(key,
// factory) polyfill. The native method lands in Node 26 but the framework floor
// is 24.16, so the framework's request-keyed Maps hand-roll `var v = m.get(k);
// if (!v) { v = ...; m.set(k, v); }` everywhere. This is the ONE place that
// shape lives, so the floor-bump sweep swaps the body for the native method in
// a single edit instead of N call sites. Returns the existing value; otherwise
// computes factory(key), stores it, and returns it.
//
// Optional cardinality ceiling so a CAPPED caller (e.g. b.metrics' label
// cardinality cap) composes this rather than re-rolling the get-then-set with
// its own size guard: when `opts.maxSize` is a number and the key is absent at
// or above that size, the value is NOT stored and `opts.onFull(key)` (or
// undefined) is returned. Works on a plain Map or the boundedMap facade above.
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
    // A bad maxSize silently breaks the ceiling (NaN/Infinity never cap →
    // unbounded; negative always caps → never stores) — validate via the
    // shared numeric-bounds / validate-opts assertions, never a hand-rolled
    // typeof check.
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

// requireAbsent / requirePresent complete the keyed-store guard family that
// getOrInsert opened. A framework registry (topics, jobs, metrics, RoPA
// activities, DSR tickets, …) keys a Map and guards every mutation by
// presence: a unique INSERT throws on a duplicate key, an UPDATE/lookup throws
// when the key is missing. That guard — `if (map.has(k)) throw <duplicate>` /
// `if (!map.has(k)) throw <not-found>` — recurred across ~18 registries, each
// re-rolling the check beside its own .set. Centralizing it makes the
// uniqueness/existence check impossible to forget (the primitive IS the check)
// while leaving the caller its own typed error and value shape.

// requireAbsent(map, key, onConflict) — uniqueness guard before an insert.
// When `key` is already present, invokes onConflict(key, existingValue)
// (callers throw their own typed duplicate error from it) and returns its
// result; otherwise returns undefined and the caller performs its insert.
function requireAbsent(map, key, onConflict) {
  _assertMapLike(map, "requireAbsent");
  if (typeof onConflict !== "function") {
    throw new BoundedMapError("bounded-map/bad-on-conflict",
      "requireAbsent: onConflict must be a function, got " + (typeof onConflict));
  }
  if (map.has(key)) return onConflict(key, map.get(key));
  return undefined;
}

// requirePresent(map, key, onMissing) — existence guard before an update or
// lookup. When `key` is absent, invokes onMissing(key) (callers throw their
// own typed not-found error) and returns its result; otherwise returns the
// existing value, so a must-exist lookup is a single call.
function requirePresent(map, key, onMissing) {
  _assertMapLike(map, "requirePresent");
  if (typeof onMissing !== "function") {
    throw new BoundedMapError("bounded-map/bad-on-missing",
      "requirePresent: onMissing must be a function, got " + (typeof onMissing));
  }
  if (!map.has(key)) return onMissing(key);
  return map.get(key);
}

// requireAbsentMember(set, key, onConflict) — the Set sibling of requireAbsent.
// A value-LESS membership store (a Set tracking seen keys while parsing, or
// visited nodes during a recursive walk) rejects a re-occurrence:
// `if (set.has(key)) throw <duplicate|cycle>` before `set.add(key)`. Unlike
// requireAbsent (a keyed Map with values), the container has nothing to return,
// so only `.has` is required — a Set, or any { has } membership view. When the
// member is already present, invokes onConflict(key) (the caller throws its own
// typed duplicate / cycle error) and returns its result; otherwise returns
// undefined and the caller performs its `.add`.
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
