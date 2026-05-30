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

module.exports = { boundedMap: boundedMap, BoundedMapError: BoundedMapError };
