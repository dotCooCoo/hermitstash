"use strict";
/**
 * Canonical JSON — deterministic stringify with sorted keys at every depth.
 *
 * Replaces the four near-identical implementations that grew up across
 * `lib/audit-chain.js`, `lib/audit-tools.js`, `lib/config-drift.js`, and
 * `lib/pagination.js`. They all walked `typeof === "object"` with
 * `Object.keys(...).sort()` and silently round-tripped Date as `{}`,
 * Buffer as `{"0":97,"1":98,…}`, Map / Set / RegExp as `{}`, Symbol /
 * function as missing keys, and BigInt as a thrown
 * `Do not know how to serialize a BigInt` mid-emit. Circular references
 * stack-overflowed instead of producing a clean framework error.
 *
 * The walk:
 *
 *   primitives + null + undefined → JSON.stringify (undefined → "null")
 *   bigint                        → decimal string  ("123" not 123n)
 *   Date                          → ISO string
 *   Buffer / Uint8Array           → hex (when bufferAs = "hex", default)
 *                                   throw     (when bufferAs = "reject")
 *   Map / Set / RegExp            → throw with constructor name
 *   symbol / function             → throw with type name
 *   circular reference            → throw via WeakSet detection
 *   plain array                   → recurse, preserve order
 *   plain object                  → recurse with sorted keys
 *
 * Two consumer policies on Buffer / Uint8Array are documented because
 * the framework historically chose differently per call site:
 *
 *   bufferAs: "hex"     audit-chain / audit-tools / config-drift —
 *                        binary data is legitimate (cert PEMs, key
 *                        material, hash bytes); preserve as hex so the
 *                        canonical output is reversible.
 *   bufferAs: "reject"  pagination — cursor state is operator-supplied
 *                        primitive data; binary in a cursor is almost
 *                        always a bug; reject loudly.
 *
 * Operators don't call this directly — it's a framework-internal walker.
 */

function _scrub(value, seen, bufferAs) {
  if (value === null || typeof value === "undefined") return null;
  var t = typeof value;
  if (t === "string" || t === "boolean" || t === "number") return value;
  if (t === "bigint") {
    if (bufferAs === "reject-jcs") {
      throw new Error("canonical-json: BigInt is not serialisable under " +
        "RFC 8785 (JCS); convert to a string or number before passing in");
    }
    return String(value);
  }
  if (t === "symbol" || t === "function") {
    throw new Error("canonical-json: " + t + " value is not " +
      "serialisable; convert to a string before passing in");
  }
  // Buffer / Uint8Array — policy-driven
  if (Buffer.isBuffer(value))           {
    if (bufferAs === "reject" || bufferAs === "reject-jcs") {
      throw new Error("canonical-json: Buffer is not serialisable in this " +
        "context (bufferAs=reject); convert to a string or hex first");
    }
    return value.toString("hex");
  }
  if (value instanceof Uint8Array) {
    if (bufferAs === "reject" || bufferAs === "reject-jcs") {
      throw new Error("canonical-json: Uint8Array is not serialisable in " +
        "this context (bufferAs=reject); convert to a string or hex first");
    }
    return Buffer.from(value).toString("hex");
  }
  if (value instanceof Date) {
    if (bufferAs === "reject-jcs") {
      throw new Error("canonical-json: Date is not serialisable under " +
        "RFC 8785 (JCS); convert to ISO-8601 string before passing in");
    }
    return value.toISOString();
  }
  // After primitives + Date + Buffer + Uint8Array, any remaining "object"
  // must be a plain object or array. Map / Set / RegExp / class instances
  // all reject so the silent-data-loss class is closed.
  if (value instanceof Map || value instanceof Set || value instanceof RegExp) {
    throw new Error("canonical-json: " + value.constructor.name +
      " is not serialisable; convert to a plain primitive / array / object first");
  }
  seen = seen || new WeakSet();
  if (seen.has(value)) {
    throw new Error("canonical-json: circular reference detected");
  }
  seen.add(value);
  if (Array.isArray(value)) {
    return value.map(function (v) { return _scrub(v, seen, bufferAs); });
  }
  // Canonical-json IS the destination for sorted-keys walks across the
  // codebase; the keys-then-sort here is the canonical primitive itself.
  var keys = Object.keys(value);
  keys.sort();
  var out = {};
  for (var i = 0; i < keys.length; i++) {
    out[keys[i]] = _scrub(value[keys[i]], seen, bufferAs);
  }
  return out;
}

// Return the deterministic JSON string. opts.bufferAs picks the Buffer
// policy ("hex" default, "reject" for callers like pagination).
function stringify(value, opts) {
  var bufferAs = (opts && opts.bufferAs) || "hex";
  if (bufferAs !== "hex" && bufferAs !== "reject" && bufferAs !== "reject-jcs") {
    throw new Error("canonical-json: bufferAs must be 'hex' / 'reject' / 'reject-jcs'; got " +
      JSON.stringify(bufferAs));
  }
  return JSON.stringify(_scrub(value, null, bufferAs));
}

// Stable key ordering for an object — same lexicographic sort used by
// the canonical-json walker. Exposed so call sites that need a sorted
// key list (CLI report ordering, fingerprint inputs) route through
// the framework's single source-of-truth ordering rule rather than
// re-implementing the keys-then-sort dance inline.
function sortKeys(obj) {
  if (!obj || typeof obj !== "object") return [];
  var keys = Object.keys(obj);
  keys.sort();
  return keys;
}

// stringifyJcs — RFC 8785 (JSON Canonicalization Scheme) strict mode.
// Refuses inputs JCS does NOT cover (BigInt, Buffer / Uint8Array, Date,
// Map, Set, RegExp, Symbol, function); operators carrying those types
// must convert to JSON-native shapes upfront. Object key ordering and
// number formatting already match JCS §3.2.2 — V8's
// `Object.keys(...).sort()` is lexicographic UTF-16 code-unit order
// (JCS §3.2.3) and `JSON.stringify` formats numbers per
// ECMA-262 §7.1.12.1 which JCS §3.2.2.3 references.
function stringifyJcs(value) {
  return JSON.stringify(_scrub(value, null, "reject-jcs"));
}

module.exports = {
  stringify: stringify,
  stringifyJcs: stringifyJcs,
  sortKeys: sortKeys,
};
