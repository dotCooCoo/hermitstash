"use strict";
/**
 * @module b.canonicalJson
 * @nav    Data
 * @title  Canonical JSON
 *
 * @intro
 *   Deterministic JSON serialization with keys sorted at every depth —
 *   the byte-for-byte stable form you hash or sign so two parties that
 *   build the same data produce the same bytes. <code>stringifyJcs</code>
 *   is strict RFC 8785 (JSON Canonicalization Scheme); <code>stringify</code>
 *   is a lenient variant that additionally serializes Buffers (as hex),
 *   Dates (ISO-8601), and BigInts (decimal) for the framework's own audit
 *   / config-drift fingerprints.
 *
 *   Both walks close the silent-data-loss class that ad-hoc
 *   <code>Object.keys(...).sort()</code> serializers fall into: Map /
 *   Set / RegExp / class instances, Symbols, functions, and circular
 *   references all throw a clean error rather than emitting <code>{}</code>
 *   or stack-overflowing. RFC 8785 strict mode additionally refuses
 *   BigInt / Buffer / Date (types JCS does not define) so the operator
 *   converts them to JSON-native shapes before signing.
 *
 *   Key ordering is V8's <code>Object.keys(...).sort()</code> —
 *   lexicographic UTF-16 code-unit order, which is exactly RFC 8785
 *   §3.2.3 — and numbers are formatted by <code>JSON.stringify</code>,
 *   whose output is the ECMA-262 Number-to-string algorithm that RFC
 *   8785 §3.2.2.3 references.
 *
 * @card
 *   Canonical JSON (RFC 8785 JCS) — the deterministic, sorted-key byte
 *   form you sign or hash. Strict <code>stringifyJcs</code> for
 *   interop, plus a lenient framework variant that serializes Buffers /
 *   Dates / BigInts. Lossy ad-hoc serializers (Map / Set / circular →
 *   <code>{}</code>) are refused.
 */

// Emit the canonical JSON STRING in one ordered pass. Object members are
// written in sorted-key order directly — building a plain object and
// relying on JSON.stringify would silently hoist integer-like keys
// ("1", "10") to the front (V8 own-property ordering), breaking the
// RFC 8785 §3.2.3 sort. Primitives, strings, and numbers use
// JSON.stringify, whose escaping (§3.2.2.2) and ECMAScript number format
// (§3.2.2.3) are exactly what JCS references.
function _emit(value, seen, bufferAs) {
  if (value === null || typeof value === "undefined") return "null";
  var t = typeof value;
  if (t === "number" || t === "string" || t === "boolean") return JSON.stringify(value);
  if (t === "bigint") {
    if (bufferAs === "reject-jcs") {
      throw new Error("canonical-json: BigInt is not serialisable under " +
        "RFC 8785 (JCS); convert to a string or number before passing in");
    }
    return JSON.stringify(String(value));
  }
  if (t === "symbol" || t === "function") {
    throw new Error("canonical-json: " + t + " value is not " +
      "serialisable; convert to a string before passing in");
  }
  // Buffer / Uint8Array — policy-driven
  if (Buffer.isBuffer(value)) {
    if (bufferAs === "reject" || bufferAs === "reject-jcs") {
      throw new Error("canonical-json: Buffer is not serialisable in this " +
        "context (bufferAs=reject); convert to a string or hex first");
    }
    return JSON.stringify(value.toString("hex"));
  }
  if (value instanceof Uint8Array) {
    if (bufferAs === "reject" || bufferAs === "reject-jcs") {
      throw new Error("canonical-json: Uint8Array is not serialisable in " +
        "this context (bufferAs=reject); convert to a string or hex first");
    }
    return JSON.stringify(Buffer.from(value).toString("hex"));
  }
  if (value instanceof Date) {
    if (bufferAs === "reject-jcs") {
      throw new Error("canonical-json: Date is not serialisable under " +
        "RFC 8785 (JCS); convert to ISO-8601 string before passing in");
    }
    return JSON.stringify(value.toISOString());
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
    // Index loop, not .map(): map() skips holes in a sparse array,
    // which join() would then render as invalid elisions ([,1]). A hole
    // reads as undefined → _emit returns "null" (matching JSON.stringify).
    var items = [];
    for (var ai = 0; ai < value.length; ai += 1) {
      items.push(_emit(value[ai], seen, bufferAs));
    }
    return "[" + items.join(",") + "]";
  }
  // Canonical-json IS the destination for sorted-keys walks across the
  // codebase; the keys-then-sort here is the canonical primitive itself.
  var keys = Object.keys(value);
  keys.sort();
  var parts = [];
  for (var i = 0; i < keys.length; i++) {
    parts.push(JSON.stringify(keys[i]) + ":" + _emit(value[keys[i]], seen, bufferAs));
  }
  return "{" + parts.join(",") + "}";
}

/**
 * @primitive b.canonicalJson.stringify
 * @signature b.canonicalJson.stringify(value, opts?)
 * @since     0.5.0
 * @status    stable
 * @related   b.canonicalJson.stringifyJcs, b.canonicalJson.sortKeys
 *
 * Deterministic JSON with keys sorted at every depth — the lenient
 * framework variant. Beyond JSON-native values it serializes Buffers /
 * Uint8Arrays (hex), Dates (ISO-8601), and BigInts (decimal string); Map
 * / Set / RegExp / class instances, Symbols, functions, and circular
 * references throw rather than silently emitting <code>{}</code>. Use
 * <code>stringifyJcs</code> for strict RFC 8785 interop.
 *
 * @opts
 *   bufferAs: string,   // "hex" (default) | "reject" — Buffer / Uint8Array policy
 *
 * @example
 *   b.canonicalJson.stringify({ b: 1, a: 2 });
 *   // → '{"a":2,"b":1}'
 */
function stringify(value, opts) {
  var bufferAs = (opts && opts.bufferAs) || "hex";
  if (bufferAs !== "hex" && bufferAs !== "reject" && bufferAs !== "reject-jcs") {
    throw new Error("canonical-json: bufferAs must be 'hex' / 'reject' / 'reject-jcs'; got " +
      JSON.stringify(bufferAs));
  }
  return _emit(value, null, bufferAs);
}

/**
 * @primitive b.canonicalJson.sortKeys
 * @signature b.canonicalJson.sortKeys(obj)
 * @since     0.5.0
 * @status    stable
 * @related   b.canonicalJson.stringify
 *
 * The object's own keys in the framework's single canonical ordering —
 * lexicographic UTF-16 code-unit sort (the same ordering the canonical
 * serializers use). Returns an empty array for a non-object. Route
 * fingerprint / report ordering through this rather than re-implementing
 * the keys-then-sort dance inline.
 *
 * @example
 *   b.canonicalJson.sortKeys({ b: 1, a: 2, c: 3 });
 *   // → ["a", "b", "c"]
 */
function sortKeys(obj) {
  if (!obj || typeof obj !== "object") return [];
  var keys = Object.keys(obj);
  keys.sort();
  return keys;
}

/**
 * @primitive b.canonicalJson.stringifyJcs
 * @signature b.canonicalJson.stringifyJcs(value)
 * @since     0.12.56
 * @status    stable
 * @compliance soc2
 * @related   b.canonicalJson.stringify, b.vc.issue, b.scitt.signStatement
 *
 * Strict RFC 8785 JSON Canonicalization Scheme — the deterministic byte
 * form to hash or sign when two parties must agree on the exact bytes
 * (signed JSON credentials, receipts, deterministic request signing).
 * Keys are sorted in UTF-16 code-unit order at every depth (§3.2.3) and
 * numbers use the ECMAScript Number-to-string formatting §3.2.2.3
 * references. Inputs JCS does not define — BigInt, Buffer / Uint8Array,
 * Date, Map, Set, RegExp, Symbol, function, and circular references —
 * are refused, so the operator converts them to JSON-native shapes
 * before signing rather than getting a silently lossy result.
 *
 * @example
 *   b.canonicalJson.stringifyJcs({ "€": 1, "$": 2 });
 *   // → '{"$":2,"€":1}'   (keys sorted by UTF-16 code unit)
 */
function stringifyJcs(value) {
  return _emit(value, null, "reject-jcs");
}

module.exports = {
  stringify: stringify,
  stringifyJcs: stringifyJcs,
  sortKeys: sortKeys,
};
