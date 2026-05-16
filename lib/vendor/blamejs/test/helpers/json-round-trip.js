"use strict";
/**
 * JSON-round-trip property test helper.
 *
 * Every primitive that persists a "row" / "envelope" / "snapshot" /
 * "cached entry" to a backend ships a test using this helper:
 *
 *   var { assertJsonRoundTrip } = require("../helpers/json-round-trip");
 *   assertJsonRoundTrip(rowShape, "agent-registry row");
 *
 * Catches the class of bug where a runtime value (function ref,
 * Buffer, Date object, Symbol, BigInt, undefined field) gets stored
 * into a row whose backend is going to serialize it to JSON — the
 * round-trip silently loses the field. Codex flagged this on PR #51
 * (v0.9.21): agent register() stored the agent function ref on the
 * backend row; DB/JSON backends couldn't preserve it; lookup()
 * returned a stub object missing the callable methods.
 *
 * Assertion: `JSON.parse(JSON.stringify(shape))` deep-equals `shape`.
 * Refuses on:
 *   - function fields (lost to undefined)
 *   - Buffer fields (turned into { type:"Buffer", data:[...] })
 *   - Date objects (turned into ISO strings on serialize but never
 *     restored to Date on parse — caller MUST pre-stringify)
 *   - Symbol-keyed properties (ignored by JSON.stringify)
 *   - BigInt values (throws RangeError)
 *   - undefined values in arrays (turned into null)
 *   - undefined fields in objects (omitted)
 *   - circular references (throws on stringify)
 *
 * The helper produces a clear error pointing at the first offending
 * field so the operator knows which shape to fix.
 */

var assert = require("node:assert");

function assertJsonRoundTrip(shape, label) {
  label = label || "shape";
  // First, walk the shape and surface bad-shape early with a clear
  // error pointing at the offending path. JSON.stringify would
  // silently lose / wrongly convert some of these.
  var badPath = _findUnserializable(shape, [], new Set());
  if (badPath) {
    throw new Error("assertJsonRoundTrip: " + label + " has unserializable field at " +
      _renderPath(badPath.path) + ": " + badPath.reason);
  }
  var serialized;
  try {
    serialized = JSON.stringify(shape);
  } catch (e) {
    throw new Error("assertJsonRoundTrip: " + label +
      " threw on JSON.stringify: " + (e && e.message ? e.message : String(e)));
  }
  if (typeof serialized !== "string") {
    throw new Error("assertJsonRoundTrip: " + label +
      " JSON.stringify returned " + typeof serialized + " (expected string)");
  }
  var roundTripped;
  try {
    roundTripped = JSON.parse(serialized);
  } catch (e) {
    throw new Error("assertJsonRoundTrip: " + label +
      " threw on JSON.parse: " + (e && e.message ? e.message : String(e)));
  }
  try {
    assert.deepStrictEqual(roundTripped, shape);
  } catch (e) {
    throw new Error("assertJsonRoundTrip: " + label +
      " round-trip mismatch — original ≠ JSON.parse(JSON.stringify(original)). " +
      "Likely a Date / Buffer / number-vs-string mismatch. " +
      (e && e.message ? e.message : String(e)));
  }
}

function _findUnserializable(value, path, seen) {
  if (value === null) return null;
  if (typeof value === "function") return { path: path, reason: "function ref (lost on serialize)" };
  if (typeof value === "bigint")   return { path: path, reason: "BigInt (throws RangeError on stringify)" };
  if (typeof value === "symbol")   return { path: path, reason: "Symbol (omitted by JSON.stringify)" };
  if (typeof value === "undefined") return { path: path, reason: "undefined (omitted from objects, becomes null in arrays)" };
  if (typeof value === "number") {
    if (!isFinite(value)) return { path: path, reason: "non-finite number (Infinity/NaN serialize as null)" };
    return null;
  }
  if (typeof value === "string" || typeof value === "boolean") return null;
  if (typeof value !== "object") return null;

  // Object case — check for Buffer / Date / cycle / nested.
  if (Buffer.isBuffer(value))     return { path: path, reason: "Buffer (serialized as { type:'Buffer', data:[...] } — operator must base64-encode first)" };
  if (value instanceof Date)      return { path: path, reason: "Date (serialized as ISO string but never restored to Date on parse — operator must pre-stringify)" };
  if (seen.has(value))             return { path: path, reason: "cycle (JSON.stringify throws on circular references)" };
  seen.add(value);

  if (Array.isArray(value)) {
    for (var i = 0; i < value.length; i += 1) {
      var found = _findUnserializable(value[i], path.concat([i]), seen);
      if (found) return found;
    }
    return null;
  }
  var keys = Object.keys(value);
  for (var k = 0; k < keys.length; k += 1) {
    var key = keys[k];
    var found2 = _findUnserializable(value[key], path.concat([key]), seen);
    if (found2) return found2;
  }
  return null;
}

function _renderPath(path) {
  if (path.length === 0) return "(root)";
  var s = "$";
  for (var i = 0; i < path.length; i += 1) {
    if (typeof path[i] === "number") s += "[" + path[i] + "]";
    else s += "." + path[i];
  }
  return s;
}

module.exports = { assertJsonRoundTrip: assertJsonRoundTrip };
