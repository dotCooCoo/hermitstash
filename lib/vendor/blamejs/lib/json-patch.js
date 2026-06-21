"use strict";
/**
 * @module b.jsonPatch
 * @nav    Data
 * @title  JSON Patch
 *
 * @intro
 *   Apply an RFC 6902 JSON Patch — an ordered list of operations
 *   (<code>add</code>, <code>remove</code>, <code>replace</code>,
 *   <code>move</code>, <code>copy</code>, <code>test</code>) — to a JSON
 *   document, the standard payload of an HTTP <code>PATCH</code> with
 *   <code>Content-Type: application/json-patch+json</code>. Each
 *   operation's <code>path</code> (and <code>from</code>) is an RFC 6901
 *   JSON Pointer, resolved through <code>b.jsonPointer</code>.
 *
 *   <code>apply</code> is atomic: operations run against a deep copy, so
 *   if any operation fails — an out-of-range index, a missing source, or
 *   a failed <code>test</code> — the original document is returned
 *   untouched and a typed error is thrown. The <code>test</code>
 *   operation compares structurally (object key order is irrelevant).
 *
 * @card
 *   JSON Patch (RFC 6902) — apply add / remove / replace / move / copy /
 *   test operations to a JSON document for HTTP PATCH. Atomic
 *   (all-or-nothing on a copy) with structural <code>test</code>
 *   comparison; paths are RFC 6901 JSON Pointers.
 */

var jsonPointer = require("./json-pointer");
var canonicalJson = require("./canonical-json");
var { defineClass } = require("./framework-error");

var JsonPatchError = defineClass("JsonPatchError", { alwaysPermanent: true });

var OPS = { add: 1, remove: 1, replace: 1, move: 1, copy: 1, test: 1 };

// Structural equality for the `test` op — canonical (sorted-key) JSON of
// both sides, so member order does not matter (RFC 6902 §4.6).
function _deepEqual(a, b) {
  return canonicalJson.stringify(a) === canonicalJson.stringify(b);
}

// Set an own property WITHOUT invoking the legacy __proto__ setter — a
// patch with path "/__proto__" must create a literal JSON key, not
// rewrite the object's prototype (prototype-pollution defense). Object
// member reads above are already gated by hasOwnProperty, so traversal
// through an inherited __proto__ is blocked; only the write needs this.
function _safeObjectSet(obj, key, value) {
  Object.defineProperty(obj, key, { value: value, writable: true, enumerable: true, configurable: true });
}

// Split a pointer into { parent: tokens, key }; "" (whole doc) → null.
function _parentAndKey(pointer) {
  var tokens = jsonPointer.parse(pointer);
  if (tokens.length === 0) return null;
  return { parent: tokens.slice(0, -1), key: tokens[tokens.length - 1] };
}

function _resolveParent(doc, parentTokens, fn) {
  var cur = doc;
  for (var i = 0; i < parentTokens.length; i += 1) {
    if (Array.isArray(cur)) {
      if (!jsonPointer.ARRAY_INDEX_RE.test(parentTokens[i]) || Number(parentTokens[i]) >= cur.length) {   // allow:regex-no-length-cap — anchored linear index regex (no backtracking); tokens are short JSON Pointer segments
        throw new JsonPatchError("json-patch/path-not-found", "jsonPatch." + fn + ": path parent does not resolve at '" + parentTokens[i] + "'");
      }
      cur = cur[Number(parentTokens[i])];
    } else if (cur !== null && typeof cur === "object") {
      if (!Object.prototype.hasOwnProperty.call(cur, parentTokens[i])) {
        throw new JsonPatchError("json-patch/path-not-found", "jsonPatch." + fn + ": path parent does not resolve at '" + parentTokens[i] + "'");
      }
      cur = cur[parentTokens[i]];
    } else {
      throw new JsonPatchError("json-patch/path-not-found", "jsonPatch." + fn + ": cannot descend into a non-container at '" + parentTokens[i] + "'");
    }
  }
  return cur;
}

function _addAt(doc, pointer, value, fn) {
  var pk = _parentAndKey(pointer);
  if (pk === null) return value;                              // add to "" replaces the whole document
  var parent = _resolveParent(doc, pk.parent, fn);
  if (Array.isArray(parent)) {
    if (pk.key === "-") { parent.push(value); return doc; }
    if (!jsonPointer.ARRAY_INDEX_RE.test(pk.key)) throw new JsonPatchError("json-patch/bad-index", "jsonPatch." + fn + ": array index '" + pk.key + "' is invalid");   // allow:regex-no-length-cap — anchored linear index regex (no backtracking); tokens are short JSON Pointer segments
    var idx = Number(pk.key);
    if (idx > parent.length) throw new JsonPatchError("json-patch/bad-index", "jsonPatch." + fn + ": array index " + idx + " is out of range");
    parent.splice(idx, 0, value);
    return doc;
  }
  if (parent !== null && typeof parent === "object") { _safeObjectSet(parent, pk.key, value); return doc; }
  throw new JsonPatchError("json-patch/path-not-found", "jsonPatch." + fn + ": target parent is not a container");
}

function _removeAt(doc, pointer, fn) {
  var pk = _parentAndKey(pointer);
  if (pk === null) throw new JsonPatchError("json-patch/bad-op", "jsonPatch." + fn + ": cannot remove the whole document");
  var parent = _resolveParent(doc, pk.parent, fn);
  if (Array.isArray(parent)) {
    if (!jsonPointer.ARRAY_INDEX_RE.test(pk.key) || Number(pk.key) >= parent.length) throw new JsonPatchError("json-patch/path-not-found", "jsonPatch." + fn + ": array index '" + pk.key + "' does not exist");   // allow:regex-no-length-cap — anchored linear index regex (no backtracking); tokens are short JSON Pointer segments
    var removed = parent.splice(Number(pk.key), 1)[0];
    return removed;
  }
  if (parent !== null && typeof parent === "object") {
    if (!Object.prototype.hasOwnProperty.call(parent, pk.key)) throw new JsonPatchError("json-patch/path-not-found", "jsonPatch." + fn + ": key '" + pk.key + "' does not exist");
    var v = parent[pk.key];
    delete parent[pk.key];
    return v;
  }
  throw new JsonPatchError("json-patch/path-not-found", "jsonPatch." + fn + ": target parent is not a container");
}

// replace overwrites an EXISTING location (array set, not insert), unlike
// add which inserts (RFC 6902 §4.3). The target must already exist.
function _replaceAt(doc, pointer, value, fn) {
  var pk = _parentAndKey(pointer);
  if (pk === null) return value;                              // replace "" → the whole document
  var parent = _resolveParent(doc, pk.parent, fn);
  if (Array.isArray(parent)) {
    if (!jsonPointer.ARRAY_INDEX_RE.test(pk.key) || Number(pk.key) >= parent.length) throw new JsonPatchError("json-patch/path-not-found", "jsonPatch." + fn + ": replace target array index '" + pk.key + "' does not exist");   // allow:regex-no-length-cap — anchored linear index regex (no backtracking); tokens are short JSON Pointer segments
    parent[Number(pk.key)] = value;
    return doc;
  }
  if (parent !== null && typeof parent === "object") {
    if (!Object.prototype.hasOwnProperty.call(parent, pk.key)) throw new JsonPatchError("json-patch/path-not-found", "jsonPatch." + fn + ": replace target key '" + pk.key + "' does not exist");
    _safeObjectSet(parent, pk.key, value);
    return doc;
  }
  throw new JsonPatchError("json-patch/path-not-found", "jsonPatch." + fn + ": replace target parent is not a container");
}

/**
 * @primitive b.jsonPatch.apply
 * @signature b.jsonPatch.apply(doc, operations)
 * @since     0.12.58
 * @status    stable
 * @compliance soc2
 * @related   b.jsonPointer.get
 *
 * Apply an RFC 6902 JSON Patch (an array of operation objects) to a JSON
 * document and return the patched result. The operations run against a
 * deep copy, so a failure at any step — an unknown op, a missing
 * <code>path</code> / <code>value</code> / <code>from</code>, an
 * out-of-range array index, or a failed <code>test</code> — throws a
 * typed error and leaves the input <code>doc</code> unmodified. The
 * <code>test</code> operation compares values structurally.
 *
 * @example
 *   b.jsonPatch.apply({ a: 1 }, [
 *     { op: "add", path: "/b", value: 2 },
 *     { op: "remove", path: "/a" },
 *   ]);
 *   // → { b: 2 }
 */
function apply(doc, operations) {
  if (!Array.isArray(operations)) throw new JsonPatchError("json-patch/bad-patch", "jsonPatch.apply: operations must be an array");
  var work = structuredClone(doc);
  for (var i = 0; i < operations.length; i += 1) {
    var op = operations[i];
    if (!op || typeof op !== "object" || typeof op.op !== "string" || !Object.prototype.hasOwnProperty.call(OPS, op.op)) {
      throw new JsonPatchError("json-patch/bad-op", "jsonPatch.apply: operations[" + i + "] has an invalid 'op'");
    }
    if (typeof op.path !== "string") throw new JsonPatchError("json-patch/bad-op", "jsonPatch.apply: operations[" + i + "] is missing 'path'");

    if (op.op === "add") {
      if (!("value" in op)) throw new JsonPatchError("json-patch/bad-op", "jsonPatch.apply: 'add' requires 'value'");
      work = _addAt(work, op.path, op.value, "apply");
    } else if (op.op === "remove") {
      work = _wholeOrMutate(work, op.path, function (d) { return _removeAt(d, op.path, "apply"); });
    } else if (op.op === "replace") {
      if (!("value" in op)) throw new JsonPatchError("json-patch/bad-op", "jsonPatch.apply: 'replace' requires 'value'");
      work = _replaceAt(work, op.path, op.value, "apply");
    } else if (op.op === "move" || op.op === "copy") {
      if (typeof op.from !== "string") throw new JsonPatchError("json-patch/bad-op", "jsonPatch.apply: '" + op.op + "' requires 'from'");
      if (op.op === "move" && (op.path === op.from || _isProperPrefix(op.from, op.path))) {
        if (op.path !== op.from) throw new JsonPatchError("json-patch/bad-op", "jsonPatch.apply: cannot move a location into one of its children");
      }
      var moved = op.op === "move" ? _removeAt(work, op.from, "apply") : structuredClone(jsonPointer.get(work, op.from));
      work = _addAt(work, op.path, moved, "apply");
    } else if (op.op === "test") {
      if (!("value" in op)) throw new JsonPatchError("json-patch/bad-op", "jsonPatch.apply: 'test' requires 'value'");
      var actual = jsonPointer.get(work, op.path);
      if (!_deepEqual(actual, op.value)) throw new JsonPatchError("json-patch/test-failed", "jsonPatch.apply: 'test' at '" + op.path + "' did not match");
    }
  }
  return work;
}

// remove/replace at "" is undefined in RFC 6902; route whole-doc ops
// through here so they fail cleanly rather than corrupting state.
function _wholeOrMutate(doc, pointer, mutate) {
  if (pointer === "") throw new JsonPatchError("json-patch/bad-op", "jsonPatch.apply: cannot remove the whole document");
  mutate(doc);
  return doc;
}

// Is `prefix` a proper ancestor pointer of `path`? (move-into-child guard)
function _isProperPrefix(prefix, path) {
  return path !== prefix && path.indexOf(prefix + "/") === 0;
}

module.exports = {
  apply:          apply,
  OPS:            OPS,
  JsonPatchError: JsonPatchError,
};
