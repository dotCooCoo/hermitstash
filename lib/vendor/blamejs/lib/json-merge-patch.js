// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.jsonMergePatch
 * @nav    Data
 * @title  JSON Merge Patch
 *
 * @intro
 *   Apply a JSON Merge Patch (RFC 7396) — the
 *   <code>application/merge-patch+json</code> body of an HTTP
 *   <code>PATCH</code>. A merge patch is a partial document overlaid on
 *   the target: a member present in the patch replaces (or, for nested
 *   objects, is merged into) the target, a member whose value is
 *   <code>null</code> removes that key, and a patch that is anything
 *   other than an object (an array, scalar, or <code>null</code>)
 *   replaces the target wholesale.
 *
 *   It is the simpler companion to the operation-based JSON Patch
 *   (<code>b.jsonPatch</code>): merge patch can't reorder arrays or
 *   express a value that is genuinely <code>null</code>, but it reads
 *   like the resource you want. <code>merge</code> returns a new
 *   document and never mutates its inputs, and writes member keys as
 *   literal own properties (a <code>"__proto__"</code> key cannot reach
 *   the prototype).
 *
 * @card
 *   JSON Merge Patch (RFC 7396) — overlay a partial document for HTTP
 *   PATCH: present members replace / merge, <code>null</code> deletes, a
 *   non-object patch replaces wholesale. The simple companion to JSON
 *   Patch; immutable and prototype-pollution-safe.
 */

var { defineClass } = require("./framework-error");

var JsonMergePatchError = defineClass("JsonMergePatchError", { alwaysPermanent: true });

function _ownGet(obj, key) {
  var d = Object.getOwnPropertyDescriptor(obj, key);          // own value, bypassing the __proto__ getter
  return d ? d.value : undefined;
}
function _ownSet(obj, key, value) {
  Object.defineProperty(obj, key, { value: value, writable: true, enumerable: true, configurable: true });
}
function _isPlainObject(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }

function _merge(target, patch) {
  // A non-object patch (array, scalar, or null) replaces the target.
  if (!_isPlainObject(patch)) return patch;
  // Object patch merges into an object target; if the target is not an
  // object, RFC 7396 §2 starts from an empty object.
  var out = _isPlainObject(target) ? target : {};
  var keys = Object.keys(patch);
  for (var i = 0; i < keys.length; i += 1) {
    var name = keys[i];
    var val = _ownGet(patch, name);
    if (val === null) {
      if (Object.prototype.hasOwnProperty.call(out, name)) delete out[name];
    } else {
      _ownSet(out, name, _merge(Object.prototype.hasOwnProperty.call(out, name) ? _ownGet(out, name) : undefined, val));
    }
  }
  return out;
}

/**
 * @primitive b.jsonMergePatch.merge
 * @signature b.jsonMergePatch.merge(target, patch)
 * @since     0.12.59
 * @status    stable
 * @compliance soc2
 * @related   b.jsonPatch.apply
 *
 * Apply a JSON Merge Patch (RFC 7396) to a target document and return the
 * result. When the patch is an object, each member overlays the target —
 * a <code>null</code> value deletes the key, a nested object merges
 * recursively, and any other value replaces; when the patch is itself an
 * array, scalar, or <code>null</code>, it replaces the whole target. The
 * inputs are never mutated (the work happens on a deep copy) and member
 * keys are written as literal own properties, so a <code>"__proto__"</code>
 * member cannot alter any prototype.
 *
 * @example
 *   b.jsonMergePatch.merge({ a: "b", c: { d: "e" } }, { a: "z", c: { d: null, f: 1 } });
 *   // → { a: "z", c: { f: 1 } }
 */
function merge(target, patch) {
  if (typeof patch === "undefined") throw new JsonMergePatchError("json-merge-patch/bad-patch", "jsonMergePatch.merge: patch is required (use null to replace the target with null)");
  return _merge(structuredClone(target), structuredClone(patch));
}

module.exports = {
  merge:                merge,
  JsonMergePatchError:  JsonMergePatchError,
};
