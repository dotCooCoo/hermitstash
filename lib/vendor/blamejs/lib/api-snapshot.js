"use strict";
/**
 * api-snapshot — public API surface walker + breaking-change detector.
 *
 * The framework's LTS-contract enforcement at the type level. Walks
 * the framework's module exports recursively, records every member's
 * type, and compares two snapshots to find:
 *
 *   - removed       a member present in the old snapshot but not the new
 *                   (BREAKING — fails CI)
 *   - typeChanged   a member's category flipped (function → object, etc.)
 *                   (BREAKING — fails CI)
 *   - added         a new member that wasn't in the old snapshot
 *                   (ADDITIVE — does not fail; signals the snapshot is
 *                    out-of-date and the operator should rerun capture)
 *
 *   var snap = b.apiSnapshot.capture(require("@blamejs/core"));
 *   //  { version, frameworkVersion, createdAt,
 *   //    exports: { ... nested tree ... } }
 *
 *   b.apiSnapshot.write(snap, "./api-snapshot.json");
 *   var loaded = b.apiSnapshot.read("./api-snapshot.json");
 *
 *   var diff = b.apiSnapshot.compare(loaded, snap);
 *   //  { breaking: [{ path, kind, was?, is? }],
 *   //    typeChanged: [{ path, was, is }],
 *   //    additive: [{ path, type }] }
 *
 *   if (diff.breaking.length > 0 || diff.typeChanged.length > 0) {
 *     console.error(b.apiSnapshot.formatDiff(diff));
 *     process.exit(1);
 *   }
 *
 * Walker rules:
 *   - Functions record as { type: 'function', arity: fn.length }.
 *     Class constructors are still 'function' — recursive scope walks
 *     prototype only when the operator explicitly opts in via
 *     opts.includeClassPrototypes.
 *   - Plain objects recurse into their own enumerable string keys.
 *   - Primitives (string, number, boolean, null, undefined) record as
 *     { type: 'primitive', valueType: typeof v }. Specific values are
 *     NOT captured — only the type — so a version-string change in
 *     constants doesn't fail CI.
 *   - Members whose key starts with '_' are skipped (test seams,
 *     internal helpers).
 *   - Cycles are detected and short-circuit as { type: 'cycle' }.
 *   - Non-plain objects (Map, Set, Buffer, Date, RegExp, Error, etc.)
 *     are recorded as { type: 'instance', constructor: name } without
 *     recursion — they're terminal nodes.
 */

var fs = require("fs");
var nb = require("./numeric-bounds");
var safeJson = require("./safe-json");
var { FrameworkError } = require("./framework-error");

var DEFAULT_MAX_DEPTH = 0x08;

class ApiSnapshotError extends FrameworkError {
  constructor(code, message) {
    super(message, code);
    this.name = "ApiSnapshotError";
    this.permanent = true;
    this.isApiSnapshotError = true;
  }
}

var SNAPSHOT_FORMAT_VERSION = 1;

function _isPlainObject(v) {
  if (v === null || typeof v !== "object") return false;
  var proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function _walkNode(value, depth, maxDepth, seen, skipUnderscore) {
  if (value === null) return { type: "primitive", valueType: "null" };
  var t = typeof value;
  if (t === "undefined") return { type: "primitive", valueType: "undefined" };
  if (t === "string" || t === "number" || t === "boolean" || t === "bigint" || t === "symbol") {
    return { type: "primitive", valueType: t };
  }
  if (t === "function") {
    return { type: "function", arity: value.length };
  }
  // Object — guard cycles + depth
  if (seen.has(value)) return { type: "cycle" };
  if (depth >= maxDepth) return { type: "deep", note: "max depth" };

  if (!_isPlainObject(value)) {
    var name = value && value.constructor && value.constructor.name
      ? value.constructor.name
      : "Object";
    // Use 'ctorName' instead of 'constructor' — json-safe.parse strips
    // 'constructor' as a prototype-pollution defense, which would
    // round-trip-mangle every instance node otherwise.
    return { type: "instance", ctorName: name };
  }

  // Plain object — recurse
  seen.add(value);
  var members = {};
  var keys = Object.keys(value);
  // Stable sort for canonical snapshot bytes
  keys.sort();
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    if (skipUnderscore && k.charAt(0) === "_") continue;
    members[k] = _walkNode(value[k], depth + 1, maxDepth, seen, skipUnderscore);
  }
  seen.delete(value);
  return { type: "object", members: members };
}

function capture(target, opts) {
  opts = opts || {};
  if (!target || typeof target !== "object") {
    throw new ApiSnapshotError("api-snapshot/bad-target",
      "capture: target must be a module's exports object");
  }
  var maxDepth = nb.isPositiveFiniteInt(opts.maxDepth) ? opts.maxDepth : DEFAULT_MAX_DEPTH;
  var skipUnderscore = opts.skipUnderscore !== false;
  var snapshot = _walkNode(target, 0, maxDepth, new Set(), skipUnderscore);
  if (snapshot.type !== "object") {
    throw new ApiSnapshotError("api-snapshot/bad-target",
      "capture: top-level target must be a plain object (got '" + snapshot.type + "')");
  }
  return {
    version:          SNAPSHOT_FORMAT_VERSION,
    frameworkVersion: typeof opts.frameworkVersion === "string" && opts.frameworkVersion.length > 0
      ? opts.frameworkVersion
      : (target.version || "0.0.0"),
    createdAt:        opts.createdAt || new Date().toISOString(),
    exports:          snapshot.members,
  };
}

function write(snapshot, filePath) {
  if (!snapshot || typeof snapshot !== "object") {
    throw new ApiSnapshotError("api-snapshot/bad-snapshot",
      "write: snapshot must be a snapshot object (returned by capture)");
  }
  if (typeof filePath !== "string" || filePath.length === 0) {
    throw new ApiSnapshotError("api-snapshot/bad-path",
      "write: filePath is required");
  }
  // Stringify with stable key order via the explicit canonical form
  var canonical = {
    version:          snapshot.version,
    frameworkVersion: snapshot.frameworkVersion,
    createdAt:        snapshot.createdAt,
    exports:          snapshot.exports,
  };
  fs.writeFileSync(filePath, JSON.stringify(canonical, null, 2) + "\n", { mode: 0o644 });
  return filePath;
}

function read(filePath) {
  if (typeof filePath !== "string" || filePath.length === 0) {
    throw new ApiSnapshotError("api-snapshot/bad-path",
      "read: filePath is required");
  }
  if (!fs.existsSync(filePath)) {
    throw new ApiSnapshotError("api-snapshot/missing",
      "read: snapshot file not found at " + filePath);
  }
  var raw;
  try { raw = fs.readFileSync(filePath, "utf8"); }
  catch (e) {
    throw new ApiSnapshotError("api-snapshot/read-failed",
      "read: cannot read " + filePath + ": " + ((e && e.message) || String(e)));
  }
  var parsed;
  try { parsed = safeJson.parse(raw); }
  catch (e) {
    throw new ApiSnapshotError("api-snapshot/bad-json",
      "read: not valid JSON: " + ((e && e.message) || String(e)));
  }
  if (!parsed || parsed.version !== SNAPSHOT_FORMAT_VERSION) {
    throw new ApiSnapshotError("api-snapshot/bad-version",
      "read: snapshot version is " + (parsed && parsed.version) +
      ", expected " + SNAPSHOT_FORMAT_VERSION);
  }
  if (!parsed.exports || typeof parsed.exports !== "object") {
    throw new ApiSnapshotError("api-snapshot/bad-shape",
      "read: snapshot is missing 'exports' object");
  }
  return parsed;
}

// Walk both trees in parallel under a path. Append to breaking,
// additive, typeChanged.
function _walkCompare(oldNode, newNode, prefix, breaking, additive, typeChanged) {
  // Both should describe the same node. If types differ at the node
  // level, that's a breaking type change.
  if (!oldNode || !newNode) return;

  if (oldNode.type !== newNode.type) {
    typeChanged.push({
      path: prefix,
      was:  oldNode.type,
      is:   newNode.type,
    });
    breaking.push({ path: prefix, kind: "type-changed", was: oldNode.type, is: newNode.type });
    return;
  }

  if (oldNode.type === "object") {
    var oldMembers = oldNode.members || {};
    var newMembers = newNode.members || {};
    var oldKeys = Object.keys(oldMembers);
    var newKeys = Object.keys(newMembers);

    // Removed: in old, not in new
    for (var i = 0; i < oldKeys.length; i++) {
      var ok = oldKeys[i];
      var childPath = prefix ? (prefix + "." + ok) : ok;
      if (!Object.prototype.hasOwnProperty.call(newMembers, ok)) {
        breaking.push({ path: childPath, kind: "removed", was: oldMembers[ok].type });
      } else {
        _walkCompare(oldMembers[ok], newMembers[ok], childPath, breaking, additive, typeChanged);
      }
    }
    // Added: in new, not in old
    for (var j = 0; j < newKeys.length; j++) {
      var nk = newKeys[j];
      if (!Object.prototype.hasOwnProperty.call(oldMembers, nk)) {
        var addPath = prefix ? (prefix + "." + nk) : nk;
        additive.push({ path: addPath, type: newMembers[nk].type });
      }
    }
    return;
  }

  // For function nodes, arity DROPS are flagged (operator removed a
  // required parameter). Arity INCREASES are not flagged (added
  // optional param at the end is additive).
  if (oldNode.type === "function") {
    if (typeof oldNode.arity === "number" && typeof newNode.arity === "number" &&
        newNode.arity < oldNode.arity) {
      breaking.push({
        path: prefix,
        kind: "arity-decreased",
        was:  "function/" + oldNode.arity,
        is:   "function/" + newNode.arity,
      });
    }
    return;
  }

  // For instance nodes, a constructor-name change is breaking
  if (oldNode.type === "instance") {
    if (oldNode.ctorName !== newNode.ctorName) {
      breaking.push({
        path: prefix,
        kind: "constructor-changed",
        was:  oldNode.ctorName,
        is:   newNode.ctorName,
      });
    }
    return;
  }

  // For primitive nodes, a valueType change is breaking
  if (oldNode.type === "primitive") {
    if (oldNode.valueType !== newNode.valueType) {
      breaking.push({
        path: prefix,
        kind: "primitive-type-changed",
        was:  oldNode.valueType,
        is:   newNode.valueType,
      });
    }
    return;
  }

  // cycle / deep — terminal, nothing more to compare
}

function compare(oldSnapshot, newSnapshot) {
  if (!oldSnapshot || !oldSnapshot.exports) {
    throw new ApiSnapshotError("api-snapshot/bad-snapshot",
      "compare: oldSnapshot is required (a snapshot from read()/capture())");
  }
  if (!newSnapshot || !newSnapshot.exports) {
    throw new ApiSnapshotError("api-snapshot/bad-snapshot",
      "compare: newSnapshot is required (a snapshot from capture())");
  }
  var breaking = [];
  var additive = [];
  var typeChanged = [];
  // Wrap exports in an object node so the recursion treats them uniformly
  _walkCompare(
    { type: "object", members: oldSnapshot.exports },
    { type: "object", members: newSnapshot.exports },
    "", breaking, additive, typeChanged
  );
  return { breaking: breaking, additive: additive, typeChanged: typeChanged };
}

function formatDiff(diff) {
  if (!diff || typeof diff !== "object") {
    throw new ApiSnapshotError("api-snapshot/bad-diff",
      "formatDiff: argument must be a diff result from compare()");
  }
  var lines = [];
  if (diff.breaking.length === 0 && diff.additive.length === 0) {
    return "[api-snapshot] no changes";
  }
  if (diff.breaking.length > 0) {
    lines.push("[api-snapshot] BREAKING (" + diff.breaking.length + "):");
    for (var i = 0; i < diff.breaking.length; i++) {
      var b = diff.breaking[i];
      var line = "  - " + b.path + " (" + b.kind + ")";
      if (b.was !== undefined) line += " was=" + JSON.stringify(b.was);
      if (b.is !== undefined)  line += " is="  + JSON.stringify(b.is);
      lines.push(line);
    }
  }
  if (diff.additive.length > 0) {
    lines.push("[api-snapshot] additive (" + diff.additive.length + ", informational):");
    for (var j = 0; j < diff.additive.length; j++) {
      var a = diff.additive[j];
      lines.push("  + " + a.path + " (" + a.type + ")");
    }
  }
  return lines.join("\n");
}

module.exports = {
  capture:                 capture,
  write:                   write,
  read:                    read,
  compare:                 compare,
  formatDiff:              formatDiff,
  SNAPSHOT_FORMAT_VERSION: SNAPSHOT_FORMAT_VERSION,
  ApiSnapshotError:        ApiSnapshotError,
};
