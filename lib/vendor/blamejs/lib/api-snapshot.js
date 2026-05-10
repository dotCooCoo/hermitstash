"use strict";
/**
 * @module b.apiSnapshot
 * @nav    Other
 * @title  API Snapshot
 *
 * @intro
 *   Public-API surface walker plus breaking-change detector — the
 *   framework's LTS-contract enforcement at the type level. Operators
 *   capture a snapshot of the framework's `module.exports` tree,
 *   commit it alongside the version bump, and the release workflow's
 *   `check-api-snapshot.js` gate fails CI when any subsequent change
 *   removes or retypes a previously-shipped public member.
 *
 *   Three diff classes:
 *
 *     - `removed`       a member present in the old snapshot but not
 *                       the new (BREAKING — fails CI)
 *     - `typeChanged`   a member's category flipped, e.g. function →
 *                       object, primitive → instance (BREAKING — fails
 *                       CI)
 *     - `additive`      a new member that wasn't in the old snapshot
 *                       (informational — signals the snapshot is out
 *                       of date and the operator should rerun capture)
 *
 *   Walker rules: functions record as
 *   `{ type: "function", arity: fn.length }`; plain objects recurse
 *   into enumerable string keys; primitives record as
 *   `{ type: "primitive", valueType }` without capturing the literal
 *   value (so a version-string change in `b.version` doesn't fail
 *   CI); non-plain objects (Map, Set, Buffer, Date, RegExp, Error
 *   instances) record as `{ type: "instance", ctorName }` without
 *   recursion; cycles short-circuit as `{ type: "cycle" }`; depth is
 *   capped at `opts.maxDepth` (default 8). Members whose key starts
 *   with `_` are skipped — the framework convention for test seams
 *   and internal helpers.
 *
 *   Function-arity changes: a DECREASE in `fn.length` is breaking
 *   (the operator removed a required parameter). An INCREASE is not
 *   flagged because adding an optional trailing parameter is additive
 *   to existing callers.
 *
 *   On-disk format: stable canonical JSON ordered as
 *   `{ version, frameworkVersion, createdAt, exports }`. The format
 *   version (`b.apiSnapshot.SNAPSHOT_FORMAT_VERSION`) is checked on
 *   read so a future schema bump can't silently mis-compare against
 *   an older baseline.
 *
 * @card
 *   Public-API surface walker plus breaking-change detector — the framework's LTS-contract enforcement at the type level.
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

/**
 * @primitive b.apiSnapshot.capture
 * @signature b.apiSnapshot.capture(target, opts)
 * @since     0.1.91
 * @status    stable
 * @related   b.apiSnapshot.compare, b.apiSnapshot.write
 *
 * Walk a module's exports tree and produce a snapshot object
 * `{ version, frameworkVersion, createdAt, exports }` suitable for
 * round-tripping through `write` / `read`. The walk is recursive
 * with cycle detection and a depth cap; underscore-prefixed keys
 * are skipped by default (override with `skipUnderscore: false`).
 * Throws `ApiSnapshotError` when the top-level target is not a plain
 * object — class instances and runtime-built exports can't be walked
 * by category.
 *
 * @opts
 *   maxDepth:         8,             // recursion ceiling
 *   skipUnderscore:   true,          // skip `_internal` keys
 *   frameworkVersion: "0.8.48",      // override target.version
 *   createdAt:        "2026-05-09T...", // pin for deterministic snapshots
 *
 * @example
 *   var snap = b.apiSnapshot.capture(require("@blamejs/core"));
 *   // → { version: 1, frameworkVersion: "0.8.48",
 *   //     createdAt: "2026-05-09T12:00:00.000Z",
 *   //     exports: { uuid: { type: "object", members: {...} }, ... } }
 */
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

/**
 * @primitive b.apiSnapshot.write
 * @signature b.apiSnapshot.write(snapshot, filePath)
 * @since     0.1.91
 * @status    stable
 * @related   b.apiSnapshot.read, b.apiSnapshot.capture
 *
 * Serialize a snapshot to disk in canonical JSON form (stable
 * `{ version, frameworkVersion, createdAt, exports }` ordering, mode
 * 0o644). Returns the filePath written. Throws `ApiSnapshotError`
 * when the snapshot or path is missing — the release workflow
 * surfaces typos at commit time instead of writing to an unintended
 * location.
 *
 * @example
 *   var snap = b.apiSnapshot.capture(require("@blamejs/core"));
 *   var written = b.apiSnapshot.write(snap, "./api-snapshot.json");
 *   // → "./api-snapshot.json"
 */
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

/**
 * @primitive b.apiSnapshot.read
 * @signature b.apiSnapshot.read(filePath)
 * @since     0.1.91
 * @status    stable
 * @related   b.apiSnapshot.write, b.apiSnapshot.compare
 *
 * Load a snapshot from disk and validate its envelope. Throws
 * `ApiSnapshotError` with a specific code on each failure mode —
 * `api-snapshot/missing` (no file), `api-snapshot/read-failed`
 * (I/O error), `api-snapshot/bad-json` (parse failure), or
 * `api-snapshot/bad-version` (format-version mismatch — the
 * baseline was written by a different snapshot major) — so the
 * release workflow can surface a precise reason instead of a
 * generic "snapshot broken" message.
 *
 * @example
 *   var loaded = b.apiSnapshot.read("./api-snapshot.json");
 *   var current = b.apiSnapshot.capture(require("@blamejs/core"));
 *   var diff = b.apiSnapshot.compare(loaded, current);
 *   // → { breaking: [], additive: [], typeChanged: [] }
 */
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

/**
 * @primitive b.apiSnapshot.compare
 * @signature b.apiSnapshot.compare(oldSnapshot, newSnapshot)
 * @since     0.1.91
 * @status    stable
 * @related   b.apiSnapshot.formatDiff, b.apiSnapshot.capture
 *
 * Diff two snapshots and return
 * `{ breaking, additive, typeChanged }`. `breaking` carries every
 * member that was removed, retyped, lost arity, swapped its
 * constructor name, or changed primitive `valueType`; the release
 * workflow exits non-zero when this list is non-empty. `additive`
 * lists new members (informational — operator should rerun
 * `capture` and commit the refreshed baseline). `typeChanged` is a
 * subset of `breaking` surfaced separately for easier triage.
 *
 * @example
 *   var loaded = b.apiSnapshot.read("./api-snapshot.json");
 *   var current = b.apiSnapshot.capture(require("@blamejs/core"));
 *   var diff = b.apiSnapshot.compare(loaded, current);
 *   if (diff.breaking.length > 0) {
 *     console.error(b.apiSnapshot.formatDiff(diff));
 *     process.exit(1);
 *   }
 */
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

/**
 * @primitive b.apiSnapshot.formatDiff
 * @signature b.apiSnapshot.formatDiff(diff)
 * @since     0.1.91
 * @status    stable
 * @related   b.apiSnapshot.compare
 *
 * Render a diff result from `compare` into a human-readable
 * multi-line string suitable for `console.error` in a CI script.
 * Breaking entries are flagged with `-`, additive entries with `+`,
 * and the `was` / `is` types are JSON-quoted so the operator can
 * paste the line verbatim into the migration notes.
 *
 * @example
 *   var diff = {
 *     breaking: [{ path: "uuid.v3", kind: "removed", was: "function" }],
 *     additive: [{ path: "uuid.v8", type: "function" }],
 *     typeChanged: [],
 *   };
 *   var rendered = b.apiSnapshot.formatDiff(diff);
 *   // → "[api-snapshot] BREAKING (1):\n  - uuid.v3 (removed) was=\"function\"\n..."
 */
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
