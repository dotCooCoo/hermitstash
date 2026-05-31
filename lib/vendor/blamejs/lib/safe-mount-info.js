"use strict";
/**
 * @module     b.safeMountInfo
 * @nav        Primitives
 * @title      Safe MountInfo
 * @order      131
 * @slug       safe-mount-info
 *
 * @card
 *   Canonical /proc/self/mountinfo parser that always reads field 4
 *   (root-within-source-FS) — defeats the bind-mount detection bug
 *   class where ad-hoc parsers picked the wrong field.
 *
 * @intro
 *   Linux `/proc/self/mountinfo` is the per-process kernel-published
 *   mount table. The format is fixed per [kernel
 *   Documentation/filesystems/proc.rst §3.5](https://www.kernel.org/doc/Documentation/filesystems/proc.txt):
 *
 *     <id> <parent> <major:minor> <root> <mountpoint> <options>
 *     [<optional-fields>...] - <fstype> <source> <super-options>
 *
 *   The `<root>` field (positional index 3, 0-based) is "root within
 *   source FS" — `"/"` for a regular mount, a non-root path for a
 *   bind-mount (e.g. `/Users/me/data` mounted onto `/data` inside a
 *   container). Bind-mount detection MUST consult this field; ad-hoc
 *   parsers that scan the options string for the word "bind" miss
 *   the truth (kernel doesn't emit "bind" as an option — bind state
 *   is observable ONLY via field 4).
 *
 *   Pre-v0.11.6 the only lib/ caller (lib/watcher.js) parsed mountinfo
 *   correctly inline. Future callers — container-escape detection,
 *   sealed-store path validation, sandbox auto-probe — would have to
 *   re-derive the discipline. This primitive centralizes it: a
 *   single canonical parser that ALWAYS reads field 4, ALWAYS
 *   handles the `" - "` optional-fields separator, ALWAYS skips
 *   malformed lines without throwing.
 *
 *   Refusal posture:
 *     - `safe-mount-info/read-failed`     — /proc/self/mountinfo
 *       unreadable (non-Linux, restricted sandbox, host filesystem
 *       hidden). Operators get the typed error AND opts.fallback
 *       value (default null) to take.
 *     - `safe-mount-info/parse-failed`    — single malformed line
 *       within /proc/self/mountinfo. Silent-skip (per-line) by
 *       default; opts.strict: true upgrades to throw on first
 *       malformed line.
 *
 *   Threat model:
 *     - **Container-escape detection** (CVE-2019-5736 Docker /
 *       CVE-2022-0185 fsconfig / CVE-2024-21626 leaky-vessels) —
 *       bind-mount + root-field analysis is the canonical signal.
 *       Wrong-field readers (operations on field 5 / 6 / options-
 *       indexOf-"bind") miss escape-attempt patterns.
 *     - **Sealed-store integrity** — sealed dbs / vault state
 *       atop a bind-mounted host directory cross trust boundaries
 *       on container restart. Detection requires reading field 4
 *       and matching the mount-point against operator-trusted paths.
 *
 *   Composes:
 *     - lib/safe-decompress / lib/audit — operator-supplied audit
 *       handle receives `system.safe_mount_info.refused` events on
 *       read-failed and parse-failed (drop-silent — observability emission must not crash the hot path that emitted the event).
 *
 * RFC / kernel-doc citations:
 *   - [Linux Documentation/filesystems/proc.rst §3.5 — /proc/<pid>/mountinfo](https://www.kernel.org/doc/Documentation/filesystems/proc.txt)
 *   - [CVE-2024-21626](https://nvd.nist.gov/vuln/detail/CVE-2024-21626) — runc leaky-vessels (bind-mount detection)
 *   - [CVE-2022-0185](https://nvd.nist.gov/vuln/detail/CVE-2022-0185) — fsconfig integer underflow
 */

var nodeFs = require("node:fs");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var numericBounds = require("./numeric-bounds");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

var SafeMountInfoError = defineClass("SafeMountInfoError", { alwaysPermanent: true });

var DEFAULT_PATH = "/proc/self/mountinfo";

/**
 * @primitive b.safeMountInfo.parse
 * @signature b.safeMountInfo.parse(text, opts?)
 * @since     0.11.6
 * @status    stable
 * @related   b.safeMountInfo.read, b.safeMountInfo.bestMatch
 *
 * Parse `/proc/self/mountinfo` text bytes into structured entries.
 * Each entry carries `{ id, parent, devMajMin, root, mountPoint,
 * options, fstype, source, superOptions }` — `root` is the
 * positional field 4 ("root within source FS") that bind-mount
 * detection requires.
 *
 * Malformed lines are skipped by default (operator's mountinfo MAY
 * contain a stray line during a concurrent mount/unmount). Set
 * `opts.strict: true` to throw on first malformed line.
 *
 * @opts
 *   strict:  boolean,        // default false; throw on malformed line
 *   maxLines: number,        // default 4096; cap to bound parser work
 *
 * @example
 *   var entries = b.safeMountInfo.parse(rawText);
 *   var bindMounts = entries.filter(function (e) { return e.root !== "/"; });
 */
function parse(text, opts) {
  opts = opts || {};
  validateOpts(opts, ["strict", "maxLines"], "safeMountInfo.parse");
  if (typeof text !== "string") {
    throw new SafeMountInfoError(
      "safe-mount-info/bad-input",
      "safeMountInfo.parse: text must be a string");
  }
  numericBounds.requirePositiveFiniteIntIfPresent(opts.maxLines,
    "safeMountInfo.parse: opts.maxLines",
    SafeMountInfoError, "safe-mount-info/bad-arg");
  var maxLines = (typeof opts.maxLines === "number") ? opts.maxLines : 4096;         // line cap matches max kernel-published mount count
  var strict = opts.strict === true;
  var lines  = text.split("\n");
  // `text.split("\n").length` counts the trailing empty segment that
  // `/proc/self/mountinfo` produces with its final newline. Adjust
  // the count so the cap reflects ACTUAL records, not segments —
  // otherwise exactly-`maxLines` valid records gets rejected as
  // `too-many-lines` because the segment count is `maxLines + 1`.
  var trailingEmpty = (lines.length > 0 && lines[lines.length - 1] === "");
  var recordCount = trailingEmpty ? lines.length - 1 : lines.length;
  if (recordCount > maxLines) {
    throw new SafeMountInfoError(
      "safe-mount-info/too-many-lines",
      "safeMountInfo.parse: mountinfo has " + recordCount +
      " lines, exceeds maxLines " + maxLines);
  }
  var out = [];
  for (var i = 0; i < lines.length; i += 1) {
    var ln = lines[i];
    if (!ln) continue;
    // Format: <id> <parent> <major:minor> <root> <mountpoint> <options>
    //         [<optional-fields>...] - <fstype> <source> <super-options>
    // The separator " - " divides the optional-fields half from the
    // post-fields half.
    var sepIdx = ln.indexOf(" - ");
    if (sepIdx === -1) {
      if (strict) {
        throw new SafeMountInfoError(
          "safe-mount-info/parse-failed",
          "safeMountInfo.parse: line " + (i + 1) + " missing ' - ' separator");
      }
      continue;
    }
    var preFields  = ln.slice(0, sepIdx).split(" ");
    var postFields = ln.slice(sepIdx + 3).split(" ");
    if (preFields.length < 6 || postFields.length < 1) {                             // kernel-mandated minimum field counts
      if (strict) {
        throw new SafeMountInfoError(
          "safe-mount-info/parse-failed",
          "safeMountInfo.parse: line " + (i + 1) + " has " + preFields.length +
          " pre-fields, " + postFields.length + " post-fields (need >=6, >=1)");
      }
      continue;
    }
    out.push({
      id:           preFields[0],
      parent:       preFields[1],
      devMajMin:    preFields[2],
      root:         preFields[3],                                                    // *** field 4 (0-indexed 3) — bind-mount detection
      mountPoint:   preFields[4],
      options:      preFields[5],
      // optional-fields (variable length, between [6] and the " - ")
      // are exposed via `optionalFields` for advanced callers.
      optionalFields: preFields.slice(6, preFields.length).filter(function (f) { return f.length > 0; }),
      fstype:       postFields[0],
      source:       postFields[1] || null,
      superOptions: postFields[2] || null,
    });
  }
  return out;
}

/**
 * @primitive b.safeMountInfo.read
 * @signature b.safeMountInfo.read(opts?)
 * @since     0.11.6
 * @status    stable
 * @related   b.safeMountInfo.parse, b.safeMountInfo.bestMatch
 *
 * Read + parse `/proc/self/mountinfo` in one call. Returns the same
 * array shape as `parse(text)`. On non-Linux platforms (where /proc
 * doesn't exist) returns `opts.fallback` (default `null`); audit
 * emission per `safe-mount-info.refused` with code `read-failed`.
 *
 * @opts
 *   path:     string,        // override path (default /proc/self/mountinfo)
 *   fallback: any,           // returned on read failure (default null)
 *   audit:    object,        // optional b.audit handle for refusal events
 *   strict:   boolean,       // forwarded to parse()
 *   maxLines: number,        // forwarded to parse()
 *
 * @example
 *   var entries = b.safeMountInfo.read();
 *   if (entries === null) {
 *     // non-Linux / sandboxed / no /proc
 *   }
 */
function read(opts) {
  opts = opts || {};
  validateOpts(opts,
    ["path", "fallback", "audit", "strict", "maxLines"],
    "safeMountInfo.read");
  var path = typeof opts.path === "string" && opts.path.length > 0
    ? opts.path
    : DEFAULT_PATH;
  var text;
  try { text = nodeFs.readFileSync(path, "utf8"); }
  catch (e) {
    _refuseEmit(opts, "safe-mount-info/read-failed",
      "/proc/self/mountinfo unreadable: " + ((e && e.message) || String(e)));
    return ("fallback" in opts) ? opts.fallback : null;
  }
  return parse(text, opts);
}

/**
 * @primitive b.safeMountInfo.bestMatch
 * @signature b.safeMountInfo.bestMatch(entries, path)
 * @since     0.11.6
 * @status    stable
 * @related   b.safeMountInfo.read, b.safeMountInfo.isBindMount
 *
 * Find the mountinfo entry whose `mountPoint` is the longest prefix
 * of `path`. Returns `null` when no entry covers `path`. The "longest
 * prefix" semantic is what bind-mount detection / sealed-store-path
 * validation needs — a mounted subdir wins over the root mount.
 *
 * @example
 *   var entries  = b.safeMountInfo.read();
 *   var atPath   = b.safeMountInfo.bestMatch(entries, "/var/lib/blamejs");
 *   if (atPath && atPath.root !== "/") {
 *     // path lives on a bind-mount (potentially crossing host/guest)
 *   }
 */
function bestMatch(entries, path) {
  if (!Array.isArray(entries) || entries.length === 0) return null;
  if (typeof path !== "string" || path.length === 0) return null;
  var best = null;
  var bestLen = -1;
  for (var i = 0; i < entries.length; i += 1) {
    var e = entries[i];
    if (!e || typeof e.mountPoint !== "string" || e.mountPoint.length === 0) continue;
    var mp = e.mountPoint;
    if (path === mp ||
        (path.length > mp.length &&
         path.indexOf(mp) === 0 &&
         (mp === "/" || path.charCodeAt(mp.length) === 47 /* "/" */))) {              // ASCII forward-slash
      if (mp.length > bestLen) {
        bestLen = mp.length;
        best = e;
      }
    }
  }
  return best;
}

/**
 * @primitive b.safeMountInfo.isBindMount
 * @signature b.safeMountInfo.isBindMount(entry)
 * @since     0.11.6
 * @status    stable
 * @related   b.safeMountInfo.bestMatch
 *
 * `true` when the mountinfo entry's `root` field is something other
 * than `"/"` (i.e. the mount is a bind from a non-root path within
 * the source filesystem). The canonical bind-mount test — does NOT
 * consult the options string (the kernel doesn't emit "bind" there).
 *
 * @example
 *   var entries = b.safeMountInfo.read();
 *   var atData  = b.safeMountInfo.bestMatch(entries, "/data");
 *   var isBind  = b.safeMountInfo.isBindMount(atData);
 */
function isBindMount(entry) {
  if (!entry || typeof entry !== "object") return false;
  return typeof entry.root === "string" && entry.root.length > 0 && entry.root !== "/";
}

function _refuseEmit(opts, code, message) {
  var auditImpl = opts.audit || (audit() && audit().safeEmit ? audit() : null);
  if (auditImpl && typeof auditImpl.safeEmit === "function") {
    try {
      auditImpl.safeEmit({
        action:   "system.safe_mount_info.refused",
        outcome:  "denied",
        metadata: { code: code, reason: message },
      });
    } catch (_e) { /* drop-silent — observability emission must not crash the hot path that emitted the event */ }
  }
}

module.exports = {
  parse:                  parse,
  read:                   read,
  bestMatch:              bestMatch,
  isBindMount:            isBindMount,
  SafeMountInfoError:     SafeMountInfoError,
  DEFAULT_PATH:           DEFAULT_PATH,
};
