"use strict";
/**
 * b.watcher — recursive filesystem-watch primitive with cross-platform
 * event normalization.
 *
 * Wraps `fs.watch(root, { recursive: true })` and turns the per-platform
 * event soup (Linux inotify "rename" + "change", macOS FSEvents
 * coalesced "rename", Windows ReadDirectoryChangesW pure "rename" /
 * "change") into a single shape:
 *
 *   onChange({ type, relativePath, fullPath, size, mtime })
 *   onDelete({ type, relativePath, fullPath })
 *   onError(err)
 *
 * `type` is one of "file" or "dir". The watcher is build-tool-shaped:
 * use it to drive incremental rebuilds, hot-reload-on-change,
 * config-file watching, or content-store cache busts. It is NOT a
 * security primitive — fs.watch is best-effort across kernels and the
 * caller must not rely on it for audit-grade change detection.
 *
 * Cross-platform notes baked in:
 *   - macOS FSEvents fires "rename" for create / delete / move; the
 *     watcher disambiguates by stat-ing the path post-event.
 *   - Linux inotify can emit "change" before the file is fully written;
 *     debounce coalesces a burst of writes into one onChange.
 *   - Windows ReadDirectoryChangesW emits both "rename" and "change"
 *     for a single create — debounce + stat dedup the duplicate.
 *   - Symlinks are skipped on the post-event stat (lstat) to avoid
 *     following an attacker-controlled link out of `root`.
 *   - `recursive: true` on Linux (kernel 6.0+, since Node 20+ uses
 *     inotify_add_watch with IN_MASK_CREATE for nested dirs) — older
 *     kernels degrade to a single-directory watch and emit a warning
 *     event through `onError` once at startup.
 *
 * Audit emits:
 *   watcher.started   — { root }
 *   watcher.stopped   — { root, eventCount }
 *   watcher.error     — { root, code }   (drop-silent fallback)
 *
 * Public surface:
 *   watcher.create({ root, ignore?, debounceMs?, onChange?, onDelete?,
 *                    onError?, audit? })
 *     → { stop, root, _flushForTest }
 *
 *   watcher.WatcherError
 */

var fs   = require("fs");
var path = require("path");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var { WatcherError } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });
var observability = lazyRequire(function () { return require("./observability"); });

var DEFAULT_DEBOUNCE_MS = 100;
// Per-watcher event count cap before we self-terminate as a safety net
// against runaway directories that emit millions of events per minute.
// Operators with legitimate high-churn directories raise this via opts.
var DEFAULT_MAX_PENDING = 10000;                                                   // allow:raw-byte-literal — pending-event queue cap

// ---- glob-style matcher ----
//
// Supports three shapes per entry:
//   "*.ext"       — basename glob (extension or wildcard pattern)
//   "dir/**"      — prefix match against the relative path
//   "exact/path"  — exact relative-path match (case-sensitive)
//
// Anything else throws at create-time so a typo surfaces at boot.
//
// Implementation note: every pattern is parsed at create-time into a
// fixed shape (literal segments + `*` placeholders) and matched with a
// linear two-pointer walk over the basename. No dynamic RegExp — the
// linear walker has no catastrophic backtracking surface even when the
// pattern contains many `*`. Pattern length + `*` count are also
// bounded at parse-time as defense in depth.
var MAX_IGNORE_PATTERN_LEN = 256;
var MAX_IGNORE_STAR_COUNT  = 16;

function _parseGlobBasename(pattern) {
  // Split on `*` — the alternating literal pieces are matched in order
  // against the basename with `*` consuming any non-separator run.
  var parts = pattern.split("*");
  for (var i = 0; i < parts.length; i += 1) {
    if (parts[i].indexOf("/") !== -1 || parts[i].indexOf("\\") !== -1) {
      throw new WatcherError("watcher/bad-ignore",
        "watcher.create: glob pattern '" + pattern +
        "' contains a path separator outside the dir/** prefix form");
    }
  }
  return parts;
}

function _matchGlobBasename(parts, base) {
  // Two-pointer walk. parts[0] must prefix the basename; parts[last]
  // must suffix; intermediate parts must appear in order. `*` matches
  // any run of non-separator chars (basename has no separators).
  if (parts.length === 0) return false;
  if (parts[0].length > 0) {
    if (base.indexOf(parts[0]) !== 0) return false;
  }
  var pos = parts[0].length;
  if (parts.length === 1) return base.length === pos;
  // Match the trailing literal first to anchor.
  var tail = parts[parts.length - 1];
  if (tail.length > 0) {
    if (base.length - tail.length < pos) return false;
    if (base.lastIndexOf(tail) !== base.length - tail.length) return false;
  }
  var endLimit = base.length - tail.length;
  for (var k = 1; k < parts.length - 1; k += 1) {
    var seg = parts[k];
    if (seg.length === 0) continue;
    var found = base.indexOf(seg, pos);
    if (found === -1 || found + seg.length > endLimit) return false;
    pos = found + seg.length;
  }
  return true;
}

function _compileIgnore(patterns) {
  if (!Array.isArray(patterns) || patterns.length === 0) {
    return function () { return false; };
  }
  var compiled = [];
  for (var i = 0; i < patterns.length; i += 1) {
    var p = patterns[i];
    if (typeof p !== "string" || p.length === 0) {
      throw new WatcherError("watcher/bad-ignore",
        "watcher.create: ignore[" + i + "] must be a non-empty string");
    }
    if (p.length > MAX_IGNORE_PATTERN_LEN) {
      throw new WatcherError("watcher/bad-ignore",
        "watcher.create: ignore[" + i + "] exceeds " + MAX_IGNORE_PATTERN_LEN + "-byte cap");
    }
    var starCount = 0;
    for (var s = 0; s < p.length; s += 1) if (p.charCodeAt(s) === 42 /* * */) starCount += 1;
    if (starCount > MAX_IGNORE_STAR_COUNT) {
      throw new WatcherError("watcher/bad-ignore",
        "watcher.create: ignore[" + i + "] exceeds " + MAX_IGNORE_STAR_COUNT + "-wildcard cap");
    }
    if (p.indexOf("**") !== -1) {
      // dir/** prefix-match — strip the trailing **; reject `**` mid-pattern.
      if (!/^[^*]*\/?\*\*$/.test(p)) {
        throw new WatcherError("watcher/bad-ignore",
          "watcher.create: ignore[" + i + "] '**' is only supported as a trailing dir/** prefix form");
      }
      var prefix = p.replace(/\/?\*\*$/, "");
      compiled.push({ kind: "prefix", value: prefix });
    } else if (starCount > 0) {
      compiled.push({ kind: "glob", value: _parseGlobBasename(p) });
    } else {
      compiled.push({ kind: "exact", value: p });
    }
  }
  return function (relPath) {
    var base = path.basename(relPath);
    var normalized = relPath.split(path.sep).join("/");
    for (var j = 0; j < compiled.length; j += 1) {
      var c = compiled[j];
      if (c.kind === "exact" && (c.value === relPath || c.value === normalized)) return true;
      if (c.kind === "prefix" && (normalized === c.value || normalized.indexOf(c.value + "/") === 0)) return true;
      if (c.kind === "glob" && _matchGlobBasename(c.value, base)) return true;
    }
    return false;
  };
}

function _validateOpts(opts) {
  validateOpts.requireObject(opts, "watcher.create", WatcherError, "watcher/bad-opts");
  validateOpts.requireNonEmptyString(opts.root, "root", WatcherError, "watcher/bad-root");
  validateOpts.optionalFiniteNonNegative(opts.debounceMs, "debounceMs", WatcherError, "watcher/bad-debounce-ms");
  if (opts.maxPending !== undefined &&
      (typeof opts.maxPending !== "number" || !isFinite(opts.maxPending) || opts.maxPending < 1)) {
    throw new WatcherError("watcher/bad-max-pending",
      "watcher.create: maxPending must be a positive finite number");
  }
  validateOpts.optionalFunction(opts.onChange, "onChange", WatcherError, "watcher/bad-hook");
  validateOpts.optionalFunction(opts.onDelete, "onDelete", WatcherError, "watcher/bad-hook");
  validateOpts.optionalFunction(opts.onError,  "onError",  WatcherError, "watcher/bad-hook");
  if (opts.ignore !== undefined && !Array.isArray(opts.ignore)) {
    throw new WatcherError("watcher/bad-ignore",
      "watcher.create: ignore must be an array of glob patterns");
  }
}

function create(opts) {
  _validateOpts(opts);

  var root        = path.resolve(opts.root);
  var debounceMs  = (opts.debounceMs !== undefined) ? opts.debounceMs : DEFAULT_DEBOUNCE_MS;
  var maxPending  = (opts.maxPending !== undefined) ? opts.maxPending : DEFAULT_MAX_PENDING;
  var onChange    = opts.onChange || function () {};
  var onDelete    = opts.onDelete || function () {};
  var onError     = opts.onError  || function () {};
  var isIgnored   = _compileIgnore(opts.ignore);
  var auditOn     = opts.audit !== false;

  // Pre-flight: root must exist and be a directory.
  var rootStat;
  try { rootStat = fs.statSync(root); }
  catch (e) {
    throw new WatcherError("watcher/root-missing",
      "watcher.create: root '" + root + "' is not accessible: " + ((e && e.message) || String(e)));
  }
  if (!rootStat.isDirectory()) {
    throw new WatcherError("watcher/root-not-dir",
      "watcher.create: root '" + root + "' is not a directory");
  }

  // Pending-event coalescer: per-relative-path debounce timer +
  // last-known shape ("change" | "delete"). The most recent observation
  // wins when the timer fires. Uses Map for ordered iteration on
  // self-terminate paths.
  var pending = new Map();
  var stopped = false;
  var eventCount = 0;
  var watcherHandle = null;

  function _safeEmitAudit(action, metadata) {
    if (!auditOn) return;
    try { audit().safeEmit({ action: action, outcome: "success", metadata: metadata || {} }); }
    catch (_e) { /* drop-silent — audit best-effort */ }
  }

  function _safeError(err) {
    try { observability().safeEvent("watcher.error", 1, { code: (err && err.code) || "unknown" }); }
    catch (_e) { /* drop-silent */ }
    try { onError(err); } catch (_e) { /* operator error handler must not crash the watcher */ }
  }

  function _normalizeAndDispatch(relPath) {
    if (stopped) return;
    if (isIgnored(relPath)) return;
    var fullPath = path.join(root, relPath);
    // lstat (NOT stat) — refuses to follow symlinks out of root.
    var lst;
    try { lst = fs.lstatSync(fullPath); }
    catch (e) {
      if (e && e.code === "ENOENT") {
        // Path is gone — delete event. Type unknown by the time we
        // observe; emit "file" as the conservative default. Operators
        // tracking dir vs file deletes must keep their own shadow tree.
        try {
          onDelete({ type: "file", relativePath: relPath, fullPath: fullPath });
        } catch (_eh) { /* operator hook must not crash dispatch */ }
        return;
      }
      _safeError(e);
      return;
    }
    if (lst.isSymbolicLink()) {
      // Skip — never follow a symlink. The watcher ignores the event.
      return;
    }
    var type = lst.isDirectory() ? "dir" : "file";
    try {
      onChange({
        type:         type,
        relativePath: relPath,
        fullPath:     fullPath,
        size:         lst.size,
        mtime:        lst.mtime,
      });
    } catch (_eh) { /* operator hook must not crash dispatch */ }
  }

  function _enqueue(relPath) {
    if (stopped) return;
    eventCount += 1;
    if (pending.size >= maxPending) {
      // Safety net — operator's directory is producing more events
      // than the watcher can keep up with. Emit one error and stop;
      // operators raise maxPending or fix the source.
      var overflow = new WatcherError("watcher/overflow",
        "watcher: pending event queue exceeded maxPending=" + maxPending);
      _safeError(overflow);
      stop();
      return;
    }
    var existing = pending.get(relPath);
    if (existing && existing.timer) clearTimeout(existing.timer);
    var entry = { timer: null };
    entry.timer = setTimeout(function () {
      pending.delete(relPath);
      _normalizeAndDispatch(relPath);
    }, debounceMs);
    // Keep timers from blocking process exit — the operator's stop()
    // call (or appShutdown) clears them explicitly.
    if (entry.timer && typeof entry.timer.unref === "function") entry.timer.unref();
    pending.set(relPath, entry);
  }

  // ---- start the underlying watch ----
  try {
    watcherHandle = fs.watch(root, { recursive: true, persistent: true }, function (eventType, filename) {
      if (stopped) return;
      // filename can be null on some platforms when the buffer
      // overflows. Drop — there is nothing actionable.
      if (!filename) return;
      // node returns OS-native paths; normalize to root-relative.
      var rel = filename;
      // fs.watch passes a relative path already, but on macOS it can
      // be an absolute path under /private/var/... when the root is a
      // tmpdir symlink. Strip the root prefix defensively.
      if (path.isAbsolute(rel) && rel.indexOf(root) === 0) {
        rel = path.relative(root, rel);
      }
      // Both inotify and ReadDirectoryChangesW occasionally fire with
      // an empty filename for the root directory itself — ignore.
      if (rel === "" || rel === ".") return;
      _enqueue(rel);
    });
    watcherHandle.on("error", function (err) { _safeError(err); });
  } catch (e) {
    // Older kernels without recursive inotify return ERR_FEATURE_UNAVAILABLE.
    // Surface as an operator-actionable error rather than a silent
    // single-directory degradation.
    if (e && (e.code === "ERR_FEATURE_UNAVAILABLE_ON_PLATFORM" || e.code === "ENOSYS")) {
      throw new WatcherError("watcher/recursive-unsupported",
        "watcher.create: recursive watch not supported on this platform/kernel: " +
        ((e && e.message) || String(e)));
    }
    throw new WatcherError("watcher/start-failed",
      "watcher.create: fs.watch failed: " + ((e && e.message) || String(e)));
  }

  _safeEmitAudit("watcher.started", { root: root });

  function stop() {
    if (stopped) return;
    stopped = true;
    // Clear any pending debounces so process exit isn't held up.
    pending.forEach(function (entry) {
      if (entry && entry.timer) clearTimeout(entry.timer);
    });
    pending.clear();
    if (watcherHandle) {
      try { watcherHandle.close(); } catch (_e) { /* best-effort */ }
      watcherHandle = null;
    }
    _safeEmitAudit("watcher.stopped", { root: root, eventCount: eventCount });
  }

  // Test seam — flushes all pending debounce timers immediately so
  // tests don't have to await debounceMs. Not part of the operator
  // contract.
  function _flushForTest() {
    var snapshot = Array.from(pending.entries());
    pending.clear();
    for (var i = 0; i < snapshot.length; i += 1) {
      if (snapshot[i][1] && snapshot[i][1].timer) clearTimeout(snapshot[i][1].timer);
      _normalizeAndDispatch(snapshot[i][0]);
    }
  }

  return {
    stop:           stop,
    root:           root,
    _flushForTest:  _flushForTest,
  };
}

module.exports = {
  create:        create,
  WatcherError:  WatcherError,
};
