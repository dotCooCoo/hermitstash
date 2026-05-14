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

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var { WatcherError } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });
var observability = lazyRequire(function () { return require("./observability"); });

var DEFAULT_DEBOUNCE_MS = 100;
// Polling-mode defaults. The polling backend exists for environments
// where nodeFs.watch's native events don't reach userspace — most commonly
// Docker Desktop bind-mounts on Windows / macOS hosts (where the
// inotify events from the Linux container's mount don't propagate
// through the gRPC-FUSE / VirtioFS bridge to the host fs), or NFS /
// SMB mounts that don't fire change notifications. Operators opt in
// explicitly via `mode: "poll"`. Default cadence is 1s per tick;
// pollMaxFiles caps the per-tick walk so a misconfigured root can't
// stall the event loop by stat'ing 100k files every second.
var DEFAULT_POLL_INTERVAL_MS = 1000;                                                              // allow:raw-byte-literal — 1-second poll cadence
var DEFAULT_POLL_MAX_FILES   = 50000;                                                             // allow:raw-byte-literal — per-tick stat cap
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
    var base = nodePath.basename(relPath);
    var normalized = relPath.split(nodePath.sep).join("/");
    for (var j = 0; j < compiled.length; j += 1) {
      var c = compiled[j];
      if (c.kind === "exact" && (c.value === relPath || c.value === normalized)) return true;
      if (c.kind === "prefix" && (normalized === c.value || normalized.indexOf(c.value + "/") === 0)) return true;
      if (c.kind === "glob" && _matchGlobBasename(c.value, base)) return true;
    }
    return false;
  };
}

var ALLOWED_MODES = ["fs", "poll"];

function _validateOpts(opts) {
  validateOpts.requireObject(opts, "watcher.create", WatcherError, "watcher/bad-opts");
  validateOpts.requireNonEmptyString(opts.root, "root", WatcherError, "watcher/bad-root");
  validateOpts.optionalFiniteNonNegative(opts.debounceMs, "debounceMs", WatcherError, "watcher/bad-debounce-ms");
  if (opts.mode !== undefined && ALLOWED_MODES.indexOf(opts.mode) === -1) {
    throw new WatcherError("watcher/bad-mode",
      "watcher.create: mode must be one of " + ALLOWED_MODES.join(", ") +
      ", got " + JSON.stringify(opts.mode));
  }
  validateOpts.optionalPositiveFinite(opts.pollIntervalMs, "pollIntervalMs", WatcherError, "watcher/bad-poll-interval-ms");
  if (opts.pollMaxFiles !== undefined &&
      (typeof opts.pollMaxFiles !== "number" || !isFinite(opts.pollMaxFiles) || opts.pollMaxFiles < 1)) {
    throw new WatcherError("watcher/bad-poll-max-files",
      "watcher.create: pollMaxFiles must be a positive finite integer");
  }
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

  var root        = nodePath.resolve(opts.root);
  var debounceMs  = (opts.debounceMs !== undefined) ? opts.debounceMs : DEFAULT_DEBOUNCE_MS;
  var maxPending  = (opts.maxPending !== undefined) ? opts.maxPending : DEFAULT_MAX_PENDING;
  var mode        = opts.mode || "fs";
  var pollIntervalMs = opts.pollIntervalMs || DEFAULT_POLL_INTERVAL_MS;
  var pollMaxFiles   = opts.pollMaxFiles   || DEFAULT_POLL_MAX_FILES;
  var onChange    = opts.onChange || function () {};
  var onDelete    = opts.onDelete || function () {};
  var onError     = opts.onError  || function () {};
  var isIgnored   = _compileIgnore(opts.ignore);
  var auditOn     = opts.audit !== false;

  // Pre-flight: root must exist and be a directory.
  var rootStat;
  try { rootStat = nodeFs.statSync(root); }
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
    var fullPath = nodePath.join(root, relPath);
    // lstat (NOT stat) — refuses to follow symlinks out of root.
    var lst;
    try { lst = nodeFs.lstatSync(fullPath); }
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

  // ---- start the underlying backend ----
  // pollSnapshot lives at function scope so stop() and _flushForTest()
  // can reach the polling tick state.
  var pollTimer    = null;
  var pollSnapshot = null;            // Map<relPath, { type, size, mtimeMs }>

  // Walk the tree honoring `ignore` patterns + the pollMaxFiles cap.
  // Returns the new snapshot Map, OR throws watcher/poll-overflow when
  // the cap is hit (that's an operator-misconfigured root signal — a
  // 100k-file tree under a 1s polling cadence stalls the event loop).
  function _walkPollTree() {
    var snapshot = new Map();
    var fileCount = 0;
    var stack = [""];
    while (stack.length > 0) {
      var relDir = stack.pop();
      var absDir = relDir === "" ? root : nodePath.join(root, relDir);
      var entries;
      try { entries = nodeFs.readdirSync(absDir, { withFileTypes: true }); }
      catch (_e) {
        // Root vanished mid-walk OR an inner dir got deleted between
        // the parent listing and the descent. Skip — the next tick's
        // walk surfaces the deletion via the snapshot diff.
        continue;
      }
      for (var i = 0; i < entries.length; i += 1) {
        var entry = entries[i];
        var relPath = relDir === "" ? entry.name : (relDir + "/" + entry.name);
        // Normalize to forward-slash so glob ignore-matching is
        // consistent with the nodeFs.watch path the operator's hooks see.
        relPath = relPath.split(nodePath.sep).join("/");
        if (isIgnored(relPath)) continue;
        if (entry.isSymbolicLink()) continue;            // never follow symlinks
        fileCount += 1;
        if (fileCount > pollMaxFiles) {
          throw new WatcherError("watcher/poll-overflow",
            "watcher.poll: tree exceeds pollMaxFiles=" + pollMaxFiles +
            " — narrow `ignore` patterns OR raise pollMaxFiles, OR switch to mode: \"fs\"");
        }
        var absPath = nodePath.join(absDir, entry.name);
        var st;
        try { st = nodeFs.statSync(absPath); }
        catch (_e) { continue; }                          // race — entry vanished
        if (entry.isDirectory()) {
          snapshot.set(relPath, { type: "dir", size: 0, mtimeMs: st.mtimeMs });
          stack.push(relPath);
        } else if (entry.isFile()) {
          snapshot.set(relPath, { type: "file", size: st.size, mtimeMs: st.mtimeMs });
        }
        // Other kinds (sockets, FIFOs, devices) — skip.
      }
    }
    return snapshot;
  }

  function _pollTick() {
    if (stopped) return;
    var next;
    try { next = _walkPollTree(); }
    catch (e) { _safeError(e); return; }
    if (pollSnapshot === null) {
      // First tick — establish the baseline without firing events.
      // Operators get add events on file CREATION after start, not on
      // pre-existing files (matches nodeFs.watch semantics).
      pollSnapshot = next;
      return;
    }
    // Diff: anything in `next` not in `pollSnapshot`, OR with size /
    // mtimeMs different, fires onChange via the same _enqueue path the
    // nodeFs.watch backend uses (so debounce + ignore + lstat dispatch
    // stay uniform). Anything in `pollSnapshot` missing from `next`
    // fires onDelete (via _normalizeAndDispatch's ENOENT branch).
    next.forEach(function (info, relPath) {
      var prev = pollSnapshot.get(relPath);
      if (!prev) { _enqueue(relPath); return; }
      if (prev.size !== info.size || prev.mtimeMs !== info.mtimeMs || prev.type !== info.type) {
        _enqueue(relPath);
      }
    });
    pollSnapshot.forEach(function (_info, relPath) {
      if (!next.has(relPath)) _enqueue(relPath);
    });
    pollSnapshot = next;
  }

  if (mode === "poll") {
    // Establish the initial snapshot synchronously so the first
    // operator-side onChange fires only on real post-start changes.
    try { pollSnapshot = _walkPollTree(); }
    catch (e) {
      throw new WatcherError("watcher/start-failed",
        "watcher.create: initial poll walk failed: " + ((e && e.message) || String(e)));
    }
    pollTimer = setInterval(_pollTick, pollIntervalMs);                                            // allow:setinterval-unref — .unref() called immediately below; timer doesn't pin the event loop
    if (typeof pollTimer.unref === "function") pollTimer.unref();
  } else {
    try {
      watcherHandle = nodeFs.watch(root, { recursive: true, persistent: true }, function (eventType, filename) {
        if (stopped) return;
        if (!filename) return;
        var rel = filename;
        if (nodePath.isAbsolute(rel) && rel.indexOf(root) === 0) {
          rel = nodePath.relative(root, rel);
        }
        if (rel === "" || rel === ".") return;
        _enqueue(rel);
      });
      watcherHandle.on("error", function (err) { _safeError(err); });
    } catch (e) {
      if (e && (e.code === "ERR_FEATURE_UNAVAILABLE_ON_PLATFORM" || e.code === "ENOSYS")) {
        throw new WatcherError("watcher/recursive-unsupported",
          "watcher.create: recursive watch not supported on this platform/kernel: " +
          ((e && e.message) || String(e)) + " — pass mode: \"poll\" to fall back to interval polling");
      }
      throw new WatcherError("watcher/start-failed",
        "watcher.create: fs.watch failed: " + ((e && e.message) || String(e)));
    }
  }

  _safeEmitAudit("watcher.started", { root: root, mode: mode });

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
    if (pollTimer) {
      try { clearInterval(pollTimer); } catch (_e) { /* best-effort */ }
      pollTimer = null;
    }
    _safeEmitAudit("watcher.stopped", { root: root, mode: mode, eventCount: eventCount });
  }

  // Test seam — flushes all pending debounce timers immediately so
  // tests don't have to await debounceMs. Not part of the operator
  // contract. In poll mode, also synchronously runs one tick so a
  // test can write a file, call _flushForTest(), and observe the
  // resulting onChange without sleeping for pollIntervalMs.
  function _flushForTest() {
    if (mode === "poll" && !stopped) {
      try { _pollTick(); }
      catch (_e) { /* tests assert via the operator's onChange callback */ }
    }
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
    mode:           mode,
    _flushForTest:  _flushForTest,
  };
}

module.exports = {
  create:        create,
  WatcherError:  WatcherError,
};
