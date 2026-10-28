// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.watcher
 * @nav    Filesystem
 * @title  Watcher
 * @slug   watcher
 *
 * @intro
 *   Watch a directory tree and get one event shape whatever the kernel
 *   underneath reports.
 *
 *   Each platform describes a change differently. Linux inotify sends
 *   "rename" and "change" and can send "change" before the write has
 *   finished. macOS FSEvents coalesces creates, deletes and moves into
 *   one "rename". Windows sends both "rename" and "change" for a single
 *   create. The watcher settles a burst, stats the path afterwards to see
 *   what actually happened, and calls <code>onChange</code> or
 *   <code>onDelete</code> once.
 *
 *   It follows no symbolic link when it stats, so a link planted inside
 *   the tree cannot walk the watcher out of it.
 *
 *   It is for rebuilds, reloads and cache busts. <code>fs.watch</code> is
 *   best-effort on every kernel and drops events under load, so nothing
 *   that has to know about every change should be built on it.
 *
 * @card
 *   Watch a directory tree and receive one event shape across Linux, macOS
 *   and Windows, with bursts settled and the real outcome read back from
 *   the filesystem. For rebuilds and reloads, not for audit.
 */

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
 *     → { stop, root, mode, ready, _flushForTest }
 *
 *   watcher.WatcherError
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");
var C        = require("./constants");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var safeMountInfo = require("./safe-mount-info");
var safeAsync = require("./safe-async");
var time     = require("./time");
var { WatcherError } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });
var observability = lazyRequire(function () { return require("./observability"); });

var DEFAULT_DEBOUNCE_MS = 100;
var DEFAULT_POLL_INTERVAL_MS = 1000;
var DEFAULT_POLL_MAX_FILES   = 50000;
var DEFAULT_MAX_PENDING = 10000;
var POLL_DIR_BATCH = 32;
var POLL_COMPARE_CHUNK = 1024;
var DISPATCH_CHUNK = 64;

var HANDLE_DEAD_CODES = ["EPERM", "EBADF", "ENOSPC", "EMFILE", "ENFILE", "EACCES"];
var WIN32_LONG_PATH_THRESHOLD = 250;

var MAX_IGNORE_PATTERN_LEN = 256;
var MAX_IGNORE_STAR_COUNT  = 16;

function _parseGlobBasename(pattern) {
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
  if (parts.length === 0) return false;
  if (parts[0].length > 0) {
    if (base.indexOf(parts[0]) !== 0) return false;
  }
  var pos = parts[0].length;
  if (parts.length === 1) return base.length === pos;
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

function _compileIgnore(patterns, caseFold) {
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
    for (var s = 0; s < p.length; s += 1) if (p.charCodeAt(s) === 42 ) starCount += 1;
    if (starCount > MAX_IGNORE_STAR_COUNT) {
      throw new WatcherError("watcher/bad-ignore",
        "watcher.create: ignore[" + i + "] exceeds " + MAX_IGNORE_STAR_COUNT + "-wildcard cap");
    }
    var pk = caseFold ? p.toLowerCase() : p;
    if (pk.indexOf("**") !== -1) {
      if (!/^[^*]*\/?\*\*$/.test(pk)) {
        throw new WatcherError("watcher/bad-ignore",
          "watcher.create: ignore[" + i + "] '**' is only supported as a trailing dir/** prefix form");
      }
      var prefix = pk.replace(/\/?\*\*$/, "");
      compiled.push({ kind: "prefix", value: prefix });
    } else if (starCount > 0) {
      compiled.push({ kind: "glob", value: _parseGlobBasename(pk) });
    } else {
      compiled.push({ kind: "exact", value: pk });
    }
  }
  return function (relPath) {
    var matchPath = caseFold ? relPath.toLowerCase() : relPath;
    var base = nodePath.basename(matchPath);
    var normalized = matchPath.split(nodePath.sep).join("/");
    for (var j = 0; j < compiled.length; j += 1) {
      var c = compiled[j];
      if (c.kind === "exact" && (c.value === matchPath || c.value === normalized)) return true;
      if (c.kind === "prefix" && (normalized === c.value || normalized.indexOf(c.value + "/") === 0)) return true;
      if (c.kind === "glob" && _matchGlobBasename(c.value, base)) return true;
    }
    return false;
  };
}

var ALLOWED_MODES = ["fs", "poll", "auto"];

var AUTO_PROBE_POLL_FSTYPES = new Set([
  "fuse",
  "fuse.gcsfuse",
  "fuse.grpcfuse",
  "fuse.virtiofs",
  "9p",
  "virtiofs",
  "cifs",
  "smbfs",
  "nfs",
  "nfs4",
  "vboxsf",
]);

function _detectAutoMode(rootPath, probe) {
  var platform = (probe && probe.platform) || process.platform;
  var readEntries = (probe && probe.readEntries) ||
    function () { return safeMountInfo.read(); };
  var exists = (probe && probe.exists) ||
    function (p) { return nodeFs.existsSync(p); };

  if (platform !== "linux") {
    return { mode: "fs", reason: "non-linux-host", fsType: null, inContainer: false };
  }

  var inContainer = false;
  try { inContainer = exists("/.dockerenv"); }
  catch (_e) { inContainer = false; }

  var entries = readEntries();
  if (entries === null || entries.length === 0) {
    return { mode: "poll", reason: "no-mountinfo", fsType: null, inContainer: inContainer };
  }
  var bestMatch = safeMountInfo.bestMatch(entries, rootPath);
  if (!bestMatch) {
    return { mode: "poll", reason: "no-mount-match", fsType: null, inContainer: inContainer };
  }
  if (AUTO_PROBE_POLL_FSTYPES.has(bestMatch.fstype)) {
    return {
      mode:        "poll",
      reason:      "fstype-non-inotify",
      fsType:      bestMatch.fstype,
      inContainer: inContainer,
    };
  }
  if (inContainer && safeMountInfo.isBindMount(bestMatch)) {
    return {
      mode:        "poll",
      reason:      "container-bind-mount",
      fsType:      bestMatch.fstype,
      inContainer: inContainer,
    };
  }
  return {
    mode:        "fs",
    reason:      "native-fs",
    fsType:      bestMatch.fstype,
    inContainer: inContainer,
  };
}

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
  validateOpts.optionalBoolean(opts.ignoreCaseFold, "ignoreCaseFold", WatcherError, "watcher/bad-ignore");
}

function _nextTurn() {
  return new Promise(function (resolve) { setImmediate(resolve); });
}

async function _comparePollSnapshots(prev, next, onPath, isStopped) {
  var seen = 0;
  var step;
  var added = next.entries();
  while (!(step = added.next()).done) {
    var relPath = step.value[0];
    var info = step.value[1];
    var was = prev.get(relPath);
    if (!was || was.size !== info.size || was.mtimeMs !== info.mtimeMs || was.type !== info.type) {
      onPath(relPath);
    }
    seen += 1;
    if (seen % POLL_COMPARE_CHUNK === 0) {
      await _nextTurn();
      if (isStopped()) return false;
    }
  }
  var removed = prev.keys();
  while (!(step = removed.next()).done) {
    if (!next.has(step.value)) onPath(step.value);
    seen += 1;
    if (seen % POLL_COMPARE_CHUNK === 0) {
      await _nextTurn();
      if (isStopped()) return false;
    }
  }
  return !isStopped();
}

function _lstatLongPathSafe(fullPath) {
  if (process.platform === "win32" && fullPath.length >= WIN32_LONG_PATH_THRESHOLD && fullPath.indexOf("\\\\?\\") !== 0) {
    try { return nodeFs.lstatSync("\\\\?\\" + fullPath); }
    catch (_e) { /* fall through to the plain path so a real ENOENT resurfaces */ }
  }
  return nodeFs.lstatSync(fullPath);
}

/**
 * @primitive b.watcher.create
 * @signature b.watcher.create(opts)
 * @since     0.8.45
 * @status    stable
 * @related   b.bundler.create, b.staticServe.create
 *
 * Start watching `root` and answer the handle to stop it. The handle
 * carries `stop()`, `root` as it was resolved, `mode`, which is the
 * backend that ended up running, and `ready`, a promise that resolves once
 * the watcher has its baseline. Under `"fs"` it resolves straight away.
 * Under `"poll"`, `create()` returns before the first walk of the tree and
 * `ready` resolves when that walk completes. A change made before `ready`
 * resolves may be taken into the baseline without being reported, or may be
 * reported by the next walk, depending on whether the first walk has read
 * that directory yet. When `stop()` is called before the first walk
 * completes, `ready` resolves at once, even while that walk is still waiting
 * on the filesystem, and a later failure of that walk does not change it.
 * After `stop()`, `onError` receives nothing.
 *
 * `onChange` receives `{ type, relativePath, fullPath, size, mtime }` and
 * `onDelete` receives the first three, where `type` is `"file"` or
 * `"dir"`. `onError` receives anything the backend reports, including the
 * one-time notice that a kernel too old for a recursive watch has fallen
 * back to watching the top directory alone. When `fs.watch` refuses a
 * recursive watch with `EACCES` or `EPERM` because a directory under a
 * readable root cannot be read, as Node 24.22.1 and 26.12.1 do on Linux, the
 * watcher polls the tree instead, skipping unreadable directories; the
 * handle's `mode` is then `"poll"` and `onError` receives a
 * `watcher/recursive-unreadable` notice.
 *
 * `create` throws `watcher/root-missing` for a root it cannot stat,
 * `watcher/root-not-dir` for a root that is not a directory,
 * `watcher/recursive-unsupported` when the platform has no recursive watch,
 * and `watcher/start-failed` when `fs.watch` cannot start. When the poll
 * backend's first walk fails, for example because the tree holds more than
 * `pollMaxFiles` entries, the watcher stops itself, `onError` receives a
 * `watcher/start-failed` whose `cause` is the walk's error, and `ready`
 * rejects with that same error. A later walk that fails reports
 * `watcher/poll-overflow` or `watcher/root-lost` through `onError` and the
 * watcher keeps polling. `onError` receives `watcher/overflow` when more
 * than `maxPending` events wait to settle.
 *
 * `mode` picks the backend. `"fs"` uses `fs.watch`. `"poll"` walks the
 * tree on an interval, for a filesystem where watching does not work, such
 * as a network mount; it reads at most `pollMaxFiles` entries so a large
 * tree cannot turn a poll into a sweep of everything. `"auto"` reads the
 * mount table and picks poll for FUSE, 9p, virtiofs, NFS, SMB and vboxsf,
 * and for a bind mount inside a container. Leaving it out picks per platform.
 *
 * A watcher keeps the process alive under either backend until `close()`,
 * so a program whose only work is watching does not exit. The poll backend
 * used to leave the process free to exit while `fs.watch` held it open,
 * which made lifetime under `"auto"` depend on the filesystem. The poll walk,
 * the first one included, reads each directory asynchronously in batches of
 * 32 entries and stats each batch concurrently. After a later walk, the
 * watcher compares the new snapshot with the previous one 1024 entries per
 * event-loop turn. Under either backend, settled changes go to `onChange` and
 * `onDelete` at most 64 per turn, in the order they settled. Under `"poll"`,
 * no event-loop turn grows with the size of the tree or of a single
 * directory. Under either backend, no dispatch turn grows with the number of
 * changed paths. Under `"fs"`, the events of one native `fs.watch` batch are
 * queued in one turn. The next walk is timed from the end of the last one.
 *
 * `debounceMs` is how long a burst is allowed to settle before one event
 * goes out. `maxPending` bounds the events held while settling, so a tree
 * being rewritten wholesale cannot grow the queue without limit.
 *
 * @opts
 *   root:           string,     // directory to watch; required
 *   mode:           string,     // "fs", "poll" or "auto"; default "fs"
 *   ignore:         string[],   // path patterns to skip
 *   ignoreCaseFold: boolean,    // default false — match ignore patterns case-insensitively
 *   debounceMs:     number,     // burst settle time; default 100
 *   maxPending:     number,     // events held while settling; default 10000
 *   pollIntervalMs: number,     // poll backend interval; default 1000
 *   pollMaxFiles:   number,     // poll backend entry ceiling; default 50000
 *   onChange:       function,   // ({ type, relativePath, fullPath, size, mtime })
 *   onDelete:       function,   // ({ type, relativePath, fullPath })
 *   onError:        function,   // (err)
 *   audit:          boolean,    // default true
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var w = b.watcher.create({
 *     root:     "./src",
 *     ignore:   ["node_modules", ".git"],
 *     onChange: function (ev) { rebuild(ev.relativePath); },
 *     onDelete: function (ev) { forget(ev.relativePath); },
 *   });
 *   w.ready.then(function () { w.stop(); });
 */
function create(opts) {
  _validateOpts(opts);

  var root        = nodePath.resolve(opts.root);
  try { root = nodeFs.realpathSync.native(root); } catch (_e) { /* keep resolved path */ }
  var debounceMs  = (opts.debounceMs !== undefined) ? opts.debounceMs : DEFAULT_DEBOUNCE_MS;
  var maxPending  = (opts.maxPending !== undefined) ? opts.maxPending : DEFAULT_MAX_PENDING;
  var requestedMode = opts.mode || "fs";
  var autoDecision  = null;
  if (requestedMode === "auto") {
    autoDecision = _detectAutoMode(root);
  }
  var mode = autoDecision ? autoDecision.mode : requestedMode;
  var pollIntervalMs = opts.pollIntervalMs || DEFAULT_POLL_INTERVAL_MS;
  var pollMaxFiles   = opts.pollMaxFiles   || DEFAULT_POLL_MAX_FILES;
  var onChange    = opts.onChange || function () {};
  var onDelete    = opts.onDelete || function () {};
  var onError     = opts.onError  || function () {};
  var isIgnored   = _compileIgnore(opts.ignore, opts.ignoreCaseFold === true);
  var auditOn     = opts.audit !== false;

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

  var pending = new Map();
  var drainTimer = null;
  var drainImmediate = null;
  var draining = false;
  var stopped = false;
  var eventCount = 0;
  var watcherHandle = null;

  function _safeEmitAudit(action, metadata) {
    if (!auditOn) return;
    try { audit().safeEmit({ action: action, outcome: "success", metadata: metadata || {} }); }
    catch (_e) { /* drop-silent — audit best-effort */ }
  }

  function _safeError(err) {
    if (stopped) return;
    try { observability().safeEvent("watcher.error", 1, { code: (err && err.code) || "unknown" }); }
    catch (_e) { /* drop-silent */ }
    safeAsync.safeInvoke(onError, err);
  }

  function _handleBackendError(err) {
    if (err && HANDLE_DEAD_CODES.indexOf(err.code) !== -1) {
      var dead = new WatcherError("watcher/handle-dead",
        "watcher: native watch handle died (" + err.code + ") — change detection has " +
        "permanently stopped; recreate the watcher to resume: " + (err.message || String(err)));
      dead.fatal = true;
      dead.cause = err;
      _safeError(dead);
      return;
    }
    _safeError(err);
  }

  function _normalizeAndDispatch(relPath) {
    if (stopped) return;
    if (isIgnored(relPath)) return;
    var fullPath = nodePath.join(root, relPath);
    var lst;
    try { lst = _lstatLongPathSafe(fullPath); }
    catch (e) {
      if (e && e.code === "ENOENT") {
        safeAsync.safeInvoke(onDelete,
          { type: "file", relativePath: relPath, fullPath: fullPath });
        return;
      }
      _safeError(e);
      return;
    }
    if (lst.isSymbolicLink()) {
      return;
    }
    var type = lst.isDirectory() ? "dir" : "file";
    safeAsync.safeInvoke(onChange, {
      type:         type,
      relativePath: relPath,
      fullPath:     fullPath,
      size:         lst.size,
      mtime:        lst.mtime,
    });
  }

  function _enqueue(relPath) {
    if (stopped) return;
    eventCount += 1;
    if (pending.size >= maxPending) {
      var overflow = new WatcherError("watcher/overflow",
        "watcher: pending event queue exceeded maxPending=" + maxPending);
      _safeError(overflow);
      stop();
      return;
    }
    pending.delete(relPath);
    pending.set(relPath, time.monotonicMs() + debounceMs);
    _scheduleDrain();
  }

  function _scheduleDrain() {
    if (stopped || draining || drainTimer !== null || drainImmediate !== null || pending.size === 0) return;
    var wait = Math.max(0, Math.ceil(pending.values().next().value - time.monotonicMs()));
    drainTimer = setTimeout(function () {
      drainTimer = null;
      _drainPending();
    }, wait);
    if (typeof drainTimer.unref === "function") drainTimer.unref();
  }

  function _drainPending() {
    if (stopped) return;
    var now = time.monotonicMs();
    var delivered = 0;
    draining = true;
    try {
      while (pending.size > 0 && delivered < DISPATCH_CHUNK && !stopped) {
        var head = pending.entries().next().value;
        if (head[1] > now) break;
        pending.delete(head[0]);
        delivered += 1;
        _normalizeAndDispatch(head[0]);
      }
    } finally {
      draining = false;
    }
    if (stopped || pending.size === 0) return;
    if (delivered >= DISPATCH_CHUNK) {
      drainImmediate = setImmediate(function () {
        drainImmediate = null;
        _drainPending();
      });
      if (typeof drainImmediate.unref === "function") drainImmediate.unref();
      return;
    }
    _scheduleDrain();
  }

  var pollTimer    = null;
  var keepAlive    = null;
  var pollSnapshot = null;
  var pollChain    = Promise.resolve();
  var readyResolve = null;
  var readyReject  = null;
  var ready = new Promise(function (resolve, reject) {
    readyResolve = resolve;
    readyReject  = reject;
  });
  ready.catch(function () { /* the rejection also reaches onError; a caller that awaits ready sees it */ });

  async function _statPollEntry(absPath) {
    try { return await nodeFs.promises.stat(absPath); }
    catch (_e) { return null; }
  }

  async function _readPollBatch(relDir, absDir, batch, snapshot, stack) {
    var stats = await Promise.all(batch.map(function (entry) {
      return _statPollEntry(nodePath.join(absDir, entry.name));
    }));
    for (var i = 0; i < batch.length; i += 1) {
      var entry = batch[i];
      var st = stats[i];
      if (st === null) continue;
      var relPath = relDir === "" ? entry.name : (relDir + "/" + entry.name);
      relPath = relPath.split(nodePath.sep).join("/");
      if (entry.isDirectory()) {
        snapshot.set(relPath, { type: "dir", size: 0, mtimeMs: st.mtimeMs });
        stack.push(relPath);
      } else if (entry.isFile()) {
        snapshot.set(relPath, { type: "file", size: st.size, mtimeMs: st.mtimeMs });
      }
    }
  }

  async function _walkPollTree() {
    var snapshot = new Map();
    var fileCount = 0;
    var stack = [""];
    while (stack.length > 0) {
      if (stopped) return null;
      var relDir = stack.pop();
      var absDir = relDir === "" ? root : nodePath.join(root, relDir);
      var dir;
      try { dir = await nodeFs.promises.opendir(absDir, { bufferSize: POLL_DIR_BATCH }); }
      catch (rootErr) {
        if (relDir === "") {
          var lost = new WatcherError("watcher/root-lost",
            "watcher.poll: root '" + root + "' is no longer readable: " +
            ((rootErr && rootErr.message) || String(rootErr)));
          lost.fatal = true;
          lost.cause = rootErr;
          throw lost;
        }
        continue;
      }
      try {
        var batch = [];
        var entry;
        while ((entry = await dir.read()) !== null) {
          if (stopped) return null;
          var relPath = relDir === "" ? entry.name : (relDir + "/" + entry.name);
          relPath = relPath.split(nodePath.sep).join("/");
          if (isIgnored(relPath)) continue;
          if (entry.isSymbolicLink()) continue;
          fileCount += 1;
          if (fileCount > pollMaxFiles) {
            throw new WatcherError("watcher/poll-overflow",
              "watcher.poll: tree exceeds pollMaxFiles=" + pollMaxFiles +
              "; narrow `ignore` patterns, raise pollMaxFiles, or switch to mode: \"fs\"");
          }
          batch.push(entry);
          if (batch.length >= POLL_DIR_BATCH) {
            await _readPollBatch(relDir, absDir, batch, snapshot, stack);
            batch = [];
          }
        }
        if (batch.length > 0) await _readPollBatch(relDir, absDir, batch, snapshot, stack);
      } catch (readErr) {
        if (readErr instanceof WatcherError) throw readErr;
        if (relDir === "") {
          var lostRead = new WatcherError("watcher/root-lost",
            "watcher.poll: root '" + root + "' is no longer readable: " +
            ((readErr && readErr.message) || String(readErr)));
          lostRead.fatal = true;
          lostRead.cause = readErr;
          throw lostRead;
        }
      } finally {
        try { await dir.close(); } catch (_e) { /* already closed by the iterator */ }
      }
    }
    return snapshot;
  }

  function _runPollWalk() {
    var run = pollChain.then(async function () {
      if (stopped) return;
      var next;
      try { next = await _walkPollTree(); }
      catch (e) { _safeError(e); return; }
      try { await _applyPollSnapshot(next); }
      catch (e) { _safeError(e); }
    });
    pollChain = run;
    return run;
  }

  async function _applyPollSnapshot(next) {
    if (next === null) return;
    if (pollSnapshot === null) {
      pollSnapshot = next;
      return;
    }
    var finished = await _comparePollSnapshots(pollSnapshot, next, _enqueue, function () { return stopped; });
    if (finished) pollSnapshot = next;
  }

  function _armPollTimer() {
    if (stopped) return;
    pollTimer = setTimeout(function () {
      _runPollWalk().then(_armPollTimer);
    }, pollIntervalMs);
    if (typeof pollTimer.unref === "function") pollTimer.unref();
  }

  function _startPoll() {
    pollChain = _walkPollTree().then(function (first) {
      if (first !== null && !stopped) {
        pollSnapshot = first;
        _armPollTimer();
      }
      readyResolve();
    }, function (e) {
      if (stopped) { readyResolve(); return; }
      var failed = new WatcherError("watcher/start-failed",
        "watcher.create: initial poll walk failed: " + ((e && e.message) || String(e)));
      failed.cause = e;
      readyReject(failed);
      _safeError(failed);
      stop();
    });
  }

  function _rootReadable() {
    try { nodeFs.opendirSync(root).closeSync(); return true; }
    catch (_e) { return false; }
  }

  if (mode === "poll") {
    _startPoll();
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
      watcherHandle.on("error", function (err) { _handleBackendError(err); });
    } catch (e) {
      if (e && (e.code === "ERR_FEATURE_UNAVAILABLE_ON_PLATFORM" || e.code === "ENOSYS")) {
        throw new WatcherError("watcher/recursive-unsupported",
          "watcher.create: recursive watch not supported on this platform/kernel: " +
          ((e && e.message) || String(e)) + " — pass mode: \"poll\" to fall back to interval polling");
      }
      if (!(e && (e.code === "EACCES" || e.code === "EPERM") && _rootReadable())) {
        throw new WatcherError("watcher/start-failed",
          "watcher.create: fs.watch failed: " + ((e && e.message) || String(e)));
      }
      watcherHandle = null;
      mode = "poll";
      _startPoll();
      var notice = new WatcherError("watcher/recursive-unreadable",
        "watcher.create: fs.watch refused to watch '" + root + "' recursively because a directory under it " +
        "is not readable (" + e.code + ": " + (e.message || String(e)) + "); the watcher polls the tree " +
        "every " + pollIntervalMs + " ms instead and skips directories it cannot read");
      notice.cause = e;
      _safeError(notice);
    }
  }
  if (mode !== "poll") readyResolve();

  keepAlive = setInterval(function () {}, C.TIME.hours(1));                                        // allow:timer-no-unref-process-pinning — pins the loop on purpose; close() clears it

  if (autoDecision) {
    _safeEmitAudit("watcher.mode_auto_decision", {
      root:        root,
      chosen:      autoDecision.mode,
      reason:      autoDecision.reason,
      fsType:      autoDecision.fsType,
      inContainer: autoDecision.inContainer,
    });
  }
  _safeEmitAudit("watcher.started", { root: root, mode: mode, requestedMode: requestedMode });

  function stop() {
    if (stopped) return;
    stopped = true;
    readyResolve();
    _cancelDrain();
    pending.clear();
    if (watcherHandle) {
      try { watcherHandle.close(); } catch (_e) { /* best-effort */ }
      watcherHandle = null;
    }
    if (pollTimer) {
      try { clearTimeout(pollTimer); } catch (_e) { /* best-effort */ }
      pollTimer = null;
    }
    if (keepAlive) {
      try { clearInterval(keepAlive); } catch (_e) { /* best-effort */ }
      keepAlive = null;
    }
    _safeEmitAudit("watcher.stopped", { root: root, mode: mode, eventCount: eventCount });
  }

  function _cancelDrain() {
    if (drainTimer !== null) { clearTimeout(drainTimer); drainTimer = null; }
    if (drainImmediate !== null) { clearImmediate(drainImmediate); drainImmediate = null; }
  }

  function _dispatchPendingNow() {
    var paths = Array.from(pending.keys());
    pending.clear();
    _cancelDrain();
    for (var i = 0; i < paths.length; i += 1) {
      _normalizeAndDispatch(paths[i]);
    }
  }

  function _flushForTest() {
    if (mode !== "poll" || stopped) {
      _dispatchPendingNow();
      return Promise.resolve();
    }
    return _runPollWalk().then(_dispatchPendingNow);
  }

  return {
    stop:           stop,
    root:           root,
    mode:           mode,
    ready:          ready,
    _flushForTest:  _flushForTest,
    _simulateBackendErrorForTest: _handleBackendError,
  };
}

module.exports = {
  create:        create,
  WatcherError:  WatcherError,
  MAX_IGNORE_PATTERN_LEN: MAX_IGNORE_PATTERN_LEN,
  MAX_IGNORE_STAR_COUNT:  MAX_IGNORE_STAR_COUNT,
  _detectAutoModeForTest: _detectAutoMode,
  _comparePollSnapshotsForTest: _comparePollSnapshots,
};
