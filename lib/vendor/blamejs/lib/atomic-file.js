"use strict";
/**
 * Atomic file I/O with integrity verification, retry on transient errors,
 * and cross-process locking.
 *
 * The framework already does atomic writes for vault.key.sealed (lib/vault.js)
 * and audit.tip (lib/db.js). This module exposes the same primitives for
 * any caller that needs:
 *
 *   - Crash-safe writes via temp + fsync + atomic rename + dir fsync
 *   - Optional integrity hash (SHA3-512) computed on write, verified on read
 *   - Retry on EBUSY / EAGAIN / ENFILE with exponential backoff
 *   - Cross-process locking for read-modify-write sequences
 *   - JSON convenience wrappers using b.json's security defaults
 *
 * The framework's "fail closed" stance applies: a partially-written file
 * NEVER survives a crash to the caller — either the new contents are
 * fully on disk (atomic rename succeeded) or the original (or absence)
 * remains. fsync calls are best-effort across platforms (Windows rejects
 * directory fsync, etc.); the rename remains atomic at the FS level
 * regardless.
 *
 * Public API:
 *   atomicFile.write(filepath, data, opts?)        → { bytesWritten, hash? }
 *   atomicFile.read(filepath, opts?)               → Buffer (or string if encoding)
 *   atomicFile.readSync(filepath, opts?)           → same, sync (for boot paths)
 *   atomicFile.writeJson(filepath, value, opts?)   → { bytesWritten, hash? }
 *   atomicFile.readJson(filepath, opts?)           → parsed value
 *   atomicFile.copy(src, dst, opts?)               → { bytesWritten, hash? }
 *   atomicFile.exists(filepath)                    → boolean
 *   atomicFile.lock(filepath, fn, opts?)           → fn's return value
 *   atomicFile.AtomicFileError                     → error class
 */
var fs = require("fs");
var path = require("path");
var { generateToken, sha3Hash } = require("./crypto");
var safeJson = require("./safe-json");
var C = require("./constants");
var { boot } = require("./log");
var safeBuffer = require("./safe-buffer");
var numericBounds = require("./numeric-bounds");
var safeAsync = require("./safe-async");
var retry = require("./retry");
var { FrameworkError } = require("./framework-error");

var log = boot("atomic-file");

var DEFAULTS = {
  maxBytes:        C.BYTES.mib(64),     // 64 MiB ceiling on read
  retryAttempts:   5,
  retryBaseMs:     50,
  retryMaxMs:      C.TIME.seconds(2),
  fileMode:        0o600,
  computeHash:     false,
  lockTimeoutMs:   C.TIME.seconds(30),
  lockPollMs:      50,
};

class AtomicFileError extends FrameworkError {
  constructor(message, code) {
    super(message);
    this.name = "AtomicFileError";
    this.code = code || "atomic-file/error";
    this.isAtomicFileError = true;
  }
}

// ---- Retry helper for transient FS errors ----
//
// Routes through b.retry.withRetry with an FS-specific classifier — the
// errnos that mean "try again" on Linux/macOS/Windows file systems differ
// from the HTTP/network-shaped default classifier. atomic-file's public
// opts (retryAttempts/retryBaseMs/retryMaxMs) are mapped to the retry
// primitive's standard names; jitterFactor 0.5 reproduces the original
// `delay * (0.5 + Math.random()/2)` range of [delay/2, delay].

var TRANSIENT_FS_ERRNOS = new Set(["EBUSY", "EAGAIN", "ENFILE", "EMFILE", "EPERM"]);

function _isFsRetryable(e) {
  return e != null && TRANSIENT_FS_ERRNOS.has(e.code);
}

async function _withRetry(fn, opts) {
  opts = Object.assign({}, DEFAULTS, opts || {});
  return retry.withRetry(function () { return fn(); }, {
    maxAttempts:  opts.retryAttempts,
    baseDelayMs:  opts.retryBaseMs,
    maxDelayMs:   opts.retryMaxMs,
    jitterFactor: 0.5,
    isRetryable:  _isFsRetryable,
    signal:       opts.signal,
  });
}

// ---- Sync helpers (best effort) ----
//
// fsync / fsyncDir / ensureDir / copyDirRecursive / pathTimestamp are
// public surface — they were previously underscore-prefixed, and other
// modules (vault-passphrase-ops, vault-rotate, backup-bundle, restore-
// bundle, restore-rollback, bundler) duplicated them inline. Hoisted
// here so the framework has one shared implementation per concern.

function fsync(fd) {
  try { fs.fsyncSync(fd); } catch (_e) { /* not all platforms support fsync on every fd type */ }
}

function fsyncDir(dirPath) {
  try {
    var fd = fs.openSync(dirPath, "r");
    try { fs.fsyncSync(fd); } catch (_e) { /* Windows rejects directory fsync */ }
    finally { fs.closeSync(fd); }
  } catch (_e) { /* dir fsync is best-effort across filesystems */ }
}

// Internal aliases so existing code in this file keeps working
function _fsync(fd) { return fsync(fd); }
function _fsyncDir(dirPath) { return fsyncDir(dirPath); }

// ensureDir — mkdirSync with recursive: true and a default mode of
// 0o700 (owner-only) suitable for framework data directories. Caller
// passes a different mode for less-restricted dirs.
function ensureDir(dirPath, mode) {
  if (typeof dirPath !== "string" || dirPath.length === 0) {
    throw new AtomicFileError("ensureDir: path must be a non-empty string", "atomic-file/bad-path");
  }
  fs.mkdirSync(dirPath, { recursive: true, mode: typeof mode === "number" ? mode : 0o700 });
  return dirPath;
}

// copyDirRecursive — synchronous, file-by-file copy that mirrors the
// source's directory structure. Skips symlinks (operator wanting symlink
// preservation should use a real archive tool). Refuses to overwrite
// existing files at dest by default — pass opts.overwrite=true to
// replace. dest is created with mode 0o700 by default.
function copyDirRecursive(src, dest, opts) {
  if (typeof src !== "string" || src.length === 0) {
    throw new AtomicFileError("copyDirRecursive: src must be a non-empty string", "atomic-file/bad-path");
  }
  if (typeof dest !== "string" || dest.length === 0) {
    throw new AtomicFileError("copyDirRecursive: dest must be a non-empty string", "atomic-file/bad-path");
  }
  if (!fs.existsSync(src)) {
    throw new AtomicFileError("copyDirRecursive: src does not exist: " + src, "atomic-file/missing-src");
  }
  opts = opts || {};
  var dirMode = typeof opts.dirMode === "number" ? opts.dirMode : 0o700;
  var overwrite = !!opts.overwrite;
  var copyFlags = overwrite ? 0 : fs.constants.COPYFILE_EXCL;

  ensureDir(dest, dirMode);
  var entries = fs.readdirSync(src, { withFileTypes: true });
  var fileCount = 0;
  var byteCount = 0;
  for (var i = 0; i < entries.length; i++) {
    var name = entries[i].name;
    var s = path.join(src, name);
    var d = path.join(dest, name);
    if (entries[i].isDirectory()) {
      var sub = copyDirRecursive(s, d, opts);
      fileCount += sub.fileCount;
      byteCount += sub.byteCount;
    } else if (entries[i].isFile()) {
      fs.copyFileSync(s, d, copyFlags);
      try { byteCount += fs.statSync(d).size; } catch (_e) { /* size best-effort */ }
      fileCount++;
    }
    // Symlinks, sockets, devices: deliberately skipped
  }
  return { fileCount: fileCount, byteCount: byteCount };
}

// pathTimestamp — filesystem-safe ISO-8601 timestamp suitable for use as
// a directory or file name on every platform. Standard
// Date.toISOString() embeds ':' and '.' which Windows reserves for
// drive letters and extension separators. This helper substitutes both
// with '-' so the result works as a path segment unmodified. String
// sort still gives chronological order.
//
//   atomicFile.pathTimestamp()
//     → "2026-04-27T14-00-00-123Z"
//   atomicFile.pathTimestamp(new Date(0))
//     → "1970-01-01T00-00-00-000Z"
function pathTimestamp(date) {
  var d = (date instanceof Date) ? date : new Date();
  return d.toISOString().replace(/[:.]/g, "-");
}

// ---- writeSync ----
// Synchronous atomic write — same temp+fsync+rename+dirfsync flow as
// async write(), but without the retry loop (which requires awaits).
// Use this from sync code paths (process exit handlers, module-load-time
// bootstraps). For everything else, prefer the async write().
//
// Transactional guarantee: either the rename completes (new contents fully
// visible) or the tmp file is removed (no state change). The caller never
// sees a half-written file at `filepath` and never leaves a tmp orphan
// from the current call's failure path.
function writeSync(filepath, data, opts) {
  opts = Object.assign({}, DEFAULTS, opts || {});
  var buf = safeBuffer.toBuffer(data, {
    errorClass: AtomicFileError,
    typeCode:   "atomic-file/invalid-data",
    typeMessage: "data must be Buffer, Uint8Array, or string",
  });

  var dir = path.dirname(filepath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  var tmpPath = filepath + ".tmp-" + generateToken(C.BYTES.bytes(8));
  var renamed = false;
  try {
    var fd = fs.openSync(tmpPath, "w", opts.fileMode);
    try {
      var pos = 0;
      while (pos < buf.length) {
        pos += fs.writeSync(fd, buf, pos, buf.length - pos, null);
      }
      _fsync(fd);
    } finally {
      try { fs.closeSync(fd); } catch (_e) { /* already closed? */ }
    }
    fs.renameSync(tmpPath, filepath);
    renamed = true;
    _fsyncDir(dir);
  } finally {
    if (!renamed) {
      // Either the write or the rename failed — remove the tmp so the next
      // boot doesn't see a leaked partial file.
      try { fs.unlinkSync(tmpPath); } catch (_e) { /* may not exist */ }
    }
  }

  return {
    bytesWritten: buf.length,
    hash:         opts.computeHash ? sha3Hash(buf) : null,
  };
}

// Clean up orphan tmp files left behind by a previously-crashed process.
// Atomic writes use random tmp names (filepath + ".tmp-" + token), so a
// crash leaves a file with a name we can't predict on next boot — only
// glob and prune by age. Default: prune anything older than 5 minutes.
//
// Operators should call this at boot for every "important" filepath
// (vault.key.sealed, audit-sign.key.sealed, db.enc, etc.) BEFORE they
// start their first atomic write to that path.
function cleanOrphans(filepath, opts) {
  opts = opts || {};
  var olderThanMs = opts.olderThanMs != null ? opts.olderThanMs : C.TIME.minutes(5);
  var dir = path.dirname(filepath);
  var basename = path.basename(filepath);
  var prefix = basename + ".tmp-";
  var nowMs = Date.now();
  var removed = 0;
  var entries = listDir(dir, {
    filter:      function (name) { return name.startsWith(prefix); },
    includeStat: true,
  });
  for (var i = 0; i < entries.length; i++) {
    var entry = entries[i];
    try {
      if (nowMs - entry.mtimeMs >= olderThanMs) {
        fs.unlinkSync(entry.fullPath);
        removed += 1;
      }
    } catch (_e) { /* concurrent cleanup or permission — best effort */ }
  }
  return removed;
}

// ---- write ----

async function write(filepath, data, opts) {
  opts = Object.assign({}, DEFAULTS, opts || {});
  var buf = safeBuffer.toBuffer(data, {
    errorClass: AtomicFileError,
    typeCode:   "atomic-file/invalid-data",
    typeMessage: "data must be Buffer, Uint8Array, or string",
  });

  return await _withRetry(function () {
    return new Promise(function (resolve, reject) {
      var dir = path.dirname(filepath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      var tmpPath = filepath + ".tmp-" + generateToken(C.BYTES.bytes(8));
      var renamed = false;
      try {
        var fd = fs.openSync(tmpPath, "w", opts.fileMode);
        try {
          var pos = 0;
          while (pos < buf.length) {
            pos += fs.writeSync(fd, buf, pos, buf.length - pos, null);
          }
          _fsync(fd);
        } finally {
          try { fs.closeSync(fd); } catch (_e) { /* already closed? */ }
        }
        // Atomic rename — POSIX rename is atomic on the same FS; on Windows,
        // fs.renameSync uses MoveFileEx with REPLACE_EXISTING.
        fs.renameSync(tmpPath, filepath);
        renamed = true;
        _fsyncDir(dir);
        var hash = opts.computeHash ? sha3Hash(buf) : null;
        resolve({ bytesWritten: buf.length, hash: hash });
      } catch (e) {
        reject(e);
      } finally {
        if (!renamed) {
          try { fs.unlinkSync(tmpPath); } catch (_e) { /* may not exist */ }
        }
      }
    });
  }, opts);
}

// ---- read ----

async function read(filepath, opts) {
  opts = Object.assign({}, DEFAULTS, opts || {});
  return await _withRetry(function () {
    return new Promise(function (resolve, reject) {
      try { resolve(_readSyncCore(filepath, opts)); }
      catch (e) { reject(e); }
    });
  }, opts);
}

// Sync variant for callers in module-init / boot paths that can't
// `await` (vault.initPlaintext, audit-sign._initPlaintext,
// db._checkRollback, db.loadOrCreateDbKey). Same semantics as
// async read: size cap, optional integrity-hash verification, ENOENT
// translation. No retry loop — sync paths can't usefully back off.
function readSync(filepath, opts) {
  opts = Object.assign({}, DEFAULTS, opts || {});
  return _readSyncCore(filepath, opts);
}

// maxBytes via shared lib/numeric-bounds — Infinity / NaN bypass the
// stat.size cap (any-comparison-with-Infinity-or-NaN is false).
function _validateMaxBytes(maxBytes) {
  if (!numericBounds.isPositiveFiniteInt(maxBytes)) {
    throw new AtomicFileError(
      "atomicFile.read: maxBytes must be a positive finite integer; got " +
        numericBounds.shape(maxBytes),
      "atomic-file/bad-opt");
  }
}

function _readSyncCore(filepath, opts) {
  if (!fs.existsSync(filepath)) {
    var e = new AtomicFileError("file not found: " + filepath, "atomic-file/not-found");
    e.code = "ENOENT";
    throw e;
  }
  _validateMaxBytes(opts.maxBytes);
  var stat = fs.statSync(filepath);
  if (stat.size > opts.maxBytes) {
    throw new AtomicFileError(
      "file size " + stat.size + " > maxBytes " + opts.maxBytes,
      "atomic-file/too-large"
    );
  }
  var buf = fs.readFileSync(filepath);
  if (opts.expectedHash) {
    var actual = sha3Hash(buf);
    if (actual !== opts.expectedHash) {
      throw new AtomicFileError(
        "integrity check failed: expected " + opts.expectedHash + " got " + actual,
        "atomic-file/integrity"
      );
    }
  }
  return opts.encoding ? buf.toString(opts.encoding) : buf;
}

// ---- writeJson / readJson ----

async function writeJson(filepath, value, opts) {
  opts = opts || {};
  var serialized = opts.canonical
    ? safeJson.canonical(value)
    : safeJson.stringify(value, { indent: opts.indent || 0 });
  return await write(filepath, serialized, opts);
}

async function readJson(filepath, opts) {
  opts = opts || {};
  var buf = await read(filepath, opts);
  var input = Buffer.isBuffer(buf) ? buf : Buffer.from(buf, "utf8");
  return safeJson.parse(input, opts);
}

// ---- copy ----

async function copy(src, dst, opts) {
  opts = Object.assign({}, DEFAULTS, opts || {});
  var srcOpts = Object.assign({}, opts);
  delete srcOpts.expectedHash;     // hash check applies to dst, not src
  var buf = await read(src, srcOpts);
  if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf, "utf8");
  return await write(dst, buf, opts);
}

// ---- exists ----

function exists(filepath) {
  return fs.existsSync(filepath);
}

// ---- lock (cross-process file mutex) ----

async function lock(filepath, fn, opts) {
  opts = Object.assign({}, DEFAULTS, opts || {});
  var lockPath = filepath + ".lock";
  var deadline = Date.now() + opts.lockTimeoutMs;
  var fd = null;

  while (Date.now() < deadline) {
    try {
      // O_CREAT | O_EXCL — fails if file exists
      fd = fs.openSync(lockPath, "wx", opts.fileMode);
      break;
    } catch (e) {
      if (e.code !== "EEXIST") throw e;
      // Stale lock detection: if the .lock file is older than 5 minutes,
      // assume the holding process crashed and remove it.
      try {
        var stat = fs.statSync(lockPath);
        if (Date.now() - stat.mtimeMs > C.TIME.minutes(5)) {
          try { fs.unlinkSync(lockPath); }
          catch (uerr) { log.debug("stale-lock unlink failed", { path: lockPath, error: uerr.message }); }
          continue;
        }
      } catch (_e) { /* stat raced with another process — keep waiting */ }
      await safeAsync.sleep(opts.lockPollMs, { signal: opts.signal });
    }
  }
  if (fd === null) {
    throw new AtomicFileError(
      "lock timeout after " + opts.lockTimeoutMs + "ms on " + filepath,
      "atomic-file/lock-timeout"
    );
  }
  try {
    fs.writeSync(fd, Buffer.from(JSON.stringify({
      pid:        process.pid,
      acquiredAt: Date.now(),
    }), "utf8"));
    _fsync(fd);
  } catch (_e) { /* lock content best-effort */ }

  try {
    return await fn();
  } finally {
    try { fs.closeSync(fd); }
    catch (cerr) { log.debug("lock fd close failed", { error: cerr.message }); }
    try { fs.unlinkSync(lockPath); }
    catch (uerr) { log.debug("lock release unlink failed", { path: lockPath, error: uerr.message }); }
  }
}

// Single-directory listing primitive. Wraps fs.readdirSync with the
// optional-stat pattern + missing-dir tolerance + filter that callers
// across the framework were re-implementing.
//
//   opts:
//     filter:      function(name) => boolean   — name-only predicate
//     includeStat: bool — adds mtimeMs / sizeBytes / isDirectory /
//                  isFile per entry (one fs.statSync call each).
//                  Skip when the caller only needs names — saves a
//                  syscall per entry.
//     missingOk:   bool — default true. Returns [] when the dir
//                  doesn't exist (ENOENT). Other errors throw.
//
//   Returns: array of { name, fullPath } (plus stat fields when
//   includeStat is true). Entries that vanish between readdir and
//   stat (concurrent cleanup) are silently dropped.
//
// For recursive directory walks, callers compose listDir per
// subdirectory — the primitive doesn't recurse, so callers can apply
// per-iteration limits / filters / stop conditions cleanly.
function listDir(dir, opts) {
  opts = opts || {};
  var missingOk   = opts.missingOk !== false;
  var includeStat = opts.includeStat === true;
  var filter      = typeof opts.filter === "function" ? opts.filter : null;

  var entries;
  try {
    entries = fs.readdirSync(dir);
  } catch (e) {
    if (missingOk && e.code === "ENOENT") return [];
    throw new AtomicFileError(
      "failed to list directory " + dir + ": " + e.message,
      "atomic-file/list-failed"
    );
  }

  var out = [];
  for (var i = 0; i < entries.length; i++) {
    var name = entries[i];
    if (filter && !filter(name)) continue;
    var fullPath = path.join(dir, name);
    var entry = { name: name, fullPath: fullPath };
    if (includeStat) {
      try {
        var stat = fs.statSync(fullPath);
        entry.mtimeMs    = stat.mtimeMs;
        entry.sizeBytes  = stat.size;
        entry.isDirectory = stat.isDirectory();
        entry.isFile     = stat.isFile();
      } catch (_e) {
        // Entry vanished between readdir and stat — concurrent cleanup
        // by another process. Skip silently; caller asked for stat
        // info that no longer exists.
        continue;
      }
    }
    out.push(entry);
  }
  return out;
}

module.exports = {
  write:             write,
  writeSync:         writeSync,
  read:              read,
  readSync:          readSync,
  writeJson:         writeJson,
  readJson:          readJson,
  copy:              copy,
  exists:            exists,
  lock:              lock,
  listDir:           listDir,
  cleanOrphans:      cleanOrphans,
  // Filesystem hygiene helpers (lifted from inline duplicates across lib/)
  fsync:             fsync,
  fsyncDir:          fsyncDir,
  ensureDir:         ensureDir,
  copyDirRecursive:  copyDirRecursive,
  pathTimestamp:     pathTimestamp,
  AtomicFileError:   AtomicFileError,
  DEFAULTS:          DEFAULTS,
};
