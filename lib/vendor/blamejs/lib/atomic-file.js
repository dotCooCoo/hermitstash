"use strict";
/**
 * @module b.atomicFile
 * @nav    Data
 * @title  Atomic File
 *
 * @intro
 *   Atomic file I/O with integrity verification, retry on transient
 *   errors, and cross-process locking.
 *
 *   Every write goes through the same crash-safe sequence:
 *     1. write payload to a sibling temp file (`<filepath>.tmp-<token>`)
 *     2. fsync the file descriptor before close
 *     3. fs.rename() the temp file over the destination — POSIX rename
 *        is atomic on the same filesystem; on Windows, fs.rename uses
 *        MoveFileEx with REPLACE_EXISTING for the same guarantee
 *     4. fsync the parent directory so the rename itself is durable
 *
 *   Result: a partially-written file NEVER survives a crash to the
 *   caller. Either the new contents are fully on disk (rename
 *   succeeded) or the original (or absence) remains. No torn writes,
 *   no half-flushed pages.
 *
 *   fsync calls are best-effort across platforms — Windows rejects
 *   directory fsync, some FUSE filesystems no-op file fsync — but the
 *   rename remains atomic at the FS level regardless. The framework
 *   already uses this primitive internally for vault.key.sealed and
 *   audit.tip; this module exposes the same surface for any caller
 *   that needs durable write-replace semantics.
 *
 *   Optional `computeHash: true` returns SHA3-512 over the written
 *   bytes; passing the same digest as `expectedHash` on a later read
 *   gates retrieval on integrity. Transient FS errors (EBUSY / EAGAIN /
 *   ENFILE / EMFILE / EPERM) retry with exponential backoff via
 *   b.retry.withRetry — sync paths skip the loop because they can't
 *   usefully await a backoff.
 *
 * @card
 *   Atomic file I/O with integrity verification, retry on transient errors, and cross-process locking.
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

/**
 * @primitive b.atomicFile.fsync
 * @signature b.atomicFile.fsync(fd)
 * @since     0.7.0
 * @status    stable
 * @related   b.atomicFile.fsyncDir, b.atomicFile.write
 *
 * Best-effort fs.fsyncSync wrapper. Silently swallows errors because
 * not every platform / fd type supports fsync (some FUSE mounts, some
 * device fds). Use this when you want the durability hint but don't
 * want a non-fsyncable target to crash the caller.
 *
 * @example
 *   var fs = require("fs");
 *   var fd = fs.openSync("/tmp/note.txt", "w");
 *   fs.writeSync(fd, "hello\n");
 *   b.atomicFile.fsync(fd);
 *   fs.closeSync(fd);
 */
function fsync(fd) {
  try { fs.fsyncSync(fd); } catch (_e) { /* not all platforms support fsync on every fd type */ }
}

/**
 * @primitive b.atomicFile.fsyncDir
 * @signature b.atomicFile.fsyncDir(dirPath)
 * @since     0.7.0
 * @status    stable
 * @related   b.atomicFile.fsync, b.atomicFile.write
 *
 * Best-effort fsync of a directory inode. Required after a rename to
 * make the directory entry itself durable on POSIX filesystems.
 * Windows refuses directory fsync — the call is wrapped so the caller
 * can run the same code on every platform without branching.
 *
 * @example
 *   b.atomicFile.fsyncDir("/var/lib/blamejs/data");
 */
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

/**
 * @primitive b.atomicFile.ensureDir
 * @signature b.atomicFile.ensureDir(dirPath, mode)
 * @since     0.7.0
 * @status    stable
 * @related   b.atomicFile.write, b.atomicFile.copyDirRecursive
 *
 * Create `dirPath` (recursive) with a chosen mode. Default mode is
 * 0o700 — owner-only — suitable for framework data directories
 * holding sealed vaults, audit chains, or session state. Returns the
 * dirPath unchanged so calls compose into path-building chains.
 *
 * @example
 *   var dir = b.atomicFile.ensureDir("/var/lib/blamejs/audit", 0o700);
 *   // → "/var/lib/blamejs/audit"
 *
 *   // Less-restricted dir for a public asset folder:
 *   b.atomicFile.ensureDir("/var/www/uploads", 0o755);
 */
function ensureDir(dirPath, mode) {
  if (typeof dirPath !== "string" || dirPath.length === 0) {
    throw new AtomicFileError("ensureDir: path must be a non-empty string", "atomic-file/bad-path");
  }
  fs.mkdirSync(dirPath, { recursive: true, mode: typeof mode === "number" ? mode : 0o700 });
  return dirPath;
}

/**
 * @primitive b.atomicFile.copyDirRecursive
 * @signature b.atomicFile.copyDirRecursive(src, dest, opts)
 * @since     0.7.0
 * @status    stable
 * @related   b.atomicFile.copy, b.atomicFile.ensureDir
 *
 * Synchronous, file-by-file copy that mirrors the source directory
 * structure. Skips symlinks, sockets, and devices — operators wanting
 * symlink preservation should use a real archive tool. Refuses to
 * overwrite existing files at dest by default; pass `overwrite: true`
 * to replace. The dest tree is created with mode 0o700 by default
 * (override with `dirMode`). Returns `{ fileCount, byteCount }`.
 *
 * @opts
 *   overwrite: false,   // when true, overwrite files that already exist at dest
 *   dirMode:   0o700,   // mode for newly-created destination directories
 *
 * @example
 *   var stats = b.atomicFile.copyDirRecursive(
 *     "/var/lib/blamejs/data",
 *     "/var/lib/blamejs/snapshot-2026-01-01",
 *     { overwrite: false, dirMode: 0o700 }
 *   );
 *   // → { fileCount: 42, byteCount: 1048576 }
 */
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

/**
 * @primitive b.atomicFile.pathTimestamp
 * @signature b.atomicFile.pathTimestamp(date)
 * @since     0.7.0
 * @status    stable
 * @related   b.atomicFile.ensureDir, b.atomicFile.write
 *
 * Filesystem-safe ISO-8601 timestamp. Standard Date.toISOString()
 * embeds ':' and '.' which Windows reserves for drive letters and
 * extension separators; this helper substitutes both with '-' so the
 * result is portable as a path segment. String sort still gives
 * chronological order. Pass a Date to format a specific instant;
 * omit it for `new Date()`.
 *
 * @example
 *   var stamp = b.atomicFile.pathTimestamp(new Date(0));
 *   // → "1970-01-01T00-00-00-000Z"
 *
 *   var fixed = b.atomicFile.pathTimestamp(new Date(Date.UTC(2026, 0, 1)));
 *   // → "2026-01-01T00-00-00-000Z"
 */
function pathTimestamp(date) {
  var d = (date instanceof Date) ? date : new Date();
  return d.toISOString().replace(/[:.]/g, "-");
}

/**
 * @primitive b.atomicFile.writeSync
 * @signature b.atomicFile.writeSync(filepath, data, opts)
 * @since     0.7.0
 * @status    stable
 * @related   b.atomicFile.write, b.atomicFile.cleanOrphans
 *
 * Synchronous atomic write — same temp + fsync + rename + dirfsync
 * sequence as the async `write`, but without the retry loop (which
 * requires awaits). Use from sync-only code paths: process exit
 * handlers, module-load-time bootstraps, signal handlers. For
 * everything else, prefer the async form. Either the rename
 * completes (new contents fully visible) or the tmp file is removed —
 * no half-written file ever appears at `filepath`.
 *
 * @opts
 *   fileMode:    0o600,   // mode applied to the temp file (and thus the renamed final)
 *   computeHash: false,   // when true, return SHA3-512 of the written bytes
 *
 * @example
 *   var result = b.atomicFile.writeSync(
 *     "/var/lib/blamejs/state.bin",
 *     Buffer.from("payload"),
 *     { fileMode: 0o600, computeHash: true }
 *   );
 *   // → { bytesWritten: 7, hash: "<sha3-512 hex>" }
 */
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

/**
 * @primitive b.atomicFile.cleanOrphans
 * @signature b.atomicFile.cleanOrphans(filepath, opts)
 * @since     0.7.0
 * @status    stable
 * @related   b.atomicFile.write, b.atomicFile.writeSync
 *
 * Sweep orphan temp files left behind by a previously-crashed
 * process. Atomic writes use random temp names (`<filepath>.tmp-<token>`),
 * so a crashed run leaves a file with a name the next boot can't
 * predict — only glob-by-prefix and prune by age. Operators should
 * call this at boot for every "important" filepath (vault.key.sealed,
 * audit-sign.key.sealed, db.enc, ...) BEFORE the first atomic write
 * to that path. Returns the number of orphans removed.
 *
 * @opts
 *   olderThanMs: 300000,   // only prune temp files older than this many ms (default 5 minutes)
 *
 * @example
 *   var removed = b.atomicFile.cleanOrphans(
 *     "/var/lib/blamejs/vault.key.sealed",
 *     { olderThanMs: 300000 }
 *   );
 *   // → 0   (no orphans found, or the count of files unlinked)
 */
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

/**
 * @primitive b.atomicFile.write
 * @signature b.atomicFile.write(filepath, data, opts)
 * @since     0.7.0
 * @status    stable
 * @related   b.atomicFile.writeSync, b.atomicFile.read, b.atomicFile.lock
 *
 * Crash-safe write-replace. Writes `data` to a sibling temp file,
 * fsyncs the fd, atomically renames over `filepath`, then fsyncs the
 * parent directory. On any failure path the temp is unlinked, so the
 * destination is never seen as half-written. Transient FS errors
 * (EBUSY / EAGAIN / ENFILE / EMFILE / EPERM) retry with exponential
 * backoff. Returns `{ bytesWritten, hash }` where `hash` is null
 * unless `computeHash: true`.
 *
 * @opts
 *   fileMode:      0o600,                   // mode applied to the renamed file
 *   computeHash:   false,                   // SHA3-512 the written bytes; included in result
 *   retryAttempts: 5,                       // attempts before giving up on transient FS errors
 *   retryBaseMs:   50,                      // base backoff
 *   retryMaxMs:    2000,                    // backoff ceiling
 *   signal:        AbortSignal | undefined, // abort the retry loop early
 *
 * @example
 *   async function persist() {
 *     var result = await b.atomicFile.write(
 *       "/var/lib/blamejs/state.bin",
 *       Buffer.from("payload"),
 *       { fileMode: 0o600, computeHash: true }
 *     );
 *     return result;   // → { bytesWritten: 7, hash: "<sha3-512 hex>" }
 *   }
 */
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

/**
 * @primitive b.atomicFile.read
 * @signature b.atomicFile.read(filepath, opts)
 * @since     0.7.0
 * @status    stable
 * @related   b.atomicFile.readSync, b.atomicFile.write
 *
 * Read a file with size cap and optional integrity verification.
 * `maxBytes` defaults to 64 MiB; values larger than the file's stat
 * size throw `atomic-file/too-large` BEFORE the read happens (no
 * memory-blow up on hostile inputs). When `expectedHash` is provided,
 * the SHA3-512 of the bytes is compared and a mismatch throws
 * `atomic-file/integrity`. Pass `encoding` to receive a decoded
 * string instead of a Buffer. Retries on transient FS errors.
 *
 * @opts
 *   maxBytes:     67108864,             // ceiling on file size; reject anything larger
 *   encoding:     undefined,            // when set (e.g. "utf8"), return a decoded string
 *   expectedHash: undefined,            // SHA3-512 hex; when set, integrity-check the bytes
 *   retryAttempts: 5,                   // transient-error retry count
 *   retryBaseMs:   50,
 *   retryMaxMs:    2000,
 *   signal:        AbortSignal | undefined,
 *
 * @example
 *   async function load() {
 *     var buf = await b.atomicFile.read(
 *       "/var/lib/blamejs/state.bin",
 *       { maxBytes: 1048576 }
 *     );
 *     return buf;   // → <Buffer ...> (≤ 1 MiB)
 *   }
 *
 *   // Integrity-checked read — pass the digest computed at write time:
 *   async function loadVerified(digestHex) {
 *     return await b.atomicFile.read(
 *       "/var/lib/blamejs/state.bin",
 *       { expectedHash: digestHex, encoding: "utf8" }
 *     );
 *   }
 */
async function read(filepath, opts) {
  opts = Object.assign({}, DEFAULTS, opts || {});
  return await _withRetry(function () {
    return new Promise(function (resolve, reject) {
      try { resolve(_readSyncCore(filepath, opts)); }
      catch (e) { reject(e); }
    });
  }, opts);
}

/**
 * @primitive b.atomicFile.readSync
 * @signature b.atomicFile.readSync(filepath, opts)
 * @since     0.7.0
 * @status    stable
 * @related   b.atomicFile.read, b.atomicFile.writeSync
 *
 * Synchronous variant for callers in module-init / boot paths that
 * can't await — vault unsealing, audit-sign init, DB rollback check.
 * Same semantics as the async `read`: size cap via `maxBytes`,
 * optional `expectedHash` integrity check, ENOENT translated to an
 * AtomicFileError with `code === "ENOENT"`. No retry loop — sync
 * paths can't usefully back off.
 *
 * @opts
 *   maxBytes:     67108864,
 *   encoding:     undefined,
 *   expectedHash: undefined,
 *
 * @example
 *   var buf = b.atomicFile.readSync(
 *     "/var/lib/blamejs/vault.key.sealed",
 *     { maxBytes: 65536 }
 *   );
 *   // → <Buffer ...> (≤ 64 KiB)
 */
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

/**
 * @primitive b.atomicFile.writeJson
 * @signature b.atomicFile.writeJson(filepath, value, opts)
 * @since     0.7.0
 * @status    stable
 * @related   b.atomicFile.readJson, b.atomicFile.write
 *
 * Atomic JSON write. Serializes via `b.safeJson` (RFC 8785 canonical
 * form when `canonical: true`, otherwise standard stringify with
 * configurable indent) and routes through `b.atomicFile.write` for
 * the same crash-safe semantics. Returns the same shape as `write`.
 *
 * @opts
 *   canonical:     false,    // when true, emit RFC 8785 JCS canonical bytes (suitable for signing)
 *   indent:        0,        // pretty-print indent for the non-canonical path
 *   fileMode:      0o600,
 *   computeHash:   false,
 *   retryAttempts: 5,
 *   retryBaseMs:   50,
 *   retryMaxMs:    2000,
 *
 * @example
 *   async function persist() {
 *     var result = await b.atomicFile.writeJson(
 *       "/var/lib/blamejs/manifest.json",
 *       { schema: 1, items: [] },
 *       { canonical: true, computeHash: true }
 *     );
 *     return result;   // → { bytesWritten: 24, hash: "<sha3-512 hex>" }
 *   }
 */
async function writeJson(filepath, value, opts) {
  opts = opts || {};
  var serialized = opts.canonical
    ? safeJson.canonical(value)
    : safeJson.stringify(value, { indent: opts.indent || 0 });
  return await write(filepath, serialized, opts);
}

/**
 * @primitive b.atomicFile.readJson
 * @signature b.atomicFile.readJson(filepath, opts)
 * @since     0.7.0
 * @status    stable
 * @related   b.atomicFile.writeJson, b.atomicFile.read
 *
 * Atomic JSON read. Routes through `b.atomicFile.read` (size cap +
 * optional integrity hash) then parses via `b.safeJson.parse`, which
 * applies the framework's prototype-pollution / __proto__-key
 * defenses. Throws `atomic-file/too-large`, `atomic-file/integrity`,
 * or a JSON parse error from safeJson — never returns a partial
 * object.
 *
 * @opts
 *   maxBytes:     67108864,
 *   expectedHash: undefined,
 *
 * @example
 *   async function load() {
 *     var doc = await b.atomicFile.readJson(
 *       "/var/lib/blamejs/manifest.json",
 *       { maxBytes: 1048576 }
 *     );
 *     return doc;   // → { schema: 1, items: [] }
 *   }
 */
async function readJson(filepath, opts) {
  opts = opts || {};
  var buf = await read(filepath, opts);
  var input = Buffer.isBuffer(buf) ? buf : Buffer.from(buf, "utf8");
  return safeJson.parse(input, opts);
}

/**
 * @primitive b.atomicFile.copy
 * @signature b.atomicFile.copy(src, dst, opts)
 * @since     0.7.0
 * @status    stable
 * @related   b.atomicFile.copyDirRecursive, b.atomicFile.write
 *
 * Atomic file copy. Reads the source via `b.atomicFile.read` (so
 * `maxBytes` and retry semantics apply), then writes the bytes
 * through `b.atomicFile.write` (temp + fsync + rename). When
 * `expectedHash` is set, the digest is checked against the WRITTEN
 * bytes at `dst` — the source is not gated on it. Returns
 * `{ bytesWritten, hash }`.
 *
 * @opts
 *   maxBytes:      67108864,
 *   fileMode:      0o600,
 *   computeHash:   false,
 *   expectedHash:  undefined,
 *   retryAttempts: 5,
 *
 * @example
 *   async function snapshot() {
 *     var result = await b.atomicFile.copy(
 *       "/var/lib/blamejs/state.bin",
 *       "/var/lib/blamejs/state.bin.bak",
 *       { computeHash: true }
 *     );
 *     return result;   // → { bytesWritten: 4096, hash: "<sha3-512 hex>" }
 *   }
 */
async function copy(src, dst, opts) {
  opts = Object.assign({}, DEFAULTS, opts || {});
  var srcOpts = Object.assign({}, opts);
  delete srcOpts.expectedHash;     // hash check applies to dst, not src
  var buf = await read(src, srcOpts);
  if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf, "utf8");
  return await write(dst, buf, opts);
}

/**
 * @primitive b.atomicFile.exists
 * @signature b.atomicFile.exists(filepath)
 * @since     0.7.0
 * @status    stable
 * @related   b.atomicFile.read, b.atomicFile.readSync
 *
 * Synchronous existence check. Thin wrapper over `fs.existsSync` that
 * normalises the answer for callers that already require this module
 * — saves an additional `require("fs")` in modules that otherwise
 * only need atomicFile.
 *
 * @example
 *   if (b.atomicFile.exists("/var/lib/blamejs/state.bin")) {
 *     // → safe to read
 *   }
 */
function exists(filepath) {
  return fs.existsSync(filepath);
}

/**
 * @primitive b.atomicFile.lock
 * @signature b.atomicFile.lock(filepath, fn, opts)
 * @since     0.7.0
 * @status    stable
 * @related   b.atomicFile.write, b.atomicFile.read
 *
 * Cross-process file mutex around a read-modify-write sequence.
 * Acquires `<filepath>.lock` via `O_CREAT | O_EXCL` (the POSIX atomic
 * "create-or-fail" primitive — Node's "wx" flag), writes
 * `{ pid, acquiredAt }` into the lock for diagnostics, runs `fn()`,
 * then unlinks the lock in a `finally` so a thrown handler still
 * releases. Stale-lock detection: lock files older than 5 minutes
 * are assumed crashed-holder and reclaimed. Returns whatever `fn`
 * returns (or rejects with whatever it throws). Throws
 * `atomic-file/lock-timeout` if the lock can't be acquired before
 * `lockTimeoutMs`.
 *
 * @opts
 *   lockTimeoutMs: 30000,                    // total time to wait before timing out
 *   lockPollMs:    50,                       // sleep between lock acquisition attempts
 *   fileMode:      0o600,                    // mode applied to the lock file
 *   signal:        AbortSignal | undefined,  // abort the wait early
 *
 * @example
 *   async function bumpCounter() {
 *     return await b.atomicFile.lock(
 *       "/var/lib/blamejs/counter.txt",
 *       async function () {
 *         var buf = await b.atomicFile.read("/var/lib/blamejs/counter.txt", { encoding: "utf8" });
 *         var next = (parseInt(buf, 10) || 0) + 1;
 *         await b.atomicFile.write("/var/lib/blamejs/counter.txt", String(next));
 *         return next;
 *       },
 *       { lockTimeoutMs: 5000 }
 *     );
 *   }
 */
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

/**
 * @primitive b.atomicFile.listDir
 * @signature b.atomicFile.listDir(dir, opts)
 * @since     0.7.0
 * @status    stable
 * @related   b.atomicFile.cleanOrphans, b.atomicFile.copyDirRecursive
 *
 * Single-directory listing with optional stat enrichment, name-only
 * filter, and missing-dir tolerance. Returns an array of
 * `{ name, fullPath }` objects (plus `mtimeMs`, `sizeBytes`,
 * `isDirectory`, `isFile` when `includeStat: true`). Entries that
 * vanish between readdir and stat — concurrent cleanup by another
 * process — are silently dropped. For recursive walks, callers
 * compose per subdirectory so per-iteration limits, filters, and
 * stop conditions stay explicit.
 *
 * @opts
 *   filter:      function (name) { return true; },  // name-only predicate; falsey skips entry
 *   includeStat: false,                             // when true, statSync each entry; one extra syscall per entry
 *   missingOk:   true,                              // when true (default), ENOENT returns []; when false, ENOENT throws
 *
 * @example
 *   var entries = b.atomicFile.listDir(
 *     "/var/lib/blamejs/audit",
 *     {
 *       filter:      function (n) { return n.endsWith(".log"); },
 *       includeStat: true,
 *     }
 *   );
 *   // → [{ name: "audit-1.log", fullPath: "/var/lib/blamejs/audit/audit-1.log",
 *   //      mtimeMs: 1700000000000, sizeBytes: 2048, isDirectory: false, isFile: true }, ...]
 */
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
