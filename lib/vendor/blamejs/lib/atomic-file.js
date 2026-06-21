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
var nodeFs = require("node:fs");
var nodePath = require("node:path");
var nodeStream = require("node:stream");
var streamPromises = require("node:stream/promises");
var { generateToken, sha3Hash } = require("./crypto");
var safeJson = require("./safe-json");
var C = require("./constants");
var { boot } = require("./log");
var safeBuffer = require("./safe-buffer");
var numericBounds = require("./numeric-bounds");
var safeAsync = require("./safe-async");
var retryHelper = require("./retry");
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

// EACCES joins the transient set: on Windows a freshly-written file is briefly
// locked by AV / the search indexer / a file-sync client (Dropbox, OneDrive),
// surfacing as EACCES (alongside EPERM/EBUSY) on the next open/rename — the same
// transient contention the sync _renameWithRetry already treats as retryable.
var TRANSIENT_FS_ERRNOS = new Set(["EBUSY", "EAGAIN", "ENFILE", "EMFILE", "EPERM", "EACCES"]);

function _isFsRetryable(e) {
  return e != null && TRANSIENT_FS_ERRNOS.has(e.code);
}

async function _withRetry(fn, opts) {
  opts = Object.assign({}, DEFAULTS, opts || {});
  return retryHelper.withRetry(function () { return fn(); }, {
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
  try { nodeFs.fsyncSync(fd); } catch (_e) { /* not all platforms support fsync on every fd type */ }
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
  // CodeQL js/insecure-temporary-file: this is a read-only open of an
  // EXISTING directory to fsync its inode — no file is created, so the
  // predictable-temp-name / symlink-race the query targets does not
  // apply. The fd is opened "r", fsynced, and closed immediately; no
  // write goes through it. The directory itself is created 0o700 by
  // ensureDir. dirPath is normally an operator data dir (e.g.
  // /var/lib/blamejs/data); when a caller fsyncs a dir under os.tmpdir
  // (test fixtures via fs.mkdtempSync, or an audit bundle written to a
  // tmp `out`), mkdtempSync already guarantees a unique 0o700 dir, so
  // there is still no race surface.
  try {
    var fd = nodeFs.openSync(dirPath, "r"); // lgtm[js/insecure-temporary-file] — read-only fsync of an existing dir; no temp file created
    try { nodeFs.fsyncSync(fd); } catch (_e) { /* Windows rejects directory fsync */ }
    finally { nodeFs.closeSync(fd); }
  } catch (_e) { /* dir fsync is best-effort across filesystems */ }
}

// Internal aliases so existing code in this file keeps working
function _fsync(fd) { return fsync(fd); }
function _fsyncDir(dirPath) { return fsyncDir(dirPath); }

// Exclusive, no-follow create of the sibling temp file that every
// atomic write stages bytes into before the rename. CWE-377
// (insecure temporary file) / CWE-59 (symlink-following): the legacy
// "w" flag is O_WRONLY|O_CREAT|O_TRUNC — it happily opens (and
// truncates, or writes through) a file an attacker pre-created at the
// temp path, including a symlink pointing at a victim file the process
// can write but the attacker can't. O_EXCL makes the open fail with
// EEXIST if anything already exists at tmpPath, so a planted file /
// symlink / FIFO is refused instead of followed; O_NOFOLLOW rejects a
// symlink in the final path component on platforms that define it
// (Windows leaves it undefined, hence the `|| 0`). The temp name
// already carries a CSPRNG token (generateToken), so EEXIST is a
// hostile-collision signal, not a benign retry. The fd is returned for
// the caller to write + fsync; mode is applied at create time so the
// bytes are never world-readable even briefly.
function _openExclTemp(tmpPath, fileMode) {
  return nodeFs.openSync(
    tmpPath,
    nodeFs.constants.O_WRONLY | nodeFs.constants.O_CREAT |
      nodeFs.constants.O_EXCL | (nodeFs.constants.O_NOFOLLOW || 0),
    fileMode
  );
}

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
  nodeFs.mkdirSync(dirPath, { recursive: true, mode: typeof mode === "number" ? mode : 0o700 });
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
  if (!nodeFs.existsSync(src)) {
    throw new AtomicFileError("copyDirRecursive: src does not exist: " + src, "atomic-file/missing-src");
  }
  opts = opts || {};
  var dirMode = typeof opts.dirMode === "number" ? opts.dirMode : 0o700;
  var overwrite = !!opts.overwrite;
  var copyFlags = overwrite ? 0 : nodeFs.constants.COPYFILE_EXCL;

  ensureDir(dest, dirMode);
  var entries = nodeFs.readdirSync(src, { withFileTypes: true });
  var fileCount = 0;
  var byteCount = 0;
  for (var i = 0; i < entries.length; i++) {
    var name = entries[i].name;
    var s = nodePath.join(src, name);
    var d = nodePath.join(dest, name);
    if (entries[i].isDirectory()) {
      var sub = copyDirRecursive(s, d, opts);
      fileCount += sub.fileCount;
      byteCount += sub.byteCount;
    } else if (entries[i].isFile()) {
      nodeFs.copyFileSync(s, d, copyFlags);
      try { byteCount += nodeFs.statSync(d).size; } catch (_e) { /* size best-effort */ }
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

// Generic [A-Za-z0-9_-]+ identifier shape used by conflictPath tag /
// suffix validation. The pattern collides with similar shapes in
// safe-buffer / redact / etc.; keeping the regex literal local to
// atomic-file rather than pulling in a cross-module dependency for a
// 30-byte regex keeps this file's lazy-load chain short.
var IDENT_RE = /^[A-Za-z0-9_-]+$/;                                                              // allow:regex-no-length-cap — caller bounds length before .test() // allow:duplicate-regex — generic [A-Za-z0-9_-]+ identifier shape; extracting a one-line regex into a cross-module dependency would lengthen atomic-file's boot-time lazy chain for no behavioral win

/**
 * @primitive b.atomicFile.conflictPath
 * @signature b.atomicFile.conflictPath(originalPath, opts?)
 * @since     0.10.8
 * @status    stable
 * @related   b.atomicFile.pathTimestamp, b.atomicFile.write
 *
 * Build a filesystem-portable conflict-suffix path next to
 * `originalPath`, e.g. `notes.md` → `notes.conflict-2026-05-17T19-30-00Z.md`.
 * Drop-in name for last-write-wins reconciliation in sync / backup /
 * dual-control workflows. Preserves the original extension. Inserts a
 * caller-supplied `tag` (default `conflict`) between the basename and
 * the timestamp. The timestamp uses `pathTimestamp` so the result is
 * portable across Windows (no `:` / `.`), macOS, and Linux. Same-second
 * collision handling: pass `opts.suffix` (e.g. a per-row crypto-random
 * hex) when multiple conflicts may land in the same second; otherwise
 * the timestamp's millisecond field disambiguates.
 *
 * @opts
 *   tag:       string,     // default "conflict"; sandwiched between basename and timestamp
 *   timestamp: Date,       // default `new Date()`
 *   suffix:    string,     // optional extra disambiguator appended after timestamp
 *
 * @example
 *   var p = b.atomicFile.conflictPath("/srv/notes.md");
 *   // → "/srv/notes.conflict-2026-05-17T20-30-00-123Z.md"
 *
 *   var withSuffix = b.atomicFile.conflictPath("/srv/notes.md", {
 *     tag: "merge", suffix: "abc123",
 *   });
 *   // → "/srv/notes.merge-2026-05-17T20-30-00-123Z.abc123.md"
 */
function conflictPath(originalPath, opts) {
  if (typeof originalPath !== "string" || originalPath.length === 0) {
    throw new TypeError("b.atomicFile.conflictPath: originalPath must be a non-empty string");
  }
  opts = opts || {};
  var tag = typeof opts.tag === "string" && opts.tag.length > 0 ? opts.tag : "conflict";
  if (typeof tag !== "string" || tag.length === 0 || tag.length > 64) {                          // tag length cap, not bytes
    throw new TypeError("b.atomicFile.conflictPath: tag must be a 1-64 char string");
  }
  if (!IDENT_RE.test(tag)) {                                                                     // allow:regex-no-length-cap — length-bounded immediately above
    throw new TypeError("b.atomicFile.conflictPath: tag must match [A-Za-z0-9_-]+");
  }
  var stamp = pathTimestamp(opts.timestamp);
  var suffix = "";
  if (opts.suffix !== undefined) {
    if (typeof opts.suffix !== "string" || opts.suffix.length === 0 ||
        opts.suffix.length > 64) {                                                               // suffix length cap, not bytes
      throw new TypeError("b.atomicFile.conflictPath: suffix must be a 1-64 char string");
    }
    if (!IDENT_RE.test(opts.suffix)) {                                                           // allow:regex-no-length-cap — length-bounded immediately above
      throw new TypeError("b.atomicFile.conflictPath: suffix must match [A-Za-z0-9_-]+");
    }
    suffix = "." + opts.suffix;
  }
  // Walk from the rightmost `.` to split base + ext. POSIX `path` module
  // does it portably; using string ops here keeps the helper free of
  // additional require()s in the hot atomic-file file (which is loaded
  // before most of the framework's lazy chain). Extension preservation
  // walks ONLY the basename — a directory containing a `.` doesn't
  // confuse the suffix.
  var sep = originalPath.lastIndexOf("/");
  var bsep = originalPath.lastIndexOf("\\");
  var lastSep = sep > bsep ? sep : bsep;
  var dir = lastSep >= 0 ? originalPath.slice(0, lastSep + 1) : "";
  var name = lastSep >= 0 ? originalPath.slice(lastSep + 1) : originalPath;
  var dotIdx = name.lastIndexOf(".");
  // Treat a leading dot (dotfile, e.g. `.env`) as part of the base, not
  // as an extension separator. `dotIdx === 0` → no extension.
  var base = dotIdx > 0 ? name.slice(0, dotIdx) : name;
  var ext  = dotIdx > 0 ? name.slice(dotIdx) : "";
  return dir + base + "." + tag + "-" + stamp + suffix + ext;
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
// Synchronous bounded sleep (writeSync is a sync primitive, so no await).
// Uses Atomics.wait on a throwaway shared buffer; falls back to a short spin
// if SharedArrayBuffer is unavailable.
function _sleepSync(ms) {
  try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); return; }
  catch (_e) { /* fall through to spin */ }
  var end = Date.now() + ms;
  while (Date.now() < end) { /* spin */ }
}

// Atomic rename with a bounded retry on Windows-transient lock errors. On
// Windows a rename target is briefly held by AV / the search indexer / a
// file-sync client (Dropbox, OneDrive), surfacing as EPERM / EACCES / EBUSY
// even though the freshly-written temp file is fine; the lock clears in a few
// ms. POSIX rename is atomic and never hits this, so the first attempt
// succeeds there. Surface the error if it is not transient or persists.
function _renameWithRetry(from, to) {
  var delays = [0, 5, 15, 40, 100];
  for (var i = 0; i < delays.length; i += 1) {
    if (delays[i] > 0) _sleepSync(delays[i]);
    try { nodeFs.renameSync(from, to); return; }
    catch (e) {
      var transient = e && (e.code === "EPERM" || e.code === "EACCES" || e.code === "EBUSY");
      if (!transient || i === delays.length - 1) throw e;
    }
  }
}

function writeSync(filepath, data, opts) {
  opts = Object.assign({}, DEFAULTS, opts || {});
  var buf = safeBuffer.toBuffer(data, {
    errorClass: AtomicFileError,
    typeCode:   "atomic-file/invalid-data",
    typeMessage: "data must be Buffer, Uint8Array, or string",
  });

  var dir = nodePath.dirname(filepath);
  if (!nodeFs.existsSync(dir)) nodeFs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  var tmpPath = filepath + ".tmp-" + generateToken(C.BYTES.bytes(8));
  var renamed = false;
  try {
    var fd = _openExclTemp(tmpPath, opts.fileMode);
    try {
      var pos = 0;
      while (pos < buf.length) {
        pos += nodeFs.writeSync(fd, buf, pos, buf.length - pos, null);
      }
      _fsync(fd);
    } finally {
      try { nodeFs.closeSync(fd); } catch (_e) { /* already closed? */ }
    }
    _renameWithRetry(tmpPath, filepath);
    renamed = true;
    _fsyncDir(dir);
  } finally {
    if (!renamed) {
      // Either the write or the rename failed — remove the tmp so the next
      // boot doesn't see a leaked partial file.
      try { nodeFs.unlinkSync(tmpPath); } catch (_e) { /* may not exist */ }
    }
  }

  return {
    bytesWritten: buf.length,
    hash:         opts.computeHash ? sha3Hash(buf) : null,
  };
}

/**
 * @primitive b.atomicFile.writeStream
 * @signature b.atomicFile.writeStream(filepath, source, opts?)
 * @since     0.15.14
 * @status    stable
 * @related   b.atomicFile.writeSync, b.atomicFile.openNoFollowSync
 *
 * Streaming sibling of `writeSync` for payloads too large to buffer in
 * memory. Pipes a Readable `source` into a sibling temp file opened with
 * `O_EXCL | O_NOFOLLOW` (the same exclusive, symlink-refusing create
 * every atomic write uses), fsyncs, then atomically renames over
 * `filepath` and fsyncs the parent directory. A plain
 * `fs.createWriteStream(filepath)` instead follows a symlink an attacker
 * pre-planted at `filepath` (CWE-59 arbitrary write) and leaves a
 * half-written object at the canonical name if the source aborts
 * mid-stream — this primitive does neither: the file appears at
 * `filepath` only after the full stream has landed and synced.
 *
 * Enforces a byte ceiling while streaming (`maxBytes`, default 64 MiB) so
 * an unbounded source cannot fill the disk; the partial temp is removed
 * on overflow or any pipeline error.
 *
 * @opts
 *   fileMode:  0o600,            // mode applied to the temp file (and thus the renamed final)
 *   maxBytes:  64 * 1024 * 1024, // refuse + clean up once the source exceeds this many bytes
 *   signal:    undefined,        // optional AbortSignal forwarded to the pipeline
 *
 * @example
 *   await b.atomicFile.writeStream(
 *     "/var/lib/blamejs/object",
 *     incomingRequestStream,
 *     { fileMode: 0o600, maxBytes: b.C.BYTES.gib(2) }
 *   );
 *   // → { bytesWritten: 12345 }
 */
async function writeStream(filepath, source, opts) {
  opts = Object.assign({}, DEFAULTS, opts || {});
  if (!source || typeof source.pipe !== "function") {
    throw new AtomicFileError(
      "writeStream: source must be a Readable stream", "atomic-file/invalid-source");
  }
  var maxBytes = opts.maxBytes;

  var dir = nodePath.dirname(filepath);
  if (!nodeFs.existsSync(dir)) nodeFs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  var tmpPath = filepath + ".tmp-" + generateToken(C.BYTES.bytes(8));
  var fd = _openExclTemp(tmpPath, opts.fileMode);
  var fileStream = nodeFs.createWriteStream(null, { fd: fd, autoClose: false });
  var bytesWritten = 0;
  var renamed = false;

  // Cap the stream as it flows — an unbounded source must not fill the disk.
  var counter = new nodeStream.Transform({
    transform: function (chunk, _enc, cb) {
      bytesWritten += chunk.length;
      if (typeof maxBytes === "number" && bytesWritten > maxBytes) {
        return cb(new AtomicFileError(
          "writeStream: source exceeds maxBytes " + maxBytes, "atomic-file/too-large"));
      }
      cb(null, chunk);
    },
  });

  try {
    if (opts.signal) {
      await streamPromises.pipeline(source, counter, fileStream, { signal: opts.signal });
    } else {
      await streamPromises.pipeline(source, counter, fileStream);
    }
    _fsync(fd);
    nodeFs.closeSync(fd);
    fd = -1;
    _renameWithRetry(tmpPath, filepath);
    renamed = true;
    _fsyncDir(dir);
  } finally {
    if (fd >= 0) { try { nodeFs.closeSync(fd); } catch (_e) { /* already closed? */ } }
    if (!renamed) {
      // Source aborted, overflowed, or the rename failed — remove the temp so
      // no half-written object survives at the canonical name.
      try { nodeFs.unlinkSync(tmpPath); } catch (_e) { /* may not exist */ }
    }
  }

  return { bytesWritten: bytesWritten };
}

/**
 * @primitive b.atomicFile.writeExclSync
 * @signature b.atomicFile.writeExclSync(filepath, data, opts?)
 * @since     0.15.14
 * @status    stable
 * @related   b.atomicFile.writeSync, b.atomicFile.openNoFollowSync
 *
 * Exclusive, symlink-refusing write to `filepath` WITHOUT the atomic
 * rename — for staged "write → fsync → verify → rename" flows where the
 * caller must re-read and validate the written bytes before committing them
 * over the live file (the vault seal/unseal round-trip re-reads the staged
 * file and confirms it decrypts before renaming it into place). Clears any
 * stale leftover at `filepath` first (an aborted prior run, or a planted
 * symlink — `unlink` removes the LINK, never its target), then creates the
 * file with `O_EXCL | O_NOFOLLOW`, so a symlink re-planted in the race
 * window fails the open closed instead of being followed (CWE-59 / CWE-377).
 * fsyncs the data before returning. For an ordinary write-and-replace use
 * `writeSync`, which renames atomically; reach for this only when a
 * verify-before-commit step sits between the write and the rename.
 *
 * @opts
 *   fileMode: 0o600,   // mode applied to the created file
 *
 * @example
 *   b.atomicFile.writeExclSync(stagingPath, bytes, { fileMode: 0o600 });
 *   // re-read + verify stagingPath, then:
 *   b.atomicFile.renameWithRetry(stagingPath, finalPath);
 */
function writeExclSync(filepath, data, opts) {
  opts = Object.assign({}, DEFAULTS, opts || {});
  var buf = safeBuffer.toBuffer(data, {
    errorClass:  AtomicFileError,
    typeCode:    "atomic-file/invalid-data",
    typeMessage: "data must be Buffer, Uint8Array, or string",
  });
  // Clear any stale leftover so the exclusive create can proceed; unlink
  // removes a planted symlink itself (not its target), and the O_EXCL open
  // then fails closed if anything re-appears at the path in the race window.
  try { nodeFs.unlinkSync(filepath); } catch (_e) { /* nothing to clear */ }
  var fd = _openExclTemp(filepath, opts.fileMode);
  try {
    var pos = 0;
    while (pos < buf.length) {
      pos += nodeFs.writeSync(fd, buf, pos, buf.length - pos, null);
    }
    _fsync(fd);
  } finally {
    try { nodeFs.closeSync(fd); } catch (_e) { /* already closed? */ }
  }
  return { bytesWritten: buf.length };
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
  var dir = nodePath.dirname(filepath);
  var basename = nodePath.basename(filepath);
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
        nodeFs.unlinkSync(entry.fullPath);
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
      var dir = nodePath.dirname(filepath);
      if (!nodeFs.existsSync(dir)) nodeFs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      var tmpPath = filepath + ".tmp-" + generateToken(C.BYTES.bytes(8));
      var renamed = false;
      try {
        var fd = _openExclTemp(tmpPath, opts.fileMode);
        try {
          var pos = 0;
          while (pos < buf.length) {
            pos += nodeFs.writeSync(fd, buf, pos, buf.length - pos, null);
          }
          _fsync(fd);
        } finally {
          try { nodeFs.closeSync(fd); } catch (_e) { /* already closed? */ }
        }
        // Atomic rename — POSIX rename is atomic on the same FS; on Windows,
        // nodeFs.renameSync uses MoveFileEx with REPLACE_EXISTING.
        nodeFs.renameSync(tmpPath, filepath);
        renamed = true;
        _fsyncDir(dir);
        var hash = opts.computeHash ? sha3Hash(buf) : null;
        resolve({ bytesWritten: buf.length, hash: hash });
      } catch (e) {
        reject(e);
      } finally {
        if (!renamed) {
          try { nodeFs.unlinkSync(tmpPath); } catch (_e) { /* may not exist */ }
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

/**
 * @primitive b.atomicFile.fdSafeReadSync
 * @signature b.atomicFile.fdSafeReadSync(filepath, opts?)
 * @since     0.15.13
 * @status    stable
 * @related   b.atomicFile.readSync, b.atomicFile.read
 *
 * TOCTOU-safe synchronous file read (CWE-367 / js/file-system-race). Opens
 * the path read-only, then binds every subsequent measurement — size,
 * content, integrity — to the inode the fd holds open, so an attacker who
 * swaps the file between stat and read can't change which bytes come back.
 * The optional guards layer on top of that core: a byte cap (`maxBytes`),
 * symlink refusal + inode-equality (`refuseSymlink` / `inodeCheck` — the
 * strongest defense, for operator-writable source paths), an integrity
 * hash (`expectedHash`, SHA3-512), and a short-read policy (throw, or
 * slice when `allowShortRead`). Each caller maps a failure KIND to its own
 * typed error via `errorFor`, so the message / code / audit posture stays
 * per-domain; the default raises an `AtomicFileError`.
 *
 * @opts
 *   mode:           number,    // open mode (default 0o600; inert under O_RDONLY)
 *   maxBytes:       number,    // refuse a file larger than this (default: no cap)
 *   refuseSymlink:  boolean,   // lstat + refuse a symlink source (default: false)
 *   inodeCheck:     boolean,   // refuse if the fd inode != the lstat inode (needs refuseSymlink)
 *   expectedHash:   string,    // SHA3-512 the content must match (default: none)
 *   encoding:       string,    // decode to a string (default: return a Buffer)
 *   allowShortRead: boolean,   // slice to the bytes read instead of throwing (default: false)
 *   withStat:       boolean,   // return { bytes, stat } — stat of the bound fd (mode/uid/gid/size/ino/nlink/mtimeMs), TOCTOU-free
 *   errorFor:       Function,  // (kind, detail) => Error|undefined; kinds: enoent / symlink / too-large / toctou / short-read / integrity
 *
 * @example
 *   var cfg = b.atomicFile.fdSafeReadSync("/etc/app/config.json", {
 *     maxBytes: b.constants.BYTES.mib(1),
 *     encoding: "utf8",
 *   });
 *
 *   // Assert mode + owner on the exact inode the bytes came from (no re-stat):
 *   var r = b.atomicFile.fdSafeReadSync("/etc/app/secret", { withStat: true });
 *   if ((r.stat.mode & 0o077) !== 0) throw new Error("secret is group/other-readable");
 *   // r.bytes is the Buffer (or string under `encoding`)
 */
function fdSafeReadSync(filepath, opts) {
  opts = opts || {};
  var errorFor = opts.errorFor || function (kind, detail) {
    return new AtomicFileError((detail && detail.message) || ("atomic-file: " + kind), "atomic-file/" + kind);
  };
  if (opts.maxBytes !== undefined) _validateMaxBytes(opts.maxBytes);
  var mode = opts.mode === undefined ? 0o600 : opts.mode;
  // refuseSymlink: lstat the path first and refuse a symlink source —
  // the strongest TOCTOU posture (open() would follow the link). The
  // fd's inode is re-checked against this lstat's inode below.
  var lstat = null;
  if (opts.refuseSymlink) {
    lstat = nodeFs.lstatSync(filepath);
    if (lstat.isSymbolicLink()) throw errorFor("symlink", { path: filepath });
    if (opts.maxBytes !== undefined && lstat.size > opts.maxBytes) {
      throw errorFor("too-large", { size: lstat.size, max: opts.maxBytes });
    }
  }
  // The third argument pins an owner-only mode (0o600 default). The flag
  // is read-only ("r" → O_RDONLY, no O_CREAT) so the mode is inert on
  // disk, but specifying it keeps this open out of the insecure-temp-file
  // class (CWE-377). ENOENT surfaces from open() rather than a pre-check;
  // a caller's errorFor("enoent") may translate it, else it rethrows raw.
  var fd;
  try {
    fd = nodeFs.openSync(filepath, "r", mode);
  } catch (openErr) {
    if (openErr && openErr.code === "ENOENT") {
      var typed = errorFor("enoent", { path: filepath, cause: openErr });
      if (typed) throw typed;
    }
    throw openErr;
  }
  var buf;
  try {
    var fstat = nodeFs.fstatSync(fd);
    // inodeCheck: the fd must point at the same inode lstat saw — any
    // swap between lstat and open is a TOCTOU and is refused. A file that
    // GREW past the cap between lstat and open is the same class of swap,
    // so under inodeCheck a post-open over-cap is reported as toctou; a
    // plain (no-inodeCheck) reader reports an over-cap as too-large.
    if (lstat && opts.inodeCheck) {
      if (fstat.ino !== lstat.ino || (opts.maxBytes !== undefined && fstat.size > opts.maxBytes)) {
        throw errorFor("toctou", { path: filepath });
      }
    } else if (opts.maxBytes !== undefined && fstat.size > opts.maxBytes) {
      throw errorFor("too-large", { size: fstat.size, max: opts.maxBytes });
    }
    buf = Buffer.alloc(fstat.size);
    var read = 0;
    while (read < fstat.size) {
      var n = nodeFs.readSync(fd, buf, read, fstat.size - read, null);
      if (n === 0) break;
      read += n;
    }
    if (read !== fstat.size) {
      if (opts.allowShortRead) { buf = buf.slice(0, read); }
      else { throw errorFor("short-read", { read: read, size: fstat.size }); }
    }
  } finally {
    try { nodeFs.closeSync(fd); } catch (_c) { /* close best-effort */ }
  }
  if (opts.expectedHash) {
    var actual = sha3Hash(buf);
    if (actual !== opts.expectedHash) {
      throw errorFor("integrity", { expected: opts.expectedHash, actual: actual });
    }
  }
  var content = opts.encoding ? buf.toString(opts.encoding) : buf;
  // withStat: return the fstat of the SAME bound fd alongside the bytes, so a
  // caller that needs the mode / owner (e.g. to assert 0o600 + owned-by-me on a
  // secrets file) reads it TOCTOU-free — the stat describes the exact inode the
  // bytes came from, not a re-stat that an attacker could swap underneath.
  if (opts.withStat) {
    return {
      bytes: content,
      stat: {
        mode:    fstat.mode,
        uid:     fstat.uid,
        gid:     fstat.gid,
        size:    fstat.size,
        ino:     fstat.ino,
        nlink:   fstat.nlink,
        mtimeMs: fstat.mtimeMs,
      },
    };
  }
  return content;
}

// Atomic-file's own reads route through fdSafeReadSync with an errorFor
// that reproduces this module's exact codes + messages (a pure refactor).
function _readSyncCore(filepath, opts) {
  return fdSafeReadSync(filepath, {
    mode:         0o600,
    maxBytes:     opts.maxBytes,
    expectedHash: opts.expectedHash,
    encoding:     opts.encoding,
    errorFor: function (kind, detail) {
      if (kind === "enoent") {
        var e = new AtomicFileError("file not found: " + filepath, "atomic-file/not-found");
        e.code = "ENOENT";
        return e;
      }
      if (kind === "too-large") {
        return new AtomicFileError(
          "file size " + detail.size + " > maxBytes " + detail.max, "atomic-file/too-large");
      }
      if (kind === "short-read") {
        return new AtomicFileError(
          "short read: " + detail.read + " of " + detail.size + " bytes", "atomic-file/short-read");
      }
      if (kind === "integrity") {
        return new AtomicFileError(
          "integrity check failed: expected " + detail.expected + " got " + detail.actual,
          "atomic-file/integrity");
      }
      return new AtomicFileError("atomic-file: " + kind, "atomic-file/" + kind);
    },
  });
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
  return nodeFs.existsSync(filepath);
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
      fd = nodeFs.openSync(lockPath, "wx", opts.fileMode);
      break;
    } catch (e) {
      if (e.code !== "EEXIST") throw e;
      // Stale lock detection: if the .lock file is older than 5 minutes,
      // assume the holding process crashed and remove it.
      try {
        var stat = nodeFs.statSync(lockPath);
        if (Date.now() - stat.mtimeMs > C.TIME.minutes(5)) {
          try { nodeFs.unlinkSync(lockPath); }
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
    nodeFs.writeSync(fd, Buffer.from(JSON.stringify({
      pid:        process.pid,
      acquiredAt: Date.now(),
    }), "utf8"));
    _fsync(fd);
  } catch (_e) { /* lock content best-effort */ }

  try {
    return await fn();
  } finally {
    try { nodeFs.closeSync(fd); }
    catch (cerr) { log.debug("lock fd close failed", { error: cerr.message }); }
    try { nodeFs.unlinkSync(lockPath); }
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
    entries = nodeFs.readdirSync(dir);
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
    var fullPath = nodePath.join(dir, name);
    var entry = { name: name, fullPath: fullPath };
    if (includeStat) {
      try {
        var stat = nodeFs.statSync(fullPath);
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

/**
 * @primitive b.atomicFile.openNoFollowSync
 * @signature b.atomicFile.openNoFollowSync(filepath, mode?)
 * @since      0.15.14
 * @status     stable
 * @related    b.atomicFile.fdSafeReadSync, b.atomicFile.readSync
 *
 * Open a path read-only with `O_NOFOLLOW` so a symlink at the final path
 * component is refused (`ELOOP`) instead of followed — the streaming-read
 * counterpart to `fdSafeReadSync` for callers that must `fs.createReadStream`
 * (range serving, SRI/ETag hashing, large-object download) and cannot buffer
 * the whole file. Stream from the returned fd: `fs.createReadStream(path, { fd
 * })`. Defends a post-confinement symlink swap (CWE-22 / CWE-367) on
 * request-reachable static-serve and object-store read paths, where a lexical
 * `_assertInsideRoot` check alone leaves a swap window between the check and the
 * open. `O_NOFOLLOW` is POSIX-only; on platforms without it the flag is 0 (a
 * plain `O_RDONLY` open) — Windows symlink semantics differ and are out of
 * scope. Throws the raw `openSync` error (caller maps `ELOOP` / `ENOENT`).
 *
 * @example
 *   var fd = b.atomicFile.openNoFollowSync(absPath);
 *   var stream = fs.createReadStream(absPath, { fd: fd });   // autoClose closes fd
 */
function openNoFollowSync(filepath, mode) {
  var flags = nodeFs.constants.O_RDONLY | (nodeFs.constants.O_NOFOLLOW || 0);
  return nodeFs.openSync(filepath, flags, mode === undefined ? 0o600 : mode);
}

module.exports = {
  write:             write,
  writeSync:         writeSync,
  writeStream:       writeStream,
  writeExclSync:     writeExclSync,
  read:              read,
  readSync:          readSync,
  fdSafeReadSync:    fdSafeReadSync,
  openNoFollowSync:  openNoFollowSync,
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
  // Atomic rename with a bounded retry on Windows-transient lock errors
  // (EPERM/EACCES/EBUSY from AV / search indexer / Dropbox / OneDrive briefly
  // holding the destination). Exposed so any final temp->dest rename routes
  // through the same retry instead of hand-rolling it (or, worse, omitting it).
  renameWithRetry:   _renameWithRetry,
  copyDirRecursive:  copyDirRecursive,
  pathTimestamp:     pathTimestamp,
  conflictPath:      conflictPath,
  AtomicFileError:   AtomicFileError,
  DEFAULTS:          DEFAULTS,
};
