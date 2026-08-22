/**
 * Local disk and S3 behind one API. Every consumer imports this module; there
 * are no direct fs calls against the upload directory anywhere else, so
 * switching backends changes no call site.
 *
 * saveFile encrypts under a fresh per-file key and returns it in plaintext for
 * the caller to store on the file row, where the database layer seals it. The
 * stored blob is opaque without that key.
 *
 * saveRaw and getRawBuffer bypass encryption, and are only for blobs a higher
 * layer has already encrypted — backup bundles, vault files. Never user
 * content. getFileStream with a null key reads a legacy unencrypted blob.
 *
 * Import `storage.uploadDir` rather than resolving the configured path again:
 * this export follows a config hot-reload and a local copy will not.
 */
var b = require("./vendor/blamejs");
var C = require("./constants");
var nodeFs = require("node:fs");
var nodePath = require("node:path");
var config = require("./config");
var { Readable } = require("node:stream");
var S3Client = require("./s3-client");

// Resolve upload directory
var uploadDir = nodePath.isAbsolute(config.storage.uploadDir)
  ? config.storage.uploadDir
  : nodePath.resolve(__dirname, "..", config.storage.uploadDir);

if (config.storage.backend === "local") {
  if (!nodeFs.existsSync(uploadDir)) nodeFs.mkdirSync(uploadDir, { recursive: true });
}

// Resolve chunk scratch directory. Always local-disk regardless of storage
// backend — S3 is unsuitable for thousands of transient chunk objects.
// Default: <uploadDir>/chunks. Override via CHUNK_SCRATCH_DIR env var.
function _resolveScratchDir() {
  var raw = config.storage.chunkScratchDir;
  if (!raw) return nodePath.join(uploadDir, "chunks");
  return nodePath.isAbsolute(raw) ? raw : nodePath.resolve(__dirname, "..", raw);
}
var scratchDir = _resolveScratchDir();

// A DoS floor on buffered local reads, not a correctness limit. Well above the
// configured upload ceiling, since a stored blob carries envelope overhead on
// top of it — high enough never to refuse a real object, low enough to bound a
// read that follows a hostile symlink.
var _LOCAL_READ_CAP = C.BYTES.gib(2);

// Guards against path traversal in component inputs. shareId/fileId are
// internally generated tokens, but we enforce a strict charset here so a
// future bug or misuse can't escape scratchDir.
var _SAFE_COMPONENT = /^[a-zA-Z0-9_-]+$/;
function _safeComponent(name) {
  if (typeof name !== "string" || !name || !_SAFE_COMPONENT.test(name)) {
    throw new Error("Invalid chunk path component");
  }
  return name;
}

// ---- File encryption (XChaCha20-Poly1305 with per-file keys) ----

function encryptBuffer(buffer) {
  var key = b.crypto.generateBytes(C.BYTES.bytes(32));
  var packed = b.crypto.encryptPacked(buffer, key);
  return { data: packed, encryptionKey: key.toString("base64") };
}

function decryptBuffer(packed, encryptionKey) {
  var key = Buffer.from(encryptionKey, "base64");
  return b.crypto.decryptPacked(packed, key);
}

// ---- Public API ----

/**
 * Encrypts under a fresh per-file key, on every backend. There is no
 * unencrypted path: relying on S3's own server-side cipher instead would put a
 * classical algorithm under data this project encrypts post-quantum.
 */
async function saveFile(buffer, storagePath) {
  var enc = encryptBuffer(buffer);
  if (config.storage.backend === "s3") {
    await s3Put(storagePath, enc.data);
    return { path: "s3://" + config.storage.s3.bucket + "/" + storagePath, encryptionKey: enc.encryptionKey };
  }
  var r = resolveLocalPath(storagePath);
  if (!r.ok) throw new Error(r.reason);
  var dir = nodePath.dirname(r.absPath);
  if (!nodeFs.existsSync(dir)) nodeFs.mkdirSync(dir, { recursive: true });
  // Atomic, symlink-refusing write (CWE-59 / torn-write): temp + fsync + rename.
  await b.atomicFile.write(r.absPath, enc.data, { fileMode: 0o600 });
  return { path: storagePath, encryptionKey: enc.encryptionKey };
}

/**
 * Detect if a storagePath is on S3 (s3://bucket/key) or local disk.
 * This allows reads/deletes to work regardless of the current global backend —
 * critical during and after storage migrations.
 */
function isS3Path(storagePath) {
  return !!storagePath && storagePath.startsWith("s3://");
}

function s3KeyFromPath(storagePath) {
  return storagePath.replace(/^s3:\/\/[^/]+\//, "");
}

/**
 * A local storagePath as an absolute path, confined to uploadDir.
 *
 * The database holds both absolute and relative paths depending on when a file
 * was uploaded, and joining one without the containment check is the shape of a
 * traversal bug — which is why every caller comes through here rather than
 * doing the ternary itself.
 *
 * Returns { ok: true, absPath } or { ok: false, reason }, and never throws.
 * Guard with isS3Path() first; an S3 path does not belong here.
 */
function resolveLocalPath(storagePath) {
  if (!storagePath || typeof storagePath !== "string") {
    return { ok: false, reason: "empty storagePath" };
  }
  if (isS3Path(storagePath)) {
    return { ok: false, reason: "s3 path — caller should branch on isS3Path" };
  }
  // Catches a `../` traversal, an absolute path outside the root, and the
  // sibling-prefix case. The file operations themselves are guarded separately
  // against a symlink swapped in afterwards.
  var resolved = b.safePath.confineToBase(uploadDir, storagePath);
  if (resolved === null) {
    return { ok: false, reason: "path escapes upload directory: " + storagePath };
  }
  return { ok: true, absPath: resolved };
}

// A not-found error indistinguishable for a missing file and a refused symlink
// (ELOOP). Mapping both to the same shape means symlink refusal on a
// request-reachable read path can't be used as an existence oracle.
function _notFound(storagePath) {
  var e = new Error("storage object not found");
  e.code = "ENOENT";
  e.storagePath = storagePath;
  return e;
}

// Open a local storage object read-only with O_NOFOLLOW after the path-escape
// check, returning the fd. ELOOP (planted symlink) and ENOENT both surface as
// the same not-found error so symlink refusal doesn't leak existence.
function _openLocalNoFollow(storagePath) {
  var r = resolveLocalPath(storagePath);
  if (!r.ok) throw new Error(r.reason);
  try {
    return { fd: b.atomicFile.openNoFollowSync(r.absPath), absPath: r.absPath };
  } catch (e) {
    if (e && (e.code === "ELOOP" || e.code === "ENOENT")) throw _notFound(storagePath);
    throw e;
  }
}

/**
 * Get a readable stream of decrypted file data.
 * If encryptionKey is null (legacy unencrypted file), returns raw stream.
 * Detects S3 vs local from storagePath prefix, not global config.
 */
async function getFileStream(storagePath, encryptionKey) {
  var onS3 = isS3Path(storagePath);
  var key = onS3 ? s3KeyFromPath(storagePath) : storagePath;

  if (!encryptionKey) {
    if (onS3) return s3Get(key);
    // Open with O_NOFOLLOW first (refuse a post-confinement symlink swap,
    // CWE-22 / CWE-367), then stream from the bound fd.
    var opened = _openLocalNoFollow(key);
    return nodeFs.createReadStream(opened.absPath, { fd: opened.fd });
  }
  var packed;
  if (onS3) {
    packed = await s3GetBuffer(key);
  } else {
    var r = resolveLocalPath(key);
    if (!r.ok) throw new Error(r.reason);
    packed = b.atomicFile.fdSafeReadSync(r.absPath, {
      refuseSymlink: true, maxBytes: _LOCAL_READ_CAP,
      errorFor: function (kind) {
        if (kind === "enoent" || kind === "symlink") return _notFound(key);
        return undefined; // default AtomicFileError for too-large / toctou / etc.
      },
    });
  }
  var decrypted = decryptBuffer(packed, encryptionKey);
  return Readable.from(decrypted);
}

/**
 * Save a raw buffer without app-level encryption — for pre-encrypted data (vault files).
 * Uses the correct backend (local or S3) but does not apply encryptBuffer().
 * Returns the storagePath (local relative path or s3:// URI).
 */
async function saveRaw(buffer, storagePath) {
  if (config.storage.backend === "s3") {
    await s3Put(storagePath, buffer);
    return "s3://" + config.storage.s3.bucket + "/" + storagePath;
  }
  var r = resolveLocalPath(storagePath);
  if (!r.ok) throw new Error(r.reason);
  var dir = nodePath.dirname(r.absPath);
  if (!nodeFs.existsSync(dir)) nodeFs.mkdirSync(dir, { recursive: true });
  // Atomic, symlink-refusing write (CWE-59 / torn-write): temp + fsync + rename.
  await b.atomicFile.write(r.absPath, buffer, { fileMode: 0o600 });
  return storagePath;
}

/**
 * Read a raw buffer from storage — no decryption. For pre-encrypted data (vault files).
 */
async function getRawBuffer(storagePath) {
  if (isS3Path(storagePath)) return s3GetBuffer(s3KeyFromPath(storagePath));
  var r = resolveLocalPath(storagePath);
  if (!r.ok) throw new Error(r.reason);
  // TOCTOU/symlink-safe read (CWE-367 / CWE-59); ELOOP/ENOENT → not-found so
  // symlink refusal doesn't leak existence on this request-reachable path.
  return b.atomicFile.fdSafeReadSync(r.absPath, {
    refuseSymlink: true, maxBytes: _LOCAL_READ_CAP,
    errorFor: function (kind) {
      if (kind === "enoent" || kind === "symlink") return _notFound(storagePath);
      return undefined;
    },
  });
}

async function deleteFile(storagePath) {
  if (isS3Path(storagePath)) return s3Delete(s3KeyFromPath(storagePath));
  var r = resolveLocalPath(storagePath);
  if (!r.ok) throw new Error(r.reason);
  // unlink removes the directory entry / symlink itself (never a symlink
  // target), so no O_NOFOLLOW guard is needed here.
  if (nodeFs.existsSync(r.absPath)) nodeFs.unlinkSync(r.absPath);
}

// ---- Chunk scratch API ----
// Layout: <scratchDir>/<bundleShareId>/<fileId>/<chunkIndex>
// All operations are synchronous local-disk I/O — chunks never go to S3.

function _bundleDir(bundleShareId) {
  return nodePath.join(scratchDir, _safeComponent(bundleShareId));
}
function _fileDir(bundleShareId, fileId) {
  return nodePath.join(_bundleDir(bundleShareId), _safeComponent(fileId));
}
function _chunkPath(bundleShareId, fileId, index) {
  // The type is checked before the coercion. Number(null), Number(""),
  // Number(false) and Number([]) are all 0, so coercing first turns an ABSENT
  // index into chunk 0 — quietly reading or deleting the first chunk when the
  // caller named none. A string is still allowed, because the index arrives as
  // one on the request and every caller parses it before reaching here.
  if (typeof index !== "number" && typeof index !== "string") {
    throw new Error("Invalid chunk index");
  }
  if (typeof index === "string" && index.trim() === "") {
    throw new Error("Invalid chunk index");
  }
  var i = Number(index);
  if (!Number.isInteger(i) || i < 0) throw new Error("Invalid chunk index");
  return nodePath.join(_fileDir(bundleShareId, fileId), String(i));
}

// In process memory only, so no plaintext fragment ever reaches the scratch
// disk: an abandoned upload leaves unreadable ciphertext, and a restart
// mid-upload costs the client a re-upload while the orphans are collected. The
// get-or-create is race-free because the runtime is single-threaded and
// saveChunk is synchronous.
var _chunkKeys = new Map();
function _chunkKeyId(bundleShareId, fileId) { return String(bundleShareId) + "/" + String(fileId); }
function _chunkKey(bundleShareId, fileId) {
  var id = _chunkKeyId(bundleShareId, fileId);
  var key = _chunkKeys.get(id);
  if (!key) { key = b.crypto.generateBytes(C.BYTES.bytes(32)); _chunkKeys.set(id, key); }
  return key;
}
function _dropChunkKey(bundleShareId, fileId) { _chunkKeys.delete(_chunkKeyId(bundleShareId, fileId)); }
function _dropBundleChunkKeys(bundleShareId) {
  var prefix = String(bundleShareId) + "/";
  for (var id of _chunkKeys.keys()) { if (id.indexOf(prefix) === 0) _chunkKeys.delete(id); }
}

function saveChunk(bundleShareId, fileId, index, buffer) {
  var dir = _fileDir(bundleShareId, fileId);
  if (!nodeFs.existsSync(dir)) nodeFs.mkdirSync(dir, { recursive: true });
  // Encrypt each chunk at rest under the per-upload key so no plaintext fragment
  // is ever written to the scratch dir; then an atomic, symlink-refusing sync
  // write (CWE-59 / torn-write): temp + fsync + rename.
  var packed = b.crypto.encryptPacked(buffer, _chunkKey(bundleShareId, fileId));
  b.atomicFile.writeSync(_chunkPath(bundleShareId, fileId, index), packed, { fileMode: 0o600 });
}

function readChunk(bundleShareId, fileId, index) {
  // TOCTOU/symlink-safe read of a scratch chunk (CWE-367 / CWE-59), then decrypt
  // it back to plaintext with the per-upload key for reassembly.
  var packed = b.atomicFile.fdSafeReadSync(_chunkPath(bundleShareId, fileId, index), {
    refuseSymlink: true, maxBytes: _LOCAL_READ_CAP,
  });
  return b.crypto.decryptPacked(packed, _chunkKey(bundleShareId, fileId));
}

function statChunk(bundleShareId, fileId, index) {
  // Outside the try, because _chunkPath's refusals — an escaping component, a
  // non-integer index — would otherwise be caught by a handler meant for "the
  // chunk is not there", reporting a malformed request as a missing chunk and
  // leaving the guard itself with no effect.
  var file = _chunkPath(bundleShareId, fileId, index);
  try { return nodeFs.statSync(file); }
  catch (_e) { return null; }
}

// Returns the count of chunk files currently present for this file. The caller
// uses this to detect "all chunks received".
function countChunks(bundleShareId, fileId) {
  var dir = _fileDir(bundleShareId, fileId);
  if (!nodeFs.existsSync(dir)) return 0;
  try { return nodeFs.readdirSync(dir).length; } catch (_e) { return 0; }
}

// Total bytes of every chunk currently staged for one file (one fileId dir),
// optionally excluding a single chunk index (the one about to be overwritten).
// Feeds the per-file aggregate cap without a caller-side stat loop.
function fileScratchBytes(bundleShareId, fileId, excludeIndex) {
  var dir = _fileDir(bundleShareId, fileId);
  if (!nodeFs.existsSync(dir)) return 0;
  var total = 0;
  try {
    var names = nodeFs.readdirSync(dir);
    for (var i = 0; i < names.length; i++) {
      if (excludeIndex !== undefined && names[i] === String(excludeIndex)) continue;
      try { total += nodeFs.statSync(nodePath.join(dir, names[i])).size; }
      catch (_e) { /* entry vanished between readdir and stat — skip */ }
    }
  } catch (_e) { /* dir readdir failed — treat as empty */ }
  return total;
}

// Summed across every in-flight assembly, so this bound holds whatever the
// policy caps say — an operator may set those to "no limit", and partial
// assemblies under many file ids would otherwise fill the scratch disk.
function bundleScratchBytes(bundleShareId) {
  var bdir = _bundleDir(bundleShareId);
  if (!nodeFs.existsSync(bdir)) return 0;
  var total = 0;
  try {
    var fileDirs = nodeFs.readdirSync(bdir, { withFileTypes: true });
    for (var i = 0; i < fileDirs.length; i++) {
      if (!fileDirs[i].isDirectory()) continue;
      total += fileScratchBytes(bundleShareId, fileDirs[i].name);
    }
  } catch (_e) { /* bundle dir readdir failed — treat as empty */ }
  return total;
}

function deleteChunk(bundleShareId, fileId, index) {
  // Built OUTSIDE the try, for the same reason as statChunk: the catch is there
  // to tolerate a chunk that has already gone, not to swallow the refusal of a
  // path component that would leave the scratch directory.
  var file = _chunkPath(bundleShareId, fileId, index);
  try { nodeFs.unlinkSync(file); } catch (_e) { /* cleanup — chunk may have been removed already */ }
}

// Remove the per-file assembly directory after successful reassembly.
function removeChunkAssembly(bundleShareId, fileId) {
  var dir = _fileDir(bundleShareId, fileId);
  try { nodeFs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* cleanup — assembly dir may already be gone */ }
  _dropChunkKey(bundleShareId, fileId);   // release the in-memory chunk key
}

// Remove the entire bundle chunk directory — used by expiry-cleanup when a
// stale bundle is being purged.
function removeBundleChunks(bundleShareId) {
  var dir = _bundleDir(bundleShareId);
  try { nodeFs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* cleanup — bundle dir may not exist */ }
  _dropBundleChunkKeys(bundleShareId);    // release every in-memory chunk key for this bundle
}

// The bundle's real last-write time. The directory's own mtime is not it: a
// directory advances only when an entry is created or removed in it, so it
// records when the last subdirectory appeared, not when the last chunk landed
// in an existing one. Collecting on that both reaps a bundle still actively
// receiving chunks and lets one be kept perpetually fresh by creating an empty
// subdirectory now and then. Falls back to the directory's mtime while it holds
// no chunks at all.
function _newestChunkMtimeMs(bundleDir) {
  var newest = 0;
  var sawChunk = false;
  try {
    var fileDirs = nodeFs.readdirSync(bundleDir, { withFileTypes: true });
    for (var i = 0; i < fileDirs.length; i++) {
      if (!fileDirs[i].isDirectory()) continue;
      var fdir = nodePath.join(bundleDir, fileDirs[i].name);
      try {
        var chunks = nodeFs.readdirSync(fdir);
        for (var j = 0; j < chunks.length; j++) {
          try {
            var cst = nodeFs.statSync(nodePath.join(fdir, chunks[j]));
            sawChunk = true;
            if (cst.mtimeMs > newest) newest = cst.mtimeMs;
          } catch (_e) { /* chunk vanished — skip */ }
        }
      } catch (_e) { /* fileId dir readdir failed — skip */ }
    }
  } catch (_e) { /* bundle dir readdir failed */ }
  if (!sawChunk) {
    try { return nodeFs.statSync(bundleDir).mtimeMs; } catch (_e) { return 0; }
  }
  return newest;
}

// Return absolute paths of bundle-level chunk directories whose most recent chunk
// write is older than `olderThanMs`. Used by chunk-gc.
function listStaleBundleChunkDirs(olderThanMs) {
  if (!nodeFs.existsSync(scratchDir)) return [];
  var cutoff = Date.now() - olderThanMs;
  var results = [];
  try {
    var entries = nodeFs.readdirSync(scratchDir, { withFileTypes: true });
    for (var i = 0; i < entries.length; i++) {
      if (!entries[i].isDirectory()) continue;
      var p = nodePath.join(scratchDir, entries[i].name);
      try {
        if (_newestChunkMtimeMs(p) < cutoff) results.push(p);
      } catch (_e) { /* entry disappeared between readdir and stat — skip */ }
    }
  } catch (_e) { /* scratchDir readdir failed — return partial results */ }
  return results;
}

// Remove a bundle chunk directory by absolute path — used by chunk-gc after
// listStaleBundleChunkDirs returns a list.
function removeDirByPath(p) {
  // Defense: ensure the path is under scratchDir before rm -rf.
  var resolvedP = nodePath.resolve(p);
  var resolvedRoot = nodePath.resolve(scratchDir);
  if (!resolvedP.startsWith(resolvedRoot + nodePath.sep) && resolvedP !== resolvedRoot) {
    throw new Error("Refusing to remove path outside scratch dir");
  }
  try { nodeFs.rmSync(resolvedP, { recursive: true, force: true }); } catch (_e) { /* cleanup — target may be gone between list + rm */ }
}

// ---- S3 client (shared S3Client module) ----

var _s3 = null;
function getS3() {
  if (!_s3) _s3 = new S3Client(config.storage.s3);
  return _s3;
}
function resetS3Client() { _s3 = null; }

// Invalidate cached S3 client and re-resolve uploadDir/scratchDir when config
// changes at runtime. scratchDir depends on uploadDir by default, so both are
// re-derived when either changes.
var _resetKeys = ["s3AccessKey", "s3Bucket", "s3Endpoint", "s3Region", "s3SecretKey", "uploadDir"];
require("./config").onReset(function (changed) {
  var recomputeScratch = false;
  for (var i = 0; i < changed.length; i++) {
    if (changed[i] === "uploadDir") {
      uploadDir = nodePath.isAbsolute(config.storage.uploadDir)
        ? config.storage.uploadDir
        : nodePath.resolve(__dirname, "..", config.storage.uploadDir);
      recomputeScratch = true;
    }
    if (changed[i] === "chunkScratchDir") recomputeScratch = true;
    if (_resetKeys.indexOf(changed[i]) !== -1) { _s3 = null; }
  }
  if (recomputeScratch) scratchDir = _resolveScratchDir();
});

function s3Put(key, buffer, extraHeaders) { return getS3().put(key, buffer, extraHeaders); }
function s3Get(key) { return getS3().getStream(key); }
function s3GetBuffer(key) { return getS3().getBuffer(key); }
function s3Delete(key) { return getS3().del(key); }

module.exports = {
  saveFile: saveFile,
  saveRaw: saveRaw,
  getRawBuffer: getRawBuffer,
  getFileStream: getFileStream,
  deleteFile: deleteFile,
  isS3Path: isS3Path,
  s3KeyFromPath: s3KeyFromPath,
  resolveLocalPath: resolveLocalPath,
  resetS3Client: resetS3Client,
  // Chunk scratch API
  saveChunk: saveChunk,
  readChunk: readChunk,
  statChunk: statChunk,
  countChunks: countChunks,
  fileScratchBytes: fileScratchBytes,
  bundleScratchBytes: bundleScratchBytes,
  deleteChunk: deleteChunk,
  removeChunkAssembly: removeChunkAssembly,
  removeBundleChunks: removeBundleChunks,
  listStaleBundleChunkDirs: listStaleBundleChunkDirs,
  removeDirByPath: removeDirByPath,
};
// uploadDir + scratchDir are getters so callers see the updated value after
// config.onReset re-resolves the nodePath. Exporting as primitives captures the
// value at require-time and goes stale on runtime UPLOAD_DIR / CHUNK_SCRATCH_DIR changes.
Object.defineProperty(module.exports, "uploadDir", {
  enumerable: true,
  get: function () { return uploadDir; },
});
Object.defineProperty(module.exports, "scratchDir", {
  enumerable: true,
  get: function () { return scratchDir; },
});
