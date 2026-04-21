/**
 * Storage abstraction — unifies local-disk and S3 backends behind one API.
 *
 * Every consumer (uploads, downloads, backup, migration) imports this
 * module; NO direct fs.* calls against the upload dir anywhere else in
 * the codebase (CLAUDE.md "Storage abstraction" invariant). When local
 * vs S3 switches via config.storage.backend, no call-site changes.
 *
 * Encryption layering:
 *   - saveFile(buffer, path) → generates per-file XChaCha20 key, encrypts
 *     buffer, returns { data, encryptionKey } where encryptionKey is
 *     vault-sealed before it ever leaves this module. Key lives in the DB
 *     alongside the file row; the on-disk/S3 blob is opaque without it.
 *   - saveRaw / getRawBuffer → bypass encryption. Reserved for blobs that
 *     are ALREADY encrypted by a higher layer (backup bundles, vault files).
 *     Never use these for user file content.
 *   - getFileStream(path, key) → passing null key reads legacy unencrypted
 *     blobs (pre-v1.5 data); all new writes are encrypted.
 *
 * Chunk scratch directory is always local-disk regardless of backend
 * (S3 is unsuitable for thousands of transient chunk objects). Consumers
 * should import `storage.uploadDir` rather than re-resolving
 * config.storage.uploadDir themselves — this export is kept in sync with
 * config hot-reload via onReset.
 */
var fs = require("fs");
var path = require("path");
var config = require("./config");
var vault = require("./vault");
var { generateBytes, encryptPacked, decryptPacked } = require("./crypto");
var { Readable } = require("stream");
var S3Client = require("./s3-client");

// Resolve upload directory
var uploadDir = path.isAbsolute(config.storage.uploadDir)
  ? config.storage.uploadDir
  : path.resolve(__dirname, "..", config.storage.uploadDir);

if (config.storage.backend === "local") {
  if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
}

// Resolve chunk scratch directory. Always local-disk regardless of storage
// backend — S3 is unsuitable for thousands of transient chunk objects.
// Default: <uploadDir>/chunks. Override via CHUNK_SCRATCH_DIR env var.
function _resolveScratchDir() {
  var raw = config.storage.chunkScratchDir;
  if (!raw) return path.join(uploadDir, "chunks");
  return path.isAbsolute(raw) ? raw : path.resolve(__dirname, "..", raw);
}
var scratchDir = _resolveScratchDir();

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
  var key = generateBytes(32);
  var packed = encryptPacked(buffer, key);
  var sealedKey = vault.seal(key.toString("base64"));
  return { data: packed, encryptionKey: sealedKey };
}

function decryptBuffer(packed, sealedKey) {
  var key = Buffer.from(vault.unseal(sealedKey), "base64");
  return decryptPacked(packed, key);
}

// ---- Public API ----

/**
 * Save a file — encrypts with XChaCha20-Poly1305, key sealed with ML-KEM-1024 + P-384 hybrid vault.
 * When S3 direct mode is on, skips app encryption and uses S3 SSE instead.
 * Returns { path, encryptionKey } — caller must store encryptionKey in DB.
 */
async function saveFile(buffer, storagePath) {
  // S3 direct mode: no app-level encryption, rely on S3 server-side encryption
  if (config.storage.backend === "s3" && config.storage.s3DirectDownloads) {
    await s3Put(storagePath, buffer, { "x-amz-server-side-encryption": "AES256" });
    return { path: "s3://" + config.storage.s3.bucket + "/" + storagePath, encryptionKey: null };
  }
  var enc = encryptBuffer(buffer);
  if (config.storage.backend === "s3") {
    await s3Put(storagePath, enc.data);
    return { path: "s3://" + config.storage.s3.bucket + "/" + storagePath, encryptionKey: enc.encryptionKey };
  }
  var fullPath = path.join(uploadDir, storagePath);
  var dir = path.dirname(fullPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(fullPath, enc.data);
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
 * Resolve a local (non-S3) storagePath to an absolute filesystem path,
 * gated by a safety check that the result stays within uploadDir.
 *
 * The DB stores both absolute and relative storagePaths depending on when
 * the file was uploaded, and callers need to read/delete the blob without
 * escaping the upload directory. Two sites previously did the ternary
 * (`path.isAbsolute(sp) ? sp : path.join(uploadDir, sp)`) without the
 * resolve+startsWith escape check — exactly the shape of a path-traversal
 * bug. Routing every caller through this helper closes that gap.
 *
 * Returns { ok: true, absPath } on success, or { ok: false, reason } if the
 * path would escape uploadDir. Never throws — callers decide how to react.
 *
 * Do NOT pass S3 paths here — the caller must guard with isS3Path() first.
 */
function resolveLocalPath(storagePath) {
  if (!storagePath || typeof storagePath !== "string") {
    return { ok: false, reason: "empty storagePath" };
  }
  if (isS3Path(storagePath)) {
    return { ok: false, reason: "s3 path — caller should branch on isS3Path" };
  }
  var local = path.isAbsolute(storagePath) ? storagePath : path.join(uploadDir, storagePath);
  var resolved = path.resolve(local);
  var root = path.resolve(uploadDir);
  if (resolved !== root && !resolved.startsWith(root + path.sep)) {
    return { ok: false, reason: "path escapes upload directory: " + storagePath };
  }
  return { ok: true, absPath: resolved };
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
    return fs.createReadStream(path.join(uploadDir, key));
  }
  var packed;
  if (onS3) {
    packed = await s3GetBuffer(key);
  } else {
    packed = fs.readFileSync(path.join(uploadDir, key));
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
  var fullPath = path.join(uploadDir, storagePath);
  var dir = path.dirname(fullPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(fullPath, buffer);
  return storagePath;
}

/**
 * Read a raw buffer from storage — no decryption. For pre-encrypted data (vault files).
 */
async function getRawBuffer(storagePath) {
  if (isS3Path(storagePath)) return s3GetBuffer(s3KeyFromPath(storagePath));
  return fs.readFileSync(path.join(uploadDir, storagePath));
}

async function deleteFile(storagePath) {
  if (isS3Path(storagePath)) return s3Delete(s3KeyFromPath(storagePath));
  var fullPath = path.join(uploadDir, storagePath);
  if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
}

// ---- Chunk scratch API ----
// Layout: <scratchDir>/<bundleShareId>/<fileId>/<chunkIndex>
// All operations are synchronous local-disk I/O — chunks never go to S3.

function _bundleDir(bundleShareId) {
  return path.join(scratchDir, _safeComponent(bundleShareId));
}
function _fileDir(bundleShareId, fileId) {
  return path.join(_bundleDir(bundleShareId), _safeComponent(fileId));
}
function _chunkPath(bundleShareId, fileId, index) {
  var i = Number(index);
  if (!Number.isInteger(i) || i < 0) throw new Error("Invalid chunk index");
  return path.join(_fileDir(bundleShareId, fileId), String(i));
}

function saveChunk(bundleShareId, fileId, index, buffer) {
  var dir = _fileDir(bundleShareId, fileId);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(_chunkPath(bundleShareId, fileId, index), buffer);
}

function readChunk(bundleShareId, fileId, index) {
  return fs.readFileSync(_chunkPath(bundleShareId, fileId, index));
}

function statChunk(bundleShareId, fileId, index) {
  try { return fs.statSync(_chunkPath(bundleShareId, fileId, index)); }
  catch (_e) { return null; }
}

// Returns the count of chunk files currently present for this file. The caller
// uses this to detect "all chunks received".
function countChunks(bundleShareId, fileId) {
  var dir = _fileDir(bundleShareId, fileId);
  if (!fs.existsSync(dir)) return 0;
  try { return fs.readdirSync(dir).length; } catch (_e) { return 0; }
}

function deleteChunk(bundleShareId, fileId, index) {
  try { fs.unlinkSync(_chunkPath(bundleShareId, fileId, index)); } catch (_e) { /* cleanup — chunk may have been removed already */ }
}

// Remove the per-file assembly directory after successful reassembly.
function removeChunkAssembly(bundleShareId, fileId) {
  var dir = _fileDir(bundleShareId, fileId);
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* cleanup — assembly dir may already be gone */ }
}

// Remove the entire bundle chunk directory — used by expiry-cleanup when a
// stale bundle is being purged.
function removeBundleChunks(bundleShareId) {
  var dir = _bundleDir(bundleShareId);
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* cleanup — bundle dir may not exist */ }
}

// Return absolute paths of bundle-level chunk directories whose mtime is
// older than `olderThanMs`. Used by chunk-gc.
function listStaleBundleChunkDirs(olderThanMs) {
  if (!fs.existsSync(scratchDir)) return [];
  var cutoff = Date.now() - olderThanMs;
  var results = [];
  try {
    var entries = fs.readdirSync(scratchDir, { withFileTypes: true });
    for (var i = 0; i < entries.length; i++) {
      if (!entries[i].isDirectory()) continue;
      var p = path.join(scratchDir, entries[i].name);
      try {
        var st = fs.statSync(p);
        if (st.mtimeMs < cutoff) results.push(p);
      } catch (_e) { /* entry disappeared between readdir and stat — skip */ }
    }
  } catch (_e) { /* scratchDir readdir failed — return partial results */ }
  return results;
}

// Remove a bundle chunk directory by absolute path — used by chunk-gc after
// listStaleBundleChunkDirs returns a list.
function removeDirByPath(p) {
  // Defense: ensure the path is under scratchDir before rm -rf.
  var resolvedP = path.resolve(p);
  var resolvedRoot = path.resolve(scratchDir);
  if (!resolvedP.startsWith(resolvedRoot + path.sep) && resolvedP !== resolvedRoot) {
    throw new Error("Refusing to remove path outside scratch dir");
  }
  try { fs.rmSync(resolvedP, { recursive: true, force: true }); } catch (_e) { /* cleanup — target may be gone between list + rm */ }
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
var _resetKeys = ["s3Bucket", "s3Region", "s3AccessKey", "s3SecretKey", "s3Endpoint", "uploadDir"];
require("./config").onReset(function (changed) {
  var recomputeScratch = false;
  for (var i = 0; i < changed.length; i++) {
    if (changed[i] === "uploadDir") {
      uploadDir = path.isAbsolute(config.storage.uploadDir)
        ? config.storage.uploadDir
        : path.resolve(__dirname, "..", config.storage.uploadDir);
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

/**
 * Generate a time-limited pre-signed S3 download URL.
 * Returns null if backend is not S3 or direct downloads are off.
 */
function getPresignedUrl(storagePath, filename, mimeType) {
  if (!isS3Path(storagePath) || !config.storage.s3DirectDownloads) return null;
  var expires = config.storage.s3PresignExpiry || 3600;
  var safeName = (filename || "download").replace(/"/g, '\\"');
  return getS3().signPresigned(s3KeyFromPath(storagePath), expires, {
    contentDisposition: 'attachment; filename="' + safeName + '"',
    contentType: mimeType || "application/octet-stream",
  });
}

module.exports = {
  saveFile: saveFile,
  saveRaw: saveRaw,
  getRawBuffer: getRawBuffer,
  getFileStream: getFileStream,
  deleteFile: deleteFile,
  getPresignedUrl: getPresignedUrl,
  isS3Path: isS3Path,
  s3KeyFromPath: s3KeyFromPath,
  resolveLocalPath: resolveLocalPath,
  resetS3Client: resetS3Client,
  // Chunk scratch API
  saveChunk: saveChunk,
  readChunk: readChunk,
  statChunk: statChunk,
  countChunks: countChunks,
  deleteChunk: deleteChunk,
  removeChunkAssembly: removeChunkAssembly,
  removeBundleChunks: removeBundleChunks,
  listStaleBundleChunkDirs: listStaleBundleChunkDirs,
  removeDirByPath: removeDirByPath,
};
// uploadDir + scratchDir are getters so callers see the updated value after
// config.onReset re-resolves the path. Exporting as primitives captures the
// value at require-time and goes stale on runtime UPLOAD_DIR / CHUNK_SCRATCH_DIR changes.
Object.defineProperty(module.exports, "uploadDir", {
  enumerable: true,
  get: function () { return uploadDir; },
});
Object.defineProperty(module.exports, "scratchDir", {
  enumerable: true,
  get: function () { return scratchDir; },
});
