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
 *     buffer, returns { path, encryptionKey } where encryptionKey is the
 *     plaintext base64 key. The DB layer (lib/field-crypto.js) seals it at
 *     rest, AAD-bound to (table, _id, column), when the file row is written.
 *     Key lives in the DB alongside the file row; the on-disk/S3 blob is
 *     opaque without it. getFileStream receives the field-crypto-unsealed
 *     plaintext key back from the row.
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
 * Save a file — encrypts with XChaCha20-Poly1305 under a fresh per-file key.
 * When S3 direct mode is on, skips app encryption and uses S3 SSE instead.
 * Returns { path, encryptionKey } where encryptionKey is the plaintext base64
 * key — the caller stores it on the file row and the DB layer seals it at rest.
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
  var fullPath = nodePath.join(uploadDir, storagePath);
  var dir = nodePath.dirname(fullPath);
  if (!nodeFs.existsSync(dir)) nodeFs.mkdirSync(dir, { recursive: true });
  nodeFs.writeFileSync(fullPath, enc.data);
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
  var local = nodePath.isAbsolute(storagePath) ? storagePath : nodePath.join(uploadDir, storagePath);
  var resolved = nodePath.resolve(local);
  var root = nodePath.resolve(uploadDir);
  if (resolved !== root && !resolved.startsWith(root + nodePath.sep)) {
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
    return nodeFs.createReadStream(nodePath.join(uploadDir, key));
  }
  var packed;
  if (onS3) {
    packed = await s3GetBuffer(key);
  } else {
    packed = nodeFs.readFileSync(nodePath.join(uploadDir, key));
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
  var fullPath = nodePath.join(uploadDir, storagePath);
  var dir = nodePath.dirname(fullPath);
  if (!nodeFs.existsSync(dir)) nodeFs.mkdirSync(dir, { recursive: true });
  nodeFs.writeFileSync(fullPath, buffer);
  return storagePath;
}

/**
 * Read a raw buffer from storage — no decryption. For pre-encrypted data (vault files).
 */
async function getRawBuffer(storagePath) {
  if (isS3Path(storagePath)) return s3GetBuffer(s3KeyFromPath(storagePath));
  return nodeFs.readFileSync(nodePath.join(uploadDir, storagePath));
}

async function deleteFile(storagePath) {
  if (isS3Path(storagePath)) return s3Delete(s3KeyFromPath(storagePath));
  var fullPath = nodePath.join(uploadDir, storagePath);
  if (nodeFs.existsSync(fullPath)) nodeFs.unlinkSync(fullPath);
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
  var i = Number(index);
  if (!Number.isInteger(i) || i < 0) throw new Error("Invalid chunk index");
  return nodePath.join(_fileDir(bundleShareId, fileId), String(i));
}

function saveChunk(bundleShareId, fileId, index, buffer) {
  var dir = _fileDir(bundleShareId, fileId);
  if (!nodeFs.existsSync(dir)) nodeFs.mkdirSync(dir, { recursive: true });
  nodeFs.writeFileSync(_chunkPath(bundleShareId, fileId, index), buffer);
}

function readChunk(bundleShareId, fileId, index) {
  return nodeFs.readFileSync(_chunkPath(bundleShareId, fileId, index));
}

function statChunk(bundleShareId, fileId, index) {
  try { return nodeFs.statSync(_chunkPath(bundleShareId, fileId, index)); }
  catch (_e) { return null; }
}

// Returns the count of chunk files currently present for this file. The caller
// uses this to detect "all chunks received".
function countChunks(bundleShareId, fileId) {
  var dir = _fileDir(bundleShareId, fileId);
  if (!nodeFs.existsSync(dir)) return 0;
  try { return nodeFs.readdirSync(dir).length; } catch (_e) { return 0; }
}

function deleteChunk(bundleShareId, fileId, index) {
  try { nodeFs.unlinkSync(_chunkPath(bundleShareId, fileId, index)); } catch (_e) { /* cleanup — chunk may have been removed already */ }
}

// Remove the per-file assembly directory after successful reassembly.
function removeChunkAssembly(bundleShareId, fileId) {
  var dir = _fileDir(bundleShareId, fileId);
  try { nodeFs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* cleanup — assembly dir may already be gone */ }
}

// Remove the entire bundle chunk directory — used by expiry-cleanup when a
// stale bundle is being purged.
function removeBundleChunks(bundleShareId) {
  var dir = _bundleDir(bundleShareId);
  try { nodeFs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* cleanup — bundle dir may not exist */ }
}

// Return absolute paths of bundle-level chunk directories whose mtime is
// older than `olderThanMs`. Used by chunk-gc.
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
        var st = nodeFs.statSync(p);
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

/**
 * Generate a time-limited pre-signed S3 download URL.
 * Returns null if backend is not S3 or direct downloads are off.
 */
function getPresignedUrl(storagePath, filename, mimeType) {
  if (!isS3Path(storagePath) || !config.storage.s3DirectDownloads) return null;
  var expires = config.storage.s3PresignExpiry || 3600; // allow:raw-time-literal — S3 presign expiresIn is seconds (1h floor), not ms
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
