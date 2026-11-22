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
var stashShim = require("./stash-shim");

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
 * True for a burn-after-read or limited-download file, whose storagePath is
 * "stash:<ref>". Its content lives in the stash store under C.PATHS.STASH_DIR
 * and is read only through consumeEphemeral.
 */
function isStashPath(storagePath) {
  return typeof storagePath === "string" && storagePath.startsWith(STASH_PREFIX);
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
    return { ok: false, reason: "s3 path; the caller branches on isS3Path" };
  }
  if (isStashPath(storagePath)) {
    return { ok: false, reason: "stash path; the caller branches on isStashPath" };
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
  // A burn file spends a read credit when it is read. Refusing here turns a
  // caller that does not know about burn files into an error instead of a
  // silent spend.
  if (isStashPath(storagePath)) {
    throw new Error("burn-after-read content is read only through storage.consumeEphemeral");
  }
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
      refuseSymlink: true, requireFile: true, maxBytes: _LOCAL_READ_CAP,
      errorFor: function (kind) {
        if (kind === "enoent" || kind === "symlink" || kind === "not-file") return _notFound(key);
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
    refuseSymlink: true, requireFile: true, maxBytes: _LOCAL_READ_CAP,
    errorFor: function (kind) {
      if (kind === "enoent" || kind === "symlink" || kind === "not-file") return _notFound(storagePath);
      return undefined;
    },
  });
}

async function deleteFile(storagePath) {
  if (isS3Path(storagePath)) return s3Delete(s3KeyFromPath(storagePath));
  if (isStashPath(storagePath)) { await dropEphemeral(storagePath); return; }
  var r = resolveLocalPath(storagePath);
  if (!r.ok) throw new Error(r.reason);
  // unlink removes the directory entry / symlink itself (never a symlink
  // target), so no O_NOFOLLOW guard is needed here.
  if (nodeFs.existsSync(r.absPath)) nodeFs.unlinkSync(r.absPath);
}

// ---- Burn-after-read store ----
//
// A burn file is pushed to the vendored @blamejs/stash store with a read budget
// (reads: N) and a TTL equal to the bundle's expiry. Each stash read spends one
// credit, and only on a full, digest-verified drain of the stored bytes; a read
// that is destroyed before the end restores the credit.
//
// Stored layout:
//   "HSB1"
//   frame*   [u8 flags][u32 BE length][encryptPacked(chunk, fileKey, aad)]
//   hold     BURN_HOLD_BYTES zero bytes
//
// Each frame holds up to BURN_CHUNK_BYTES of plaintext under XChaCha20-Poly1305
// with a fresh nonce. The AAD binds the chunk index and the final flag (bit 0 of
// flags), so reordering, dropping or truncating frames fails authentication.
//
// The hold region keeps the credit unspent while the response is in flight.
// consumeEphemeral writes every decrypted frame to the response and ends it, and
// only then reads the hold region, which lets stash finish its drain and commit
// the read. The hold region is larger than the bytes the stream pipeline can
// buffer ahead of the reader (about 64 KiB in the file stream plus 16 KiB on each
// side of the verifying transform), so stash cannot reach the end of the entry
// before the response has finished. A client that disconnects first causes the
// read to be destroyed, and stash restores the credit.

var STASH_PREFIX = "stash:";
var STASH_REF = /^v1_[A-Za-z0-9_-]{43}$/;
var BURN_MAGIC = Buffer.from("HSB1", "ascii");
var BURN_CHUNK_BYTES = C.BYTES.kib(64);
// encryptPacked adds a format byte, a 24-byte nonce and a 16-byte tag.
var BURN_FRAME_MAX = BURN_CHUNK_BYTES + C.BYTES.bytes(64);
var BURN_HOLD_BYTES = C.BYTES.mib(1);
var BURN_FLAG_FINAL = 1;
// A claim left by a crashed process is restored after this long, which returns
// the credit of a read the crash interrupted.
var BURN_CLAIM_TIMEOUT_MS = C.TIME.minutes(10);

var _ephemeral = null;

function ephemeral() {
  if (_ephemeral) return _ephemeral;
  nodeFs.mkdirSync(C.PATHS.STASH_DIR, { recursive: true, mode: 0o700 });
  _ephemeral = new stashShim.Stash({
    backend: new stashShim.DiskBackend({ root: C.PATHS.STASH_DIR }),
    digest: "sha3-512",
    onPopFailure: "restore",
    claimTimeout: BURN_CLAIM_TIMEOUT_MS,
  });
  return _ephemeral;
}

function _stashRef(storagePath) {
  if (!isStashPath(storagePath)) throw new Error("not a stash path");
  var ref = storagePath.slice(STASH_PREFIX.length);
  if (!STASH_REF.test(ref)) throw new Error("malformed stash path");
  return ref;
}

// AAD: label, u32 BE chunk index, u8 final flag, u8 layout version.
var BURN_AAD_LABEL = "hs-burn1";
var BURN_AAD_INDEX_OFFSET = BURN_AAD_LABEL.length;
var BURN_AAD_FINAL_OFFSET = BURN_AAD_INDEX_OFFSET + 4;
var BURN_AAD_VERSION_OFFSET = BURN_AAD_FINAL_OFFSET + 1;
var BURN_AAD_LAYOUT_VERSION = 1;

function _burnAad(index, final) {
  var aad = Buffer.alloc(BURN_AAD_VERSION_OFFSET + 1);
  aad.write(BURN_AAD_LABEL, 0, "ascii");
  aad.writeUInt32BE(index, BURN_AAD_INDEX_OFFSET);
  aad.writeUInt8(final ? 1 : 0, BURN_AAD_FINAL_OFFSET);
  aad.writeUInt8(BURN_AAD_LAYOUT_VERSION, BURN_AAD_VERSION_OFFSET);
  return aad;
}

function _burnFrames(buffer, key) {
  var frames = [BURN_MAGIC];
  var count = Math.max(1, Math.ceil(buffer.length / BURN_CHUNK_BYTES));
  for (var i = 0; i < count; i++) {
    var final = i === count - 1;
    var packed = b.crypto.encryptPacked(buffer.subarray(i * BURN_CHUNK_BYTES, (i + 1) * BURN_CHUNK_BYTES), key, _burnAad(i, final));
    var header = Buffer.alloc(5);
    header.writeUInt8(final ? BURN_FLAG_FINAL : 0, 0);
    header.writeUInt32BE(packed.length, 1);
    frames.push(header, packed);
  }
  frames.push(Buffer.alloc(BURN_HOLD_BYTES));
  return frames;
}

// Bytes encryptPacked adds to a chunk (format byte, nonce and tag), measured
// once from the primitive itself.
var _burnPackOverhead = null;
function _packOverhead() {
  if (_burnPackOverhead === null) {
    _burnPackOverhead = b.crypto.encryptPacked(Buffer.alloc(0), b.crypto.generateBytes(C.BYTES.bytes(32)), _burnAad(0, true)).length;
  }
  return _burnPackOverhead;
}

/**
 * The bytes a file occupies in storage, for quota and usage accounting.
 *
 * For a burn file this is the exact length _burnFrames writes for a plaintext
 * of `plaintextSize` bytes: the magic, a 5-byte header and the encryptPacked
 * overhead per chunk (an empty file still has one chunk), and the hold region.
 * For any other file it is `plaintextSize`, which is what the quotas have
 * always counted.
 */
function storedSizeOf(plaintextSize, isBurn) {
  var n = Number(plaintextSize);
  if (!Number.isFinite(n) || n < 0) n = 0;
  if (!isBurn) return n;
  var chunks = Math.max(1, Math.ceil(n / BURN_CHUNK_BYTES));
  return BURN_MAGIC.length + n + chunks * (5 + _packOverhead()) + BURN_HOLD_BYTES;
}

/**
 * The stored size of a file row: its storedSize column when set (burn files),
 * otherwise its plaintext size.
 */
function storedSizeOfRecord(doc) {
  if (!doc) return 0;
  var stored = Number(doc.storedSize);
  if (Number.isFinite(stored) && stored > 0) return stored;
  return Number(doc.size) || 0;
}

/**
 * Store a burn file. reads is the read budget (1..UPLOAD.MAX_BURN_READS_CEILING)
 * and expiresAt the bundle expiry; burn files always expire. Returns
 * { path: "stash:<ref>", encryptionKey, storedSize } for the file row, which
 * seals the first two. storedSize is the byte count written to the store and
 * equals storedSizeOf(buffer.length, true).
 */
async function saveEphemeral(buffer, opts) {
  var reads = opts && opts.reads;
  if (!Number.isInteger(reads) || reads < 1 || reads > C.UPLOAD.MAX_BURN_READS_CEILING) {
    throw new Error("burn read budget out of range");
  }
  var ttl = Date.parse(opts.expiresAt) - Date.now();
  if (!Number.isFinite(ttl) || ttl <= 0) throw new Error("burn file needs a future expiry");
  var key = b.crypto.generateBytes(C.BYTES.bytes(32));
  var frames = _burnFrames(buffer, key);
  var storedSize = 0;
  for (var i = 0; i < frames.length; i++) storedSize += frames[i].length;
  var ref = await ephemeral().push(Readable.from(frames), { reads: reads, ttl: ttl });
  return { path: STASH_PREFIX + ref, encryptionKey: key.toString("base64"), storedSize: storedSize };
}

function _abortError() {
  var e = new Error("client closed the connection before the download finished");
  e.code = "EBURNABORT";
  return e;
}

function _burnIntegrityError(msg) {
  var e = new Error("burn file failed authentication: " + msg);
  e.code = "EBURNINTEGRITY";
  return e;
}

function _writeChunk(sink, chunk) {
  if (sink.destroyed) return Promise.reject(_abortError());
  if (sink.write(chunk)) return Promise.resolve();
  return new Promise(function (resolve, reject) {
    function done() { sink.removeListener("drain", onDrain); sink.removeListener("close", onClose); }
    function onDrain() { done(); resolve(); }
    function onClose() { done(); reject(_abortError()); }
    sink.once("drain", onDrain);
    sink.once("close", onClose);
  });
}

function _endSink(sink) {
  if (sink.destroyed) return Promise.reject(_abortError());
  return new Promise(function (resolve, reject) {
    function onClose() { if (!sink.writableFinished) reject(_abortError()); }
    sink.once("close", onClose);
    sink.end(function () {
      sink.removeListener("close", onClose);
      if (sink.writableFinished) resolve(); else reject(_abortError());
    });
  });
}

/**
 * Spend one read credit of a burn file by streaming it to `sink`.
 *
 * The stash claim is taken before anything is written, so a concurrent reader
 * gets RefClaimed (code ECLAIMED) and an unknown, spent or expired file gets
 * RefNotFound (code ENOREF), both before `onStart` runs. `onStart` writes the
 * response headers. The credit is spent after the response has been ended and
 * flushed. A client disconnect (EBURNABORT) or an authentication failure
 * (EBURNINTEGRITY) before that point destroys the read and leaves the credit in
 * place; the caller then destroys the response.
 *
 * A failure after the whole file has been delivered, such as stored bytes in
 * the hold region failing the store's digest check, destroys the entry instead
 * of restoring the credit, and the read counts.
 *
 * Resolves { readsLeft, damaged } with the credits remaining after this read;
 * `damaged` is true when the entry was destroyed for that reason.
 */
async function consumeEphemeral(storagePath, encryptionKey, opts) {
  var ref = _stashRef(storagePath);
  var key = Buffer.from(String(encryptionKey || ""), "base64");
  var sink = opts.sink;
  var st = ephemeral();
  var src = await st.apply(ref);
  // Listen at once: an unhandled 'error' on a destroyed read would crash the process.
  src.on("error", function () { /* surfaced through the iterator below */ });
  var delivered = false;
  var before;
  try {
    // The claim is held, so no other read can debit the entry until this one
    // commits: the count read now is the balance before this read.
    before = await peekEphemeral(storagePath);
    if (sink.destroyed) throw _abortError();
    opts.onStart();
    var pending = null;
    var index = 0;
    var sawMagic = false;
    var done = false;
    for await (var chunk of src) {
      if (done) continue; // the hold region; draining it lets stash commit the read
      pending = pending ? Buffer.concat([pending, chunk]) : chunk;
      if (!sawMagic) {
        if (pending.length < BURN_MAGIC.length) continue;
        if (!pending.subarray(0, BURN_MAGIC.length).equals(BURN_MAGIC)) throw _burnIntegrityError("bad header");
        pending = pending.subarray(BURN_MAGIC.length);
        sawMagic = true;
      }
      while (!done && pending.length >= 5) {
        var flags = pending.readUInt8(0);
        var len = pending.readUInt32BE(1);
        if ((flags & ~BURN_FLAG_FINAL) !== 0 || len > BURN_FRAME_MAX) throw _burnIntegrityError("bad frame");
        if (pending.length < 5 + len) break;
        var final = (flags & BURN_FLAG_FINAL) !== 0;
        var plain;
        try { plain = b.crypto.decryptPacked(pending.subarray(5, 5 + len), key, _burnAad(index, final)); }
        catch (_e) { throw _burnIntegrityError("chunk " + index); }
        pending = pending.subarray(5 + len);
        index++;
        if (plain.length > 0) await _writeChunk(sink, plain);
        if (final) {
          done = true;
          pending = null;
          await _endSink(sink);
          delivered = true;
        }
      }
    }
    if (!done) throw _burnIntegrityError("truncated");
  } catch (err) {
    // Destroying the read before its drain completes restores the credit.
    if (!src.destroyed) src.destroy();
    if (delivered) {
      try { await dropEphemeral(storagePath); }
      catch (dropErr) { if (!dropErr || dropErr.code !== "ENOREF") throw dropErr; }
      return { readsLeft: 0, damaged: true };
    }
    if (err && (err.code === "EBURNABORT" || err.code === "EBURNINTEGRITY")) throw err;
    if (sink.destroyed && !sink.writableFinished) throw _abortError();
    throw err;
  }
  // The read has committed. The store held `before` credits when it was
  // claimed and no other read could spend one in between.
  return { readsLeft: before === null ? 0 : Math.max(0, before - 1), damaged: false };
}

/**
 * Credits left on a burn file, or null when it has been spent, dropped or has
 * expired. Reads metadata only; spends nothing.
 */
async function peekEphemeral(storagePath) {
  try {
    var entry = await ephemeral().show(_stashRef(storagePath));
    return Number.isInteger(entry.readsLeft) ? entry.readsLeft : null;
  } catch (e) {
    if (e && e.code === "ENOREF") return null;
    throw e;
  }
}

/** Destroy a burn file before its credits run out. Leaves a stash tombstone. */
async function dropEphemeral(storagePath) {
  return ephemeral().drop(_stashRef(storagePath));
}

/** Destroy every expired burn file. Returns the count destroyed. */
async function pruneEphemeral() {
  return ephemeral().prune();
}

/** Close the burn store at shutdown. */
async function closeEphemeral() {
  if (!_ephemeral) return;
  var st = _ephemeral;
  _ephemeral = null;
  await st.close();
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
    refuseSymlink: true, requireFile: true, maxBytes: _LOCAL_READ_CAP,
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
// A change to any of these re-lists the pooled S3 origins (lib/s3-client.js
// trustS3Configs). Requests in flight finish on the connections they started on.
var _poolKeys = ["s3Bucket", "s3Endpoint", "s3Region", "backupS3Bucket", "backupS3Endpoint", "backupS3Region"];
require("./config").onReset(function (changed) {
  var recomputeScratch = false;
  var repool = false;
  for (var i = 0; i < changed.length; i++) {
    if (changed[i] === "uploadDir") {
      uploadDir = nodePath.isAbsolute(config.storage.uploadDir)
        ? config.storage.uploadDir
        : nodePath.resolve(__dirname, "..", config.storage.uploadDir);
      recomputeScratch = true;
    }
    if (changed[i] === "chunkScratchDir") recomputeScratch = true;
    if (_resetKeys.indexOf(changed[i]) !== -1) { _s3 = null; }
    if (_poolKeys.indexOf(changed[i]) !== -1) repool = true;
  }
  if (recomputeScratch) scratchDir = _resolveScratchDir();
  if (repool) S3Client.trustS3Configs([config.storage && config.storage.s3, config.backup && config.backup.s3]);
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
  LOCAL_READ_CAP: _LOCAL_READ_CAP,
  deleteFile: deleteFile,
  isS3Path: isS3Path,
  isStashPath: isStashPath,
  s3KeyFromPath: s3KeyFromPath,
  // Burn-after-read store
  saveEphemeral: saveEphemeral,
  consumeEphemeral: consumeEphemeral,
  peekEphemeral: peekEphemeral,
  dropEphemeral: dropEphemeral,
  pruneEphemeral: pruneEphemeral,
  closeEphemeral: closeEphemeral,
  BURN_HOLD_BYTES: BURN_HOLD_BYTES,
  storedSizeOf: storedSizeOf,
  storedSizeOfRecord: storedSizeOfRecord,
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
