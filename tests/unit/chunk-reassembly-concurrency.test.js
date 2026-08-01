/**
 * E-1 regression: bound concurrent in-memory chunk reassemblies.
 *
 * The final chunk of a chunked upload triggers a Buffer.concat of the whole
 * plaintext file, held across the re-encryption await in
 * saveAndCreateFileRecord. Unbounded concurrency multiplies peak memory by the
 * per-file ceiling — an attacker can pre-stage many uploads (every chunk but the
 * last) and release the final chunks together for a synchronized reassembly
 * burst that the per-subnet rate limit does not bound.
 *
 * handleChunkUpload must refuse the excess with a retryable 503 once
 * C.UPLOAD.MAX_CONCURRENT_REASSEMBLY reassemblies are in flight, and must return
 * the counter to zero when each finalization settles (the try/finally decrement).
 *
 * This drives handleChunkUpload directly with the heavy dependencies stubbed so
 * a reassembly hangs at the save step, holding a slot. With the cap forced low,
 * N+1 concurrent finalizations must yield exactly N in-flight saves and one 503;
 * after release, a second identical batch must behave the same — proving the
 * counter drained back to zero rather than staying pinned at the cap.
 *
 * Fail-before: without the concurrency gate + finally, every finalization would
 * proceed (no 503), or a missing finally would leave the counter pinned and the
 * second batch would 503 all N+1.
 */
const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const fs = require("fs");
const b = require("../../lib/vendor/blamejs");

var testId = b.crypto.generateToken(4);
var testDbPath = path.join(__dirname, "..", "..", "data", "test-reassembly-" + testId + ".db");
process.env.HERMITSTASH_DB_PATH = testDbPath;

Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

var vault = require("../../lib/vault");
var C, storage, fileService, uploadValidator, bundlesRepo, bundleService, audit, config, uploadHandler;

// Saved originals for restore.
var orig = {};
var origCap;
var origIpQuota, origStorageQuota;

// Controllable save: each call parks a resolver so the reassembly hangs, holding
// a concurrency slot until the test releases it.
var savesStarted = 0;
var pendingSaves = [];
function releaseAllSaves() {
  var toRelease = pendingSaves.splice(0);
  toRelease.forEach(function (fn) { fn(); });
}

function flush() {
  // Yield to the event loop several times so every queued handleChunkUpload
  // reaches either the parked save (pending) or the 503 return (settled).
  return (async function () {
    for (var i = 0; i < 8; i++) { await new Promise(function (r) { setImmediate(r); }); }
  })();
}

before(async function () {
  await vault.init();
  C = require("../../lib/constants");
  storage = require("../../lib/storage");
  fileService = require("../../app/domain/uploads/file.service");
  uploadValidator = require("../../app/http/validators/upload.validator");
  bundlesRepo = require("../../app/data/repositories/bundles.repo");
  bundleService = require("../../app/domain/uploads/bundle.service");
  audit = require("../../lib/audit");
  config = require("../../lib/config");
  uploadHandler = require("../../app/domain/uploads/upload.handler");

  // Force the cap low so the batch stays small and fast.
  origCap = C.UPLOAD.MAX_CONCURRENT_REASSEMBLY;
  C.UPLOAD.MAX_CONCURRENT_REASSEMBLY = 2;
  assert.strictEqual(C.UPLOAD.MAX_CONCURRENT_REASSEMBLY, 2, "cap must be mutable for the test");

  // Neutralize the quota checks so checkAllQuotas is a cheap pass with no
  // per-IP reservation (ownerId=null bundle + these two configs at 0).
  origIpQuota = config.publicIpQuotaBytes;
  origStorageQuota = config.storageQuotaBytes;
  config.publicIpQuotaBytes = 0;
  config.storageQuotaBytes = 0;

  // Stub the storage scratch layer so no real chunk files are needed.
  orig.statChunk = storage.statChunk;
  orig.fileScratchBytes = storage.fileScratchBytes;
  orig.bundleScratchBytes = storage.bundleScratchBytes;
  orig.saveChunk = storage.saveChunk;
  orig.countChunks = storage.countChunks;
  orig.readChunk = storage.readChunk;
  orig.removeChunkAssembly = storage.removeChunkAssembly;
  storage.statChunk = function () { return { size: 100 }; };
  storage.fileScratchBytes = function () { return 0; };
  storage.bundleScratchBytes = function () { return 0; };
  storage.saveChunk = function () {};
  storage.countChunks = function () { return 1; };
  storage.readChunk = function () { return Buffer.from("chunkbytes"); };
  storage.removeChunkAssembly = function () {};

  // Stub the validators to unconditionally pass.
  orig.validateChunk = uploadValidator.validateChunk;
  orig.validateFile = uploadValidator.validateFile;
  orig.validateMagicBytes = uploadValidator.validateMagicBytes;
  orig.safeServeMime = uploadValidator.safeServeMime;
  orig.validateBundleLimits = uploadValidator.validateBundleLimits;
  uploadValidator.validateChunk = function () { return { valid: true }; };
  uploadValidator.validateFile = function () { return { valid: true }; };
  uploadValidator.validateMagicBytes = function () { return { valid: true }; };
  uploadValidator.safeServeMime = function () { return "application/octet-stream"; };
  uploadValidator.validateBundleLimits = function () { return { valid: true }; };

  // Stub the post-write repo + storage-quota calls to non-blocking passes.
  orig.incrementCounters = bundlesRepo.incrementCounters;
  bundlesRepo.incrementCounters = function () { return { receivedFiles: 1, totalSize: 100 }; };
  orig.checkStorageQuota = bundleService.checkStorageQuota;
  bundleService.checkStorageQuota = function () {};
  orig.auditLog = audit.log;
  audit.log = function () {};

  // The save parks until released — this is what holds a concurrency slot.
  orig.saveAndCreateFileRecord = fileService.saveAndCreateFileRecord;
  fileService.saveAndCreateFileRecord = function () {
    savesStarted++;
    return new Promise(function (resolve) {
      pendingSaves.push(function () {
        resolve({ shareId: "sid", checksum: "sum", saved: { path: "p" }, doc: { _id: "d" } });
      });
    });
  };
});

after(function () {
  if (C) C.UPLOAD.MAX_CONCURRENT_REASSEMBLY = origCap;
  if (config) { config.publicIpQuotaBytes = origIpQuota; config.storageQuotaBytes = origStorageQuota; }
  if (storage) {
    storage.statChunk = orig.statChunk;
    storage.fileScratchBytes = orig.fileScratchBytes;
    storage.bundleScratchBytes = orig.bundleScratchBytes;
    storage.saveChunk = orig.saveChunk;
    storage.countChunks = orig.countChunks;
    storage.readChunk = orig.readChunk;
    storage.removeChunkAssembly = orig.removeChunkAssembly;
  }
  if (uploadValidator) {
    uploadValidator.validateChunk = orig.validateChunk;
    uploadValidator.validateFile = orig.validateFile;
    uploadValidator.validateMagicBytes = orig.validateMagicBytes;
    uploadValidator.safeServeMime = orig.safeServeMime;
    uploadValidator.validateBundleLimits = orig.validateBundleLimits;
  }
  if (bundlesRepo) bundlesRepo.incrementCounters = orig.incrementCounters;
  if (bundleService) bundleService.checkStorageQuota = orig.checkStorageQuota;
  if (audit) audit.log = orig.auditLog;
  if (fileService) fileService.saveAndCreateFileRecord = orig.saveAndCreateFileRecord;

  try { fs.unlinkSync(testDbPath); } catch {}
  try { fs.unlinkSync(testDbPath + "-shm"); } catch {}
  try { fs.unlinkSync(testDbPath + "-wal"); } catch {}
  try { fs.unlinkSync(testDbPath + ".enc"); } catch {}
});

function makeCtx(i) {
  return {
    bundle: { _id: "bundle1", shareId: "share1", ownerId: null, teamId: null, bundleType: "snapshot", receivedFiles: 0, expectedFiles: 1 },
    chunk: { data: Buffer.from("finalchunk-" + i) },
    fields: { chunkIndex: "0", totalChunks: "1", fileId: "file" + i, filename: "f" + i + ".bin", relativePath: "f" + i + ".bin", mimeType: "application/octet-stream" },
    limits: { maxFileSize: 0, maxFiles: 0, maxBundleSize: 0, allowedExtensions: [] },
    uploadedBy: "public", uploaderEmail: null, expiresAt: null, auditSuffix: "", req: {},
  };
}

// Fire n concurrent finalizations; return the settled outcomes (undefined =
// still parked at the save) and the aggregate promise for later awaiting.
async function fireBatch(n) {
  var outcomes = new Array(n).fill(undefined);
  var proms = [];
  for (var i = 0; i < n; i++) {
    (function (idx) {
      var p = uploadHandler.handleChunkUpload(makeCtx("b" + n + "-" + idx))
        .then(function (r) { outcomes[idx] = r; });
      proms.push(p);
    })(i);
  }
  await flush();
  return { outcomes: outcomes, all: Promise.all(proms) };
}

describe("chunked-upload reassembly concurrency gate (E-1)", function () {
  it("admits up to the cap and 503s the overflow, then drains back to zero", async function () {
    var cap = C.UPLOAD.MAX_CONCURRENT_REASSEMBLY; // 2

    // ---- Round 1: cap+1 concurrent finalizations ----
    savesStarted = 0;
    var r1 = await fireBatch(cap + 1);

    var settled1 = r1.outcomes.filter(function (o) { return o !== undefined; });
    var busy1 = settled1.filter(function (o) { return o && o.status === 503; });
    assert.strictEqual(settled1.length, 1, "exactly one call settles immediately (the 503)");
    assert.strictEqual(busy1.length, 1, "the settled call is the retryable 503");
    assert.match(busy1[0].error, /busy/i, "503 body signals a busy/retry condition");
    assert.strictEqual(savesStarted, cap, "exactly cap reassemblies reached the save (held a slot)");

    // Release the parked saves and let the finalizations complete.
    releaseAllSaves();
    await r1.all;
    // Every non-503 outcome is now a success (no rollback fired).
    var succeeded1 = r1.outcomes.filter(function (o) { return o && o.success === true; });
    assert.strictEqual(succeeded1.length, cap, "the admitted reassemblies all succeeded after release");

    // ---- Round 2: identical batch. If the finally decrement ran, the counter is
    // back at zero and this behaves exactly like round 1. A missing finally would
    // leave the counter pinned at cap and 503 ALL cap+1. ----
    savesStarted = 0;
    var r2 = await fireBatch(cap + 1);

    var settled2 = r2.outcomes.filter(function (o) { return o !== undefined; });
    var busy2 = settled2.filter(function (o) { return o && o.status === 503; });
    assert.strictEqual(busy2.length, 1, "counter drained to zero: second batch again admits cap and 503s one");
    assert.strictEqual(savesStarted, cap, "second batch again admits exactly cap reassemblies");

    releaseAllSaves();
    await r2.all;
  });
});
