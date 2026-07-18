// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.storage — the classification-routing, residency-validating object-
 * storage layer above b.objectStore. Exercises the config-normalization
 * and dispatch error branches (unknown backend, classification mismatch,
 * refuse-unclassified, no-backend-for-classification, empty registry),
 * the encrypt/decrypt round-trip and its fail-closed KEY_REQUIRED guard,
 * the raw/delete/exists surface, the presign success + rejection paths
 * (sigv4 signing is pure-local, no network), boot-time residency
 * validation, and the chunkScratch resumable-upload primitive with its
 * assemblyId / chunkIndex adversarial-input rejections.
 *
 * Run standalone: `node test/layer-0-primitives/storage.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b     = helpers.b;
var fs    = helpers.fs;
var os    = helpers.os;
var path  = helpers.path;
var check = helpers.check;
var C     = require("../../lib/constants");

// ---- small local utilities (not mocks — assertion + tmp-dir plumbing) ----

var _tmpDirs = [];
function _mkTmp(tag) {
  var d = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-storage-" + tag + "-"));
  _tmpDirs.push(d);
  return d;
}
function _cleanupTmp() {
  while (_tmpDirs.length) {
    var d = _tmpDirs.pop();
    try { fs.rmSync(d, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

// expectThrow — drives fn (sync throw OR async rejection) and asserts the
// framework error code. Not a fixture: a thin assertion wrapper over check().
async function expectThrow(label, code, fn) {
  var threw = null;
  try { await fn(); } catch (e) { threw = e; }
  check(label + " throws " + code, threw && threw.code === code);
}

// ---- getBackend escape-hatch (original coverage, retained) ----

async function testGetBackend() {
  var uploadDir = _mkTmp("getbackend");
  b.storage._resetForTest();
  try {
    // Before init, any file-op accessor refuses.
    var preThrew = null;
    try { b.storage.getBackend("default"); } catch (e) { preThrew = e; }
    check("storage.getBackend before init throws NOT_INITIALIZED",
          preThrew && preThrew.code === "NOT_INITIALIZED");

    b.storage.init({ backend: "local", uploadDir: uploadDir });

    var backend = b.storage.getBackend("default");
    check("storage.getBackend returns the registered backend instance",
          backend && typeof backend === "object");
    check("storage.getBackend backend reports protocol 'local'",
          backend.protocol === "local");
    check("storage.getBackend unknown name returns null",
          b.storage.getBackend("does-not-exist") === null);

    // The escape-hatch handle corresponds to what listBackends reports.
    var listed = b.storage.listBackends();
    check("storage.getBackend default name matches listBackends",
          listed.length === 1 && listed[0].name === "default" && listed[0].protocol === "local");
    check("storage.listBackends surfaces the resolved local rootDir",
          typeof listed[0].rootDir === "string" && listed[0].rootDir.length > 0);
    check("storage.listBackends surfaces breakerState",
          typeof listed[0].breakerState === "string");
    // Same registry object on repeat lookups (not a fresh build per call).
    check("storage.getBackend returns a stable handle across calls",
          b.storage.getBackend("default") === backend);
  } finally {
    try { b.storage._resetForTest(); } catch (_e) { /* best-effort */ }
    _cleanupTmp();
  }
}

// ---- init config normalization + validation ----

async function testInitConfigValidation() {
  var uploadDir = _mkTmp("initcfg");
  b.storage._resetForTest();
  try {
    // Missing options entirely.
    await expectThrow("storage.init(undefined)", "INVALID_CONFIG",
      function () { b.storage.init(undefined); });

    // 's3' was renamed to 'sigv4' — the rename is a hard error, not a silent alias.
    await expectThrow("storage.init { backend: 's3' }", "INVALID_CONFIG",
      function () { b.storage.init({ backend: "s3", uploadDir: uploadDir }); });

    // Unknown single-backend name.
    await expectThrow("storage.init unknown backend", "INVALID_CONFIG",
      function () { b.storage.init({ backend: "frobnicate", uploadDir: uploadDir }); });

    // Neither { backend } nor { backends }.
    await expectThrow("storage.init with no backend/backends", "INVALID_CONFIG",
      function () { b.storage.init({ defaultClassification: "public" }); });

    // Multi-backend shape sets defaultClassification + refuseUnclassified.
    b.storage._resetForTest();
    b.storage.init({
      backends: {
        "eu-private": { protocol: "local", rootDir: path.join(uploadDir, "eu"), classifications: ["personal"], residencyTag: "EU" },
        "us-ops":     { protocol: "local", rootDir: path.join(uploadDir, "us"), classifications: ["operational", "public"], residencyTag: "US" },
      },
      defaultClassification: "operational",
      refuseUnclassified:    true,
    });
    var listed = b.storage.listBackends();
    check("storage.init multi-backend registers both backends", listed.length === 2);

    // Idempotent: a second init after a successful one is a no-op.
    b.storage.init({ backend: "local", uploadDir: uploadDir });
    check("storage.init is idempotent (second call is a no-op)",
          b.storage.listBackends().length === 2);

    // Single remote-protocol shorthand normalizes to a forwarded default backend.
    b.storage._resetForTest();
    b.storage.init({ backend: "http-put", baseUrl: "https://uploads.example.com/put" });
    var httpListed = b.storage.listBackends();
    check("storage.init http-put shorthand forwards a single default backend",
          httpListed.length === 1 && httpListed[0].name === "default" && httpListed[0].protocol === "http-put");
  } finally {
    try { b.storage._resetForTest(); } catch (_e) { /* best-effort */ }
    _cleanupTmp();
  }
}

// ---- backend-selection dispatch errors (_pickBackend) ----

async function testBackendDispatchErrors() {
  var uploadDir = _mkTmp("dispatch");
  b.storage._resetForTest();
  try {
    b.storage.init({
      backends: {
        "eu-private": { protocol: "local", rootDir: path.join(uploadDir, "eu"), classifications: ["personal"], residencyTag: "EU" },
        "us-ops":     { protocol: "local", rootDir: path.join(uploadDir, "us"), classifications: ["operational", "public"], residencyTag: "US" },
      },
      defaultClassification: "operational",
    });
    var body = Buffer.from("dispatch-bytes");

    // Explicit backend that doesn't exist.
    await expectThrow("saveRaw explicit unknown backend", "UNKNOWN_BACKEND",
      function () { return b.storage.saveRaw(body, "k1", { backend: "no-such" }); });

    // Explicit backend that doesn't serve the requested classification.
    await expectThrow("saveRaw explicit backend classification mismatch", "CLASSIFICATION_MISMATCH",
      function () { return b.storage.saveRaw(body, "k2", { backend: "eu-private", classification: "operational" }); });

    // A classification no backend serves.
    await expectThrow("saveRaw classification with no serving backend", "NO_BACKEND_FOR_CLASSIFICATION",
      function () { return b.storage.saveRaw(body, "k3", { classification: "top-secret" }); });

    // Explicit backend + matching classification routes correctly.
    var savedEu = await b.storage.saveRaw(body, "eu/doc.bin", { backend: "eu-private", classification: "personal" });
    check("saveRaw explicit backend+classification routes to eu-private", savedEu.backend === "eu-private");

    // No classification → defaultClassification routes to the serving backend.
    var savedDefault = await b.storage.saveRaw(body, "ops/doc.bin", {});
    check("saveRaw no-classification routes via defaultClassification to us-ops", savedDefault.backend === "us-ops");
    check("saveRaw returns versionId null on a non-versioning backend", savedDefault.versionId === null);

    // Explicit classification that a backend serves routes by classification.
    var savedPublic = await b.storage.saveRaw(body, "pub/logo.bin", { classification: "public" });
    check("saveRaw classification 'public' routes to us-ops", savedPublic.backend === "us-ops");

    // refuseUnclassified: a call with no classification and no explicit backend refuses.
    b.storage._resetForTest();
    b.storage.init({
      backends: {
        "us-ops": { protocol: "local", rootDir: path.join(uploadDir, "us2"), classifications: ["operational"], residencyTag: "US" },
      },
      refuseUnclassified: true,
    });
    await expectThrow("saveRaw under refuseUnclassified without classification", "UNCLASSIFIED",
      function () { return b.storage.saveRaw(body, "k4", {}); });

    // An empty backend registry is a valid-but-degenerate config; dispatch fails closed.
    b.storage._resetForTest();
    b.storage.init({ backends: {} });
    await expectThrow("saveRaw with an empty backend registry", "NO_BACKENDS",
      function () { return b.storage.saveRaw(body, "k5", {}); });
  } finally {
    try { b.storage._resetForTest(); } catch (_e) { /* best-effort */ }
    _cleanupTmp();
  }
}

// ---- encrypt/decrypt round-trip + body validation ----

async function testEncryptionRoundTripAndBodyValidation() {
  var uploadDir = _mkTmp("encrypt");
  b.storage._resetForTest();
  try {
    b.storage.init({ backend: "local", uploadDir: uploadDir });

    // Pre-init guard is exercised on a fresh reset (drives _requireInit's throw).
    b.storage._resetForTest();
    await expectThrow("saveFile before init", "NOT_INITIALIZED",
      function () { return b.storage.saveFile(Buffer.from("x"), "k"); });
    b.storage.init({ backend: "local", uploadDir: uploadDir });

    // Non-Buffer bodies are refused before any encryption / write.
    await expectThrow("saveFile non-Buffer body", "INVALID_BODY",
      function () { return b.storage.saveFile("not-a-buffer", "k"); });
    await expectThrow("saveRaw non-Buffer body", "INVALID_BODY",
      function () { return b.storage.saveRaw({}, "k"); });

    // Full encrypted round-trip: saveFile seals a per-file key; getFileBuffer
    // unseals + verifies the AEAD tag before releasing plaintext.
    var plaintext = Buffer.from("invoice pdf bytes — sensitive");
    var saved = await b.storage.saveFile(plaintext, "invoices/001.pdf");
    check("saveFile returns a sealed encryptionKey", typeof saved.encryptionKey === "string" && saved.encryptionKey.length > 0);
    check("saveFile returns the storedPath", saved.storedPath === "invoices/001.pdf");

    var roundTrip = await b.storage.getFileBuffer("invoices/001.pdf", saved.encryptionKey);
    check("getFileBuffer round-trips the plaintext", roundTrip.equals(plaintext));

    // Ciphertext on disk is NOT the plaintext (encryption actually happened).
    var onDisk = await b.storage.getRawBuffer("invoices/001.pdf");
    check("stored bytes are ciphertext, not plaintext", !onDisk.equals(plaintext));

    // getFileStream buffers-then-streams the same verified plaintext.
    var stream = await b.storage.getFileStream("invoices/001.pdf", saved.encryptionKey);
    var chunks = [];
    for await (var chunk of stream) chunks.push(chunk);
    check("getFileStream yields the decrypted plaintext", Buffer.concat(chunks).equals(plaintext));

    // Fail-closed: a decrypt attempt without the sealed key is refused (no
    // legacy plaintext fallback).
    await b.storage.saveRaw(Buffer.from("raw-envelope-bytes"), "raw/blob.bin");
    await expectThrow("getFileBuffer without a sealed key", "KEY_REQUIRED",
      function () { return b.storage.getFileBuffer("raw/blob.bin", undefined); });
  } finally {
    try { b.storage._resetForTest(); } catch (_e) { /* best-effort */ }
    _cleanupTmp();
  }
}

// ---- saveRaw / getRawBuffer / deleteFile / exists ----

async function testRawDeleteExists() {
  var uploadDir = _mkTmp("rawops");
  b.storage._resetForTest();
  try {
    b.storage.init({ backend: "local", uploadDir: uploadDir });

    // saveRaw skips the envelope — getRawBuffer returns byte-for-byte.
    var raw = Buffer.from("public-cdn-bytes");
    var savedRaw = await b.storage.saveRaw(raw, "assets/logo.png");
    check("saveRaw stores to the default backend", savedRaw.backend === "default");
    var fetched = await b.storage.getRawBuffer("assets/logo.png");
    check("getRawBuffer returns raw bytes unchanged", fetched.equals(raw));

    // exists is a HEAD-style probe.
    check("exists returns true for a present key", (await b.storage.exists("assets/logo.png")) === true);
    check("exists returns false for an absent key", (await b.storage.exists("assets/missing.png")) === false);

    // A non-NOT_FOUND backend error (traversal-escaping key) propagates rather
    // than being swallowed as "doesn't exist".
    await expectThrow("exists propagates a non-NOT_FOUND backend error", "INVALID_KEY",
      function () { return b.storage.exists("../escape.png"); });

    // deleteFile: true when present, false when already absent.
    check("deleteFile returns true when the object existed", (await b.storage.deleteFile("assets/logo.png")) === true);
    check("deleteFile returns false when already absent", (await b.storage.deleteFile("assets/logo.png")) === false);

    // A versioned delete against a filesystem backend is refused — a local file
    // has no version history to erase.
    await b.storage.saveRaw(raw, "assets/keep.png");
    await expectThrow("deleteFile versionId on a filesystem backend", "VERSIONID_UNSUPPORTED",
      function () { return b.storage.deleteFile("assets/keep.png", { versionId: "v-does-not-exist" }); });
  } finally {
    try { b.storage._resetForTest(); } catch (_e) { /* best-effort */ }
    _cleanupTmp();
  }
}

// ---- listVersions unsupported (local) + presign paths (sigv4 = offline signing) ----

async function testListVersionsAndPresign() {
  var uploadDir = _mkTmp("presign");
  b.storage._resetForTest();
  try {
    // A filesystem backend has no version surface — listVersions refuses
    // rather than silently returning the current-only view.
    b.storage.init({ backend: "local", uploadDir: uploadDir });
    await expectThrow("listVersions on a filesystem backend", "VERSIONS_UNSUPPORTED",
      function () { return b.storage.listVersions("prefix/"); });

    // Calling a presign primitive on a local backend surfaces PRESIGN_NOT_SUPPORTED.
    await expectThrow("presignedUploadUrl on a local backend", "PRESIGN_NOT_SUPPORTED",
      function () { b.storage.presignedUploadUrl("k", {}); });

    // sigv4 presigning is pure-local HMAC signing — no network. Drives the
    // success + audit-emit path for all three presign surfaces.
    b.storage._resetForTest();
    b.storage.init({
      backends: {
        "us-ops": {
          protocol:        "sigv4",
          endpoint:        "https://s3.us-east-1.amazonaws.com",
          region:          "us-east-1",
          bucket:          "uploads",
          accessKeyId:     "AKIAEXAMPLE",
          secretAccessKey: "secret",
          classifications: ["operational", "public"],
          residencyTag:    "US",
        },
      },
    });

    // Empty key is refused before any signing work.
    await expectThrow("presignedUploadUrl empty key", "INVALID_KEY",
      function () { b.storage.presignedUploadUrl("", { backend: "us-ops" }); });
    await expectThrow("presignedUploadPolicy empty key", "INVALID_KEY",
      function () { b.storage.presignedUploadPolicy("", { backend: "us-ops" }); });

    var up = b.storage.presignedUploadUrl("incoming/x.bin", { backend: "us-ops", expiresInSec: 300 });
    check("presignedUploadUrl returns a PUT URL", up.method === "PUT" && typeof up.url === "string" && up.url.indexOf("X-Amz-Signature") !== -1);
    check("presignedUploadUrl carries an expiresAt", typeof up.expiresAt === "number");

    var down = b.storage.presignedDownloadUrl("public/logo.png", {
      backend:      "us-ops",
      expiresInSec: 60,
      responseHeaders: { contentDisposition: 'attachment; filename="logo.png"' },
    });
    check("presignedDownloadUrl returns a GET URL", down.method === "GET");

    var policy = b.storage.presignedUploadPolicy("user/avatar.png", {
      backend:      "us-ops",
      maxBytes:     C.BYTES.mib(5),
      expiresInSec: 300,
      contentType:  "image/png",
    });
    check("presignedUploadPolicy returns a POST policy", policy.method === "POST");
    check("presignedUploadPolicy bakes in the maxBytes cap", policy.maxBytes === C.BYTES.mib(5));
    check("presignedUploadPolicy reports an enforcement mode", typeof policy.enforcement === "string" && policy.enforcement.length > 0);
  } finally {
    try { b.storage._resetForTest(); } catch (_e) { /* best-effort */ }
    _cleanupTmp();
  }
}

// ---- boot-time residency validation (needs a db with dataResidency) ----

async function testResidencyValidation() {
  var tmpDir = _mkTmp("residency");
  process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
  helpers.setTestPassphraseEnv();
  b.cluster._resetForTest();
  b.audit._resetForTest();
  b.vault._resetForTest();
  b.db._resetForTest();
  await b.vault.init({ dataDir: tmpDir });
  await b.db.init({
    dataDir:             tmpDir,
    tmpDir:              path.join(tmpDir, "tmpfs"),
    allowNonTmpfsTmpDir: true,
    schema:              [],
    dataResidency:       { region: "EU", allowedStorageRegions: ["EU"] },
  });
  try {
    var euDir = path.join(tmpDir, "eu");
    var usDir = path.join(tmpDir, "us");
    var pubDir = path.join(tmpDir, "pub");

    // A backend serving 'personal' data outside the app's residency region
    // fails the deployment at boot instead of leaking on first write.
    b.storage._resetForTest();
    await expectThrow("init residency violation (personal served from US, app region EU)", "RESIDENCY_VIOLATION",
      function () {
        b.storage.init({
          backends: { "bad": { protocol: "local", rootDir: euDir, classifications: ["personal"], residencyTag: "US" } },
        });
      });

    // defaultClassification 'personal' with no backend that declares 'personal'.
    b.storage._resetForTest();
    await expectThrow("init defaultClassification=personal with no personal backend", "NO_PERSONAL_BACKEND",
      function () {
        b.storage.init({
          backends: { "pub": { protocol: "local", rootDir: pubDir, classifications: ["public"], residencyTag: "EU" } },
          defaultClassification: "personal",
        });
      });

    // A correctly-tagged personal backend inside the region passes validation.
    b.storage._resetForTest();
    b.storage.init({
      backends: { "eu-private": { protocol: "local", rootDir: usDir, classifications: ["personal"], residencyTag: "EU" } },
      defaultClassification: "personal",
    });
    check("init passes with an in-region personal backend", b.storage.listBackends().length === 1);

    // A wildcard ('*') backend serves personal implicitly; validated the same way.
    b.storage._resetForTest();
    b.storage.init({
      backends: { "any": { protocol: "local", rootDir: path.join(tmpDir, "any"), classifications: ["*"], residencyTag: "EU" } },
    });
    check("init passes with an in-region wildcard backend", b.storage.listBackends().length === 1);
  } finally {
    // Drain + anchor the audit chain BEFORE close so close()'s own
    // fire-and-forget checkpoint no-ops (mirrors teardownTestDb ordering and
    // avoids a checkpoint straddling the db boundary).
    try { await b.audit.flush(); } catch (_e) { /* best-effort */ }
    try { await b.audit.checkpoint({ skipIfUnchanged: true }); } catch (_e) { /* best-effort */ }
    try { b.db.close(); } catch (_e) { /* best-effort */ }
    try { b.storage._resetForTest(); } catch (_e) { /* best-effort */ }
    b.db._resetForTest();
    b.vault._resetForTest();
    b.audit._resetForTest();
    b.cluster._resetForTest();
    _cleanupTmp();
  }
}

// ---- chunkScratch adversarial-input validation ----

async function testChunkScratchValidation() {
  var uploadDir = _mkTmp("chunkval");
  b.storage._resetForTest();
  try {
    // chunkScratch itself is gated on init.
    await expectThrow("chunkScratch before init", "NOT_INITIALIZED",
      function () { b.storage.chunkScratch(); });

    b.storage.init({ backend: "local", uploadDir: uploadDir });

    // Numeric opts are validated at construction.
    await expectThrow("chunkScratch negative maxChunkBytes", "INVALID_ARGUMENT",
      function () { b.storage.chunkScratch({ maxChunkBytes: -1 }); });
    await expectThrow("chunkScratch zero staleAfterMs", "INVALID_ARGUMENT",
      function () { b.storage.chunkScratch({ staleAfterMs: 0 }); });

    // rootKeyPrefix with trailing slashes is normalized (linear strip).
    var cs = b.storage.chunkScratch({ rootKeyPrefix: "uploads/scratch///" });
    var data = Buffer.from("chunk-bytes");

    // saveChunk arg-shape + assemblyId rejections.
    await expectThrow("saveChunk non-object args", "INVALID_ARGUMENT",
      function () { return cs.saveChunk(null); });
    await expectThrow("saveChunk empty assemblyId", "INVALID_ARGUMENT",
      function () { return cs.saveChunk({ assemblyId: "", chunkIndex: 0, data: data }); });
    await expectThrow("saveChunk oversize assemblyId", "INVALID_ARGUMENT",
      function () { return cs.saveChunk({ assemblyId: "a".repeat(129), chunkIndex: 0, data: data }); });
    await expectThrow("saveChunk assemblyId with slash", "INVALID_ARGUMENT",
      function () { return cs.saveChunk({ assemblyId: "has/slash", chunkIndex: 0, data: data }); });
    await expectThrow("saveChunk assemblyId with control char", "INVALID_ARGUMENT",
      function () { return cs.saveChunk({ assemblyId: "ctrl\u0001id", chunkIndex: 0, data: data }); });
    await expectThrow("saveChunk assemblyId with dot-dot traversal", "INVALID_ARGUMENT",
      function () { return cs.saveChunk({ assemblyId: "a..b", chunkIndex: 0, data: data }); });
    await expectThrow("saveChunk assemblyId with leading dot", "INVALID_ARGUMENT",
      function () { return cs.saveChunk({ assemblyId: ".hidden", chunkIndex: 0, data: data }); });

    // chunkIndex rejections.
    await expectThrow("saveChunk non-integer chunkIndex", "INVALID_ARGUMENT",
      function () { return cs.saveChunk({ assemblyId: "ok", chunkIndex: 1.5, data: data }); });
    await expectThrow("saveChunk negative chunkIndex", "INVALID_ARGUMENT",
      function () { return cs.saveChunk({ assemblyId: "ok", chunkIndex: -1, data: data }); });
    await expectThrow("saveChunk chunkIndex over cap", "INVALID_ARGUMENT",
      function () { return cs.saveChunk({ assemblyId: "ok", chunkIndex: 100000, data: data }); });

    // data-shape + size rejections.
    await expectThrow("saveChunk non-Buffer data", "INVALID_ARGUMENT",
      function () { return cs.saveChunk({ assemblyId: "ok", chunkIndex: 0, data: "nope" }); });
    var csTiny = b.storage.chunkScratch({ rootKeyPrefix: "tiny", maxChunkBytes: C.BYTES.bytes(4) });
    await expectThrow("saveChunk exceeds maxChunkBytes", "INVALID_ARGUMENT",
      function () { return csTiny.saveChunk({ assemblyId: "ok", chunkIndex: 0, data: Buffer.from("too-long") }); });

    // getChunk arg-shape rejections.
    await expectThrow("getChunk non-object args", "INVALID_ARGUMENT",
      function () { return cs.getChunk(null); });
    await expectThrow("getChunk missing encryptionKey", "INVALID_ARGUMENT",
      function () { return cs.getChunk({ assemblyId: "ok", chunkIndex: 0, encryptionKey: "" }); });

    // assemble arg-shape rejections.
    await expectThrow("assemble non-object args", "INVALID_ARGUMENT",
      function () { return cs.assemble(null); });
    await expectThrow("assemble empty chunkEncryptionKeys", "INVALID_ARGUMENT",
      function () { return cs.assemble({ assemblyId: "ok", chunkEncryptionKeys: [] }); });
  } finally {
    try { b.storage._resetForTest(); } catch (_e) { /* best-effort */ }
    _cleanupTmp();
  }
}

// ---- chunkScratch full round-trip + assembly integrity ----

async function testChunkScratchRoundTrip() {
  var uploadDir = _mkTmp("chunkrt");
  b.storage._resetForTest();
  try {
    b.storage.init({ backend: "local", uploadDir: uploadDir });
    var cs = b.storage.chunkScratch({ rootKeyPrefix: "uploads/scratch" });

    // Save three ordered chunks; collect the per-chunk sealed keys.
    var keys = [];
    var parts = ["aaa", "bbb", "ccc"];
    for (var i = 0; i < parts.length; i += 1) {
      var res = await cs.saveChunk({ assemblyId: "upload-abc", chunkIndex: i, data: Buffer.from(parts[i]) });
      check("saveChunk[" + i + "] returns a sealed encryptionKey", typeof res.encryptionKey === "string" && res.encryptionKey.length > 0);
      check("saveChunk[" + i + "] reports sizeBytes", res.sizeBytes === 3);
      keys.push(res.encryptionKey);
    }

    // getChunk round-trips one chunk's plaintext.
    var c0 = await cs.getChunk({ assemblyId: "upload-abc", chunkIndex: 0, encryptionKey: keys[0] });
    check("getChunk round-trips chunk bytes", c0.toString("utf8") === "aaa");

    // chunkExists / listChunks / countChunks.
    check("chunkExists true for a saved chunk", (await cs.chunkExists({ assemblyId: "upload-abc", chunkIndex: 1 })) === true);
    check("chunkExists false for a missing chunk", (await cs.chunkExists({ assemblyId: "upload-abc", chunkIndex: 9 })) === false);
    var indices = await cs.listChunks("upload-abc");
    check("listChunks returns sorted indices", indices.length === 3 && indices[0] === 0 && indices[1] === 1 && indices[2] === 2);
    check("countChunks matches", (await cs.countChunks("upload-abc")) === 3);

    // assemble integrity rejections.
    await expectThrow("assemble expectedTotal mismatch", "INCOMPLETE_ASSEMBLY",
      function () { return cs.assemble({ assemblyId: "upload-abc", expectedTotal: 5, chunkEncryptionKeys: keys }); });
    await expectThrow("assemble key-count mismatch", "INVALID_ARGUMENT",
      function () { return cs.assemble({ assemblyId: "upload-abc", chunkEncryptionKeys: [keys[0]] }); });

    // Valid assemble concatenates in order.
    var assembled = await cs.assemble({ assemblyId: "upload-abc", expectedTotal: 3, chunkEncryptionKeys: keys });
    check("assemble concatenates chunks in order", assembled.toString("utf8") === "aaabbbccc");

    // A gapped assembly (chunks 0 and 2, missing 1) is refused.
    var gapKeys = [];
    gapKeys.push((await cs.saveChunk({ assemblyId: "gappy", chunkIndex: 0, data: Buffer.from("g0") })).encryptionKey);
    gapKeys.push((await cs.saveChunk({ assemblyId: "gappy", chunkIndex: 2, data: Buffer.from("g2") })).encryptionKey);
    await expectThrow("assemble refuses a chunk gap", "INCOMPLETE_ASSEMBLY",
      function () { return cs.assemble({ assemblyId: "gappy", expectedTotal: 2, chunkEncryptionKeys: gapKeys }); });

    // listAssemblies surfaces both assembly ids.
    var assemblies = await cs.listAssemblies();
    check("listAssemblies includes the saved assemblies",
          assemblies.indexOf("upload-abc") !== -1 && assemblies.indexOf("gappy") !== -1);

    // Stale-scan + gc run cleanly (filesystem backend surfaces no mtime, so
    // nothing is stale — exercises the scan/gc paths without a false prune).
    var staleDefault = await cs.listStaleAssemblies();
    check("listStaleAssemblies returns an array (default window)", Array.isArray(staleDefault));
    var staleExplicit = await cs.listStaleAssemblies({ olderThanMs: 1 });
    check("listStaleAssemblies returns an array (explicit window)", Array.isArray(staleExplicit));
    var gcRes = await cs.gc({ olderThanMs: C.TIME.hours(48) });
    check("gc returns a removed[] list", Array.isArray(gcRes.removed));
    // gc with no args uses the constructed staleAfterMs default window.
    var gcDefault = await cs.gc();
    check("gc with no args returns a removed[] list", Array.isArray(gcDefault.removed));

    // removeChunk / removeAssembly.
    check("removeChunk deletes a single chunk", (await cs.removeChunk({ assemblyId: "upload-abc", chunkIndex: 2 })) === true);
    var removed = await cs.removeAssembly("upload-abc");
    check("removeAssembly reports the removed chunk count", removed.chunksRemoved >= 1);
    await cs.removeAssembly("gappy");

    // The backend-override path routes chunks through an explicitly named backend.
    var csOverride = b.storage.chunkScratch({ rootKeyPrefix: "ov", backend: "default" });
    var ovRes = await csOverride.saveChunk({ assemblyId: "ov-1", chunkIndex: 0, data: Buffer.from("z") });
    check("chunkScratch backend override saves through the named backend", typeof ovRes.encryptionKey === "string");
    await csOverride.removeAssembly("ov-1");

    // Construction with no opts (default rootKeyPrefix "chunk-scratch") and with
    // explicit numeric windows exercises the opts-default branches.
    var csDefaults = b.storage.chunkScratch();
    var defRes = await csDefaults.saveChunk({ assemblyId: "def-1", chunkIndex: 0, data: Buffer.from("d") });
    check("chunkScratch with no opts uses the default prefix", typeof defRes.encryptionKey === "string");
    await csDefaults.removeAssembly("def-1");

    var csWindows = b.storage.chunkScratch({ rootKeyPrefix: "win", maxChunkBytes: C.BYTES.mib(8), staleAfterMs: C.TIME.hours(1) });
    var winStale = await csWindows.listStaleAssemblies();
    check("chunkScratch with explicit windows scans cleanly", Array.isArray(winStale));
  } finally {
    try { b.storage._resetForTest(); } catch (_e) { /* best-effort */ }
    _cleanupTmp();
  }
}

async function run() {
  await testGetBackend();
  await testResidencyValidation();

  var vaultDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-storage-vault-"));
  await helpers.setupVaultOnly(vaultDir);
  try {
    await testInitConfigValidation();
    await testBackendDispatchErrors();
    await testEncryptionRoundTripAndBodyValidation();
    await testRawDeleteExists();
    await testListVersionsAndPresign();
    await testChunkScratchValidation();
    await testChunkScratchRoundTrip();
  } finally {
    helpers.teardownVaultOnly(vaultDir);
    _cleanupTmp();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[storage] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e); process.exit(1); }
  );
}
