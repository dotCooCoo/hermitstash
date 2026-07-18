// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * file-upload — canonical per-primitive test file.
 *
 * Drives the b.fileUpload consumer path (create → init → acceptChunk →
 * finalize → status/list/cancelUpload/purgeIncomplete) end-to-end, with a
 * focus on the error / adversarial / defensive / option-default branches:
 * create-time opt validation, path-traversal-hostile uploadIds, per-chunk
 * hash + size + shape rejection, manifest verification failures, the
 * magic-byte MIME allowlist + claim-vs-detected cross-check, filename- and
 * content-safety gate refusal / throw / sanitize, the streaming reassembly
 * path, quota exhaustion, idle / TTL expiry, and permission denial.
 *
 * Every gate is exercised through the REAL returned surface (no reaching
 * past the public API except where a corrupt-on-disk sidecar is the
 * scenario under test). Adversarial filenames / bytes assert refusal.
 */
var nodeOs = require("node:os");
var nodePath = require("node:path");
var nodeFs = require("node:fs");
var nodeCrypto = require("node:crypto");
var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

// ---- shared fixtures ------------------------------------------------------

var _createdDirs = [];
function _tmpDir(suffix) {
  var dir = nodePath.join(nodeOs.tmpdir(), "fileupload-canon-" + suffix + "-" +
    nodeCrypto.randomBytes(6).toString("hex"));
  nodeFs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  _createdDirs.push(dir);
  return dir;
}
function _cleanupDirs() {
  for (var i = 0; i < _createdDirs.length; i++) {
    try { nodeFs.rmSync(_createdDirs[i], { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
  _createdDirs.length = 0;
}

// SHA3-512 hex — the framework's per-chunk + total hash. node's sha3-512
// digest matches b.crypto.sha3Hash, so the manifest the lib verifies against
// is computed the same way an operator's client would.
function _sha3(buf) { return nodeCrypto.createHash("sha3-512").update(buf).digest("hex"); }
function _fullSha3(pieces) {
  var h = nodeCrypto.createHash("sha3-512");
  for (var i = 0; i < pieces.length; i++) h.update(pieces[i]);
  return h.digest("hex");
}
function _manifestFor(pieces) {
  var total = 0;
  for (var i = 0; i < pieces.length; i++) total += pieces[i].length;
  return {
    totalBytes: total,
    sha3:       _fullSha3(pieces),
    chunks:     pieces.map(function (p, idx) { return { index: idx, sha3: _sha3(p) }; }),
  };
}
// init + push every chunk for `actor`, leaving the upload READY to finalize.
async function _seedUpload(u, uploadId, pieces, actor, metadata) {
  await u.init({ uploadId: uploadId, actor: actor,
                 metadata: metadata || { filename: "doc.txt" } });
  for (var i = 0; i < pieces.length; i++) {
    await u.acceptChunk({ uploadId: uploadId, index: i, body: pieces[i],
                          sha3: _sha3(pieces[i]), actor: actor });
  }
}
async function _expectThrows(fn) {
  try { await fn(); return null; }
  catch (e) { return e; }
}
// Drain a Readable so the streaming reassembly path never leaks an open fd.
async function _drain(stream) {
  if (!stream) return 0;
  var n = 0;
  for await (var chunk of stream) { n += chunk.length; }
  return n;
}

// PNG / PDF magic-byte fixtures for the fileType-sniff paths.
var PNG_BYTES = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  Buffer.from("IHDR-placeholder-body-bytes-for-a-valid-enough-sniff", "utf8"),
]);
var PDF_BYTES = Buffer.from("%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n", "utf8");

// ---- happy-path lifecycle -------------------------------------------------

async function testHappyLifecycle() {
  var stagingDir = _tmpDir("happy");
  var finalizeInfo = null;
  var u = b.fileUpload.create({
    stagingDir:     stagingDir,
    contentSafety:  null,
    filenameSafety: null,
    onFinalize:     async function (info) {
      finalizeInfo = info;
      return { ok: true, sha3: info.sha3, size: info.size, echoed: true };
    },
  });

  var pieces = [Buffer.from("hello ", "utf8"), Buffer.from("world!", "utf8")];
  var initRv = await u.init({ uploadId: "u-happy", actor: { id: "ada" },
                              metadata: { filename: "greeting.txt" } });
  check("happy[init]: returns uploadId/createdAt/expiresAt",
        initRv.uploadId === "u-happy" &&
        typeof initRv.createdAt === "number" &&
        initRv.expiresAt > initRv.createdAt);

  var acc0 = await u.acceptChunk({ uploadId: "u-happy", index: 0, body: pieces[0],
                                   sha3: _sha3(pieces[0]), actor: { id: "ada" } });
  check("happy[accept]: first chunk received count is 1",
        acc0.received === 1 && acc0.status === "in-progress" &&
        acc0.totalBytesAccepted === pieces[0].length);
  await u.acceptChunk({ uploadId: "u-happy", index: 1, body: pieces[1],
                        sha3: _sha3(pieces[1]), actor: { id: "ada" } });

  // Idempotent re-PUT of the same (index, body) is a no-op flagged duplicate.
  var dup = await u.acceptChunk({ uploadId: "u-happy", index: 0, body: pieces[0],
                                  sha3: _sha3(pieces[0]), actor: { id: "ada" } });
  check("happy[accept]: idempotent re-PUT flagged duplicate", dup.duplicate === true);

  var manifest = _manifestFor(pieces);
  var rv = await u.finalize({ uploadId: "u-happy", manifest: manifest, actor: { id: "ada" } });
  check("happy[finalize]: onFinalize result returned",
        rv.ok === true && rv.echoed === true && rv.size === manifest.totalBytes);
  check("happy[finalize]: onFinalize got the reassembled buffer + total sha3",
        Buffer.isBuffer(finalizeInfo.body) &&
        finalizeInfo.body.toString("utf8") === "hello world!" &&
        finalizeInfo.sha3 === manifest.sha3 &&
        finalizeInfo.stream === null);
  // Staging dir reclaimed on success.
  check("happy[finalize]: staging dir removed on success",
        nodeFs.existsSync(nodePath.join(stagingDir, "u-happy")) === false);
}

// Default onFinalize (operator supplies none) returns { ok, sha3, size }.
async function testDefaultOnFinalize() {
  var u = b.fileUpload.create({
    stagingDir: _tmpDir("default-final"), contentSafety: null, filenameSafety: null,
  });
  var pieces = [Buffer.from("no onFinalize wired", "utf8")];
  await _seedUpload(u, "u-def", pieces, { id: "x" });
  var rv = await u.finalize({ uploadId: "u-def", manifest: _manifestFor(pieces),
                              actor: { id: "x" } });
  check("default-onFinalize: framework returns { ok, sha3, size }",
        rv.ok === true && rv.size === pieces[0].length &&
        rv.sha3 === _fullSha3(pieces));
}

// ---- status / list / cancel / purge ---------------------------------------

async function testStatusListCancel() {
  var u = b.fileUpload.create({
    stagingDir: _tmpDir("slc"), contentSafety: null, filenameSafety: null,
  });
  var pieces = [Buffer.from("status body", "utf8")];
  await _seedUpload(u, "u-a", pieces, { id: "alice" }, { filename: "a.txt" });
  await _seedUpload(u, "u-b", pieces, { id: "bob" }, { filename: "b.txt" });

  var st = u.status("u-a", { actor: { id: "alice" } });
  check("status: returns received indices + metadata for the owner",
        st && st.uploadId === "u-a" && st.received.length === 1 &&
        st.metadata.filename === "a.txt" && st.totalBytesAccepted === pieces[0].length);
  check("status: unknown upload returns null",
        u.status("u-missing", { actor: { id: "alice" } }) === null);

  var mine = u.list({ actor: { id: "alice" } });
  check("list: scoped to the calling actor by default",
        mine.length === 1 && mine[0].uploadId === "u-a");
  var all = u.list({ actor: { id: "alice" }, scopeToActor: false });
  check("list: scopeToActor:false returns every actor's uploads", all.length === 2);
  var sinceFuture = u.list({ actor: { id: "alice" }, since: Date.now() + 1e9 });
  check("list: since filter excludes older uploads", sinceFuture.length === 0);

  var cancelMissing = await u.cancelUpload("u-missing", { actor: { id: "alice" } });
  check("cancel: unknown upload returns { ok:false, reason:'not-found' }",
        cancelMissing.ok === false && cancelMissing.reason === "not-found");
  var cancelled = await u.cancelUpload("u-a", { actor: { id: "alice" } });
  check("cancel: owner cancel returns { ok:true }",
        cancelled.ok === true && cancelled.uploadId === "u-a");
  check("cancel: staging removed after cancel",
        u.status("u-a", { actor: { id: "alice" } }) === null);

  u.close();  // lifecycle parity — no-op, must not throw.
  check("close: no-op close does not throw", true);
}

// A null-safeties manager — the plain lifecycle harness for the branches
// that aren't about the content/filename gates.
function _plainManager(suffix, extra) {
  var opts = { stagingDir: _tmpDir(suffix), contentSafety: null, filenameSafety: null };
  if (extra) for (var k in extra) opts[k] = extra[k];
  return b.fileUpload.create(opts);
}

// ---- create() opt validation (config-time THROW tier) ---------------------

async function testCreateOptValidation() {
  var abs = _tmpDir("optval");
  var cases = [
    ["stagingDir must be absolute", { stagingDir: "relative/dir" }],
    ["allowedFileTypes without fileType is a misconfig",
      { stagingDir: abs, contentSafety: null, filenameSafety: null, allowedFileTypes: ["image/png"] }],
    ["contentSafety must be a plain object / null / undefined",
      { stagingDir: abs, filenameSafety: null, contentSafety: 123 }],
    ["contentSafety entry must be a gate",
      { stagingDir: abs, filenameSafety: null, contentSafety: { ".csv": { notAGate: true } } }],
    ["filenameSafety must be a gate",
      { stagingDir: abs, contentSafety: null, filenameSafety: { notAGate: true } }],
    ["fileType must expose detect()",
      { stagingDir: abs, contentSafety: null, filenameSafety: null, fileType: { nope: 1 } }],
    ["permissions must expose check()",
      { stagingDir: abs, contentSafety: null, filenameSafety: null, permissions: { nope: 1 } }],
    ["allowCrossActor must be a boolean",
      { stagingDir: abs, contentSafety: null, filenameSafety: null, allowCrossActor: "yes" }],
    ["unknown opt refused (exhaustive)",
      { stagingDir: abs, contentSafety: null, filenameSafety: null, bogusOpt: 1 }],
  ];
  for (var i = 0; i < cases.length; i++) {
    var label = cases[i][0], opts = cases[i][1];
    var err = (function (o) { try { b.fileUpload.create(o); return null; } catch (e) { return e; } })(opts);
    check("create-opt: " + label,
          err !== null && err.code === "BAD_OPT" && err.name === "FileUploadError");
  }
}

// contentSafety:null / filenameSafety:null emit an audited disable row whose
// reason defaults to operator-explicit-opt-out, or the operator's own reason.
async function testAuditedOptOut() {
  var defaults = [];
  b.fileUpload.create({
    stagingDir: _tmpDir("optout-default"), contentSafety: null, filenameSafety: null,
    audit: { safeEmit: function (e) { defaults.push(e); } },
  });
  var cs = defaults.filter(function (e) { return e.action === "fileUpload.contentSafety.disabled"; });
  var fs2 = defaults.filter(function (e) { return e.action === "fileUpload.filenameSafety.disabled"; });
  check("opt-out audit: content-safety disable row with default reason",
        cs.length === 1 && cs[0].metadata.reason === "operator-explicit-opt-out" &&
        cs[0].outcome === "success");
  check("opt-out audit: filename-safety disable row with default reason",
        fs2.length === 1 && fs2[0].metadata.reason === "operator-explicit-opt-out");

  var custom = [];
  b.fileUpload.create({
    stagingDir: _tmpDir("optout-custom"), contentSafety: null, filenameSafety: null,
    contentSafetyDisabledReason:  "legacy-import-path",
    filenameSafetyDisabledReason: "operator-accepts-unicode-names",
    audit: { safeEmit: function (e) { custom.push(e); } },
  });
  check("opt-out audit: operator-supplied reasons are recorded",
        custom.some(function (e) { return e.action === "fileUpload.contentSafety.disabled" &&
                                          e.metadata.reason === "legacy-import-path"; }) &&
        custom.some(function (e) { return e.action === "fileUpload.filenameSafety.disabled" &&
                                          e.metadata.reason === "operator-accepts-unicode-names"; }));

  // A throwing audit sink during the disable-audit must not break create().
  var threw = false;
  try {
    b.fileUpload.create({
      stagingDir: _tmpDir("optout-throw"), contentSafety: null, filenameSafety: null,
      audit: { safeEmit: function () { throw new Error("sink down"); } },
    });
  } catch (_e) { threw = true; }
  check("opt-out audit: throwing sink does not break create()", threw === false);
}

// ---- path-traversal-hostile uploadIds --------------------------------------

async function testUploadIdValidation() {
  var u = _plainManager("uploadid");
  var hostile = ["", "a".repeat(129), ".", "..", "a/b", "a\\b", "a\0b", "a*b",
                 "with space", "a?b", 123, null];
  for (var i = 0; i < hostile.length; i++) {
    var id = hostile[i];
    var err = await _expectThrows(function () {
      return u.init({ uploadId: id, actor: { id: "x" }, metadata: {} });
    });
    check("uploadId refused: " + JSON.stringify(id),
          err !== null && err.code === "BAD_UPLOAD_ID");
  }
  // A well-formed id in the allowed char class is accepted.
  var okRv = await u.init({ uploadId: "OK.file-1_2", actor: { id: "x" }, metadata: {} });
  check("uploadId accepted: dotted/underscored/hyphenated id", okRv.uploadId === "OK.file-1_2");
}

// ---- init() branches -------------------------------------------------------

async function testInitBranches() {
  var u = _plainManager("init");
  check("init: null callerOpts throws BAD_OPT",
        (await _expectThrows(function () { return u.init(null); })).code === "BAD_OPT");

  var arrErr = await _expectThrows(function () {
    return u.init({ uploadId: "u-meta-arr", actor: { id: "x" }, metadata: [1, 2, 3] });
  });
  check("init: array metadata → BAD_METADATA", arrErr.code === "BAD_METADATA");
  var strErr = await _expectThrows(function () {
    return u.init({ uploadId: "u-meta-str", actor: { id: "x" }, metadata: "not-an-object" });
  });
  check("init: string metadata → BAD_METADATA", strErr.code === "BAD_METADATA");

  var bigErr = await _expectThrows(function () {
    return u.init({ uploadId: "u-meta-big", actor: { id: "x" },
                    metadata: { blob: "x".repeat(70000) } });
  });
  check("init: oversized metadata → METADATA_TOO_LARGE", bigErr.code === "METADATA_TOO_LARGE");

  await u.init({ uploadId: "u-dupe", actor: { id: "x" }, metadata: {} });
  var dupeErr = await _expectThrows(function () {
    return u.init({ uploadId: "u-dupe", actor: { id: "x" }, metadata: {} });
  });
  check("init: re-init of an existing upload → UPLOAD_EXISTS", dupeErr.code === "UPLOAD_EXISTS");

  // Per-actor active-upload quota.
  var q = _plainManager("init-actorq", { maxActiveUploadsPerActor: 1 });
  await q.init({ uploadId: "q-1", actor: { id: "heavy" }, metadata: {} });
  var qErr = await _expectThrows(function () {
    return q.init({ uploadId: "q-2", actor: { id: "heavy" }, metadata: {} });
  });
  check("init: exceeding maxActiveUploadsPerActor → ACTOR_QUOTA_EXCEEDED",
        qErr.code === "ACTOR_QUOTA_EXCEEDED");

  // Total staging-bytes quota (a prior upload has accepted bytes).
  var s = _plainManager("init-stagingq", { maxStagingBytes: 1 });
  await _seedUpload(s, "s-1", [Buffer.from("some bytes on disk", "utf8")], { id: "a" });
  var sErr = await _expectThrows(function () {
    return s.init({ uploadId: "s-2", actor: { id: "b" }, metadata: {} });
  });
  check("init: exceeding maxStagingBytes → STAGING_QUOTA_EXCEEDED",
        sErr.code === "STAGING_QUOTA_EXCEEDED");
}

// ---- acceptChunk() branches ------------------------------------------------

async function testAcceptChunkBranches() {
  var u = _plainManager("accept");
  await u.init({ uploadId: "u-ac", actor: { id: "x" }, metadata: {} });
  var good = Buffer.from("a valid chunk body", "utf8");

  check("acceptChunk: null callerOpts → BAD_OPT",
        (await _expectThrows(function () { return u.acceptChunk(null); })).code === "BAD_OPT");

  var unknownErr = await _expectThrows(function () {
    return u.acceptChunk({ uploadId: "never-init", index: 0, body: good,
                           sha3: _sha3(good), actor: { id: "x" } });
  });
  check("acceptChunk: no init() → UNKNOWN_UPLOAD", unknownErr.code === "UNKNOWN_UPLOAD");

  var badIdx = [-1, 1.5, 0x40000000];
  for (var i = 0; i < badIdx.length; i++) {
    var bErr = await (function (ix) {
      return _expectThrows(function () {
        return u.acceptChunk({ uploadId: "u-ac", index: ix, body: good,
                               sha3: _sha3(good), actor: { id: "x" } });
      });
    })(badIdx[i]);
    check("acceptChunk: bad index " + badIdx[i] + " → BAD_INDEX", bErr.code === "BAD_INDEX");
  }

  var notBufErr = await _expectThrows(function () {
    return u.acceptChunk({ uploadId: "u-ac", index: 0, body: "a string not a buffer",
                           sha3: _sha3(good), actor: { id: "x" } });
  });
  check("acceptChunk: non-Buffer body → BAD_BODY", notBufErr.code === "BAD_BODY");

  var emptyErr = await _expectThrows(function () {
    return u.acceptChunk({ uploadId: "u-ac", index: 0, body: Buffer.alloc(0),
                           sha3: _sha3(Buffer.alloc(0)), actor: { id: "x" } });
  });
  check("acceptChunk: empty chunk → EMPTY_CHUNK", emptyErr.code === "EMPTY_CHUNK");

  var big = _plainManager("accept-big", { maxChunkBytes: 4 });
  await big.init({ uploadId: "u-big", actor: { id: "x" }, metadata: {} });
  var over = Buffer.from("way too many bytes", "utf8");
  var bigErr = await _expectThrows(function () {
    return big.acceptChunk({ uploadId: "u-big", index: 0, body: over,
                             sha3: _sha3(over), actor: { id: "x" } });
  });
  check("acceptChunk: chunk over maxChunkBytes → CHUNK_TOO_LARGE", bigErr.code === "CHUNK_TOO_LARGE");

  var notHexErr = await _expectThrows(function () {
    return u.acceptChunk({ uploadId: "u-ac", index: 0, body: good,
                           sha3: "zz-not-hex", actor: { id: "x" } });
  });
  check("acceptChunk: non-hex sha3 → BAD_CHUNK_HASH", notHexErr.code === "BAD_CHUNK_HASH");
  var shortHexErr = await _expectThrows(function () {
    return u.acceptChunk({ uploadId: "u-ac", index: 0, body: good,
                           sha3: "abcdef", actor: { id: "x" } });
  });
  check("acceptChunk: wrong-length sha3 → BAD_CHUNK_HASH", shortHexErr.code === "BAD_CHUNK_HASH");

  var wrongHash = _sha3(Buffer.from("a different body entirely", "utf8"));
  var mismatchErr = await _expectThrows(function () {
    return u.acceptChunk({ uploadId: "u-ac", index: 0, body: good,
                           sha3: wrongHash, actor: { id: "x" } });
  });
  check("acceptChunk: supplied hash != computed → CHUNK_HASH_MISMATCH",
        mismatchErr.code === "CHUNK_HASH_MISMATCH");

  // onChunk hook rejection propagates the operator's error verbatim.
  var hookMgr = _plainManager("accept-hook", {
    onChunk: async function () { throw new Error("virus scanner said no"); },
  });
  await hookMgr.init({ uploadId: "u-hook", actor: { id: "x" }, metadata: {} });
  var hookErr = await _expectThrows(function () {
    return hookMgr.acceptChunk({ uploadId: "u-hook", index: 0, body: good,
                                 sha3: _sha3(good), actor: { id: "x" } });
  });
  check("acceptChunk: onChunk throw propagates the operator error",
        hookErr !== null && hookErr.message === "virus scanner said no");

  // Re-PUT same index with a DIFFERENT body is refused.
  await u.acceptChunk({ uploadId: "u-ac", index: 0, body: good, sha3: _sha3(good), actor: { id: "x" } });
  var other = Buffer.from("totally different content", "utf8");
  var reuseErr = await _expectThrows(function () {
    return u.acceptChunk({ uploadId: "u-ac", index: 0, body: other,
                           sha3: _sha3(other), actor: { id: "x" } });
  });
  check("acceptChunk: same index, different body → CHUNK_REUSE_MISMATCH",
        reuseErr.code === "CHUNK_REUSE_MISMATCH");

  // Cumulative file-size cap trips mid-stream and reclaims staging.
  var cap = _plainManager("accept-filecap", { maxFileBytes: 5 });
  await cap.init({ uploadId: "u-cap", actor: { id: "x" }, metadata: {} });
  var tenBytes = Buffer.from("0123456789", "utf8");
  var capErr = await _expectThrows(function () {
    return cap.acceptChunk({ uploadId: "u-cap", index: 0, body: tenBytes,
                             sha3: _sha3(tenBytes), actor: { id: "x" } });
  });
  check("acceptChunk: cumulative bytes over maxFileBytes → FILE_TOO_LARGE",
        capErr.code === "FILE_TOO_LARGE");
  check("acceptChunk: staging reclaimed after FILE_TOO_LARGE",
        cap.status("u-cap", { actor: { id: "x" } }) === null);

  // Idle timeout via an injected clock.
  var now = 1000000;
  var idle = _plainManager("accept-idle", { maxIdleMs: 500, clock: function () { return now; } });
  await idle.init({ uploadId: "u-idle", actor: { id: "x" }, metadata: {} });
  now += 2000;   // > maxIdleMs since init/last chunk
  var idleErr = await _expectThrows(function () {
    return idle.acceptChunk({ uploadId: "u-idle", index: 0, body: good,
                              sha3: _sha3(good), actor: { id: "x" } });
  });
  check("acceptChunk: idle past maxIdleMs → UPLOAD_IDLE_EXPIRED", idleErr.code === "UPLOAD_IDLE_EXPIRED");
}

// ---- finalize() manifest verification --------------------------------------

async function testFinalizeManifestBranches() {
  var A = Buffer.from("chunk-A-content", "utf8");
  var B = Buffer.from("chunk-B-never-uploaded", "utf8");

  var u = _plainManager("fin-man");
  await _seedUpload(u, "u-man", [A], { id: "x" });

  check("finalize: null callerOpts → BAD_OPT",
        (await _expectThrows(function () { return u.finalize(null); })).code === "BAD_OPT");
  check("finalize: unknown upload → UNKNOWN_UPLOAD",
        (await _expectThrows(function () {
          return u.finalize({ uploadId: "no-such", manifest: _manifestFor([A]), actor: { id: "x" } });
        })).code === "UNKNOWN_UPLOAD");
  check("finalize: non-object manifest → BAD_OPT",
        (await _expectThrows(function () {
          return u.finalize({ uploadId: "u-man", manifest: 42, actor: { id: "x" } });
        })).code === "BAD_OPT");
  check("finalize: empty chunks array → BAD_MANIFEST",
        (await _expectThrows(function () {
          return u.finalize({ uploadId: "u-man",
            manifest: { chunks: [], totalBytes: 1, sha3: _sha3(A) }, actor: { id: "x" } });
        })).code === "BAD_MANIFEST");
  check("finalize: non-array chunks → BAD_MANIFEST",
        (await _expectThrows(function () {
          return u.finalize({ uploadId: "u-man",
            manifest: { chunks: "nope", totalBytes: 1, sha3: _sha3(A) }, actor: { id: "x" } });
        })).code === "BAD_MANIFEST");
  check("finalize: non-positive totalBytes → BAD_MANIFEST",
        (await _expectThrows(function () {
          return u.finalize({ uploadId: "u-man",
            manifest: { chunks: [{ index: 0, sha3: _sha3(A) }], totalBytes: 0, sha3: _sha3(A) },
            actor: { id: "x" } });
        })).code === "BAD_MANIFEST");
  check("finalize: non-hex manifest.sha3 → BAD_MANIFEST",
        (await _expectThrows(function () {
          return u.finalize({ uploadId: "u-man",
            manifest: { chunks: [{ index: 0, sha3: _sha3(A) }], totalBytes: A.length, sha3: "nothex" },
            actor: { id: "x" } });
        })).code === "BAD_MANIFEST");

  // manifest.totalBytes over maxFileBytes (checked before chunk verification,
  // so the seeded chunk just needs to fit the cap).
  var tiny = Buffer.from("t", "utf8");
  var capMgr = _plainManager("fin-cap", { maxFileBytes: 5 });
  await _seedUpload(capMgr, "u-fcap", [tiny], { id: "x" });
  check("finalize: manifest.totalBytes over maxFileBytes → FILE_TOO_LARGE",
        (await _expectThrows(function () {
          return capMgr.finalize({ uploadId: "u-fcap",
            manifest: { chunks: [{ index: 0, sha3: _sha3(tiny) }], totalBytes: 100, sha3: _sha3(tiny) },
            actor: { id: "x" } });
        })).code === "FILE_TOO_LARGE");

  // Too many declared chunks.
  var mcMgr = _plainManager("fin-maxchunks", { maxChunks: 1 });
  await _seedUpload(mcMgr, "u-mc", [A], { id: "x" });
  check("finalize: chunks over maxChunks → TOO_MANY_CHUNKS",
        (await _expectThrows(function () {
          return mcMgr.finalize({ uploadId: "u-mc",
            manifest: { chunks: [{ index: 0, sha3: _sha3(A) }, { index: 1, sha3: _sha3(B) }],
                        totalBytes: A.length + B.length, sha3: _fullSha3([A, B]) },
            actor: { id: "x" } });
        })).code === "TOO_MANY_CHUNKS");

  // Non-contiguous manifest indices (0, 2 → gap at position 1).
  check("finalize: non-contiguous chunk index → MANIFEST_INDEX_GAP",
        (await _expectThrows(function () {
          return u.finalize({ uploadId: "u-man",
            manifest: { chunks: [{ index: 0, sha3: _sha3(A) }, { index: 2, sha3: _sha3(B) }],
                        totalBytes: A.length + B.length, sha3: _fullSha3([A, B]) },
            actor: { id: "x" } });
        })).code === "MANIFEST_INDEX_GAP");

  // A manifest chunk with a non-hex sha3.
  check("finalize: non-hex chunk.sha3 → BAD_MANIFEST",
        (await _expectThrows(function () {
          return u.finalize({ uploadId: "u-man",
            manifest: { chunks: [{ index: 0, sha3: "not-hex-at-all" }],
                        totalBytes: A.length, sha3: _sha3(A) },
            actor: { id: "x" } });
        })).code === "BAD_MANIFEST");

  // A chunk declared but never written to staging.
  check("finalize: chunk missing from staging → MISSING_CHUNK",
        (await _expectThrows(function () {
          return u.finalize({ uploadId: "u-man",
            manifest: { chunks: [{ index: 0, sha3: _sha3(A) }, { index: 1, sha3: _sha3(B) }],
                        totalBytes: A.length + B.length, sha3: _fullSha3([A, B]) },
            actor: { id: "x" } });
        })).code === "MISSING_CHUNK");

  // On-disk chunk hash disagrees with the manifest's per-chunk sha3.
  check("finalize: on-disk chunk hash != manifest → CHUNK_HASH_MISMATCH",
        (await _expectThrows(function () {
          return u.finalize({ uploadId: "u-man",
            manifest: { chunks: [{ index: 0, sha3: _sha3(B) }], totalBytes: A.length, sha3: _sha3(A) },
            actor: { id: "x" } });
        })).code === "CHUNK_HASH_MISMATCH");

  // Reassembled size disagrees with manifest.totalBytes.
  check("finalize: reassembled size != manifest.totalBytes → MANIFEST_SIZE_MISMATCH",
        (await _expectThrows(function () {
          return u.finalize({ uploadId: "u-man",
            manifest: { chunks: [{ index: 0, sha3: _sha3(A) }], totalBytes: A.length + 100,
                        sha3: _sha3(A) },
            actor: { id: "x" } });
        })).code === "MANIFEST_SIZE_MISMATCH");

  // Reassembled total hash disagrees with manifest.sha3.
  check("finalize: reassembled total hash != manifest.sha3 → MANIFEST_HASH_MISMATCH",
        (await _expectThrows(function () {
          return u.finalize({ uploadId: "u-man",
            manifest: { chunks: [{ index: 0, sha3: _sha3(A) }], totalBytes: A.length,
                        sha3: _sha3(B) },
            actor: { id: "x" } });
        })).code === "MANIFEST_HASH_MISMATCH");
}

// ---- MIME magic-byte allowlist + claim cross-check -------------------------

async function testMimeGate() {
  // Exact allow.
  var exact = _plainManager("mime-exact", { allowedFileTypes: ["image/png"], fileType: b.fileType });
  await _seedUpload(exact, "m-png", [PNG_BYTES], { id: "x" }, { filename: "pic.png" });
  var okRv = await exact.finalize({ uploadId: "m-png", manifest: _manifestFor([PNG_BYTES]),
                                    actor: { id: "x" } });
  check("mime: allowed exact type finalizes", okRv.ok === true);

  // Wildcard allow.
  var wild = _plainManager("mime-wild", { allowedFileTypes: ["image/*"], fileType: b.fileType });
  await _seedUpload(wild, "m-wild", [PNG_BYTES], { id: "x" }, { filename: "pic.png" });
  check("mime: wildcard image/* accepts image/png",
        (await wild.finalize({ uploadId: "m-wild", manifest: _manifestFor([PNG_BYTES]),
                               actor: { id: "x" } })).ok === true);

  // Not in the allowlist.
  var deny = _plainManager("mime-deny", { allowedFileTypes: ["application/pdf"], fileType: b.fileType });
  await _seedUpload(deny, "m-deny", [PNG_BYTES], { id: "x" }, { filename: "pic.png" });
  check("mime: detected type not in allowlist → MIME_NOT_ALLOWED",
        (await _expectThrows(function () {
          return deny.finalize({ uploadId: "m-deny", manifest: _manifestFor([PNG_BYTES]), actor: { id: "x" } });
        })).code === "MIME_NOT_ALLOWED");

  // Unclassifiable bytes.
  var undet = _plainManager("mime-undet", { allowedFileTypes: ["image/png"], fileType: b.fileType });
  var plain = [Buffer.from("just some ascii text, no magic bytes", "utf8")];
  await _seedUpload(undet, "m-undet", plain, { id: "x" }, { filename: "note.png" });
  check("mime: unclassifiable magic bytes → MIME_NOT_DETECTED",
        (await _expectThrows(function () {
          return undet.finalize({ uploadId: "m-undet", manifest: _manifestFor(plain), actor: { id: "x" } });
        })).code === "MIME_NOT_DETECTED");

  // Claimed Content-Type family disagrees with detected magic-byte family.
  var claim = _plainManager("mime-claim", { allowedFileTypes: ["application/pdf"], fileType: b.fileType });
  await _seedUpload(claim, "m-claim", [PDF_BYTES], { id: "x" },
                    { filename: "doc.pdf", contentType: "image/png" });
  check("mime: claimed family != detected family → MIME_CLAIM_MISMATCH",
        (await _expectThrows(function () {
          return claim.finalize({ uploadId: "m-claim", manifest: _manifestFor([PDF_BYTES]), actor: { id: "x" } });
        })).code === "MIME_CLAIM_MISMATCH");

  // Same-family claim with a charset param + mixed case is accepted (synonym).
  var syn = _plainManager("mime-syn", { allowedFileTypes: ["image/png"], fileType: b.fileType });
  await _seedUpload(syn, "m-syn", [PNG_BYTES], { id: "x" },
                    { filename: "pic.png", contentType: "IMAGE/PNG; charset=binary" });
  check("mime: same-family claim with param/case is accepted",
        (await syn.finalize({ uploadId: "m-syn", manifest: _manifestFor([PNG_BYTES]), actor: { id: "x" } })).ok === true);
}

// ---- filename-safety gate (refuse / throw / sanitize) ----------------------

async function testFilenameSafety() {
  // The default-on strict guard refuses a shell-exec extension.
  var strict = b.fileUpload.create({ stagingDir: _tmpDir("fn-strict"), contentSafety: null });
  await _seedUpload(strict, "f-exe", [Buffer.from("MZ payload", "utf8")], { id: "x" },
                    { filename: "evil.exe" });
  check("filename: default strict guard refuses evil.exe → FILENAME_SAFETY_REFUSED",
        (await _expectThrows(function () {
          return strict.finalize({ uploadId: "f-exe",
            manifest: _manifestFor([Buffer.from("MZ payload", "utf8")]), actor: { id: "x" } });
        })).code === "FILENAME_SAFETY_REFUSED");

  var strict2 = b.fileUpload.create({ stagingDir: _tmpDir("fn-strict2"), contentSafety: null });
  await _seedUpload(strict2, "f-trav", [Buffer.from("body", "utf8")], { id: "x" },
                    { filename: "../../etc/passwd" });
  check("filename: default strict guard refuses path traversal",
        (await _expectThrows(function () {
          return strict2.finalize({ uploadId: "f-trav",
            manifest: _manifestFor([Buffer.from("body", "utf8")]), actor: { id: "x" } });
        })).code === "FILENAME_SAFETY_REFUSED");

  // A throwing filename gate surfaces as FILENAME_SAFETY_THREW.
  var thrower = _plainManager("fn-throw", {
    filenameSafety: { check: function () { throw new Error("gate exploded"); } },
  });
  // re-enable content=null already via _plainManager; override filenameSafety above.
  await _seedUpload(thrower, "f-throw", [Buffer.from("body", "utf8")], { id: "x" },
                    { filename: "ok.txt" });
  check("filename: a throwing gate → FILENAME_SAFETY_THREW",
        (await _expectThrows(function () {
          return thrower.finalize({ uploadId: "f-throw",
            manifest: _manifestFor([Buffer.from("body", "utf8")]), actor: { id: "x" } });
        })).code === "FILENAME_SAFETY_THREW");

  // A sanitize decision rewrites metadata.filename that onFinalize sees.
  var seen = null;
  var san = b.fileUpload.create({
    stagingDir: _tmpDir("fn-san"), contentSafety: null,
    filenameSafety: { check: function () {
      return { ok: true, action: "sanitize", sanitizedFilename: "cleaned.txt" };
    } },
    onFinalize: async function (info) { seen = info.metadata.filename; return { ok: true }; },
  });
  await _seedUpload(san, "f-san", [Buffer.from("body", "utf8")], { id: "x" },
                    { filename: "we!rd  name.txt" });
  await san.finalize({ uploadId: "f-san", manifest: _manifestFor([Buffer.from("body", "utf8")]),
                       actor: { id: "x" } });
  check("filename: sanitize rewrites the filename onFinalize sees", seen === "cleaned.txt");
}

// ---- content-safety gate (refuse / throw / sanitize) -----------------------

async function testContentSafety() {
  // The default-on strict content guard refuses HTML with a <script> tag.
  var strict = b.fileUpload.create({ stagingDir: _tmpDir("cs-strict"), filenameSafety: null });
  var evil = Buffer.from("<script>alert(document.cookie)</script>", "utf8");
  await _seedUpload(strict, "c-html", [evil], { id: "x" }, { filename: "page.html" });
  check("content: default strict guard refuses <script> HTML → CONTENT_SAFETY_REFUSED",
        (await _expectThrows(function () {
          return strict.finalize({ uploadId: "c-html", manifest: _manifestFor([evil]), actor: { id: "x" } });
        })).code === "CONTENT_SAFETY_REFUSED");

  // A throwing content gate surfaces as CONTENT_SAFETY_THREW.
  var body = Buffer.from("some text body", "utf8");
  var thrower = b.fileUpload.create({
    stagingDir: _tmpDir("cs-throw"), filenameSafety: null,
    contentSafety: { ".txt": { check: function () { throw new Error("scanner crashed"); } } },
  });
  await _seedUpload(thrower, "c-throw", [body], { id: "x" }, { filename: "note.txt" });
  check("content: a throwing gate → CONTENT_SAFETY_THREW",
        (await _expectThrows(function () {
          return thrower.finalize({ uploadId: "c-throw", manifest: _manifestFor([body]), actor: { id: "x" } });
        })).code === "CONTENT_SAFETY_THREW");

  // A sanitize decision replaces the bytes onFinalize receives.
  var seen = null;
  var san = b.fileUpload.create({
    stagingDir: _tmpDir("cs-san"), filenameSafety: null,
    contentSafety: { ".txt": { check: function () {
      return { ok: true, action: "sanitize", sanitized: Buffer.from("SANITIZED-BODY", "utf8") };
    } } },
    onFinalize: async function (info) { seen = info.body; return { ok: true }; },
  });
  await _seedUpload(san, "c-san", [body], { id: "x" }, { filename: "note.txt" });
  await san.finalize({ uploadId: "c-san", manifest: _manifestFor([body]), actor: { id: "x" } });
  check("content: sanitize replaces the body onFinalize receives",
        Buffer.isBuffer(seen) && seen.toString("utf8") === "SANITIZED-BODY");

  // An explicit refuse decision (ok:false) also refuses.
  var refuser = b.fileUpload.create({
    stagingDir: _tmpDir("cs-refuse"), filenameSafety: null,
    contentSafety: { ".txt": { check: function () {
      return { ok: false, action: "refuse", issues: [{ kind: "policy-violation" }] };
    } } },
  });
  await _seedUpload(refuser, "c-refuse", [body], { id: "x" }, { filename: "note.txt" });
  check("content: an explicit refuse decision → CONTENT_SAFETY_REFUSED",
        (await _expectThrows(function () {
          return refuser.finalize({ uploadId: "c-refuse", manifest: _manifestFor([body]), actor: { id: "x" } });
        })).code === "CONTENT_SAFETY_REFUSED");
}

// ---- streaming reassembly path + onFinalize throw --------------------------

async function testStreamAndFinalizeThrow() {
  var drained = -1;
  var streamInfo = null;
  var streamMgr = _plainManager("stream", {
    maxStreamReassemblyBytes: 4,
    onFinalize: async function (info) {
      streamInfo = { hasBody: info.body !== null, isStream: !!info.stream, size: info.size };
      drained = await _drain(info.stream);
      return { ok: true, sha3: info.sha3, size: info.size };
    },
  });
  var big = [Buffer.from("0123456789abcdef", "utf8")];   // 16 bytes > 4-byte cap
  await _seedUpload(streamMgr, "u-stream", big, { id: "x" }, { filename: "blob.dat" });
  var rv = await streamMgr.finalize({ uploadId: "u-stream", manifest: _manifestFor(big),
                                      actor: { id: "x" } });
  check("stream: upload past cap hands onFinalize a stream (body null)",
        streamInfo && streamInfo.hasBody === false && streamInfo.isStream === true &&
        streamInfo.size === big[0].length);
  check("stream: draining the stream yields every byte",
        drained === big[0].length && rv.ok === true);

  // onFinalize throwing propagates out of finalize.
  var throwMgr = _plainManager("finalize-throw", {
    onFinalize: async function () { throw new Error("storage backend down"); },
  });
  var body = [Buffer.from("body for finalize throw", "utf8")];
  await _seedUpload(throwMgr, "u-fthrow", body, { id: "x" });
  var fErr = await _expectThrows(function () {
    return throwMgr.finalize({ uploadId: "u-fthrow", manifest: _manifestFor(body), actor: { id: "x" } });
  });
  check("finalize: onFinalize throw propagates to the caller",
        fErr !== null && fErr.message === "storage backend down");
  // Staging is retained after an onFinalize failure so the caller can retry.
  check("finalize: staging retained after onFinalize throw",
        throwMgr.status("u-fthrow", { actor: { id: "x" } }) !== null);
}

// ---- permissions (coarse capability denial) --------------------------------

async function testPermissionDenied() {
  var obsEvents = [];
  var deny = b.fileUpload.create({
    stagingDir: _tmpDir("perm-deny"), contentSafety: null, filenameSafety: null,
    permissions: { check: function () { return false; } },
    observability: { event: function () {}, safeEvent: function (n) { obsEvents.push(n); } },
  });
  var body = Buffer.from("x", "utf8");
  var ops = [
    ["init", function () { return deny.init({ uploadId: "p-1", actor: { id: "x" }, metadata: {} }); }],
    ["accept", function () { return deny.acceptChunk({ uploadId: "p-1", index: 0, body: body, sha3: _sha3(body), actor: { id: "x" } }); }],
    ["finalize", function () { return deny.finalize({ uploadId: "p-1", manifest: _manifestFor([body]), actor: { id: "x" } }); }],
    ["status", function () { return Promise.resolve(deny.status("p-1", { actor: { id: "x" } })); }],
    ["list", function () { return Promise.resolve(deny.list({ actor: { id: "x" } })); }],
    ["cancel", function () { return deny.cancelUpload("p-1", { actor: { id: "x" } }); }],
  ];
  for (var i = 0; i < ops.length; i++) {
    var name = ops[i][0], fn = ops[i][1];
    var err = await _expectThrows(fn);
    check("permission: " + name + " denied → PERMISSION_DENIED",
          err !== null && err.code === "PERMISSION_DENIED");
  }
  check("permission: denial emitted a permission_denied observability event",
        obsEvents.indexOf("fileUpload.permission_denied") !== -1);

  // A permissions.check that THROWS is treated as a denial (fail-closed).
  var throwPerms = b.fileUpload.create({
    stagingDir: _tmpDir("perm-throw"), contentSafety: null, filenameSafety: null,
    permissions: { check: function () { throw new Error("authz backend unreachable"); } },
  });
  var tErr = await _expectThrows(function () {
    return throwPerms.init({ uploadId: "p-2", actor: { id: "x" }, metadata: {} });
  });
  check("permission: a throwing check() fails closed → PERMISSION_DENIED",
        tErr !== null && tErr.code === "PERMISSION_DENIED");
}

// ---- ownership (IDOR / cross-actor) + admin escape hatch -------------------

async function testOwnershipAndAdmin() {
  var A = { id: "actor-a" }, B = { id: "actor-b" };
  var pieces = [Buffer.from("owned bytes", "utf8")];
  var coarse = { check: function (actor, scope) { return scope !== "fileUpload.admin"; } };

  // Cross-actor finalize is refused; the owner succeeds.
  var u = _plainManager("own", { permissions: coarse });
  await _seedUpload(u, "o-1", pieces, A);
  check("ownership: actor B cannot finalize A's upload → OWNERSHIP_VIOLATION",
        (await _expectThrows(function () {
          return u.finalize({ uploadId: "o-1", manifest: _manifestFor(pieces), actor: B });
        })).code === "OWNERSHIP_VIOLATION");
  check("ownership: owner A finalizes successfully",
        (await u.finalize({ uploadId: "o-1", manifest: _manifestFor(pieces), actor: A })).ok === true);

  // allowCrossActor + the admin scope lets an admin act cross-actor.
  var admin = _plainManager("own-admin", {
    permissions: { check: function () { return true; } }, allowCrossActor: true,
  });
  await _seedUpload(admin, "o-2", pieces, A);
  check("ownership: allowCrossActor + admin scope lets B finalize A's upload",
        (await admin.finalize({ uploadId: "o-2", manifest: _manifestFor(pieces), actor: B })).ok === true);

  // allowCrossActor WITHOUT the admin scope is still refused.
  var gated = _plainManager("own-gated", { permissions: coarse, allowCrossActor: true });
  await _seedUpload(gated, "o-3", pieces, A);
  check("ownership: allowCrossActor still requires the admin scope → PERMISSION_DENIED",
        (await _expectThrows(function () {
          return gated.finalize({ uploadId: "o-3", manifest: _manifestFor(pieces), actor: B });
        })).code === "PERMISSION_DENIED");

  // allowCrossActor with NO permissions instance (single-tenant) is allowed.
  var singleTenant = _plainManager("own-single", { allowCrossActor: true });
  await _seedUpload(singleTenant, "o-4", pieces, A);
  check("ownership: allowCrossActor alone (no permissions) permits cross-actor",
        (await singleTenant.finalize({ uploadId: "o-4", manifest: _manifestFor(pieces), actor: B })).ok === true);
}

// ---- purgeIncomplete -------------------------------------------------------

async function testPurgeIncomplete() {
  // TTL-exceeded (createdAt older than incompleteTtlMs).
  var now = 5000000;
  var clock = function () { return now; };
  var ttl = _plainManager("purge-ttl", { incompleteTtlMs: 1000, maxIdleMs: 500, clock: clock });
  await _seedUpload(ttl, "t-1", [Buffer.from("body", "utf8")], { id: "x" });
  // Immediately, nothing is expired.
  check("purge: fresh upload is not purged", ttl.purgeIncomplete().purged === 0);
  now += 2000;
  var ttlRv = ttl.purgeIncomplete();
  check("purge: TTL-exceeded upload reclaimed",
        ttlRv.purged === 1 && ttlRv.ids.indexOf("t-1") !== -1 &&
        ttlRv.reasons[0].reason === "ttl-exceeded");

  // Idle-exceeded (within TTL, but lastChunkAt older than maxIdleMs).
  var now2 = 8000000;
  var idle = _plainManager("purge-idle", {
    incompleteTtlMs: 1000000, maxIdleMs: 500, clock: function () { return now2; },
  });
  await _seedUpload(idle, "i-1", [Buffer.from("body", "utf8")], { id: "x" });
  now2 += 900;   // < TTL, > idle
  var idleRv = idle.purgeIncomplete();
  check("purge: idle-exceeded upload reclaimed",
        idleRv.purged === 1 && idleRv.reasons[0].reason === "idle-exceeded");

  // Orphan directory with no _meta sidecar, reclaimed by mtime (real clock).
  var orphanStaging = _tmpDir("purge-orphan");
  var orphanMgr = b.fileUpload.create({
    stagingDir: orphanStaging, contentSafety: null, filenameSafety: null,
  });
  var orphanDir = nodePath.join(orphanStaging, "orphan-1");
  nodeFs.mkdirSync(orphanDir, { recursive: true, mode: 0o700 });
  helpers.backdateFile(orphanDir, 48 * 60 * 60 * 1000);   // 48h ago — older than the 24h default TTL
  var orphanRv = orphanMgr.purgeIncomplete();
  check("purge: orphan dir (no meta) reclaimed by mtime",
        orphanRv.purged === 1 && orphanRv.reasons[0].reason === "orphan");

  // Empty staging (dir removed) → { purged: 0 }.
  var emptyStaging = _tmpDir("purge-empty");
  var emptyMgr = b.fileUpload.create({
    stagingDir: emptyStaging, contentSafety: null, filenameSafety: null,
  });
  nodeFs.rmSync(emptyStaging, { recursive: true, force: true });
  var emptyRv = emptyMgr.purgeIncomplete();
  check("purge: missing staging dir → { purged: 0 }",
        emptyRv.purged === 0 && emptyRv.ids.length === 0);
}

// ---- defensive: corrupt meta sidecar is treated as not-found ---------------

async function testCorruptSidecar() {
  var stagingDir = _tmpDir("corrupt");
  var u = b.fileUpload.create({ stagingDir: stagingDir, contentSafety: null, filenameSafety: null });
  await u.init({ uploadId: "u-corrupt", actor: { id: "x" }, metadata: {} });
  // Corrupt the on-disk meta sidecar (disk-corruption / partial-write scenario).
  nodeFs.writeFileSync(nodePath.join(stagingDir, "u-corrupt", "_meta.json"), "{ this is not json", "utf8");
  var body = Buffer.from("body", "utf8");
  var err = await _expectThrows(function () {
    return u.acceptChunk({ uploadId: "u-corrupt", index: 0, body: body,
                           sha3: _sha3(body), actor: { id: "x" } });
  });
  check("corrupt-sidecar: unreadable _meta.json is treated as UNKNOWN_UPLOAD",
        err !== null && err.code === "UNKNOWN_UPLOAD");
}

// ---- mid-walk cumulative cap (defensive, inside _verifyChunksOnDisk) -------

async function testMidWalkFileCap() {
  // Two 10-byte chunks (20 bytes total) with a 15-byte cap. manifest.totalBytes
  // is set to the cap (15) so _validateManifest's up-front check passes, and the
  // cumulative overflow is only caught mid-walk once both chunk files are summed.
  // Seed through a high-cap manager (acceptChunk enforces its own maxFileBytes),
  // then finalize through a low-cap manager over the SAME on-disk staging dir.
  var c0 = Buffer.from("0123456789", "utf8");
  var c1 = Buffer.from("abcdefghij", "utf8");
  var shared = _tmpDir("midwalk");
  var seedMgr = b.fileUpload.create({ stagingDir: shared, contentSafety: null, filenameSafety: null });
  await _seedUpload(seedMgr, "u-mid", [c0, c1], { id: "x" });
  var capMgr = b.fileUpload.create({
    stagingDir: shared, contentSafety: null, filenameSafety: null, maxFileBytes: 15,
  });
  var err = await _expectThrows(function () {
    return capMgr.finalize({ uploadId: "u-mid",
      manifest: { chunks: [{ index: 0, sha3: _sha3(c0) }, { index: 1, sha3: _sha3(c1) }],
                  totalBytes: 15, sha3: _fullSha3([c0, c1]) },
      actor: { id: "x" } });
  });
  check("mid-walk: reassembly exceeding maxFileBytes mid-walk → FILE_TOO_LARGE",
        err.code === "FILE_TOO_LARGE");
}

// ---- content-safety skip audits + sniffed-extension routing ---------------

async function testContentSafetySkipAndSniff() {
  // no-gate-for-extension: a gate is wired only for .csv; a .txt upload has no
  // matching gate, so the byte scan is skipped and audited.
  var skips1 = [];
  var noGate = b.fileUpload.create({
    stagingDir: _tmpDir("skip-nogate"), filenameSafety: null,
    contentSafety: { ".csv": { check: function () { return { ok: true, action: "serve" }; } } },
    audit: { safeEmit: function (e) { skips1.push(e); } },
  });
  var txt = [Buffer.from("plain text, no gate for .txt", "utf8")];
  await _seedUpload(noGate, "s-nogate", txt, { id: "x" }, { filename: "notes.txt" });
  await noGate.finalize({ uploadId: "s-nogate", manifest: _manifestFor(txt), actor: { id: "x" } });
  check("skip: no gate for the extension → no-gate-for-extension audit",
        skips1.some(function (e) { return e.action === "fileUpload.content_safety_skipped" &&
                                          e.reason === "no-gate-for-extension"; }));

  // streamed-over-reassembly-cap: a gate IS registered for the ext but the
  // upload streamed past the cap, so the byte gate could not run.
  var skips2 = [];
  var streamed = b.fileUpload.create({
    stagingDir: _tmpDir("skip-stream"), filenameSafety: null, maxStreamReassemblyBytes: 4,
    contentSafety: { ".dat": { check: function () { return { ok: true, action: "serve" }; } } },
    audit: { safeEmit: function (e) { skips2.push(e); } },
    onFinalize: async function (info) { await _drain(info.stream); return { ok: true }; },
  });
  var big = [Buffer.from("0123456789abcdef", "utf8")];   // 16 bytes > 4-byte cap
  await _seedUpload(streamed, "s-stream", big, { id: "x" }, { filename: "blob.dat" });
  await streamed.finalize({ uploadId: "s-stream", manifest: _manifestFor(big), actor: { id: "x" } });
  check("skip: gate present but streamed past cap → streamed-over-reassembly-cap audit",
        skips2.some(function (e) { return e.reason === "streamed-over-reassembly-cap"; }));

  // Sniffed-extension routing: PDF magic bytes named "*.png" (no .png gate)
  // route to the .pdf gate via magic-byte detection, so the mislabel cannot
  // dodge its real type's scanner by choosing the extension.
  var pdfGateRan = false;
  var sniff = b.fileUpload.create({
    stagingDir: _tmpDir("skip-sniff"), filenameSafety: null, fileType: b.fileType,
    contentSafety: { ".pdf": { check: function () {
      pdfGateRan = true;
      return { ok: false, action: "refuse", issues: [{ kind: "pdf-refused" }] };
    } } },
    audit: { safeEmit: function () {} },
  });
  await _seedUpload(sniff, "s-sniff", [PDF_BYTES], { id: "x" }, { filename: "evil.png" });
  var sniffErr = await _expectThrows(function () {
    return sniff.finalize({ uploadId: "s-sniff", manifest: _manifestFor([PDF_BYTES]), actor: { id: "x" } });
  });
  check("sniff: mislabeled PDF (.png) routes to the sniffed .pdf gate → CONTENT_SAFETY_REFUSED",
        pdfGateRan === true && sniffErr.code === "CONTENT_SAFETY_REFUSED");
}

// ---- actor-identity defaults + no-opts accessor arms -----------------------

async function testActorDefaultsAndAccessors() {
  var u = _plainManager("anon");
  // init with only uploadId — actor defaults to anonymous, metadata to {}.
  await u.init({ uploadId: "anon-1" });
  var body = Buffer.from("anonymous upload body", "utf8");
  // acceptChunk with no actor — the anonymous owner matches.
  await u.acceptChunk({ uploadId: "anon-1", index: 0, body: body, sha3: _sha3(body) });
  // A non-string sha3 exercises the non-string arm of the hash-shape error.
  var numHashErr = await _expectThrows(function () {
    return u.acceptChunk({ uploadId: "anon-1", index: 1, body: body, sha3: 12345 });
  });
  check("accept: numeric (non-string) sha3 → BAD_CHUNK_HASH", numHashErr.code === "BAD_CHUNK_HASH");

  // status / list with no opts object at all.
  var st = u.status("anon-1");
  check("status: no-opts call resolves for the anonymous owner",
        st !== null && st.uploadId === "anon-1");
  var listed = u.list();
  check("list: no-opts call returns every upload", listed.length >= 1);

  // finalize with no actor — metadata has no filename, so filename falls back
  // to the uploadId.
  var seenName = null;
  var uf = b.fileUpload.create({
    stagingDir: _tmpDir("anon-fin"), contentSafety: null,
    filenameSafety: { check: function (arg) { seenName = arg.filename;
                       return { ok: true, action: "serve" }; } },
  });
  await uf.init({ uploadId: "anon-fin-1" });
  await uf.acceptChunk({ uploadId: "anon-fin-1", index: 0, body: body, sha3: _sha3(body) });
  await uf.finalize({ uploadId: "anon-fin-1", manifest: _manifestFor([body]) });
  check("finalize: filename falls back to uploadId when metadata carries none",
        seenName === "anon-fin-1");

  // cancelUpload with no opts object.
  var cancelled = await u.cancelUpload("anon-1");
  check("cancel: no-opts call cancels the anonymous owner's upload", cancelled.ok === true);

  // actor.userId (not .id) is the identity key.
  var uid = _plainManager("uid");
  var uidInit = await uid.init({ uploadId: "uid-1", actor: { userId: "by-user-id" } });
  check("init: actor.userId is accepted as the owner key", uidInit.uploadId === "uid-1");
}

// ---- ownership admin escape: a throwing admin check fails closed -----------

async function testAdminScopeCheckThrows() {
  var A = { id: "actor-a" }, B = { id: "actor-b" };
  var pieces = [Buffer.from("admin-throw body", "utf8")];
  var mgr = _plainManager("own-admin-throw", {
    permissions: { check: function (actor, scope) {
      if (scope === "fileUpload.admin") throw new Error("authz backend down");
      return true;
    } },
    allowCrossActor: true,
  });
  await _seedUpload(mgr, "oa-1", pieces, A);
  var err = await _expectThrows(function () {
    return mgr.finalize({ uploadId: "oa-1", manifest: _manifestFor(pieces), actor: B });
  });
  check("ownership: a throwing admin-scope check fails closed → PERMISSION_DENIED",
        err !== null && err.code === "PERMISSION_DENIED");
}

// ---- accessors on an in-progress (0-byte) upload + a few default arms ------

async function testInProgressAndDefaultArms() {
  var u = _plainManager("inprogress");
  // init only — no chunk yet, so totalBytesAccepted is 0.
  await u.init({ uploadId: "ip-1", actor: { id: "x" } });
  var st = u.status("ip-1", { actor: { id: "x" } });
  check("status: an init-only upload reports zero bytes + empty received",
        st !== null && st.totalBytesAccepted === 0 && st.received.length === 0);
  var cancelled = await u.cancelUpload("ip-1", { actor: { id: "x" } });
  check("cancel: an init-only (zero-byte) upload cancels cleanly", cancelled.ok === true);

  // list filtered by an actor keyed on userId (not id).
  var uid = _plainManager("inprogress-uid");
  await uid.init({ uploadId: "ip-uid", actor: { userId: "by-user-id" } });
  var mine = uid.list({ actor: { userId: "by-user-id" } });
  check("list: filter matches an actor keyed on userId",
        mine.length === 1 && mine[0].uploadId === "ip-uid");

  // onChunk throwing a non-Error value (a string) still refuses the chunk.
  var hookMgr = _plainManager("inprogress-hook", {
    onChunk: function () { throw "string rejection"; },   // eslint-disable-line no-throw-literal
  });
  await hookMgr.init({ uploadId: "ip-hook", actor: { id: "x" } });
  var body = Buffer.from("body", "utf8");
  var hookErr = await _expectThrows(function () {
    return hookMgr.acceptChunk({ uploadId: "ip-hook", index: 0, body: body,
                                 sha3: _sha3(body), actor: { id: "x" } });
  });
  check("acceptChunk: onChunk throwing a non-Error propagates the raw value",
        hookErr === "string rejection");

  // A content gate that refuses with no issues array still refuses.
  var refuser = b.fileUpload.create({
    stagingDir: _tmpDir("inprogress-refuse"), filenameSafety: null,
    contentSafety: { ".txt": { check: function () { return { ok: false, action: "refuse" }; } } },
  });
  await _seedUpload(refuser, "ip-refuse", [body], { id: "x" }, { filename: "note.txt" });
  check("content: refuse with no issues array still → CONTENT_SAFETY_REFUSED",
        (await _expectThrows(function () {
          return refuser.finalize({ uploadId: "ip-refuse", manifest: _manifestFor([body]), actor: { id: "x" } });
        })).code === "CONTENT_SAFETY_REFUSED");
}

async function run() {
  try {
    await testHappyLifecycle();
    await testDefaultOnFinalize();
    await testStatusListCancel();
    await testCreateOptValidation();
    await testAuditedOptOut();
    await testUploadIdValidation();
    await testInitBranches();
    await testAcceptChunkBranches();
    await testFinalizeManifestBranches();
    await testMimeGate();
    await testFilenameSafety();
    await testContentSafety();
    await testStreamAndFinalizeThrow();
    await testPermissionDenied();
    await testOwnershipAndAdmin();
    await testPurgeIncomplete();
    await testCorruptSidecar();
    await testMidWalkFileCap();
    await testContentSafetySkipAndSniff();
    await testActorDefaultsAndAccessors();
    await testAdminScopeCheckThrows();
    await testInProgressAndDefaultArms();
  } finally {
    _cleanupDirs();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
