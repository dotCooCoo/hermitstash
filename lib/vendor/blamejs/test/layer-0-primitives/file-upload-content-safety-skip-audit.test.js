"use strict";
/**
 * file-upload — content-safety SKIP is audited.
 *
 * When the byte-level content-safety scan does not run for a finalized
 * upload, an operator reviewing the audit log must be able to tell the
 * upload bypassed scanning, and WHY. Each skip path emits exactly one
 * `fileUpload.content_safety_skipped` audit naming the reason:
 *
 *   - content-safety-disabled        (contentSafety: null opt-out)
 *   - no-gate-for-extension          (no gate registered for the ext)
 *   - streamed-over-reassembly-cap   (upload streamed past the cap)
 *
 * The audit is observability-only: a throwing audit sink must NOT crash
 * the upload (the finalize still returns its result).
 */
var nodeOs = require("node:os");
var nodePath = require("node:path");
var nodeFs = require("node:fs");
var nodeCrypto = require("node:crypto");
var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

function _tmpDir(suffix) {
  var dir = nodePath.join(nodeOs.tmpdir(), "fileupload-skipaudit-" + suffix + "-" +
    nodeCrypto.randomBytes(6).toString("hex"));
  nodeFs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}
function _chunkSha3(buf) { return require("../../lib/crypto").sha3Hash(buf); }
function _fullSha3(pieces) {
  var h = nodeCrypto.createHash("sha3-512");
  for (var i = 0; i < pieces.length; i++) h.update(pieces[i]);
  return h.digest("hex");
}
function _skipEvents(emitted) {
  return emitted.filter(function (e) {
    return e.action === "fileUpload.content_safety_skipped";
  });
}

// Drive one small (in-memory) upload end-to-end through finalize.
async function _uploadAndFinalize(u, uploadId, pieces, extra) {
  await u.init({ uploadId: uploadId, actor: { id: uploadId },
                 metadata: (extra && extra.metadata) || {} });
  var total = 0;
  for (var i = 0; i < pieces.length; i++) {
    await u.acceptChunk({ uploadId: uploadId, index: i, body: pieces[i],
                          sha3: _chunkSha3(pieces[i]), actor: { id: uploadId } });
    total += pieces[i].length;
  }
  var manifest = {
    totalBytes: total,
    sha3:       _fullSha3(pieces),
    chunks:     pieces.map(function (p, idx) { return { index: idx, sha3: _chunkSha3(p) }; }),
  };
  return u.finalize({ uploadId: uploadId, manifest: manifest, actor: { id: uploadId } });
}

async function run() {
  // ---- Skip reason: content-safety-disabled (contentSafety: null) ----
  {
    var emitted = [];
    var fakeAudit = { safeEmit: function (e) { emitted.push(e); } };
    var u = b.fileUpload.create({
      stagingDir:    _tmpDir("disabled"),
      contentSafety: null,
      filenameSafety: null,
      audit:         fakeAudit,
    });
    emitted.length = 0;  // drop the create-time disable audits
    var c0 = Buffer.from("plain text body", "utf8");
    await _uploadAndFinalize(u, "u-disabled", [c0],
                             { metadata: { filename: "doc.txt" } });
    var skips = _skipEvents(emitted);
    check("skip[disabled]: exactly one skip audit", skips.length === 1);
    check("skip[disabled]: reason names the disable",
          skips.length === 1 && skips[0].reason === "content-safety-disabled" &&
          skips[0].metadata && skips[0].metadata.reason === "content-safety-disabled");
    check("skip[disabled]: outcome is an accepted audit outcome",
          skips.length === 1 && skips[0].outcome === "success");
    check("skip[disabled]: metadata carries size",
          skips.length === 1 && skips[0].metadata.size === c0.length);
  }

  // ---- Skip reason: no-gate-for-extension ----
  // contentSafety wired with a gate ONLY for ".csv"; upload a ".txt" so
  // no gate matches the extension.
  {
    var emitted2 = [];
    var fakeAudit2 = { safeEmit: function (e) { emitted2.push(e); } };
    var csvGateChecked = false;
    var u2 = b.fileUpload.create({
      stagingDir:     _tmpDir("nogate"),
      filenameSafety: null,
      contentSafety:  {
        ".csv": { check: function () { csvGateChecked = true; return { ok: true, action: "serve" }; } },
      },
      audit: fakeAudit2,
    });
    emitted2.length = 0;
    var t0 = Buffer.from("not a csv", "utf8");
    await _uploadAndFinalize(u2, "u-nogate", [t0],
                             { metadata: { filename: "notes.txt" } });
    var skips2 = _skipEvents(emitted2);
    check("skip[no-gate]: the .csv gate was NOT invoked for a .txt", csvGateChecked === false);
    check("skip[no-gate]: exactly one skip audit", skips2.length === 1);
    check("skip[no-gate]: reason names the missing gate",
          skips2.length === 1 && skips2[0].reason === "no-gate-for-extension");
    check("skip[no-gate]: metadata carries ext",
          skips2.length === 1 && skips2[0].metadata.ext === ".txt");
  }

  // ---- A gate that DOES match must NOT emit a skip audit ----
  {
    var emitted3 = [];
    var fakeAudit3 = { safeEmit: function (e) { emitted3.push(e); } };
    var u3 = b.fileUpload.create({
      stagingDir:     _tmpDir("matched"),
      filenameSafety: null,
      contentSafety:  {
        ".txt": { check: function () { return { ok: true, action: "serve" }; } },
      },
      audit: fakeAudit3,
    });
    emitted3.length = 0;
    var m0 = Buffer.from("scanned body", "utf8");
    await _uploadAndFinalize(u3, "u-matched", [m0],
                             { metadata: { filename: "scan.txt" } });
    check("scan[matched]: gate ran → NO skip audit emitted",
          _skipEvents(emitted3).length === 0);
  }

  // ---- Skip reason: streamed-over-reassembly-cap ----
  // Force the streaming path by setting maxStreamReassemblyBytes below the
  // upload size, while a gate IS registered for the extension.
  {
    var emitted4 = [];
    var fakeAudit4 = { safeEmit: function (e) { emitted4.push(e); } };
    var streamGateChecked = false;
    var u4 = b.fileUpload.create({
      stagingDir:               _tmpDir("streamed"),
      filenameSafety:           null,
      maxStreamReassemblyBytes: 4,   // tiny — anything bigger streams
      contentSafety:  {
        ".bin": { check: function () { streamGateChecked = true; return { ok: true, action: "serve" }; } },
      },
      audit: fakeAudit4,
      onFinalize: async function (info) {
        // Drain the stream so the readable doesn't leak open.
        if (info.stream) { for await (var _c of info.stream) { void _c; } }
        return { ok: true, sha3: info.sha3, size: info.size };
      },
    });
    emitted4.length = 0;
    var big0 = Buffer.from("0123456789", "utf8");   // 10 bytes > 4-byte cap
    await _uploadAndFinalize(u4, "u-streamed", [big0],
                             { metadata: { filename: "blob.bin" } });
    var skips4 = _skipEvents(emitted4);
    check("skip[streamed]: gate could not run on a streamed body", streamGateChecked === false);
    check("skip[streamed]: exactly one skip audit", skips4.length === 1);
    check("skip[streamed]: reason names the reassembly cap",
          skips4.length === 1 && skips4[0].reason === "streamed-over-reassembly-cap");
  }

  // ---- A throwing audit sink must NOT crash the upload ----
  {
    var u5 = b.fileUpload.create({
      stagingDir:    _tmpDir("throwing"),
      contentSafety: null,
      filenameSafety: null,
      audit:         { safeEmit: function () { throw new Error("audit sink down"); } },
    });
    var s0 = Buffer.from("survives a broken audit sink", "utf8");
    var rv = null, threw = false;
    try {
      rv = await _uploadAndFinalize(u5, "u-throwing", [s0],
                                    { metadata: { filename: "ok.txt" } });
    } catch (_e) { threw = true; }
    check("skip[throwing-sink]: upload finalized despite throwing audit sink",
          threw === false && rv && rv.ok === true && rv.size === s0.length);
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
