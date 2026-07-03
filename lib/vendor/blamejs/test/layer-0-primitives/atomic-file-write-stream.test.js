// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.atomicFile.writeStream — streaming sibling of writeSync (CWE-377
 * insecure temporary file / CWE-59 symlink follow).
 *
 * A plain fs.createWriteStream(dest) follows a symlink an attacker planted
 * at `dest` (arbitrary write outside the intended tree) and leaves a
 * half-written file at the canonical name if the source aborts mid-stream.
 * writeStream stages the bytes into a CSPRNG-named sibling temp opened
 * O_EXCL | O_NOFOLLOW, fsyncs, then atomically renames over `dest` — so the
 * file appears at `dest` only after the full stream lands, and a symlink at
 * `dest` is replaced by the rename rather than followed.
 *
 * Coverage:
 *   - stream round-trip (exact bytes, bytesWritten, no orphan temp)
 *   - a non-stream source is refused (atomic-file/invalid-source)
 *   - maxBytes overflow rejects, writes NO file, leaves no orphan temp
 *   - a source that errors mid-stream leaves NO file + no orphan temp
 *   - a symlink at the destination is replaced by the rename, not followed
 *     (POSIX only — Windows without symlink privilege skips that assertion)
 */

var fs   = require("fs");
var path = require("path");
var { Readable } = require("node:stream");

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _tmpDir() {
  return b.testing.tempDir("atomicfile-writestream");
}

function _orphans(dirPath, base) {
  return fs.readdirSync(dirPath).filter(function (n) {
    return n.indexOf(base + ".tmp-") === 0;
  });
}

// A Readable that emits one chunk then errors — models an upstream that
// aborts mid-transfer (dropped socket, decompression bomb tripwire, etc.).
function _erroringSource() {
  var emitted = false;
  return new Readable({
    read: function () {
      if (!emitted) { emitted = true; this.push(Buffer.from("partial")); }
      else { this.destroy(new Error("upstream aborted mid-stream")); }
    },
  });
}

async function testStreamRoundTrips() {
  var dir = _tmpDir();
  try {
    var p = path.join(dir.path, "obj.bin");
    var payload = Buffer.from("streamed payload ✓ with multibyte", "utf8");
    var res = await b.atomicFile.writeStream(p, Readable.from([payload]), { fileMode: 0o600 });
    check("writeStream: bytesWritten matches", res.bytesWritten === payload.length);
    check("writeStream: dest exists",          fs.existsSync(p));
    check("writeStream: content round-trips",  fs.readFileSync(p).equals(payload));
    check("writeStream: no temp file leaked",  _orphans(dir.path, "obj.bin").length === 0);

    // Chunked source reassembles in order.
    var p2 = path.join(dir.path, "chunked.bin");
    var chunks = [Buffer.from("aaa"), Buffer.from("bbb"), Buffer.from("ccc")];
    var res2 = await b.atomicFile.writeStream(p2, Readable.from(chunks));
    check("writeStream: chunked bytesWritten matches", res2.bytesWritten === 9);
    check("writeStream: chunked content in order", fs.readFileSync(p2, "utf8") === "aaabbbccc");
  } finally {
    dir.cleanup();
  }
}

async function testInvalidSourceRefused() {
  var dir = _tmpDir();
  try {
    var p = path.join(dir.path, "nope.bin");
    var code = null;
    try { await b.atomicFile.writeStream(p, Buffer.from("not a stream")); }
    catch (e) { code = e && e.code; }
    check("writeStream: non-stream source refused", code === "atomic-file/invalid-source");
    check("writeStream: nothing written for invalid source", !fs.existsSync(p));
  } finally {
    dir.cleanup();
  }
}

async function testMaxBytesOverflow() {
  var dir = _tmpDir();
  try {
    var p = path.join(dir.path, "toobig.bin");
    var big = Buffer.alloc(1024, 0x41); // 1 KiB
    var code = null;
    try {
      await b.atomicFile.writeStream(p, Readable.from([big]), { maxBytes: 16 });
    } catch (e) { code = e && e.code; }
    check("writeStream: overflow rejected with too-large", code === "atomic-file/too-large");
    check("writeStream: overflow wrote NO file at dest", !fs.existsSync(p));
    check("writeStream: overflow left no orphan temp", _orphans(dir.path, "toobig.bin").length === 0);
  } finally {
    dir.cleanup();
  }
}

async function testMidStreamErrorLeavesNothing() {
  var dir = _tmpDir();
  try {
    var p = path.join(dir.path, "aborted.bin");
    var threw = false;
    try { await b.atomicFile.writeStream(p, _erroringSource()); }
    catch (_e) { threw = true; }
    check("writeStream: mid-stream error propagates", threw);
    check("writeStream: aborted stream wrote NO file at dest", !fs.existsSync(p));
    check("writeStream: aborted stream left no orphan temp", _orphans(dir.path, "aborted.bin").length === 0);
  } finally {
    dir.cleanup();
  }
}

async function testSymlinkAtDestinationReplacedNotFollowed() {
  var dir = _tmpDir();
  try {
    var victim = path.join(dir.path, "outside-victim.bin");
    fs.writeFileSync(victim, "DO NOT OVERWRITE", { mode: 0o600 });
    var dest = path.join(dir.path, "dest-link.bin");

    var symlinkOk = true;
    try { fs.symlinkSync(victim, dest); }
    catch (_e) { symlinkOk = false; }

    if (!symlinkOk) {
      check("writeStream: dest-symlink case skipped (platform lacks symlink privilege)", true);
      return;
    }

    var payload = Buffer.from("fresh streamed contents", "utf8");
    await b.atomicFile.writeStream(dest, Readable.from([payload]));

    // Open ONE no-follow fd and take both the type check (fstat) and the
    // bytes from it — no lstat-then-read race (CWE-367). O_NOFOLLOW makes the
    // open fail if dest were still a symlink, so a successful open already
    // proves the rename replaced the link with a regular file.
    var destFd = fs.openSync(dest, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    try {
      var fst = fs.fstatSync(destFd);
      check("writeStream: destination is a regular file after write",
            fst.isFile() && !fst.isSymbolicLink());
      var destBytes = Buffer.alloc(fst.size);
      var got = 0;
      while (got < fst.size) {
        var n = fs.readSync(destFd, destBytes, got, fst.size - got, null);
        if (n === 0) break;
        got += n;
      }
      check("writeStream: destination holds the new bytes",
            got === payload.length && destBytes.equals(payload));
    } finally {
      fs.closeSync(destFd);
    }
    check("writeStream: symlink target (victim) untouched",
          fs.readFileSync(victim, "utf8") === "DO NOT OVERWRITE");
  } finally {
    dir.cleanup();
  }
}

async function run() {
  await testStreamRoundTrips();
  await testInvalidSourceRefused();
  await testMaxBytesOverflow();
  await testMidStreamErrorLeavesNothing();
  await testSymlinkAtDestinationReplacedNotFollowed();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
