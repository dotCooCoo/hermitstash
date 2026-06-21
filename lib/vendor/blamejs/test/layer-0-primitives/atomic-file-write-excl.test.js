"use strict";
/**
 * b.atomicFile.writeExclSync — staged exclusive, symlink-refusing write
 * (CWE-377 insecure temp / CWE-59 symlink follow).
 *
 * The non-renaming sibling of writeSync, for write→verify→rename flows
 * (vault seal/unseal/rotate stage the bytes, re-read + decrypt-verify them,
 * THEN rename into place). It must: write the bytes straight to the given
 * path (no rename of its own), clear any stale leftover first, and refuse to
 * follow a symlink pre-planted at the path — a bare writeFileSync would
 * follow it (arbitrary write) or truncate a planted file.
 *
 * Coverage:
 *   - round-trip (bytes land at the path verbatim, bytesWritten correct)
 *   - a stale regular file at the path is cleared + replaced (retry-safe)
 *   - invalid data type is refused (atomic-file/invalid-data)
 *   - a symlink at the path is NOT followed: the link is removed and a fresh
 *     regular file is created, the symlink's target left untouched (POSIX;
 *     skipped where the platform lacks symlink privilege)
 */

var fs   = require("fs");
var path = require("path");

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _tmpDir() {
  return b.testing.tempDir("atomicfile-writeexcl");
}

function testRoundTrips() {
  var dir = _tmpDir();
  try {
    var p = path.join(dir.path, "staged.bin");
    var payload = Buffer.from("staged bytes ✓ multibyte", "utf8");
    var res = b.atomicFile.writeExclSync(p, payload, { fileMode: 0o600 });
    check("writeExclSync: bytesWritten matches", res.bytesWritten === payload.length);
    check("writeExclSync: file written at the path verbatim (no rename)",
          fs.existsSync(p) && fs.readFileSync(p).equals(payload));
  } finally {
    dir.cleanup();
  }
}

function testClearsStale() {
  var dir = _tmpDir();
  try {
    var p = path.join(dir.path, "staged.bin");
    // An aborted prior run left a stale staging file at the (predictable) path.
    fs.writeFileSync(p, "STALE LEFTOVER FROM A CRASHED RUN", { mode: 0o600 });
    var payload = Buffer.from("fresh", "utf8");
    b.atomicFile.writeExclSync(p, payload, { fileMode: 0o600 });
    check("writeExclSync: stale leftover cleared + replaced (retry-safe)",
          fs.readFileSync(p).equals(payload));
  } finally {
    dir.cleanup();
  }
}

function testInvalidDataRefused() {
  var dir = _tmpDir();
  try {
    var p = path.join(dir.path, "nope.bin");
    var code = null;
    try { b.atomicFile.writeExclSync(p, { not: "bytes" }); }
    catch (e) { code = e && e.code; }
    check("writeExclSync: non-buffer/string data refused", code === "atomic-file/invalid-data");
  } finally {
    dir.cleanup();
  }
}

function testSymlinkNotFollowed() {
  var dir = _tmpDir();
  try {
    var victim = path.join(dir.path, "victim-secret.txt");
    fs.writeFileSync(victim, "SECRET", { mode: 0o600 });
    var staged = path.join(dir.path, "staged.tmp");

    var symlinkOk = true;
    try { fs.symlinkSync(victim, staged); }
    catch (_e) { symlinkOk = false; }

    if (!symlinkOk) {
      check("writeExclSync: symlink case skipped (platform lacks symlink privilege)", true);
      return;
    }

    var payload = Buffer.from("staged-not-through-the-link", "utf8");
    b.atomicFile.writeExclSync(staged, payload, { fileMode: 0o600 });

    // staged is now a regular file with the new bytes (the link was unlinked,
    // then a fresh file created). O_NOFOLLOW would have failed the open if the
    // link had survived. Take type + bytes from one no-follow fd (no race).
    var fd = fs.openSync(staged, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    try {
      var st = fs.fstatSync(fd);
      check("writeExclSync: path is a regular file after write",
            st.isFile() && !st.isSymbolicLink());
      var buf = Buffer.alloc(st.size);
      var got = 0;
      while (got < st.size) {
        var n = fs.readSync(fd, buf, got, st.size - got, null);
        if (n === 0) break;
        got += n;
      }
      check("writeExclSync: path holds the new bytes", buf.equals(payload));
    } finally {
      fs.closeSync(fd);
    }
    check("writeExclSync: symlink target (victim) NOT written through",
          fs.readFileSync(victim, "utf8") === "SECRET");
  } finally {
    dir.cleanup();
  }
}

async function run() {
  testRoundTrips();
  testClearsStale();
  testInvalidDataRefused();
  testSymlinkNotFollowed();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
