"use strict";
/**
 * b.atomicFile temp-file create hardening (CWE-377 insecure temporary
 * file / CWE-59 symlink follow).
 *
 * Every atomic write stages bytes into a sibling temp file
 * (`<filepath>.tmp-<csprng>`) before renaming over the destination. The
 * temp create must be EXCLUSIVE and NO-FOLLOW: an attacker who guesses
 * (or, on a shared dir, races) the temp path and pre-plants a regular
 * file or a symlink there must NOT have that file truncated or written
 * through. O_EXCL makes the open fail with EEXIST when anything already
 * exists at the path; O_NOFOLLOW refuses a symlink in the final
 * component where the platform defines it.
 *
 * Coverage:
 *   - write / writeSync round-trip (the atomicity contract is intact)
 *   - the exact create flag set the substrate uses refuses a pre-existing
 *     regular file (EEXIST) instead of truncating it
 *   - the same flag set refuses a pre-existing symlink (does not follow
 *     it to a victim path) on platforms where symlinks are creatable
 *   - a symlink planted at the DESTINATION is replaced by the rename, not
 *     followed — the victim the symlink pointed at is left untouched
 */

var fs   = require("fs");
var path = require("path");

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// The production temp-create flag set (lib/atomic-file.js _openExclTemp /
// lib/http-client.js downloadStream). Reproduced here so the test asserts
// the SAME security property the substrate depends on; O_NOFOLLOW is
// undefined on Windows, hence the `|| 0` fold both here and in the source.
var EXCL_FLAGS = fs.constants.O_WRONLY | fs.constants.O_CREAT |
  fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0);

function _tmpDir() {
  return b.testing.tempDir("atomicfile-excl");
}

async function testWriteRoundTrips() {
  var dir = _tmpDir();
  try {
    var p = path.join(dir.path, "state.bin");
    var payload = Buffer.from("round-trip payload ✓", "utf8");
    var res = await b.atomicFile.write(p, payload, { computeHash: true });
    check("write: bytesWritten matches", res.bytesWritten === payload.length);
    check("write: dest exists",          fs.existsSync(p));
    check("write: content round-trips",  fs.readFileSync(p).equals(payload));
    // No temp left behind on the success path.
    var leftovers = fs.readdirSync(dir.path).filter(function (n) {
      return n.indexOf("state.bin.tmp-") === 0;
    });
    check("write: no temp file leaked", leftovers.length === 0);

    // Overwrite the same destination — the temp create must succeed each
    // time even though `p` already exists (we stage to a fresh temp path,
    // never to `p` itself), and the new bytes must win.
    var payload2 = Buffer.from("second write", "utf8");
    await b.atomicFile.write(p, payload2);
    check("write: overwrite replaces content", fs.readFileSync(p).equals(payload2));
  } finally {
    dir.cleanup();
  }
}

function testWriteSyncRoundTrips() {
  var dir = _tmpDir();
  try {
    var p = path.join(dir.path, "sync-state.bin");
    var payload = Buffer.from("sync payload", "utf8");
    var res = b.atomicFile.writeSync(p, payload);
    check("writeSync: bytesWritten matches", res.bytesWritten === payload.length);
    check("writeSync: content round-trips",  fs.readFileSync(p).equals(payload));
    var leftovers = fs.readdirSync(dir.path).filter(function (n) {
      return n.indexOf("sync-state.bin.tmp-") === 0;
    });
    check("writeSync: no temp file leaked", leftovers.length === 0);
  } finally {
    dir.cleanup();
  }
}

function testExclusiveRefusesExistingFile() {
  var dir = _tmpDir();
  try {
    var p = path.join(dir.path, "victim.bin");
    fs.writeFileSync(p, "ATTACKER PRE-CREATED THIS", { mode: 0o600 });
    var threw = null;
    var fd = null;
    try {
      fd = fs.openSync(p, EXCL_FLAGS, 0o600);
    } catch (e) { threw = e; }
    finally { if (fd !== null) { try { fs.closeSync(fd); } catch (_c) { /* ignore */ } } }
    check("excl flags: existing regular file refused with EEXIST",
          threw != null && threw.code === "EEXIST");
    // The pre-existing bytes must be intact — O_EXCL refused before any
    // truncation could happen (the old "w"/O_TRUNC flag would have wiped it).
    check("excl flags: pre-existing file NOT truncated",
          fs.readFileSync(p, "utf8") === "ATTACKER PRE-CREATED THIS");
  } finally {
    dir.cleanup();
  }
}

function testNoFollowRefusesSymlink() {
  var dir = _tmpDir();
  try {
    var victim = path.join(dir.path, "victim-secret.txt");
    fs.writeFileSync(victim, "SECRET", { mode: 0o600 });
    var link = path.join(dir.path, "staged.tmp");

    var symlinkOk = true;
    try {
      fs.symlinkSync(victim, link);
    } catch (_e) {
      // Windows without the SeCreateSymbolicLink privilege (common on CI
      // and dev boxes) cannot create symlinks. The O_NOFOLLOW property is
      // still exercised by the EEXIST-on-existing-file test above; skip
      // only the symlink-specific assertion here.
      symlinkOk = false;
    }

    if (symlinkOk) {
      var threw = null;
      var fd = null;
      try {
        fd = fs.openSync(link, EXCL_FLAGS, 0o600);
      } catch (e) { threw = e; }
      finally { if (fd !== null) { try { fs.closeSync(fd); } catch (_c) { /* ignore */ } } }
      check("excl flags: pre-existing symlink refused (not followed)",
            threw != null && (threw.code === "EEXIST" || threw.code === "ELOOP"));
      // The victim the symlink pointed at must be untouched — neither
      // truncated nor written through.
      check("excl flags: symlink target (victim) NOT written through",
            fs.readFileSync(victim, "utf8") === "SECRET");
    } else {
      check("excl flags: symlink case skipped (platform lacks symlink privilege)", true);
    }
  } finally {
    dir.cleanup();
  }
}

async function testSymlinkAtDestinationReplacedNotFollowed() {
  // A symlink planted at the DESTINATION path (not the temp path) must be
  // replaced by the atomic rename, not followed to its target. The temp
  // file is created next to the dest, then renamed over the symlink — the
  // rename swaps the directory entry, leaving the symlink's old target
  // (the victim) untouched.
  var dir = _tmpDir();
  try {
    var victim = path.join(dir.path, "outside-victim.bin");
    fs.writeFileSync(victim, "DO NOT OVERWRITE", { mode: 0o600 });
    var dest = path.join(dir.path, "dest-link.bin");

    var symlinkOk = true;
    try { fs.symlinkSync(victim, dest); }
    catch (_e) { symlinkOk = false; }

    if (!symlinkOk) {
      check("dest-symlink case skipped (platform lacks symlink privilege)", true);
      return;
    }

    var payload = Buffer.from("fresh contents", "utf8");
    await b.atomicFile.write(dest, payload);

    // dest is now a regular file with the new bytes (the rename replaced
    // the symlink entry). Open ONE no-follow fd and take both the type
    // check (fstat) and the byte read from that same descriptor — no
    // lstat-then-read against the path, which would be a check-then-use
    // file-system race (CWE-367). O_NOFOLLOW makes the open itself fail
    // if dest were still a symlink, so a successful open already proves
    // the rename replaced the link with a regular file.
    var destFd = fs.openSync(dest, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    try {
      var fst = fs.fstatSync(destFd);
      check("dest-symlink: destination is a regular file after write",
            fst.isFile() && !fst.isSymbolicLink());
      var destBytes = Buffer.alloc(fst.size);
      var got = 0;
      while (got < fst.size) {
        var n = fs.readSync(destFd, destBytes, got, fst.size - got, null);
        if (n === 0) break;
        got += n;
      }
      check("dest-symlink: destination holds the new bytes",
            got === payload.length && destBytes.equals(payload));
    } finally {
      fs.closeSync(destFd);
    }
    // ... and the victim the symlink pointed at was NOT written through.
    check("dest-symlink: symlink target (victim) untouched",
          fs.readFileSync(victim, "utf8") === "DO NOT OVERWRITE");
  } finally {
    dir.cleanup();
  }
}

async function run() {
  await testWriteRoundTrips();
  testWriteSyncRoundTrips();
  testExclusiveRefusesExistingFile();
  testNoFollowRefusesSymlink();
  await testSymlinkAtDestinationReplacedNotFollowed();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
