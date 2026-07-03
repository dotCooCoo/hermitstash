// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// b.atomicFile.openNoFollowSync — O_NOFOLLOW read-only open for streaming reads
// that cannot buffer (static-serve range / SRI hashing, object-store download).
// Opens a path read-only and refuses a symlink at the final component (ELOOP)
// instead of following it — the streaming counterpart to fdSafeReadSync's
// refuseSymlink. POSIX-only; on a platform without O_NOFOLLOW the flag is 0.

var fs   = require("node:fs");
var os   = require("node:os");
var path = require("node:path");
var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  check("b.atomicFile.openNoFollowSync is a function",
        typeof b.atomicFile.openNoFollowSync === "function");

  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-nofollow-"));
  try {
    var real = path.join(dir, "real.txt");
    fs.writeFileSync(real, "payload-bytes");

    // Regular file: opens, returns a numeric fd, reads the bytes, closes.
    var fd = b.atomicFile.openNoFollowSync(real);
    check("returns a numeric fd for a regular file", typeof fd === "number" && fd >= 0);
    var buf = Buffer.alloc(64);
    var n = fs.readSync(fd, buf, 0, buf.length, 0);
    fs.closeSync(fd);
    check("the fd reads the real file's bytes", buf.slice(0, n).toString("utf8") === "payload-bytes");

    // Stream from the fd (the intended consumer shape).
    var streamed = "";
    // (synchronous read above already proves the fd; the stream shape is
    // exercised by static-serve / object-store integration — here just assert
    // the fd is consumable by createReadStream without double-open.)
    var fd2 = b.atomicFile.openNoFollowSync(real);
    var rs = fs.createReadStream(real, { fd: fd2 });
    rs.on("data", function (c) { streamed += c.toString("utf8"); });
    // Missing file → ENOENT (propagated raw).
    var enoentCode = null;
    try { b.atomicFile.openNoFollowSync(path.join(dir, "nope.txt")); }
    catch (e) { enoentCode = e && e.code; }
    check("missing file throws ENOENT", enoentCode === "ENOENT");

    // Symlink at the final component → refused with ELOOP (POSIX). On a
    // platform without O_NOFOLLOW (Windows) the flag is 0 and the open follows;
    // symlink creation also often requires privilege there, so gate the assertion.
    if (process.platform !== "win32") {
      var linkPath = path.join(dir, "link.txt");
      var symlinkMade = false;
      try { fs.symlinkSync(real, linkPath); symlinkMade = true; } catch (_e) { /* no symlink priv */ }
      if (symlinkMade) {
        var loopCode = null;
        try { b.atomicFile.openNoFollowSync(linkPath); }
        catch (e) { loopCode = e && e.code; }
        check("symlink final component is refused (ELOOP, not followed)", loopCode === "ELOOP");
      }
    }

    // Await the stream's end BEFORE the finally cleanup. Without the await,
    // the try block returns its promise and the finally runs synchronously —
    // removing the dir and leaving the stream's in-flight read (FSReqCallback)
    // alive past run(). Awaiting drains the read before cleanup.
    await new Promise(function (resolve, reject) {
      rs.on("end", function () {
        check("an fd from openNoFollowSync is consumable by createReadStream",
              streamed === "payload-bytes");
        resolve();
      });
      rs.on("error", reject);
    });
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

module.exports = { run: run };
if (require.main === module) {
  Promise.resolve(run()).then(
    function () { console.log("OK — atomicFile.openNoFollowSync (" + helpers.getChecks() + " checks)"); process.exit(0); },
    function (e) { console.error("FAIL: " + (e && e.message)); process.exit(1); }
  );
}
