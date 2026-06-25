"use strict";
// b.atomicFile.openAppendNoFollowSync — O_NOFOLLOW append open for long-lived
// append sinks (active log file kept open across appends + reopened on
// rotation). Creates the file if absent and appends if it is a regular file,
// but refuses a symlink at the final path component (ELOOP) instead of
// following it — so log writes cannot be redirected to an attacker-chosen
// file (CWE-59). RED before 0.15.16: log-stream-local opened the active log
// with a bare `openSync(path, "a")`, following a symlink planted at the path.

var fs   = require("node:fs");
var os   = require("node:os");
var path = require("node:path");
var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var localProto = require("../../lib/log-stream-local");

function run() {
  check("b.atomicFile.openAppendNoFollowSync is a function",
        typeof b.atomicFile.openAppendNoFollowSync === "function");

  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-append-nofollow-"));
  try {
    // --- primitive: create-if-absent + append to a regular file ---
    var p = path.join(dir, "active.log");
    var fd = b.atomicFile.openAppendNoFollowSync(p, 0o600);
    check("returns a numeric fd, creating the file if absent",
          typeof fd === "number" && fd >= 0 && fs.existsSync(p));
    fs.writeSync(fd, Buffer.from("line-1\n"));
    fs.closeSync(fd);
    var fd2 = b.atomicFile.openAppendNoFollowSync(p, 0o600);
    fs.writeSync(fd2, Buffer.from("line-2\n"));
    fs.closeSync(fd2);
    check("appends rather than truncates an existing regular file",
          fs.readFileSync(p, "utf8") === "line-1\nline-2\n");

    // --- primitive: symlink at the final component is refused (POSIX) ---
    if (process.platform !== "win32") {
      var victim = path.join(dir, "victim.txt");
      fs.writeFileSync(victim, "ORIGINAL");
      var linkPath = path.join(dir, "evil.log");
      var symlinkMade = false;
      try { fs.symlinkSync(victim, linkPath); symlinkMade = true; } catch (_e) { /* no symlink priv */ }
      if (symlinkMade) {
        var loopCode = null;
        try {
          var bad = b.atomicFile.openAppendNoFollowSync(linkPath, 0o600);
          fs.closeSync(bad);
        } catch (e) { loopCode = e && e.code; }
        check("symlink final component refused with ELOOP (not followed)", loopCode === "ELOOP");
        check("the symlink target was never written through",
              fs.readFileSync(victim, "utf8") === "ORIGINAL");
      }

      // --- consumer path (#356): log-stream-local refuses a symlinked active log ---
      var logDir = path.join(dir, "logs");
      fs.mkdirSync(logDir, { recursive: true });
      var logVictim = path.join(dir, "log-victim.txt");
      fs.writeFileSync(logVictim, "VICTIM-LOG");
      var activePath = path.join(logDir, "blamejs.log");   // <prefix>.log
      var planted = false;
      try { fs.symlinkSync(logVictim, activePath); planted = true; } catch (_e) { /* no priv */ }
      if (planted) {
        var refusedCode = null;
        var sink = null;
        try { sink = localProto.create({ dir: logDir }); }
        catch (e) { refusedCode = e && e.code; }
        if (sink) { try { sink.close(); } catch (_c) { /* ignore */ } }
        check("log-stream-local refuses to open a symlinked active log path",
              refusedCode === "SYMLINK_REFUSED");
        check("log-stream-local never writes through the symlink to the victim",
              fs.readFileSync(logVictim, "utf8") === "VICTIM-LOG");
      }
    }
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
  return Promise.resolve();
}

module.exports = { run: run };
if (require.main === module) {
  Promise.resolve(run()).then(
    function () { console.log("OK — atomicFile.openAppendNoFollowSync + log-stream-local symlink refusal (" + helpers.getChecks() + " checks)"); process.exit(0); },
    function (e) { console.error("FAIL: " + (e && e.message)); process.exit(1); }
  );
}
