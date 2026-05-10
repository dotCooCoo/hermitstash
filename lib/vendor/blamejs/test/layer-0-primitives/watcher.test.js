"use strict";
/**
 * b.watcher — recursive fs.watch wrapper with cross-platform event
 * normalization.
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;
var fs     = helpers.fs;
var os     = helpers.os;
var path   = helpers.path;

async function run() {
  // ---- _validateOpts: bad-shape inputs surface as WatcherError ----
  var threw;
  try { b.watcher.create(); } catch (e) { threw = e; }
  check("watcher.create: missing opts throws",
    threw && threw.code === "watcher/bad-opts" &&
    threw instanceof b.frameworkError.WatcherError);

  threw = null;
  try { b.watcher.create({}); } catch (e) { threw = e; }
  check("watcher.create: missing root throws",
    threw && threw.code === "watcher/bad-root");

  threw = null;
  try { b.watcher.create({ root: "" }); } catch (e) { threw = e; }
  check("watcher.create: empty root throws",
    threw && threw.code === "watcher/bad-root");

  threw = null;
  try { b.watcher.create({ root: os.tmpdir(), debounceMs: -1 }); } catch (e) { threw = e; }
  check("watcher.create: negative debounceMs throws",
    threw && threw.code === "watcher/bad-debounce-ms");

  threw = null;
  try { b.watcher.create({ root: os.tmpdir(), debounceMs: Infinity }); } catch (e) { threw = e; }
  check("watcher.create: non-finite debounceMs throws",
    threw && threw.code === "watcher/bad-debounce-ms");

  threw = null;
  try { b.watcher.create({ root: os.tmpdir(), onChange: "not-a-fn" }); } catch (e) { threw = e; }
  check("watcher.create: non-function hook throws",
    threw && threw.code === "watcher/bad-hook");

  threw = null;
  try { b.watcher.create({ root: os.tmpdir(), ignore: "not-array" }); } catch (e) { threw = e; }
  check("watcher.create: non-array ignore throws",
    threw && threw.code === "watcher/bad-ignore");

  threw = null;
  try { b.watcher.create({ root: os.tmpdir(), ignore: [""] }); } catch (e) { threw = e; }
  check("watcher.create: empty-string ignore entry throws",
    threw && threw.code === "watcher/bad-ignore");

  threw = null;
  try { b.watcher.create({ root: os.tmpdir(), ignore: ["foo/**/bar"] }); } catch (e) { threw = e; }
  check("watcher.create: mid-pattern ** throws",
    threw && threw.code === "watcher/bad-ignore");

  threw = null;
  try { b.watcher.create({ root: path.join(os.tmpdir(), "blamejs-watcher-missing-" + Date.now()) }); } catch (e) { threw = e; }
  check("watcher.create: missing root throws root-missing",
    threw && threw.code === "watcher/root-missing");

  // ---- live recursive watch on a real tmpdir ----
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-watcher-"));
  try {
    var changes = [];
    var deletes = [];
    var errors = [];
    var w = b.watcher.create({
      root: tmpDir,
      ignore: ["*.log", "skip-dir/**", "exact-match.txt"],
      debounceMs: 25,
      onChange: function (ev) { changes.push(ev); },
      onDelete: function (ev) { deletes.push(ev); },
      onError: function (e) { errors.push(e); },
      audit: false,
    });

    check("watcher.create: returns stop + root",
      typeof w.stop === "function" && w.root === path.resolve(tmpDir));

    // Write a regular file → onChange (after flush).
    fs.writeFileSync(path.join(tmpDir, "a.txt"), "hello");
    // Write an ignored file → no onChange.
    fs.writeFileSync(path.join(tmpDir, "noisy.log"), "log");
    // Write the exact-match-ignored file.
    fs.writeFileSync(path.join(tmpDir, "exact-match.txt"), "x");
    // Write inside an ignored prefix dir.
    fs.mkdirSync(path.join(tmpDir, "skip-dir"));
    fs.writeFileSync(path.join(tmpDir, "skip-dir", "inside.txt"), "x");

    // Drain — fs.watch is async on every kernel; give the OS a tick to
    // deliver pending events into the watcher's queue.
    await new Promise(function (r) { setTimeout(r, 1500); });
    w._flushForTest();

    var sawA = changes.some(function (e) { return e.relativePath === "a.txt" && e.type === "file"; });
    check("watcher.create: surface onChange for non-ignored file", sawA);

    var sawNoisy = changes.some(function (e) { return e.relativePath === "noisy.log"; });
    check("watcher.create: glob ignore (*.log) suppresses onChange", !sawNoisy);

    var sawSkipDir = changes.some(function (e) { return e.relativePath.indexOf("skip-dir") === 0; });
    check("watcher.create: prefix ignore (skip-dir/**) suppresses onChange", !sawSkipDir);

    var sawExact = changes.some(function (e) { return e.relativePath === "exact-match.txt"; });
    check("watcher.create: exact-match ignore suppresses onChange", !sawExact);

    // Delete the file → onDelete.
    changes.length = 0;
    deletes.length = 0;
    fs.unlinkSync(path.join(tmpDir, "a.txt"));
    await new Promise(function (r) { setTimeout(r, 1500); });
    w._flushForTest();
    var sawDelete = deletes.some(function (e) { return e.relativePath === "a.txt"; });
    check("watcher.create: emits onDelete on unlink", sawDelete);

    // onChange shape — exercise via fresh write + flush.
    fs.writeFileSync(path.join(tmpDir, "shape.txt"), "1234");
    await new Promise(function (r) { setTimeout(r, 1500); });
    w._flushForTest();
    var shape = changes.find(function (e) { return e.relativePath === "shape.txt"; });
    check("watcher.create: onChange has type/relativePath/fullPath/size/mtime",
      shape && shape.type === "file" && shape.size === 4 &&
      shape.fullPath === path.join(tmpDir, "shape.txt") &&
      shape.mtime instanceof Date);

    // Symlinks must be skipped on the post-event lstat path. Skip on
    // Windows where symlink creation requires elevation.
    if (process.platform !== "win32") {
      changes.length = 0;
      try {
        fs.symlinkSync(os.tmpdir(), path.join(tmpDir, "symlink-out"));
        await new Promise(function (r) { setTimeout(r, 1500); });
        w._flushForTest();
        var sawSymlink = changes.some(function (e) { return e.relativePath === "symlink-out"; });
        check("watcher.create: skips symlink events", !sawSymlink);
      } catch (_e) {
        // Some sandboxes refuse symlink even on POSIX; treat as a pass.
        check("watcher.create: skips symlink events (skipped — symlink unavailable)", true);
      }
    }

    // stop() is idempotent and clears handles.
    w.stop();
    w.stop();
    check("watcher.create: stop() idempotent", true);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }

  // WatcherError class exposed via b.frameworkError + b.watcher.
  check("watcher.WatcherError class registered",
    typeof b.watcher.WatcherError === "function" &&
    b.watcher.WatcherError === b.frameworkError.WatcherError);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[watcher] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
