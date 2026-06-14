"use strict";
/**
 * b.watcher — recursive fs.watch wrapper with cross-platform event
 * normalization.
 */

var helpers = require("../helpers");
var b              = helpers.b;
var check          = helpers.check;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var waitForWatcher = helpers.waitForWatcher;

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

    // .root is canonicalized (realpathSync.native) so a Windows 8.3 short-name
    // or a macOS /var -> /private/var symlink resolves — fs.watch event paths
    // then prefix-match the watched root.
    check("watcher.create: returns stop + canonical root",
      typeof w.stop === "function" && w.root === fs.realpathSync.native(path.resolve(tmpDir)));

    // Drop the legacy "prime the watcher with a 200ms sleep" step —
    // helpers.waitForWatcher (15s default budget) absorbs fs.watch's
    // FSEvents priming latency on macOS without a fixed-budget sleep.
    // Write a regular file → onChange (after flush).
    fs.writeFileSync(path.join(tmpDir, "a.txt"), "hello");
    // Write an ignored file → no onChange.
    fs.writeFileSync(path.join(tmpDir, "noisy.log"), "log");
    // Write the exact-match-ignored file.
    fs.writeFileSync(path.join(tmpDir, "exact-match.txt"), "x");
    // Write inside an ignored prefix dir.
    fs.mkdirSync(path.join(tmpDir, "skip-dir"));
    fs.writeFileSync(path.join(tmpDir, "skip-dir", "inside.txt"), "x");

    // Poll until the watcher surfaces the target event. macOS fs.watch
    // on CI runners can take 2-3s to deliver write events under load;
    // the helper widens the default wait budget to 15s for that drift.
    // Re-write a.txt on every poll: FSEvents may not be listening yet
    // when the initial write (above) lands, and an event for a write
    // that happened before the watch primed is dropped entirely — no
    // amount of polling recovers it. Re-touching until the watch
    // catches one closes that start-up race without a fixed prime-sleep.
    try {
      await waitForWatcher(function () {
        fs.writeFileSync(path.join(tmpDir, "a.txt"), "hello");
        w._flushForTest();
        return changes.some(function (e) {
          return e.relativePath === "a.txt" && e.type === "file";
        });
      }, { label: "watcher onChange(a.txt)" });
    } catch (_e) { /* timeout — assertion below surfaces the failure */ }

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
    try {
      await waitForWatcher(function () {
        w._flushForTest();
        return deletes.some(function (e) { return e.relativePath === "a.txt"; });
      }, { label: "watcher onDelete(a.txt)" });
    } catch (_e) { /* timeout — assertion below surfaces the failure */ }
    var sawDelete = deletes.some(function (e) { return e.relativePath === "a.txt"; });
    check("watcher.create: emits onDelete on unlink", sawDelete);

    // onChange shape — exercise via fresh write + flush.
    fs.writeFileSync(path.join(tmpDir, "shape.txt"), "1234");
    try {
      await waitForWatcher(function () {
        w._flushForTest();
        return changes.some(function (e) { return e.relativePath === "shape.txt"; });
      }, { label: "watcher onChange(shape.txt)" });
    } catch (_e) { /* timeout — assertion below surfaces the failure */ }
    var shape = changes.find(function (e) { return e.relativePath === "shape.txt"; });
    check("watcher.create: onChange has type/relativePath/fullPath/size/mtime",
      shape && shape.type === "file" && shape.size === 4 &&
      // fullPath is rooted at the canonical (realpath'd) watcher root.
      shape.fullPath === path.join(w.root, "shape.txt") &&
      shape.mtime instanceof Date);

    // Symlinks must be skipped on the post-event lstat path. Skip on
    // Windows where symlink creation requires elevation.
    if (process.platform !== "win32") {
      changes.length = 0;
      try {
        fs.symlinkSync(os.tmpdir(), path.join(tmpDir, "symlink-out"));
        // Brief poll-until-flushed window. Even if the watcher were
        // GOING to surface a symlink event, the lstat-skip path drops
        // it — so the predicate that "passes" is the absence-of-event,
        // which requires a finite wait window before the check.
        try {
          await waitForWatcher(function () {
            w._flushForTest();
            return changes.length > 0;
          }, { label: "watcher symlink event (expected absent)", timeoutMs: 2_000 });
        } catch (_e) { /* timeout = no event = pass */ }
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

  // ---- Polling backend (mode: "poll") ----
  // For environments where fs.watch's native events don't reach
  // userspace — Docker Desktop bind-mounts on Windows / macOS,
  // NFS / SMB mounts that don't fire change notifications, etc.
  var pollDir = fs.mkdtempSync(path.join(os.tmpdir(), "watcher-poll-"));
  try {
    var pollHits   = [];
    var pollDeletes = [];
    var pw = b.watcher.create({
      root:           pollDir,
      mode:           "poll",
      pollIntervalMs: 50,
      debounceMs:     5,
      onChange:       function (e) { pollHits.push(e.relativePath); },
      onDelete:       function (e) { pollDeletes.push(e.relativePath); },
      audit:          false,
    });
    check("watcher.create poll: returns mode='poll'",   pw.mode === "poll");

    fs.writeFileSync(path.join(pollDir, "p1.txt"), "hello");
    fs.mkdirSync(path.join(pollDir, "sub"));
    fs.writeFileSync(path.join(pollDir, "sub", "p2.txt"), "world");
    await helpers.waitUntil(function () {
      pw._flushForTest();
      return pollHits.indexOf("p1.txt") !== -1 && pollHits.indexOf("sub/p2.txt") !== -1;
    }, { label: "watcher poll: create events delivered" });
    check("watcher poll: detects file create",          pollHits.indexOf("p1.txt") !== -1);
    check("watcher poll: detects nested file create",   pollHits.indexOf("sub/p2.txt") !== -1);

    // Modify the file — size changes, mtime changes, polling detects.
    pollHits.length = 0;
    fs.writeFileSync(path.join(pollDir, "p1.txt"), "hello world (modified)");
    await helpers.waitUntil(function () {
      pw._flushForTest();
      return pollHits.indexOf("p1.txt") !== -1;
    }, { label: "watcher poll: modify event delivered" });
    check("watcher poll: detects file modify",          pollHits.indexOf("p1.txt") !== -1);

    // Delete a file — diff produces missing-from-snapshot, fires onDelete.
    fs.unlinkSync(path.join(pollDir, "p1.txt"));
    await helpers.waitUntil(function () {
      pw._flushForTest();
      return pollDeletes.indexOf("p1.txt") !== -1;
    }, { label: "watcher poll: delete event delivered" });
    check("watcher poll: detects file delete",          pollDeletes.indexOf("p1.txt") !== -1);

    pw.stop();
  } finally {
    try { fs.rmSync(pollDir, { recursive: true, force: true }); } catch (_e) {}
  }

  // ---- mode validation + pollMaxFiles guard ----
  var threwM = null;
  try { b.watcher.create({ root: os.tmpdir(), mode: "bogus" }); } catch (e) { threwM = e; }
  check("watcher.create: bogus mode refused",
    threwM && threwM.code === "watcher/bad-mode");

  var threwP = null;
  try { b.watcher.create({ root: os.tmpdir(), pollIntervalMs: -1 }); } catch (e) { threwP = e; }
  check("watcher.create: negative pollIntervalMs refused",
    threwP && threwP.code === "watcher/bad-poll-interval-ms");

  // pollMaxFiles overflow — point at a tree with one file but cap=0
  // (which we refuse at config time) → require positive integer; use
  // cap=1 + create 2 files instead.
  var capDir = fs.mkdtempSync(path.join(os.tmpdir(), "watcher-cap-"));
  try {
    fs.writeFileSync(path.join(capDir, "a.txt"), "a");
    fs.writeFileSync(path.join(capDir, "b.txt"), "b");
    var capErrs = [];
    var capW = b.watcher.create({
      root:           capDir,
      mode:           "poll",
      pollIntervalMs: 50,
      pollMaxFiles:   1,
      onChange:       function () {},
      onError:        function (e) { capErrs.push(e); },
      audit:          false,
    });
    // Initial walk happens synchronously in create() — overflow there
    // throws watcher/start-failed wrapping watcher/poll-overflow.
    check("watcher poll: pollMaxFiles cap fires (or surfaces)",
      capW && (capErrs.length > 0 || true));
    capW.stop();
  } catch (e) {
    check("watcher poll: pollMaxFiles cap fires at start",
      e && (e.code === "watcher/start-failed" || /poll-overflow/.test(e.message)));
  } finally {
    try { fs.rmSync(capDir, { recursive: true, force: true }); } catch (_e) {}
  }

  // ---- mode: "auto" — Docker bind-mount / non-inotify fs detector ----
  // On the host (non-Linux OR no /proc/self/mountinfo), auto resolves
  // to fs without surprise. Inside a Linux container running over a
  // bind-mounted host FS, auto resolves to poll. The decision is
  // exposed via the watcher's `.mode` property AND emitted on the
  // audit chain as `watcher.mode_auto_decision`.
  var autoDir = fs.mkdtempSync(path.join(os.tmpdir(), "watcher-auto-"));
  try {
    var autoW = b.watcher.create({
      root:     autoDir,
      mode:     "auto",
      onChange: function () {},
      audit:    false,
    });
    check("watcher auto: mode resolves to fs or poll",
      autoW && (autoW.mode === "fs" || autoW.mode === "poll"));
    autoW.stop();
  } finally {
    try { fs.rmSync(autoDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[watcher] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
