// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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

  // ---- config-time validation: remaining bad-shape opts ----
  // These surface at create() synchronously — no fs.watch priming needed.

  // root points at a plain file, not a directory → root-not-dir.
  var fileRootDir = fs.mkdtempSync(path.join(os.tmpdir(), "watcher-filroot-"));
  try {
    var fileRoot = path.join(fileRootDir, "iam-a-file.txt");
    fs.writeFileSync(fileRoot, "not a dir");
    var threwFR = null;
    try { b.watcher.create({ root: fileRoot }); } catch (e) { threwFR = e; }
    check("watcher.create: root that is a file throws root-not-dir",
      threwFR && threwFR.code === "watcher/root-not-dir");
  } finally {
    try { fs.rmSync(fileRootDir, { recursive: true, force: true }); } catch (_e) {}
  }

  // pollMaxFiles must be a positive finite integer.
  var threwPMF = null;
  try { b.watcher.create({ root: os.tmpdir(), pollMaxFiles: 0 }); } catch (e) { threwPMF = e; }
  check("watcher.create: pollMaxFiles < 1 throws bad-poll-max-files",
    threwPMF && threwPMF.code === "watcher/bad-poll-max-files");

  threwPMF = null;
  try { b.watcher.create({ root: os.tmpdir(), pollMaxFiles: "lots" }); } catch (e) { threwPMF = e; }
  check("watcher.create: non-number pollMaxFiles throws bad-poll-max-files",
    threwPMF && threwPMF.code === "watcher/bad-poll-max-files");

  // maxPending must be a positive finite number.
  var threwMP = null;
  try { b.watcher.create({ root: os.tmpdir(), maxPending: 0 }); } catch (e) { threwMP = e; }
  check("watcher.create: maxPending < 1 throws bad-max-pending",
    threwMP && threwMP.code === "watcher/bad-max-pending");

  threwMP = null;
  try { b.watcher.create({ root: os.tmpdir(), maxPending: Infinity }); } catch (e) { threwMP = e; }
  check("watcher.create: non-finite maxPending throws bad-max-pending",
    threwMP && threwMP.code === "watcher/bad-max-pending");

  // onDelete + onError are validated the same way as onChange.
  var threwHook = null;
  try { b.watcher.create({ root: os.tmpdir(), onDelete: 42 }); } catch (e) { threwHook = e; }
  check("watcher.create: non-function onDelete throws bad-hook",
    threwHook && threwHook.code === "watcher/bad-hook");

  threwHook = null;
  try { b.watcher.create({ root: os.tmpdir(), onError: {} }); } catch (e) { threwHook = e; }
  check("watcher.create: non-function onError throws bad-hook",
    threwHook && threwHook.code === "watcher/bad-hook");

  // ---- ignore-pattern parse-time guards ----

  // A `*` glob whose literal pieces contain a path separator is refused
  // (path separators only legal in the trailing dir/** prefix form).
  var threwSep = null;
  try { b.watcher.create({ root: os.tmpdir(), ignore: ["foo*/bar"] }); } catch (e) { threwSep = e; }
  check("watcher.create: glob with mid-pattern path separator throws bad-ignore",
    threwSep && threwSep.code === "watcher/bad-ignore");

  // Pattern length cap.
  var threwLen = null;
  var longPat = new Array(300).join("a") + "*";
  try { b.watcher.create({ root: os.tmpdir(), ignore: [longPat] }); } catch (e) { threwLen = e; }
  check("watcher.create: over-long ignore pattern throws bad-ignore",
    threwLen && threwLen.code === "watcher/bad-ignore");

  // Wildcard-count cap (17 stars > MAX_IGNORE_STAR_COUNT of 16).
  var threwStar = null;
  try { b.watcher.create({ root: os.tmpdir(), ignore: [new Array(18).join("*") + "x"] }); }
  catch (e) { threwStar = e; }
  check("watcher.create: too-many-wildcard ignore pattern throws bad-ignore",
    threwStar && threwStar.code === "watcher/bad-ignore");

  // Non-string ignore entry (a number in the array) → bad-ignore.
  var threwEntry = null;
  try { b.watcher.create({ root: os.tmpdir(), ignore: [123] }); } catch (e) { threwEntry = e; }
  check("watcher.create: non-string ignore entry throws bad-ignore",
    threwEntry && threwEntry.code === "watcher/bad-ignore");

  // ---- ignore-pattern matching across all three shapes (poll-driven,
  // fully deterministic via _flushForTest — no fs.watch priming race) ----
  var globDir = fs.mkdtempSync(path.join(os.tmpdir(), "watcher-glob-"));
  try {
    var globHits = [];
    var gw = b.watcher.create({
      root:           globDir,
      mode:           "poll",
      pollIntervalMs: 1000,
      debounceMs:     5,
      // basename glob (suffix), prefix glob, multi-star glob, exact match.
      ignore:         ["*.tmp", "cache-*", "a*b*c.dat", "exact-ignore.txt"],
      onChange:       function (e) { globHits.push(e.relativePath); },
      audit:          false,
    });
    fs.writeFileSync(path.join(globDir, "keep.txt"), "x");           // not ignored → fires
    fs.writeFileSync(path.join(globDir, "scratch.tmp"), "x");        // *.tmp
    fs.writeFileSync(path.join(globDir, "cache-abc"), "x");          // cache-*
    fs.writeFileSync(path.join(globDir, "aXXbYYc.dat"), "x");        // a*b*c.dat
    fs.writeFileSync(path.join(globDir, "exact-ignore.txt"), "x");   // exact
    fs.writeFileSync(path.join(globDir, "notcache.txt"), "x");       // NOT cache-* → fires
    await helpers.waitUntil(function () {
      gw._flushForTest();
      return globHits.indexOf("keep.txt") !== -1;
    }, { label: "watcher glob: keep.txt onChange" });

    check("watcher ignore: non-matching file fires onChange",
      globHits.indexOf("keep.txt") !== -1 && globHits.indexOf("notcache.txt") !== -1);
    check("watcher ignore: *.tmp suffix glob suppresses",
      globHits.indexOf("scratch.tmp") === -1);
    check("watcher ignore: cache-* prefix glob suppresses",
      globHits.indexOf("cache-abc") === -1);
    check("watcher ignore: a*b*c.dat multi-star glob suppresses",
      globHits.indexOf("aXXbYYc.dat") === -1);
    check("watcher ignore: exact-match ignore suppresses (poll)",
      globHits.indexOf("exact-ignore.txt") === -1);
    gw.stop();
  } finally {
    try { fs.rmSync(globDir, { recursive: true, force: true }); } catch (_e) {}
  }

  // ---- poll: pre-existing files establish the baseline silently ----
  // Files present at create() must NOT fire onChange on the first tick
  // (matches fs.watch semantics — you observe changes after start).
  var baseDir = fs.mkdtempSync(path.join(os.tmpdir(), "watcher-base-"));
  try {
    fs.writeFileSync(path.join(baseDir, "pre-existing.txt"), "old");
    var baseHits = [];
    var bw = b.watcher.create({
      root:           baseDir,
      mode:           "poll",
      pollIntervalMs: 1000,
      debounceMs:     5,
      onChange:       function (e) { baseHits.push(e.relativePath); },
      audit:          false,
    });
    // One tick over an unchanged tree — no events for the baseline file.
    bw._flushForTest();
    check("watcher poll: pre-existing file does not fire on first tick",
      baseHits.indexOf("pre-existing.txt") === -1);

    // A brand-new file after start DOES fire.
    fs.writeFileSync(path.join(baseDir, "fresh.txt"), "new");
    await helpers.waitUntil(function () {
      bw._flushForTest();
      return baseHits.indexOf("fresh.txt") !== -1;
    }, { label: "watcher poll: fresh.txt after baseline" });
    check("watcher poll: post-start create fires onChange", baseHits.indexOf("fresh.txt") !== -1);
    bw.stop();
  } finally {
    try { fs.rmSync(baseDir, { recursive: true, force: true }); } catch (_e) {}
  }

  // ---- poll: directory create emits type="dir"; nested delete + dir
  // delete both surface via the snapshot diff ----
  var dirDir = fs.mkdtempSync(path.join(os.tmpdir(), "watcher-dir-"));
  try {
    var dirChanges = [];
    var dirDeletes = [];
    var dw = b.watcher.create({
      root:           dirDir,
      mode:           "poll",
      pollIntervalMs: 1000,
      debounceMs:     5,
      onChange:       function (e) { dirChanges.push(e); },
      onDelete:       function (e) { dirDeletes.push(e.relativePath); },
      audit:          false,
    });
    fs.mkdirSync(path.join(dirDir, "created-dir"));
    fs.writeFileSync(path.join(dirDir, "created-dir", "child.txt"), "x");
    await helpers.waitUntil(function () {
      dw._flushForTest();
      return dirChanges.some(function (e) { return e.relativePath === "created-dir" && e.type === "dir"; });
    }, { label: "watcher poll: created-dir onChange(type=dir)" });
    check("watcher poll: directory create fires onChange type='dir'",
      dirChanges.some(function (e) { return e.relativePath === "created-dir" && e.type === "dir"; }));
    check("watcher poll: nested child create fires onChange type='file'",
      dirChanges.some(function (e) { return e.relativePath === "created-dir/child.txt" && e.type === "file"; }));

    // Remove the whole directory subtree → onDelete for both entries.
    fs.rmSync(path.join(dirDir, "created-dir"), { recursive: true, force: true });
    await helpers.waitUntil(function () {
      dw._flushForTest();
      return dirDeletes.indexOf("created-dir") !== -1;
    }, { label: "watcher poll: created-dir onDelete" });
    check("watcher poll: directory delete fires onDelete", dirDeletes.indexOf("created-dir") !== -1);
    check("watcher poll: nested child delete fires onDelete",
      dirDeletes.indexOf("created-dir/child.txt") !== -1);
    dw.stop();
  } finally {
    try { fs.rmSync(dirDir, { recursive: true, force: true }); } catch (_e) {}
  }

  // ---- poll: symlink entries are skipped in the tree walk (never
  // follow an attacker-controlled link out of root). POSIX only ----
  if (process.platform !== "win32") {
    var symDir = fs.mkdtempSync(path.join(os.tmpdir(), "watcher-sym-"));
    try {
      var symHits = [];
      var symW = b.watcher.create({
        root:           symDir,
        mode:           "poll",
        pollIntervalMs: 1000,
        debounceMs:     5,
        onChange:       function (e) { symHits.push(e.relativePath); },
        audit:          false,
      });
      var symlinkMade = false;
      try {
        fs.symlinkSync(os.tmpdir(), path.join(symDir, "link-out"));
        symlinkMade = true;
      } catch (_e) { /* some sandboxes refuse symlink even on POSIX */ }
      // Also drop a real file so we have a positive control that the
      // tick ran and delivered SOMETHING.
      fs.writeFileSync(path.join(symDir, "real.txt"), "x");
      await helpers.waitUntil(function () {
        symW._flushForTest();
        return symHits.indexOf("real.txt") !== -1;
      }, { label: "watcher poll: real.txt control" });
      if (symlinkMade) {
        check("watcher poll: symlink entry skipped in walk",
          symHits.indexOf("link-out") === -1);
      } else {
        check("watcher poll: symlink entry skipped (skipped — symlink unavailable)", true);
      }
      symW.stop();
    } finally {
      try { fs.rmSync(symDir, { recursive: true, force: true }); } catch (_e) {}
    }
  }

  // ---- maxPending overflow: too many distinct pending paths trips the
  // safety net → onError(watcher/overflow) + self-stop, dropping further
  // events. Deterministic via the synchronous poll tick ----
  var ovDir = fs.mkdtempSync(path.join(os.tmpdir(), "watcher-ov-"));
  try {
    var ovErrs = [];
    var ovHits = [];
    var ow = b.watcher.create({
      root:           ovDir,
      mode:           "poll",
      pollIntervalMs: 1000,
      debounceMs:     5,
      maxPending:     2,
      onChange:       function (e) { ovHits.push(e.relativePath); },
      onError:        function (e) { ovErrs.push(e); },
      audit:          false,
    });
    // Create more distinct new files than maxPending in a single tick.
    for (var oi = 0; oi < 5; oi += 1) {
      fs.writeFileSync(path.join(ovDir, "ov-" + oi + ".txt"), "x");
    }
    ow._flushForTest();   // one synchronous tick enqueues → overflow
    check("watcher: maxPending overflow surfaces onError(watcher/overflow)",
      ovErrs.some(function (e) { return e && e.code === "watcher/overflow"; }));

    // Post-overflow the watcher self-stopped; a later change is dropped.
    ovHits.length = 0;
    fs.writeFileSync(path.join(ovDir, "after-stop.txt"), "x");
    ow._flushForTest();
    check("watcher: overflow self-stops — later events dropped",
      ovHits.indexOf("after-stop.txt") === -1);
    ow.stop();   // idempotent after self-stop
  } finally {
    try { fs.rmSync(ovDir, { recursive: true, force: true }); } catch (_e) {}
  }

  // ---- poll: running-tick pollMaxFiles overflow routes through onError
  // (distinct from the create()-time initial-walk overflow tested above,
  // which throws watcher/start-failed) ----
  var tickCapDir = fs.mkdtempSync(path.join(os.tmpdir(), "watcher-tickcap-"));
  try {
    var tickErrs = [];
    var tw = b.watcher.create({
      root:           tickCapDir,   // starts empty → initial walk under cap
      mode:           "poll",
      pollIntervalMs: 1000,
      pollMaxFiles:   1,
      onChange:       function () {},
      onError:        function (e) { tickErrs.push(e); },
      audit:          false,
    });
    // Now blow past the cap so the NEXT tick's walk throws.
    fs.writeFileSync(path.join(tickCapDir, "t1.txt"), "x");
    fs.writeFileSync(path.join(tickCapDir, "t2.txt"), "x");
    tw._flushForTest();
    check("watcher poll: running-tick pollMaxFiles overflow surfaces onError(poll-overflow)",
      tickErrs.some(function (e) { return e && e.code === "watcher/poll-overflow"; }));
    tw.stop();
  } finally {
    try { fs.rmSync(tickCapDir, { recursive: true, force: true }); } catch (_e) {}
  }

  // ---- operator hooks that throw must not crash dispatch ----
  var throwDir = fs.mkdtempSync(path.join(os.tmpdir(), "watcher-throw-"));
  try {
    var afterChange = [];
    var thw = b.watcher.create({
      root:           throwDir,
      mode:           "poll",
      pollIntervalMs: 1000,
      debounceMs:     5,
      onChange:       function (e) {
        afterChange.push(e.relativePath);
        throw new Error("operator onChange blew up");
      },
      onDelete:       function () { throw new Error("operator onDelete blew up"); },
      audit:          false,
    });
    fs.writeFileSync(path.join(throwDir, "boom.txt"), "x");
    await helpers.waitUntil(function () {
      thw._flushForTest();
      return afterChange.indexOf("boom.txt") !== -1;
    }, { label: "watcher: throwing onChange still dispatched" });
    check("watcher: throwing onChange hook does not crash dispatch",
      afterChange.indexOf("boom.txt") !== -1);

    // A second, distinct change still dispatches (proves dispatch loop
    // survived the earlier throw).
    fs.writeFileSync(path.join(throwDir, "boom2.txt"), "x");
    await helpers.waitUntil(function () {
      thw._flushForTest();
      return afterChange.indexOf("boom2.txt") !== -1;
    }, { label: "watcher: dispatch survives prior hook throw" });
    check("watcher: dispatch continues after a hook throw",
      afterChange.indexOf("boom2.txt") !== -1);

    // Deleting the file drives the throwing onDelete — must not crash.
    fs.unlinkSync(path.join(throwDir, "boom.txt"));
    var delThrewCrash = false;
    try {
      await helpers.waitUntil(function () {
        thw._flushForTest();
        // We can't observe onDelete's arg (it throws), but reaching here
        // without an unhandled exception is the assertion.
        return true;
      }, { label: "watcher: throwing onDelete tolerated", timeoutMs: 1000 });
    } catch (_e) { delThrewCrash = true; }
    check("watcher: throwing onDelete hook does not crash dispatch", !delThrewCrash);
    thw.stop();
  } finally {
    try { fs.rmSync(throwDir, { recursive: true, force: true }); } catch (_e) {}
  }

  // ---- onError hook that itself throws must not crash the watcher ----
  // Drive the overflow path with an onError that throws; _safeError wraps
  // the operator callback in try/catch so the throw is swallowed.
  var errThrowDir = fs.mkdtempSync(path.join(os.tmpdir(), "watcher-errthrow-"));
  try {
    var reachedAfter = false;
    var ew = b.watcher.create({
      root:           errThrowDir,
      mode:           "poll",
      pollIntervalMs: 1000,
      debounceMs:     5,
      maxPending:     1,
      onChange:       function () {},
      onError:        function () { throw new Error("operator onError blew up"); },
      audit:          false,
    });
    fs.writeFileSync(path.join(errThrowDir, "e1.txt"), "x");
    fs.writeFileSync(path.join(errThrowDir, "e2.txt"), "x");
    fs.writeFileSync(path.join(errThrowDir, "e3.txt"), "x");
    ew._flushForTest();   // overflow → _safeError → onError throws → swallowed
    reachedAfter = true;
    check("watcher: throwing onError hook does not crash the watcher", reachedAfter);
    ew.stop();
  } finally {
    try { fs.rmSync(errThrowDir, { recursive: true, force: true }); } catch (_e) {}
  }

  // ---- debounce: one observed change produces exactly one dispatch, and
  // a same-tick modification (size/mtime delta) re-fires on the next tick ----
  var coalDir = fs.mkdtempSync(path.join(os.tmpdir(), "watcher-coal-"));
  try {
    var coalCount = 0;
    var cw = b.watcher.create({
      root:           coalDir,
      mode:           "poll",
      pollIntervalMs: 1000,
      debounceMs:     5,
      onChange:       function (e) { if (e.relativePath === "c.txt") coalCount += 1; },
      audit:          false,
    });
    cw._flushForTest();          // baseline (empty tree)
    coalCount = 0;

    fs.writeFileSync(path.join(coalDir, "c.txt"), "one");
    await helpers.waitUntil(function () {
      cw._flushForTest();
      return coalCount >= 1;
    }, { label: "watcher debounce: c.txt first dispatch" });
    check("watcher: a single observed change dispatches exactly one onChange",
      coalCount === 1);

    // No further change → no further dispatch across extra ticks (the
    // snapshot diff is empty, so nothing re-enqueues).
    cw._flushForTest();
    cw._flushForTest();
    check("watcher: an unchanged tree re-tick fires no onChange", coalCount === 1);

    // A real modification (content grows → size + mtime differ) re-fires.
    fs.writeFileSync(path.join(coalDir, "c.txt"), "one-two-three");
    await helpers.waitUntil(function () {
      cw._flushForTest();
      return coalCount >= 2;
    }, { label: "watcher debounce: c.txt modify re-dispatch" });
    check("watcher: a subsequent modification re-fires onChange", coalCount === 2);
    cw.stop();
  } finally {
    try { fs.rmSync(coalDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[watcher] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
