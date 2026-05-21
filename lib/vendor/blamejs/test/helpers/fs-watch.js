"use strict";
/**
 * test/helpers/fs-watch — shared test primitives for fs.watch /
 * fs.watchFile-backed tests.
 *
 * Two ergonomic issues fs.watch tests keep tripping on without these:
 *
 *   1. `fs.watchFile` records its `prev` baseline on the FIRST poll
 *      cycle, NOT at registration time. On a contended runner the
 *      first poll can land AFTER the test has already mutated the
 *      watched file — recording the post-mutation mtime as `prev`
 *      and never observing the transition the test asserts on.
 *      `backdateFile(path)` solves it: shift the source mtime an
 *      hour into the past before starting the watcher, so any
 *      subsequent mutation is unambiguously newer regardless of
 *      when the first poll lands.
 *
 *   2. `fs.watch` (kernel-event-based) needs an event-loop turn
 *      after construction before the kernel-side inotify / FSEvents
 *      machinery is fully primed. Plus, event delivery cadence can
 *      drift 2-3 seconds under CI runner contention. `waitForWatcher`
 *      handles both: polls the predicate every 50ms up to a 15s
 *      default budget (3× the canonical `helpers.waitUntil` budget;
 *      fast platforms still finish in milliseconds).
 *
 * Composes `helpers.waitUntil` for the wait machinery; the helper
 * here only widens the default budget + standardizes the label
 * format for fs-watch tests.
 *
 * Migration: every existing `fs.watch` / `fs.watchFile`-driven test
 * routes through `backdateFile` + `waitForWatcher` instead of
 * inlining the backdate trick + ad-hoc `_waitForGen` polls. The
 * `test-fs-watch-without-helper` codebase-patterns detector
 * enforces this composition for new tests.
 */

var nodeFs = require("node:fs");
var wait   = require("./wait");

var DEFAULT_BACKDATE_MS = 3_600_000;                                            // allow:raw-byte-literal — 1 hour, wall-clock ms
var DEFAULT_FS_WATCH_TIMEOUT_MS = 30_000;                                       // allow:raw-byte-literal — fs-watch wait budget, ms (3× helpers.waitUntil's default; ubuntu-latest at peak contention has shown 15s + 30s timing-race classes; pick the larger to absorb both)
var DEFAULT_FS_WATCH_INTERVAL_MS = 50;                                          // allow:raw-byte-literal — poll interval, ms

/**
 * Backdate a file's mtime + atime by `msAgo` milliseconds (default
 * one hour). Use IMMEDIATELY before starting an fs.watchFile-based
 * watcher so the first observed change is unambiguously newer than
 * the baseline the watcher's first poll records.
 *
 *   var src = path.join(ctx.dataDir, "privkey.pem");
 *   fs.writeFileSync(src, "PEM-V1\n");
 *   helpers.backdateFile(src);                  // 1h ago
 *   var watcher = b.vault.sealPemFile({ source: src, ... });
 *   // watcher first poll: prev = (1h ago)
 *   fs.writeFileSync(src, "PEM-V2\n");          // now
 *   await helpers.waitForWatcher(() => watcher.generation >= 2);
 *
 * Throws if `filePath` doesn't exist or isn't writable — same shape
 * as `fs.utimesSync` itself, since this is a thin wrapper.
 */
function backdateFile(filePath, msAgo) {
  if (typeof filePath !== "string" || filePath.length === 0) {
    throw new TypeError("backdateFile: filePath must be a non-empty string");
  }
  var ms = (typeof msAgo === "number" && isFinite(msAgo) && msAgo > 0)
    ? msAgo
    : DEFAULT_BACKDATE_MS;
  var when = new Date(Date.now() - ms);                                         // allow:raw-byte-literal — wall-clock ms
  nodeFs.utimesSync(filePath, when, when);
}

/**
 * Wait for an fs.watch / fs.watchFile-backed observation to become
 * true. Same predicate shape as `helpers.waitUntil` but widens the
 * default timeout to 15s (fs.watch's cross-platform event-delivery
 * cadence drifts 2-3s under CI runner contention; 5s — the default
 * `waitUntil` budget — has been the recurring failure point).
 *
 *   await helpers.waitForWatcher(function () {
 *     return changes.some(function (e) { return e.path === "a.txt"; });
 *   }, { label: "watcher emitted onChange(a.txt)" });
 *
 * Throws `Error("waitUntil timeout: <label> (after <N>ms)")` on
 * timeout — same shape as `helpers.waitUntil` so the failure
 * messages stay consistent across the test suite.
 */
async function waitForWatcher(predicate, opts) {
  opts = opts || {};
  return wait.waitUntil(predicate, {
    timeoutMs:  opts.timeoutMs  || DEFAULT_FS_WATCH_TIMEOUT_MS,
    intervalMs: opts.intervalMs || DEFAULT_FS_WATCH_INTERVAL_MS,
    label:      opts.label      || "fs-watch observation",
  });
}

module.exports = {
  backdateFile:               backdateFile,
  waitForWatcher:             waitForWatcher,
  DEFAULT_BACKDATE_MS:        DEFAULT_BACKDATE_MS,
  DEFAULT_FS_WATCH_TIMEOUT_MS: DEFAULT_FS_WATCH_TIMEOUT_MS,
};
