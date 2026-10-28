/**
 * The cross-process lock for DATA_DIR/.server-lease, shared by lib/server-lease.js
 * and its heartbeat thread (lib/server-lease-worker.js). Every read-then-write
 * of the lease file (taking it, refreshing it, deleting it or writing back a
 * replaced lease) runs while holding it.
 *
 * The lock is the directory <lease path>.lock, created with mkdir, which fails
 * with EEXIST while another process holds it. A process that died while holding
 * it leaves the directory behind, and a lock older than STALE_MS is removed.
 * This module uses only node:fs, so the heartbeat thread can load it without
 * the framework.
 */
"use strict";

var nodeFs = require("node:fs");

var ONE_SECOND_MS = 1000; // allow:raw-time-literal — loaded by the heartbeat thread without lib/constants
var STALE_MS = 10 * ONE_SECOND_MS;
var POLL_MS = 20;

function _sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * Run fn while holding the lock for leasePath. Returns fn's result. Throws when
 * the lock cannot be taken within waitMs.
 */
function withLock(leasePath, waitMs, fn) {
  var lockDir = leasePath + ".lock";
  var deadline = Date.now() + waitMs;
  for (;;) {
    try { nodeFs.mkdirSync(lockDir, { mode: 0o700 }); break; }
    catch (e) {
      if (!e || e.code !== "EEXIST") throw e;
      var age = null;
      try { age = Date.now() - nodeFs.statSync(lockDir).mtimeMs; } catch (_e) { continue; }
      if (age > STALE_MS) {
        try { nodeFs.rmdirSync(lockDir); } catch (_e) { /* another process removed it */ }
        continue;
      }
      if (Date.now() > deadline) {
        var err = new Error("timed out waiting for " + lockDir);
        err.code = "server-lease/lock-timeout";
        throw err;
      }
      _sleepSync(POLL_MS);
    }
  }
  try { return fn(); }
  finally { try { nodeFs.rmdirSync(lockDir); } catch (_e) { /* removed as stale by another process */ } }
}

module.exports = { withLock: withLock, STALE_MS: STALE_MS };
