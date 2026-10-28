/**
 * Heartbeat thread for lib/server-lease.js.
 *
 * It rewrites the lease through a temp file and a rename every heartbeatMs,
 * holding lib/server-lease-lock.js, and stops writing once the parent sets the
 * stop flag. A server's lease is written on every beat. A tool's lease is
 * written only while the file still carries the tool's token. It runs on its own event loop, so it
 * keeps the lease fresh while synchronous work blocks the parent's main thread.
 *
 * workerData: { path, lease, flags (SharedArrayBuffer: Int32 [stop, busy]),
 *   lastForeignServer (SharedArrayBuffer: Float64 [ms]), heartbeatMs }
 */
"use strict";

var nodeFs = require("node:fs");
var { workerData } = require("node:worker_threads");
var leaseLock = require("./server-lease-lock");

var STOP = 0;
var BUSY = 1;
// A beat that cannot take the lock this quickly is skipped; the next one retries.
var LOCK_WAIT_MS = 500;

if (!workerData || typeof workerData.path !== "string" || !workerData.lease ||
    typeof workerData.lease.token !== "string" || !(workerData.flags instanceof SharedArrayBuffer) ||
    !(workerData.lastForeignServer instanceof SharedArrayBuffer) || !(workerData.heartbeatMs > 0)) {
  throw new Error("server-lease-worker: invalid workerData");
}

var leasePath = workerData.path;
var lease = workerData.lease;
var flags = new Int32Array(workerData.flags);
// The parent writes the lease with JSON.stringify, so its own token appears in
// the file exactly in this form while the file is still its lease.
var tokenField = JSON.stringify("token") + ":" + JSON.stringify(lease.token);
var serverKindField = JSON.stringify("kind") + ":" + JSON.stringify("server");
var lastForeignServer = new Float64Array(workerData.lastForeignServer);
var seq = 0;

function write() {
  var raw;
  try { raw = nodeFs.readFileSync(leasePath, "utf8"); } catch (_e) { raw = ""; }
  var foreign = raw !== "" && raw.indexOf(tokenField) === -1;
  // A tool writes only while the file still carries its own token.
  if (lease.kind !== "server" && foreign) return;
  // A server writes its lease on every beat, so the lease stays fresh while any
  // server using the directory is alive, whoever wrote it last. It records when
  // it last found another server's lease, for release() in lib/server-lease.js.
  if (foreign && raw.indexOf(serverKindField) !== -1) lastForeignServer[0] = Date.now();
  lease.heartbeatAt = new Date().toISOString();
  var tmp = leasePath + ".tmp-" + process.pid + "-" + (seq++);
  nodeFs.writeFileSync(tmp, JSON.stringify(lease), { mode: 0o600, flag: "wx" });
  nodeFs.renameSync(tmp, leasePath);
}

function beat() {
  if (Atomics.load(flags, STOP) === 1) return;
  Atomics.store(flags, BUSY, 1);
  try {
    if (Atomics.load(flags, STOP) === 1) return;
    // The token check and the write run under the lock acquire() and release()
    // take, so a takeover cannot land between them.
    leaseLock.withLock(leasePath, LOCK_WAIT_MS, write);
  } catch (_e) {
    /* the next beat retries */
  } finally {
    Atomics.store(flags, BUSY, 0);
  }
}

// allow:timer-no-unref — this timer is the only work of the thread; the parent unrefs the Worker itself.
setInterval(beat, workerData.heartbeatMs);
