/**
 * The lease a process holds on the data directory while it uses it.
 *
 * The server and the offline vault tools (vault-key-rotate and the
 * vault-passphrase tools) write DATA_DIR/.server-lease, rewrite it every
 * HEARTBEAT_MS, and delete it when the process exits. The file records whether
 * a "server" or a "tool" holds it. It sits in the data directory, so it is
 * visible from the host, from another container, and from a one-off container
 * on the same volume, whatever port or network namespace the holder uses.
 *
 * - A tool takes the lease only when no fresh lease exists
 *   (scripts/lib/server-liveness.js).
 * - The server takes the lease at the start of boot, before the vault init
 *   runs rotation recovery. It replaces a fresh server lease, which a previous
 *   run of the server leaves when it is killed, and refuses a fresh tool lease.
 * - Boot recovery does not touch an interrupted rotation while another process
 *   holds a fresh tool lease (lib/vault.js).
 *
 * acquire() reads and writes the lease while it holds DATA_DIR/.server-lease.lock,
 * a directory created with mkdir, so two processes cannot both take the lease.
 * A worker thread writes the heartbeat, so it keeps running while synchronous
 * work blocks the main thread. A server's heartbeat rewrites the lease on every
 * beat, so the lease stays fresh while any server using the directory is alive,
 * and a tool that took the lease in the meantime finds it replaced. A server
 * that has found another server's lease in the last STALE_MS does not delete
 * the lease when it exits. A tool's heartbeat writes only while the file still
 * carries the tool's token.
 *
 * A lease is fresh while its heartbeat is younger than STALE_MS. A process that
 * was killed without running its exit handlers leaves a lease that turns stale
 * STALE_MS after its last heartbeat.
 */
var nodeFs = require("node:fs");
var nodeOs = require("node:os");
var { Worker } = require("node:worker_threads");
var b = require("./vendor/blamejs");
var C = require("./constants");
var leaseLock = require("./server-lease-lock");

var HEARTBEAT_MS = C.TIME.seconds(30);
var STALE_MS = C.TIME.seconds(90);
var ONE_SECOND_MS = C.TIME.seconds(1);
var LOCK_WAIT_MS = C.TIME.seconds(5);

// Shared with the heartbeat worker (lib/server-lease-worker.js): [stop, busy].
var STOP = 0;
var BUSY = 1;
var WORKER_PATH = require.resolve("./server-lease-worker");

class LeaseHeldError extends Error {
  constructor(lease) {
    super(describe(lease) + " holds " + C.PATHS.SERVER_LEASE);
    this.name = "LeaseHeldError";
    this.code = "server-lease/held";
    this.lease = lease;
  }
}

var _held = null;

function _sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function _withLock(path, fn) {
  return leaseLock.withLock(path, LOCK_WAIT_MS, fn);
}

/**
 * Take the lease and start the heartbeat. Calling it again is a no-op.
 * Throws LeaseHeldError when another process holds a fresh lease that this
 * caller may not replace.
 *
 * @param {object} [opts]
 * @param {string} [opts.kind] - "server" (default) or "tool"
 * @param {string} [opts.name] - the tool's script name, shown to other processes
 * @param {string} [opts.path] - defaults to C.PATHS.SERVER_LEASE
 * @param {number} [opts.heartbeatMs] - defaults to HEARTBEAT_MS
 */
function acquire(opts) {
  if (_held) return;
  opts = opts || {};
  var path = opts.path || C.PATHS.SERVER_LEASE;
  var kind = opts.kind === "tool" ? "tool" : "server";
  var lease = {
    kind: kind,
    name: opts.name || null,
    pid: process.pid,
    hostname: nodeOs.hostname(),
    token: b.crypto.generateToken(C.BYTES.bytes(16)),
    startedAt: new Date().toISOString(),
    heartbeatAt: null,
  };
  var foreignBuf = new SharedArrayBuffer(Float64Array.BYTES_PER_ELEMENT);
  var lastForeignServer = new Float64Array(foreignBuf);
  _withLock(path, function () {
    var current = read(path);
    // A server replaces a fresh server lease; nothing else replaces a fresh lease.
    if (current && current.fresh && !(kind === "server" && current.kind === "server")) {
      throw new LeaseHeldError(current);
    }
    // The server that wrote it may still be running.
    if (current && current.fresh) lastForeignServer[0] = Date.now();
    lease.heartbeatAt = new Date().toISOString();
    b.atomicFile.writeSync(path, JSON.stringify(lease), { fileMode: 0o600 });
  });
  var flags = new SharedArrayBuffer(2 * Int32Array.BYTES_PER_ELEMENT);
  var worker = new Worker(WORKER_PATH, {
    workerData: { path: path, lease: lease, flags: flags, lastForeignServer: foreignBuf,
      heartbeatMs: opts.heartbeatMs || HEARTBEAT_MS },
  });
  worker.unref();
  worker.on("error", function () { /* the lease turns stale; isMine() still reads the file */ });
  _held = { path: path, token: lease.token, worker: worker, flags: new Int32Array(flags),
    lastForeignServer: lastForeignServer };
  process.on("exit", release);
}

/**
 * Move the exit handler that deletes the lease behind every exit handler
 * registered so far. lib/db.js calls it right after it registers the handler
 * that writes the final hermitstash.db.enc, so the lease outlasts that write.
 * Without a lease held it does nothing.
 */
function releaseAfterExistingExitHandlers() {
  if (!_held) return;
  process.removeListener("exit", release);
  process.on("exit", release);
}

/**
 * Stop the heartbeat and delete the lease if it is still the one this process
 * wrote. A server that found another server's fresh lease within the last
 * STALE_MS leaves its own lease in place instead: the other server may still be
 * running, and its next heartbeat rewrites the lease before this one turns stale.
 */
function release() {
  if (!_held) return;
  var held = _held;
  _held = null;
  process.removeListener("exit", release);
  Atomics.store(held.flags, STOP, 1);
  var until = Date.now() + ONE_SECOND_MS;
  while (Atomics.load(held.flags, BUSY) === 1 && Date.now() < until) _sleepSync(1);
  try { held.worker.terminate(); } catch (_e) { /* exiting */ }
  try {
    _withLock(held.path, function () {
      var current = read(held.path);
      if (!current || current.token !== held.token) return;
      if (Date.now() - held.lastForeignServer[0] < STALE_MS) return;
      nodeFs.unlinkSync(held.path);
    });
  } catch (_e) { /* the lease turns stale on its own */ }
}

function isMine(lease) {
  return !!(_held && lease && lease.token === _held.token);
}

/**
 * Read a lease file. Returns null when there is none, or an object with the
 * lease fields plus ageMs and fresh. A lease that cannot be parsed is reported
 * as a fresh tool lease with unreadable: true.
 */
function read(path) {
  path = path || C.PATHS.SERVER_LEASE;
  var raw;
  try { raw = nodeFs.readFileSync(path, "utf8"); }
  catch (e) { if (e && e.code === "ENOENT") return null; throw e; }
  var unreadable = { unreadable: true, kind: "tool", fresh: true, ageMs: null };
  var lease;
  try { lease = b.safeJson.parse(raw, { maxBytes: C.BYTES.kib(4) }); }
  catch (_e) { return unreadable; }
  var beat = Date.parse(lease && lease.heartbeatAt);
  if (!Number.isFinite(beat)) return unreadable;
  var ageMs = Date.now() - beat;
  return {
    kind: lease.kind === "server" ? "server" : "tool",
    name: lease.name || null,
    pid: lease.pid,
    hostname: lease.hostname,
    token: lease.token,
    startedAt: lease.startedAt,
    heartbeatAt: lease.heartbeatAt,
    ageMs: ageMs,
    fresh: ageMs < STALE_MS,
  };
}

/**
 * One line naming who holds a lease, for error messages.
 */
function describe(lease) {
  if (lease.unreadable) return "an unreadable lease";
  var who = lease.kind === "server" ? "a HermitStash server" : (lease.name || "an offline vault tool");
  return who + " (pid " + lease.pid + " on " + lease.hostname + ", last refreshed " +
    Math.round(lease.ageMs / ONE_SECOND_MS) + "s ago)";
}

function secondsUntilStale(lease) {
  var remainingMs = lease.ageMs === null ? STALE_MS : Math.max(0, STALE_MS - lease.ageMs);
  return Math.ceil(remainingMs / ONE_SECOND_MS);
}

module.exports = {
  acquire: acquire,
  release: release,
  releaseAfterExistingExitHandlers: releaseAfterExistingExitHandlers,
  isMine: isMine,
  read: read,
  describe: describe,
  secondsUntilStale: secondsUntilStale,
  LeaseHeldError: LeaseHeldError,
  HEARTBEAT_MS: HEARTBEAT_MS,
  STALE_MS: STALE_MS,
};
