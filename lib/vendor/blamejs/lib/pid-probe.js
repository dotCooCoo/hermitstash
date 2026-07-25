// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// pid-probe — the signal-0 liveness probe + fd-safe pidfile reader shared by
// b.daemon (lib/daemon.js) and b.appShutdown.pidLock (lib/app-shutdown.js).
// Both files carried a byte-for-byte copy of the liveness check and the capped,
// symlink-refusing pidfile reader; a single owner keeps the liveness semantics
// (process.kill(pid, 0) → alive; EPERM → alive-but-unowned; ESRCH → dead) and
// the read hardening (1 KiB cap + O_NOFOLLOW refusal so a planted symlink or an
// oversized file can neither redirect nor OOM the read) identical across every
// caller — daemon.start / stop / status and pidLock.acquire / release.
//
// This is not request-reachable: the two callers are process-lifecycle
// primitives, so a throw here would only ever surface at daemon start/stop.
// Both entry points are defensive readers (return-default, never throw): a
// missing / malformed / hostile pidfile yields null ("nothing live there")
// rather than propagating an error into the shutdown path.

var atomicFile = require("./atomic-file");
var C = require("./constants");

// isLivePid(pid) — signal-0 existence probe. process.kill(pid, 0) sends no
// signal but performs the permission + existence check the kernel would do for
// a real signal: it succeeds when the process is alive and signalable, throws
// EPERM when the process is alive but owned by another user (still "live"), and
// throws ESRCH when no such process exists (dead). A non-numeric / non-finite /
// non-positive pid is never live.
function isLivePid(pid) {
  if (typeof pid !== "number" || !isFinite(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; }
  catch (e) { return !!(e && e.code === "EPERM"); }
}

// readPidFile(pidFile) — fd-safe + capped + symlink-refusing read of a PID
// sidecar. A PID file is never a legitimate symlink mount (unlike a k8s/certbot
// secret mount), so refuseSymlink is safe here and stops a planted symlink from
// redirecting the read; the 1 KiB cap stops an oversized planted file from
// OOM-ing it. Returns the parsed positive PID, or null for any failure
// (missing / symlink / too-large / non-numeric) — the uniform "nothing live
// there" sentinel both callers already relied on.
function readPidFile(pidFile) {
  try {
    var raw = atomicFile.fdSafeReadSync(pidFile, {
      maxBytes: C.BYTES.kib(1), refuseSymlink: true, encoding: "utf8",
    });
    var pid = parseInt(String(raw).trim(), 10);
    return isFinite(pid) && pid > 0 ? pid : null;
  } catch (_e) { return null; }
}

module.exports = {
  isLivePid:   isLivePid,
  readPidFile: readPidFile,
};
