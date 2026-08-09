// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * HTTP/2 session teardown — two dispositions, deliberately different.
 *
 *   tearDownH2Session(session)  — the session is UNWANTED. Graceful close
 *                                 then force-destroy; open streams die.
 *   drainH2Session(session, …)  — the session is merely RETIRED (no longer
 *                                 eligible for new work). Close it so it
 *                                 takes no new streams, let the open ones
 *                                 finish, and force the socket down only if
 *                                 it stops making progress.
 *
 * Reach for the second whenever the session may still be carrying work that
 * is not itself the reason for retiring it — a TLS-posture change, say.
 * Forcing there aborts unrelated requests.
 *
 * `Http2Session.close()` is the *graceful* close: it returns synchronously
 * while letting in-flight streams complete on their own, but it does NOT
 * free the underlying TCP socket until those streams complete (or the
 * peer disconnects). On idle / error / fallback paths — where we
 * explicitly DON'T want the session anymore — that means the socket
 * lingers until the OS-level TCP timeout fires. In a test process the
 * mock-server's `server.close()` then waits for that lingering socket
 * to release, which on Linux can be tens of minutes. v0.6.58 hit
 * exactly this in the OTLP-gRPC sink and timed out the npm-publish
 * workflow on every tag from v0.6.38 → v0.6.57.
 *
 * The fix is structural: every call site that wants the session GONE
 * routes through this helper, which calls close() (best-effort drain)
 * then destroy() (force socket teardown). Used by `lib/http-client.js`
 * (h2 transport pool — fallback, error, idle-timeout, reset) and by
 * `lib/log-stream-otlp-grpc.js` (sink shutdown after final flush).
 *
 * No-op on a null / undefined session. Wraps each call in try/catch so
 * a partially-torn-down session can't throw and cancel the second call.
 */

var C = require("./constants");
var safeAsync = require("./safe-async");

function tearDownH2Session(session) {
  if (!session) return;
  try { if (typeof session.close === "function") session.close(); }
  catch (_e1) { /* best-effort graceful */ }
  try { if (typeof session.destroy === "function") session.destroy(); }
  catch (_e2) { /* best-effort socket teardown */ }
}

// drainH2Session(session, graceMs) — retire a session WITHOUT cutting off the
// streams already running on it.
//
// tearDownH2Session is the right call when the session is unwanted: it forces
// the socket down, which also kills any open stream. That is wrong when the
// session is merely no longer ELIGIBLE for new work — retiring a pooled
// transport after a TLS-posture change, say — because the requests already in
// flight on it are unrelated to the policy that changed and must be allowed
// to finish.
//
// close() alone is the graceful half: it refuses new streams and frees the
// socket once the open ones complete. On its own it is also how v0.6.58 hung
// a publish workflow — if a stream never completes, the socket lingers until
// the OS TCP timeout. So this pairs it with a bounded fallback: after the
// grace period, force the socket down. The timer is unref'd, so a process
// whose work is otherwise finished still exits promptly.
var DEFAULT_DRAIN_GRACE_MS = C.TIME.seconds(30);
function drainH2Session(session, graceMs) {
  if (!session) return;
  try { if (typeof session.close === "function") session.close(); }
  catch (_e) { /* best-effort graceful close */ }
  var grace = typeof graceMs === "number" && graceMs > 0 ? graceMs : DEFAULT_DRAIN_GRACE_MS;

  // The fallback fires only for a session that has STOPPED, not one that is
  // merely slow — b.httpClient.downloadStream has no wall-clock limit, so any
  // fixed deadline would cut a legitimate long transfer short because
  // something unrelated retired the pool.
  //
  // Progress is read from the SOCKET's byte counters, which are cumulative and
  // only ever increase. That choice is deliberate, because the two failure
  // modes are not symmetric:
  //
  //   - reporting a live transfer as stalled DESTROYS it, losing data;
  //   - reporting a stalled session as busy holds a socket open.
  //
  // The session's own counters look like the better signal — they count
  // application data, so control frames do not register — but they are
  // flow-control occupancy, not totals: effectiveRecvDataLength is bytes since
  // the last window update and remoteWindowSize is restored as data is
  // acknowledged, so both cycle. A transfer that happens to move a whole
  // number of windows between two samples reads as frozen, and the watchdog
  // would kill it. A counter that can wrap must not decide whether to destroy
  // live work.
  //
  // The cost is the case this cannot see: a stalled stream on a peer that
  // keeps sending PING or WINDOW_UPDATE looks busy, so its socket is held
  // until the request's own timeout tears the stream down. That bound belongs
  // to the caller's request timeout, not to this watchdog. Doing better needs
  // a monotonic per-stream byte count, which node:http2 does not expose on the
  // session — the caller would have to supply it.
  var lastMoved = null;
  var watch = safeAsync.repeating(function () {
    if (session.destroyed) { watch.stop(); return; }
    var sock = session.socket;
    var moved = sock ? (Number(sock.bytesRead) || 0) + (Number(sock.bytesWritten) || 0) : 0;
    if (moved !== lastMoved) { lastMoved = moved; return; }   // still moving bytes
    watch.stop();
    try { if (typeof session.destroy === "function") session.destroy(); }
    catch (_e) { /* best-effort socket teardown */ }
  }, grace, { name: "h2-drain-watch" });
}

module.exports = {
  tearDownH2Session: tearDownH2Session,
  drainH2Session:    drainH2Session,
};
