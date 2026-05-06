"use strict";
/**
 * HTTP/2 session teardown — graceful close *then* force-destroy.
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

function tearDownH2Session(session) {
  if (!session) return;
  try { if (typeof session.close === "function") session.close(); }
  catch (_e1) { /* best-effort graceful */ }
  try { if (typeof session.destroy === "function") session.destroy(); }
  catch (_e2) { /* best-effort socket teardown */ }
}

module.exports = { tearDownH2Session: tearDownH2Session };
