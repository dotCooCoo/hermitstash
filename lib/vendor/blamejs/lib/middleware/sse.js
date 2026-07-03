// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * sse — Server-Sent Events middleware. One-way streaming from server
 * to browser over a single HTTP response with `Content-Type:
 * text/event-stream`. Browsers reconnect automatically with the
 * `Last-Event-ID` header so the operator's handler can resume from
 * the last delivered event.
 *
 * Use case: live dashboards, log tailing, progress updates, real-time
 * counters. SSE is the right tool when the server pushes and the
 * client doesn't need to send anything back. For bidirectional, use
 * `b.websocket`.
 *
 *   router.get("/events", b.middleware.sse(async function (channel, req) {
 *     channel.send({ id: 1, event: "tick", data: { count: 1 } });
 *     channel.send({ id: 2, event: "tick", data: { count: 2 } });
 *     // resume support — read req.headers["last-event-id"] and
 *     // resume from that point.
 *   }));
 *
 * `channel`:
 *   send({ id?, event?, data, retry? })  — emit one SSE message
 *   ping(comment?)                       — emit a comment line (keeps
 *                                          intermediate proxies happy)
 *   close()                              — end the stream
 *   onAbort(fn)                          — register cleanup when the
 *                                          client disconnects (browser
 *                                          tab close, network drop)
 *
 * Heartbeat: the middleware sends a comment line every `heartbeatMs`
 * (default 15s) automatically so corporate proxies / Heroku-style
 * idle-timeouts don't kill the stream. Operators with strict
 * deployments override `heartbeatMs: false` to disable.
 *
 * Compression: SSE streams typically should NOT be compressed —
 * `b.middleware.compression` skips `text/event-stream` by default.
 */
var C = require("../constants");
var requestHelpers = require("../request-helpers");
var safeBuffer = require("../safe-buffer");
var sse = require("../sse");
var validateOpts = require("../validate-opts");

var DEFAULT_HEARTBEAT_MS = C.TIME.seconds(15);

// _formatEvent — REFUSES on CRLF/NUL injection in event/id (CVE-2026-
// 33128 / 29085 / 44217 class). Pre-v0.8.15 this stripped CRLF
// silently; the strip-instead-of-refuse behavior was the
// vulnerability. The framework now refuses at the source, returning
// the operator a clear error code so the caller knows the event was
// rejected. Validation routes through b.sse.serializeEvent so the
// middleware surface and the low-level surface share one policy.
function _formatEvent(msg) {
  var coerced = msg || {};
  var dataStr;
  if (coerced.data === undefined || coerced.data === null) dataStr = "";
  else if (typeof coerced.data === "string")               dataStr = coerced.data;
  else                                                      dataStr = JSON.stringify(coerced.data);
  return sse.serializeEvent({
    id:    coerced.id !== undefined && coerced.id !== null ? String(coerced.id) : undefined,
    event: coerced.event !== undefined && coerced.event !== null ? String(coerced.event) : undefined,
    retry: coerced.retry,
    data:  dataStr,
  });
}

/**
 * @primitive b.middleware.sse
 * @signature b.middleware.sse(handler, opts)
 * @since     0.1.0
 * @related   b.sse.serializeEvent, b.middleware.compression
 *
 * Server-Sent Events handler — one-way streaming from server to
 * browser over a single HTTP response with `Content-Type:
 * text/event-stream`. Browsers reconnect automatically with
 * `Last-Event-ID` so the operator's handler can resume from the
 * last delivered event. Refuses CRLF / NUL injection in `event` /
 * `id` (CVE-2026-33128 / 29085 / 44217 class) — the framework
 * does NOT silently strip; it returns a structured error.
 * Heartbeat (default 15s) keeps corporate proxies / Heroku-style
 * idle-timeouts from killing the stream; pass `heartbeatMs: false`
 * to disable. SSE streams should NOT be compressed —
 * `b.middleware.compression` already skips `text/event-stream`.
 *
 * The handler receives `(channel, req)`. The channel exposes
 * `send({ id, event, data, retry })`, `ping(comment)`, `close()`,
 * `onAbort(fn)`.
 *
 * @opts
 *   {
 *     heartbeatMs: number|false,   // default 15000
 *     headers:     object,         // extra response headers
 *     proxyBuffer: boolean,        // default true — sets X-Accel-Buffering: no; false to suppress
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.get("/events", b.middleware.sse(async function (channel, req) {
 *     channel.send({ id: 1, event: "tick", data: { count: 1 } });
 *     channel.close();
 *   }, { heartbeatMs: 15000 }));
 */
function create(handler, opts) {
  if (typeof handler !== "function") {
    throw new Error("middleware.sse: handler must be a function (channel, req) => ...");
  }
  opts = opts || {};
  validateOpts(opts, ["heartbeatMs", "headers", "proxyBuffer"], "middleware.sse");
  var heartbeatMs = opts.heartbeatMs === false ? 0
    : (opts.heartbeatMs != null ? opts.heartbeatMs : DEFAULT_HEARTBEAT_MS);
  if (heartbeatMs !== 0 && (typeof heartbeatMs !== "number" || !isFinite(heartbeatMs) || heartbeatMs <= 0)) {
    throw new Error("middleware.sse: heartbeatMs must be a positive finite number or false");
  }
  var extraHeaders = opts.headers || {};
  // proxyBuffer (default true) sets `X-Accel-Buffering: no` (the nginx hint
  // that disables proxy buffering). Pass false when not behind nginx, or
  // when buffering is controlled at the load balancer, to suppress it.
  var proxyBuffer = opts.proxyBuffer !== false;

  return async function sseMiddleware(req, res) {
    if (typeof res.writeHead !== "function" || typeof res.write !== "function") {
      // Not an http.ServerResponse — operator wired this onto something
      // unusual. Fail closed rather than silently dropping the handler.
      throw new Error("middleware.sse: res does not support writeHead/write — wire SSE only on HTTP routes");
    }
    var baseHeaders = {
      "Content-Type":  "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
      "Connection":    "keep-alive",
    };
    // Disable nginx response buffering when terminating behind it.
    if (proxyBuffer) baseHeaders["X-Accel-Buffering"] = "no";
    var headers = Object.assign(baseHeaders, extraHeaders);
    // Append Vary: Accept so a proxy doesn't serve a cached non-SSE
    // response on the same URL to a future client.
    res.writeHead(requestHelpers.HTTP_STATUS.OK, headers);
    requestHelpers.appendVary(res, "Accept");
    // Initial flush — some proxies hold the headers until first byte.
    res.write(":\n\n");

    var closed = false;
    var heartbeatTimer = null;
    var abortHandlers = [];

    function _scheduleHeartbeat() {
      if (heartbeatMs === 0) return;
      heartbeatTimer = setTimeout(function () {
        if (closed) return;
        try { res.write(": heartbeat\n\n"); } catch (_e) { /* socket closed */ }
        _scheduleHeartbeat();
      }, heartbeatMs);
      if (typeof heartbeatTimer.unref === "function") heartbeatTimer.unref();
    }
    _scheduleHeartbeat();

    var channel = {
      send: function (msg) {
        if (closed) return false;
        try { res.write(_formatEvent(msg || {})); return true; }
        catch (_e) { return false; }
      },
      ping: function (comment) {
        if (closed) return false;
        var safe = comment ? safeBuffer.stripCrlf(String(comment), " ") : "ping";
        try { res.write(": " + safe + "\n\n"); return true; }
        catch (_e) { return false; }
      },
      close: function () {
        if (closed) return;
        closed = true;
        if (heartbeatTimer) { clearTimeout(heartbeatTimer); heartbeatTimer = null; }
        try { res.end(); } catch (_e) { /* already ended */ }
      },
      onAbort: function (fn) {
        if (typeof fn === "function") abortHandlers.push(fn);
      },
      get closed() { return closed; },
    };

    function _onClose() {
      if (closed) return;
      closed = true;
      if (heartbeatTimer) { clearTimeout(heartbeatTimer); heartbeatTimer = null; }
      for (var i = 0; i < abortHandlers.length; i++) {
        try { abortHandlers[i](); } catch (_e) { /* operator handler error — drop */ }
      }
    }
    res.once("close", _onClose);
    res.once("error", _onClose);
    if (req && typeof req.once === "function") req.once("aborted", _onClose);

    try {
      await handler(channel, req);
    } catch (e) {
      _onClose();
      try { res.end(); } catch (_ignored) { /* */ }
      throw e;
    }
  };
}

module.exports = {
  create:        create,
  _formatEvent:  _formatEvent,   // test-only export
};
