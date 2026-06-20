"use strict";
/**
 * Server-Sent Events primitive — text/event-stream transport with
 * newline-injection refusal in event:/id:/data: fields.
 *
 * The SSE wire format is line-oriented (W3C HTML Living Standard
 * §server-sent-events-spec): each field is a line of the form
 * "<name>: <value>" terminated by a single LF, and an empty line
 * separates events. Any LF/CR/NUL inside a value silently splits the
 * field, letting an attacker forge subsequent events, the event id
 * (which the client echoes back as Last-Event-ID on reconnect), or
 * the message data. Three CVEs in one quarter — CVE-2026-33128 (h3),
 * CVE-2026-29085 (Hono), CVE-2026-44217 (sse-channel) — published in
 * the same vulnerability class.
 *
 * Public API:
 *
 *   sse.create(req, res, opts) → channel
 *     Wires the response stream as text/event-stream, sets the
 *     SSE-required headers, and returns a channel object. opts:
 *       heartbeatMs    — interval for `:keepalive` comment frames
 *                        (default 15 s; pass 0 to disable)
 *       retryMs        — initial reconnection-time advisory sent on
 *                        stream open (sets the `retry:` field once;
 *                        omitted when null/undefined)
 *       errorClass     — FrameworkError subclass to throw on bad
 *                        input (default SseError)
 *       audit          — bool, default true. Emit SSE lifecycle audit
 *                        events.
 *       proxyBuffer    — bool, default true. Sets `X-Accel-Buffering:
 *                        no` (the nginx hint that disables proxy
 *                        buffering of the stream). Pass false when not
 *                        behind nginx, or when buffering is handled at
 *                        the load balancer, to suppress the header.
 *
 *   channel.send({ event, id, data, retry })
 *     Writes a single SSE event. Each field is validated; LF/CR/NUL
 *     anywhere in event/id is refused via `errorClass`. data is
 *     allowed to contain LF — the framework splits it into multiple
 *     `data:` lines per the spec — but CR and NUL are refused. retry
 *     must be a non-negative finite integer.
 *
 *   channel.comment(text)
 *     Writes a `:<text>` comment line (used for keepalive). LF/CR/NUL
 *     in `text` are refused.
 *
 *   channel.close()
 *     Ends the underlying response stream and stops the heartbeat
 *     timer. Idempotent.
 *
 *   channel.lastEventId
 *     The Last-Event-ID header value from the initial request, or
 *     null. Sanitized — any LF/CR/NUL renders the header null
 *     (refuse-on-bad-input rather than passing through to handlers).
 *
 *   sse.serializeEvent({ event, id, data, retry })
 *     Returns the SSE-encoded string for a single event. Same
 *     validation rules as channel.send. Exposed for operators that
 *     buffer events through their own queue before writing.
 *
 * Error discipline:
 *   channel.send and serializeEvent THROW errorClass on bad input.
 *   SSE is not a drop-silent surface — a refused event is a
 *   programming bug, and silently dropping would mask the injection
 *   attempt the refusal exists to flag. close() is idempotent and
 *   never throws.
 *
 * Composition:
 *   - Composes with router via raw req/res — no router-specific
 *     coupling. Works under h1 and h2 (h2 keeps the stream open
 *     identically; the response is just chunked-transfer at h1 and
 *     a long-running DATA-frame stream at h2).
 *   - Audit emissions go through audit.safeEmit so SSE doesn't
 *     escape audit-bus failures back to the caller.
 */

var C = require("./constants");
var audit = require("./audit");
var validateOpts = require("./validate-opts");
var numericBounds = require("./numeric-bounds");
var { SseError } = require("./framework-error");

// Per W3C SSE — the wire format uses LF as terminator. A single LF
// inside any field splits the value at the parser. CR is canonicalized
// to LF by the parser (CR-only and CRLF terminators are also valid),
// so CR is equally injection-shaped. NUL is refused universally — it
// has no place in an event-stream wire-form and any presence is
// suspicious.
// eslint-disable-next-line no-control-regex
var INJECTION_RE = /[\r\n\u0000]/;

// retry: must be a non-negative finite integer. Browsers floor /
// reject non-integer or negative values; refuse them at the source so
// downstream behavior is uniform.
function _validateRetry(retry, errorClass) {
  if (retry === undefined || retry === null) return null;
  if (typeof retry !== "number" || !isFinite(retry) || retry < 0 ||
      Math.floor(retry) !== retry) {
    throw errorClass.factory("sse/bad-retry",
      "sse.send: retry must be a non-negative finite integer (got " +
      JSON.stringify(retry) + ")");
  }
  return retry;
}

function _refuseInjection(field, value, errorClass) {
  if (typeof value !== "string") {
    throw errorClass.factory("sse/bad-field",
      "sse.send: " + field + " must be a string");
  }
  // Length-bound BEFORE the regex test — _capField applies a tighter
  // cap further along, but the regex itself runs against the full
  // value so we bound here too.
  if (value.length > MAX_DATA_BYTES) {
    throw errorClass.factory("sse/field-too-large",
      "sse.send: " + field + " too large for injection scan");
  }
  if (INJECTION_RE.test(value)) {                                                          // allow:regex-no-length-cap — value length capped above
    audit.safeEmit({
      action:   "sse.injection_refused",
      outcome:  "denied",
      metadata: { field: field, length: value.length },
    });
    throw errorClass.factory("sse/injection",
      "sse.send: " + field + " contains LF/CR/NUL — refused " +
      "(CVE-2026-33128 / 29085 / 44217 class)");
  }
}

// Field caps. Values aren't open-ended — a 100 MiB `id:` is an abuse
// shape. Operators who need larger bodies use the chunked binary
// transports (websocket / file-upload). SSE is for text events.
var MAX_EVENT_BYTES = C.BYTES.kib(8);
var MAX_ID_BYTES    = C.BYTES.kib(8);
var MAX_DATA_BYTES  = C.BYTES.mib(1);

function _capField(field, value, capBytes, errorClass) {
  var len = Buffer.byteLength(value, "utf8");
  if (len > capBytes) {
    throw errorClass.factory("sse/field-too-large",
      "sse.send: " + field + " exceeds cap (" + len + " > " +
      capBytes + " bytes)");
  }
}

function serializeEvent(opts, errorClass) {
  errorClass = errorClass || SseError;
  if (!opts || typeof opts !== "object") {
    throw errorClass.factory("sse/bad-opts", "sse.serializeEvent: opts required");
  }
  var out = "";
  // Field order: id, event, retry, data — matches the framework's
  // historical b.middleware.sse layout. The W3C SSE spec is order-
  // agnostic, but consumers (incl. the existing wiki test fixtures)
  // pin this order.
  if (opts.id !== undefined && opts.id !== null) {
    _refuseInjection("id", opts.id, errorClass);
    _capField("id", opts.id, MAX_ID_BYTES, errorClass);
    out += "id: " + opts.id + "\n";
  }
  if (opts.event !== undefined && opts.event !== null) {
    _refuseInjection("event", opts.event, errorClass);
    _capField("event", opts.event, MAX_EVENT_BYTES, errorClass);
    out += "event: " + opts.event + "\n";
  }
  var retry = _validateRetry(opts.retry, errorClass);
  if (retry !== null) {
    out += "retry: " + retry + "\n";
  }
  if (opts.data !== undefined && opts.data !== null) {
    if (typeof opts.data !== "string") {
      throw errorClass.factory("sse/bad-field",
        "sse.send: data must be a string");
    }
    _capField("data", opts.data, MAX_DATA_BYTES, errorClass);
    // CR / NUL refused; LF allowed (split into multiple data: lines).
    // eslint-disable-next-line no-control-regex
    if (/[\r\u0000]/.test(opts.data)) {
      audit.safeEmit({
        action:   "sse.injection_refused",
        outcome:  "denied",
        metadata: { field: "data", length: opts.data.length, char: "cr-or-nul" },
      });
      throw errorClass.factory("sse/injection",
        "sse.send: data contains CR or NUL — refused");
    }
    var lines = opts.data.split("\n");
    for (var i = 0; i < lines.length; i += 1) {
      out += "data: " + lines[i] + "\n";
    }
  }
  // Empty line separator.
  out += "\n";
  return out;
}

function _validateComment(text, errorClass) {
  if (typeof text !== "string") {
    throw errorClass.factory("sse/bad-field",
      "sse.comment: text must be a string");
  }
  if (text.length > MAX_DATA_BYTES) {
    throw errorClass.factory("sse/field-too-large",
      "sse.comment: text too large for injection scan");
  }
  if (INJECTION_RE.test(text)) {                                                            // allow:regex-no-length-cap — text length capped above
    audit.safeEmit({
      action:   "sse.injection_refused",
      outcome:  "denied",
      metadata: { field: "comment", length: text.length },
    });
    throw errorClass.factory("sse/injection",
      "sse.comment: text contains LF/CR/NUL — refused");
  }
}

// Sanitize the Last-Event-ID header value the client echoed on
// reconnect. Per the spec the client SHOULD send the most recent id,
// but we receive raw header bytes — refuse the value entirely (return
// null) if it carries any injection-shaped char.
function _readLastEventId(req) {
  if (!req || !req.headers) return null;
  var raw = req.headers["last-event-id"];
  if (typeof raw !== "string" || raw.length === 0) return null;
  if (INJECTION_RE.test(raw)) return null;
  if (Buffer.byteLength(raw, "utf8") > MAX_ID_BYTES) return null;
  return raw;
}

function create(req, res, opts) {
  opts = opts || {};
  var errorClass = opts.errorClass || SseError;
  validateOpts.requireMethods(res, ["write", "end"],
    "sse.create: res (writable response stream)", errorClass, "sse/bad-res");
  var heartbeatMs = opts.heartbeatMs;
  if (heartbeatMs === undefined) heartbeatMs = C.TIME.seconds(15);
  if (typeof heartbeatMs !== "number" || !isFinite(heartbeatMs) ||
      heartbeatMs < 0 || Math.floor(heartbeatMs) !== heartbeatMs) {
    throw errorClass.factory("sse/bad-opts",
      "sse.create: heartbeatMs must be a non-negative integer ms (got " +
      JSON.stringify(heartbeatMs) + ")");
  }
  var auditOn = opts.audit !== false;
  // proxyBuffer (default true) sets `X-Accel-Buffering: no` — the nginx hint
  // that defeats proxy buffering of the event stream. Operators not behind
  // nginx, or whose buffering is controlled at the load balancer, pass
  // proxyBuffer: false to suppress the nginx-specific header.
  var proxyBuffer = opts.proxyBuffer !== false;

  // Slow-consumer bound. SSE is server-push: when a client stalls, res.write()
  // returns false but the app keeps pushing, so Node buffers the unsent bytes
  // in res.writableLength without limit — one stuck connection grows the heap
  // until exhaustion (memory-exhaustion DoS). Cap the per-channel buffer and
  // evict the slow consumer past it. A healthy client (writableLength ~0) is
  // never affected. Config-time input → throw on a bad value.
  var maxBufferedBytes = opts.maxBufferedBytes;
  if (maxBufferedBytes === undefined) maxBufferedBytes = C.BYTES.mib(1);
  numericBounds.requirePositiveFiniteInt(maxBufferedBytes,
    "sse.create: maxBufferedBytes", errorClass, "sse/bad-opts");

  var lastEventId = _readLastEventId(req);

  // Headers. text/event-stream is the contract; Cache-Control: no-cache
  // and Connection: keep-alive (h1) are the operationally required pair.
  if (typeof res.setHeader === "function") {
    res.setHeader("Content-Type",      "text/event-stream; charset=utf-8");
    res.setHeader("Cache-Control",     "no-cache, no-transform");
    if (proxyBuffer) res.setHeader("X-Accel-Buffering", "no");
    // Connection: keep-alive only meaningful on h1; h2 streams stay
    // open until either side closes. node:http2 surfaces res.stream
    // (h2 ServerHttp2Stream) where setHeader works the same.
    if (req && req.httpVersionMajor !== 2) {
      res.setHeader("Connection", "keep-alive");
    }
  }
  if (typeof res.flushHeaders === "function") {
    try { res.flushHeaders(); } catch (_e) { /* response may have flushed already */ }
  }

  var closed = false;
  var heartbeatTimer = null;

  function _writeRaw(s) {
    if (closed) {
      throw errorClass.factory("sse/closed",
        "sse.send: channel closed");
    }
    res.write(s);
    // res.writableLength is the count of bytes Node has buffered but not yet
    // flushed to the socket. A healthy client drains it (≈0); a stalled one
    // lets it climb. Past the per-channel cap, evict the slow consumer rather
    // than buffer without bound. h2 streams + h1 responses both expose it.
    var buffered = (typeof res.writableLength === "number") ? res.writableLength : 0;
    if (buffered > maxBufferedBytes) {
      close({ reason: "backpressure-exceeded" });
      throw errorClass.factory("sse/backpressure",
        "sse.send: client too slow — buffered " + buffered +
        " bytes exceeds maxBufferedBytes " + maxBufferedBytes + "; channel closed");
    }
  }

  function send(eventOpts) {
    var encoded = serializeEvent(eventOpts || {}, errorClass);
    _writeRaw(encoded);
  }

  function comment(text) {
    _validateComment(text, errorClass);
    _writeRaw(":" + text + "\n\n");
  }

  function close(cause) {
    if (closed) return;
    closed = true;
    if (heartbeatTimer) {
      clearInterval(heartbeatTimer);
      heartbeatTimer = null;
    }
    try { res.end(); } catch (_e) { /* already destroyed */ }
    if (auditOn) {
      var closeMeta = { lastEventId: lastEventId };
      if (cause) closeMeta.reason = cause.reason || "fault";
      audit.safeEmit({
        action:   "sse.channel_closed",
        outcome:  cause ? "failure" : "success",
        metadata: closeMeta,
      });
    }
  }

  // Stream-side close detection — when the client disconnects, free
  // the heartbeat timer.
  if (typeof res.on === "function") {
    res.on("close",  close);
    res.on("error",  function (_e) { close({ reason: "stream-error" }); });
    res.on("finish", function () { closed = true; if (heartbeatTimer) { clearInterval(heartbeatTimer); heartbeatTimer = null; } });
  }

  // Optional retry: advisory on open.
  if (opts.retryMs !== undefined && opts.retryMs !== null) {
    var validatedRetry = _validateRetry(opts.retryMs, errorClass);
    _writeRaw("retry: " + validatedRetry + "\n\n");
  }

  // Heartbeat keeps intermediaries from idle-timing out the stream and
  // gives the client a reliable progress signal. Timer is unref'd so a
  // single live SSE channel doesn't pin the event loop on shutdown.
  if (heartbeatMs > 0) {
    heartbeatTimer = setInterval(function () {
      if (closed) return;
      try { _writeRaw(":keepalive\n\n"); }
      catch (_e) { close({ reason: "heartbeat-write-failed" }); }
    }, heartbeatMs).unref();
  }

  if (auditOn) {
    audit.safeEmit({
      action:   "sse.channel_opened",
      outcome:  "success",
      metadata: { lastEventId: lastEventId, heartbeatMs: heartbeatMs },
    });
  }

  return {
    send:        send,
    comment:     comment,
    close:       close,
    get lastEventId() { return lastEventId; },
    get closed()      { return closed;      },
  };
}

module.exports = {
  create:          create,
  serializeEvent:  serializeEvent,
  // Cap exposure for operators wiring their own framing.
  MAX_EVENT_BYTES: MAX_EVENT_BYTES,
  MAX_ID_BYTES:    MAX_ID_BYTES,
  MAX_DATA_BYTES:  MAX_DATA_BYTES,
};
