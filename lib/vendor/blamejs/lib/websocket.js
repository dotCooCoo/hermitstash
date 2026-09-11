// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.websocket
 * @nav    HTTP
 * @title  Websocket
 *
 * @intro
 *   RFC 6455 WebSocket server on top of Node's `'upgrade'` event, plus
 *   RFC 8441 Extended CONNECT for HTTP/2. Built on `node:net` +
 *   `node:crypto` + `node:zlib` with no npm runtime dep.
 *
 *   Three layers exposed to operators:
 *
 *     1. Handshake — `handleUpgrade(req, socket, head, opts)` for h1
 *        and `handleExtendedConnect(stream, headers, opts)` for h2.
 *        Validate the request, enforce same-origin (default) or an
 *        operator-supplied allowlist, negotiate subprotocol +
 *        permessage-deflate, return a `WebSocketConnection`. Refuse
 *        credential-shaped query parameters (`access_token`, `apikey`,
 *        `authorization`, …) — query strings leak via access logs,
 *        Referer headers, and browser history.
 *
 *     2. Connection — `WebSocketConnection` is an EventEmitter
 *        mirroring the browser API. Read `conn.readyState`
 *        (`'open' | 'closing' | 'closed'`); call `conn.send(data)`,
 *        `conn.ping(payload?)`, `conn.close(code?, reason?)`. Listen
 *        on `'message'`, `'ping'`, `'pong'`, `'close'`, `'error'`.
 *
 *     3. Frame layer — `FrameParser` + `serializeFrame` exposed for
 *        tests and advanced callers (custom proxy / multiplexer use
 *        cases). Operator code rarely touches these directly.
 *
 *   Defenses wired in by default:
 *
 *     - Same-origin Origin check on browser-initiated upgrades. Cross-
 *       site WebSocket hijacking (CSWSH) requires explicit opt-in via
 *       `origins: [...allowlist]` or `origins: "*"`.
 *     - Control-frame payload cap of 125 bytes (RFC 6455 §5.5).
 *       Without it, a 1 MiB PING echoes back as a 1 MiB PONG — a 2x
 *       outbound-bandwidth amplification DoS.
 *     - Strict UTF-8 validation on TEXT frames + close reasons (§5.6).
 *     - Close-code allowlist per §7.4.2 (1000–1011, 3000–4999;
 *       reserved 1004/1005/1006/1015 refused on the wire).
 *     - Frame + message length capped at `maxMessageBytes`
 *       (default 1 MiB).
 *     - Heartbeat: ping every 30s, abort after 35s without pong.
 *     - Cluster fan-out lives at the router/channel layer above this
 *       module; this primitive owns the per-connection protocol.
 *
 *   Configurable handshake GUID: closed-ecosystem clients with a
 *   custom magic string pass `opts.handshakeGuid` (UUID-shaped). The
 *   default is the RFC 6455 §1.3 value so RFC-compliant clients
 *   interoperate out of the box. SHA-1 used in `Sec-WebSocket-Accept`
 *   is a protocol marker, not a security primitive — its collision
 *   resistance is irrelevant to the connection's security.
 *
 *   Spec compliance notes (where naive implementations get it wrong):
 *
 *     1. Mask handling (§5.3). All client→server h1 frames MUST be
 *        masked; server→client frames MUST NOT be masked. The h2
 *        transport (RFC 8441) flips both: frames MUST NOT be masked
 *        because h2 already provides the framing guarantees masking
 *        defends.
 *     2. Close handshake reciprocity (§5.5.1). Peer-initiated close
 *        echoes a close frame back before ending the TCP socket.
 *     3. Subprotocol negotiation. Server picks the FIRST entry from
 *        `Sec-WebSocket-Protocol` that's in the operator's allowlist.
 *        If none match, response omits the header (§11.3.4).
 *     4. permessage-deflate (RFC 7692). Negotiated when the client
 *        offers it; runs in `no_context_takeover` mode in both
 *        directions so each message uses a fresh zlib state.
 *
 * @card
 *   RFC 6455 WebSocket server on top of Node's `'upgrade'` event, plus RFC 8441 Extended CONNECT for HTTP/2.
 */

var nodeCrypto = require("node:crypto");
var zlib = require("node:zlib");
var safeDecompress = require("./safe-decompress").safeDecompress;
var { EventEmitter } = require("node:events");
var C                = require("./constants");
var requestHelpers   = require("./request-helpers");
var safeAsync        = require("./safe-async");
var safeBuffer       = require("./safe-buffer");
var pick             = require("./pick");
var structuredFields = require("./structured-fields");
var { FrameworkError } = require("./framework-error");
var { boot } = require("./log");

var HTTP = requestHelpers.HTTP_STATUS;
var log = boot("websocket");

var GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

var GUID_RE = /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/;

var REFUSED_AUTH_QUERY_PARAMS = Object.freeze([
  "access_token",
  "bearer",
  "bearer_token",
  "apikey",
  "api_key",
  "api-key",
  "authorization",
]);

var OPCODE_CONTINUATION = 0x0;
var OPCODE_TEXT         = 0x1;
var OPCODE_BINARY       = 0x2;
var OPCODE_CLOSE        = 0x8;
var OPCODE_PING         = 0x9;
var OPCODE_PONG         = 0xA;

var CLOSE_NORMAL              = 0x3E8;
var CLOSE_GOING_AWAY          = 0x3E9;
var CLOSE_PROTOCOL_ERROR      = 0x3EA;
var CLOSE_UNSUPPORTED_DATA    = 0x3EB;
var CLOSE_INVALID_PAYLOAD     = 0x3EF;
var CLOSE_POLICY_VIOLATION    = 0x3F0;
var CLOSE_MESSAGE_TOO_BIG     = 0x3F1;
var CLOSE_INTERNAL_ERROR      = 0x3F3;

var DEFAULT_MAX_MESSAGE_BYTES = C.BYTES.mib(1);
var DEFAULT_PING_INTERVAL_MS  = C.TIME.seconds(30);
var DEFAULT_PONG_TIMEOUT_MS   = C.TIME.seconds(35);
var CLOSE_GRACE_MS            = C.TIME.seconds(2);

function _isValidCloseCode(code) {
  if (code === 1004 || code === 1005 || code === 1006 || code === 1015) return false;
  if (code >= 1000 && code <= 1011) return true;                                              // allow:raw-time-literal — code is a numeric, not seconds
  if (code >= 3000 && code <= 4999) return true;                                              // allow:raw-time-literal — WebSocket close-code range bound (RFC 6455 7.4.2); coincidental multiple-of-60, C.TIME N/A
  return false;
}

var STATE_OPEN    = "open";
var STATE_CLOSING = "closing";
var STATE_CLOSED  = "closed";

/**
 * @primitive b.websocket.WebSocketError
 * @signature b.websocket.WebSocketError(code, message, closeCode)
 * @since     0.1.38
 * @status    stable
 * @related   b.websocket.WebSocketConnection
 *
 * Framework-error subclass thrown for protocol violations + invalid
 * caller input (`send()` on a closed connection, malformed frame
 * payload, frame-too-large detected at parse time). Carries the
 * RFC 6455 §7.4.1 `closeCode` the connection layer uses when
 * aborting (1002 protocol error, 1007 invalid payload, 1009 message
 * too big, 1011 internal error). Operators usually catch via the
 * shared `b.errors` surface and never construct one directly.
 *
 * @example
 *   try {
 *     conn.send("late message");
 *   } catch (err) {
 *     if (err.isWebSocketError) {
 *       console.log(err.code, err.closeCode);
 *       // → "ws/closed" 1002
 *     }
 *   }
 */
class WebSocketError extends FrameworkError {
  constructor(code, message, closeCode) {
    super(message, code);
    this.name = "WebSocketError";
    this.closeCode = closeCode || CLOSE_PROTOCOL_ERROR;
    this.isWebSocketError = true;
  }
}

/**
 * @primitive b.websocket.computeAcceptKey
 * @signature b.websocket.computeAcceptKey(secWebSocketKey, handshakeGuid)
 * @since     0.1.38
 * @status    stable
 * @related   b.websocket.handleUpgrade, b.websocket.buildUpgradeResponse
 *
 * Compute the `Sec-WebSocket-Accept` value RFC 6455 §1.3 mandates:
 * `base64(SHA1(secWebSocketKey || handshakeGuid))`. The SHA-1 is a
 * protocol marker confirming both ends agree on the upgrade — it is
 * NOT a security primitive, and the framework's other crypto stays
 * SHA3 / SHAKE-based regardless. Pass `handshakeGuid` undefined to
 * use the RFC value (`258EAFA5-E914-47DA-95CA-C5AB0DC85B11`); pass a
 * UUID-shaped override only for closed-ecosystem clients with a
 * matching custom magic string.
 *
 * @example
 *   var accept = b.websocket.computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ==");
 *   // → "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
 */
function computeAcceptKey(secWebSocketKey, handshakeGuid) {
  var hash = nodeCrypto.createHash("sha1");
  hash.update(String(secWebSocketKey) + (handshakeGuid || GUID));
  return hash.digest("base64");
}

/**
 * @primitive b.websocket.validateUpgradeRequest
 * @signature b.websocket.validateUpgradeRequest(req, opts)
 * @since     0.1.38
 * @status    stable
 * @related   b.websocket.handleUpgrade, b.websocket.isOriginAllowed
 *
 * Strict shape check on the HTTP/1.1 upgrade request. Verifies the
 * method is GET, `Upgrade: websocket` and `Connection: upgrade`
 * tokens are present, `Sec-WebSocket-Version: 13`, and
 * `Sec-WebSocket-Key` is a 24-character base64 of 16 random bytes
 * (RFC 6455 §4.1). Refuses credential-shaped query parameters
 * (`access_token`, `apikey`, `authorization`, …) unless the operator
 * passes `opts.allowQueryAuthParams: true` with an audited reason.
 * Returns `{ ok: true }` on success or
 * `{ ok: false, status, reason }` on refusal — never throws, so the
 * caller can write the refusal response and end the socket cleanly.
 *
 * @opts
 *   allowQueryAuthParams: boolean,   // opt out of credential-query refusal
 *
 * @example
 *   var v = b.websocket.validateUpgradeRequest(req, {});
 *   if (!v.ok) {
 *     // → { ok: false, status: 400, reason: "..." }
 *     socket.write("HTTP/1.1 " + v.status + " Bad Request\r\n\r\n");
 *     socket.destroy();
 *   }
 */
function validateUpgradeRequest(req, opts) {
  if (req.method !== "GET") {
    return { ok: false, status: HTTP.METHOD_NOT_ALLOWED, reason: "method must be GET" };
  }
  var h = req.headers || {};
  if ((h.upgrade || "").toLowerCase() !== "websocket") {
    return { ok: false, status: HTTP.BAD_REQUEST, reason: "missing Upgrade: websocket" };
  }
  if (!/(^|,)\s*upgrade\s*(,|$)/i.test(h.connection || "")) {
    return { ok: false, status: HTTP.BAD_REQUEST, reason: "missing Connection: upgrade" };
  }
  if (!h["sec-websocket-key"]) {
    return { ok: false, status: HTTP.BAD_REQUEST, reason: "missing Sec-WebSocket-Key" };
  }
  if (!/^[A-Za-z0-9+/]{22}==$/.test(h["sec-websocket-key"])) {
    return { ok: false, status: HTTP.BAD_REQUEST,
      reason: "Sec-WebSocket-Key must be base64 of 16 random bytes (RFC 6455 §4.1)" };
  }
  if (h["sec-websocket-version"] !== "13") {
    return { ok: false, status: HTTP.BAD_REQUEST, reason: "Sec-WebSocket-Version must be 13" };
  }
  if (!(opts && opts.allowQueryAuthParams === true)) {
    var leaked = _findCredentialQueryParam(req.url);
    if (leaked) {
      return {
        ok:     false,
        status: HTTP.BAD_REQUEST,
        reason: "credential-shaped query parameter '" + leaked +
          "' refused — query strings leak via logs / Referer / history. " +
          "Move the credential to the Authorization header, or set " +
          "opts.allowQueryAuthParams: true with an audited operator reason " +
          "if this parameter is not actually a credential.",
      };
    }
  }
  return { ok: true };
}

function _findCredentialQueryParam(reqUrl) {
  if (typeof reqUrl !== "string" || reqUrl.length === 0) return null;
  var qIdx = reqUrl.indexOf("?");
  if (qIdx === -1) return null;
  var query = reqUrl.slice(qIdx + 1);
  var fIdx = query.indexOf("#");
  if (fIdx !== -1) query = query.slice(0, fIdx);
  if (query.length === 0) return null;
  var pairs = query.split("&");
  for (var p = 0; p < pairs.length; p++) {
    var eqIdx = pairs[p].indexOf("=");
    var rawName = eqIdx === -1 ? pairs[p] : pairs[p].slice(0, eqIdx);
    if (rawName.length === 0) continue;
    var name;
    try { name = decodeURIComponent(rawName).toLowerCase(); }
    catch (_e) { name = rawName.toLowerCase(); }
    for (var r = 0; r < REFUSED_AUTH_QUERY_PARAMS.length; r++) {
      if (name === REFUSED_AUTH_QUERY_PARAMS[r]) return name;
    }
  }
  return null;
}

/**
 * @primitive b.websocket.negotiateSubprotocol
 * @signature b.websocket.negotiateSubprotocol(req, supported)
 * @since     0.1.38
 * @status    stable
 * @related   b.websocket.handleUpgrade, b.websocket.buildUpgradeResponse
 *
 * Pick the first client-offered subprotocol that appears in
 * `supported`. Returns the chosen string, or `null` when there is no
 * intersection (per RFC 6455 §11.3.4 the response then omits the
 * `Sec-WebSocket-Protocol` header and the client decides whether to
 * proceed). `supported` falsy or empty is treated as "no preference"
 * and always returns `null`.
 *
 * @example
 *   var req = { headers: { "sec-websocket-protocol": "chat.v2, chat.v1" } };
 *   var picked = b.websocket.negotiateSubprotocol(req, ["chat.v1"]);
 *   // → "chat.v1"
 */
function negotiateSubprotocol(req, supported) {
  if (!supported || supported.length === 0) return null;
  var raw = (req.headers || {})["sec-websocket-protocol"] || "";
  var offered = requestHelpers.parseListHeader(raw);
  for (var i = 0; i < offered.length; i++) {
    if (supported.indexOf(offered[i]) !== -1) return offered[i];
  }
  return null;
}

/**
 * @primitive b.websocket.isOriginAllowed
 * @signature b.websocket.isOriginAllowed(req, origins, opts?)
 * @since     0.1.38
 * @status    stable
 * @related   b.websocket.handleUpgrade, b.websocket.validateUpgradeRequest
 *
 * Browser-Origin policy gate. Behavior by the `origins` shape:
 *
 *   - Array — strict allowlist; the request's `Origin` header must
 *     match one entry exactly.
 *   - `"*"` — explicit accept-all (operator opt-in to no checking).
 *   - `null` / `undefined` — DEFAULT same-origin: the `Origin` must match
 *     the request's own origin on all three members RFC 6454 names —
 *     scheme, host and port. The scheme comes from the connection, the
 *     host from the HTTP/2 `:authority` or the HTTP/1.1 `Host`. Closes
 *     the cross-site WebSocket hijacking (CSWSH) class on
 *     browser-targeted routes, including an attacker at the cleartext
 *     origin of the same host.
 *
 * Non-browser clients (curl, server-to-server, native apps) don't
 * send `Origin` and bypass the check — gating those callers is the
 * operator's network-ACL / auth-middleware job, not Origin's.
 *
 * @opts
 *   trustProxy: function   // peer predicate; behind a TLS-terminating proxy
 *                          // the browser's Origin says https while the
 *                          // backend socket is cleartext, so the external
 *                          // scheme comes from X-Forwarded-Proto — honored
 *                          // only when the immediate peer satisfies this,
 *                          // the same gate b.requestHelpers.requestProtocol
 *                          // applies. `handleUpgrade` passes its own opts
 *                          // through, so wiring it there is enough.
 *
 * @example
 *   var req = { headers: { origin: "https://app.example.com",
 *                          host:   "app.example.com" } };
 *   b.websocket.isOriginAllowed(req, undefined);                 // → true
 *   b.websocket.isOriginAllowed(req, ["https://other.example"]); // → false
 *   b.websocket.isOriginAllowed(req, "*");                       // → true
 */
function isOriginAllowed(req, origins, opts) {
  if (origins === "*") return true;
  var origin = (req.headers || {}).origin;
  if (!origin) return true;
  if (Array.isArray(origins)) return origins.indexOf(origin) !== -1;
  if (!origins) {
    var host = requestHelpers.requestHost(req, opts);
    if (!host) return false;
    var scheme = requestHelpers.requestProtocol(req, opts) === "https" ? "https:" : "http:";
    var parsed;
    try { parsed = new URL(origin); }                                            // allow:raw-new-url-parse-only — comparing browser-supplied Origin header against the request's own authority; safeUrl.parse adds policy filtering that isn't appropriate for an exact origin comparison
    catch (_e) { return false; }
    return parsed.host === host && parsed.protocol === scheme;
  }
  return false;
}

/**
 * @primitive b.websocket.buildUpgradeResponse
 * @signature b.websocket.buildUpgradeResponse(secWebSocketKey, subprotocol, extensionHeader, handshakeGuid)
 * @since     0.1.38
 * @status    stable
 * @related   b.websocket.handleUpgrade, b.websocket.computeAcceptKey
 *
 * Format the HTTP/1.1 101 Switching Protocols response that completes
 * the WebSocket handshake. Always emits `Upgrade: websocket`,
 * `Connection: Upgrade`, and `Sec-WebSocket-Accept`. Adds
 * `Sec-WebSocket-Protocol` when `subprotocol` is non-null, and
 * `Sec-WebSocket-Extensions` when `extensionHeader` is non-null
 * (e.g. the `permessage-deflate; ...` echo). Pass `handshakeGuid`
 * undefined to use the RFC 6455 default. Returns the raw
 * `\r\n`-delimited response string ready for `socket.write()`.
 *
 * @example
 *   var resp = b.websocket.buildUpgradeResponse(
 *     "dGhlIHNhbXBsZSBub25jZQ==", "chat.v1", null);
 *   // → "HTTP/1.1 101 Switching Protocols\r\n..."
 *   socket.write(resp);
 */
function buildUpgradeResponse(secWebSocketKey, subprotocol, extensionHeader, handshakeGuid) {
  var lines = [
    "HTTP/1.1 101 Switching Protocols",
    "Upgrade: websocket",
    "Connection: Upgrade",
    "Sec-WebSocket-Accept: " + computeAcceptKey(secWebSocketKey, handshakeGuid),
  ];
  if (subprotocol) lines.push("Sec-WebSocket-Protocol: " + subprotocol);
  if (extensionHeader) lines.push("Sec-WebSocket-Extensions: " + extensionHeader);
  return lines.join("\r\n") + "\r\n\r\n";
}

var DEFLATE_TRAILING = Buffer.from([0x00, 0x00, 0xff, 0xff]);

function _parseExtensionHeader(header) {
  if (!header) return [];
  var entries = structuredFields.splitTopLevel(String(header), ",");
  var out = [];
  for (var i = 0; i < entries.length; i++) {
    var parts = structuredFields.splitTopLevel(entries[i], ";").map(function (s) { return s.trim(); });
    if (!parts[0]) continue;
    var paramPairs = [];
    for (var j = 1; j < parts.length; j++) {
      var kv = parts[j].split("=");
      var k = kv[0].trim().toLowerCase();
      if (!k) continue;
      if (pick.isPoisonedKey(k)) continue;
      var v = kv.length > 1 ? kv.slice(1).join("=").trim() : true;
      if (typeof v === "string") {
        var _unq = structuredFields.unquoteSfString(v);
        if (_unq !== null) v = _unq;
      }
      paramPairs.push([k, v]);
    }
    var ext = {
      name:   parts[0].toLowerCase(),
      params: Object.assign(Object.create(null), Object.fromEntries(paramPairs)),
    };
    out.push(ext);
  }
  return out;
}

function _negotiatePermessageDeflate(reqHeader) {
  var entries = _parseExtensionHeader(reqHeader);
  for (var i = 0; i < entries.length; i++) {
    if (entries[i].name !== "permessage-deflate") continue;
    var p = entries[i].params;
    var KNOWN = {
      "server_no_context_takeover": true, "client_no_context_takeover": true,
      "server_max_window_bits": true,     "client_max_window_bits": true,
    };
    var ok = true;
    for (var k in p) { if (Object.prototype.hasOwnProperty.call(p, k) && !Object.prototype.hasOwnProperty.call(KNOWN, k)) { ok = false; break; } }
    if (!ok) continue;
    var responseParams = ["client_no_context_takeover", "server_no_context_takeover"];
    if (p.client_max_window_bits && p.client_max_window_bits !== true) {
      responseParams.push("client_max_window_bits=" + p.client_max_window_bits);
    }
    if (p.server_max_window_bits && p.server_max_window_bits !== true) {
      responseParams.push("server_max_window_bits=" + p.server_max_window_bits);
    }
    var WB_MIN = 0x8;
    var WB_MAX = 0xF;
    return {
      negotiated: true,
      responseHeader: "permessage-deflate; " + responseParams.join("; "),
      serverMaxWindowBits: p.server_max_window_bits && p.server_max_window_bits !== true
        ? Math.max(WB_MIN, Math.min(WB_MAX, parseInt(p.server_max_window_bits, 10) || WB_MAX)) : WB_MAX,
      clientMaxWindowBits: p.client_max_window_bits && p.client_max_window_bits !== true
        ? Math.max(WB_MIN, Math.min(WB_MAX, parseInt(p.client_max_window_bits, 10) || WB_MAX)) : WB_MAX,
    };
  }
  return { negotiated: false };
}

function _deflateMessage(payload, windowBits) {
  var raw = zlib.deflateRawSync(payload, { windowBits: windowBits, level: zlib.constants.Z_DEFAULT_COMPRESSION });
  if (raw.length >= 4 &&
      raw[raw.length - 4] === 0x00 && raw[raw.length - 3] === 0x00 &&
      raw[raw.length - 2] === 0xff && raw[raw.length - 1] === 0xff) {
    return raw.slice(0, raw.length - 4);
  }
  return raw;
}

function _inflateMessage(payload, windowBits, maxOutputBytes) {
  var withTrailer = Buffer.concat([payload, DEFLATE_TRAILING]);
  return safeDecompress(withTrailer, {
    algorithm:          "deflate-raw",
    maxOutputBytes:     maxOutputBytes,
    maxCompressedBytes: maxOutputBytes,
    maxRatio:           0,
    windowBits:         windowBits,
    ctx:                "websocket._inflateMessage",
  });
}

/**
 * @primitive b.websocket.FrameParser
 * @signature b.websocket.FrameParser(opts)
 * @since     0.1.38
 * @status    stable
 * @related   b.websocket.serializeFrame, b.websocket.WebSocketConnection
 *
 * Incremental RFC 6455 §5.2 frame parser. `push(chunk)` accepts
 * arbitrary buffer slices straight from the socket and returns zero
 * or more complete frames; partial frame state persists across
 * calls. Each emitted frame is
 * `{ fin, rsv1, rsv2, rsv3, opcode, masked, payload }`. Throws a
 * `WebSocketError` (closeCode = 1009 message-too-big) when a single
 * frame's declared payload length exceeds `opts.maxFrameBytes`
 * (default 1 MiB) — the caller catches it and aborts the connection.
 * The parser does NOT enforce control-frame ≤125-byte caps,
 * mask-direction policy, or RSV-bit-vs-extension consistency; those
 * are the connection layer's job.
 *
 * @opts
 *   maxFrameBytes: number,   // single-frame payload cap (default 1 MiB)
 *
 * @example
 *   var parser = new b.websocket.FrameParser({ maxFrameBytes: 65536 });
 *   var frames = parser.push(Buffer.from([0x81, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f]));
 *   // → [{ fin: true, opcode: 1, payload: <Buffer 68 65 6c 6c 6f>, ... }]
 */
function FrameParser(opts) {
  opts = opts || {};
  this.maxFrameBytes = opts.maxFrameBytes || DEFAULT_MAX_MESSAGE_BYTES;
  this._buffer = Buffer.alloc(0);
}

FrameParser.prototype.push = function (chunk) {
  this._buffer = Buffer.concat([this._buffer, chunk]);
  var frames = [];
  while (true) {
    var frame = this._tryParseFrame();
    if (!frame) break;
    frames.push(frame);
  }
  return frames;
};

FrameParser.prototype._tryParseFrame = function () {
  if (this._buffer.length < 2) return null;
  var b0 = this._buffer[0];
  var b1 = this._buffer[1];
  var fin    = !!(b0 & 0x80);
  var rsv1   = !!(b0 & 0x40);
  var rsv2   = !!(b0 & 0x20);
  var rsv3   = !!(b0 & 0x10);
  var opcode = b0 & 0x0F;
  var masked = !!(b1 & 0x80);
  var lenInd = b1 & 0x7F;

  var headerLen = 2;
  if (lenInd === 126) headerLen += 2;
  else if (lenInd === 127) headerLen += C.BYTES.bytes(8);
  if (masked) headerLen += 4;
  if (this._buffer.length < headerLen) return null;

  var payloadLen;
  var off = 2;
  if (lenInd < 126) {
    payloadLen = lenInd;
  } else if (lenInd === 126) {
    payloadLen = this._buffer.readUInt16BE(off);
    off += 2;
  } else {
    var hi = this._buffer.readUInt32BE(off);
    var lo = this._buffer.readUInt32BE(off + 4);
    if (hi > 0x1FFFFF) {
      throw new WebSocketError("ws/frame-too-large",
        "frame length exceeds Number.MAX_SAFE_INTEGER", CLOSE_MESSAGE_TOO_BIG);
    }
    payloadLen = (hi * 0x100000000) + lo;
    off += C.BYTES.bytes(8);
  }

  if (payloadLen > this.maxFrameBytes) {
    throw new WebSocketError("ws/frame-too-large",
      "frame payload exceeds maxFrameBytes (" + this.maxFrameBytes + ")",
      CLOSE_MESSAGE_TOO_BIG);
  }

  var maskKey = null;
  if (masked) {
    maskKey = Buffer.from(this._buffer.subarray(off, off + 4));
    off += 4;
  }

  var totalLen = off + payloadLen;
  if (this._buffer.length < totalLen) return null;

  var payload = this._buffer.subarray(off, totalLen);
  if (masked) {
    var unmasked = Buffer.alloc(payloadLen);
    for (var i = 0; i < payloadLen; i++) {
      unmasked[i] = payload[i] ^ maskKey[i & 3];
    }
    payload = unmasked;
  } else {
    payload = Buffer.from(payload);
  }

  this._buffer = this._buffer.subarray(totalLen);

  return {
    fin:    fin,
    rsv1:   rsv1,
    rsv2:   rsv2,
    rsv3:   rsv3,
    opcode: opcode,
    masked: masked,
    payload: payload,
  };
};

/**
 * @primitive b.websocket.serializeFrame
 * @signature b.websocket.serializeFrame(opcode, payload, opts)
 * @since     0.1.38
 * @status    stable
 * @related   b.websocket.FrameParser, b.websocket.WebSocketConnection
 *
 * Build a single RFC 6455 §5.2 frame. `opcode` is one of
 * `b.websocket.OPCODE_TEXT` / `OPCODE_BINARY` / `OPCODE_CLOSE` /
 * `OPCODE_PING` / `OPCODE_PONG` / `OPCODE_CONTINUATION`. `payload`
 * is a `Buffer` or string (string is UTF-8 encoded). Server-side
 * frames default to unmasked; pass `mask: true` only for
 * client-shaped fixtures or test harnesses. `rsv1: true` marks the
 * first frame of a permessage-deflate-compressed message (RFC 7692).
 * Returns the framed `Buffer`.
 *
 * @opts
 *   fin:  boolean,    // FIN bit, default true (single-frame message)
 *   mask: boolean,    // mask the payload, default false (server side)
 *   rsv1: boolean,    // RSV1 bit (permessage-deflate), default false
 *
 * @example
 *   var frame = b.websocket.serializeFrame(
 *     b.websocket.OPCODE_TEXT, "hello");
 *   // → <Buffer 81 05 68 65 6c 6c 6f>
 *   socket.write(frame);
 */
function serializeFrame(opcode, payload, opts) {
  opts = opts || {};
  var fin  = opts.fin !== false;
  var mask = opts.mask === true;
  var rsv1 = opts.rsv1 === true;
  payload = payload || Buffer.alloc(0);
  if (typeof payload === "string") payload = Buffer.from(payload, "utf8");
  if (!Buffer.isBuffer(payload)) {
    throw new WebSocketError("ws/invalid-payload",
      "frame payload must be Buffer or string");
  }
  var len = payload.length;

  var headerLen = 2;
  var lenByte;
  var EXT16_BOUNDARY = 0x10000;
  if (len < 126)                     { lenByte = len; }
  else if (len < EXT16_BOUNDARY)     { lenByte = 126; headerLen += 2; }
  else                               { lenByte = 127; headerLen += C.BYTES.bytes(8); }
  if (mask) headerLen += 4;

  var header = Buffer.alloc(headerLen);
  header[0] = (fin ? 0x80 : 0) | (rsv1 ? 0x40 : 0) | (opcode & 0x0F);
  header[1] = (mask ? 0x80 : 0) | lenByte;

  var off = 2;
  if (lenByte === 126) {
    header.writeUInt16BE(len, off);
    off += 2;
  } else if (lenByte === 127) {
    var hi = Math.floor(len / 0x100000000);
    var lo = len % 0x100000000;
    header.writeUInt32BE(hi, off);
    header.writeUInt32BE(lo, off + 4);
    off += C.BYTES.bytes(8);
  }

  if (mask) {
    var maskKey = nodeCrypto.randomBytes(4);
    maskKey.copy(header, off);
    var masked = Buffer.alloc(len);
    for (var i = 0; i < len; i++) masked[i] = payload[i] ^ maskKey[i & 3];
    return Buffer.concat([header, masked]);
  }
  return Buffer.concat([header, payload]);
}

/**
 * @primitive b.websocket.WebSocketConnection
 * @signature b.websocket.WebSocketConnection(socket, opts)
 * @since     0.1.38
 * @status    stable
 * @related   b.websocket.handleUpgrade, b.websocket.handleExtendedConnect, b.websocket.WebSocketError
 *
 * EventEmitter wrapping a post-upgrade socket / h2 stream. State
 * machine mirrors the browser WebSocket API:
 *
 *   - `conn.readyState` — `'open' | 'closing' | 'closed'`
 *   - `conn.send(data)` — `Buffer` or string. Routes to BINARY or
 *     TEXT frame; throws `WebSocketError` if not OPEN.
 *   - `conn.ping(payload?)` — send PING (no-op if not OPEN).
 *   - `conn.close(code?, reason?)` — send CLOSE, wait `closeGraceMs`
 *     for the peer's echo, end the underlying socket.
 *
 * Events: `'message' (data, isBinary)`, `'ping' (payload)`,
 * `'pong' (payload)`, `'close' (code, reason, wasClean)` (fires
 * exactly once at lifecycle end), `'error' (err)`.
 *
 * Cluster fan-out / channel broadcast lives at the router layer that
 * owns the connection registry; this primitive owns the per-
 * connection protocol. To broadcast, iterate the operator-side
 * registry and call `send` on each.
 *
 * @opts
 *   subprotocol:        string,             // negotiated value from handleUpgrade
 *   transport:          "h1" | "h2",        // mask-direction policy, default "h1"
 *   maxMessageBytes:    number,             // total reassembled-message cap, default 1 MiB
 *   pingIntervalMs:     number,             // heartbeat interval, default 30s
 *   pongTimeoutMs:      number,             // abort threshold without pong, default 35s
 *   closeGraceMs:       number,             // peer-echo wait after close(), default 2s
 *   permessageDeflate:  object | null,      // negotiated state, usually from handleUpgrade
 *
 * @example
 *   server.on("upgrade", function (req, socket, head) {
 *     var conn = b.websocket.handleUpgrade(req, socket, head, {
 *       subprotocols: ["chat.v1"],
 *     });
 *     if (!conn) return;
 *     conn.on("message", function (data, isBinary) {
 *       conn.send(isBinary ? data : "echo: " + data);
 *     });
 *     conn.on("ping",  function (payload) { void payload; });   // framework auto-pongs
 *     conn.on("pong",  function (payload) { void payload; });   // heartbeat reply

 *     conn.on("close", function (code, reason, wasClean) {
 *       // → 1000, "", true
 *     });
 *   });
 */
class WebSocketConnection extends EventEmitter {
  constructor(socket, opts) {
    super();
    opts = opts || {};
    this.socket = socket;
    this.subprotocol = opts.subprotocol || null;
    this.maxMessageBytes = opts.maxMessageBytes || DEFAULT_MAX_MESSAGE_BYTES;
    this.transport = opts.transport === "h2" ? "h2" : "h1";
    this._permessageDeflate = opts.permessageDeflate || null;
    var pingMs = opts.pingIntervalMs || DEFAULT_PING_INTERVAL_MS;
    var pongMs = opts.pongTimeoutMs  || DEFAULT_PONG_TIMEOUT_MS;
    this._closeGraceMs = opts.closeGraceMs != null ? opts.closeGraceMs : CLOSE_GRACE_MS;

    this._state      = STATE_OPEN;
    this._closeSent  = false;
    this._closeTimer = null;
    this.lastError   = null;
    this._fragOpcode = null;
    this._fragChunks = null;
    this._fragLen    = 0;

    this._parser = new FrameParser({ maxFrameBytes: this.maxMessageBytes });
    this._lastPongAt = Date.now();

    var self = this;
    this._pingTimer = safeAsync.repeating(function () { self._heartbeat(pongMs); },
      pingMs, { name: "websocket-ping" });

    socket.on("data",  function (chunk) { self._onData(chunk); });
    socket.on("error", function (err)   {
      self._transitionToClosed(1006, (err && err.message) || "socket error", false, err);
    });
    socket.on("close", function ()      {
      if (self._state !== STATE_CLOSED) {
        self._transitionToClosed(1006, "abnormal closure", false, null);
      }
    });
    socket.on("end", function ()        {
      if (self._state !== STATE_CLOSED) {
        self._transitionToClosed(1006, "abnormal closure", false, null);
      }
      try { socket.end(); } catch (_e) { /* socket already closing */ }
    });
  }

  _transitionToClosed(code, reason, wasClean, error) {
    if (this._state === STATE_CLOSED) return;
    this._state = STATE_CLOSED;
    if (error) this.lastError = error;
    if (this._pingTimer)  { this._pingTimer.stop();  this._pingTimer  = null; }
    if (this._closeTimer) { clearTimeout(this._closeTimer);  this._closeTimer = null; }
    if (error && this.listenerCount("error") > 0) {
      try { this.emit("error", error); } catch (_e) { /* listener threw — ignore */ }
    }
    this.emit("close", code, reason, !!wasClean);
  }

  get readyState() { return this._state; }

  _onData(chunk) {
    var frames;
    try { frames = this._parser.push(chunk); }
    catch (err) {
      var code = err.closeCode || CLOSE_PROTOCOL_ERROR;
      return this._abort(code, err.message);
    }
    for (var i = 0; i < frames.length; i++) {
      this._handleFrame(frames[i]);
      if (this._state === STATE_CLOSED) return;
    }
  }

  _handleFrame(frame) {
    if (this.transport === "h1" && !frame.masked) {
      return this._abort(CLOSE_PROTOCOL_ERROR, "client frame not masked (h1)");
    }
    if (this.transport === "h2" && frame.masked) {
      return this._abort(CLOSE_PROTOCOL_ERROR, "frame must not be masked (h2)");
    }
    if (frame.rsv2 || frame.rsv3) {
      return this._abort(CLOSE_PROTOCOL_ERROR, "reserved bits set without extension");
    }
    if (frame.rsv1 && !this._permessageDeflate) {
      return this._abort(CLOSE_PROTOCOL_ERROR, "RSV1 set without permessage-deflate negotiated");
    }
    if (frame.rsv1 && frame.opcode === OPCODE_CONTINUATION) {
      return this._abort(CLOSE_PROTOCOL_ERROR, "RSV1 on continuation frame (must be on start)");
    }

    if (frame.opcode >= 0x8) {
      if (frame.payload.length > 125) {
        return this._abort(CLOSE_PROTOCOL_ERROR,
          "control frame payload exceeds 125 bytes (RFC 6455 §5.5)");
      }
      if (!frame.fin) {
        return this._abort(CLOSE_PROTOCOL_ERROR,
          "control frame must not be fragmented (RFC 6455 §5.5)");
      }
    }

    if (frame.opcode === OPCODE_CONTINUATION) {
      if (this._fragOpcode === null) {
        return this._abort(CLOSE_PROTOCOL_ERROR, "continuation without start");
      }
      this._appendFragment(frame);
    } else if (frame.opcode === OPCODE_TEXT || frame.opcode === OPCODE_BINARY) {
      if (this._fragOpcode !== null) {
        return this._abort(CLOSE_PROTOCOL_ERROR, "new message during fragmentation");
      }
      this._fragOpcode = frame.opcode;
      this._fragChunks = [frame.payload];
      this._fragLen    = frame.payload.length;
      this._fragCompressed = !!frame.rsv1;
      if (frame.fin) this._emitMessage();
    } else if (frame.opcode === OPCODE_CLOSE) {
      this._handleClose(frame);
    } else if (frame.opcode === OPCODE_PING) {
      this.emit("ping", frame.payload);
      this._sendFrame(OPCODE_PONG, frame.payload);
    } else if (frame.opcode === OPCODE_PONG) {
      this._lastPongAt = Date.now();
      this.emit("pong", frame.payload);
    } else {
      this._abort(CLOSE_PROTOCOL_ERROR, "unknown opcode " + frame.opcode);
    }
  }

  _appendFragment(frame) {
    var newLen = this._fragLen + frame.payload.length;
    if (newLen > this.maxMessageBytes) {
      return this._abort(CLOSE_MESSAGE_TOO_BIG, "message exceeds maxMessageBytes");
    }
    this._fragChunks.push(frame.payload);
    this._fragLen = newLen;
    if (frame.fin) this._emitMessage();
  }

  _emitMessage() {
    var data = this._fragChunks.length === 1
      ? this._fragChunks[0]
      : Buffer.concat(this._fragChunks, this._fragLen);
    var opcode = this._fragOpcode;
    var wasCompressed = this._fragCompressed;
    this._fragOpcode = null;
    this._fragChunks = null;
    this._fragLen    = 0;
    this._fragCompressed = false;
    if (wasCompressed) {
      try {
        data = _inflateMessage(data, this._permessageDeflate.clientMaxWindowBits,
                                this.maxMessageBytes);
      } catch (e) {
        return this._abort(CLOSE_INVALID_PAYLOAD,
          "permessage-deflate inflate failed: " + ((e && e.message) || String(e)));
      }
      if (safeBuffer.byteLengthOf(data) > this.maxMessageBytes) {
        return this._abort(CLOSE_MESSAGE_TOO_BIG,
          "decompressed message exceeds maxMessageBytes");
      }
    }
    if (opcode === OPCODE_TEXT) {
      var str;
      try { str = new TextDecoder("utf-8", { fatal: true }).decode(data); }
      catch (_e) { return this._abort(CLOSE_INVALID_PAYLOAD, "text frame is not valid UTF-8"); }
      this.emit("message", str, false);
    } else {
      this.emit("message", data, true);
    }
  }

  _handleClose(frame) {
    var code = CLOSE_NORMAL, reason = "";
    if (frame.payload.length === 1) {
      return this._abort(CLOSE_PROTOCOL_ERROR,
        "close frame payload must be 0 or >=2 bytes (RFC 6455 §5.5.1)");
    }
    if (frame.payload.length >= 2) {
      code = frame.payload.readUInt16BE(0);
      if (!_isValidCloseCode(code)) {
        return this._abort(CLOSE_PROTOCOL_ERROR,
          "close code " + code + " is reserved or invalid (RFC 6455 §7.4.2)");
      }
      if (frame.payload.length > 2) {
        try { reason = new TextDecoder("utf-8", { fatal: true }).decode(frame.payload.subarray(2)); }
        catch (_e) { return this._abort(CLOSE_INVALID_PAYLOAD, "close reason is not valid UTF-8"); }
      }
    }
    if (!this._closeSent) {
      this._sendCloseFrame(code, reason);
      this._closeSent = true;
    }
    try { this.socket.end(); } catch (_e) { /* socket already closed by peer */ }
    this._transitionToClosed(code, reason, true, null);
  }

  _sendCloseFrame(code, reason) {
    var reasonBuf = reason ? Buffer.from(String(reason), "utf8") : Buffer.alloc(0);
    var payload = Buffer.alloc(2 + reasonBuf.length);
    payload.writeUInt16BE(code, 0);
    if (reasonBuf.length) reasonBuf.copy(payload, 2);
    this._sendFrame(OPCODE_CLOSE, payload);
  }

  _sendFrame(opcode, payload, opts) {
    if (this._state === STATE_CLOSED) return;
    if (this.socket.destroyed || this.socket.writable === false) {
      this._transitionToClosed(1006, "socket no longer writable", false, null);
      return;
    }
    try {
      this.socket.write(serializeFrame(opcode, payload, opts));
    } catch (err) {
      this._transitionToClosed(1006, (err && err.message) || "write failed", false, err);
    }
  }

  _sendDataFrame(opcode, payload) {
    if (this._permessageDeflate && opcode !== OPCODE_PING &&
        opcode !== OPCODE_PONG && opcode !== OPCODE_CLOSE) {
      try {
        var compressed = _deflateMessage(payload, this._permessageDeflate.serverMaxWindowBits);
        this._sendFrame(opcode, compressed, { rsv1: true });
        return;
      } catch (_e) {
        // Compression failure on send — fall through to uncompressed
        // (we still have the original payload) so the connection
        // keeps working. The underlying issue surfaces as observability.
      }
    }
    this._sendFrame(opcode, payload);
  }

  send(data) {
    if (this._state !== STATE_OPEN) {
      throw new WebSocketError("ws/closed",
        "connection is " + this._state + ", cannot send");
    }
    if (typeof data === "string") {
      this._sendDataFrame(OPCODE_TEXT, Buffer.from(data, "utf8"));
    } else if (Buffer.isBuffer(data)) {
      this._sendDataFrame(OPCODE_BINARY, data);
    } else {
      data = safeBuffer.toBuffer(data, {
        errorFactory: function (code, message) { return new WebSocketError(code, message); },
        typeCode:   "ws/invalid-payload",
        typeMessage: "send() requires Buffer, Uint8Array, or string",
      });
      this._sendDataFrame(OPCODE_BINARY, data);
    }
  }

  ping(payload) {
    if (this._state !== STATE_OPEN) return;
    this._sendFrame(OPCODE_PING, payload || Buffer.alloc(0));
  }

  close(code, reason) {
    if (this._state !== STATE_OPEN) return;
    code = code || CLOSE_NORMAL;
    this._sendCloseFrame(code, reason || "");
    this._closeSent = true;
    this._state = STATE_CLOSING;
    var self = this;
    this._closeTimer = setTimeout(function () {
      try { self.socket.end(); } catch (_e) { /* socket already closed */ }
      self._transitionToClosed(code, reason || "", false, null);
    }, this._closeGraceMs);
    this._closeTimer.unref();
  }

  _abort(code, reason) {
    if (this._state === STATE_CLOSED) return;
    if (!this._closeSent) {
      try { this._sendCloseFrame(code, reason); this._closeSent = true; } catch (_e) { /* close frame send-best-effort during abort */ }
    }
    try { this.socket.destroy(); } catch (_e) { /* socket already destroyed */ }
    this._transitionToClosed(code, reason, false, null);
  }

  _heartbeat(pongTimeoutMs) {
    if (this._state !== STATE_OPEN) return;
    if (Date.now() - this._lastPongAt > pongTimeoutMs) {
      this._abort(CLOSE_INTERNAL_ERROR, "ping timeout — peer unresponsive");
      return;
    }
    this.ping();
  }
}

/**
 * @primitive b.websocket.handleUpgrade
 * @signature b.websocket.handleUpgrade(req, socket, head, opts)
 * @since     0.1.38
 * @status    stable
 * @related   b.websocket.handleExtendedConnect, b.websocket.WebSocketConnection
 *
 * RFC 6455 HTTP/1.1 upgrade entry point. Wire it to the HTTP
 * server's `'upgrade'` event. Validates the handshake, enforces the
 * Origin policy (same-origin by default), negotiates subprotocol +
 * permessage-deflate, writes the 101 response, and returns a
 * `WebSocketConnection`. Returns `null` and writes a refusal HTTP
 * response on bad handshake / origin mismatch — the caller does not
 * need a try/catch around the normal refusal paths. Throws
 * synchronously only when `opts.handshakeGuid` is supplied with a
 * malformed value (config-time typo).
 *
 * @opts
 *   origins:               string[] | "*",  // allowlist, or "*" accept-all; default same-origin
 *   subprotocols:          string[],        // negotiation allowlist
 *   handshakeGuid:         string,          // UUID-shape override of RFC 6455 §1.3 GUID
 *   permessageDeflate:     boolean,         // RFC 7692 negotiation, default true
 *   maxMessageBytes:       number,          // total message cap, default 1 MiB
 *   pingIntervalMs:        number,          // heartbeat interval, default 30s
 *   pongTimeoutMs:         number,          // abort-after-silence, default 35s
 *   allowQueryAuthParams:  boolean,         // opt out of credential-query refusal
 *
 * @example
 *   var http = require("http");
 *   var server = http.createServer();
 *   server.on("upgrade", function (req, socket, head) {
 *     var conn = b.websocket.handleUpgrade(req, socket, head, {
 *       origins:      ["https://app.example.com"],
 *       subprotocols: ["chat.v1"],
 *     });
 *     if (!conn) return;   // refusal already written + socket destroyed
 *     conn.on("message", function (data, isBinary) {
 *       // → "hello", false
 *       conn.send("ack: " + data);
 *     });
 *   });
 */
function handleUpgrade(req, socket, head, opts) {
  opts = opts || {};

  var GUID_MAX_LENGTH = C.BYTES.bytes(64);
  if (opts.handshakeGuid !== undefined && opts.handshakeGuid !== null) {
    if (typeof opts.handshakeGuid !== "string" ||
        opts.handshakeGuid.length > GUID_MAX_LENGTH ||
        !GUID_RE.test(opts.handshakeGuid)) {
      throw new Error("websocket.handleUpgrade: handshakeGuid must be a UUID-shaped string (8-4-4-4-12 hex with dashes), got " +
        JSON.stringify(opts.handshakeGuid));
    }
  }

  var v = validateUpgradeRequest(req, opts);
  if (!v.ok) {
    _refuseUpgrade(socket, v.status || 400, v.reason);
    return null;
  }

  if (!isOriginAllowed(req, opts.origins, opts)) {
    _refuseUpgrade(socket, 403, "origin not allowed");
    return null;
  }

  var subprotocol = negotiateSubprotocol(req, opts.subprotocols);

  var pmd = null;
  if (opts.permessageDeflate !== false) {
    var negotiated = _negotiatePermessageDeflate(req.headers["sec-websocket-extensions"]);
    if (negotiated.negotiated) pmd = negotiated;
  }

  try {
    socket.write(buildUpgradeResponse(
      req.headers["sec-websocket-key"], subprotocol,
      pmd ? pmd.responseHeader : null, opts.handshakeGuid));
  } catch (err) {
    log.error("failed to write upgrade response: " + err.message);
    try { socket.destroy(); } catch (_e) { /* socket already destroyed */ }
    return null;
  }

  var conn = new WebSocketConnection(socket, {
    subprotocol:        subprotocol,
    maxMessageBytes:    opts.maxMessageBytes,
    pingIntervalMs:     opts.pingIntervalMs,
    pongTimeoutMs:      opts.pongTimeoutMs,
    permessageDeflate:  pmd,
  });
  if (head && head.length > 0) {
    conn._onData(head);
  }
  return conn;
}

/**
 * @primitive b.websocket.handleExtendedConnect
 * @signature b.websocket.handleExtendedConnect(stream, requestHeaders, opts)
 * @since     0.1.39
 * @status    stable
 * @related   b.websocket.handleUpgrade, b.websocket.WebSocketConnection
 *
 * RFC 8441 Extended CONNECT entry point for HTTP/2. Wire it to the
 * h2 server's `'stream'` event when `:method` is `CONNECT` and
 * `:protocol` is `websocket`. Same Origin / subprotocol policy as
 * `handleUpgrade`. Responds with `:status 200` (NOT 101 — Extended
 * CONNECT is a CONNECT, not an Upgrade) and returns a
 * `WebSocketConnection` wrapping the h2 stream with mask-direction
 * flipped (h2 frames MUST NOT be masked). The h2 server must
 * advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`; pass
 * `settings: { enableConnectProtocol: true }` to
 * `http2.createSecureServer`. Returns `null` on refusal.
 *
 * @opts
 *   origins:           string[] | "*",   // allowlist / accept-all; default same-origin
 *   subprotocols:      string[],         // negotiation allowlist
 *   maxMessageBytes:   number,           // total message cap, default 1 MiB
 *   pingIntervalMs:    number,           // heartbeat interval, default 30s
 *   pongTimeoutMs:     number,           // abort-after-silence, default 35s
 *
 * @example
 *   var http2 = require("http2");
 *   var server = http2.createSecureServer({
 *     key:  fs.readFileSync("/etc/blamejs/tls.key"),
 *     cert: fs.readFileSync("/etc/blamejs/tls.crt"),
 *     settings: { enableConnectProtocol: true },
 *   });
 *   server.on("stream", function (stream, headers) {
 *     if (headers[":method"] !== "CONNECT") return;
 *     var conn = b.websocket.handleExtendedConnect(stream, headers, {
 *       origins:      ["https://app.example.com"],
 *       subprotocols: ["chat.v1"],
 *     });
 *     if (!conn) return;
 *     conn.close(1000, "shutdown");   // → 1000, "shutdown", true on the peer's 'close'
 *   });
 */
function handleExtendedConnect(stream, requestHeaders, opts) {
  opts = opts || {};

  if (requestHeaders[":method"] !== "CONNECT") {
    _refuseH2Connect(stream, HTTP.BAD_REQUEST, "method must be CONNECT");
    return null;
  }
  if (requestHeaders[":protocol"] !== "websocket") {
    _refuseH2Connect(stream, HTTP.BAD_REQUEST, ":protocol must be websocket");
    return null;
  }

  var h2Socket = (stream && stream.session && stream.session.socket) || null;
  var fakeReq = { headers: requestHeaders, method: "CONNECT", socket: h2Socket };
  if (!isOriginAllowed(fakeReq, opts.origins, opts)) {
    _refuseH2Connect(stream, HTTP.FORBIDDEN, "origin not allowed");
    return null;
  }

  var subprotocol = negotiateSubprotocol(fakeReq, opts.subprotocols);

  var responseHeaders = { ":status": HTTP.OK };
  if (subprotocol) responseHeaders["sec-websocket-protocol"] = subprotocol;
  try {
    stream.respond(responseHeaders);
  } catch (err) {
    log.error("failed to write h2 Extended CONNECT response: " + err.message);
    try { stream.close(); } catch (_e) { /* stream already closing */ }
    return null;
  }

  return new WebSocketConnection(stream, {
    transport:       "h2",
    subprotocol:     subprotocol,
    maxMessageBytes: opts.maxMessageBytes,
    pingIntervalMs:  opts.pingIntervalMs,
    pongTimeoutMs:   opts.pongTimeoutMs,
  });
}

function _refuseH2Connect(stream, status, reason) {
  try {
    stream.respond({ ":status": status, "content-type": "text/plain; charset=utf-8" });
    stream.end(reason || ("HTTP " + status));
  } catch (_e) {
    try { stream.close(); } catch (_e2) { /* stream already closed */ }
  }
}

var _UPGRADE_REFUSAL_TEXT = {};
_UPGRADE_REFUSAL_TEXT[HTTP.BAD_REQUEST]        = "Bad Request";
_UPGRADE_REFUSAL_TEXT[HTTP.FORBIDDEN]          = "Forbidden";
_UPGRADE_REFUSAL_TEXT[HTTP.METHOD_NOT_ALLOWED] = "Method Not Allowed";
_UPGRADE_REFUSAL_TEXT[0x1AA]                   = "Upgrade Required";

function _refuseUpgrade(socket, status, reason) {
  var statusText = _UPGRADE_REFUSAL_TEXT[status] || "Bad Request";
  var body = reason || statusText;
  var resp =
    "HTTP/1.1 " + status + " " + statusText + "\r\n" +
    "Connection: close\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "Content-Length: " + Buffer.byteLength(body, "utf8") + "\r\n" +
    "\r\n" +
    body;
  try { socket.write(resp); } catch (_e) { /* socket already closed */ }
  try { socket.destroy(); } catch (_e) { /* socket already closed */ }
}

module.exports = {
  computeAcceptKey:        computeAcceptKey,
  validateUpgradeRequest:  validateUpgradeRequest,
  negotiateSubprotocol:    negotiateSubprotocol,
  isOriginAllowed:         isOriginAllowed,
  buildUpgradeResponse:    buildUpgradeResponse,
  FrameParser:             FrameParser,
  serializeFrame:          serializeFrame,
  WebSocketConnection:     WebSocketConnection,
  WebSocketError:          WebSocketError,
  handleUpgrade:           handleUpgrade,
  handleExtendedConnect:   handleExtendedConnect,
  _parseExtensionHeader:   _parseExtensionHeader,
  GUID:                    GUID,
  REFUSED_AUTH_QUERY_PARAMS: REFUSED_AUTH_QUERY_PARAMS,
  OPCODE_CONTINUATION:     OPCODE_CONTINUATION,
  OPCODE_TEXT:             OPCODE_TEXT,
  OPCODE_BINARY:           OPCODE_BINARY,
  OPCODE_CLOSE:            OPCODE_CLOSE,
  OPCODE_PING:             OPCODE_PING,
  OPCODE_PONG:             OPCODE_PONG,
  CLOSE_NORMAL:            CLOSE_NORMAL,
  CLOSE_GOING_AWAY:        CLOSE_GOING_AWAY,
  CLOSE_PROTOCOL_ERROR:    CLOSE_PROTOCOL_ERROR,
  CLOSE_UNSUPPORTED_DATA:  CLOSE_UNSUPPORTED_DATA,
  CLOSE_INVALID_PAYLOAD:   CLOSE_INVALID_PAYLOAD,
  CLOSE_POLICY_VIOLATION:  CLOSE_POLICY_VIOLATION,
  CLOSE_MESSAGE_TOO_BIG:   CLOSE_MESSAGE_TOO_BIG,
  CLOSE_INTERNAL_ERROR:    CLOSE_INTERNAL_ERROR,
};
