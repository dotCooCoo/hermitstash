// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * websocket — RFC 6455 server + RFC 8441 h2 Extended CONNECT.
 *
 * Covers the handshake helpers (b.websocket.WebSocketError,
 * buildUpgradeResponse, computeAcceptKey, validateUpgradeRequest,
 * negotiateSubprotocol, isOriginAllowed), the frame layer (FrameParser
 * + serializeFrame against adversarial frames — oversized, over-length,
 * masked/unmasked, extended lengths), the WebSocketConnection state
 * machine (send/ping/close, fragmentation, control-frame caps, close-
 * code allowlist, UTF-8 validation, permessage-deflate, heartbeat), and
 * the server-side entry points (handleUpgrade + handleExtendedConnect
 * refusal + success paths) driven through injected socket / h2-stream
 * stubs — never the real network.
 *
 * Run standalone: `node test/layer-0-primitives/websocket.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var EventEmitter = require("node:events").EventEmitter;
var zlib         = require("node:zlib");

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

var ws = b.websocket;

// RFC 6455 §1.3 canonical example.
var RFC_KEY    = "dGhlIHNhbXBsZSBub25jZQ==";
var RFC_ACCEPT = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

// ---- injected stubs (no network) ----

// A Duplex-shaped socket stub. WebSocketConnection registers
// data/error/close/end listeners and calls write/end/destroy — this
// captures every server-side write as a raw chunk and lets the test
// drive inbound bytes via socket.emit("data", frame).
function makeSocket(opts) {
  opts = opts || {};
  var s = new EventEmitter();
  s.written   = [];
  s.destroyed = false;
  s.writable  = true;
  s.ended     = false;
  s.write = function (chunk) {
    if (opts.writeThrows) throw new Error("write EPIPE");
    s.written.push(chunk);          // raw — strings (101 response) stay strings
    return true;
  };
  s.end     = function () { s.ended = true; s.writable = false; };
  s.destroy = function () { s.destroyed = true; s.writable = false; };
  return s;
}

// An h2 stream stub for handleExtendedConnect. Adds respond()/close()
// on top of the socket surface WebSocketConnection consumes.
function makeH2Stream(opts) {
  opts = opts || {};
  var s = new EventEmitter();
  s.written   = [];
  s.responded = null;
  s.ended     = false;
  s.closed    = false;
  s.destroyed = false;
  s.writable  = true;
  s.respond = function (headers) {
    if (opts.respondThrows) throw new Error("h2 respond failed");
    s.responded = headers;
  };
  s.end     = function (data) { s.ended = true; if (data !== undefined) s.endData = data; s.writable = false; };
  s.close   = function () { s.closed = true; s.writable = false; };
  s.write   = function (chunk) { s.written.push(chunk); return true; };
  s.destroy = function () { s.destroyed = true; s.writable = false; };
  return s;
}

// Parse every Buffer chunk the server wrote back into frames.
function serverFrames(socket) {
  var bufs = socket.written.filter(function (w) { return Buffer.isBuffer(w); });
  if (bufs.length === 0) return [];
  var fp = new ws.FrameParser();
  return fp.push(Buffer.concat(bufs));
}

// Build a masked client→server frame (RFC 6455 §5.3: client frames MUST
// be masked). serializeFrame with mask:true is exactly the client shape.
function clientFrame(opcode, payload, extra) {
  var o = Object.assign({ mask: true }, extra || {});
  return ws.serializeFrame(opcode, payload, o);
}

// serializeFrame only wires RSV1; set RSV2/RSV3 (or any header-byte-0
// bit) by mutating the flags byte of an already-built masked frame.
function withByte0Bit(frame, bit) {
  frame[0] = frame[0] | bit;
  return frame;
}

function closePayload(code, reason) {
  var r = reason ? (Buffer.isBuffer(reason) ? reason : Buffer.from(reason, "utf8")) : Buffer.alloc(0);
  var buf = Buffer.alloc(2 + r.length);
  buf.writeUInt16BE(code, 0);
  if (r.length) r.copy(buf, 2);
  return buf;
}

function upgradeReq(extraHeaders, url) {
  var h = Object.assign({
    upgrade:                 "websocket",
    connection:              "Upgrade",
    "sec-websocket-key":     RFC_KEY,
    "sec-websocket-version": "13",
    host:                    "app.example.com",
    origin:                  "https://app.example.com",
  }, extraHeaders || {});
  return { method: "GET", url: url || "/ws", headers: h };
}

// Ensure a connection's ping timer is stopped (unref'd, but transition
// releases it cleanly). Idempotent.
function teardown(conn, socket) {
  if (conn && conn.readyState !== "closed") socket.emit("close");
}

// ============================================================
//  Existing handshake-helper coverage
// ============================================================

function testWebSocketError() {
  var err = new ws.WebSocketError("ws/closed", "send() on a closed connection", 1002);
  check("WebSocketError is an Error subclass",         err instanceof Error);
  check("WebSocketError carries the framework code",   err.code === "ws/closed");
  check("WebSocketError carries the message",          err.message === "send() on a closed connection");
  check("WebSocketError carries the RFC closeCode",    err.closeCode === 1002);
  check("WebSocketError flags isWebSocketError",       err.isWebSocketError === true);
  check("WebSocketError name is WebSocketError",       err.name === "WebSocketError");

  // Omitted closeCode defaults to 1002 (protocol error).
  var dflt = new ws.WebSocketError("ws/proto", "bad frame");
  check("WebSocketError defaults closeCode to CLOSE_PROTOCOL_ERROR (1002)",
        dflt.closeCode === ws.CLOSE_PROTOCOL_ERROR && dflt.closeCode === 1002);
}

function testBuildUpgradeResponse() {
  var resp = ws.buildUpgradeResponse(RFC_KEY, null, null);
  check("buildUpgradeResponse starts with 101 Switching Protocols",
        resp.indexOf("HTTP/1.1 101 Switching Protocols\r\n") === 0);
  check("buildUpgradeResponse emits Upgrade: websocket",
        /\r\nUpgrade: websocket\r\n/.test(resp));
  check("buildUpgradeResponse emits Connection: Upgrade",
        /\r\nConnection: Upgrade\r\n/.test(resp));
  check("buildUpgradeResponse computes the RFC 6455 Sec-WebSocket-Accept",
        resp.indexOf("Sec-WebSocket-Accept: " + RFC_ACCEPT + "\r\n") !== -1);
  check("buildUpgradeResponse terminates with a blank line",
        resp.slice(-4) === "\r\n\r\n");
  check("buildUpgradeResponse omits Sec-WebSocket-Protocol when subprotocol is null",
        resp.indexOf("Sec-WebSocket-Protocol") === -1);
  check("buildUpgradeResponse omits Sec-WebSocket-Extensions when null",
        resp.indexOf("Sec-WebSocket-Extensions") === -1);

  check("buildUpgradeResponse Accept agrees with computeAcceptKey",
        resp.indexOf("Sec-WebSocket-Accept: " + ws.computeAcceptKey(RFC_KEY) + "\r\n") !== -1);

  var resp2 = ws.buildUpgradeResponse(RFC_KEY, "chat.v1", "permessage-deflate; server_no_context_takeover");
  check("buildUpgradeResponse includes Sec-WebSocket-Protocol when subprotocol given",
        /\r\nSec-WebSocket-Protocol: chat\.v1\r\n/.test(resp2));
  check("buildUpgradeResponse includes Sec-WebSocket-Extensions when given",
        resp2.indexOf("Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover\r\n") !== -1);
  check("buildUpgradeResponse with options still terminates with a blank line",
        resp2.slice(-4) === "\r\n\r\n");
}

function testComputeAcceptKeyCustomGuid() {
  var guid = "12345678-1234-1234-1234-1234567890AB";
  var custom = ws.computeAcceptKey(RFC_KEY, guid);
  check("computeAcceptKey with a custom GUID differs from the RFC default",
        custom !== ws.computeAcceptKey(RFC_KEY));
  check("computeAcceptKey with a custom GUID is deterministic",
        custom === ws.computeAcceptKey(RFC_KEY, guid));
}

// ============================================================
//  validateUpgradeRequest — every refusal branch
// ============================================================

function testValidateUpgradeRequest() {
  check("validate: valid handshake ok",
        ws.validateUpgradeRequest(upgradeReq(), {}).ok === true);

  var m = ws.validateUpgradeRequest({ method: "POST", headers: upgradeReq().headers }, {});
  check("validate: non-GET refused 405",
        m.ok === false && m.status === 405 && /GET/.test(m.reason));

  var u = ws.validateUpgradeRequest(upgradeReq({ upgrade: "h2c" }), {});
  check("validate: missing Upgrade: websocket refused 400",
        u.ok === false && u.status === 400 && /Upgrade/.test(u.reason));

  var c = ws.validateUpgradeRequest(upgradeReq({ connection: "keep-alive" }), {});
  check("validate: missing Connection: upgrade refused 400",
        c.ok === false && /Connection/.test(c.reason));

  // Multi-token Connection header ("keep-alive, Upgrade") still matches.
  check("validate: multi-token Connection: keep-alive, Upgrade accepted",
        ws.validateUpgradeRequest(upgradeReq({ connection: "keep-alive, Upgrade" }), {}).ok === true);

  var noKey = upgradeReq();
  delete noKey.headers["sec-websocket-key"];
  var k = ws.validateUpgradeRequest(noKey, {});
  check("validate: missing Sec-WebSocket-Key refused 400",
        k.ok === false && /Sec-WebSocket-Key/.test(k.reason));

  var badKey = ws.validateUpgradeRequest(upgradeReq({ "sec-websocket-key": "not-base64" }), {});
  check("validate: malformed Sec-WebSocket-Key refused 400",
        badKey.ok === false && /base64/.test(badKey.reason));

  var ver = ws.validateUpgradeRequest(upgradeReq({ "sec-websocket-version": "8" }), {});
  check("validate: wrong Sec-WebSocket-Version refused 400",
        ver.ok === false && /Version/.test(ver.reason));

  check("validate: missing headers object refused (no Upgrade)",
        ws.validateUpgradeRequest({ method: "GET" }, {}).ok === false);
}

function testValidateCredentialQueryRefusal() {
  var leak = ws.validateUpgradeRequest(upgradeReq({}, "/ws?access_token=abc"), {});
  check("validate: credential query param refused 400",
        leak.ok === false && /access_token/.test(leak.reason));

  // URL-encoded param name still decodes + matches.
  var enc = ws.validateUpgradeRequest(upgradeReq({}, "/ws?%61pi_key=abc"), {});
  check("validate: URL-encoded credential param name still refused",
        enc.ok === false && /api_key/.test(enc.reason));

  // Malformed percent-encoding in an earlier param hits the decode
  // catch, then a later credential param still matches.
  var mal = ws.validateUpgradeRequest(upgradeReq({}, "/ws?%=1&apikey=x"), {});
  check("validate: decode-error param falls through, later credential refused",
        mal.ok === false && /apikey/.test(mal.reason));

  // Fragment after the query is stripped before scanning.
  check("validate: non-credential query with fragment accepted",
        ws.validateUpgradeRequest(upgradeReq({}, "/ws?room=5#frag"), {}).ok === true);

  // Param without '=' and empty pairs are skipped, not matched.
  check("validate: bare + empty query pairs accepted",
        ws.validateUpgradeRequest(upgradeReq({}, "/ws?flag&&room=1"), {}).ok === true);

  // No query string at all.
  check("validate: no query string accepted",
        ws.validateUpgradeRequest(upgradeReq({}, "/ws"), {}).ok === true);

  // Opt-out lets the credential-shaped param through.
  check("validate: allowQueryAuthParams bypasses the refusal",
        ws.validateUpgradeRequest(upgradeReq({}, "/ws?access_token=abc"),
          { allowQueryAuthParams: true }).ok === true);
}

// ============================================================
//  negotiateSubprotocol + isOriginAllowed — pure branches
// ============================================================

function testNegotiateSubprotocol() {
  var req = { headers: { "sec-websocket-protocol": "chat.v2, chat.v1" } };
  check("negotiate: no supported list returns null",
        ws.negotiateSubprotocol(req, null) === null);
  check("negotiate: empty supported list returns null",
        ws.negotiateSubprotocol(req, []) === null);
  check("negotiate: picks first client-offered that is supported",
        ws.negotiateSubprotocol(req, ["chat.v1"]) === "chat.v1");
  check("negotiate: honours client preference order",
        ws.negotiateSubprotocol(req, ["chat.v1", "chat.v2"]) === "chat.v2");
  check("negotiate: no intersection returns null",
        ws.negotiateSubprotocol(req, ["chat.v9"]) === null);
  check("negotiate: absent header with supported list returns null",
        ws.negotiateSubprotocol({ headers: {} }, ["chat.v1"]) === null);
}

function testIsOriginAllowed() {
  var same = { headers: { origin: "https://app.example.com", host: "app.example.com" } };
  check("origin: '*' accept-all returns true",
        ws.isOriginAllowed(same, "*") === true);
  check("origin: default same-origin match returns true",
        ws.isOriginAllowed(same, undefined) === true);

  var cross = { headers: { origin: "https://evil.example.com", host: "app.example.com" } };
  check("origin: default same-origin mismatch returns false",
        ws.isOriginAllowed(cross, undefined) === false);

  check("origin: array allowlist match returns true",
        ws.isOriginAllowed(same, ["https://app.example.com"]) === true);
  check("origin: array allowlist miss returns false",
        ws.isOriginAllowed(same, ["https://other.example"]) === false);

  check("origin: no Origin header (non-browser) bypasses to true",
        ws.isOriginAllowed({ headers: { host: "app.example.com" } }, undefined) === true);

  check("origin: default with Origin but no Host returns false",
        ws.isOriginAllowed({ headers: { origin: "https://app.example.com" } }, undefined) === false);

  check("origin: malformed Origin URL returns false (parse catch)",
        ws.isOriginAllowed({ headers: { origin: "::::not a url", host: "app.example.com" } }, undefined) === false);

  // origins present but not "*", not array, not falsy (e.g. a bogus
  // string) falls through to the final `return false`.
  check("origin: unrecognized origins shape returns false",
        ws.isOriginAllowed(same, "https://app.example.com") === false);
}

// ============================================================
//  FrameParser — adversarial + extended-length frames
// ============================================================

function testFrameParserRoundTrip() {
  var fp = new ws.FrameParser();
  var frames = fp.push(clientFrame(ws.OPCODE_TEXT, "hello"));
  check("parser: one complete masked text frame",
        frames.length === 1 && frames[0].opcode === ws.OPCODE_TEXT);
  check("parser: unmasks the payload",
        frames[0].payload.toString("utf8") === "hello" && frames[0].masked === true);
  check("parser: fin bit decoded",
        frames[0].fin === true);

  // Unmasked (server-shape) frame — the copy-out branch.
  var fp2 = new ws.FrameParser();
  var f2 = fp2.push(ws.serializeFrame(ws.OPCODE_BINARY, Buffer.from([1, 2, 3])));
  check("parser: unmasked frame copied out",
        f2.length === 1 && f2[0].masked === false && f2[0].payload.length === 3);
}

function testFrameParserExtendedLengths() {
  // 126 => 16-bit extended length.
  var p16 = Buffer.alloc(200, 0x61);
  var fp16 = new ws.FrameParser();
  var f16 = fp16.push(clientFrame(ws.OPCODE_BINARY, p16));
  check("parser: 16-bit extended length frame",
        f16.length === 1 && f16[0].payload.length === 200);

  // 127 => 64-bit extended length.
  var p64 = Buffer.alloc(70000, 0x62);
  var fp64 = new ws.FrameParser();
  var f64 = fp64.push(clientFrame(ws.OPCODE_BINARY, p64));
  check("parser: 64-bit extended length frame",
        f64.length === 1 && f64[0].payload.length === 70000);
}

function testFrameParserIncremental() {
  // Masked "chunked": headerLen = 2 + 4 mask = 6, payload = 7, total 13.
  var full = clientFrame(ws.OPCODE_TEXT, "chunked");
  var fp = new ws.FrameParser();
  check("parser: single byte is incomplete (< 2 header bytes)",
        fp.push(full.subarray(0, 1)).length === 0);
  // 4 bytes: past the 2-byte minimum but short of the 6-byte masked
  // header (exercises the header-pending return).
  check("parser: partial header (2..5 bytes) is incomplete",
        fp.push(full.subarray(1, 4)).length === 0);
  // 8 bytes: full 6-byte header + 2 payload bytes — header complete but
  // the payload is not (the payload-pending return, distinct from above).
  check("parser: full header but partial payload is incomplete",
        fp.push(full.subarray(4, 8)).length === 0);
  var done = fp.push(full.subarray(8));
  check("parser: completes once all bytes arrive",
        done.length === 1 && done[0].payload.toString("utf8") === "chunked");
}

function testFrameParserFrameTooLarge() {
  var fp = new ws.FrameParser({ maxFrameBytes: 4 });
  var big = clientFrame(ws.OPCODE_BINARY, Buffer.alloc(100));
  var threw = null;
  try { fp.push(big); } catch (e) { threw = e; }
  check("parser: over-maxFrameBytes throws WebSocketError",
        threw && threw.isWebSocketError === true);
  check("parser: frame-too-large carries closeCode 1009",
        threw && threw.closeCode === ws.CLOSE_MESSAGE_TOO_BIG && threw.closeCode === 1009);
}

function testFrameParser64BitOverflow() {
  // Hand-craft a 127-length frame whose high 32 bits exceed 0x1FFFFF
  // (would overflow Number.MAX_SAFE_INTEGER). Masked so headerLen has
  // the 4 mask bytes present.
  var header = Buffer.alloc(2 + 8 + 4);
  header[0] = 0x82;               // fin + BINARY
  header[1] = 0x80 | 127;         // masked + 64-bit length indicator
  header.writeUInt32BE(0x00200000, 2);  // hi = 0x200000 > 0x1FFFFF
  header.writeUInt32BE(0x00000000, 6);  // lo
  // 4 mask bytes already zero-filled.
  var fp = new ws.FrameParser({ maxFrameBytes: 1000000 });
  var threw = null;
  try { fp.push(header); } catch (e) { threw = e; }
  check("parser: 64-bit length past MAX_SAFE_INTEGER throws",
        threw && threw.isWebSocketError === true && /MAX_SAFE_INTEGER/.test(threw.message));
}

// ============================================================
//  serializeFrame — masking, extended lengths, invalid payload
// ============================================================

function testSerializeFrame() {
  var basic = ws.serializeFrame(ws.OPCODE_TEXT, "hi");
  check("serialize: basic unmasked text frame header",
        basic[0] === 0x81 && (basic[1] & 0x80) === 0 && basic[1] === 2);

  // Round-trip a masked frame — mask bit set, payload recovered.
  var masked = ws.serializeFrame(ws.OPCODE_BINARY, Buffer.from([9, 8, 7]), { mask: true });
  check("serialize: mask bit set on masked frame",
        (masked[1] & 0x80) !== 0);
  var rt = new ws.FrameParser().push(masked);
  check("serialize: masked frame round-trips through the parser",
        rt.length === 1 && rt[0].payload.length === 3 && rt[0].payload[0] === 9);

  // fin:false + rsv1 header bits.
  var frag = ws.serializeFrame(ws.OPCODE_TEXT, "x", { fin: false, rsv1: true });
  check("serialize: fin:false clears the FIN bit",  (frag[0] & 0x80) === 0);
  check("serialize: rsv1:true sets the RSV1 bit",   (frag[0] & 0x40) !== 0);

  // 16-bit + 64-bit extended-length encodings round-trip.
  var r16 = new ws.FrameParser().push(ws.serializeFrame(ws.OPCODE_BINARY, Buffer.alloc(300)));
  check("serialize: 16-bit length round-trips", r16[0].payload.length === 300);
  var r64 = new ws.FrameParser().push(ws.serializeFrame(ws.OPCODE_BINARY, Buffer.alloc(70000)));
  check("serialize: 64-bit length round-trips", r64[0].payload.length === 70000);

  // Null payload => empty frame.
  var empty = ws.serializeFrame(ws.OPCODE_PING, null);
  check("serialize: null payload yields a zero-length frame", empty[1] === 0);

  // Non-buffer/non-string payload throws.
  var threw = null;
  try { ws.serializeFrame(ws.OPCODE_TEXT, 12345); } catch (e) { threw = e; }
  check("serialize: numeric payload throws WebSocketError",
        threw && threw.isWebSocketError === true && threw.code === "ws/invalid-payload");
}

// ============================================================
//  WebSocketConnection — send / ping / close surface
// ============================================================

function testConnectionSendVariants() {
  var socket = makeSocket();
  var conn = new ws.WebSocketConnection(socket, { closeGraceMs: 10 });
  try {
    check("conn: initial readyState is open", conn.readyState === "open");

    conn.send("a string");
    conn.send(Buffer.from([0xde, 0xad]));
    conn.send(new Uint8Array([1, 2, 3]));
    var frames = serverFrames(socket);
    check("conn: string send emits a TEXT frame",
          frames[0] && frames[0].opcode === ws.OPCODE_TEXT && frames[0].payload.toString() === "a string");
    check("conn: Buffer send emits a BINARY frame",
          frames[1] && frames[1].opcode === ws.OPCODE_BINARY);
    check("conn: Uint8Array send routes through toBuffer to BINARY",
          frames[2] && frames[2].opcode === ws.OPCODE_BINARY && frames[2].payload.length === 3);
  } finally { teardown(conn, socket); }
}

function testConnectionSendInvalidPayload() {
  var socket = makeSocket();
  var conn = new ws.WebSocketConnection(socket, { closeGraceMs: 10 });
  try {
    var threw = null;
    try { conn.send(12345); } catch (e) { threw = e; }
    check("conn: send(non-buffer/non-string) throws WebSocketError",
          threw && threw.isWebSocketError === true && threw.code === "ws/invalid-payload");
  } finally { teardown(conn, socket); }
}

function testConnectionSendRejectsWhenClosed() {
  var socket = makeSocket();
  var conn = new ws.WebSocketConnection(socket, { closeGraceMs: 10 });
  socket.emit("close");           // → transition to CLOSED
  check("conn: closed after socket close", conn.readyState === "closed");
  var threw = null;
  try { conn.send("late"); } catch (e) { threw = e; }
  check("conn: send() on a closed connection throws ws/closed",
        threw && threw.isWebSocketError === true && threw.code === "ws/closed");
}

function testConnectionPing() {
  var socket = makeSocket();
  var conn = new ws.WebSocketConnection(socket, { closeGraceMs: 10 });
  try {
    conn.ping(Buffer.from("pong-me"));
    var frames = serverFrames(socket);
    check("conn: ping() emits a PING frame with the payload",
          frames[0] && frames[0].opcode === ws.OPCODE_PING && frames[0].payload.toString() === "pong-me");
  } finally { teardown(conn, socket); }

  // ping() on a non-open connection is a silent no-op.
  var s2 = makeSocket();
  var c2 = new ws.WebSocketConnection(s2, { closeGraceMs: 10 });
  s2.emit("close");
  c2.ping(Buffer.from("ignored"));
  check("conn: ping() after close writes nothing", serverFrames(s2).length === 0);
}

function testConnectionClose() {
  var socket = makeSocket();
  var conn = new ws.WebSocketConnection(socket, { closeGraceMs: 10 });
  conn.close(1000, "bye");
  check("conn: close() moves to closing state", conn.readyState === "closing");
  var frames = serverFrames(socket);
  check("conn: close() writes a CLOSE frame with the code + reason",
        frames[0] && frames[0].opcode === ws.OPCODE_CLOSE &&
        frames[0].payload.readUInt16BE(0) === 1000 &&
        frames[0].payload.subarray(2).toString("utf8") === "bye");

  // A second close() while not OPEN is a no-op.
  var before = socket.written.length;
  conn.close(1001, "again");
  check("conn: second close() is a no-op", socket.written.length === before);
  teardown(conn, socket);
}

async function testConnectionCloseGraceTimerFires() {
  // When the peer never echoes the close frame, the grace timer fires,
  // half-closes the socket, and transitions with wasClean:false.
  await helpers.withTestTimeout("ws close: grace timer fires", async function () {
    var socket = makeSocket();
    var conn = new ws.WebSocketConnection(socket, { closeGraceMs: 10 });
    var closeArgs = null;
    conn.on("close", function (code, reason, wasClean) { closeArgs = { code: code, wasClean: wasClean }; });
    conn.close(1000, "bye");
    await helpers.waitUntil(function () { return conn.readyState === "closed"; },
      { label: "ws close: grace timer transitioned to closed" });
    check("conn: grace timer transitions closed with wasClean false (no peer echo)",
          closeArgs && closeArgs.code === 1000 && closeArgs.wasClean === false);
    check("conn: grace timer half-closes the socket", socket.ended === true);
  }, { timeoutMs: 3000 });
}

function testConnectionCloseDefaultsCode() {
  var socket = makeSocket();
  var conn = new ws.WebSocketConnection(socket, { closeGraceMs: 10 });
  conn.close();
  var frames = serverFrames(socket);
  check("conn: close() with no code defaults to 1000",
        frames[0] && frames[0].payload.readUInt16BE(0) === 1000);
  teardown(conn, socket);
}

// ============================================================
//  WebSocketConnection — inbound frame handling
// ============================================================

function testConnectionReceiveMessages() {
  var socket = makeSocket();
  var conn = new ws.WebSocketConnection(socket, { closeGraceMs: 10 });
  try {
    var got = [];
    conn.on("message", function (data, isBinary) { got.push({ data: data, isBinary: isBinary }); });
    socket.emit("data", clientFrame(ws.OPCODE_TEXT, "hello text"));
    socket.emit("data", clientFrame(ws.OPCODE_BINARY, Buffer.from([1, 2, 3, 4])));
    check("conn: TEXT frame emits a string message (isBinary false)",
          got[0] && got[0].data === "hello text" && got[0].isBinary === false);
    check("conn: BINARY frame emits a Buffer message (isBinary true)",
          got[1] && Buffer.isBuffer(got[1].data) && got[1].isBinary === true);
  } finally { teardown(conn, socket); }
}

function testConnectionFragmentedMessage() {
  var socket = makeSocket();
  var conn = new ws.WebSocketConnection(socket, { closeGraceMs: 10 });
  try {
    var got = null;
    conn.on("message", function (data) { got = data; });
    socket.emit("data", clientFrame(ws.OPCODE_TEXT, "Hel", { fin: false }));
    socket.emit("data", clientFrame(ws.OPCODE_CONTINUATION, "lo ", { fin: false }));
    socket.emit("data", clientFrame(ws.OPCODE_CONTINUATION, "world"));
    check("conn: fragmented TEXT reassembles across continuation frames",
          got === "Hello world");
  } finally { teardown(conn, socket); }
}

function testConnectionPingPong() {
  var socket = makeSocket();
  var conn = new ws.WebSocketConnection(socket, { closeGraceMs: 10 });
  try {
    var pingSeen = null, pongSeen = null;
    conn.on("ping", function (p) { pingSeen = p; });
    conn.on("pong", function (p) { pongSeen = p; });
    socket.emit("data", clientFrame(ws.OPCODE_PING, Buffer.from("hb")));
    check("conn: inbound PING emits 'ping'", pingSeen && pingSeen.toString() === "hb");
    var frames = serverFrames(socket);
    check("conn: inbound PING is auto-answered with a PONG echo",
          frames.some(function (f) { return f.opcode === ws.OPCODE_PONG && f.payload.toString() === "hb"; }));
    socket.emit("data", clientFrame(ws.OPCODE_PONG, Buffer.from("ok")));
    check("conn: inbound PONG emits 'pong'", pongSeen && pongSeen.toString() === "ok");
  } finally { teardown(conn, socket); }
}

// Every protocol-violation abort: assert the connection closes and (when
// a close frame is sent) carries the RFC 6455 close code.
function _abortCase(label, opts, frames, expectCode) {
  var socket = makeSocket();
  var conn = new ws.WebSocketConnection(socket, Object.assign({ closeGraceMs: 10 }, opts || {}));
  var closeCode = null;
  conn.on("close", function (code) { closeCode = code; });
  for (var i = 0; i < frames.length; i++) socket.emit("data", frames[i]);
  check(label + ": connection closed", conn.readyState === "closed");
  if (expectCode != null) {
    var sent = serverFrames(socket).filter(function (f) { return f.opcode === ws.OPCODE_CLOSE; });
    check(label + ": abort close-code " + expectCode,
          (sent[0] && sent[0].payload.readUInt16BE(0) === expectCode) || closeCode === expectCode);
  }
  teardown(conn, socket);
}

function testConnectionAbortBranches() {
  // Unmasked client frame on h1 transport.
  _abortCase("abort: unmasked h1 frame", {},
    [ws.serializeFrame(ws.OPCODE_TEXT, "x")], ws.CLOSE_PROTOCOL_ERROR);

  // Masked frame on h2 transport.
  _abortCase("abort: masked h2 frame", { transport: "h2" },
    [clientFrame(ws.OPCODE_TEXT, "x")], ws.CLOSE_PROTOCOL_ERROR);

  // RSV2/RSV3 set without an extension (0x20 is the RSV2 flag bit).
  _abortCase("abort: reserved rsv2 bit", {},
    [withByte0Bit(clientFrame(ws.OPCODE_TEXT, "x"), 0x20)], ws.CLOSE_PROTOCOL_ERROR);

  // RSV1 without permessage-deflate negotiated.
  _abortCase("abort: rsv1 without deflate", {},
    [clientFrame(ws.OPCODE_TEXT, "x", { rsv1: true })], ws.CLOSE_PROTOCOL_ERROR);

  // RSV1 on a continuation frame (deflate negotiated, but RSV1 belongs
  // on the START frame only).
  _abortCase("abort: rsv1 on continuation", { permessageDeflate: { serverMaxWindowBits: 15, clientMaxWindowBits: 15 } },
    [clientFrame(ws.OPCODE_CONTINUATION, "x", { rsv1: true })], ws.CLOSE_PROTOCOL_ERROR);

  // Control frame > 125 bytes.
  _abortCase("abort: oversized control frame", {},
    [clientFrame(ws.OPCODE_PING, Buffer.alloc(126))], ws.CLOSE_PROTOCOL_ERROR);

  // Fragmented control frame.
  _abortCase("abort: fragmented control frame", {},
    [clientFrame(ws.OPCODE_PING, Buffer.from("x"), { fin: false })], ws.CLOSE_PROTOCOL_ERROR);

  // Continuation without a start frame.
  _abortCase("abort: continuation without start", {},
    [clientFrame(ws.OPCODE_CONTINUATION, "x")], ws.CLOSE_PROTOCOL_ERROR);

  // New data frame during an open fragmentation sequence.
  _abortCase("abort: new message during fragmentation", {},
    [clientFrame(ws.OPCODE_TEXT, "a", { fin: false }), clientFrame(ws.OPCODE_TEXT, "b")],
    ws.CLOSE_PROTOCOL_ERROR);

  // Reserved (non-control) opcode 0x3.
  _abortCase("abort: unknown opcode 0x3", {},
    [clientFrame(0x3, "x")], ws.CLOSE_PROTOCOL_ERROR);

  // Invalid UTF-8 in a TEXT frame.
  _abortCase("abort: invalid utf-8 text", {},
    [clientFrame(ws.OPCODE_TEXT, Buffer.from([0xff, 0xfe]))], ws.CLOSE_INVALID_PAYLOAD);

  // Reassembled fragmented message exceeds maxMessageBytes.
  _abortCase("abort: fragment exceeds maxMessageBytes", { maxMessageBytes: 4 },
    [clientFrame(ws.OPCODE_TEXT, "abc", { fin: false }), clientFrame(ws.OPCODE_CONTINUATION, "def")],
    ws.CLOSE_MESSAGE_TOO_BIG);

  // Frame declared larger than maxFrameBytes — parser throws, _onData
  // catches and aborts with the parser's close code.
  _abortCase("abort: frame past maxFrameBytes", { maxMessageBytes: 4 },
    [clientFrame(ws.OPCODE_BINARY, Buffer.alloc(100))], ws.CLOSE_MESSAGE_TOO_BIG);
}

function testConnectionCloseHandshake() {
  // Peer-initiated clean close with a valid code + reason.
  var socket = makeSocket();
  var conn = new ws.WebSocketConnection(socket, { closeGraceMs: 10 });
  var closeArgs = null;
  conn.on("close", function (code, reason, wasClean) { closeArgs = { code: code, reason: reason, wasClean: wasClean }; });
  socket.emit("data", clientFrame(ws.OPCODE_CLOSE, closePayload(1000, "done")));
  check("conn: peer close transitions to closed", conn.readyState === "closed");
  check("conn: peer close surfaces code+reason, wasClean true",
        closeArgs && closeArgs.code === 1000 && closeArgs.reason === "done" && closeArgs.wasClean === true);
  var echoed = serverFrames(socket).filter(function (f) { return f.opcode === ws.OPCODE_CLOSE; });
  check("conn: peer close is echoed back (§5.5.1)",
        echoed.length === 1 && echoed[0].payload.readUInt16BE(0) === 1000);
  check("conn: underlying socket ended on clean close", socket.ended === true);

  // Empty-body close => defaults to 1000.
  var s2 = makeSocket();
  var c2 = new ws.WebSocketConnection(s2, { closeGraceMs: 10 });
  var code2 = null;
  c2.on("close", function (code) { code2 = code; });
  s2.emit("data", clientFrame(ws.OPCODE_CLOSE, Buffer.alloc(0)));
  check("conn: empty-body close defaults to code 1000", code2 === 1000);

  // Private-use close code (3000) is valid.
  var s3 = makeSocket();
  var c3 = new ws.WebSocketConnection(s3, { closeGraceMs: 10 });
  var code3 = null;
  c3.on("close", function (code) { code3 = code; });
  s3.emit("data", clientFrame(ws.OPCODE_CLOSE, closePayload(3000, "app")));
  check("conn: private-use close code 3000 accepted", code3 === 3000 && c3.readyState === "closed");
}

function testConnectionCloseFrameViolations() {
  // 1-byte close body is malformed.
  _abortCase("close-violation: 1-byte body", {},
    [clientFrame(ws.OPCODE_CLOSE, Buffer.from([0x03]))], ws.CLOSE_PROTOCOL_ERROR);

  // Reserved close code 1005 (local-only sentinel) refused on the wire.
  _abortCase("close-violation: reserved code 1005", {},
    [clientFrame(ws.OPCODE_CLOSE, closePayload(1005, ""))], ws.CLOSE_PROTOCOL_ERROR);

  // Out-of-range close code 2000 (between 1011 and 3000).
  _abortCase("close-violation: invalid code 2000", {},
    [clientFrame(ws.OPCODE_CLOSE, closePayload(2000, ""))], ws.CLOSE_PROTOCOL_ERROR);

  // Below-range close code 999.
  _abortCase("close-violation: below-range code 999", {},
    [clientFrame(ws.OPCODE_CLOSE, closePayload(999, ""))], ws.CLOSE_PROTOCOL_ERROR);

  // Valid code but invalid UTF-8 in the reason.
  _abortCase("close-violation: invalid utf-8 reason", {},
    [clientFrame(ws.OPCODE_CLOSE, closePayload(1000, Buffer.from([0xff, 0xfe])))],
    ws.CLOSE_INVALID_PAYLOAD);
}

// ============================================================
//  WebSocketConnection — socket lifecycle transitions
// ============================================================

function testConnectionSocketErrorTransition() {
  var socket = makeSocket();
  var conn = new ws.WebSocketConnection(socket, { closeGraceMs: 10 });
  var errSeen = null, closeArgs = null;
  conn.on("error", function (e) { errSeen = e; });
  conn.on("close", function (code, reason, wasClean) { closeArgs = { code: code, wasClean: wasClean }; });
  socket.emit("error", new Error("boom"));
  check("conn: socket error surfaces via 'error'", errSeen && errSeen.message === "boom");
  check("conn: socket error transitions to closed 1006 wasClean false",
        conn.readyState === "closed" && closeArgs.code === 1006 && closeArgs.wasClean === false);
  check("conn: lastError captured", conn.lastError && conn.lastError.message === "boom");
}

function testConnectionSocketEndTransition() {
  var socket = makeSocket();
  var conn = new ws.WebSocketConnection(socket, { closeGraceMs: 10 });
  var closeArgs = null;
  conn.on("close", function (code, reason, wasClean) { closeArgs = { code: code, wasClean: wasClean }; });
  socket.emit("end");
  check("conn: socket end transitions to closed 1006",
        conn.readyState === "closed" && closeArgs.code === 1006 && closeArgs.wasClean === false);
  check("conn: socket end half-closes our writable side", socket.ended === true);
}

function testConnectionSendAfterSocketUnwritable() {
  // Socket destroyed under us — send() detects the unwritable socket and
  // routes through the abnormal-closure path instead of writing.
  var socket = makeSocket();
  var conn = new ws.WebSocketConnection(socket, { closeGraceMs: 10 });
  var closeCode = null;
  conn.on("close", function (code) { closeCode = code; });
  socket.destroyed = true;
  conn.send("x");
  check("conn: send() to a destroyed socket transitions closed 1006",
        conn.readyState === "closed" && closeCode === 1006);
  check("conn: nothing framed to a destroyed socket", serverFrames(socket).length === 0);
}

function testConnectionSendWriteThrows() {
  var socket = makeSocket({ writeThrows: true });
  var conn = new ws.WebSocketConnection(socket, { closeGraceMs: 10 });
  var closeArgs = null;
  conn.on("close", function (code, reason, wasClean) { closeArgs = { code: code, wasClean: wasClean }; });
  conn.send("x");
  check("conn: socket.write throwing transitions closed 1006 wasClean false",
        conn.readyState === "closed" && closeArgs.code === 1006 && closeArgs.wasClean === false);
}

// ============================================================
//  WebSocketConnection — permessage-deflate send/receive
// ============================================================

function testConnectionDeflateSend() {
  var socket = makeSocket();
  var conn = new ws.WebSocketConnection(socket, {
    closeGraceMs: 10,
    permessageDeflate: { serverMaxWindowBits: 15, clientMaxWindowBits: 15 },
  });
  try {
    conn.send("compress me ".repeat(40));
    var frames = serverFrames(socket);
    check("conn: deflate send marks the frame RSV1 (compressed)",
          frames[0] && frames[0].rsv1 === true && frames[0].opcode === ws.OPCODE_TEXT);
    check("conn: deflate send actually shrinks a repetitive payload",
          frames[0].payload.length < ("compress me ".repeat(40)).length);
  } finally { teardown(conn, socket); }
}

function testConnectionDeflateReceive() {
  var socket = makeSocket();
  var conn = new ws.WebSocketConnection(socket, {
    closeGraceMs: 10,
    permessageDeflate: { serverMaxWindowBits: 15, clientMaxWindowBits: 15 },
  });
  try {
    var got = null;
    conn.on("message", function (data) { got = data; });
    var original = "inflate me ".repeat(30);
    var raw = zlib.deflateRawSync(Buffer.from(original, "utf8"));
    // Strip the RFC 7692 §7.2.1 trailing 0x00 0x00 0xff 0xff.
    if (raw.length >= 4 && raw[raw.length - 4] === 0x00 && raw[raw.length - 3] === 0x00 &&
        raw[raw.length - 2] === 0xff && raw[raw.length - 1] === 0xff) {
      raw = raw.subarray(0, raw.length - 4);
    }
    socket.emit("data", clientFrame(ws.OPCODE_TEXT, raw, { rsv1: true }));
    check("conn: compressed inbound frame inflates to the original text", got === original);
  } finally { teardown(conn, socket); }
}

function testConnectionDeflateReceiveGarbage() {
  // RSV1-flagged frame whose body is not valid deflate → inflate fails →
  // abort CLOSE_INVALID_PAYLOAD.
  _abortCase("deflate: undecodable compressed frame",
    { permessageDeflate: { serverMaxWindowBits: 15, clientMaxWindowBits: 15 } },
    [clientFrame(ws.OPCODE_TEXT, Buffer.from([0xff, 0xff, 0xff, 0xff]), { rsv1: true })],
    ws.CLOSE_INVALID_PAYLOAD);
}

function testConnectionDeflateSendFailureFallsThrough() {
  // A bad windowBits makes deflateRawSync throw; _sendDataFrame's catch
  // falls through to an uncompressed send so the connection keeps working.
  var socket = makeSocket();
  var conn = new ws.WebSocketConnection(socket, {
    closeGraceMs: 10,
    permessageDeflate: { serverMaxWindowBits: 3, clientMaxWindowBits: 15 },   // 3 is out of deflate's 9..15 range
  });
  try {
    conn.send("payload");
    var frames = serverFrames(socket);
    check("conn: deflate failure sends the frame uncompressed (no RSV1)",
          frames[0] && frames[0].rsv1 === false && frames[0].payload.toString() === "payload");
  } finally { teardown(conn, socket); }
}

// ============================================================
//  WebSocketConnection — heartbeat (real timers)
// ============================================================

async function testHeartbeat() {
  // Healthy heartbeat: within the pong window, the timer emits a PING.
  await helpers.withTestTimeout("ws heartbeat: healthy ping", async function () {
    var socket = makeSocket();
    var conn = new ws.WebSocketConnection(socket, {
      closeGraceMs: 10, pingIntervalMs: 20, pongTimeoutMs: 5000,
    });
    try {
      await helpers.waitUntil(function () {
        return serverFrames(socket).some(function (f) { return f.opcode === ws.OPCODE_PING; });
      }, { label: "ws heartbeat: PING emitted by the interval timer" });
      check("conn: heartbeat emits a PING within the interval", true);
    } finally { teardown(conn, socket); }
  }, { timeoutMs: 3000 });

  // Unresponsive peer: no pong before pongTimeoutMs → abort 1011.
  await helpers.withTestTimeout("ws heartbeat: pong timeout", async function () {
    var socket = makeSocket();
    var conn = new ws.WebSocketConnection(socket, {
      closeGraceMs: 10, pingIntervalMs: 20, pongTimeoutMs: 1,
    });
    var closeCode = null;
    conn.on("close", function (code) { closeCode = code; });
    await helpers.waitUntil(function () {
      return conn.readyState === "closed";
    }, { label: "ws heartbeat: abort on pong timeout" });
    check("conn: pong timeout aborts with CLOSE_INTERNAL_ERROR (1011)",
          closeCode === ws.CLOSE_INTERNAL_ERROR && closeCode === 1011);
    teardown(conn, socket);
  }, { timeoutMs: 3000 });
}

// ============================================================
//  handleUpgrade — h1 entry point
// ============================================================

function testHandleUpgradeGuidThrows() {
  var socket = makeSocket();
  var threw = null;
  try { ws.handleUpgrade(upgradeReq(), socket, null, { handshakeGuid: "not-a-uuid" }); }
  catch (e) { threw = e; }
  check("handleUpgrade: malformed handshakeGuid throws at config time",
        threw && /UUID-shaped/.test(threw.message));

  var t2 = null;
  try { ws.handleUpgrade(upgradeReq(), socket, null, { handshakeGuid: 123 }); }
  catch (e) { t2 = e; }
  check("handleUpgrade: non-string handshakeGuid throws", t2 !== null);

  var t3 = null;
  try { ws.handleUpgrade(upgradeReq(), socket, null, { handshakeGuid: "x".repeat(65) }); }
  catch (e) { t3 = e; }
  check("handleUpgrade: over-long handshakeGuid throws", t3 !== null);

  // A valid UUID-shaped override is accepted and used.
  var s2 = makeSocket();
  var conn = ws.handleUpgrade(upgradeReq(), s2, null, { handshakeGuid: "12345678-1234-1234-1234-1234567890ab" });
  check("handleUpgrade: valid custom GUID completes the upgrade", conn !== null);
  check("handleUpgrade: custom-GUID Accept matches computeAcceptKey",
        String(s2.written[0]).indexOf("Sec-WebSocket-Accept: " +
          ws.computeAcceptKey(RFC_KEY, "12345678-1234-1234-1234-1234567890ab")) !== -1);
  teardown(conn, s2);
}

function testHandleUpgradeRefusals() {
  // Bad handshake → 405, socket destroyed, returns null.
  var s1 = makeSocket();
  var r1 = ws.handleUpgrade({ method: "POST", url: "/ws", headers: upgradeReq().headers }, s1, null, {});
  check("handleUpgrade: bad method returns null", r1 === null);
  check("handleUpgrade: bad method writes 405 + destroys socket",
        /HTTP\/1\.1 405 Method Not Allowed/.test(String(s1.written[0])) && s1.destroyed === true);

  // Origin mismatch → 403.
  var s2 = makeSocket();
  var r2 = ws.handleUpgrade(upgradeReq({ origin: "https://evil.example.com" }), s2, null, {});
  check("handleUpgrade: origin mismatch returns null", r2 === null);
  check("handleUpgrade: origin mismatch writes 403 Forbidden",
        /HTTP\/1\.1 403 Forbidden/.test(String(s2.written[0])));
}

function testHandleUpgradeSuccess() {
  var socket = makeSocket();
  var conn = ws.handleUpgrade(upgradeReq(), socket, null, {});
  check("handleUpgrade: success returns a WebSocketConnection",
        conn instanceof ws.WebSocketConnection);
  var resp = String(socket.written[0]);
  check("handleUpgrade: success writes the 101 response",
        resp.indexOf("HTTP/1.1 101 Switching Protocols") === 0 &&
        resp.indexOf("Sec-WebSocket-Accept: " + RFC_ACCEPT) !== -1);
  check("handleUpgrade: open readyState after success", conn.readyState === "open");
  teardown(conn, socket);
}

function testHandleUpgradeSubprotocolAndDeflate() {
  var socket = makeSocket();
  var conn = ws.handleUpgrade(upgradeReq({
    "sec-websocket-protocol":   "chat.v2, chat.v1",
    "sec-websocket-extensions": "permessage-deflate; server_max_window_bits=10; client_max_window_bits=12",
  }), socket, null, { subprotocols: ["chat.v1"] });
  var resp = String(socket.written[0]);
  check("handleUpgrade: negotiates the supported subprotocol",
        conn.subprotocol === "chat.v1" && /Sec-WebSocket-Protocol: chat\.v1/.test(resp));
  check("handleUpgrade: echoes a permessage-deflate extension header",
        /Sec-WebSocket-Extensions: permessage-deflate;/.test(resp));
  check("handleUpgrade: window-bits echoed in the extension response",
        /server_max_window_bits=10/.test(resp) && /client_max_window_bits=12/.test(resp));
  check("handleUpgrade: connection carries negotiated deflate state",
        conn._permessageDeflate && conn._permessageDeflate.negotiated === true);
  teardown(conn, socket);
}

function testHandleUpgradeDeflateDisabledAndUnknownParam() {
  // Operator opts out of permessage-deflate even though the client offers it.
  var s1 = makeSocket();
  var c1 = ws.handleUpgrade(upgradeReq({ "sec-websocket-extensions": "permessage-deflate" }),
    s1, null, { permessageDeflate: false });
  check("handleUpgrade: permessageDeflate:false skips the extension",
        String(s1.written[0]).indexOf("Sec-WebSocket-Extensions") === -1 && c1._permessageDeflate === null);
  teardown(c1, s1);

  // An unknown extension parameter makes negotiation decline.
  var s2 = makeSocket();
  var c2 = ws.handleUpgrade(upgradeReq({ "sec-websocket-extensions": "permessage-deflate; bogus_param=1" }),
    s2, null, {});
  check("handleUpgrade: unknown deflate param declines negotiation",
        String(s2.written[0]).indexOf("Sec-WebSocket-Extensions") === -1 && c2._permessageDeflate === null);
  teardown(c2, s2);
}

function testHandleUpgradeHeadPrefeed() {
  // Bytes buffered between headers and the upgrade handler are pre-fed
  // into the parser. Use a PING so the connection's auto-PONG lands in
  // socket.written and proves the head was processed.
  var socket = makeSocket();
  var head = clientFrame(ws.OPCODE_PING, Buffer.from("early"));
  var conn = ws.handleUpgrade(upgradeReq(), socket, head, {});
  var frames = serverFrames(socket);
  check("handleUpgrade: head buffer is pre-fed (auto-PONG emitted)",
        frames.some(function (f) { return f.opcode === ws.OPCODE_PONG && f.payload.toString() === "early"; }));
  teardown(conn, socket);
}

function testHandleUpgradeWriteThrows() {
  var socket = makeSocket({ writeThrows: true });
  var conn = ws.handleUpgrade(upgradeReq(), socket, null, {});
  check("handleUpgrade: 101 write failure returns null + destroys socket",
        conn === null && socket.destroyed === true);
}

// ============================================================
//  handleExtendedConnect — h2 entry point (RFC 8441)
// ============================================================

function h2Headers(extra) {
  return Object.assign({
    ":method":   "CONNECT",
    ":protocol": "websocket",
  }, extra || {});
}

function testHandleExtendedConnectRefusals() {
  // Not a CONNECT.
  var s1 = makeH2Stream();
  var r1 = ws.handleExtendedConnect(s1, h2Headers({ ":method": "GET" }), {});
  check("h2: non-CONNECT method refused 400 + null",
        r1 === null && s1.responded && s1.responded[":status"] === 400);

  // CONNECT but wrong :protocol.
  var s2 = makeH2Stream();
  var r2 = ws.handleExtendedConnect(s2, h2Headers({ ":protocol": "ftp" }), {});
  check("h2: wrong :protocol refused 400 + null",
        r2 === null && s2.responded && s2.responded[":status"] === 400);

  // Origin refusal (Origin present, no Host → default same-origin fails).
  var s3 = makeH2Stream();
  var r3 = ws.handleExtendedConnect(s3, h2Headers({ origin: "https://evil.example.com" }), {});
  check("h2: origin refusal returns 403 + null",
        r3 === null && s3.responded && s3.responded[":status"] === 403);
}

function testHandleExtendedConnectSuccess() {
  var stream = makeH2Stream();
  var conn = ws.handleExtendedConnect(stream, h2Headers({ "sec-websocket-protocol": "chat.v1" }),
    { subprotocols: ["chat.v1"] });
  check("h2: success returns a WebSocketConnection", conn instanceof ws.WebSocketConnection);
  check("h2: responds :status 200 (not 101)", stream.responded && stream.responded[":status"] === 200);
  check("h2: negotiated subprotocol echoed in response headers",
        stream.responded["sec-websocket-protocol"] === "chat.v1" && conn.subprotocol === "chat.v1");
  check("h2: connection uses h2 transport", conn.transport === "h2");

  // h2 frames MUST NOT be masked — an unmasked inbound frame is accepted.
  var got = null;
  conn.on("message", function (data) { got = data; });
  stream.emit("data", ws.serializeFrame(ws.OPCODE_TEXT, "over h2"));
  check("h2: unmasked inbound frame delivered as a message", got === "over h2");
  teardown(conn, stream);
}

function testHandleExtendedConnectRespondThrows() {
  var stream = makeH2Stream({ respondThrows: true });
  var conn = ws.handleExtendedConnect(stream, h2Headers(), {});
  check("h2: respond() failure returns null + closes stream",
        conn === null && stream.closed === true);
}

function testHandleExtendedConnectRefusalRespondThrows() {
  // A refusal whose stream.respond() throws hits _refuseH2Connect's
  // catch, which falls back to stream.close().
  var stream = makeH2Stream({ respondThrows: true });
  var conn = ws.handleExtendedConnect(stream, h2Headers({ ":method": "GET" }), {});
  check("h2: refusal respond() failure falls back to stream.close()",
        conn === null && stream.closed === true);
}

// ============================================================
//  Defensive / fallback branch coverage
// ============================================================

function testValidateHeaderFallbacks() {
  // Connection header entirely absent (upgrade present) — the `|| ""`
  // fallback in the token test.
  var noConn = upgradeReq();
  delete noConn.headers.connection;
  check("validate: absent Connection header refused",
        ws.validateUpgradeRequest(noConn, {}).ok === false);

  // A valid handshake with a non-string url reaches the credential
  // scan with a non-string reqUrl (returns null → accepted).
  var noUrl = upgradeReq();
  delete noUrl.url;
  check("validate: valid handshake with no url accepted",
        ws.validateUpgradeRequest(noUrl, {}).ok === true);

  // Trailing '?' yields an empty query string.
  check("validate: empty query string ('/ws?') accepted",
        ws.validateUpgradeRequest(upgradeReq({}, "/ws?"), {}).ok === true);
}

function testPureHelpersMissingHeaders() {
  // negotiateSubprotocol with req.headers undefined → `|| {}` fallback.
  check("negotiate: undefined req.headers returns null",
        ws.negotiateSubprotocol({}, ["chat.v1"]) === null);
  // isOriginAllowed with req.headers undefined → `|| {}` fallback, no
  // Origin → non-browser bypass.
  check("origin: undefined req.headers bypasses to true",
        ws.isOriginAllowed({}, undefined) === true);
}

function testParseExtensionHeaderEdges() {
  var out = ws._parseExtensionHeader(
    "permessage-deflate; server_no_context_takeover; =bad; __proto__=evil; token=\"q\", , foo");
  check("ext-edge: empty-name entry skipped, two extensions parsed",
        Array.isArray(out) && out.length === 2 && out[1].name === "foo");
  var p = out[0].params;
  check("ext-edge: valueless param materializes as boolean true",
        p.server_no_context_takeover === true);
  check("ext-edge: empty parameter key ('=bad') dropped",
        !Object.prototype.hasOwnProperty.call(p, ""));
  check("ext-edge: poisoned parameter key ('__proto__') dropped",
        !Object.prototype.hasOwnProperty.call(p, "__proto__"));
  check("ext-edge: quoted parameter value is unquoted",
        p.token === "q");
}

function testHandleUpgradeDeflateDefaultsAndNameSkip() {
  // A non-deflate extension precedes deflate (name-mismatch skip), and
  // deflate is offered with no window-bits (both default to 15).
  var s1 = makeSocket();
  var c1 = ws.handleUpgrade(upgradeReq({ "sec-websocket-extensions": "foo; x=1, permessage-deflate" }),
    s1, null, {});
  check("handleUpgrade: deflate negotiated after skipping a foreign extension",
        c1._permessageDeflate && c1._permessageDeflate.negotiated === true);
  check("handleUpgrade: no window-bits => both default to 15",
        c1._permessageDeflate.serverMaxWindowBits === 15 && c1._permessageDeflate.clientMaxWindowBits === 15);
  check("handleUpgrade: bare deflate response omits window-bits echo",
        String(s1.written[0]).indexOf("max_window_bits") === -1);
  teardown(c1, s1);

  // Non-numeric window bits parse-fail into the 15 default.
  var s2 = makeSocket();
  var c2 = ws.handleUpgrade(upgradeReq({ "sec-websocket-extensions": "permessage-deflate; client_max_window_bits=abc" }),
    s2, null, {});
  check("handleUpgrade: non-numeric window-bits defaults to 15",
        c2._permessageDeflate.clientMaxWindowBits === 15);
  teardown(c2, s2);

  // Valueless window-bits params (offered with no '=value') are the
  // `=== true` case: the extension is honoured but no bits are echoed
  // and both windows default to 15.
  var s3 = makeSocket();
  var c3 = ws.handleUpgrade(upgradeReq({
    "sec-websocket-extensions": "permessage-deflate; server_max_window_bits; client_max_window_bits",
  }), s3, null, {});
  check("handleUpgrade: valueless window-bits honoured, defaults to 15",
        c3._permessageDeflate.serverMaxWindowBits === 15 && c3._permessageDeflate.clientMaxWindowBits === 15);
  check("handleUpgrade: valueless window-bits not echoed in the response",
        String(s3.written[0]).indexOf("max_window_bits=") === -1);
  teardown(c3, s3);
}

function testEntryPointsNoOpts() {
  // handleUpgrade / handleExtendedConnect with the opts argument omitted
  // exercise the `opts || {}` default.
  var s1 = makeSocket();
  var c1 = ws.handleUpgrade(upgradeReq(), s1);
  check("handleUpgrade: omitted opts uses defaults",
        c1 instanceof ws.WebSocketConnection);
  teardown(c1, s1);

  var s2 = makeH2Stream();
  var c2 = ws.handleExtendedConnect(s2, h2Headers());
  check("h2: omitted opts uses defaults",
        c2 instanceof ws.WebSocketConnection && c2.transport === "h2");
  teardown(c2, s2);
}

function testConnectionConstructorNoOpts() {
  var socket = makeSocket();
  var conn = new ws.WebSocketConnection(socket);   // opts omitted → `opts || {}`
  check("conn: constructs with no opts (defaults applied)",
        conn.readyState === "open" && conn.transport === "h1" && conn.subprotocol === null);
  teardown(conn, socket);
}

function testConnectionErrorFallbackAndNoListener() {
  // Error object without a message → the "socket error" reason fallback.
  var s1 = makeSocket();
  var c1 = new ws.WebSocketConnection(s1, { closeGraceMs: 10 });
  var seen1 = null, closeCode1 = null;
  c1.on("error", function (e) { seen1 = e; });
  c1.on("close", function (code) { closeCode1 = code; });
  s1.emit("error", {});          // truthy err, no .message
  check("conn: messageless socket error still transitions closed 1006",
        c1.readyState === "closed" && closeCode1 === 1006 && seen1 !== null);

  // Error present but NO 'error' listener → the emit is gated (no throw).
  var s2 = makeSocket();
  var c2 = new ws.WebSocketConnection(s2, { closeGraceMs: 10 });
  var closeCode2 = null;
  c2.on("close", function (code) { closeCode2 = code; });
  s2.emit("error", new Error("unheard"));
  check("conn: socket error with no 'error' listener closes without throwing",
        c2.readyState === "closed" && closeCode2 === 1006 && c2.lastError.message === "unheard");
}

function testConnectionIdempotentTransitions() {
  // Second transition after CLOSED is a no-op (the error handler calls
  // _transitionToClosed directly, unguarded).
  var s1 = makeSocket();
  var c1 = new ws.WebSocketConnection(s1, { closeGraceMs: 10 });
  var closeCount = 0, firstCode = null;
  c1.on("error", function () { /* absorb */ });
  c1.on("close", function (code) { closeCount += 1; if (firstCode === null) firstCode = code; });
  s1.emit("close");                        // first transition (1006)
  s1.emit("error", new Error("after"));    // second transition — early return
  check("conn: 'close' emitted exactly once across repeat transitions",
        closeCount === 1 && firstCode === 1006);

  // _abort after CLOSED early-returns: feed a protocol-violating frame
  // after the connection is already closed.
  var s2 = makeSocket();
  var c2 = new ws.WebSocketConnection(s2, { closeGraceMs: 10 });
  var closeCount2 = 0;
  c2.on("close", function () { closeCount2 += 1; });
  s2.emit("close");
  s2.emit("data", ws.serializeFrame(ws.OPCODE_TEXT, "x"));   // unmasked → would abort, but already closed
  check("conn: abort after close is a no-op (single close event)",
        c2.readyState === "closed" && closeCount2 === 1);
}

async function run() {
  // Handshake helpers
  testWebSocketError();
  testBuildUpgradeResponse();
  testComputeAcceptKeyCustomGuid();
  testValidateUpgradeRequest();
  testValidateCredentialQueryRefusal();
  testValidateHeaderFallbacks();
  testNegotiateSubprotocol();
  testIsOriginAllowed();
  testPureHelpersMissingHeaders();
  testParseExtensionHeaderEdges();

  // Frame layer
  testFrameParserRoundTrip();
  testFrameParserExtendedLengths();
  testFrameParserIncremental();
  testFrameParserFrameTooLarge();
  testFrameParser64BitOverflow();
  testSerializeFrame();

  // Connection — send/ping/close
  testConnectionSendVariants();
  testConnectionSendInvalidPayload();
  testConnectionSendRejectsWhenClosed();
  testConnectionPing();
  testConnectionClose();
  await testConnectionCloseGraceTimerFires();
  testConnectionCloseDefaultsCode();

  // Connection — inbound frames
  testConnectionReceiveMessages();
  testConnectionFragmentedMessage();
  testConnectionPingPong();
  testConnectionAbortBranches();
  testConnectionCloseHandshake();
  testConnectionCloseFrameViolations();

  // Connection — socket lifecycle
  testConnectionSocketErrorTransition();
  testConnectionSocketEndTransition();
  testConnectionSendAfterSocketUnwritable();
  testConnectionSendWriteThrows();
  testConnectionConstructorNoOpts();
  testConnectionErrorFallbackAndNoListener();
  testConnectionIdempotentTransitions();

  // Connection — permessage-deflate
  testConnectionDeflateSend();
  testConnectionDeflateReceive();
  testConnectionDeflateReceiveGarbage();
  testConnectionDeflateSendFailureFallsThrough();

  // Connection — heartbeat (real timers)
  await testHeartbeat();

  // Server-side entry points
  testHandleUpgradeGuidThrows();
  testHandleUpgradeRefusals();
  testHandleUpgradeSuccess();
  testHandleUpgradeSubprotocolAndDeflate();
  testHandleUpgradeDeflateDisabledAndUnknownParam();
  testHandleUpgradeDeflateDefaultsAndNameSkip();
  testHandleUpgradeHeadPrefeed();
  testHandleUpgradeWriteThrows();
  testHandleExtendedConnectRefusals();
  testHandleExtendedConnectSuccess();
  testHandleExtendedConnectRespondThrows();
  testHandleExtendedConnectRefusalRespondThrows();
  testEntryPointsNoOpts();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[websocket] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e); process.exit(1); }
  );
}
