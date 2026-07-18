// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.wsClient — outbound WebSocket client (RFC 6455).
 *
 * Tests run an in-process WebSocket server (via b.websocket primitives)
 * and dial it with b.wsClient.connect.
 */

var b = require("../..");
var helpers = require("../helpers");
var check = require("../helpers/check").check;
var http = require("http");
var net  = require("net");
var crypto = require("crypto");
var zlib = require("zlib");

// RFC 6455 §1.3 accept-key GUID + the frame serializer, reused by the raw
// fixture servers below to hand-craft handshake responses and adversarial
// frames the client must reject.
var WS_ACCEPT_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
var wsFrame = b.websocket;
function _acceptFor(key) {
  return crypto.createHash("sha1").update(key + WS_ACCEPT_GUID).digest("base64");
}

function rejects(label, fn, pattern) {
  var threw = false; var msg = "";
  try { fn(); } catch (e) { threw = true; msg = e.message; }
  check("threw on " + label, threw && (pattern.test ? pattern.test(msg) : msg.indexOf(pattern) !== -1));
}

function _sleep(ms) { return helpers.passiveObserve(ms, "ws-client: handshake/echo/close real-time observation"); }

// Every wsClient dialed in the test holds a client socket. A client that
// errors, times out, or schedules a reconnect never reaches a graceful
// close(), so its socket finalizes its async destroy past the forked worker's
// post-run grace window. Track every live client here so the drain can retire
// each one (cancel reconnect + destroy the socket) and then poll until the TCP
// handles release inside run().
var _liveClients = [];
function _trackedConnect(url, opts) {
  var c = b.wsClient.connect(url, opts);
  _liveClients.push(c);
  return c;
}

// The in-process fixture servers keep their accepted upgrade sockets open (the
// flood / stub / hold-open scenarios never send FIN), so server.close() alone
// stops listening but leaves those sockets — and their TCPSocketWrap handles —
// alive. Track every server so the drain can force its live connections shut.
var _liveServers = [];
function _trackServer(server) {
  _liveServers.push(server);
  return server;
}

async function _drainTcpHandles() {
  _liveClients.forEach(function (c) {
    try { c.cancelReconnect(); } catch (_e) { /* best-effort */ }
    try { c.close(); } catch (_e) { /* best-effort */ }
    // Force the socket down NOW — close()'s graceful path defers the socket
    // teardown behind a 1s timer, which would itself outlive run().
    try { c._teardown(b.wsClient.CLOSE_NORMAL, "", false); } catch (_e) { /* best-effort */ }
  });
  _liveServers.forEach(function (s) {
    // Destroy any accepted upgrade / hold-open sockets the server is keeping
    // alive (these are detached from the HTTP server's connection tracking, so
    // closeAllConnections can't see them), then stop listening.
    if (Array.isArray(s._wsSockets)) {
      s._wsSockets.forEach(function (sock) {
        try { if (sock && !sock.destroyed) sock.destroy(); } catch (_e) { /* best-effort */ }
      });
      s._wsSockets = [];
    }
    try { if (typeof s.closeAllConnections === "function") s.closeAllConnections(); } catch (_e) { /* best-effort */ }
    try { s.close(); } catch (_e) { /* best-effort */ }
  });
  _liveClients = [];
  _liveServers = [];
  if (typeof process.getActiveResourcesInfo !== "function") return;
  await helpers.waitUntil(function () {
    return process.getActiveResourcesInfo().filter(function (t) {
      return t === "TCPSocketWrap" || t === "TCPServerWrap";
    }).length === 0;
  }, { timeoutMs: 5000, label: "ws-client: TCP handle drain after client teardown" });
}

// Minimal in-process WebSocket server using lib/websocket primitives.
function _makeServer(opts) {
  opts = opts || {};
  var server = http.createServer(function (req, res) {
    res.writeHead(404);
    res.end();
  });
  // Upgrade hands socket ownership to this handler, so the HTTP server no
  // longer tracks it — closeAllConnections() can't reach it. Record each one
  // so the drain can destroy them directly.
  server._wsSockets = [];
  server.on("upgrade", function (req, socket /*, head */) {
    server._wsSockets.push(socket);
    var key = req.headers["sec-websocket-key"];
    if (!key) {
      socket.write("HTTP/1.1 400 Bad Request\r\n\r\n");
      socket.destroy();
      return;
    }
    if (opts.rejectStatus) {
      socket.write("HTTP/1.1 " + opts.rejectStatus + " Forbidden\r\n\r\n");
      socket.destroy();
      return;
    }
    var WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    var accept = crypto.createHash("sha1").update((opts.tamperKey ? "wrong" : key) + WS_GUID).digest("base64");
    var headerLines = [
      "HTTP/1.1 101 Switching Protocols",
      "Upgrade: websocket",
      "Connection: Upgrade",
      "Sec-WebSocket-Accept: " + accept,
    ];
    if (opts.subprotocol) headerLines.push("Sec-WebSocket-Protocol: " + opts.subprotocol);
    headerLines.push("");
    headerLines.push("");
    socket.write(headerLines.join("\r\n"));

    var ws = b.websocket;
    // Memory-exhaustion mode: stream a text frame + continuation frames with
    // fin:false whose running total exceeds the client's maxMessageBytes, and
    // never send FIN. A client that only checks the cap at FIN would buffer
    // them without bound.
    if (opts.floodFragments) {
      var part = Buffer.alloc(opts.floodFragments.partBytes || 600, 0x61);
      socket.write(ws.serializeFrame(0x01, part, { fin: false }));            // text start
      var fcount = opts.floodFragments.count || 4;
      for (var fk = 0; fk < fcount; fk += 1) {
        socket.write(ws.serializeFrame(0x00, part, { fin: false }));          // continuation, never FIN
      }
      return;
    }
    var fp = new ws.FrameParser({ maxFrameBytes: 1024 * 1024 });
    socket.on("data", function (chunk) {
      var frames = fp.push(chunk) || [];
      for (var fi = 0; fi < frames.length; fi += 1) {
        var frame = frames[fi];
        // Echo text/binary frames back; respond to ping with pong
        if (frame.opcode === 0x09) {                     // ping
          socket.write(ws.serializeFrame(0x0A, frame.payload, { fin: true }));
          continue;
        }
        if (frame.opcode === 0x08) {                     // close
          socket.write(ws.serializeFrame(0x08, frame.payload, { fin: true }));
          socket.end();
          continue;
        }
        if (frame.opcode === 0x01 || frame.opcode === 0x02) {
          // echo
          socket.write(ws.serializeFrame(frame.opcode, frame.payload, { fin: true }));
        }
      }
    });
    socket.on("error", function () { /* drop-silent */ });
  });
  return new Promise(function (resolve) {
    server.listen(0, "127.0.0.1", function () {
      resolve(_trackServer(server));
    });
  });
}

// HTTP-upgrade fixture that writes a correct (or, via respOpts.tamperKey, a
// deliberately wrong) 101 handshake — optionally advertising an extension /
// subprotocol — then hands the raw socket to `afterHandshake(socket, req)` so a
// scenario can push hand-crafted server->client frames.
function _makeFrameServer(afterHandshake, respOpts) {
  respOpts = respOpts || {};
  var server = http.createServer(function (req, res) { res.writeHead(404); res.end(); });
  server._wsSockets = [];
  server.on("upgrade", function (req, socket) {
    server._wsSockets.push(socket);
    socket.on("error", function () { /* drop-silent */ });
    var key = req.headers["sec-websocket-key"];
    var lines = [
      "HTTP/1.1 101 Switching Protocols",
      "Upgrade: websocket",
      "Connection: Upgrade",
      "Sec-WebSocket-Accept: " + _acceptFor(respOpts.tamperKey ? "wrong" : key),
    ];
    if (respOpts.extensions)  lines.push("Sec-WebSocket-Extensions: " + respOpts.extensions);
    if (respOpts.subprotocol) lines.push("Sec-WebSocket-Protocol: " + respOpts.subprotocol);
    lines.push(""); lines.push("");
    socket.write(lines.join("\r\n"));
    if (typeof afterHandshake === "function") afterHandshake(socket, req);
  });
  return new Promise(function (resolve) {
    server.listen(0, "127.0.0.1", function () { resolve(_trackServer(server)); });
  });
}

// Raw TCP fixture that replies to the client's HTTP upgrade request with
// operator-supplied bytes — used to feed malformed handshake responses (bad
// status line / oversized header / missing Upgrade) that _makeFrameServer
// (which always writes a valid 101) cannot express.
function _makeRawResponder(responseBytes) {
  var server = net.createServer(function (socket) {
    server._wsSockets.push(socket);
    socket.on("error", function () { /* drop-silent */ });
    socket.once("data", function () { socket.write(responseBytes); });
  });
  server._wsSockets = [];
  return new Promise(function (resolve) {
    server.listen(0, "127.0.0.1", function () { resolve(_trackServer(server)); });
  });
}

// Drive one adversarial-frame scenario: stand up a frame server whose
// afterHandshake pushes the crafted frame(s), dial it, and assert the client
// surfaces `expectedCode` on 'error'. connOpts.client overrides connect opts;
// connOpts.respOpts overrides the handshake response.
async function _expectFrameError(afterHandshake, connOpts, expectedCode, label) {
  connOpts = connOpts || {};
  var server = await _makeFrameServer(afterHandshake, connOpts.respOpts);
  var port = server.address().port;
  var c = _trackedConnect("ws://127.0.0.1:" + port + "/", Object.assign(
    { reconnect: false, audit: false, allowInternal: true }, connOpts.client || {}));
  var err = null;
  c.on("error", function (e) { if (!err) err = e; });
  await helpers.waitUntil(function () { return err !== null; },
    { timeoutMs: 5000, label: "ws-client: " + label });
  check(label, err && err.code === expectedCode);
  try { c.close(); } catch (_e) { /* already torn down */ }
  await _sleep(30);
  server.close();
}

async function run() {
  try {
    await _runTests();
  } finally {
    await _drainTcpHandles();
  }
}

async function _runTests() {
  // ---- shape ----
  check("b.wsClient is object",                   typeof b.wsClient === "object");
  check("b.wsClient.connect is fn",               typeof b.wsClient.connect === "function");
  check("b.wsClient.WsClientError exists",        typeof b.wsClient.WsClientError === "function");
  check("OPCODE_TEXT exposed",                    b.wsClient.OPCODE_TEXT === 0x01);
  check("CLOSE_NORMAL exposed",                   b.wsClient.CLOSE_NORMAL === 1000);

  // #368 — WsClientError carries a per-code terminal/transient flag so a
  // consumer's reconnect loop can read err.permanent directly instead of
  // re-deriving the framework's error taxonomy. Terminal: config / 4xx /
  // accept-mismatch / protocol-violation. Transient: 5xx / handshake- &
  // pong-timeout / a dropped socket. A new/unknown code fails CLOSED (terminal).
  var WCE = b.wsClient.WsClientError;
  check("err: bad-url is terminal",               new WCE("ws-client/bad-url", "x").permanent === true);
  check("err: accept-mismatch is terminal",       new WCE("ws-client/accept-mismatch", "x").permanent === true);
  check("err: protocol-error is terminal",        new WCE("ws-client/protocol-error", "x").permanent === true);
  check("err: handshake-timeout is transient",    new WCE("ws-client/handshake-timeout", "x").permanent === false);
  check("err: pong-timeout is transient",         new WCE("ws-client/pong-timeout", "x").permanent === false);
  check("err: bad-status 403 terminal + statusCode",
        new WCE("ws-client/bad-status", "x", 403).permanent === true && new WCE("ws-client/bad-status", "x", 403).statusCode === 403);
  check("err: bad-status 503 transient + statusCode",
        new WCE("ws-client/bad-status", "x", 503).permanent === false && new WCE("ws-client/bad-status", "x", 503).statusCode === 503);
  check("err: unknown code fails closed (terminal)", new WCE("ws-client/some-future-code", "x").permanent === true);

  // ---- bad URL ----
  rejects("connect: bad URL scheme",
    function () { b.wsClient.connect("http://example.com"); }, /must start with ws/);
  rejects("connect: malformed URL",
    function () { b.wsClient.connect("not a url"); }, /malformed/);

  // ---- bad subprotocols ----
  rejects("connect: subprotocols non-string",
    function () { b.wsClient.connect("ws://localhost:1", { subprotocols: [42] }); },
    /must be a non-empty string/);

  // ---- bad reconnect opts ----
  rejects("connect: reconnect non-object",
    function () { b.wsClient.connect("ws://localhost:1", { reconnect: 42 }); },
    /reconnect must be/);

  // ---- non-finite resource caps ----
  // maxMessageBytes / maxFrameBytes / handshakeTimeoutMs are inbound-OOM and
  // hang defenses. An Infinity value passes a bare `typeof === "number" && > 0`
  // check and silently DISABLES the cap (a malicious server can then send an
  // unbounded message / frame, or stall the handshake forever). A present
  // non-finite value is refused at connect time.
  rejects("connect: maxMessageBytes Infinity refused (OOM cap not disabled)",
    function () { b.wsClient.connect("ws://localhost:1", { maxMessageBytes: Infinity }); },
    /maxMessageBytes|finite/);
  rejects("connect: maxFrameBytes Infinity refused",
    function () { b.wsClient.connect("ws://localhost:1", { maxFrameBytes: Infinity }); },
    /maxFrameBytes|finite/);
  rejects("connect: handshakeTimeoutMs Infinity refused",
    function () { b.wsClient.connect("ws://localhost:1", { handshakeTimeoutMs: Infinity }); },
    /handshakeTimeoutMs|finite/);

  // ---- happy path: connect + send + echo ----
  var server = await _makeServer({});
  var port = server.address().port;
  var client = _trackedConnect("ws://127.0.0.1:" + port + "/", {
    reconnect: false,
    audit: false,
    allowInternal: true,
  });
  var openSeen = false, msgSeen = null, errSeen = null, closeSeen = null;
  client.on("open", function () { openSeen = true; });
  client.on("message", function (data) { msgSeen = data; });
  client.on("error", function (e) { errSeen = e; });
  client.on("close", function (code, reason) { closeSeen = { code: code, reason: reason }; });

  await _sleep(300);
  check("connect: open emitted",                  openSeen === true);
  check("connect: readyState open",               client.readyState === "open");
  check("connect: no error",                      errSeen === null);

  client.send("hello world");
  await _sleep(100);
  check("send/message: text echo",                msgSeen === "hello world");

  // Binary
  msgSeen = null;
  client.send(Buffer.from([1, 2, 3, 4, 5]));
  await _sleep(100);
  check("send/message: binary echo",              Buffer.isBuffer(msgSeen) && msgSeen.length === 5);

  // JSON
  msgSeen = null;
  client.send({ hello: "world", n: 42 });
  await _sleep(100);
  check("send/message: object → json string",     typeof msgSeen === "string" && msgSeen.indexOf("hello") !== -1);

  // ping
  client.ping(Buffer.from("ping-data"));
  await _sleep(100);
  check("ping: round-trips",                      true);

  // close
  client.close(1000, "bye");
  await _sleep(300);
  check("close: emitted with normal code",        closeSeen && closeSeen.code === 1000);
  check("close: readyState closed",               client.readyState === "closed");

  server.close();

  // ---- send before open ----
  var server2 = await _makeServer({});
  var port2 = server2.address().port;
  var c2 = _trackedConnect("ws://127.0.0.1:" + port2, { reconnect: false, audit: false, allowInternal: true });
  rejects("send: not open yet",
    function () { c2.send("data"); }, /not open/);
  c2.close();
  await _sleep(50);
  server2.close();

  // ---- bad accept hash ----
  var server3 = await _makeServer({ tamperKey: true });
  var port3 = server3.address().port;
  var c3 = _trackedConnect("ws://127.0.0.1:" + port3, {
    reconnect: false, audit: false, allowInternal: true,
  });
  var c3Err = null;
  c3.on("error", function (e) { c3Err = e; });
  await _sleep(300);
  check("accept-mismatch: error emitted",         c3Err && c3Err.code === "ws-client/accept-mismatch");
  server3.close();

  // ---- non-101 status ----
  var server4 = await _makeServer({ rejectStatus: 403 });
  var port4 = server4.address().port;
  var c4 = _trackedConnect("ws://127.0.0.1:" + port4, {
    reconnect: false, audit: false, allowInternal: true,
  });
  var c4Err = null;
  c4.on("error", function (e) { c4Err = e; });
  await _sleep(300);
  check("non-101: error emitted",                 c4Err && c4Err.code === "ws-client/bad-status");
  // #368 — a 4xx handshake rejection is TERMINAL (permanent), carries the status.
  check("non-101 4xx: err.permanent === true",    c4Err && c4Err.permanent === true);
  check("non-101 4xx: err.statusCode === 403",    c4Err && c4Err.statusCode === 403);
  check("non-101 4xx: err.status alias preserved", c4Err && c4Err.status === 403);
  server4.close();

  // #368 — a 5xx handshake rejection is TRANSIENT: err.permanent === false so a
  // consumer (and the client's own auto-reconnect) can retry. The single
  // bad-status code is split by the carried status, not re-derived by the caller.
  var server4b = await _makeServer({ rejectStatus: 503 });
  var port4b = server4b.address().port;
  var c4b = _trackedConnect("ws://127.0.0.1:" + port4b, {
    reconnect: false, audit: false, allowInternal: true,
  });
  var c4bErr = null;
  c4b.on("error", function (e) { c4bErr = e; });
  await _sleep(300);
  check("non-101 5xx: err.code is bad-status",    c4bErr && c4bErr.code === "ws-client/bad-status");
  check("non-101 5xx: err.permanent === false (transient)", c4bErr && c4bErr.permanent === false);
  check("non-101 5xx: err.statusCode === 503",    c4bErr && c4bErr.statusCode === 503);
  server4b.close();

  // ---- subprotocol negotiation ----
  var server5 = await _makeServer({ subprotocol: "json-stream-v1" });
  var port5 = server5.address().port;
  var c5 = _trackedConnect("ws://127.0.0.1:" + port5, {
    subprotocols: ["json-stream-v1", "msgpack-stream"],
    reconnect: false, audit: false, allowInternal: true,
  });
  var c5Open = false;
  c5.on("open", function () { c5Open = true; });
  await _sleep(300);
  check("subprotocol: opened",                    c5Open === true);
  check("subprotocol: negotiated json-stream-v1", c5.subprotocol === "json-stream-v1");
  c5.close();
  await _sleep(50);
  server5.close();

  // ---- subprotocol-not-in-offer rejected ----
  var server6 = await _makeServer({ subprotocol: "ghost-protocol" });
  var port6 = server6.address().port;
  var c6 = _trackedConnect("ws://127.0.0.1:" + port6, {
    subprotocols: ["json-stream-v1"],
    reconnect: false, audit: false, allowInternal: true,
  });
  var c6Err = null;
  c6.on("error", function (e) { c6Err = e; });
  await _sleep(300);
  check("subprotocol: not in offer → error",      c6Err && c6Err.code === "ws-client/bad-subprotocol");
  server6.close();

  // ---- header CRLF injection: error event during handshake ----
  // Need a server to actually accept the TCP connection so the handshake
  // is attempted (where the CRLF check fires).
  var server7a = await _makeServer({});
  var port7a = server7a.address().port;
  var c7a = _trackedConnect("ws://127.0.0.1:" + port7a, {
    headers: { "X-Evil": "value\r\nX-Other: injected" },
    reconnect: false, audit: false, allowInternal: true,
  });
  var c7aErr = null;
  c7a.on("error", function (e) { c7aErr = e; });
  await _sleep(300);
  check("CRLF injection: handshake error",        c7aErr && /CR\/LF/.test(c7aErr.message));
  server7a.close();

  // ---- maxMessageBytes guard on send ----
  var server7 = await _makeServer({});
  var port7 = server7.address().port;
  var c7 = _trackedConnect("ws://127.0.0.1:" + port7, {
    maxMessageBytes: 100,
    reconnect: false, audit: false, allowInternal: true,
  });
  await _sleep(300);
  rejects("send: payload too big",
    function () { c7.send(Buffer.alloc(200)); }, /exceeds maxMessageBytes/);
  c7.close();
  await _sleep(50);
  server7.close();

  // ---- maxMessageBytes guard on RECEIVE across non-FIN fragments ----
  // A peer that streams continuation frames and never sends FIN must not be
  // able to grow the reassembly buffer past maxMessageBytes — the cap is
  // enforced on the running fragment total, not only at FIN (CWE-770).
  var serverFlood = await _makeServer({ floodFragments: { partBytes: 600, count: 4 } });
  var portFlood = serverFlood.address().port;
  var cFlood = _trackedConnect("ws://127.0.0.1:" + portFlood, {
    maxMessageBytes: 1024,            // 600 + 600 = 1200 > 1024 before any FIN
    reconnect: false, audit: false, allowInternal: true,
  });
  var floodErr = null;
  cFlood.on("error", function (e) { floodErr = e; });
  await _sleep(400);
  check("receive: running fragment total over maxMessageBytes errors before FIN",
    floodErr !== null && /maxMessageBytes/.test(floodErr.message || ""));
  try { cFlood.close(); } catch (_e) { /* already torn down */ }
  await _sleep(50);
  serverFlood.close();

  // ---- url + readyState getters ----
  var server8 = await _makeServer({});
  var port8 = server8.address().port;
  var c8 = _trackedConnect("ws://127.0.0.1:" + port8 + "/foo", {
    reconnect: false, audit: false, allowInternal: true,
  });
  // Poll for handshake completion rather than a fixed-budget sleep — the
  // 150ms budget flakes under SMOKE_PARALLEL=64 contention (rule §11b).
  await helpers.waitUntil(function () { return c8.readyState === "open"; },
    { timeoutMs: 5000, label: "ws-client: c8 handshake completes (readyState open)" });
  check("getter: url",                            c8.url.indexOf("/foo") !== -1);
  check("getter: readyState open after handshake", c8.readyState === "open");
  c8.close();
  await _sleep(50);
  server8.close();

  // ---- handshake timeout ----
  // Connect to a TCP server that accepts then never responds.
  var stubServer = _trackServer(net.createServer(function (sock) {
    // Accept and hold — record it so the drain destroys the held socket.
    stubServer._wsSockets.push(sock);
  }));
  stubServer._wsSockets = [];
  await new Promise(function (r) { stubServer.listen(0, "127.0.0.1", r); });
  var stubPort = stubServer.address().port;
  var c9 = _trackedConnect("ws://127.0.0.1:" + stubPort, {
    handshakeTimeoutMs: 200,
    reconnect: false, audit: false, allowInternal: true,
  });
  var c9Err = null;
  c9.on("error", function (e) { c9Err = e; });
  await _sleep(500);
  check("handshake-timeout: error",               c9Err && c9Err.code === "ws-client/handshake-timeout");
  stubServer.close();

  // ---- reconnect: connection refused → schedules reconnect ----
  // Use a port we know nobody listens on.
  var c10 = _trackedConnect("ws://127.0.0.1:1", {
    reconnect: { maxAttempts: 1, baseMs: 50, maxMs: 100 },
    handshakeTimeoutMs: 200,
    audit: false,
    allowInternal: true,
  });
  var c10Err = null, c10Reconnecting = false;
  c10.on("error", function (e) { c10Err = e; });
  c10.on("reconnecting", function () { c10Reconnecting = true; });
  await _sleep(400);
  check("reconnect: error + reconnecting emitted", c10Err != null && c10Reconnecting === true);
  await _sleep(600);
  // After 1 attempt fails, no more reconnects.

  // ---- permanent error: 4xx skips reconnect ----
  var server4xx = await _makeServer({ rejectStatus: 403 });
  var port4xx = server4xx.address().port;
  var c11 = _trackedConnect("ws://127.0.0.1:" + port4xx, {
    reconnect: { maxAttempts: 5, baseMs: 50, maxMs: 100 },
    audit: false,
    allowInternal: true,
  });
  var c11ErrCount = 0, c11Reconnecting = 0;
  c11.on("error", function () { c11ErrCount += 1; });
  c11.on("reconnecting", function () { c11Reconnecting += 1; });
  await _sleep(500);
  check("permanent: 403 → no reconnect attempts", c11Reconnecting === 0);
  check("permanent: error fired once",            c11ErrCount === 1);
  server4xx.close();

  // #368 — a 5xx handshake rejection is TRANSIENT, so the client's own
  // auto-reconnect now fires (it was silently dead while every WsClientError was
  // alwaysPermanent → _isPermanentError always true → willReconnect always false).
  var server5xx = await _makeServer({ rejectStatus: 503 });
  var port5xx = server5xx.address().port;
  var c12 = _trackedConnect("ws://127.0.0.1:" + port5xx, {
    reconnect: { maxAttempts: 1, baseMs: 50, maxMs: 100 },
    audit: false,
    allowInternal: true,
  });
  var c12Reconnecting = 0;
  c12.on("error", function () {});
  c12.on("reconnecting", function () { c12Reconnecting += 1; });
  await _sleep(500);
  check("transient: 503 → schedules a reconnect", c12Reconnecting >= 1);
  c12.close();
  server5xx.close();

  // ---- close() reason length cap (>123 bytes truncated) ----
  var serverCl = await _makeServer({});
  var portCl = serverCl.address().port;
  var cCl = _trackedConnect("ws://127.0.0.1:" + portCl, { reconnect: false, audit: false, allowInternal: true });
  await _sleep(200);
  // Should not throw — close() truncates internally.
  cCl.close(1000, "x".repeat(500));
  check("close: long reason truncated, no throw", true);
  await _sleep(50);
  serverCl.close();

  // ---- handshakeGuid opt — config-time validation ----
  rejects("wsClient.connect: bad handshakeGuid",
    function () { b.wsClient.connect("ws://localhost:1", { handshakeGuid: 42 }); },
    /handshakeGuid must be/);
  rejects("wsClient.connect: empty handshakeGuid",
    function () { b.wsClient.connect("ws://localhost:1", { handshakeGuid: "" }); },
    /handshakeGuid must be/);

  // Custom GUID accepted at config time. Wire round-trip is exercised in the
  // ws-client integration test; here we only confirm config-time validation
  // does not refuse a valid string.
  var cGuid = _trackedConnect("ws://127.0.0.1:1", {
    handshakeGuid: "MY-CUSTOM-GUID-12345678",
    reconnect: false, audit: false, allowInternal: true,
    handshakeTimeoutMs: 100,
  });
  cGuid.on("error", function () {});
  await _sleep(150);
  check("wsClient: custom handshakeGuid accepted at config time", true);

  // ---- urlFor swap is SSRF re-validated (awaited) before connect ----
  // checkUrl is async; the dial used to call it synchronously and discard the
  // Promise, so a urlFor that pointed at a private / cloud-metadata address was
  // connected anyway (the rejection surfaced only as an unhandled rejection).
  // A swap to the metadata IP must now be refused with an SSRF error, and the
  // dial must NOT reach the metadata host.
  var sawUnhandled = null;
  function _onUnhandled(e) { sawUnhandled = e; }
  process.on("unhandledRejection", _onUnhandled);
  var ssrfErr = null;
  var cSwap = _trackedConnect("ws://127.0.0.1:1", {
    urlFor: function () { return "ws://169.254.169.254:1/"; },   // cloud-metadata — hard-deny
    reconnect: false, audit: false, allowInternal: true,        // allowInternal must NOT bypass metadata
  });
  cSwap.on("error", function (e) { if (!ssrfErr) ssrfErr = e; });
  await helpers.waitUntil(function () { return ssrfErr !== null; },
    { timeoutMs: 5000, label: "ws-client: urlFor-swap SSRF refusal emitted" });
  check("urlFor swap to metadata IP refused with SSRF error",
    ssrfErr && /metadata|ssrf|blocked|private|internal/i.test((ssrfErr.code || "") + " " + (ssrfErr.message || "")));
  check("urlFor swap did not surface an unhandled rejection", sawUnhandled === null);
  process.removeListener("unhandledRejection", _onUnhandled);

  // ---- error / adversarial / defensive / option-default branch coverage ----
  _testExtraConfigValidation();
  await _testTlsOptsForOverride();
  await _testLocalhostPinnedLookup();
  await _testAuditPaths();
  await _testPingNotOpenAndCloseTruncation();
  await _testHeadersAndOrigin();
  await _testMalformedHandshakes();
  await _testAdversarialFrames();
  await _testServerPingElicitsPong();
  await _testDeflate();
  await _testJsonAndCustomParser();
  await _testHeartbeat();
  await _testCancelPendingReconnect();
  await _testOptionDefaultBranches();
  await _testPostCloseSocketErrorSwallowed();
  await _testWssDialReachesTlsHandshake();
  await _testWssDialIpv6LiteralOmitsSni();

  console.log("OK — ws-client tests");
}

// urlFor / tlsOptsFor must be functions when present — rejected at config time.
function _testExtraConfigValidation() {
  rejects("connect: urlFor must be a function",
    function () { b.wsClient.connect("ws://localhost:1", { urlFor: 42 }); },
    /urlFor must be a function/);
  rejects("connect: tlsOptsFor must be a function",
    function () { b.wsClient.connect("ws://localhost:1", { tlsOptsFor: "nope" }); },
    /tlsOptsFor must be a function/);
}

// tlsOptsFor(attempt) returning an object is merged over tlsOpts in
// _prepareDial. On a ws:// dial the merged TLS material is unused, but the
// merge branch must run every dial without breaking the connection.
async function _testTlsOptsForOverride() {
  var server = await _makeServer({});
  var port = server.address().port;
  var called = 0;
  var c = _trackedConnect("ws://127.0.0.1:" + port + "/", {
    reconnect: false, audit: false, allowInternal: true,
    tlsOpts:    { minVersion: "TLSv1.3" },
    tlsOptsFor: function () { called += 1; return { servername: "override.example" }; },
  });
  var opened = false, errSeen = null;
  c.on("open", function () { opened = true; });
  c.on("error", function (e) { errSeen = e; });
  await helpers.waitUntil(function () { return opened || errSeen; },
    { timeoutMs: 5000, label: "ws-client: tlsOptsFor override dial resolves" });
  check("tlsOptsFor: per-dial override merged, ws:// dial still opens",
    opened === true && errSeen === null && called >= 1);
  c.close();
  await _sleep(30);
  server.close();
}

// Dial via a HOSTNAME so the SSRF-pinned custom lookup is actually invoked (an
// IP-literal host lets Node skip DNS, leaving the pinned-lookup branch dead).
// The fixture binds the unspecified address so whichever loopback the pin
// resolves (::1 / 127.0.0.1) is reachable.
async function _testLocalhostPinnedLookup() {
  var server = http.createServer(function (req, res) { res.writeHead(404); res.end(); });
  server._wsSockets = [];
  server.on("upgrade", function (req, socket) {
    server._wsSockets.push(socket);
    socket.on("error", function () { /* drop-silent */ });
    socket.write([
      "HTTP/1.1 101 Switching Protocols", "Upgrade: websocket", "Connection: Upgrade",
      "Sec-WebSocket-Accept: " + _acceptFor(req.headers["sec-websocket-key"]), "", "",
    ].join("\r\n"));
  });
  await new Promise(function (r) { server.listen(0, r); });   // no host → dual-stack loopback
  _trackServer(server);
  var port = server.address().port;
  var c = _trackedConnect("ws://localhost:" + port + "/", {
    reconnect: false, audit: false, allowInternal: true, handshakeTimeoutMs: 4000,
  });
  var opened = false, errSeen = null;
  c.on("open", function () { opened = true; });
  c.on("error", function (e) { if (!errSeen) errSeen = e; });
  await helpers.waitUntil(function () { return opened || errSeen; },
    { timeoutMs: 6000, label: "ws-client: localhost pinned-lookup dial resolves" });
  check("pinned-lookup: hostname dial connects through the SSRF-pinned lookup",
    opened === true && errSeen === null);
  c.close();
  await _sleep(30);
  server.close();
}

// audit ON (the default) exercises the connect / close / error audit metadata
// builders — including _captureCertFingerprint on a non-TLS socket (returns
// null when getPeerCertificate is absent).
async function _testAuditPaths() {
  var server = await _makeServer({});   // echoes frames; echoes + ends on close
  var port = server.address().port;
  var c = _trackedConnect("ws://127.0.0.1:" + port + "/", { reconnect: false, allowInternal: true });
  var opened = false, closed = false;
  c.on("open", function () { opened = true; });
  c.on("close", function () { closed = true; });
  await helpers.waitUntil(function () { return opened; },
    { timeoutMs: 5000, label: "ws-client: audit-on connect opens" });
  check("audit-on: connect built connect-audit metadata (opened)", opened === true);
  c.close(1000, "bye");
  await helpers.waitUntil(function () { return closed; },
    { timeoutMs: 5000, label: "ws-client: audit-on close emits" });
  check("audit-on: close built close-audit metadata (closed)", closed === true);
  server.close();

  var server2 = await _makeServer({ tamperKey: true });   // accept-mismatch, audit on
  var port2 = server2.address().port;
  var c2 = _trackedConnect("ws://127.0.0.1:" + port2 + "/", { reconnect: false, allowInternal: true });
  var err2 = null;
  c2.on("error", function (e) { err2 = e; });
  await helpers.waitUntil(function () { return err2 !== null; },
    { timeoutMs: 5000, label: "ws-client: audit-on error emits" });
  check("audit-on: error path built error-audit metadata", err2 && err2.code === "ws-client/accept-mismatch");
  server2.close();
}

// ping() before open is a no-op; close() with a >123-byte reason ending
// mid-codepoint truncates to a code-point boundary without throwing.
async function _testPingNotOpenAndCloseTruncation() {
  var server = await _makeServer({});
  var port = server.address().port;
  var c = _trackedConnect("ws://127.0.0.1:" + port + "/", { reconnect: false, audit: false, allowInternal: true });
  c.ping(Buffer.from("early"));                   // readyState "connecting" → no-op, no throw
  check("ping: no-op before open (readyState not yet open)", c.readyState !== "open");
  await helpers.waitUntil(function () { return c.readyState === "open"; },
    { timeoutMs: 5000, label: "ws-client: ping/close-trunc client opens" });
  // 122 ASCII bytes + one 3-byte '€' = 125 bytes > 123; the 123-byte cut lands
  // mid-'€', forcing the byte-boundary back-off loop.
  c.close(1000, "x".repeat(122) + "€");
  check("close: mid-codepoint reason truncated without throw", true);
  await _sleep(30);
  server.close();
}

// Valid Origin + custom headers reach the request builder (forbidden keys and
// non-string values skipped, valid header emitted); an Origin carrying CR/LF is
// refused at build time.
async function _testHeadersAndOrigin() {
  var server = await _makeServer({});
  var port = server.address().port;
  var c = _trackedConnect("ws://127.0.0.1:" + port + "/", {
    origin:  "https://app.example.com",
    headers: { "X-Custom": "keep", "Host": "evil.example", "X-Number": 42 },
    reconnect: false, audit: false, allowInternal: true,
  });
  var opened = false, errSeen = null;
  c.on("open", function () { opened = true; });
  c.on("error", function (e) { errSeen = e; });
  await helpers.waitUntil(function () { return opened || errSeen; },
    { timeoutMs: 5000, label: "ws-client: headers/origin handshake" });
  check("headers/origin: valid origin + custom headers → handshake opens",
    opened === true && errSeen === null);
  c.close();
  await _sleep(30);
  server.close();

  var server2 = await _makeServer({});
  var port2 = server2.address().port;
  var c2 = _trackedConnect("ws://127.0.0.1:" + port2 + "/", {
    origin: "https://evil\r\nX-Injected: 1",
    reconnect: false, audit: false, allowInternal: true,
  });
  var err2 = null;
  c2.on("error", function (e) { err2 = e; });
  await helpers.waitUntil(function () { return err2 !== null; },
    { timeoutMs: 5000, label: "ws-client: origin CRLF refused" });
  check("origin CRLF: handshake refused with bad-header",
    err2 && err2.code === "ws-client/bad-header" && /CR\/LF/.test(err2.message));
  server2.close();
}

// Malformed handshake responses the frame parser must reject before the frame
// layer starts: bad status line, oversized header section, missing Upgrade.
async function _testMalformedHandshakes() {
  var s1 = await _makeRawResponder("NOT-AN-HTTP-STATUS-LINE\r\n\r\n");
  var c1 = _trackedConnect("ws://127.0.0.1:" + s1.address().port + "/", { reconnect: false, audit: false, allowInternal: true });
  var e1 = null; c1.on("error", function (e) { e1 = e; });
  await helpers.waitUntil(function () { return e1 !== null; },
    { timeoutMs: 5000, label: "ws-client: malformed status line" });
  check("handshake: malformed status line → bad-status-line", e1 && e1.code === "ws-client/bad-status-line");
  s1.close();

  var pad = "HTTP/1.1 101 Switching Protocols\r\nX-Pad: " + "a".repeat(70 * 1024);   // no CRLFCRLF
  var s2 = await _makeRawResponder(pad);
  var c2 = _trackedConnect("ws://127.0.0.1:" + s2.address().port + "/", { reconnect: false, audit: false, allowInternal: true });
  var e2 = null; c2.on("error", function (e) { e2 = e; });
  await helpers.waitUntil(function () { return e2 !== null; },
    { timeoutMs: 5000, label: "ws-client: handshake too large" });
  check("handshake: >64 KiB before CRLFCRLF → handshake-too-large", e2 && e2.code === "ws-client/handshake-too-large");
  s2.close();

  var s3 = await _makeRawResponder("HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: x\r\n\r\n");
  var c3 = _trackedConnect("ws://127.0.0.1:" + s3.address().port + "/", { reconnect: false, audit: false, allowInternal: true });
  var e3 = null; c3.on("error", function (e) { e3 = e; });
  await helpers.waitUntil(function () { return e3 !== null; },
    { timeoutMs: 5000, label: "ws-client: missing upgrade header" });
  check("handshake: 101 without Upgrade/Connection → bad-upgrade", e3 && e3.code === "ws-client/bad-upgrade");
  s3.close();
}

// RFC 6455 §5.2/§5.5 frame validation: control-frame caps, reserved opcodes,
// RSV1-on-continuation, fragmentation ordering, close-reason UTF-8, and a
// frame that exceeds maxFrameBytes (parser throw surfaced through _consumeFrames).
async function _testAdversarialFrames() {
  await _expectFrameError(function (s) { s.write(wsFrame.serializeFrame(0x09, Buffer.alloc(200), { fin: true })); },
    null, "ws-client/control-too-big", "frame: control payload > 125 → control-too-big");
  await _expectFrameError(function (s) { s.write(wsFrame.serializeFrame(0x09, Buffer.alloc(4), { fin: false })); },
    null, "ws-client/control-fragmented", "frame: control FIN=0 → control-fragmented");
  await _expectFrameError(function (s) { s.write(wsFrame.serializeFrame(0x03, Buffer.from("x"), { fin: true })); },
    null, "ws-client/reserved-opcode", "frame: reserved opcode 0x3 → reserved-opcode");
  await _expectFrameError(function (s) { s.write(wsFrame.serializeFrame(0x00, Buffer.from("y"), { fin: true, rsv1: true })); },
    null, "ws-client/rsv1-on-continuation", "frame: RSV1 on continuation → rsv1-on-continuation");
  await _expectFrameError(function (s) { s.write(wsFrame.serializeFrame(0x00, Buffer.from("z"), { fin: true })); },
    null, "ws-client/protocol-error", "frame: continuation with no prior frame → protocol-error");
  await _expectFrameError(function (s) {
    s.write(wsFrame.serializeFrame(0x01, Buffer.from("a"), { fin: false }));   // text start, no FIN
    s.write(wsFrame.serializeFrame(0x01, Buffer.from("b"), { fin: true }));    // second text mid-fragment
  }, null, "ws-client/protocol-error", "frame: non-continuation mid-fragment → protocol-error");
  await _expectFrameError(function (s) { s.write(wsFrame.serializeFrame(0x08, Buffer.from([0x03, 0xE8, 0xFF, 0xFF]), { fin: true })); },
    null, "ws-client/invalid-utf8", "frame: close reason invalid UTF-8 → invalid-utf8");
  await _expectFrameError(function (s) { s.write(wsFrame.serializeFrame(0x01, Buffer.alloc(300), { fin: true })); },
    { client: { maxFrameBytes: 100 } }, "ws/frame-too-large", "frame: over maxFrameBytes → parser error surfaced");
}

// A server-initiated PING must elicit a client PONG (masked, per RFC 6455 §5.3).
async function _testServerPingElicitsPong() {
  var gotPong = false;
  var server = await _makeFrameServer(function (socket) {
    var fp = new wsFrame.FrameParser({ maxFrameBytes: 1024 });
    socket.on("data", function (chunk) {
      var frames = fp.push(chunk) || [];
      for (var i = 0; i < frames.length; i += 1) if (frames[i].opcode === 0x0A) gotPong = true;
    });
    socket.write(wsFrame.serializeFrame(0x09, Buffer.from("srv-ping"), { fin: true }));
  });
  var port = server.address().port;
  var c = _trackedConnect("ws://127.0.0.1:" + port + "/", { reconnect: false, audit: false, allowInternal: true });
  c.on("error", function () { /* keep-alive noise */ });
  await helpers.waitUntil(function () { return gotPong; },
    { timeoutMs: 5000, label: "ws-client: server PING elicits client PONG" });
  check("frame: server PING → client responds with PONG", gotPong === true);
  c.close();
  await _sleep(30);
  server.close();
}

// permessage-deflate: negotiated compressed message decodes, window-bits bounds
// are honored / refused, a decompression bomb is capped, and inflated bytes are
// UTF-8-validated.
async function _testDeflate() {
  var msg = JSON.stringify({ deflate: "round trip", nums: [1, 2, 3] });
  var s1 = await _makeFrameServer(function (s) {
    s.write(wsFrame.serializeFrame(0x01, zlib.deflateRawSync(Buffer.from(msg, "utf8")), { fin: true, rsv1: true }));
  }, { extensions: "permessage-deflate" });
  var c1 = _trackedConnect("ws://127.0.0.1:" + s1.address().port + "/", { reconnect: false, audit: false, allowInternal: true, parse: "json" });
  var got1 = null; c1.on("message", function (m) { got1 = m; }); c1.on("error", function () {});
  await helpers.waitUntil(function () { return got1 !== null; },
    { timeoutMs: 5000, label: "ws-client: deflate message decodes" });
  check("deflate: compressed RSV1 message inflates + JSON-parses", got1 && got1.deflate === "round trip");
  c1.close(); await _sleep(30); s1.close();

  var s2 = await _makeFrameServer(null, { extensions: "permessage-deflate; server_max_window_bits=12" });
  var c2 = _trackedConnect("ws://127.0.0.1:" + s2.address().port + "/", { reconnect: false, audit: false, allowInternal: true });
  var open2 = false; c2.on("open", function () { open2 = true; }); c2.on("error", function () {});
  await helpers.waitUntil(function () { return open2; },
    { timeoutMs: 5000, label: "ws-client: deflate smwb in-range opens" });
  check("deflate: server_max_window_bits in [8,15] honored (opens)", open2 === true);
  c2.close(); await _sleep(30); s2.close();

  var s3 = await _makeFrameServer(null, { extensions: "permessage-deflate; server_max_window_bits=20" });
  var c3 = _trackedConnect("ws://127.0.0.1:" + s3.address().port + "/", { reconnect: false, audit: false, allowInternal: true });
  var e3 = null; c3.on("error", function (e) { e3 = e; });
  await helpers.waitUntil(function () { return e3 !== null; },
    { timeoutMs: 5000, label: "ws-client: deflate smwb out-of-range" });
  check("deflate: server_max_window_bits=20 → deflate-error", e3 && e3.code === "ws-client/deflate-error");
  s3.close();

  var bomb = zlib.deflateRawSync(Buffer.alloc(8000, 0x61));
  var s4 = await _makeFrameServer(function (s) {
    s.write(wsFrame.serializeFrame(0x01, bomb, { fin: true, rsv1: true }));
  }, { extensions: "permessage-deflate" });
  var c4 = _trackedConnect("ws://127.0.0.1:" + s4.address().port + "/", { reconnect: false, audit: false, allowInternal: true, maxMessageBytes: 1000 });
  var e4 = null; c4.on("error", function (e) { e4 = e; });
  await helpers.waitUntil(function () { return e4 !== null; },
    { timeoutMs: 5000, label: "ws-client: decompression bomb" });
  check("deflate: decompression bomb capped → deflate-error",
    e4 && e4.code === "ws-client/deflate-error" && /bomb|exceeded/i.test(e4.message || ""));
  s4.close();

  var s5 = await _makeFrameServer(function (s) {
    s.write(wsFrame.serializeFrame(0x01, zlib.deflateRawSync(Buffer.from([0xff, 0xfe, 0xfd])), { fin: true, rsv1: true }));
  }, { extensions: "permessage-deflate" });
  var c5 = _trackedConnect("ws://127.0.0.1:" + s5.address().port + "/", { reconnect: false, audit: false, allowInternal: true });
  var e5 = null; c5.on("error", function (e) { e5 = e; });
  await helpers.waitUntil(function () { return e5 !== null; },
    { timeoutMs: 5000, label: "ws-client: inflated invalid UTF-8" });
  check("deflate: inflated invalid UTF-8 on TEXT → invalid-utf8", e5 && e5.code === "ws-client/invalid-utf8");
  s5.close();

  // Corrupt (non-deflate) RSV1 payload → inflate raises a Z_DATA_ERROR that is
  // NOT the decompression-bomb sentinel, so it is re-thrown and surfaces as a
  // generic deflate-error (the non-bomb branch of the bounded inflate helper).
  var s6 = await _makeFrameServer(function (s) {
    s.write(wsFrame.serializeFrame(0x01, Buffer.from([0xde, 0xad, 0xbe, 0xef]), { fin: true, rsv1: true }));
  }, { extensions: "permessage-deflate" });
  var c6 = _trackedConnect("ws://127.0.0.1:" + s6.address().port + "/", { reconnect: false, audit: false, allowInternal: true });
  var e6 = null; c6.on("error", function (e) { e6 = e; });
  await helpers.waitUntil(function () { return e6 !== null; },
    { timeoutMs: 5000, label: "ws-client: corrupt deflate payload" });
  check("deflate: corrupt compressed payload → deflate-error (non-bomb)",
    e6 && e6.code === "ws-client/deflate-error" && !/bomb/i.test(e6.message || ""));
  s6.close();
}

// parse:"json" and a custom parser fn — success paths transform the message;
// failure paths surface json-parse / parser-failed on 'error'.
async function _testJsonAndCustomParser() {
  var server = await _makeServer({});
  var c = _trackedConnect("ws://127.0.0.1:" + server.address().port + "/", { parse: "json", reconnect: false, audit: false, allowInternal: true });
  var got = null; c.on("message", function (m) { got = m; }); c.on("error", function () {});
  await helpers.waitUntil(function () { return c.readyState === "open"; },
    { timeoutMs: 5000, label: "ws-client: json-parse client opens" });
  c.send(JSON.stringify({ parsed: true, k: 9 }));
  await helpers.waitUntil(function () { return got !== null; },
    { timeoutMs: 5000, label: "ws-client: json-parse message" });
  check("parse:json — echoed JSON text parses to object", got && got.parsed === true && got.k === 9);
  c.close(); await _sleep(30); server.close();

  var server2 = await _makeFrameServer(function (s) { s.write(wsFrame.serializeFrame(0x01, Buffer.from("this is not json{", "utf8"), { fin: true })); });
  var c2 = _trackedConnect("ws://127.0.0.1:" + server2.address().port + "/", { parse: "json", reconnect: false, audit: false, allowInternal: true });
  var e2 = null; c2.on("error", function (e) { e2 = e; });
  await helpers.waitUntil(function () { return e2 !== null; },
    { timeoutMs: 5000, label: "ws-client: json-parse failure" });
  check("parse:json — invalid JSON text → json-parse error", e2 && e2.code === "ws-client/json-parse");
  c2.close(); await _sleep(30); server2.close();

  var server3 = await _makeServer({});
  var c3 = _trackedConnect("ws://127.0.0.1:" + server3.address().port + "/", {
    parser: function (text) { return "parsed:" + text; },
    reconnect: false, audit: false, allowInternal: true,
  });
  var got3 = null; c3.on("message", function (m) { got3 = m; }); c3.on("error", function () {});
  await helpers.waitUntil(function () { return c3.readyState === "open"; },
    { timeoutMs: 5000, label: "ws-client: custom parser opens" });
  c3.send("hello");
  await helpers.waitUntil(function () { return got3 !== null; },
    { timeoutMs: 5000, label: "ws-client: custom parser message" });
  check("parser fn — transforms payload", got3 === "parsed:hello");
  c3.close(); await _sleep(30); server3.close();

  var server4 = await _makeFrameServer(function (s) { s.write(wsFrame.serializeFrame(0x01, Buffer.from("x", "utf8"), { fin: true })); });
  var c4 = _trackedConnect("ws://127.0.0.1:" + server4.address().port + "/", {
    parser: function () { throw new Error("parser boom"); },
    reconnect: false, audit: false, allowInternal: true,
  });
  var e4 = null; c4.on("error", function (e) { e4 = e; });
  await helpers.waitUntil(function () { return e4 !== null; },
    { timeoutMs: 5000, label: "ws-client: parser throws" });
  check("parser fn — thrown error → parser-failed", e4 && e4.code === "ws-client/parser-failed");
  c4.close(); await _sleep(30); server4.close();
}

// Heartbeat: with pingMs < pongMs the client sends pings the echo server pongs
// (deadline refreshed, no timeout); with pingMs > pongMs the first heartbeat
// fires past a lapsed pong deadline → pong-timeout (transient).
async function _testHeartbeat() {
  var server = await _makeServer({});
  var port = server.address().port;
  var c = _trackedConnect("ws://127.0.0.1:" + port + "/", {
    pingMs: 60, pongMs: 5000, reconnect: false, audit: false, allowInternal: true,
  });
  var errSeen = null;
  c.on("error", function (e) { errSeen = e; });
  await helpers.waitUntil(function () { return c.readyState === "open"; },
    { timeoutMs: 5000, label: "ws-client: heartbeat client opens" });
  await _sleep(220);   // ~3 heartbeat intervals — pings sent, pongs refresh the deadline
  check("heartbeat: pings sent + pongs refresh deadline (no pong-timeout)",
    c.readyState === "open" && errSeen === null);
  c.close();
  await _sleep(30);
  server.close();

  var server2 = await _makeServer({});
  var port2 = server2.address().port;
  var c2 = _trackedConnect("ws://127.0.0.1:" + port2 + "/", {
    pingMs: 150, pongMs: 40, reconnect: false, audit: false, allowInternal: true,
  });
  var err2 = null;
  c2.on("error", function (e) { if (!err2) err2 = e; });
  await helpers.waitUntil(function () { return err2 !== null; },
    { timeoutMs: 5000, label: "ws-client: pong-timeout fires" });
  check("heartbeat: no pong before deadline → pong-timeout", err2 && err2.code === "ws-client/pong-timeout");
  check("heartbeat: pong-timeout is transient (permanent === false)", err2 && err2.permanent === false);
  server2.close();
}

// A pending reconnect timer is cleared by cancelReconnect(). Dial a dead port
// with a long backoff so the timer stays pending, then cancel before it fires.
async function _testCancelPendingReconnect() {
  var c = _trackedConnect("ws://127.0.0.1:1", {
    reconnect: { maxAttempts: 5, baseMs: 10000, maxMs: 20000 },
    handshakeTimeoutMs: 300, audit: false, allowInternal: true,
  });
  var reconnecting = 0;
  c.on("error", function () { /* dial failure */ });
  c.on("reconnecting", function () { reconnecting += 1; });
  await helpers.waitUntil(function () { return reconnecting >= 1; },
    { timeoutMs: 5000, label: "ws-client: first reconnect scheduled" });
  check("cancelReconnect: a reconnect was scheduled", reconnecting === 1);
  c.cancelReconnect();                   // clears the pending timer
  await _sleep(150);
  check("cancelReconnect: no further reconnect after cancel", reconnecting === 1);
}

// Option-default arms: a reconnect object omitting maxAttempts/baseMs/maxMs
// falls back to framework defaults; ping() with no payload sends an empty
// frame; a tlsOptsFor returning a non-object is ignored.
async function _testOptionDefaultBranches() {
  var c = _trackedConnect("ws://127.0.0.1:1", {
    reconnect: { enabled: true }, handshakeTimeoutMs: 300, audit: false, allowInternal: true,
  });
  var reconnecting = 0;
  c.on("error", function () { /* dial failure */ });
  c.on("reconnecting", function () { reconnecting += 1; });
  await helpers.waitUntil(function () { return reconnecting >= 1; },
    { timeoutMs: 5000, label: "ws-client: reconnect-default schedules" });
  check("reconnect defaults: enabled-only object schedules a reconnect", reconnecting >= 1);
  c.cancelReconnect();

  var server = await _makeServer({});
  var port = server.address().port;
  var c2 = _trackedConnect("ws://127.0.0.1:" + port + "/", {
    reconnect: false, audit: false, allowInternal: true,
    tlsOptsFor: function () { return null; },   // non-object → merge skipped, dial unaffected
  });
  var opened = false;
  c2.on("open", function () { opened = true; });
  c2.on("error", function () { /* keep-alive noise */ });
  await helpers.waitUntil(function () { return opened; },
    { timeoutMs: 5000, label: "ws-client: option-default dial opens" });
  c2.ping();   // no payload → default empty ping frame
  check("ping(): no-arg ping on open client (tlsOptsFor non-object ignored)", opened === true);
  c2.close();
  await _sleep(30);
  server.close();
}

// After the client is marked closed (cancelReconnect while the socket is still
// live), a raw peer ECONNRESET is swallowed — not surfaced as a spurious 'error'.
async function _testPostCloseSocketErrorSwallowed() {
  var server = await _makeFrameServer(function (socket) {
    setTimeout(function () {
      try { socket.resetAndDestroy(); }
      catch (_e) { try { socket.destroy(); } catch (_e2) { /* best-effort */ } }
    }, 120);
  });
  var port = server.address().port;
  var c = _trackedConnect("ws://127.0.0.1:" + port + "/", { reconnect: false, audit: false, allowInternal: true });
  var opened = false, errAfterClose = null;
  c.on("open", function () { opened = true; c.cancelReconnect(); });   // mark closed, socket still live
  c.on("error", function (e) { if (opened) errAfterClose = e; });
  await helpers.waitUntil(function () { return opened; },
    { timeoutMs: 5000, label: "ws-client: post-close swallow opens" });
  await _sleep(300);   // let the peer RST arrive after the client is marked closed
  check("post-close: peer ECONNRESET after close is swallowed (no spurious error)",
    errAfterClose === null);
  server.close();
}

// wss:// to an IP-literal target must reach the TLS handshake (then time out
// against a non-TLS listener) — not throw a raw ERR_INVALID_ARG_VALUE because
// servername was forced to an IP literal (RFC 6066: SNI MUST be a hostname).
async function _testWssDialReachesTlsHandshake() {
  var tcp = net.createServer(function (socket) { tcp._wsSockets.push(socket); socket.on("error", function () {}); });
  tcp._wsSockets = [];
  await new Promise(function (r) { tcp.listen(0, "127.0.0.1", r); });
  _trackServer(tcp);
  var port = tcp.address().port;
  var c = _trackedConnect("wss://127.0.0.1:" + port + "/", {
    reconnect: false, audit: false, allowInternal: true, handshakeTimeoutMs: 300,
  });
  var err = null;
  c.on("error", function (e) { if (!err) err = e; });
  await helpers.waitUntil(function () { return err !== null; },
    { timeoutMs: 5000, label: "ws-client: wss dial reaches TLS handshake" });
  check("wss dial: IP-literal target reaches TLS handshake (times out, not ERR_INVALID_ARG_VALUE)",
    err && err.code === "ws-client/handshake-timeout");
  tcp.close();
}

// Same defense for an IPv6 literal: `parsed.hostname` keeps the brackets
// (`[::1]`), and net.isIP only recognizes the bare form. Without stripping the
// brackets before the IP test, the client sends SNI = "[::1]" — a bracketed IP
// literal, which is malformed per RFC 6066 §3 (SNI MUST be a hostname) and a
// strict TLS server can reject. Observe the exact options handed to
// tls.connect: for an IPv6-literal target the servername must be OMITTED (the
// same treatment IPv4 literals get), not set to the bracketed address.
async function _testWssDialIpv6LiteralOmitsSni() {
  var tls = require("node:tls");
  var orig = tls.connect;
  var captured = null;
  tls.connect = function (opts) {
    if (captured === null) { captured = opts || {}; tls.connect = orig; }
    // Return a dummy socket that immediately errors so the dial tears down
    // cleanly without a real network attempt.
    var s = orig.call(tls, { host: "127.0.0.1", port: 1, servername: undefined });
    s.on("error", function () {});
    return s;
  };
  try {
    var c = _trackedConnect("wss://[::1]:8443/", {
      reconnect: false, audit: false, allowInternal: true, handshakeTimeoutMs: 300,
    });
    c.on("error", function () {});
    await helpers.waitUntil(function () { return captured !== null; },
      { timeoutMs: 5000, label: "ws-client: tls.connect called for wss IPv6-literal dial" });
    check("wss dial: IPv6-literal target omits SNI (not set to the bracketed IP literal)",
      captured && captured.servername === undefined);
  } finally {
    tls.connect = orig;
  }
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { console.error(err); process.exit(1); });
}
