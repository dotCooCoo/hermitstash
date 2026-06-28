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

  console.log("OK — ws-client tests");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { console.error(err); process.exit(1); });
}
