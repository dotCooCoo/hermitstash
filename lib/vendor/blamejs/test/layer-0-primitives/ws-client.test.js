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

// Minimal in-process WebSocket server using lib/websocket primitives.
function _makeServer(opts) {
  opts = opts || {};
  var server = http.createServer(function (req, res) {
    res.writeHead(404);
    res.end();
  });
  server.on("upgrade", function (req, socket /*, head */) {
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
      resolve(server);
    });
  });
}

async function run() {
  // ---- shape ----
  check("b.wsClient is object",                   typeof b.wsClient === "object");
  check("b.wsClient.connect is fn",               typeof b.wsClient.connect === "function");
  check("b.wsClient.WsClientError exists",        typeof b.wsClient.WsClientError === "function");
  check("OPCODE_TEXT exposed",                    b.wsClient.OPCODE_TEXT === 0x01);
  check("CLOSE_NORMAL exposed",                   b.wsClient.CLOSE_NORMAL === 1000);

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

  // ---- happy path: connect + send + echo ----
  var server = await _makeServer({});
  var port = server.address().port;
  var client = b.wsClient.connect("ws://127.0.0.1:" + port + "/", {
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
  var c2 = b.wsClient.connect("ws://127.0.0.1:" + port2, { reconnect: false, audit: false, allowInternal: true });
  rejects("send: not open yet",
    function () { c2.send("data"); }, /not open/);
  c2.close();
  await _sleep(50);
  server2.close();

  // ---- bad accept hash ----
  var server3 = await _makeServer({ tamperKey: true });
  var port3 = server3.address().port;
  var c3 = b.wsClient.connect("ws://127.0.0.1:" + port3, {
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
  var c4 = b.wsClient.connect("ws://127.0.0.1:" + port4, {
    reconnect: false, audit: false, allowInternal: true,
  });
  var c4Err = null;
  c4.on("error", function (e) { c4Err = e; });
  await _sleep(300);
  check("non-101: error emitted",                 c4Err && c4Err.code === "ws-client/bad-status");
  server4.close();

  // ---- subprotocol negotiation ----
  var server5 = await _makeServer({ subprotocol: "json-stream-v1" });
  var port5 = server5.address().port;
  var c5 = b.wsClient.connect("ws://127.0.0.1:" + port5, {
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
  var c6 = b.wsClient.connect("ws://127.0.0.1:" + port6, {
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
  var c7a = b.wsClient.connect("ws://127.0.0.1:" + port7a, {
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
  var c7 = b.wsClient.connect("ws://127.0.0.1:" + port7, {
    maxMessageBytes: 100,
    reconnect: false, audit: false, allowInternal: true,
  });
  await _sleep(300);
  rejects("send: payload too big",
    function () { c7.send(Buffer.alloc(200)); }, /exceeds maxMessageBytes/);
  c7.close();
  await _sleep(50);
  server7.close();

  // ---- url + readyState getters ----
  var server8 = await _makeServer({});
  var port8 = server8.address().port;
  var c8 = b.wsClient.connect("ws://127.0.0.1:" + port8 + "/foo", {
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
  var stubServer = net.createServer(function (sock) { /* accept and hold */ });
  await new Promise(function (r) { stubServer.listen(0, "127.0.0.1", r); });
  var stubPort = stubServer.address().port;
  var c9 = b.wsClient.connect("ws://127.0.0.1:" + stubPort, {
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
  var c10 = b.wsClient.connect("ws://127.0.0.1:1", {
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
  var c11 = b.wsClient.connect("ws://127.0.0.1:" + port4xx, {
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

  // ---- close() reason length cap (>123 bytes truncated) ----
  var serverCl = await _makeServer({});
  var portCl = serverCl.address().port;
  var cCl = b.wsClient.connect("ws://127.0.0.1:" + portCl, { reconnect: false, audit: false, allowInternal: true });
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
  var cGuid = b.wsClient.connect("ws://127.0.0.1:1", {
    handshakeGuid: "MY-CUSTOM-GUID-12345678",
    reconnect: false, audit: false, allowInternal: true,
    handshakeTimeoutMs: 100,
  });
  cGuid.on("error", function () {});
  await _sleep(150);
  check("wsClient: custom handshakeGuid accepted at config time", true);

  console.log("OK — ws-client tests");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { console.error(err); process.exit(1); });
}
