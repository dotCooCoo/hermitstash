"use strict";
/**
 * Live WebSocket permessage-deflate (RFC 7692) round-trip.
 *
 * Boots a minimal http server that handles `upgrade` via b.websocket,
 * connects with a raw TCP client that issues an HTTP/1.1 handshake
 * advertising `Sec-WebSocket-Extensions: permessage-deflate`, sends a
 * compressible message, and verifies:
 *
 *   1. Server's 101 response carries `Sec-WebSocket-Extensions:
 *      permessage-deflate; ...negotiated params...`
 *   2. The first frame the server sends on echo has RSV1 = 1 (extension
 *      bit indicating compressed payload)
 *   3. Inflating the payload (with the RFC 7692 trailer appended)
 *      yields the original message bytes
 *   4. The wire-bytes payload is meaningfully smaller than the source
 *      for a high-redundancy input — proves real compression
 *   5. Sending an uncompressed (RSV1=0) frame from the client still
 *      works — extension stays mixed-mode per RFC 7692 §6
 *
 * No docker dependency; this test boots its own ephemeral server.
 * Lives under test/integration/ because it boots a real socket and
 * the assertions take wire-level inspection a layer-0 unit test can't.
 */
var net = require("node:net");
var http = require("node:http");
var crypto = require("node:crypto");
var zlib = require("node:zlib");
var helpers = require("../helpers");
var check = helpers.check;
var b = require("../../");

var DEFLATE_TRAILING = Buffer.from([0x00, 0x00, 0xff, 0xff]);

function _wsAcceptKey(secKey) {
  return crypto.createHash("sha1")
    .update(secKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
    .digest("base64");
}

function _bootEchoServer() {
  return new Promise(function (resolve) {
    var srv = http.createServer();
    srv.on("upgrade", function (req, sock, head) {
      var conn = b.websocket.handleUpgrade(req, sock, head, {
        origins: null,   // allow all in test
      });
      if (!conn) return;
      conn.on("message", function (data, isBinary) {
        // Echo it back. Server compresses since extension was
        // negotiated at handshake.
        if (isBinary) conn.send(data);
        else          conn.send(data.toString("utf8"));
      });
    });
    srv.listen(0, "127.0.0.1", function () {
      resolve({ server: srv, port: srv.address().port });
    });
  });
}

function _frameRequest(opcode, payload, mask) {
  var len = payload.length;
  var headerLen = 2;
  var lenByte;
  if (len < 126)        { lenByte = len; }
  else if (len < 65536) { lenByte = 126; headerLen += 2; }
  else                  { lenByte = 127; headerLen += 8; }
  if (mask) headerLen += 4;
  var hdr = Buffer.alloc(headerLen);
  hdr[0] = 0x80 | (opcode & 0x0F);     // FIN=1, RSV1/2/3=0
  hdr[1] = (mask ? 0x80 : 0) | lenByte;
  var off = 2;
  if (lenByte === 126) { hdr.writeUInt16BE(len, off); off += 2; }
  else if (lenByte === 127) {
    hdr.writeUInt32BE(Math.floor(len / 0x100000000), off);
    hdr.writeUInt32BE(len % 0x100000000, off + 4);
    off += 8;
  }
  if (!mask) return Buffer.concat([hdr, payload]);
  var key = crypto.randomBytes(4);
  key.copy(hdr, off);
  var masked = Buffer.alloc(len);
  for (var i = 0; i < len; i++) masked[i] = payload[i] ^ key[i % 4];
  return Buffer.concat([hdr, masked]);
}

function _readFrames(buf) {
  var frames = [];
  var off = 0;
  while (off < buf.length) {
    if (off + 2 > buf.length) break;
    var b0 = buf[off];
    var b1 = buf[off + 1];
    var fin  = (b0 & 0x80) !== 0;
    var rsv1 = (b0 & 0x40) !== 0;
    var opcode = b0 & 0x0F;
    var masked = (b1 & 0x80) !== 0;
    var len = b1 & 0x7F;
    var hOff = off + 2;
    if (len === 126) { len = buf.readUInt16BE(hOff); hOff += 2; }
    else if (len === 127) {
      len = buf.readUInt32BE(hOff) * 0x100000000 + buf.readUInt32BE(hOff + 4);
      hOff += 8;
    }
    if (masked) hOff += 4;
    if (hOff + len > buf.length) break;
    var payload = buf.slice(hOff, hOff + len);
    frames.push({ fin: fin, rsv1: rsv1, opcode: opcode, payload: payload });
    off = hOff + len;
  }
  return { frames: frames, consumed: off };
}

async function _doHandshake(port, sendExtensions) {
  return new Promise(function (resolve, reject) {
    var sock = net.connect({ host: "127.0.0.1", port: port });
    var key = crypto.randomBytes(16).toString("base64");
    var headers = [
      "GET / HTTP/1.1",
      "Host: 127.0.0.1:" + port,
      "Upgrade: websocket",
      "Connection: Upgrade",
      "Sec-WebSocket-Key: " + key,
      "Sec-WebSocket-Version: 13",
    ];
    if (sendExtensions) headers.push("Sec-WebSocket-Extensions: " + sendExtensions);
    headers.push("");
    headers.push("");
    sock.write(headers.join("\r\n"));

    var resp = Buffer.alloc(0);
    var resolved = false;
    sock.on("data", function (chunk) {
      if (resolved) return;
      resp = Buffer.concat([resp, chunk]);
      var sep = resp.indexOf("\r\n\r\n");
      if (sep === -1) return;
      resolved = true;
      var hdrText = resp.slice(0, sep).toString("utf8");
      var leftover = resp.slice(sep + 4);
      resolve({ sock: sock, hdrText: hdrText, leftover: leftover, key: key });
    });
    sock.on("error", reject);
  });
}

async function run() {
  var ctx = await _bootEchoServer();
  var port = ctx.port;

  try {
    // ---- handshake offering permessage-deflate ----
    var hs = await _doHandshake(port, "permessage-deflate");
    check("handshake: 101 status",
          /^HTTP\/1\.1 101 /.test(hs.hdrText));
    check("handshake: server echoed Sec-WebSocket-Extensions: permessage-deflate",
          /Sec-WebSocket-Extensions:\s*permessage-deflate/i.test(hs.hdrText));
    check("handshake: server echoed client_no_context_takeover",
          /client_no_context_takeover/i.test(hs.hdrText));
    check("handshake: server echoed server_no_context_takeover",
          /server_no_context_takeover/i.test(hs.hdrText));
    check("handshake: Sec-WebSocket-Accept correct",
          new RegExp("Sec-WebSocket-Accept:\\s*" + _wsAcceptKey(hs.key).replace(/\+/g, "\\+").replace(/\//g, "\\/")).test(hs.hdrText));

    // ---- send a compressible payload uncompressed; expect compressed echo ----
    var msg = "blamejs ".repeat(500);  // ~4000 bytes, highly redundant
    var msgBuf = Buffer.from(msg, "utf8");
    var collected = Buffer.alloc(0);
    var msgFrames = null;
    hs.sock.on("data", function (chunk) {
      collected = Buffer.concat([collected, chunk]);
      var rv = _readFrames(collected);
      if (rv.frames.length > 0 && rv.frames[rv.frames.length - 1].fin) {
        msgFrames = rv.frames;
      }
    });
    hs.sock.write(_frameRequest(0x01 /* TEXT */, msgBuf, true));
    // Wait until the server's deflate-encoded echo lands as a final
    // frame on the read stream. waitUntil's 5s default budget covers
    // the original race-with-timeout window.
    await helpers.waitUntil(function () {
      return msgFrames && msgFrames.length >= 1;
    }, { label: "ws permessage-deflate: server echoed deflate-encoded frame" });

    check("echo: server replied with at least one frame",
          msgFrames && msgFrames.length >= 1);
    var first = msgFrames[0];
    check("echo: first frame is TEXT (opcode 0x01)",
          first.opcode === 0x01);
    check("echo: first frame has RSV1=1 (compression marker)",
          first.rsv1 === true);
    check("echo: server payload is meaningfully smaller than source (real compression)",
          first.payload.length < msgBuf.length / 2);

    // ---- decompress and confirm round-trip ----
    var decompressed = zlib.inflateRawSync(
      Buffer.concat([first.payload, DEFLATE_TRAILING]),
      { windowBits: 15 }
    );
    check("echo: decompressed payload matches original bytes",
          Buffer.compare(decompressed, msgBuf) === 0);

    hs.sock.end();
    await helpers.waitUntil(function () {
      return hs.sock.destroyed;
    }, { label: "ws handshake: first socket fully closed" });

    // ---- second handshake WITHOUT permessage-deflate offered:
    //      server should NOT advertise the extension in the response ----
    var hs2 = await _doHandshake(port, null);
    check("plain handshake: 101 status",
          /^HTTP\/1\.1 101 /.test(hs2.hdrText));
    check("plain handshake: NO Sec-WebSocket-Extensions header on response",
          !/Sec-WebSocket-Extensions/i.test(hs2.hdrText));

    // Send + receive an UNCOMPRESSED echo on the plain connection.
    var plain = "hello-plain";
    var plainBuf = Buffer.from(plain, "utf8");
    var collected2 = Buffer.alloc(0);
    var plainFrame = null;
    hs2.sock.on("data", function (chunk) {
      collected2 = Buffer.concat([collected2, chunk]);
      var rv = _readFrames(collected2);
      if (rv.frames.length > 0 && rv.frames[0].fin) {
        plainFrame = rv.frames[0];
      }
    });
    hs2.sock.write(_frameRequest(0x01, plainBuf, true));
    // Wait until the server's plain echo lands as a final frame.
    await helpers.waitUntil(function () {
      return plainFrame !== null && plainFrame !== undefined;
    }, { label: "ws permessage-deflate: server echoed plain (uncompressed) frame" });

    check("plain echo: RSV1 NOT set (no compression negotiated)",
          plainFrame && plainFrame.rsv1 === false);
    check("plain echo: payload is unmodified bytes",
          plainFrame && Buffer.compare(plainFrame.payload, plainBuf) === 0);

    hs2.sock.end();

    // ---- handshake offering UNKNOWN extension: ignored by server ----
    var hs3 = await _doHandshake(port, "unknown-extension; foo=bar");
    check("unknown extension: 101 status",
          /^HTTP\/1\.1 101 /.test(hs3.hdrText));
    check("unknown extension: NO Sec-WebSocket-Extensions echoed (server ignored unknown)",
          !/Sec-WebSocket-Extensions/i.test(hs3.hdrText));
    hs3.sock.end();
  } finally {
    await new Promise(function (r) { ctx.server.close(r); });
  }
}

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}

module.exports = { run: run };
