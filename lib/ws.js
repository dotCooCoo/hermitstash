/**
 * Minimal WebSocket server implementation (RFC 6455).
 * Handles text frames, ping/pong, close, and frame masking.
 * No external dependencies.
 */
var crypto = require("node:crypto");
var { EventEmitter } = require("node:events");

var WS_GUID = "258EAFA5-E914-47DA-95CA-5AB5DC11CE46";

// Frame-layer DoS defense: cap the declared payload size before any buffer growth
// or allocation. Application-level limits (e.g. SYNC_MAX_MESSAGE_SIZE = 65536) still
// apply on top. 1 MB is large enough to accommodate legitimate ping/pong/text frames
// for this application and small enough that a handful of concurrent attackers can't
// exhaust process memory.
var MAX_FRAME_SIZE = 1 * 1024 * 1024;
// Max WS frame header is 14 bytes (2 fixed + 8 extended len + 4 mask). Buffer should
// never exceed one full frame worth of data; if it does, the peer is malicious.
var MAX_BUFFER_SIZE = MAX_FRAME_SIZE + 14;

/**
 * Complete the WebSocket handshake on an HTTP upgrade request.
 * Returns a WebSocket instance or null if the handshake fails.
 */
function acceptUpgrade(req, socket, head) {
  var key = req.headers["sec-websocket-key"];
  if (!key) return null;

  var acceptHash = crypto.createHash("sha1")
    .update(key + WS_GUID)
    .digest("base64");

  socket.write(
    "HTTP/1.1 101 Switching Protocols\r\n" +
    "Upgrade: websocket\r\n" +
    "Connection: Upgrade\r\n" +
    "Sec-WebSocket-Accept: " + acceptHash + "\r\n" +
    "\r\n"
  );

  return new WebSocket(socket, head);
}

/**
 * Reject an upgrade request with an HTTP error.
 */
function rejectUpgrade(socket, statusCode, message) {
  try {
    socket.write("HTTP/1.1 " + statusCode + " " + message + "\r\n\r\n");
    socket.destroy();
  } catch (_e) { /* socket may have already closed — rejection complete either way */ }
}

class WebSocket extends EventEmitter {
  constructor(socket, head) {
    super();
    this.socket = socket;
    this.readyState = 1; // OPEN
    this._buffer = head && head.length ? Buffer.from(head) : Buffer.alloc(0);

    socket.on("data", (data) => {
      if (this._buffer.length + data.length > MAX_BUFFER_SIZE) {
        // Peer is either sending a frame too large to process or withholding
        // a boundary to drive memory growth. Drop the connection immediately.
        this.readyState = 3;
        try { socket.destroy(); } catch (_e) {}
        return;
      }
      this._buffer = Buffer.concat([this._buffer, data]);
      this._processFrames();
    });

    socket.on("close", () => {
      this.readyState = 3; // CLOSED
      this.emit("close");
    });

    socket.on("error", (err) => {
      this.readyState = 3;
      // Only emit error if there's a listener — prevents unhandled error crash
      if (this.listenerCount("error") > 0) this.emit("error", err);
      this.emit("close");
    });
  }

  /**
   * Send a text message.
   */
  send(data) {
    if (this.readyState !== 1) return;
    var payload = Buffer.from(data, "utf8");
    this._writeFrame(0x01, payload); // text frame
  }

  /**
   * Send a WebSocket ping.
   */
  ping() {
    if (this.readyState !== 1) return;
    this._writeFrame(0x09, Buffer.alloc(0));
  }

  /**
   * Close the connection.
   */
  close(code, reason) {
    if (this.readyState >= 2) return;
    this.readyState = 2; // CLOSING
    var payload = Buffer.alloc(2);
    payload.writeUInt16BE(code || 1000, 0);
    if (reason) payload = Buffer.concat([payload, Buffer.from(reason, "utf8")]);
    this._writeFrame(0x08, payload);
    var self = this;
    setTimeout(function () {
      if (self.socket && !self.socket.destroyed) self.socket.destroy();
    }, 1000);
  }

  /**
   * Write a WebSocket frame (server→client frames are NOT masked).
   */
  _writeFrame(opcode, payload) {
    var len = payload.length;
    var header;
    if (len < 126) {
      header = Buffer.alloc(2);
      header[0] = 0x80 | opcode; // FIN + opcode
      header[1] = len;
    } else if (len < 65536) {
      header = Buffer.alloc(4);
      header[0] = 0x80 | opcode;
      header[1] = 126;
      header.writeUInt16BE(len, 2);
    } else {
      header = Buffer.alloc(10);
      header[0] = 0x80 | opcode;
      header[1] = 127;
      // Write as two 32-bit values (no BigInt needed for reasonable payloads)
      header.writeUInt32BE(0, 2);
      header.writeUInt32BE(len, 6);
    }
    try {
      this.socket.write(header);
      if (payload.length > 0) this.socket.write(payload);
    } catch (_e) { /* write after close — socket error handler will clean up */ }
  }

  /**
   * Process buffered data into WebSocket frames.
   */
  _processFrames() {
    while (this._buffer.length >= 2) {
      var b0 = this._buffer[0];
      var b1 = this._buffer[1];
      var opcode = b0 & 0x0f;
      var masked = !!(b1 & 0x80);
      var payloadLen = b1 & 0x7f;
      var offset = 2;

      if (payloadLen === 126) {
        if (this._buffer.length < 4) return; // need more data
        payloadLen = this._buffer.readUInt16BE(2);
        offset = 4;
      } else if (payloadLen === 127) {
        if (this._buffer.length < 10) return;
        // 64-bit length. Reject anything with the upper 32 bits set — that's
        // multi-GB and we have no legitimate use for it. Safe to read just the
        // low 32 bits after that guard.
        if (this._buffer.readUInt32BE(2) !== 0) {
          try { this.socket.destroy(); } catch (_e) {}
          return;
        }
        payloadLen = this._buffer.readUInt32BE(6);
        offset = 10;
      }

      // RFC 6455 §5.1: a server MUST close the connection on an unmasked
      // client-to-server frame. Also our cap defense — reject oversize frames
      // before allocating a subarray.
      if (!masked || payloadLen > MAX_FRAME_SIZE) {
        try { this.socket.destroy(); } catch (_e) {}
        return;
      }

      var maskOffset = offset;
      offset += 4;

      var totalLen = offset + payloadLen;
      if (this._buffer.length < totalLen) return; // need more data

      var payload = this._buffer.subarray(offset, offset + payloadLen);

      // Unmask client→server frames (masking is enforced above).
      var mask = this._buffer.subarray(maskOffset, maskOffset + 4);
      for (var i = 0; i < payload.length; i++) {
        payload[i] ^= mask[i & 3];
      }

      // Advance buffer
      this._buffer = this._buffer.subarray(totalLen);

      // Handle frame by opcode
      if (opcode === 0x01) {
        // Text frame
        this.emit("message", payload.toString("utf8"));
      } else if (opcode === 0x08) {
        // Close frame
        var closeCode = payload.length >= 2 ? payload.readUInt16BE(0) : 1000;
        this.close(closeCode);
        this.readyState = 3;
        this.emit("close", closeCode);
        return;
      } else if (opcode === 0x09) {
        // Ping → reply with pong
        this._writeFrame(0x0A, payload);
      } else if (opcode === 0x0A) {
        // Pong
        this.emit("pong");
      }
      // Ignore continuation frames (0x00) and binary frames (0x02) for now
    }
  }
}

module.exports = { acceptUpgrade, rejectUpgrade, WebSocket };
