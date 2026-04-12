/**
 * PQC Gate — enforces post-quantum key exchange at the TCP level.
 *
 * Inspects TLS ClientHello messages for PQC hybrid group IDs before
 * allowing the connection to reach the HTTPS server. Connections that
 * don't offer any PQC group are rejected with a TLS handshake_failure alert.
 *
 * Architecture:
 *   net.Server (public port) → parse ClientHello → pipe to internal HTTPS server
 */
var net = require("node:net");
var logger = require("../app/shared/logger");

// IANA TLS Supported Groups Registry — PQC hybrid group IDs
var PQC_GROUP_IDS = new Set([
  0x11EC, // X25519MLKEM768
  0x11EB, // SecP256r1MLKEM768
  0x11ED, // SecP384r1MLKEM1024
]);

// TLS handshake_failure alert (fatal)
var TLS_ALERT_HANDSHAKE_FAILURE = Buffer.from([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]);

var MAX_CLIENTHELLO_SIZE = 16384; // 16KB max buffer
var CLIENTHELLO_TIMEOUT = 5000;   // 5 seconds to receive ClientHello

/**
 * Check if a TLS ClientHello buffer contains any PQC group in supported_groups extension.
 * Returns true if PQC group found, false otherwise.
 */
function clientHelloHasPQC(buf) {
  if (!buf || buf.length < 44) return false;

  // TLS record header: type(1) version(2) length(2)
  if (buf[0] !== 0x16) return false; // not a handshake record

  var recordLen = buf.readUInt16BE(3);
  var recordEnd = Math.min(5 + recordLen, buf.length);

  // Handshake header: type(1) length(3)
  if (buf.length < 10) return false;
  if (buf[5] !== 0x01) return false; // not ClientHello

  // ClientHello body starts at offset 9
  // version(2) + random(32) = 34 bytes
  var offset = 9 + 2 + 32; // skip version + random
  if (offset + 1 > recordEnd) return false;

  // Session ID: length(1) + data
  var sessionIdLen = buf[offset];
  offset += 1 + sessionIdLen;
  if (offset + 2 > recordEnd) return false;

  // Cipher suites: length(2) + data
  var cipherSuitesLen = buf.readUInt16BE(offset);
  offset += 2 + cipherSuitesLen;
  if (offset + 1 > recordEnd) return false;

  // Compression methods: length(1) + data
  var compLen = buf[offset];
  offset += 1 + compLen;
  if (offset + 2 > recordEnd) return false;

  // Extensions: total_length(2)
  var extensionsLen = buf.readUInt16BE(offset);
  offset += 2;
  var extensionsEnd = Math.min(offset + extensionsLen, recordEnd);

  // Walk extensions looking for supported_groups (type 0x000A)
  while (offset + 4 <= extensionsEnd) {
    var extType = buf.readUInt16BE(offset);
    var extLen = buf.readUInt16BE(offset + 2);
    offset += 4;

    if (extType === 0x000A && extLen >= 2 && offset + extLen <= extensionsEnd) {
      // supported_groups extension: list_length(2) + group_ids(2 each)
      var listLen = buf.readUInt16BE(offset);
      var groupsOffset = offset + 2;
      var groupsEnd = Math.min(groupsOffset + listLen, offset + extLen);

      while (groupsOffset + 2 <= groupsEnd) {
        var groupId = buf.readUInt16BE(groupsOffset);
        if (PQC_GROUP_IDS.has(groupId)) return true;
        groupsOffset += 2;
      }
      return false; // Found supported_groups but no PQC group in it
    }

    offset += extLen;
  }

  return false; // No supported_groups extension found
}

/**
 * Create a PQC enforcement gate.
 * Returns a net.Server that inspects ClientHello and pipes valid connections
 * to the internal TLS server.
 *
 * @param {number} internalPort — port of the internal HTTPS server (127.0.0.1)
 */
function createPQCGate(internalPort) {
  var gate = net.createServer({ pauseOnConnect: true }, function (socket) {
    var clientIp = socket.remoteAddress || "";

    // Localhost bypass for health probes
    if (clientIp === "127.0.0.1" || clientIp === "::1" || clientIp === "::ffff:127.0.0.1") {
      return pipeToInternal(socket, internalPort);
    }

    var chunks = [];
    var totalLen = 0;
    var resolved = false;

    var timeout = setTimeout(function () {
      if (!resolved) {
        resolved = true;
        logger.warn("[PQC] ClientHello timeout", { ip: clientIp });
        socket.destroy();
      }
    }, CLIENTHELLO_TIMEOUT);

    socket.on("data", function onData(chunk) {
      if (resolved) return;
      chunks.push(chunk);
      totalLen += chunk.length;

      // Reject if exceeds max buffer
      if (totalLen > MAX_CLIENTHELLO_SIZE) {
        resolved = true;
        clearTimeout(timeout);
        logger.warn("[PQC] ClientHello too large", { ip: clientIp, size: totalLen });
        socket.destroy();
        return;
      }

      // Check if first byte is TLS handshake
      if (totalLen >= 1 && chunks[0][0] !== 0x16) {
        resolved = true;
        clearTimeout(timeout);
        socket.destroy();
        return;
      }

      // Need at least 5 bytes for record header to get length
      if (totalLen < 5) return;

      var buf = Buffer.concat(chunks);

      // Check if we have the full record (or enough to parse extensions)
      var recordLen = buf.readUInt16BE(3);
      var neededLen = 5 + recordLen;

      // Don't wait for more than we need, but need enough to parse
      if (buf.length < Math.min(neededLen, MAX_CLIENTHELLO_SIZE)) return;

      resolved = true;
      clearTimeout(timeout);
      socket.removeListener("data", onData);
      socket.pause();

      if (clientHelloHasPQC(buf)) {
        // PQC group found — pipe to internal HTTPS server
        pipeToInternal(socket, internalPort, buf);
      } else {
        // No PQC — reject with TLS alert
        logger.warn("[PQC] Connection rejected — no PQC group in ClientHello", { ip: clientIp });
        socket.write(TLS_ALERT_HANDSHAKE_FAILURE, function () {
          socket.destroy();
        });
      }
    });

    socket.on("error", function () {
      resolved = true;
      clearTimeout(timeout);
    });

    socket.resume();
  });

  return gate;
}

/**
 * Pipe a TCP connection to the internal HTTPS server, optionally prepending buffered data.
 */
function pipeToInternal(socket, internalPort, prependData) {
  var internal = net.createConnection({ port: internalPort, host: "127.0.0.1" }, function () {
    if (prependData) internal.write(prependData);
    socket.pipe(internal);
    internal.pipe(socket);
    socket.resume();
  });

  internal.on("error", function () { socket.destroy(); });
  socket.on("error", function () { internal.destroy(); });
  internal.on("close", function () { socket.destroy(); });
  socket.on("close", function () { internal.destroy(); });
}

module.exports = { clientHelloHasPQC, createPQCGate, PQC_GROUP_IDS };
