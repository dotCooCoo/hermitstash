"use strict";
/**
 * b.* NTS-KE handshake byte-cap.
 *
 * The NTS-KE (RFC 8915) key-establishment handshake reader accumulates
 * received bytes until a REC_END record terminates the exchange. A
 * wall-clock timer bounds the handshake by time, but NOT by memory: a
 * server that streams non-END records fast enough OOMs the process
 * before the timer fires. The reader must cap the accumulated buffer at
 * a sane ceiling (64 KiB) and fail closed with an nts/* typed error.
 *
 * This drives the real consumer path — network-nts.performKeHandshake
 * against a live loopback TLS server negotiating ALPN "ntske/1" that
 * streams > 64 KiB of non-END records.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var nts     = require("../../lib/network-nts");
var nodeTls = require("node:tls");

var REC_NEW_COOKIE = 5;

// Encode an NTS-KE record: u16 type (top bit = critical) || u16 length
// || body. We emit non-critical NEW_COOKIE records that never include a
// REC_END (type 0), so a conformant reader keeps accumulating.
function _encodeRecord(type, body) {
  var hdr = Buffer.alloc(4);
  hdr.writeUInt16BE(type & 0x7fff, 0);
  hdr.writeUInt16BE(body.length, 2);
  return Buffer.concat([hdr, body]);
}

function testHandshakeByteCapFailsClosed() {
  return new Promise(function (resolve, reject) {
    (async function () {
      var server = null;
      try {
        var ca = await helpers.b.mtlsEngine.generateCa({ name: "nts-test-ca" });
        var leaf = await helpers.b.mtlsEngine.signClientCert({
          cn:           "localhost",
          caCertPem:    ca.caCertPem,
          caKeyPem:     ca.caKeyPem,
          usage:        "server",
          sans:         ["DNS:localhost", "IP:127.0.0.1"],
          validityDays: 1,
        });

        // One ~1 KiB non-END record; streamed enough times to exceed the
        // 64 KiB ceiling without ever sending REC_END.
        var oneRecord = _encodeRecord(REC_NEW_COOKIE, Buffer.alloc(1020, 0x41));
        var TOTAL_BYTES = 128 * 1024; // 2x the 64 KiB cap

        server = nodeTls.createServer({
          key:           leaf.key,
          cert:          leaf.cert,
          minVersion:    "TLSv1.3",
          maxVersion:    "TLSv1.3",
          ALPNProtocols: ["ntske/1"],
        }, function (sock) {
          sock.on("error", function () { /* client tears down mid-stream */ });
          var sent = 0;
          function pump() {
            while (sent < TOTAL_BYTES) {
              sent += oneRecord.length;
              if (!sock.write(oneRecord)) {
                sock.once("drain", pump);
                return;
              }
            }
          }
          pump();
        });

        server.listen(0, "127.0.0.1", function () {
          var port = server.address().port;
          var startedAt = Date.now();
          nts.performKeHandshake({
            host:       "127.0.0.1",
            port:       port,
            servername: "localhost",
            ca:         ca.caCertPem,
            // Generous timeout: a passing run must reject on the byte cap
            // FAST (well under this), proving the cap — not the timer —
            // bounded the read.
            timeoutMs:  30000,
          }).then(function () {
            server.close();
            reject(new Error("handshake resolved despite > 64 KiB of non-END records"));
          }).catch(function (e) {
            var elapsed = Date.now() - startedAt;
            try { server.close(); } catch (_e) { /* best-effort */ }
            try {
              check("handshake rejects on oversized stream",
                    e && e.code === "nts/ke-too-large");
              check("rejection is NtsError typed",
                    e instanceof nts.NtsError);
              check("rejection is bounded, not the wall-clock timeout",
                    e.code !== "nts/ke-timeout");
              check("bounded fast (well under the 30s timer)",
                    elapsed < 15000);
              resolve();
            } catch (assertErr) {
              reject(assertErr);
            }
          });
        });

        server.on("error", function (e) { reject(e); });
      } catch (e) {
        if (server) { try { server.close(); } catch (_e) { /* best-effort */ } }
        reject(e);
      }
    })();
  });
}

async function run() {
  await testHandshakeByteCapFailsClosed();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
