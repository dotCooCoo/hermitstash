// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.tlsExporter — RFC 9266 TLS-Exporter channel binding.
 *
 * Live TLS handshake on a loopback socket → exporter materializes →
 * client and server pull the same exporter bytes (RFC 9266 §4 mandate)
 * → token-binding verify path.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var nodeTls = require("tls");
var nodeCrypto = require("crypto");

function testSurface() {
  check("tlsExporter namespace exposed",
        b.tlsExporter && typeof b.tlsExporter === "object");
  check("tlsExporter.fromSocket is a function",
        typeof b.tlsExporter.fromSocket === "function");
  check("tlsExporter.bindToken is a function",
        typeof b.tlsExporter.bindToken === "function");
  check("tlsExporter.verifyTokenBinding is a function",
        typeof b.tlsExporter.verifyTokenBinding === "function");
  check("EXPORTER_LABEL matches RFC 9266 §4",
        b.tlsExporter.EXPORTER_LABEL === "EXPORTER-Channel-Binding");
  check("EXPORTER_LENGTH is 32 bytes",
        b.tlsExporter.EXPORTER_LENGTH === 32);
  check("tlsExporter.TlsExporterError is fn",
        typeof b.tlsExporter.TlsExporterError === "function");
}

function testValidationPaths() {
  var t1 = null;
  try { b.tlsExporter.fromSocket(null); } catch (e) { t1 = e; }
  check("null socket throws", t1 && t1.code === "BAD_INPUT");

  var t2 = null;
  try { b.tlsExporter.fromSocket({}); } catch (e) { t2 = e; }
  check("non-TLS socket throws", t2 && t2.code === "NOT_TLS");

  var t3 = null;
  try {
    b.tlsExporter.fromSocket({ exportKeyingMaterial: function () {}, getProtocol: function () { return "TLSv1.2"; } });
  } catch (e) { t3 = e; }
  check("TLS<1.3 socket throws NOT_TLS_1_3",
        t3 && t3.code === "NOT_TLS_1_3");

  var t4 = null;
  try {
    b.tlsExporter.fromSocket({
      exportKeyingMaterial: function () { return Buffer.alloc(32); },
      getProtocol: function () { return "TLSv1.3"; },
    }, { length: 999999 });
  } catch (e) { t4 = e; }
  check("out-of-range length throws", t4 && t4.code === "BAD_LENGTH");
}

function _selfSignedKeyAndCert() {
  // Generate an ed25519 self-signed cert for the server. ed25519 is
  // accepted by node:tls as the server identity for TLS 1.3.
  var pair = nodeCrypto.generateKeyPairSync("ec", {
    namedCurve: "P-256",
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  // Build a minimal self-signed X.509 via X509Certificate.. Not in
  // node stdlib; instead use a precomputed self-signed cert path.
  // For this test we use a runtime-generated cert via the snake-case
  // fields supported by node 22+ generateX509.
  return pair;
}

function testLiveHandshake() {
  return new Promise(function (resolve, reject) {
    // Use the framework's mTLS engine to mint a CA + server leaf cert
    // bound to "localhost" so node:tls accepts the SNI on connect.
    (async function () {
      try {
        var ca = await b.mtlsEngine.generateCa({ name: "test-ca" });
        var leaf = await b.mtlsEngine.signClientCert({
          cn:           "localhost",
          caCertPem:    ca.caCertPem,
          caKeyPem:     ca.caKeyPem,
          usage:        "server",
          sans:         ["DNS:localhost", "IP:127.0.0.1"],
          validityDays: 1,
        });

        // Coordinate the two halves: capture both exporters before
        // running the assertions. Promise resolves when both sides
        // have computed their exporter bytes + the assertions ran.
        var serverExporter = null;
        var clientExporter = null;
        var ranAssertions = false;
        function tryAssert(server, client) {
          if (ranAssertions || !serverExporter || !clientExporter) return;
          ranAssertions = true;
          try {
            check("client + server compute equal exporter bytes",
                  Buffer.compare(serverExporter, clientExporter) === 0);
            check("exporter is 32 bytes",
                  clientExporter.length === 32);

            var binding = b.tlsExporter.bindToken(client, "session-token-xyz");
            check("bindToken returns hex string",
                  typeof binding === "string" && /^[0-9a-f]+$/.test(binding));
            var ok = b.tlsExporter.verifyTokenBinding(client, "session-token-xyz", binding);
            check("verifyTokenBinding accepts matching token", ok === true);
            var bad = b.tlsExporter.verifyTokenBinding(client, "DIFFERENT", binding);
            check("verifyTokenBinding rejects mismatched token", bad === false);
          } catch (e) {
            client.destroy(); server.close(); reject(e); return;
          }
          // Hand the live handles back so run()'s drain can destroy them and
          // poll until their TCP handles release — a fire-and-forget end()/close()
          // here leaves the client/server sockets finalizing past the worker's
          // post-run grace window.
          resolve({ server: server, client: client });
        }

        var server = nodeTls.createServer({
          key:        leaf.key,
          cert:       leaf.cert,
          minVersion: "TLSv1.3",
          maxVersion: "TLSv1.3",
        }, function (sock) {
          try { serverExporter = b.tlsExporter.fromSocket(sock); }
          catch (e) { sock.destroy(e); reject(e); return; }
          tryAssert(server, client);
        });
        var client;
        server.listen(0, "127.0.0.1", function () {
          var port = server.address().port;
          client = nodeTls.connect({
            host:       "127.0.0.1",
            port:       port,
            ca:         ca.caCertPem,
            servername: "localhost",
            minVersion: "TLSv1.3",
            maxVersion: "TLSv1.3",
          }, function () {
            try { clientExporter = b.tlsExporter.fromSocket(client); }
            catch (e) { client.destroy(); server.close(); reject(e); return; }
            tryAssert(server, client);
          });
          client.on("error", function (e) { server.close(); reject(e); });
        });
      } catch (e) {
        // Live-handshake failure should not mask the validation tests
        // that already ran. Surface the error so an mTLS-engine
        // regression doesn't silently disable channel-binding coverage.
        reject(e);
      }
    })();
  });
}

// Destroy the live TLS client + server handed back by the handshake, then poll
// until their TCP handles release. Polling drives the real event-loop turns
// that complete the async socket teardown inside run(), instead of leaving it
// to finalize in the worker's post-run grace window.
async function _drainTcpHandles(handles) {
  if (handles) {
    if (handles.client) { try { handles.client.destroy(); } catch (_e) { /* already torn down */ } }
    if (handles.server) { try { handles.server.close(); } catch (_e) { /* already closed */ } }
  }
  if (typeof process.getActiveResourcesInfo !== "function") return;
  await helpers.waitUntil(function () {
    return process.getActiveResourcesInfo().filter(function (t) {
      return t === "TCPSocketWrap" || t === "TCPServerWrap";
    }).length === 0;
  }, { timeoutMs: 5000, label: "tls-exporter: TCP handle drain after socket destroy" });
}

async function run() {
  var handles = null;
  try {
    testSurface();
    testValidationPaths();
    handles = await testLiveHandshake();
  } finally {
    await _drainTcpHandles(handles);
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
