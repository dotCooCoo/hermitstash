"use strict";

/**
 * A certificate reload must not disarm mTLS.
 *
 * server.setSecureContext() REPLACES the secure context: every option the
 * caller omits is assigned undefined rather than carried over from the context
 * the listener booted with. A reload object built from cert/key alone therefore
 * drops the mTLS trust bundle, and from the first ACME renewal onward every
 * client certificate stops verifying — silently, with the listener still up and
 * still reporting mTLS as configured.
 *
 * These cases pin the hazard and the fix against the running Node, rather than
 * asserting on the shape of the object server-main.js happens to build:
 *   1. Node's setSecureContext really does null out an omitted `ca` (the premise).
 *   2. A reload WITHOUT `ca` stops a previously-verifying client cert verifying.
 *   3. A reload WITH `ca` — what reloadTlsContext now supplies — keeps it verifying.
 */

var { describe, it, before } = require("node:test");
var assert = require("node:assert");
var tls = require("node:tls");
var b = require("../../lib/vendor/blamejs");
var tlsContext = require("../../lib/tls-context");

var ca = null;
var serverCert = null;
var clientCert = null;

// Connect once and report whether the peer certificate verified.
function probeAuthorized(port, cert, key, caPem) {
  return new Promise(function (resolve) {
    var socket = tls.connect({
      host: "127.0.0.1",
      port: port,
      cert: cert,
      key: key,
      ca: [caPem],
      servername: "localhost",
      minVersion: "TLSv1.3",
    }, function () {
      // The server records its verdict on its own socket; the client learns it
      // by asking the server, so the server handler stamps it on the response.
      var chunks = [];
      socket.on("data", function (d) { chunks.push(d); });
      socket.on("end", function () {
        resolve(Buffer.concat(chunks).toString().trim());
        socket.destroy();
      });
    });
    socket.on("error", function (e) { resolve("error:" + (e.code || e.message)); });
  });
}

describe("TLS certificate reload preserves the mTLS trust bundle", function () {
  before(async function () {
    var caPems = await b.mtlsEngine.generateCa({ generation: 1 });
    ca = caPems;
    serverCert = await b.mtlsEngine.signClientCert({
      caCertPem: caPems.caCertPem,
      caKeyPem: caPems.caKeyPem,
      cn: "localhost",
      usage: "server",
      sans: ["localhost", "127.0.0.1"],
    });
    clientCert = await b.mtlsEngine.signClientCert({
      caCertPem: caPems.caCertPem,
      caKeyPem: caPems.caKeyPem,
      cn: "reload-probe-client",
    });
  });

  it("node:tls setSecureContext nulls an omitted ca (the premise)", function () {
    var src = tls.Server.prototype.setSecureContext.toString();
    assert.match(src, /options\.ca/,
      "setSecureContext must still read options.ca for this hazard to exist");
    assert.match(src, /this\.ca = undefined/,
      "setSecureContext no longer nulls an omitted ca — re-check whether the reload still needs to resupply it");
  });

  it("a reload without ca stops a client certificate verifying; resupplying it restores verification", async function () {
    var server = tls.createServer({
      cert: serverCert.cert,
      key: serverCert.key,
      ca: [ca.caCertPem],
      requestCert: true,
      // Refuse rather than flag. Accepting the connection and reporting
      // socket.authorized would test the same thing one step earlier, but it
      // asks a listener to keep talking to a peer it could not verify — the
      // posture this file exists to defend. Refusing means the dropped-trust
      // case arrives as a handshake failure, which is also what an operator
      // would actually see.
      rejectUnauthorized: true,
      minVersion: "TLSv1.3",
    }, function (s) {
      s.end("authorized");
    });

    await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
    var port = server.address().port;

    try {
      var before = await probeAuthorized(port, clientCert.cert, clientCert.key, ca.caCertPem);
      assert.equal(before, "authorized", "baseline: the client cert verifies against the booted context");

      // The shape the reload used to build — cert/key only. Hard-coded on
      // purpose: this half is the hazard, not the fix.
      server.setSecureContext({
        cert: serverCert.cert,
        key: serverCert.key,
        minVersion: "TLSv1.3",
      });
      // "authorized" is written only from the connection handler, which a
      // refused peer never reaches. Refusal shows up two ways depending on how
      // far the handshake got — a client-side alert, or a socket closed with no
      // response — so the assertion is that the client did not get authorized,
      // rather than one particular shape of failure.
      var dropped = await probeAuthorized(port, clientCert.cert, clientCert.key, ca.caCertPem);
      assert.notEqual(dropped, "authorized",
        "omitting ca on reload must stop the client being authorized — if it still is, Node changed and the hazard comment is stale");

      // The PRODUCTION builder, not a copy of it. Asserting against a
      // hand-written object here would pass just as happily after the fix was
      // reverted, which is the one thing this test exists to prevent — so it
      // calls the same function reloadTlsContext() calls, with the trust bundle
      // stubbed to this test's throwaway CA.
      var newContext = await tlsContext.reloadContext({
        cert: serverCert.cert,
        key: serverCert.key,
        ecdhCurve: "X25519MLKEM768",
        ca: [ca.caCertPem],
      });
      server.setSecureContext(newContext);
      var restored = await probeAuthorized(port, clientCert.cert, clientCert.key, ca.caCertPem);
      assert.equal(restored, "authorized",
        "the context lib/tls-context.js builds must carry the trust bundle — drop `ca` from reloadContext() and this fails");
    } finally {
      await new Promise(function (r) { server.close(r); });
    }
  });
});
