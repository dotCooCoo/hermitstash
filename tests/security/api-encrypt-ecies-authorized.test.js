/**
 * Regression: the first-response hybrid ECIES key wrap (middleware/api-encrypt.js)
 * must only fire for an AUTHORIZED mTLS peer. Under requestCert:true /
 * rejectUnauthorized:false a client can present a self-signed / untrusted cert
 * that getPeerCertificate still returns; without an req.socket.authorized gate
 * the server would wrap the session key to that unverified peer's P-384 key —
 * handing it to a keypair the peer controls. These tests drive the middleware
 * with a mocked socket carrying a real client cert + a real ML-KEM-1024 public
 * key and assert the wrap is present for authorized:true and absent for
 * authorized:false (identical inputs — the gate is the only difference).
 */
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var nodeCrypto = require("node:crypto");

var testServer = require("../helpers/test-server");

describe("hybrid ECIES wrap requires an authorized mTLS peer", function () {
  var apiEncrypt, clientCertDer, kemPubB64u;

  after(function () { return testServer.stop(); });

  before(async function () {
    await testServer.start(); // initializes the vault + data dir the middleware needs
    var root = testServer.projectRoot;
    apiEncrypt = require(path.join(root, "middleware", "api-encrypt"));
    var ml_kem1024 = require(path.join(root, "lib", "vendor", "blamejs", "lib", "vendor", "noble-post-quantum.cjs")).ml_kem1024;
    var mtlsCa = require(path.join(root, "lib", "mtls-ca"));

    await mtlsCa.initCA();
    var clientCert = await mtlsCa.generateClientCert({ cn: "ecies-authz-test" });
    // The middleware reads req.socket.getPeerCertificate(true).raw (DER bytes).
    clientCertDer = new nodeCrypto.X509Certificate(clientCert.cert).raw;
    kemPubB64u = Buffer.from(ml_kem1024.keygen().publicKey).toString("base64url");
  });

  // Invoke the middleware with an empty session (so isNewSession is true) and a
  // mocked socket. Returns the object the wrapped res.json emits to the wire.
  function runWithAuthorized(authorized) {
    var captured = null;
    var req = {
      session: {},
      headers: { "x-kem-public-key": kemPubB64u },
      method: "GET",
      socket: {
        authorized: authorized,
        getPeerCertificate: function () { return { raw: clientCertDer }; },
      },
    };
    var res = { json: function (d) { captured = d; } };
    apiEncrypt(req, res, function () {});
    res.json({ ok: true });
    return captured;
  }

  it("wraps the session key for a verified (authorized) peer", function () {
    var resp = runWithAuthorized(true);
    assert.ok(resp._e && resp._t, "base session envelope is always present");
    assert.ok(resp._ek && resp._epk && resp._kem, "an authorized peer receives the ECIES-wrapped session key");
  });

  it("does NOT wrap the session key for an unauthorized peer presenting a cert", function () {
    var resp = runWithAuthorized(false);
    assert.ok(resp._e && resp._t, "base session envelope is still present");
    assert.ok(!resp._ek && !resp._epk && !resp._kem, "an unauthorized peer must NOT receive the wrapped session key");
  });
});
