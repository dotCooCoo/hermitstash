/**
 * The session key never rides out in a response body.
 *
 * A hybrid ECIES wrap used to ride along on the first response to an mTLS
 * client, encrypting the session key to a shared secret derived from ML-KEM-1024
 * encapsulation plus ECDH against the P-384 key in the peer's certificate. That
 * ECDH leg was the part that bound the wrap to the AUTHENTICATED peer rather
 * than to whatever key a caller put in a header — without it the server would
 * have wrapped the key to any key it was handed.
 *
 * Certificates are post-quantum now and carry a signature key with no ECDH
 * counterpart, so the wrap became impossible to compute and there was nothing
 * safe to fall back to. It was removed rather than weakened.
 *
 * These tests hold the resulting invariant, which is stronger than the one they
 * replaced: a response body carries the encrypted payload and its timestamp and
 * no key material at all, for an authorized peer and an unauthorized one alike.
 * Clients get the session key by a route that does not put it on the wire — a
 * browser from its page template over TLS, an API-key client from the
 * framework's encrypted wrapper, which runs its own ML-KEM-1024 exchange
 * against the server's published public key.
 */
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var nodeCrypto = require("node:crypto");

var testServer = require("../helpers/test-server");

describe("no session key appears in a response body", function () {
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
    clientCertDer = new nodeCrypto.X509Certificate(clientCert.cert).raw;
    kemPubB64u = Buffer.from(ml_kem1024.keygen().publicKey).toString("base64url");
  });

  // Drive the middleware with an empty session (so this is a first response) and
  // a mocked socket presenting a real client certificate, which is the case the
  // wrap used to fire on. Returns the object the wrapped res.json emits.
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

  [true, false].forEach(function (authorized) {
    it("carries payload and timestamp only, for an " + (authorized ? "authorized" : "unauthorized") + " peer", function () {
      var resp = runWithAuthorized(authorized);
      assert.ok(resp._e && resp._t, "the session envelope is always present");
      assert.deepEqual(Object.keys(resp).sort(), ["_e", "_t"],
        "a response must carry no field beyond the payload and its timestamp");
    });
  });

  it("does not offer to wrap a key to a certificate", function () {
    // The removed path took its ECDH key from the peer certificate. Pinned so
    // that reintroducing it is a deliberate act with a test to answer to, since
    // a post-quantum certificate has no key it could be reintroduced against.
    var src = require("node:fs").readFileSync(
      path.join(testServer.projectRoot, "middleware", "api-encrypt.js"), "utf8");
    ["diffieHellman", "secp384r1", "getPeerCertificate", "_epk", "_kem"].forEach(function (token) {
      assert.ok(src.indexOf(token) === -1, token + " must not reappear in the response path");
    });
  });

  it("a post-quantum certificate has no key to wrap against", function () {
    // The fact that made the removal necessary rather than optional. If the CA
    // ever issues a certificate with an ECDH-capable key again, this fails and
    // the decision above deserves rereading.
    var pub = new nodeCrypto.X509Certificate(clientCertDer).publicKey;
    assert.equal(pub.asymmetricKeyType, "ml-dsa-87",
      "client certificates are post-quantum, so there is no P-384 key in them");
    assert.throws(function () {
      nodeCrypto.diffieHellman({
        privateKey: nodeCrypto.generateKeyPairSync("ec", { namedCurve: "secp384r1" }).privateKey,
        publicKey: pub,
      });
    }, /Incompatible key types/, "and ECDH against it cannot be performed");
  });
});
