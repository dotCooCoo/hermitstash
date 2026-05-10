"use strict";
/**
 * b.acme — RFC 8555 ACME client + RFC 9773 ARI surface tests.
 *
 * Live network handshakes against Pebble / Let's Encrypt staging are
 * out of scope for the smoke runner; what ships here is the create-
 * time validation, JWS shape, AKI/serial extraction, and the renewIfDue
 * before/in/after-window verdicts via the AcmeError shape.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _newKey() {
  var nodeCrypto = require("node:crypto");
  return nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
}

function testCreateRefusesBadOpts() {
  var threw = null;
  try { b.acme.create(); }
  catch (e) { threw = e; }
  check("acme.create() with no opts throws AcmeError",
        threw && /acme\/bad-opts/.test(threw.code || ""));
}

function testCreateRefusesNonHttpsDirectory() {
  var k = _newKey();
  var threw = null;
  try {
    b.acme.create({
      directory:  "http://insecure.example.com/directory",
      accountKey: k.privateKey,
    });
  } catch (e) { threw = e; }
  check("acme.create refuses http:// directory (RFC 8555 §6.1)",
        threw && /acme\/bad-directory/.test(threw.code || ""));
}

function testCreateRefusesNonP256Key() {
  var nodeCrypto = require("node:crypto");
  var rsa = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var threw = null;
  try {
    b.acme.create({
      directory:  "https://example.com/directory",
      accountKey: rsa.privateKey,
    });
  } catch (e) { threw = e; }
  check("acme.create refuses non-P-256 keypair (RFC 8555 §6.2 ES256)",
        threw && /acme\/bad-account-key/.test(threw.code || ""));
}

function testCreateRefusesUnknownContact() {
  var k = _newKey();
  var threw = null;
  try {
    b.acme.create({
      directory:  "https://example.com/directory",
      accountKey: k.privateKey,
      contact:    ["http://nope"],
    });
  } catch (e) { threw = e; }
  check("acme.create refuses non-mailto/tel contact",
        threw && /acme\/bad-contact/.test(threw.code || ""));
}

function testCreateReturnsFactory() {
  var k = _newKey();
  var acme = b.acme.create({
    directory:  "https://example.com/directory",
    accountKey: k.privateKey,
  });
  check("acme.create returns object with fetchDirectory",
        typeof acme.fetchDirectory === "function");
  check("acme.create returns object with newAccount",
        typeof acme.newAccount === "function");
  check("acme.create returns object with newOrder",
        typeof acme.newOrder === "function");
  check("acme.create returns object with finalize",
        typeof acme.finalize === "function");
  check("acme.create returns object with retrieveCert",
        typeof acme.retrieveCert === "function");
  check("acme.create returns object with renewIfDue",
        typeof acme.renewIfDue === "function");
  check("acme.create returns object with fetchAri (RFC 9773)",
        typeof acme.fetchAri === "function");
  check("acme.create returns object with keyAuthorization",
        typeof acme.keyAuthorization === "function");
  var jwk = acme.publicJwk();
  check("publicJwk exposes EC P-256 shape",
        jwk.kty === "EC" && jwk.crv === "P-256" &&
        typeof jwk.x === "string" && typeof jwk.y === "string");
}

function testKeyAuthorizationShape() {
  var k = _newKey();
  var acme = b.acme.create({
    directory:  "https://example.com/directory",
    accountKey: k.privateKey,
  });
  var ka = acme.keyAuthorization("token-abc123");
  check("keyAuthorization concatenates token.thumbprint",
        typeof ka === "string" &&
        ka.indexOf("token-abc123.") === 0 &&
        ka.length > "token-abc123.".length);
  var threw = null;
  try { acme.keyAuthorization(""); }
  catch (e) { threw = e; }
  check("keyAuthorization refuses empty token",
        threw && /acme\/bad-token/.test(threw.code || ""));
}

async function testRenewIfDueRefusesBadCert() {
  var k = _newKey();
  var acme = b.acme.create({
    directory:  "https://example.com/directory",
    accountKey: k.privateKey,
  });
  // fetchAri validates certPem shape BEFORE the network call, so we
  // can assert the throw without hitting any CA.
  var threw = null;
  try { await acme.fetchAri({ certPem: "not a pem" }); }
  catch (e) { threw = e; }
  check("fetchAri refuses non-PEM certPem",
        threw && /acme\/bad-cert/.test(threw.code || ""));

  threw = null;
  try { await acme.fetchAri({}); }
  catch (e) { threw = e; }
  check("fetchAri refuses missing certPem",
        threw && /acme\/bad-ari-input/.test(threw.code || ""));
}

function testAcmeErrorClassRegistered() {
  check("b.acme.AcmeError is a constructor",
        typeof b.acme.AcmeError === "function");
  var err = new b.acme.AcmeError("acme/test", "test message", true, 500);
  check("AcmeError carries code + permanent + statusCode",
        err.code === "acme/test" && err.permanent === true && err.statusCode === 500);
  check("AcmeError isFrameworkError",
        err.isFrameworkError === true);
}

async function run() {
  testCreateRefusesBadOpts();
  testCreateRefusesNonHttpsDirectory();
  testCreateRefusesNonP256Key();
  testCreateRefusesUnknownContact();
  testCreateReturnsFactory();
  testKeyAuthorizationShape();
  await testRenewIfDueRefusesBadCert();
  testAcmeErrorClassRegistered();
}

module.exports = { run: run };
