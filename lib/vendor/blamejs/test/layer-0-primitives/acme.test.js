// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.acme — RFC 8555 ACME client + RFC 9773 ARI surface tests.
 *
 * Live network handshakes against Pebble / Let's Encrypt staging are
 * out of scope for the smoke runner; what ships here is the create-
 * time validation, JWS shape, AKI/serial extraction, and the renewIfDue
 * before/in/after-window verdicts via the AcmeError shape.
 * Also here: the create() key-normalization branches, the pure PKCS#10
 * buildCsr builder (P-256 / P-384 / RSA, with signature verification),
 * the offline-reachable order / challenge / revoke / deactivate guards,
 * and the network-driven flows (directory, account + EAB, order,
 * finalize, cert polling, authorizations, ARI verdicts, key rollover,
 * listProfiles) driven through a loopback-stubbed httpClient.request —
 * no CA is ever contacted.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var nodeCrypto = require("node:crypto");

var asn1       = require("../../lib/asn1-der");
var C          = require("../../lib/constants");
var httpClient = require("../../lib/http-client");

var CA = "https://ca.example.test";

function _newKey() {
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

function testV0883NewSurface() {
  var k = _newKey();
  var acme = b.acme.create({
    directory:  "https://example.com/directory",
    accountKey: k.privateKey,
  });
  check("acme.create returns object with listProfiles",
        typeof acme.listProfiles === "function");
  check("acme.create returns object with dnsAccount01ChallengeRecord",
        typeof acme.dnsAccount01ChallengeRecord === "function");
  // listProfiles pre-fetch-directory returns empty object
  var profiles = acme.listProfiles();
  check("listProfiles before fetchDirectory returns {}",
        profiles && typeof profiles === "object" &&
        Object.keys(profiles).length === 0);
  // dnsAccount01ChallengeRecord refuses pre-account
  var threw = null;
  try { acme.dnsAccount01ChallengeRecord("token", { identifier: "example.com" }); }
  catch (e) { threw = e; }
  check("dnsAccount01ChallengeRecord refuses pre-newAccount",
        threw && /acme\/no-account/.test(threw.code || ""));
}

function testV0883Base32Helper() {
  // Reach for the internal helper through a shape that uses it; the
  // record name's account-label segment must be lowercase base32
  // (alphabet a-z + 2-7) of fixed length.
  var k = _newKey();
  var acme = b.acme.create({
    directory:  "https://example.com/directory",
    accountKey: k.privateKey,
  });
  // We can't reach _base32lc directly without exporting; instead drive
  // through dnsAccount01ChallengeRecord with a fake accountUrl. The
  // primitive refuses pre-account, so set state via the rollover path
  // would need a network call. Skip the direct-drive check — the helper
  // is exercised by integration tests when accountUrl exists.
  check("acme.create object frozen",
        Object.isFrozen(acme));
}

function testV0883NewOrderProfileValidation() {
  // newOrder refuses bad profile shape BEFORE the network call (the
  // identifier validation is reached after the profile check returns
  // successfully; here we drive a non-string profile to hit the throw
  // directly). newOrder will also refuse missing accountUrl before any
  // profile check — verify both shapes.
  var k = _newKey();
  var acme = b.acme.create({
    directory:  "https://example.com/directory",
    accountKey: k.privateKey,
  });
  // newOrder refuses pre-newAccount; profile validation lives after
  // account check, so we test the documented contract surface via the
  // public refuse-shape instead.
  check("newOrder exists and is async",
        typeof acme.newOrder === "function");
}

function _handle() {
  var k = _newKey();
  return b.acme.create({
    directory:  "https://ca.example.test/directory",
    accountKey: k.privateKey,
  });
}

// Capture the AcmeError code from a synchronous throw.
function _codeOf(fn) {
  try { fn(); return null; }
  catch (e) { return (e && e.code) || null; }
}

// Capture the AcmeError code from a rejected promise.
async function _acode(promise) {
  try { await promise; return "NO-THROW"; }
  catch (e) { return (e && e.code) || ("PLAIN:" + (e && e.message)); }
}

// ---- minimal DER TLV reader — used ONLY to verify buildCsr output ----
// (definite-form length; returns the byte boundaries of one TLV).
function _readTLV(buf, off) {
  var lenByte = buf[off + 1];
  var contentStart, contentLen;
  if (lenByte < 0x80) {
    contentLen = lenByte;
    contentStart = off + 2;
  } else {
    var n = lenByte & 0x7f;
    contentLen = 0;
    for (var i = 0; i < n; i += 1) contentLen = (contentLen * 256) + buf[off + 2 + i];
    contentStart = off + 2 + n;
  }
  return {
    tag:          buf[off],
    contentStart: contentStart,
    contentLen:   contentLen,
    tlvEnd:       contentStart + contentLen,
  };
}

function _csrPemToDer(pem) {
  var b64 = pem
    .replace(/-----BEGIN CERTIFICATE REQUEST-----/, "")
    .replace(/-----END CERTIFICATE REQUEST-----/, "")
    .replace(/\s+/g, "");
  return Buffer.from(b64, "base64");
}

// Verify the signature inside a CSR: signature is over the DER of the
// first child (CertificationRequestInfo) using the supplied public key.
function _csrSignatureVerifies(pem, publicKey, digest) {
  var der    = _csrPemToDer(pem);
  var outer  = _readTLV(der, 0);                    // CertificationRequest SEQUENCE
  var cri    = _readTLV(der, outer.contentStart);   // certReqInfo SEQUENCE (child 0)
  var criTlv = der.subarray(outer.contentStart, cri.tlvEnd);
  var sigAlg = _readTLV(der, cri.tlvEnd);           // signatureAlgorithm (child 1)
  var sigBit = _readTLV(der, sigAlg.tlvEnd);        // signature BIT STRING (child 2)
  // BIT STRING content: first byte = unused-bits count (0), rest = sig.
  var sig = der.subarray(sigBit.contentStart + 1, sigBit.tlvEnd);
  var v = nodeCrypto.createVerify(digest);
  v.update(criTlv);
  return v.verify(publicKey, sig);
}

// ---- create(): directory + accountKey normalization branches ----

function testCreateRefusesMissingDirectory() {
  var k = _newKey();
  check("create refuses missing directory",
        _codeOf(function () { b.acme.create({ accountKey: k.privateKey }); }) === "acme/bad-directory");
  check("create refuses empty directory string",
        _codeOf(function () {
          b.acme.create({ directory: "", accountKey: k.privateKey });
        }) === "acme/bad-directory");
}

function testCreateRefusesMissingAccountKey() {
  check("create refuses missing accountKey",
        _codeOf(function () {
          b.acme.create({ directory: "https://ca.example.test/directory" });
        }) === "acme/bad-account-key");
}

function testCreateRefusesPublicKeyObject() {
  var k = _newKey();
  // A public KeyObject is not "private", carries no privatePem and no
  // nested privateKey → the create() normalizer must refuse it.
  check("create refuses a public KeyObject as accountKey",
        _codeOf(function () {
          b.acme.create({ directory: "https://ca.example.test/directory", accountKey: k.publicKey });
        }) === "acme/bad-account-key");
}

function testCreateAcceptsPrivatePem() {
  var k = _newKey();
  var privatePem = k.privateKey.export({ type: "pkcs8", format: "pem" });
  var acme = b.acme.create({
    directory:  "https://ca.example.test/directory",
    accountKey: { privatePem: privatePem },
  });
  var jwk = acme.publicJwk();
  check("create accepts { privatePem } and derives the P-256 public JWK",
        jwk.kty === "EC" && jwk.crv === "P-256" &&
        typeof jwk.x === "string" && typeof jwk.y === "string");
}

function testCreateAcceptsNestedPrivateKey() {
  var k = _newKey();
  var acme = b.acme.create({
    directory:  "https://ca.example.test/directory",
    accountKey: { privateKey: k.privateKey },
  });
  check("create accepts { privateKey: KeyObject } nested shape",
        acme.publicJwk().kty === "EC");
}

function testCreateRefusesBadPrivatePem() {
  check("create refuses an unparseable privatePem",
        _codeOf(function () {
          b.acme.create({
            directory:  "https://ca.example.test/directory",
            accountKey: { privatePem: "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----" },
          });
        }) === "acme/bad-account-key");
}

function testCreateRefusesUnknownOpt() {
  var k = _newKey();
  var threw = null;
  try {
    b.acme.create({
      directory:  "https://ca.example.test/directory",
      accountKey: k.privateKey,
      bogusOption: true,
    });
  } catch (e) { threw = e; }
  // validateOpts throws a plain Error (code-shaped message) for typos.
  check("create refuses an unknown opt key (typo guard)",
        threw && /unknown option 'bogusOption'/.test(threw.message || ""));
}

function testCreateContactShapeBranches() {
  var k = _newKey();
  function mk(contact) {
    return b.acme.create({
      directory:  "https://ca.example.test/directory",
      accountKey: k.privateKey,
      contact:    contact,
    });
  }
  check("create refuses a non-array contact",
        _codeOf(function () { mk("mailto:ops@example.com"); }) === "acme/bad-contact");
  var longContact = "mailto:" + "a".repeat(300) + "@example.com";
  check("create refuses an over-length contact URI",
        _codeOf(function () { mk([longContact]); }) === "acme/bad-contact");
  check("create accepts a valid mailto contact",
        typeof mk(["mailto:ops@example.com"]).newAccount === "function");
  check("create accepts a valid tel contact",
        typeof mk(["tel:+15551234567"]).newAccount === "function");
}

// ---- getters + pure key-derived helpers ----

function testGettersNullBeforeLifecycle() {
  var acme = _handle();
  check("accountUrl() is null before newAccount()", acme.accountUrl() === null);
  check("directory() is null before fetchDirectory()", acme.directory() === null);
}

function testPublicJwkReturnsIsolatedCopy() {
  var acme = _handle();
  var j = acme.publicJwk();
  j.x = "TAMPERED";
  j.injected = "x";
  check("publicJwk() returns a fresh copy (mutation does not leak back)",
        acme.publicJwk().x !== "TAMPERED" && acme.publicJwk().injected === undefined);
}

function testKeyAuthorizationDeterministicAndDistinct() {
  var acme = _handle();
  var a1 = acme.keyAuthorization("tokenA");
  var a2 = acme.keyAuthorization("tokenA");
  var b1 = acme.keyAuthorization("tokenB");
  check("keyAuthorization is deterministic for the same token", a1 === a2);
  check("keyAuthorization differs across tokens", a1 !== b1);
  // token + "." + thumbprint — the thumbprint segment is base64url.
  check("keyAuthorization thumbprint segment is base64url",
        /^tokenA\.[A-Za-z0-9_-]+$/.test(a1));
}

function testTlsAlpn01KeyAuthorization() {
  var acme = _handle();
  var digest = acme.tlsAlpn01KeyAuthorization("tok-xyz");
  check("tlsAlpn01KeyAuthorization returns a 32-byte SHA-256 Buffer",
        Buffer.isBuffer(digest) && digest.length === 32);
  // RFC 8737: digest == SHA-256(keyAuthorization(token)).
  var expected = nodeCrypto.createHash("sha256")
    .update(acme.keyAuthorization("tok-xyz"), "utf8").digest();
  check("tlsAlpn01KeyAuthorization == SHA-256(keyAuthorization(token))",
        Buffer.compare(digest, expected) === 0);
  check("tlsAlpn01KeyAuthorization refuses an empty token",
        _codeOf(function () { acme.tlsAlpn01KeyAuthorization(""); }) === "acme/bad-token");
  check("tlsAlpn01KeyAuthorization refuses a non-string token",
        _codeOf(function () { acme.tlsAlpn01KeyAuthorization(123); }) === "acme/bad-token");
}

function testDnsAccount01ValidationBeforeAccount() {
  var acme = _handle();
  // token + identifier validation fire BEFORE the accountUrl guard.
  check("dnsAccount01ChallengeRecord refuses an empty token",
        _codeOf(function () {
          acme.dnsAccount01ChallengeRecord("", { identifier: "example.com" });
        }) === "acme/bad-token");
  check("dnsAccount01ChallengeRecord refuses a non-string token",
        _codeOf(function () {
          acme.dnsAccount01ChallengeRecord(42, { identifier: "example.com" });
        }) === "acme/bad-token");
  check("dnsAccount01ChallengeRecord refuses a missing identifier",
        _codeOf(function () {
          acme.dnsAccount01ChallengeRecord("tok", {});
        }) === "acme/bad-identifier");
  check("dnsAccount01ChallengeRecord refuses an over-length identifier",
        _codeOf(function () {
          acme.dnsAccount01ChallengeRecord("tok", { identifier: "a".repeat(300) });
        }) === "acme/bad-identifier");
}

// ---- buildCsr: pure PKCS#10 builder ----

function testBuildCsrInputValidation() {
  var acme = _handle();
  var ec = _newKey();
  check("buildCsr refuses missing opts",
        _codeOf(function () { acme.buildCsr(); }) === "acme/bad-csr-opts");
  check("buildCsr refuses a non-private privateKey",
        _codeOf(function () {
          acme.buildCsr({ privateKey: ec.publicKey, publicKey: ec.publicKey, domains: ["x.com"] });
        }) === "acme/bad-csr-private-key");
  check("buildCsr refuses a non-public publicKey",
        _codeOf(function () {
          acme.buildCsr({ privateKey: ec.privateKey, publicKey: ec.privateKey, domains: ["x.com"] });
        }) === "acme/bad-csr-public-key");
  check("buildCsr refuses a non-array domains",
        _codeOf(function () {
          acme.buildCsr({ privateKey: ec.privateKey, publicKey: ec.publicKey, domains: "x.com" });
        }) === "acme/bad-csr-domains");
  check("buildCsr refuses an empty domains array",
        _codeOf(function () {
          acme.buildCsr({ privateKey: ec.privateKey, publicKey: ec.publicKey, domains: [] });
        }) === "acme/bad-csr-domains");
  check("buildCsr refuses a non-string domain element",
        _codeOf(function () {
          acme.buildCsr({ privateKey: ec.privateKey, publicKey: ec.publicKey, domains: [123] });
        }) === "acme/bad-csr-domain");
  check("buildCsr refuses an empty domain element",
        _codeOf(function () {
          acme.buildCsr({ privateKey: ec.privateKey, publicKey: ec.publicKey, domains: [""] });
        }) === "acme/bad-csr-domain");
  check("buildCsr refuses an over-length domain element",
        _codeOf(function () {
          acme.buildCsr({ privateKey: ec.privateKey, publicKey: ec.publicKey, domains: ["a".repeat(300)] });
        }) === "acme/bad-csr-domain");
}

function testBuildCsrP256() {
  var acme = _handle();
  var pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var csr = acme.buildCsr({
    privateKey: pair.privateKey,
    publicKey:  pair.publicKey,
    domains:    ["example.com", "www.example.com"],
  });
  check("buildCsr (P-256) emits a CERTIFICATE REQUEST PEM",
        csr.indexOf("-----BEGIN CERTIFICATE REQUEST-----") === 0 &&
        csr.indexOf("-----END CERTIFICATE REQUEST-----") !== -1);
  check("buildCsr (P-256) produces a signature that verifies (ecdsa-with-SHA256)",
        _csrSignatureVerifies(csr, pair.publicKey, "sha256"));
}

function testBuildCsrP384() {
  var acme = _handle();
  var pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-384" });
  var csr = acme.buildCsr({
    privateKey: pair.privateKey,
    publicKey:  pair.publicKey,
    domains:    ["p384.example.com"],
  });
  check("buildCsr (P-384) produces a signature that verifies (ecdsa-with-SHA384)",
        _csrSignatureVerifies(csr, pair.publicKey, "sha384"));
}

function testBuildCsrRsa() {
  var acme = _handle();
  var pair = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var csr = acme.buildCsr({
    privateKey: pair.privateKey,
    publicKey:  pair.publicKey,
    domains:    ["rsa.example.com"],
  });
  check("buildCsr (RSA-2048) produces a signature that verifies (sha256WithRSAEncryption)",
        _csrSignatureVerifies(csr, pair.publicKey, "sha256"));
}

function testBuildCsrRejectsUnsupportedKeys() {
  var acme = _handle();
  var ed = nodeCrypto.generateKeyPairSync("ed25519");
  check("buildCsr rejects Ed25519 leaf keys",
        _codeOf(function () {
          acme.buildCsr({ privateKey: ed.privateKey, publicKey: ed.publicKey, domains: ["ed.example.com"] });
        }) === "acme/bad-csr-key-type");
  var p521 = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "secp521r1" });
  check("buildCsr rejects an unsupported ECDSA curve (P-521)",
        _codeOf(function () {
          acme.buildCsr({ privateKey: p521.privateKey, publicKey: p521.publicKey, domains: ["p521.example.com"] });
        }) === "acme/bad-csr-curve");
}

// ---- offline-reachable order / challenge / revoke / deactivate guards ----

async function testFinalizeValidation() {
  var acme = _handle();
  check("finalize refuses a null order",
        (await _acode(acme.finalize(null, Buffer.from([1])))) === "acme/bad-order");
  check("finalize refuses an order without a finalize URL",
        (await _acode(acme.finalize({}, Buffer.from([1])))) === "acme/bad-order");
  check("finalize refuses a CSR that is neither Buffer nor PEM string",
        (await _acode(acme.finalize({ finalize: "https://ca.example.test/f" }, 12345))) === "acme/bad-csr");
  check("finalize refuses a CSR string without the PEM marker",
        (await _acode(acme.finalize({ finalize: "https://ca.example.test/f" }, "xxxxx"))) === "acme/bad-csr");
  check("finalize refuses an empty CSR buffer",
        (await _acode(acme.finalize({ finalize: "https://ca.example.test/f" }, Buffer.alloc(0)))) === "acme/bad-csr");
  check("finalize refuses an oversize CSR buffer (> 64 KiB)",
        (await _acode(acme.finalize({ finalize: "https://ca.example.test/f" }, Buffer.alloc(64 * 1024 + 1)))) === "acme/bad-csr");
}

async function testSignedPostNeedsDirectory() {
  // A well-formed finalize call clears validation, then the first signed
  // POST demands a fetched directory for the nonce — surfaced offline.
  var acme = _handle();
  var pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var csr = acme.buildCsr({ privateKey: pair.privateKey, publicKey: pair.publicKey, domains: ["x.example.com"] });
  check("a signed POST without a fetched directory throws acme/no-directory",
        (await _acode(acme.finalize({ finalize: "https://ca.example.test/f", url: "https://ca.example.test/o" }, csr))) === "acme/no-directory");
}

async function testRevokeCertRejectsNonBuffer() {
  var acme = _handle();
  check("revokeCert refuses a non-Buffer cert argument",
        (await _acode(acme.revokeCert("not-a-buffer"))) === "acme/revoke-bad-cert");
}

async function testDeactivateAccountNeedsAccount() {
  var acme = _handle();
  check("deactivateAccount refuses before newAccount()",
        (await _acode(acme.deactivateAccount())) === "acme/no-account");
}

async function testChallengeUrlValidation() {
  var acme = _handle();
  check("fetchAuthorization refuses an empty authUrl",
        (await _acode(acme.fetchAuthorization(""))) === "acme/bad-auth-url");
  check("notifyChallengeReady refuses an empty challengeUrl",
        (await _acode(acme.notifyChallengeReady(""))) === "acme/bad-challenge-url");
}

async function testFetchAriRejectsUnparseableCert() {
  var acme = _handle();
  // Carries the BEGIN marker (clears the string check) but is not a
  // parseable X.509 — the second guard (X509 parse) must reject it.
  var fakePem = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----";
  check("fetchAri rejects a marker-bearing but unparseable certPem",
        (await _acode(acme.fetchAri({ certPem: fakePem }))) === "acme/bad-cert");
}

// ---- transport-stub helpers ---------------------------------------------

function _resp(status, headers, body) {
  return {
    statusCode: status,
    headers:    headers || {},
    body:       body === undefined ? "" : (typeof body === "string" ? body : JSON.stringify(body)),
  };
}

// Install a fake httpClient.request, run fn, always restore.
async function _withHttp(handler, fn) {
  var orig = httpClient.request;
  httpClient.request = handler;
  try { return await fn(); }
  finally { httpClient.request = orig; }
}

// A rolling replay-nonce header generator.
function _nonceState() {
  var n = 0;
  return function () { n += 1; return { "replay-nonce": "nonce-" + n }; };
}

// A capturing audit sink (audit.safeEmit shape).
function _auditSink() {
  var events = [];
  return { events: events, safeEmit: function (e) { events.push(e); } };
}

function _acme(opts) {
  var k = _newKey();
  var base = {
    directory:  CA + "/directory",
    accountKey: k.privateKey,
  };
  if (opts) { for (var key in opts) { if (Object.prototype.hasOwnProperty.call(opts, key)) base[key] = opts[key]; } }
  return b.acme.create(base);
}

// ---- self-signed cert builder (carries an AKI keyIdentifier) -----------
// Uses the framework's own DER writer so no external toolchain is needed.
// Node's X509Certificate parses structure without verifying the chain, so
// the self-signed shape is sufficient to drive AKI + serial extraction.

function _utcTime(s) { return asn1.writeNode(0x17, Buffer.from(s, "ascii")); }

// A default 4-byte serial; individual tests override it (e.g. a serial of 0
// to drive the odd-length-hex guard in _extractAkiAndSerial).
var _DEFAULT_SERIAL = Buffer.from([0x12, 0x34, 0x56, 0x78]);

// BasicConstraints with all-default fields — an empty SEQUENCE. Placing a
// non-AKI extension first lets the AKI walker exercise its skip path.
function _bcExt() {
  return asn1.writeSequence([
    asn1.writeOid("2.5.29.19"),                                                // id-ce-basicConstraints
    asn1.writeOctetString(asn1.writeSequence([])),
  ]);
}

// An AuthorityKeyIdentifier extension whose extnValue OCTET STRING wraps
// `innerOctetContent` verbatim. A well-formed AKI passes a SEQUENCE
// containing the keyIdentifier [0]; the malformed-shape tests pass raw
// non-SEQUENCE bytes to drive the walker's reject branches.
function _akiExt(innerOctetContent) {
  return asn1.writeSequence([
    asn1.writeOid("2.5.29.35"),                                               // id-ce-authorityKeyIdentifier
    asn1.writeOctetString(innerOctetContent),
  ]);
}

// Build a self-signed cert from an explicit serial + extension list. `exts`
// false/null omits the extensions [3] field entirely. Node's
// X509Certificate parses structure without verifying the chain, so the
// self-signed shape is sufficient to drive AKI + serial extraction.
function _buildCertGeneric(serial, exts) {
  var pair    = _newKey();
  var spkiDer = pair.publicKey.export({ type: "spki", format: "der" });
  var sigAlg  = asn1.writeSequence([asn1.writeOid("1.2.840.10045.4.3.2")]);   // ecdsa-with-SHA256
  var cnAttr  = asn1.writeSequence([asn1.writeOid("2.5.4.3"), asn1.writePrintableString("acme-ari-test")]);
  var name    = asn1.writeSequence([asn1.writeSet([cnAttr])]);
  var validity = asn1.writeSequence([_utcTime("250101000000Z"), _utcTime("350101000000Z")]);
  var tbsChildren = [
    asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2]))),          // version v3
    asn1.writeInteger(serial),                                                  // serialNumber
    sigAlg, name, validity, name, spkiDer,
  ];
  if (exts) tbsChildren.push(asn1.writeContextExplicit(3, asn1.writeSequence(exts)));
  var tbs = asn1.writeSequence(tbsChildren);
  var signer = nodeCrypto.createSign("SHA256");
  signer.update(tbs);
  var sig = signer.sign(pair.privateKey);
  var cert = asn1.writeSequence([tbs, sigAlg, asn1.writeBitString(sig, 0)]);
  return "-----BEGIN CERTIFICATE-----\n" +
    cert.toString("base64").match(/.{1,64}/g).join("\n") +
    "\n-----END CERTIFICATE-----\n";
}

// A well-formed cert: BasicConstraints followed (optionally) by an AKI
// carrying keyIdentifier [0]. keyIdBytes null -> no AKI extension.
function _buildCert(keyIdBytes) {
  var exts = [_bcExt()];
  if (keyIdBytes) {
    exts.push(_akiExt(asn1.writeSequence([asn1.writeContextImplicit(0, keyIdBytes)])));   // [0] keyIdentifier
  }
  return _buildCertGeneric(_DEFAULT_SERIAL, exts);
}

// A cert WITH an AKI keyIdentifier; built once, reused across ARI tests.
var CERT_WITH_AKI = _buildCert(Buffer.from("0102030405060708090a0b0c0d0e0f1011121314", "hex"));
var CERT_NO_AKI   = _buildCert(null);

// Adversarial cert variants driving _extractAkiAndSerial + the AKI walker.
//   - serial 0 renders as odd-length hex ("0") -> malformed-serial guard.
//   - no extensions [3] field -> the walker finds no extensions node.
//   - AKI with only authorityCertSerialNumber [2] -> no keyIdentifier [0].
//   - AKI OCTET STRING that is an un-parseable TLV / a primitive (NULL) /
//     a SEQUENCE with a truncated inner body -> the walker's parse-guard
//     continue branches.
var CERT_SERIAL_ZERO           = _buildCertGeneric(Buffer.from([0x00]), [_bcExt()]);
var CERT_NO_EXTENSIONS         = _buildCertGeneric(_DEFAULT_SERIAL, null);
var CERT_AKI_NO_KEYID          = _buildCertGeneric(_DEFAULT_SERIAL,
  [_bcExt(), _akiExt(asn1.writeSequence([asn1.writeContextImplicit(2, Buffer.from([0x01, 0x02]))]))]);
var CERT_AKI_OCTET_UNPARSEABLE = _buildCertGeneric(_DEFAULT_SERIAL,
  [_bcExt(), _akiExt(Buffer.from([0x30, 0x82, 0xff, 0xff]))]);
var CERT_AKI_OCTET_NOT_SEQ     = _buildCertGeneric(_DEFAULT_SERIAL,
  [_bcExt(), _akiExt(Buffer.from([0x05, 0x00]))]);
var CERT_AKI_INNER_BAD         = _buildCertGeneric(_DEFAULT_SERIAL,
  [_bcExt(), _akiExt(Buffer.from([0x30, 0x02, 0x30, 0x05]))]);

// ---- directory shapes ---------------------------------------------------

function _fullDir() {
  return {
    newNonce:    CA + "/new-nonce",
    newAccount:  CA + "/new-account",
    newOrder:    CA + "/new-order",
    keyChange:   CA + "/key-change",
    revokeCert:  CA + "/revoke-cert",
    renewalInfo: CA + "/renewal-info",
    meta:        { profiles: { def: "Standard 90-day", short: "47-day", broken: 42 } },
  };
}

// ---- create(): provided-numeric-opt branches ---------------------------

function testCreateNumericOpts() {
  var acme = _acme({
    timeoutMs:      C.TIME.seconds(10),
    pollIntervalMs: C.TIME.seconds(1),
    pollMaxMs:      C.TIME.minutes(2),
    maxBytes:       C.BYTES.mib(1),
  });
  check("create honors explicit timeout / poll / maxBytes opts (handle still built)",
        typeof acme.newAccount === "function" && typeof acme.fetchAri === "function");
}

// ---- fetchDirectory: status + shape + JSON guards -----------------------

async function testFetchDirectoryStatusAndShape() {
  var acme = _acme();
  await _withHttp(function () { return Promise.resolve(_resp(500, {}, "")); }, async function () {
    check("fetchDirectory non-200 -> acme/directory-fetch",
          (await _acode(acme.fetchDirectory())) === "acme/directory-fetch");
  });

  var acme2 = _acme();
  await _withHttp(function () {
    return Promise.resolve(_resp(200, {}, { newNonce: CA + "/n", newAccount: CA + "/a" }));   // missing newOrder
  }, async function () {
    check("fetchDirectory missing required field -> acme/directory-shape",
          (await _acode(acme2.fetchDirectory())) === "acme/directory-shape");
  });

  var acme3 = _acme();
  await _withHttp(function () { return Promise.resolve(_resp(200, {}, "5")); }, async function () {
    check("fetchDirectory non-object JSON body -> acme/bad-json",
          (await _acode(acme3.fetchDirectory())) === "acme/bad-json");
  });

  var acme4 = _acme();
  await _withHttp(function () { return Promise.resolve(_resp(200, {}, "not json at all")); }, async function () {
    check("fetchDirectory invalid JSON body -> acme/bad-json",
          (await _acode(acme4.fetchDirectory())) === "acme/bad-json");
  });
}

async function testFetchDirectoryNetworkError() {
  var acme = _acme();
  await _withHttp(function () { return Promise.reject(new Error("ECONNREFUSED")); }, async function () {
    check("fetchDirectory transport throw -> acme/network",
          (await _acode(acme.fetchDirectory())) === "acme/network");
  });
}

async function testFetchDirectorySuccessBranches() {
  // With renewalInfo -> hasAri true; capitalized Replay-Nonce header read.
  var sink = _auditSink();
  var acme = _acme({ audit: sink });
  await _withHttp(function () {
    return Promise.resolve(_resp(200, { "Replay-Nonce": "cap-nonce-1" }, _fullDir()));
  }, async function () {
    var dir = await acme.fetchDirectory();
    check("fetchDirectory success returns the directory body", dir && dir.newOrder === CA + "/new-order");
    check("fetchDirectory getter now returns the cached directory", acme.directory() && acme.directory().newNonce === CA + "/new-nonce");
  });
  check("fetchDirectory emits acme.directory.fetched success audit",
        sink.events.some(function (e) { return e.action === "acme.directory.fetched" && e.outcome === "success" && e.metadata.hasAri === true; }));

  // Without renewalInfo -> hasAri false. Audit sink lacking safeEmit hits
  // the _emitAudit early-return branch.
  var noAri = _fullDir(); delete noAri.renewalInfo;
  var acme2 = _acme({ audit: {} });
  await _withHttp(function () { return Promise.resolve(_resp(200, {}, noAri)); }, async function () {
    var dir = await acme2.fetchDirectory();
    check("fetchDirectory (no renewalInfo) still succeeds", dir && typeof dir.newOrder === "string");
  });
}

// ---- newAccount: EAB, failure, location branches ------------------------

function _accountHandler(dir, acctResp) {
  var nonce = _nonceState();
  return function (req) {
    var h = nonce();
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, dir));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/new-account") !== -1) {
      var merged = Object.assign(h, acctResp.headers || {});
      return Promise.resolve(_resp(acctResp.status, merged, acctResp.body === undefined ? { status: "valid" } : acctResp.body));
    }
    return Promise.resolve(_resp(404, h, ""));
  };
}

async function testNewAccountEabValidation() {
  var acme = _acme();
  await _withHttp(_accountHandler(_fullDir(), { status: 201, headers: { location: CA + "/acct/1" } }), async function () {
    check("newAccount EAB missing kid -> acme/eab-no-kid",
          (await _acode(acme.newAccount({ externalAccountBinding: { hmacKey: "AAAA" } }))) === "acme/eab-no-kid");
    check("newAccount EAB missing hmacKey -> acme/eab-no-hmac",
          (await _acode(acme.newAccount({ externalAccountBinding: { kid: "kid-1" } }))) === "acme/eab-no-hmac");
  });
}

async function testNewAccountEabSuccess() {
  var acme = _acme();
  var captured = { body: null };
  var handler = function (req) {
    var h = { "replay-nonce": "n" + Math.random() };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/new-account") !== -1) {
      captured.body = req.body;
      h.location = CA + "/acct/eab";
      return Promise.resolve(_resp(201, h, { status: "valid" }));
    }
    return Promise.resolve(_resp(404, h, ""));
  };
  await _withHttp(handler, async function () {
    var hmac = Buffer.from("super-secret-hmac-key").toString("base64url");
    var res = await acme.newAccount({ externalAccountBinding: { kid: "kid-xyz", hmacKey: hmac } });
    check("newAccount with EAB resolves to an account URL", res && res.accountUrl === CA + "/acct/eab");
  });
  var outer = JSON.parse(captured.body);
  var payload = JSON.parse(Buffer.from(outer.payload, "base64url").toString("utf8"));
  check("newAccount EAB embeds externalAccountBinding in the account payload",
        payload.externalAccountBinding && typeof payload.externalAccountBinding.signature === "string" &&
        typeof payload.externalAccountBinding.protected === "string");
}

async function testNewAccountFailureBranches() {
  // Failure status carrying a problem+json `type` -> extractProblemReason.
  var sink = _auditSink();
  var acme = _acme({ audit: sink });
  await _withHttp(_accountHandler(_fullDir(), { status: 403, body: { type: "urn:ietf:params:acme:error:unauthorized" } }),
    async function () {
      check("newAccount non-2xx -> acme/newaccount",
            (await _acode(acme.newAccount())) === "acme/newaccount");
    });
  check("newAccount failure audit records the RFC 7807 type as reason",
        sink.events.some(function (e) { return e.action === "acme.account.registered" && e.outcome === "failure" &&
          e.metadata.reason === "urn:ietf:params:acme:error:unauthorized"; }));

  // 2xx but no Location header.
  var acme2 = _acme();
  await _withHttp(_accountHandler(_fullDir(), { status: 200, body: { status: "valid" } }), async function () {
    check("newAccount 200 without Location -> acme/newaccount-no-location",
          (await _acode(acme2.newAccount())) === "acme/newaccount-no-location");
  });

  // Failure whose body is unparseable JSON -> _extractProblemReason swallows
  // the parse error and records reason null (the catch branch).
  var sink3 = _auditSink();
  var acme3 = _acme({ audit: sink3 });
  await _withHttp(_accountHandler(_fullDir(), { status: 500, body: "not-json-at-all" }), async function () {
    check("newAccount failure with an unparseable body still throws acme/newaccount",
          (await _acode(acme3.newAccount())) === "acme/newaccount");
  });
  check("newAccount failure audit reason is null when the body is not RFC 7807 JSON",
        sink3.events.some(function (e) { return e.action === "acme.account.registered" && e.outcome === "failure" && e.metadata.reason === null; }));
}

async function testNewAccountSuccessWithContact() {
  var sink = _auditSink();
  var acme = _acme({ audit: sink, contact: ["mailto:ops@example.com"] });
  await _withHttp(_accountHandler(_fullDir(), { status: 201, headers: { "Location": CA + "/acct/9" }, body: { status: "valid" } }),
    async function () {
      var res = await acme.newAccount();
      check("newAccount success returns accountUrl + body", res.accountUrl === CA + "/acct/9" && res.body && res.body.status === "valid");
      check("accountUrl() getter now reflects the registered account", acme.accountUrl() === CA + "/acct/9");
    });
  check("newAccount success audit carries the contact list",
        sink.events.some(function (e) { return e.action === "acme.account.registered" && e.outcome === "success" &&
          Array.isArray(e.metadata.contact) && e.metadata.contact[0] === "mailto:ops@example.com"; }));
}

// ---- _newNonce: HEAD path (nonce not pre-seeded) ------------------------

function _noSeedNonceHandler(dir, headResp, revokeResp) {
  return function (req) {
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, {}, dir));   // no nonce header
    if (req.method === "HEAD") return Promise.resolve(headResp);
    if (req.method === "POST" && req.url.indexOf("/revoke-cert") !== -1) return Promise.resolve(revokeResp || _resp(200, {}, ""));
    return Promise.resolve(_resp(404, {}, ""));
  };
}

async function testNewNonceHeadBranches() {
  var der = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x05]);   // trivial DER cert bytes for revoke

  var acme1 = _acme();
  await _withHttp(_noSeedNonceHandler(_fullDir(), _resp(500, {}, "")), async function () {
    check("newNonce HEAD non-200 -> acme/newnonce-failed",
          (await _acode(acme1.revokeCert(der))) === "acme/newnonce-failed");
  });

  var acme2 = _acme();
  await _withHttp(_noSeedNonceHandler(_fullDir(), _resp(200, {}, "")), async function () {
    check("newNonce HEAD 200 without Replay-Nonce -> acme/newnonce-no-header",
          (await _acode(acme2.revokeCert(der))) === "acme/newnonce-no-header");
  });

  var acme3 = _acme();
  await _withHttp(_noSeedNonceHandler(_fullDir(), _resp(200, { "replay-nonce": "fresh-1" }, ""), _resp(200, {}, "")), async function () {
    check("newNonce HEAD 200 + Replay-Nonce feeds a successful revoke",
          (await acme3.revokeCert(der)) === true);
  });
}

// ---- newOrder: guards + success -----------------------------------------

function _orderHandler(dir, orderResp) {
  var nonce = _nonceState();
  return function (req) {
    var h = nonce();
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, dir));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/new-account") !== -1) {
      h.location = CA + "/acct/1";
      return Promise.resolve(_resp(201, h, { status: "valid" }));
    }
    if (req.method === "POST" && req.url.indexOf("/new-order") !== -1) {
      var merged = Object.assign(h, orderResp.headers || {});
      return Promise.resolve(_resp(orderResp.status, merged, orderResp.body === undefined ? { status: "pending" } : orderResp.body));
    }
    return Promise.resolve(_resp(404, h, ""));
  };
}

async function testNewOrderGuards() {
  var acme = _acme();
  // No account yet (directory not fetched either) -> newOrder auto-fetches
  // directory, then trips the no-account guard.
  await _withHttp(_orderHandler(_fullDir(), { status: 201 }), async function () {
    check("newOrder before newAccount -> acme/no-account",
          (await _acode(acme.newOrder({ identifiers: [{ type: "dns", value: "x.com" }] }))) === "acme/no-account");
  });

  var acme2 = _acme();
  await _withHttp(_orderHandler(_fullDir(), { status: 201 }), async function () {
    await acme2.newAccount();
    check("newOrder without identifiers -> acme/bad-order",
          (await _acode(acme2.newOrder({}))) === "acme/bad-order");
    check("newOrder with empty identifiers -> acme/bad-order",
          (await _acode(acme2.newOrder({ identifiers: [] }))) === "acme/bad-order");
    check("newOrder with a malformed identifier -> acme/bad-identifier",
          (await _acode(acme2.newOrder({ identifiers: [{ type: "dns" }] }))) === "acme/bad-identifier");
    check("newOrder with an over-length identifier -> acme/bad-identifier",
          (await _acode(acme2.newOrder({ identifiers: [{ type: "dns", value: "a".repeat(300) }] }))) === "acme/bad-identifier");
    check("newOrder with a non-string profile -> acme/bad-profile",
          (await _acode(acme2.newOrder({ identifiers: [{ type: "dns", value: "x.com" }], profile: 42 }))) === "acme/bad-profile");
    check("newOrder with an empty profile string -> acme/bad-profile",
          (await _acode(acme2.newOrder({ identifiers: [{ type: "dns", value: "x.com" }], profile: "" }))) === "acme/bad-profile");
    check("newOrder with an over-length profile -> acme/bad-profile",
          (await _acode(acme2.newOrder({ identifiers: [{ type: "dns", value: "x.com" }], profile: "p".repeat(80) }))) === "acme/bad-profile");
  });
}

async function testNewOrderFailureAndSuccess() {
  var sink = _auditSink();
  var acme = _acme({ audit: sink });
  await _withHttp(_orderHandler(_fullDir(), { status: 400, body: { detail: "policy refused" } }), async function () {
    await acme.newAccount();
    check("newOrder non-201 -> acme/neworder",
          (await _acode(acme.newOrder({ identifiers: [{ type: "dns", value: "x.com" }] }))) === "acme/neworder");
  });
  check("newOrder failure audit extracts RFC 7807 detail",
        sink.events.some(function (e) { return e.action === "acme.order.created" && e.outcome === "failure" && e.metadata.reason === "policy refused"; }));

  var sink2 = _auditSink();
  var acme2 = _acme({ audit: sink2 });
  await _withHttp(_orderHandler(_fullDir(), { status: 201, headers: { location: CA + "/order/77" }, body: { status: "pending", finalize: CA + "/finalize/77" } }),
    async function () {
      await acme2.newAccount();
      var order = await acme2.newOrder({
        identifiers: [{ type: "dns", value: "good.com" }],
        notBefore:   "2026-01-01T00:00:00Z",
        notAfter:    "2026-04-01T00:00:00Z",
        profile:     "short",
      });
      check("newOrder success returns the order with its url", order.url === CA + "/order/77" && order.finalize === CA + "/finalize/77");
    });
  check("newOrder success emits acme.order.created success audit",
        sink2.events.some(function (e) { return e.action === "acme.order.created" && e.outcome === "success"; }));
}

// ---- finalize: network success + failure --------------------------------

function _finalizeHandler(finalizeResp) {
  var nonce = _nonceState();
  return function (req) {
    var h = nonce();
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/finalize") !== -1) return Promise.resolve(_resp(finalizeResp.status, h, finalizeResp.body));
    return Promise.resolve(_resp(404, h, ""));
  };
}

async function testFinalizeNetworkBranches() {
  var pair = _newKey();
  var sink = _auditSink();
  var acme = _acme({ audit: sink });
  var csr  = acme.buildCsr({ privateKey: pair.privateKey, publicKey: pair.publicKey, domains: ["f.example.com"] });
  var order = { finalize: CA + "/finalize/1", url: CA + "/order/1" };

  await _withHttp(_finalizeHandler({ status: 200, body: { status: "processing" } }), async function () {
    await acme.fetchDirectory();
    var updated = await acme.finalize(order, csr);
    check("finalize success returns the updated order carrying its url", updated.url === CA + "/order/1" && updated.status === "processing");
  });
  check("finalize success emits acme.order.finalize success audit",
        sink.events.some(function (e) { return e.action === "acme.order.finalize" && e.outcome === "success"; }));

  var sink2 = _auditSink();
  var acme2 = _acme({ audit: sink2 });
  await _withHttp(_finalizeHandler({ status: 400, body: { title: "bad CSR" } }), async function () {
    await acme2.fetchDirectory();
    check("finalize non-2xx -> acme/finalize",
          (await _acode(acme2.finalize(order, Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00])))) === "acme/finalize");
  });
  check("finalize failure audit extracts RFC 7807 title",
        sink2.events.some(function (e) { return e.action === "acme.order.finalize" && e.outcome === "failure" && e.metadata.reason === "bad CSR"; }));
}

// ---- retrieveCert: polling + download branches --------------------------

var PEM_CERT = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

async function testRetrieveCertBadOrder() {
  var acme = _acme();
  check("retrieveCert without order.url -> acme/bad-order",
        (await _acode(acme.retrieveCert({}))) === "acme/bad-order");
}

async function testRetrieveCertImmediateValid() {
  var sink = _auditSink();
  var acme = _acme({ audit: sink });
  var handler = function (req) {
    var h = { "replay-nonce": "n-" + Math.random() };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/cert/1") !== -1) return Promise.resolve(_resp(200, h, PEM_CERT));
    return Promise.resolve(_resp(404, h, ""));
  };
  await _withHttp(handler, async function () {
    await acme.fetchDirectory();
    var order = { url: CA + "/order/1", status: "valid", certificate: CA + "/cert/1" };
    var pem = await acme.retrieveCert(order);
    check("retrieveCert (already valid) downloads the PEM", pem.indexOf("-----BEGIN CERTIFICATE-----") === 0);
  });
  check("retrieveCert success emits acme.cert.issued success audit",
        sink.events.some(function (e) { return e.action === "acme.cert.issued" && e.outcome === "success"; }));
}

async function testRetrieveCertInvalidOrder() {
  var sink = _auditSink();
  var acme = _acme({ audit: sink });
  check("retrieveCert on an invalid order -> acme/order-invalid",
        (await _acode(acme.retrieveCert({ url: CA + "/order/x", status: "invalid" }))) === "acme/order-invalid");
  check("retrieveCert invalid emits acme.order.poll failure audit",
        sink.events.some(function (e) { return e.action === "acme.order.poll" && e.outcome === "failure"; }));
}

async function testRetrieveCertPollToValid() {
  var acme = _acme({ pollIntervalMs: 1, pollMaxMs: C.TIME.seconds(5) });
  var polls = 0;
  var handler = function (req) {
    var h = { "replay-nonce": "n-" + Math.random() };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/order/poll") !== -1) {
      polls += 1;
      if (polls < 2) return Promise.resolve(_resp(200, h, { status: "pending" }));
      return Promise.resolve(_resp(200, h, { status: "valid", certificate: CA + "/cert/poll" }));
    }
    if (req.method === "POST" && req.url.indexOf("/cert/poll") !== -1) return Promise.resolve(_resp(200, h, PEM_CERT));
    return Promise.resolve(_resp(404, h, ""));
  };
  await _withHttp(handler, async function () {
    await acme.fetchDirectory();
    var pem = await acme.retrieveCert({ url: CA + "/order/poll", status: "pending" });
    check("retrieveCert polls pending->valid then downloads", pem.indexOf("-----BEGIN CERTIFICATE-----") === 0 && polls >= 2);
  });
}

async function testRetrieveCertPollNon2xx() {
  var acme = _acme({ pollIntervalMs: 1, pollMaxMs: C.TIME.seconds(5) });
  var handler = function (req) {
    var h = { "replay-nonce": "n-" + Math.random() };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/order/pollerr") !== -1) return Promise.resolve(_resp(500, h, ""));
    return Promise.resolve(_resp(404, h, ""));
  };
  await _withHttp(handler, async function () {
    await acme.fetchDirectory();
    check("retrieveCert poll non-2xx -> acme/order-poll",
          (await _acode(acme.retrieveCert({ url: CA + "/order/pollerr", status: "pending" }))) === "acme/order-poll");
  });
}

async function testRetrieveCertTimeout() {
  var acme = _acme({ pollIntervalMs: 5, pollMaxMs: 40 });
  var handler = function (req) {
    var h = { "replay-nonce": "n-" + Math.random() };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/order/slow") !== -1) return Promise.resolve(_resp(200, h, { status: "pending" }));
    return Promise.resolve(_resp(404, h, ""));
  };
  await _withHttp(handler, async function () {
    await acme.fetchDirectory();
    check("retrieveCert never-valid -> acme/order-timeout",
          (await _acode(acme.retrieveCert({ url: CA + "/order/slow", status: "pending" }))) === "acme/order-timeout");
  });
}

async function testRetrieveCertDownloadBranches() {
  var sink = _auditSink();
  var acme = _acme({ audit: sink });
  var handler = function (req) {
    var h = { "replay-nonce": "n-" + Math.random() };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/cert/500") !== -1) return Promise.resolve(_resp(500, h, ""));
    if (req.method === "POST" && req.url.indexOf("/cert/notpem") !== -1) return Promise.resolve(_resp(200, h, "this is not a certificate"));
    return Promise.resolve(_resp(404, h, ""));
  };
  await _withHttp(handler, async function () {
    await acme.fetchDirectory();
    check("retrieveCert download non-200 -> acme/cert-download",
          (await _acode(acme.retrieveCert({ url: CA + "/order/a", status: "valid", certificate: CA + "/cert/500" }))) === "acme/cert-download");
    check("retrieveCert download non-PEM body -> acme/bad-cert-bytes",
          (await _acode(acme.retrieveCert({ url: CA + "/order/b", status: "valid", certificate: CA + "/cert/notpem" }))) === "acme/bad-cert-bytes");
  });
  check("retrieveCert download failure emits acme.cert.issued failure audit",
        sink.events.some(function (e) { return e.action === "acme.cert.issued" && e.outcome === "failure"; }));
}

// ---- authorization flow -------------------------------------------------

function _authHandler(map) {
  var nonce = _nonceState();
  return function (req) {
    var h = nonce();
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    for (var key in map) {
      if (Object.prototype.hasOwnProperty.call(map, key) && req.url.indexOf(key) !== -1) {
        var r = map[key](req);
        return Promise.resolve(_resp(r.status, h, r.body));
      }
    }
    return Promise.resolve(_resp(404, h, ""));
  };
}

async function testAuthorizationFlow() {
  var acme = _acme();
  await _withHttp(_authHandler({
    "/auth/ok":  function () { return { status: 200, body: { status: "pending", challenges: [{ type: "http-01", url: CA + "/chal/1", token: "tok" }] } }; },
    "/auth/err": function () { return { status: 500, body: "" }; },
    "/chal/ok":  function () { return { status: 200, body: { status: "processing" } }; },
    "/chal/err": function () { return { status: 403, body: "" }; },
  }), async function () {
    await acme.fetchDirectory();
    var auth = await acme.fetchAuthorization(CA + "/auth/ok");
    check("fetchAuthorization returns the auth object with its url", auth.url === CA + "/auth/ok" && Array.isArray(auth.challenges));
    check("fetchAuthorization non-2xx -> acme/auth-fetch",
          (await _acode(acme.fetchAuthorization(CA + "/auth/err"))) === "acme/auth-fetch");
    var updated = await acme.notifyChallengeReady(CA + "/chal/ok");
    check("notifyChallengeReady returns the updated challenge", updated.status === "processing");
    check("notifyChallengeReady non-2xx -> acme/challenge-ready",
          (await _acode(acme.notifyChallengeReady(CA + "/chal/err"))) === "acme/challenge-ready");
  });
}

async function testWaitForAuthorization() {
  // valid immediately (default interval/deadline branch).
  var acme = _acme();
  await _withHttp(_authHandler({ "/auth/valid": function () { return { status: 200, body: { status: "valid" } }; } }), async function () {
    await acme.fetchDirectory();
    var auth = await acme.waitForAuthorization(CA + "/auth/valid");
    check("waitForAuthorization returns when status is valid", auth.status === "valid");
  });

  // invalid -> throw + audit.
  var sink = _auditSink();
  var acme2 = _acme({ audit: sink });
  await _withHttp(_authHandler({ "/auth/bad": function () { return { status: 200, body: { status: "invalid", challenges: [{ error: { detail: "dns failed" } }] } }; } }),
    async function () {
      await acme2.fetchDirectory();
      check("waitForAuthorization invalid -> acme/auth-invalid",
            (await _acode(acme2.waitForAuthorization(CA + "/auth/bad"))) === "acme/auth-invalid");
    });
  check("waitForAuthorization invalid emits acme.auth.poll failure audit",
        sink.events.some(function (e) { return e.action === "acme.auth.poll" && e.outcome === "failure"; }));

  // timeout (explicit intervalMs/timeoutMs opts branch).
  var acme3 = _acme();
  await _withHttp(_authHandler({ "/auth/slow": function () { return { status: 200, body: { status: "pending" } }; } }), async function () {
    await acme3.fetchDirectory();
    check("waitForAuthorization never-valid -> acme/auth-timeout",
          (await _acode(acme3.waitForAuthorization(CA + "/auth/slow", { intervalMs: 5, timeoutMs: 30 }))) === "acme/auth-timeout");
  });
}

// ---- fetchAri + renewIfDue ----------------------------------------------

function _ariHandler(dir, ariResponder) {
  var nonce = _nonceState();
  return function (req) {
    var h = nonce();
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, dir));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "GET" && req.url.indexOf("/renewal-info/") !== -1) {
      var r = ariResponder(req);
      return Promise.resolve({ statusCode: r.status, headers: Object.assign(h, r.headers || {}), body: typeof r.body === "string" ? r.body : JSON.stringify(r.body) });
    }
    return Promise.resolve(_resp(404, h, ""));
  };
}

async function testFetchAriGuards() {
  // Directory has no renewalInfo -> acme/no-ari.
  var noAri = _fullDir(); delete noAri.renewalInfo;
  var acme = _acme();
  await _withHttp(_ariHandler(noAri, function () { return { status: 200, body: {} }; }), async function () {
    check("fetchAri when directory lacks renewalInfo -> acme/no-ari",
          (await _acode(acme.fetchAri({ certPem: CERT_WITH_AKI }))) === "acme/no-ari");
  });

  // Cert without AKI -> acme/no-aki (extraction fails before network).
  var acme2 = _acme();
  await _withHttp(_ariHandler(_fullDir(), function () { return { status: 200, body: {} }; }), async function () {
    check("fetchAri on a cert with no AKI -> acme/no-aki",
          (await _acode(acme2.fetchAri({ certPem: CERT_NO_AKI }))) === "acme/no-aki");
  });

  // ARI GET non-200.
  var acme3 = _acme();
  await _withHttp(_ariHandler(_fullDir(), function () { return { status: 404, body: "" }; }), async function () {
    check("fetchAri ARI GET non-200 -> acme/ari-fetch",
          (await _acode(acme3.fetchAri({ certPem: CERT_WITH_AKI }))) === "acme/ari-fetch");
  });
}

async function _assertAriShape(label, body) {
  var acme = _acme();
  await _withHttp(_ariHandler(_fullDir(), function () { return { status: 200, body: body }; }), async function () {
    check("fetchAri " + label + " -> acme/ari-shape",
          (await _acode(acme.fetchAri({ certPem: CERT_WITH_AKI }))) === "acme/ari-shape");
  });
}

async function testFetchAriShapeGuards() {
  await _assertAriShape("missing suggestedWindow",  { foo: 1 });
  await _assertAriShape("non-string window bounds", { suggestedWindow: { start: 1, end: 2 } });
  await _assertAriShape("unparseable timestamps",   { suggestedWindow: { start: "nope", end: "also-nope" } });
  await _assertAriShape("end before start",         { suggestedWindow: { start: "2027-01-02T00:00:00Z", end: "2027-01-01T00:00:00Z" } });
}

async function testFetchAriSuccess() {
  var now = Date.now();
  var start = new Date(now - C.TIME.hours(1)).toISOString();
  var end   = new Date(now + C.TIME.hours(1)).toISOString();
  var acme = _acme();
  await _withHttp(_ariHandler(_fullDir(), function () {
    return { status: 200, headers: { "retry-after": "21600" }, body: { suggestedWindow: { start: start, end: end }, explanationURL: "https://ca.example.test/why" } };
  }), async function () {
    var ari = await acme.fetchAri({ certPem: CERT_WITH_AKI });
    check("fetchAri returns a certId derived from AKI + serial", typeof ari.certId === "string" && ari.certId.indexOf(".") > 0);
    check("fetchAri surfaces retry-after + explanationURL", ari.retryAfter === "21600" && ari.explanationURL === "https://ca.example.test/why");
    check("fetchAri parses the window into epoch ms", isFinite(ari.suggestedWindow.startMs) && isFinite(ari.suggestedWindow.endMs));
  });

  // retry-after absent + explanationURL non-string -> both normalize to null.
  var acme2 = _acme();
  await _withHttp(_ariHandler(_fullDir(), function () {
    return { status: 200, body: { suggestedWindow: { start: start, end: end }, explanationURL: 12345 } };
  }), async function () {
    var ari = await acme2.fetchAri({ certPem: CERT_WITH_AKI });
    check("fetchAri null retryAfter + null explanationURL when absent/non-string", ari.retryAfter === null && ari.explanationURL === null);
  });
}

function _ariWindowFake(startOffset, endOffset) {
  var now = Date.now();
  var start = new Date(now + startOffset).toISOString();
  var end   = new Date(now + endOffset).toISOString();
  return _ariHandler(_fullDir(), function () {
    return { status: 200, body: { suggestedWindow: { start: start, end: end } } };
  });
}

async function testRenewIfDueVerdicts() {
  var H = C.TIME.hours(1);

  // before-window
  var sink = _auditSink();
  var acme = _acme({ audit: sink });
  await _withHttp(_ariWindowFake(H, 2 * H), async function () {
    var v = await acme.renewIfDue({ certPem: CERT_WITH_AKI });
    check("renewIfDue before the window -> shouldRenew false, before-window", v.shouldRenew === false && v.reason === "before-window");
  });
  check("renewIfDue before-window emits acme.cert.renew.skipped audit",
        sink.events.some(function (e) { return e.action === "acme.cert.renew.skipped"; }));

  // in-window
  var acme2 = _acme();
  await _withHttp(_ariWindowFake(-H, H), async function () {
    var v = await acme2.renewIfDue({ certPem: CERT_WITH_AKI });
    check("renewIfDue inside the window -> shouldRenew true, in-window", v.shouldRenew === true && v.reason === "in-window");
  });

  // past-window
  var acme3 = _acme();
  await _withHttp(_ariWindowFake(-2 * H, -H), async function () {
    var v = await acme3.renewIfDue({ certPem: CERT_WITH_AKI });
    check("renewIfDue past the window -> shouldRenew true, past-window", v.shouldRenew === true && v.reason === "past-window");
  });
}

async function testRenewIfDueJitter() {
  var H = C.TIME.hours(1);

  // before-window + jitter -> renewAt is an ISO string within [start, end].
  var acme = _acme();
  await _withHttp(_ariWindowFake(H, 2 * H), async function () {
    var v = await acme.renewIfDue({ certPem: CERT_WITH_AKI, jitter: true });
    check("renewIfDue before-window jitter yields an ISO renewAt", v.shouldRenew === false && typeof v.renewAt === "string" &&
          isFinite(Date.parse(v.renewAt)));
  });

  // in-window + jitter.
  var acme2 = _acme();
  await _withHttp(_ariWindowFake(-H, H), async function () {
    var v = await acme2.renewIfDue({ certPem: CERT_WITH_AKI, jitter: true });
    check("renewIfDue in-window jitter yields an ISO renewAt", v.shouldRenew === true && typeof v.renewAt === "string");
  });

  // past-window + jitter -> jHi < jLo branch (renewAt == now).
  var acme3 = _acme();
  await _withHttp(_ariWindowFake(-2 * H, -H), async function () {
    var v = await acme3.renewIfDue({ certPem: CERT_WITH_AKI, jitter: true });
    check("renewIfDue past-window jitter yields an ISO renewAt", v.shouldRenew === true && typeof v.renewAt === "string");
  });
}

// ---- revokeCert branches ------------------------------------------------

function _revokeHandler(dir, revokeResp) {
  var nonce = _nonceState();
  return function (req) {
    var h = nonce();
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, dir));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/revoke-cert") !== -1) return Promise.resolve(_resp(revokeResp.status, h, revokeResp.body));
    return Promise.resolve(_resp(404, h, ""));
  };
}

async function testRevokeCertBranches() {
  var der = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x05]);

  // directory without revokeCert endpoint.
  var noRevoke = _fullDir(); delete noRevoke.revokeCert;
  var acme0 = _acme();
  await _withHttp(_revokeHandler(noRevoke, { status: 200, body: "" }), async function () {
    check("revokeCert when directory lacks revokeCert -> acme/revoke-not-supported",
          (await _acode(acme0.revokeCert(der))) === "acme/revoke-not-supported");
  });

  // useCertKey: true is a reserved/deferred path -> throws.
  var acme1 = _acme();
  await _withHttp(_revokeHandler(_fullDir(), { status: 200, body: "" }), async function () {
    check("revokeCert useCertKey:true -> acme/revoke-cert-key-not-implemented",
          (await _acode(acme1.revokeCert(der, { useCertKey: true }))) === "acme/revoke-cert-key-not-implemented");
  });

  // success with a reason code + Uint8Array input.
  var sink = _auditSink();
  var acme2 = _acme({ audit: sink });
  await _withHttp(_revokeHandler(_fullDir(), { status: 200, body: "" }), async function () {
    var ok = await acme2.revokeCert(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x04]), { reason: 4 });
    check("revokeCert (Uint8Array + reason) resolves true", ok === true);
  });
  check("revokeCert success emits acme.cert.revoked success audit",
        sink.events.some(function (e) { return e.action === "acme.cert.revoked" && e.outcome === "success"; }));

  // failure status with an empty body (extractProblemReason(null) branch).
  var sink2 = _auditSink();
  var acme3 = _acme({ audit: sink2 });
  await _withHttp(_revokeHandler(_fullDir(), { status: 409, body: "" }), async function () {
    check("revokeCert non-200 -> acme/revoke-failed",
          (await _acode(acme3.revokeCert(der))) === "acme/revoke-failed");
  });
  check("revokeCert failure emits acme.cert.revoked failure audit with null reason",
        sink2.events.some(function (e) { return e.action === "acme.cert.revoked" && e.outcome === "failure" && e.metadata.reason === null; }));
}

// ---- accountKeyRollover branches ----------------------------------------

async function testRolloverBranches() {
  // No account (directory fetched, but newAccount not called).
  var acme0 = _acme();
  await _withHttp(_orderHandler(_fullDir(), { status: 201 }), async function () {
    await acme0.fetchDirectory();
    check("accountKeyRollover before newAccount -> acme/no-account",
          (await _acode(acme0.accountKeyRollover(_newKey().privateKey))) === "acme/no-account");
  });

  // Account present but directory lacks keyChange.
  var noKc = _fullDir(); delete noKc.keyChange;
  var acme1 = _acme();
  await _withHttp(_accountHandler(noKc, { status: 201, headers: { location: CA + "/acct/1" } }), async function () {
    await acme1.newAccount();
    check("accountKeyRollover without keyChange endpoint -> acme/key-change-not-supported",
          (await _acode(acme1.accountKeyRollover(_newKey().privateKey))) === "acme/key-change-not-supported");
  });

  // Bad new key.
  var acme2 = _acme();
  await _withHttp(_accountHandler(_fullDir(), { status: 201, headers: { location: CA + "/acct/1" } }), async function () {
    await acme2.newAccount();
    check("accountKeyRollover with a non-object new key -> acme/bad-new-key",
          (await _acode(acme2.accountKeyRollover("not-a-key"))) === "acme/bad-new-key");
    // An object lacking a KeyObject export() reaches _publicJwkFromKeyObject.
    check("accountKeyRollover with a bare object (no export) -> acme/bad-account-key",
          (await _acode(acme2.accountKeyRollover({}))) === "acme/bad-account-key");
  });

  // keyChange POST failure.
  var sink = _auditSink();
  var acme3 = _acme({ audit: sink });
  var handler = function (req) {
    var h = { "replay-nonce": "n-" + Math.random() };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/new-account") !== -1) { h.location = CA + "/acct/1"; return Promise.resolve(_resp(201, h, { status: "valid" })); }
    if (req.method === "POST" && req.url.indexOf("/key-change") !== -1) return Promise.resolve(_resp(500, h, { detail: "rotation refused" }));
    return Promise.resolve(_resp(404, h, ""));
  };
  await _withHttp(handler, async function () {
    await acme3.newAccount();
    check("accountKeyRollover keyChange non-200 -> acme/key-change-failed",
          (await _acode(acme3.accountKeyRollover(_newKey().privateKey))) === "acme/key-change-failed");
  });
  check("accountKeyRollover failure emits acme.account.key_rotated failure audit",
        sink.events.some(function (e) { return e.action === "acme.account.key_rotated" && e.outcome === "failure"; }));
}

// ---- deactivateAccount + dnsAccount01 record success --------------------

async function testDeactivateBranches() {
  // failure.
  var sink = _auditSink();
  var acme = _acme({ audit: sink });
  var handlerFail = function (req) {
    var h = { "replay-nonce": "n-" + Math.random() };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/new-account") !== -1) { h.location = CA + "/acct/d"; return Promise.resolve(_resp(201, h, { status: "valid" })); }
    if (req.method === "POST" && req.url.indexOf("/acct/d") !== -1) return Promise.resolve(_resp(500, h, ""));
    return Promise.resolve(_resp(404, h, ""));
  };
  await _withHttp(handlerFail, async function () {
    await acme.newAccount();
    check("deactivateAccount non-200 -> acme/deactivate-failed",
          (await _acode(acme.deactivateAccount())) === "acme/deactivate-failed");
  });
  check("deactivateAccount failure emits audit", sink.events.some(function (e) { return e.action === "acme.account.deactivated" && e.outcome === "failure"; }));

  // success.
  var sink2 = _auditSink();
  var acme2 = _acme({ audit: sink2 });
  var handlerOk = function (req) {
    var h = { "replay-nonce": "n-" + Math.random() };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/new-account") !== -1) { h.location = CA + "/acct/e"; return Promise.resolve(_resp(201, h, { status: "valid" })); }
    if (req.method === "POST" && req.url.indexOf("/acct/e") !== -1) return Promise.resolve(_resp(200, h, { status: "deactivated" }));
    return Promise.resolve(_resp(404, h, ""));
  };
  await _withHttp(handlerOk, async function () {
    await acme2.newAccount();
    check("deactivateAccount success resolves true", (await acme2.deactivateAccount()) === true);
  });
  check("deactivateAccount success emits audit", sink2.events.some(function (e) { return e.action === "acme.account.deactivated" && e.outcome === "success"; }));
}

async function testDnsAccount01Success() {
  var acme = _acme();
  await _withHttp(_accountHandler(_fullDir(), { status: 201, headers: { location: CA + "/acct/dns" } }), async function () {
    await acme.newAccount();
    // ttl validation branch (after accountUrl guard).
    var threw = null;
    try { acme.dnsAccount01ChallengeRecord("tok", { identifier: "example.com", ttl: -5 }); }
    catch (e) { threw = e; }
    check("dnsAccount01ChallengeRecord rejects a negative ttl -> acme/bad-ttl", threw && threw.code === "acme/bad-ttl");
    var threw2 = null;
    try { acme.dnsAccount01ChallengeRecord("tok", { identifier: "example.com", ttl: 90000 }); }
    catch (e) { threw2 = e; }
    check("dnsAccount01ChallengeRecord rejects a ttl above 86400 -> acme/bad-ttl", threw2 && threw2.code === "acme/bad-ttl");

    var rec = acme.dnsAccount01ChallengeRecord("tok123", { identifier: "example.com" });
    check("dnsAccount01ChallengeRecord default ttl is 60", rec.ttl === 60);
    check("dnsAccount01ChallengeRecord name is _<label>._acme-challenge.<identifier>",
          /^_[a-z2-7]+\._acme-challenge\.example\.com$/.test(rec.name));
    check("dnsAccount01ChallengeRecord value is base64url", /^[A-Za-z0-9_-]+$/.test(rec.value));

    var rec2 = acme.dnsAccount01ChallengeRecord("tok123", { identifier: "example.com", ttl: 300 });
    check("dnsAccount01ChallengeRecord honors a provided ttl", rec2.ttl === 300);
  });
}

// ---- listProfiles branches ----------------------------------------------

async function testListProfiles() {
  // full map (string + non-string values).
  var acme = _acme();
  await _withHttp(function (req) {
    var h = { "replay-nonce": "n" };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    return Promise.resolve(_resp(404, h, ""));
  }, async function () {
    await acme.fetchDirectory();
    var p = acme.listProfiles();
    check("listProfiles surfaces advertised profile names", p.def === "Standard 90-day" && p.short === "47-day");
    check("listProfiles coerces a non-string profile description to \"\"", p.broken === "");
  });

  // meta not an object -> {}.
  var acme2 = _acme();
  var dirMetaBad = _fullDir(); dirMetaBad.meta = "x";
  await _withHttp(function (req) {
    var h = { "replay-nonce": "n" };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, dirMetaBad));
    return Promise.resolve(_resp(404, h, ""));
  }, async function () {
    await acme2.fetchDirectory();
    check("listProfiles with non-object meta -> {}", Object.keys(acme2.listProfiles()).length === 0);
  });

  // profiles not an object -> {}.
  var acme3 = _acme();
  var dirProfBad = _fullDir(); dirProfBad.meta = { profiles: 5 };
  await _withHttp(function (req) {
    var h = { "replay-nonce": "n" };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, dirProfBad));
    return Promise.resolve(_resp(404, h, ""));
  }, async function () {
    await acme3.fetchDirectory();
    check("listProfiles with non-object profiles -> {}", Object.keys(acme3.listProfiles()).length === 0);
  });
}

// ---- audit best-effort catch --------------------------------------------

async function testAuditThrowIsSwallowed() {
  var throwing = { safeEmit: function () { throw new Error("audit sink exploded"); } };
  var acme = _acme({ audit: throwing });
  await _withHttp(function (req) {
    var h = { "replay-nonce": "n" };
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    return Promise.resolve(_resp(404, h, ""));
  }, async function () {
    var dir = await acme.fetchDirectory();
    check("a throwing audit sink does not break fetchDirectory (best-effort emit)", dir && typeof dir.newOrder === "string");
  });
}

// ---- cert-variant driven _extractAkiAndSerial + AKI-walker rejections ----

async function testFetchAriSerialZeroCert() {
  // A serial of 0 renders as an odd-length hex string ("0"); the serial
  // guard in _extractAkiAndSerial refuses it before any network call.
  var acme = _acme();
  check("fetchAri on a serial-0 cert (odd-length hex serial) -> acme/bad-cert",
        (await _acode(acme.fetchAri({ certPem: CERT_SERIAL_ZERO }))) === "acme/bad-cert");
}

async function testFetchAriAkiWalkerRejections() {
  // Every malformed-AKI shape resolves to acme/no-aki (fail-closed) — the
  // walker never surfaces a truncated/garbage keyIdentifier as valid.
  var acme = _acme();
  check("fetchAri on a cert with no extensions field -> acme/no-aki",
        (await _acode(acme.fetchAri({ certPem: CERT_NO_EXTENSIONS }))) === "acme/no-aki");
  check("fetchAri on an AKI lacking keyIdentifier [0] -> acme/no-aki",
        (await _acode(acme.fetchAri({ certPem: CERT_AKI_NO_KEYID }))) === "acme/no-aki");
  check("fetchAri on an AKI whose octet content is an un-parseable TLV -> acme/no-aki",
        (await _acode(acme.fetchAri({ certPem: CERT_AKI_OCTET_UNPARSEABLE }))) === "acme/no-aki");
  check("fetchAri on an AKI whose octet content is a primitive (not a SEQUENCE) -> acme/no-aki",
        (await _acode(acme.fetchAri({ certPem: CERT_AKI_OCTET_NOT_SEQ }))) === "acme/no-aki");
  check("fetchAri on an AKI SEQUENCE with a truncated inner body -> acme/no-aki",
        (await _acode(acme.fetchAri({ certPem: CERT_AKI_INNER_BAD }))) === "acme/no-aki");
}

// ---- accountKeyRollover: auto-fetch, key-material failures, success ------

async function testRolloverAutoFetchesDirectory() {
  // A fresh handle (directory not yet fetched) must fetch it inside
  // accountKeyRollover before the no-account guard fires.
  var acme = _acme();
  await _withHttp(_orderHandler(_fullDir(), { status: 201 }), async function () {
    check("accountKeyRollover on a fresh handle fetches the directory then trips no-account",
          (await _acode(acme.accountKeyRollover(_newKey().privateKey))) === "acme/no-account");
    check("accountKeyRollover populated the directory cache during the auto-fetch",
          acme.directory() && acme.directory().keyChange === CA + "/key-change");
  });
}

async function testRolloverBadKeyMaterial() {
  var acme = _acme();
  await _withHttp(_accountHandler(_fullDir(), { status: 201, headers: { location: CA + "/acct/1" } }), async function () {
    await acme.newAccount();
    // A DH KeyObject exposes export() but export({format:"jwk"}) throws;
    // _publicJwkFromKeyObject surfaces acme/bad-account-key.
    var dh = nodeCrypto.generateKeyPairSync("dh", { group: "modp14" });
    check("accountKeyRollover with a non-EC key (jwk export throws) -> acme/bad-account-key",
          (await _acode(acme.accountKeyRollover(dh.privateKey))) === "acme/bad-account-key");
    // A P-256 *public* KeyObject passes the JWK shape check but cannot sign
    // the inner JWS -> the ES256 signer throws acme/sign-failed.
    var pub = _newKey().publicKey;
    check("accountKeyRollover with a public KeyObject (cannot sign) -> acme/sign-failed",
          (await _acode(acme.accountKeyRollover(pub))) === "acme/sign-failed");
  });
}

async function testRolloverSuccessSwapsKey() {
  var sink = _auditSink();
  var acme = _acme({ audit: sink });
  var captured = { keyChangeBody: null };
  var nonce = _nonceState();
  var handler = function (req) {
    var h = nonce();
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/new-account") !== -1) { h.location = CA + "/acct/roll"; return Promise.resolve(_resp(201, h, { status: "valid" })); }
    if (req.method === "POST" && req.url.indexOf("/key-change") !== -1) { captured.keyChangeBody = req.body; return Promise.resolve(_resp(200, h, { status: "valid" })); }
    return Promise.resolve(_resp(404, h, ""));
  };
  var newKey = _newKey();
  var newJwk = newKey.publicKey.export({ format: "jwk" });
  var oldX;
  await _withHttp(handler, async function () {
    await acme.newAccount();
    oldX = acme.publicJwk().x;
    var ok = await acme.accountKeyRollover(newKey.privateKey);
    check("accountKeyRollover success resolves true", ok === true);
    check("accountKeyRollover swaps publicJwk() to the new key",
          acme.publicJwk().x === newJwk.x && acme.publicJwk().y === newJwk.y && acme.publicJwk().x !== oldX);
  });
  // RFC 8555 §7.3.5 — the inner JWS is signed by the NEW key and commits
  // { account, oldKey } as its payload.
  var outer = JSON.parse(captured.keyChangeBody);
  var innerJws = JSON.parse(Buffer.from(outer.payload, "base64url").toString("utf8"));
  var innerProt = JSON.parse(Buffer.from(innerJws.protected, "base64url").toString("utf8"));
  var innerPayload = JSON.parse(Buffer.from(innerJws.payload, "base64url").toString("utf8"));
  check("rollover inner JWS protected header carries the NEW key jwk", innerProt.jwk && innerProt.jwk.x === newJwk.x);
  check("rollover inner JWS payload commits the OLD key + account url",
        innerPayload.oldKey && innerPayload.oldKey.x === oldX && innerPayload.account === CA + "/acct/roll");
  check("accountKeyRollover success emits acme.account.key_rotated success audit",
        sink.events.some(function (e) { return e.action === "acme.account.key_rotated" && e.outcome === "success"; }));
}

// ---- newOrder capitalized Location header --------------------------------

async function testNewOrderCapitalLocationHeader() {
  // A CA returning only a capitalized "Location" header still yields the
  // order URL (case-insensitive header read).
  var acme = _acme();
  await _withHttp(_orderHandler(_fullDir(), { status: 201, headers: { "Location": CA + "/order/cap" }, body: { status: "pending", finalize: CA + "/finalize/cap" } }), async function () {
    await acme.newAccount();
    var order = await acme.newOrder({ identifiers: [{ type: "dns", value: "cap.com" }] });
    check("newOrder reads a capitalized Location header for order.url", order.url === CA + "/order/cap");
  });
}

// ---- waitForAuthorization timeout using the client-default pollMaxMs -----

async function testWaitForAuthorizationDefaultTimeout() {
  var acme = _acme({ pollIntervalMs: 5, pollMaxMs: 30 });
  await _withHttp(_authHandler({ "/auth/pending": function () { return { status: 200, body: { status: "pending" } }; } }), async function () {
    await acme.fetchDirectory();
    check("waitForAuthorization with no opts times out via the client pollMaxMs -> acme/auth-timeout",
          (await _acode(acme.waitForAuthorization(CA + "/auth/pending"))) === "acme/auth-timeout");
  });
}

// ---- _parseJsonBody empty-body + Buffer-body branches --------------------

async function testParseJsonBodyEmptyAndBufferBranches() {
  var acme = _acme();
  var nonce = _nonceState();
  var handler = function (req) {
    var h = nonce();
    if (req.method === "GET" && req.url.indexOf("/directory") !== -1) return Promise.resolve(_resp(200, h, _fullDir()));
    if (req.method === "HEAD") return Promise.resolve(_resp(200, h, ""));
    if (req.method === "POST" && req.url.indexOf("/chal/empty-str") !== -1) return Promise.resolve({ statusCode: 200, headers: h, body: "" });
    if (req.method === "POST" && req.url.indexOf("/chal/buffer") !== -1) return Promise.resolve({ statusCode: 200, headers: h, body: Buffer.from(JSON.stringify({ status: "processing" }), "utf8") });
    if (req.method === "POST" && req.url.indexOf("/chal/empty-buf") !== -1) return Promise.resolve({ statusCode: 200, headers: h, body: Buffer.alloc(0) });
    return Promise.resolve(_resp(404, h, ""));
  };
  await _withHttp(handler, async function () {
    await acme.fetchDirectory();
    var emptyStr = await acme.notifyChallengeReady(CA + "/chal/empty-str");
    check("notifyChallengeReady with an empty-string body parses to {}", emptyStr && typeof emptyStr === "object" && emptyStr.status === undefined);
    var bufBody = await acme.notifyChallengeReady(CA + "/chal/buffer");
    check("notifyChallengeReady with a Buffer body parses the JSON", bufBody.status === "processing");
    var emptyBuf = await acme.notifyChallengeReady(CA + "/chal/empty-buf");
    check("notifyChallengeReady with an empty Buffer body parses to {}", emptyBuf && typeof emptyBuf === "object" && emptyBuf.status === undefined);
  });
}

// ---- _extractProblemReason with no recognized fields ---------------------

async function testExtractProblemReasonNoRecognizedFields() {
  var sink = _auditSink();
  var acme = _acme({ audit: sink });
  await _withHttp(_orderHandler(_fullDir(), { status: 400, body: { instance: "urn:x", extra: 7 } }), async function () {
    await acme.newAccount();
    check("newOrder failure with no type/detail/title still -> acme/neworder",
          (await _acode(acme.newOrder({ identifiers: [{ type: "dns", value: "x.com" }] }))) === "acme/neworder");
  });
  check("newOrder failure audit reason is null when the problem doc has no type/detail/title",
        sink.events.some(function (e) { return e.action === "acme.order.created" && e.outcome === "failure" && e.metadata.reason === null; }));
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
  testV0883NewSurface();
  testV0883Base32Helper();
  testV0883NewOrderProfileValidation();
  testCreateRefusesMissingDirectory();
  testCreateRefusesMissingAccountKey();
  testCreateRefusesPublicKeyObject();
  testCreateAcceptsPrivatePem();
  testCreateAcceptsNestedPrivateKey();
  testCreateRefusesBadPrivatePem();
  testCreateRefusesUnknownOpt();
  testCreateContactShapeBranches();
  testGettersNullBeforeLifecycle();
  testPublicJwkReturnsIsolatedCopy();
  testKeyAuthorizationDeterministicAndDistinct();
  testTlsAlpn01KeyAuthorization();
  testDnsAccount01ValidationBeforeAccount();
  testBuildCsrInputValidation();
  testBuildCsrP256();
  testBuildCsrP384();
  testBuildCsrRsa();
  testBuildCsrRejectsUnsupportedKeys();
  await testFinalizeValidation();
  await testSignedPostNeedsDirectory();
  await testRevokeCertRejectsNonBuffer();
  await testDeactivateAccountNeedsAccount();
  await testChallengeUrlValidation();
  await testFetchAriRejectsUnparseableCert();
  await testFetchAriSerialZeroCert();
  await testFetchAriAkiWalkerRejections();

  // acme's internal poll uses an unref'd timer (it must not pin a host
  // process). Standalone, that means the event loop can empty mid-poll and
  // Node would exit before run() resolves. A ref'd keep-alive timer holds
  // the loop open while the transport-stubbed tests below run; cleared in
  // finally so the process (and the forked smoke child) exits cleanly once
  // every check has run.
  var keepAlive = setInterval(function () {}, C.TIME.seconds(1));
  try {
    testCreateNumericOpts();
    await testFetchDirectoryStatusAndShape();
    await testFetchDirectoryNetworkError();
    await testFetchDirectorySuccessBranches();
    await testNewAccountEabValidation();
    await testNewAccountEabSuccess();
    await testNewAccountFailureBranches();
    await testNewAccountSuccessWithContact();
    await testNewNonceHeadBranches();
    await testNewOrderGuards();
    await testNewOrderFailureAndSuccess();
    await testFinalizeNetworkBranches();
    await testRetrieveCertBadOrder();
    await testRetrieveCertImmediateValid();
    await testRetrieveCertInvalidOrder();
    await testRetrieveCertPollToValid();
    await testRetrieveCertPollNon2xx();
    await testRetrieveCertTimeout();
    await testRetrieveCertDownloadBranches();
    await testAuthorizationFlow();
    await testWaitForAuthorization();
    await testFetchAriGuards();
    await testFetchAriShapeGuards();
    await testFetchAriSuccess();
    await testRenewIfDueVerdicts();
    await testRenewIfDueJitter();
    await testRevokeCertBranches();
    await testRolloverBranches();
    await testDeactivateBranches();
    await testDnsAccount01Success();
    await testListProfiles();
    await testAuditThrowIsSwallowed();
    await testRolloverAutoFetchesDirectory();
    await testRolloverBadKeyMaterial();
    await testRolloverSuccessSwapsKey();
    await testNewOrderCapitalLocationHeader();
    await testWaitForAuthorizationDefaultTimeout();
    await testParseJsonBodyEmptyAndBufferBranches();
    await testExtractProblemReasonNoRecognizedFields();
  } finally {
    clearInterval(keepAlive);
  }
}

module.exports = { run: run };

// Allow direct execution: `node test/layer-0-primitives/acme.test.js`
if (require.main === module) {
  run().then(function () {
    console.log("OK — acme " + helpers.getChecks() + " checks passed");
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exit(1);
  });
}
