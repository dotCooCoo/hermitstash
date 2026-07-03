// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.acme — additional coverage for the config-time validation surface,
 * the pure PKCS#10 CSR builder, and the offline-reachable order /
 * challenge / revoke / deactivate guards.
 *
 * Companion to acme.test.js: that file pins the create-time refusals,
 * keyAuthorization shape, AKI/serial refusal, and the v0.8.83 surface.
 * This file drives the branches those tests leave uncovered — every
 * assertion runs offline (no CA round-trip): create() key-normalization
 * paths, buildCsr across P-256 / P-384 / RSA (with signature
 * verification), and the validation throws that fire before any signed
 * POST leaves the process.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var nodeCrypto = require("node:crypto");

function _newKey() {
  return nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
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

async function run() {
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
}

module.exports = { run: run };

// Allow direct execution: `node test/layer-0-primitives/acme-coverage.test.js`
if (require.main === module) {
  run().then(function () {
    console.log("OK — acme-coverage " + helpers.getChecks() + " checks passed");
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exit(1);
  });
}
