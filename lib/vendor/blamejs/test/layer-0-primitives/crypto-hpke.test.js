"use strict";
/**
 * b.crypto.hpke — RFC 9180 Hybrid Public-Key Encryption.
 *
 * Suite: ML-KEM-1024 + HKDF-SHA3-512 + ChaCha20-Poly1305. Round-trip
 * + AAD binding + suite-id binding (info string changes derive a
 * different key) + tampered-ciphertext rejection.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("crypto.hpke namespace exposed",
        b.crypto.hpke && typeof b.crypto.hpke === "object");
  check("crypto.hpke.seal is a function",
        typeof b.crypto.hpke.seal === "function");
  check("crypto.hpke.open is a function",
        typeof b.crypto.hpke.open === "function");
  check("crypto.hpke.generateKeyPair is a function",
        typeof b.crypto.hpke.generateKeyPair === "function");
  check("crypto.hpke.SUPPORTED_SUITE describes ML-KEM-1024",
        b.crypto.hpke.SUPPORTED_SUITE.kem === "ML-KEM-1024");
  check("crypto.hpke.HpkeError is a class",
        typeof b.crypto.hpke.HpkeError === "function");
}

function testRoundTrip() {
  var pair = b.crypto.hpke.generateKeyPair();
  check("generateKeyPair returns ML-KEM-1024 PEMs",
        typeof pair.publicKey === "string" &&
        /^-----BEGIN PUBLIC KEY-----/.test(pair.publicKey) &&
        typeof pair.privateKey === "string" &&
        /^-----BEGIN PRIVATE KEY-----/.test(pair.privateKey));

  var pt = "hello hpke";
  var sealed = b.crypto.hpke.seal({
    recipientPubKey: pair.publicKey,
    plaintext:       pt,
    info:            "session-1",
    aad:             "tenant-acme",
  });
  check("seal returns Buffer enc + ciphertext",
        Buffer.isBuffer(sealed.enc) && Buffer.isBuffer(sealed.ciphertext));

  var recovered = b.crypto.hpke.open({
    privateKey:  pair.privateKey,
    enc:         sealed.enc,
    ciphertext:  sealed.ciphertext,
    info:        "session-1",
    aad:         "tenant-acme",
  });
  check("round-trip recovers the plaintext",
        recovered.toString("utf8") === pt);
}

function testAadBinding() {
  var pair = b.crypto.hpke.generateKeyPair();
  var sealed = b.crypto.hpke.seal({
    recipientPubKey: pair.publicKey,
    plaintext:       "secret",
    info:            "info-x",
    aad:             "aad-1",
  });

  var threwAad = null;
  try {
    b.crypto.hpke.open({
      privateKey:  pair.privateKey,
      enc:         sealed.enc,
      ciphertext:  sealed.ciphertext,
      info:        "info-x",
      aad:         "aad-DIFFERENT",
    });
  } catch (e) { threwAad = e; }
  check("AAD mismatch refuses decrypt",
        threwAad && threwAad.code === "AEAD_DECRYPT_FAILED");

  var threwInfo = null;
  try {
    b.crypto.hpke.open({
      privateKey:  pair.privateKey,
      enc:         sealed.enc,
      ciphertext:  sealed.ciphertext,
      info:        "info-DIFFERENT",
      aad:         "aad-1",
    });
  } catch (e) { threwInfo = e; }
  check("info-string mismatch refuses decrypt (suite_id binding)",
        threwInfo && threwInfo.code === "AEAD_DECRYPT_FAILED");
}

function testTamperedCiphertext() {
  var pair = b.crypto.hpke.generateKeyPair();
  var sealed = b.crypto.hpke.seal({
    recipientPubKey: pair.publicKey,
    plaintext:       "tampered-test",
    info:            "i",
    aad:             "a",
  });
  var tampered = Buffer.from(sealed.ciphertext);
  tampered[tampered.length - 1] ^= 0x01;
  var threw = null;
  try {
    b.crypto.hpke.open({
      privateKey:  pair.privateKey,
      enc:         sealed.enc,
      ciphertext:  tampered,
      info:        "i",
      aad:         "a",
    });
  } catch (e) { threw = e; }
  check("tampered ciphertext refuses decrypt",
        threw && threw.code === "AEAD_DECRYPT_FAILED");
}

function testValidation() {
  var threwOpts = null;
  try { b.crypto.hpke.seal(null); } catch (e) { threwOpts = e; }
  check("seal(null) throws", threwOpts && threwOpts.code === "BAD_OPT");

  var threwPub = null;
  try { b.crypto.hpke.seal({ recipientPubKey: 123, plaintext: "x" }); }
  catch (e) { threwPub = e; }
  check("non-string recipientPubKey throws",
        threwPub && threwPub.code === "BAD_OPT");

  var threwPt = null;
  try { b.crypto.hpke.seal({ recipientPubKey: "PEM", plaintext: 42 }); }
  catch (e) { threwPt = e; }
  check("non-string/Buffer plaintext throws",
        threwPt && threwPt.code === "BAD_OPT");

  var threwOpenEnc = null;
  try { b.crypto.hpke.open({ privateKey: "x", enc: "not-a-buffer", ciphertext: Buffer.alloc(0) }); }
  catch (e) { threwOpenEnc = e; }
  check("open with non-Buffer enc throws",
        threwOpenEnc && threwOpenEnc.code === "BAD_OPT");
}

async function run() {
  testSurface();
  testRoundTrip();
  testAadBinding();
  testTamperedCiphertext();
  testValidation();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
