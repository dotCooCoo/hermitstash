// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * pgp — RFC 9580 detached-signature sign + verify
 * round-trip coverage for Ed25519 and RSA (2048-bit).
 *
 * Run standalone: `node test/layer-0-primitives/mail-crypto-pgp.test.js`
 * Or via smoke:   `node test/smoke.js`
 *
 * The facade `lib/mail-crypto.js` is reached via direct require here
 * because the v1 ship of this surface intentionally does not modify
 * the top-level `b` export in index.js — operators reach it via
 * `require("blamejs/lib/mail-crypto")` until the next minor wires it
 * onto `b.mail.crypto`.
 */
var helpers = require("../helpers");
var check   = helpers.check;
var nodeCrypto = require("crypto");

var mailCrypto = require("../../lib/mail-crypto");
var pgp        = mailCrypto.pgp;

// ---- Keypair fixtures (one per algorithm) ----

function _rsaKeypair(bits) {
  return nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: bits || 2048,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

function _ed25519Keypair() {
  return nodeCrypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

// ---- Surface + input validation ----

function testPgpSurface() {
  check("mail.crypto namespace present",        typeof mailCrypto === "object");
  check("mail.crypto.pgp present",              typeof pgp === "object");
  check("mail.crypto.smime present",            typeof mailCrypto.smime === "object");
  check("pgp.sign is a function",               typeof pgp.sign === "function");
  check("pgp.verify is a function",             typeof pgp.verify === "function");
  check("MailCryptoError is a class",           typeof mailCrypto.MailCryptoError === "function");
  check("isMailCryptoError is a function",      typeof mailCrypto.isMailCryptoError === "function");
}

function testPgpSignInputValidation() {
  var kp = _ed25519Keypair();

  function shouldThrow(label, opts, codeRe) {
    var threw = null;
    try { pgp.sign(opts); } catch (e) { threw = e; }
    check("pgp.sign validate: " + label,
      threw && codeRe.test(String(threw.code || "") + " " + String(threw.message || "")));
  }

  shouldThrow("rejects null opts",
    null, /mail-crypto\/pgp\/bad-opts/);
  shouldThrow("rejects unknown opt key",
    { message: "x", privateKeyPem: kp.privateKey, bogus: 1 },
    /mail\.crypto\.pgp\.sign/);
  shouldThrow("rejects missing message",
    { privateKeyPem: kp.privateKey },
    /mail-crypto\/pgp\/bad-message/);
  shouldThrow("rejects empty message",
    { message: "", privateKeyPem: kp.privateKey },
    /mail-crypto\/pgp\/bad-message/);
  shouldThrow("rejects missing privateKeyPem",
    { message: "hi" },
    /mail-crypto\/pgp\/bad-key/);
  shouldThrow("rejects unparseable privateKeyPem",
    { message: "hi", privateKeyPem: "not-a-pem" },
    /mail-crypto\/pgp\/bad-key/);
  shouldThrow("rejects bad passphrase shape",
    { message: "hi", privateKeyPem: kp.privateKey, passphrase: 42 },
    /mail-crypto\/pgp\/bad-passphrase/);
  shouldThrow("rejects negative creationTime",
    { message: "hi", privateKeyPem: kp.privateKey, creationTime: -1 },
    /mail-crypto\/pgp\/bad-creation-time/);
  shouldThrow("rejects NaN creationTime",
    { message: "hi", privateKeyPem: kp.privateKey, creationTime: NaN },
    /mail-crypto\/pgp\/bad-creation-time/);

  // RSA < 2048 — refused per RFC 8301 §3.1 (mail-surface cross-posture).
  var smallRsa = _rsaKeypair(1024);
  shouldThrow("rejects RSA < 2048 bits",
    { message: "hi", privateKeyPem: smallRsa.privateKey },
    /mail-crypto\/pgp\/rsa-too-small/);
}

// ---- Ed25519 sign + verify round-trip ----

function testPgpEd25519RoundTrip() {
  var kp = _ed25519Keypair();
  var message = "From: alice@example.com\r\n" +
                "To: bob@example.org\r\n" +
                "Subject: Hi\r\n" +
                "\r\n" +
                "Hello, world.";
  var t0 = Math.floor(Date.now() / 1000);
  var rv = pgp.sign({
    message:       message,
    privateKeyPem: kp.privateKey,
    creationTime:  t0,
  });

  check("ed25519 sign returns armored",       typeof rv.armored === "string");
  check("ed25519 armored starts with BEGIN",  rv.armored.indexOf("-----BEGIN PGP SIGNATURE-----") === 0);
  check("ed25519 armored ends with END",      rv.armored.indexOf("-----END PGP SIGNATURE-----") !== -1);
  check("ed25519 fingerprint is 40 hex chars", typeof rv.fingerprint === "string" && /^[0-9a-f]{40}$/.test(rv.fingerprint));
  check("ed25519 signedAt matches input",     rv.signedAt === t0);
  check("ed25519 multipart wrapper present",  rv.multipartSigned.indexOf("multipart/signed") !== -1);
  check("ed25519 multipart protocol is pgp",  rv.multipartSigned.indexOf('protocol="application/pgp-signature"') !== -1);
  check("ed25519 micalg is pgp-sha512",       rv.multipartSigned.indexOf('micalg="pgp-sha512"') !== -1);
  check("ed25519 multipartSigned is a Buffer", Buffer.isBuffer(rv.multipartSigned));
  // Byte-fidelity: a UTF-8 multibyte signed part must appear verbatim in the
  // wrapper (a latin1 string round-trip would corrupt it and break the sig).
  var utf8Part = Buffer.from("Subject: éè 中文\r\n\r\nbody\r\n", "utf8");
  var rvU = pgp.sign({ message: utf8Part, privateKeyPem: kp.privateKey, creationTime: t0 });
  check("ed25519 multipartSigned preserves UTF-8 signed bytes verbatim",
        rvU.multipartSigned.indexOf(utf8Part) !== -1);

  var verify = pgp.verify({
    message:      message,
    armored:      rv.armored,
    publicKeyPem: kp.publicKey,
  });
  check("ed25519 verify returns ok=true",        verify.ok === true);
  check("ed25519 verify reports hashAlg sha512", verify.hashAlg === "sha512");
  check("ed25519 verify reports signedAt",       verify.signedAt === t0);
  check("ed25519 verify reports fingerprint",    verify.signerFingerprint === rv.fingerprint);
}

// ---- RSA sign + verify round-trip ----

function testPgpRsaRoundTrip() {
  var kp = _rsaKeypair(2048);
  var message = "RSA-signed payload bytes — RFC 9580 §5.2.4 over SHA-256.";
  var rv = pgp.sign({
    message:       message,
    privateKeyPem: kp.privateKey,
  });
  check("rsa sign returns armored",          typeof rv.armored === "string");
  check("rsa armored well-framed",           rv.armored.indexOf("-----BEGIN PGP SIGNATURE-----") === 0);
  check("rsa fingerprint is 40 hex chars",   /^[0-9a-f]{40}$/.test(rv.fingerprint));
  check("rsa micalg is pgp-sha256",          rv.multipartSigned.indexOf('micalg="pgp-sha256"') !== -1);

  var verify = pgp.verify({
    message:      message,
    armored:      rv.armored,
    publicKeyPem: kp.publicKey,
  });
  check("rsa verify ok=true",                  verify.ok === true);
  check("rsa verify reports hashAlg sha256",   verify.hashAlg === "sha256");
  check("rsa verify reports fingerprint",      verify.signerFingerprint === rv.fingerprint);
}

// Minimal parse of an ASCII-armored detached signature down to the RSA
// signature MPI's value byte-length, so the test can DETERMINISTICALLY find a
// signature whose high zero byte was stripped (rather than relying on a ~1/256
// random round-trip to flake). New-format packet (RFC 9580 §4.2.1): tag byte +
// length octet(s), then v4 sig body: ver/type/pubalg/hashalg(4) + hashedLen(2) +
// hashed + unhashedLen(2) + unhashed + hashLeft16(2) + MPI(2-byte bits + value).
function _rsaSigMpiByteLen(armored) {
  var lines = armored.replace(/\r/g, "").split("\n");
  var collecting = false, body = "";
  for (var i = 0; i < lines.length; i++) {
    var L = lines[i];
    if (L.indexOf("-----BEGIN") === 0) { collecting = false; continue; }
    if (L.indexOf("-----END") === 0) break;
    if (L === "") { collecting = true; continue; }   // blank line precedes the body
    if (collecting) { if (L.charAt(0) === "=") break; body += L; }   // '=' is the CRC line
  }
  var pkt = Buffer.from(body, "base64");
  var p = 1;                                          // skip the new-format tag byte
  var l0 = pkt[p];
  if (l0 < 192) p += 1; else if (l0 < 224) p += 2; else if (l0 === 255) p += 5; else p += 1;
  p += 4;                                             // ver, type, pubalg, hashalg
  var hashedLen = pkt.readUInt16BE(p); p += 2 + hashedLen;
  var unhashedLen = pkt.readUInt16BE(p); p += 2 + unhashedLen;
  p += 2;                                             // hashLeft16
  return Math.ceil(pkt.readUInt16BE(p) / 8);          // MPI bit-length → value byte-length
}

function testPgpRsaVerifyLeadingZeroSignature() {
  // An RSA signature is an integer in [0, n); ~1/256 of (key, message) pairs
  // produce a value with a high zero byte, which the OpenPGP MPI encoding
  // strips (RFC 9580 §3.2). verify() must left-pad the stripped MPI back to the
  // modulus byte length before the RSA op, or it rejects a VALID signature.
  // That bug surfaced only as a ~0.4% flake in the random-key round-trip above;
  // this finds the case deterministically and proves the signature still verifies.
  var kp = _rsaKeypair(2048);
  var MOD_BYTES = 256;                                // 2048-bit modulus
  var tested = false;
  for (var i = 0; i < 4000 && !tested; i++) {
    var message = "rsa-leading-zero-probe-" + i;
    var rv = pgp.sign({ message: message, privateKeyPem: kp.privateKey });
    if (_rsaSigMpiByteLen(rv.armored) < MOD_BYTES) {
      var verify = pgp.verify({ message: message, armored: rv.armored, publicKeyPem: kp.publicKey });
      check("rsa verify accepts a high-zero-byte (short-MPI) signature", verify.ok === true);
      tested = true;
    }
  }
  check("found a short-MPI RSA signature to exercise (within 4000 messages)", tested);
}

// ---- Tamper detection ----

function testPgpTamperDetection() {
  var kp = _ed25519Keypair();
  var message = "original message";
  var rv = pgp.sign({ message: message, privateKeyPem: kp.privateKey });

  // Tamper the message — verify must fail.
  var tampered = pgp.verify({
    message:      "tampered message",
    armored:      rv.armored,
    publicKeyPem: kp.publicKey,
  });
  check("verify refuses tampered message",
    tampered.ok === false && typeof tampered.code === "string");

  // Tamper the armored signature body — CRC-24 should catch it.
  var badArmor = rv.armored.replace(/[A-Za-z0-9]/, function (c) {
    return c === "A" ? "B" : "A";
  });
  var armorFail = pgp.verify({
    message:      message,
    armored:      badArmor,
    publicKeyPem: kp.publicKey,
  });
  check("verify refuses corrupted armor",
    armorFail.ok === false);

  // Wrong key — verify must fail (fingerprint mismatch).
  var otherKp = _ed25519Keypair();
  var wrongKey = pgp.verify({
    message:      message,
    armored:      rv.armored,
    publicKeyPem: otherKp.publicKey,
  });
  check("verify refuses wrong public key",
    wrongKey.ok === false);
}

// ---- Verify input validation ----

function testPgpVerifyInputValidation() {
  var kp = _ed25519Keypair();

  function shouldThrow(label, opts, codeRe) {
    var threw = null;
    try { pgp.verify(opts); } catch (e) { threw = e; }
    check("pgp.verify validate: " + label,
      threw && codeRe.test(String(threw.code || "") + " " + String(threw.message || "")));
  }

  shouldThrow("rejects null opts",
    null, /mail-crypto\/pgp\/bad-opts/);
  shouldThrow("rejects missing message",
    { armored: "-", publicKeyPem: kp.publicKey },
    /mail-crypto\/pgp\/bad-message/);
  shouldThrow("rejects missing armored",
    { message: "x", publicKeyPem: kp.publicKey },
    /mail-crypto\/pgp\/bad-armor/);
  shouldThrow("rejects missing publicKeyPem",
    { message: "x", armored: "-" },
    /mail-crypto\/pgp\/bad-key/);
}

// ---- EFAIL threat-model documentation assertion ----
//
// Per the @intro contract in lib/mail-crypto-pgp.js, the module
// names EFAIL by CVE so operators reading the source see the threat
// surface this primitive defends. The recurring drift this guards
// against is silently dropping the citation across refactors — when
// the citation goes missing, the @intro audit drift catches it
// here.

function testPgpDocBlockNamesEfail() {
  var fs = require("fs");
  var path = require("path");
  var src = fs.readFileSync(path.join(__dirname, "..", "..", "lib", "mail-crypto-pgp.js"), "utf8");
  check("doc block names EFAIL CVE-2017-17688",
    src.indexOf("CVE-2017-17688") !== -1);
  check("doc block names RFC 9580",
    src.indexOf("RFC 9580") !== -1);
  check("doc block names RFC 3156",
    src.indexOf("RFC 3156") !== -1);
  check("doc block names RFC 8301 (RSA bit floor)",
    src.indexOf("RFC 8301") !== -1);
}

// ---- Deferred encrypt/decrypt surface — verify the deferral is
// documented per the project's defer-with-condition rule. ----

function testPgpEncryptDecryptDeferralDocumented() {
  var fs = require("fs");
  var path = require("path");
  var src = fs.readFileSync(path.join(__dirname, "..", "..", "lib", "mail-crypto-pgp.js"), "utf8");
  check("pgp encrypt+decrypt deferral has a reopen condition",
    /Reopen|reopen|opt-in|condition/i.test(src));
  // The phrase "escape hatch" may wrap across a JSDoc line, so strip
  // JSDoc comment leaders and collapse whitespace before searching.
  var collapsed = src.replace(/\n\s*\*\s*/g, " ").replace(/\s+/g, " ");
  check("pgp encrypt+decrypt deferral names an escape hatch",
    collapsed.indexOf("escape hatch") !== -1);
}

// ---- Run ----

// ---- v0.11.32 — PGP promotion: top-level encrypt/decrypt/wkd ----

function testPgpStableTopLevelSurface() {
  check("pgp.encrypt promoted",     typeof pgp.encrypt === "function");
  check("pgp.decrypt promoted",     typeof pgp.decrypt === "function");
  check("pgp.wkd promoted",         typeof pgp.wkd === "object");
  check("pgp.wkd.fetch",            typeof pgp.wkd.fetch === "function");
  check("pgp.wkd.computeUrl",       typeof pgp.wkd.computeUrl === "function");
  // experimental alias preserved for v0.10.16 import paths.
  check("experimental alias kept (encrypt)",      typeof pgp.experimental.encrypt === "function");
  check("experimental alias kept (wkd.fetch)",    typeof pgp.experimental.wkd.fetch === "function");
  check("top-level === experimental ref",         pgp.encrypt === pgp.experimental.encrypt);
}

function testWkdComputeUrlRefusesIdnHomograph() {
  function expect(label, email, codeFragment) {
    var threw = null;
    try { pgp.wkd.computeUrl(email); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(codeFragment) !== -1);
  }
  // Cyrillic 'а' (U+0430) in domain — pure homograph for 'a'. The
  // homograph-encoded email passes a naive ASCII visual check but
  // the host string the framework would otherwise emit is ambiguous.
  // Operators MUST Punycode-encode upstream.
  expect("Cyrillic homograph domain refused",  "alice@pаypal.com",  "mail-crypto/pgp/bad-domain");
  expect("Full-width digit domain refused",     "x@pＡypal.com",       "mail-crypto/pgp/bad-domain");
  expect("Greek omicron domain refused",        "x@gοogle.com",       "mail-crypto/pgp/bad-domain");
  expect("Empty-label domain refused",          "x@bad..example.com",      "mail-crypto/pgp/bad-domain");
  expect("Leading-dot domain refused",          "x@.example.com",          "mail-crypto/pgp/bad-domain");
  expect("Over-length email refused",           "x@" + "a".repeat(320),    "mail-crypto/pgp/bad-email");
}

function testWkdComputeUrlPunycodeAccepted() {
  // Punycode-encoded IDN (xn-- form) is plain LDH ASCII, passes.
  var urls = pgp.wkd.computeUrl("alice@xn--bcher-kva.example");
  check("Punycode domain accepted",            /^https:\/\/xn--bcher-kva\.example\//.test(urls.direct));
  check("Punycode produces direct URL",        urls.direct.indexOf("/.well-known/openpgpkey/hu/") !== -1);
}

function run() {
  testPgpSurface();
  testPgpSignInputValidation();
  testPgpEd25519RoundTrip();
  testPgpRsaRoundTrip();
  testPgpRsaVerifyLeadingZeroSignature();
  testPgpTamperDetection();
  testPgpVerifyInputValidation();
  testPgpDocBlockNamesEfail();
  testPgpEncryptDecryptDeferralDocumented();
  testPgpStableTopLevelSurface();
  testWkdComputeUrlRefusesIdnHomograph();
  testWkdComputeUrlPunycodeAccepted();
}

module.exports = { run: run };

if (require.main === module) {
  try {
    run();
    console.log("OK — " + helpers.getChecks() + " checks passed");
  } catch (e) {
    console.error("FAIL:", e && e.stack || e);
    process.exit(1);
  }
}
