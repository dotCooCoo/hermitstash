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
var pq         = require("../../lib/pqc-software");

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

// ============================================================================
// Uncovered error / adversarial / defensive branch coverage
// ----------------------------------------------------------------------------
// The round-trip tests above exercise the happy path. The following drive the
// malformed-packet, key-resolution, and defensive-guard branches through the
// real consumer path (pgp.sign / pgp.verify / pgp.encrypt / pgp.decrypt /
// pgp.wkd.*), plus the exported dearmor hook for the ASCII-armor parser.
// ============================================================================

// Shared keypairs — reused across the crafted-packet tests to avoid repeated
// keygen. Ed25519 keygen is cheap; one RSA-2048 keygen amortizes across tests.
var _edKp  = _ed25519Keypair();
var _rsaKp = _rsaKeypair(2048);

// ---- New-format OpenPGP packet builders (RFC 9580 §4.2 / §5.2) ----

function _u16(n) { var buf = Buffer.alloc(2); buf.writeUInt16BE(n, 0); return buf; }

function _encLen(n) {
  if (n < 192) return Buffer.from([n]);
  if (n < 8384) return Buffer.from([((n - 192) >> 8) + 192, (n - 192) & 0xff]);
  var b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0, 0);
  return Buffer.concat([Buffer.from([0xff]), b]);
}

// New-format Signature packet (tag 2) wrapper around a body buffer.
function _sigPacket(body) {
  return Buffer.concat([Buffer.from([0xc2]), _encLen(body.length), body]);
}

// A v4 signature-packet body with per-field control.
function _sigBody(f) {
  var hashedSub   = f.hashedSub   || Buffer.alloc(0);
  var unhashedSub = f.unhashedSub || Buffer.alloc(0);
  var hashLeft16  = f.hashLeft16  || Buffer.from([0x00, 0x00]);
  var sigMpis     = f.sigMpis     || Buffer.alloc(0);
  return Buffer.concat([
    Buffer.from([4, f.sigType, f.pubAlg, f.hashAlg]),
    _u16(hashedSub.length), hashedSub,
    _u16(unhashedSub.length), unhashedSub,
    hashLeft16, sigMpis,
  ]);
}

// Take a real armored signature, split it into (everything up to and
// including hashLeft16) + (the signature-MPI tail). The header carries the
// signed-section and issuer-fingerprint subpacket, so a rebuilt packet with a
// mutated MPI tail still passes the leading-hash fast-fail and the fingerprint
// check — letting the crypto-verify and MPI-decode branches be exercised.
function _dissect(armored) {
  var pkt = pgp._dearmorForTest(armored);
  var idx = 1;
  var l0 = pkt[idx];
  if (l0 < 192) idx += 1;
  else if (l0 < 224) idx += 2;
  else if (l0 === 0xff) idx += 5;
  else idx += 1;
  var body = pkt.slice(idx);
  var hashedSubLen = body.readUInt16BE(4);
  var p = 6 + hashedSubLen;
  var unhashedSubLen = body.readUInt16BE(p);
  p += 2 + unhashedSubLen;
  return { headerToHashLeft: body.slice(0, p + 2), sigMpis: body.slice(p + 2) };
}

function _rebuild(headerToHashLeft, sigTail) {
  return pgp._armorForTest(_sigPacket(Buffer.concat([headerToHashLeft, sigTail])));
}

// ---- sign: unsupported key type + passphrase-protected key ----

function testPgpSignRejectsUnsupportedKeyType() {
  var ec = nodeCrypto.generateKeyPairSync("ec", {
    namedCurve:         "P-256",
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  var threw = null;
  try { pgp.sign({ message: "hi", privateKeyPem: ec.privateKey }); } catch (e) { threw = e; }
  check("sign: EC (unsupported) key type → bad-key-type",
    threw && threw.code === "mail-crypto/pgp/bad-key-type");
}

function testPgpSignWithPassphraseProtectedKey() {
  var kp = nodeCrypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem",
      cipher: "aes-256-cbc", passphrase: "s3cret-pass" },
  });
  var rv = pgp.sign({ message: "hi", privateKeyPem: kp.privateKey, passphrase: "s3cret-pass" });
  check("sign: passphrase-protected key signs", typeof rv.armored === "string");
  var v = pgp.verify({ message: "hi", armored: rv.armored, publicKeyPem: kp.publicKey });
  check("sign: passphrase-protected key round-trips verify", v.ok === true);

  var threw = null;
  try { pgp.sign({ message: "hi", privateKeyPem: kp.privateKey, passphrase: "wrong-pass" }); }
  catch (e) { threw = e; }
  check("sign: wrong passphrase → bad-key", threw && threw.code === "mail-crypto/pgp/bad-key");
}

// ---- audit hot-path is drop-silent even when the sink throws ----

function testPgpAuditHandleThatThrows() {
  var throwingAudit = { safeEmit: function () { throw new Error("audit sink down"); } };
  var rv = pgp.sign({ message: "hi", privateKeyPem: _edKp.privateKey, audit: throwingAudit });
  check("sign: throwing audit sink does not crash sign", typeof rv.armored === "string");
  var v = pgp.verify({ message: "hi", armored: rv.armored,
    publicKeyPem: _edKp.publicKey, audit: throwingAudit });
  check("verify: throwing audit sink does not crash verify", v.ok === true);
}

// ---- ASCII-armor (dearmor) parser error paths ----

function testDearmorErrorPaths() {
  function de(label, input, re) {
    var threw = null;
    try { pgp._dearmorForTest(input); } catch (e) { threw = e; }
    check("dearmor: " + label,
      threw && re.test(String(threw.code) + " " + String(threw.message)));
  }
  de("non-string input refused", 12345, /bad-armor/);
  de("missing BEGIN/END framing refused", "no armor here at all", /bad-armor/);

  var good = pgp.sign({ message: "m", privateKeyPem: _edKp.privateKey }).armored;

  // Strip the CRC-24 trailer line (starts with '=').
  var noCrc = good.split("\r\n").filter(function (l) { return l.charAt(0) !== "="; }).join("\r\n");
  de("missing CRC-24 trailer refused", noCrc, /bad-armor/);

  // Corrupt one base64 body character → recomputed CRC-24 mismatches.
  var lines = good.split("\r\n");
  for (var i = 0; i < lines.length; i += 1) {
    if (lines[i].length > 20 && lines[i].charAt(0) !== "=" && lines[i].indexOf("-----") === -1) {
      lines[i] = (lines[i].charAt(0) === "A" ? "B" : "A") + lines[i].slice(1);
      break;
    }
  }
  de("corrupt-body CRC-24 mismatch refused", lines.join("\r\n"), /bad-armor/);

  // CRC-24 trailer that base64-decodes to the wrong byte length.
  var badCrcLen = good.replace(/\r\n=[^\r\n]+/, "\r\n=AA");   // "AA" → 1 byte, not 3
  de("CRC-24 trailer wrong byte length refused", badCrcLen, /bad-armor/);

  // A well-formed armor carrying an RFC 9580 §6.2 header line (Comment:)
  // before the blank separator must parse — exercises the header-skip path.
  var withHeader = good.replace("-----BEGIN PGP SIGNATURE-----\r\n",
    "-----BEGIN PGP SIGNATURE-----\r\nComment: test header\r\n");
  var parsed = pgp._dearmorForTest(withHeader);
  check("dearmor: armor with a header line parses to packet bytes",
    Buffer.isBuffer(parsed) && parsed.length > 0);
}

// ---- verify: malformed signature packets (structural parse branches) ----

function testVerifyMalformedPackets() {
  function vf(label, packetBytes, codeRe) {
    var armored = pgp._armorForTest(packetBytes);
    var rv = null, threw = null;
    try { rv = pgp.verify({ message: "m", armored: armored, publicKeyPem: _edKp.publicKey }); }
    catch (e) { threw = e; }
    check("verify malformed: " + label,
      threw === null && rv && rv.ok === false &&
      codeRe.test(String(rv.code) + " " + String(rv.reason)));
  }
  vf("packet too short",                 Buffer.from([0xc2]),                        /bad-packet/);
  vf("legacy/old-format header refused",  Buffer.from([0x80, 0x00]),                  /bad-packet/);
  vf("wrong tag (not Signature)",         Buffer.from([0xc1, 0x00]),                  /bad-packet/);
  vf("truncated 2-octet length",          Buffer.from([0xc2, 192]),                   /bad-packet/);
  vf("truncated 5-octet length",          Buffer.from([0xc2, 0xff, 0x00]),            /bad-packet/);
  vf("partial-body length refused",       Buffer.from([0xc2, 0xe0, 0x00]),            /bad-packet/);
  vf("packet body truncated",             Buffer.from([0xc2, 10, 4, 0, 22, 10]),      /bad-packet/);
  vf("5-octet length then bad version",
    Buffer.concat([Buffer.from([0xc2, 0xff, 0, 0, 0, 6]), Buffer.from([5, 0, 22, 10, 0, 0])]),
    /bad-version/);
  vf("bad version (not v4)",              _sigPacket(Buffer.from([5, 0, 22, 10, 0, 0])),      /bad-version/);
  vf("non-binary signature type refused", _sigPacket(Buffer.from([4, 1, 22, 10, 0, 0])),      /bad-sig-type/);
  vf("SHA-1 hash algorithm refused",      _sigPacket(Buffer.from([4, 0, 22, 2,  0, 0])),      /bad-hash/);
  vf("hashed-subpacket length overflow",  _sigPacket(Buffer.from([4, 0, 22, 10, 0xff, 0xff])), /bad-packet/);
  vf("missing unhashed-subpacket length", _sigPacket(Buffer.from([4, 0, 22, 10, 0, 0])),      /bad-packet/);
  vf("unhashed-subpacket length overflow",
    _sigPacket(Buffer.from([4, 0, 22, 10, 0, 0, 0xff, 0xff])), /bad-packet/);
}

// ---- verify: subpacket length-octet decoding (2-octet + 5-octet forms) ----

function testVerifySubpacketLengthEncodings() {
  // 2-octet subpacket length (first octet in [192,255)) that overruns the
  // hashed area → decoded then bounded.
  var hs2 = Buffer.from([200, 5]);
  var pkt2 = _sigPacket(_sigBody({ sigType: 0, pubAlg: 22, hashAlg: 8, hashedSub: hs2 }));
  var r2 = pgp.verify({ message: "x", armored: pgp._armorForTest(pkt2), publicKeyPem: _edKp.publicKey });
  check("verify: 2-octet subpacket length decoded then bounded", r2.ok === false);

  // 5-octet subpacket length (first octet === 255).
  var hs5 = Buffer.from([255, 0, 0, 0, 3, 2, 0, 0]);
  var pkt5 = _sigPacket(_sigBody({ sigType: 0, pubAlg: 22, hashAlg: 8, hashedSub: hs5 }));
  var r5 = pgp.verify({ message: "x", armored: pgp._armorForTest(pkt5), publicKeyPem: _edKp.publicKey });
  check("verify: 5-octet subpacket length decoded", r5.ok === false);

  // 2-octet length header itself truncated (only the first octet present).
  var hs2t = Buffer.from([200]);
  var pkt2t = _sigPacket(_sigBody({ sigType: 0, pubAlg: 22, hashAlg: 8, hashedSub: hs2t }));
  var r2t = pgp.verify({ message: "x", armored: pgp._armorForTest(pkt2t), publicKeyPem: _edKp.publicKey });
  check("verify: truncated 2-octet subpacket header bounded", r2t.ok === false);

  // 5-octet length header itself truncated.
  var hs5t = Buffer.from([255, 0, 0]);
  var pkt5t = _sigPacket(_sigBody({ sigType: 0, pubAlg: 22, hashAlg: 8, hashedSub: hs5t }));
  var r5t = pgp.verify({ message: "x", armored: pgp._armorForTest(pkt5t), publicKeyPem: _edKp.publicKey });
  check("verify: truncated 5-octet subpacket header bounded", r5t.ok === false);
}

// ---- verify: key resolution + algorithm-mismatch branches ----

function testVerifyKeyResolution() {
  var msg    = "key-resolution-probe";
  var edSig  = pgp.sign({ message: msg, privateKeyPem: _edKp.privateKey });
  var rsaSig = pgp.sign({ message: msg, privateKeyPem: _rsaKp.privateKey });

  var r1 = pgp.verify({ message: msg, armored: edSig.armored,
    publicKeyPem: "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----" });
  check("verify: unparseable publicKeyPem → bad-key",
    r1.ok === false && r1.code === "mail-crypto/pgp/bad-key");

  var r2 = pgp.verify({ message: msg, armored: rsaSig.armored, publicKeyPem: _edKp.publicKey });
  check("verify: RSA signature + Ed25519 key → key-alg-mismatch",
    r2.ok === false && r2.code === "mail-crypto/pgp/key-alg-mismatch");

  var r3 = pgp.verify({ message: msg, armored: edSig.armored, publicKeyPem: _rsaKp.publicKey });
  check("verify: Ed25519 signature + RSA key → key-alg-mismatch",
    r3.ok === false && r3.code === "mail-crypto/pgp/key-alg-mismatch");

  var smallRsa = _rsaKeypair(1024);
  var r4 = pgp.verify({ message: msg, armored: rsaSig.armored, publicKeyPem: smallRsa.publicKey });
  check("verify: RSA signature verified against <2048-bit key → rsa-too-small",
    r4.ok === false && r4.code === "mail-crypto/pgp/rsa-too-small");

  // Packet claims an unsupported public-key algorithm (id 3).
  var badAlg = _sigPacket(_sigBody({ sigType: 0, pubAlg: 3, hashAlg: 8,
    hashLeft16: Buffer.from([0xab, 0xcd]) }));
  var r5 = pgp.verify({ message: msg, armored: pgp._armorForTest(badAlg), publicKeyPem: _edKp.publicKey });
  check("verify: unsupported public-key algorithm → bad-pubalg",
    r5.ok === false && r5.code === "mail-crypto/pgp/bad-pubalg");
}

// ---- verify: a valid-algorithm packet with no creation-time subpacket ----
//
// Exercises the `subs.signedAt === undefined ? 0` fallback in the fingerprint
// recompute for both the RSA and Ed25519 branches (with real public keys).

function testVerifyNoCreationTimeSubpacket() {
  var edPkt = _sigPacket(_sigBody({ sigType: 0, pubAlg: 22, hashAlg: 8 }));
  var rvE = pgp.verify({ message: "x", armored: pgp._armorForTest(edPkt), publicKeyPem: _edKp.publicKey });
  check("verify: Ed25519 packet without creation-time subpacket rejected cleanly",
    rvE.ok === false);

  var rsaPkt = _sigPacket(_sigBody({ sigType: 0, pubAlg: 1, hashAlg: 8 }));
  var rvR = pgp.verify({ message: "x", armored: pgp._armorForTest(rsaPkt), publicKeyPem: _rsaKp.publicKey });
  check("verify: RSA packet without creation-time subpacket rejected cleanly",
    rvR.ok === false);
}

// ---- verify: crypto rejects a mutated (but structurally valid) signature ----
//
// hashLeft16 + signed-section preserved → the leading-hash fast-fail passes and
// the asymmetric verify is what rejects (the `!ok → bad-signature` branch).

function testVerifyCryptoRejectsMutatedSignature() {
  var msg = "mutate-sig-probe";

  var edSig = pgp.sign({ message: msg, privateKeyPem: _edKp.privateKey });
  var de = _dissect(edSig.armored);
  var em = Buffer.from(de.sigMpis); em[em.length - 1] ^= 0xff;
  var rvE = pgp.verify({ message: msg, armored: _rebuild(de.headerToHashLeft, em),
    publicKeyPem: _edKp.publicKey });
  check("verify: mutated Ed25519 signature → bad-signature (crypto reject)",
    rvE.ok === false && rvE.code === "mail-crypto/pgp/bad-signature");

  var rsaSig = pgp.sign({ message: msg, privateKeyPem: _rsaKp.privateKey });
  var dr = _dissect(rsaSig.armored);
  var rm = Buffer.from(dr.sigMpis); rm[rm.length - 1] ^= 0xff;
  var rvR = pgp.verify({ message: msg, armored: _rebuild(dr.headerToHashLeft, rm),
    publicKeyPem: _rsaKp.publicKey });
  check("verify: mutated RSA signature → bad-signature (crypto reject)",
    rvR.ok === false && rvR.code === "mail-crypto/pgp/bad-signature");
}

// ---- verify: truncated signature MPI returns a verdict (root-fixed) ----
//
// Every other malformed-signature path returns { ok:false, code }; the raw
// _readMpi reads in the crypto section previously threw out of verify() on a
// truncated MPI. Root-fixed to route through _fail like its siblings.

function testVerifyTruncatedMpiReturnsFail() {
  var msg = "truncated-mpi-probe";
  var d = _dissect(pgp.sign({ message: msg, privateKeyPem: _edKp.privateKey }).armored);

  // 1-byte tail — the R MPI's 2-byte length header itself is truncated.
  var rv1 = null, t1 = null;
  try { rv1 = pgp.verify({ message: msg, armored: _rebuild(d.headerToHashLeft, Buffer.from([0x00])),
    publicKeyPem: _edKp.publicKey }); }
  catch (e) { t1 = e; }
  check("verify: truncated-MPI signature returns ok:false (does not throw)",
    t1 === null && rv1 && rv1.ok === false && rv1.code === "mail-crypto/pgp/bad-mpi");

  // 2-byte length header claims 32 value bytes but only 1 is present.
  var rv2 = null, t2 = null;
  try { rv2 = pgp.verify({ message: msg,
    armored: _rebuild(d.headerToHashLeft, Buffer.from([0x01, 0x00, 0x00])),
    publicKeyPem: _edKp.publicKey }); }
  catch (e) { t2 = e; }
  check("verify: MPI value truncation returns ok:false (does not throw)",
    t2 === null && rv2 && rv2.ok === false && rv2.code === "mail-crypto/pgp/bad-mpi");

  // Same guard on the RSA branch's MPI read.
  var dr = _dissect(pgp.sign({ message: msg, privateKeyPem: _rsaKp.privateKey }).armored);
  var rvR = null, tR = null;
  try { rvR = pgp.verify({ message: msg, armored: _rebuild(dr.headerToHashLeft, Buffer.from([0x00])),
    publicKeyPem: _rsaKp.publicKey }); }
  catch (e) { tR = e; }
  check("verify: truncated RSA MPI returns ok:false (does not throw)",
    tR === null && rvR && rvR.ok === false && rvR.code === "mail-crypto/pgp/bad-mpi");
}

// ---- verify: over-sized MPI components are length-normalized then rejected --

function testVerifyOversizedMpiComponents() {
  var msg = "oversized-mpi-probe";

  var d = _dissect(pgp.sign({ message: msg, privateKeyPem: _edKp.privateKey }).armored);
  // R MPI declares a 33-byte value (bits=264); S a normal 32-byte value.
  var rOver = Buffer.concat([Buffer.from([0x01, 0x08]), Buffer.alloc(33, 0x11)]);
  var sNorm = Buffer.concat([Buffer.from([0x01, 0x00]), Buffer.alloc(32, 0x22)]);
  var rvE = pgp.verify({ message: msg,
    armored: _rebuild(d.headerToHashLeft, Buffer.concat([rOver, sNorm])),
    publicKeyPem: _edKp.publicKey });
  check("verify: >32-byte Ed25519 MPI component normalized then rejected",
    rvE.ok === false &&
    (rvE.code === "mail-crypto/pgp/bad-signature" || rvE.code === "mail-crypto/pgp/verify-error"));

  // Under-sized R MPI (30 bytes, bits=240) — the high-zero-stripped form the
  // MPI encoding produces; _padTo32 must left-pad it back to 32 bytes.
  var rUnder = Buffer.concat([Buffer.from([0x00, 0xf0]), Buffer.alloc(30, 0x44)]);
  var rvU = pgp.verify({ message: msg,
    armored: _rebuild(d.headerToHashLeft, Buffer.concat([rUnder, sNorm])),
    publicKeyPem: _edKp.publicKey });
  check("verify: <32-byte Ed25519 MPI component left-padded then rejected",
    rvU.ok === false && rvU.code === "mail-crypto/pgp/bad-signature");

  var dr = _dissect(pgp.sign({ message: msg, privateKeyPem: _rsaKp.privateKey }).armored);
  // RSA MPI declares 300 value bytes (bits=2400), exceeding the 256-byte modulus.
  var over = Buffer.concat([Buffer.from([0x09, 0x60]), Buffer.alloc(300, 0x33)]);
  var rvR = pgp.verify({ message: msg, armored: _rebuild(dr.headerToHashLeft, over),
    publicKeyPem: _rsaKp.publicKey });
  check("verify: over-modulus RSA signature rejected",
    rvR.ok === false &&
    (rvR.code === "mail-crypto/pgp/bad-signature" || rvR.code === "mail-crypto/pgp/verify-error"));
}

// ---- encrypt / decrypt (ML-KEM-1024 framework envelope) ----

function testPgpEncryptDecryptRoundTrip() {
  var kp  = pq.ml_kem_1024.keygen();
  var rid = Buffer.from([0x42, 0x43]);
  var enc = pgp.encrypt({ message: "top secret",
    recipients: [{ recipientId: rid, publicKey: kp.publicKey }] });
  check("encrypt: returns BEGIN PGP MESSAGE armor",
    typeof enc.armored === "string" && enc.armored.indexOf("BEGIN PGP MESSAGE") !== -1);
  check("encrypt: returns envelope Buffer", Buffer.isBuffer(enc.envelope));

  var d1 = pgp.decrypt({ armored: enc.armored, recipientId: rid, secretKey: kp.secretKey });
  check("decrypt: recovers plaintext via armored", d1.plaintext.toString("utf8") === "top secret");
  var d2 = pgp.decrypt({ envelope: enc.envelope, recipientId: rid, secretKey: kp.secretKey });
  check("decrypt: recovers plaintext via envelope Buffer", d2.plaintext.toString("utf8") === "top secret");
}

function testPgpEncryptMultiRecipient() {
  var kp1 = pq.ml_kem_1024.keygen();
  var kp2 = pq.ml_kem_1024.keygen();
  var rid1 = Buffer.from([0x01]);
  var rid2 = Buffer.from([0x02]);
  var enc = pgp.encrypt({ message: "to-both", recipients: [
    { recipientId: rid1, publicKey: kp1.publicKey },
    { recipientId: rid2, publicKey: kp2.publicKey },
  ] });
  var a = pgp.decrypt({ envelope: enc.envelope, recipientId: rid1, secretKey: kp1.secretKey });
  var b = pgp.decrypt({ envelope: enc.envelope, recipientId: rid2, secretKey: kp2.secretKey });
  check("encrypt/decrypt: recipient 1 recovers", a.plaintext.toString("utf8") === "to-both");
  check("encrypt/decrypt: recipient 2 recovers", b.plaintext.toString("utf8") === "to-both");
}

function testPgpEncryptInputValidation() {
  var kp  = pq.ml_kem_1024.keygen();
  var rid = Buffer.from([0x01]);
  function encThrow(label, opts, code) {
    var threw = null;
    try { pgp.encrypt(opts); } catch (e) { threw = e; }
    check("encrypt validate: " + label, threw && threw.code === code);
  }
  encThrow("empty message",
    { message: "", recipients: [{ recipientId: rid, publicKey: kp.publicKey }] },
    "mail-crypto/pgp/bad-message");
  encThrow("non-Buffer/string message",
    { message: 123, recipients: [{ recipientId: rid, publicKey: kp.publicKey }] },
    "mail-crypto/pgp/bad-message");
  encThrow("empty recipients array",
    { message: "x", recipients: [] }, "mail-crypto/pgp/no-recipients");
  encThrow("recipientId not a Buffer",
    { message: "x", recipients: [{ recipientId: "nope", publicKey: kp.publicKey }] },
    "mail-crypto/pgp/bad-recipient");
  encThrow("publicKey not a Uint8Array",
    { message: "x", recipients: [{ recipientId: rid, publicKey: [1, 2, 3] }] },
    "mail-crypto/pgp/bad-recipient");
  encThrow("recipientId over 255 bytes",
    { message: "x", recipients: [{ recipientId: Buffer.alloc(256), publicKey: kp.publicKey }] },
    "mail-crypto/pgp/bad-recipient");
}

function testPgpDecryptInputValidation() {
  var kp  = pq.ml_kem_1024.keygen();
  var rid = Buffer.from([0xaa]);
  var enc = pgp.encrypt({ message: "x", recipients: [{ recipientId: rid, publicKey: kp.publicKey }] });
  var MAGIC = Buffer.from("BJ-PGP-PQ", "ascii");

  function decThrow(label, opts, code) {
    var threw = null;
    try { pgp.decrypt(opts); } catch (e) { threw = e; }
    check("decrypt validate: " + label, threw && threw.code === code);
  }
  decThrow("recipientId not a Buffer",
    { envelope: enc.envelope, recipientId: "x", secretKey: kp.secretKey }, "mail-crypto/pgp/bad-opts");
  decThrow("secretKey not a Uint8Array",
    { envelope: enc.envelope, recipientId: rid, secretKey: "x" }, "mail-crypto/pgp/bad-opts");
  decThrow("neither envelope nor armored supplied",
    { recipientId: rid, secretKey: kp.secretKey }, "mail-crypto/pgp/bad-opts");
  decThrow("envelope magic mismatch",
    { envelope: Buffer.from("not a valid envelope at all!!"), recipientId: rid, secretKey: kp.secretKey },
    "mail-crypto/pgp/bad-magic");
  decThrow("unsupported envelope version",
    { envelope: Buffer.concat([MAGIC, Buffer.from([2, 0])]), recipientId: rid, secretKey: kp.secretKey },
    "mail-crypto/pgp/bad-version");
  decThrow("truncated envelope (recipient count exceeds data)",
    { envelope: Buffer.concat([MAGIC, Buffer.from([1, 1])]), recipientId: rid, secretKey: kp.secretKey },
    "mail-crypto/pgp/truncated");
}

function testPgpDecryptErrorPaths() {
  var kp  = pq.ml_kem_1024.keygen();
  var rid = Buffer.from([0xaa]);
  var enc = pgp.encrypt({ message: "secret-body",
    recipients: [{ recipientId: rid, publicKey: kp.publicKey }] });

  var kp2 = pq.ml_kem_1024.keygen();
  var w = null;
  try { pgp.decrypt({ envelope: enc.envelope, recipientId: rid, secretKey: kp2.secretKey }); }
  catch (e) { w = e.code; }
  check("decrypt: wrong secret key → decap/unwrap failure",
    w === "mail-crypto/pgp/unwrap-failed" || w === "mail-crypto/pgp/decap-failed");

  var nm = null;
  try { pgp.decrypt({ envelope: enc.envelope, recipientId: Buffer.from([0x99]), secretKey: kp.secretKey }); }
  catch (e) { nm = e.code; }
  check("decrypt: non-matching recipientId → no-matching-recipient",
    nm === "mail-crypto/pgp/no-matching-recipient");

  var corrupt = Buffer.from(enc.envelope);
  corrupt[corrupt.length - 1] ^= 0xff;
  var bd = null;
  try { pgp.decrypt({ envelope: corrupt, recipientId: rid, secretKey: kp.secretKey }); }
  catch (e) { bd = e.code; }
  check("decrypt: corrupted AEAD body → body-decrypt-failed",
    bd === "mail-crypto/pgp/body-decrypt-failed");
}

// ---- Buffer (not string) message inputs on verify + encrypt ----

function testBufferMessageInputs() {
  var msg = Buffer.from("binary\x00message\xff bytes", "latin1");
  var sig = pgp.sign({ message: msg, privateKeyPem: _edKp.privateKey });
  var v = pgp.verify({ message: msg, armored: sig.armored, publicKeyPem: _edKp.publicKey });
  check("verify: accepts a Buffer message", v.ok === true);

  var kp  = pq.ml_kem_1024.keygen();
  var rid = Buffer.from([0x55]);
  var enc = pgp.encrypt({ message: Buffer.from([0x00, 0x01, 0x02, 0xff]),
    recipients: [{ recipientId: rid, publicKey: kp.publicKey }] });
  var dec = pgp.decrypt({ envelope: enc.envelope, recipientId: rid, secretKey: kp.secretKey });
  check("encrypt/decrypt: round-trips a Buffer message",
    Buffer.compare(dec.plaintext, Buffer.from([0x00, 0x01, 0x02, 0xff])) === 0);
}

// ---- decrypt: ML-KEM decapsulate failure (malformed ciphertext length) ----

function testPgpDecryptDecapFailure() {
  var kp   = pq.ml_kem_1024.keygen();
  var rid  = Buffer.from([0xaa]);
  var MAGIC = Buffer.from("BJ-PGP-PQ", "ascii");
  // Hand-built envelope whose recipient ciphertext is the wrong length, so
  // ML-KEM-1024 decapsulate rejects it before session-key unwrap.
  var env = Buffer.concat([
    MAGIC, Buffer.from([1, 1]),          // version 1, 1 recipient
    Buffer.from([1, 0xaa]),              // ridLen=1, rid=0xaa (matches)
    _u16(10), Buffer.alloc(10),          // ct: 10 bytes (invalid ML-KEM length)
    _u16(5),  Buffer.alloc(5),           // wrappedKey
    Buffer.from([0, 0, 0, 0]),           // bodyLen=0
  ]);
  var threw = null;
  try { pgp.decrypt({ envelope: env, recipientId: rid, secretKey: kp.secretKey }); }
  catch (e) { threw = e; }
  check("decrypt: malformed recipient ciphertext → decap-failed",
    threw && threw.code === "mail-crypto/pgp/decap-failed");
}

function testPgpDecryptArmoredErrorPaths() {
  var kp = pq.ml_kem_1024.keygen();
  function decThrow(label, armored, code) {
    var threw = null;
    try { pgp.decrypt({ armored: armored, recipientId: Buffer.from([0x01]), secretKey: kp.secretKey }); }
    catch (e) { threw = e; }
    check("decrypt armored: " + label, threw && threw.code === code);
  }
  decThrow("not BEGIN PGP MESSAGE armored", "just some text", "mail-crypto/pgp/bad-armor");
  decThrow("armor header without blank-line separator",
    "-----BEGIN PGP MESSAGE-----\r\n-----END PGP MESSAGE-----\r\n", "mail-crypto/pgp/bad-armor");
}

// ---- wkd.computeUrl: bad-email + over-length-domain branches ----

function testPgpWkdComputeUrlErrorBranches() {
  function throwCode(label, email, code) {
    var threw = null;
    try { pgp.wkd.computeUrl(email); } catch (e) { threw = e; }
    check("wkd.computeUrl: " + label, threw && threw.code === code);
  }
  throwCode("missing @",     "noatsign",              "mail-crypto/pgp/bad-email");
  throwCode("@ at start",    "@domain.com",           "mail-crypto/pgp/bad-email");
  throwCode("@ at end",      "local@",                "mail-crypto/pgp/bad-email");
  throwCode("over-length domain", "a@" + "d".repeat(254), "mail-crypto/pgp/bad-domain");
}

// ---- wkd.fetch: driven entirely through an injected httpsGet stub (no net) --

function _wkdStub(responses, calls) {
  return function (url) {
    calls.push(url);
    return Promise.resolve(responses[url] || { status: 404, body: Buffer.alloc(0) });
  };
}

async function testPgpWkdFetchStubbed() {
  var email = "alice@example.com";
  var urls  = pgp.wkd.computeUrl(email);

  var keyBytes = Buffer.from([0x99, 0x01, 0x02]);
  var callsA = [];
  var rA = {}; rA[urls.direct] = { status: 200, body: keyBytes };
  var outA = await pgp.wkd.fetch(email, { httpsGet: _wkdStub(rA, callsA) });
  check("wkd.fetch: direct hit → source direct",
    outA.source === "direct" && outA.url === urls.direct);
  check("wkd.fetch: direct hit returns reply body",
    Buffer.compare(outA.keyBytes, keyBytes) === 0);
  check("wkd.fetch: direct hit requested only the direct URL", callsA.length === 1);

  var callsB = [];
  var rB = {}; rB[urls.advanced] = { status: 200, body: Buffer.from([0xde, 0xad]) };
  var outB = await pgp.wkd.fetch(email, { httpsGet: _wkdStub(rB, callsB) });
  check("wkd.fetch: advanced fallback → source advanced", outB.source === "advanced");
  check("wkd.fetch: advanced fallback tried direct then advanced",
    callsB.length === 2 && callsB[0] === urls.direct && callsB[1] === urls.advanced);

  var bothErr = null;
  try { await pgp.wkd.fetch(email, { httpsGet: _wkdStub({}, []) }); } catch (e) { bothErr = e; }
  check("wkd.fetch: both URLs fail → wkd-not-found",
    bothErr && bothErr.code === "mail-crypto/pgp/wkd-not-found");

  var noGet = null;
  try { await pgp.wkd.fetch(email, {}); } catch (e) { noGet = e; }
  check("wkd.fetch: missing httpsGet → no-https-get",
    noGet && noGet.code === "mail-crypto/pgp/no-https-get");

  var rC = {}; rC[urls.direct] = { status: 200, body: Buffer.alloc(100) };
  var bigDirect = null;
  try { await pgp.wkd.fetch(email, { httpsGet: _wkdStub(rC, []), maxKeyBytes: 10 }); }
  catch (e) { bigDirect = e; }
  check("wkd.fetch: direct reply over maxKeyBytes → wkd-too-large",
    bigDirect && bigDirect.code === "mail-crypto/pgp/wkd-too-large");

  var rD = {}; rD[urls.advanced] = { status: 200, body: Buffer.alloc(100) };
  var bigAdv = null;
  try { await pgp.wkd.fetch(email, { httpsGet: _wkdStub(rD, []), maxKeyBytes: 10 }); }
  catch (e) { bigAdv = e; }
  check("wkd.fetch: advanced reply over maxKeyBytes → wkd-too-large",
    bigAdv && bigAdv.code === "mail-crypto/pgp/wkd-too-large");

  var badMax = null;
  try { await pgp.wkd.fetch(email, { httpsGet: _wkdStub({}, []), maxKeyBytes: -1 }); }
  catch (e) { badMax = e; }
  check("wkd.fetch: negative maxKeyBytes → bad-max-key-bytes",
    badMax && badMax.code === "mail-crypto/pgp/bad-max-key-bytes");
}

// ---- verify: global invariants over a hostile signature-MPI corpus --------
//
// Two properties must hold for EVERY structurally-hostile signature the parser
// lets through to the crypto stage: verify() NEVER throws on signature content
// (the v0.16.12 truncated-MPI regression class — untrusted bytes return a
// verdict, they don't escape as an exception), and verify() NEVER returns
// ok:true for anything but the genuine signature (no fail-open). The real
// signatures supply valid framing (issuer fingerprint + leading-hash), so each
// mutated MPI tail reaches the MPI-decode + asymmetric-verify branches rather
// than short-circuiting at an earlier structural check.

function testVerifyFailsClosedOnHostileMpiCorpus() {
  var msg     = "hostile-mpi-corpus";
  var edReal  = pgp.sign({ message: msg, privateKeyPem: _edKp.privateKey });
  var rsaReal = pgp.sign({ message: msg, privateKeyPem: _rsaKp.privateKey });
  var edD     = _dissect(edReal.armored);
  var rsaD    = _dissect(rsaReal.armored);

  var tails = [
    Buffer.alloc(0),                                                    // no MPI at all
    Buffer.from([0x00]),                                               // MPI length header truncated
    Buffer.from([0xff]),                                               // 1-byte high tail
    Buffer.from([0x01, 0x00]),                                         // header claims 1 bit, no value
    Buffer.from([0x01, 0x00, 0x00]),                                   // header vs value length mismatch
    Buffer.from([0x00, 0x08]),                                         // zero-bit MPI header
    Buffer.concat([Buffer.from([0x01, 0x00]), Buffer.alloc(32, 0x00)]), // 32-byte all-zero component
    Buffer.concat([Buffer.from([0x01, 0x00]), Buffer.alloc(32, 0xff)]), // 32-byte all-ones component
    Buffer.concat([Buffer.from([0xff, 0xff]), Buffer.alloc(4, 0xaa)]),  // 65535-bit header, 4-byte value
    Buffer.concat([Buffer.from([0x09, 0x00]), Buffer.alloc(288, 0x33)]), // over-modulus RSA-sized value
  ];

  var fixtures = [
    { d: edD,  key: _edKp.publicKey },
    { d: rsaD, key: _rsaKp.publicKey },
  ];
  var cases = 0, threw = 0, failOpen = 0;
  for (var fi = 0; fi < fixtures.length; fi += 1) {
    for (var ti = 0; ti < tails.length; ti += 1) {
      cases += 1;
      var armored = _rebuild(fixtures[fi].d.headerToHashLeft, tails[ti]);
      try {
        var r = pgp.verify({ message: msg, armored: armored, publicKeyPem: fixtures[fi].key });
        if (r && r.ok === true) failOpen += 1;
      } catch (_e) { threw += 1; }
    }
  }
  check("verify: hostile MPI-tail corpus never throws (v0.16.12 class holds)", threw === 0);
  check("verify: hostile MPI-tail corpus never fails open", failOpen === 0);
  check("verify: hostile MPI-tail corpus swept both algorithms fully",
    cases === tails.length * fixtures.length);
}

// ---- decrypt: only typed MailCryptoError escapes on hostile envelopes ------
//
// Every attacker-controlled length field in the envelope (recipient count,
// ridLen, ct/wrapped-key/body lengths) must be bounds-checked before the read
// so a truncated envelope surfaces as a typed mail-crypto/pgp/* refusal, never
// a raw RangeError leaking out of decrypt(). Sweeps the truncation boundary at
// each field plus the decapsulate-reject and no-matching-recipient exits.

function testDecryptTypedThrowsOnHostileEnvelopeCorpus() {
  var MAGIC = Buffer.from("BJ-PGP-PQ", "ascii");
  var rid   = Buffer.from([0xaa]);
  var kp    = pq.ml_kem_1024.keygen();

  var envs = [
    Buffer.concat([MAGIC, Buffer.from([1, 1])]),                                   // count=1, no recipient
    Buffer.concat([MAGIC, Buffer.from([1, 1, 5])]),                                // ridLen=5, no rid
    Buffer.concat([MAGIC, Buffer.from([1, 1, 1, 0xaa])]),                          // rid ok, no ctLen
    Buffer.concat([MAGIC, Buffer.from([1, 1, 1, 0xaa, 0x00, 0x05])]),              // ctLen=5, no ct
    Buffer.concat([MAGIC, Buffer.from([1, 1, 1, 0xaa, 0x00, 0x01, 0x00])]),        // ct ok, no wkLen
    Buffer.concat([MAGIC, Buffer.from([1, 1, 1, 0xaa, 0x00, 0x01, 0x00, 0x00, 0x05])]), // wkLen=5, no wk
    Buffer.concat([MAGIC, Buffer.from([1, 1, 1, 0xaa, 0x00, 0x01, 0x11, 0x00, 0x01, 0x22])]), // matches → decap-reject
    Buffer.concat([MAGIC, Buffer.from([1, 1, 1, 0xbb, 0x00, 0x01, 0x11, 0x00, 0x01, 0x22, 0x00, 0x00, 0x00, 0x00])]), // rid mismatch → no-match
  ];

  var cases = 0, untyped = 0;
  for (var i = 0; i < envs.length; i += 1) {
    cases += 1;
    try { pgp.decrypt({ envelope: envs[i], recipientId: rid, secretKey: kp.secretKey }); }
    catch (e) {
      if (!(e && typeof e.code === "string" && e.code.indexOf("mail-crypto/pgp/") === 0)) untyped += 1;
    }
  }
  check("decrypt: hostile-envelope corpus surfaces only typed MailCryptoError", untyped === 0);
  check("decrypt: hostile-envelope corpus swept every length boundary", cases === envs.length);
}

// ---- verify: the hash-algorithm octet is signed (confusion defense) --------
//
// The signature's hash-algorithm octet sits inside the signed section, so any
// substitution changes both the recomputed hash input and (for RSA) the
// EMSA-PKCS1 DigestInfo. Swapping it for the OTHER supported algorithm — a
// value the parser still accepts — must be rejected by the hash binding, not
// silently tolerated (hash-algorithm-confusion per the module threat model).

function testVerifyHashAlgorithmBinding() {
  var msg = "hash-binding-probe";

  var edSig = pgp.sign({ message: msg, privateKeyPem: _edKp.privateKey });
  var ed    = _dissect(edSig.armored);
  var edHdr = Buffer.from(ed.headerToHashLeft);
  edHdr[3]  = 8;   // module Ed25519 signs under SHA-512 (10); swap to SHA-256 (8)
  var rvE = pgp.verify({ message: msg, armored: _rebuild(edHdr, ed.sigMpis), publicKeyPem: _edKp.publicKey });
  check("verify: Ed25519 hash-algorithm octet is bound (10→8 rejected)", rvE.ok === false);

  var rsaSig = pgp.sign({ message: msg, privateKeyPem: _rsaKp.privateKey });
  var rs     = _dissect(rsaSig.armored);
  var rsHdr  = Buffer.from(rs.headerToHashLeft);
  rsHdr[3]   = 10;  // module RSA signs under SHA-256 (8); swap to SHA-512 (10)
  var rvR = pgp.verify({ message: msg, armored: _rebuild(rsHdr, rs.sigMpis), publicKeyPem: _rsaKp.publicKey });
  check("verify: RSA hash-algorithm octet is bound (8→10 rejected)", rvR.ok === false);
}

// ---- Run ----

async function run() {
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

  // Error / adversarial / defensive branch coverage.
  testPgpSignRejectsUnsupportedKeyType();
  testPgpSignWithPassphraseProtectedKey();
  testPgpAuditHandleThatThrows();
  testDearmorErrorPaths();
  testVerifyMalformedPackets();
  testVerifySubpacketLengthEncodings();
  testVerifyKeyResolution();
  testVerifyNoCreationTimeSubpacket();
  testVerifyCryptoRejectsMutatedSignature();
  testVerifyTruncatedMpiReturnsFail();
  testVerifyOversizedMpiComponents();
  testPgpEncryptDecryptRoundTrip();
  testPgpEncryptMultiRecipient();
  testPgpEncryptInputValidation();
  testPgpDecryptInputValidation();
  testPgpDecryptErrorPaths();
  testBufferMessageInputs();
  testPgpDecryptDecapFailure();
  testPgpDecryptArmoredErrorPaths();
  testPgpWkdComputeUrlErrorBranches();
  await testPgpWkdFetchStubbed();

  // Verifier / decryptor global-invariant regression locks (fuzz-derived).
  testVerifyFailsClosedOnHostileMpiCorpus();
  testDecryptTypedThrowsOnHostileEnvelopeCorpus();
  testVerifyHashAlgorithmBinding();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
