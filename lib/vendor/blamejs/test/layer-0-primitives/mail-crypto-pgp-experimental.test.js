// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.crypto.pgp.experimental — PQC PGP encrypt/decrypt + WKD URL
 * computation. Framework-private envelope (ML-KEM-1024 +
 * ChaCha20-Poly1305) shipped under `experimental` namespace because
 * RFC 9580bis PKESK ML-KEM codepoints haven't IANA-registered yet.
 */

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
var pq = require("../../lib/pqc-software");
var nodeCrypto = require("node:crypto");
var pgpMod = require("../../lib/mail-crypto-pgp");

function testEncryptDecryptRoundtrip() {
  var kp = pq.ml_kem_1024.keygen();
  var msg = "top secret";
  var rid = Buffer.from([0x42, 0x43]);
  var enc = b.mail.crypto.pgp.experimental.encrypt({
    message: msg,
    recipients: [{ recipientId: rid, publicKey: kp.publicKey }],
  });
  check("encrypt returns armored", typeof enc.armored === "string" && enc.armored.indexOf("BEGIN PGP MESSAGE") !== -1);
  check("encrypt returns envelope Buffer", Buffer.isBuffer(enc.envelope));
  var dec = b.mail.crypto.pgp.experimental.decrypt({
    armored: enc.armored, recipientId: rid, secretKey: kp.secretKey,
  });
  check("decrypt recovers plaintext", dec.plaintext.toString("utf8") === msg);
}

function testEncryptMultiRecipient() {
  var kp1 = pq.ml_kem_1024.keygen();
  var kp2 = pq.ml_kem_1024.keygen();
  var rid1 = Buffer.from([0x01]);
  var rid2 = Buffer.from([0x02]);
  var enc = b.mail.crypto.pgp.experimental.encrypt({
    message: "to-both",
    recipients: [
      { recipientId: rid1, publicKey: kp1.publicKey },
      { recipientId: rid2, publicKey: kp2.publicKey },
    ],
  });
  var dec1 = b.mail.crypto.pgp.experimental.decrypt({
    envelope: enc.envelope, recipientId: rid1, secretKey: kp1.secretKey,
  });
  var dec2 = b.mail.crypto.pgp.experimental.decrypt({
    envelope: enc.envelope, recipientId: rid2, secretKey: kp2.secretKey,
  });
  check("multi-recipient: recipient 1 decrypts", dec1.plaintext.toString("utf8") === "to-both");
  check("multi-recipient: recipient 2 decrypts", dec2.plaintext.toString("utf8") === "to-both");
}

function testDecryptRefusesWrongRecipient() {
  var kp = pq.ml_kem_1024.keygen();
  var kp2 = pq.ml_kem_1024.keygen();
  var rid = Buffer.from([0xaa]);
  var enc = b.mail.crypto.pgp.experimental.encrypt({
    message: "x", recipients: [{ recipientId: rid, publicKey: kp.publicKey }],
  });
  var threw = null;
  try {
    b.mail.crypto.pgp.experimental.decrypt({
      envelope: enc.envelope, recipientId: rid, secretKey: kp2.secretKey,
    });
  } catch (e) { threw = e.code; }
  check("wrong secret key refused at unwrap",
    threw === "mail-crypto/pgp/unwrap-failed" || threw === "mail-crypto/pgp/decap-failed");
}

function testDecryptRefusesNoMatchingRid() {
  var kp = pq.ml_kem_1024.keygen();
  var rid = Buffer.from([0x01]);
  var otherRid = Buffer.from([0x99]);
  var enc = b.mail.crypto.pgp.experimental.encrypt({
    message: "x", recipients: [{ recipientId: rid, publicKey: kp.publicKey }],
  });
  var threw = null;
  try {
    b.mail.crypto.pgp.experimental.decrypt({
      envelope: enc.envelope, recipientId: otherRid, secretKey: kp.secretKey,
    });
  } catch (e) { threw = e.code; }
  check("non-matching recipientId refused", threw === "mail-crypto/pgp/no-matching-recipient");
}

function testDecryptRefusesBadMagic() {
  var threw = null;
  try {
    b.mail.crypto.pgp.experimental.decrypt({
      envelope: Buffer.from("not a real envelope at all"),
      recipientId: Buffer.from([0]), secretKey: new Uint8Array(3168),
    });
  } catch (e) { threw = e.code; }
  check("bad-magic envelope refused", threw === "mail-crypto/pgp/bad-magic");
}

function testEncryptRefusesNoRecipients() {
  var threw = null;
  try {
    b.mail.crypto.pgp.experimental.encrypt({ message: "x", recipients: [] });
  } catch (e) { threw = e.code; }
  check("empty recipients refused", threw === "mail-crypto/pgp/no-recipients");
}

function testWkdComputeUrlShape() {
  var urls = b.mail.crypto.pgp.experimental.wkd.computeUrl("Alice@Example.COM");
  check("WKD direct URL uses lowercased domain",
    urls.direct.indexOf("https://example.com/.well-known/openpgpkey/hu/") === 0);
  check("WKD advanced URL uses openpgpkey.<domain>",
    urls.advanced.indexOf("https://openpgpkey.example.com/.well-known/openpgpkey/example.com/hu/") === 0);
  check("WKD localLower lowercased",  urls.localLower === "alice");
  check("WKD hashed is zbase32",      /^[ybndrfg8ejkmcpqxot1uwisza345h769]+$/.test(urls.hashed));
  check("WKD includes original localpart as l= query",
    urls.direct.indexOf("?l=Alice") !== -1);
}

function testWkdAdvancedHostOverride() {
  var urls = b.mail.crypto.pgp.experimental.wkd.computeUrl("bob@example.com",
    { advancedHost: "keys.example.com" });
  check("WKD operator-supplied advancedHost honored",
    urls.advanced.indexOf("https://keys.example.com/") === 0);
}

function testWkdRefusesBadEmail() {
  var bad = ["no-at-sign", "@nolocal.com", "trailing@", ""];
  for (var i = 0; i < bad.length; i += 1) {
    var threw = null;
    try { b.mail.crypto.pgp.experimental.wkd.computeUrl(bad[i]); }
    catch (e) { threw = e.code; }
    check("WKD refuses '" + bad[i] + "'", threw === "mail-crypto/pgp/bad-email");
  }
}

// ---- b.mail.crypto.pgp.experimental.wkd.fetch ----
//
// fetch() is driven entirely through the operator-supplied
// `httpsGet(url) => Promise<{ status, body }>` — the framework never
// couples to a specific HTTP client, so these tests inject an in-memory
// stub that records the URLs requested and returns canned responses.
// NO real network is touched.

// Build a recording httpsGet stub: `responses` maps a URL → its
// { status, body } reply; any URL absent from the map answers 404.
function _wkdStub(responses, calls) {
  return function (url) {
    calls.push(url);
    var r = responses[url];
    return Promise.resolve(r || { status: 404, body: Buffer.alloc(0) });
  };
}

async function testWkdFetchDirectHit() {
  var email = "alice@example.com";
  var urls  = b.mail.crypto.pgp.experimental.wkd.computeUrl(email);
  var keyBytes = Buffer.from([0x99, 0x01, 0x02, 0x03, 0x04]);
  var calls = [];
  var responses = {};
  responses[urls.direct] = { status: 200, body: keyBytes };

  var out = await b.mail.crypto.pgp.experimental.wkd.fetch(email, {
    httpsGet: _wkdStub(responses, calls),
  });
  check("wkd.fetch direct: source is 'direct'",       out.source === "direct");
  check("wkd.fetch direct: url is the direct URL",     out.url === urls.direct);
  check("wkd.fetch direct: keyBytes are the reply body",
    Buffer.isBuffer(out.keyBytes) && Buffer.compare(out.keyBytes, keyBytes) === 0);
  check("wkd.fetch direct: only the direct URL was requested",
    calls.length === 1 && calls[0] === urls.direct);
}

async function testWkdFetchAdvancedFallback() {
  var email = "bob@example.com";
  var urls  = b.mail.crypto.pgp.experimental.wkd.computeUrl(email);
  var keyBytes = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
  var calls = [];
  var responses = {};
  // direct absent (→ 404); advanced serves the key.
  responses[urls.advanced] = { status: 200, body: keyBytes };

  var out = await b.mail.crypto.pgp.experimental.wkd.fetch(email, {
    httpsGet: _wkdStub(responses, calls),
  });
  check("wkd.fetch fallback: source is 'advanced'",   out.source === "advanced");
  check("wkd.fetch fallback: url is the advanced URL", out.url === urls.advanced);
  check("wkd.fetch fallback: keyBytes are the reply body",
    Buffer.compare(out.keyBytes, keyBytes) === 0);
  check("wkd.fetch fallback: tried direct FIRST, then advanced",
    calls.length === 2 && calls[0] === urls.direct && calls[1] === urls.advanced);
}

async function testWkdFetchBothFail() {
  var email = "nokey@example.com";
  var calls = [];
  var threw = null;
  try {
    // Empty response map → both URLs 404.
    await b.mail.crypto.pgp.experimental.wkd.fetch(email, { httpsGet: _wkdStub({}, calls) });
  } catch (e) { threw = e; }
  check("wkd.fetch both-fail: throws wkd-not-found",
    threw && threw.code === "mail-crypto/pgp/wkd-not-found");
  check("wkd.fetch both-fail: is a MailCryptoError (facade classifier)",
    threw && b.mail.crypto.isMailCryptoError(threw) === true);
  check("wkd.fetch both-fail: both direct + advanced were attempted",
    calls.length === 2);
}

async function testWkdFetchRequiresHttpsGet() {
  var threw = null;
  try { await b.mail.crypto.pgp.experimental.wkd.fetch("alice@example.com", {}); }
  catch (e) { threw = e; }
  check("wkd.fetch: missing httpsGet throws no-https-get",
    threw && threw.code === "mail-crypto/pgp/no-https-get");

  var threwOpts = null;
  try { await b.mail.crypto.pgp.experimental.wkd.fetch("alice@example.com", null); }
  catch (e) { threwOpts = e; }
  check("wkd.fetch: null opts throws bad-opts",
    threwOpts && threwOpts.code === "mail-crypto/pgp/bad-opts");
}

async function testWkdFetchEnforcesMaxKeyBytes() {
  var email = "big@example.com";
  var urls  = b.mail.crypto.pgp.experimental.wkd.computeUrl(email);
  var calls = [];
  var responses = {};
  responses[urls.direct] = { status: 200, body: Buffer.alloc(100) };   // 100-byte reply

  var threwLarge = null;
  try {
    await b.mail.crypto.pgp.experimental.wkd.fetch(email, {
      httpsGet: _wkdStub(responses, calls), maxKeyBytes: 10,
    });
  } catch (e) { threwLarge = e; }
  check("wkd.fetch: reply over maxKeyBytes throws wkd-too-large",
    threwLarge && threwLarge.code === "mail-crypto/pgp/wkd-too-large");

  var threwBad = null;
  try {
    await b.mail.crypto.pgp.experimental.wkd.fetch(email, {
      httpsGet: _wkdStub(responses, []), maxKeyBytes: -1,
    });
  } catch (e) { threwBad = e; }
  check("wkd.fetch: negative maxKeyBytes throws bad-max-key-bytes",
    threwBad && threwBad.code === "mail-crypto/pgp/bad-max-key-bytes");
}

// ---- b.mail.crypto.pgp.sign / .verify (RFC 9580 detached signatures) ----
//
// The crypto/auth-verify tier: every trust decision here is a
// signature-forgery / tamper seam if it fails open (accepts a forged
// input) or crashes with an untyped throw where a typed refusal is the
// contract. Keys are generated in-process with node:crypto — NO network,
// NO fixtures on disk. The slow RSA-2048 keygen is memoized once.

function _edPair() {
  var k = nodeCrypto.generateKeyPairSync("ed25519");
  return {
    pub:  k.publicKey.export({ type: "spki", format: "pem" }),
    priv: k.privateKey.export({ type: "pkcs8", format: "pem" }),
  };
}

var _rsaPairMemo = null;
function _rsaPair() {
  if (_rsaPairMemo) return _rsaPairMemo;
  var k = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  _rsaPairMemo = {
    pub:  k.publicKey.export({ type: "spki", format: "pem" }),
    priv: k.privateKey.export({ type: "pkcs8", format: "pem" }),
  };
  return _rsaPairMemo;
}

var _rsaPssPairMemo = null;
function _rsaPssPair() {
  if (_rsaPssPairMemo) return _rsaPssPairMemo;
  var k = nodeCrypto.generateKeyPairSync("rsa-pss", { modulusLength: 2048 });
  _rsaPssPairMemo = {
    pub:  k.publicKey.export({ type: "spki", format: "pem" }),
    priv: k.privateKey.export({ type: "pkcs8", format: "pem" }),
  };
  return _rsaPssPairMemo;
}

function testSignVerifyEd25519Roundtrip() {
  var kp = _edPair();
  var msg = "The quick brown fox\r\n";
  var s = b.mail.crypto.pgp.sign({ message: msg, privateKeyPem: kp.priv });
  check("ed25519 sign: armored PGP SIGNATURE", typeof s.armored === "string" &&
    s.armored.indexOf("BEGIN PGP SIGNATURE") !== -1);
  check("ed25519 sign: hashAlg sha512", s.hashAlg === "sha512");
  check("ed25519 sign: multipartSigned is a Buffer", Buffer.isBuffer(s.multipartSigned));
  var v = b.mail.crypto.pgp.verify({ message: msg, armored: s.armored, publicKeyPem: kp.pub });
  check("ed25519 verify: ok", v.ok === true);
  check("ed25519 verify: fingerprint round-trips", v.signerFingerprint === s.fingerprint);
  check("ed25519 verify: hashAlg reported", v.hashAlg === "sha512");
}

function testSignVerifyRsaRoundtrip() {
  var kp = _rsaPair();
  var msg = "invoice body\r\n";
  var s = b.mail.crypto.pgp.sign({ message: msg, privateKeyPem: kp.priv });
  check("rsa sign: hashAlg sha256", s.hashAlg === "sha256");
  var v = b.mail.crypto.pgp.verify({ message: msg, armored: s.armored, publicKeyPem: kp.pub });
  check("rsa verify: ok", v.ok === true);
  check("rsa verify: fingerprint round-trips", v.signerFingerprint === s.fingerprint);
}

function testVerifyTamperedMessageFails() {
  var kp = _edPair();
  var msg = "authentic content\r\n";
  var s = b.mail.crypto.pgp.sign({ message: msg, privateKeyPem: kp.priv });
  var v = b.mail.crypto.pgp.verify({ message: msg + "X", armored: s.armored, publicKeyPem: kp.pub });
  check("tampered message: ok:false", v.ok === false);
  check("tampered message: hash-mismatch verdict", v.code === "mail-crypto/pgp/hash-mismatch");
}

function testVerifyWrongKeyFails() {
  var kp = _edPair();
  var other = _edPair();
  var msg = "content\r\n";
  var s = b.mail.crypto.pgp.sign({ message: msg, privateKeyPem: kp.priv });
  var v = b.mail.crypto.pgp.verify({ message: msg, armored: s.armored, publicKeyPem: other.pub });
  check("wrong key: ok:false", v.ok === false);
  check("wrong key: fingerprint-mismatch pin fires",
    v.code === "mail-crypto/pgp/fingerprint-mismatch");
}

function testVerifyKeyAlgMismatchFails() {
  var rsa = _rsaPair();
  var ed = _edPair();
  var msg = "m\r\n";
  var s = b.mail.crypto.pgp.sign({ message: msg, privateKeyPem: rsa.priv });
  var v = b.mail.crypto.pgp.verify({ message: msg, armored: s.armored, publicKeyPem: ed.pub });
  check("RSA sig + ed25519 key: ok:false", v.ok === false);
  check("RSA sig + ed25519 key: key-alg-mismatch verdict",
    v.code === "mail-crypto/pgp/key-alg-mismatch");
}

function testVerifyMalformedArmorReturnsVerdict() {
  var kp = _edPair();
  // Every malformed-armor path must return a typed {ok:false} VERDICT,
  // never throw out of verify() (a verifier that throws on hostile input
  // is a fail-closed-but-crash seam).
  var cases = [
    "not armored at all",
    "-----BEGIN PGP SIGNATURE-----\r\n\r\nAAAA\r\n=AAAA\r\n-----END PGP SIGNATURE-----\r\n",
    "-----BEGIN PGP SIGNATURE-----\r\n\r\nAAAA\r\n-----END PGP SIGNATURE-----\r\n",
  ];
  for (var i = 0; i < cases.length; i += 1) {
    var threw = null, r = null;
    try { r = b.mail.crypto.pgp.verify({ message: "x\r\n", armored: cases[i], publicKeyPem: kp.pub }); }
    catch (e) { threw = e; }
    check("malformed armor [" + i + "]: no throw, typed verdict",
      threw === null && r !== null && r.ok === false && r.code === "mail-crypto/pgp/bad-armor");
  }
}

function testVerifyMalformedPacketReturnsVerdict() {
  var kp = _edPair();
  var s = b.mail.crypto.pgp.sign({ message: "p\r\n", privateKeyPem: kp.priv });
  var pkt = pgpMod._dearmorForTest(s.armored);

  // (a) hashed-subpacket length claims more than the packet body holds.
  var body = Buffer.from(pkt.slice(2));
  body.writeUInt16BE(0xffff, 4);
  var vHuge = b.mail.crypto.pgp.verify({
    message: "p\r\n", armored: pgpMod._armorForTest(Buffer.concat([pkt.slice(0, 2), body])),
    publicKeyPem: kp.pub,
  });
  check("huge hashedSubLen: ok:false bad-packet",
    vHuge.ok === false && vHuge.code === "mail-crypto/pgp/bad-packet");

  // (b) truncated signature MPI — a hostile MPI is untrusted input and
  // must return a verdict, not throw.
  var full = pkt.slice(2);
  var cut = full.slice(0, full.length - 12);
  var truncPkt = Buffer.concat([Buffer.from([0xc0 | 2, cut.length]), cut]);
  var threw = null, vTrunc = null;
  try { vTrunc = b.mail.crypto.pgp.verify({ message: "p\r\n", armored: pgpMod._armorForTest(truncPkt), publicKeyPem: kp.pub }); }
  catch (e) { threw = e; }
  check("truncated MPI: no throw, bad-mpi verdict",
    threw === null && vTrunc !== null && vTrunc.ok === false && vTrunc.code === "mail-crypto/pgp/bad-mpi");

  // (c) legacy/old-format packet header is refused as a verdict.
  var vLegacy = b.mail.crypto.pgp.verify({
    message: "p\r\n", armored: pgpMod._armorForTest(Buffer.from([0x88, 0x02, 0x04, 0x00])),
    publicKeyPem: kp.pub,
  });
  check("legacy header: ok:false bad-packet",
    vLegacy.ok === false && vLegacy.code === "mail-crypto/pgp/bad-packet");
}

function testSignRefusesSmallRsa() {
  var k = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 1024 });
  var threw = null;
  try {
    b.mail.crypto.pgp.sign({ message: "x\r\n", privateKeyPem: k.privateKey.export({ type: "pkcs8", format: "pem" }) });
  } catch (e) { threw = e; }
  check("RSA < 2048 refused at sign", threw && threw.code === "mail-crypto/pgp/rsa-too-small");
  check("RSA < 2048 refusal is typed MailCryptoError",
    threw && b.mail.crypto.isMailCryptoError(threw) === true);
}

function testSignRefusesUnsupportedKeyType() {
  var ec = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var threw = null;
  try {
    b.mail.crypto.pgp.sign({ message: "x\r\n", privateKeyPem: ec.privateKey.export({ type: "pkcs8", format: "pem" }) });
  } catch (e) { threw = e; }
  check("P-256 key refused at sign", threw && threw.code === "mail-crypto/pgp/bad-key-type");
}

function testSignVerifyPassphraseKey() {
  var k = nodeCrypto.generateKeyPairSync("ed25519");
  var encPriv = k.privateKey.export({
    type: "pkcs8", format: "pem", cipher: "aes-256-cbc", passphrase: "s3cr3t",
  });
  var pub = k.publicKey.export({ type: "spki", format: "pem" });
  var s = b.mail.crypto.pgp.sign({ message: "secret body\r\n", privateKeyPem: encPriv, passphrase: "s3cr3t" });
  var v = b.mail.crypto.pgp.verify({ message: "secret body\r\n", armored: s.armored, publicKeyPem: pub });
  check("passphrase-protected key signs + verifies", v.ok === true);

  var threw = null;
  try { b.mail.crypto.pgp.sign({ message: "x\r\n", privateKeyPem: encPriv, passphrase: "WRONG" }); }
  catch (e) { threw = e; }
  check("wrong passphrase refused (typed bad-key)",
    threw && threw.code === "mail-crypto/pgp/bad-key");
}

function testSignCreationTimeOption() {
  var kp = _edPair();
  var s = b.mail.crypto.pgp.sign({ message: "dated\r\n", privateKeyPem: kp.priv, creationTime: 1700000000 });
  check("explicit creationTime stamped", s.signedAt === 1700000000);
  var v = b.mail.crypto.pgp.verify({ message: "dated\r\n", armored: s.armored, publicKeyPem: kp.pub });
  check("verify reflects signed creationTime (bound in hashed subpacket)",
    v.ok === true && v.signedAt === 1700000000);

  var threw = null;
  try { b.mail.crypto.pgp.sign({ message: "x\r\n", privateKeyPem: kp.priv, creationTime: -5 }); }
  catch (e) { threw = e; }
  check("negative creationTime refused", threw && threw.code === "mail-crypto/pgp/bad-creation-time");
}

// ---- RED: rsa-pss keys crash sign/verify with an UNTYPED throw ----
//
// Both sign() and verify() explicitly accept keyType "rsa-pss", but node
// cannot express this module's PKCS#1-v1.5 signatures with an rsa-pss key
// (OpenSSL refuses the padding mode) AND refuses to JWK-export it
// (ERR_CRYPTO_JWK_UNSUPPORTED_KEY_TYPE). The key-shape extraction crashes
// with a raw Error — not a typed MailCryptoError — so an operator's
// try/catch keyed on b.mail.crypto.isMailCryptoError never catches it and
// a crafted / mis-typed key crashes the caller. verify() must return a
// typed verdict; sign() must throw a typed refusal.

function testVerifyRsaPssKeyReturnsTypedVerdict() {
  var rsa = _rsaPair();
  var pss = _rsaPssPair();
  var s = b.mail.crypto.pgp.sign({ message: "m\r\n", privateKeyPem: rsa.priv });
  var threw = null, r = null;
  try { r = b.mail.crypto.pgp.verify({ message: "m\r\n", armored: s.armored, publicKeyPem: pss.pub }); }
  catch (e) { threw = e; }
  check("verify with rsa-pss key: does NOT throw untyped (typed verdict only)",
    threw === null || b.mail.crypto.isMailCryptoError(threw) === true);
  check("verify with rsa-pss key: typed ok:false verdict",
    r !== null && r.ok === false && r.code === "mail-crypto/pgp/key-alg-mismatch");
}

function testSignRsaPssKeyThrowsTyped() {
  var pss = _rsaPssPair();
  var threw = null;
  try { b.mail.crypto.pgp.sign({ message: "m\r\n", privateKeyPem: pss.priv }); }
  catch (e) { threw = e; }
  check("sign with rsa-pss key: throws a typed MailCryptoError (not raw Error)",
    threw && b.mail.crypto.isMailCryptoError(threw) === true);
  check("sign with rsa-pss key: bad-key-type code",
    threw && threw.code === "mail-crypto/pgp/bad-key-type");
}

// ---- RED: truncated PQ envelope crashes decrypt with an UNTYPED RangeError ----
//
// experimentalDecrypt advances an offset using attacker-controlled length
// fields (ridLen / ctLen / wkLen / bodyLen) and issues multi-byte
// readUInt16BE / readUInt32BE reads without first bounds-checking
// off + N <= envelope.length. A truncated envelope escapes as a raw
// RangeError (ERR_OUT_OF_RANGE) instead of the typed
// mail-crypto/pgp/truncated the function already defines — an
// uncaught-exception DoS on adversarial input.

function testDecryptTruncatedEnvelopeThrowsTyped() {
  var kp = pq.ml_kem_1024.keygen();
  var rid = Buffer.from([0x42]);
  var real = b.mail.crypto.pgp.encrypt({
    message: "x", recipients: [{ recipientId: rid, publicKey: kp.publicKey }],
  });
  // magic(9) || version || nRecips  then a recipient claiming ridLen=0xff
  // with no bytes behind it → the ctLen readUInt16BE reads off the end.
  var truncated = Buffer.concat([real.envelope.slice(0, 11), Buffer.from([0xff])]);
  var threw = null;
  try {
    b.mail.crypto.pgp.decrypt({ envelope: truncated, recipientId: rid, secretKey: kp.secretKey });
  } catch (e) { threw = e; }
  check("truncated envelope: throws a typed MailCryptoError (not raw RangeError)",
    threw && b.mail.crypto.isMailCryptoError(threw) === true);
  check("truncated envelope: mail-crypto/pgp/truncated code",
    threw && threw.code === "mail-crypto/pgp/truncated");
}

async function run() {
  testSignVerifyEd25519Roundtrip();
  testSignVerifyRsaRoundtrip();
  testVerifyTamperedMessageFails();
  testVerifyWrongKeyFails();
  testVerifyKeyAlgMismatchFails();
  testVerifyMalformedArmorReturnsVerdict();
  testVerifyMalformedPacketReturnsVerdict();
  testSignRefusesSmallRsa();
  testSignRefusesUnsupportedKeyType();
  testSignVerifyPassphraseKey();
  testSignCreationTimeOption();
  testVerifyRsaPssKeyReturnsTypedVerdict();
  testSignRsaPssKeyThrowsTyped();
  testDecryptTruncatedEnvelopeThrowsTyped();
  testEncryptDecryptRoundtrip();
  testEncryptMultiRecipient();
  testDecryptRefusesWrongRecipient();
  testDecryptRefusesNoMatchingRid();
  testDecryptRefusesBadMagic();
  testEncryptRefusesNoRecipients();
  testWkdComputeUrlShape();
  testWkdAdvancedHostOverride();
  testWkdRefusesBadEmail();
  await testWkdFetchDirectHit();
  await testWkdFetchAdvancedFallback();
  await testWkdFetchBothFail();
  await testWkdFetchRequiresHttpsGet();
  await testWkdFetchEnforcesMaxKeyBytes();
}

if (require.main === module) {
  run().then(
    function () { console.log("[mail-crypto-pgp-experimental] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
module.exports = { run: run };
