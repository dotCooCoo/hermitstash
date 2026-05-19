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

function run() {
  testEncryptDecryptRoundtrip();
  testEncryptMultiRecipient();
  testDecryptRefusesWrongRecipient();
  testDecryptRefusesNoMatchingRid();
  testDecryptRefusesBadMagic();
  testEncryptRefusesNoRecipients();
  testWkdComputeUrlShape();
  testWkdAdvancedHostOverride();
  testWkdRefusesBadEmail();
}

if (require.main === module) {
  try { run(); }
  catch (e) { console.error(e); process.exit(1); }
}
module.exports = { run: run };
