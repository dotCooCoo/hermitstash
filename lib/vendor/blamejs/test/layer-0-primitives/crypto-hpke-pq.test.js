"use strict";
/**
 * b.crypto.hpke.pq.connolly / .wg — opt-in PQ-HPKE draft wrappers.
 * Cross-draft substitution refused via info-label binding.
 */

var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

function testConnollyRoundTrip() {
  var pair = b.crypto.hpke.generateKeyPair();
  var sealed = b.crypto.hpke.pq.connolly.seal({
    recipientPubKey: pair.publicKey,
    plaintext:       "msg",
    info:            "topic/a",
    aad:             "context",
  });
  check("connolly seal returns enc",        Buffer.isBuffer(sealed.enc));
  check("connolly seal returns ciphertext", Buffer.isBuffer(sealed.ciphertext));

  var pt = b.crypto.hpke.pq.connolly.open({
    privateKey: pair.privateKey,
    enc:        sealed.enc,
    ciphertext: sealed.ciphertext,
    info:       "topic/a",
    aad:        "context",
  });
  check("connolly round-trip", pt.toString("utf8") === "msg");
}

function testWgRoundTrip() {
  var pair = b.crypto.hpke.generateKeyPair();
  var sealed = b.crypto.hpke.pq.wg.seal({
    recipientPubKey: pair.publicKey,
    plaintext:       "wg msg",
    info:            "topic/b",
  });
  var pt = b.crypto.hpke.pq.wg.open({
    privateKey: pair.privateKey,
    enc:        sealed.enc,
    ciphertext: sealed.ciphertext,
    info:       "topic/b",
  });
  check("wg round-trip", pt.toString("utf8") === "wg msg");
}

function testCrossDraftRefused() {
  var pair = b.crypto.hpke.generateKeyPair();
  var sealedConnolly = b.crypto.hpke.pq.connolly.seal({
    recipientPubKey: pair.publicKey,
    plaintext:       "secret",
    info:            "ctx",
  });
  // Attempt to open a connolly envelope with the wg primitive — the
  // info-label binding diverges so the AEAD tag verify fails.
  var threw = false;
  try {
    b.crypto.hpke.pq.wg.open({
      privateKey: pair.privateKey,
      enc:        sealedConnolly.enc,
      ciphertext: sealedConnolly.ciphertext,
      info:       "ctx",
    });
  } catch (_e) { threw = true; }
  check("connolly → wg cross-open refused", threw);

  var sealedWg = b.crypto.hpke.pq.wg.seal({
    recipientPubKey: pair.publicKey,
    plaintext:       "secret",
    info:            "ctx",
  });
  threw = false;
  try {
    b.crypto.hpke.pq.connolly.open({
      privateKey: pair.privateKey,
      enc:        sealedWg.enc,
      ciphertext: sealedWg.ciphertext,
      info:       "ctx",
    });
  } catch (_e) { threw = true; }
  check("wg → connolly cross-open refused", threw);
}

function testEmptyInfoEquivalentToOmitted() {
  var pair = b.crypto.hpke.generateKeyPair();
  // Seal without info, open with info: "" — MUST round-trip.
  var sealed = b.crypto.hpke.pq.connolly.seal({
    recipientPubKey: pair.publicKey,
    plaintext:       "neutral",
  });
  var pt = b.crypto.hpke.pq.connolly.open({
    privateKey: pair.privateKey,
    enc:        sealed.enc,
    ciphertext: sealed.ciphertext,
    info:       "",
  });
  check("empty info round-trips with omitted info", pt.toString("utf8") === "neutral");

  // Reverse: seal with info: "", open without info.
  var sealed2 = b.crypto.hpke.pq.wg.seal({
    recipientPubKey: pair.publicKey,
    plaintext:       "back",
    info:            "",
  });
  var pt2 = b.crypto.hpke.pq.wg.open({
    privateKey: pair.privateKey,
    enc:        sealed2.enc,
    ciphertext: sealed2.ciphertext,
  });
  check("omitted info round-trips with empty info on seal", pt2.toString("utf8") === "back");
}

function testLabelsExported() {
  check("connolly label exported",
    typeof b.crypto.hpke.pq.connolly.label === "string" &&
    b.crypto.hpke.pq.connolly.label.indexOf("connolly") !== -1);
  check("wg label exported",
    typeof b.crypto.hpke.pq.wg.label === "string" &&
    b.crypto.hpke.pq.wg.label.indexOf("hpke-pq") !== -1);
}

function run() {
  testConnollyRoundTrip();
  testWgRoundTrip();
  testCrossDraftRefused();
  testEmptyInfoEquivalentToOmitted();
  testLabelsExported();
}

if (require.main === module) run();
module.exports = { run: run };
