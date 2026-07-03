// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.crypto.xwing (X-Wing hybrid PQ/T KEM, draft-connolly-cfrg-xwing-kem).
 *
 * Oracle. The X-Wing-specific contribution is the combiner — SHA3-256 over a
 * fixed concatenation plus a fixed label — so that is known-answer-tested
 * byte-for-byte against an independent SHA3-256. The ML-KEM-768 and X25519
 * halves are pre-validated vendored primitives; the composition is checked by
 * full encaps → decaps agreement, by deterministic reproducibility from fixed
 * seeds (regression-anchored to pinned digests), and by implicit-rejection
 * behaviour on a tampered ciphertext.
 */

var nodeCrypto = require("crypto");
var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

var x = b.crypto.xwing;

function testSurface() {
  check("xwing.keygen is fn",       typeof x.keygen === "function");
  check("xwing.encapsulate is fn",  typeof x.encapsulate === "function");
  check("xwing.decapsulate is fn",  typeof x.decapsulate === "function");
  check("xwing.combiner is fn",     typeof x.combiner === "function");
  check("xwing.NAME is X-Wing",     x.NAME === "X-Wing");
  check("xwing.XWingError is class", typeof x.XWingError === "function");
  check("SIZES pk 1216",  x.SIZES.publicKey === 1216);
  check("SIZES ct 1120",  x.SIZES.ciphertext === 1120);
  check("SIZES sk 32",    x.SIZES.secretKey === 32);
  check("SIZES ss 32",    x.SIZES.sharedSecret === 32);
}

function testCombinerKAT() {
  // Byte-exact against the draft: SHA3-256(ssM ‖ ssX ‖ ctX ‖ pkX ‖ label),
  // label = the six bytes 5c2e2f2f5e5c ("\./" "/^\").
  var ssM = Buffer.alloc(32, 0x11), ssX = Buffer.alloc(32, 0x22),
      ctX = Buffer.alloc(32, 0x33), pkX = Buffer.alloc(32, 0x44);
  var ref = nodeCrypto.createHash("sha3-256")
    .update(Buffer.concat([ssM, ssX, ctX, pkX, Buffer.from("5c2e2f2f5e5c", "hex")])).digest();
  check("combiner matches independent SHA3-256 + label byte-for-byte", x.combiner(ssM, ssX, ctX, pkX).equals(ref));
  // Order matters: swapping two inputs changes the output.
  check("combiner is order-sensitive", !x.combiner(ssX, ssM, ctX, pkX).equals(ref));
  check("combiner rejects a short input", code(function () { x.combiner(Buffer.alloc(31), ssX, ctX, pkX); }) === "xwing/bad-input");
}

function testSizes() {
  var kp = x.keygen();
  check("public key is 1216 bytes", kp.publicKey.length === 1216);
  check("secret key (seed) is 32 bytes", kp.secretKey.length === 32);
  var enc = x.encapsulate(kp.publicKey);
  check("ciphertext is 1120 bytes", enc.ciphertext.length === 1120);
  check("shared secret is 32 bytes", enc.sharedSecret.length === 32);
}

function testRoundTrip() {
  for (var i = 0; i < 5; i++) {
    var kp = x.keygen();
    var enc = x.encapsulate(kp.publicKey);
    var ss = x.decapsulate(kp.secretKey, enc.ciphertext);
    check("round-trip " + i + ": decaps recovers the encaps shared secret", ss.equals(enc.sharedSecret));
  }
}

function testDeterminism() {
  var seed = Buffer.alloc(32, 1);
  check("keygen(seed) is deterministic", x.keygen(seed).publicKey.equals(x.keygen(seed).publicKey));
  var pk = x.keygen(seed).publicKey;
  // Distinct eseed halves so the value depends on the draft's split order
  // (eseed[0:32] = ML-KEM coins, eseed[32:64] = X25519 ephemeral).
  var eseed = Buffer.concat([Buffer.alloc(32, 2), Buffer.alloc(32, 3)]);
  var a = x.encapsulate(pk, eseed), c2 = x.encapsulate(pk, eseed);
  check("encapsulate(pk, eseed) is deterministic", a.ciphertext.equals(c2.ciphertext) && a.sharedSecret.equals(c2.sharedSecret));
  check("deterministic encaps round-trips", x.decapsulate(seed, a.ciphertext).equals(a.sharedSecret));

  // Regression anchors: pinned digests of the full deterministic flow. A change
  // to the combiner, the seed expansion, the eseed split order, or the wire
  // framing breaks these.
  check("keygen(0x01) public key digest is stable",
    nodeCrypto.createHash("sha3-256").update(pk).digest("hex") === "60068c4c0bfc7421bb1cb4a4202bf0ef75ee27e61bf2f6b08780869485cc736a");
  check("deterministic ciphertext digest is stable",
    nodeCrypto.createHash("sha3-256").update(a.ciphertext).digest("hex") === "1422e82c4307fcb8117b28ceaf686241cbe48d1a5546e05cd1aa7401d5fc2624");
  check("deterministic shared secret is stable",
    a.sharedSecret.toString("hex") === "356f5611bb146e8baf7fa61410552a9c724a170b8a0d4e742fac19161d8fdf4a");
}

function testImplicitRejection() {
  var kp = x.keygen();
  var enc = x.encapsulate(kp.publicKey);
  // Wrong key: ML-KEM implicit rejection yields a different 32-byte secret, no throw.
  var wrong = x.decapsulate(x.keygen().secretKey, enc.ciphertext);
  check("wrong key yields a 32-byte secret (no throw)", Buffer.isBuffer(wrong) && wrong.length === 32);
  check("wrong key yields a different secret", !wrong.equals(enc.sharedSecret));
  // Tampered ciphertext: still no throw, different secret.
  var bad = Buffer.from(enc.ciphertext); bad[0] ^= 0xff; bad[bad.length - 1] ^= 0xff;
  var ssBad = x.decapsulate(kp.secretKey, bad);
  check("tampered ciphertext yields a different secret without throwing", !ssBad.equals(enc.sharedSecret));
}

function testErrors() {
  var kp = x.keygen();
  check("keygen rejects a short seed",       code(function () { x.keygen(Buffer.alloc(16)); }) === "xwing/bad-seed");
  check("encapsulate rejects a short pubkey", code(function () { x.encapsulate(Buffer.alloc(100)); }) === "xwing/bad-public-key");
  check("encapsulate rejects a short eseed",  code(function () { x.encapsulate(kp.publicKey, Buffer.alloc(32)); }) === "xwing/bad-eseed");
  check("decapsulate rejects a short seed",   code(function () { x.decapsulate(Buffer.alloc(16), Buffer.alloc(1120)); }) === "xwing/bad-seed");
  check("decapsulate rejects a short ct",     code(function () { x.decapsulate(kp.secretKey, Buffer.alloc(100)); }) === "xwing/bad-ciphertext");
}

async function run() {
  testSurface();
  testCombinerKAT();
  testSizes();
  testRoundTrip();
  testDeterminism();
  testImplicitRejection();
  testErrors();
}
module.exports = { run: run };
if (require.main === module) { run().then(function () { console.log("[crypto-xwing] OK — " + helpers.getChecks() + " checks passed"); }, function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }); }
