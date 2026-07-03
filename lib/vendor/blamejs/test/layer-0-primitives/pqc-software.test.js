// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.pqcSoftware — pure-JS post-quantum primitives wrapper.
 */

var b = require("../..");
var check = require("../helpers/check").check;

function run() {
  // ---- shape ----
  check("b.pqcSoftware is object",                typeof b.pqcSoftware === "object");
  check("isAvailable is fn",                      typeof b.pqcSoftware.isAvailable === "function");
  check("listAlgorithms is fn",                   typeof b.pqcSoftware.listAlgorithms === "function");

  check("isAvailable returns true",               b.pqcSoftware.isAvailable() === true);

  var algos = b.pqcSoftware.listAlgorithms();
  check("listAlgorithms: 12 algorithms",          algos.length === 12);
  check("listAlgorithms: ml_kem_1024",             algos.indexOf("ml_kem_1024") !== -1);
  check("listAlgorithms: ml_dsa_87",               algos.indexOf("ml_dsa_87") !== -1);
  check("listAlgorithms: slh_dsa_shake_256f",      algos.indexOf("slh_dsa_shake_256f") !== -1);

  // ---- defaults: highest-security-first ----
  check("DEFAULT_KEM is ml_kem_1024",             b.pqcSoftware.DEFAULT_KEM === b.pqcSoftware.ml_kem_1024);
  check("DEFAULT_LATTICE_SIG is ml_dsa_87",       b.pqcSoftware.DEFAULT_LATTICE_SIG === b.pqcSoftware.ml_dsa_87);
  check("DEFAULT_HASH_SIG is slh_dsa_shake_256f", b.pqcSoftware.DEFAULT_HASH_SIG === b.pqcSoftware.slh_dsa_shake_256f);

  // ---- ml_kem_1024 e2e ----
  var pq = b.pqcSoftware;
  var k = pq.ml_kem_1024.keygen();
  check("ml_kem_1024.keygen pub size",            k.publicKey.length === 1568);
  check("ml_kem_1024.keygen priv size",           k.secretKey.length === 3168);

  var enc = pq.ml_kem_1024.encapsulate(k.publicKey);
  check("ml_kem_1024.encapsulate ct size",        enc.cipherText.length === 1568);
  check("ml_kem_1024.encapsulate ss size",        enc.sharedSecret.length === 32);

  var ss2 = pq.ml_kem_1024.decapsulate(enc.cipherText, k.secretKey);
  check("ml_kem_1024.decapsulate matches",        Buffer.from(enc.sharedSecret).equals(Buffer.from(ss2)));

  // ---- ml_kem_768 ----
  var k768 = pq.ml_kem_768.keygen();
  check("ml_kem_768.keygen pub size",             k768.publicKey.length === 1184);
  check("ml_kem_768.keygen priv size",            k768.secretKey.length === 2400);

  // ---- ml_kem_512 ----
  var k512 = pq.ml_kem_512.keygen();
  check("ml_kem_512.keygen pub size",             k512.publicKey.length === 800);
  check("ml_kem_512.keygen priv size",            k512.secretKey.length === 1632);

  // ---- ml_dsa_87 sign/verify e2e ----
  // noble-pq order: sign(msg, secretKey, opts?) and verify(sig, msg, publicKey)
  var dk = pq.ml_dsa_87.keygen();
  check("ml_dsa_87.keygen pub size",               dk.publicKey.length === 2592);
  check("ml_dsa_87.keygen priv size",              dk.secretKey.length === 4896);
  var msg = new TextEncoder().encode("blamejs test message");
  var sig = pq.ml_dsa_87.sign(msg, dk.secretKey);
  check("ml_dsa_87.sign returns bytes",            sig.length > 0);
  var ok = pq.ml_dsa_87.verify(sig, msg, dk.publicKey);
  check("ml_dsa_87.verify ok",                     ok === true);

  // tampered signature fails
  var sigTamp = sig.slice();
  sigTamp[0] = sigTamp[0] ^ 0xFF;                  // allow:raw-byte-literal — tamper byte
  var okTamp = pq.ml_dsa_87.verify(sigTamp, msg, dk.publicKey);
  check("ml_dsa_87.verify tampered fails",         okTamp === false);

  // ---- ml_dsa_65 / ml_dsa_44 keygen smoke ----
  check("ml_dsa_65.keygen ok",                     pq.ml_dsa_65.keygen().publicKey.length > 1000);
  check("ml_dsa_44.keygen ok",                     pq.ml_dsa_44.keygen().publicKey.length > 1000);

  // ---- slh_dsa_shake_256f keygen smoke ----
  // SLH-DSA keygen is ~10ms but sign is multi-hundred-ms — skip sign in test loop
  var sk256 = pq.slh_dsa_shake_256f.keygen();
  check("slh_dsa_shake_256f.keygen pub",           sk256.publicKey.length > 0);

  // ---- algo accessors are getters → live binding ----
  check("DEFAULT_KEM accessor stable",             b.pqcSoftware.DEFAULT_KEM.lengths.publicKey === 1568);

  // ---- listAlgorithms when bundle missing returns empty ----
  // Cannot easily test without unmounting; trust the runtime path.

  // KAT — boot-time round-trip against the vendored ML-KEM-1024.
  var kat = b.pqcSoftware.runKnownAnswerTest();
  check("pqcSoftware.runKnownAnswerTest: ok",
    kat && kat.ok === true && kat.sharedSecretLength === 32);

  console.log("OK — pqc-software tests");
}

module.exports = { run: run };
if (require.main === module) {
  try { run(); process.exit(0); } catch (e) { console.error(e); process.exit(1); }
}
