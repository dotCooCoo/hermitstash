"use strict";
/**
 * Layer 0 — b.crypto.oprf (RFC 9497).
 * Oracle: the official RFC 9497 Appendix A test vectors (A.1.1
 * ristretto255-SHA512 OPRF, A.3.1 P-256-SHA256 OPRF) — deriveKeyPair must
 * reproduce skSm and the server-side evaluate must reproduce Output (both
 * deterministic). Round-trips cover oprf + voprf; poprf is not exposed
 * (the vendored @noble/curves does not implement it).
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
function hb(s) { return Buffer.from(s, "hex"); }
function toHex(u) { return Buffer.from(u).toString("hex"); }

var SEED = Buffer.alloc(32, 0xa3);                 // RFC 9497 vectors use Seed = 0xA3 × 32
var KEYINFO = hb("74657374206b6579");              // "test key"
var INPUT0 = hb("00");

// RFC 9497 Appendix A — OPRF (mode 0x00) vectors.
var VEC = {
  "ristretto255-sha512": {
    skSm: "5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e",
    out:  "527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6",
  },
  "p256-sha256": {
    skSm: "159749d750713afe245d2d39ccfaae8381c53ce92d098a9375ee70739c7ac0bf",
    out:  "a0b34de5fa4c5b6da07e72af73cc507cceeb48981b97b7285fc375345fe495dd",
  },
};

function testSurface() {
  check("b.crypto.oprf.suite is a function", typeof b.crypto.oprf.suite === "function");
  check("SUITES lists the four RFC 9497 ciphersuites", b.crypto.oprf.SUITES.join(",") === "ristretto255-sha512,p256-sha256,p384-sha384,p521-sha512");
  check("OprfError is a class", typeof b.crypto.oprf.OprfError === "function");
  var s = b.crypto.oprf.suite("ristretto255-sha512");
  check("suite exposes oprf + voprf, not poprf", typeof s.oprf === "object" && typeof s.voprf === "object" && s.poprf === undefined);
  check("suite name is case-insensitive", b.crypto.oprf.suite("P256-SHA256").name !== undefined);
  check("unknown suite throws", code(function () { b.crypto.oprf.suite("x25519-sha256"); }) === "oprf/bad-suite");
}

function testRfc9497Vectors() {
  Object.keys(VEC).forEach(function (name) {
    var s = b.crypto.oprf.suite(name);
    var kp = s.oprf.deriveKeyPair(SEED, KEYINFO);
    check(name + ": deriveKeyPair reproduces skSm", toHex(kp.secretKey) === VEC[name].skSm);
    check(name + ": evaluate reproduces Output", toHex(s.oprf.evaluate(kp.secretKey, INPUT0)) === VEC[name].out);
  });
}

function testOprfRoundTrip() {
  var s = b.crypto.oprf.suite("ristretto255-sha512");
  var kp = s.oprf.deriveKeyPair(SEED, KEYINFO);
  var input = Buffer.from("user@example.com", "utf8");
  var c = s.oprf.blind(input);
  var ev = s.oprf.blindEvaluate(kp.secretKey, c.blinded);
  var out = toHex(s.oprf.finalize(input, c.blind, ev));
  // The output is blind-independent: the oblivious client result equals the
  // server's direct evaluation of the same key + input.
  check("oprf finalize == server evaluate (blind-independent)", out === toHex(s.oprf.evaluate(kp.secretKey, input)));
  // A fresh blind of the same input still finalizes to the same output.
  var c2 = s.oprf.blind(input);
  var ev2 = s.oprf.blindEvaluate(kp.secretKey, c2.blinded);
  check("oprf output stable across blinds", toHex(s.oprf.finalize(input, c2.blind, ev2)) === out);
  // Different input → different output.
  check("oprf output differs for different input", toHex(s.oprf.evaluate(kp.secretKey, Buffer.from("other"))) !== out);
}

function testVoprfRoundTripAndProof() {
  var s = b.crypto.oprf.suite("p256-sha256");
  var v = s.voprf;
  var kp = v.deriveKeyPair(SEED, KEYINFO);
  var input = Buffer.from("verifiable-input", "utf8");
  var c = v.blind(input);
  var ev = v.blindEvaluate(kp.secretKey, kp.publicKey, c.blinded);
  check("voprf blindEvaluate yields evaluated + proof", ev.evaluated && ev.proof);
  var out = toHex(v.finalize(input, c.blind, ev.evaluated, c.blinded, kp.publicKey, ev.proof));
  check("voprf finalize produces output", out.length > 0);
  // The verifiable client output matches the server-side VOPRF evaluate
  // (same mode). It is NOT the base-OPRF output — each mode mixes a
  // distinct context string, so the two modes produce different values.
  check("voprf finalize == server voprf.evaluate", out === toHex(v.evaluate(kp.secretKey, input)));
  check("voprf output differs from oprf output (distinct mode DST)", out !== toHex(s.oprf.evaluate(kp.secretKey, input)));
  // A tampered proof must make finalize reject (proof verification fails).
  var badProof = Buffer.from(ev.proof); badProof[0] ^= 0xff;
  check("voprf rejects a tampered proof", code(function () { v.finalize(input, c.blind, ev.evaluated, c.blinded, kp.publicKey, badProof); }) !== "NO-THROW");
  // Wrong public key must also reject.
  var otherKp = v.deriveKeyPair(Buffer.alloc(32, 0x11), KEYINFO);
  check("voprf rejects a mismatched public key", code(function () { v.finalize(input, c.blind, ev.evaluated, c.blinded, otherKp.publicKey, ev.proof); }) !== "NO-THROW");
}

async function run() {
  testSurface();
  testRfc9497Vectors();
  testOprfRoundTrip();
  testVoprfRoundTripAndProof();
}
module.exports = { run: run };
if (require.main === module) { run().then(function () { console.log("[crypto-oprf] OK — " + helpers.getChecks() + " checks passed"); }, function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }); }
