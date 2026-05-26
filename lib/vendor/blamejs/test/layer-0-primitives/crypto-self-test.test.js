"use strict";
/**
 * Layer 0 — b.crypto.selfTest (FIPS 140-3-style power-on self-test).
 * Confirms the KATs (NIST FIPS 202 SHA3/SHAKE vectors), the AEAD
 * round-trip + tamper-detect, and the PQC pairwise-consistency +
 * negative checks all run and pass, and that the report shape +
 * throwOnFailure contract hold.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
var nodeCrypto = require("node:crypto");

var EXPECTED = [
  "SHA3-512 KAT (FIPS 202)",
  "SHA3-256 KAT (FIPS 202)",
  "SHAKE256 KAT (FIPS 202)",
  "HMAC-SHA3-512 determinism",
  "XChaCha20-Poly1305 round-trip + tamper-detect",
  "ML-KEM-1024 encaps/decaps pairwise consistency",
  "ML-DSA-87 sign/verify + negative",
  "SLH-DSA-SHAKE-256f sign/verify + negative",
];

function testSurface() {
  check("b.crypto.selfTest is a function", typeof b.crypto.selfTest === "function");
}

function testAllPass() {
  var r = b.crypto.selfTest();
  check("selfTest: ok true", r.ok === true);
  check("selfTest: no failures", r.failures.length === 0);
  check("selfTest: ranAt is an ISO timestamp", typeof r.ranAt === "string" && !isNaN(Date.parse(r.ranAt)));
  // every expected check ran and passed
  var names = r.results.map(function (x) { return x.name; });
  EXPECTED.forEach(function (name) {
    check("selfTest ran + passed: " + name, names.indexOf(name) !== -1 && r.results[names.indexOf(name)].ok === true);
  });
}

function testKatMatchesNistVectors() {
  // Independent cross-check of the KAT references against node's own
  // FIPS-validated SHA3 (the self-test's hash digests are the standard
  // FIPS 202 answers, not framework-vs-framework).
  check("SHA3-512(abc) is the FIPS 202 vector",
    b.crypto.sha3Hash("abc") === nodeCrypto.createHash("sha3-512").update("abc").digest("hex"));
  check("SHA3-512(abc) starts with the published prefix",
    b.crypto.sha3Hash("abc").indexOf("b751850b1a57168a") === 0);
}

function testReportContract() {
  // throwOnFailure:false always returns the structured report.
  var r = b.crypto.selfTest({ throwOnFailure: false });
  check("throwOnFailure:false returns a report", r && Array.isArray(r.results) && typeof r.ok === "boolean");
  // each result carries a name + ok boolean
  check("each result has name + ok", r.results.every(function (x) { return typeof x.name === "string" && typeof x.ok === "boolean"; }));
}

async function run() {
  testSurface();
  testAllPass();
  testKatMatchesNistVectors();
  testReportContract();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[crypto-self-test] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
