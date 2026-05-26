"use strict";
/**
 * Layer 0 — b.scitt (SCITT signed statements) over b.cose.
 * Covers the signed-statement round-trip, the integrity-protected
 * CWT_Claims (iss/sub) binding, refusal of a bare COSE_Sign1 that
 * carries no CWT_Claims, expected-issuer/subject enforcement, the
 * reserved-claim guard, content-type media-type strings, and that the
 * signature checks delegate to b.cose. Exercises the classical (ES256 /
 * EdDSA) algorithms and the ML-DSA-87 PQC-forward path.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
var nodeCrypto = require("node:crypto");

var EC = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
var ED = nodeCrypto.generateKeyPairSync("ed25519");
var SBOM = Buffer.from('{"spdxVersion":"SPDX-2.3","name":"widget"}', "utf8");

function testSurface() {
  check("b.scitt.signStatement exposed", typeof b.scitt.signStatement === "function");
  check("b.scitt.verifyStatement exposed", typeof b.scitt.verifyStatement === "function");
  check("b.scitt.CWT_CLAIMS_LABEL is RFC 9597 label 15", b.scitt.CWT_CLAIMS_LABEL === 15);
  check("b.scitt.ScittError exposed", typeof b.scitt.ScittError === "function");
}

async function testRoundTrip() {
  var stmt = await b.scitt.signStatement(SBOM, {
    alg: "ES256", privateKey: EC.privateKey,
    issuer: "https://builder.example", subject: "pkg:npm/widget@1.2.3",
    contentType: "application/spdx+json", claims: { 6: 1700000000 },
  });
  check("signed statement is bytes", Buffer.isBuffer(stmt));

  var out = await b.scitt.verifyStatement(stmt, {
    algorithms: ["ES256"], publicKey: EC.publicKey,
    expectedIssuer: "https://builder.example", expectedSubject: "pkg:npm/widget@1.2.3",
  });
  check("verify: payload round-trips", out.payload.equals(SBOM));
  check("verify: issuer extracted from CWT_Claims", out.issuer === "https://builder.example");
  check("verify: subject extracted from CWT_Claims", out.subject === "pkg:npm/widget@1.2.3");
  check("verify: extra CWT claim (iat) preserved", out.cwtClaims.get(6) === 1700000000);
  check("verify: alg reported", out.alg === "ES256");
  // Content type is a media-type STRING in the protected header (label 3).
  check("verify: content-type media-type string in protected header", out.protectedHeaders.get(3) === "application/spdx+json");
  // CWT_Claims live in the INTEGRITY-PROTECTED header (label 15), not unprotected.
  check("verify: CWT_Claims is in the protected header", out.protectedHeaders.get(15) instanceof Map);
}

async function testIdentityBindingRefusals() {
  var stmt = await b.scitt.signStatement(SBOM, {
    alg: "ES256", privateKey: EC.privateKey, issuer: "iss-a", subject: "sub-a",
  });

  var e1 = null;
  try {
    await b.scitt.verifyStatement(stmt, { algorithms: ["ES256"], publicKey: EC.publicKey, expectedIssuer: "iss-b" });
  } catch (e) { e1 = e; }
  check("verify: issuer mismatch refused", e1 && e1.code === "scitt/issuer-mismatch");

  var e2 = null;
  try {
    await b.scitt.verifyStatement(stmt, { algorithms: ["ES256"], publicKey: EC.publicKey, expectedSubject: "sub-b" });
  } catch (e) { e2 = e; }
  check("verify: subject mismatch refused", e2 && e2.code === "scitt/subject-mismatch");

  // A bare COSE_Sign1 (no CWT_Claims header) is NOT a SCITT statement.
  var bare = await b.cose.sign(SBOM, { alg: "ES256", privateKey: EC.privateKey });
  var e3 = null;
  try { await b.scitt.verifyStatement(bare, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { e3 = e; }
  check("verify: bare COSE_Sign1 (no CWT_Claims) refused", e3 && e3.code === "scitt/missing-cwt-claims");
}

async function testSignRefusals() {
  var refusals = [
    ["missing issuer", { alg: "ES256", privateKey: EC.privateKey, subject: "s" }, "scitt/bad-issuer"],
    ["empty issuer", { alg: "ES256", privateKey: EC.privateKey, issuer: "", subject: "s" }, "scitt/bad-issuer"],
    ["missing subject", { alg: "ES256", privateKey: EC.privateKey, issuer: "i" }, "scitt/bad-subject"],
    ["iss override via claims", { alg: "ES256", privateKey: EC.privateKey, issuer: "i", subject: "s", claims: { 1: "evil" } }, "scitt/reserved-claim"],
    ["sub override via claims", { alg: "ES256", privateKey: EC.privateKey, issuer: "i", subject: "s", claims: { 2: "evil" } }, "scitt/reserved-claim"],
    ["non-integer claim label", { alg: "ES256", privateKey: EC.privateKey, issuer: "i", subject: "s", claims: { 1.5: "x" } }, "scitt/bad-claim-label"],
  ];
  for (var i = 0; i < refusals.length; i++) {
    var err = null;
    try { await b.scitt.signStatement(SBOM, refusals[i][1]); } catch (e) { err = e; }
    check("signStatement refuses: " + refusals[i][0], err && err.code === refusals[i][2]);
  }
}

async function testTamperAndDelegation() {
  var stmt = await b.scitt.signStatement(SBOM, {
    alg: "ES256", privateKey: EC.privateKey, issuer: "i", subject: "s",
  });

  // Tampering the bytes fails the underlying COSE signature check.
  var bad = Buffer.from(stmt); bad[bad.length - 1] ^= 0xff;
  var t = null;
  try { await b.scitt.verifyStatement(bad, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { t = e; }
  check("verify: tampered statement refused by COSE signature", t && t.code === "cose/bad-signature");

  // The algorithm allowlist is mandatory and delegated to b.cose.verify.
  var a = null;
  try { await b.scitt.verifyStatement(stmt, { algorithms: ["EdDSA"], publicKey: EC.publicKey }); } catch (e) { a = e; }
  check("verify: alg outside allowlist refused (delegated to cose)", a && a.code === "cose/alg-not-allowed");
}

async function testEdDsaAndPqc() {
  // EdDSA (final COSE id, interoperable today).
  var s1 = await b.scitt.signStatement(SBOM, { alg: "EdDSA", privateKey: ED.privateKey, issuer: "i", subject: "s" });
  var o1 = await b.scitt.verifyStatement(s1, { algorithms: ["EdDSA"], publicKey: ED.publicKey });
  check("EdDSA: round-trips with iss/sub", o1.issuer === "i" && o1.subject === "s");

  // ML-DSA-87 (PQC-forward) — skip gracefully if the runtime lacks it.
  var mldsa = null;
  try { mldsa = nodeCrypto.generateKeyPairSync("ml-dsa-87"); } catch (_e) { mldsa = null; }
  if (mldsa) {
    var s2 = await b.scitt.signStatement(SBOM, { alg: "ML-DSA-87", privateKey: mldsa.privateKey, issuer: "pqc-iss", subject: "pqc-sub" });
    var o2 = await b.scitt.verifyStatement(s2, { algorithms: ["ML-DSA-87"], publicKey: mldsa.publicKey });
    check("ML-DSA-87: round-trips with iss/sub", o2.issuer === "pqc-iss" && o2.subject === "pqc-sub");
  } else {
    check("ML-DSA-87: runtime lacks ml-dsa-87 — classical path covers the contract", true);
  }
}

async function testExternalAadBinding() {
  var aad = Buffer.from("registration-context", "utf8");
  var stmt = await b.scitt.signStatement(SBOM, {
    alg: "ES256", privateKey: EC.privateKey, issuer: "i", subject: "s", externalAad: aad,
  });
  var ok = await b.scitt.verifyStatement(stmt, { algorithms: ["ES256"], publicKey: EC.publicKey, externalAad: aad });
  check("externalAad: matching context verifies", ok.subject === "s");

  var mism = null;
  try {
    await b.scitt.verifyStatement(stmt, { algorithms: ["ES256"], publicKey: EC.publicKey, externalAad: Buffer.from("other") });
  } catch (e) { mism = e; }
  check("externalAad: mismatched context refused", mism && mism.code === "cose/bad-signature");
}

async function run() {
  testSurface();
  await testRoundTrip();
  await testIdentityBindingRefusals();
  await testSignRefusals();
  await testTamperAndDelegation();
  await testEdDsaAndPqc();
  await testExternalAadBinding();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[scitt] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
