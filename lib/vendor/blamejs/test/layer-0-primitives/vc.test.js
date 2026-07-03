// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.vc (W3C Verifiable Credentials 2.0, VC-JOSE-COSE).
 * Covers JOSE (compact JWS, vc+jwt) and COSE (COSE_Sign1, vc+cose)
 * securing round-trips, the byte-exact credential payload (no injected
 * JWT claims), VCDM structural validation, the validFrom / validUntil
 * window, expected-issuer enforcement, the mandatory algorithm
 * allowlist, and refusal of the JOSE `none` algorithm.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
var nodeCrypto = require("node:crypto");

var EC = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
var ED = nodeCrypto.generateKeyPairSync("ed25519");

// Sign an arbitrary header + payload as a compact JWS with the EC key —
// bypasses b.vc.issue's validation so the verify-side fail-closed paths
// (malformed validity, crit) can be exercised on a real signature.
function _rawJose(header, payloadObj) {
  var h = Buffer.from(JSON.stringify(header), "utf8").toString("base64url");
  var p = Buffer.from(JSON.stringify(payloadObj), "utf8").toString("base64url");
  var signingInput = h + "." + p;
  var sig = nodeCrypto.sign("sha256", Buffer.from(signingInput, "ascii"), { key: EC.privateKey, dsaEncoding: "ieee-p1363" });
  return signingInput + "." + sig.toString("base64url");
}

function _cred(extra) {
  return Object.assign({
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential", "ExampleDegree"],
    "issuer": "did:example:issuer123",
    "credentialSubject": { "id": "did:example:subject", "degree": "BS" },
  }, extra || {});
}

function testSurface() {
  check("b.vc.issue is a function", typeof b.vc.issue === "function");
  check("b.vc.verify is a function", typeof b.vc.verify === "function");
  check("b.vc.VCDM_V2_CONTEXT is the v2 context", b.vc.VCDM_V2_CONTEXT === "https://www.w3.org/ns/credentials/v2");
  check("b.vc.JOSE_ALGS includes ES256 + EdDSA", !!b.vc.JOSE_ALGS.ES256 && !!b.vc.JOSE_ALGS.EdDSA);
  check("b.vc.VcError is a class", typeof b.vc.VcError === "function");
}

async function testJoseRoundTrip() {
  var jws = await b.vc.issue(_cred(), { securing: "jose", alg: "ES256", privateKey: EC.privateKey, kid: "k1", cty: "vc" });
  check("jose: compact JWS has 3 segments", typeof jws === "string" && jws.split(".").length === 3);
  var header = JSON.parse(Buffer.from(jws.split(".")[0], "base64url").toString("utf8"));
  check("jose: typ header is vc+jwt", header.typ === "vc+jwt");
  check("jose: cty + kid headers present", header.cty === "vc" && header.kid === "k1");
  var payload = JSON.parse(Buffer.from(jws.split(".")[1], "base64url").toString("utf8"));
  check("jose: payload is the credential, no injected iat/vc claim", payload.iat === undefined && payload.vc === undefined && payload.issuer === "did:example:issuer123");

  var out = await b.vc.verify(jws, { algorithms: ["ES256"], publicKey: EC.publicKey, expectedIssuer: "did:example:issuer123" });
  check("jose verify: securing detected", out.securing === "jose");
  check("jose verify: alg + issuer", out.alg === "ES256" && out.issuer === "did:example:issuer123");
  check("jose verify: credential returned", out.credential.credentialSubject.degree === "BS");

  // EdDSA
  var jed = await b.vc.issue(_cred(), { securing: "jose", alg: "EdDSA", privateKey: ED.privateKey });
  var jedv = await b.vc.verify(jed, { algorithms: ["EdDSA"], publicKey: ED.publicKey });
  check("jose EdDSA: round-trips", jedv.issuer === "did:example:issuer123");
}

async function testCoseRoundTrip() {
  var token = await b.vc.issue(_cred(), { securing: "cose", alg: "ES256", privateKey: EC.privateKey });
  check("cose: returns tagged COSE_Sign1 bytes", Buffer.isBuffer(token) && token[0] === 0xd2);
  var out = await b.vc.verify(token, { algorithms: ["ES256"], publicKey: EC.publicKey, expectedIssuer: "did:example:issuer123" });
  check("cose verify: securing detected", out.securing === "cose");
  check("cose verify: credential returned", out.credential.type.indexOf("VerifiableCredential") !== -1);

  // ML-DSA-87 PQC-forward (skip gracefully if the runtime lacks it).
  var ml = null;
  try { ml = nodeCrypto.generateKeyPairSync("ml-dsa-87"); } catch (_e) { ml = null; }
  if (ml) {
    var t2 = await b.vc.issue(_cred(), { securing: "cose", alg: "ML-DSA-87", privateKey: ml.privateKey });
    var o2 = await b.vc.verify(t2, { algorithms: ["ML-DSA-87"], publicKey: ml.publicKey });
    check("cose ML-DSA-87: round-trips", o2.issuer === "did:example:issuer123");
  } else {
    check("cose ML-DSA-87: runtime lacks it — classical path covers the contract", true);
  }
}

async function testRefusals() {
  var jws = await b.vc.issue(_cred(), { securing: "jose", alg: "ES256", privateKey: EC.privateKey });

  var e1 = null;
  try { await b.vc.verify(jws, { algorithms: ["EdDSA"], publicKey: EC.publicKey }); } catch (e) { e1 = e; }
  check("verify: alg outside allowlist refused", e1 && e1.code === "vc/alg-not-allowed");

  // tampered payload
  var parts = jws.split(".");
  parts[1] = Buffer.from(JSON.stringify(_cred({ issuer: "did:evil" })), "utf8").toString("base64url");
  var e2 = null;
  try { await b.vc.verify(parts.join("."), { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { e2 = e; }
  check("verify: tampered payload refused", e2 && e2.code === "vc/bad-signature");

  // alg none always refused
  var noneTok = Buffer.from(JSON.stringify({ alg: "none", typ: "vc+jwt" }), "utf8").toString("base64url") +
    "." + Buffer.from(JSON.stringify(_cred()), "utf8").toString("base64url") + ".";
  var e3 = null;
  try { await b.vc.verify(noneTok, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { e3 = e; }
  check("verify: JOSE alg 'none' refused", e3 && e3.code === "vc/bad-alg");

  // expectedIssuer mismatch
  var e4 = null;
  try { await b.vc.verify(jws, { algorithms: ["ES256"], publicKey: EC.publicKey, expectedIssuer: "did:other" }); } catch (e) { e4 = e; }
  check("verify: expectedIssuer mismatch refused", e4 && e4.code === "vc/issuer-mismatch");

  // invalid opts.at Date refused (lesson carried from b.tsa)
  var e5 = null;
  try { await b.vc.verify(jws, { algorithms: ["ES256"], publicKey: EC.publicKey, at: new Date("nope") }); } catch (e) { e5 = e; }
  check("verify: invalid opts.at refused", e5 && e5.code === "vc/bad-at");

  // crit-bypass defense: a critical header extension the verifier does
  // not implement must be refused (the check precedes signature verify).
  var critTok = _rawJose({ alg: "ES256", typ: "vc+jwt", crit: ["https://example/ext"] }, _cred());
  var e6 = null;
  try { await b.vc.verify(critTok, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { e6 = e; }
  check("verify: JWS crit header refused", e6 && e6.code === "vc/crit-unsupported");

  // A malformed validity field on a validly-signed credential fails
  // closed at verify (not just at issue) — no silent skip.
  var badValidityTok = _rawJose({ alg: "ES256", typ: "vc+jwt" }, _cred({ validUntil: "not-a-date" }));
  var e7 = null;
  try { await b.vc.verify(badValidityTok, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { e7 = e; }
  check("verify: malformed validUntil refused (fail closed)", e7 && e7.code === "vc/bad-validity");
}

async function testTemporalAndStructural() {
  // validUntil in the past → expired
  var je = await b.vc.issue(_cred({ validUntil: "2020-01-01T00:00:00Z" }), { securing: "jose", alg: "ES256", privateKey: EC.privateKey });
  var e1 = null;
  try { await b.vc.verify(je, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { e1 = e; }
  check("verify: expired credential refused", e1 && e1.code === "vc/expired");

  // validFrom in the future → not yet valid
  var jf = await b.vc.issue(_cred({ validFrom: "2099-01-01T00:00:00Z" }), { securing: "jose", alg: "ES256", privateKey: EC.privateKey });
  var e2 = null;
  try { await b.vc.verify(jf, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { e2 = e; }
  check("verify: not-yet-valid credential refused", e2 && e2.code === "vc/not-yet-valid");

  // opts.at lets a verifier check validity at a chosen instant
  var ok = await b.vc.verify(je, { algorithms: ["ES256"], publicKey: EC.publicKey, at: new Date("2019-06-01T00:00:00Z") });
  check("verify: opts.at within window accepts", ok.issuer === "did:example:issuer123");

  // issue refuses a malformed VCDM credential
  var structural = [
    ["missing v2 context", { "@context": ["https://other"], type: ["VerifiableCredential"], issuer: "x", credentialSubject: {} }, "vc/bad-context"],
    ["missing VerifiableCredential type", { "@context": ["https://www.w3.org/ns/credentials/v2"], type: ["Foo"], issuer: "x", credentialSubject: {} }, "vc/bad-type"],
    ["missing issuer", { "@context": ["https://www.w3.org/ns/credentials/v2"], type: ["VerifiableCredential"], credentialSubject: {} }, "vc/no-issuer"],
    ["missing credentialSubject", { "@context": ["https://www.w3.org/ns/credentials/v2"], type: ["VerifiableCredential"], issuer: "x" }, "vc/no-subject"],
  ];
  for (var i = 0; i < structural.length; i++) {
    var err = null;
    try { await b.vc.issue(structural[i][1], { securing: "jose", alg: "ES256", privateKey: EC.privateKey }); } catch (e) { err = e; }
    check("issue refuses: " + structural[i][0], err && err.code === structural[i][2]);
  }

  // issue refuses a malformed validity datetime (structural, fail closed)
  var em = null;
  try { await b.vc.issue(_cred({ validFrom: "yesterday" }), { securing: "jose", alg: "ES256", privateKey: EC.privateKey }); } catch (e) { em = e; }
  check("issue refuses malformed validFrom", em && em.code === "vc/bad-validity");

  // issuer-as-object { id } is accepted
  var jo = await b.vc.issue(_cred({ issuer: { id: "did:example:obj", name: "Acme" } }), { securing: "jose", alg: "ES256", privateKey: EC.privateKey });
  var oo = await b.vc.verify(jo, { algorithms: ["ES256"], publicKey: EC.publicKey, expectedIssuer: "did:example:obj" });
  check("verify: object issuer id extracted", oo.issuer === "did:example:obj");
}

async function testPresentation() {
  var HOLDER = nodeCrypto.generateKeyPairSync("ed25519");
  var holderId = "did:example:holder";
  var jws = await b.vc.issue(_cred(), { securing: "jose", alg: "ES256", privateKey: EC.privateKey });

  // jose VP wrapping a VC, with nonce + audience holder-binding
  var vp = await b.vc.present({
    credentials: [jws], holder: holderId, securing: "jose", alg: "EdDSA", privateKey: HOLDER.privateKey,
    nonce: "chal-1", audience: "https://verifier.example",
  });
  check("present: VP is a compact JWS", typeof vp === "string" && vp.split(".").length === 3);
  check("present: typ vp+jwt", JSON.parse(Buffer.from(vp.split(".")[0], "base64url").toString("utf8")).typ === "vp+jwt");

  var out = await b.vc.verifyPresentation(vp, {
    algorithms: ["EdDSA"], publicKey: HOLDER.publicKey, expectedHolder: holderId,
    nonce: "chal-1", audience: "https://verifier.example",
    verifyCredentials: true, credentialOpts: { algorithms: ["ES256"], publicKey: EC.publicKey },
  });
  check("verifyPresentation: holder returned", out.holder === holderId && out.securing === "jose");
  check("verifyPresentation: enclosed VC verified", out.credentials.length === 1 && out.credentials[0].credential.credentialSubject.degree === "BS");

  // cose VP
  var coseVc = await b.vc.issue(_cred(), { securing: "cose", alg: "ES256", privateKey: EC.privateKey });
  var vpc = await b.vc.present({ credentials: [coseVc], holder: holderId, securing: "cose", alg: "EdDSA", privateKey: HOLDER.privateKey });
  var outc = await b.vc.verifyPresentation(vpc, { algorithms: ["EdDSA"], publicKey: HOLDER.publicKey, verifyCredentials: true, credentialOpts: { algorithms: ["ES256"], publicKey: EC.publicKey } });
  check("cose VP: round-trips + enclosed VC verified", outc.holder === holderId && outc.credentials.length === 1);

  // refusals
  var e1 = null;
  try { await b.vc.verifyPresentation(vp, { algorithms: ["EdDSA"], publicKey: HOLDER.publicKey, nonce: "wrong" }); } catch (e) { e1 = e; }
  check("verifyPresentation: nonce mismatch refused", e1 && e1.code === "vc/nonce-mismatch");
  var e2 = null;
  try { await b.vc.verifyPresentation(vp, { algorithms: ["EdDSA"], publicKey: HOLDER.publicKey, audience: "https://other" }); } catch (e) { e2 = e; }
  check("verifyPresentation: audience mismatch refused", e2 && e2.code === "vc/audience-mismatch");
  var e3 = null;
  try { await b.vc.verifyPresentation(vp, { algorithms: ["EdDSA"], publicKey: HOLDER.publicKey, expectedHolder: "did:example:other" }); } catch (e) { e3 = e; }
  check("verifyPresentation: holder mismatch refused", e3 && e3.code === "vc/holder-mismatch");
  // verifying the VP with the wrong typ (a VC) must fail typ check
  var e4 = null;
  try { await b.vc.verifyPresentation(jws, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { e4 = e; }
  check("verifyPresentation: a VC (vc+jwt) is refused as a VP", e4 && e4.code === "vc/bad-typ");
  // a VP cannot be verified as a VC
  var e5 = null;
  try { await b.vc.verify(vp, { algorithms: ["EdDSA"], publicKey: HOLDER.publicKey }); } catch (e) { e5 = e; }
  check("verify: a VP (vp+jwt) is refused as a VC", e5 && e5.code === "vc/bad-typ");
  // present requires credentials + holder
  var e6 = null;
  try { await b.vc.present({ credentials: [], holder: holderId, securing: "jose", alg: "EdDSA", privateKey: HOLDER.privateKey }); } catch (e) { e6 = e; }
  check("present: empty credentials refused", e6 && e6.code === "vc/no-credentials");

  // A holder-signed VP with a NON-ARRAY verifiableCredential must fail
  // closed (not coerce to [] and skip credential verification).
  var badVp = { "@context": ["https://www.w3.org/ns/credentials/v2"], type: ["VerifiablePresentation"], holder: holderId, verifiableCredential: { foo: "bar" } };
  var h = Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "vp+jwt" }), "utf8").toString("base64url");
  var p = Buffer.from(JSON.stringify(badVp), "utf8").toString("base64url");
  var si = h + "." + p;
  var badVpJws = si + "." + nodeCrypto.sign(null, Buffer.from(si, "ascii"), HOLDER.privateKey).toString("base64url");
  var e7 = null;
  try { await b.vc.verifyPresentation(badVpJws, { algorithms: ["EdDSA"], publicKey: HOLDER.publicKey, verifyCredentials: true, credentialOpts: { algorithms: ["ES256"], publicKey: EC.publicKey } }); } catch (e) { e7 = e; }
  check("verifyPresentation: non-array verifiableCredential refused (no bypass)", e7 && e7.code === "vc/bad-presentation");
}

async function testAlgKeyBinding() {
  // RFC 7518 §3.4: ES384 is bound to curve P-384. A JWS whose header claims
  // ES384 but is keyed with a P-256 key must be refused BEFORE the signature
  // verify — the verifier must not let the attacker pick an alg independent of
  // the key's curve (ECDSA curve/type confusion, CWE-347).
  var mismatched = _rawJose({ alg: "ES384", typ: "vc+jwt" }, _cred());
  var e1 = null;
  try { await b.vc.verify(mismatched, { algorithms: ["ES384"], publicKey: EC.publicKey }); } catch (e) { e1 = e; }
  check("jose verify: ES384 header on a P-256 key throws alg-key-mismatch",
    e1 && /vc\/alg-key-mismatch/.test(e1.code || ""));
  // EdDSA alg with an EC key is likewise refused.
  var mismatched2 = _rawJose({ alg: "EdDSA", typ: "vc+jwt" }, _cred());
  var e2 = null;
  try { await b.vc.verify(mismatched2, { algorithms: ["EdDSA"], publicKey: EC.publicKey }); } catch (e) { e2 = e; }
  check("jose verify: EdDSA header on an EC key throws alg-key-mismatch",
    e2 && /vc\/alg-key-mismatch/.test(e2.code || ""));
  // The matched pair (ES256 + P-256) still verifies — no over-rejection.
  var okTok = await b.vc.issue(_cred(), { securing: "jose", alg: "ES256", privateKey: EC.privateKey });
  var okOut = await b.vc.verify(okTok, { algorithms: ["ES256"], publicKey: EC.publicKey, expectedIssuer: "did:example:issuer123" });
  check("jose verify: matched ES256 + P-256 still verifies", okOut.securing === "jose");
}

async function run() {
  testSurface();
  await testJoseRoundTrip();
  await testAlgKeyBinding();
  await testCoseRoundTrip();
  await testRefusals();
  await testTemporalAndStructural();
  await testPresentation();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[vc] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
