// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.cwt (RFC 8392 CBOR Web Token) = COSE_Sign1 over a CBOR
 * claims map. Composes b.cose (signature + alg allowlist) + b.cbor.
 * Covers round-trip + standard-claim mapping + exp/nbf/iss/aud
 * enforcement + tag-61 + tamper (delegated to cose).
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
var nodeCrypto = require("node:crypto");

var EC = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
function _now() { return Math.floor(Date.now() / 1000); }

function testSurface() {
  check("b.cwt.sign exposed", typeof b.cwt.sign === "function");
  check("b.cwt.verify exposed", typeof b.cwt.verify === "function");
  check("b.cwt.CLAIM_LABELS maps standard claims", b.cwt.CLAIM_LABELS.iss === 1 && b.cwt.CLAIM_LABELS.exp === 4 && b.cwt.CLAIM_LABELS.cti === 7);
  check("b.cwt.CwtError exposed", typeof b.cwt.CwtError === "function");
}

async function testRoundTrip() {
  var now = _now();
  var cwt = await b.cwt.sign(
    { iss: "issuer.example", sub: "dev-42", aud: "svc", exp: now + 3600, nbf: now - 10, iat: now, scope: "telemetry" },
    { alg: "ES256", privateKey: EC.privateKey, kid: "k1" });
  check("sign: produces a COSE_Sign1 (tag 18 → 0xd2)", cwt[0] === 0xd2);
  var v = await b.cwt.verify(cwt, { algorithms: ["ES256"], publicKey: EC.publicKey });
  check("verify: standard claims mapped back to names", v.claims.iss === "issuer.example" && v.claims.sub === "dev-42" && v.claims.exp === now + 3600);
  check("verify: custom claim preserved", v.claims.scope === "telemetry");
  check("verify: raw Map uses integer labels", v.raw.get(1) === "issuer.example" && v.raw.get(4) === now + 3600);
  check("verify: alg surfaced", v.alg === "ES256");
}

async function testTimeClaims() {
  var now = _now();
  var expired = await b.cwt.sign({ exp: now - 3600 }, { alg: "ES256", privateKey: EC.privateKey });
  var e1 = null;
  try { await b.cwt.verify(expired, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { e1 = e; }
  check("verify: expired token refused", e1 && e1.code === "cwt/expired");

  var future = await b.cwt.sign({ nbf: now + 3600 }, { alg: "ES256", privateKey: EC.privateKey });
  var e2 = null;
  try { await b.cwt.verify(future, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { e2 = e; }
  check("verify: not-yet-valid (nbf) token refused", e2 && e2.code === "cwt/not-yet-valid");

  // Clock skew tolerance: exp 30s in the past passes with 60s skew.
  var justExpired = await b.cwt.sign({ exp: now - 30 }, { alg: "ES256", privateKey: EC.privateKey });
  var skewOk = await b.cwt.verify(justExpired, { algorithms: ["ES256"], publicKey: EC.publicKey, clockSkewSec: 60 });
  check("verify: clock skew tolerates marginally-expired exp", skewOk.claims.exp === now - 30);

  // now override (testing): a token valid in the future verifies if now is advanced.
  var fut = await b.cwt.sign({ nbf: now + 100, exp: now + 200 }, { alg: "ES256", privateKey: EC.privateKey });
  var adv = await b.cwt.verify(fut, { algorithms: ["ES256"], publicKey: EC.publicKey, now: (now + 150) * 1000 });
  check("verify: now override advances the clock", adv.claims.nbf === now + 100);
}

async function testIssuerAudience() {
  var cwt = await b.cwt.sign({ iss: "iss-A", aud: ["svc-1", "svc-2"] }, { alg: "ES256", privateKey: EC.privateKey });
  var ok = await b.cwt.verify(cwt, { algorithms: ["ES256"], publicKey: EC.publicKey, expectedIssuer: "iss-A", expectedAudience: "svc-2" });
  check("verify: matching iss + aud (array) accepted", ok.claims.iss === "iss-A");
  var e1 = null;
  try { await b.cwt.verify(cwt, { algorithms: ["ES256"], publicKey: EC.publicKey, expectedIssuer: "iss-B" }); } catch (e) { e1 = e; }
  check("verify: issuer mismatch refused", e1 && e1.code === "cwt/issuer-mismatch");
  var e2 = null;
  try { await b.cwt.verify(cwt, { algorithms: ["ES256"], publicKey: EC.publicKey, expectedAudience: "svc-3" }); } catch (e) { e2 = e; }
  check("verify: audience not in aud array refused", e2 && e2.code === "cwt/audience-mismatch");
}

async function testTaggedAndTamper() {
  var tagged = await b.cwt.sign({ iss: "x" }, { alg: "ES256", privateKey: EC.privateKey, tagged: true });
  check("sign: tagged wraps in CWT tag 61 (0xd8 0x3d)", tagged[0] === 0xd8 && tagged[1] === 0x3d);
  var v = await b.cwt.verify(tagged, { algorithms: ["ES256"], publicKey: EC.publicKey });
  check("verify: accepts tag-61-wrapped CWT", v.claims.iss === "x");

  var cwt = await b.cwt.sign({ iss: "y" }, { alg: "ES256", privateKey: EC.privateKey });
  var t = Buffer.from(cwt); t[t.length - 1] ^= 0xff;
  var tampered = null;
  try { await b.cwt.verify(t, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { tampered = e; }
  check("verify: tampered token refused by the COSE signature check", tampered && tampered.code === "cose/bad-signature");
}

async function testRobustTagAndMalformedClaims() {
  // Codex P1 on PR #185 — a non-minimal CBOR tag-61 encoding
  // (0xd9 0x00 0x3d, the 2-byte-argument form) must still be unwrapped.
  var bare = await b.cwt.sign({ iss: "x" }, { alg: "ES256", privateKey: EC.privateKey });
  var nonMinimal = Buffer.concat([Buffer.from([0xd9, 0x00, 0x3d]), bare]);
  var v = await b.cwt.verify(nonMinimal, { algorithms: ["ES256"], publicKey: EC.publicKey });
  check("verify: non-minimal tag-61 encoding accepted (interop)", v.claims.iss === "x");

  // Codex P2 on PR #185 — a present-but-non-numeric exp must be
  // refused, not silently skipped (it would otherwise never expire).
  var badExp = b.cbor.encode(new Map([[1, "iss-A"], [4, "whenever"]]));   // label 4 = exp, string value
  var badToken = await b.cose.sign(badExp, { alg: "ES256", privateKey: EC.privateKey });
  var e1 = null;
  try { await b.cwt.verify(badToken, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { e1 = e; }
  check("verify: malformed (non-numeric) exp refused", e1 && e1.code === "cwt/malformed-claim");

  var badNbf = b.cbor.encode(new Map([[5, "soon"]]));   // label 5 = nbf
  var badNbfToken = await b.cose.sign(badNbf, { alg: "ES256", privateKey: EC.privateKey });
  var e2 = null;
  try { await b.cwt.verify(badNbfToken, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { e2 = e; }
  check("verify: malformed (non-numeric) nbf refused", e2 && e2.code === "cwt/malformed-claim");
}

async function testClockSkewInfinityRejected() {
  // A non-finite clockSkewSec must be a config error, NOT a silent
  // expiry-disable: the check is `now > exp + skew`, so skew === Infinity
  // makes it `now > Infinity` (always false) and ANY expired token would
  // verify. A present-but-invalid skew (Infinity / NaN / negative /
  // non-integer) is refused at the entry point.
  var now = _now();
  var expired = await b.cwt.sign({ exp: now - 100000 }, { alg: "ES256", privateKey: EC.privateKey });
  var errInf = null;
  try {
    await b.cwt.verify(expired, { algorithms: ["ES256"], publicKey: EC.publicKey, clockSkewSec: Infinity });
  } catch (e) { errInf = e; }
  check("verify: clockSkewSec Infinity refused (does not disable expiry)",
    errInf && errInf.code === "cwt/bad-clock-skew");

  var errNeg = null;
  try {
    await b.cwt.verify(expired, { algorithms: ["ES256"], publicKey: EC.publicKey, clockSkewSec: -1 });
  } catch (e) { errNeg = e; }
  check("verify: negative clockSkewSec refused", errNeg && errNeg.code === "cwt/bad-clock-skew");

  // Absent skew still applies the default (marginally-expired tolerated),
  // and a valid finite skew still works — the fix must not regress those.
  var justExpired = await b.cwt.sign({ exp: now - 30 }, { alg: "ES256", privateKey: EC.privateKey });
  var ok = await b.cwt.verify(justExpired, { algorithms: ["ES256"], publicKey: EC.publicKey, clockSkewSec: 60 });
  check("verify: a valid finite skew still tolerates a marginally-expired token", ok.claims.exp === now - 30);
}

async function testValidation() {
  var bad = null;
  try { await b.cwt.sign({ exp: "not-a-number" }, { alg: "ES256", privateKey: EC.privateKey }); } catch (e) { bad = e; }
  check("sign: non-integer NumericDate refused", bad && bad.code === "cwt/bad-numeric-date");
  var noAlg = null;
  try { await b.cwt.verify(await b.cwt.sign({ iss: "z" }, { alg: "ES256", privateKey: EC.privateKey }), { publicKey: EC.publicKey }); } catch (e) { noAlg = e; }
  check("verify: missing algorithms refused (delegated to cose)", noAlg !== null);
  var badInput = null;
  try { await b.cwt.verify("not-a-buffer", { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { badInput = e; }
  check("verify: non-buffer input refused", badInput && badInput.code === "cwt/bad-input");
}

async function run() {
  testSurface();
  await testRoundTrip();
  await testTimeClaims();
  await testIssuerAudience();
  await testTaggedAndTamper();
  await testRobustTagAndMalformedClaims();
  await testClockSkewInfinityRejected();
  await testValidation();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[cwt] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
