// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.eat (RFC 9711 Entity Attestation Token) over b.cwt.
 * Covers EAT claim-label mapping, the verifier-nonce freshness
 * binding, debug-status policy, profile pinning, and that the
 * signature / time checks delegate to b.cwt / b.cose.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
var nodeCrypto = require("node:crypto");

var EC = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
function _now() { return Math.floor(Date.now() / 1000); }

function testSurface() {
  check("b.eat.sign exposed", typeof b.eat.sign === "function");
  check("b.eat.verify exposed", typeof b.eat.verify === "function");
  check("b.eat.CLAIM_LABELS has RFC 9711 keys", b.eat.CLAIM_LABELS.nonce === 10 && b.eat.CLAIM_LABELS.dbgstat === 263 && b.eat.CLAIM_LABELS.eat_profile === 265);
  check("b.eat.DBGSTAT enum", b.eat.DBGSTAT["disabled-permanently"] === 3 && b.eat.DBGSTAT.enabled === 0);
  check("b.eat.EatError exposed", typeof b.eat.EatError === "function");
}

async function testRoundTripAndLabels() {
  var nonce = b.crypto.generateBytes(16);
  var eat = await b.eat.sign(
    { nonce: nonce, ueid: Buffer.from([1, 2, 3, 4]), oemid: Buffer.from("acme"), dbgstat: "disabled-permanently",
      eat_profile: "https://example.com/eat/p1", iss: "device-ca", iat: _now() },
    { alg: "ES256", privateKey: EC.privateKey });
  var v = await b.eat.verify(eat, { algorithms: ["ES256"], publicKey: EC.publicKey, expectedNonce: nonce });
  check("verify: friendly EAT claim names returned", Buffer.isBuffer(v.claims.ueid) && v.claims.eat_profile === "https://example.com/eat/p1");
  check("verify: dbgstat decoded to enum name", v.claims.dbgstat === "disabled-permanently");
  check("verify: standard claim (iss) still named", v.claims.iss === "device-ca");
  check("verify: raw Map uses RFC 9711 integer labels", v.raw.get(10) !== undefined && v.raw.get(263) === 3 && v.raw.get(265) === "https://example.com/eat/p1");
}

async function testNonceBinding() {
  var nonce = b.crypto.generateBytes(16);
  var eat = await b.eat.sign({ nonce: nonce, ueid: Buffer.from([9]) }, { alg: "ES256", privateKey: EC.privateKey });
  var ok = await b.eat.verify(eat, { algorithms: ["ES256"], publicKey: EC.publicKey, expectedNonce: nonce });
  check("nonce: matching expectedNonce accepted", Buffer.isBuffer(ok.claims.nonce));
  var mismatch = null;
  try { await b.eat.verify(eat, { algorithms: ["ES256"], publicKey: EC.publicKey, expectedNonce: b.crypto.generateBytes(16) }); } catch (e) { mismatch = e; }
  check("nonce: mismatch refused (replay/freshness defense)", mismatch && mismatch.code === "eat/nonce-mismatch");
  // Token with no nonce but RP expects one → refused.
  var noNonce = await b.eat.sign({ ueid: Buffer.from([1]) }, { alg: "ES256", privateKey: EC.privateKey });
  var missing = null;
  try { await b.eat.verify(noNonce, { algorithms: ["ES256"], publicKey: EC.publicKey, expectedNonce: nonce }); } catch (e) { missing = e; }
  check("nonce: expectedNonce but no eat_nonce claim refused", missing && missing.code === "eat/nonce-missing");
  // Array-of-nonces (multi-verifier) membership.
  var multi = await b.eat.sign({ nonce: [b.crypto.generateBytes(16), nonce] }, { alg: "ES256", privateKey: EC.privateKey });
  var m = await b.eat.verify(multi, { algorithms: ["ES256"], publicKey: EC.publicKey, expectedNonce: nonce });
  check("nonce: array form matches when one entry equals expectedNonce", Array.isArray(m.claims.nonce));
}

async function testDebugStatusAndProfile() {
  var enabled = await b.eat.sign({ dbgstat: "enabled" }, { alg: "ES256", privateKey: EC.privateKey });
  var e1 = null;
  try { await b.eat.verify(enabled, { algorithms: ["ES256"], publicKey: EC.publicKey, requireDebugDisabled: true }); } catch (e) { e1 = e; }
  check("dbgstat: enabled refused under requireDebugDisabled", e1 && e1.code === "eat/debug-not-disabled");

  var absent = await b.eat.sign({ ueid: Buffer.from([1]) }, { alg: "ES256", privateKey: EC.privateKey });
  var e2 = null;
  try { await b.eat.verify(absent, { algorithms: ["ES256"], publicKey: EC.publicKey, requireDebugDisabled: true }); } catch (e) { e2 = e; }
  check("dbgstat: absent refused under requireDebugDisabled", e2 && e2.code === "eat/debug-not-disabled");

  var disabled = await b.eat.sign({ dbgstat: "disabled-fully-and-permanently" }, { alg: "ES256", privateKey: EC.privateKey });
  var ok = await b.eat.verify(disabled, { algorithms: ["ES256"], publicKey: EC.publicKey, requireDebugDisabled: true });
  check("dbgstat: a disabled state passes", ok.claims.dbgstat === "disabled-fully-and-permanently");

  var prof = await b.eat.sign({ eat_profile: "p-A" }, { alg: "ES256", privateKey: EC.privateKey });
  var e3 = null;
  try { await b.eat.verify(prof, { algorithms: ["ES256"], publicKey: EC.publicKey, expectedProfile: "p-B" }); } catch (e) { e3 = e; }
  check("profile: expectedProfile mismatch refused", e3 && e3.code === "eat/profile-mismatch");
}

async function testValidationAndTamper() {
  var bad = null;
  try { await b.eat.sign({ dbgstat: "bogus" }, { alg: "ES256", privateKey: EC.privateKey }); } catch (e) { bad = e; }
  check("sign: bad dbgstat enum refused", bad && bad.code === "eat/bad-dbgstat");

  var eat = await b.eat.sign({ nonce: b.crypto.generateBytes(16) }, { alg: "ES256", privateKey: EC.privateKey });
  var t = Buffer.from(eat); t[t.length - 1] ^= 0xff;
  var tampered = null;
  try { await b.eat.verify(t, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { tampered = e; }
  check("verify: tampered token refused by COSE signature check", tampered && tampered.code === "cose/bad-signature");

  // exp from the CWT layer still enforced through EAT.
  var expired = await b.eat.sign({ exp: _now() - 3600, ueid: Buffer.from([1]) }, { alg: "ES256", privateKey: EC.privateKey });
  var exp = null;
  try { await b.eat.verify(expired, { algorithms: ["ES256"], publicKey: EC.publicKey }); } catch (e) { exp = e; }
  check("verify: expired EAT refused (delegated to cwt)", exp && exp.code === "cwt/expired");
}

async function run() {
  testSurface();
  await testRoundTripAndLabels();
  await testNonceBinding();
  await testDebugStatusAndProfile();
  await testValidationAndTamper();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[eat] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
