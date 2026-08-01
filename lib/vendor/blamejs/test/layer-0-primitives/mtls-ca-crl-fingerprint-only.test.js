// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mtlsCa.generateCrl must tolerate a registry that holds fingerprint-only
 * revocations.
 *
 * revoke({ fingerprint }) is a first-class revocation mode — it is the value
 * the require-mtls gate pins on, and generateClientCert surfaces a fingerprint
 * for exactly this use. Such an entry carries no certificate serial number. A
 * standard X.509 CRL (RFC 5280 §5.1) is keyed by serial, so a fingerprint-only
 * entry cannot be represented in the CRL and must be projected out.
 *
 * Before the fix, generateCrl handed the null serial straight to the CRL
 * encoder, which threw ("Cannot read properties of null"). That broke CRL
 * generation for the WHOLE registry — including the serial-keyed certs that
 * CAN be published — so a single (correct) fingerprint-based revocation stalled
 * the entire published-revocation path: a fail-open for every OTHER revoked
 * cert whose serial should have appeared in a fresh CRL.
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;
var fs     = require("fs");
var os     = require("os");
var path   = require("path");
var pki    = require("../../lib/vendor/blamejs-pki.cjs");
var engine = require("../../lib/mtls-engine-default");

function _mkTmp(prefix) { return fs.mkdtempSync(path.join(os.tmpdir(), prefix)); }

// The framework-side generateCrl guards: an engine that does not implement
// generateCrl at all, and one whose generateCrl returns an empty (invalid)
// PEM. Both use a minimal custom engine so no real key material is minted.
async function testCrlEngineGuards() {
  var okGen = async function () { return { caCertPem: "CA-CERT", caKeyPem: "CA-KEY" }; };

  var caNoCrl = b.mtlsCa.create({ dataDir: _mkTmp("blamejs-mtls-crlno-"), caKeySealedMode: "disabled", engine: { generateCa: okGen } });
  var threwNoCrl = false;
  try { await caNoCrl.generateCrl(); } catch (e) { threwNoCrl = /engine-no-crl/.test(e.code || ""); }
  check("generateCrl on an engine without a generateCrl() is refused", threwNoCrl);

  var caBadCrl = b.mtlsCa.create({ dataDir: _mkTmp("blamejs-mtls-crlbad-"), caKeySealedMode: "disabled", engine: { generateCa: okGen, generateCrl: async function () { return ""; } } });
  var threwBadCrl = false;
  try { await caBadCrl.generateCrl(); } catch (e) { threwBadCrl = /bad-engine-output/.test(e.code || ""); }
  check("generateCrl rejecting an empty engine PEM surfaces bad-engine-output", threwBadCrl);
}

// The default engine's generateCrl serial-normalisation + argument arms,
// exercised directly against a real CA: missing arguments, a non-array
// revocations input, a revocation with no revokedAt (default date), a
// 0x-prefixed serial (passed through), a null serial and a non-hex serial
// (both normalised, then rejected by the RFC 5280 CRL encoder downstream).
async function testEngineDirectCrl() {
  var ca = await engine.generateCa();

  // Missing-argument arms.
  var crlArgCases = [
    ["engine.generateCrl() with no opts throws missing-arg", undefined],
    ["engine.generateCrl missing the CA key throws missing-arg", { caCertPem: "c" }],
    ["engine.generateCrl missing the CA cert throws missing-arg", { caKeyPem: "k" }],
  ];
  for (var i = 0; i < crlArgCases.length; i++) {
    var threw = false;
    try { await engine.generateCrl(crlArgCases[i][1]); } catch (e) { threw = /missing-arg/.test(e.code || ""); }
    check(crlArgCases[i][0], threw);
  }

  // Non-array revocations → treated as empty; still a valid CRL.
  var emptyCrl = await engine.generateCrl({ caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem, revocations: "not-an-array" });
  check("a non-array revocations list produces a valid empty CRL",
    typeof emptyCrl === "string" && /-----BEGIN (?:X509 )?CRL-----/.test(emptyCrl));

  // A revocation with no revokedAt (default revocation date) + a hex serial.
  var noDateCrl = await engine.generateCrl({ caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem, revocations: [{ serialNumber: "ab" }] });
  check("a revocation without a revokedAt defaults its revocation date", typeof noDateCrl === "string" && noDateCrl.length > 0);

  // A 0x-prefixed serial is passed through unchanged.
  var prefixedCrl = await engine.generateCrl({ caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem, revocations: [{ serialNumber: "0x1a2b" }] });
  check("a 0x-prefixed serial is accepted by the CRL encoder", typeof prefixedCrl === "string" && prefixedCrl.length > 0);

  // A null serial normalises to "" and a non-hex serial passes through
  // unchanged; both are then rejected by the RFC 5280 serial encoder, which
  // is the current (correct) downstream behaviour — the normalisation arms
  // still execute before the encoder throws.
  var threwNull = false;
  try { await engine.generateCrl({ caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem, revocations: [{ serialNumber: null }] }); }
  catch (_e) { threwNull = true; }
  check("a null revocation serial is rejected downstream by the CRL encoder", threwNull);

  var threwNonHex = false;
  try { await engine.generateCrl({ caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem, revocations: [{ serialNumber: "zz-not-hex" }] }); }
  catch (_e) { threwNonHex = true; }
  check("a non-hex revocation serial is rejected downstream by the CRL encoder", threwNonHex);
}

// Canonicalize a serial to its numeric hex: drop any 0x prefix, separators, and
// leading zeros. The DER INTEGER encoding of a serial whose high bit is set
// carries a 0x00 sign byte (RFC 5280 §5.1 serials are keyed as integers), so the
// parsed CRL hex ("00c5..") and the framework's canonical serial ("c5..") differ
// by that padding — and a serial whose own leading nibble is zero differs the
// other way. Comparing numerically (both sides through this helper) makes the
// serial-equality check exact regardless of sign-byte padding.
function _normHex(s) { return String(s || "").replace(/^0x/i, "").replace(/[:\-\s]/g, "").toLowerCase().replace(/^0+(?=.)/, ""); }

function _crlSerials(crlPem) {
  var crl = pki.schema.crl.parse(crlPem);
  return (crl.revokedCertificates || []).map(function (e) { return _normHex(e.serialNumberHex); });
}

async function run() {
  // ---- Scenario 1: a serial-revoked cert AND a fingerprint-only revocation
  // coexist. The CRL must still publish the serial-revoked cert. ----
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mtls-crl-fp-"));
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", generation: 1 });

  var a = await ca.generateClientCert({ cn: "serial-revoked" });
  var bCert = await ca.generateClientCert({ cn: "fingerprint-revoked" });

  await ca.revoke(a.serialNumber, { reason: "superseded" });                 // serial-keyed
  await ca.revoke({ fingerprint: bCert.fingerprint, reason: "keyCompromise" }); // fingerprint-only (null serial)

  // RED before the fix: this throws inside the CRL encoder on the null serial.
  var res = await ca.generateCrl();

  check("generateCrl succeeds with a mixed serial + fingerprint-only registry",
        res && typeof res.crlPem === "string" && /-----BEGIN (?:X509 )?CRL-----/.test(res.crlPem));
  check("generateCrl entryCount counts only the serial-bearing (CRL-able) revocations",
        res.entryCount === 1);
  check("generateCrl surfaces the count of fingerprint-only revocations it could not represent",
        res.fingerprintOnlyOmitted === 1);

  var serials = _crlSerials(res.crlPem);
  check("the serial-revoked cert IS published in the CRL (not lost to the null-serial crash)",
        serials.indexOf(_normHex(a.serialNumber)) !== -1);
  check("the CRL carries exactly the one serial-keyed entry",
        serials.length === 1);

  // ---- Scenario 2: a registry with ONLY fingerprint-only revocations still
  // produces a valid (empty) CRL rather than throwing. ----
  var dir2 = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mtls-crl-fponly-"));
  var ca2 = b.mtlsCa.create({ dataDir: dir2, caKeySealedMode: "disabled" });
  var c = await ca2.generateClientCert({ cn: "only-fp" });
  await ca2.revoke({ fingerprint: c.fingerprint });

  var res2 = await ca2.generateCrl();
  check("generateCrl with only fingerprint-only revocations produces a valid CRL",
        res2 && typeof res2.crlPem === "string" && /-----BEGIN (?:X509 )?CRL-----/.test(res2.crlPem));
  check("that CRL has zero serial entries", _crlSerials(res2.crlPem).length === 0);
  check("entryCount is 0 and fingerprintOnlyOmitted is 1",
        res2.entryCount === 0 && res2.fingerprintOnlyOmitted === 1);

  await testCrlEngineGuards();
  await testEngineDirectCrl();

  try {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(dir2, { recursive: true, force: true });
  } catch (_e) { /* best-effort */ }

  console.log("OK — mtls-ca CRL fingerprint-only tolerance (" + helpers.getChecks() + " checks)");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
