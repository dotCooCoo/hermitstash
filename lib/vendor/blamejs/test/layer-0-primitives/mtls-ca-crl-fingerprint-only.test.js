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
var b     = helpers.b;
var check = helpers.check;
var fs   = require("fs");
var os   = require("os");
var path = require("path");
var pki  = require("../../lib/vendor/pki.cjs");

function _normHex(s) { return String(s || "").replace(/^0x/i, "").replace(/[:\-\s]/g, "").toLowerCase(); }

function _crlSerials(crlPem) {
  var crl = new pki.x509.X509Crl(crlPem);
  return (crl.entries || []).map(function (e) { return _normHex(e.serialNumber); });
}

async function run() {
  // ---- Scenario 1: a serial-revoked cert AND a fingerprint-only revocation
  // coexist. The CRL must still publish the serial-revoked cert. ----
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mtls-crl-fp-"));
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", generation: 1 });

  var a = await ca.generateClientCert({ cn: "serial-revoked" });
  var bCert = await ca.generateClientCert({ cn: "fingerprint-revoked" });

  ca.revoke(a.serialNumber, { reason: "superseded" });                 // serial-keyed
  ca.revoke({ fingerprint: bCert.fingerprint, reason: "keyCompromise" }); // fingerprint-only (null serial)

  // RED before the fix: this throws inside the CRL encoder on the null serial.
  var res = await ca.generateCrl();

  check("generateCrl succeeds with a mixed serial + fingerprint-only registry",
        res && typeof res.crlPem === "string" && res.crlPem.indexOf("BEGIN CRL") !== -1);
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
  ca2.revoke({ fingerprint: c.fingerprint });

  var res2 = await ca2.generateCrl();
  check("generateCrl with only fingerprint-only revocations produces a valid CRL",
        res2 && typeof res2.crlPem === "string" && res2.crlPem.indexOf("BEGIN CRL") !== -1);
  check("that CRL has zero serial entries", _crlSerials(res2.crlPem).length === 0);
  check("entryCount is 0 and fingerprintOnlyOmitted is 1",
        res2.entryCount === 0 && res2.fingerprintOnlyOmitted === 1);

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
