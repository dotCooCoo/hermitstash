"use strict";
/**
 * b.mail.crypto.smime.checkCert — fail closed on unparseable validity.
 *
 * RFC 5280 §4.1.2.5 makes notBefore / notAfter mandatory; checkCert's
 * validity-window guard refuses certs outside that window. The guard
 * gated each comparison behind isFinite(Date.parse(...)), so a cert
 * carrying a PRESENT-but-unparseable validFrom / validTo (Date.parse
 * → NaN) silently skipped BOTH checks and passed validity. A signing
 * cert whose dates a peer cannot parse must be refused at preflight,
 * not accepted and left to fail interop later.
 *
 * This drives the real operator consumer path
 * b.mail.crypto.smime.checkCert({ certPem }). node:crypto's
 * X509Certificate always exposes parseable RFC date strings, so we
 * stub the parser on the shared crypto module (require("node:crypto")
 * === require("crypto"); lib reads X509Certificate off it) to present
 * unparseable validity to the real checkCert logic.
 *
 * Run standalone: `node test/layer-0-primitives/mail-crypto-smime-bad-validity.test.js`
 * Or via smoke:   `node test/smoke.js`
 */
var helpers    = require("../helpers");
var check      = helpers.check;
var nodeCrypto = require("crypto");

var b     = helpers.b;
var smime = b.mail.crypto.smime;

// ---- Stub: a cert that parses fine but carries unparseable dates ----
//
// Passes the sig-algorithm (sha256WithRSAEncryption) and RSA-bit
// (publicKey null → bit-floor check skipped) gates so execution
// reaches the validity window — the only thing under test here.
function _withUnparseableValidityCert(validFrom, validTo, fn) {
  var Real = nodeCrypto.X509Certificate;
  function StubCert(_input) {
    return {
      subject:               "CN=signer.example",
      issuer:                "CN=signer.example",
      signatureAlgorithm:    "sha256WithRSAEncryption",
      signatureAlgorithmOid: "1.2.840.113549.1.1.11",
      publicKey:             null,
      fingerprint256:        "AA:BB:CC",
      validFrom:             validFrom,
      validTo:               validTo,
    };
  }
  nodeCrypto.X509Certificate = StubCert;
  try {
    return fn();
  } finally {
    nodeCrypto.X509Certificate = Real;
  }
}

var DUMMY_PEM =
  "-----BEGIN CERTIFICATE-----\nMIIBdummy\n-----END CERTIFICATE-----\n";

function testRejectsUnparseableValidity() {
  // Both dates unparseable.
  var threw = null, res = null;
  _withUnparseableValidityCert("GARBAGE-NOT-A-DATE", "ALSO-GARBAGE", function () {
    try { res = smime.checkCert({ certPem: DUMMY_PEM }); }
    catch (e) { threw = e; }
  });
  check("checkCert refuses cert with unparseable validity (does not return)",
    res === null);
  check("checkCert throws on unparseable validity",
    threw instanceof Error);
  check("checkCert unparseable-validity uses the bad-validity code",
    threw && threw.code === "mail-crypto/smime/bad-validity");
  check("checkCert unparseable-validity message names the dates",
    threw && /unparseable validity/.test(threw.message) &&
    threw.message.indexOf("GARBAGE-NOT-A-DATE") !== -1);
}

function testRejectsUnparseableNotBeforeOnly() {
  var threw = null, res = null;
  // validTo parseable + in the future, validFrom unparseable — the
  // old isFinite-gated notAfter check passes, so only fail-closed on
  // the NaN notBefore catches this.
  var future = new Date(Date.now() + 86400000).toUTCString();
  _withUnparseableValidityCert("NOT-A-REAL-DATE", future, function () {
    try { res = smime.checkCert({ certPem: DUMMY_PEM }); }
    catch (e) { threw = e; }
  });
  check("checkCert refuses cert with unparseable notBefore only",
    res === null && threw && threw.code === "mail-crypto/smime/bad-validity");
}

function testRejectsUnparseableNotAfterOnly() {
  var threw = null, res = null;
  var past = new Date(Date.now() - 86400000).toUTCString();
  _withUnparseableValidityCert(past, "NOT-A-REAL-DATE", function () {
    try { res = smime.checkCert({ certPem: DUMMY_PEM }); }
    catch (e) { threw = e; }
  });
  check("checkCert refuses cert with unparseable notAfter only",
    res === null && threw && threw.code === "mail-crypto/smime/bad-validity");
}

function testParseableValidityStillPasses() {
  // Regression: a cert with parseable, in-window dates must NOT be
  // tripped by the new fail-closed branch.
  var threw = null, res = null;
  var past   = new Date(Date.now() - 86400000).toUTCString();
  var future = new Date(Date.now() + 86400000).toUTCString();
  _withUnparseableValidityCert(past, future, function () {
    try { res = smime.checkCert({ certPem: DUMMY_PEM }); }
    catch (e) { threw = e; }
  });
  check("checkCert accepts cert with parseable in-window validity",
    threw === null && res && res.subject === "CN=signer.example");
}

function run() {
  testRejectsUnparseableValidity();
  testRejectsUnparseableNotBeforeOnly();
  testRejectsUnparseableNotAfterOnly();
  testParseableValidityStillPasses();
}

module.exports = { run: run };

if (require.main === module) {
  try {
    run();
    console.log("OK — " + helpers.getChecks() + " checks passed");
  } catch (e) {
    console.error("FAIL:", e && e.stack || e);
    process.exit(1);
  }
}
