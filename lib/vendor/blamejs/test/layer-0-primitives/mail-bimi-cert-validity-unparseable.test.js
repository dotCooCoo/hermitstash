// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.bimi — VMC / CMC certificate validity-window enforcement when the
 * cert's notBefore / notAfter are PRESENT but UNPARSEABLE.
 *
 * _verifyCertChain reads `current.validFrom` / `current.validTo` and runs
 * `Date.parse` to derive the validity window. A cert whose date strings
 * Date.parse cannot interpret yields NaN. The window checks were guarded by
 * `isFinite(...)`, so a NaN date SKIPPED both the not-yet-valid and the
 * expired check and the cert validated — a present-but-unparseable validity
 * window must FAIL CLOSED, not be waved through.
 *
 * This drives the real consumer path: b.mail.bimi.fetchAndVerifyMark with a
 * self-signed test chain + stubbed httpClient. Date.parse is stubbed to
 * return NaN for exactly the leaf cert's two date strings (simulating a cert
 * whose ASN.1 time fields node surfaces as a string Date.parse rejects);
 * every other Date.parse call is unaffected, so chain signature / issuer /
 * SAN / EKU validation proceed normally and the ONLY failing signal is the
 * unparseable window.
 *
 * Live network is NOT used.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var pki        = require("../../lib/vendor/blamejs-pki.cjs");
var nodeCrypto = require("crypto");

// The BIMI KeyPurposeId (id-kp-BrandIndicatorforMessageIdentification) the leaf
// carries in extendedKeyUsage, so the mark's EKU validation proceeds normally.
var BIMI_EKU_OID = "1.3.6.1.5.5.7.3.31";

// Export a CryptoKey public key to its SPKI DER (what pki.x509.sign certifies).
async function _spki(publicKey) {
  return Buffer.from(await pki.webcrypto.subtle.exportKey("spki", publicKey));
}

async function _generateTestChain() {
  var alg = { name: "ECDSA", namedCurve: "P-256" };
  var caKeys   = await pki.webcrypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  var leafKeys = await pki.webcrypto.subtle.generateKey(alg, true, ["sign", "verify"]);

  var now = new Date();
  var notAfter = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);

  var caSpki   = await _spki(caKeys.publicKey);
  var leafSpki = await _spki(leafKeys.publicKey);

  // Root: a genuine CA (basicConstraints cA:TRUE critical, pathLen 1; keyUsage
  // keyCertSign|cRLSign critical), self-signed. DN = CN=BIMI Test Root.
  var rootPem = await pki.x509.sign({
    subject:          "BIMI Test Root",
    subjectPublicKey: caSpki,
    serialNumber:     "01",
    notBefore:        now,
    notAfter:         notAfter,
    extensions: {
      basicConstraints: { cA: true, pathLen: 1, critical: true },
      keyUsage:         ["keyCertSign", "cRLSign"], keyUsageCritical: true,
    },
  }, { key: caKeys.privateKey }, { pem: true });

  // Leaf: CA-signed by the root (a real CA, so the { cert } issuer form signs
  // through its CA gate). DN = CN=example.com; SAN dNSName example.com; the
  // BIMI EKU (non-critical); basicConstraints cA:FALSE critical; keyUsage
  // digitalSignature critical — so chain / issuer / SAN / EKU validation all
  // pass and the ONLY failing signal is the unparseable validity window.
  var leafPem = await pki.x509.sign({
    subject:          "example.com",
    subjectPublicKey: leafSpki,
    serialNumber:     "02",
    notBefore:        now,
    notAfter:         notAfter,
    extensions: {
      basicConstraints:  { cA: false, critical: true },
      keyUsage:          ["digitalSignature"], keyUsageCritical: true,
      subjectAltName:    [{ dNSName: "example.com" }],
      extendedKeyUsage:  [BIMI_EKU_OID], extendedKeyUsageCritical: false,
    },
  }, { cert: rootPem, key: caKeys.privateKey }, { pem: true });

  return { rootPem: rootPem, leafPem: leafPem };
}

function _stubHttpClient(body) {
  return {
    request: function () {
      return Promise.resolve({
        statusCode: 200,
        headers:    {},
        body:       Buffer.from(String(body), "utf8"),
      });
    },
  };
}

async function testUnparseableValidityFailsClosed() {
  var chain = await _generateTestChain();

  // Surface the leaf's exact date strings the lib will feed to Date.parse,
  // then stub Date.parse to return NaN for ONLY those two strings — every
  // other Date.parse call (and the rest of chain validation) is untouched.
  var leafCert = new nodeCrypto.X509Certificate(chain.leafPem);
  var certDateStrings = [leafCert.validFrom, leafCert.validTo];
  var origParse = Date.parse;
  Date.parse = function (value) {
    if (certDateStrings.indexOf(value) !== -1) return NaN;
    return origParse.call(Date, value);
  };

  var threw = null;
  var rv = null;
  try {
    rv = await b.mail.bimi.fetchAndVerifyMark({
      domain:          "example.com",
      vmcUrl:          "https://example.com/cert.pem",
      trustAnchorsPem: chain.rootPem,
      httpClient:      _stubHttpClient(chain.leafPem),
    });
  } catch (e) {
    threw = e;
  } finally {
    Date.parse = origParse;
  }

  // RED on the buggy tree: rv.ok === true (cert accepted despite an
  // unparseable validity window). GREEN after the fix: rejected with
  // bimi/vmc-chain-invalid and a "validity dates unparseable" reason.
  check("fetchAndVerifyMark: present-but-unparseable cert validity is rejected",
        rv === null && threw !== null &&
        threw.code === "bimi/vmc-chain-invalid");
  check("fetchAndVerifyMark: unparseable-validity rejection names the cause",
        threw !== null && /unparseable/i.test(String(threw.message)));
}

async function run() {
  await testUnparseableValidityFailsClosed();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
