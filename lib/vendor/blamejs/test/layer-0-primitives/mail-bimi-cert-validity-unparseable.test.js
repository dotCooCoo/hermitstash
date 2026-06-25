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

var pki        = require("../../lib/vendor/pki.cjs");
var x509       = pki.x509;
var nodeCrypto = require("crypto");

async function _generateTestChain() {
  var caKeys = await pki.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  var leafKeys = await pki.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);

  var now = new Date();
  var notAfter = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);

  var ca = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: "CN=BIMI Test Root",
    notBefore: now,
    notAfter: notAfter,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    keys: caKeys,
    extensions: [
      new x509.BasicConstraintsExtension(true, 1, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    ],
  });

  var leaf = await x509.X509CertificateGenerator.create({
    serialNumber: "02",
    issuer: ca.subject,
    subject: "CN=example.com",
    notBefore: now,
    notAfter: notAfter,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    publicKey: leafKeys.publicKey,
    signingKey: caKeys.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      new x509.SubjectAlternativeNameExtension([
        { type: "dns", value: "example.com" },
      ]),
      new x509.ExtendedKeyUsageExtension(["1.3.6.1.5.5.7.3.31"], false),
    ],
  });

  return { rootPem: ca.toString("pem"), leafPem: leaf.toString("pem") };
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
