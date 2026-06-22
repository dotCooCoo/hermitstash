"use strict";
/**
 * X.509 basicConstraints cA enforcement across the framework's cert-chain
 * walkers (b.tsa.verifyToken, b.mail.bimi, b.mail.crypto.smime.verify).
 *
 * node:crypto X509Certificate.checkIssued() does NOT enforce basicConstraints
 * cA:TRUE, so a leaf / end-entity cert (cA:FALSE) that omits keyUsage is
 * wrongly accepted as a signing CA — the classic basicConstraints bypass
 * (CVE-2002-0862 class). All three walkers route their issuer test through
 * lib/x509-chain.js, which adds the cA check. This proves:
 *   1. the shared primitive (isCaCert / issuerValidlyIssued) — the exact
 *      logic every walker now depends on — rejects a non-CA issuer; and
 *   2. an end-to-end consumer path (b.mail.bimi.fetchAndVerifyMark) refuses
 *      a forged mark whose chain hangs off a cA:FALSE intermediate.
 *
 * The intermediate deliberately OMITS keyUsage: checkIssued already rejects
 * keyUsage-without-keyCertSign, so a keyUsage-bearing intermediate would pass
 * even on the buggy code — only the missing basicConstraints check is under
 * test here.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var nodeCrypto = require("crypto");
var pki  = require("../../lib/vendor/pki.cjs");
var x509 = pki.x509;
var x509Chain = require("../../lib/x509-chain");

var BIMI_EKU_OID = "1.3.6.1.5.5.7.3.31";

// Mint root(CA:TRUE) -> intermediate(cA per opts) -> leaf, returning PEMs and
// node X509Certificate objects. The intermediate omits keyUsage so the cA
// check is the only thing that can reject it as an issuer.
async function _mintChain(opts) {
  opts = opts || {};
  var interCa = opts.interCa === true;          // default cA:FALSE (the attack)
  var leafSan = opts.leafSan || "victim.example";
  var now = new Date();
  var notAfter = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);
  var alg = { name: "ECDSA", namedCurve: "P-256" };
  var sigAlg = { name: "ECDSA", hash: "SHA-256" };

  var rootKeys  = await pki.crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  var interKeys = await pki.crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  var leafKeys  = await pki.crypto.subtle.generateKey(alg, true, ["sign", "verify"]);

  var root = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01", name: "CN=Test Root CA", notBefore: now, notAfter: notAfter,
    signingAlgorithm: sigAlg, keys: rootKeys,
    extensions: [
      new x509.BasicConstraintsExtension(true, 2, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    ],
  });

  // The intermediate: cA per opts, and NO keyUsage extension at all.
  var inter = await x509.X509CertificateGenerator.create({
    serialNumber: "02", issuer: root.subject, subject: "CN=Test Intermediate",
    notBefore: now, notAfter: notAfter, signingAlgorithm: sigAlg,
    publicKey: interKeys.publicKey, signingKey: rootKeys.privateKey,
    extensions: [ new x509.BasicConstraintsExtension(interCa, interCa ? 0 : undefined, true) ],
  });

  var leaf = await x509.X509CertificateGenerator.create({
    serialNumber: "03", issuer: inter.subject, subject: "CN=" + leafSan,
    notBefore: now, notAfter: notAfter, signingAlgorithm: sigAlg,
    publicKey: leafKeys.publicKey, signingKey: interKeys.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      new x509.SubjectAlternativeNameExtension([{ type: "dns", value: leafSan }]),
      new x509.ExtendedKeyUsageExtension([BIMI_EKU_OID], false),
    ],
  });

  return {
    rootPem:  root.toString("pem"),
    interPem: inter.toString("pem"),
    leafPem:  leaf.toString("pem"),
    root:  new nodeCrypto.X509Certificate(root.toString("pem")),
    inter: new nodeCrypto.X509Certificate(inter.toString("pem")),
    leaf:  new nodeCrypto.X509Certificate(leaf.toString("pem")),
  };
}

function _stubHttpClient(body) {
  return {
    request: function () {
      return Promise.resolve({
        statusCode: 200, headers: {},
        body: Buffer.isBuffer(body) ? body : Buffer.from(String(body), "utf8"),
      });
    },
  };
}

async function run() {
  // ---- 0. Public surface: the CA-bit issuer test is reachable on `b` so a
  // consumer validating a chain outside a TLS handshake uses the hardened,
  // fail-closed test instead of raw X509Certificate.checkIssued().
  check("b.x509Chain is exposed on the public surface", b.x509Chain && typeof b.x509Chain === "object");
  check("b.x509Chain.isCaCert is the internal helper", b.x509Chain.isCaCert === x509Chain.isCaCert);
  check("b.x509Chain.issuerValidlyIssued is the internal helper",
        b.x509Chain.issuerValidlyIssued === x509Chain.issuerValidlyIssued);
  check("b.x509Chain.isCaCert fails closed on a missing cert", b.x509Chain.isCaCert(null) === false);
  check("b.x509Chain.issuerValidlyIssued fails closed on garbage input",
        b.x509Chain.issuerValidlyIssued(null, null) === false);

  // ---- 1. Shared primitive: the cA enforcement every walker routes through.
  var c = await _mintChain({ interCa: false });        // intermediate is cA:FALSE
  check("isCaCert: root (cA:TRUE) is a CA", x509Chain.isCaCert(c.root) === true);
  check("isCaCert: intermediate (cA:FALSE) is NOT a CA", x509Chain.isCaCert(c.inter) === false);
  check("isCaCert: leaf (cA:FALSE) is NOT a CA", x509Chain.isCaCert(c.leaf) === false);
  check("issuerValidlyIssued: root validly issued the intermediate",
        x509Chain.issuerValidlyIssued(c.root, c.inter) === true);
  // THE FIX: the intermediate genuinely issued + signed the leaf, but it is
  // not a CA, so it must be refused as a chain issuer.
  check("issuerValidlyIssued: cA:FALSE intermediate is REFUSED as the leaf's issuer",
        x509Chain.issuerValidlyIssued(c.inter, c.leaf) === false);

  // Control: when the intermediate IS a CA, the same call accepts it.
  var ok = await _mintChain({ interCa: true });
  check("issuerValidlyIssued: cA:TRUE intermediate is ACCEPTED as the leaf's issuer",
        x509Chain.issuerValidlyIssued(ok.inter, ok.leaf) === true);

  // ---- 2. Consumer path: b.mail.bimi.fetchAndVerifyMark must refuse a mark
  // whose chain hangs off the cA:FALSE intermediate (leaf + intermediate
  // served from the VMC URL, root as the trust anchor).
  var threw = null;
  try {
    await b.mail.bimi.fetchAndVerifyMark({
      domain:          "victim.example",
      vmcUrl:          "https://victim.example/cert.pem",
      trustAnchorsPem: c.rootPem,
      httpClient:      _stubHttpClient(c.leafPem + "\n" + c.interPem),
    });
  } catch (e) { threw = e; }
  check("bimi.fetchAndVerifyMark: forged mark via cA:FALSE intermediate is REJECTED",
        threw && threw.code === "bimi/vmc-chain-invalid");

  // Control: the same wiring with a cA:TRUE intermediate verifies.
  var rv = await b.mail.bimi.fetchAndVerifyMark({
    domain:          "victim.example",
    vmcUrl:          "https://victim.example/cert.pem",
    trustAnchorsPem: ok.rootPem,
    httpClient:      _stubHttpClient(ok.leafPem + "\n" + ok.interPem),
  });
  check("bimi.fetchAndVerifyMark: valid CA chain still verifies", rv.ok === true);

  console.log("OK — x509 cA enforcement (" + helpers.getChecks() + " checks)");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
