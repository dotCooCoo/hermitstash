// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
  // Default SAN is DNS:<leafSan>; a test can supply explicit entries (e.g. a
  // hostile URI SAN) to exercise the SAN-vs-domain matcher.
  var leafSanEntries = opts.leafSanEntries || [{ type: "dns", value: leafSan }];
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
      new x509.SubjectAlternativeNameExtension(leafSanEntries),
      new x509.ExtendedKeyUsageExtension([BIMI_EKU_OID], false),
    ],
  });

  // Export the leaf's private key so a consumer test can sign a payload that
  // the forged leaf would verify (e.g. a fido-mds3 BLOB).
  var leafPkcs8 = await pki.crypto.subtle.exportKey("pkcs8", leafKeys.privateKey);
  var leafKeyB64 = Buffer.from(leafPkcs8).toString("base64").match(/.{1,64}/g).join("\n");
  var leafKeyPem = "-----BEGIN PRIVATE KEY-----\n" + leafKeyB64 + "\n-----END PRIVATE KEY-----\n";

  return {
    rootPem:  root.toString("pem"),
    interPem: inter.toString("pem"),
    leafPem:  leaf.toString("pem"),
    leafKeyPem: leafKeyPem,
    root:  new nodeCrypto.X509Certificate(root.toString("pem")),
    inter: new nodeCrypto.X509Certificate(inter.toString("pem")),
    leaf:  new nodeCrypto.X509Certificate(leaf.toString("pem")),
  };
}

// Build a fido-mds3 JWS BLOB signed by `leafKeyPem` with x5c = the given cert
// chain (PEMs, leaf-first), so a forged leaf can attempt to authenticate a BLOB.
function _b64url(buf) { return Buffer.from(buf).toString("base64url"); }
function _mds3Blob(payload, leafKeyPem, chainPems) {
  var x5c = chainPems.map(function (pem) {
    return pem.replace(/-----BEGIN CERTIFICATE-----/g, "")
              .replace(/-----END CERTIFICATE-----/g, "").replace(/\s+/g, "");
  });
  var header = { alg: "ES256", typ: "JWT", x5c: x5c };
  var signingInput = _b64url(JSON.stringify(header)) + "." + _b64url(JSON.stringify(payload));
  var sig = nodeCrypto.sign("sha256", Buffer.from(signingInput, "ascii"),
    { key: leafKeyPem, dsaEncoding: "ieee-p1363" });
  return signingInput + "." + _b64url(sig);
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

  // ---- 2b. SAN-vs-domain authorization must bind to the cert's actual host.
  // A CA-chained VMC whose only SAN is a URI the URL parser refuses (here the
  // real host is attacker.test, with the victim domain placed in the userinfo)
  // must NOT vouch for the victim domain. The pre-fix matcher fell back to a raw
  // substring search of the whole SAN string when safeUrl.parse threw, so
  // "victim.example" appearing anywhere (userinfo / path) wrongly matched.
  var hostile = await _mintChain({
    interCa: true,
    leafSan: "attacker.test",
    leafSanEntries: [{ type: "url", value: "https://victim.example@attacker.test/" }],
  });
  var sanThrew = null;
  try {
    await b.mail.bimi.fetchAndVerifyMark({
      domain:          "victim.example",
      vmcUrl:          "https://victim.example/cert.pem",
      trustAnchorsPem: hostile.rootPem,
      httpClient:      _stubHttpClient(hostile.leafPem + "\n" + hostile.interPem),
    });
  } catch (e) { sanThrew = e; }
  check("bimi.fetchAndVerifyMark: hostile URI-SAN (userinfo) does NOT vouch for the victim domain",
        sanThrew && sanThrew.code === "bimi/vmc-domain-mismatch");

  // Control: a CA-chained VMC whose URI SAN host genuinely IS the domain verifies.
  var legit = await _mintChain({
    interCa: true,
    leafSan: "good.example",
    leafSanEntries: [{ type: "url", value: "https://good.example/" }],
  });
  var legitRv = await b.mail.bimi.fetchAndVerifyMark({
    domain:          "good.example",
    vmcUrl:          "https://good.example/cert.pem",
    trustAnchorsPem: legit.rootPem,
    httpClient:      _stubHttpClient(legit.leafPem + "\n" + legit.interPem),
  });
  check("bimi.fetchAndVerifyMark: a genuine URI-SAN host still verifies", legitRv.ok === true);

  // domainToASCII truncates at a URL delimiter, so a DNS SAN "victim.example/evil"
  // would have canonicalized to "victim.example" and matched — must fail closed.
  var dnsDelim = await _mintChain({
    interCa: true,
    leafSan: "attacker.test",
    leafSanEntries: [{ type: "dns", value: "victim.example/evil" }],
  });
  var dnsThrew = null;
  try {
    await b.mail.bimi.fetchAndVerifyMark({
      domain:          "victim.example",
      vmcUrl:          "https://victim.example/cert.pem",
      trustAnchorsPem: dnsDelim.rootPem,
      httpClient:      _stubHttpClient(dnsDelim.leafPem + "\n" + dnsDelim.interPem),
    });
  } catch (e) { dnsThrew = e; }
  check("bimi.fetchAndVerifyMark: a delimiter-bearing DNS SAN does NOT vouch for the prefix domain",
        dnsThrew && dnsThrew.code === "bimi/vmc-domain-mismatch");

  // ---- 3. Consumer path: b.auth.fidoMds3.fetch must refuse a BLOB whose x5c
  // chains the leaf through the cA:FALSE intermediate. The forged leaf GENUINELY
  // signs the BLOB (ES256), so without cA enforcement on the intermediate link a
  // basicConstraints bypass would accept attacker-forged FIDO metadata.
  var mds3Payload = {
    legalHeader: "Test BLOB", no: 1,
    nextUpdate: new Date(Date.now() + 7 * 86400000).toISOString().slice(0, 10),
    entries: [{ aaguid: "01234567-89ab-cdef-0123-456789abcdef",
                metadataStatement: { description: "Test entry" },
                statusReports: [{ status: "FIDO_CERTIFIED_L2" }] }],
  };
  var forgedBlob = _mds3Blob(mds3Payload, c.leafKeyPem, [c.leafPem, c.interPem]);
  var hcPath = require.resolve("../../lib/http-client");
  var origHc = require.cache[hcPath].exports;
  require.cache[hcPath].exports = Object.assign({}, origHc, {
    request: async function () {
      return { statusCode: 200, headers: {}, body: Buffer.from(forgedBlob, "ascii") };
    },
  });
  var fmPath = require.resolve("../../lib/auth/fido-mds3");
  delete require.cache[fmPath];
  var fm = require(fmPath);
  var mdsThrew = null;
  try {
    await fm.fetch({ url: "https://test.invalid/mds3", caCertificate: c.rootPem, force: true });
  } catch (e) { mdsThrew = e; }
  finally {
    require.cache[hcPath].exports = origHc;
    delete require.cache[fmPath];
  }
  check("fido-mds3.fetch: forged BLOB via cA:FALSE intermediate is REJECTED",
        mdsThrew && mdsThrew.code === "fido-mds3/chain-broken");

  console.log("OK — x509 cA enforcement (" + helpers.getChecks() + " checks)");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
