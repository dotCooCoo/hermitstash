// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.saml.fetchMdq — XML signature-wrapping (XSW) defense on the
 * metadata-query trust-bootstrap path.
 *
 * fetchMdq verifies federation metadata via the same _verifyXmldsig the
 * assertion path uses, but pre-fix discarded the returned refId and never
 * bound it to the consumed element — unlike verifyResponse, which enforces
 * signed.refId === _attr(root/assertion, "ID"). Combined with a first-child
 * Signature lookup, that let a genuine federation signature over a buried
 * EntityDescriptor be paired with a forged outer/sibling EntityDescriptor
 * carrying an attacker signing cert: fetchMdq accepted the wrapped document
 * and returned it, so the operator extracted the attacker's IdP trust anchor
 * (CVE-2024-45409 / ruby-saml class — the same vector verifyResponse already
 * defends).
 *
 * The federation signature, digest, and SignedInfo are computed through the
 * framework's own b.xmlC14n so _verifyXmldsig's recomputation matches — there
 * is no test bypass of the signature check (the attacker-signed negative
 * control proves the trust anchor is real).
 */

var helpers    = require("../helpers");
var check      = helpers.check;
var nodeCrypto = require("node:crypto");
var c14n       = require("../../lib/xml-c14n");

var DS  = "http://www.w3.org/2000/09/xmldsig#";
var EXC = "http://www.w3.org/2001/10/xml-exc-c14n#";
var MD  = "urn:oasis:names:tc:SAML:2.0:metadata";

var IDP_ENTITY_ID = "https://idp.example";

// Mint a self-signed RSA cert via the vendored @peculiar/x509 bundle —
// identical to the saml-subjectconfirmation tests' _mintRsaCert.
async function _mintRsaCert(cn) {
  var pki  = require("../../lib/vendor/pki.cjs");
  var x509 = pki.x509;
  var keys = await nodeCrypto.webcrypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048,                                           // allow:raw-byte-literal — RFC 8301 §3.1 RSA bit floor
      publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true, ["sign", "verify"]);
  var now = new Date();
  var cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber:     "01",
    name:             "CN=" + cn,
    notBefore:        now,
    notAfter:         new Date(now.getTime() + 365 * 24 * 3600 * 1000),                         // allow:raw-time-literal — 1y fixture validity
    signingAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    keys:             keys,
  });
  var pkcs8 = await nodeCrypto.webcrypto.subtle.exportKey("pkcs8", keys.privateKey);
  var keyPem = "-----BEGIN PRIVATE KEY-----\n" +
    Buffer.from(pkcs8).toString("base64").match(/.{1,64}/g).join("\n") +
    "\n-----END PRIVATE KEY-----\n";
  return { certPem: cert.toString("pem"), keyPem: keyPem };
}

function _certBodyB64(pem) {
  return pem.replace(/-----BEGIN CERTIFICATE-----/, "")
            .replace(/-----END CERTIFICATE-----/, "")
            .replace(/\s+/g, "");
}

// An EntityDescriptor (no Signature) whose signing KeyDescriptor carries `cert`.
function _entityDescriptor(id, signingCertPem) {
  return "<md:EntityDescriptor xmlns:md=\"" + MD + "\" ID=\"" + id +
    "\" entityID=\"" + IDP_ENTITY_ID + "\">" +
    "<md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">" +
    "<md:KeyDescriptor use=\"signing\">" +
    "<ds:KeyInfo xmlns:ds=\"" + DS + "\"><ds:X509Data><ds:X509Certificate>" +
    _certBodyB64(signingCertPem) +
    "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>" +
    "</md:KeyDescriptor></md:IDPSSODescriptor></md:EntityDescriptor>";
}

// Federation-sign `elementXml` (enveloped-signature + exc-c14n digest, ref
// #refId, SignedInfo c14n'd + RSA-SHA-256), returning the standalone
// ds:Signature. Mirrors the SAML suite's signer so _verifyXmldsig matches.
function _federationSignature(fed, refId, elementXml) {
  var digest = nodeCrypto.createHash("sha256")
    .update(c14n.canonicalize(elementXml)).digest("base64");
  var signedInfo =
    "<ds:SignedInfo xmlns:ds=\"" + DS + "\">" +
    "<ds:CanonicalizationMethod Algorithm=\"" + EXC + "\"></ds:CanonicalizationMethod>" +
    "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></ds:SignatureMethod>" +
    "<ds:Reference URI=\"#" + refId + "\">" +
    "<ds:Transforms>" +
    "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></ds:Transform>" +
    "<ds:Transform Algorithm=\"" + EXC + "\"></ds:Transform>" +
    "</ds:Transforms>" +
    "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod>" +
    "<ds:DigestValue>" + digest + "</ds:DigestValue>" +
    "</ds:Reference></ds:SignedInfo>";
  var priv = nodeCrypto.createPrivateKey({ key: fed.keyPem, format: "pem" });
  var sigValue = nodeCrypto.sign("sha256", c14n.canonicalize(signedInfo),
    { key: priv, padding: nodeCrypto.constants.RSA_PKCS1_PADDING }).toString("base64");
  return "<ds:Signature xmlns:ds=\"" + DS + "\">" + signedInfo +
    "<ds:SignatureValue>" + sigValue + "</ds:SignatureValue></ds:Signature>";
}

// Insert a ds:Signature as the first child of a single-EntityDescriptor doc
// (enveloped) — the normal, well-formed signed-metadata shape.
function _envelopeSignature(entityXml, signatureXml) {
  var insertAt = entityXml.indexOf(">") + 1;
  return entityXml.slice(0, insertAt) + signatureXml + entityXml.slice(insertAt);
}

// Drive the REAL fetchMdq path with a mocked transport (require-cache override,
// same mechanism as fido-mds3.test.js), returning { xml, code }.
async function _fetchMdqWith(metadataXml, trustCertPem) {
  var hcPath = require.resolve("../../lib/http-client");
  var origHc = require.cache[hcPath].exports;
  require.cache[hcPath].exports = Object.assign({}, origHc, {
    request: async function () {
      return { statusCode: 200, headers: {}, body: Buffer.from(metadataXml, "utf8") };
    },
  });
  var samlPath = require.resolve("../../lib/auth/saml");
  delete require.cache[samlPath];
  var saml = require(samlPath);
  try {
    var xml = await saml.fetchMdq({
      baseUrl:      "https://mdq.test.invalid",
      entityId:     IDP_ENTITY_ID,
      trustCertPem: trustCertPem,
    });
    return { xml: xml, code: null };
  } catch (e) {
    return { xml: null, code: e.code || e.message };
  } finally {
    require.cache[hcPath].exports = origHc;
    delete require.cache[samlPath];
  }
}

// Positive control — a normally-signed single EntityDescriptor verifies and the
// returned metadata carries the genuine signing cert.
async function testGenuineSignedMetadataAccepted() {
  var fed = await _mintRsaCert("federation.example");
  var idp = await _mintRsaCert("idp.example");
  var entity = _entityDescriptor("G1", idp.certPem);
  var signed = _envelopeSignature(entity, _federationSignature(fed, "G1", entity));
  var r = await _fetchMdqWith(signed, fed.certPem);
  check("genuine signed metadata: fetchMdq resolves",
        r.code === null && typeof r.xml === "string");
  check("genuine signed metadata: carries genuine IdP cert",
        r.xml && r.xml.indexOf(_certBodyB64(idp.certPem)) !== -1);
}

// Negative control — an attacker-signed (not federation-signed) document is
// refused. Proves the trust anchor is real, so a pass in the wrapping cases is
// the binding gap, not a broken signature check.
async function testAttackerSignedMetadataRefused() {
  var fed      = await _mintRsaCert("federation.example");
  var attacker = await _mintRsaCert("attacker.example");
  var entity = _entityDescriptor("G1", attacker.certPem);
  var signed = _envelopeSignature(entity, _federationSignature(attacker, "G1", entity)); // wrong signer
  var r = await _fetchMdqWith(signed, fed.certPem);
  check("attacker-signed metadata refused (bad-signature)",
        r.code === "auth-saml/bad-signature");
}

// THE BUG — a wrapping md:EntitiesDescriptor root whose FIRST child is the
// genuine federation ds:Signature (URI=#G1), followed by a FORGED
// EntityDescriptor carrying the ATTACKER signing cert, then the intact genuine
// entity G1 (the digest target). A first-child Signature lookup picks the
// genuine sig; _verifyXmldsig validates G1 + the federation signature; the
// discarded refId is never bound to the consumed root — so pre-fix the wrapped
// doc (carrying the attacker cert) is accepted and returned (RED).
async function testMetadataSignatureWrappingRefused() {
  var fed      = await _mintRsaCert("federation.example");
  var attacker = await _mintRsaCert("attacker.example");
  var idp      = await _mintRsaCert("idp.example");

  var genuineEntity = _entityDescriptor("G1", idp.certPem);                // federation signs THIS
  var genuineSig    = _federationSignature(fed, "G1", genuineEntity);
  var forgedEntity  = _entityDescriptor("EVIL", attacker.certPem);         // attacker cert, unsigned

  var wrapped =
    "<md:EntitiesDescriptor xmlns:md=\"" + MD + "\">" +
    genuineSig +        // moved up → first-child Signature lookup picks the genuine sig
    forgedEntity +      // first EntityDescriptor an operator parse would extract
    genuineEntity +     // intact digest target #G1, unsigned copy
    "</md:EntitiesDescriptor>";

  var r = await _fetchMdqWith(wrapped, fed.certPem);
  check("MDQ signature-wrapping (EntitiesDescriptor): fetchMdq refuses",
        r.code !== null && r.xml === null);
  check("MDQ signature-wrapping (EntitiesDescriptor): attacker cert never returned",
        r.xml === null || r.xml.indexOf(_certBodyB64(attacker.certPem)) === -1);
}

// THE BUG, intra-document variant — a single EntityDescriptor root with an
// attacker-chosen ID (EVIL) carrying the attacker signing cert, while the
// genuine federation ds:Signature (URI=#G1) + intact genuine entity G1 are
// buried in md:Extensions. The discarded refId ("G1") never gets bound to the
// root ID ("EVIL"). Post-fix this is exactly auth-saml/signed-different-element.
async function testMetadataInnerWrappingRefused() {
  var fed      = await _mintRsaCert("federation.example");
  var attacker = await _mintRsaCert("attacker.example");
  var idp      = await _mintRsaCert("idp.example");

  var genuineEntity = _entityDescriptor("G1", idp.certPem);
  var genuineSig    = _federationSignature(fed, "G1", genuineEntity);

  var evilRoot =
    "<md:EntityDescriptor xmlns:md=\"" + MD + "\" ID=\"EVIL\" entityID=\"" + IDP_ENTITY_ID + "\">" +
    genuineSig +
    "<md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">" +
    "<md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"" + DS + "\"><ds:X509Data><ds:X509Certificate>" +
    _certBodyB64(attacker.certPem) +
    "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor></md:IDPSSODescriptor>" +
    "<md:Extensions>" + genuineEntity + "</md:Extensions>" +
    "</md:EntityDescriptor>";

  var r = await _fetchMdqWith(evilRoot, fed.certPem);
  check("MDQ inner-wrapping: fetchMdq throws signed-different-element",
        r.code === "auth-saml/signed-different-element");
  check("MDQ inner-wrapping: attacker cert never returned", r.xml === null);
}

async function run() {
  await testGenuineSignedMetadataAccepted();
  await testAttackerSignedMetadataRefused();
  await testMetadataSignatureWrappingRefused();
  await testMetadataInnerWrappingRefused();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); });
}
