"use strict";
/**
 * b.auth.saml.sp.verifyResponse — Bearer SubjectConfirmationData
 * NotBefore must fail closed when present-but-unparseable.
 *
 * SAML 2.0 Web Browser SSO Profile §4.1.4.2: a Bearer
 * SubjectConfirmationData MAY carry a `NotBefore` bounding the start of
 * its validity window. When NotBefore is PRESENT, the verifier must
 * honor it. A NotBefore that cannot be parsed (Date.parse → NaN) is an
 * IdP error or a tampered attribute — it cannot establish that the
 * confirmation has begun, so it must NOT be silently dropped, leaving
 * the SCD accepted. It must fail closed (the confirmation is skipped,
 * the verifier tries the next one, and an assertion with no other valid
 * confirmation is refused) — mirroring the NotOnOrAfter line just above
 * and the already-hardened Conditions block.
 *
 * These tests drive the shipped consumer path:
 *   sp = b.auth.saml.sp.create({ ... }); sp.verifyResponse(b64, vopts).
 * They mint a self-signed RSA IdP cert, build a genuinely XMLDSig-
 * signed SAML Response (digest + SignatureValue computed through the
 * framework's own b.xmlC14n so the verifier's recomputation matches),
 * and vary ONLY the SubjectConfirmationData's NotBefore between the
 * accepted and refused cases.
 */

var helpers    = require("../helpers");
var check      = helpers.check;
var b          = helpers.b;
var nodeCrypto = require("node:crypto");
var c14n       = require("../../lib/xml-c14n");

var DS  = "http://www.w3.org/2000/09/xmldsig#";
var EXC = "http://www.w3.org/2001/10/xml-exc-c14n#";

var IDP_ENTITY_ID = "https://idp.example";
var SP_ENTITY_ID  = "https://sp.example";
var ACS_URL       = "https://sp.example/saml/acs";

// Mint a self-signed RSA cert via the vendored @peculiar/x509 bundle.
// verifyResponse parses idpCertPem with nodeCrypto.createPublicKey and
// verifies an rsa-sha256 PKCS1 signature, so a real RSA cert + matching
// private key is required — there is no test bypass of the signature
// check.
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

function _isoFromNow(ms) { return new Date(Date.now() + ms).toISOString(); }

// Build a SAML Response with an Assertion-level enveloped XMLDSig
// signature. The Assertion's Signature child is stripped before the
// digest (the enveloped-signature transform), and both the digest and
// the SignedInfo are canonicalized through b.xmlC14n so the values
// match exactly what verifyResponse recomputes.
function _buildSignedResponse(idp, parts) {
  var assertionId  = "_assertion-" + parts.tag;
  var responseId   = "_response-" + parts.tag;
  var issueInstant = _isoFromNow(0);
  var subjectConfirmation =
    "<saml:SubjectConfirmation Method=\"" + parts.method + "\">" +
    parts.scd +
    "</saml:SubjectConfirmation>";

  var assertionInner =
    "<saml:Issuer>" + IDP_ENTITY_ID + "</saml:Issuer>" +
    "SIGNATURE_PLACEHOLDER" +
    "<saml:Subject>" +
    "<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">" +
    parts.nameId + "</saml:NameID>" +
    subjectConfirmation +
    "</saml:Subject>" +
    (parts.conditions !== undefined ? parts.conditions :
      "<saml:Conditions NotBefore=\"" + _isoFromNow(-5 * 60 * 1000) +                            // allow:raw-time-literal — 5m skew window
      "\" NotOnOrAfter=\"" + _isoFromNow(5 * 60 * 1000) + "\">" +                                // allow:raw-time-literal — 5m skew window
      "<saml:AudienceRestriction><saml:Audience>" + SP_ENTITY_ID +
      "</saml:Audience></saml:AudienceRestriction>" +
      "</saml:Conditions>") +
    "<saml:AuthnStatement SessionIndex=\"_sess-1\" AuthnInstant=\"" + issueInstant + "\">" +
    "<saml:AuthnContext><saml:AuthnContextClassRef>" +
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" +
    "</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>";

  var assertionOpen =
    "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
    "ID=\"" + assertionId + "\" Version=\"2.0\" IssueInstant=\"" + issueInstant + "\">";
  var assertionClose = "</saml:Assertion>";

  // Digest the assertion with no Signature child (enveloped-signature
  // transform output), canonicalized through b.xmlC14n.
  var assertionNoSig = assertionOpen +
    assertionInner.replace("SIGNATURE_PLACEHOLDER", "") + assertionClose;
  var digest = nodeCrypto.createHash("sha256")
    .update(c14n.canonicalize(assertionNoSig)).digest("base64");

  var signedInfo =
    "<ds:SignedInfo xmlns:ds=\"" + DS + "\">" +
    "<ds:CanonicalizationMethod Algorithm=\"" + EXC + "\"></ds:CanonicalizationMethod>" +
    "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></ds:SignatureMethod>" +
    "<ds:Reference URI=\"#" + assertionId + "\">" +
    "<ds:Transforms>" +
    "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></ds:Transform>" +
    "<ds:Transform Algorithm=\"" + EXC + "\"></ds:Transform>" +
    "</ds:Transforms>" +
    "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod>" +
    "<ds:DigestValue>" + digest + "</ds:DigestValue>" +
    "</ds:Reference>" +
    "</ds:SignedInfo>";
  var priv = nodeCrypto.createPrivateKey({ key: idp.keyPem, format: "pem" });
  var sigValue = nodeCrypto.sign("sha256", c14n.canonicalize(signedInfo),
    { key: priv, padding: nodeCrypto.constants.RSA_PKCS1_PADDING }).toString("base64");

  var signatureXml =
    "<ds:Signature xmlns:ds=\"" + DS + "\">" + signedInfo +
    "<ds:SignatureValue>" + sigValue + "</ds:SignatureValue></ds:Signature>";
  var assertionFull = assertionOpen +
    assertionInner.replace("SIGNATURE_PLACEHOLDER", signatureXml) + assertionClose;

  var response =
    "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
    "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
    "ID=\"" + responseId + "\" Version=\"2.0\" IssueInstant=\"" + issueInstant + "\" " +
    "Destination=\"" + ACS_URL + "\">" +
    "<saml:Issuer>" + IDP_ENTITY_ID + "</saml:Issuer>" +
    "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>" +
    assertionFull + "</samlp:Response>";

  return Buffer.from(response, "utf8").toString("base64");
}

function _bearerScd(notBeforeAttr, inResponseTo) {
  return "<saml:SubjectConfirmationData" +
    " NotOnOrAfter=\"" + _isoFromNow(5 * 60 * 1000) + "\"" +                                      // allow:raw-time-literal — 5m future, otherwise-valid window
    notBeforeAttr +
    " Recipient=\"" + ACS_URL + "\"" +
    " InResponseTo=\"" + inResponseTo + "\"/>";
}

function _newSp(idp) {
  return b.auth.saml.sp.create({
    entityId:                    SP_ENTITY_ID,
    assertionConsumerServiceUrl: ACS_URL,
    idpEntityId:                 IDP_ENTITY_ID,
    idpSsoUrl:                   "https://idp.example/sso",
    idpCertPem:                  idp.certPem,
  });
}

function _verifyThrows(sp, b64, vopts) {
  try { sp.verifyResponse(b64, vopts); return null; }
  catch (e) { return e.code || e.message; }
}

// Case 1 — a past (already-valid) NotBefore succeeds. Proves the signer
// + harness are correct and the fail-closed fix does not break the happy
// path (an otherwise-acceptable confirmation that has begun).
async function testBearerPastNotBeforeAccepted() {
  var idp = await _mintRsaCert("idp.example");
  var sp  = _newSp(idp);
  var inResponseTo = "_req-past-nb";
  var b64 = _buildSignedResponse(idp, {
    tag:    "bearer-past-nb",
    method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
    nameId: "alice@example.com",
    scd:    _bearerScd(" NotBefore=\"" + _isoFromNow(-5 * 60 * 1000) + "\"", inResponseTo),       // allow:raw-time-literal — 5m past, already valid
  });
  var info = sp.verifyResponse(b64, { expectedInResponseTo: inResponseTo });
  check("Bearer with past NotBefore verifies",           info && typeof info === "object");
  check("Bearer past NotBefore: nameId returned",        info.nameId === "alice@example.com");
}

// Case 2 — a NotBefore in the FUTURE (not yet valid) must be refused.
// This path already fails closed on the unfixed tree (isFinite(nb) is
// true and nb > now), so it is the harness-correctness control proving
// the not-yet-valid axis is enforced at all.
async function testBearerFutureNotBeforeRefused() {
  var idp = await _mintRsaCert("idp.example");
  var sp  = _newSp(idp);
  var inResponseTo = "_req-future-nb";
  var b64 = _buildSignedResponse(idp, {
    tag:    "bearer-future-nb",
    method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
    nameId: "alice@example.com",
    scd:    _bearerScd(" NotBefore=\"" + _isoFromNow(60 * 60 * 1000) + "\"", inResponseTo),       // allow:raw-time-literal — 1h future, not yet valid
  });
  check("Bearer with future NotBefore is refused (not yet valid)",
    _verifyThrows(sp, b64, { expectedInResponseTo: inResponseTo }) === "auth-saml/no-valid-confirmation");
}

// Case 3 — the RED case: a Bearer SubjectConfirmationData with a
// present-but-UNPARSEABLE NotBefore. On the unfixed tree `isFinite(nb)`
// is false, so the `&&`-guarded not-yet-valid check is skipped and the
// SCD is wrongly ACCEPTED. It must fail closed: an unparseable NotBefore
// cannot establish that the confirmation has begun, so the SCD is
// skipped and the assertion (with no other valid confirmation) refused.
async function testBearerUnparseableNotBeforeRefused() {
  var idp = await _mintRsaCert("idp.example");
  var sp  = _newSp(idp);
  var inResponseTo = "_req-bad-nb";
  var b64 = _buildSignedResponse(idp, {
    tag:    "bearer-bad-nb",
    method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
    nameId: "alice@example.com",
    scd:    _bearerScd(" NotBefore=\"not-a-date\"", inResponseTo),
  });
  check("Bearer unparseable NotBefore is refused (fail-closed)",
    _verifyThrows(sp, b64, { expectedInResponseTo: inResponseTo }) === "auth-saml/no-valid-confirmation");
}

async function run() {
  await testBearerPastNotBeforeAccepted();
  await testBearerFutureNotBeforeRefused();
  await testBearerUnparseableNotBeforeRefused();
}

if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
module.exports = { run: run };
