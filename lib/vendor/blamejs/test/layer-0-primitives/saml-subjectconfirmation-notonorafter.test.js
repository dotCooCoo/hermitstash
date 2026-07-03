// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.saml.sp.verifyResponse — SubjectConfirmationData NotOnOrAfter
 * is mandatory and must fail closed.
 *
 * SAML 2.0 Web Browser SSO Profile §4.1.4.2 requires every Bearer
 * SubjectConfirmationData to carry a `NotOnOrAfter` attribute that
 * bounds the assertion's freshness window. A SubjectConfirmationData
 * with no NotOnOrAfter — or an unparseable one — must be rejected:
 * accepting it grants an unbounded, replay-forever confirmation. The
 * Holder-of-Key confirmation (Profile §3.1, which incorporates the
 * §3 time-bounding by reference) has the same requirement.
 *
 * These tests drive the shipped consumer path:
 *   sp = b.auth.saml.sp.create({ ... }); sp.verifyResponse(b64, vopts).
 * They mint a self-signed RSA IdP cert, build a genuinely XMLDSig-
 * signed SAML Response (digest + SignatureValue computed through the
 * framework's own b.xmlC14n so the verifier's recomputation matches),
 * and vary ONLY the SubjectConfirmationData's NotOnOrAfter between the
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

function _bearerScd(notOnOrAfterAttr, inResponseTo) {
  return "<saml:SubjectConfirmationData" + notOnOrAfterAttr +
    " Recipient=\"" + ACS_URL + "\"" +
    " InResponseTo=\"" + inResponseTo + "\"/>";
}

function _certBodyB64(pem) {
  return pem.replace(/-----BEGIN CERTIFICATE-----/, "")
            .replace(/-----END CERTIFICATE-----/, "")
            .replace(/\s+/g, "");
}

function _hokScd(notOnOrAfterAttr, holderCertPem) {
  return "<saml:SubjectConfirmationData" + notOnOrAfterAttr +
    " Recipient=\"" + ACS_URL + "\">" +
    "<ds:KeyInfo xmlns:ds=\"" + DS + "\"><ds:X509Data><ds:X509Certificate>" +
    _certBodyB64(holderCertPem) +
    "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>" +
    "</saml:SubjectConfirmationData>";
}

// Same shape, Recipient attribute OMITTED — the Web SSO profile (§4.1.4.2)
// makes Recipient mandatory for a Bearer/HoK confirmation delivered to an ACS.
function _bearerScdNoRecipient(notOnOrAfterAttr, inResponseTo) {
  return "<saml:SubjectConfirmationData" + notOnOrAfterAttr +
    " InResponseTo=\"" + inResponseTo + "\"/>";
}

function _hokScdNoRecipient(notOnOrAfterAttr, holderCertPem) {
  return "<saml:SubjectConfirmationData" + notOnOrAfterAttr + ">" +
    "<ds:KeyInfo xmlns:ds=\"" + DS + "\"><ds:X509Data><ds:X509Certificate>" +
    _certBodyB64(holderCertPem) +
    "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>" +
    "</saml:SubjectConfirmationData>";
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

// Case 1 — a valid future NotOnOrAfter succeeds. Proves the signer +
// harness are correct and the fail-closed fix does not break the
// happy path.
async function testBearerValidNotOnOrAfterAccepted() {
  var idp = await _mintRsaCert("idp.example");
  var sp  = _newSp(idp);
  var inResponseTo = "_req-valid";
  var b64 = _buildSignedResponse(idp, {
    tag:    "bearer-valid",
    method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
    nameId: "alice@example.com",
    scd:    _bearerScd(" NotOnOrAfter=\"" + _isoFromNow(5 * 60 * 1000) + "\"", inResponseTo),   // allow:raw-time-literal — 5m future
  });
  var info = sp.verifyResponse(b64, { expectedInResponseTo: inResponseTo });
  check("Bearer with valid NotOnOrAfter verifies",       info && typeof info === "object");
  check("Bearer valid: nameId returned",                 info.nameId === "alice@example.com");
  check("Bearer valid: issuer matches IdP entityID",     info.issuer === IDP_ENTITY_ID);
  check("Bearer valid: inResponseTo captured",           info.inResponseTo === inResponseTo);
}

// Case 2 — a Bearer SubjectConfirmationData with NO NotOnOrAfter must
// be refused (§4.1.4.2). This is the RED case: on the unfixed tree the
// confirmation is wrongly accepted as fresh-forever.
async function testBearerMissingNotOnOrAfterRefused() {
  var idp = await _mintRsaCert("idp.example");
  var sp  = _newSp(idp);
  var inResponseTo = "_req-missing";
  var b64 = _buildSignedResponse(idp, {
    tag:    "bearer-missing",
    method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
    nameId: "alice@example.com",
    scd:    _bearerScd("", inResponseTo),
  });
  var code = _verifyThrows(sp, b64, { expectedInResponseTo: inResponseTo });
  check("Bearer missing NotOnOrAfter is refused",
    code === "auth-saml/no-valid-confirmation");
}

// Case 3 — a Bearer SubjectConfirmationData with an UNPARSEABLE
// NotOnOrAfter must be refused (it cannot bound freshness).
async function testBearerUnparseableNotOnOrAfterRefused() {
  var idp = await _mintRsaCert("idp.example");
  var sp  = _newSp(idp);
  var inResponseTo = "_req-bad";
  var b64 = _buildSignedResponse(idp, {
    tag:    "bearer-bad",
    method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
    nameId: "alice@example.com",
    scd:    _bearerScd(" NotOnOrAfter=\"not-a-date\"", inResponseTo),
  });
  var code = _verifyThrows(sp, b64, { expectedInResponseTo: inResponseTo });
  check("Bearer unparseable NotOnOrAfter is refused",
    code === "auth-saml/no-valid-confirmation");
}

// Case 4 — the Holder-of-Key sibling: an HoK SubjectConfirmationData
// missing NotOnOrAfter (and one with an unparseable value) must be
// refused. On the unfixed tree both are wrongly accepted (the missing
// case skips the check; the unparseable case is masked by an `&&`
// short-circuit).
async function testHolderOfKeyNotOnOrAfterRefused() {
  var idp    = await _mintRsaCert("idp.example");
  var holder = await _mintRsaCert("holder.example");
  var sp     = _newSp(idp);
  var vopts  = { holderOfKey: { presentedCertPem: holder.certPem } };

  // Sanity — a valid HoK NotOnOrAfter verifies (harness correctness).
  var b64ok = _buildSignedResponse(idp, {
    tag:    "hok-valid",
    method: "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key",
    nameId: "bob@example.com",
    scd:    _hokScd(" NotOnOrAfter=\"" + _isoFromNow(5 * 60 * 1000) + "\"", holder.certPem),    // allow:raw-time-literal — 5m future
  });
  var info = sp.verifyResponse(b64ok, vopts);
  check("HoK with valid NotOnOrAfter verifies",          info && info.nameId === "bob@example.com");

  var b64missing = _buildSignedResponse(idp, {
    tag:    "hok-missing",
    method: "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key",
    nameId: "bob@example.com",
    scd:    _hokScd("", holder.certPem),
  });
  check("HoK missing NotOnOrAfter is refused",
    _verifyThrows(sp, b64missing, vopts) === "auth-saml/no-valid-confirmation");

  var b64bad = _buildSignedResponse(idp, {
    tag:    "hok-bad",
    method: "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key",
    nameId: "bob@example.com",
    scd:    _hokScd(" NotOnOrAfter=\"not-a-date\"", holder.certPem),
  });
  check("HoK unparseable NotOnOrAfter is refused",
    _verifyThrows(sp, b64bad, vopts) === "auth-saml/no-valid-confirmation");
}

// SAML 2.0 Profiles §4.1.4.2 — a Bearer SubjectConfirmationData delivered to
// an ACS MUST carry a Recipient equal to the SP's ACS URL. An assertion whose
// Bearer confirmation omits Recipient must be refused; accepting it lets an
// assertion relayed to an unintended endpoint pass the recipient-binding axis.
async function testBearerMissingRecipientRefused() {
  var idp = await _mintRsaCert("idp.example");
  var sp  = _newSp(idp);
  var inResponseTo = "_req-no-recip";
  var b64 = _buildSignedResponse(idp, {
    tag:    "bearer-no-recip",
    method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
    nameId: "alice@example.com",
    scd:    _bearerScdNoRecipient(" NotOnOrAfter=\"" + _isoFromNow(5 * 60 * 1000) + "\"", inResponseTo),   // allow:raw-time-literal — 5m future
  });
  check("Bearer with no Recipient is refused (§4.1.4.2 mandatory)",
    _verifyThrows(sp, b64, { expectedInResponseTo: inResponseTo }) === "auth-saml/no-valid-confirmation");
}

// The Holder-of-Key sibling incorporates the same Web SSO Recipient requirement
// (Profile §3.1 by reference). An HoK confirmation delivered to an ACS with no
// Recipient must be refused too.
async function testHolderOfKeyMissingRecipientRefused() {
  var idp    = await _mintRsaCert("idp.example");
  var holder = await _mintRsaCert("holder.example");
  var sp     = _newSp(idp);
  var b64 = _buildSignedResponse(idp, {
    tag:    "hok-no-recip",
    method: "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key",
    nameId: "bob@example.com",
    scd:    _hokScdNoRecipient(" NotOnOrAfter=\"" + _isoFromNow(5 * 60 * 1000) + "\"", holder.certPem),    // allow:raw-time-literal — 5m future
  });
  check("HoK with no Recipient is refused (§3.1 incorporates §4.1.4.2)",
    _verifyThrows(sp, b64, { holderOfKey: { presentedCertPem: holder.certPem } }) === "auth-saml/no-valid-confirmation");
}

// #B0 — a signed assertion with NO AudienceRestriction is not bound to THIS
// SP. Accepting it is audience-confusion: an IdP-signed assertion minted for
// another SP is replayed here. Must fail closed (default on).
async function testMissingAudienceRestrictionRefused() {
  var idp = await _mintRsaCert("idp.example");
  var sp  = _newSp(idp);
  var inResponseTo = "_req-noaud";
  var b64 = _buildSignedResponse(idp, {
    tag:    "no-aud",
    method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
    nameId: "u@example.com",
    scd:    _bearerScd(" NotOnOrAfter=\"" + _isoFromNow(5 * 60 * 1000) + "\"", inResponseTo),    // allow:raw-time-literal — 5m future
    conditions: "<saml:Conditions NotBefore=\"" + _isoFromNow(-5 * 60 * 1000) +                  // allow:raw-time-literal — 5m skew
      "\" NotOnOrAfter=\"" + _isoFromNow(5 * 60 * 1000) + "\"></saml:Conditions>",               // allow:raw-time-literal — NO AudienceRestriction
  });
  check("signed assertion without AudienceRestriction refused (audience-confusion)",
    _verifyThrows(sp, b64, { expectedInResponseTo: inResponseTo }) === "auth-saml/no-audience-restriction");
}

// #B0 — a present-but-unparseable Conditions NotBefore/NotOnOrAfter must fail
// CLOSED (the Bearer SCD path already does; the Conditions path skipped it via
// an isFinite() short-circuit, so an unparseable validity window was ignored).
async function testUnparseableConditionsTimestampRefused() {
  var idp = await _mintRsaCert("idp.example");
  var sp  = _newSp(idp);
  var inResponseTo = "_req-badts";
  var b64 = _buildSignedResponse(idp, {
    tag:    "bad-ts",
    method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
    nameId: "u@example.com",
    scd:    _bearerScd(" NotOnOrAfter=\"" + _isoFromNow(5 * 60 * 1000) + "\"", inResponseTo),    // allow:raw-time-literal — 5m future
    conditions: "<saml:Conditions NotBefore=\"" + _isoFromNow(-5 * 60 * 1000) +                  // allow:raw-time-literal — valid NotBefore
      "\" NotOnOrAfter=\"not-a-date\">" +
      "<saml:AudienceRestriction><saml:Audience>" + SP_ENTITY_ID +
      "</saml:Audience></saml:AudienceRestriction></saml:Conditions>",
  });
  check("unparseable Conditions NotOnOrAfter refused (fail-closed)",
    _verifyThrows(sp, b64, { expectedInResponseTo: inResponseTo }) === "auth-saml/conditions-bad-timestamp");
}

// SAML core §2.5.1.4 — multiple <AudienceRestriction> elements are AND-combined:
// the SP must be a member of EVERY one. An assertion whose first restriction
// lists this SP but whose second narrows to a DIFFERENT audience must be refused
// (checking only the first let it through — audience-confusion).
async function testSecondAudienceRestrictionEnforced() {
  var idp = await _mintRsaCert("idp.example");
  var sp  = _newSp(idp);
  var inResponseTo = "_req-2aud";
  var b64 = _buildSignedResponse(idp, {
    tag:    "two-aud",
    method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
    nameId: "u@example.com",
    scd:    _bearerScd(" NotOnOrAfter=\"" + _isoFromNow(5 * 60 * 1000) + "\"", inResponseTo),    // allow:raw-time-literal — 5m future
    conditions: "<saml:Conditions NotBefore=\"" + _isoFromNow(-5 * 60 * 1000) +                  // allow:raw-time-literal — 5m skew
      "\" NotOnOrAfter=\"" + _isoFromNow(5 * 60 * 1000) + "\">" +                                 // allow:raw-time-literal — 5m future
      "<saml:AudienceRestriction><saml:Audience>" + SP_ENTITY_ID +
      "</saml:Audience></saml:AudienceRestriction>" +
      "<saml:AudienceRestriction><saml:Audience>https://other-sp.example/different" +
      "</saml:Audience></saml:AudienceRestriction></saml:Conditions>",
  });
  check("second AudienceRestriction (different audience) refused (AND-combined)",
    _verifyThrows(sp, b64, { expectedInResponseTo: inResponseTo }) === "auth-saml/wrong-audience");
}

async function run() {
  await testBearerValidNotOnOrAfterAccepted();
  await testBearerMissingNotOnOrAfterRefused();
  await testBearerUnparseableNotOnOrAfterRefused();
  await testHolderOfKeyNotOnOrAfterRefused();
  await testBearerMissingRecipientRefused();
  await testHolderOfKeyMissingRecipientRefused();
  await testMissingAudienceRestrictionRefused();
  await testSecondAudienceRestrictionEnforced();
  await testUnparseableConditionsTimestampRefused();
}

if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
module.exports = { run: run };
