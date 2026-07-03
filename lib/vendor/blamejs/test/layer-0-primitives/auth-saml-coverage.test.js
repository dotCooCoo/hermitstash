// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.saml.sp — branch-coverage sweep for the SAML 2.0 SP primitive.
 *
 * The existing SAML suites cover the SubjectConfirmation NotBefore /
 * NotOnOrAfter fail-closed windows, the SLO HTTP-Redirect signing round-trip,
 * and the MDQ signature-wrapping defense. This file closes the remaining
 * unit-testable branches driven through the shipped consumer path
 * (b.auth.saml.sp.create + the returned SP methods, b.auth.saml.fetchMdq):
 *
 *   - create() config-time validation (missing required fields, unknown opt,
 *     bad clockSkew) — each throws through the AuthError codes it advertises;
 *   - buildAuthnRequest / metadata XML-attribute escaping (RFC 3741) so a
 *     hostile ACS / entityId / nameIdFormat cannot break out of its context;
 *   - verifyResponse pre-signature structural refusals: non-string / non-XML
 *     input, wrong root, non-Success Status, the XSW duplicate-element shapes
 *     (Status / StatusCode / Assertion / EncryptedAssertion), the unsigned
 *     refusal, and EncryptedAssertion-without-SP-key;
 *   - verifyResponse signed-path refusals that fire only after XMLDSig
 *     verification succeeds (wrong Issuer, audience-confusion, expired
 *     Conditions, the duplicate-Subject XSW), plus the happy path returning
 *     nameId / sessionIndex / attributes;
 *   - the SLO redirect + HTTP-POST + SOAP build/parse validation surface.
 *
 * Signed fixtures mint a self-signed RSA IdP cert and compute the digest +
 * SignatureValue through the framework's own b.xmlC14n so verifyResponse's
 * recomputation matches exactly — there is no test bypass of the signature
 * check (a wrong-key negative control proves the signature gate is live).
 */

var helpers    = require("../helpers");
var check      = helpers.check;
var b          = helpers.b;
var nodeCrypto = require("node:crypto");
var c14n       = require("../../lib/xml-c14n");
var pq         = require("../../lib/pqc-software");

var DS  = "http://www.w3.org/2000/09/xmldsig#";
var EXC = "http://www.w3.org/2001/10/xml-exc-c14n#";

var IDP_ENTITY_ID = "https://idp.example";
var SP_ENTITY_ID  = "https://sp.example";
var ACS_URL       = "https://sp.example/saml/acs";
var IDP_SSO_URL   = "https://idp.example/sso";
var IDP_SLO_URL   = "https://idp.example/slo";
var FAKE_CERT     = "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----";

var BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
var SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";

function iso(ms) { return new Date(Date.now() + ms).toISOString(); }
function b64(xml) { return Buffer.from(xml, "utf8").toString("base64"); }

// Mint a self-signed RSA cert via the vendored @peculiar/x509 bundle — the
// same shape the SubjectConfirmation / MDQ suites use. verifyResponse parses
// idpCertPem with nodeCrypto.createPublicKey and verifies an rsa-sha256 PKCS1
// signature, so a real RSA keypair is required.
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

// An SP with a placeholder cert — for branches that throw BEFORE any real
// signature verification (all the input-validation / XSW-structural refusals),
// where idpCertPem is stored but never parsed.
function _fakeSp(extra) {
  var opts = {
    entityId:                    SP_ENTITY_ID,
    assertionConsumerServiceUrl: ACS_URL,
    idpEntityId:                 IDP_ENTITY_ID,
    idpSsoUrl:                   IDP_SSO_URL,
    idpSloUrl:                   IDP_SLO_URL,
    idpCertPem:                  FAKE_CERT,
  };
  if (extra) { for (var k in extra) { opts[k] = extra[k]; } }
  return b.auth.saml.sp.create(opts);
}

// An SP whose trust anchor is a minted RSA cert — for the signed-path branches.
function _realSp(idp, extra) {
  var opts = {
    entityId:                    SP_ENTITY_ID,
    assertionConsumerServiceUrl: ACS_URL,
    idpEntityId:                 IDP_ENTITY_ID,
    idpSsoUrl:                   IDP_SSO_URL,
    idpCertPem:                  idp.certPem,
  };
  if (extra) { for (var k in extra) { opts[k] = extra[k]; } }
  return b.auth.saml.sp.create(opts);
}

function _codeOf(fn) {
  try { fn(); return "NO-THROW"; }
  catch (e) { return e.code || e.message; }
}
function _verifyCode(sp, xmlB64, vopts) {
  return _codeOf(function () { sp.verifyResponse(xmlB64, vopts || {}); });
}

// Build a SAML Response with an Assertion-level enveloped XMLDSig signature.
// The Assertion's Signature child is stripped before the digest (the
// enveloped-signature transform); both the digest and the SignedInfo are
// canonicalized through b.xmlC14n so the verifier's recomputation matches.
// `o` overrides: issuer, subjectXml, conditions, audience, attrStmt, scd.
function _buildSignedResponse(idp, o) {
  o = o || {};
  var assertionId  = "_assertion-" + o.tag;
  var responseId   = "_response-" + o.tag;
  var issueInstant = iso(0);

  var issuer = o.issuer !== undefined ? o.issuer : IDP_ENTITY_ID;
  var issuerXml = issuer === null ? "" : "<saml:Issuer>" + issuer + "</saml:Issuer>";

  var scd = o.scd !== undefined ? o.scd :
    "<saml:SubjectConfirmationData NotOnOrAfter=\"" + iso(5 * 60 * 1000) + "\"" +          // allow:raw-time-literal — 5m otherwise-valid window
    " Recipient=\"" + ACS_URL + "\"" +
    (o.inResponseTo ? " InResponseTo=\"" + o.inResponseTo + "\"" : "") + "/>";
  var subjectXml = o.subjectXml !== undefined ? o.subjectXml :
    "<saml:Subject>" +
    "<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">" +
    (o.nameId || "alice@example.com") + "</saml:NameID>" +
    "<saml:SubjectConfirmation Method=\"" + BEARER + "\">" + scd +
    "</saml:SubjectConfirmation></saml:Subject>";

  var conditions = o.conditions !== undefined ? o.conditions :
    "<saml:Conditions NotBefore=\"" + iso(-5 * 60 * 1000) +                                 // allow:raw-time-literal — 5m skew window
    "\" NotOnOrAfter=\"" + iso(5 * 60 * 1000) + "\">" +                                     // allow:raw-time-literal — 5m skew window
    "<saml:AudienceRestriction><saml:Audience>" + (o.audience || SP_ENTITY_ID) +
    "</saml:Audience></saml:AudienceRestriction></saml:Conditions>";

  var authnStmt = "<saml:AuthnStatement SessionIndex=\"_sess-1\" AuthnInstant=\"" + issueInstant +
    "\"><saml:AuthnContext><saml:AuthnContextClassRef>" +
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" +
    "</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>";
  var attrStmt = o.attrStmt || "";

  var open = "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
    "ID=\"" + assertionId + "\" Version=\"2.0\" IssueInstant=\"" + issueInstant + "\">";
  var close = "</saml:Assertion>";
  var inner = issuerXml + "SIGNATURE_PLACEHOLDER" + subjectXml + conditions + authnStmt + attrStmt;

  var noSig = open + inner.replace("SIGNATURE_PLACEHOLDER", "") + close;
  var digest = nodeCrypto.createHash("sha256").update(c14n.canonicalize(noSig)).digest("base64");

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
    "</ds:Reference></ds:SignedInfo>";
  var priv = nodeCrypto.createPrivateKey({ key: idp.keyPem, format: "pem" });
  var sigValue = nodeCrypto.sign("sha256", c14n.canonicalize(signedInfo),
    { key: priv, padding: nodeCrypto.constants.RSA_PKCS1_PADDING }).toString("base64");
  var signatureXml = "<ds:Signature xmlns:ds=\"" + DS + "\">" + signedInfo +
    "<ds:SignatureValue>" + sigValue + "</ds:SignatureValue></ds:Signature>";

  var assertionFull = open + inner.replace("SIGNATURE_PLACEHOLDER", signatureXml) + close;
  var response =
    "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
    "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
    "ID=\"" + responseId + "\" Version=\"2.0\" IssueInstant=\"" + issueInstant + "\" " +
    "Destination=\"" + ACS_URL + "\">" +
    "<saml:Issuer>" + IDP_ENTITY_ID + "</saml:Issuer>" +
    "<samlp:Status><samlp:StatusCode Value=\"" + SUCCESS + "\"/></samlp:Status>" +
    assertionFull + "</samlp:Response>";
  return b64(response);
}

// A bare (unsigned) Response envelope for the pre-signature structural cases.
var P_NS = "xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
           "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"";
var STATUS_OK = "<samlp:Status><samlp:StatusCode Value=\"" + SUCCESS + "\"/></samlp:Status>";
function _response(inner) { return "<samlp:Response " + P_NS + " ID=\"_r\">" + inner + "</samlp:Response>"; }

// ---------------------------------------------------------------------------
// create() config-time validation
// ---------------------------------------------------------------------------

function testCreateRequiredFields() {
  var base = {
    entityId: SP_ENTITY_ID, assertionConsumerServiceUrl: ACS_URL,
    idpEntityId: IDP_ENTITY_ID, idpSsoUrl: IDP_SSO_URL, idpCertPem: FAKE_CERT,
  };
  function omit(k) { var c = Object.assign({}, base); delete c[k]; return _codeOf(function () { b.auth.saml.sp.create(c); }); }
  check("create: missing entityId → no-entity-id",       omit("entityId") === "auth-saml/no-entity-id");
  check("create: missing ACS → no-acs",                  omit("assertionConsumerServiceUrl") === "auth-saml/no-acs");
  check("create: missing idpEntityId → no-idp-entity-id", omit("idpEntityId") === "auth-saml/no-idp-entity-id");
  check("create: missing idpSsoUrl → no-idp-sso",        omit("idpSsoUrl") === "auth-saml/no-idp-sso");
  check("create: missing idpCertPem → no-idp-cert",      omit("idpCertPem") === "auth-saml/no-idp-cert");
}

function testCreateRejectsBadOpts() {
  var base = {
    entityId: SP_ENTITY_ID, assertionConsumerServiceUrl: ACS_URL,
    idpEntityId: IDP_ENTITY_ID, idpSsoUrl: IDP_SSO_URL, idpCertPem: FAKE_CERT,
  };
  function withOpt(o) { return _codeOf(function () { b.auth.saml.sp.create(Object.assign({}, base, o)); }); }

  var unknown = null;
  try { b.auth.saml.sp.create(Object.assign({}, base, { bogusKey: 1 })); }
  catch (e) { unknown = e; }
  check("create: unknown opt is refused",             unknown !== null && unknown.code === "BAD_OPT");
  check("create: unknown-opt message names the key",  unknown && /bogusKey/.test(unknown.message));

  // clockSkewSec must be a finite, non-negative number — a negative, Infinity,
  // or string value is refused at config time (an Infinity that slipped
  // through would disable the freshness windows downstream).
  check("create: negative clockSkewSec refused", withOpt({ clockSkewSec: -1 }) === "BAD_OPT");
  check("create: Infinity clockSkewSec refused", withOpt({ clockSkewSec: Infinity }) === "BAD_OPT");
  check("create: string clockSkewSec refused",   withOpt({ clockSkewSec: "60" }) === "BAD_OPT");

  check("create: non-object opts refused", _codeOf(function () { b.auth.saml.sp.create("nope"); }) === "BAD_OPT");
  check("create: null opts refused",       _codeOf(function () { b.auth.saml.sp.create(null); }) === "BAD_OPT");
}

// ---------------------------------------------------------------------------
// buildAuthnRequest — shape + RFC 3741 XML escaping + redirect assembly
// ---------------------------------------------------------------------------

function testAuthnRequestShapeAndRelayState() {
  var sp = _fakeSp();
  var ar = sp.buildAuthnRequest({ relayState: "/dash&x=1" });
  check("authn: id is an underscore-prefixed token", typeof ar.id === "string" && ar.id.charAt(0) === "_");
  check("authn: redirectUrl starts at the IdP SSO URL", ar.redirectUrl.indexOf(IDP_SSO_URL) === 0);
  check("authn: redirectUrl carries SAMLRequest param", ar.redirectUrl.indexOf("SAMLRequest=") !== -1);
  check("authn: RelayState is URL-encoded",
    ar.redirectUrl.indexOf("RelayState=" + encodeURIComponent("/dash&x=1")) !== -1);
  check("authn: raw is a samlp:AuthnRequest", ar.raw.indexOf("<samlp:AuthnRequest") === 0);
}

function testAuthnRequestNameIdPolicy() {
  var without = _fakeSp().buildAuthnRequest().raw;
  check("authn: no NameIDPolicy when nameIdFormat unset", without.indexOf("NameIDPolicy") === -1);
  var withFmt = _fakeSp({ nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" })
    .buildAuthnRequest().raw;
  check("authn: NameIDPolicy present when nameIdFormat set", withFmt.indexOf("<samlp:NameIDPolicy") !== -1);
}

function testAuthnRequestQuerySeparator() {
  // When the IdP SSO URL already carries a query, the SAMLRequest param is
  // appended with & (not a second ?), so the redirect stays a valid URL.
  var sp = _fakeSp({ idpSsoUrl: IDP_SSO_URL + "?foo=1" });
  var url = sp.buildAuthnRequest().redirectUrl;
  check("authn: pre-existing query gets &SAMLRequest", url.indexOf("?foo=1&SAMLRequest=") !== -1);
}

function testAuthnRequestAttributeEscaping() {
  // A hostile ACS carrying a quote + angle brackets must be escaped inside the
  // AssertionConsumerServiceURL attribute — it cannot break out of the
  // attribute and inject unsigned markup (RFC 3741 §1.3.2).
  var sp = _fakeSp({
    entityId:                    "https://sp.example/e<vil",
    assertionConsumerServiceUrl: "https://sp.example/acs\"><evil>&",
  });
  var raw = sp.buildAuthnRequest().raw;
  check("authn: hostile ACS cannot break out of the attribute", raw.indexOf("\"><evil>") === -1);
  check("authn: quote in ACS is escaped to &quot;", raw.indexOf("&quot;") !== -1);
  check("authn: '<' in entityId Issuer text is escaped",
    raw.indexOf("e&lt;vil") !== -1 && raw.indexOf("e<vil") === -1);
}

// ---------------------------------------------------------------------------
// metadata()
// ---------------------------------------------------------------------------

function testMetadata() {
  var sp = _fakeSp();
  var meta = sp.metadata();
  check("metadata: is an EntityDescriptor", meta.indexOf("<md:EntityDescriptor") !== -1);
  check("metadata: carries the SP entityID", meta.indexOf("entityID=\"" + SP_ENTITY_ID + "\"") !== -1);
  check("metadata: advertises the ACS location", meta.indexOf(ACS_URL) !== -1);
  check("metadata: WantAssertionsSigned is true", meta.indexOf("WantAssertionsSigned=\"true\"") !== -1);
  check("metadata: no SingleLogoutService when unconfigured", meta.indexOf("SingleLogoutService") === -1);
}

function testMetadataSlo() {
  var configured = _fakeSp({ singleLogoutServiceUrl: "https://sp.example/slo" }).metadata();
  check("metadata: SLO service emitted when configured on create",
    configured.indexOf("SingleLogoutService") !== -1 && configured.indexOf("https://sp.example/slo") !== -1);
  var override = _fakeSp().metadata({ singleLogoutServiceUrl: "https://sp.example/slo2" });
  check("metadata: metaOpts singleLogoutServiceUrl override honored",
    override.indexOf("https://sp.example/slo2") !== -1);
  // Hostile SLO URL is attribute-escaped.
  var hostile = _fakeSp().metadata({ singleLogoutServiceUrl: "https://sp.example/x\"><evil>" });
  check("metadata: hostile SLO URL cannot break out of the attribute",
    hostile.indexOf("\"><evil>") === -1 && hostile.indexOf("&quot;") !== -1);
}

// ---------------------------------------------------------------------------
// verifyResponse — pre-signature input validation + XSW structural refusals
// ---------------------------------------------------------------------------

function testVerifyResponseInputValidation() {
  var sp = _fakeSp();
  check("verify: non-string SAMLResponse → no-response",
    _verifyCode(sp, 12345) === "auth-saml/no-response");
  check("verify: empty SAMLResponse → no-response",
    _verifyCode(sp, "") === "auth-saml/no-response");
  check("verify: base64 that decodes to non-XML → bad-response-decode",
    _verifyCode(sp, b64("no-angle-brackets-here")) === "auth-saml/bad-response-decode");
  check("verify: wrong root element → wrong-root",
    _verifyCode(sp, b64("<samlp:Foo " + P_NS + "/>")) === "auth-saml/wrong-root");
}

function testVerifyResponseStatus() {
  var sp = _fakeSp();
  var reqStatus = "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Requester\"/></samlp:Status>";
  check("verify: non-Success Status → bad-status",
    _verifyCode(sp, b64(_response(reqStatus))) === "auth-saml/bad-status");
  check("verify: absent Status → bad-status",
    _verifyCode(sp, b64(_response(""))) === "auth-saml/bad-status");
}

function testVerifyResponseXswStructural() {
  var sp = _fakeSp();
  check("verify: duplicate <Status> → duplicate-status (XSW)",
    _verifyCode(sp, b64(_response(STATUS_OK + STATUS_OK))) === "auth-saml/duplicate-status");
  check("verify: duplicate <StatusCode> → duplicate-status-code (XSW)",
    _verifyCode(sp, b64(_response(
      "<samlp:Status><samlp:StatusCode Value=\"" + SUCCESS + "\"/><samlp:StatusCode Value=\"x\"/></samlp:Status>"
    ))) === "auth-saml/duplicate-status-code");
  check("verify: duplicate <Assertion> → duplicate-assertion (XSW)",
    _verifyCode(sp, b64(_response(STATUS_OK + "<saml:Assertion ID=\"_a1\"/><saml:Assertion ID=\"_a2\"/>")))
      === "auth-saml/duplicate-assertion");
  check("verify: duplicate <EncryptedAssertion> → duplicate-encrypted-assertion (XSW)",
    _verifyCode(sp, b64(_response(STATUS_OK + "<saml:EncryptedAssertion/><saml:EncryptedAssertion/>")))
      === "auth-saml/duplicate-encrypted-assertion");
}

function testVerifyResponseNoAssertionAndUnsigned() {
  var sp = _fakeSp();
  check("verify: Success but no Assertion → no-assertion",
    _verifyCode(sp, b64(_response(STATUS_OK))) === "auth-saml/no-assertion");
  check("verify: single Assertion with no Signature → unsigned",
    _verifyCode(sp, b64(_response(STATUS_OK +
      "<saml:Assertion ID=\"_a1\"><saml:Issuer>" + IDP_ENTITY_ID + "</saml:Issuer></saml:Assertion>")))
      === "auth-saml/unsigned");
}

function testVerifyResponseEncryptedWithoutKey() {
  var sp = _fakeSp();
  check("verify: EncryptedAssertion without spPrivateKeyPem → encrypted-no-sp-key",
    _verifyCode(sp, b64(_response(STATUS_OK +
      "<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"/></saml:EncryptedAssertion>")))
      === "auth-saml/encrypted-no-sp-key");
}

// ---------------------------------------------------------------------------
// verifyResponse — signed-path branches (fire only after XMLDSig verify)
// ---------------------------------------------------------------------------

async function testVerifyResponseHappyPath() {
  var idp = await _mintRsaCert("idp.example");
  var sp  = _realSp(idp);
  var attrStmt =
    "<saml:AttributeStatement>" +
    "<saml:Attribute Name=\"email\"><saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute>" +
    "<saml:Attribute Name=\"roles\">" +
    "<saml:AttributeValue>admin</saml:AttributeValue><saml:AttributeValue>ops</saml:AttributeValue></saml:Attribute>" +
    "</saml:AttributeStatement>";
  var info = sp.verifyResponse(_buildSignedResponse(idp, { tag: "happy", attrStmt: attrStmt }));
  check("verify happy: nameId returned",               info.nameId === "alice@example.com");
  check("verify happy: nameIdFormat returned",
    info.nameIdFormat === "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
  check("verify happy: sessionIndex from AuthnStatement", info.sessionIndex === "_sess-1");
  check("verify happy: issuer echoed",                 info.issuer === IDP_ENTITY_ID);
  check("verify happy: single-valued attribute is a scalar", info.attributes.email === "alice@example.com");
  check("verify happy: multi-valued attribute is an array",
    Array.isArray(info.attributes.roles) && info.attributes.roles.join(",") === "admin,ops");
  check("verify happy: audience defaults to entityId", info.audience === SP_ENTITY_ID);
}

async function testVerifyResponseInResponseTo() {
  var idp = await _mintRsaCert("idp.example");
  var sp  = _realSp(idp);
  var rt  = "_req-abc";
  var okB64 = _buildSignedResponse(idp, { tag: "irt-ok", inResponseTo: rt });
  var info = sp.verifyResponse(okB64, { expectedInResponseTo: rt });
  check("verify: matching InResponseTo is captured", info.inResponseTo === rt);
  var mismatchCode = _verifyCode(sp,
    _buildSignedResponse(idp, { tag: "irt-bad", inResponseTo: "_other" }),
    { expectedInResponseTo: rt });
  check("verify: InResponseTo mismatch → bad-in-response-to (replay defense)",
    mismatchCode === "auth-saml/bad-in-response-to");
}

async function testVerifyResponseWrongIssuer() {
  var idp = await _mintRsaCert("idp.example");
  var sp  = _realSp(idp);
  check("verify: Issuer != configured idpEntityId → wrong-issuer",
    _verifyCode(sp, _buildSignedResponse(idp, { tag: "wi", issuer: "https://evil.example" }))
      === "auth-saml/wrong-issuer");
}

async function testVerifyResponseAudience() {
  var idp = await _mintRsaCert("idp.example");
  var sp  = _realSp(idp);
  var noRestriction = "<saml:Conditions NotBefore=\"" + iso(-5 * 60 * 1000) +               // allow:raw-time-literal — 5m skew window
    "\" NotOnOrAfter=\"" + iso(5 * 60 * 1000) + "\"></saml:Conditions>";                    // allow:raw-time-literal — 5m skew window
  check("verify: no AudienceRestriction → no-audience-restriction (audience-confusion defense)",
    _verifyCode(sp, _buildSignedResponse(idp, { tag: "na", conditions: noRestriction }))
      === "auth-saml/no-audience-restriction");
  check("verify: AudienceRestriction for a different SP → wrong-audience",
    _verifyCode(sp, _buildSignedResponse(idp, { tag: "wa", audience: "https://other.example" }))
      === "auth-saml/wrong-audience");

  // requireAudienceRestriction:false opts out of the binding requirement.
  var info = sp.verifyResponse(
    _buildSignedResponse(idp, { tag: "opt", conditions: noRestriction }),
    { requireAudienceRestriction: false });
  check("verify: requireAudienceRestriction:false accepts a missing binding", info.nameId === "alice@example.com");
}

async function testVerifyResponseConditionsExpired() {
  var idp = await _mintRsaCert("idp.example");
  var sp  = _realSp(idp);
  var expired = "<saml:Conditions NotOnOrAfter=\"" + iso(-60 * 60 * 1000) + "\">" +          // allow:raw-time-literal — 1h in the past
    "<saml:AudienceRestriction><saml:Audience>" + SP_ENTITY_ID +
    "</saml:Audience></saml:AudienceRestriction></saml:Conditions>";
  check("verify: expired Conditions/NotOnOrAfter → conditions-expired",
    _verifyCode(sp, _buildSignedResponse(idp, { tag: "ce", conditions: expired }))
      === "auth-saml/conditions-expired");
  var future = "<saml:Conditions NotBefore=\"" + iso(60 * 60 * 1000) + "\">" +               // allow:raw-time-literal — 1h in the future
    "<saml:AudienceRestriction><saml:Audience>" + SP_ENTITY_ID +
    "</saml:Audience></saml:AudienceRestriction></saml:Conditions>";
  check("verify: future Conditions/NotBefore → conditions-not-yet-valid",
    _verifyCode(sp, _buildSignedResponse(idp, { tag: "cf", conditions: future }))
      === "auth-saml/conditions-not-yet-valid");
}

async function testVerifyResponseDuplicateSubjectXsw() {
  var idp = await _mintRsaCert("idp.example");
  var sp  = _realSp(idp);
  var twoSubjects =
    "<saml:Subject>" +
    "<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">alice@example.com</saml:NameID>" +
    "<saml:SubjectConfirmation Method=\"" + BEARER + "\">" +
    "<saml:SubjectConfirmationData NotOnOrAfter=\"" + iso(5 * 60 * 1000) +                   // allow:raw-time-literal — 5m window
    "\" Recipient=\"" + ACS_URL + "\"/></saml:SubjectConfirmation></saml:Subject>" +
    "<saml:Subject><saml:NameID>attacker@evil.example</saml:NameID></saml:Subject>";
  check("verify: duplicate <Subject> in a signed Assertion → duplicate-subject (XSW)",
    _verifyCode(sp, _buildSignedResponse(idp, { tag: "ds", subjectXml: twoSubjects }))
      === "auth-saml/duplicate-subject");
}

async function testVerifyResponseTamperedDigest() {
  // A validly-signed assertion whose signed bytes are then mutated must be
  // refused: the recomputed digest no longer matches the signed DigestValue.
  var idp = await _mintRsaCert("idp.example");
  var sp  = _realSp(idp);
  var goodB64 = _buildSignedResponse(idp, { tag: "tamper", nameId: "alice@example.com" });
  var xml = Buffer.from(goodB64, "base64").toString("utf8").replace("alice@example.com", "mallory@evil.example");
  var code = _verifyCode(sp, b64(xml));
  check("verify: tampering signed content → digest-mismatch",
    code === "auth-saml/digest-mismatch");
}

// ---------------------------------------------------------------------------
// SLO — HTTP-Redirect build/parse validation
// ---------------------------------------------------------------------------

function testLogoutRequestValidation() {
  var sp = _fakeSp();
  check("buildLogoutRequest: missing nameId → no-nameid",
    _codeOf(function () { sp.buildLogoutRequest({ sessionIndex: "_s" }); }) === "auth-saml/no-nameid");
  check("buildLogoutRequest: non-object opts → bad-opts",
    _codeOf(function () { sp.buildLogoutRequest("nope"); }) === "auth-saml/bad-opts");
  var unknownCode = _codeOf(function () { sp.buildLogoutRequest({ nameId: "a", bogus: 1 }); });
  check("buildLogoutRequest: unknown opt is refused", /unknown option/.test(unknownCode));
}

function testLogoutResponseValidation() {
  var sp = _fakeSp();
  check("buildLogoutResponse: missing inResponseTo → no-in-response-to",
    _codeOf(function () { sp.buildLogoutResponse({ destination: IDP_SLO_URL }); }) === "auth-saml/no-in-response-to");
  check("buildLogoutResponse: missing destination → no-destination",
    _codeOf(function () { sp.buildLogoutResponse({ inResponseTo: "_x" }); }) === "auth-saml/no-destination");
}

function testParseLogoutRequestValidation() {
  var sp = _fakeSp();
  check("parseLogoutRequest: non-string input → no-saml-request",
    _codeOf(function () { sp.parseLogoutRequest(123); }) === "auth-saml/no-saml-request");
  check("parseLogoutRequest: undeflatable base64 → bad-saml-request",
    _codeOf(function () { sp.parseLogoutRequest(b64("this is not deflate-raw data")); }) === "auth-saml/bad-saml-request");
}

function testLogoutResponseRoundTrip() {
  var sp = _fakeSp();
  // buildLogoutResponse produces the redirect; extract + parse the SAMLResponse.
  var built = sp.buildLogoutResponse({ inResponseTo: "_orig-1", destination: IDP_SLO_URL });
  var samlResp = decodeURIComponent(built.redirectUrl.split("?")[1].split("&")[0].slice("SAMLResponse=".length));
  var parsed = sp.parseLogoutResponse(samlResp, { expectedInResponseTo: "_orig-1" });
  check("parseLogoutResponse: default status → success true", parsed.success === true);
  check("parseLogoutResponse: InResponseTo round-trips", parsed.inResponseTo === "_orig-1");
  check("parseLogoutResponse: issuer is the SP entityId", parsed.issuer === SP_ENTITY_ID);

  check("parseLogoutResponse: non-string input → no-saml-response",
    _codeOf(function () { sp.parseLogoutResponse(null); }) === "auth-saml/no-saml-response");
  check("parseLogoutResponse: expectedInResponseTo mismatch → inresponseto-mismatch",
    _codeOf(function () { sp.parseLogoutResponse(samlResp, { expectedInResponseTo: "_different" }); })
      === "auth-saml/inresponseto-mismatch");

  // A non-Success statusCode surfaces success=false.
  var failBuilt = sp.buildLogoutResponse({
    inResponseTo: "_orig-2", destination: IDP_SLO_URL,
    statusCode: "urn:oasis:names:tc:SAML:2.0:status:Requester",
  });
  var failResp = decodeURIComponent(failBuilt.redirectUrl.split("?")[1].split("&")[0].slice("SAMLResponse=".length));
  check("parseLogoutResponse: non-Success statusCode → success false",
    sp.parseLogoutResponse(failResp).success === false);
}

// ---------------------------------------------------------------------------
// SLO — HTTP-POST + SOAP bindings (embedded XMLDSig)
// ---------------------------------------------------------------------------

function testLogoutRequestPostRoundTrip() {
  var sp = _fakeSp();
  var kp = pq.ml_dsa_65.keygen();
  var post = sp.buildLogoutRequestPost({
    nameId: "alice@idp", sessionIndex: "_s-9", signingKey: kp.secretKey, signingAlg: "ml-dsa-65",
  });
  check("buildLogoutRequestPost: action is the IdP SLO URL", post.action === IDP_SLO_URL);
  check("buildLogoutRequestPost: formHtml auto-submits SAMLRequest",
    post.formHtml.indexOf("name=\"SAMLRequest\"") !== -1 && post.formHtml.indexOf("document.forms[0].submit()") !== -1);
  var parsed = sp.parseLogoutRequestPost(post.samlRequest, {
    idpVerifyKey: kp.publicKey, idpVerifyAlg: "ml-dsa-65",
  });
  check("POST SLO round-trip: nameId recovered", parsed.nameId === "alice@idp");
  check("POST SLO round-trip: sessionIndex recovered", parsed.sessionIndex === "_s-9");
  check("POST SLO round-trip: id recovered", parsed.id === post.id);

  // Negative control — a different verify key refuses (the embedded XMLDSig
  // gate is live), proving the round-trip pass above is a real verification.
  check("POST SLO: wrong verify key → bad-signature",
    _codeOf(function () {
      sp.parseLogoutRequestPost(post.samlRequest, {
        idpVerifyKey: pq.ml_dsa_65.keygen().publicKey, idpVerifyAlg: "ml-dsa-65",
      });
    }) === "auth-saml/bad-signature");
}

function testParseLogoutRequestPostValidation() {
  var sp = _fakeSp();
  check("parseLogoutRequestPost: non-string input → bad-input",
    _codeOf(function () { sp.parseLogoutRequestPost(42); }) === "auth-saml/bad-input");
  check("parseLogoutRequestPost: wrong root element → wrong-root",
    _codeOf(function () { sp.parseLogoutRequestPost(b64("<samlp:Foo " + P_NS + "/>")); }) === "auth-saml/wrong-root");
}

function testLogoutRequestSoapShape() {
  var sp = _fakeSp();
  var soap = sp.buildLogoutRequestSoap({ nameId: "a@idp" });
  check("buildLogoutRequestSoap: action is the IdP SLO URL", soap.action === IDP_SLO_URL);
  check("buildLogoutRequestSoap: body is a SOAP envelope wrapping the LogoutRequest",
    soap.body.indexOf("soapenv:Envelope") !== -1 &&
    soap.body.indexOf("soapenv:Body") !== -1 &&
    soap.body.indexOf("<samlp:LogoutRequest") !== -1);
}

function testParseLogoutResponseSoap() {
  var sp = _fakeSp();
  // Build a LogoutResponse XML (via buildLogoutResponse.raw) and wrap it in a
  // SOAP envelope, then drive the public parse path.
  var lr = sp.buildLogoutResponse({ inResponseTo: "_orig-soap", destination: IDP_SLO_URL });
  var envelope = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
    "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">" +
    "<soapenv:Body>" + lr.raw + "</soapenv:Body></soapenv:Envelope>";
  var parsed = sp.parseLogoutResponseSoap(envelope);
  check("parseLogoutResponseSoap: unwraps Body + reports success", parsed.success === true);
  check("parseLogoutResponseSoap: InResponseTo recovered", parsed.inResponseTo === "_orig-soap");

  check("parseLogoutResponseSoap: non-string input → bad-input",
    _codeOf(function () { sp.parseLogoutResponseSoap(0); }) === "auth-saml/bad-input");
  check("parseLogoutResponseSoap: non-Envelope root → bad-soap",
    _codeOf(function () { sp.parseLogoutResponseSoap("<foo/>"); }) === "auth-saml/bad-soap");
  check("parseLogoutResponseSoap: empty Body → bad-soap",
    _codeOf(function () {
      sp.parseLogoutResponseSoap("<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">" +
        "<soapenv:Body></soapenv:Body></soapenv:Envelope>");
    }) === "auth-saml/bad-soap");
}

// ---------------------------------------------------------------------------
// fetchMdq — synchronous input validation (throws before any network I/O)
// ---------------------------------------------------------------------------

async function testFetchMdqInputValidation() {
  async function mdqCode(o) {
    try { await b.auth.saml.fetchMdq(o); return "NO-THROW"; }
    catch (e) { return e.code || e.message; }
  }
  check("fetchMdq: non-object opts refused", (await mdqCode(null)) === "BAD_OPT");
  check("fetchMdq: missing baseUrl → no-mdq-base", (await mdqCode({ entityId: IDP_ENTITY_ID })) === "auth-saml/no-mdq-base");
  check("fetchMdq: missing entityId → no-mdq-entity", (await mdqCode({ baseUrl: "https://mdq.example" })) === "auth-saml/no-mdq-entity");
}

async function run() {
  // create()
  testCreateRequiredFields();
  testCreateRejectsBadOpts();
  // buildAuthnRequest
  testAuthnRequestShapeAndRelayState();
  testAuthnRequestNameIdPolicy();
  testAuthnRequestQuerySeparator();
  testAuthnRequestAttributeEscaping();
  // metadata
  testMetadata();
  testMetadataSlo();
  // verifyResponse — pre-signature
  testVerifyResponseInputValidation();
  testVerifyResponseStatus();
  testVerifyResponseXswStructural();
  testVerifyResponseNoAssertionAndUnsigned();
  testVerifyResponseEncryptedWithoutKey();
  // verifyResponse — signed path
  await testVerifyResponseHappyPath();
  await testVerifyResponseInResponseTo();
  await testVerifyResponseWrongIssuer();
  await testVerifyResponseAudience();
  await testVerifyResponseConditionsExpired();
  await testVerifyResponseDuplicateSubjectXsw();
  await testVerifyResponseTamperedDigest();
  // SLO redirect
  testLogoutRequestValidation();
  testLogoutResponseValidation();
  testParseLogoutRequestValidation();
  testLogoutResponseRoundTrip();
  // SLO POST / SOAP
  testLogoutRequestPostRoundTrip();
  testParseLogoutRequestPostValidation();
  testLogoutRequestSoapShape();
  testParseLogoutResponseSoap();
  // fetchMdq
  await testFetchMdqInputValidation();
}

if (require.main === module) {
  run().then(function () {
    console.log("OK — " + helpers.getChecks() + " checks passed");
    process.exit(0);
  }).catch(function (e) { console.error(e && e.stack || e); process.exit(1); });
}
module.exports = { run: run };
