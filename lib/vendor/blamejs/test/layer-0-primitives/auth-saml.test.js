// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.saml.sp — validation, adversarial, and error-branch suite for the
 * SAML 2.0 SP primitive.
 *
 * The sibling SAML suites cover the SubjectConfirmation NotBefore /
 * NotOnOrAfter fail-closed windows, the SLO HTTP-Redirect signing round-trip,
 * and the MDQ signature-wrapping defense. This file exercises the remaining
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
 * It also drives the deeper adversarial surface: the _verifyXmldsig and
 * embedded-XMLDSig structural refusals, Response-level signatures and the
 * signed-different-element wrapping guard, the Bearer and holder-of-key
 * SubjectConfirmation fail-closed paths, EncryptedAssertion decryption
 * (RSA-OAEP + AES-256-GCM plus the ML-KEM-1024 / XChaCha20-Poly1305 paths),
 * the SLO classical + Ed25519 signing round trips, and the fetchMdq
 * transport / verification branches.
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
var zlib       = require("node:zlib");
var c14n       = require("../../lib/xml-c14n");
var pq         = require("../../lib/pqc-software");

var C = b.constants;

var DS  = "http://www.w3.org/2000/09/xmldsig#";
var EXC = "http://www.w3.org/2001/10/xml-exc-c14n#";
var SAML_A = "urn:oasis:names:tc:SAML:2.0:assertion";
var SAML_P = "urn:oasis:names:tc:SAML:2.0:protocol";
var XENC = "http://www.w3.org/2001/04/xmlenc#";

var IDP_ENTITY_ID = "https://idp.example";
var SP_ENTITY_ID  = "https://sp.example";
var ACS_URL       = "https://sp.example/saml/acs";
var IDP_SSO_URL   = "https://idp.example/sso";
var IDP_SLO_URL   = "https://idp.example/slo";
var FAKE_CERT     = "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----";

var BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
var SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
var HOK     = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";
var EMAIL   = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
var RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
var ENVELOPED  = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
var MLDSA65_URN = "urn:blamejs:experimental:saml-sig-alg:ml-dsa-65";
var SHA3_512    = "http://www.w3.org/2007/05/xmldsig-more#sha3-512";
var XCHACHA_URN = "urn:blamejs:experimental:xmlenc:xchacha20-poly1305";

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

// ---------------------------------------------------------------------------
// Signed-fixture builders for the deeper adversarial surface below: each
// assertion body is assembled ONCE with a signature placeholder, so the
// signed bytes and the verified bytes are identical; the IdP signature +
// digest + SignedInfo are computed through the framework's own b.xmlC14n so
// verifyResponse's recomputation matches with no test bypass of the crypto
// gate.
// ---------------------------------------------------------------------------

function _certBody(pem) {
  return pem.replace(/-----BEGIN CERTIFICATE-----/, "").replace(/-----END CERTIFICATE-----/, "").replace(/\s+/g, "");
}

// Mint a self-signed cert via the vendored @peculiar/x509 bundle — the same
// shape the sibling SAML suites use. verifyResponse parses idpCertPem with
// nodeCrypto.createPublicKey and verifies the assertion signature against it.
async function _mint(cn, alg) {
  var pki  = require("../../lib/vendor/pki.cjs");
  var x509 = pki.x509;
  var genAlg = alg === "ec"
    ? { name: "ECDSA", namedCurve: "P-256" }
    : { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048,                                          // allow:raw-byte-literal — RFC 8301 §3.1 RSA bit floor
        publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };
  var keys = await nodeCrypto.webcrypto.subtle.generateKey(genAlg, true, ["sign", "verify"]);
  var now = new Date();
  var cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber:     "01",
    name:             "CN=" + cn,
    notBefore:        now,
    notAfter:         new Date(now.getTime() + C.TIME.days(365)),
    signingAlgorithm: alg === "ec" ? { name: "ECDSA", hash: "SHA-256" } : { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    keys:             keys,
  });
  var pkcs8 = await nodeCrypto.webcrypto.subtle.exportKey("pkcs8", keys.privateKey);
  var keyPem = "-----BEGIN PRIVATE KEY-----\n" +
    Buffer.from(pkcs8).toString("base64").match(/.{1,64}/g).join("\n") +
    "\n-----END PRIVATE KEY-----\n";
  return { certPem: cert.toString("pem"), keyPem: keyPem };
}

function _mkSp(certPem, extra) {
  var opts = {
    entityId:                    SP_ENTITY_ID,
    assertionConsumerServiceUrl: ACS_URL,
    idpEntityId:                 IDP_ENTITY_ID,
    idpSsoUrl:                   IDP_SSO_URL,
    idpSloUrl:                   IDP_SLO_URL,
    idpCertPem:                  certPem,
  };
  if (extra) { for (var k in extra) { opts[k] = extra[k]; } }
  return b.auth.saml.sp.create(opts);
}

// Build a <ds:Signature> that VERIFIES: digest over the canonicalized target,
// SignatureValue over the canonicalized SignedInfo, both through b.xmlC14n.
function _validSig(keyPem, refId, target, o) {
  o = o || {};
  var wc = !!o.withComments;
  var canonUri = wc ? (EXC + "WithComments") : EXC;
  var refTransform = wc ? (EXC + "WithComments") : EXC;
  var sm = o.sigMethod || RSA_SHA256;
  var hn = o.hashName || "sha256";
  var du = o.digestUri || "http://www.w3.org/2001/04/xmlenc#sha256";
  var dh = o.digestHash || "sha256";
  var dg = nodeCrypto.createHash(dh).update(c14n.canonicalize(target, { withComments: wc })).digest("base64");
  var si = "<ds:SignedInfo xmlns:ds=\"" + DS + "\">" +
    "<ds:CanonicalizationMethod Algorithm=\"" + canonUri + "\"></ds:CanonicalizationMethod>" +
    "<ds:SignatureMethod Algorithm=\"" + sm + "\"></ds:SignatureMethod>" +
    "<ds:Reference URI=\"#" + refId + "\">" +
    "<ds:Transforms>" +
    "<ds:Transform Algorithm=\"" + ENVELOPED + "\"></ds:Transform>" +
    "<ds:Transform Algorithm=\"" + refTransform + "\"></ds:Transform>" +
    "</ds:Transforms>" +
    "<ds:DigestMethod Algorithm=\"" + du + "\"></ds:DigestMethod>" +
    "<ds:DigestValue>" + dg + "</ds:DigestValue>" +
    "</ds:Reference></ds:SignedInfo>";
  var priv = nodeCrypto.createPrivateKey({ key: keyPem, format: "pem" });
  var so = { key: priv };
  if (o.ec) so.dsaEncoding = "der"; else so.padding = nodeCrypto.constants.RSA_PKCS1_PADDING;
  var sv = nodeCrypto.sign(hn, c14n.canonicalize(si, { withComments: wc }), so).toString("base64");
  return "<ds:Signature xmlns:ds=\"" + DS + "\">" + si + "<ds:SignatureValue>" + sv + "</ds:SignatureValue></ds:Signature>";
}

// A structurally-valid-until-the-target-defect <ds:Signature>, used for the
// _verifyXmldsig refusals that fire BEFORE the digest/signature is checked.
function _craftSig(o) {
  o = o || {};
  if (o.noSignedInfo) return "<ds:Signature xmlns:ds=\"" + DS + "\"><ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>";
  var canon = o.canon !== undefined ? o.canon : EXC;
  var parts = "<ds:CanonicalizationMethod Algorithm=\"" + canon + "\"></ds:CanonicalizationMethod>";
  if (!o.omitSigMethod) parts += "<ds:SignatureMethod Algorithm=\"" + (o.sigMethod || RSA_SHA256) + "\"></ds:SignatureMethod>";
  if (!o.omitReference) {
    var refUri = o.refUri !== undefined ? o.refUri : ("#" + o.refId);
    var refInner = "";
    if (o.transforms !== undefined) refInner += o.transforms;
    if (!o.omitDigestMethod) refInner += "<ds:DigestMethod Algorithm=\"" + (o.digestMethod || "http://www.w3.org/2001/04/xmlenc#sha256") + "\"></ds:DigestMethod>";
    var dv = o.digestValue !== undefined ? o.digestValue : "AA==";
    refInner += "<ds:DigestValue>" + dv + "</ds:DigestValue>";
    parts += "<ds:Reference URI=\"" + refUri + "\">" + refInner + "</ds:Reference>";
  }
  return "<ds:Signature xmlns:ds=\"" + DS + "\"><ds:SignedInfo xmlns:ds=\"" + DS + "\">" + parts +
    "</ds:SignedInfo><ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>";
}

function _defSubject() {
  return "<saml:Subject><saml:NameID Format=\"" + EMAIL + "\">alice@example.com</saml:NameID>" +
    "<saml:SubjectConfirmation Method=\"" + BEARER + "\">" +
    "<saml:SubjectConfirmationData NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\" Recipient=\"" + ACS_URL + "\"/>" +
    "</saml:SubjectConfirmation></saml:Subject>";
}
function _defCond() {
  return "<saml:Conditions NotBefore=\"" + iso(-C.TIME.minutes(5)) + "\" NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\">" +
    "<saml:AudienceRestriction><saml:Audience>" + SP_ENTITY_ID + "</saml:Audience></saml:AudienceRestriction></saml:Conditions>";
}
function _defAuthn(ii) {
  return "<saml:AuthnStatement SessionIndex=\"_sess-1\" AuthnInstant=\"" + ii + "\">" +
    "<saml:AuthnContext><saml:AuthnContextClassRef>" +
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" +
    "</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>";
}

// Build a signed Assertion. inner is assembled ONCE with a SIG placeholder so
// the bytes signed == the bytes verified. Overrides let each test shape the
// subject / conditions / signature.
function _buildAssertion(idp, o) {
  o = o || {};
  var ii = iso(0);
  var aid = o.assertionId || ("_assertion-" + (o.tag || "t"));
  var issuer = o.issuer !== undefined ? o.issuer : IDP_ENTITY_ID;
  var issuerXml = issuer === null ? "" : ("<saml:Issuer>" + issuer + "</saml:Issuer>");
  var subjectXml = o.subjectXml !== undefined ? o.subjectXml : _defSubject();
  var conditions = o.conditions !== undefined ? o.conditions : _defCond();
  var authnStmt = o.authnStmt !== undefined ? o.authnStmt : _defAuthn(ii);
  var attrStmt = o.attrStmt || "";
  var decoy = o.decoy || "";
  var open = "<saml:Assertion xmlns:saml=\"" + SAML_A + "\" ID=\"" + aid + "\" Version=\"2.0\" IssueInstant=\"" + ii + "\">";
  var close = "</saml:Assertion>";
  var inner = issuerXml + "SIGPH" + subjectXml + conditions + authnStmt + attrStmt + decoy;
  var noSig = open + inner.replace("SIGPH", "") + close;
  var sigXml;
  if (o.signatureXml !== undefined) {
    sigXml = o.signatureXml;
  } else {
    var refId = o.refId || aid;
    var digestTarget = o.digestTarget !== undefined ? o.digestTarget : noSig;
    sigXml = _validSig((o.signKeyPem || idp.keyPem), refId, digestTarget, o.sigOpts);
  }
  return { full: open + inner.replace("SIGPH", sigXml) + close, assertionId: aid };
}

function _mkAssertionResponse(idp, o) {
  o = o || {};
  var a = _buildAssertion(idp, o);
  var rid = "_response-" + (o.tag || "t");
  var xml = "<samlp:Response xmlns:samlp=\"" + SAML_P + "\" xmlns:saml=\"" + SAML_A + "\" ID=\"" + rid +
    "\" Version=\"2.0\" IssueInstant=\"" + iso(0) + "\" Destination=\"" + ACS_URL + "\">" +
    "<saml:Issuer>" + IDP_ENTITY_ID + "</saml:Issuer>" + STATUS_OK + a.full + "</samlp:Response>";
  return { xml: xml, b64: b64(xml), assertionId: a.assertionId, responseId: rid };
}

// Response-level signature (Assertion carries no Signature of its own).
function _mkResponseLevel(idp, o) {
  o = o || {};
  var ii = iso(0);
  var rid = "_response-" + (o.tag || "rl");
  var aid = "_assertion-" + (o.tag || "rl");
  var assertion = "<saml:Assertion xmlns:saml=\"" + SAML_A + "\" ID=\"" + aid + "\" Version=\"2.0\" IssueInstant=\"" + ii + "\">" +
    "<saml:Issuer>" + IDP_ENTITY_ID + "</saml:Issuer>" + _defSubject() + _defCond() + _defAuthn(ii) + "</saml:Assertion>";
  var decoy = o.decoy || "";
  var open = "<samlp:Response xmlns:samlp=\"" + SAML_P + "\" xmlns:saml=\"" + SAML_A + "\" ID=\"" + rid +
    "\" Version=\"2.0\" IssueInstant=\"" + ii + "\" Destination=\"" + ACS_URL + "\">";
  var close = "</samlp:Response>";
  var inner = "<saml:Issuer>" + IDP_ENTITY_ID + "</saml:Issuer>" + "RSIGPH" + STATUS_OK + assertion + decoy;
  var noSig = open + inner.replace("RSIGPH", "") + close;
  var refId = o.refId || rid;
  var digestTarget = o.digestTarget !== undefined ? o.digestTarget : noSig;
  var sig = _validSig(idp.keyPem, refId, digestTarget, o.sigOpts);
  var full = open + inner.replace("RSIGPH", sig) + close;
  return { b64: b64(full), responseId: rid, assertionId: aid };
}

// ---------------------------------------------------------------------------
// _verifyXmldsig — structural refusals via a hostile assertion Signature
// ---------------------------------------------------------------------------

function testVerifyXmldsigStructural(idp) {
  var sp = _mkSp(idp.certPem);
  function code(sigXml, extra) {
    var o = { tag: "vx", signatureXml: sigXml };
    if (extra) { for (var k in extra) o[k] = extra[k]; }
    return _verifyCode(sp, _mkAssertionResponse(idp, o).b64);
  }
  var aid = "_assertion-vx";
  var goodTransforms = "<ds:Transforms><ds:Transform Algorithm=\"" + ENVELOPED + "\"></ds:Transform>" +
    "<ds:Transform Algorithm=\"" + EXC + "\"></ds:Transform></ds:Transforms>";

  check("vxmldsig: Signature without SignedInfo -> no-signed-info",
    code(_craftSig({ noSignedInfo: true })) === "auth-saml/no-signed-info");
  check("vxmldsig: unsupported CanonicalizationMethod -> unsupported-c14n",
    code(_craftSig({ canon: "http://example/bogus-c14n", refId: aid })) === "auth-saml/unsupported-c14n");
  check("vxmldsig: unsupported SignatureMethod -> unsupported-sig-alg",
    code(_craftSig({ sigMethod: "http://example/bogus-sig", refId: aid })) === "auth-saml/unsupported-sig-alg");
  check("vxmldsig: SignedInfo without Reference -> no-reference",
    code(_craftSig({ omitReference: true })) === "auth-saml/no-reference");
  check("vxmldsig: non-fragment Reference URI -> external-reference",
    code(_craftSig({ refUri: "https://evil.example/x" })) === "auth-saml/external-reference");
  check("vxmldsig: unsupported DigestMethod -> unsupported-digest",
    code(_craftSig({ refId: aid, digestMethod: "http://example/bogus-digest" })) === "auth-saml/unsupported-digest");
  check("vxmldsig: empty DigestValue -> no-digest-value",
    code(_craftSig({ refId: aid, digestValue: "" })) === "auth-saml/no-digest-value");
  check("vxmldsig: unsupported Transform -> unsupported-transform",
    code(_craftSig({ refId: aid, transforms: "<ds:Transforms><ds:Transform Algorithm=\"http://example/bogus-xform\"></ds:Transform></ds:Transforms>" }))
      === "auth-saml/unsupported-transform");
  check("vxmldsig: Reference URI matching no element -> no-id-match",
    code(_craftSig({ refUri: "#does-not-exist", transforms: goodTransforms })) === "auth-saml/no-id-match");
  check("vxmldsig: Reference URI matching two elements -> duplicate-id (anti-wrapping)",
    code(_craftSig({ refId: "dupid", transforms: goodTransforms }),
      { assertionId: "dupid", decoy: "<saml:Advice xmlns:saml=\"" + SAML_A + "\" ID=\"dupid\">x</saml:Advice>" })
      === "auth-saml/duplicate-id");
}

function testVerifyXmldsigNoSignatureValue(idp) {
  var sp = _mkSp(idp.certPem);
  var good = _mkAssertionResponse(idp, { tag: "nsv" }).b64;
  var xml = Buffer.from(good, "base64").toString("utf8")
    .replace(/<ds:SignatureValue>[^<]*<\/ds:SignatureValue>/, "<ds:SignatureValue></ds:SignatureValue>");
  check("vxmldsig: empty SignatureValue (valid digest) -> no-signature-value",
    _verifyCode(sp, b64(xml)) === "auth-saml/no-signature-value");
}

function testVerifyXmldsigBadSignature(idp, otherIdp) {
  // Valid digest but SignedInfo signed by a DIFFERENT key -> bad-signature.
  var sp = _mkSp(idp.certPem);
  var resp = _mkAssertionResponse(idp, { tag: "bs", signKeyPem: otherIdp.keyPem }).b64;
  check("vxmldsig: SignedInfo signed by wrong key -> bad-signature",
    _verifyCode(sp, resp) === "auth-saml/bad-signature");
}

async function testVerifyXmldsigEcdsa() {
  var ec = await _mint("ec-idp.example", "ec");
  var sp = _mkSp(ec.certPem);
  var info = _mkAssertionResponse(ec, {
    tag: "ec",
    sigOpts: { sigMethod: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", hashName: "sha256", ec: true },
  });
  check("vxmldsig: ECDSA-SHA256 assertion signature verifies (dsaEncoding der path)",
    sp.verifyResponse(info.b64).nameId === "alice@example.com");
}

function testVerifyXmldsigWithComments(idp) {
  var sp = _mkSp(idp.certPem);
  var info = _mkAssertionResponse(idp, { tag: "wc", sigOpts: { withComments: true } });
  check("vxmldsig: exclusive-c14n WithComments assertion signature verifies",
    sp.verifyResponse(info.b64).nameId === "alice@example.com");
}

// ---------------------------------------------------------------------------
// verifyResponse — Response-level signature + signed-different-element
// ---------------------------------------------------------------------------

function testResponseLevelSignature(idp) {
  var sp = _mkSp(idp.certPem);
  var ok = _mkResponseLevel(idp, { tag: "rl-ok" });
  check("verify: Response-level signature verifies (assertion unsigned)",
    sp.verifyResponse(ok.b64).nameId === "alice@example.com");

  var decoy = "<saml:Advice xmlns:saml=\"" + SAML_A + "\" ID=\"_rdecoy\">x</saml:Advice>";
  var wrapped = _mkResponseLevel(idp, { tag: "rl-w", decoy: decoy, refId: "_rdecoy", digestTarget: decoy });
  check("verify: Response signature over a different element -> signed-different-element",
    _verifyCode(sp, wrapped.b64) === "auth-saml/signed-different-element");
}

function testAssertionSignedDifferentElement(idp) {
  var sp = _mkSp(idp.certPem);
  var decoy = "<saml:Advice xmlns:saml=\"" + SAML_A + "\" ID=\"_decoyA\">payload</saml:Advice>";
  var resp = _mkAssertionResponse(idp, { tag: "sde", decoy: decoy, refId: "_decoyA", digestTarget: decoy });
  check("verify: Assertion signature over a different element -> signed-different-element",
    _verifyCode(sp, resp.b64) === "auth-saml/signed-different-element");
}

// ---------------------------------------------------------------------------
// verifyResponse — Bearer SubjectConfirmation fail-closed skips
// ---------------------------------------------------------------------------

function _bearerSubject(scd, method) {
  return "<saml:Subject><saml:NameID Format=\"" + EMAIL + "\">alice@example.com</saml:NameID>" +
    "<saml:SubjectConfirmation Method=\"" + (method || BEARER) + "\">" + scd + "</saml:SubjectConfirmation></saml:Subject>";
}

function testNoValidConfirmation(idp) {
  var sp = _mkSp(idp.certPem);
  function code(subjectXml) {
    return _verifyCode(sp, _mkAssertionResponse(idp, { tag: "nvc" + (testNoValidConfirmation._n = (testNoValidConfirmation._n || 0) + 1), subjectXml: subjectXml }).b64);
  }
  var expect = "auth-saml/no-valid-confirmation";
  check("verify: Bearer Recipient mismatch -> no-valid-confirmation",
    code(_bearerSubject("<saml:SubjectConfirmationData NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\" Recipient=\"https://evil.example\"/>")) === expect);
  check("verify: Bearer without SubjectConfirmationData -> no-valid-confirmation",
    code(_bearerSubject("")) === expect);
  check("verify: Bearer without NotOnOrAfter -> no-valid-confirmation",
    code(_bearerSubject("<saml:SubjectConfirmationData Recipient=\"" + ACS_URL + "\"/>")) === expect);
  check("verify: Bearer expired NotOnOrAfter -> no-valid-confirmation",
    code(_bearerSubject("<saml:SubjectConfirmationData NotOnOrAfter=\"" + iso(-C.TIME.hours(1)) + "\" Recipient=\"" + ACS_URL + "\"/>")) === expect);
  check("verify: Bearer unparseable NotOnOrAfter -> no-valid-confirmation",
    code(_bearerSubject("<saml:SubjectConfirmationData NotOnOrAfter=\"not-a-date\" Recipient=\"" + ACS_URL + "\"/>")) === expect);
  check("verify: Bearer NotBefore in the future -> no-valid-confirmation",
    code(_bearerSubject("<saml:SubjectConfirmationData NotBefore=\"" + iso(C.TIME.hours(1)) + "\" NotOnOrAfter=\"" + iso(C.TIME.hours(2)) + "\" Recipient=\"" + ACS_URL + "\"/>")) === expect);
  check("verify: Bearer unparseable NotBefore -> no-valid-confirmation",
    code(_bearerSubject("<saml:SubjectConfirmationData NotBefore=\"not-a-date\" NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\" Recipient=\"" + ACS_URL + "\"/>")) === expect);
  check("verify: non-Bearer/non-HoK Method -> no-valid-confirmation",
    code(_bearerSubject("<saml:SubjectConfirmationData NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\" Recipient=\"" + ACS_URL + "\"/>",
      "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches")) === expect);
}

// ---------------------------------------------------------------------------
// verifyResponse — holder-of-key possession proof
// ---------------------------------------------------------------------------

function _hokScd(certB64, attrs) {
  var a = attrs !== undefined ? attrs : (" NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\" Recipient=\"" + ACS_URL + "\"");
  var keyInfo = certB64 === null ? "" :
    "<ds:KeyInfo xmlns:ds=\"" + DS + "\"><ds:X509Data><ds:X509Certificate>" + certB64 + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>";
  return "<saml:SubjectConfirmationData" + a + ">" + keyInfo + "</saml:SubjectConfirmationData>";
}
function _hokSubject(scd) {
  return "<saml:Subject><saml:NameID Format=\"" + EMAIL + "\">alice@example.com</saml:NameID>" +
    "<saml:SubjectConfirmation Method=\"" + HOK + "\">" + (scd === null ? "" : scd) + "</saml:SubjectConfirmation></saml:Subject>";
}

function testHolderOfKey(idp, client, other) {
  var sp = _mkSp(idp.certPem);
  var clientB64 = _certBody(client.certPem);
  var otherB64 = _certBody(other.certPem);
  var presented = { presentedCertPem: client.certPem };
  function verify(subjectXml, vopts, tag) {
    return _mkAssertionResponse(idp, { tag: "hok-" + tag, subjectXml: subjectXml });
  }

  // Success — embedded X509 matches the presented possession-proof cert.
  var okInfo = sp.verifyResponse(verify(_hokSubject(_hokScd(clientB64)), null, "ok").b64, { holderOfKey: presented });
  check("HoK: matching possession cert -> confirmed, nameId returned", okInfo.nameId === "alice@example.com");
  check("HoK: HoK confirmation returns null inResponseTo (bearerOk false)", okInfo.inResponseTo === null);

  // Assertion uses HoK but the operator supplied no presented key.
  check("HoK: HoK confirmation without holderOfKey opt -> hok-no-presented-key",
    _verifyCode(sp, verify(_hokSubject(_hokScd(clientB64)), null, "npk").b64) === "auth-saml/hok-no-presented-key");

  // presentedCertPem itself unparseable -> bad-hok-cert (fires before the loop).
  check("HoK: unparseable presentedCertPem -> bad-hok-cert",
    _verifyCode(sp, verify(_hokSubject(_hokScd(clientB64)), null, "bad").b64, { holderOfKey: { presentedCertPem: "not-a-cert" } })
      === "auth-saml/bad-hok-cert");

  // Embedded cert is a different key than presented -> key mismatch.
  check("HoK: embedded X509 != presented key -> hok-key-mismatch",
    _verifyCode(sp, verify(_hokSubject(_hokScd(otherB64)), null, "mm").b64, { holderOfKey: presented })
      === "auth-saml/hok-key-mismatch");

  // KeyInfo shapes.
  check("HoK: SubjectConfirmationData without KeyInfo -> hok-no-keyinfo",
    _verifyCode(sp, verify(_hokSubject(_hokScd(null)), null, "nki").b64, { holderOfKey: presented })
      === "auth-saml/hok-no-keyinfo");
  check("HoK: KeyInfo without X509Data/X509Certificate -> hok-unsupported-keyinfo",
    _verifyCode(sp, verify(_hokSubject("<saml:SubjectConfirmationData NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\" Recipient=\"" + ACS_URL +
      "\"><ds:KeyInfo xmlns:ds=\"" + DS + "\"><ds:KeyValue><ds:RSAKeyValue></ds:RSAKeyValue></ds:KeyValue></ds:KeyInfo></saml:SubjectConfirmationData>"), null, "uki").b64,
      { holderOfKey: presented }) === "auth-saml/hok-unsupported-keyinfo");
  check("HoK: empty X509Certificate -> hok-no-cert",
    _verifyCode(sp, verify(_hokSubject(_hokScd("")), null, "nc").b64, { holderOfKey: presented })
      === "auth-saml/hok-no-cert");
  check("HoK: garbage X509Certificate -> hok-bad-cert",
    _verifyCode(sp, verify(_hokSubject(_hokScd(Buffer.from("not a cert").toString("base64"))), null, "bc").b64, { holderOfKey: presented })
      === "auth-saml/hok-bad-cert");

  // Matching key but time / recipient / SCD fail-closed skips -> no confirmation.
  var nvc = "auth-saml/no-valid-confirmation";
  check("HoK: matched key but no SubjectConfirmationData -> no-valid-confirmation",
    _verifyCode(sp, verify(_hokSubject(null), null, "noscd").b64, { holderOfKey: presented }) === nvc);
  check("HoK: matched key but no NotOnOrAfter -> no-valid-confirmation",
    _verifyCode(sp, verify(_hokSubject(_hokScd(clientB64, " Recipient=\"" + ACS_URL + "\"")), null, "nnoa").b64, { holderOfKey: presented }) === nvc);
  check("HoK: matched key but expired NotOnOrAfter -> no-valid-confirmation",
    _verifyCode(sp, verify(_hokSubject(_hokScd(clientB64, " NotOnOrAfter=\"" + iso(-C.TIME.hours(1)) + "\" Recipient=\"" + ACS_URL + "\"")), null, "exp").b64, { holderOfKey: presented }) === nvc);
  check("HoK: matched key but NotBefore in the future -> no-valid-confirmation",
    _verifyCode(sp, verify(_hokSubject(_hokScd(clientB64, " NotBefore=\"" + iso(C.TIME.hours(1)) + "\" NotOnOrAfter=\"" + iso(C.TIME.hours(2)) + "\" Recipient=\"" + ACS_URL + "\"")), null, "nbf").b64, { holderOfKey: presented }) === nvc);
  check("HoK: matched key but Recipient mismatch -> no-valid-confirmation",
    _verifyCode(sp, verify(_hokSubject(_hokScd(clientB64, " NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\" Recipient=\"https://evil.example\"")), null, "rcp").b64, { holderOfKey: presented }) === nvc);
}

// verifyResponse — holder-of-key must apply the SAME InResponseTo replay
// check the Bearer path applies when the operator opts in via
// expectedInResponseTo. SAML Web-Browser-SSO Profile §4.1.4.2 (incorporated
// into the HoK profile by §3.1) binds a solicited response's
// SubjectConfirmationData InResponseTo to the stored AuthnRequest ID. A HoK
// confirmation that ignored expectedInResponseTo would silently drop the
// operator's replay defense on that path.
function testHolderOfKeyInResponseTo(idp, client) {
  var sp = _mkSp(idp.certPem);
  var clientB64 = _certBody(client.certPem);
  var presented = { presentedCertPem: client.certPem };
  function attrs(irt) {
    return " NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\" Recipient=\"" + ACS_URL + "\"" +
      (irt !== undefined ? " InResponseTo=\"" + irt + "\"" : "");
  }
  function mk(tag, irt) {
    return _mkAssertionResponse(idp, {
      tag: "hok-irt-" + tag,
      subjectXml: _hokSubject(_hokScd(clientB64, attrs(irt))),
    }).b64;
  }

  // Matching InResponseTo — accepted and the validated value is echoed back
  // (not sourced from a different, non-validated confirmation).
  var okInfo = sp.verifyResponse(mk("ok", "_req-1"), { holderOfKey: presented, expectedInResponseTo: "_req-1" });
  check("HoK: matching InResponseTo -> accepted",       okInfo.nameId === "alice@example.com");
  check("HoK: matching InResponseTo -> value echoed",   okInfo.inResponseTo === "_req-1");

  // Mismatched InResponseTo — the operator's replay defense MUST fire on the
  // HoK path, exactly as it does for Bearer.
  check("HoK: InResponseTo mismatch -> bad-in-response-to (replay defense on HoK path)",
    _verifyCode(sp, mk("mm", "_other"), { holderOfKey: presented, expectedInResponseTo: "_req-1" })
      === "auth-saml/bad-in-response-to");

  // Absent InResponseTo while the operator expects one — also refused (a
  // solicited response missing the binding cannot be correlated).
  check("HoK: absent InResponseTo while expected -> bad-in-response-to",
    _verifyCode(sp, mk("absent"), { holderOfKey: presented, expectedInResponseTo: "_req-1" })
      === "auth-saml/bad-in-response-to");

  // No expectedInResponseTo -> HoK still succeeds regardless of any present
  // InResponseTo (the operator did not opt into the replay binding).
  var noExpect = sp.verifyResponse(mk("noexp", "_whatever"), { holderOfKey: presented });
  check("HoK: no expectedInResponseTo -> accepted", noExpect.nameId === "alice@example.com");
}

// ---------------------------------------------------------------------------
// verifyResponse — Conditions, Audience, AuthnStatement variants
// ---------------------------------------------------------------------------

function testConditionsAndAudience(idp) {
  var sp = _mkSp(idp.certPem);
  var ar = "<saml:AudienceRestriction><saml:Audience>" + SP_ENTITY_ID + "</saml:Audience></saml:AudienceRestriction>";

  check("verify: unparseable Conditions/NotBefore -> conditions-bad-timestamp",
    _verifyCode(sp, _mkAssertionResponse(idp, { tag: "cbt1",
      conditions: "<saml:Conditions NotBefore=\"not-a-date\" NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\">" + ar + "</saml:Conditions>" }).b64)
      === "auth-saml/conditions-bad-timestamp");
  check("verify: unparseable Conditions/NotOnOrAfter -> conditions-bad-timestamp",
    _verifyCode(sp, _mkAssertionResponse(idp, { tag: "cbt2",
      conditions: "<saml:Conditions NotBefore=\"" + iso(-C.TIME.minutes(5)) + "\" NotOnOrAfter=\"not-a-date\">" + ar + "</saml:Conditions>" }).b64)
      === "auth-saml/conditions-bad-timestamp");

  // No Conditions element at all -> the audience binding is absent.
  check("verify: no Conditions element -> no-audience-restriction",
    _verifyCode(sp, _mkAssertionResponse(idp, { tag: "nocond", conditions: "" }).b64)
      === "auth-saml/no-audience-restriction");

  // AND-combined AudienceRestriction (SAML core 2.5.1.4): SP must be in EVERY one.
  var bothOk = "<saml:Conditions NotBefore=\"" + iso(-C.TIME.minutes(5)) + "\" NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\">" +
    ar + "<saml:AudienceRestriction><saml:Audience>" + SP_ENTITY_ID + "</saml:Audience></saml:AudienceRestriction></saml:Conditions>";
  check("verify: two AudienceRestrictions both naming SP -> accepted",
    sp.verifyResponse(_mkAssertionResponse(idp, { tag: "ars-ok", conditions: bothOk }).b64).nameId === "alice@example.com");
  var secondBad = "<saml:Conditions NotBefore=\"" + iso(-C.TIME.minutes(5)) + "\" NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\">" +
    ar + "<saml:AudienceRestriction><saml:Audience>https://other.example</saml:Audience></saml:AudienceRestriction></saml:Conditions>";
  check("verify: SP absent from a later AudienceRestriction -> wrong-audience",
    _verifyCode(sp, _mkAssertionResponse(idp, { tag: "ars-bad", conditions: secondBad }).b64) === "auth-saml/wrong-audience");

  // No AuthnStatement -> sessionIndex null.
  var noAuthn = sp.verifyResponse(_mkAssertionResponse(idp, { tag: "noauthn", authnStmt: "" }).b64);
  check("verify: assertion without AuthnStatement -> sessionIndex null", noAuthn.sessionIndex === null);
}

// ---------------------------------------------------------------------------
// verifyResponse — missing structural fields on an otherwise-signed assertion
// (each fires only AFTER the XMLDSig verifies, so the signature gate is live)
// ---------------------------------------------------------------------------

function testVerifyResponseMissingFields(idp) {
  var sp = _mkSp(idp.certPem);

  // Signed assertion whose Subject is absent -> no-subject.
  check("verify: signed assertion without Subject -> no-subject",
    _verifyCode(sp, _mkAssertionResponse(idp, { tag: "nosub", subjectXml: "" }).b64)
      === "auth-saml/no-subject");

  // Signed assertion with a Subject but no NameID -> no-nameid.
  var subjectNoNameId = "<saml:Subject><saml:SubjectConfirmation Method=\"" + BEARER + "\">" +
    "<saml:SubjectConfirmationData NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\" Recipient=\"" + ACS_URL + "\"/>" +
    "</saml:SubjectConfirmation></saml:Subject>";
  check("verify: signed Subject without NameID -> no-nameid",
    _verifyCode(sp, _mkAssertionResponse(idp, { tag: "nonid", subjectXml: subjectNoNameId }).b64)
      === "auth-saml/no-nameid");

  // Bearer confirmation with NO InResponseTo, but the operator expects one:
  // the `inResponseTo === null` arm of the replay check must fire (this is the
  // sibling of the HoK path exercised above).
  check("verify: Bearer absent InResponseTo while expected -> bad-in-response-to",
    _verifyCode(sp, _mkAssertionResponse(idp, { tag: "birt" }).b64, { expectedInResponseTo: "_req-1" })
      === "auth-saml/bad-in-response-to");
}

// ---------------------------------------------------------------------------
// verifyResponse — NameID XML-comment truncation defense
//
// The classic SAML comment-truncation bypass (Duo Labs, 2018): an attacker
// splits a signed NameID text value with an XML comment so a partial-text
// extractor reads a shorter, higher-privilege value while the signature still
// validates (exclusive-c14n strips the comment before digesting). This
// implementation extracts the FULL concatenated text of every text node
// (skipping comments) and canonicalizes with the same comment-stripping, so
// both the signed digest and the consumed NameID are the whole value — never a
// truncated prefix. A single flat-text read here would be a full auth bypass.
// ---------------------------------------------------------------------------

function testNameIdCommentTruncation(idp) {
  var sp = _mkSp(idp.certPem);
  var split = "<saml:Subject><saml:NameID Format=\"" + EMAIL + "\">" +
    "admin@good.example<!--wrap-->.attacker.example</saml:NameID>" +
    "<saml:SubjectConfirmation Method=\"" + BEARER + "\">" +
    "<saml:SubjectConfirmationData NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\" Recipient=\"" + ACS_URL + "\"/>" +
    "</saml:SubjectConfirmation></saml:Subject>";
  var info = sp.verifyResponse(_mkAssertionResponse(idp, { tag: "cmt", subjectXml: split }).b64);
  check("verify: comment-split NameID yields the FULL value, not a truncated prefix",
    info.nameId === "admin@good.example.attacker.example");
  check("verify: comment-split NameID is not truncated at the comment",
    info.nameId !== "admin@good.example");
}

// ---------------------------------------------------------------------------
// verifyResponse — EncryptedAssertion (RSA-OAEP-SHA256 + AES-256-GCM)
// ---------------------------------------------------------------------------

function _encData(o) {
  o = o || {};
  var contentAlg = o.contentAlg || "http://www.w3.org/2009/xmlenc11#aes256-gcm";
  var keyAlg = o.keyAlg || "http://www.w3.org/2009/xmlenc11#rsa-oaep";
  var digestXml = o.oaepDigest === null ? "" :
    "<ds:DigestMethod Algorithm=\"" + (o.oaepDigest || "http://www.w3.org/2001/04/xmlenc#sha256") + "\"></ds:DigestMethod>";
  return "<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc=\"" + XENC + "\">" +
    "<xenc:EncryptionMethod Algorithm=\"" + contentAlg + "\"></xenc:EncryptionMethod>" +
    "<ds:KeyInfo xmlns:ds=\"" + DS + "\"><xenc:EncryptedKey xmlns:xenc=\"" + XENC + "\">" +
    "<xenc:EncryptionMethod Algorithm=\"" + keyAlg + "\">" + digestXml + "</xenc:EncryptionMethod>" +
    "<xenc:CipherData><xenc:CipherValue>" + o.wrapped + "</xenc:CipherValue></xenc:CipherData>" +
    "</xenc:EncryptedKey></ds:KeyInfo>" +
    "<xenc:CipherData><xenc:CipherValue>" + o.content + "</xenc:CipherValue></xenc:CipherData>" +
    "</xenc:EncryptedData></saml:EncryptedAssertion>";
}

function testEncryptedAssertion(idp) {
  var sp = _mkSp(idp.certPem);
  var spKp = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });                     // allow:raw-byte-literal — RFC 8301 §3.1 RSA bit floor
  var spPriv = spKp.privateKey.export({ type: "pkcs8", format: "pem" });
  var spPub = spKp.publicKey.export({ type: "spki", format: "pem" });
  function wrap(cek) { return nodeCrypto.publicEncrypt({ key: spPub, padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, cek).toString("base64"); }
  function gcm(cek, buf) {
    var iv = nodeCrypto.randomBytes(12);                                                          // allow:raw-byte-literal — GCM 96-bit IV
    var cipher = nodeCrypto.createCipheriv("aes-256-gcm", cek, iv);
    var ct = Buffer.concat([cipher.update(buf), cipher.final()]);
    return Buffer.concat([iv, ct, cipher.getAuthTag()]).toString("base64");
  }
  function verifyEnc(encInner, key) { return _verifyCode(sp, b64(_response(STATUS_OK + encInner)), { spPrivateKeyPem: key }); }

  // Happy path: decrypt -> splice -> verify the recovered signed assertion.
  var cek = nodeCrypto.randomBytes(32);                                                           // allow:raw-byte-literal — AES-256 key
  var clear = _buildAssertion(idp, { tag: "enc" }).full;
  var okXml = b64(_response(STATUS_OK + _encData({ wrapped: wrap(cek), content: gcm(cek, Buffer.from(clear, "utf8")) })));
  check("encrypted: RSA-OAEP-SHA256 + AES-256-GCM round trip -> nameId",
    sp.verifyResponse(okXml, { spPrivateKeyPem: spPriv }).nameId === "alice@example.com");

  // Structural refusals (no crypto reached — any non-empty spPrivateKeyPem).
  check("encrypted: EncryptedAssertion without EncryptedData -> encrypted-no-encrypted-data",
    verifyEnc("<saml:EncryptedAssertion></saml:EncryptedAssertion>", "x") === "auth-saml/encrypted-no-encrypted-data");
  check("encrypted: EncryptedData without EncryptionMethod -> encrypted-no-method",
    verifyEnc("<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc=\"" + XENC + "\"></xenc:EncryptedData></saml:EncryptedAssertion>", "x")
      === "auth-saml/encrypted-no-method");
  check("encrypted: EncryptedData without KeyInfo -> encrypted-no-keyinfo",
    verifyEnc("<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc=\"" + XENC + "\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"></xenc:EncryptionMethod></xenc:EncryptedData></saml:EncryptedAssertion>", "x")
      === "auth-saml/encrypted-no-keyinfo");
  check("encrypted: KeyInfo without EncryptedKey -> encrypted-no-encrypted-key",
    verifyEnc("<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc=\"" + XENC + "\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"></xenc:EncryptionMethod><ds:KeyInfo xmlns:ds=\"" + DS + "\"></ds:KeyInfo></xenc:EncryptedData></saml:EncryptedAssertion>", "x")
      === "auth-saml/encrypted-no-encrypted-key");
  check("encrypted: EncryptedKey without EncryptionMethod -> encrypted-no-key-alg",
    verifyEnc("<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc=\"" + XENC + "\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"></xenc:EncryptionMethod><ds:KeyInfo xmlns:ds=\"" + DS + "\"><xenc:EncryptedKey xmlns:xenc=\"" + XENC + "\"></xenc:EncryptedKey></ds:KeyInfo></xenc:EncryptedData></saml:EncryptedAssertion>", "x")
      === "auth-saml/encrypted-no-key-alg");
  check("encrypted: EncryptedKey without CipherValue -> encrypted-no-key-cipher-value",
    verifyEnc("<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc=\"" + XENC + "\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"></xenc:EncryptionMethod><ds:KeyInfo xmlns:ds=\"" + DS + "\"><xenc:EncryptedKey xmlns:xenc=\"" + XENC + "\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#rsa-oaep\"></xenc:EncryptionMethod></xenc:EncryptedKey></ds:KeyInfo></xenc:EncryptedData></saml:EncryptedAssertion>", "x")
      === "auth-saml/encrypted-no-key-cipher-value");
  check("encrypted: unsupported key-transport alg -> encrypted-unsupported-key-alg",
    verifyEnc(_encData({ keyAlg: "http://example/bogus-key-alg", wrapped: "AA==", content: "AA==" }), "x")
      === "auth-saml/encrypted-unsupported-key-alg");
  check("encrypted: unsupported OAEP DigestMethod -> encrypted-unsupported-oaep-digest",
    verifyEnc(_encData({ oaepDigest: "http://example/bogus-digest", wrapped: "AA==", content: "AA==" }), "x")
      === "auth-saml/encrypted-unsupported-oaep-digest");
  check("encrypted: SHA-1 OAEP (default) -> encrypted-weak-oaep-digest",
    verifyEnc(_encData({ oaepDigest: null, wrapped: "AA==", content: "AA==" }), "x")
      === "auth-saml/encrypted-weak-oaep-digest");
  check("encrypted: unparseable spPrivateKeyPem -> encrypted-bad-sp-key",
    verifyEnc(_encData({ wrapped: "AA==", content: "AA==" }), "not-a-key") === "auth-saml/encrypted-bad-sp-key");

  // Crypto-reaching refusals (need the real SP key).
  check("encrypted: undecryptable wrapped key -> encrypted-key-unwrap-failed",
    verifyEnc(_encData({ wrapped: nodeCrypto.randomBytes(256).toString("base64"), content: "AA==" }), spPriv)
      === "auth-saml/encrypted-key-unwrap-failed");
  check("encrypted: wrong CEK length for AES-256-GCM -> encrypted-wrong-cek-len",
    verifyEnc(_encData({ wrapped: wrap(nodeCrypto.randomBytes(16)), content: "AA==" }), spPriv)
      === "auth-saml/encrypted-wrong-cek-len");
  check("encrypted: content shorter than IV+tag -> encrypted-content-too-short",
    verifyEnc(_encData({ wrapped: wrap(nodeCrypto.randomBytes(32)), content: Buffer.alloc(10).toString("base64") }), spPriv)
      === "auth-saml/encrypted-content-too-short");
  check("encrypted: AES-GCM tag mismatch -> encrypted-content-tag-mismatch",
    verifyEnc(_encData({ wrapped: wrap(nodeCrypto.randomBytes(32)),
      content: Buffer.concat([nodeCrypto.randomBytes(12), nodeCrypto.randomBytes(20), nodeCrypto.randomBytes(16)]).toString("base64") }), spPriv)
      === "auth-saml/encrypted-content-tag-mismatch");
  check("encrypted: AES-CBC content alg refused -> encrypted-unsupported-content-alg",
    verifyEnc(_encData({ contentAlg: "http://www.w3.org/2001/04/xmlenc#aes256-cbc", wrapped: wrap(nodeCrypto.randomBytes(32)), content: "AA==" }), spPriv)
      === "auth-saml/encrypted-unsupported-content-alg");

  var cek2 = nodeCrypto.randomBytes(32);
  check("encrypted: cleartext root is not an Assertion -> encrypted-not-assertion",
    verifyEnc(_encData({ wrapped: wrap(cek2), content: gcm(cek2, Buffer.from("<saml:Foo xmlns:saml=\"" + SAML_A + "\">x</saml:Foo>", "utf8")) }), spPriv)
      === "auth-saml/encrypted-not-assertion");
  var cek3 = nodeCrypto.randomBytes(32);
  check("encrypted: cleartext is not parseable XML -> encrypted-bad-cleartext",
    verifyEnc(_encData({ wrapped: wrap(cek3), content: gcm(cek3, Buffer.from("garbage-no-xml", "utf8")) }), spPriv)
      === "auth-saml/encrypted-bad-cleartext");
}

// ---------------------------------------------------------------------------
// SLO — embedded XMLDSig (POST) classical + Ed25519, and error branches
// ---------------------------------------------------------------------------

function _ed25519Raw() {
  var ed = nodeCrypto.generateKeyPairSync("ed25519");
  var pk8 = ed.privateKey.export({ type: "pkcs8", format: "der" });
  var spki = ed.publicKey.export({ type: "spki", format: "der" });
  return { seed: new Uint8Array(pk8.subarray(pk8.length - 32)), pub: new Uint8Array(spki.subarray(spki.length - 32)) };
}

function testSloPostBindings() {
  var sp = _mkSp(FAKE_CERT);
  var rsa = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });                       // allow:raw-byte-literal — RFC 8301 §3.1 RSA bit floor
  var skPem = rsa.privateKey.export({ type: "pkcs8", format: "pem" });
  var pkPem = rsa.publicKey.export({ type: "spki", format: "pem" });
  var ed = _ed25519Raw();

  function roundTrip(alg, sk, pk) {
    var post = sp.buildLogoutRequestPost({ nameId: "alice@idp", sessionIndex: "_s-9", signingKey: sk, signingAlg: alg });
    var parsed = sp.parseLogoutRequestPost(post.samlRequest, { idpVerifyKey: pk, idpVerifyAlg: alg });
    return parsed.nameId === "alice@idp" && parsed.sessionIndex === "_s-9";
  }
  check("SLO POST: rsa-sha256 embedded XMLDSig round trip (PEM)", roundTrip("rsa-sha256", skPem, pkPem));
  check("SLO POST: rsa-sha256 embedded XMLDSig round trip (KeyObject)", roundTrip("rsa-sha256", rsa.privateKey, rsa.publicKey));
  check("SLO POST: rsa-sha384 embedded XMLDSig round trip", roundTrip("rsa-sha384", skPem, pkPem));
  check("SLO POST: rsa-sha512 embedded XMLDSig round trip", roundTrip("rsa-sha512", skPem, pkPem));
  check("SLO POST: ed25519 embedded XMLDSig round trip (raw key)", roundTrip("ed25519", ed.seed, ed.pub));

  // _embedXmlDsig key/alg validation (buildLogoutRequestPost calls it directly).
  check("SLO POST: unknown signingAlg -> bad-signing-alg",
    _codeOf(function () { sp.buildLogoutRequestPost({ nameId: "a", signingAlg: "bogus" }); }) === "auth-saml/bad-signing-alg");
  check("SLO POST: classical signingKey not a PEM/KeyObject -> bad-signing-key",
    _codeOf(function () { sp.buildLogoutRequestPost({ nameId: "a", signingKey: 123, signingAlg: "rsa-sha256" }); }) === "auth-saml/bad-signing-key");
  check("SLO POST: ml-dsa signingKey not a Uint8Array -> bad-signing-key",
    _codeOf(function () { sp.buildLogoutRequestPost({ nameId: "a", signingKey: "nope", signingAlg: "ml-dsa-65" }); }) === "auth-saml/bad-signing-key");

  // _verifyEmbeddedXmlDsig error branches.
  var unsigned = sp.buildLogoutRequestPost({ nameId: "a@idp" });
  var kp = pq.ml_dsa_65.keygen();
  check("SLO POST: verify requested but body unsigned -> no-signature",
    _codeOf(function () { sp.parseLogoutRequestPost(unsigned.samlRequest, { idpVerifyKey: kp.publicKey, idpVerifyAlg: "ml-dsa-65" }); }) === "auth-saml/no-signature");

  var signed65 = sp.buildLogoutRequestPost({ nameId: "a@idp", signingKey: kp.secretKey, signingAlg: "ml-dsa-65" });
  var kp87 = pq.ml_dsa_87.keygen();
  check("SLO POST: SignatureMethod URN != expected -> wrong-sig-alg",
    _codeOf(function () { sp.parseLogoutRequestPost(signed65.samlRequest, { idpVerifyKey: kp87.publicKey, idpVerifyAlg: "ml-dsa-87" }); }) === "auth-saml/wrong-sig-alg");

  var respRaw = sp.buildLogoutResponse({ inResponseTo: "_x", destination: IDP_SLO_URL }).raw;
  check("SLO POST: verify a LogoutResponse as a LogoutRequest -> wrong-root",
    _codeOf(function () { sp.parseLogoutRequestPost(b64(respRaw), { idpVerifyKey: kp.publicKey, idpVerifyAlg: "ml-dsa-65" }); }) === "auth-saml/wrong-root");

  var tampered = Buffer.from(signed65.samlRequest, "base64").toString("utf8").replace("a@idp", "b@idp");
  check("SLO POST: tampered signed content -> digest-mismatch",
    _codeOf(function () { sp.parseLogoutRequestPost(b64(tampered), { idpVerifyKey: kp.publicKey, idpVerifyAlg: "ml-dsa-65" }); }) === "auth-saml/digest-mismatch");

  var noNameId = "<samlp:LogoutRequest xmlns:samlp=\"" + SAML_P + "\" xmlns:saml=\"" + SAML_A + "\" ID=\"_x\"><saml:Issuer>i</saml:Issuer></samlp:LogoutRequest>";
  check("SLO POST: LogoutRequest without NameID -> no-nameid",
    _codeOf(function () { sp.parseLogoutRequestPost(b64(noNameId)); }) === "auth-saml/no-nameid");
}

function testSloRedirectAndParse() {
  var sp = _mkSp(FAKE_CERT);
  var ed = _ed25519Raw();
  var kp = pq.ml_dsa_65.keygen();

  // Ed25519 redirect-binding round trip (raw key sign + verify paths).
  var lr = sp.buildLogoutRequest({ nameId: "a@idp", sessionIndex: "_s", signingKey: ed.seed, signingAlg: "ed25519" });
  var q = lr.redirectUrl.split("?")[1];
  var samlReq = decodeURIComponent(q.split("&")[0].slice("SAMLRequest=".length));
  check("SLO redirect: ed25519 raw-key round trip",
    sp.parseLogoutRequest(samlReq, { queryString: q, idpVerifyKey: ed.pub, idpVerifyAlg: "ed25519" }).nameId === "a@idp");
  check("SLO redirect: verify requested without queryString -> no-query-string",
    _codeOf(function () { sp.parseLogoutRequest(samlReq, { idpVerifyKey: ed.pub, idpVerifyAlg: "ed25519" }); }) === "auth-saml/no-query-string");
  check("SLO redirect: unknown idpVerifyAlg -> bad-verify-alg",
    _codeOf(function () { sp.parseLogoutRequest(samlReq, { queryString: q, idpVerifyKey: ed.pub, idpVerifyAlg: "bogus" }); }) === "auth-saml/bad-verify-alg");

  // buildLogoutRequest classical bad key.
  check("SLO redirect: classical signingKey not a PEM/KeyObject -> bad-signing-key",
    _codeOf(function () { sp.buildLogoutRequest({ nameId: "a", signingKey: 123, signingAlg: "rsa-sha256" }); }) === "auth-saml/bad-signing-key");

  // parseLogoutResponse signed round trip + error branches.
  var resp = sp.buildLogoutResponse({ inResponseTo: "_o", destination: IDP_SLO_URL, signingKey: kp.secretKey, signingAlg: "ml-dsa-65" });
  var rq = resp.redirectUrl.split("?")[1];
  var samlResp = decodeURIComponent(rq.split("&")[0].slice("SAMLResponse=".length));
  check("SLO redirect: parseLogoutResponse signed round trip -> success",
    sp.parseLogoutResponse(samlResp, { queryString: rq, idpVerifyKey: kp.publicKey, idpVerifyAlg: "ml-dsa-65" }).success === true);
  check("SLO redirect: parseLogoutResponse verify without queryString -> no-query-string",
    _codeOf(function () { sp.parseLogoutResponse(samlResp, { idpVerifyKey: kp.publicKey, idpVerifyAlg: "ml-dsa-65" }); }) === "auth-saml/no-query-string");
  check("SLO redirect: parseLogoutResponse unknown idpVerifyAlg -> bad-verify-alg",
    _codeOf(function () { sp.parseLogoutResponse(samlResp, { queryString: rq, idpVerifyKey: kp.publicKey, idpVerifyAlg: "bogus" }); }) === "auth-saml/bad-verify-alg");

  // buildLogoutResponse signing validation.
  check("SLO: buildLogoutResponse unknown signingAlg -> bad-signing-alg",
    _codeOf(function () { sp.buildLogoutResponse({ inResponseTo: "_x", destination: IDP_SLO_URL, signingAlg: "bogus" }); }) === "auth-saml/bad-signing-alg");
  check("SLO: buildLogoutResponse classical bad signingKey -> bad-signing-key",
    _codeOf(function () { sp.buildLogoutResponse({ inResponseTo: "_x", destination: IDP_SLO_URL, signingKey: 123, signingAlg: "rsa-sha256" }); }) === "auth-saml/bad-signing-key");

  // Wrong-document parse refusals.
  var respQuery = sp.buildLogoutResponse({ inResponseTo: "_x", destination: IDP_SLO_URL }).redirectUrl.split("?")[1];
  var respOnly = decodeURIComponent(respQuery.split("&")[0].slice("SAMLResponse=".length));
  check("SLO: parseLogoutRequest given a LogoutResponse -> not-logout-request",
    _codeOf(function () { sp.parseLogoutRequest(respOnly); }) === "auth-saml/not-logout-request");
  var reqQuery = sp.buildLogoutRequest({ nameId: "a", sessionIndex: "_s" }).redirectUrl.split("?")[1];
  var reqOnly = decodeURIComponent(reqQuery.split("&")[0].slice("SAMLRequest=".length));
  check("SLO: parseLogoutResponse given a LogoutRequest -> not-logout-response",
    _codeOf(function () { sp.parseLogoutResponse(reqOnly); }) === "auth-saml/not-logout-response");
  var noNameIdReq = zlib.deflateRawSync(Buffer.from(
    "<samlp:LogoutRequest xmlns:samlp=\"" + SAML_P + "\" xmlns:saml=\"" + SAML_A + "\" ID=\"_x\"><saml:Issuer>i</saml:Issuer></samlp:LogoutRequest>", "utf8")).toString("base64");
  check("SLO: parseLogoutRequest LogoutRequest without NameID -> no-nameid",
    _codeOf(function () { sp.parseLogoutRequest(noNameIdReq); }) === "auth-saml/no-nameid");

  // SOAP parse-side branches.
  check("SLO SOAP: unparseable envelope -> bad-soap",
    _codeOf(function () { sp.parseLogoutResponseSoap("<not-closed"); }) === "auth-saml/bad-soap");
  var soapWrongInner = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><soapenv:Body>" +
    "<samlp:Foo xmlns:samlp=\"" + SAML_P + "\"></samlp:Foo></soapenv:Body></soapenv:Envelope>";
  check("SLO SOAP: body element is not a LogoutResponse -> wrong-root",
    _codeOf(function () { sp.parseLogoutResponseSoap(soapWrongInner); }) === "auth-saml/wrong-root");
  var lrResp = sp.buildLogoutResponse({ inResponseTo: "_o", destination: IDP_SLO_URL }).raw;
  var soapUnsigned = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><soapenv:Body>" + lrResp + "</soapenv:Body></soapenv:Envelope>";
  check("SLO SOAP: verify requested but LogoutResponse unsigned -> no-signature",
    _codeOf(function () { sp.parseLogoutResponseSoap(soapUnsigned, { idpVerifyKey: kp.publicKey, idpVerifyAlg: "ml-dsa-65" }); }) === "auth-saml/no-signature");
}

// ---------------------------------------------------------------------------
// fetchMdq — transport + verification branches (require-cache transport fake)
// ---------------------------------------------------------------------------

function _fedSignature(fed, refId, elementXml) {
  var digest = nodeCrypto.createHash("sha256").update(c14n.canonicalize(elementXml)).digest("base64");
  var signedInfo = "<ds:SignedInfo xmlns:ds=\"" + DS + "\">" +
    "<ds:CanonicalizationMethod Algorithm=\"" + EXC + "\"></ds:CanonicalizationMethod>" +
    "<ds:SignatureMethod Algorithm=\"" + RSA_SHA256 + "\"></ds:SignatureMethod>" +
    "<ds:Reference URI=\"#" + refId + "\"><ds:Transforms>" +
    "<ds:Transform Algorithm=\"" + ENVELOPED + "\"></ds:Transform>" +
    "<ds:Transform Algorithm=\"" + EXC + "\"></ds:Transform></ds:Transforms>" +
    "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod>" +
    "<ds:DigestValue>" + digest + "</ds:DigestValue></ds:Reference></ds:SignedInfo>";
  var priv = nodeCrypto.createPrivateKey({ key: fed.keyPem, format: "pem" });
  var sig = nodeCrypto.sign("sha256", c14n.canonicalize(signedInfo), { key: priv, padding: nodeCrypto.constants.RSA_PKCS1_PADDING }).toString("base64");
  return "<ds:Signature xmlns:ds=\"" + DS + "\">" + signedInfo + "<ds:SignatureValue>" + sig + "</ds:SignatureValue></ds:Signature>";
}

async function _fetchMdqWith(status, body, trustCertPem) {
  var hcPath = require.resolve("../../lib/http-client");
  var origHc = require.cache[hcPath].exports;
  require.cache[hcPath].exports = Object.assign({}, origHc, {
    request: async function () { return { statusCode: status, headers: {}, body: body == null ? body : Buffer.from(body, "utf8") }; },
  });
  var samlPath = require.resolve("../../lib/auth/saml");
  delete require.cache[samlPath];
  var saml = require(samlPath);
  try {
    var xml = await saml.fetchMdq({ baseUrl: "https://mdq.test.invalid", entityId: IDP_ENTITY_ID, trustCertPem: trustCertPem });
    return { xml: xml, code: null };
  } catch (e) {
    return { xml: null, code: e.code || e.message };
  } finally {
    require.cache[hcPath].exports = origHc;
    delete require.cache[samlPath];
  }
}

async function testFetchMdqBranches(fed) {
  var r1 = await _fetchMdqWith(500, "<x/>", null);
  check("fetchMdq: non-2xx status -> mdq-fetch-failed", r1.code === "auth-saml/mdq-fetch-failed");
  var r2 = await _fetchMdqWith(200, "", null);
  check("fetchMdq: empty body -> mdq-empty", r2.code === "auth-saml/mdq-empty");

  var plainEd = "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"" + IDP_ENTITY_ID + "\"></md:EntityDescriptor>";
  var r3 = await _fetchMdqWith(200, plainEd, null);
  check("fetchMdq: no trustCertPem -> returns metadata unverified", r3.code === null && r3.xml === plainEd);

  var r4 = await _fetchMdqWith(200, plainEd, fed.certPem);
  check("fetchMdq: trustCertPem supplied but metadata unsigned -> mdq-unsigned", r4.code === "auth-saml/mdq-unsigned");

  var dupSig = "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"G1\" entityID=\"" + IDP_ENTITY_ID + "\">" +
    "<ds:Signature xmlns:ds=\"" + DS + "\"></ds:Signature><ds:Signature xmlns:ds=\"" + DS + "\"></ds:Signature></md:EntityDescriptor>";
  var r5 = await _fetchMdqWith(200, dupSig, fed.certPem);
  check("fetchMdq: duplicate top-level Signature -> mdq-duplicate-signature", r5.code === "auth-saml/mdq-duplicate-signature");

  // Federation-signed descriptor whose entityID differs from the requested one.
  var mismatchEntity = "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"G1\" entityID=\"https://other.example\">" +
    "<md:IDPSSODescriptor protocolSupportEnumeration=\"" + SAML_P + "\"></md:IDPSSODescriptor></md:EntityDescriptor>";
  var sig = _fedSignature(fed, "G1", mismatchEntity);
  var signedMismatch = mismatchEntity.slice(0, mismatchEntity.indexOf(">") + 1) + sig + mismatchEntity.slice(mismatchEntity.indexOf(">") + 1);
  var r6 = await _fetchMdqWith(200, signedMismatch, fed.certPem);
  check("fetchMdq: signed EntityDescriptor entityID != requested -> mdq-entity-mismatch", r6.code === "auth-saml/mdq-entity-mismatch");

  // Full success: a federation-signed EntityDescriptor whose signature
  // verifies against trustCertPem, whose Reference binds the document-root
  // EntityDescriptor, and whose entityID equals the requested one -> the raw
  // metadata XML is returned (the advertised happy path, end to end).
  var okEntity = "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"G1\" entityID=\"" + IDP_ENTITY_ID + "\">" +
    "<md:IDPSSODescriptor protocolSupportEnumeration=\"" + SAML_P + "\"></md:IDPSSODescriptor></md:EntityDescriptor>";
  var okSig = _fedSignature(fed, "G1", okEntity);
  var signedOk = okEntity.slice(0, okEntity.indexOf(">") + 1) + okSig + okEntity.slice(okEntity.indexOf(">") + 1);
  var r7 = await _fetchMdqWith(200, signedOk, fed.certPem);
  check("fetchMdq: valid federation signature + matching entityID -> returns metadata",
    r7.code === null && r7.xml === signedOk);
}

// ---------------------------------------------------------------------------
// verifyResponse — duplicate NameID + undeclared-prefix namespace resolution
// ---------------------------------------------------------------------------

function testMoreVerifyResponse(idp) {
  var sp = _mkSp(idp.certPem);
  var twoNameId = "<saml:Subject>" +
    "<saml:NameID Format=\"" + EMAIL + "\">alice@example.com</saml:NameID>" +
    "<saml:NameID>mallory@evil.example</saml:NameID>" +
    "<saml:SubjectConfirmation Method=\"" + BEARER + "\">" +
    "<saml:SubjectConfirmationData NotOnOrAfter=\"" + iso(C.TIME.minutes(5)) + "\" Recipient=\"" + ACS_URL + "\"/>" +
    "</saml:SubjectConfirmation></saml:Subject>";
  check("verify: Subject with two NameID children -> duplicate-nameid (XSW)",
    _verifyCode(sp, _mkAssertionResponse(idp, { tag: "dnid", subjectXml: twoNameId }).b64) === "auth-saml/duplicate-nameid");

  // A Status carried under an UNDECLARED namespace prefix does not resolve to
  // the SAML protocol namespace, so it is treated as absent -> bad-status. This
  // drives the prefix->namespace lookup returning null for an undeclared prefix.
  var undeclared = "<samlp:Response xmlns:samlp=\"" + SAML_P + "\" ID=\"_r\">" +
    "<zz:Status><zz:StatusCode Value=\"" + SUCCESS + "\"/></zz:Status></samlp:Response>";
  check("verify: Status under an undeclared prefix -> bad-status",
    _verifyCode(_mkSp(FAKE_CERT), b64(undeclared)) === "auth-saml/bad-status");
}

// ---------------------------------------------------------------------------
// SLO — remaining redirect + response build/parse branches
// ---------------------------------------------------------------------------

function testSloExtraBranches() {
  var sp = _mkSp(FAKE_CERT);
  var kp = pq.ml_dsa_65.keygen();

  var lrRs = sp.buildLogoutRequest({ nameId: "a@idp", sessionIndex: "_s", relayState: "/back&x=1" });
  check("SLO: buildLogoutRequest appends RelayState",
    lrRs.redirectUrl.indexOf("RelayState=" + encodeURIComponent("/back&x=1")) !== -1);
  var respRs = sp.buildLogoutResponse({ inResponseTo: "_o", destination: IDP_SLO_URL, relayState: "/back" });
  check("SLO: buildLogoutResponse appends RelayState",
    respRs.redirectUrl.indexOf("RelayState=" + encodeURIComponent("/back")) !== -1);

  check("SLO: buildLogoutResponse ml-dsa signingKey not a Uint8Array -> bad-signing-key",
    _codeOf(function () { sp.buildLogoutResponse({ inResponseTo: "_o", destination: IDP_SLO_URL, signingKey: "nope", signingAlg: "ml-dsa-65" }); }) === "auth-saml/bad-signing-key");

  check("SLO: parseLogoutResponse undeflatable base64 -> bad-saml-response",
    _codeOf(function () { sp.parseLogoutResponse(b64("this is not deflate-raw data")); }) === "auth-saml/bad-saml-response");

  var lrSigned = sp.buildLogoutRequest({ nameId: "a@idp", sessionIndex: "_s", signingKey: kp.secretKey, signingAlg: "ml-dsa-65" });
  var lq = lrSigned.redirectUrl.split("?")[1];
  var lreq = decodeURIComponent(lq.split("&")[0].slice("SAMLRequest=".length));
  check("SLO: parseLogoutRequest verify throws on malformed key -> verify-threw",
    _codeOf(function () { sp.parseLogoutRequest(lreq, { queryString: lq, idpVerifyKey: new Uint8Array(5), idpVerifyAlg: "ml-dsa-65" }); }) === "auth-saml/verify-threw");

  var unsignedResp = sp.buildLogoutResponse({ inResponseTo: "_o", destination: IDP_SLO_URL });
  var urq = unsignedResp.redirectUrl.split("?")[1];
  var uresp = decodeURIComponent(urq.split("&")[0].slice("SAMLResponse=".length));
  check("SLO: parseLogoutResponse verify but query lacks Signature -> no-signature",
    _codeOf(function () { sp.parseLogoutResponse(uresp, { queryString: urq, idpVerifyKey: kp.publicKey, idpVerifyAlg: "ml-dsa-65" }); }) === "auth-saml/no-signature");

  var signedResp = sp.buildLogoutResponse({ inResponseTo: "_o", destination: IDP_SLO_URL, signingKey: kp.secretKey, signingAlg: "ml-dsa-65" });
  var srq = signedResp.redirectUrl.split("?")[1];
  var sresp = decodeURIComponent(srq.split("&")[0].slice("SAMLResponse=".length));
  check("SLO: parseLogoutResponse verify throws on malformed key -> verify-threw",
    _codeOf(function () { sp.parseLogoutResponse(sresp, { queryString: srq, idpVerifyKey: new Uint8Array(5), idpVerifyAlg: "ml-dsa-65" }); }) === "auth-saml/verify-threw");
  check("SLO: parseLogoutResponse wrong verify key -> bad-signature",
    _codeOf(function () { sp.parseLogoutResponse(sresp, { queryString: srq, idpVerifyKey: pq.ml_dsa_65.keygen().publicKey, idpVerifyAlg: "ml-dsa-65" }); }) === "auth-saml/bad-signature");

  var noBody = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">" +
    "<soapenv:Header></soapenv:Header></soapenv:Envelope>";
  check("SLO SOAP: Envelope without a Body child -> bad-soap",
    _codeOf(function () { sp.parseLogoutResponseSoap(noBody); }) === "auth-saml/bad-soap");
}

// ---------------------------------------------------------------------------
// _verifyEmbeddedXmlDsig — structural refusals via a crafted embedded Signature
// ---------------------------------------------------------------------------

function _craftReq(sigXml, rootId) {
  return b64("<samlp:LogoutRequest xmlns:samlp=\"" + SAML_P + "\" xmlns:saml=\"" + SAML_A + "\" ID=\"" + (rootId || "_x") +
    "\" Version=\"2.0\" IssueInstant=\"" + iso(0) + "\" Destination=\"" + IDP_SLO_URL + "\">" +
    "<saml:Issuer>i</saml:Issuer>" + sigXml + "<saml:NameID>a</saml:NameID></samlp:LogoutRequest>");
}

function testEmbeddedXmlDsigStructural() {
  var sp = _mkSp(FAKE_CERT);
  var kp = pq.ml_dsa_65.keygen();
  function code(sigXml, rootId, alg) {
    return _codeOf(function () { sp.parseLogoutRequestPost(_craftReq(sigXml, rootId), { idpVerifyKey: kp.publicKey, idpVerifyAlg: alg || "ml-dsa-65" }); });
  }
  check("embedded: unknown idpVerifyAlg -> bad-verify-alg",
    code(_craftSig({ noSignedInfo: true }), "_x", "bogus") === "auth-saml/bad-verify-alg");
  check("embedded: Signature without SignedInfo -> no-signed-info",
    code(_craftSig({ noSignedInfo: true })) === "auth-saml/no-signed-info");
  check("embedded: unsupported CanonicalizationMethod -> unsupported-c14n",
    code(_craftSig({ canon: "http://example/bogus-c14n" })) === "auth-saml/unsupported-c14n");
  check("embedded: SignedInfo without Reference -> no-reference",
    code(_craftSig({ sigMethod: MLDSA65_URN, omitReference: true })) === "auth-saml/no-reference");
  check("embedded: non-fragment Reference URI -> external-reference",
    code(_craftSig({ sigMethod: MLDSA65_URN, refUri: "https://evil.example/x" })) === "auth-saml/external-reference");
  check("embedded: Reference URI != root ID -> ref-mismatch",
    code(_craftSig({ sigMethod: MLDSA65_URN, refUri: "#other" }), "_x") === "auth-saml/ref-mismatch");
  check("embedded: unsupported DigestMethod -> unsupported-digest",
    code(_craftSig({ sigMethod: MLDSA65_URN, refId: "_x", digestMethod: "http://example/bogus-digest" }), "_x") === "auth-saml/unsupported-digest");
  check("embedded: empty DigestValue -> no-digest-value",
    code(_craftSig({ sigMethod: MLDSA65_URN, refId: "_x", digestMethod: SHA3_512, digestValue: "" }), "_x") === "auth-saml/no-digest-value");

  // no-signature-value: a validly-signed post whose SignatureValue is blanked
  // (the digest still matches, so the branch after the digest gate fires).
  var rsa = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });                       // allow:raw-byte-literal — RFC 8301 §3.1 RSA bit floor
  var skPem = rsa.privateKey.export({ type: "pkcs8", format: "pem" });
  var pkPem = rsa.publicKey.export({ type: "spki", format: "pem" });
  var post = sp.buildLogoutRequestPost({ nameId: "a@idp", signingKey: skPem, signingAlg: "rsa-sha256" });
  var blanked = Buffer.from(post.samlRequest, "base64").toString("utf8")
    .replace(/<ds:SignatureValue>[^<]*<\/ds:SignatureValue>/, "<ds:SignatureValue></ds:SignatureValue>");
  check("embedded: empty SignatureValue (valid digest) -> no-signature-value",
    _codeOf(function () { sp.parseLogoutRequestPost(b64(blanked), { idpVerifyKey: pkPem, idpVerifyAlg: "rsa-sha256" }); }) === "auth-saml/no-signature-value");

  // sig-verify-threw: valid signed post, verify with a malformed ml-dsa key.
  var post2 = sp.buildLogoutRequestPost({ nameId: "a@idp", signingKey: kp.secretKey, signingAlg: "ml-dsa-65" });
  check("embedded: signature verify throws on malformed key -> sig-verify-threw",
    _codeOf(function () { sp.parseLogoutRequestPost(post2.samlRequest, { idpVerifyKey: new Uint8Array(5), idpVerifyAlg: "ml-dsa-65" }); }) === "auth-saml/sig-verify-threw");
}

// ---------------------------------------------------------------------------
// EncryptedAssertion — content-cipher + XChaCha20 length pre-checks
// ---------------------------------------------------------------------------

function testEncryptedExtra(idp) {
  var sp = _mkSp(idp.certPem);
  var rsa = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });                       // allow:raw-byte-literal — RFC 8301 §3.1 RSA bit floor
  var spPriv = rsa.privateKey.export({ type: "pkcs8", format: "pem" });
  var spPub = rsa.publicKey.export({ type: "spki", format: "pem" });
  function wrap(cek) { return nodeCrypto.publicEncrypt({ key: spPub, padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, cek).toString("base64"); }
  function verifyEnc(encInner) { return _verifyCode(sp, b64(_response(STATUS_OK + encInner)), { spPrivateKeyPem: spPriv }); }

  var noContent = "<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc=\"" + XENC + "\">" +
    "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"></xenc:EncryptionMethod>" +
    "<ds:KeyInfo xmlns:ds=\"" + DS + "\"><xenc:EncryptedKey xmlns:xenc=\"" + XENC + "\">" +
    "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#rsa-oaep\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod></xenc:EncryptionMethod>" +
    "<xenc:CipherData><xenc:CipherValue>" + wrap(nodeCrypto.randomBytes(32)) + "</xenc:CipherValue></xenc:CipherData>" +   // allow:raw-byte-literal — AES-256 key
    "</xenc:EncryptedKey></ds:KeyInfo></xenc:EncryptedData></saml:EncryptedAssertion>";
  check("encrypted: EncryptedData without content CipherValue -> encrypted-no-content-cipher-value",
    verifyEnc(noContent) === "auth-saml/encrypted-no-content-cipher-value");

  // XChaCha20-Poly1305 length pre-checks (fire before the AEAD call).
  check("encrypted: XChaCha20 wrong CEK length -> encrypted-wrong-cek-len",
    verifyEnc(_encData({ contentAlg: XCHACHA_URN, wrapped: wrap(nodeCrypto.randomBytes(16)), content: "AA==" })) === "auth-saml/encrypted-wrong-cek-len");
  check("encrypted: XChaCha20 content shorter than nonce+tag -> encrypted-content-too-short",
    verifyEnc(_encData({ contentAlg: XCHACHA_URN, wrapped: wrap(nodeCrypto.randomBytes(32)), content: Buffer.alloc(10).toString("base64") })) === "auth-saml/encrypted-content-too-short");
}

// ---------------------------------------------------------------------------
// EncryptedAssertion — PQC-first key transport + content encryption round trips
//   ML-KEM-1024 key transport (urn:blamejs:experimental:xmlenc:ml-kem-1024)
//   XChaCha20-Poly1305 content (urn:blamejs:experimental:xmlenc:xchacha20-poly1305)
// These exercise the two framework-experimental decrypt paths end to end:
// _decryptEncryptedAssertion must call real, exported b.crypto primitives
// (the envelope opener + the packed XChaCha20-Poly1305 AEAD), not symbols
// crypto.js never exposed.
// ---------------------------------------------------------------------------

var MLKEM_URN = "urn:blamejs:experimental:xmlenc:ml-kem-1024";

// AES-256-GCM content framing (nonce(12) || ciphertext || tag(16)) — the wire
// shape _decryptEncryptedAssertion reads for the AES-GCM content branch.
function _gcmContent(cek, buf) {
  var iv = nodeCrypto.randomBytes(12);                                                            // allow:raw-byte-literal — GCM 96-bit IV
  var cipher = nodeCrypto.createCipheriv("aes-256-gcm", cek, iv);
  var ct = Buffer.concat([cipher.update(buf), cipher.final()]);
  return Buffer.concat([iv, ct, cipher.getAuthTag()]).toString("base64");
}

// XChaCha20-Poly1305 content framing (nonce(24) || ciphertext || tag(16)).
// b.crypto.encryptPacked emits a 1-byte format tag + that exact tail; strip
// the format byte to leave the XMLEnc CipherValue the SAML reader expects.
function _xchachaContent(cek, buf) {
  var packed = b.crypto.encryptPacked(buf, cek);                                                  // [fmt(1) | nonce(24) | ct+tag]
  return packed.subarray(1).toString("base64");
}

// Wrap a CEK in the framework ML-KEM-1024 KEM-only envelope; the envelope's
// plaintext IS the CEK. Passing only the ML-KEM public key selects the
// KEM-only suite (no P-384 hybrid leg) that the SAML urn expects.
function _wrapMlkem(spPubMlkem, cek) { return b.crypto.encrypt(cek, spPubMlkem); }

function testEncryptedAssertionPqc(idp) {
  var sp = _mkSp(idp.certPem);
  var clear = _buildAssertion(idp, { tag: "pqc-enc" }).full;

  // SP holds an ML-KEM-1024 keypair for PQC key transport.
  var mlkemKp = b.crypto.generateEncryptionKeyPair();       // { publicKey: ml-kem-1024, privateKey, ec... }

  // RSA keypair for the mixed RSA-transport + XChaCha-content case.
  var rsa = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });                       // allow:raw-byte-literal — RFC 8301 §3.1 RSA bit floor
  var rsaPriv = rsa.privateKey.export({ type: "pkcs8", format: "pem" });
  var rsaPub = rsa.publicKey.export({ type: "spki", format: "pem" });
  function wrapRsa(cek) {
    return nodeCrypto.publicEncrypt({ key: rsaPub, padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, cek).toString("base64");
  }

  // Case A — ML-KEM-1024 key transport + AES-256-GCM content. Isolates the
  // envelope-unwrap primitive (bug 1): pre-fix, the ml-kem branch called the
  // never-exported bCrypto.decryptEnvelope and threw encrypted-key-unwrap-failed.
  var cekA = nodeCrypto.randomBytes(32);                                                          // allow:raw-byte-literal — AES-256 key
  var xmlA = b64(_response(STATUS_OK + _encData({
    keyAlg: MLKEM_URN, oaepDigest: null,
    wrapped: _wrapMlkem(mlkemKp.publicKey, cekA),
    content: _gcmContent(cekA, Buffer.from(clear, "utf8")),
  })));
  check("encrypted(pqc): ML-KEM-1024 key transport + AES-256-GCM -> nameId",
    sp.verifyResponse(xmlA, { spPrivateKeyPem: mlkemKp.privateKey }).nameId === "alice@example.com");

  // Case B — RSA-OAEP-SHA256 key transport + XChaCha20-Poly1305 content.
  // Isolates the AEAD content primitive (bug 2): pre-fix, the xchacha branch
  // called the never-exported bCrypto.aeadDecrypt and threw content-tag-mismatch.
  var cekB = nodeCrypto.randomBytes(32);                                                          // allow:raw-byte-literal — XChaCha20 key
  var xmlB = b64(_response(STATUS_OK + _encData({
    contentAlg: XCHACHA_URN,
    wrapped: wrapRsa(cekB),
    content: _xchachaContent(cekB, Buffer.from(clear, "utf8")),
  })));
  check("encrypted(pqc): RSA-OAEP-SHA256 + XChaCha20-Poly1305 content -> nameId",
    sp.verifyResponse(xmlB, { spPrivateKeyPem: rsaPriv }).nameId === "alice@example.com");

  // Case C — full PQC-first path: ML-KEM-1024 key transport + XChaCha20-Poly1305
  // content (both fixed primitives in one assertion).
  var cekC = nodeCrypto.randomBytes(32);                                                          // allow:raw-byte-literal — XChaCha20 key
  var xmlC = b64(_response(STATUS_OK + _encData({
    keyAlg: MLKEM_URN, oaepDigest: null, contentAlg: XCHACHA_URN,
    wrapped: _wrapMlkem(mlkemKp.publicKey, cekC),
    content: _xchachaContent(cekC, Buffer.from(clear, "utf8")),
  })));
  check("encrypted(pqc): ML-KEM-1024 + XChaCha20-Poly1305 full PQC path -> nameId",
    sp.verifyResponse(xmlC, { spPrivateKeyPem: mlkemKp.privateKey }).nameId === "alice@example.com");

  // Authentication must still hold: a single flipped byte in the XChaCha20
  // ciphertext+tag fails the Poly1305 verification (the fix routes through
  // the real AEAD, it does not skip the tag check).
  var packedBad = b.crypto.encryptPacked(Buffer.from(clear, "utf8"), cekC);                       // [fmt(1) | nonce(24) | ct+tag]
  packedBad[packedBad.length - 1] ^= 0xff;                                                        // allow:raw-byte-literal — corrupt the Poly1305 tag
  var xmlBad = b64(_response(STATUS_OK + _encData({
    keyAlg: MLKEM_URN, oaepDigest: null, contentAlg: XCHACHA_URN,
    wrapped: _wrapMlkem(mlkemKp.publicKey, cekC),
    content: packedBad.subarray(1).toString("base64"),
  })));
  check("encrypted(pqc): XChaCha20 tampered tag -> encrypted-content-tag-mismatch",
    _verifyCode(sp, xmlBad, { spPrivateKeyPem: mlkemKp.privateKey }) === "auth-saml/encrypted-content-tag-mismatch");

  // A corrupt ML-KEM envelope still fails closed as an unwrap error (no
  // silent accept of an undecryptable key transport).
  check("encrypted(pqc): corrupt ML-KEM envelope -> encrypted-key-unwrap-failed",
    _verifyCode(sp, b64(_response(STATUS_OK + _encData({
      keyAlg: MLKEM_URN, oaepDigest: null, contentAlg: XCHACHA_URN,
      wrapped: nodeCrypto.randomBytes(64).toString("base64"),
      content: _xchachaContent(cekC, Buffer.from(clear, "utf8")),
    }))), { spPrivateKeyPem: mlkemKp.privateKey }) === "auth-saml/encrypted-key-unwrap-failed");
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

  var idp   = await _mint("idp.example");
  var other = await _mint("other-idp.example");
  var client = await _mint("client.example");
  var otherClient = await _mint("other-client.example");
  var fed   = await _mint("federation.example");

  // _verifyXmldsig
  testVerifyXmldsigStructural(idp);
  testVerifyXmldsigNoSignatureValue(idp);
  testVerifyXmldsigBadSignature(idp, other);
  await testVerifyXmldsigEcdsa();
  testVerifyXmldsigWithComments(idp);
  // verifyResponse signed-path
  testResponseLevelSignature(idp);
  testAssertionSignedDifferentElement(idp);
  testNoValidConfirmation(idp);
  testHolderOfKey(idp, client, otherClient);
  testHolderOfKeyInResponseTo(idp, client);
  testConditionsAndAudience(idp);
  testVerifyResponseMissingFields(idp);
  testNameIdCommentTruncation(idp);
  testMoreVerifyResponse(idp);
  testEncryptedAssertion(idp);
  testEncryptedExtra(idp);
  testEncryptedAssertionPqc(idp);
  // SLO
  testSloPostBindings();
  testSloRedirectAndParse();
  testSloExtraBranches();
  testEmbeddedXmlDsigStructural();
  // fetchMdq
  await testFetchMdqBranches(fed);
}

if (require.main === module) {
  run().then(function () {
    console.log("OK — " + helpers.getChecks() + " checks passed");
    process.exit(0);
  }).catch(function (e) { console.error(e && e.stack || e); process.exit(1); });
}
module.exports = { run: run };
