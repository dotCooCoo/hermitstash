"use strict";
/**
 * b.auth.saml SLO (Single Logout) — HTTP-Redirect binding with
 * canonical query-string signature per SAML Bindings §3.4.4.1.
 * v0.10.16 closes the largest item from the v0.10.15 SAML SLO plan.
 */

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
var pq = require("../../lib/pqc-software");
var nodeCrypto = require("node:crypto");

function _newSp() {
  return b.auth.saml.sp.create({
    entityId:                    "https://sp.example/saml",
    assertionConsumerServiceUrl: "https://sp.example/acs",
    idpEntityId:                 "https://idp.example/saml",
    idpSsoUrl:                   "https://idp.example/sso",
    idpSloUrl:                   "https://idp.example/slo",
    idpCertPem:                  "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----",
  });
}

function _stripQuery(url) { return url.split("?")[1]; }
function _samlReq(query)  { return decodeURIComponent(query.split("&")[0].slice("SAMLRequest=".length)); }
function _samlResp(query) { return decodeURIComponent(query.split("&")[0].slice("SAMLResponse=".length)); }

function testBuildLogoutRequestShape() {
  var sp = _newSp();
  var lr = sp.buildLogoutRequest({ nameId: "alice", sessionIndex: "_s" });
  check("buildLogoutRequest returns id",      typeof lr.id === "string" && lr.id.length > 0);
  check("buildLogoutRequest returns URL",     typeof lr.redirectUrl === "string" && lr.redirectUrl.indexOf("https://idp.example/slo") === 0);
  check("buildLogoutRequest URL has SAMLRequest param",
    lr.redirectUrl.indexOf("SAMLRequest=") !== -1);
  check("unsigned LogoutRequest has no Signature param",
    lr.redirectUrl.indexOf("Signature=") === -1);
}

function testBuildLogoutRequestSignedMlDsa65() {
  var sp = _newSp();
  var kp = pq.ml_dsa_65.keygen();
  var lr = sp.buildLogoutRequest({ nameId: "alice", sessionIndex: "_s",
    signingKey: kp.secretKey, signingAlg: "ml-dsa-65" });
  check("signed LogoutRequest has &Signature=",
    lr.redirectUrl.indexOf("&Signature=") !== -1);
  check("signed LogoutRequest has &SigAlg=",
    lr.redirectUrl.indexOf("&SigAlg=") !== -1);
}

function testRoundtripSignedMlDsa65() {
  var sp = _newSp();
  var kp = pq.ml_dsa_65.keygen();
  var lr = sp.buildLogoutRequest({ nameId: "alice@idp", sessionIndex: "_s-9876",
    signingKey: kp.secretKey, signingAlg: "ml-dsa-65" });
  var q = _stripQuery(lr.redirectUrl);
  var samlReq = _samlReq(q);
  var parsed = sp.parseLogoutRequest(samlReq, {
    queryString: q, idpVerifyKey: kp.publicKey, idpVerifyAlg: "ml-dsa-65",
  });
  check("parseLogoutRequest recovers nameId",       parsed.nameId === "alice@idp");
  check("parseLogoutRequest recovers sessionIndex", parsed.sessionIndex === "_s-9876");
  check("parseLogoutRequest recovers id",           parsed.id === lr.id);
  check("parseLogoutRequest recovers issuer",
    parsed.issuer === "https://sp.example/saml");
}

function testRoundtripSignedMlDsa87() {
  var sp = _newSp();
  var kp = pq.ml_dsa_87.keygen();
  var lr = sp.buildLogoutRequest({ nameId: "u", sessionIndex: "_s",
    signingKey: kp.secretKey, signingAlg: "ml-dsa-87" });
  var q = _stripQuery(lr.redirectUrl);
  var parsed = sp.parseLogoutRequest(_samlReq(q), {
    queryString: q, idpVerifyKey: kp.publicKey, idpVerifyAlg: "ml-dsa-87",
  });
  check("ML-DSA-87 SLO roundtrip", parsed.nameId === "u");
}

function testWrongKeyRefused() {
  var sp = _newSp();
  var kp  = pq.ml_dsa_65.keygen();
  var kp2 = pq.ml_dsa_65.keygen();
  var lr = sp.buildLogoutRequest({ nameId: "x", sessionIndex: "_s",
    signingKey: kp.secretKey, signingAlg: "ml-dsa-65" });
  var q = _stripQuery(lr.redirectUrl);
  var threw = null;
  try { sp.parseLogoutRequest(_samlReq(q), { queryString: q, idpVerifyKey: kp2.publicKey, idpVerifyAlg: "ml-dsa-65" }); }
  catch (e) { threw = e.code; }
  check("wrong verify key → auth-saml/bad-signature", threw === "auth-saml/bad-signature");
}

function testFlippedSignatureRefused() {
  var sp = _newSp();
  var kp = pq.ml_dsa_65.keygen();
  var lr = sp.buildLogoutRequest({ nameId: "x", sessionIndex: "_s",
    signingKey: kp.secretKey, signingAlg: "ml-dsa-65" });
  var q = _stripQuery(lr.redirectUrl);
  var qBad = q.replace(/&Signature=([^&]+)/, function (_m, b64) {
    var bytes = Buffer.from(decodeURIComponent(b64), "base64");
    bytes[0] ^= 0x01;
    return "&Signature=" + encodeURIComponent(bytes.toString("base64"));
  });
  var threw = null;
  try { sp.parseLogoutRequest(_samlReq(q), { queryString: qBad, idpVerifyKey: kp.publicKey, idpVerifyAlg: "ml-dsa-65" }); }
  catch (e) { threw = e.code; }
  check("flipped-bit signature refused", threw === "auth-saml/bad-signature");
}

function testMissingSignatureRefused() {
  var sp = _newSp();
  var lr = sp.buildLogoutRequest({ nameId: "x", sessionIndex: "_s" });
  var q = _stripQuery(lr.redirectUrl);
  var threw = null;
  try {
    sp.parseLogoutRequest(_samlReq(q), {
      queryString: q,
      idpVerifyKey: pq.ml_dsa_65.keygen().publicKey,
      idpVerifyAlg: "ml-dsa-65",
    });
  } catch (e) { threw = e.code; }
  check("missing-signature refused when verifyKey supplied", threw === "auth-saml/no-signature");
}

function testBuildLogoutResponse() {
  var sp = _newSp();
  var kp = pq.ml_dsa_65.keygen();
  var lr = sp.buildLogoutResponse({
    inResponseTo: "_orig-id-123",
    destination:  "https://idp.example/slo",
    signingKey:   kp.secretKey,
    signingAlg:   "ml-dsa-65",
  });
  check("buildLogoutResponse returns id",     typeof lr.id === "string");
  check("buildLogoutResponse URL has SAMLResponse param",
    lr.redirectUrl.indexOf("SAMLResponse=") !== -1);
  check("buildLogoutResponse signed",
    lr.redirectUrl.indexOf("&Signature=") !== -1);
  // The XML contains InResponseTo + Success status.
  check("buildLogoutResponse XML names InResponseTo",
    lr.raw.indexOf("InResponseTo=\"_orig-id-123\"") !== -1);
  check("buildLogoutResponse XML names Success",
    lr.raw.indexOf("urn:oasis:names:tc:SAML:2.0:status:Success") !== -1);
}

function testBuildLogoutRequestBadSigningKey() {
  var sp = _newSp();
  var threw = null;
  try {
    sp.buildLogoutRequest({ nameId: "x", sessionIndex: "_s",
      signingKey: "not-a-uint8array", signingAlg: "ml-dsa-65" });
  } catch (e) { threw = e.code; }
  check("non-Uint8Array signingKey refused", threw === "auth-saml/bad-signing-key");
}

function testBuildLogoutRequestBadAlg() {
  var sp = _newSp();
  var kp = pq.ml_dsa_65.keygen();
  var threw = null;
  try {
    sp.buildLogoutRequest({ nameId: "x", sessionIndex: "_s",
      signingKey: kp.secretKey, signingAlg: "not-a-real-alg" });
  } catch (e) { threw = e.code; }
  check("unknown signingAlg refused", threw === "auth-saml/bad-signing-alg");
}

function testRoundtripSignedRsaSha256() {
  // Classical RSA-SHA-256 — interop with deployed IdPs (ADFS / Azure AD /
  // Okta / Keycloak / OneLogin) that haven't moved to PQC. The SP
  // signs the SAMLRequest and parses it back through the matching
  // public-key path; signature verification must round-trip.
  var sp = _newSp();
  var kp = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });                    // allow:raw-byte-literal — RFC 8301 §3.1 RSA bit floor
  var skPem = kp.privateKey.export({ type: "pkcs8", format: "pem" });
  var pkPem = kp.publicKey.export({ type: "spki", format: "pem" });
  var lr = sp.buildLogoutRequest({
    nameId: "alice", sessionIndex: "_s",
    signingKey: skPem, signingAlg: "rsa-sha256",
  });
  check("classical rsa-sha256 SAML req signed",
    lr.redirectUrl.indexOf("Signature=") !== -1);
  check("classical rsa-sha256 SAML SigAlg is W3C XMLDSig URI",
    lr.redirectUrl.indexOf("SigAlg=" + encodeURIComponent("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")) !== -1);
  var query = _stripQuery(lr.redirectUrl);
  var b64 = _samlReq(query);
  var parsed = sp.parseLogoutRequest(b64, {
    idpVerifyKey: pkPem, idpVerifyAlg: "rsa-sha256", queryString: query,
  });
  check("classical rsa-sha256 SAML req round-trips",
    parsed.id === lr.id && parsed.nameId === "alice");
}

function testRoundtripSignedEcdsaSha256() {
  // Classical ECDSA-P256 + SHA-256 — used by some Azure AD deployments
  // and the Okta "Sign SAML with EC key" feature.
  var sp = _newSp();
  var kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var skPem = kp.privateKey.export({ type: "pkcs8", format: "pem" });
  var pkPem = kp.publicKey.export({ type: "spki", format: "pem" });
  var lr = sp.buildLogoutRequest({
    nameId: "alice", sessionIndex: "_s",
    signingKey: skPem, signingAlg: "ecdsa-sha256",
  });
  check("classical ecdsa-sha256 SAML req signed",
    lr.redirectUrl.indexOf("Signature=") !== -1);
  var query = _stripQuery(lr.redirectUrl);
  var b64 = _samlReq(query);
  var parsed = sp.parseLogoutRequest(b64, {
    idpVerifyKey: pkPem, idpVerifyAlg: "ecdsa-sha256", queryString: query,
  });
  check("classical ecdsa-sha256 SAML req round-trips",
    parsed.id === lr.id && parsed.nameId === "alice");
}

function testBuildLogoutRequestSha1Refused() {
  // SHA-1 stays refused under both `rsa-sha1` and the equivalent
  // XMLDSig URI — CVE-2017-7525-class. Operators upgrade the IdP
  // digest algorithm to SHA-256+ rather than relax framework defense.
  var sp = _newSp();
  var kp = pq.ml_dsa_65.keygen();
  var threw = null;
  try {
    sp.buildLogoutRequest({ nameId: "x", sessionIndex: "_s",
      signingKey: kp.secretKey, signingAlg: "rsa-sha1" });
  } catch (e) { threw = e.code; }
  check("rsa-sha1 signingAlg refused", threw === "auth-saml/bad-signing-alg");
}

function run() {
  testBuildLogoutRequestShape();
  testBuildLogoutRequestSignedMlDsa65();
  testRoundtripSignedMlDsa65();
  testRoundtripSignedMlDsa87();
  testRoundtripSignedRsaSha256();
  testRoundtripSignedEcdsaSha256();
  testWrongKeyRefused();
  testFlippedSignatureRefused();
  testMissingSignatureRefused();
  testBuildLogoutRequestBadSigningKey();
  testBuildLogoutRequestBadAlg();
  testBuildLogoutRequestSha1Refused();
  testBuildLogoutResponse();
}

if (require.main === module) {
  try { run(); }
  catch (e) { console.error(e); process.exit(1); }
}
module.exports = { run: run };
