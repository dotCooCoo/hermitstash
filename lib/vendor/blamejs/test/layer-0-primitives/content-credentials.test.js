// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.contentCredentials — SB-942 / AB-853 / C2PA manifest builder, the
 * COSE_Sign1 interop wrapper with its RFC 3161 sigTst2 countersignature,
 * and the CAWG identity assertion. Also drives the error paths: validation
 * refusals, malformed-input rejections, fail-closed verdicts across
 * build / sign / verify / signCose / verifyCose / the identity assertion,
 * and the GB 45438-2025 CAC implicit-label gate.
 */

var helpers = require("../helpers");
var dbHelpers = require("../helpers/db");
var b     = helpers.b;
var check = helpers.check;
var fs    = helpers.fs;
var os    = helpers.os;
var path  = helpers.path;
var asn1  = require("../../lib/asn1-der");
var nodeCrypto = require("node:crypto");

// ---- RFC 3161 token-mint helpers (mock TSA, in-tree ASN.1 DER) ----
// Mirrors test/layer-0-primitives/tsa.test.js so the sigTst2
// countersignature round-trip exercises a real-shaped timestamp token
// (CMS SignedData over a TSTInfo) with full control over the imprint.
var ID_CT_TST_INFO = "1.2.840.113549.1.9.16.1.4";
var ID_KP_TIMESTAMPING = "1.3.6.1.5.5.7.3.8";
var OID_CONTENT_TYPE_ATTR = "1.2.840.113549.1.9.3";
var OID_MESSAGE_DIGEST_ATTR = "1.2.840.113549.1.9.4";
var OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
var OID_SHA512 = "2.16.840.1.101.3.4.2.3";
var OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1";

function _utcTime(d) { var s = d.toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z"; return asn1.writeNode(0x17, Buffer.from(s, "ascii")); }
function _genTime(d) { var s = d.toISOString().replace(/[-:T]/g, "").slice(0, 14) + "Z"; return asn1.writeNode(0x18, Buffer.from(s, "ascii")); }
function _algId(oid, n) { return n ? asn1.writeSequence([asn1.writeOid(oid), asn1.writeNull()]) : asn1.writeSequence([asn1.writeOid(oid)]); }
function _certName(cn) { return asn1.writeSequence([asn1.writeSet([asn1.writeSequence([asn1.writeOid("2.5.4.3"), asn1.writeUtf8String(cn)])])]); }

function _makeTsaCert() {
  var kp = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var spki = kp.publicKey.export({ type: "spki", format: "der" });
  var version = asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2])));
  var serial = asn1.writeInteger(Buffer.from([0x2a]));
  var sigAlgId = _algId("1.2.840.113549.1.1.11", true);
  var name = _certName("Test TSA");
  var now = Date.now();
  var validity = asn1.writeSequence([_utcTime(new Date(now - 86400000)), _utcTime(new Date(now + 86400000 * 3650))]);
  var ekuChildren = [asn1.writeOid("2.5.29.37"), asn1.writeBoolean(true),
    asn1.writeOctetString(asn1.writeSequence([asn1.writeOid(ID_KP_TIMESTAMPING)]))];
  var exts = [asn1.writeSequence(ekuChildren)];
  var children = [version, serial, sigAlgId, name, validity, name, spki, asn1.writeContextExplicit(3, asn1.writeSequence(exts))];
  var tbs = asn1.writeSequence(children);
  var tbsSig = nodeCrypto.sign("sha256", tbs, kp.privateKey);
  var certDer = asn1.writeSequence([tbs, sigAlgId, asn1.writeBitString(tbsSig, 0)]);
  return { certDer: certDer, key: kp.privateKey, serial: Buffer.from([0x2a]), issuer: name };
}

// Build an X.509 cert for `cn`, signed by `issuer` ({ name, key }) or
// self-signed (issuer null). Used to assemble a real [leaf, intermediate,
// root] chain so the identity-assertion chain walk is exercised through
// an intermediate CA, not only a direct-root / self-signed leaf.
function _makeCert(cn, issuer, isCa, val) {
  var kp = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var spki = kp.publicKey.export({ type: "spki", format: "der" });
  var subjName  = _certName(cn);
  var issuerName = issuer ? issuer.name : subjName;
  var issuerKey  = issuer ? issuer.key  : kp.privateKey;
  var sigAlgId = _algId("1.2.840.113549.1.1.11", true);
  var version = asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2])));
  var serial = asn1.writeInteger(Buffer.from([0x2b]));
  var now = Date.now();
  // Default validity is a wide now-1d..now+10y window; `val` ({ from, to } in
  // epoch-ms) lets a caller mint an already-expired cert so the chain walk's
  // per-cert and anchor validity-window rejections are exercised.
  var vFrom = val && val.from != null ? val.from : now - 86400000;
  var vTo   = val && val.to   != null ? val.to   : now + 86400000 * 3650;
  var validity = asn1.writeSequence([_utcTime(new Date(vFrom)), _utcTime(new Date(vTo))]);
  var tbsChildren = [version, serial, sigAlgId, issuerName, validity, subjName, spki];
  // Issuer (root / intermediate) certs carry basicConstraints cA:TRUE so the
  // chain walk's cA enforcement (x509Chain.issuerValidlyIssued) accepts them;
  // a leaf omits it (cA:FALSE) as a real end-entity cert does.
  if (isCa) {
    var bcExt = asn1.writeSequence([
      asn1.writeOid("2.5.29.19"),                                  // basicConstraints
      asn1.writeBoolean(true),                                     // critical
      asn1.writeOctetString(asn1.writeSequence([asn1.writeBoolean(true)])),  // { cA TRUE }
    ]);
    tbsChildren.push(asn1.writeContextExplicit(3, asn1.writeSequence([bcExt])));
  }
  var tbs = asn1.writeSequence(tbsChildren);
  var tbsSig = nodeCrypto.sign("sha256", tbs, issuerKey);
  var certDer = asn1.writeSequence([tbs, sigAlgId, asn1.writeBitString(tbsSig, 0)]);
  return { name: subjName, key: kp.privateKey, pem: new nodeCrypto.X509Certificate(certDer).toString() };
}

function _makeTsToken(o) {
  var tstChildren = [
    asn1.writeInteger(Buffer.from([1])),
    asn1.writeOid("1.2.3.4.1"),
    asn1.writeSequence([_algId(OID_SHA512, true), asn1.writeOctetString(o.imprintHash)]),
    asn1.writeInteger(Buffer.from([0x05])),
    _genTime(new Date()),
  ];
  if (o.nonce) tstChildren.push(asn1.writeInteger(o.nonce));
  var tstInfo = asn1.writeSequence(tstChildren);
  var msgDigest = nodeCrypto.createHash("sha512").update(tstInfo).digest();
  var ctAttr = asn1.writeSequence([asn1.writeOid(OID_CONTENT_TYPE_ATTR), asn1.writeSet([asn1.writeOid(ID_CT_TST_INFO)])]);
  var mdAttr = asn1.writeSequence([asn1.writeOid(OID_MESSAGE_DIGEST_ATTR), asn1.writeSet([asn1.writeOctetString(msgDigest)])]);
  var signedSet = asn1.writeSet([ctAttr, mdAttr]);
  var sig = nodeCrypto.sign("sha512", signedSet, o.key);
  var signedAttrsImplicit = Buffer.concat([Buffer.from([0xa0]), signedSet.slice(1)]);
  var sid = asn1.writeSequence([o.issuer, asn1.writeInteger(o.serial)]);
  var signerInfo = asn1.writeSequence([
    asn1.writeInteger(Buffer.from([1])), sid, _algId(OID_SHA512, true), signedAttrsImplicit,
    _algId(OID_RSA_ENCRYPTION, true), asn1.writeOctetString(sig),
  ]);
  var encap = asn1.writeSequence([asn1.writeOid(ID_CT_TST_INFO), asn1.writeContextExplicit(0, asn1.writeOctetString(tstInfo))]);
  var certsField = asn1.writeContextImplicit(0, o.certDer, { constructed: true });
  var signedData = asn1.writeSequence([
    asn1.writeInteger(Buffer.from([3])), asn1.writeSet([_algId(OID_SHA512, true)]),
    encap, certsField, asn1.writeSet([signerInfo]),
  ]);
  return asn1.writeSequence([asn1.writeOid(OID_SIGNED_DATA), asn1.writeContextExplicit(0, signedData)]);
}

// Drive a full signCose request→TSA→attach→verify round trip and return
// { attached, verifyResult, anchorPem, nonce }.
function _timestampedRoundTrip(manifest, pair) {
  var req = b.contentCredentials.signCose(manifest, {
    privateKeyPem: pair.privateKey, alg: "ml-dsa-87", timestamp: {}, audit: false,
  });
  var digest = nodeCrypto.createHash("sha512").update(req.timestampRequest.toBeSigned).digest();
  var cert = _makeTsaCert();
  var token = _makeTsToken({
    certDer: cert.certDer, key: cert.key, issuer: cert.issuer, serial: cert.serial,
    imprintHash: digest, nonce: req.timestampRequest.nonce,
  });
  var attached = b.contentCredentials.signCose(manifest, {
    privateKeyPem: pair.privateKey, alg: "ml-dsa-87",
    timestamp: { token: token, signature: req.timestampRequest.signature }, audit: false,
  });
  var anchorPem = new nodeCrypto.X509Certificate(cert.certDer).toString();
  return { req: req, attached: attached, cert: cert, token: token, anchorPem: anchorPem };
}

// ---- error-path fixtures ----

var cc = b.contentCredentials;

// Capture the error a thrower raises (or null when it does not throw) —
// one definition so the many config-time refusal checks below don't each
// re-roll a `threw = null; try {} catch {}` block.
function _err(fn) {
  try { fn(); return null; } catch (e) { return e; }
}

var VALID_BUILD = {
  provider: "Acme AI Inc.", system: "acme-image-v3",
  systemVersion: "3.2.1", contentId: "img-001",
};
function _buildOpts(overrides) {
  return Object.assign({}, VALID_BUILD, overrides);
}

// Error-path + adversarial-input checks: the validation refusals,
// malformed-input rejections, wrong-state protocol errors, and
// fail-closed verdicts the round-trip checks in run() never reach —
// bad build opts, missing required fields, signCose timestamp-posture
// and reuse-signature refusals, verifyCose malformed-CBOR / bad hashAlg
// / wrong-key verdicts, CAWG identity-assertion shape + trust-resolution
// refusals, and the GB 45438-2025 CAC implicit-label gate.
async function runErrorPaths() {
  var e;

  // ---- build() / _validateBuildOpts adversarial input ----
  check("build(null) rejected as bad-opts",
    (e = _err(function () { cc.build(null); })) && e.code === "content-credentials/bad-opts");
  check("build('str') rejected as bad-opts",
    (e = _err(function () { cc.build("nope"); })) && e.code === "content-credentials/bad-opts");

  check("build missing system rejected",
    (e = _err(function () { cc.build({ provider: "x", systemVersion: "1.0.0", contentId: "y" }); })) &&
    e.code === "MISSING_SYSTEM");
  check("build missing systemVersion rejected",
    (e = _err(function () { cc.build({ provider: "x", system: "s", contentId: "y" }); })) &&
    e.code === "MISSING_SYSTEMVERSION");
  check("build missing contentId rejected",
    (e = _err(function () { cc.build({ provider: "x", system: "s", systemVersion: "1.0.0" }); })) &&
    e.code === "MISSING_CONTENTID");

  check("build provider over 256 chars rejected",
    (e = _err(function () { cc.build(_buildOpts({ provider: "a".repeat(257) })); })) &&
    e.code === "content-credentials/bad-provider");
  check("build system with illegal chars rejected",
    (e = _err(function () { cc.build(_buildOpts({ system: "has space!" })); })) &&
    e.code === "content-credentials/bad-system");
  check("build systemVersion over 64 chars rejected",
    (e = _err(function () { cc.build(_buildOpts({ systemVersion: "1.0.0-" + "a".repeat(60) })); })) &&
    e.code === "content-credentials/bad-version");
  check("build contentId with illegal chars rejected",
    (e = _err(function () { cc.build(_buildOpts({ contentId: "bad id!" })); })) &&
    e.code === "content-credentials/bad-content-id");
  check("build contentSha3 wrong length rejected",
    (e = _err(function () { cc.build(_buildOpts({ contentSha3: "abc123" })); })) &&
    e.code === "content-credentials/bad-content-hash");
  check("build contentSha3 non-hex rejected",
    (e = _err(function () { cc.build(_buildOpts({ contentSha3: "z".repeat(128) })); })) &&
    e.code === "content-credentials/bad-content-hash");

  // Valid optional fields flow through (providerContact / sha3 / visibleDisclosure).
  var mFull = cc.build(_buildOpts({
    providerContact: "https://acme.example/contact",
    contentType: "image/png", contentSha3: "a".repeat(128),
    visibleDisclosure: "AI-generated by Acme",
  }));
  check("build carries optional contentSha3", mFull.content.sha3_512 === "a".repeat(128));
  check("build carries providerContact", mFull.provider.contact === "https://acme.example/contact");
  check("build carries visibleDisclosure", mFull.visibleDisclosure === "AI-generated by Acme");

  // Adversarial numeric generatedAt (NaN) must not yield a manifest whose
  // ISO timestamp is a broken value — either a clean rejection or a valid
  // ISO string is acceptable; an unparseable generatedAtIso is not.
  var nanRes = null, nanErr = null;
  try { nanRes = cc.build(_buildOpts({ generatedAt: NaN })); } catch (ne) { nanErr = ne; }
  check("build NaN generatedAt: rejected or valid ISO (no Invalid-Date manifest)",
    nanErr !== null || (nanRes && !isNaN(Date.parse(nanRes.generatedAtIso))));

  // ---- required() ----
  check("required(null) returns opts-required",
    JSON.stringify(cc.required(null)) === JSON.stringify(["opts-required"]));
  check("required('str') returns opts-required",
    JSON.stringify(cc.required("x")) === JSON.stringify(["opts-required"]));
  var reqNonString = cc.required({ provider: 123, system: "s", systemVersion: "1.0.0", contentId: "c" });
  check("required treats non-string provider as missing",
    reqNonString.length === 1 && reqNonString[0] === "missing-provider");

  // ---- sign() ----
  var pair = b.crypto.generateSigningKeyPair("ml-dsa-87");
  var manifest = cc.build(VALID_BUILD);

  check("sign(null) rejected as bad-manifest",
    (e = _err(function () { cc.sign(null, { privateKeyPem: pair.privateKey }); })) &&
    e.code === "content-credentials/bad-manifest");
  check("sign missing privateKeyPem rejected",
    (e = _err(function () { cc.sign(manifest, {}); })) && e.code === "BAD_KEY");
  check("sign no opts rejected",
    (e = _err(function () { cc.sign(manifest); })) && e.code === "BAD_KEY");

  // ---- verify() fail-closed verdicts (never throws) ----
  var env = cc.sign(manifest, { privateKeyPem: pair.privateKey, audit: false });
  check("verify(null) returns envelope-shape", cc.verify(null, pair.publicKey, { audit: false }).reason === "envelope-shape");
  check("verify({}) returns envelope-shape", cc.verify({}, pair.publicKey, { audit: false }).reason === "envelope-shape");
  check("verify empty signature returns envelope-shape",
    cc.verify({ manifest: manifest, signature: "" }, pair.publicKey, { audit: false }).reason === "envelope-shape");
  check("verify non-string key returns public-key-required",
    cc.verify(env, 123, { audit: false }).reason === "public-key-required");
  check("verify empty key returns public-key-required",
    cc.verify(env, "", { audit: false }).reason === "public-key-required");

  // A cryptographically valid signature over a payload that is NOT a
  // complete SB-942 manifest must still fail the required-field gate.
  var envPartial = cc.sign({ foo: "bar" }, { privateKeyPem: pair.privateKey, audit: false });
  var vPartial = cc.verify(envPartial, pair.publicKey, { audit: false });
  check("verify valid-sig-but-incomplete-manifest returns missing-required",
    vPartial.valid === false && vPartial.reason.indexOf("missing-required") === 0);

  // ---- signCose() config-time refusals ----
  check("signCose(null) rejected as bad-manifest",
    (e = _err(function () { cc.signCose(null, { privateKeyPem: pair.privateKey }); })) &&
    e.code === "content-credentials/bad-manifest");
  check("signCose missing privateKeyPem rejected",
    (e = _err(function () { cc.signCose(manifest, { alg: "ml-dsa-87", timestamp: false, timestampOptOutReason: "x" }); })) &&
    e.code === "BAD_KEY");
  check("signCose timestamp as string rejected",
    (e = _err(function () { cc.signCose(manifest, { privateKeyPem: pair.privateKey, timestamp: "soon" }); })) &&
    e.code === "content-credentials/bad-timestamp");
  check("signCose timestamp as array rejected",
    (e = _err(function () { cc.signCose(manifest, { privateKeyPem: pair.privateKey, timestamp: [] }); })) &&
    e.code === "content-credentials/bad-timestamp");
  check("signCose timestamp with unknown key rejected",
    (e = _err(function () { cc.signCose(manifest, { privateKeyPem: pair.privateKey, timestamp: { bogus: 1 } }); })) &&
    /unknown option/.test(e.message));
  check("signCose timestamp.token non-Buffer rejected",
    (e = _err(function () { cc.signCose(manifest, { privateKeyPem: pair.privateKey, timestamp: { token: "not-a-buffer" } }); })) &&
    e.code === "content-credentials/bad-timestamp-token");
  check("signCose timestamp.signature empty rejected",
    (e = _err(function () { cc.signCose(manifest, { privateKeyPem: pair.privateKey, timestamp: { token: Buffer.from([1]), signature: "" } }); })) &&
    e.code === "content-credentials/bad-reuse-signature");

  // An inherited Object.prototype member as the alg must not slip the COSE
  // alg-registry check. `constructor` / `__proto__` survive `.toLowerCase()`
  // and are truthy prototype-chain lookups, so an `in`-based guard would
  // accept them and emit a signature under a bogus COSE alg id (fail-open).
  check("signCose alg 'constructor' rejected (inherited member, not fail-open)",
    (e = _err(function () { cc.signCose(manifest, { privateKeyPem: pair.privateKey, alg: "constructor", timestamp: false, timestampOptOutReason: "x" }); })) &&
    e.code === "content-credentials/bad-alg");
  check("signCose alg '__proto__' rejected (inherited member, not fail-open)",
    (e = _err(function () { cc.signCose(manifest, { privateKeyPem: pair.privateKey, alg: "__proto__", timestamp: false, timestampOptOutReason: "x" }); })) &&
    e.code === "content-credentials/bad-alg");

  // Reused (pinned) signature that does not verify against this manifest+key
  // is refused — a stale or foreign signature can't be re-embedded.
  check("signCose reuse-signature that does not verify is refused",
    (e = _err(function () {
      cc.signCose(manifest, { privateKeyPem: pair.privateKey,
        timestamp: { token: Buffer.from([1, 2, 3]), signature: nodeCrypto.randomBytes(32).toString("base64") } });
    })) && e.code === "content-credentials/reuse-signature-mismatch");

  // certChain emission — single-cert and multi-cert branches (bytes are
  // carried opaquely; a non-Buffer entry is rejected, not silently kept).
  var coseSingle = cc.signCose(manifest, {
    privateKeyPem: pair.privateKey, timestamp: false, timestampOptOutReason: "x",
    certChain: [Buffer.from([1, 2, 3])], audit: false,
  });
  var coseMulti = cc.signCose(manifest, {
    privateKeyPem: pair.privateKey, timestamp: false, timestampOptOutReason: "x",
    certChain: [Buffer.from([1, 2, 3]), Buffer.from([4, 5, 6])], audit: false,
  });
  check("signCose single-cert certChain produces COSE bytes", Buffer.isBuffer(coseSingle.coseSign1));
  check("signCose multi-cert certChain grows COSE bytes", coseMulti.coseSign1.length > coseSingle.coseSign1.length);
  check("signCose non-Buffer certChain entry is rejected (throws)",
    _err(function () {
      cc.signCose(manifest, { privateKeyPem: pair.privateKey, timestamp: false,
        timestampOptOutReason: "x", certChain: ["not a buffer"] });
    }) !== null);

  // ---- verifyCose() fail-closed verdicts (never throws) ----
  var optout = cc.signCose(manifest, {
    privateKeyPem: pair.privateKey, alg: "ml-dsa-87",
    timestamp: false, timestampOptOutReason: "no TSA in test", audit: false,
  });
  check("verifyCose bad timestampHashAlg returns bad-tst-hash verdict",
    cc.verifyCose(optout.coseSign1, pair.publicKey, { timestampHashAlg: "MD5", audit: false }).reason === "content-credentials/bad-tst-hash");
  check("verifyCose non-CBOR (0x00) returns cose-malformed verdict",
    cc.verifyCose(Buffer.from([0x00]), pair.publicKey, { audit: false }).reason === "content-credentials/cose-malformed");
  check("verifyCose undecodable CBOR (0xff) returns cose-malformed verdict",
    cc.verifyCose(Buffer.from([0xff]), pair.publicKey, { audit: false }).reason === "content-credentials/cose-malformed");
  var otherPair = b.crypto.generateSigningKeyPair("ml-dsa-87");
  var vWrongKey = cc.verifyCose(optout.coseSign1, otherPair.publicKey, { requireTimestamp: false, audit: false });
  check("verifyCose wrong key returns signature-mismatch verdict",
    vWrongKey.valid === false && vWrongKey.reason === "signature-mismatch");

  // ---- attachIdentityAssertion() config-time refusals ----
  var refs = [{ label: "c2pa.actions", data: { action: "c2pa.created" } }];
  check("attach() no args rejected (bad binding)",
    (e = _err(function () { cc.attachIdentityAssertion(); })) && e.code === "content-credentials/bad-identity-binding");
  check("attach subject non-object rejected",
    (e = _err(function () { cc.attachIdentityAssertion({ binding: "x509", subject: "nope", referencedAssertions: refs, privateKeyPem: pair.privateKey }); })) &&
    e.code === "content-credentials/bad-identity-subject");
  check("attach subject array rejected",
    (e = _err(function () { cc.attachIdentityAssertion({ binding: "x509", subject: [], referencedAssertions: refs, privateKeyPem: pair.privateKey }); })) &&
    e.code === "content-credentials/bad-identity-subject");
  check("attach subject empty object rejected",
    (e = _err(function () { cc.attachIdentityAssertion({ binding: "x509", subject: {}, referencedAssertions: refs, privateKeyPem: pair.privateKey }); })) &&
    e.code === "content-credentials/bad-identity-subject");
  check("attach referencedAssertions non-array rejected",
    (e = _err(function () { cc.attachIdentityAssertion({ binding: "x509", subject: { name: "x" }, referencedAssertions: "nope", privateKeyPem: pair.privateKey }); })) &&
    e.code === "content-credentials/bad-referenced-assertions");
  check("attach referencedAssertions empty rejected",
    (e = _err(function () { cc.attachIdentityAssertion({ binding: "x509", subject: { name: "x" }, referencedAssertions: [], privateKeyPem: pair.privateKey }); })) &&
    e.code === "content-credentials/bad-referenced-assertions");
  check("attach missing privateKeyPem rejected",
    (e = _err(function () { cc.attachIdentityAssertion({ binding: "x509", subject: { name: "x" }, referencedAssertions: refs }); })) &&
    e.code === "BAD_KEY");
  check("attach unknown opt key rejected",
    (e = _err(function () { cc.attachIdentityAssertion({ binding: "x509", subject: { name: "x" }, referencedAssertions: refs, privateKeyPem: pair.privateKey, bogus: 1 }); })) &&
    /unknown option/.test(e.message));

  // ---- verifyIdentityAssertion() fail-closed verdicts (never throws) ----
  var ia = cc.attachIdentityAssertion({
    binding: "x509", subject: { name: "Acme Newsroom" },
    referencedAssertions: refs, privateKeyPem: pair.privateKey, audit: false,
  });
  check("verifyIdentity null assertion returns assertion-shape",
    cc.verifyIdentityAssertion(null, pair.publicKey, { referencedAssertions: refs }).reason === "assertion-shape");
  check("verifyIdentity missing signer_payload returns assertion-shape",
    cc.verifyIdentityAssertion({ signature: "x" }, pair.publicKey, { referencedAssertions: refs }).reason === "assertion-shape");
  check("verifyIdentity non-string key returns public-key-required",
    cc.verifyIdentityAssertion(ia, 123, { referencedAssertions: refs }).reason === "public-key-required");
  check("verifyIdentity bad signer_payload binding returns signer-payload-shape",
    cc.verifyIdentityAssertion({ signer_payload: { binding: "bogus", referenced_assertions: [] }, signature: "AA==" }, pair.publicKey, { referencedAssertions: refs }).reason === "signer-payload-shape");
  check("verifyIdentity missing referencedAssertions opt returns referenced-assertions-required",
    cc.verifyIdentityAssertion(ia, pair.publicKey, { audit: false }).reason === "referenced-assertions-required");
  check("verifyIdentity referencedAssertions count mismatch returns count-mismatch",
    cc.verifyIdentityAssertion(ia, pair.publicKey, { referencedAssertions: [refs[0], { label: "b" }], audit: false }).reason === "referenced-assertions-count-mismatch");

  // x509 trust-resolution reason branches (self-asserted -> verified:false).
  var vNoChain = cc.verifyIdentityAssertion(ia, pair.publicKey, {
    referencedAssertions: refs, identityTrustAnchorsPem: "anchor-pem", audit: false,
  });
  check("verifyIdentity anchor but no chain -> verified:false no-cert-chain",
    vNoChain.valid === true && vNoChain.verified === false && vNoChain.reason === "no-cert-chain");
  var vBadAnchors = cc.verifyIdentityAssertion(ia, pair.publicKey, {
    referencedAssertions: refs, identityCertChainPem: "chain-pem", identityTrustAnchorsPem: "", audit: false,
  });
  check("verifyIdentity empty trust anchor -> verified:false bad-trust-anchors",
    vBadAnchors.verified === false && vBadAnchors.reason === "bad-trust-anchors");
  var vBadChain = cc.verifyIdentityAssertion(ia, pair.publicKey, {
    referencedAssertions: refs, identityCertChainPem: "not a pem", identityTrustAnchorsPem: "also not a pem", audit: false,
  });
  check("verifyIdentity unparseable chain cert -> verified:false bad-chain-cert",
    vBadChain.verified === false && vBadChain.reason === "bad-chain-cert");

  // ---- cacImplicitLabel() GB 45438-2025 gate ----
  var CAC_VALID = {
    providerName: "Example AI", providerCode: "91110000600037341A",
    contentId: "asset-2026-05-17-abc123", contentKind: "image",
    generatedAt: "2026-05-17T20:00:00Z",
  };
  function _cac(overrides) { return Object.assign({}, CAC_VALID, overrides); }

  var label = cc.cacImplicitLabel(CAC_VALID);
  check("cacImplicitLabel valid returns frozen AIGC block",
    Object.isFrozen(label) && label.aigcMarker === "AIGC" && label.providerCode === "91110000600037341A");
  check("cacImplicitLabel(null) rejected",
    (e = _err(function () { cc.cacImplicitLabel(null); })) && e.code === "cac-implicit-label/bad-opts");
  check("cacImplicitLabel missing providerName rejected",
    (e = _err(function () { cc.cacImplicitLabel(_cac({ providerName: undefined })); })) &&
    e.code === "cac-implicit-label/bad-provider-name");
  check("cacImplicitLabel oversize providerName rejected",
    (e = _err(function () { cc.cacImplicitLabel(_cac({ providerName: "a".repeat(257) })); })) &&
    e.code === "cac-implicit-label/oversize-provider-name");
  check("cacImplicitLabel bad providerCode rejected",
    (e = _err(function () { cc.cacImplicitLabel(_cac({ providerCode: "123" })); })) &&
    e.code === "cac-implicit-label/bad-provider-code");
  check("cacImplicitLabel illegal contentId rejected",
    (e = _err(function () { cc.cacImplicitLabel(_cac({ contentId: "bad id!" })); })) &&
    e.code === "cac-implicit-label/bad-content-id");
  check("cacImplicitLabel unknown contentKind rejected",
    (e = _err(function () { cc.cacImplicitLabel(_cac({ contentKind: "hologram" })); })) &&
    e.code === "cac-implicit-label/bad-content-kind");
  check("cacImplicitLabel non-ISO generatedAt rejected",
    (e = _err(function () { cc.cacImplicitLabel(_cac({ generatedAt: "yesterday" })); })) &&
    e.code === "cac-implicit-label/bad-generated-at");

  // ---- cacImplicitLabelRead() parser ----
  check("cacImplicitLabelRead object input",
    cc.cacImplicitLabelRead(Object.assign({ aigcMarker: "AIGC" }, CAC_VALID)).aigcMarker === "AIGC");
  check("cacImplicitLabelRead string input",
    cc.cacImplicitLabelRead(JSON.stringify(Object.assign({ aigcMarker: "AIGC" }, CAC_VALID))).contentKind === "image");
  check("cacImplicitLabelRead Buffer input",
    cc.cacImplicitLabelRead(Buffer.from(JSON.stringify(Object.assign({ aigcMarker: "AIGC" }, CAC_VALID)))).providerCode === "91110000600037341A");
  check("cacImplicitLabelRead malformed JSON string rejected",
    (e = _err(function () { cc.cacImplicitLabelRead("{not json"); })) && e.code === "cac-implicit-label/bad-json");
  check("cacImplicitLabelRead malformed JSON Buffer rejected",
    (e = _err(function () { cc.cacImplicitLabelRead(Buffer.from("{not json")); })) && e.code === "cac-implicit-label/bad-json");
  check("cacImplicitLabelRead numeric input rejected",
    (e = _err(function () { cc.cacImplicitLabelRead(42); })) && e.code === "cac-implicit-label/bad-input");
  check("cacImplicitLabelRead missing AIGC marker rejected",
    (e = _err(function () { cc.cacImplicitLabelRead({ providerName: "x" }); })) &&
    e.code === "cac-implicit-label/missing-aigc-marker");
  check("cacImplicitLabelRead re-applies field gate",
    (e = _err(function () { cc.cacImplicitLabelRead(Object.assign({ aigcMarker: "AIGC" }, CAC_VALID, { providerCode: "BAD" })); })) &&
    e.code === "cac-implicit-label/bad-provider-code");
}

// Default-on audit branches: every build / sign / verify / signCose /
// verifyCose and the CAWG identity assertion carries an `audit !== false`
// emit block the audit:false round-trips never execute. Drive each through
// the REAL audit sink (setupTestDb wires the encrypted db + audit chain)
// and assert durable rows land — the emit does real work, not a no-op —
// covering both the success and the fail-closed "denied" audit paths.
async function runAuditOnPaths() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cc-audit-"));
  await dbHelpers.setupTestDb(tmpDir);
  try {
    var pair = b.crypto.generateSigningKeyPair("ml-dsa-87");
    var manifest = cc.build(VALID_BUILD);

    // sign() + verify() audit-on (verify called with opts omitted → opts:{}).
    var env = cc.sign(manifest, { privateKeyPem: pair.privateKey });
    check("audit-on verify still valid", cc.verify(env, pair.publicKey).valid === true);

    // signCose audit-on: opt-out (warning outcome), request, and attach.
    cc.signCose(manifest, { privateKeyPem: pair.privateKey, timestamp: false, timestampOptOutReason: "no TSA in audit test" });
    cc.signCose(manifest, { privateKeyPem: pair.privateKey, timestamp: {} });
    var rt = _timestampedRoundTrip(manifest, pair);
    var attachedAudited = cc.signCose(manifest, {
      privateKeyPem: pair.privateKey, alg: "ml-dsa-87",
      timestamp: { token: rt.token, signature: rt.req.timestampRequest.signature },
    });

    // verifyCose audit-on: success (1054-1066), signature-mismatch (967-969),
    // timestamp-required (1017-1019), timestamp-invalid (1027-1029), and
    // missing-required (1047-1049) denied-audit blocks.
    var vc = cc.verifyCose(attachedAudited.coseSign1, pair.publicKey, {
      timestampNonce: rt.req.timestampRequest.nonce, timestampTrustAnchorsPem: [rt.anchorPem],
    });
    check("audit-on verifyCose success", vc.valid === true);
    var otherPair = b.crypto.generateSigningKeyPair("ml-dsa-87");
    cc.verifyCose(attachedAudited.coseSign1, otherPair.publicKey, { requireTimestamp: false });
    var optout = cc.signCose(manifest, { privateKeyPem: pair.privateKey, timestamp: false, timestampOptOutReason: "x", audit: false });
    cc.verifyCose(optout.coseSign1, pair.publicKey);                                   // token-less → timestamp-required (opts omitted → opts:{})
    cc.verifyCose(rt.attached.coseSign1, pair.publicKey, { timestampNonce: nodeCrypto.randomBytes(8) });   // wrong nonce → timestamp-invalid
    var incompleteCose = cc.signCose({ provider: { name: "x" } }, { privateKeyPem: pair.privateKey, timestamp: false, timestampOptOutReason: "x", audit: false });
    cc.verifyCose(incompleteCose.coseSign1, pair.publicKey, { requireTimestamp: false });  // missing-required

    // attachIdentityAssertion + verifyIdentityAssertion audit-on (success/
    // warning + signature-mismatch + assertion-hash-mismatch denied audits).
    var refs = [{ label: "c2pa.actions", data: { action: "c2pa.created" } }];
    var ia = cc.attachIdentityAssertion({ binding: "x509", subject: { name: "Acme Newsroom" }, referencedAssertions: refs, privateKeyPem: pair.privateKey });
    cc.verifyIdentityAssertion(ia, pair.publicKey, { referencedAssertions: refs });                                    // self-asserted → warning
    cc.verifyIdentityAssertion(ia, otherPair.publicKey, { referencedAssertions: refs });                               // wrong key → denied
    cc.verifyIdentityAssertion(ia, pair.publicKey, { referencedAssertions: [{ label: "x", data: { other: 1 } }] });    // transplant → denied
    // x509 chained to a trusted anchor → verified:true, audit outcome "success".
    var trustCert = _makeTsaCert();
    var trustPem = new nodeCrypto.X509Certificate(trustCert.certDer).toString();
    var iaVerified = cc.verifyIdentityAssertion(ia, pair.publicKey, { referencedAssertions: refs, identityCertChainPem: trustPem, identityTrustAnchorsPem: trustPem });
    check("audit-on identity verified:true (x509 chained)", iaVerified.verified === true);

    await b.audit.flush();
    var signedRows       = await b.audit.query({ action: "contentcredentials.signed" });
    var verifiedRows     = await b.audit.query({ action: "contentcredentials.verified" });
    var signedCoseRows   = await b.audit.query({ action: "contentcredentials.signed_cose" });
    var verifiedCoseRows = await b.audit.query({ action: "contentcredentials.verified_cose" });
    var identAttachRows  = await b.audit.query({ action: "contentcredentials.identity_attached" });
    var identVerifyRows  = await b.audit.query({ action: "contentcredentials.identity_verified" });
    check("audit-on: b.contentCredentials.sign emits a durable row", signedRows.length >= 1);
    check("audit-on: b.contentCredentials.verify emits a durable row", verifiedRows.length >= 1);
    check("audit-on: b.contentCredentials.signCose emits durable rows (optout/request/attach)", signedCoseRows.length >= 3);
    check("audit-on: b.contentCredentials.verifyCose emits durable rows (success + denied)", verifiedCoseRows.length >= 4);
    check("audit-on: b.contentCredentials.attachIdentityAssertion emits a durable row", identAttachRows.length >= 1);
    check("audit-on: b.contentCredentials.verifyIdentityAssertion emits durable rows", identVerifyRows.length >= 3);
  } finally {
    await dbHelpers.teardownTestDb(tmpDir);
  }
}

// CBOR + COSE_Sign1 encode/decode edge branches: the large-length CBOR
// paths, the malformed-COSE structural rejections, the empty / non-decodable
// protected header, and the config-time input branches (numeric generatedAt,
// non-string signature, reuse-signature key mismatch) the happy-path
// round-trips never reach.
async function runCoseEdgeCases() {
  var pair = b.crypto.generateSigningKeyPair("ml-dsa-87");
  var manifest = cc.build(VALID_BUILD);

  // build(): a valid numeric generatedAt flows through the pinned-timestamp
  // branch rather than defaulting to Date.now().
  var pinned = cc.build(_buildOpts({ generatedAt: Date.UTC(2026, 4, 8) }));
  check("build honors a valid numeric generatedAt",
    pinned.generatedAt === Date.UTC(2026, 4, 8) && pinned.generatedAtIso === "2026-05-08T00:00:00.000Z");

  // verify(): a non-string (numeric) signature is truthy but Buffer.from(n)
  // throws → the base64 catch returns signature-base64-bad, never crashes.
  check("verify numeric signature returns signature-base64-bad",
    cc.verify({ manifest: manifest, signature: 12345 }, pair.publicKey, { audit: false }).reason === "signature-base64-bad");

  // signCose reuse mode with a malformed private-key PEM: _publicKeyFromPrivatePem
  // catches the createPublicKey throw and returns false → reuse mismatch.
  check("signCose reuse-mode with unparseable PEM refused as reuse-signature-mismatch",
    (function () {
      var er = _err(function () {
        cc.signCose(manifest, { privateKeyPem: "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----",
          timestamp: { token: Buffer.from([1]), signature: "AAAA" } });
      });
      return er && er.code === "content-credentials/reuse-signature-mismatch";
    })());

  // signCose with opts omitted defaults opts to {} then rejects the missing key.
  check("signCose with no opts rejected as BAD_KEY",
    (function () { var er = _err(function () { cc.signCose(manifest); }); return er && er.code === "BAD_KEY"; })());

  // signCose attach WITHOUT a re-pinned signature signs fresh (the
  // reuseSignature==null branch) and still emits a timestamped COSE.
  var attachFresh = cc.signCose(manifest, {
    privateKeyPem: pair.privateKey, timestamp: { token: Buffer.from([1, 2, 3]) }, audit: false,
  });
  check("signCose attach without reuse-signature signs fresh + timestamped",
    attachFresh.timestamped === true && Buffer.isBuffer(attachFresh.coseSign1));

  // Large certChain crosses the CBOR array-header length thresholds
  // (24 → 1-byte count header, 300 → 2-byte count header).
  function _dummyChain(n) { var a = []; for (var i = 0; i < n; i += 1) a.push(Buffer.from([i & 0xff])); return a; }
  var cose24  = cc.signCose(manifest, { privateKeyPem: pair.privateKey, timestamp: false, timestampOptOutReason: "x", certChain: _dummyChain(24), audit: false });
  var cose300 = cc.signCose(manifest, { privateKeyPem: pair.privateKey, timestamp: false, timestampOptOutReason: "x", certChain: _dummyChain(300), audit: false });
  check("signCose 24-cert chain (CBOR 1-byte array header) emits COSE bytes", Buffer.isBuffer(cose24.coseSign1));
  check("signCose 300-cert chain (CBOR 2-byte array header) grows the COSE bytes", cose300.coseSign1.length > cose24.coseSign1.length);

  // A cert chain at the CBOR array-count ceiling (65536 entries) overflows the
  // 2-byte array-header range: _cborArrayHeader refuses it fail-closed with a
  // typed cbor-overflow error rather than emitting a truncated length header
  // that would silently misframe the x5chain array. Every fixed protocol
  // codepoint (tag 18, labels 1/33/35, ≤2-entry maps) stays well below this
  // ceiling, so an operator-supplied absurd chain is the only path here.
  var overflowErr = _err(function () {
    b.contentCredentials.signCose(manifest, {
      privateKeyPem: pair.privateKey, timestamp: false,
      timestampOptOutReason: "x", certChain: _dummyChain(65536), audit: false,
    });
  });
  check("signCose certChain at the CBOR array ceiling (65536) refused as cbor-overflow",
    overflowErr && overflowErr.code === "content-credentials/cbor-overflow");

  // A >1 MiB manifest payload crosses the 4-byte CBOR byte-string length
  // path AND, on verify, exceeds the safeJson payload cap so claims parse
  // is caught (claims:null) → the required-field gate fails it closed.
  var huge = cc.build(_buildOpts({ visibleDisclosure: "a".repeat(1100000) }));
  var coseHuge = cc.signCose(huge, { privateKeyPem: pair.privateKey, timestamp: false, timestampOptOutReason: "x", audit: false });
  check("signCose >1 MiB payload produces a multi-MiB COSE (4-byte length header)", coseHuge.coseSign1.length > 1048576);
  var vHuge = cc.verifyCose(coseHuge.coseSign1, pair.publicKey, { requireTimestamp: false, audit: false });
  check("verifyCose oversized payload fails closed (claims unrecoverable → missing-required)",
    vHuge.valid === false && vHuge.claims === null && vHuge.reason.indexOf("missing-required") === 0);

  // Malformed COSE_Sign1 shapes decode but fail the structural gate in
  // _decodeCoseSign1 → cose-malformed verdict (never a throw).
  function _vc(bytes) { return cc.verifyCose(bytes, pair.publicKey, { requireTimestamp: false, audit: false }); }
  check("verifyCose 3-element array rejected as cose-malformed",
    _vc(Buffer.from([0x83, 0x01, 0x02, 0x03])).reason === "content-credentials/cose-malformed");
  check("verifyCose non-bytestring protected header rejected as cose-malformed",
    _vc(Buffer.from([0x84, 0x01, 0xA0, 0x40, 0x40])).reason === "content-credentials/cose-malformed");
  check("verifyCose non-map unprotected header rejected as cose-malformed",
    _vc(Buffer.from([0x84, 0x40, 0x40, 0x40, 0x40])).reason === "content-credentials/cose-malformed");

  // Well-formed COSE shape with an EMPTY protected header → alg decode yields
  // an empty map (algName null); with a NON-DECODABLE protected header → the
  // alg decode catch (algName null). Both then fail the signature check
  // (garbage signature) → signature-mismatch, not a throw.
  var vEmptyProt = _vc(Buffer.from([0x84, 0x40, 0xA0, 0x41, 0x00, 0x41, 0x00]));
  check("verifyCose empty protected header → signature-mismatch (alg null)",
    vEmptyProt.valid === false && vEmptyProt.reason === "signature-mismatch" && vEmptyProt.alg === null);
  var vBadProt = _vc(Buffer.from([0x84, 0x41, 0xFF, 0xA0, 0x41, 0x00, 0x41, 0x00]));
  check("verifyCose non-decodable protected header → signature-mismatch (alg null)",
    vBadProt.valid === false && vBadProt.reason === "signature-mismatch" && vBadProt.alg === null);

  // verifyCose signature verify THROWS on a malformed (non-empty) public-key
  // PEM → the catch sets sigOk false → signature-mismatch.
  var vBadKey = cc.verifyCose(Buffer.from([0x84, 0x40, 0xA0, 0x41, 0x00, 0x41, 0x00]),
    "-----BEGIN PUBLIC KEY-----\nnotvalid\n-----END PUBLIC KEY-----", { requireTimestamp: false, audit: false });
  check("verifyCose malformed public key PEM → signature-mismatch (verify throw caught)",
    vBadKey.valid === false && vBadKey.reason === "signature-mismatch");
}

// _verifyIdentityX509Chain error branches: the certificate-parse failures,
// expired-cert rejections, and broken-linkage refusals a valid chain never
// reaches. Each surfaces as verified:false with a specific reason while
// valid stays true (the signature + hash-binding are intact).
async function runX509ChainErrorBranches() {
  var pair = b.crypto.generateSigningKeyPair("ml-dsa-87");
  var refs = [{ label: "c2pa.actions", data: { action: "c2pa.created" } }];
  var ia = cc.attachIdentityAssertion({
    binding: "x509", subject: { name: "Acme Newsroom" },
    referencedAssertions: refs, privateKeyPem: pair.privateKey, audit: false,
  });
  function _vi(trustOpts) {
    return cc.verifyIdentityAssertion(ia, pair.publicKey,
      Object.assign({ referencedAssertions: refs, audit: false }, trustOpts));
  }
  var DAY = 86400000;
  var now = Date.now();

  // Valid chain leaf but an unparseable trust anchor → bad-anchor-cert
  // (the chain parses first, then the anchor parse throws).
  var leaf = _makeCert("Acme Leaf", null, false);
  check("verifyIdentity valid chain + garbage anchor → bad-anchor-cert",
    _vi({ identityCertChainPem: leaf.pem, identityTrustAnchorsPem: "not-a-pem" }).reason === "bad-anchor-cert");

  // An expired leaf in the presented chain → leaf-expired.
  var expiredLeaf = _makeCert("Expired Leaf", null, false, { from: now - DAY * 10, to: now - DAY * 5 });
  check("verifyIdentity expired leaf cert → leaf-expired",
    _vi({ identityCertChainPem: expiredLeaf.pem, identityTrustAnchorsPem: leaf.pem }).reason === "leaf-expired");

  // A chain whose presented intermediate did NOT issue the leaf → broken-chain.
  var root       = _makeCert("Chain Root", null, true);
  var inter      = _makeCert("Chain Intermediate", { name: root.name, key: root.key }, true);
  var leafSigned = _makeCert("Chain Leaf", { name: inter.name, key: inter.key }, false);
  var rogueInter = _makeCert("Rogue Intermediate", null, true);
  check("verifyIdentity leaf not issued by presented intermediate → broken-chain",
    _vi({ identityCertChainPem: [leafSigned.pem, rogueInter.pem], identityTrustAnchorsPem: root.pem }).reason === "broken-chain");

  // Chain links to an EXPIRED trust anchor → anchor-expired (the chain certs
  // are valid; only the anchor's own validity window has passed).
  var expiredRoot   = _makeCert("Expired Root", null, true, { from: now - DAY * 10, to: now - DAY * 5 });
  var leafOfExpired = _makeCert("Leaf of Expired Root", { name: expiredRoot.name, key: expiredRoot.key }, false);
  check("verifyIdentity chain to expired anchor → anchor-expired",
    _vi({ identityCertChainPem: leafOfExpired.pem, identityTrustAnchorsPem: expiredRoot.pem }).reason === "anchor-expired");

  // An expired NON-leaf cert in the presented chain → chain-cert-expired
  // (the per-cert validity loop rejects at index !== 0, before linkage).
  var validLeaf2 = _makeCert("Valid Leaf 2", null, false);
  var expiredCa  = _makeCert("Expired CA", null, true, { from: now - DAY * 10, to: now - DAY * 5 });
  check("verifyIdentity expired non-leaf chain cert → chain-cert-expired",
    _vi({ identityCertChainPem: [validLeaf2.pem, expiredCa.pem], identityTrustAnchorsPem: leaf.pem }).reason === "chain-cert-expired");

  // Trust anchors supplied as an ARRAY (not a single PEM string) still resolve
  // — the [leaf, intermediate] chain verifies to the array-form root anchor.
  var arrRoot  = _makeCert("Array Anchor Root", null, true);
  var arrInter = _makeCert("Array Anchor Intermediate", { name: arrRoot.name, key: arrRoot.key }, true);
  var arrLeaf  = _makeCert("Array Anchor Leaf", { name: arrInter.name, key: arrInter.key }, false);
  var vArr = _vi({ identityCertChainPem: [arrLeaf.pem, arrInter.pem], identityTrustAnchorsPem: [arrRoot.pem] });
  check("verifyIdentity array-form trust anchor verifies", vArr.valid === true && vArr.verified === true);

  // A trust anchor of the wrong type (neither PEM string nor array) →
  // bad-trust-anchors (the anchor-normalization null branch).
  check("verifyIdentity wrong-type trust anchor → bad-trust-anchors",
    _vi({ identityCertChainPem: leaf.pem, identityTrustAnchorsPem: 12345 }).reason === "bad-trust-anchors");
}

// CAWG identity-assertion + GB 45438-2025 CAC-label input branches the
// happy-path checks miss: a non-string assertion signature, a malformed
// verification key, the opts-omitted default, and the contentId length ceiling.
async function runIdentityAndCacEdge() {
  var pair = b.crypto.generateSigningKeyPair("ml-dsa-87");
  var refs = [{ label: "c2pa.actions", data: { action: "c2pa.created" } }];

  // A structurally valid signer_payload with a NON-STRING signature: the
  // shape gate passes, then Buffer.from(number) throws → signature-base64-bad.
  var spShaped = { signer_payload: { binding: "x509", subject: { name: "n" }, referenced_assertions: [] }, signature: 12345 };
  check("verifyIdentity numeric signature returns signature-base64-bad",
    cc.verifyIdentityAssertion(spShaped, pair.publicKey, { referencedAssertions: refs, audit: false }).reason === "signature-base64-bad");

  var ia = cc.attachIdentityAssertion({
    binding: "x509", subject: { name: "n" }, referencedAssertions: refs,
    privateKeyPem: pair.privateKey, audit: false,
  });

  // A malformed (non-empty) verification key makes b.crypto.verify throw →
  // the catch sets sigOk false → signature-mismatch (fail closed, no throw).
  check("verifyIdentity malformed key → signature-mismatch (verify throw caught)",
    cc.verifyIdentityAssertion(ia, "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----",
      { referencedAssertions: refs, audit: false }).reason === "signature-mismatch");

  // verifyIdentityAssertion with opts omitted defaults opts to {} then fails
  // the required-referencedAssertions gate (never throws).
  check("verifyIdentity with no opts → referenced-assertions-required",
    cc.verifyIdentityAssertion(ia, pair.publicKey).reason === "referenced-assertions-required");

  // cacImplicitLabel contentId over the 128-char ceiling → bad-content-id
  // (the length branch, distinct from the illegal-character branch).
  var e;
  check("cacImplicitLabel over-long contentId (>128) rejected as bad-content-id",
    (e = _err(function () {
      cc.cacImplicitLabel({ providerName: "P", providerCode: "91110000600037341A",
        contentId: "a".repeat(129), contentKind: "image", generatedAt: "2026-05-17T20:00:00Z" });
    })) && e.code === "cac-implicit-label/bad-content-id");
}

async function run() {
  check("build is fn",    typeof b.contentCredentials.build === "function");
  check("sign is fn",     typeof b.contentCredentials.sign === "function");
  check("verify is fn",   typeof b.contentCredentials.verify === "function");
  check("required is fn", typeof b.contentCredentials.required === "function");
  check("ContentCredentialsError", typeof b.contentCredentials.ContentCredentialsError === "function");
  check("REQUIRED_FIELDS",         Array.isArray(b.contentCredentials.REQUIRED_FIELDS) &&
                                    b.contentCredentials.REQUIRED_FIELDS.length === 4);

  var manifest = b.contentCredentials.build({
    provider:        "Acme AI Inc.",
    system:          "acme-image-v3",
    systemVersion:   "3.2.1",
    contentId:       "img-2026-05-08-abc123",
    contentType:     "image/png",
  });
  check("build returns frozen manifest", Object.isFrozen(manifest));
  check("manifest aiGenerated true",     manifest.aiGenerated === true);
  check("manifest cites SB-942",         manifest.citations.indexOf("california-sb-942") !== -1);

  var kp = b.crypto.generateSigningKeyPair("ml-dsa-87");
  var env = b.contentCredentials.sign(manifest, { privateKeyPem: kp.privateKey, audit: false });
  check("sign returns envelope", typeof env.signature === "string" && env.signature.length > 0);

  var v = b.contentCredentials.verify(env, kp.publicKey, { audit: false });
  check("verify valid", v.valid === true);

  // Tamper
  var tampered = { manifest: Object.assign({}, env.manifest, { aiGenerated: false }), signature: env.signature };
  var v2 = b.contentCredentials.verify(tampered, kp.publicKey, { audit: false });
  check("verify rejects tampered", v2.valid === false);

  // required() audit
  var missing = b.contentCredentials.required({ provider: "x" });
  check("required missing fields", missing.indexOf("missing-system") !== -1 &&
        missing.indexOf("missing-systemVersion") !== -1 &&
        missing.indexOf("missing-contentId") !== -1);

  // Bad shapes
  var threw = null;
  try { b.contentCredentials.build({}); } catch (e) { threw = e; }
  check("refuses missing required",  threw && threw.code === "MISSING_PROVIDER");

  threw = null;
  try { b.contentCredentials.build({
    provider: "x", system: "x", systemVersion: "not.semver",
    contentId: "y",
  }); } catch (e) { threw = e; }
  check("refuses bad systemVersion", threw && threw.code === "content-credentials/bad-version");

  threw = null;
  try { b.contentCredentials.build({
    provider: "x", system: "x", systemVersion: "1.0.0",
    contentId: "y", contentType: "not-a-mime",
  }); } catch (e) { threw = e; }
  check("refuses bad contentType",   threw && threw.code === "content-credentials/bad-content-type");

  // ---- v0.8.77: COSE_Sign1 interop ----
  check("COSE_ALGS table exported",            typeof b.contentCredentials.COSE_ALGS === "object");
  check("COSE_ALGS includes ml-dsa-87",        b.contentCredentials.COSE_ALGS["ml-dsa-87"] === -50);
  check("COSE_ALGS includes ed25519",          b.contentCredentials.COSE_ALGS["ed25519"] === -8);

  var pair = b.crypto.generateSigningKeyPair("ml-dsa-87");
  var manifest2 = b.contentCredentials.build({
    provider:      "Acme",
    system:        "acme-v3",
    systemVersion: "3.2.1",
    contentId:     "img-002",
  });
  var cose = b.contentCredentials.signCose(manifest2, {
    privateKeyPem: pair.privateKey,
    alg:           "ml-dsa-87",
    timestamp:     false,
    timestampOptOutReason: "interop fixture — no TSA in this test",
  });
  check("signCose: returns coseSign1 Buffer",  Buffer.isBuffer(cose.coseSign1));
  check("signCose: alg echoed",                cose.alg === "ml-dsa-87");
  check("signCose: CBOR tag 18 (COSE_Sign1)",  cose.coseSign1[0] === 0xD2);
  check("signCose: array of 4 elements",       cose.coseSign1[1] === 0x84);
  check("signCose: not timestamped on opt-out", cose.timestamped === false);

  threw = null;
  try { b.contentCredentials.signCose(manifest2, { privateKeyPem: pair.privateKey, alg: "unknown", timestamp: false, timestampOptOutReason: "x" }); }
  catch (e) { threw = e; }
  check("signCose: unknown alg refused",       threw && threw.code === "content-credentials/bad-alg");

  // ---- v0.14.11: sigTst2 timestamp + verifyCose fail-closed ----
  check("verifyCose is fn", typeof b.contentCredentials.verifyCose === "function");

  // Timestamping is fail-closed: a missing timestamp opt THROWS.
  threw = null;
  try { b.contentCredentials.signCose(manifest2, { privateKeyPem: pair.privateKey, alg: "ml-dsa-87" }); }
  catch (e) { threw = e; }
  check("signCose: missing timestamp opt refused", threw && threw.code === "content-credentials/timestamp-required");

  // Explicit opt-out requires a recorded reason.
  threw = null;
  try { b.contentCredentials.signCose(manifest2, { privateKeyPem: pair.privateKey, alg: "ml-dsa-87", timestamp: false }); }
  catch (e) { threw = e; }
  check("signCose: timestamp:false without reason refused", threw && threw.code === "TIMESTAMP_OPT_OUT_NO_REASON");

  // Request-builder mode returns a TSA query + the signature to re-pin.
  var reqOnly = b.contentCredentials.signCose(manifest2, {
    privateKeyPem: pair.privateKey, alg: "ml-dsa-87", timestamp: {}, audit: false,
  });
  check("signCose request mode: not timestamped yet", reqOnly.timestamped === false);
  check("signCose request mode: returns DER request",  Buffer.isBuffer(reqOnly.timestampRequest.der));
  check("signCose request mode: returns signature to re-pin", typeof reqOnly.timestampRequest.signature === "string");
  check("signCose request mode: hashAlg default SHA-512", reqOnly.timestampRequest.hashAlg === "SHA-512");

  // Bad hashAlg refused.
  threw = null;
  try { b.contentCredentials.signCose(manifest2, { privateKeyPem: pair.privateKey, alg: "ml-dsa-87", timestamp: { hashAlg: "MD5" } }); }
  catch (e) { threw = e; }
  check("signCose: bad timestamp hashAlg refused", threw && threw.code === "content-credentials/bad-tst-hash");

  // Full round trip: request → mint token → attach → verify (timestamp valid).
  var rt = _timestampedRoundTrip(manifest2, pair);
  check("signCose attach mode: timestamped", rt.attached.timestamped === true);
  check("signCose attach mode: sigTst2 present grows the COSE bytes", rt.attached.coseSign1.length > cose.coseSign1.length);

  var v3 = b.contentCredentials.verifyCose(rt.attached.coseSign1, pair.publicKey, {
    timestampNonce: rt.req.timestampRequest.nonce, timestampTrustAnchorsPem: [rt.anchorPem], audit: false,
  });
  check("verifyCose: signature valid", v3.valid === true);
  check("verifyCose: timestamp valid (routed through tsa.verifyToken)", v3.timestamp && v3.timestamp.valid === true);
  check("verifyCose: timestamp genTime is a Date", v3.timestamp.genTime instanceof Date);
  check("verifyCose: alg surfaced", v3.alg === "ml-dsa-87");
  check("verifyCose: claims recovered", v3.claims && v3.claims.content && v3.claims.content.id === "img-002");

  // verifyCose NEVER throws — bad inputs return { valid:false }.
  var vNoBuf = b.contentCredentials.verifyCose("not a buffer", pair.publicKey, { audit: false });
  check("verifyCose: non-buffer fails closed (no throw)", vNoBuf.valid === false && vNoBuf.reason === "cose-not-buffer");
  var vNoKey = b.contentCredentials.verifyCose(rt.attached.coseSign1, "", { audit: false });
  check("verifyCose: missing key fails closed", vNoKey.valid === false && vNoKey.reason === "public-key-required");

  // requireTimestamp default true refuses a token-less COSE_Sign1.
  var vReq = b.contentCredentials.verifyCose(cose.coseSign1, pair.publicKey, { audit: false });
  check("verifyCose: token-less refused by default", vReq.valid === false && vReq.reason === "timestamp-required");
  var vReqOff = b.contentCredentials.verifyCose(cose.coseSign1, pair.publicKey, { requireTimestamp: false, audit: false });
  check("verifyCose: requireTimestamp:false accepts token-less", vReqOff.valid === true);

  // Tampered payload byte → signature mismatch, fail-closed.
  var tamperedCose = Buffer.from(rt.attached.coseSign1); tamperedCose[tamperedCose.length - 3] ^= 0xff;
  var vTamper = b.contentCredentials.verifyCose(tamperedCose, pair.publicKey, { audit: false });
  check("verifyCose: tampered token fails closed", vTamper.valid === false);

  // Wrong nonce on an otherwise-valid token → tsa-derived timestamp failure,
  // surfaced as a fail-closed verdict (NOT a throw, NOT a chain-only pass).
  var vNonce = b.contentCredentials.verifyCose(rt.attached.coseSign1, pair.publicKey, {
    timestampNonce: nodeCrypto.randomBytes(8), audit: false,
  });
  check("verifyCose: wrong timestamp nonce fails closed via tsa.verifyToken",
    vNonce.valid === false && /^timestamp-invalid:/.test(vNonce.reason));

  // A cryptographically valid COSE_Sign1 over a payload that is NOT a
  // complete SB-942 manifest must NOT verify as a content credential —
  // verifyCose re-runs the required-field gate that verify() applies.
  var partialCose = b.contentCredentials.signCose({ provider: { name: "x" }, content: { id: "y" } }, {
    privateKeyPem: pair.privateKey, alg: "ml-dsa-87",
    timestamp: false, timestampOptOutReason: "test fixture", audit: false,
  });
  var vPartial = b.contentCredentials.verifyCose(partialCose.coseSign1, pair.publicKey, {
    requireTimestamp: false, audit: false,
  });
  check("verifyCose: incomplete manifest rejected (missing-required)",
    vPartial.valid === false && vPartial.reason.indexOf("missing-required") === 0);

  // ---- v0.14.11: CAWG identity assertion ----
  check("attachIdentityAssertion is fn", typeof b.contentCredentials.attachIdentityAssertion === "function");
  check("verifyIdentityAssertion is fn", typeof b.contentCredentials.verifyIdentityAssertion === "function");

  var orgPair = b.crypto.generateSigningKeyPair("ml-dsa-87");
  var refs = [{ label: "c2pa.actions", data: { action: "c2pa.created" } }];
  var ia = b.contentCredentials.attachIdentityAssertion({
    binding: "x509",
    subject: { name: "Acme Newsroom", org: "Acme Media", id: "acme-001" },
    referencedAssertions: refs,
    privateKeyPem: orgPair.privateKey,
    audit: false,
  });
  check("attachIdentityAssertion: v1.2 envelope", ia.type === "cawg.identity" && ia.version === "1.2");
  check("attachIdentityAssertion: hash-binds referenced assertions", ia.signer_payload.referenced_assertions.length === 1);
  check("attachIdentityAssertion: assertion is hash-bound (sha3-512)", ia.signer_payload.referenced_assertions[0].alg === "sha3-512");
  check("attachIdentityAssertion: base64 signature", typeof ia.signature === "string" && ia.signature.length > 0);

  // Self-asserted (no trust anchor) → valid signature, but verified:false.
  var iaSelf = b.contentCredentials.verifyIdentityAssertion(ia, orgPair.publicKey, { referencedAssertions: refs, audit: false });
  check("verifyIdentityAssertion: self-asserted valid", iaSelf.valid === true);
  check("verifyIdentityAssertion: self-asserted NOT verified (no anchor)", iaSelf.verified === false && iaSelf.reason === "no-trust-anchor");

  // x509 chained to a supplied trust anchor → verified:true. Reuse the
  // mock TSA cert as a self-signed leaf==anchor.
  var orgCert = _makeTsaCert();
  var orgPem = new nodeCrypto.X509Certificate(orgCert.certDer).toString();
  var iaTrusted = b.contentCredentials.verifyIdentityAssertion(ia, orgPair.publicKey, {
    referencedAssertions: refs, identityCertChainPem: orgPem, identityTrustAnchorsPem: orgPem, audit: false,
  });
  check("verifyIdentityAssertion: x509 chained → verified", iaTrusted.valid === true && iaTrusted.verified === true);

  // x509 chain through an INTERMEDIATE CA: chain [leaf, intermediate]
  // with the root as the trust anchor must verify — the chain walk uses
  // chain[1..], not only a direct leaf-vs-anchor test.
  var caRoot  = _makeCert("CAWG Test Root", null, true);
  var caInter = _makeCert("CAWG Test Intermediate", { name: caRoot.name, key: caRoot.key }, true);
  var caLeaf  = _makeCert("Acme Newsroom Leaf", { name: caInter.name, key: caInter.key });
  var iaChain = b.contentCredentials.verifyIdentityAssertion(ia, orgPair.publicKey, {
    referencedAssertions: refs,
    identityCertChainPem: [caLeaf.pem, caInter.pem],
    identityTrustAnchorsPem: caRoot.pem, audit: false,
  });
  check("verifyIdentityAssertion: [leaf,intermediate]→root anchor verified (walks intermediates)",
    iaChain.valid === true && iaChain.verified === true);
  // The same chain against an unrelated anchor must NOT verify.
  var caRogue = _makeCert("Rogue Root", null, true);
  var iaWrongAnchor = b.contentCredentials.verifyIdentityAssertion(ia, orgPair.publicKey, {
    referencedAssertions: refs,
    identityCertChainPem: [caLeaf.pem, caInter.pem],
    identityTrustAnchorsPem: caRogue.pem, audit: false,
  });
  check("verifyIdentityAssertion: chain to unrelated anchor → not verified",
    iaWrongAnchor.verified === false);

  // Transplanted referenced assertions → fail closed.
  var iaTransplant = b.contentCredentials.verifyIdentityAssertion(ia, orgPair.publicKey, {
    referencedAssertions: [{ label: "x", data: { other: 1 } }], audit: false,
  });
  check("verifyIdentityAssertion: transplanted assertions fail closed",
    iaTransplant.valid === false && iaTransplant.reason === "assertion-hash-mismatch");

  // Aggregator path is never verified:true even with an anchor.
  var iaAgg = b.contentCredentials.attachIdentityAssertion({
    binding: "identity-claims-aggregator", subject: { name: "Jane Doe" },
    referencedAssertions: refs, privateKeyPem: orgPair.privateKey, audit: false,
  });
  var iaAggV = b.contentCredentials.verifyIdentityAssertion(iaAgg, orgPair.publicKey, {
    referencedAssertions: refs, identityTrustAnchorsPem: orgPem, audit: false,
  });
  check("verifyIdentityAssertion: aggregator path never verified:true",
    iaAggV.valid === true && iaAggV.verified === false && iaAggV.reason === "aggregator-self-asserted");

  // Wrong key → signature mismatch, fail closed (no throw).
  var otherPair = b.crypto.generateSigningKeyPair("ml-dsa-87");
  var iaWrongKey = b.contentCredentials.verifyIdentityAssertion(ia, otherPair.publicKey, { referencedAssertions: refs, audit: false });
  check("verifyIdentityAssertion: wrong key fails closed", iaWrongKey.valid === false && iaWrongKey.reason === "signature-mismatch");

  // Bad binding refused at config time.
  threw = null;
  try { b.contentCredentials.attachIdentityAssertion({ binding: "made-up", subject: { name: "x" }, referencedAssertions: refs, privateKeyPem: orgPair.privateKey }); }
  catch (e) { threw = e; }
  check("attachIdentityAssertion: bad binding refused", threw && threw.code === "content-credentials/bad-identity-binding");

  await runErrorPaths();
  await runCoseEdgeCases();
  await runX509ChainErrorBranches();
  await runIdentityAndCacEdge();
  await runAuditOnPaths();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[content-credentials] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
