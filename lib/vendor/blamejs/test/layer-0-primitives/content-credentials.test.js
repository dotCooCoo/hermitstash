"use strict";
/**
 * b.contentCredentials — SB-942 / AB-853 / C2PA manifest builder, the
 * COSE_Sign1 interop wrapper with its RFC 3161 sigTst2 countersignature,
 * and the CAWG identity assertion.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
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
function _makeCert(cn, issuer, isCa) {
  var kp = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var spki = kp.publicKey.export({ type: "spki", format: "der" });
  var subjName  = _certName(cn);
  var issuerName = issuer ? issuer.name : subjName;
  var issuerKey  = issuer ? issuer.key  : kp.privateKey;
  var sigAlgId = _algId("1.2.840.113549.1.1.11", true);
  var version = asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2])));
  var serial = asn1.writeInteger(Buffer.from([0x2b]));
  var now = Date.now();
  var validity = asn1.writeSequence([_utcTime(new Date(now - 86400000)), _utcTime(new Date(now + 86400000 * 3650))]);
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
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[content-credentials] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
