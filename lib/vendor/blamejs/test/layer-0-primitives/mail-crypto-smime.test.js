// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.crypto.smime — v1 surface coverage.
 *
 * In v1 sign() + verify() are DEFERRED with a documented condition
 * (see the @intro block in lib/mail-crypto-smime.js); only
 * checkCert() is operator-callable. These tests cover:
 *
 *   - the deferred sign() / verify() throw with the expected
 *     "deferred" code so operators reaching for them get a clear
 *     error rather than a silent no-op,
 *   - the doc-block contains the required RFC citations + CVE
 *     references + deferral conditions + escape hatch (per the
 *     project's defer-with-condition rule),
 *   - checkCert() refuses SHA-1 / MD5 cert signatures (SHAttered SHA-1
 *     collision; RFC 8551 §2.5) and < 2048-bit RSA (RFC 8301 §3.1).
 *
 * Run standalone: `node test/layer-0-primitives/mail-crypto-smime.test.js`
 * Or via smoke:   `node test/smoke.js`
 */
var helpers    = require("../helpers");
var check      = helpers.check;
var nodeCrypto = require("crypto");

var mailCrypto = require("../../lib/mail-crypto");
var smime      = mailCrypto.smime;
var b          = helpers.b;

var asn1       = require("../../lib/asn1-der");
var cms        = require("../../lib/cms-codec");
var pqc        = require("../../lib/pqc-software");
var spawnSync  = require("child_process").spawnSync;

var OID          = cms.OID;
var OID_MD_ATTR  = "1.2.840.113549.1.9.4";                                   // RFC 5652 §11.2 messageDigest
var OID_CT_ATTR  = "1.2.840.113549.1.9.3";                                   // RFC 5652 §11.1 contentType

// ---- Helper: minimal self-signed certificate (node:crypto only) ----
//
// Node's X509Certificate API can parse PEM-encoded certs but cannot
// MINT them from a KeyObject directly without OpenSSL CLI or a
// vendored ASN.1 library. The mtls-ca module is allowed to use
// node:crypto + child_process; we avoid touching it here. Instead
// we generate a self-signed cert via openssl(1) if available;
// otherwise we mark this test SKIP with an explanatory check.
// Generating a cert is required only for the positive checkCert
// path — the SHA-1 + RSA-too-small refusal paths use static PEMs.

function _maybeMakeSelfSignedCertViaOpenssl(keyPem, hash) {
  var spawnSync = require("child_process").spawnSync;
  var fs = require("fs");
  var os = require("os");
  var path = require("path");
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-smime-cert-"));
  var keyPath  = path.join(tmp, "key.pem");
  var certPath = path.join(tmp, "cert.pem");
  fs.writeFileSync(keyPath, keyPem);
  var rv = spawnSync("openssl", [
    "req", "-x509", "-key", keyPath, "-out", certPath,
    "-days", "1", "-" + (hash || "sha256"),
    "-subj", "/CN=test.example/O=blamejs-test",
  ], { stdio: "ignore" });
  if (rv.status !== 0) {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    return null;
  }
  var pem = fs.readFileSync(certPath, "utf8");
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  return pem;
}

// ---- Surface ----

function testSmimeSurface() {
  check("smime.sign is a function",         typeof smime.sign === "function");
  check("smime.verify is a function",       typeof smime.verify === "function");
  check("smime.checkCert is a function",    typeof smime.checkCert === "function");
  check("smime.PROFILES is an array",       Array.isArray(smime.PROFILES));
  check("smime PROFILES includes strict",   smime.PROFILES.indexOf("strict") !== -1);
  check("smime PROFILES includes balanced", smime.PROFILES.indexOf("balanced") !== -1);
  check("smime PROFILES includes permissive", smime.PROFILES.indexOf("permissive") !== -1);
  check("smime COMPLIANCE_POSTURES.hipaa is strict",     smime.COMPLIANCE_POSTURES.hipaa === "strict");
  check("smime COMPLIANCE_POSTURES.pci-dss is strict",   smime.COMPLIANCE_POSTURES["pci-dss"] === "strict");
  check("smime COMPLIANCE_POSTURES.gdpr is strict",      smime.COMPLIANCE_POSTURES.gdpr === "strict");
  check("smime COMPLIANCE_POSTURES.soc2 is strict",      smime.COMPLIANCE_POSTURES.soc2 === "strict");
  check("smime ALLOWED_HASHES includes sha256",          smime.ALLOWED_HASHES.indexOf("sha256") !== -1);
  check("smime REFUSED_HASHES includes sha1",            smime.REFUSED_HASHES.indexOf("sha1") !== -1);
  check("smime REFUSED_HASHES includes md5",             smime.REFUSED_HASHES.indexOf("md5") !== -1);
  check("smime RSA_MIN_BITS is 2048",                    smime.RSA_MIN_BITS === 2048);
}

// ---- v0.10.16 live sign() + verify() roundtrip ----

function _testCertDer() {
  var asn1 = require("../../lib/asn1-der");
  var serial = asn1.writeInteger(Buffer.from([0x01]));
  var sigAlg = asn1.writeNode(0x30, asn1.writeOid("2.16.840.1.101.3.4.3.18"));
  var issuer = asn1.writeNode(0x30, asn1.writeOid("2.5.4.3"));
  var tbs    = asn1.writeNode(0x30, Buffer.concat([serial, sigAlg, issuer]));
  var fakeSigAlg = asn1.writeNode(0x30, asn1.writeOid("2.16.840.1.101.3.4.3.18"));
  var fakeSig    = asn1.writeNode(0x03, Buffer.from([0x00, 0x00, 0x01]));
  return asn1.writeNode(0x30, Buffer.concat([tbs, fakeSigAlg, fakeSig]));
}

function testSmimeSignVerifyRoundtrip() {
  var pq = require("../../lib/pqc-software");
  var kp = pq.ml_dsa_65.keygen();
  var msg = "From: x@y\r\nSubject: hi\r\n\r\nbody";
  var out = smime.sign({
    message:     msg,
    certificate: _testCertDer(),
    secretKey:   kp.secretKey,
    sigAlg:      "ML-DSA-65",
  });
  check("sign returns multipart string", typeof out.multipart === "string" && out.multipart.indexOf("multipart/signed") !== -1);
  check("sign returns Buffer signature", Buffer.isBuffer(out.signature) && out.signature.length > 100);
  check("sign returns boundary",        typeof out.boundary === "string" && out.boundary.length > 0);
  check("sign returns micalg=sha3-512", out.micalg === "sha3-512");
  var v = smime.verify({ message: msg, signature: out.signature, signerPublicKey: kp.publicKey });
  check("verify clean roundtrip ok",  v.valid === true && v.sigAlg === "ML-DSA-65");
}

function testSmimeVerifyTamperRefused() {
  var pq = require("../../lib/pqc-software");
  var kp = pq.ml_dsa_65.keygen();
  var msg = "original bytes";
  var out = smime.sign({
    message: msg, certificate: _testCertDer(),
    secretKey: kp.secretKey, sigAlg: "ML-DSA-65",
  });
  var threw = null;
  try { smime.verify({ message: msg + "TAMPER", signature: out.signature, signerPublicKey: kp.publicKey }); }
  catch (e) { threw = e; }
  check("tampered message refused with message-digest-mismatch",
    threw && threw.code === "mail-crypto/smime/message-digest-mismatch");
}

function testSmimeVerifyWrongKeyRefused() {
  var pq = require("../../lib/pqc-software");
  var kp  = pq.ml_dsa_65.keygen();
  var kp2 = pq.ml_dsa_65.keygen();
  var msg = "bytes";
  var out = smime.sign({ message: msg, certificate: _testCertDer(), secretKey: kp.secretKey, sigAlg: "ML-DSA-65" });
  var threw = null;
  try { smime.verify({ message: msg, signature: out.signature, signerPublicKey: kp2.publicKey }); }
  catch (e) { threw = e; }
  check("wrong public key refused with signature-mismatch",
    threw && threw.code === "mail-crypto/smime/signature-mismatch");
}

function testSmimeSignSupportsMlDsa87() {
  var pq = require("../../lib/pqc-software");
  var kp = pq.ml_dsa_87.keygen();
  var msg = "body";
  var out = smime.sign({ message: msg, certificate: _testCertDer(), secretKey: kp.secretKey, sigAlg: "ML-DSA-87" });
  var v = smime.verify({ message: msg, signature: out.signature, signerPublicKey: kp.publicKey });
  check("ML-DSA-87 sign+verify roundtrips", v.valid === true && v.sigAlg === "ML-DSA-87");
}

function testSmimeSignSupportsSlhDsa() {
  var pq = require("../../lib/pqc-software");
  var kp = pq.slh_dsa_shake_256f.keygen();
  var msg = "body";
  var out = smime.sign({ message: msg, certificate: _testCertDer(), secretKey: kp.secretKey, sigAlg: "SLH-DSA-SHAKE-256f" });
  var v = smime.verify({ message: msg, signature: out.signature, signerPublicKey: kp.publicKey });
  check("SLH-DSA-SHAKE-256f sign+verify roundtrips", v.valid === true);
}

function testSmimeSignBadOpts() {
  var threw = null;
  try { smime.sign({}); }
  catch (e) { threw = e; }
  check("sign with no message refused",
    threw && /smime\/bad/.test(threw.code || ""));
}

// ---- checkCert: positive path (self-signed via openssl if available) ----

function testSmimeCheckCertHappyPath() {
  var kp = nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  var certPem = _maybeMakeSelfSignedCertViaOpenssl(kp.privateKey, "sha256");
  if (!certPem) {
    // openssl(1) not on PATH — record one check and bail gracefully.
    check("smime.checkCert positive path skipped (openssl(1) not available)", true);
    return;
  }
  var rv = smime.checkCert({ certPem: certPem });
  check("checkCert returns subject",        typeof rv.subject === "string");
  check("checkCert returns issuer",         typeof rv.issuer === "string");
  check("checkCert returns sigAlgName",     typeof rv.sigAlgName === "string");
  check("checkCert reports rsa keyType",    rv.keyType === "rsa");
  check("checkCert returns sha256 fingerprint", /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(rv.fingerprint256));
}

// ---- checkCert: SHA-1 cert refusal ----

function testSmimeCheckCertRefusesSha1() {
  var kp = nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  var certPem = _maybeMakeSelfSignedCertViaOpenssl(kp.privateKey, "sha1");
  if (!certPem) {
    check("smime.checkCert sha1-refusal skipped (openssl(1) not available)", true);
    return;
  }
  var threw = null;
  try { smime.checkCert({ certPem: certPem }); } catch (e) { threw = e; }
  check("checkCert refuses SHA-1 cert signature",
    threw && threw.code === "mail-crypto/smime/refused-hash");
  check("checkCert SHA-1 refusal names the weakness class",
    threw && /SHAttered|RFC 8551/.test(threw.message));
}

// ---- checkCert: RSA < 2048 refusal ----

function testSmimeCheckCertRefusesSmallRsa() {
  var kp = nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 1024,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  var certPem = _maybeMakeSelfSignedCertViaOpenssl(kp.privateKey, "sha256");
  if (!certPem) {
    check("smime.checkCert rsa-too-small skipped (openssl(1) not available)", true);
    return;
  }
  var threw = null;
  try { smime.checkCert({ certPem: certPem }); } catch (e) { threw = e; }
  check("checkCert refuses RSA < 2048 bits",
    threw && threw.code === "mail-crypto/smime/rsa-too-small");
  check("checkCert small-RSA refusal names RFC 8301",
    threw && /RFC 8301/.test(threw.message));
}

// ---- checkCert: input validation ----

function testSmimeCheckCertInputValidation() {
  function shouldThrow(label, opts, codeRe) {
    var threw = null;
    try { smime.checkCert(opts); } catch (e) { threw = e; }
    check("checkCert validate: " + label,
      threw && codeRe.test(String(threw.code || "") + " " + String(threw.message || "")));
  }
  shouldThrow("rejects null opts",
    null, /mail-crypto\/smime\/bad-opts/);
  shouldThrow("rejects missing certPem",
    {}, /mail-crypto\/smime\/bad-cert/);
  shouldThrow("rejects unparseable certPem",
    { certPem: "not a cert" },
    /mail-crypto\/smime\/bad-cert/);
  shouldThrow("rejects unknown opt key",
    { certPem: "x", bogus: 1 },
    /mail\.crypto\.smime\.checkCert/);
}

// ---- Doc-block surface: RFCs + CVEs + deferral discipline ----

function testSmimeDocBlockCitations() {
  var fs = require("fs");
  var path = require("path");
  var src = fs.readFileSync(path.join(__dirname, "..", "..", "lib", "mail-crypto-smime.js"), "utf8");
  check("smime doc block names RFC 8551",        src.indexOf("RFC 8551") !== -1);
  check("smime doc block names RFC 5652",        src.indexOf("RFC 5652") !== -1);
  check("smime doc block names RFC 8550",        src.indexOf("RFC 8550") !== -1);
  check("smime doc block names RFC 8301",        src.indexOf("RFC 8301") !== -1);
  check("smime doc block names CVE-2017-17688",  src.indexOf("CVE-2017-17688") !== -1);
  check("smime doc block names SHAttered SHA-1 class", src.indexOf("SHAttered") !== -1);
  // v0.10.16 — sign/verify went live; deferred-conditions language
  // was replaced with "LIVE on b.cms substrate".
  check("smime doc block names live status",
    /LIVE on `b\.cms`|b\.cms\.parseSignedData|sign\(\) and verify\(\) ship/.test(src));
}

// ---- Run ----

// ---- trust-chain leaf is bound to the verified signer key ----
//
// _verifyTrustChain must select the chain leaf as the cert whose public
// key matches signerPublicKey (the key that actually verified the
// signature) — not chain[0] unconditionally. Otherwise a validly-chained
// cert for a DIFFERENT identity passes chain validation. _certKeyMatches
// is that binding decision; a mock { publicKey } is all it touches.
function testSmimeCertKeyBinding() {
  var kpA = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var kpB = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var certA = { publicKey: kpA.publicKey };
  var spkiA = Buffer.from(kpA.publicKey.export({ format: "der", type: "spki" }));
  check("smime binding: cert matches its own full SPKI key",
        smime._certKeyMatches(certA, spkiA) === true);
  // Production form: signerPublicKey is the raw subjectPublicKey (the
  // uncompressed EC point 0x04||x||y), which is the SPKI's suffix.
  var jwkA = kpA.publicKey.export({ format: "jwk" });
  var rawA = Buffer.concat([Buffer.from([0x04]),
    Buffer.from(jwkA.x, "base64url"), Buffer.from(jwkA.y, "base64url")]);
  check("smime binding: cert matches its raw subjectPublicKey (suffix)",
        smime._certKeyMatches(certA, rawA) === true);
  // The gap this closes: a DIFFERENT key must not match.
  var spkiB = Buffer.from(kpB.publicKey.export({ format: "der", type: "spki" }));
  check("smime binding: cert does NOT match a different cert's key",
        smime._certKeyMatches(certA, spkiB) === false);
  // Unextractable / absent key → no match (caller fails closed).
  check("smime binding: unextractable key → no match",
        smime._certKeyMatches({ publicKey: { export: function () { throw new Error("nope"); } } }, spkiA) === false);
}

function testSmimeContentTypeAttrExtraction() {
  // RFC 5652 §11.1: verify() binds the contentType signed-attr to the
  // eContentType. _extractContentTypeOid must surface a present contentType
  // OID and return null when the attribute is absent (which verify rejects).
  var asn1 = require("../../lib/asn1-der");
  var OID_CT_ATTR = "1.2.840.113549.1.9.3";
  var OID_MD_ATTR = "1.2.840.113549.1.9.4";
  var OID_ID_DATA = "1.2.840.113549.1.7.1";
  function setOf(buf) { return asn1.writeNode(0x31, buf); }            // SET
  var ctAttr = asn1.writeSequence([asn1.writeOid(OID_CT_ATTR), setOf(asn1.writeOid(OID_ID_DATA))]);
  var mdAttr = asn1.writeSequence([asn1.writeOid(OID_MD_ATTR), setOf(asn1.writeOctetString(Buffer.alloc(32)))]);
  var withCt    = setOf(Buffer.concat([mdAttr, ctAttr]));
  var withoutCt = setOf(mdAttr);
  check("smime contentType: present attribute extracts its eContentType OID",
        smime._extractContentTypeOid(withCt) === OID_ID_DATA);
  check("smime contentType: absent attribute yields null (verify then refuses)",
        smime._extractContentTypeOid(withoutCt) === null);
}

// ---- b.mail.crypto.smime.verifyAll — multi-signer envelopes ----
//
// verifyAll walks EVERY SignerInfo in a CMS SignedData and verifies each
// against the matching key in signerPublicKeys, a map keyed by the
// SignerInfo's issuerAndSerialNumber serial-hex. smime.sign() only mints
// single-signer envelopes, so a genuine two-signer envelope is built
// directly via b.cms.encodeSignedData to exercise the multi-signer path.

function _certDerWithSerial(serialByte) {
  var asn1 = require("../../lib/asn1-der");
  var serial = asn1.writeInteger(Buffer.from([serialByte]));
  var sigAlg = asn1.writeNode(0x30, asn1.writeOid("2.16.840.1.101.3.4.3.18"));
  var issuer = asn1.writeNode(0x30, asn1.writeOid("2.5.4.3"));
  var tbs    = asn1.writeNode(0x30, Buffer.concat([serial, sigAlg, issuer]));
  var fakeSigAlg = asn1.writeNode(0x30, asn1.writeOid("2.16.840.1.101.3.4.3.18"));
  var fakeSig    = asn1.writeNode(0x03, Buffer.from([0x00, 0x00, 0x01]));
  return asn1.writeNode(0x30, Buffer.concat([tbs, fakeSigAlg, fakeSig]));
}

// Two-signer detached CMS SignedData over `msg`; certs carry serials
// 0x01 / 0x02 so verifyAll extracts serial-hex "01" / "02".
function _twoSignerEnvelope(msg) {
  var pq = require("../../lib/pqc-software");
  var kp1 = pq.ml_dsa_65.keygen();
  var kp2 = pq.ml_dsa_65.keygen();
  var sd = b.cms.encodeSignedData({
    encapContent: msg, digestAlg: "sha3-512", detached: true,
    signers: [
      { certificate: _certDerWithSerial(0x01), secretKey: kp1.secretKey, sigAlg: "ML-DSA-65" },
      { certificate: _certDerWithSerial(0x02), secretKey: kp2.secretKey, sigAlg: "ML-DSA-65" },
    ],
  });
  return { signature: sd, pub1: kp1.publicKey, pub2: kp2.publicKey };
}

function testVerifyAllMultiSigner() {
  var msg = Buffer.from("multi-signer body");
  var env = _twoSignerEnvelope(msg);
  var v = b.mail.crypto.smime.verifyAll({
    message: msg, signature: env.signature,
    signerPublicKeys: { "01": env.pub1, "02": env.pub2 },
  });
  check("verifyAll: valid true when every signer verifies", v.valid === true);
  check("verifyAll: reports both signers", v.signers.length === 2);
  var serials = v.signers.map(function (s) { return s.serialHex; }).sort();
  check("verifyAll: surfaces both signer serials ('01','02')",
    serials[0] === "01" && serials[1] === "02");
  check("verifyAll: reports the PQC sigAlg per signer",
    v.signers.every(function (s) { return s.sigAlg === "ML-DSA-65"; }));
}

// The advertised guarantee: each SignerInfo is verified against its OWN
// key. Swapping the two keys must be refused (each signature checked
// against the wrong key), proving per-signer binding — not a reuse of
// signerInfos[0]'s key for every signer.
function testVerifyAllPerSignerKeyBinding() {
  var msg = Buffer.from("bind-each-signer");
  var env = _twoSignerEnvelope(msg);
  var threw = null;
  try {
    b.mail.crypto.smime.verifyAll({
      message: msg, signature: env.signature,
      signerPublicKeys: { "01": env.pub2, "02": env.pub1 },   // swapped
    });
  } catch (e) { threw = e; }
  check("verifyAll: swapped per-signer keys refused (signature-mismatch)",
    threw && threw.code === "mail-crypto/smime/signature-mismatch");
}

function testVerifyAllMissingKey() {
  var msg = Buffer.from("missing-key-case");
  var env = _twoSignerEnvelope(msg);
  var threw = null;
  try {
    b.mail.crypto.smime.verifyAll({
      message: msg, signature: env.signature,
      signerPublicKeys: { "01": env.pub1 },   // no key for serial "02"
    });
  } catch (e) { threw = e; }
  check("verifyAll: a SignerInfo with no supplied key throws missing-key",
    threw && threw.code === "mail-crypto/smime/missing-key");
  check("verifyAll: missing-key names the unresolved serial",
    threw && /02/.test(threw.message || ""));
}

function testVerifyAllTamperRefused() {
  var msg = Buffer.from("original signed bytes");
  var env = _twoSignerEnvelope(msg);
  var threw = null;
  try {
    b.mail.crypto.smime.verifyAll({
      message: Buffer.from("TAMPERED bytes"), signature: env.signature,
      signerPublicKeys: { "01": env.pub1, "02": env.pub2 },
    });
  } catch (e) { threw = e; }
  check("verifyAll: tampered message refused with message-digest-mismatch",
    threw && threw.code === "mail-crypto/smime/message-digest-mismatch");
}

// A single-signer envelope minted by smime.sign() must also verify
// through verifyAll — the consumer path for operators who always route
// through verifyAll regardless of signer count. The signer cert (serial
// 0x01) keys the map.
function testVerifyAllSingleSigner() {
  var pq = require("../../lib/pqc-software");
  var kp = pq.ml_dsa_65.keygen();
  var msg = "From: x@y\r\nSubject: one\r\n\r\nbody";
  var out = smime.sign({
    message: msg, certificate: _testCertDer(),
    secretKey: kp.secretKey, sigAlg: "ML-DSA-65",
  });
  var v = b.mail.crypto.smime.verifyAll({
    message: msg, signature: out.signature,
    signerPublicKeys: { "01": kp.publicKey },
  });
  check("verifyAll: single-signer sign()-produced envelope verifies",
    v.valid === true && v.signers.length === 1);
  check("verifyAll: single-signer serial is '01'", v.signers[0].serialHex === "01");
}

function testVerifyAllInputValidation() {
  function shouldThrow(label, opts) {
    var threw = null;
    try { b.mail.crypto.smime.verifyAll(opts); } catch (e) { threw = e; }
    check("verifyAll validate: " + label,
      threw && threw.code === "mail-crypto/smime/bad-opts");
  }
  shouldThrow("null opts", null);
  shouldThrow("signerPublicKeys not a map",
    { message: Buffer.from("x"), signature: Buffer.from("x"), signerPublicKeys: 5 });
  shouldThrow("message missing",
    { signature: Buffer.from("x"), signerPublicKeys: {} });
  shouldThrow("signature not a Buffer",
    { message: Buffer.from("x"), signature: "notbuf", signerPublicKeys: {} });
}

// ============================================================================
// Uncovered error / adversarial / defensive branch coverage.
//
// These exercise the fail-closed guards in sign() / verify() /
// _verifySignerInfo / _verifyTrustChain / checkCert that the happy-path
// roundtrip tests above never reach. Two fixture machineries drive them:
//
//   1. asn1-level CMS SignedData crafting (`_craftSignedData`) — builds a
//      malformed SignedData that b.cms.parseSignedData accepts but whose
//      SignerInfo carries an unknown sigAlg / digest OID, absent signed-
//      attrs, a missing messageDigest / contentType attribute, etc. These
//      reach _verifySignerInfo's typed refusals with no key material.
//   2. openssl-minted certificates (`_mintCertMinimal` / `_withMlDsaCa`) —
//      real X.509 certs (RSA / EC for checkCert; ML-DSA-65 for the trust-
//      anchor chain walk). ML-DSA CMS signatures are produced by openssl and
//      verified by the vendored pqc-software (FIPS 204 interop), which is the
//      only way to feed _verifyTrustChain a node-parseable cert whose SPKI
//      equals the PQC signer key. Every openssl path degrades to a recorded
//      skip when the toolchain lacks the algorithm, so the suite still
//      exits 0 on a host without ML-DSA support.
// ============================================================================

function _algId(oid)      { return asn1.writeSequence([asn1.writeOid(oid)]); }
function _attr(oid, val)  { return asn1.writeSequence([asn1.writeOid(oid), asn1.writeSet([val])]); }
function _issuerSerialSid(serialByte) {
  return asn1.writeSequence([
    asn1.writeSequence([asn1.writeOid("2.5.4.3")]),                          // issuer Name
    asn1.writeInteger(Buffer.from([serialByte])),                           // serialNumber
  ]);
}
function _sha3_512(bytes) { return nodeCrypto.createHash("sha3-512").update(bytes).digest(); }

// Build a ContentInfo → SignedData DER with a single controllable SignerInfo.
// opts: { digestOid, sigOid, eContentType, sid, signedAttrsImplicit (or null
// to omit), signature, certsDer, signerInfos (raw SET member list — overrides
// the single-signer build) }.
function _craftSignedData(o) {
  o = o || {};
  var digestOid    = o.digestOid    || OID.sha3_512;
  var sigOid       = o.sigOid       || OID.mldsa65;
  var eContentType = o.eContentType || OID.data;
  var encap = asn1.writeSequence([asn1.writeOid(eContentType)]);            // detached — eContentType only
  var siList;
  if (o.signerInfos) {
    siList = o.signerInfos;
  } else {
    var siChildren = [asn1.writeInteger(Buffer.from([1])), o.sid || _issuerSerialSid(0x01), _algId(digestOid)];
    if (o.signedAttrsImplicit !== null && o.signedAttrsImplicit !== undefined) {
      siChildren.push(o.signedAttrsImplicit);
    }
    siChildren.push(_algId(sigOid));
    siChildren.push(asn1.writeOctetString(o.signature || Buffer.from([0, 0, 1])));
    siList = [asn1.writeSequence(siChildren)];
  }
  var sdChildren = [asn1.writeInteger(Buffer.from([1])), asn1.writeSet([_algId(digestOid)]), encap];
  if (o.certsDer && o.certsDer.length) {
    sdChildren.push(asn1.writeContextExplicit(0, Buffer.concat(o.certsDer)));
  }
  sdChildren.push(asn1.writeSet(siList));
  var sd = asn1.writeSequence(sdChildren);
  return asn1.writeSequence([asn1.writeOid(OID.signedData), asn1.writeContextExplicit(0, sd)]);
}

// A signedAttrs SET re-tagged [0] IMPLICIT for the SignerInfo. Returns both the
// universal-SET form (what the signature covers) and the [0] IMPLICIT form (what
// the SignerInfo embeds). Byte-identical apart from the leading tag, so a
// signature over `.set` is what verify() reconstructs.
function _signedAttrs(attrBufs) {
  var set = asn1.writeSet(attrBufs);
  return { set: set, implicit: Buffer.concat([Buffer.from([0xa0]), set.slice(1)]) };
}

// ---- openssl cert minting (RSA / EC, minimal config) ----
//
// OpenSSL 3.5's default req config trips on its v3_ca extension section; a
// minimal inline config avoids it. Returns { pem, der } or null when openssl
// is unavailable / the mint fails, so callers can record a graceful skip.
function _mintCertMinimal(opts) {
  var fs = require("fs"), os = require("os"), path = require("path");
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-smime-mint-"));
  try {
    var keyShape = opts.alg === "ec"
      ? { namedCurve: opts.curve || "P-256" }
      : { modulusLength: opts.bits || 2048 };
    var kp = nodeCrypto.generateKeyPairSync(opts.alg, Object.assign({
      publicKeyEncoding:  { type: "spki",  format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    }, keyShape));
    var keyPath = path.join(dir, "k.pem"), certPath = path.join(dir, "c.pem"), cfgPath = path.join(dir, "m.cnf");
    fs.writeFileSync(keyPath, kp.privateKey);
    fs.writeFileSync(cfgPath,
      "[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n" +
      "[dn]\nCN=" + (opts.cn || "smime-test.example") + "\n" +
      "[v3]\nbasicConstraints=critical,CA:TRUE\n");
    var args = ["req", "-x509", "-config", cfgPath, "-key", keyPath, "-out", certPath, "-" + (opts.hash || "sha256")];
    if (opts.notBefore) { args.push("-not_before", opts.notBefore, "-not_after", opts.notAfter); }
    else                { args.push("-days", String(opts.days || 30)); }
    var rv = spawnSync("openssl", args, { stdio: "pipe" });
    if (rv.status !== 0) return null;
    var pem = fs.readFileSync(certPath, "utf8");
    var der = Buffer.from(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");
    return { pem: pem, der: der };
  } catch (_e) {
    return null;
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e2) { /* ignore */ }
  }
}

var _opensslCap = null;
function _opensslAvailable() {
  if (_opensslCap === null) {
    _opensslCap = _mintCertMinimal({ alg: "rsa", bits: 2048, hash: "sha256", days: 1 }) !== null;
  }
  return _opensslCap;
}

// ---- openssl ML-DSA certificate authority (self-signed + CA-issued) ----
//
// Runs `fn(toolkit)` inside a throwaway workspace directory, then removes it.
// The toolkit mints ML-DSA-65 self-signed and CA-issued certs and raw-signs
// bytes with an ML-DSA key. Returns null from a mint when the openssl build
// lacks ML-DSA.
function _withMlDsaCa(fn) {
  var fs = require("fs"), os = require("os"), path = require("path");
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-smime-mldsa-"));
  var seq = 0;
  function name(tag) { seq += 1; return path.join(dir, tag + seq); }
  function genKey() {
    var k = name("key") + ".pem";
    return spawnSync("openssl", ["genpkey", "-algorithm", "ML-DSA-65", "-out", k], { stdio: "pipe" }).status === 0 ? k : null;
  }
  function load(certPath, keyPath) {
    var pem = fs.readFileSync(certPath, "utf8");
    var der = Buffer.from(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");
    var cert = new nodeCrypto.X509Certificate(der);
    var spki = Buffer.from(cert.publicKey.export({ format: "der", type: "spki" }));
    return { pem: pem, der: der, cert: cert, certPath: certPath, keyPath: keyPath, rawPub: spki.subarray(spki.length - 1952) };
  }
  function selfSigned(cn, opts) {
    opts = opts || {};
    var key = genKey(); if (!key) return null;
    var cfg = name("cfg") + ".cnf";
    fs.writeFileSync(cfg, "[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=" + cn + "\n[v3]\nbasicConstraints=critical,CA:TRUE\n");
    var cert = name("cert") + ".pem";
    var args = ["req", "-x509", "-config", cfg, "-key", key, "-out", cert];
    if (opts.notBefore) { args.push("-not_before", opts.notBefore, "-not_after", opts.notAfter); }
    else                { args.push("-days", "3650"); }
    if (spawnSync("openssl", args, { stdio: "pipe" }).status !== 0) return null;
    return load(cert, key);
  }
  function caSign(cn, ca) {
    var key = genKey(); if (!key) return null;
    var rcfg = name("rcfg") + ".cnf";
    fs.writeFileSync(rcfg, "[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=" + cn + "\n");
    var csr = name("csr") + ".csr";
    if (spawnSync("openssl", ["req", "-new", "-config", rcfg, "-key", key, "-out", csr], { stdio: "pipe" }).status !== 0) return null;
    var ext = name("ext") + ".cnf";
    fs.writeFileSync(ext, "basicConstraints=critical,CA:TRUE\n");
    var cert = name("cert") + ".pem";
    if (spawnSync("openssl", ["x509", "-req", "-in", csr, "-CA", ca.certPath, "-CAkey", ca.keyPath,
      "-out", cert, "-days", "3650", "-extfile", ext, "-CAcreateserial"], { stdio: "pipe" }).status !== 0) return null;
    return load(cert, key);
  }
  function rawSign(keyPath, bytes) {
    var mp = name("msg") + ".bin"; fs.writeFileSync(mp, bytes);
    var r = spawnSync("openssl", ["pkeyutl", "-sign", "-rawin", "-inkey", keyPath, "-in", mp], { stdio: ["pipe", "pipe", "pipe"] });
    if (r.status !== 0) throw new Error("openssl ML-DSA sign failed");
    return r.stdout;
  }
  try { return fn({ selfSigned: selfSigned, caSign: caSign, rawSign: rawSign }); }
  finally { try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* ignore */ } }
}

var _mlDsaCap = null;
function _mlDsaAvailable() {
  if (_mlDsaCap === null) {
    _mlDsaCap = _withMlDsaCa(function (tk) { return tk.selfSigned("cap-probe") !== null; });
  }
  return _mlDsaCap;
}

// Detached ML-DSA CMS SignedData over `msg`, signed by openssl, embedding
// `certsDer` in SignedData.certificates. contentType + messageDigest signed-
// attrs are set so _verifySignerInfo's digest + content-type binding pass.
function _mlDsaEnvelope(tk, signerKeyPath, msg, certsDer) {
  var sa = _signedAttrs([
    _attr(OID_CT_ATTR, asn1.writeOid(OID.data)),
    _attr(OID_MD_ATTR, asn1.writeOctetString(_sha3_512(msg))),
  ]);
  var sig = tk.rawSign(signerKeyPath, sa.set);
  var si = asn1.writeSequence([
    asn1.writeInteger(Buffer.from([1])), _issuerSerialSid(0x01), _algId(OID.sha3_512),
    sa.implicit, _algId(OID.mldsa65), asn1.writeOctetString(sig),
  ]);
  return _craftSignedData({ signerInfos: [si], certsDer: certsDer });
}

// ---- sign(): input validation + cms-encode failure ----

function testSmimeSignInputValidation() {
  var kp = pqc.ml_dsa_65.keygen();
  function refused(label, opts, codeRe) {
    var threw = null;
    try { smime.sign(opts); } catch (e) { threw = e; }
    check("sign validate: " + label, threw && codeRe.test(String(threw.code || "")));
  }
  refused("certificate must be a Buffer",
    { message: "x", certificate: "not-a-buffer", secretKey: kp.secretKey, sigAlg: "ML-DSA-65" },
    /smime\/bad-opts/);
  refused("secretKey must be a Uint8Array",
    { message: "x", certificate: _testCertDer(), secretKey: "not-a-key", sigAlg: "ML-DSA-65" },
    /smime\/bad-opts/);
  refused("message must be Buffer or string",
    { message: 12345, certificate: _testCertDer(), secretKey: kp.secretKey, sigAlg: "ML-DSA-65" },
    /smime\/bad-opts/);
  // A well-formed opts bundle whose sigAlg the CMS substrate rejects surfaces
  // as sign-failed (the encodeSignedData throw is caught + re-typed).
  var threw = null;
  try { smime.sign({ message: "x", certificate: _testCertDer(), secretKey: kp.secretKey, sigAlg: "RSA-2048" }); }
  catch (e) { threw = e; }
  check("sign: unsupported sigAlg surfaces as sign-failed",
    threw && threw.code === "mail-crypto/smime/sign-failed");
}

// ---- verify(): input validation + parse failure + zero signers ----

function testSmimeVerifyInputValidation() {
  var kp = pqc.ml_dsa_65.keygen();
  function refused(label, opts, code) {
    var threw = null;
    try { smime.verify(opts); } catch (e) { threw = e; }
    check("verify validate: " + label, threw && threw.code === code);
  }
  refused("message missing",
    { signature: Buffer.from([1]), signerPublicKey: kp.publicKey }, "mail-crypto/smime/bad-opts");
  refused("signature not a Buffer",
    { message: "x", signature: "nope", signerPublicKey: kp.publicKey }, "mail-crypto/smime/bad-opts");
  refused("signerPublicKey not a Uint8Array",
    { message: "x", signature: Buffer.from([1]), signerPublicKey: "nope" }, "mail-crypto/smime/bad-opts");
  refused("garbage CMS signature bytes rejected at parse",
    { message: "x", signature: Buffer.from("not valid der at all"), signerPublicKey: kp.publicKey },
    "mail-crypto/smime/parse-failed");
}

function testSmimeVerifyNoSigners() {
  var kp = pqc.ml_dsa_65.keygen();
  var env = _craftSignedData({ signerInfos: [] });   // SignerInfos SET is empty
  var threw = null;
  try { smime.verify({ message: "x", signature: env, signerPublicKey: kp.publicKey }); }
  catch (e) { threw = e; }
  check("verify: zero-SignerInfo envelope refused with no-signers",
    threw && threw.code === "mail-crypto/smime/no-signers");
}

// ---- _verifySignerInfo(): every typed per-signer refusal ----

function testSmimeVerifySignerInfoRefusals() {
  var msg = Buffer.from("per-signer-refusal-body");
  var goodMd = _attr(OID_MD_ATTR, asn1.writeOctetString(_sha3_512(msg)));
  var goodCt = _attr(OID_CT_ATTR, asn1.writeOid(OID.data));
  var dummyPub = new Uint8Array(1952);
  function verifyCraft(label, craftOpts, code, pub) {
    var threw = null;
    try { smime.verify({ message: msg, signature: _craftSignedData(craftOpts), signerPublicKey: pub || dummyPub }); }
    catch (e) { threw = e; }
    check("verify signerInfo: " + label, threw && threw.code === code);
  }
  // sigAlg OID outside the PQC allowlist.
  verifyCraft("unknown sigAlg OID refused",
    { sigOid: "1.2.3.4.5", signedAttrsImplicit: _signedAttrs([goodMd]).implicit },
    "mail-crypto/smime/bad-sig-alg");
  // digestAlg OID outside {sha3-256, sha3-512}.
  verifyCraft("unknown digestAlg OID refused",
    { digestOid: "1.2.3.4.6", signedAttrsImplicit: _signedAttrs([goodMd]).implicit },
    "mail-crypto/smime/bad-digest");
  // v1 requires the signed-attrs path.
  verifyCraft("absent signedAttrs refused",
    { signedAttrsImplicit: null },
    "mail-crypto/smime/no-signed-attrs");
  // signedAttrs present but no messageDigest attribute.
  verifyCraft("missing messageDigest attribute refused",
    { signedAttrsImplicit: _signedAttrs([goodCt]).implicit },
    "mail-crypto/smime/no-message-digest-attr");
  // messageDigest matches but the contentType attribute is absent.
  verifyCraft("missing contentType attribute refused",
    { signedAttrsImplicit: _signedAttrs([goodMd]).implicit },
    "mail-crypto/smime/no-content-type-attr");
  // contentType present but does not equal the eContentType.
  verifyCraft("contentType mismatch refused",
    { signedAttrsImplicit: _signedAttrs([goodMd, _attr(OID_CT_ATTR, asn1.writeOid("1.2.3.4.7"))]).implicit },
    "mail-crypto/smime/content-type-mismatch");
  // Digest + contentType bind, but the PQC verify itself throws (a signer
  // public key of the wrong length makes ml-dsa verify reject its input).
  verifyCraft("PQC verify throwing surfaces as verify-failed",
    { signedAttrsImplicit: _signedAttrs([goodMd, goodCt]).implicit, signature: Buffer.from([1, 2, 3]) },
    "mail-crypto/smime/verify-failed", new Uint8Array([1, 2, 3]));
}

// _extractMessageDigest walks the attribute SET defensively — a malformed
// messageDigest attribute is skipped rather than trusted, and the walk then
// reports the missing attribute. Several distinct malformations exercise the
// per-attribute skip branches, all resolving to no-message-digest-attr.
function testSmimeMessageDigestExtractorDefensive() {
  var msg = Buffer.from("md-extractor-body");
  var dummyPub = new Uint8Array(1952);
  var badInner = Buffer.from([0x30, 0x05, 0x01]);   // SEQUENCE claiming length 5 with 1 byte
  // Re-tag a raw universal-SET buffer as the SignerInfo's [0] IMPLICIT signedAttrs.
  function implicitFromSet(setBuf) { return Buffer.concat([Buffer.from([0xa0]), setBuf.slice(1)]); }
  function expectNoMd(label, implicit) {
    var env = _craftSignedData({ signedAttrsImplicit: implicit });
    var threw = null;
    try { smime.verify({ message: msg, signature: env, signerPublicKey: dummyPub }); } catch (e) { threw = e; }
    check("md extractor: " + label, threw && threw.code === "mail-crypto/smime/no-message-digest-attr");
  }
  function fromAttrs(attrBufs) { return _signedAttrs(attrBufs).implicit; }
  // messageDigest OID present but its value SET carries an OID, not an OCTET STRING.
  expectNoMd("messageDigest value not an OCTET STRING",
    fromAttrs([_attr(OID_MD_ATTR, asn1.writeOid("1.2.3.4"))]));
  // An attribute SEQUENCE with a single child (attrType only, no values SET).
  expectNoMd("attribute with fewer than two children skipped",
    fromAttrs([asn1.writeSequence([asn1.writeOid(OID_MD_ATTR)]), _attr(OID_CT_ATTR, asn1.writeOid(OID.data))]));
  // messageDigest attrValues is an empty SET.
  expectNoMd("messageDigest with empty values SET skipped",
    fromAttrs([asn1.writeSequence([asn1.writeOid(OID_MD_ATTR), asn1.writeSet([])])]));
  // The signedAttrs SET contents are truncated → the attribute walk throws and
  // the extractor reports the attribute missing.
  expectNoMd("malformed signedAttrs SET body skipped", implicitFromSet(asn1.writeNode(0x31, badInner)));
  // A SET member that is not a SEQUENCE is skipped.
  expectNoMd("non-SEQUENCE attribute skipped", implicitFromSet(asn1.writeSet([asn1.writeOid("1.2.3")])));
  // An attribute SEQUENCE with truncated contents is skipped.
  expectNoMd("attribute with malformed contents skipped",
    implicitFromSet(asn1.writeSet([asn1.writeNode(0x30, badInner)])));
  // An attribute whose attrType is not an OID is skipped.
  expectNoMd("attribute with non-OID attrType skipped",
    implicitFromSet(asn1.writeSet([asn1.writeSequence([asn1.writeSequence([]), asn1.writeSet([])])])));
  // messageDigest attribute present but its values field is not a SET.
  expectNoMd("messageDigest values field not a SET skipped",
    fromAttrs([asn1.writeSequence([asn1.writeOid(OID_MD_ATTR), asn1.writeSequence([])])]));
  // messageDigest attribute present but its values SET body is truncated.
  expectNoMd("messageDigest values SET malformed skipped",
    fromAttrs([asn1.writeSequence([asn1.writeOid(OID_MD_ATTR), asn1.writeNode(0x31, badInner)])]));
}

// _audit is drop-silent and tolerates an audit handle that lacks a safeEmit
// method — sign() must not throw when handed such an object.
function testSmimeAuditHandleWithoutSafeEmit() {
  var kp = pqc.ml_dsa_65.keygen();
  var out = smime.sign({ message: "audited", certificate: _testCertDer(),
    secretKey: kp.secretKey, sigAlg: "ML-DSA-65", audit: { notSafeEmit: true } });
  check("sign: audit handle without safeEmit is tolerated (drop-silent)",
    typeof out.multipart === "string" && out.multipart.indexOf("multipart/signed") !== -1);
}

// ---- _extractContentTypeOid(): defensive extraction branches ----

function testSmimeContentTypeExtractorDefensive() {
  function isNull(label, raw) {
    check("ct extractor: " + label, smime._extractContentTypeOid(raw) === null);
  }
  var badInner = Buffer.from([0x30, 0x05, 0x01]);   // SEQUENCE claiming length 5 with 1 byte
  // Unparseable top-level bytes → null (the readNode itself throws).
  isNull("unparseable top node yields null", Buffer.from([0x31, 0x05, 0x01]));
  // Not a SET at the top → null.
  isNull("non-SET top node yields null", asn1.writeSequence([asn1.writeOid(OID.data)]));
  // Top SET whose contents are truncated so the attribute walk throws → null.
  isNull("malformed SET contents yield null", asn1.writeNode(0x31, badInner));
  // A SET member that is not a SEQUENCE is skipped → null.
  isNull("non-SEQUENCE attribute skipped", asn1.writeSet([asn1.writeOid("1.2.3")]));
  // An attribute SEQUENCE with truncated contents is skipped → null.
  isNull("attribute with malformed contents skipped", asn1.writeSet([asn1.writeNode(0x30, badInner)]));
  // An attribute whose attrType is not an OID is skipped → null.
  isNull("attribute with non-OID attrType skipped",
    asn1.writeSet([asn1.writeSequence([asn1.writeSequence([]), asn1.writeSet([])])]));
  // A SET whose only attribute is not the contentType OID → null.
  isNull("SET without a contentType attribute yields null",
    asn1.writeSet([_attr(OID_MD_ATTR, asn1.writeOctetString(Buffer.alloc(4)))]));
  // contentType attribute present but its values field is not a SET → null.
  isNull("contentType values field not a SET yields null",
    asn1.writeSet([asn1.writeSequence([asn1.writeOid(OID_CT_ATTR), asn1.writeSequence([])])]));
  // contentType attribute present but its values SET is truncated → null.
  isNull("contentType values SET malformed yields null",
    asn1.writeSet([asn1.writeSequence([asn1.writeOid(OID_CT_ATTR), asn1.writeNode(0x31, badInner)])]));
  // contentType attribute present but its values SET is empty → null.
  isNull("contentType with empty values SET yields null",
    asn1.writeSet([asn1.writeSequence([asn1.writeOid(OID_CT_ATTR), asn1.writeSet([])])]));
  // contentType values SET carries a non-OID value → null.
  isNull("contentType value not an OID yields null",
    asn1.writeSet([_attr(OID_CT_ATTR, asn1.writeOctetString(Buffer.from([1])))]));
  // An attribute SEQUENCE with only one child is skipped → null.
  isNull("attribute with a single child skipped",
    asn1.writeSet([asn1.writeSequence([asn1.writeOid(OID_CT_ATTR)])]));
}

// The sha3-256 digest option is a documented alternative to the sha3-512
// default; it drives the sha3-256 micalg in sign() and the sha3-256 resolver
// in verify().
function testSmimeSignVerifySha3_256() {
  var kp = pqc.ml_dsa_65.keygen();
  var msg = "From: a@b\r\nSubject: sha3-256\r\n\r\nbody";
  var out = smime.sign({ message: msg, certificate: _testCertDer(), secretKey: kp.secretKey,
    sigAlg: "ML-DSA-65", digestAlg: "sha3-256" });
  check("sign: sha3-256 option sets micalg=sha3-256", out.micalg === "sha3-256");
  var v = smime.verify({ message: msg, signature: out.signature, signerPublicKey: kp.publicKey });
  check("verify: sha3-256 envelope verifies with digestAlg sha3-256",
    v.valid === true && v.digestAlg === "sha3-256");
}

// ---- _certKeyMatches(): signer key longer than the cert SPKI ----

function testSmimeCertKeyMatchesLongerSigner() {
  var kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var spki = Buffer.from(kp.publicKey.export({ format: "der", type: "spki" }));
  var longer = Buffer.concat([spki, Buffer.alloc(16)]);   // strictly longer than the SPKI
  check("certKeyMatches: signer key longer than SPKI does not match",
    smime._certKeyMatches({ publicKey: kp.publicKey }, longer) === false);
}

// ---- verifyAll(): zero signers + SKI serial-hex fallback ----

function testVerifyAllNoSigners() {
  var env = _craftSignedData({ signerInfos: [] });
  var threw = null;
  try { smime.verifyAll({ message: "x", signature: env, signerPublicKeys: {} }); }
  catch (e) { threw = e; }
  check("verifyAll: zero-SignerInfo envelope refused with no-signers",
    threw && threw.code === "mail-crypto/smime/no-signers");
}

function testVerifyAllSkiSidFallback() {
  // A SignerInfo whose sid is a [0] IMPLICIT SubjectKeyIdentifier (not an
  // issuerAndSerialNumber SEQUENCE). _extractSerialHex falls back to the raw
  // node value hex; with no key mapped to that hex, verifyAll refuses.
  var skiBytes = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
  var sid = asn1.writeContextImplicit(0, skiBytes);       // [0] IMPLICIT OCTET STRING
  var sa = _signedAttrs([_attr(OID_CT_ATTR, asn1.writeOid(OID.data))]);
  var si = asn1.writeSequence([
    asn1.writeInteger(Buffer.from([1])), sid, _algId(OID.sha3_512),
    sa.implicit, _algId(OID.mldsa65), asn1.writeOctetString(Buffer.from([0, 0, 1])),
  ]);
  var env = _craftSignedData({ signerInfos: [si] });
  var threw = null;
  try { smime.verifyAll({ message: "x", signature: env, signerPublicKeys: {} }); }
  catch (e) { threw = e; }
  check("verifyAll: SKI-variant sid resolves to raw-hex, then missing-key",
    threw && threw.code === "mail-crypto/smime/missing-key");
  check("verifyAll: missing-key names the SKI-derived serial",
    threw && /deadbeef/.test(String(threw.message || "")));
}

// ---- Trust-chain refusals reachable without ML-DSA certs ----

function testSmimeTrustChainNoCerts() {
  // sign() embeds no certificates, so verifying with trust anchors present
  // reaches _verifyTrustChain and fails at the empty-certificate-set guard.
  var kp = pqc.ml_dsa_65.keygen();
  var msg = "no-embedded-certs";
  var out = smime.sign({ message: msg, certificate: _testCertDer(), secretKey: kp.secretKey, sigAlg: "ML-DSA-65" });
  var threw = null;
  try {
    smime.verify({ message: msg, signature: out.signature, signerPublicKey: kp.publicKey,
      trustAnchorCertsPem: ["-----BEGIN CERTIFICATE-----\nunused\n-----END CERTIFICATE-----"] });
  } catch (e) { threw = e; }
  check("trust chain: verify with anchors but no embedded certs refused (no-certs)",
    threw && threw.code === "mail-crypto/smime/no-certs");
}

function testSmimeTrustChainBadChainCert() {
  // An unparseable cert in SignedData.certificates fails the chain-cert parse.
  var kp = pqc.ml_dsa_65.keygen();
  var msg = Buffer.from("bad-embedded-cert");
  var fakeDer = asn1.writeSequence([asn1.writeInteger(Buffer.from([1]))]);
  var env = b.cms.encodeSignedData({
    encapContent: msg, digestAlg: "sha3-512", detached: true, certificates: [fakeDer],
    signers: [{ certificate: _testCertDer(), secretKey: kp.secretKey, sigAlg: "ML-DSA-65" }],
  });
  var threw = null;
  try {
    smime.verify({ message: msg, signature: env, signerPublicKey: kp.publicKey,
      trustAnchorCertsPem: ["-----BEGIN CERTIFICATE-----\nunused\n-----END CERTIFICATE-----"] });
  } catch (e) { threw = e; }
  check("trust chain: unparseable embedded cert refused (bad-chain-cert)",
    threw && threw.code === "mail-crypto/smime/bad-chain-cert");
}

function testSmimeTrustChainRealCertRefusals() {
  if (!_opensslAvailable()) {
    check("trust chain real-cert refusals skipped (openssl unavailable)", true);
    return;
  }
  var real = _mintCertMinimal({ alg: "rsa", bits: 2048, hash: "sha256", days: 30, cn: "chain-real.example" });
  if (!real) {
    check("trust chain real-cert refusals skipped (cert mint failed)", true);
    return;
  }
  var kp = pqc.ml_dsa_65.keygen();
  var msg = Buffer.from("real-cert-in-chain");
  function envWith() {
    return b.cms.encodeSignedData({
      encapContent: msg, digestAlg: "sha3-512", detached: true, certificates: [real.der],
      signers: [{ certificate: _testCertDer(), secretKey: kp.secretKey, sigAlg: "ML-DSA-65" }],
    });
  }
  function refused(label, trustAnchors, code) {
    var threw = null;
    try {
      smime.verify({ message: msg, signature: envWith(), signerPublicKey: kp.publicKey, trustAnchorCertsPem: trustAnchors });
    } catch (e) { threw = e; }
    check("trust chain: " + label, threw && threw.code === code);
  }
  // The PQC signer key matches no embedded (RSA) cert → signer not in chain.
  refused("PQC signer key absent from embedded certs (signer-not-in-chain)",
    [real.pem], "mail-crypto/smime/signer-not-in-chain");
  // A non-string trust anchor entry is refused at anchor parse.
  refused("non-string trust anchor entry refused (bad-trust-anchor)",
    [123], "mail-crypto/smime/bad-trust-anchor");
  // An unparseable trust anchor PEM is refused at anchor parse.
  refused("unparseable trust anchor PEM refused (bad-trust-anchor)",
    ["not a certificate"], "mail-crypto/smime/bad-trust-anchor");
}

// ---- Trust-chain walk (ML-DSA certs; openssl-signed CMS) ----

function testSmimeTrustChainMlDsaWalk() {
  if (!_mlDsaAvailable()) {
    check("trust chain ML-DSA walk skipped (openssl ML-DSA unavailable)", true);
    return;
  }
  _withMlDsaCa(function (tk) {
    var msg = Buffer.from("ml-dsa-chain-walk-body");
    var leaf = tk.selfSigned("Leaf Signer");
    var other = tk.selfSigned("Unrelated Root");
    if (!leaf || !other) {
      check("trust chain ML-DSA walk skipped (cert mint failed)", true);
      return;
    }
    // Self-signed leaf IS the trust anchor → full walk validates.
    var v = smime.verify({ message: msg, signature: _mlDsaEnvelope(tk, leaf.keyPath, msg, [leaf.der]),
      signerPublicKey: leaf.rawPub, trustAnchorCertsPem: [leaf.pem] });
    check("trust chain: self-signed leaf as anchor verifies with chainVerified",
      v.valid === true && v.chainVerified === true);

    // Same leaf, but the only anchor is an unrelated root → no anchor reached.
    var t1 = null;
    try {
      smime.verify({ message: msg, signature: _mlDsaEnvelope(tk, leaf.keyPath, msg, [leaf.der]),
        signerPublicKey: leaf.rawPub, trustAnchorCertsPem: [other.pem] });
    } catch (e) { t1 = e; }
    check("trust chain: leaf not reaching any anchor refused (untrusted-chain)",
      t1 && t1.code === "mail-crypto/smime/untrusted-chain");

    // An expired cert alongside the valid leaf trips the validity-window check.
    var expired = tk.selfSigned("Expired Cert", { notBefore: "20200101000000Z", notAfter: "20200102000000Z" });
    if (expired) {
      var t2 = null;
      try {
        smime.verify({ message: msg, signature: _mlDsaEnvelope(tk, leaf.keyPath, msg, [leaf.der, expired.der]),
          signerPublicKey: leaf.rawPub, trustAnchorCertsPem: [leaf.pem] });
      } catch (e) { t2 = e; }
      check("trust chain: expired chain cert refused (cert-expired)",
        t2 && t2.code === "mail-crypto/smime/cert-expired");
    }

    // A not-yet-valid cert alongside the valid leaf trips the same check.
    var future = tk.selfSigned("Future Cert", { notBefore: "20350101000000Z", notAfter: "20360101000000Z" });
    if (future) {
      var t3 = null;
      try {
        smime.verify({ message: msg, signature: _mlDsaEnvelope(tk, leaf.keyPath, msg, [leaf.der, future.der]),
          signerPublicKey: leaf.rawPub, trustAnchorCertsPem: [leaf.pem] });
      } catch (e) { t3 = e; }
      check("trust chain: not-yet-valid chain cert refused (cert-not-yet-valid)",
        t3 && t3.code === "mail-crypto/smime/cert-not-yet-valid");
    }
  });
}

function testSmimeTrustChainMlDsaIntermediate() {
  if (!_mlDsaAvailable()) {
    check("trust chain ML-DSA intermediate skipped (openssl ML-DSA unavailable)", true);
    return;
  }
  _withMlDsaCa(function (tk) {
    var root = tk.selfSigned("Root CA");
    if (!root) { check("trust chain intermediate skipped (root mint failed)", true); return; }
    var inter = tk.caSign("Intermediate CA", root);
    var leaf  = inter && tk.caSign("Leaf Signer", inter);
    if (!inter || !leaf) { check("trust chain intermediate skipped (CA issuance failed)", true); return; }
    var msg = Buffer.from("intermediate-walk-body");
    // Chain carries leaf + intermediate; only the root is a trust anchor, so
    // the walk must hop leaf → intermediate → root.
    var v = smime.verify({ message: msg, signature: _mlDsaEnvelope(tk, leaf.keyPath, msg, [leaf.der, inter.der]),
      signerPublicKey: leaf.rawPub, trustAnchorCertsPem: [root.pem] });
    check("trust chain: leaf → intermediate → root walk validates",
      v.valid === true && v.chainVerified === true);
  });
}

function testVerifyAllTrustChain() {
  if (!_mlDsaAvailable()) {
    check("verifyAll trust chain skipped (openssl ML-DSA unavailable)", true);
    return;
  }
  _withMlDsaCa(function (tk) {
    var leaf = tk.selfSigned("VerifyAll Leaf");
    if (!leaf) { check("verifyAll trust chain skipped (cert mint failed)", true); return; }
    var msg = Buffer.from("verifyall-chain-body");
    var v = smime.verifyAll({ message: msg, signature: _mlDsaEnvelope(tk, leaf.keyPath, msg, [leaf.der]),
      signerPublicKeys: { "01": leaf.rawPub }, trustAnchorCertsPem: [leaf.pem] });
    check("verifyAll: trust-anchor chain validates through the bundle",
      v.valid === true && v.chainVerified === true);
  });
}

// ---- checkCert(): parsed-cert body (real openssl certs) ----

function testSmimeCheckCertRealCerts() {
  if (!_opensslAvailable()) {
    check("checkCert real-cert body skipped (openssl unavailable)", true);
    return;
  }
  var rsa = _mintCertMinimal({ alg: "rsa", bits: 2048, hash: "sha256", days: 30, cn: "rsa.example" });
  if (rsa) {
    var rv = smime.checkCert({ certPem: rsa.pem });
    check("checkCert: RSA-2048/sha256 cert returns rsa keyType", rv.keyType === "rsa");
    check("checkCert: reports the signature algorithm name", /rsa/i.test(rv.sigAlgName));
    check("checkCert: returns a SHA-256 fingerprint", /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(rv.fingerprint256));
    check("checkCert: returns subject + issuer DN strings",
      typeof rv.subject === "string" && typeof rv.issuer === "string");
  } else {
    check("checkCert RSA happy path skipped (mint failed)", true);
  }

  // EC cert exercises the non-RSA path — the RSA bit-floor block is skipped.
  var ec = _mintCertMinimal({ alg: "ec", curve: "P-256", hash: "sha256", days: 30, cn: "ec.example" });
  if (ec) {
    var ev = smime.checkCert({ certPem: ec.pem });
    check("checkCert: EC cert reports ec keyType (RSA floor skipped)", ev.keyType === "ec");
  } else {
    check("checkCert EC happy path skipped (mint failed)", true);
  }

  // SHA-1-signed cert is refused at the signature-algorithm screen.
  var sha1 = _mintCertMinimal({ alg: "rsa", bits: 2048, hash: "sha1", days: 30, cn: "sha1.example" });
  if (sha1) {
    var t1 = null;
    try { smime.checkCert({ certPem: sha1.pem }); } catch (e) { t1 = e; }
    check("checkCert: SHA-1 cert signature refused (refused-hash)",
      t1 && t1.code === "mail-crypto/smime/refused-hash");
  } else {
    check("checkCert SHA-1 refusal skipped (mint failed)", true);
  }

  // Sub-2048-bit RSA is refused at the bit floor.
  var weak = _mintCertMinimal({ alg: "rsa", bits: 1024, hash: "sha256", days: 30, cn: "weak.example" });
  if (weak) {
    var t2 = null;
    try { smime.checkCert({ certPem: weak.pem }); } catch (e) { t2 = e; }
    check("checkCert: RSA-1024 cert refused at the bit floor (rsa-too-small)",
      t2 && t2.code === "mail-crypto/smime/rsa-too-small");
  } else {
    check("checkCert small-RSA refusal skipped (mint failed)", true);
  }
}

function testSmimeCheckCertValidityWindow() {
  if (!_opensslAvailable()) {
    check("checkCert validity window skipped (openssl unavailable)", true);
    return;
  }
  var expired = _mintCertMinimal({ alg: "rsa", bits: 2048, hash: "sha256",
    notBefore: "20200101000000Z", notAfter: "20200102000000Z", cn: "expired.example" });
  if (expired) {
    var t1 = null;
    try { smime.checkCert({ certPem: expired.pem }); } catch (e) { t1 = e; }
    check("checkCert: expired cert refused (expired-cert)",
      t1 && t1.code === "mail-crypto/smime/expired-cert" && /expired/.test(t1.message));
  } else {
    check("checkCert expired-cert skipped (mint failed)", true);
  }
  var future = _mintCertMinimal({ alg: "rsa", bits: 2048, hash: "sha256",
    notBefore: "20350101000000Z", notAfter: "20360101000000Z", cn: "future.example" });
  if (future) {
    var t2 = null;
    try { smime.checkCert({ certPem: future.pem }); } catch (e) { t2 = e; }
    check("checkCert: not-yet-valid cert refused (expired-cert / not yet valid)",
      t2 && t2.code === "mail-crypto/smime/expired-cert" && /not yet valid/.test(t2.message));
  } else {
    check("checkCert not-yet-valid skipped (mint failed)", true);
  }
}

function run() {
  testSmimeSurface();
  testSmimeContentTypeAttrExtraction();
  testSmimeCertKeyBinding();
  testSmimeSignVerifyRoundtrip();
  testSmimeVerifyTamperRefused();
  testSmimeVerifyWrongKeyRefused();
  testSmimeSignSupportsMlDsa87();
  testSmimeSignSupportsSlhDsa();
  testSmimeSignBadOpts();
  testSmimeCheckCertHappyPath();
  testSmimeCheckCertRefusesSha1();
  testSmimeCheckCertRefusesSmallRsa();
  testSmimeCheckCertInputValidation();
  testSmimeDocBlockCitations();
  testVerifyAllMultiSigner();
  testVerifyAllPerSignerKeyBinding();
  testVerifyAllMissingKey();
  testVerifyAllTamperRefused();
  testVerifyAllSingleSigner();
  testVerifyAllInputValidation();
  // Uncovered error / adversarial / defensive branches.
  testSmimeSignInputValidation();
  testSmimeVerifyInputValidation();
  testSmimeVerifyNoSigners();
  testSmimeVerifySignerInfoRefusals();
  testSmimeMessageDigestExtractorDefensive();
  testSmimeContentTypeExtractorDefensive();
  testSmimeAuditHandleWithoutSafeEmit();
  testSmimeSignVerifySha3_256();
  testSmimeCertKeyMatchesLongerSigner();
  testVerifyAllNoSigners();
  testVerifyAllSkiSidFallback();
  testSmimeTrustChainNoCerts();
  testSmimeTrustChainBadChainCert();
  testSmimeTrustChainRealCertRefusals();
  testSmimeTrustChainMlDsaWalk();
  testSmimeTrustChainMlDsaIntermediate();
  testVerifyAllTrustChain();
  testSmimeCheckCertRealCerts();
  testSmimeCheckCertValidityWindow();
}

module.exports = { run: run };

if (require.main === module) {
  try {
    run();
    console.log("OK — " + helpers.getChecks() + " checks passed");
  } catch (e) {
    console.error("FAIL:", e && e.stack || e);
    process.exit(1);
  }
}
