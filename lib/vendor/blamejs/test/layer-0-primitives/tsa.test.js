// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.tsa (RFC 3161 timestamp client) over b.cms + asn1-der.
 *
 * The verify paths need real-shaped timestamp tokens. Two sources:
 *   (1) a pure-node "mock TSA" (cert + TimeStampToken built with the
 *       in-tree ASN.1 DER codec, signed with classical RSA / ECDSA via
 *       node:crypto) — hermetic, runs everywhere, and gives full control
 *       over the cert's extendedKeyUsage so the §2.3 refusal paths
 *       (non-critical / multi-purpose EKU) are exercised;
 *   (2) an OpenSSL `ts -reply` round-trip when openssl(1) is on PATH —
 *       an independent implementation, regression-guarding real-world
 *       interop (skipped gracefully where openssl is absent).
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
var asn1 = require("../../lib/asn1-der");
var nodeCrypto = require("node:crypto");

var ID_CT_TST_INFO = "1.2.840.113549.1.9.16.1.4";
var ID_KP_TIMESTAMPING = "1.3.6.1.5.5.7.3.8";
var ID_KP_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
var OID_CONTENT_TYPE_ATTR = "1.2.840.113549.1.9.3";
var OID_MESSAGE_DIGEST_ATTR = "1.2.840.113549.1.9.4";
var OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
var OID_SHA256 = "2.16.840.1.101.3.4.2.1";
var OID_SHA512 = "2.16.840.1.101.3.4.2.3";
var OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1";
var OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";

function _utcTime(date) {
  var s = date.toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z";   // YYMMDDHHMMSSZ
  return asn1.writeNode(0x17, Buffer.from(s, "ascii"));
}
function _genTime(date) {
  var s = date.toISOString().replace(/[-:T]/g, "").slice(0, 14) + "Z";   // YYYYMMDDHHMMSSZ
  return asn1.writeNode(0x18, Buffer.from(s, "ascii"));
}
function _algId(oid, withNull) {
  return withNull ? asn1.writeSequence([asn1.writeOid(oid), asn1.writeNull()])
    : asn1.writeSequence([asn1.writeOid(oid)]);
}
function _name(cn) {
  return asn1.writeSequence([asn1.writeSet([
    asn1.writeSequence([asn1.writeOid("2.5.4.3"), asn1.writeUtf8String(cn)]),
  ])]);
}

// Mint a minimal self-signed X.509v3 cert with a chosen extendedKeyUsage.
function _makeCert(opts) {
  opts = opts || {};
  var keyType = opts.keyType || "rsa";
  var kp = keyType === "ec"
    ? nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" })
    : nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var spki = kp.publicKey.export({ type: "spki", format: "der" });

  var version = asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2])));   // v3
  var serial = asn1.writeInteger(Buffer.from([0x2a]));
  var sigOid = keyType === "ec" ? OID_ECDSA_SHA256 : "1.2.840.113549.1.1.11";
  var sigAlgId = _algId(sigOid, keyType !== "ec");
  var name = _name(opts.cn || "Test TSA");
  var now = Date.now();
  var validity = asn1.writeSequence([
    _utcTime(new Date(now - 86400000)),
    _utcTime(new Date(now + 86400000 * 3650)),
  ]);

  var extsList = [];
  if (opts.ekuOids !== null) {
    var ekuOids = opts.ekuOids || [ID_KP_TIMESTAMPING];
    var ekuChildren = [asn1.writeOid("2.5.29.37")];
    if (opts.ekuCritical !== false) ekuChildren.push(asn1.writeBoolean(true));
    ekuChildren.push(asn1.writeOctetString(asn1.writeSequence(ekuOids.map(asn1.writeOid))));
    extsList.push(asn1.writeSequence(ekuChildren));
  }
  var children = [version, serial, sigAlgId, name, validity, name, spki];
  if (extsList.length) children.push(asn1.writeContextExplicit(3, asn1.writeSequence(extsList)));
  var tbs = asn1.writeSequence(children);

  var tbsSig = nodeCrypto.sign("sha256", tbs, kp.privateKey);
  var certDer = asn1.writeSequence([tbs, sigAlgId, asn1.writeBitString(tbsSig, 0)]);
  return { certDer: certDer, key: kp.privateKey, serial: Buffer.from([0x2a]), issuer: name };
}

// Build an RFC 3161 TimeStampToken (CMS SignedData over a TSTInfo).
function _makeToken(opts) {
  var imprintOid = opts.imprintHashOid || OID_SHA512;
  var imprintHash = opts.imprintHash;
  var tstChildren = [
    asn1.writeInteger(Buffer.from([1])),                                  // version
    asn1.writeOid(opts.policy || "1.2.3.4.1"),                            // policy
    asn1.writeSequence([_algId(imprintOid, true), asn1.writeOctetString(imprintHash)]),
    asn1.writeInteger(Buffer.from([0x05])),                               // serialNumber
    _genTime(opts.genTime || new Date()),
  ];
  if (opts.nonce) tstChildren.push(asn1.writeInteger(opts.nonce));
  var tstInfo = asn1.writeSequence(tstChildren);

  // signed attributes (contentType + messageDigest), signed as a SET.
  var digestNode = opts.signerDigest || "sha512";
  var digestOid = digestNode === "sha256" ? OID_SHA256 : OID_SHA512;
  var msgDigest = nodeCrypto.createHash(digestNode).update(tstInfo).digest();
  var ctAttr = asn1.writeSequence([asn1.writeOid(OID_CONTENT_TYPE_ATTR),
    asn1.writeSet([asn1.writeOid(ID_CT_TST_INFO)])]);
  var mdAttr = asn1.writeSequence([asn1.writeOid(OID_MESSAGE_DIGEST_ATTR),
    asn1.writeSet([asn1.writeOctetString(msgDigest)])]);
  var signedSet = asn1.writeSet([ctAttr, mdAttr]);                        // 0x31… — the signed bytes
  var sigAlgOid = opts.sigAlgOid || OID_RSA_ENCRYPTION;
  // The signature hash is the one the signatureAlgorithm OID implies;
  // hashless OIDs (rsaEncryption / id-ecPublicKey / PSS) take the
  // digestAlgorithm hash — exactly what the verifier derives.
  var SIGN_HASH = {
    "1.2.840.10045.4.3.2": "sha256", "1.2.840.10045.4.3.3": "sha384", "1.2.840.10045.4.3.4": "sha512",
    "1.2.840.113549.1.1.11": "sha256", "1.2.840.113549.1.1.12": "sha384", "1.2.840.113549.1.1.13": "sha512",
  };
  var signHash = SIGN_HASH[sigAlgOid] || digestNode;
  var sig = nodeCrypto.sign(signHash, signedSet, opts.key);
  var signedAttrsImplicit = Buffer.concat([Buffer.from([0xa0]), signedSet.slice(1)]);  // [0] IMPLICIT

  var sid = asn1.writeSequence([opts.issuer, asn1.writeInteger(opts.serial)]);
  var signerInfo = asn1.writeSequence([
    asn1.writeInteger(Buffer.from([1])),                                  // version
    sid,
    _algId(digestOid, true),
    signedAttrsImplicit,
    _algId(sigAlgOid, sigAlgOid.indexOf("10045") === -1),                 // RSA: AlgId+NULL; EC: no NULL
    asn1.writeOctetString(sig),
  ]);

  var encap = asn1.writeSequence([asn1.writeOid(ID_CT_TST_INFO),
    asn1.writeContextExplicit(0, asn1.writeOctetString(tstInfo))]);
  var certsField = asn1.writeContextImplicit(0, opts.certDer, { constructed: true });
  var signedData = asn1.writeSequence([
    asn1.writeInteger(Buffer.from([3])),                                  // version
    asn1.writeSet([_algId(digestOid, true)]),
    encap,
    certsField,
    asn1.writeSet([signerInfo]),
  ]);
  return asn1.writeSequence([asn1.writeOid(OID_SIGNED_DATA), asn1.writeContextExplicit(0, signedData)]);
}

function _imprintOf(data, hashAlg) {
  var node = hashAlg === "SHA-256" ? "sha256" : "sha512";
  return nodeCrypto.createHash(node).update(data).digest();
}

function testSurface() {
  check("b.tsa.buildRequest is a function", typeof b.tsa.buildRequest === "function");
  check("b.tsa.parseResponse is a function", typeof b.tsa.parseResponse === "function");
  check("b.tsa.verifyToken is a function", typeof b.tsa.verifyToken === "function");
  check("b.tsa.IMPRINT_HASHES includes SHA-512", !!b.tsa.IMPRINT_HASHES["SHA-512"]);
  check("b.tsa.TsaError is a class", typeof b.tsa.TsaError === "function");
}

function testBuildRequest() {
  var req = b.tsa.buildRequest(Buffer.from("hello"), { hashAlg: "SHA-512" });
  check("buildRequest returns der + nonce + imprint", Buffer.isBuffer(req.der) && Buffer.isBuffer(req.nonce) && Buffer.isBuffer(req.messageImprint));
  check("buildRequest imprint is the SHA-512 of the data", req.messageImprint.equals(_imprintOf(Buffer.from("hello"), "SHA-512")));
  // Decode the request and confirm structure.
  var c = asn1.readSequence(asn1.readNode(req.der, 0).value);
  check("request version is 1", asn1.readUnsignedInt(c[0]) === 1);
  var mi = asn1.readSequence(c[1].value);
  check("request imprint hash OID is SHA-512", asn1.readOid(asn1.readSequence(mi[0].value)[0]) === OID_SHA512);

  // nonce:false omits it; certReq:false omits the boolean.
  var noNonce = b.tsa.buildRequest(Buffer.from("x"), { nonce: false });
  check("buildRequest nonce:false → null nonce", noNonce.nonce === null);

  // pre-hashed input must match the algorithm length.
  var ok = b.tsa.buildRequest(_imprintOf(Buffer.from("y"), "SHA-512"), { hashAlg: "SHA-512", hashed: true });
  check("buildRequest hashed:true accepts a correct-length digest", ok.messageImprint.equals(_imprintOf(Buffer.from("y"), "SHA-512")));
  var threw = null;
  try { b.tsa.buildRequest(Buffer.from("short"), { hashAlg: "SHA-512", hashed: true }); } catch (e) { threw = e; }
  check("buildRequest rejects wrong-length pre-hash", threw && threw.code === "tsa/bad-hash-length");
  var badAlg = null;
  try { b.tsa.buildRequest(Buffer.from("z"), { hashAlg: "MD5" }); } catch (e) { badAlg = e; }
  check("buildRequest rejects unknown hashAlg", badAlg && badAlg.code === "tsa/bad-hash-alg");
}

function testVerifyHappyPath(keyType, sigAlgOid, label) {
  var data = Buffer.from("artifact-bytes-" + label);
  var nonce = nodeCrypto.randomBytes(8);
  var cert = _makeCert({ keyType: keyType });
  // Independent cross-check: node parses our minted cert and reports the EKU.
  var x = new nodeCrypto.X509Certificate(cert.certDer);
  check(label + ": minted cert carries timeStamping EKU (node-parsed)", (x.keyUsage || []).indexOf(ID_KP_TIMESTAMPING) !== -1);

  var token = _makeToken({
    certDer: cert.certDer, key: cert.key, issuer: cert.issuer, serial: cert.serial,
    imprintHash: _imprintOf(data, "SHA-512"), nonce: nonce,
    sigAlgOid: sigAlgOid, signerDigest: "sha512",
  });
  var out = b.tsa.verifyToken(token, { data: data, hashAlg: "SHA-512", nonce: nonce });
  check(label + ": verifyToken returns genTime Date", out.genTime instanceof Date);
  check(label + ": verifyToken returns policy", out.policy === "1.2.3.4.1");
  check(label + ": verifyToken reports hashAlg", out.hashAlg === "SHA-512");

  // wrong data → imprint mismatch
  var e1 = null;
  try { b.tsa.verifyToken(token, { data: Buffer.from("other"), hashAlg: "SHA-512" }); } catch (e) { e1 = e; }
  check(label + ": wrong data refused (imprint-mismatch)", e1 && e1.code === "tsa/imprint-mismatch");

  // wrong nonce → nonce mismatch
  var e2 = null;
  try { b.tsa.verifyToken(token, { data: data, hashAlg: "SHA-512", nonce: nodeCrypto.randomBytes(8) }); } catch (e) { e2 = e; }
  check(label + ": wrong nonce refused", e2 && e2.code === "tsa/nonce-mismatch");

  // wrong hashAlg → imprint-alg mismatch
  var e3 = null;
  try { b.tsa.verifyToken(token, { data: data, hashAlg: "SHA-256" }); } catch (e) { e3 = e; }
  check(label + ": wrong hashAlg refused (imprint-alg-mismatch)", e3 && e3.code === "tsa/imprint-alg-mismatch");

  // tamper a byte in the token → signature fails
  var bad = Buffer.from(token); bad[bad.length - 5] ^= 0xff;
  var e4 = null;
  try { b.tsa.verifyToken(bad, { data: data, hashAlg: "SHA-512" }); } catch (e) { e4 = e; }
  check(label + ": tampered token refused", e4 && (e4.code === "tsa/bad-signature" || e4.code === "tsa/message-digest-mismatch" || e4.code === "tsa/not-cms"));
}

function testEkuRefusals() {
  var data = Buffer.from("eku-test");
  function tokenFor(certOpts) {
    var cert = _makeCert(certOpts);
    return _makeToken({ certDer: cert.certDer, key: cert.key, issuer: cert.issuer, serial: cert.serial,
      imprintHash: _imprintOf(data, "SHA-512") });
  }
  // non-critical EKU
  var e1 = null;
  try { b.tsa.verifyToken(tokenFor({ ekuCritical: false }), { data: data, hashAlg: "SHA-512" }); } catch (e) { e1 = e; }
  check("non-critical EKU refused", e1 && e1.code === "tsa/bad-eku");
  // multi-purpose EKU (timeStamping + serverAuth) — not the sole purpose
  var e2 = null;
  try { b.tsa.verifyToken(tokenFor({ ekuOids: [ID_KP_TIMESTAMPING, ID_KP_SERVER_AUTH] }), { data: data, hashAlg: "SHA-512" }); } catch (e) { e2 = e; }
  check("multi-purpose EKU refused (not sole)", e2 && e2.code === "tsa/bad-eku");
  // wrong single purpose
  var e3 = null;
  try { b.tsa.verifyToken(tokenFor({ ekuOids: [ID_KP_SERVER_AUTH] }), { data: data, hashAlg: "SHA-512" }); } catch (e) { e3 = e; }
  check("wrong EKU purpose refused", e3 && e3.code === "tsa/bad-eku");
  // no EKU extension at all
  var e4 = null;
  try { b.tsa.verifyToken(tokenFor({ ekuOids: null }), { data: data, hashAlg: "SHA-512" }); } catch (e) { e4 = e; }
  check("missing EKU refused", e4 && e4.code === "tsa/bad-eku");
}

function testChainVerify() {
  var data = Buffer.from("chain-test");
  var cert = _makeCert({});
  var token = _makeToken({ certDer: cert.certDer, key: cert.key, issuer: cert.issuer, serial: cert.serial,
    imprintHash: _imprintOf(data, "SHA-512") });
  var anchorPem = new nodeCrypto.X509Certificate(cert.certDer).toString();
  var out = b.tsa.verifyToken(token, { data: data, hashAlg: "SHA-512", trustAnchorsPem: [anchorPem] });
  check("chain verify accepts the self-signed anchor", out.policy === "1.2.3.4.1");

  // a different, unrelated anchor → untrusted
  var other = _makeCert({ cn: "Unrelated Root" });
  var otherPem = new nodeCrypto.X509Certificate(other.certDer).toString();
  var e1 = null;
  try { b.tsa.verifyToken(token, { data: data, hashAlg: "SHA-512", trustAnchorsPem: [otherPem] }); } catch (e) { e1 = e; }
  check("chain verify refuses an unrelated anchor", e1 && e1.code === "tsa/untrusted-chain");

  // A single PEM *string* anchor must enforce the chain — not silently
  // skip it (the string shape previously bypassed the array-only guard).
  var okStr = b.tsa.verifyToken(token, { data: data, hashAlg: "SHA-512", trustAnchorsPem: anchorPem });
  check("string trustAnchorsPem enforces + accepts the matching anchor", okStr.policy === "1.2.3.4.1");
  var e2 = null;
  try { b.tsa.verifyToken(token, { data: data, hashAlg: "SHA-512", trustAnchorsPem: otherPem }); } catch (e) { e2 = e; }
  check("string trustAnchorsPem refuses an unrelated anchor (no fail-open)", e2 && e2.code === "tsa/untrusted-chain");

  // Empty / malformed anchor shapes are refused, never silently skipped.
  var e3 = null;
  try { b.tsa.verifyToken(token, { data: data, hashAlg: "SHA-512", trustAnchorsPem: [] }); } catch (e) { e3 = e; }
  check("empty trustAnchorsPem array refused", e3 && e3.code === "tsa/bad-trust-anchors");

  // An Invalid Date for opts.at must throw, not silently disable the
  // validity-window check (NaN comparisons).
  var e4 = null;
  try { b.tsa.verifyToken(token, { data: data, hashAlg: "SHA-512", trustAnchorsPem: [anchorPem], at: new Date("not-a-date") }); } catch (e) { e4 = e; }
  check("invalid opts.at Date refused", e4 && e4.code === "tsa/bad-at");
}

function testParseResponseAndInputGuards() {
  // garbage token → not CMS
  var e1 = null;
  try { b.tsa.verifyToken(Buffer.from([0x30, 0x01, 0x00]), { data: Buffer.from("x"), hashAlg: "SHA-512" }); } catch (e) { e1 = e; }
  check("verifyToken refuses non-CMS bytes", e1 && (e1.code === "tsa/not-cms" || e1.code === "tsa/malformed"));
  // no data
  var e2 = null;
  try { b.tsa.verifyToken(Buffer.from([0x30, 0x00]), { hashAlg: "SHA-512" }); } catch (e) { e2 = e; }
  check("verifyToken requires data/hash", e2 && e2.code === "tsa/no-data");
  // parseResponse on a hand-built rejection (status 2 + failInfo badRequest)
  var statusInfo = asn1.writeSequence([
    asn1.writeInteger(Buffer.from([0x02])),                               // rejection
    asn1.writeNode(0x03, Buffer.from([0x05, 0x20])),                      // BIT STRING failInfo (bit 2 = badRequest)
  ]);
  var resp = asn1.writeSequence([statusInfo]);
  var parsed = b.tsa.parseResponse(resp);
  check("parseResponse decodes a rejection (not granted)", parsed.granted === false && parsed.status === 2);
  check("parseResponse decodes failInfo bits", parsed.failInfo.indexOf("badRequest") !== -1);
  check("parseResponse rejection carries no token", parsed.token === null);
  // garbage response
  var e3 = null;
  try { b.tsa.parseResponse(Buffer.from([0x01, 0x02, 0x03])); } catch (e) { e3 = e; }
  check("parseResponse refuses non-SEQUENCE", e3 && e3.code === "tsa/malformed");
}

// OpenSSL `ts -reply` interop — independent-implementation regression.
function testOpensslInterop() {
  var cp = require("child_process");
  var fs = require("fs");
  var os = require("os");
  var path = require("path");
  var dir;
  try { dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-tsa-")); } catch (_e) { dir = null; }
  if (!dir) { check("openssl interop skipped (no tmpdir)", true); return; }
  var cnf = path.join(dir, "ossl.cnf");
  fs.writeFileSync(cnf, "[req]\ndistinguished_name=dn\nx509_extensions=v3_tsa\nprompt=no\n[dn]\nCN=Test TSA\n[v3_tsa]\nextendedKeyUsage=critical,timeStamping\nbasicConstraints=CA:false\n");
  var env = Object.assign({}, process.env, { OPENSSL_CONF: cnf });
  function ossl(args) { return cp.spawnSync("openssl", args, { cwd: dir, env: env, stdio: "ignore" }); }
  var gen = ossl(["req", "-x509", "-newkey", "rsa:2048", "-keyout", "tsa.key", "-out", "tsa.crt", "-days", "3650", "-nodes", "-config", "ossl.cnf"]);
  if (!gen || gen.status !== 0) {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    check("openssl interop skipped (openssl(1) unavailable)", true);
    return;
  }
  fs.writeFileSync(path.join(dir, "tsa.cnf"), "[c1]\nserial=./serial\ncrypto_device=builtin\nsigner_cert=./tsa.crt\nsigner_key=./tsa.key\ncerts=./tsa.crt\nsigner_digest=sha512\ndefault_policy=1.2.3.4.1\ndigests=sha256,sha384,sha512\naccuracy=secs:1\n");
  fs.writeFileSync(path.join(dir, "serial"), "01\n");
  var req = b.tsa.buildRequest(Buffer.from("hello world"), { hashAlg: "SHA-512" });
  fs.writeFileSync(path.join(dir, "q.tsq"), req.der);
  var reply = ossl(["ts", "-reply", "-queryfile", "q.tsq", "-config", "tsa.cnf", "-section", "c1", "-out", "r.tsr"]);
  if (!reply || reply.status !== 0 || !fs.existsSync(path.join(dir, "r.tsr"))) {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
    check("openssl interop skipped (ts -reply unavailable)", true);
    return;
  }
  var tsr = fs.readFileSync(path.join(dir, "r.tsr"));
  var anchor = fs.readFileSync(path.join(dir, "tsa.crt"), "utf8");
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* ignore */ }

  var resp = b.tsa.parseResponse(tsr);
  check("openssl interop: response granted", resp.granted === true && resp.status === 0);
  var out = b.tsa.verifyToken(resp.token, { data: Buffer.from("hello world"), hashAlg: "SHA-512", nonce: req.nonce });
  check("openssl interop: real token verifies", out.genTime instanceof Date && out.policy === "1.2.3.4.1");
  var out2 = b.tsa.verifyToken(resp.token, { data: Buffer.from("hello world"), hashAlg: "SHA-512", trustAnchorsPem: [anchor] });
  check("openssl interop: chain verifies to the TSA cert", out2.genTime instanceof Date);
  var e1 = null;
  try { b.tsa.verifyToken(resp.token, { data: Buffer.from("tampered"), hashAlg: "SHA-512" }); } catch (e) { e1 = e; }
  check("openssl interop: wrong data refused", e1 && e1.code === "tsa/imprint-mismatch");
}

async function run() {
  testSurface();
  testBuildRequest();
  testVerifyHappyPath("rsa", OID_RSA_ENCRYPTION, "RSA(rsaEncryption)");
  testVerifyHappyPath("rsa", "1.2.840.113549.1.1.13", "RSA(sha512WithRSA)");
  testVerifyHappyPath("ec", OID_ECDSA_SHA256, "ECDSA");
  testEkuRefusals();
  testChainVerify();
  testParseResponseAndInputGuards();
  testOpensslInterop();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[tsa] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
