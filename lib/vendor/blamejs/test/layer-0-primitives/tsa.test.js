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
 *
 * The mock-TSA builders below take a wide option surface so the
 * adversarial §2.4.2 / §2.3 verification branches (malformed / truncated
 * responses, wrong PKIStatus, missing fields, imprint / digest / nonce /
 * signature / EKU / chain mismatches) can be driven through the exported
 * b.tsa.* consumer path without a live TSA.
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
var OID_RSA_PSS = "1.2.840.113549.1.1.10";
var OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";
var OID_BASIC_CONSTRAINTS = "2.5.29.19";
var OID_EKU_EXT = "2.5.29.37";

function _utcTime(date) {
  var s = date.toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z";   // YYMMDDHHMMSSZ
  return asn1.writeNode(0x17, Buffer.from(s, "ascii"));
}
function _genTime(date, fractional) {
  var s = date.toISOString().replace(/[-:T]/g, "").slice(0, 14);          // YYYYMMDDHHMMSS
  s += fractional ? ".500Z" : "Z";
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

// Mint a minimal X.509v3 cert. Self-signed unless opts.issuerName +
// opts.issuerKey supply an issuing certificate. Supports a chosen
// extendedKeyUsage, basicConstraints cA, a custom serial / validity
// window, and deliberately-malformed EKU shapes for the refusal paths.
function _makeCert(opts) {
  opts = opts || {};
  var keyType = opts.keyType || "rsa";
  var kp;
  if (keyType === "ec") kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  else if (keyType === "ed25519") kp = nodeCrypto.generateKeyPairSync("ed25519");
  else kp = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var spki = kp.publicKey.export({ type: "spki", format: "der" });

  var version = asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2])));   // v3
  var serialBuf = opts.serial || Buffer.from([0x2a]);
  var serial = asn1.writeInteger(serialBuf);
  // Whatever key signs the tbs determines the cert's signatureAlgorithm.
  var signingKey = opts.issuerKey || kp.privateKey;
  var signingType = opts.issuerKey ? (opts.issuerKeyType || "rsa") : keyType;
  var signingIsEc = signingType === "ec";
  var signingIsEd = signingType === "ed25519";
  var sigOid = signingIsEd ? "1.3.101.112" : (signingIsEc ? OID_ECDSA_SHA256 : "1.2.840.113549.1.1.11");
  var sigAlgId = signingIsEd ? _algId(sigOid, false) : _algId(sigOid, !signingIsEc);
  var subjectName = _name(opts.cn || "Test TSA");
  var issuerName = opts.issuerName || subjectName;
  var now = Date.now();
  var validity = asn1.writeSequence([
    _utcTime(opts.notBefore || new Date(now - 86400000)),
    _utcTime(opts.notAfter || new Date(now + 86400000 * 3650)),
  ]);

  var extsList = [];
  if (opts.ca) {
    extsList.push(asn1.writeSequence([
      asn1.writeOid(OID_BASIC_CONSTRAINTS), asn1.writeBoolean(true),
      asn1.writeOctetString(asn1.writeSequence([asn1.writeBoolean(true)])),   // cA TRUE
    ]));
  } else if (opts.basicConstraintsFalse) {
    extsList.push(asn1.writeSequence([
      asn1.writeOid(OID_BASIC_CONSTRAINTS),
      asn1.writeOctetString(asn1.writeSequence([])),   // empty → cA defaults FALSE
    ]));
  }
  if (opts.ekuOids !== null) {
    var ekuOids = opts.ekuOids || [ID_KP_TIMESTAMPING];
    var ekuChildren = [asn1.writeOid(OID_EKU_EXT)];
    if (opts.ekuCritical !== false) ekuChildren.push(asn1.writeBoolean(true));
    // ekuNoValue omits the extnValue OCTET STRING — a malformed extension
    // whose value node the manual walker cannot find.
    if (!opts.ekuNoValue) {
      ekuChildren.push(asn1.writeOctetString(asn1.writeSequence(ekuOids.map(asn1.writeOid))));
    }
    extsList.push(asn1.writeSequence(ekuChildren));
  }
  var children = [version, serial, sigAlgId, issuerName, validity, subjectName, spki];
  if (extsList.length) children.push(asn1.writeContextExplicit(3, asn1.writeSequence(extsList)));
  var tbs = asn1.writeSequence(children);

  var tbsSig = nodeCrypto.sign(signingIsEd ? null : "sha256", tbs, signingKey);
  var certDer = asn1.writeSequence([tbs, sigAlgId, asn1.writeBitString(tbsSig, 0)]);
  return {
    certDer: certDer, key: kp.privateKey, serial: serialBuf,
    issuer: issuerName, subjectName: subjectName, publicKey: kp.publicKey,
  };
}

// Build a chain: self-signed Root CA → Intermediate CA → Leaf TSA. The
// leaf carries the timeStamping EKU (+ a benign basicConstraints:FALSE so
// the extension walker iterates past a non-matching extension); the CAs
// carry basicConstraints cA:TRUE and no EKU.
function _makeChain() {
  var root = _makeCert({ cn: "Root CA", serial: Buffer.from([0x01]), ca: true, ekuOids: null });
  var interm = _makeCert({
    cn: "Intermediate CA", serial: Buffer.from([0x02]), ca: true, ekuOids: null,
    issuerName: root.subjectName, issuerKey: root.key,
  });
  var leaf = _makeCert({
    cn: "Leaf TSA", serial: Buffer.from([0x03]), basicConstraintsFalse: true,
    issuerName: interm.subjectName, issuerKey: interm.key,
  });
  return { root: root, interm: interm, leaf: leaf,
    tokenCerts: Buffer.concat([leaf.certDer, interm.certDer]) };
}

// Build an RFC 3161 TimeStampToken (CMS SignedData over a TSTInfo). The
// wide option surface drives the verifier's adversarial branches.
function _makeToken(opts) {
  var imprintOid = opts.imprintHashOid || OID_SHA512;
  var tstInfo;
  if (opts.rawTstInfo) {
    tstInfo = opts.rawTstInfo;
  } else {
    var genTimeNode = opts.rawGenTimeNode || _genTime(opts.genTime || new Date(), opts.genTimeFractional);
    var tstChildren = [
      asn1.writeInteger(Buffer.from([1])),                                  // version
      asn1.writeOid(opts.policy || "1.2.3.4.1"),                            // policy
      asn1.writeSequence([_algId(imprintOid, true), asn1.writeOctetString(opts.imprintHash)]),
      asn1.writeInteger(Buffer.from([0x05])),                              // serialNumber
      genTimeNode,
    ];
    if (opts.accuracy) tstChildren.push(opts.accuracy);
    if (opts.nonce) tstChildren.push(asn1.writeInteger(opts.nonce));
    tstInfo = asn1.writeSequence(tstChildren);
  }

  var digestNode = opts.signerDigest || "sha512";
  var digestOid = digestNode === "sha256" ? OID_SHA256 : OID_SHA512;
  var siDigestOid = opts.signerDigestOidOverride || digestOid;
  var msgDigest = nodeCrypto.createHash(digestNode).update(tstInfo).digest();

  // signed attributes (contentType + messageDigest), signed as a SET.
  var attrs = [];
  if (!opts.omitContentTypeAttr) {
    attrs.push(asn1.writeSequence([asn1.writeOid(OID_CONTENT_TYPE_ATTR),
      asn1.writeSet([asn1.writeOid(opts.wrongContentTypeOid || ID_CT_TST_INFO)])]));
  }
  if (!opts.omitMessageDigestAttr) {
    attrs.push(asn1.writeSequence([asn1.writeOid(OID_MESSAGE_DIGEST_ATTR),
      asn1.writeSet([asn1.writeOctetString(opts.messageDigestOverride || msgDigest)])]));
  }
  if (opts.extraEmptyAttr) {
    attrs.push(asn1.writeSequence([asn1.writeOid("1.2.3.4.99"), asn1.writeSet([])]));
  }
  var signedSet = asn1.writeSet(attrs);                                    // 0x31… — the signed bytes

  var sigAlgOid = opts.sigAlgOid || OID_RSA_ENCRYPTION;
  // The signature hash is the one the signatureAlgorithm OID implies;
  // hashless OIDs (rsaEncryption / id-ecPublicKey / PSS) take the
  // digestAlgorithm hash — exactly what the verifier derives.
  var SIGN_HASH = {
    "1.2.840.10045.4.3.2": "sha256", "1.2.840.10045.4.3.3": "sha384", "1.2.840.10045.4.3.4": "sha512",
    "1.2.840.113549.1.1.11": "sha256", "1.2.840.113549.1.1.12": "sha384", "1.2.840.113549.1.1.13": "sha512",
  };
  var signHash = SIGN_HASH[sigAlgOid] || digestNode;
  var sig;
  if (opts.corruptSignature) {
    sig = Buffer.from([0xff]);                                            // garbage — skip signing entirely
  } else if (opts.pss) {
    sig = nodeCrypto.sign(signHash, signedSet, {
      key: opts.key, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: nodeCrypto.constants.RSA_PSS_SALTLEN_DIGEST,
    });
  } else {
    sig = nodeCrypto.sign(signHash, signedSet, opts.key);
  }
  var signedAttrsImplicit = Buffer.concat([Buffer.from([0xa0]), signedSet.slice(1)]);  // [0] IMPLICIT

  var sid = opts.rawSid || asn1.writeSequence([opts.issuer, asn1.writeInteger(opts.serial)]);
  var siChildren = [
    asn1.writeInteger(Buffer.from([1])),                                  // version
    sid,
    _algId(siDigestOid, true),
  ];
  if (!opts.omitSignedAttrs) siChildren.push(signedAttrsImplicit);
  siChildren.push(_algId(sigAlgOid, sigAlgOid.indexOf("10045") === -1));  // RSA: AlgId+NULL; EC: no NULL
  siChildren.push(asn1.writeOctetString(sig));
  var signerInfo = asn1.writeSequence(siChildren);

  var eContentTypeOid = opts.wrongEContentTypeOid || ID_CT_TST_INFO;
  var encapChildren = [asn1.writeOid(eContentTypeOid)];
  if (!opts.detached) encapChildren.push(asn1.writeContextExplicit(0, asn1.writeOctetString(tstInfo)));
  var encap = asn1.writeSequence(encapChildren);

  var signerInfosSet = opts.emptySignerInfos ? asn1.writeSet([]) : asn1.writeSet([signerInfo]);
  var sdChildren = [
    asn1.writeInteger(Buffer.from([3])),                                  // version
    asn1.writeSet([_algId(digestOid, true)]),
    encap,
  ];
  if (!opts.omitCerts) {
    var certBytes = opts.extraCertDer ? Buffer.concat([opts.certDer, opts.extraCertDer]) : opts.certDer;
    sdChildren.push(asn1.writeContextImplicit(0, certBytes, { constructed: true }));
  }
  sdChildren.push(signerInfosSet);
  var signedData = asn1.writeSequence(sdChildren);
  return asn1.writeSequence([asn1.writeOid(OID_SIGNED_DATA), asn1.writeContextExplicit(0, signedData)]);
}

function _imprintOf(data, hashAlg) {
  var node = hashAlg === "SHA-256" ? "sha256" : "sha512";
  return nodeCrypto.createHash(node).update(data).digest();
}

// A ready-to-verify token bound to `data` with a fresh timeStamping cert.
function _validTokenFor(data, tokenOpts) {
  var cert = _makeCert({});
  var o = { certDer: cert.certDer, key: cert.key, issuer: cert.issuer, serial: cert.serial,
    imprintHash: _imprintOf(data, "SHA-512") };
  Object.keys(tokenOpts || {}).forEach(function (k) { o[k] = tokenOpts[k]; });
  return { token: _makeToken(o), cert: cert };
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
  // An inherited Object.prototype member must get the typed refusal, not a
  // raw createHash(undefined) ERR_INVALID_ARG_TYPE: the hashAlg indexes the
  // IMPRINT_HASHES lookup, and every such member is a truthy prototype-chain
  // hit that a `!IMPRINT_HASHES[hashAlg]` guard would let slip.
  ["constructor", "__proto__", "toString", "valueOf"].forEach(function (m) {
    var inh = null;
    try { b.tsa.buildRequest(Buffer.from("z"), { hashAlg: m }); } catch (e) { inh = e; }
    check("buildRequest rejects inherited-member hashAlg '" + m + "' with typed error",
      inh && inh.code === "tsa/bad-hash-alg");
  });
}

// buildRequest: opts omitted entirely, a requested policy OID, an
// explicit nonce Buffer, and certReq:false omitting the boolean.
function testBuildRequestExtras() {
  var noOpts = b.tsa.buildRequest(Buffer.from("no-opts"));
  check("buildRequest with no opts defaults to SHA-512 + random nonce",
    noOpts.hashAlg === "SHA-512" && Buffer.isBuffer(noOpts.nonce) && noOpts.nonce.length === 8);

  var withPolicy = b.tsa.buildRequest(Buffer.from("p"), { reqPolicy: "1.3.6.1.4.1.99.5", nonce: false, certReq: false });
  var pc = asn1.readSequence(asn1.readNode(withPolicy.der, 0).value);
  // children: version, messageImprint, reqPolicy(OID) — no nonce, no certReq boolean.
  var hasPolicyOid = pc.some(function (n) {
    return n.tag === asn1.TAG.OID && n.tagClass === asn1.TAG_CLASS.UNIVERSAL && asn1.readOid(n) === "1.3.6.1.4.1.99.5";
  });
  check("buildRequest reqPolicy encodes the policy OID", hasPolicyOid);
  var hasBoolean = pc.some(function (n) { return n.tag === asn1.TAG.BOOLEAN; });
  check("buildRequest certReq:false omits the certReq boolean", hasBoolean === false);

  var myNonce = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]);
  var withNonce = b.tsa.buildRequest(Buffer.from("n"), { nonce: myNonce });
  check("buildRequest honours an explicit nonce Buffer", withNonce.nonce === myNonce);
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

// verifyToken driven by a pre-computed digest (opts.hash) rather than raw
// data, plus a token whose imprint uses a pre-hashed input.
function testVerifyWithPrecomputedHash() {
  var data = Buffer.from("prehash-bytes");
  var digest = _imprintOf(data, "SHA-512");
  var cert = _makeCert({});
  var token = _makeToken({ certDer: cert.certDer, key: cert.key, issuer: cert.issuer, serial: cert.serial,
    imprintHash: digest });
  var out = b.tsa.verifyToken(token, { hash: digest, hashAlg: "SHA-512" });
  check("verifyToken accepts a pre-computed hash via opts.hash", out.policy === "1.2.3.4.1");
  var e1 = null;
  try { b.tsa.verifyToken(token, { hash: _imprintOf(Buffer.from("other"), "SHA-512"), hashAlg: "SHA-512" }); } catch (e) { e1 = e; }
  check("verifyToken opts.hash mismatch refused", e1 && e1.code === "tsa/imprint-mismatch");
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
  // no EKU extension at all (no extensions wrapper at all)
  var e4 = null;
  try { b.tsa.verifyToken(tokenFor({ ekuOids: null }), { data: data, hashAlg: "SHA-512" }); } catch (e) { e4 = e; }
  check("missing EKU refused", e4 && e4.code === "tsa/bad-eku");
  // extensions present (basicConstraints) but NO EKU among them — the
  // walker must iterate past the non-matching extension and still refuse.
  var e5 = null;
  try { b.tsa.verifyToken(tokenFor({ ekuOids: null, ca: true }), { data: data, hashAlg: "SHA-512" }); } catch (e) { e5 = e; }
  check("cert with other extensions but no EKU refused", e5 && e5.code === "tsa/bad-eku");
  // EKU extension present but malformed (no extnValue OCTET STRING).
  var e6 = null;
  try { b.tsa.verifyToken(tokenFor({ ekuNoValue: true }), { data: data, hashAlg: "SHA-512" }); } catch (e) { e6 = e; }
  check("malformed EKU (no value) refused", e6 && e6.code === "tsa/bad-eku");
}

// Structural CMS refusals: wrong eContentType, detached content, no
// SignerInfo, no certificate, and SignerInfo with no signed attributes.
function testVerifyStructuralRefusals() {
  var data = Buffer.from("structural-test");
  var e1 = null;
  try { b.tsa.verifyToken(_validTokenFor(data, { wrongEContentTypeOid: "1.2.3.4.7" }).token, { data: data, hashAlg: "SHA-512" }); } catch (e) { e1 = e; }
  check("wrong eContentType refused (not-tst)", e1 && e1.code === "tsa/not-tst");

  var e2 = null;
  try { b.tsa.verifyToken(_validTokenFor(data, { detached: true }).token, { data: data, hashAlg: "SHA-512" }); } catch (e) { e2 = e; }
  check("detached token (no embedded TSTInfo) refused", e2 && e2.code === "tsa/detached");

  var e3 = null;
  try { b.tsa.verifyToken(_validTokenFor(data, { emptySignerInfos: true }).token, { data: data, hashAlg: "SHA-512" }); } catch (e) { e3 = e; }
  check("token with no SignerInfo refused", e3 && e3.code === "tsa/no-signer");

  var e4 = null;
  try { b.tsa.verifyToken(_validTokenFor(data, { omitCerts: true }).token, { data: data, hashAlg: "SHA-512" }); } catch (e) { e4 = e; }
  check("token carrying no certificate refused (no-cert)", e4 && e4.code === "tsa/no-cert");

  var e5 = null;
  try { b.tsa.verifyToken(_validTokenFor(data, { omitSignedAttrs: true }).token, { data: data, hashAlg: "SHA-512" }); } catch (e) { e5 = e; }
  check("SignerInfo with no signed attributes refused", e5 && e5.code === "tsa/no-signed-attrs");
}

// Attribute + signature-algorithm refusals inside the CMS signature check,
// plus a token that verifies against a MISMATCHED messageDigest (a valid
// signature over the wrong content must not be accepted).
function testVerifyAttrAndSigRefusals() {
  var data = Buffer.from("attr-sig-test");

  var e1 = null;
  try { b.tsa.verifyToken(_validTokenFor(data, { sigAlgOid: "1.3.6.1.4.1.99.3.2" }).token, { data: data, hashAlg: "SHA-512" }); } catch (e) { e1 = e; }
  check("unsupported signature algorithm refused (bad-sig-alg)", e1 && e1.code === "tsa/bad-sig-alg");

  var e2 = null;
  try { b.tsa.verifyToken(_validTokenFor(data, { signerDigestOidOverride: "1.3.14.3.2.26" }).token, { data: data, hashAlg: "SHA-512" }); } catch (e) { e2 = e; }
  check("unsupported SignerInfo digest algorithm refused (bad-digest)", e2 && e2.code === "tsa/bad-digest");

  var e3 = null;
  try { b.tsa.verifyToken(_validTokenFor(data, { omitMessageDigestAttr: true }).token, { data: data, hashAlg: "SHA-512" }); } catch (e) { e3 = e; }
  check("missing messageDigest attribute refused (no-message-digest)", e3 && e3.code === "tsa/no-message-digest");

  var e4 = null;
  try { b.tsa.verifyToken(_validTokenFor(data, { wrongContentTypeOid: "1.2.3.4.8" }).token, { data: data, hashAlg: "SHA-512" }); } catch (e) { e4 = e; }
  check("wrong signed contentType attribute refused (bad-content-type-attr)", e4 && e4.code === "tsa/bad-content-type-attr");

  // A cryptographically-valid signature over a messageDigest attribute that
  // does NOT equal the recomputed eContent digest must be refused — the
  // signature must bind the exact TSTInfo bytes, never a substituted digest.
  var e5 = null;
  var mismatchDigest = nodeCrypto.createHash("sha512").update(Buffer.from("some other content")).digest();
  try {
    b.tsa.verifyToken(_validTokenFor(data, { messageDigestOverride: mismatchDigest }).token, { data: data, hashAlg: "SHA-512" });
  } catch (e) { e5 = e; }
  check("valid signature over a mismatched messageDigest refused", e5 && e5.code === "tsa/message-digest-mismatch");

  // A signed attrs SET carrying an extra attribute with an empty value SET
  // is tolerated (skipped) — contentType + messageDigest still verify.
  var okExtra = b.tsa.verifyToken(_validTokenFor(data, { extraEmptyAttr: true }).token, { data: data, hashAlg: "SHA-512" });
  check("extra empty-valued signed attribute skipped, token still verifies", okExtra.policy === "1.2.3.4.1");

  // RSASSA-PSS signer (hash taken from the digestAlgorithm).
  var okPss = b.tsa.verifyToken(_validTokenFor(data, { sigAlgOid: OID_RSA_PSS, pss: true }).token, { data: data, hashAlg: "SHA-512" });
  check("RSASSA-PSS signed token verifies", okPss.genTime instanceof Date);

  // A garbage ECDSA signature (structurally broken) is refused, never
  // silently accepted.
  var e6 = null;
  var ecCert = _makeCert({ keyType: "ec" });
  var ecTok = _makeToken({ certDer: ecCert.certDer, key: ecCert.key, issuer: ecCert.issuer, serial: ecCert.serial,
    imprintHash: _imprintOf(data, "SHA-512"), sigAlgOid: OID_ECDSA_SHA256, signerDigest: "sha512", corruptSignature: true });
  try { b.tsa.verifyToken(ecTok, { data: data, hashAlg: "SHA-512" }); } catch (e) { e6 = e; }
  check("garbage ECDSA signature refused (bad-signature / verify-threw)",
    e6 && (e6.code === "tsa/verify-threw" || e6.code === "tsa/bad-signature"));

  // A token declaring a supported RSA signatureAlgorithm whose certificate
  // actually carries an Ed25519 key: node's hashed verify cannot run
  // against an Ed25519 key and throws — the verifier must surface that as
  // tsa/verify-threw, never treat the failure-to-verify as a pass.
  var e7 = null;
  var edCert = _makeCert({ keyType: "ed25519" });
  var edTok = _makeToken({ certDer: edCert.certDer, key: edCert.key, issuer: edCert.issuer, serial: edCert.serial,
    imprintHash: _imprintOf(data, "SHA-512"), sigAlgOid: OID_RSA_ENCRYPTION, corruptSignature: true });
  try { b.tsa.verifyToken(edTok, { data: data, hashAlg: "SHA-512" }); } catch (e) { e7 = e; }
  check("Ed25519-key cert under an RSA signature algorithm surfaces (verify-threw)", e7 && e7.code === "tsa/verify-threw");
}

// TSTInfo-parsing branches: malformed / fractional GeneralizedTime,
// accuracy fields, too-short / non-SEQUENCE TSTInfo, and a token with no
// nonce compared against a request nonce.
function testTstInfoParsing() {
  var data = Buffer.from("tstinfo-test");
  var imp = _imprintOf(data, "SHA-512");
  var cert = _makeCert({});
  function tok(extra) {
    var o = { certDer: cert.certDer, key: cert.key, issuer: cert.issuer, serial: cert.serial, imprintHash: imp };
    Object.keys(extra || {}).forEach(function (k) { o[k] = extra[k]; });
    return _makeToken(o);
  }

  // malformed GeneralizedTime → bad-gentime
  var e1 = null;
  try { b.tsa.verifyToken(tok({ rawGenTimeNode: asn1.writeNode(0x18, Buffer.from("not-a-time", "ascii")) }), { data: data, hashAlg: "SHA-512" }); } catch (e) { e1 = e; }
  check("malformed GeneralizedTime refused (bad-gentime)", e1 && e1.code === "tsa/bad-gentime");

  // fractional-second GeneralizedTime → parsed to milliseconds
  var frac = b.tsa.verifyToken(tok({ genTimeFractional: true }), { data: data, hashAlg: "SHA-512" });
  check("fractional-second genTime parses to ms", frac.genTime instanceof Date && frac.genTime.getUTCMilliseconds() === 500);

  // accuracy { seconds, [0] millis, [1] micros } surfaces on the result
  var accuracy = asn1.writeSequence([
    asn1.writeInteger(Buffer.from([0x01])),               // seconds = 1
    asn1.writeContextImplicit(0, Buffer.from([0x64])),    // millis = 100 [0] IMPLICIT
    asn1.writeContextImplicit(1, Buffer.from([0x0a])),    // micros = 10  [1] IMPLICIT
  ]);
  var acc = b.tsa.verifyToken(tok({ accuracy: accuracy }), { data: data, hashAlg: "SHA-512" });
  check("accuracy seconds/millis/micros decoded",
    acc.accuracy && acc.accuracy.seconds === 1 && acc.accuracy.millis === 100 && acc.accuracy.micros === 10);

  // too-short TSTInfo (fewer than 5 fields) → malformed
  var e2 = null;
  var shortTst = asn1.writeSequence([asn1.writeInteger(Buffer.from([1])), asn1.writeOid("1.2.3"), asn1.writeOctetString(Buffer.alloc(0))]);
  try { b.tsa.verifyToken(tok({ rawTstInfo: shortTst }), { data: data, hashAlg: "SHA-512" }); } catch (e) { e2 = e; }
  check("too-short TSTInfo refused (malformed)", e2 && e2.code === "tsa/malformed");

  // TSTInfo that is not a SEQUENCE → malformed
  var e3 = null;
  try { b.tsa.verifyToken(tok({ rawTstInfo: asn1.writeInteger(Buffer.from([1])) }), { data: data, hashAlg: "SHA-512" }); } catch (e) { e3 = e; }
  check("non-SEQUENCE TSTInfo refused (malformed)", e3 && e3.code === "tsa/malformed");

  // token has no nonce but a request nonce is supplied → nonce-mismatch
  // (the absent-nonce comparison branch).
  var e4 = null;
  try { b.tsa.verifyToken(tok({}), { data: data, hashAlg: "SHA-512", nonce: nodeCrypto.randomBytes(8) }); } catch (e) { e4 = e; }
  check("nonce required but token has none refused", e4 && e4.code === "tsa/nonce-mismatch");
}

// SignerInfo-selection (_candidateSigners) branches: a SID that is not an
// IssuerAndSerialNumber, an IssuerAndSerial whose serial matches no cert,
// and a bogus (unparseable) cert in the pool alongside the real signer.
function testCandidateSigners() {
  var data = Buffer.from("candidate-signers");
  var cert = _makeCert({});
  var imp = _imprintOf(data, "SHA-512");

  // (a) SID is a [0] SubjectKeyIdentifier (no serial) → fall back to all certs.
  var skiSid = asn1.writeContextImplicit(0, Buffer.from([0xab, 0xcd, 0xef]));
  var outA = b.tsa.verifyToken(
    _makeToken({ certDer: cert.certDer, key: cert.key, rawSid: skiSid, serial: cert.serial, issuer: cert.issuer, imprintHash: imp }),
    { data: data, hashAlg: "SHA-512" });
  check("SKI-style SID (no serial) falls back to all certs", outA.policy === "1.2.3.4.1");

  // (b) IssuerAndSerial SID whose serial matches no cert → fall back to all certs.
  var outB = b.tsa.verifyToken(
    _makeToken({ certDer: cert.certDer, key: cert.key, serial: Buffer.from([0x77]), issuer: cert.issuer, imprintHash: imp }),
    { data: data, hashAlg: "SHA-512" });
  check("SID serial matching no cert falls back to all certs", outB.policy === "1.2.3.4.1");

  // (c) a bogus, unparseable cert in the pool is skipped; the real signer
  //     is still selected by serial.
  var bogus = asn1.writeSequence([asn1.writeInteger(Buffer.from([0x01]))]);
  var outC = b.tsa.verifyToken(
    _makeToken({ certDer: cert.certDer, extraCertDer: bogus, key: cert.key, serial: cert.serial, issuer: cert.issuer, imprintHash: imp }),
    { data: data, hashAlg: "SHA-512" });
  check("bogus cert in the pool skipped; real signer selected", outC.policy === "1.2.3.4.1");
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

// Multi-cert chain: signer → intermediate CA → root anchor. Exercises the
// walk-up through the token's intermediates and the cA-enforced anchor
// termination, plus the validity-window check driven by opts.at.
function testChainWalkAndValidity() {
  var data = Buffer.from("chain-walk-test");
  var chain = _makeChain();
  var token = _makeToken({ certDer: chain.tokenCerts, key: chain.leaf.key, issuer: chain.leaf.issuer,
    serial: chain.leaf.serial, imprintHash: _imprintOf(data, "SHA-512") });
  var rootPem = new nodeCrypto.X509Certificate(chain.root.certDer).toString();
  var out = b.tsa.verifyToken(token, { data: data, hashAlg: "SHA-512", trustAnchorsPem: [rootPem] });
  check("chain walks signer → intermediate → root anchor", out.policy === "1.2.3.4.1");

  // The intermediate is NOT a trust anchor on its own — only the root is.
  // Supplying only the intermediate fails to terminate at an anchor.
  var intermPem = new nodeCrypto.X509Certificate(chain.interm.certDer).toString();
  var eNoRoot = null;
  try { b.tsa.verifyToken(token, { data: data, hashAlg: "SHA-512", trustAnchorsPem: [intermPem] }); } catch (e) { eNoRoot = e; }
  // The intermediate DID issue the signer, so it terminates as a
  // fingerprint/issuer anchor — this asserts it verifies (intermediate is a
  // valid anchor for the signer directly).
  check("intermediate as sole anchor still terminates (it issued the signer)", eNoRoot === null);

  // Validity window: a self-anchored cert with opts.at far past the cert's
  // notAfter must be refused (cert-expired), and a valid opts.at accepted.
  var soloData = Buffer.from("validity-window");
  var solo = _makeCert({});
  var soloTok = _makeToken({ certDer: solo.certDer, key: solo.key, issuer: solo.issuer, serial: solo.serial,
    imprintHash: _imprintOf(soloData, "SHA-512") });
  var soloPem = new nodeCrypto.X509Certificate(solo.certDer).toString();
  var eExpired = null;
  try {
    b.tsa.verifyToken(soloTok, { data: soloData, hashAlg: "SHA-512", trustAnchorsPem: [soloPem],
      at: new Date(Date.now() + 86400000 * 100000) });
  } catch (e) { eExpired = e; }
  check("cert not valid at opts.at refused (cert-expired)", eExpired && eExpired.code === "tsa/cert-expired");

  var okAt = b.tsa.verifyToken(soloTok, { data: soloData, hashAlg: "SHA-512", trustAnchorsPem: [soloPem], at: new Date() });
  check("valid opts.at within the window accepted", okAt.policy === "1.2.3.4.1");
}

// parseResponse malformed / non-granted / granted-with-token branches.
function testParseResponseBranches() {
  // Well-formed non-SEQUENCE root (an INTEGER) → malformed.
  var e1 = null;
  try { b.tsa.parseResponse(asn1.writeInteger(Buffer.from([1]))); } catch (e) { e1 = e; }
  check("parseResponse refuses a non-SEQUENCE root", e1 && e1.code === "tsa/malformed");

  // First child is not the PKIStatusInfo SEQUENCE.
  var e2 = null;
  try { b.tsa.parseResponse(asn1.writeSequence([asn1.writeInteger(Buffer.from([1]))])); } catch (e) { e2 = e; }
  check("parseResponse refuses a missing PKIStatusInfo SEQUENCE", e2 && e2.code === "tsa/malformed");

  // PKIStatusInfo present but first element is not an INTEGER.
  var e3 = null;
  try { b.tsa.parseResponse(asn1.writeSequence([asn1.writeSequence([asn1.writeNull()])])); } catch (e) { e3 = e; }
  check("parseResponse refuses a PKIStatusInfo without a status INTEGER", e3 && e3.code === "tsa/malformed");

  // Status INTEGER too large to be a small unsigned status → out of range.
  var e4 = null;
  var bigStatus = asn1.writeNode(0x02, Buffer.from([0, 1, 2, 3, 4, 5, 6, 7, 8]));   // 9-byte INTEGER
  try { b.tsa.parseResponse(asn1.writeSequence([asn1.writeSequence([bigStatus])])); } catch (e) { e4 = e; }
  check("parseResponse refuses an out-of-range status integer", e4 && e4.code === "tsa/malformed");

  // Rejection with a PKIFreeText statusString.
  var withText = asn1.writeSequence([asn1.writeSequence([
    asn1.writeInteger(Buffer.from([0x02])),                                          // rejection
    asn1.writeSequence([asn1.writeUtf8String("policy not accepted")]),               // PKIFreeText
  ])]);
  var pText = b.tsa.parseResponse(withText);
  check("parseResponse decodes a statusString", pText.granted === false && pText.statusString === "policy not accepted");

  // failInfo BIT STRING with only the unused-bits byte → empty flags.
  var emptyFail = asn1.writeSequence([asn1.writeSequence([
    asn1.writeInteger(Buffer.from([0x02])),
    asn1.writeNode(0x03, Buffer.from([0x00])),                                       // empty BIT STRING
  ])]);
  var pEmpty = b.tsa.parseResponse(emptyFail);
  check("parseResponse handles an empty failInfo BIT STRING", pEmpty.failInfo.length === 0);

  // failInfo bit at a position with no named flag → "bitN".
  var unknownBit = asn1.writeSequence([asn1.writeSequence([
    asn1.writeInteger(Buffer.from([0x02])),
    asn1.writeNode(0x03, Buffer.from([0x06, 0x40])),                                 // bit position 1 set (unnamed)
  ])]);
  var pUnknown = b.tsa.parseResponse(unknownBit);
  check("parseResponse names an unmapped failInfo bit", pUnknown.failInfo.indexOf("bit1") !== -1);

  // granted status but no timeStampToken present → no-token.
  var e5 = null;
  try { b.tsa.parseResponse(asn1.writeSequence([asn1.writeSequence([asn1.writeInteger(Buffer.from([0x01]))])])); } catch (e) { e5 = e; }
  check("parseResponse refuses granted-without-token", e5 && e5.code === "tsa/no-token");

  // granted status WITH a token → surfaces the token and verifies end-to-end.
  var data = Buffer.from("granted-with-token");
  var vt = _validTokenFor(data, {});
  var grantedResp = asn1.writeSequence([asn1.writeSequence([asn1.writeInteger(Buffer.from([0x00]))]), vt.token]);
  var pGranted = b.tsa.parseResponse(grantedResp);
  check("parseResponse surfaces a granted token", pGranted.granted === true && pGranted.status === 0 && Buffer.isBuffer(pGranted.token));
  var out = b.tsa.verifyToken(pGranted.token, { data: data, hashAlg: "SHA-512" });
  check("token surfaced by parseResponse verifies", out.policy === "1.2.3.4.1");
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
  testBuildRequestExtras();
  testVerifyHappyPath("rsa", OID_RSA_ENCRYPTION, "RSA(rsaEncryption)");
  testVerifyHappyPath("rsa", "1.2.840.113549.1.1.13", "RSA(sha512WithRSA)");
  testVerifyHappyPath("ec", OID_ECDSA_SHA256, "ECDSA");
  testVerifyWithPrecomputedHash();
  testEkuRefusals();
  testVerifyStructuralRefusals();
  testVerifyAttrAndSigRefusals();
  testTstInfoParsing();
  testCandidateSigners();
  testChainVerify();
  testChainWalkAndValidity();
  testParseResponseBranches();
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
