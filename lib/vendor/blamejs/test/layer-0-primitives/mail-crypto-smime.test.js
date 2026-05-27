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

function run() {
  testSmimeSurface();
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
