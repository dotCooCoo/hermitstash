// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Core b.crypto surface without a dedicated sub-domain file:
 *   - hmac / kdf / sri  — keyed integrity, SHAKE256 derivation, W3C SRI.
 *   - hashCertFingerprint / isCertRevoked — peer-cert pinning + deny lists.
 *   - encryptEnvelopeAsCertPeer / decryptEnvelopeAsCertPeer — cert-bound
 *     envelope round trip against real P-384 cert + ML-KEM-1024 material.
 *
 * The cert-peer + fingerprint + revocation cases share one in-tree ASN.1
 * DER self-signed cert whose SubjectPublicKeyInfo carries a P-384 ECDH
 * public key — the exact shape `encryptEnvelopeAsCertPeer` extracts.
 *
 * Run standalone: `node test/layer-0-primitives/crypto.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var asn1       = require("../../lib/asn1-der");
var nodeCrypto = require("node:crypto");

// ---- In-tree self-signed cert builder (mirrors content-credentials.test.js
// but keyed on an EC curve so the SPKI carries an ECDH public key). Node's
// X509Certificate only parses — it never verifies the signature — so an
// ECDSA self-signature over the TBS is enough for `.publicKey` extraction.
function _utcTime(d) {
  var s = d.toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z";
  return asn1.writeNode(0x17, Buffer.from(s, "ascii"));
}
function _certName(cn) {
  return asn1.writeSequence([
    asn1.writeSet([
      asn1.writeSequence([asn1.writeOid("2.5.4.3"), asn1.writeUtf8String(cn)]),
    ]),
  ]);
}
// Build a self-signed X.509 cert for `cn` over `namedCurve`. Returns the
// DER bytes, the matching EC private key (KeyObject), and the parsed PEM.
function _makeEcCert(cn, namedCurve) {
  var kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: namedCurve });
  var spki = kp.publicKey.export({ type: "spki", format: "der" });
  var name = _certName(cn);
  var version = asn1.writeContextExplicit(0, asn1.writeInteger(Buffer.from([2])));
  var serial = asn1.writeInteger(Buffer.from([0x2c]));
  // ecdsa-with-SHA384 (1.2.840.10045.4.3.3) — ECDSA AlgorithmIdentifiers
  // carry no parameters (not even NULL).
  var sigAlgId = asn1.writeSequence([asn1.writeOid("1.2.840.10045.4.3.3")]);
  var now = Date.now();
  var validity = asn1.writeSequence([
    _utcTime(new Date(now - 86400000)),
    _utcTime(new Date(now + 86400000 * 3650)),
  ]);
  var tbs = asn1.writeSequence([version, serial, sigAlgId, name, validity, name, spki]);
  var sig = nodeCrypto.sign("sha384", tbs, kp.privateKey);
  var certDer = asn1.writeSequence([tbs, sigAlgId, asn1.writeBitString(sig, 0)]);
  return {
    certDer:      certDer,
    ecPrivateKey: kp.privateKey,
    ecPrivatePem: kp.privateKey.export({ type: "pkcs8", format: "pem" }),
    pem:          new nodeCrypto.X509Certificate(certDer).toString(),
  };
}

function testHmac() {
  // DEFAULT: omitting the algorithm gives the PQC-first SHA3-512 (128 hex chars).
  var def = b.crypto.hmac("shared-secret", "POST /webhook|123");
  var sha3Kat = nodeCrypto.createHmac("sha3-512", "shared-secret").update("POST /webhook|123").digest("hex");
  check("hmac default is SHA3-512 (128 hex chars, matches KAT)",
    def.length === 128 && /^[0-9a-f]+$/.test(def) && def === sha3Kat);
  check("hmac default equals explicit sha3-512",
    b.crypto.hmac("k", "d") === b.crypto.hmac("k", "d", "sha3-512"));
  var det1 = b.crypto.hmac("k", "d"), det2 = b.crypto.hmac("k", "d");
  check("hmac default is deterministic",  det1 === det2);

  // Explicit algorithms across the allowlist match independent node computations.
  ["sha256", "sha384", "sha512", "sha3-256", "sha3-512"].forEach(function (alg) {
    var tag = b.crypto.hmac("shared-secret", "t.body", alg);
    var kat = nodeCrypto.createHmac(alg, "shared-secret").update("t.body").digest("hex");
    check("hmac(" + alg + ") matches KAT (lowercase hex)", tag === kat && /^[0-9a-f]+$/.test(tag));
  });
  // Buffer key + Buffer data.
  check("hmac accepts Buffer key + data",
    b.crypto.hmac(Buffer.from("k"), Buffer.from("d"), "sha256") ===
    nodeCrypto.createHmac("sha256", Buffer.from("k")).update(Buffer.from("d")).digest("hex"));
  // SHA-1 / MD5 / a case-wrong or unknown alg are refused at the entry tier.
  ["sha1", "md5", "SHA256", "bogus"].forEach(function (bad) {
    var t = false;
    try { b.crypto.hmac("k", "d", bad); } catch (e) { t = e instanceof TypeError; }
    check("hmac refuses weak/unknown alg '" + bad + "'", t);
  });
  // Bad key / data types throw.
  var badKey = false, badData = false;
  try { b.crypto.hmac(123, "d", "sha256"); } catch (e) { badKey = e instanceof TypeError; }
  try { b.crypto.hmac("k", 123, "sha256"); } catch (e) { badData = e instanceof TypeError; }
  check("hmac refuses a non-string/Buffer key", badKey);
  check("hmac refuses non-string/Buffer data", badData);
  // A null argument is reported distinctly from a typeof (the "null" branch of
  // each error message), covering the explicit-null caller shape.
  var nullAlg = false, nullKey = false, nullData = false;
  try { b.crypto.hmac("k", "d", null); } catch (e) { nullAlg = e instanceof TypeError && /null/.test(e.message); }
  try { b.crypto.hmac(null, "d"); }      catch (e) { nullKey = e instanceof TypeError && /null/.test(e.message); }
  try { b.crypto.hmac("k", null); }      catch (e) { nullData = e instanceof TypeError && /null/.test(e.message); }
  check("hmac reports a null algorithm distinctly", nullAlg);
  check("hmac reports a null key distinctly",       nullKey);
  check("hmac reports null data distinctly",        nullData);
  // Keyed + data divergence.
  check("hmac diverges on key change",  b.crypto.hmac("a", "d", "sha256") !== b.crypto.hmac("b", "d", "sha256"));
  check("hmac diverges on data change", b.crypto.hmac("k", "a", "sha256") !== b.crypto.hmac("k", "b", "sha256"));
}

function testKdf() {
  var seed = Buffer.from("master-secret|session-42", "utf8");

  // Exact requested output length (SHAKE256 XOF — arbitrary length).
  var k32 = b.crypto.kdf(seed, 32);
  var k64 = b.crypto.kdf(seed, 64);
  check("kdf honours outputLength 32", Buffer.isBuffer(k32) && k32.length === 32);
  check("kdf honours outputLength 64", Buffer.isBuffer(k64) && k64.length === 64);

  // Known answer against an independent SHAKE256 computation.
  var expected = nodeCrypto.createHash("shake256", { outputLength: 32 })
    .update(seed).digest();
  check("kdf matches SHAKE256 KAT", Buffer.compare(k32, expected) === 0);

  // Determinism — same (input, length) → identical key.
  var kdet1 = b.crypto.kdf(seed, 32);
  var kdet2 = b.crypto.kdf(seed, 32);
  check("kdf is deterministic", Buffer.compare(kdet1, kdet2) === 0);

  // Different input → different key (the "different salt" case: kdf's only
  // domain-separation lever is the input, since it takes no explicit salt).
  var other = b.crypto.kdf(Buffer.from("master-secret|session-99", "utf8"), 32);
  check("kdf diverges on input change", Buffer.compare(k32, other) !== 0);

  // XOF prefix property — the 32-byte output is the prefix of the 64-byte
  // output for the same input (SHAKE256 is a stream, not a fresh hash).
  check("kdf shorter output prefixes the longer", Buffer.compare(k32, k64.subarray(0, 32)) === 0);
}

function testSri() {
  // W3C SRI 1.0 attribute string: "<alg>-<base64>". Known answer against an
  // independent SHA-384 base64 computation.
  var payload = Buffer.from("alert(1);", "utf8");
  var attr = b.crypto.sri(payload, { algorithm: "sha384" });
  var expB64 = nodeCrypto.createHash("sha384").update(payload).digest("base64");
  check("sri sha384 matches known answer", attr === "sha384-" + expB64);

  // RFC/W3C integrity format: alg token + base64 body (with optional padding).
  check("sri emits W3C integrity format", /^sha(256|384|512)-[A-Za-z0-9+/]+={0,2}$/.test(attr));
  check("sri base64 body decodes to 48 bytes (sha384)",
    Buffer.from(attr.slice("sha384-".length), "base64").length === 48);

  // Default algorithm is sha384.
  check("sri default algorithm is sha384", b.crypto.sri("x").indexOf("sha384-") === 0);

  // string and Buffer inputs agree; Uint8Array accepted.
  check("sri string and Buffer agree",
    b.crypto.sri("alert(1);", { algorithm: "sha384" }) === attr);
  check("sri accepts Uint8Array",
    b.crypto.sri(new Uint8Array(payload), { algorithm: "sha384" }) === attr);

  // sha256 / sha512 emit the correct token + digest length.
  var s256 = b.crypto.sri(payload, { algorithm: "sha256" });
  var s512 = b.crypto.sri(payload, { algorithm: "sha512" });
  check("sri sha256 token + 32-byte digest",
    s256.indexOf("sha256-") === 0 && Buffer.from(s256.slice(7), "base64").length === 32);
  check("sri sha512 token + 64-byte digest",
    s512.indexOf("sha512-") === 0 && Buffer.from(s512.slice(7), "base64").length === 64);

  // Array input → space-separated multi-integrity per W3C §3.3.
  var multi = b.crypto.sri(["payload-a", "payload-b"], { algorithm: "sha512" });
  var tokens = multi.split(" ");
  check("sri array emits one token per element", tokens.length === 2);
  check("sri array tokens are each valid integrity strings",
    tokens[0] === b.crypto.sri("payload-a", { algorithm: "sha512" }) &&
    tokens[1] === b.crypto.sri("payload-b", { algorithm: "sha512" }));

  // Unsupported algorithm throws (config-time entry-tier).
  var threwAlg = false;
  try { b.crypto.sri(payload, { algorithm: "sha1" }); }
  catch (e) { threwAlg = /unsupported algorithm/.test(e.message); }
  check("sri refuses unsupported algorithm", threwAlg);

  // Non-Buffer/string/Uint8Array content throws.
  var threwType = false;
  try { b.crypto.sri(42, { algorithm: "sha384" }); }
  catch (e) { threwType = /content must be/.test(e.message); }
  check("sri refuses non-byte content", threwType);
}

function testCertFingerprint() {
  var cert = _makeEcCert("fp.example", "P-384");

  // Accepts a PEM string (the shape the @example documents) — this path was
  // silently broken before the safeBuffer()-call fix and threw a TypeError.
  var fp = b.crypto.hashCertFingerprint(cert.pem);
  check("hashCertFingerprint hex is 128 chars (SHA3-512)",
    typeof fp.hex === "string" && fp.hex.length === 128 && /^[0-9a-f]+$/.test(fp.hex));
  check("hashCertFingerprint colon form has 64 groups",
    fp.colon.split(":").length === 64);
  check("hashCertFingerprint colon form is uppercase hex pairs",
    /^[0-9A-F]{2}(:[0-9A-F]{2}){63}$/.test(fp.colon));

  // DER (Buffer) and PEM of the same cert produce identical fingerprints.
  var fpDer = b.crypto.hashCertFingerprint(cert.certDer);
  check("hashCertFingerprint PEM and DER agree", fpDer.hex === fp.hex);

  // Known answer against an independent SHA3-512 over the DER bytes.
  var direct = nodeCrypto.createHash("sha3-512").update(cert.certDer).digest("hex");
  check("hashCertFingerprint matches SHA3-512(DER) KAT", fp.hex === direct);

  // Non-Buffer / non-string input throws.
  var threwType = false;
  try { b.crypto.hashCertFingerprint(42); }
  catch (e) { threwType = e instanceof TypeError; }
  check("hashCertFingerprint refuses non-Buffer/non-string", threwType);

  // PEM without BEGIN/END markers throws.
  var threwMarker = false;
  try { b.crypto.hashCertFingerprint("not a pem at all"); }
  catch (e) { threwMarker = e instanceof TypeError && /BEGIN\/END/.test(e.message); }
  check("hashCertFingerprint refuses markerless PEM", threwMarker);
}

function testCertRevoked() {
  var cert  = _makeEcCert("revoked.example", "P-384");
  var other = _makeEcCert("other.example", "P-384");
  var fp = b.crypto.hashCertFingerprint(cert.pem);

  // A cert whose fingerprint (colon form) is on the deny list → revoked.
  check("isCertRevoked true when colon fingerprint on deny list",
    b.crypto.isCertRevoked(cert.pem, [fp.colon]) === true);

  // Lowercase-hex deny entry also matches.
  check("isCertRevoked true when hex fingerprint on deny list",
    b.crypto.isCertRevoked(cert.pem, [fp.hex]) === true);

  // A deny list carrying only an unrelated cert's fingerprint → not revoked.
  var otherFp = b.crypto.hashCertFingerprint(other.pem);
  check("isCertRevoked false when only another cert is denied",
    b.crypto.isCertRevoked(cert.pem, [otherFp.colon, otherFp.hex]) === false);

  // Empty deny list → not revoked.
  check("isCertRevoked false on empty deny list",
    b.crypto.isCertRevoked(cert.pem, []) === false);

  // Match survives a deny list where the hit is not the first entry.
  check("isCertRevoked scans the whole deny list",
    b.crypto.isCertRevoked(cert.pem, ["DEADBEEF", "", fp.hex]) === true);

  // Non-array deny list throws (entry-tier).
  var threw = false;
  try { b.crypto.isCertRevoked(cert.pem, "not-an-array"); }
  catch (e) { threw = e instanceof TypeError; }
  check("isCertRevoked refuses non-array deny list", threw);
}

function testCertPeerEnvelopeRoundTrip() {
  // The recipient peer owns: a TLS cert carrying its P-384 ECDH pubkey, and
  // an ML-KEM-1024 keypair (publishes the pubkey, keeps the secret).
  var kem  = b.crypto.generateEncryptionKeyPair();  // ML-KEM-1024 + P-384 bundle; use the KEM half
  var cert = _makeEcCert("peer.example", "P-384");

  var sealed = b.crypto.encryptEnvelopeAsCertPeer("cross-peer payload", {
    peerCertDer:   cert.certDer,
    peerKemPubkey: kem.publicKey,
  });
  check("encryptEnvelopeAsCertPeer returns a base64 envelope string",
    typeof sealed === "string" && sealed.length > 0);

  // Receive side with the EC private key as a KeyObject.
  var openedKo = b.crypto.decryptEnvelopeAsCertPeer(sealed, {
    certPrivateKey: cert.ecPrivateKey,
    kemSecret:      kem.privateKey,
  });
  check("decryptEnvelopeAsCertPeer round-trips with KeyObject cert key",
    openedKo === "cross-peer payload");

  // Receive side with the EC private key as a PEM string.
  var openedPem = b.crypto.decryptEnvelopeAsCertPeer(sealed, {
    certPrivateKey: cert.ecPrivatePem,
    kemSecret:      kem.privateKey,
  });
  check("decryptEnvelopeAsCertPeer round-trips with PEM cert key",
    openedPem === "cross-peer payload");

  // Wrong recipient (fresh unrelated ML-KEM secret) cannot open it.
  var wrongKem = b.crypto.generateEncryptionKeyPair();
  var threwWrong = false;
  try {
    b.crypto.decryptEnvelopeAsCertPeer(sealed, {
      certPrivateKey: cert.ecPrivateKey,
      kemSecret:      wrongKem.privateKey,
    });
  } catch (_e) { threwWrong = true; }
  check("decryptEnvelopeAsCertPeer refuses a mismatched KEM secret", threwWrong);
}

function testCertPeerEnvelopeValidation() {
  var kem  = b.crypto.generateEncryptionKeyPair();
  var cert = _makeEcCert("peer.example", "P-384");

  // A cert whose key is not ECDH P-384 is refused with a specific code.
  var p256 = _makeEcCert("p256.example", "P-256");
  var threwCurve;
  try {
    b.crypto.encryptEnvelopeAsCertPeer("x", { peerCertDer: p256.certDer, peerKemPubkey: kem.publicKey });
  } catch (e) { threwCurve = e; }
  check("encryptEnvelopeAsCertPeer rejects non-P-384 cert key",
    threwCurve && threwCurve.code === "crypto/cert-key-not-ecdh-p384");

  // Missing peerCertDer / peerKemPubkey carry their documented codes.
  var missCert;
  try { b.crypto.encryptEnvelopeAsCertPeer("x", { peerKemPubkey: kem.publicKey }); }
  catch (e) { missCert = e; }
  check("encryptEnvelopeAsCertPeer flags missing peerCertDer",
    missCert && missCert.code === "crypto/peer-cert-missing");

  var missKem;
  try { b.crypto.encryptEnvelopeAsCertPeer("x", { peerCertDer: cert.certDer, peerKemPubkey: "" }); }
  catch (e) { missKem = e; }
  check("encryptEnvelopeAsCertPeer flags empty peerKemPubkey",
    missKem && missKem.code === "crypto/peer-kem-pubkey-missing");

  // Decrypt side: missing keys + wrong-shape / wrong-curve cert private key.
  var missCertPriv;
  try { b.crypto.decryptEnvelopeAsCertPeer("AAAA", { kemSecret: kem.privateKey }); }
  catch (e) { missCertPriv = e; }
  check("decryptEnvelopeAsCertPeer flags missing certPrivateKey",
    missCertPriv && missCertPriv.code === "crypto/cert-private-key-missing");

  var badShape;
  try { b.crypto.decryptEnvelopeAsCertPeer("AAAA", { certPrivateKey: 42, kemSecret: kem.privateKey }); }
  catch (e) { badShape = e; }
  check("decryptEnvelopeAsCertPeer flags bad-shape certPrivateKey",
    badShape && badShape.code === "crypto/cert-private-key-bad-shape");

  // A P-256 KeyObject as certPrivateKey is refused (wrong curve).
  var p256Key = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
  var wrongCurveKey;
  try { b.crypto.decryptEnvelopeAsCertPeer("AAAA", { certPrivateKey: p256Key, kemSecret: kem.privateKey }); }
  catch (e) { wrongCurveKey = e; }
  check("decryptEnvelopeAsCertPeer rejects non-P-384 KeyObject cert key",
    wrongCurveKey && wrongCurveKey.code === "crypto/cert-key-not-ecdh-p384");
}

function run() {
  testHmac();
  testKdf();
  testSri();
  testCertFingerprint();
  testCertRevoked();
  testCertPeerEnvelopeRoundTrip();
  testCertPeerEnvelopeValidation();
}

// _makeEcCert is shared with crypto-spki-pin.test.js so the SPKI-pin
// suite reuses the same in-tree self-signed cert builder rather than
// rolling its own ASN.1 fixture.
module.exports = { run: run, _makeEcCert: _makeEcCert };

if (require.main === module) {
  try { run(); console.log("[crypto] OK"); }
  catch (e) { console.error(e); process.exit(1); }
}
