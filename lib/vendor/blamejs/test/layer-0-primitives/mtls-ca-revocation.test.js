// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mtlsCa revocation + issuance identity (#322).
 *
 * The require-mtls gate denies by SHA3-512 fingerprint, but revocation used to
 * be keyed only by serial, the registry could only be a plaintext file, and
 * issuance discarded the serial + fingerprint. This proves the three additive
 * fixes: fingerprint-addressable revoke()/isRevoked(), a bring-your-own
 * revocation store, and serial+fingerprint surfaced from issuance.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var nodeCrypto = require("crypto");
var fs   = require("fs");
var os   = require("os");
var path = require("path");
var engine = require("../../lib/mtls-engine-default");
var pki    = require("../../lib/vendor/blamejs-pki.cjs");   // parse a built P12 to assert its MAC form

function _mkTmp(prefix) { return fs.mkdtempSync(path.join(os.tmpdir(), prefix)); }

// Issuance variants drive the engine's leaf-signing branches through the
// b.mtlsCa consumer: the extended-key-usage arms (client / server / both),
// SAN entry mapping (DNS: / IP: / bare-IPv4 / bare-DNS / IPv6), the
// serverAuth auto-SAN, an explicit validity window, and the reject paths.
async function testIssuanceVariants() {
  var dir = _mkTmp("blamejs-mtls-issue-");
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });

  var srv = await ca.generateClientCert({ cn: "svc-1", usage: "server", validityDays: 30 });
  check("usage:'server' with an explicit validity issues a cert", typeof srv.cert === "string" && srv.usage === "server");

  var both = await ca.generateClientCert({
    cn: "svc-2",
    usage: "both",
    sans: ["DNS:api.example", "IP:10.0.0.7", "192.168.1.1", "2001:db8::5", "IP:2001:db8::9"],
  });
  check("usage:'both' with mixed DNS/IPv4/IPv6 SANs issues a cert", typeof both.cert === "string");

  var badUsage = false;
  try { await ca.generateClientCert({ cn: "x", usage: "bogus" }); }
  catch (e) { badUsage = /bad-usage/.test(e.code || ""); }
  check("a usage outside client|server|both is refused", badUsage);

  var badCn = false;
  try { await ca.generateClientCert({ cn: "@@@" }); }
  catch (e) { badCn = /bad-cn/.test(e.code || ""); }
  check("a CN of only non-identifier characters is refused", badCn);

  var emptyCn = false;
  try { await ca.generateClientCert({ cn: "" }); }
  catch (e) { emptyCn = /bad-cn/.test(e.code || ""); }
  check("an empty-string CN is refused", emptyCn);

  var badDays = false;
  try { await ca.generateClientCert({ cn: "y", validityDays: -1 }); }
  catch (e) { badDays = /bad-validity-days/.test(e.code || ""); }
  check("a negative validityDays is refused", badDays);

  var badSan = false;
  try { await ca.generateClientCert({ cn: "z", sans: ["IP:not.an.ip"] }); }
  catch (e) { badSan = /bad-san/.test(e.code || ""); }
  check("an unparseable IP SAN is refused", badSan);

  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
}

// Revocation-key + reason validation: every reject arm of _normalizeSerial,
// _normalizeFingerprint, the unknown-reason guard, isRevoked's type guard,
// and the default file store's non-array / corrupt-registry paths.
async function testRevocationValidation() {
  var dir = _mkTmp("blamejs-mtls-revval-");
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });

  var cases = [
    ["a non-string fingerprint is refused",        function () { ca.revoke({ fingerprint: 123 }); },      /bad-fingerprint/],
    ["a non-hex fingerprint is refused",           function () { ca.revoke({ fingerprint: "zzz" }); },    /bad-fingerprint/],
    ["a non-string serial is refused",             function () { ca.revoke(123); },                       /bad-serial/],
    ["a non-hex serial is refused",                function () { ca.revoke("zz-not-hex"); },              /bad-serial/],
    ["an unknown revocation reason is refused",    function () { ca.revoke("ab", { reason: "bogus" }); }, /bad-reason/],
    ["isRevoked with a non-string key is refused", function () { ca.isRevoked(123); },                    /bad-revocation-key/],
  ];
  for (var i = 0; i < cases.length; i++) {
    var threw = false;
    try { cases[i][1](); } catch (e) { threw = cases[i][2].test(e.code || ""); }
    check(cases[i][0], threw);
  }

  // Registry file present but carrying no revocations array → empty list.
  var dirNoArr = _mkTmp("blamejs-mtls-revnoarr-");
  var caNoArr = b.mtlsCa.create({ dataDir: dirNoArr, caKeySealedMode: "disabled" });
  fs.writeFileSync(path.join(dirNoArr, "revocations.json"), '{"unrelated":1}');
  check("a revocations.json without a revocations array reads as not-revoked", caNoArr.isRevoked("ab") === false);

  // Corrupt registry file → surfaced as revocation-corrupt.
  var dirBad = _mkTmp("blamejs-mtls-revbad-");
  var caBad = b.mtlsCa.create({ dataDir: dirBad, caKeySealedMode: "disabled" });
  fs.writeFileSync(path.join(dirBad, "revocations.json"), "{ this is not json");
  var threwCorrupt = false;
  try { caBad.isRevoked("ab"); } catch (e) { threwCorrupt = /revocation-corrupt/.test(e.code || ""); }
  check("a corrupt revocations.json surfaces revocation-corrupt", threwCorrupt);

  [dir, dirNoArr, dirBad].forEach(function (d) { try { fs.rmSync(d, { recursive: true, force: true }); } catch (_e) { /* best-effort */ } });
}

// The default engine's direct contract: argument defaulting, the
// missing-argument guards on every entry point, the PKCS#12 password
// guard, and algorithm pinning (both the label and the keyAlg-name forms,
// plus the unknown-algorithm reject).
async function testEngineDirectContract() {
  // generateCa with no opts: opts defaults + generation defaults to 1.
  var ca = await engine.generateCa();
  check("engine.generateCa() defaults its options and issues a CA", typeof ca.caCertPem === "string");

  // signClientCert missing-argument arms.
  var signCases = [
    ["engine.signClientCert() with no opts throws missing-arg", undefined],
    ["engine.signClientCert missing both CA PEMs throws missing-arg", { cn: "x" }],
    ["engine.signClientCert missing the CA key throws missing-arg", { cn: "x", caCertPem: "c" }],
  ];
  for (var i = 0; i < signCases.length; i++) {
    var threwS = false;
    try { await engine.signClientCert(signCases[i][1]); } catch (e) { threwS = /missing-arg/.test(e.code || ""); }
    check(signCases[i][0], threwS);
  }

  // packageP12 password guard (no opts and empty-string password).
  var p12Cases = [
    ["engine.packageP12() with no opts throws no-password", undefined],
    ["engine.packageP12 with an empty password throws no-password", { password: "" }],
  ];
  for (var j = 0; j < p12Cases.length; j++) {
    var threwP = false;
    try { await engine.packageP12(p12Cases[j][1]); } catch (e) { threwP = /no-password/.test(e.code || ""); }
    check(p12Cases[j][0], threwP);
  }

  // Algorithm pinning: an unknown label, a match by label, and a match by
  // the underlying keyAlg.name.
  var threwUnknown = false;
  try { await engine.generateCa({ algorithm: "no-such-alg" }); }
  catch (e) { threwUnknown = /unknown-algorithm/.test(e.code || ""); }
  check("engine.generateCa pinned to an unknown algorithm is refused", threwUnknown);

  var byLabel = await engine.generateCa({ algorithm: "ML-DSA-87" });
  check("engine.generateCa pins an algorithm by its label", typeof byLabel.caCertPem === "string");

  var byName = await engine.generateCa({ algorithm: "ECDSA" });
  check("engine.generateCa pins an algorithm by its keyAlg name", typeof byName.caCertPem === "string");
  check("a pinned CA is issued under the classical algorithm requested",
        nodeCrypto.createPrivateKey(byName.caKeyPem).asymmetricKeyType === "ec");

  // PQC-downgrade guard: a per-call classical pin MUST NOT become the process
  // default. Immediately after pinning ECDSA above, a default (unpinned) CA has
  // to be issued under the ML-DSA-87 PQC-first default — not silently
  // downgraded to the last-pinned classical algorithm.
  var afterPin = await engine.generateCa();
  var afterType = String(nodeCrypto.createPrivateKey(afterPin.caKeyPem).asymmetricKeyType || "");
  check("pinning a classical algorithm does not downgrade a later default CA off ML-DSA-87",
        /ml-dsa/i.test(afterType));
}

// The PKCS#12 outer MAC must follow the cert's interop tier. The classical
// ECDSA-P384 bridge exists FOR peers predating OpenSSL 3.5, so its P12 must use
// the legacy-importable RFC 7292 App. B HMAC MacData — NOT PBMAC1 (RFC 9579,
// OpenSSL 3.4+), which those same consumers cannot verify. The PQC default keeps
// PBMAC1. RED before the fix: every P12 used PBMAC1, so an ECDSA-fallback P12 was
// unreadable by the very legacy peers it exists to serve.
async function testP12MacFollowsAlgorithmTier() {
  var dirC = _mkTmp("blamejs-mtls-p12c-");
  var dirP = _mkTmp("blamejs-mtls-p12p-");
  var caC = b.mtlsCa.create({ dataDir: dirC, caKeySealedMode: "disabled", algorithm: "ECDSA-P384-SHA384" });
  var p12c = await caC.generateClientP12({ cn: "classical-holder", password: "p12-pw-classical-7h2" });
  var parsedC = pki.schema.pkcs12.parse(p12c.p12);
  check("classical-bridge P12 uses the legacy RFC 7292 HMAC MacData (not PBMAC1)",
        parsedC.mac && parsedC.mac.kind === "hmac");
  check("classical-bridge P12 MacData verifies under its password",
        (await pki.pkcs12.verifyMac(p12c.p12, "p12-pw-classical-7h2")) === true);

  var caP = b.mtlsCa.create({ dataDir: dirP, caKeySealedMode: "disabled" });
  var p12p = await caP.generateClientP12({ cn: "pqc-holder", password: "p12-pw-pqc-7h2" });
  var parsedP = pki.schema.pkcs12.parse(p12p.p12);
  check("PQC-default P12 keeps the PBMAC1 (RFC 9579) outer MAC",
        parsedP.mac && parsedP.mac.kind === "pbmac1");

  // The public algorithm envelope must describe the P12 MAC the engine actually
  // builds for BOTH tiers — RED before the fix it hardcoded pbmac1, misdescribing
  // a classical-bridge archive to a compatibility/policy consumer.
  var env = engine.algorithmEnvelope();
  check("envelope: PQC-tier P12 MAC is PBMAC1 @ 2,000,000",
        env.p12 && env.p12.mac && env.p12.mac["pqc-pure"] &&
        env.p12.mac["pqc-pure"].algorithm === "pbmac1" &&
        env.p12.mac["pqc-pure"].iterations === 2000000);
  check("envelope: classical-tier P12 MAC is the RFC 7292 HMAC MacData @ 1,000,000",
        env.p12.mac.classical && env.p12.mac.classical.algorithm === "hmac" &&
        env.p12.mac.classical.iterations === 1000000);
}

// A pinned algorithm that DISAGREES with a stored CA cannot be honored: leaf
// issuance would sign an ECDSA leaf under an existing ML-DSA CA, a chain the
// pre-OpenSSL-3.5 peer the pin targets cannot verify. initCA refuses the
// mismatch and tells the operator to rotate. RED before the fix: initCA returned
// the stored ML-DSA CA and issued the ECDSA-pinned leaf against it.
async function testAlgorithmPinMismatchOnExistingCa() {
  var dir = _mkTmp("blamejs-mtls-algmismatch-");
  var caDefault = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });   // ML-DSA default
  await caDefault.initCA();
  check("mismatch setup: the stored default CA is ML-DSA",
        /ml-dsa/i.test(nodeCrypto.createPrivateKey(caDefault.loadKey()).asymmetricKeyType));

  var caPinned = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", algorithm: "ECDSA-P384-SHA384" });
  var threw = null;
  try { await caPinned.generateClientCert({ cn: "legacy-peer" }); } catch (e) { threw = e; }
  check("an ECDSA pin against a stored ML-DSA CA is refused (rotate instead)",
        threw && /mtls-ca\/algorithm-mismatch/.test(threw.code || ""));

  // The pin must MATCH the on-disk CA, not merely share a family: an ML-DSA-65
  // pin against a stored ML-DSA-87 CA is refused too (rotate to switch levels).
  var caMl65 = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", algorithm: "ML-DSA-65" });
  var threwMl = null;
  try { await caMl65.generateClientCert({ cn: "ml65" }); } catch (e) { threwMl = e; }
  check("an ML-DSA-65 pin against a stored ML-DSA-87 CA is refused",
        threwMl && /mtls-ca\/algorithm-mismatch/.test(threwMl.code || ""));

  // A label this file can't map (a custom engine's own naming) skips the check —
  // initCA returns the stored CA and the engine owns the algorithm semantics.
  var caCustom = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", algorithm: "custom-engine-alg" });
  var custom = await caCustom.initCA();
  check("an unmappable algorithm-pin label skips the stored-CA check",
        typeof custom.caCertPem === "string");

  // A stored CA whose key node cannot parse (a custom engine's own key form) —
  // the check can't determine the algorithm, so it skips rather than refusing.
  var dir3 = _mkTmp("blamejs-mtls-algstub-");
  var okGen = async function () {
    return { caCertPem: "-----BEGIN CERTIFICATE-----\nSTUB\n-----END CERTIFICATE-----\n", caKeyPem: "NOT-A-PARSEABLE-KEY" };
  };
  var caStub1 = b.mtlsCa.create({ dataDir: dir3, caKeySealedMode: "disabled", engine: { generateCa: okGen }, algorithm: "ECDSA-P384-SHA384" });
  await caStub1.initCA();                                   // commits the non-PEM key
  var caStub2 = b.mtlsCa.create({ dataDir: dir3, caKeySealedMode: "disabled", engine: { generateCa: okGen }, algorithm: "ECDSA-P384-SHA384" });
  var stubCa = await caStub2.initCA();                      // CA exists; key unparseable → check skips
  check("a stored CA key node cannot parse skips the algorithm-pin check",
        typeof stubCa.caCertPem === "string");

  // The same pin against a MATCHING stored CA still issues (re-open a pinned CA).
  var dir2 = _mkTmp("blamejs-mtls-algmatch-");
  var caEc1 = b.mtlsCa.create({ dataDir: dir2, caKeySealedMode: "disabled", algorithm: "ECDSA-P384-SHA384" });
  await caEc1.initCA();
  var caEc2 = b.mtlsCa.create({ dataDir: dir2, caKeySealedMode: "disabled", algorithm: "ECDSA-P384-SHA384" });
  var leaf = await caEc2.generateClientCert({ cn: "ec-peer" });
  check("re-opening a matching pinned CA still issues a leaf", typeof leaf.cert === "string");

  // A stored EC CA on the WRONG curve (a P-256 CA, e.g. imported via a custom
  // engine) must be refused under the ECDSA-P384 pin: every ECDSA label maps to the
  // generic "ec" type, so without a curve check a P-256 CA would satisfy the P-384
  // pin and misrepresent the posture. RED before the fix: only the key TYPE was
  // compared, so the P-256 CA passed.
  var p256Key = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" })
    .privateKey.export({ type: "pkcs8", format: "pem" });
  function _p256Engine() {
    return {
      generateCa: async function () {
        return { caCertPem: "-----BEGIN CERTIFICATE-----\nP256CA\n-----END CERTIFICATE-----\n", caKeyPem: p256Key };
      },
      signClientCert: async function () { return { cert: "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n", key: "k" }; },
    };
  }
  var dirCurve = _mkTmp("blamejs-mtls-curve-");
  await b.mtlsCa.create({ dataDir: dirCurve, caKeySealedMode: "disabled", engine: _p256Engine() }).initCA();
  var caWrongCurve = b.mtlsCa.create({ dataDir: dirCurve, caKeySealedMode: "disabled", engine: _p256Engine(), algorithm: "ECDSA-P384-SHA384" });
  var curveThrew = null;
  try { await caWrongCurve.initCA(); } catch (e) { curveThrew = e; }
  check("a P-256 stored CA is refused under the ECDSA-P384 pin (curve mismatch)",
        curveThrew && /mtls-ca\/algorithm-mismatch/.test(curveThrew.code || "") && /secp384r1/.test(curveThrew.message || ""));

  // A custom-engine label (not the ECDSA-P384 pin) leaves the curve to the engine:
  // a P-256 CA under such a label is NOT curve-checked here.
  var dirCustomCurve = _mkTmp("blamejs-mtls-curve-custom-");
  await b.mtlsCa.create({ dataDir: dirCustomCurve, caKeySealedMode: "disabled", engine: _p256Engine() }).initCA();
  var caCustomCurve = b.mtlsCa.create({ dataDir: dirCustomCurve, caKeySealedMode: "disabled", engine: _p256Engine(), algorithm: "custom-engine-alg" });
  var customCurveThrew = null;
  try { await caCustomCurve.initCA(); } catch (e) { customCurveThrew = e; }
  check("a custom-engine label does not impose the P-384 curve check on a P-256 CA",
        customCurveThrew === null);
}

// An upgrade path: a pre-existing (classical) CA re-opened with NO algorithm pin
// must still issue leaves under the CA's OWN algorithm, not the new ML-DSA-87
// default — else an EC CA signs an ML-DSA leaf the legacy peers it served cannot
// complete a handshake with. RED before the fix: an unpinned leaf followed the
// engine's process default (ML-DSA-87).
async function testUnpinnedLeafFollowsStoredCaAlgorithm() {
  var dir = _mkTmp("blamejs-mtls-cafollow-");
  var caEc = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", algorithm: "ECDSA-P384-SHA384" });
  await caEc.initCA();                                       // a classical EC CA (pre-0.18 deployment)
  var caUpgraded = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });   // upgrade: no pin
  var leaf = await caUpgraded.generateClientCert({ cn: "legacy-client" });
  check("unpinned issuance under a stored EC CA yields an EC leaf (not the ML-DSA default)",
        nodeCrypto.createPrivateKey(leaf.key).asymmetricKeyType === "ec");
  var p12 = await caUpgraded.generateClientP12({ cn: "legacy-p12", password: "cafollow-pw-9k2" });
  check("unpinned P12 under a stored EC CA is produced (classical MAC tier)",
        Buffer.isBuffer(p12.p12));

  // Passing engine: null explicitly (an app clearing its optional engine setting)
  // selects the bundled engine — so it is NOT a custom engine and MUST keep the
  // stored-CA inference. RED before the fix: usesDefaultEngine tested
  // `engine === undefined`, so an explicit null skipped the inference and the
  // bundled engine issued an ML-DSA leaf under the classical CA.
  var caNullEngine = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", engine: null });
  var leafNull = await caNullEngine.generateClientCert({ cn: "null-engine-client" });
  check("engine: null selects the bundled engine and still follows the stored EC CA",
        nodeCrypto.createPrivateKey(leafNull.key).asymmetricKeyType === "ec");

  // The default ML-DSA CA still issues ML-DSA leaves when unpinned (no regression).
  var dir2 = _mkTmp("blamejs-mtls-cafollow-pqc-");
  var caPqc = b.mtlsCa.create({ dataDir: dir2, caKeySealedMode: "disabled" });
  var leafPqc = await caPqc.generateClientCert({ cn: "pqc-client" });
  check("unpinned issuance under a default ML-DSA CA still yields an ML-DSA leaf",
        /ml-dsa/i.test(nodeCrypto.createPrivateKey(leafPqc.key).asymmetricKeyType));

  // A custom engine whose CA key node cannot parse: no algorithm can be derived,
  // so the engine's own default applies (an undefined label passes through).
  var dir3 = _mkTmp("blamejs-mtls-cafollow-stub-");
  var okGen = async function () {
    return { caCertPem: "-----BEGIN CERTIFICATE-----\nSTUB\n-----END CERTIFICATE-----\n", caKeyPem: "NOT-A-PARSEABLE-KEY" };
  };
  var stubEng = {
    generateCa: okGen,
    signClientCert: async function () { return { cert: "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n", key: "k" }; },
  };
  var caStub = b.mtlsCa.create({ dataDir: dir3, caKeySealedMode: "disabled", engine: stubEng });
  var stubLeaf = await caStub.generateClientCert({ cn: "stub" });
  check("an unparseable stored CA key derives no leaf algorithm (engine default applies)",
        typeof stubLeaf.cert === "string");

  // A parseable but non-EC / non-ML-DSA stored CA key (e.g. RSA): also unmapped,
  // so the engine's default applies.
  var rsaPem = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
    .privateKey.export({ type: "pkcs8", format: "pem" });
  var okGenRsa = async function () {
    return { caCertPem: "-----BEGIN CERTIFICATE-----\nRSA\n-----END CERTIFICATE-----\n", caKeyPem: rsaPem };
  };
  var caRsa = b.mtlsCa.create({
    dataDir: _mkTmp("blamejs-mtls-cafollow-rsa-"), caKeySealedMode: "disabled",
    engine: { generateCa: okGenRsa, signClientCert: stubEng.signClientCert },
  });
  var rsaLeaf = await caRsa.generateClientCert({ cn: "rsa" });
  check("a non-EC / non-ML-DSA stored CA key derives no leaf algorithm",
        typeof rsaLeaf.cert === "string");

  // A CUSTOM engine with a PARSEABLE EC CA key must NOT have the default engine's
  // "ECDSA-P384-SHA384" label inferred and injected: a custom engine owns its own
  // label set and key curve (it may run a P-256/P-521 CA, or name its labels
  // differently), so injecting the bundled label would break an engine that
  // validates its option shape or rejects unknown labels. The CA-following
  // inference is the DEFAULT engine's alone. RED before the fix: _labelForCaKeyType
  // mapped every EC key to ECDSA-P384-SHA384 for every engine, so the stub saw
  // that label instead of undefined.
  var ecP256Pem = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" })
    .privateKey.export({ type: "pkcs8", format: "pem" });
  var seenAlg = "UNSET";
  var ecEngine = {
    generateCa: async function () {
      return { caCertPem: "-----BEGIN CERTIFICATE-----\nECCA\n-----END CERTIFICATE-----\n", caKeyPem: ecP256Pem };
    },
    signClientCert: async function (a) {
      seenAlg = a.algorithm;
      return { cert: "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n", key: "k" };
    },
  };
  var caEcCustom = b.mtlsCa.create({
    dataDir: _mkTmp("blamejs-mtls-cafollow-ec-"), caKeySealedMode: "disabled", engine: ecEngine,
  });
  await caEcCustom.generateClientCert({ cn: "ec" });
  check("an unpinned custom engine with an EC CA key receives no inferred algorithm",
        seenAlg === undefined);
}

// The CA's algorithm (a factory pin verified against the stored CA, or the bundled
// engine's stored-CA inference) is AUTHORITATIVE for the leaf: a per-issuance
// opts.algorithm that conflicts with it is refused, not silently honored — else a
// classical ECDSA-P384 CA would issue an ML-DSA-87 leaf its legacy peers cannot
// authenticate, and the P12 path would select the incompatible PBMAC1 MAC tier.
// RED before the fix: opts2.algorithm overrode the pin via Object.assign order.
// algorithmEnvelope().cert must describe the most-recent RESOLVED algorithm,
// including a per-call PIN (deliberately never cached as the process default). RED
// before the fix: the envelope read only _selectedAlg (the default cache), so it
// was null after a pinned generateCa with no prior default op, or reported the
// unrelated default otherwise.
async function testAlgorithmEnvelopeReportsPinnedSelection() {
  await engine.generateCa({ generation: 1, algorithm: "ECDSA-P384-SHA384" });
  var envPin = engine.algorithmEnvelope();
  check("envelope: reports the pinned classical selection after a pinned generateCa",
        envPin.cert.label === "ECDSA-P384-SHA384" && envPin.cert.posture === "classical");
  // An unpinned generateCa resolves the ML-DSA default; the envelope follows it.
  await engine.generateCa({ generation: 1 });
  var envDefault = engine.algorithmEnvelope();
  check("envelope: follows the ML-DSA default after an unpinned generateCa",
        /ml-dsa/i.test(String(envDefault.cert.label)) && envDefault.cert.posture === "pqc-pure");
}

async function testLeafAlgorithmConflictRefused() {
  var dir = _mkTmp("blamejs-mtls-algconflict-");
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", algorithm: "ECDSA-P384-SHA384" });
  await ca.initCA();

  var certThrew = null;
  try { await ca.generateClientCert({ cn: "conflict", algorithm: "ML-DSA-87" }); }
  catch (e) { certThrew = e; }
  check("generateClientCert refuses a per-issuance algorithm conflicting with the pinned CA",
        certThrew && /mtls-ca\/algorithm-conflict/.test(certThrew.code || ""));

  var p12Threw = null;
  try { await ca.generateClientP12({ cn: "conflict-p12", password: "algconflict-pw-7k", algorithm: "ML-DSA-87" }); }
  catch (e) { p12Threw = e; }
  check("generateClientP12 refuses a per-issuance algorithm conflicting with the pinned CA",
        p12Threw && /mtls-ca\/algorithm-conflict/.test(p12Threw.code || ""));

  // A per-issuance algorithm that MATCHES the CA is accepted (an EC leaf).
  var matchLeaf = await ca.generateClientCert({ cn: "match", algorithm: "ECDSA-P384-SHA384" });
  check("generateClientCert accepts a per-issuance algorithm matching the pinned CA",
        nodeCrypto.createPrivateKey(matchLeaf.key).asymmetricKeyType === "ec");
}

// A strict custom engine validates its generateCa option shape. An UNPINNED
// create({ engine }) must call generateCa with { generation } only — no own
// `algorithm: undefined` key — so such an engine can still do first-time CA init
// without the operator opting into the algorithm feature. A PINNED create passes
// the algorithm. RED before the fix: the call always included `algorithm`.
async function testGenerateCaOmitsUnsetAlgorithm() {
  var seenUnpinned = null;
  var stubUnpinned = {
    generateCa: async function (o) {
      seenUnpinned = Object.keys(o);
      return { caCertPem: "-----BEGIN CERTIFICATE-----\nUNP\n-----END CERTIFICATE-----\n", caKeyPem: "K" };
    },
  };
  await b.mtlsCa.create({ dataDir: _mkTmp("blamejs-mtls-cagen-unp-"), caKeySealedMode: "disabled", engine: stubUnpinned }).initCA();
  check("unpinned generateCa receives only { generation }, no algorithm key",
        seenUnpinned && seenUnpinned.indexOf("generation") !== -1 && seenUnpinned.indexOf("algorithm") === -1);

  var seenPinned = null;
  var stubPinned = {
    generateCa: async function (o) {
      seenPinned = Object.keys(o);
      return { caCertPem: "-----BEGIN CERTIFICATE-----\nPIN\n-----END CERTIFICATE-----\n", caKeyPem: "K" };
    },
  };
  await b.mtlsCa.create({ dataDir: _mkTmp("blamejs-mtls-cagen-pin-"), caKeySealedMode: "disabled", engine: stubPinned, algorithm: "ECDSA-P384-SHA384" }).initCA();
  check("pinned generateCa receives the algorithm key",
        seenPinned && seenPinned.indexOf("algorithm") !== -1);
}

// The classical ECDSA-P384-SHA384 bridge must sign the CA, every leaf, and every
// CRL with ecdsa-with-SHA-384 (OID 1.2.840.10045.4.3.3) — matching its advertised
// posture and the pre-flip release — NOT the toolkit's EC default of SHA-256,
// which would silently downgrade the digest below the framework no-SHA-256 rule.
// RED before the fix: the engine passed no digestAlgorithm, so every classical
// signature was ecdsa-with-SHA-256 (OID ...4.3.2).
async function testClassicalBridgeSignsWithSha384() {
  var SHA384 = "1.2.840.10045.4.3.3";
  var dir = _mkTmp("blamejs-mtls-sha384-");
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", algorithm: "ECDSA-P384-SHA384" });
  var bundle = await ca.initCA();
  var leaf = await ca.generateClientCert({ cn: "svc" });
  check("classical CA cert signature is ecdsa-with-SHA384 (not the SHA-256 EC default)",
        pki.schema.x509.parse(bundle.caCertPem).signatureAlgorithm.oid === SHA384);
  check("classical leaf cert signature is ecdsa-with-SHA384",
        pki.schema.x509.parse(leaf.cert).signatureAlgorithm.oid === SHA384);
  await ca.revoke({ fingerprint: leaf.fingerprint });
  var crl = await ca.generateCrl();
  check("classical CRL signature is ecdsa-with-SHA384",
        pki.schema.crl.parse(crl.crlPem).signatureAlgorithm.oid === SHA384);
}

// A bare IPv6 SAN must encode as an iPAddress GeneralName, not a DNS name — a
// colon-bearing DNS SAN can never match, so a TLS client connecting by the IPv6
// address would fail verification. RED before the fix: sans:["fe80::1"] emitted
// DNS:fe80::1 (IPv4 was auto-detected, IPv6 fell through to the DNS default).
async function testIpv6SanEncodesAsIpAddress() {
  var dir = _mkTmp("blamejs-mtls-v6san-");
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  var leaf = await ca.generateClientCert({ cn: "svc", usage: "server", sans: ["fe80::1"] });
  var san = new nodeCrypto.X509Certificate(leaf.cert).subjectAltName || "";
  check("a bare IPv6 SAN encodes as an iPAddress, not a DNS name",
        /IP Address:/i.test(san) && !/DNS:fe80/i.test(san));
  // A bare hostname (not an IP) still encodes as a DNS SAN — the IPv6 branch must
  // not swallow it.
  var leaf2 = await ca.generateClientCert({ cn: "svc", usage: "server", sans: ["api.example.com"] });
  var san2 = new nodeCrypto.X509Certificate(leaf2.cert).subjectAltName || "";
  check("a bare hostname SAN encodes as a DNS name",
        /DNS:api\.example\.com/i.test(san2));
}

// removeFromCRL (RFC 5280 code 8) is a delta-CRL un-revocation directive, invalid
// in a full CRL — the only kind this CA issues. RED before the fix: revoke()
// accepted it, and one persisted code-8 entry made every later generateCrl() fail
// (the toolkit rejects code 8 in a full CRL), blocking all revocation publishing.
async function testRevokeRejectsRemoveFromCrl() {
  var dir = _mkTmp("blamejs-mtls-removefromcrl-");
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
  var leaf = await ca.generateClientCert({ cn: "x" });
  var threw = null;
  try { ca.revoke(leaf.serialNumber, { reason: "removeFromCRL" }); } catch (e) { threw = e; }
  check("revoke: removeFromCRL is refused (delta-CRL directive, not a reason)",
        threw && /mtls-ca\/bad-reason/.test(threw.code || ""));
  // A valid reason still revokes AND generateCrl() publishes (not poisoned).
  await ca.revoke(leaf.serialNumber, { reason: "keyCompromise" });
  var crl = await ca.generateCrl();
  check("revoke: a valid reason still publishes a CRL", typeof crl.crlPem === "string");
}

// revoke() refuses removeFromCRL going forward, but a revocations registry written
// by a pre-fix build (or hand-edited) may still hold a legacy code-8 entry. A full
// CRL cannot carry it, so generateCrl() must DROP the invalid reason -- keeping the
// serial revoked (fail-secure) -- rather than forward code 8 and fail the ENTIRE
// CRL. RED before the fix: the engine forwarded reasonCode 8, so pki.crl.sign
// rejected it (crl/bad-reason-code) and one legacy entry blocked publishing every
// other revocation.
async function testGenerateCrlDropsLegacyRemoveFromCrl() {
  var ca = await engine.generateCa({ generation: 1, algorithm: "ECDSA-P384-SHA384" });
  var threw = null, crlPem = null;
  try {
    crlPem = await engine.generateCrl({
      caCertPem: ca.caCertPem, caKeyPem: ca.caKeyPem,
      revocations: [
        { serialNumber: "0A", reasonCode: 8, revokedAt: Date.now() },   // legacy removeFromCRL
        { serialNumber: "0B", reasonCode: 1, revokedAt: Date.now() },   // valid keyCompromise
      ],
    });
  } catch (e) { threw = e; }
  check("generateCrl signs despite a legacy removeFromCRL (code 8) entry",
        threw === null && typeof crlPem === "string" && /BEGIN X509 CRL/.test(crlPem));
  var revoked = pki.schema.crl.parse(crlPem).revokedCertificates || [];
  var serials = revoked.map(function (e) { return parseInt(e.serialNumberHex, 16); });
  check("generateCrl keeps the legacy-reason serial revoked (fail-secure)", serials.indexOf(0x0A) >= 0);
  check("generateCrl keeps the valid revocation", serials.indexOf(0x0B) >= 0);
}

async function run() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mtls-revoke-"));
  var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled", generation: 1 });

  // ---- #322 part 3: issuance surfaces serial + fingerprint ----
  var issued = await ca.generateClientCert({ cn: "client-1" });
  check("issuance surfaces a hex serialNumber",
    typeof issued.serialNumber === "string" && /^[0-9a-f]+$/.test(issued.serialNumber));
  check("issuance surfaces a 128-hex SHA3-512 fingerprint",
    typeof issued.fingerprint === "string" && issued.fingerprint.length === 128);
  check("the surfaced fingerprint equals the value the require-mtls gate pins (hashCertFingerprint of the DER)",
    issued.fingerprint === b.crypto.hashCertFingerprint(issued.cert).hex);

  // ---- parseGeneration across its input arms ----
  // A framework-issued CA cert carries an OU=CAv{N} tag; a leaf does not
  // (falls back to generation 1); non-PEM inputs read as 0.
  check("parseGeneration reads the OU=CAv{N} tag off a real CA cert",
    b.mtlsCa.parseGeneration(ca.loadCert()) === 1);
  check("parseGeneration falls back to generation 1 for an untagged leaf cert",
    b.mtlsCa.parseGeneration(issued.cert) === 1);
  check("parseGeneration(null) reads 0", b.mtlsCa.parseGeneration(null) === 0);
  check("parseGeneration(number) reads 0", b.mtlsCa.parseGeneration(12345) === 0);
  check("parseGeneration of an unparseable PEM reads 0",
    b.mtlsCa.parseGeneration("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n") === 0);

  // ---- #322 part 1: revoke + isRevoked by serial (backward-compat) ----
  await ca.revoke(issued.serialNumber, { reason: "superseded" });
  check("revoke(serial) then isRevoked(serial) is true", ca.isRevoked(issued.serialNumber) === true);
  check("a serial that was never revoked reads false", ca.isRevoked("00ff") === false);
  var first = await ca.revoke(issued.serialNumber);
  var again = await ca.revoke(issued.serialNumber);
  check("revoke is idempotent (revokedAt unchanged)", first.revokedAt === again.revokedAt);

  // ---- #322 part 1: revoke + isRevoked by fingerprint (the gate's key) ----
  var issued2 = await ca.generateClientCert({ cn: "client-2" });
  await ca.revoke({ fingerprint: issued2.fingerprint, reason: "keyCompromise" });
  check("revoke({fingerprint}) then isRevoked(fingerprint) is true",
    ca.isRevoked(issued2.fingerprint) === true);
  check("isRevoked tolerates separator/case formatting",
    ca.isRevoked(issued2.fingerprint.toUpperCase()) === true);

  var threwNoKey = false;
  try { ca.revoke({ reason: "x" }); } catch (e) { threwNoKey = /no-revocation-key/.test(e.code || ""); }
  check("revoke with neither serial nor fingerprint throws", threwNoKey);

  // ---- #322 part 2: bring-your-own revocation store ----
  var rows = [];
  var store = { list: function () { return rows.slice(); }, add: function (e) { rows.push(e); } };
  var dir2 = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mtls-byostore-"));
  var ca2 = b.mtlsCa.create({ dataDir: dir2, caKeySealedMode: "disabled", revocationStore: store });
  await ca2.revoke("AB:CD:EF", { reason: "cessationOfOperation" });
  check("BYO store: revoke writes through the operator store (normalized serial)",
    rows.length === 1 && rows[0].serialNumber === "abcdef");
  check("BYO store: isRevoked reads through the operator store", ca2.isRevoked("abcdef") === true);
  check("BYO store: the default revocations.json was not written",
    !fs.existsSync(path.join(dir2, "revocations.json")));

  var threwBadStore = false;
  try {
    b.mtlsCa.create({ dataDir: dir2, caKeySealedMode: "disabled", revocationStore: { list: 1 } });
  } catch (e) { threwBadStore = /bad-revocation-store/.test(e.code || ""); }
  check("a revocationStore missing list()/add() is refused at create()", threwBadStore);

  // ---- #322 part 3: a custom engine may return a non-X.509 cert shape ----
  // The serial comes from an X.509 parse (best-effort); the fingerprint is a
  // hash of the returned bytes (always available). Optional identity
  // enrichment must never crash issuance.
  var dir3 = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mtls-stub-"));
  var stubEngine = {
    generateCa: async function () {
      return { caCertPem: "ENGINE-CA", caKeyPem: "ENGINE-KEY", generation: 1 };
    },
    signClientCert: async function (a) {
      // A cert with NO decodable PEM/DER envelope — hashCertFingerprint cannot
      // process it, so _certIdentity falls back to a stable byte-hash; issuance
      // must still surface a revocable fingerprint and never crash.
      return { cert: "NOT-X509-" + a.cn, key: "k" };
    },
  };
  var ca3 = b.mtlsCa.create({ dataDir: dir3, engine: stubEngine, caKeySealedMode: "disabled" });
  var stub = await ca3.generateClientCert({ cn: "stub-client" });
  check("non-X.509 engine cert does not crash issuance", typeof stub.cert === "string");
  check("unparseable cert yields serialNumber null (best-effort)", stub.serialNumber === null);
  check("fingerprint is still surfaced for an undecodable cert (byte-hash fallback)",
    stub.fingerprint === b.crypto.sha3Hash(stub.cert));
  await ca3.revoke({ fingerprint: stub.fingerprint });
  check("a non-X.509 cert is still revocable by fingerprint", ca3.isRevoked(stub.fingerprint) === true);

  await testIssuanceVariants();
  await testRevocationValidation();
  await testEngineDirectContract();
  await testP12MacFollowsAlgorithmTier();
  await testAlgorithmPinMismatchOnExistingCa();
  await testUnpinnedLeafFollowsStoredCaAlgorithm();
  await testLeafAlgorithmConflictRefused();
  await testAlgorithmEnvelopeReportsPinnedSelection();
  await testGenerateCaOmitsUnsetAlgorithm();
  await testClassicalBridgeSignsWithSha384();
  await testIpv6SanEncodesAsIpAddress();
  await testRevokeRejectsRemoveFromCrl();
  await testGenerateCrlDropsLegacyRemoveFromCrl();

  try {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(dir2, { recursive: true, force: true });
    fs.rmSync(dir3, { recursive: true, force: true });
  } catch (_e) { /* best-effort */ }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mtls-ca-revocation] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
