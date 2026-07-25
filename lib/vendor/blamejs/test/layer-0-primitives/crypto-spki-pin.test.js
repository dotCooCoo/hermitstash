// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.crypto.spkiPin / b.crypto.spkiPinVerifier — RFC 7469 (HPKP §2.4)
 * SubjectPublicKeyInfo pinning.
 *
 * The pin is base64(SHA-256(SPKI DER)) — the interop wire form browsers,
 * curl `--pinnedpubkey`, and other pinning tooling render. Distinct from
 * `b.crypto.hashCertFingerprint`, which is SHA3-512 over the WHOLE cert:
 * an SPKI pin survives certificate reissue on the same key, a whole-cert
 * fingerprint does not.
 *
 * Reuses the in-tree self-signed cert builder from crypto.test.js so the
 * SPKI bytes come from a real X.509 cert rather than a synthetic fixture.
 *
 * Run standalone: `node test/layer-0-primitives/crypto-spki-pin.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("node:crypto");

var _makeEcCert = require("./crypto.test.js")._makeEcCert;

// Peer-cert object in the shape Node hands `checkServerIdentity`: the
// detailed cert carries `.subject`, `.subjectaltname`, and `.raw` (DER).
function _peerCertObject(fixture, cn, san) {
  return {
    subject:        { CN: cn },
    subjectaltname: san,
    raw:            fixture.certDer,
  };
}

function testSpkiPinShape() {
  var fixture = _makeEcCert("pin-shape.example", "P-256");
  var pin = b.crypto.spkiPin(fixture.certDer);
  check("spkiPin returns { sha256, b64, hex }",
        pin && typeof pin.sha256 === "string" &&
        typeof pin.b64 === "string" && typeof pin.hex === "string");
  // SHA-256 = 32 bytes → 44 base64 chars (43 data + 1 '=' pad).
  check("spkiPin.sha256 is 'sha256/<44-char base64>'",
        /^sha256\/[A-Za-z0-9+/]{43}=$/.test(pin.sha256));
  check("spkiPin.b64 is the 44-char base64 body",
        pin.b64.length === 44 && pin.sha256 === "sha256/" + pin.b64);
  // SHA-256 = 32 bytes → 64 lowercase-hex chars.
  check("spkiPin.hex is 64 lowercase-hex chars",
        /^[0-9a-f]{64}$/.test(pin.hex));
}

function testSpkiPinKnownAnswer() {
  var fixture = _makeEcCert("pin-kat.example", "P-384");
  // Independently derive the pin: extract SPKI DER, SHA-256, base64.
  var spkiDer = new nodeCrypto.X509Certificate(fixture.certDer)
    .publicKey.export({ type: "spki", format: "der" });
  var expB64 = nodeCrypto.createHash("sha256").update(spkiDer).digest("base64");
  var expHex = nodeCrypto.createHash("sha256").update(spkiDer).digest("hex");
  var pin = b.crypto.spkiPin(fixture.certDer);
  check("spkiPin.b64 matches independent SHA-256(SPKI) KAT", pin.b64 === expB64);
  check("spkiPin.sha256 matches 'sha256/' + KAT", pin.sha256 === "sha256/" + expB64);
  check("spkiPin.hex matches independent hex KAT", pin.hex === expHex);
}

function testSpkiPinPemDerAgreement() {
  var fixture = _makeEcCert("pin-pemder.example", "P-256");
  var fromDer = b.crypto.spkiPin(fixture.certDer);
  var fromPem = b.crypto.spkiPin(fixture.pem);
  check("spkiPin(DER) === spkiPin(PEM)", fromDer.sha256 === fromPem.sha256);
}

function testSpkiPinBadInput() {
  var threw = null;
  try { b.crypto.spkiPin(42); } catch (e) { threw = e; }
  check("spkiPin rejects non-Buffer/non-string input", threw instanceof TypeError);
}

function testVerifierMatchingCert() {
  var fixture = _makeEcCert("verify-ok.example", "P-256");
  var correctPin = b.crypto.spkiPin(fixture.certDer).sha256;
  // RFC 7469 requires a backup pin — supply a second, non-matching one.
  var backupPin = b.crypto.spkiPin(_makeEcCert("backup.example", "P-256").certDer).sha256;
  var verify = b.crypto.spkiPinVerifier({ pins: [correctPin, backupPin] });
  var certObj = _peerCertObject(fixture, "verify-ok.example", "DNS:verify-ok.example");
  check("verifier: undefined for matching pin + matching hostname",
        verify("verify-ok.example", certObj) === undefined);
}

function testVerifierNonMatchingPin() {
  var fixture = _makeEcCert("verify-badpin.example", "P-256");
  // Two pins, neither derived from this cert.
  var wrong1 = b.crypto.spkiPin(_makeEcCert("other-1.example", "P-256").certDer).sha256;
  var wrong2 = b.crypto.spkiPin(_makeEcCert("other-2.example", "P-256").certDer).sha256;
  var verify = b.crypto.spkiPinVerifier({ pins: [wrong1, wrong2] });
  var certObj = _peerCertObject(fixture, "verify-badpin.example", "DNS:verify-badpin.example");
  var res = verify("verify-badpin.example", certObj);
  check("verifier: Error when peer pin matches no configured pin",
        res instanceof Error && res.code === "crypto/spki-pin-mismatch");
}

function testVerifierHostnameMismatchWinsOverPin() {
  var fixture = _makeEcCert("verify-host.example", "P-256");
  var correctPin = b.crypto.spkiPin(fixture.certDer).sha256;
  var backupPin = b.crypto.spkiPin(_makeEcCert("backup2.example", "P-256").certDer).sha256;
  var verify = b.crypto.spkiPinVerifier({ pins: [correctPin, backupPin] });
  // Cert SAN is for verify-host.example, but we ask the verifier about a
  // different host — the identity (hostname/SAN) check must refuse FIRST,
  // even though the SPKI pin itself would match.
  var certObj = _peerCertObject(fixture, "verify-host.example", "DNS:verify-host.example");
  var res = verify("wrong-host.example", certObj);
  check("verifier: hostname/SAN error precedes the pin match",
        res instanceof Error &&
        typeof res.code === "string" && res.code.indexOf("tls/pkix") === 0);
}

function testVerifierHostnameOptOverride() {
  var fixture = _makeEcCert("verify-opt.example", "P-256");
  var correctPin = b.crypto.spkiPin(fixture.certDer).sha256;
  var backupPin = b.crypto.spkiPin(_makeEcCert("backup3.example", "P-256").certDer).sha256;
  // opts.hostname pins the expected name; the host argument Node supplies
  // is ignored in favour of it.
  var verify = b.crypto.spkiPinVerifier({
    pins:     [correctPin, backupPin],
    hostname: "verify-opt.example",
  });
  var certObj = _peerCertObject(fixture, "verify-opt.example", "DNS:verify-opt.example");
  check("verifier: opts.hostname override accepts a matching cert",
        verify("ignored-by-override.example", certObj) === undefined);
}

function testVerifierBadOpts() {
  var t1 = null;
  try { b.crypto.spkiPinVerifier(); } catch (e) { t1 = e; }
  check("spkiPinVerifier: requires opts", t1 instanceof TypeError);

  var t2 = null;
  try { b.crypto.spkiPinVerifier({ pins: "sha256/x" }); } catch (e) { t2 = e; }
  check("spkiPinVerifier: pins must be an array", t2 instanceof TypeError);

  var t3 = null;
  try { b.crypto.spkiPinVerifier({ pins: ["sha256/" + "A".repeat(43) + "="] }); }
  catch (e) { t3 = e; }
  check("spkiPinVerifier: refuses a single pin (RFC 7469 backup pin required)",
        t3 instanceof TypeError);

  // Two IDENTICAL pins are not a backup — the same key repeated passes a
  // length-only check but leaves the endpoint with no rotation key.
  var t3dup = null;
  try {
    var samePin = "sha256/" + "A".repeat(43) + "=";
    b.crypto.spkiPinVerifier({ pins: [samePin, samePin] });
  } catch (e) { t3dup = e; }
  check("spkiPinVerifier: refuses two duplicate pins (no distinct backup key)",
        t3dup instanceof TypeError);

  var t4 = null;
  try {
    b.crypto.spkiPinVerifier({ pins: ["not-a-pin", "sha256/" + "A".repeat(43) + "="] });
  } catch (e) { t4 = e; }
  check("spkiPinVerifier: refuses a pin missing the 'sha256/' prefix",
        t4 instanceof TypeError);
}

function run() {
  testSpkiPinShape();
  testSpkiPinKnownAnswer();
  testSpkiPinPemDerAgreement();
  testSpkiPinBadInput();
  testVerifierMatchingCert();
  testVerifierNonMatchingPin();
  testVerifierHostnameMismatchWinsOverPin();
  testVerifierHostnameOptOverride();
  testVerifierBadOpts();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[crypto-spki-pin] OK"); }
  catch (e) { console.error(e); process.exit(1); }
}
