// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.selfUpdate.standaloneVerifier — zero-dep companion to b.selfUpdate.verify
 * for install-pipeline contexts that run BEFORE the framework is installed.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var fs      = require("node:fs");
var os      = require("node:os");
var path    = require("node:path");
var nc      = require("node:crypto");

function _scratch(label) {
  var d = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-sv-" + label + "-"));
  return d;
}

function _writeAsset(dir, name, data) {
  var p = path.join(dir, name);
  fs.writeFileSync(p, data);
  return p;
}

function testSurface() {
  var sv = b.selfUpdate.standaloneVerifier;
  check("standaloneVerifier.verify is fn",   typeof sv.verify === "function");
  check("standaloneVerifier.path is string", typeof sv.path === "string");
  check("standaloneVerifier.path exists",    fs.existsSync(sv.path));
  check("standaloneVerifier.path ends in .js",
        sv.path.endsWith("self-update-standalone-verifier.js"));
}

function testEcdsaP384IeeeP1363() {
  var dir = _scratch("ecdsa-iee");
  try {
    var kp = nc.generateKeyPairSync("ec", { namedCurve: "P-384" });
    var pub = kp.publicKey.export({ type: "spki", format: "pem" });
    var asset = _writeAsset(dir, "asset", Buffer.from("blamejs v0.9.13 ecdsa ieee-p1363"));
    var sig = nc.createSign("sha3-512");
    sig.update(fs.readFileSync(asset));
    var sigBytes = sig.sign({ key: kp.privateKey, dsaEncoding: "ieee-p1363" });
    var sigPath = _writeAsset(dir, "asset.sig", sigBytes);
    var r = b.selfUpdate.standaloneVerifier.verify(asset, sigPath, pub);
    check("ECDSA P-384 IEEE-P1363: ok",                  r.ok === true);
    check("ECDSA P-384 IEEE-P1363: alg detected",        r.alg === "ecdsa-p384");
    check("ECDSA P-384 IEEE-P1363: sha3_512 hex emitted", typeof r.sha3_512 === "string" && r.sha3_512.length === 128);
    check("ECDSA P-384 IEEE-P1363: sha256 hex emitted",   typeof r.sha256 === "string" && r.sha256.length === 64);
    check("ECDSA P-384 IEEE-P1363: 96-byte sig",          sigBytes.length === 96);
  } finally {
    fs.rmSync(dir, { recursive: true });
  }
}

function testEcdsaP384Der() {
  var dir = _scratch("ecdsa-der");
  try {
    var kp = nc.generateKeyPairSync("ec", { namedCurve: "P-384" });
    var pub = kp.publicKey.export({ type: "spki", format: "pem" });
    var asset = _writeAsset(dir, "asset", Buffer.from("blamejs v0.9.13 ecdsa der"));
    var sig = nc.createSign("sha3-512");
    sig.update(fs.readFileSync(asset));
    var sigBytes = sig.sign(kp.privateKey);   // default DER encoding
    var sigPath = _writeAsset(dir, "asset.sig", sigBytes);
    var r = b.selfUpdate.standaloneVerifier.verify(asset, sigPath, pub);
    check("ECDSA P-384 DER: ok",                  r.ok === true);
    check("ECDSA P-384 DER: alg detected",        r.alg === "ecdsa-p384");
    check("ECDSA P-384 DER: sig length != 96",    sigBytes.length !== 96);
  } finally {
    fs.rmSync(dir, { recursive: true });
  }
}

function testEd25519() {
  var dir = _scratch("ed25519");
  try {
    var kp = nc.generateKeyPairSync("ed25519");
    var pub = kp.publicKey.export({ type: "spki", format: "pem" });
    var asset = _writeAsset(dir, "asset", Buffer.from("blamejs v0.9.13 ed25519 stream"));
    var sigBytes = nc.sign(null, fs.readFileSync(asset), kp.privateKey);
    var sigPath = _writeAsset(dir, "asset.sig", sigBytes);
    var r = b.selfUpdate.standaloneVerifier.verify(asset, sigPath, pub);
    check("Ed25519: ok",            r.ok === true);
    check("Ed25519: alg detected",  r.alg === "ed25519");
  } finally {
    fs.rmSync(dir, { recursive: true });
  }
}

function testTamperDetected() {
  var dir = _scratch("tamper");
  try {
    var kp = nc.generateKeyPairSync("ec", { namedCurve: "P-384" });
    var pub = kp.publicKey.export({ type: "spki", format: "pem" });
    var asset = _writeAsset(dir, "asset", Buffer.from("original content"));
    var sig = nc.createSign("sha3-512");
    sig.update(fs.readFileSync(asset));
    var sigPath = _writeAsset(dir, "asset.sig",
                              sig.sign({ key: kp.privateKey, dsaEncoding: "ieee-p1363" }));

    // Flip a byte in the asset
    fs.appendFileSync(asset, "!");

    var threw = null;
    try { b.selfUpdate.standaloneVerifier.verify(asset, sigPath, pub); }
    catch (e) { threw = e; }
    check("tamper: throws on signature mismatch",
          threw && /signature INVALID/.test(threw.message));
    check("tamper: error names the sha3-512 prefix for forensics",
          threw && /sha3-512=[0-9a-f]{16}/.test(threw.message));
  } finally {
    fs.rmSync(dir, { recursive: true });
  }
}

function testRefusesUnsupportedKey() {
  var dir = _scratch("badkey");
  try {
    var asset = _writeAsset(dir, "asset", Buffer.from("x"));
    var sigPath = _writeAsset(dir, "asset.sig", Buffer.from("x"));
    // Unsupported EC curve (P-256, not P-384)
    var kp = nc.generateKeyPairSync("ec", { namedCurve: "P-256" });
    var pub = kp.publicKey.export({ type: "spki", format: "pem" });
    var threw = null;
    try { b.selfUpdate.standaloneVerifier.verify(asset, sigPath, pub); }
    catch (e) { threw = e; }
    check("unsupported curve: refused",
          threw && /unsupported EC curve/.test(threw.message));
  } finally {
    fs.rmSync(dir, { recursive: true });
  }
}

function testRefusesBadInput() {
  var threw1 = null;
  try { b.selfUpdate.standaloneVerifier.verify("", "/x", "-----BEGIN PUBLIC KEY-----\n"); }
  catch (e) { threw1 = e; }
  check("bad input: empty assetPath refused", threw1 && /assetPath/.test(threw1.message));

  var threw2 = null;
  try { b.selfUpdate.standaloneVerifier.verify("/nonexistent", "/x", "-----BEGIN PUBLIC KEY-----\n"); }
  catch (e) { threw2 = e; }
  check("bad input: missing asset refused", threw2 && /asset not found/.test(threw2.message));

  var threw3 = null;
  try { b.selfUpdate.standaloneVerifier.verify("/x", "/y", "not a pem"); }
  catch (e) { threw3 = e; }
  check("bad input: non-PEM pubkey refused", threw3 && /PEM/.test(threw3.message));
}

async function run() {
  testSurface();
  testEcdsaP384IeeeP1363();
  testEcdsaP384Der();
  testEd25519();
  testTamperDetected();
  testRefusesUnsupportedKey();
  testRefusesBadInput();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
