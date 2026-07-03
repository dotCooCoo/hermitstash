// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.ai.modelManifest — CycloneDX 1.6 AIBOM emit / sign / verify.
 *
 * Run standalone: `node test/layer-0-primitives/ai-model-manifest.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

function testBuild() {
  var bom = b.ai.modelManifest.build({
    model: { name: "acme-classifier", version: "1.2.3", license: "MIT" },
    datasets: [{ name: "training-2026", type: "dataset" }],
    hyperparameters: { lr: "0.001", batchSize: "64" },
  });
  check("bomFormat is CycloneDX",         bom.bomFormat === "CycloneDX");
  check("specVersion 1.6",                bom.specVersion === "1.6");
  check("serialNumber urn:uuid:",         bom.serialNumber.indexOf("urn:uuid:") === 0);
  check("metadata.timestamp present",     typeof bom.metadata.timestamp === "string");
  check("metadata.component is model",    bom.metadata.component.type === "machine-learning-model");
  check("primary model name preserved",   bom.metadata.component.name === "acme-classifier");
  check("dataset emitted in components",  bom.components.length === 1);
  check("hyperparameter -> properties",   bom.properties.length === 2);
}

function testSignVerifyRoundTrip() {
  var pair = b.crypto.generateSigningKeyPair("ml-dsa-87");
  var bom = b.ai.modelManifest.build({ model: { name: "m", version: "1" }});
  var env = b.ai.modelManifest.sign(bom, { privateKeyPem: pair.privateKey, audit: false });
  check("envelope has bom",        env.bom === bom);
  check("signature is base64",     /^[A-Za-z0-9+/=]+$/.test(env.signature));

  var ok = b.ai.modelManifest.verify(env, pair.publicKey, { audit: false });
  check("verify valid",            ok.valid === true);
  check("verify reason null",      ok.reason === null);
}

function testVerifyRejectsTamper() {
  var pair = b.crypto.generateSigningKeyPair("ml-dsa-87");
  var bom = b.ai.modelManifest.build({ model: { name: "m", version: "1" }});
  var env = b.ai.modelManifest.sign(bom, { privateKeyPem: pair.privateKey, audit: false });
  // Tamper the BOM after signing — re-canonicalize MUST diverge.
  var tampered = {
    bom:       Object.assign({}, env.bom, { specVersion: "1.5" }),
    signature: env.signature,
  };
  var verdict = b.ai.modelManifest.verify(tampered, pair.publicKey, { audit: false });
  check("tampered BOM rejected",   verdict.valid === false);
}

function testVerifyHandlesMalformedKey() {
  var pair = b.crypto.generateSigningKeyPair("ml-dsa-87");
  var bom = b.ai.modelManifest.build({ model: { name: "m", version: "1" }});
  var env = b.ai.modelManifest.sign(bom, { privateKeyPem: pair.privateKey, audit: false });
  // Malformed but non-empty PEM. Per the documented `{ valid, reason }`
  // contract, this MUST NOT throw — caller must see a structured
  // invalid verdict.
  var threw = false;
  var verdict;
  try {
    verdict = b.ai.modelManifest.verify(env, "-----BEGIN PUBLIC KEY-----\nnot-a-real-key\n-----END PUBLIC KEY-----",
      { audit: false });
  } catch (_e) { threw = true; }
  check("malformed PEM does not throw",  threw === false);
  check("malformed PEM returns invalid", verdict && verdict.valid === false);
  check("reason names the failure",      verdict && verdict.reason === "public-key-malformed");
}

function testBuildValidation() {
  var threw;
  threw = false;
  try { b.ai.modelManifest.build({}); } catch (_e) { threw = true; }
  check("missing model throws",    threw);

  threw = false;
  try {
    b.ai.modelManifest.build({
      model: { name: "x", version: "1", "bom-ref": "has space" },
    });
  } catch (_e) { threw = true; }
  check("bad bom-ref throws",      threw);
}

function run() {
  testBuild();
  testSignVerifyRoundTrip();
  testVerifyRejectsTamper();
  testVerifyHandlesMalformedKey();
  testBuildValidation();
}

if (require.main === module) run();
module.exports = { run: run };
