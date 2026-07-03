// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.ai.aiContentDetect + b.contentCredentials.cacImplicitLabel.
 *
 * Run standalone: `node test/layer-0-primitives/ai-content-detect.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

function testCacImplicitLabelRoundTrip() {
  var label = b.contentCredentials.cacImplicitLabel({
    providerName: "Example AI",
    providerCode: "91110000600037341A",
    contentId:    "asset-2026-05-17-abc123",
    contentKind:  "image",
    generatedAt:  "2026-05-17T20:00:00Z",
  });
  check("aigcMarker = AIGC",         label.aigcMarker === "AIGC");
  check("providerName preserved",    label.providerName === "Example AI");
  check("contentKind preserved",     label.contentKind === "image");

  var parsed = b.contentCredentials.cacImplicitLabelRead(JSON.stringify(label));
  check("round-trip via JSON",       parsed.contentId === label.contentId);
  check("USCC preserved",            parsed.providerCode === label.providerCode);
}

function testCacImplicitLabelRefusals() {
  var bad;

  bad = false;
  try { b.contentCredentials.cacImplicitLabel({}); } catch (_e) { bad = true; }
  check("empty opts throws",         bad);

  bad = false;
  try {
    b.contentCredentials.cacImplicitLabel({
      providerName: "x", providerCode: "TOO_SHORT", contentId: "a",
      contentKind: "image", generatedAt: "2026-05-17T20:00:00Z",
    });
  } catch (_e) { bad = true; }
  check("bad USCC throws",           bad);

  bad = false;
  try {
    b.contentCredentials.cacImplicitLabel({
      providerName: "x", providerCode: "91110000600037341A", contentId: "a",
      contentKind: "stylesheet", generatedAt: "2026-05-17T20:00:00Z",
    });
  } catch (_e) { bad = true; }
  check("bad contentKind throws",    bad);

  bad = false;
  try {
    b.contentCredentials.cacImplicitLabel({
      providerName: "x", providerCode: "91110000600037341A", contentId: "a",
      contentKind: "image", generatedAt: "yesterday",
    });
  } catch (_e) { bad = true; }
  check("bad generatedAt throws",    bad);
}

function testAiContentDetectComplianceCascade() {
  check("ca-ab-853 -> strict",
    b.ai.aiContentDetect.compliancePosture("ca-ab-853") === "strict");
  check("eu-ai-act-art-50 -> strict",
    b.ai.aiContentDetect.compliancePosture("eu-ai-act-art-50") === "strict");
  check("unknown -> null",
    b.ai.aiContentDetect.compliancePosture("nonsense") === null);
}

function testAiContentDetectNoProvenance() {
  // Balanced profile permits an empty report.
  var rep = b.ai.aiContentDetect.report({});
  check("kind = none",               rep.kind === "none");
  check("verified false",            rep.verified === false);
  check("alerts include no-provenance",
    rep.alerts.indexOf("no-provenance") !== -1);

  // Strict profile refuses outright.
  var threw = false;
  try { b.ai.aiContentDetect.report({ profile: "strict" }); }
  catch (_e) { threw = true; }
  check("strict refuses on no-provenance", threw);
}

function testAiContentDetectC2PA() {
  var pair = b.crypto.generateSigningKeyPair("ml-dsa-87");
  var manifest = b.contentCredentials.build({
    provider:      "Acme AI Inc.",
    system:        "acme-image-v3",
    systemVersion: "3.2.1",
    contentId:     "img-001",
  });
  var envelope = b.contentCredentials.sign(manifest, {
    privateKeyPem: pair.privateKey, audit: false,
  });

  // Balanced + empty trust list — verify succeeds but trust-list-empty
  // alert surfaces so operators see the gap.
  var rep = b.ai.aiContentDetect.report({
    c2paEnvelope:     envelope,
    c2paPublicKeyPem: pair.publicKey,
  });
  check("c2pa kind detected",         rep.kind === "c2pa");
  check("verified true",              rep.verified === true);
  check("trust-list-empty alert",
    rep.alerts.indexOf("trust-list-empty") !== -1);

  // Strict mode + tampered envelope — verify fails, MUST throw rather
  // than return an alert object. The advertised fail-closed contract
  // for AB-853 / EU AI Act Art. 50 posture would be silently broken
  // otherwise.
  var tampered = {
    manifest:  Object.assign({}, envelope.manifest, { provider: "Attacker" }),
    signature: envelope.signature,
  };
  var threw = false;
  try {
    b.ai.aiContentDetect.report({
      c2paEnvelope:     tampered,
      c2paPublicKeyPem: pair.publicKey,
      profile:          "strict",
      trustList:        ["CN=Acme AI Inc."],
    });
  } catch (_e) { threw = true; }
  check("strict refuses tampered C2PA", threw);

  // Strict mode + missing pubkey — must also throw, not warn.
  threw = false;
  try {
    b.ai.aiContentDetect.report({
      c2paEnvelope: envelope, profile: "strict",
    });
  } catch (_e) { threw = true; }
  check("strict refuses missing c2paPublicKeyPem", threw);
}

function run() {
  testCacImplicitLabelRoundTrip();
  testCacImplicitLabelRefusals();
  testAiContentDetectComplianceCascade();
  testAiContentDetectNoProvenance();
  testAiContentDetectC2PA();
}

if (require.main === module) run();
module.exports = { run: run };
