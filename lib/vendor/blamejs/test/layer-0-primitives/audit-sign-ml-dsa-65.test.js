// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auditSign + b.webhook — FIPS 204 ML-DSA-65 opt-in.
 *
 * audit-sign: SUPPORTED_SIGNING_ALGS includes ml-dsa-65; init() with
 * algorithm:"ml-dsa-65" generates and round-trips through the keypair.
 *
 * webhook: PQC_ALGORITHMS includes ml-dsa-65; signer/verifier accept
 * the explicit pqcAlgorithm pin and refuse mismatched PEMs at config
 * time.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var nodeCrypto = require("crypto");
var fs   = require("fs");
var os   = require("os");
var path = require("path");

function _genKeyPair(alg) {
  return nodeCrypto.generateKeyPairSync(alg, {
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

function testAuditSignSurface() {
  check("audit-sign SUPPORTED_SIGNING_ALGS includes ml-dsa-65",
        b.auditSign.SUPPORTED_SIGNING_ALGS.indexOf("ml-dsa-65") !== -1);
  check("audit-sign default remains slh-dsa-shake-256f",
        b.auditSign.DEFAULT_SIGNING_ALG === "slh-dsa-shake-256f");
  check("audit-sign SUPPORTED_SIGNING_ALGS frozen",
        Object.isFrozen(b.auditSign.SUPPORTED_SIGNING_ALGS));
}

async function testAuditSignMlDsa65Init() {
  // Spin up a temp dataDir + plaintext mode (no passphrase prompt).
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-audit-sign-mldsa65-"));
  try {
    b.auditSign._resetForTest();
    await b.auditSign.init({
      dataDir:   tmp,
      mode:      "plaintext",
      algorithm: "ml-dsa-65",
    });
    check("audit-sign init algorithm=ml-dsa-65 records the alg",
          b.auditSign.getAlgorithm() === "ml-dsa-65");
    var sig = b.auditSign.sign("hello-audit");
    check("ml-dsa-65 signature is non-empty Buffer",
          Buffer.isBuffer(sig) && sig.length > 0);
    check("ml-dsa-65 signature verifies",
          b.auditSign.verify("hello-audit", sig) === true);
    check("ml-dsa-65 signature rejects tampered payload",
          b.auditSign.verify("hello-audit-TAMPER", sig) === false);
  } finally {
    b.auditSign._resetForTest();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

async function testAuditSignBadAlg() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-audit-sign-bad-"));
  try {
    b.auditSign._resetForTest();
    var threw = null;
    try {
      await b.auditSign.init({
        dataDir:   tmp,
        mode:      "plaintext",
        algorithm: "ed25519",   // not in SUPPORTED_SIGNING_ALGS
      });
    } catch (e) { threw = e; }
    check("audit-sign refuses non-PQC algorithm",
          threw && threw.code === "audit-sign/bad-algorithm");
  } finally {
    b.auditSign._resetForTest();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

function testWebhookSurface() {
  check("webhook PQC_ALGORITHMS includes ml-dsa-65",
        b.webhook.PQC_ALGORITHMS.indexOf("ml-dsa-65") !== -1);
  check("webhook PQC_ALGORITHMS includes slh-dsa-shake-256f",
        b.webhook.PQC_ALGORITHMS.indexOf("slh-dsa-shake-256f") !== -1);
  check("webhook PQC_ALGORITHMS frozen",
        Object.isFrozen(b.webhook.PQC_ALGORITHMS));
}

async function testWebhookMlDsa65Roundtrip() {
  var pair = _genKeyPair("ml-dsa-65");
  var signer = b.webhook.signer({
    algo:         "pqc-pem",
    pqcAlgorithm: "ml-dsa-65",
    keys:         { v1: { privateKey: pair.privateKey, publicKey: pair.publicKey } },
    defaultKid:   "v1",
  });
  var signed = signer.sign("hello-webhook");
  check("webhook ml-dsa-65 signer emits Webhook-Signature",
        signed.headers["Webhook-Signature"]);

  var verifier = b.webhook.verifier({
    algo:         "pqc-pem",
    pqcAlgorithm: "ml-dsa-65",
    keys:         { v1: pair.publicKey },
  });
  var info = await verifier.verify({
    body:    "hello-webhook",
    headers: signed.headers,
  });
  check("webhook ml-dsa-65 verifier accepts the signature",
        info && info.kid === "v1");
}

function testWebhookPemMismatch() {
  // Pin ml-dsa-65 but supply ml-dsa-87 PEM — config-time refusal.
  var pair87 = _genKeyPair("ml-dsa-87");
  var threw = null;
  try {
    b.webhook.signer({
      algo:         "pqc-pem",
      pqcAlgorithm: "ml-dsa-65",
      keys:         { v1: { privateKey: pair87.privateKey, publicKey: pair87.publicKey } },
      defaultKid:   "v1",
    });
  } catch (e) { threw = e; }
  check("webhook signer refuses mismatched pqcAlgorithm vs PEM",
        threw && threw.code === "BAD_OPT" &&
        /does not match PEM/.test(threw.message));
}

function testWebhookHmacRejectsPqcAlgorithm() {
  var threw = null;
  try {
    b.webhook.signer({
      algo:         "hmac-sha3-512",
      pqcAlgorithm: "ml-dsa-65",
      keys:         { v1: Buffer.alloc(32, 1) },
      defaultKid:   "v1",
    });
  } catch (e) { threw = e; }
  check("webhook refuses pqcAlgorithm with hmac-sha3-512",
        threw && threw.code === "BAD_OPT" &&
        /pqcAlgorithm only meaningful/.test(threw.message));
}

async function run() {
  testAuditSignSurface();
  await testAuditSignMlDsa65Init();
  await testAuditSignBadAlg();
  testWebhookSurface();
  await testWebhookMlDsa65Roundtrip();
  testWebhookPemMismatch();
  testWebhookHmacRejectsPqcAlgorithm();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
