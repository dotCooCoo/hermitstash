"use strict";
/**
 * b.a2a — A2A signed agent-card primitive.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  check("a2a.createCard is fn",  typeof b.a2a.createCard === "function");
  check("a2a.signCard is fn",    typeof b.a2a.signCard === "function");
  check("a2a.verifyCard is fn",  typeof b.a2a.verifyCard === "function");
  check("a2a.canonicalize is fn", typeof b.a2a.canonicalize === "function");

  var kp = b.crypto.generateSigningKeyPair("ml-dsa-87");
  var card = b.a2a.createCard({
    issuer: "acme.example",
    agentId: "agent-001",
    capabilities: ["translate", "summarize"],
  });
  check("createCard returns object", typeof card === "object");
  check("createCard sets default version", card.version === "1.0.0");

  var env = b.a2a.signCard(card, kp.privateKey, { audit: false });
  check("signCard returns envelope", env && typeof env.signature === "string" && env.signedAt && env.expiresAt);

  var v = b.a2a.verifyCard(env, kp.publicKey, { audit: false });
  check("verifyCard valid",  v.valid === true);
  check("verifyCard claims",  v.claims && v.claims.issuer === "acme.example");

  // Tamper
  env.card.capabilities.push("exfil");
  var v2 = b.a2a.verifyCard(env, kp.publicKey, { audit: false });
  check("verifyCard tamper detected", v2.valid === false && v2.reason === "signature-mismatch");

  // Issuer mismatch
  var card2 = b.a2a.createCard({ issuer: "evil.example", agentId: "x", capabilities: [] });
  var env2  = b.a2a.signCard(card2, kp.privateKey, { audit: false });
  var v3    = b.a2a.verifyCard(env2, kp.publicKey, { expectedIssuer: "acme.example", audit: false });
  check("verifyCard issuer mismatch", v3.valid === false && v3.reason === "issuer-mismatch");

  // Expired
  var env3 = b.a2a.signCard(b.a2a.createCard({ issuer: "x", agentId: "y", capabilities: [] }),
    kp.privateKey, { audit: false, ttlMs: 1 });
  var v4 = await helpers.waitUntil(function () {
    var v = b.a2a.verifyCard(env3, kp.publicKey, { clockSkewMs: 0, audit: false });
    if (!v.valid && v.reason === "expired") return v;
    return false;
  }, { label: "a2a card TTL expiration" });
  check("verifyCard expired", v4.valid === false && v4.reason === "expired");

  // Bad shape
  var threw = null;
  try { b.a2a.createCard({ issuer: "x" }); } catch (e) { threw = e; }
  check("createCard refuses incomplete card", threw && threw.code === "a2a/missing-field");
}

module.exports = { run: run };
