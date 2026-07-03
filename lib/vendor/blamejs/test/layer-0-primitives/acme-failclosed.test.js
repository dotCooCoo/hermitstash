// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
/**
 * b.acme — fail-closed / wire-format correctness for the signed-POST
 * surface that the offline coverage tests can't reach.
 *
 * Drives the RFC 8555 §7.3.5 account-key rollover through the public
 * b.acme consumer path with the HTTP transport stubbed, then decodes
 * the inner keyChange JWS the CA would receive and asserts its payload
 * base64url-decodes to the keyChange OBJECT — not a double-encoded JSON
 * string. A double-encoded inner payload is rejected by every RFC 8555
 * server (the JWS body is a JSON string, not the { account, oldKey }
 * object the spec requires), so rollover always fails on a live CA.
 */

"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var nodeCrypto = require("node:crypto");
var httpClient = require("../../lib/http-client");

function _newKey() {
  return nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
}

var CA = "https://ca.example.test";
var DIR = {
  newNonce:   CA + "/acme/new-nonce",
  newAccount: CA + "/acme/new-account",
  newOrder:   CA + "/acme/new-order",
  keyChange:  CA + "/acme/key-change",
};

// Base64url-decode + JSON.parse one JWS member.
function _decodeB64uJson(b64u) {
  return JSON.parse(Buffer.from(b64u, "base64url").toString("utf8"));
}

// ---- accountKeyRollover: inner keyChange JWS payload wire format ----

async function testRolloverInnerPayloadIsObjectNotDoubleEncoded() {
  var original = httpClient.request;
  var nonceSeq = 0;
  var captured = { keyChangeBody: null };

  httpClient.request = function (req) {
    var headers = { "replay-nonce": "nonce-" + (nonceSeq += 1) };
    var url = req.url;
    var method = req.method;
    if (method === "GET" && /\/directory$/.test(url)) {
      return Promise.resolve({ statusCode: 200, headers: headers, body: JSON.stringify(DIR) });
    }
    if (method === "HEAD") {
      return Promise.resolve({ statusCode: 200, headers: headers, body: "" });
    }
    if (method === "POST" && /\/new-account$/.test(url)) {
      headers.location = CA + "/acme/acct/1";
      return Promise.resolve({ statusCode: 201, headers: headers, body: JSON.stringify({ status: "valid" }) });
    }
    if (method === "POST" && /\/key-change$/.test(url)) {
      captured.keyChangeBody = req.body;
      return Promise.resolve({ statusCode: 200, headers: headers, body: "{}" });
    }
    return Promise.resolve({ statusCode: 404, headers: headers, body: "" });
  };

  try {
    var oldKey = _newKey();
    var acme = b.acme.create({
      directory:  CA + "/directory",
      accountKey: oldKey.privateKey,
    });
    var oldPublicJwk = acme.publicJwk();
    await acme.newAccount();

    var newKey = _newKey();
    var ok = await acme.accountKeyRollover(newKey.privateKey);
    check("accountKeyRollover resolves true when the CA accepts", ok === true);
    check("keyChange POST body was captured", typeof captured.keyChangeBody === "string");

    // Outer JWS body → its payload decodes to the inner JWS object.
    var outerJws = JSON.parse(captured.keyChangeBody);
    var innerJws = _decodeB64uJson(outerJws.payload);
    check("inner keyChange JWS carries protected/payload/signature",
          innerJws && typeof innerJws.protected === "string" &&
          typeof innerJws.payload === "string" && typeof innerJws.signature === "string");

    // The crux: the inner JWS payload MUST base64url-decode to the
    // keyChange OBJECT, not a JSON string of that object. A double
    // _stringify() yields a quoted JSON string here → JSON.parse gives
    // a `string`, which every RFC 8555 server rejects.
    var innerPayload = _decodeB64uJson(innerJws.payload);
    check("inner keyChange payload decodes to an OBJECT (not a double-encoded JSON string)",
          innerPayload !== null && typeof innerPayload === "object" && !Array.isArray(innerPayload));
    check("inner keyChange payload.account is the account URL (RFC 8555 §7.3.5)",
          innerPayload && innerPayload.account === CA + "/acme/acct/1");
    check("inner keyChange payload.oldKey is the old public JWK object",
          innerPayload && innerPayload.oldKey && innerPayload.oldKey.kty === "EC" &&
          innerPayload.oldKey.crv === oldPublicJwk.crv &&
          innerPayload.oldKey.x === oldPublicJwk.x &&
          innerPayload.oldKey.y === oldPublicJwk.y);

    // Belt-and-suspenders: the inner protected header commits the new
    // public JWK (the key being rotated to) — the sibling wire member.
    var innerProtected = _decodeB64uJson(innerJws.protected);
    check("inner keyChange protected header binds the new public JWK",
          innerProtected && innerProtected.jwk && innerProtected.jwk.kty === "EC" &&
          innerProtected.url === DIR.keyChange);
  } finally {
    httpClient.request = original;
  }
}

async function run() {
  await testRolloverInnerPayloadIsObjectNotDoubleEncoded();
}

module.exports = { run: run };

// Allow direct execution: `node test/layer-0-primitives/acme-failclosed.test.js`
if (require.main === module) {
  run().then(function () {
    console.log("OK — acme-failclosed " + helpers.getChecks() + " checks passed");
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exit(1);
  });
}
