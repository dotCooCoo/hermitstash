"use strict";
// #135: SD-JWT-VC ES256/ES384 signatures must be JOSE-encoded (raw r||s,
// "ieee-p1363"), not node:crypto's default DER. A DER signature (ASN.1
// SEQUENCE, leading 0x30, ~70-72 bytes for P-256) is rejected by every
// conformant JOSE / EUDI-wallet verifier, and this library would likewise
// reject a conformant wallet's raw-r||s signature. The issuer JWT and the
// holder KB-JWT both sign through the core _signJwt, so the format applies
// to both.
//
// RED on the buggy tree: the issuer-JWT signature is DER (length != 64,
// first byte 0x30) and a JOSE-conformant verifier (dsaEncoding ieee-p1363)
// rejects it. GREEN after the fix: signature is exactly 64 bytes and the
// conformant verifier accepts it.

var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;
var nodeCrypto = require("node:crypto");
var sdJwtVc = b.auth.sdJwtVc;

function _b64uToBuf(s) {
  return Buffer.from(s, "base64url");
}

async function run() {
  var issuer = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });

  var sd = sdJwtVc.issue({
    issuer:  "https://issuer.example.com",
    subject: "did:web:alice",
    vct:     "https://example.com/vct/identity",
    claims:  { given_name: "Alice", country: "US" },
    selectivelyDisclosed: ["given_name"],
    issuerKey: issuer.privateKey,
    algorithm: "ES256",
  });

  // An SD-JWT serializes as <issuerJWT>~<disclosure>~…~ — strip the
  // tilde-joined disclosures to get the issuer JWT before splitting on ".".
  var issuerJwt = sd.token.split("~")[0];
  var parts = issuerJwt.split(".");
  check("issuer JWT has 3 parts", parts.length === 3);
  var signingInput = parts[0] + "." + parts[1];
  var sig = _b64uToBuf(parts[2]);

  // ES256 raw r||s is exactly 64 bytes; DER is variable (~70-72) and starts
  // with the 0x30 SEQUENCE tag.
  check("#135 ES256 signature is JOSE raw r||s (64 bytes), not DER",
        sig.length === 64);
  check("#135 ES256 signature does not carry the DER SEQUENCE tag",
        sig[0] !== 0x30 || sig.length === 64);

  // A JOSE-conformant verifier (explicit ieee-p1363) must accept it. On the
  // buggy tree the signature is DER, so a conformant verifier rejects it.
  var conformantOk = nodeCrypto.verify(
    "sha256",
    Buffer.from(signingInput, "ascii"),
    { key: issuer.publicKey, dsaEncoding: "ieee-p1363" },
    sig);
  check("#135 a JOSE-conformant verifier (ieee-p1363) accepts the issuer JWT",
        conformantOk === true);

  // ES384 carries the same root — exercise it too (96-byte raw r||s).
  var issuer384 = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-384" });
  var sd384 = sdJwtVc.issue({
    issuer:  "https://issuer.example.com",
    subject: "did:web:carol",
    vct:     "https://example.com/vct/identity",
    claims:  { given_name: "Carol" },
    selectivelyDisclosed: ["given_name"],
    issuerKey: issuer384.privateKey,
    algorithm: "ES384",
  });
  var sig384 = _b64uToBuf(sd384.token.split("~")[0].split(".")[2]);
  check("#135 ES384 signature is JOSE raw r||s (96 bytes), not DER",
        sig384.length === 96);
}

module.exports = { run: run };
