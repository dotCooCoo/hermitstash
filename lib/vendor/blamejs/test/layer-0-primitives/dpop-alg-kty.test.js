// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.dpop.verify — alg/kty cross-check (alg-confusion family,
 * CVE-2026-22817 class).
 *
 * The DPoP proof embeds its own public key (header.jwk) and declares the
 * signing alg (header.alg). Every other JWS verifier in the framework calls
 * jwtExternal._assertAlgKtyMatch(alg, jwk) before handing the self-asserted
 * key to node:crypto; the DPoP verifier omitted it. A proof declaring
 * alg:"ES256" while embedding an RSA jwk must be refused with a clean
 * alg/kty mismatch — not run through node:crypto with mismatched params.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var nodeCrypto = require("crypto");

function _b64url(buf) {
  return Buffer.from(buf).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function run() {
  var rsa = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var rsaJwk = rsa.publicKey.export({ format: "jwk" });   // { kty:"RSA", n, e }

  // Hand-craft a proof: header.alg="ES256" but header.jwk is the RSA key,
  // signed (RS256) with the matching RSA private key. The embedded jwk and
  // the declared alg disagree on key type.
  var header  = { typ: "dpop+jwt", alg: "ES256", jwk: rsaJwk };
  var payload = { htm: "POST", htu: "https://api.example.com/r",
                  jti: "jti-" + rsaJwk.n.slice(0, 8), iat: Math.floor(Date.now() / 1000) };
  var signingInput = _b64url(JSON.stringify(header)) + "." + _b64url(JSON.stringify(payload));
  var sig = nodeCrypto.sign("sha256", Buffer.from(signingInput, "ascii"), rsa.privateKey);
  var proof = signingInput + "." + _b64url(sig);

  var threw = null;
  try {
    await b.auth.dpop.verify(proof, { htm: "POST", htu: "https://api.example.com/r" });
  } catch (e) { threw = e; }
  check("dpop.verify: alg/kty mismatch (ES256 alg, RSA jwk) is refused with alg-kty-mismatch",
        threw && (threw.code === "auth-jwt-external/alg-kty-mismatch" ||
                  threw.code === "auth-jwt-external/alg-crv-mismatch"));
  check("dpop.verify: it is NOT mis-reported as a plain invalid-signature",
        threw && threw.code !== "auth-dpop/invalid-signature");

  // Control: a well-formed ES256 proof (alg matches the EC jwk) still verifies.
  var ec = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var goodProof = await b.auth.dpop.buildProof({
    htm: "POST", htu: "https://api.example.com/r", privateKey: ec.privateKey,
  });
  var rv = await b.auth.dpop.verify(goodProof, { htm: "POST", htu: "https://api.example.com/r" });
  check("dpop.verify: matching ES256/EC proof still verifies", rv && rv.header.jwk.kty === "EC");

  console.log("OK — dpop alg/kty cross-check (" + helpers.getChecks() + " checks)");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
