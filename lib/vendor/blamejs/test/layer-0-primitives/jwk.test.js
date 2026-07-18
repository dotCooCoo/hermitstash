// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.jwk (RFC 7638 thumbprint).
 * Oracle: the RFC 7638 §3.1 worked example (an RSA key whose SHA-256
 * thumbprint is "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"), plus
 * canonicalization + per-kty + composition (DPoP / DBSC delegate here).
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

// RFC 7638 §3.1 example key (with extra members that must be ignored).
var RFC_RSA = {
  kty: "RSA",
  n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
  e: "AQAB", alg: "RS256", kid: "2011-04-29", use: "sig",
};
var RFC_THUMB = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

function testSurface() {
  check("b.jwk.thumbprint is a function", typeof b.jwk.thumbprint === "function");
  check("b.jwk.canonicalize is a function", typeof b.jwk.canonicalize === "function");
  check("b.jwk.JwkError is a class", typeof b.jwk.JwkError === "function");
}

function testRfc7638() {
  check("RFC 7638 §3.1 thumbprint matches", b.jwk.thumbprint(RFC_RSA) === RFC_THUMB);
  check("optional members are ignored", b.jwk.thumbprint({ kty: "RSA", n: RFC_RSA.n, e: "AQAB" }) === RFC_THUMB);
  check("canonical JSON is lexicographic + minimal", b.jwk.canonicalize(RFC_RSA) === '{"e":"AQAB","kty":"RSA","n":"' + RFC_RSA.n + '"}');
}

function testKtys() {
  // EC required members are crv, kty, x, y (lexicographic).
  check("EC canonical", b.jwk.canonicalize({ kty: "EC", crv: "P-256", x: "X", y: "Y", d: "secret" }) === '{"crv":"P-256","kty":"EC","x":"X","y":"Y"}');
  check("OKP canonical (RFC 8037)", b.jwk.canonicalize({ kty: "OKP", crv: "Ed25519", x: "X" }) === '{"crv":"Ed25519","kty":"OKP","x":"X"}');
  check("oct canonical", b.jwk.canonicalize({ kty: "oct", k: "GawgguFyGrWKav7AX4VKUg" }) === '{"k":"GawgguFyGrWKav7AX4VKUg","kty":"oct"}');
  check("AKP canonical (PQC)", b.jwk.canonicalize({ kty: "AKP", alg: "ML-DSA-87", pub: "UFVC" }) === '{"alg":"ML-DSA-87","kty":"AKP","pub":"UFVC"}');
  check("different keys → different thumbprints", b.jwk.thumbprint({ kty: "oct", k: "AAAA" }) !== b.jwk.thumbprint({ kty: "oct", k: "BBBB" }));
}

function testHashOption() {
  check("sha384 differs from sha256", b.jwk.thumbprint(RFC_RSA, { hash: "sha384" }) !== RFC_THUMB);
  check("sha512 is a string", typeof b.jwk.thumbprint(RFC_RSA, { hash: "sha512" }) === "string");
  check("bad hash throws", code(function () { b.jwk.thumbprint(RFC_RSA, { hash: "md5" }); }) === "jwk/bad-hash");
}

function testErrors() {
  check("missing kty throws", code(function () { b.jwk.thumbprint({ n: "x", e: "y" }); }) === "jwk/bad-jwk");
  check("unsupported kty throws", code(function () { b.jwk.thumbprint({ kty: "XYZ" }); }) === "jwk/unsupported-kty");
  check("missing required member throws", code(function () { b.jwk.thumbprint({ kty: "EC", crv: "P-256", x: "X" }); }) === "jwk/bad-jwk");
  check("non-object throws", code(function () { b.jwk.thumbprint("nope"); }) === "jwk/bad-jwk");
}

function testUnsupportedKtyPrototypeNames() {
  // An attacker-controlled `kty` that names an Object.prototype member
  // (`__proto__`, `toString`, `valueOf`, `toLocaleString`, `constructor`,
  // `hasOwnProperty`) must be refused as an unsupported key type — the
  // required-member table is a plain-object lookup, so an inherited member
  // name must NOT be treated as a supported kty. Left unguarded, the
  // zero-`length`-prototype names (`__proto__` / `toString` / `valueOf` /
  // `toLocaleString`) silently thumbprint the empty object, collapsing four
  // distinct inputs onto base64url(SHA-256("{}")) — a shared, predictable
  // thumbprint that breaks RFC 7638's "distinct keys → distinct identifiers"
  // contract behind DPoP jkt / ACME account-key / DBSC session pins.
  var protoNames = ["__proto__", "toString", "valueOf", "toLocaleString",
                    "constructor", "hasOwnProperty", "isPrototypeOf"];
  var emptyObjThumb = b.jwk.thumbprint({ kty: "oct", k: "AA" });
  void emptyObjThumb;
  for (var i = 0; i < protoNames.length; i++) {
    var kty = protoNames[i];
    check("canonicalize refuses prototype-named kty `" + kty + "`",
          code(function () { b.jwk.canonicalize({ kty: kty }); }) === "jwk/unsupported-kty");
    check("thumbprint refuses prototype-named kty `" + kty + "`",
          code(function () { b.jwk.thumbprint({ kty: kty }); }) === "jwk/unsupported-kty");
  }
}

function testHashOptionPrototypeNames() {
  // Sibling root: the `hash` option indexes the HASHES lookup table by a
  // caller-controlled key. A prototype-member name (`toString`, `valueOf`,
  // `constructor`, `__proto__`) must surface the typed `jwk/bad-hash`
  // refusal — not leak a raw Node ERR_INVALID_ARG_TYPE from createHash when
  // the inherited member (a function/object, truthy) slips past the `!hash`
  // guard.
  var badHashes = ["toString", "valueOf", "constructor", "__proto__", "hasOwnProperty"];
  for (var i = 0; i < badHashes.length; i++) {
    var h = badHashes[i];
    check("thumbprint refuses prototype-named hash `" + h + "` with jwk/bad-hash",
          code(function () { b.jwk.thumbprint(RFC_RSA, { hash: h }); }) === "jwk/bad-hash");
  }
}

function testComposition() {
  // DPoP and DBSC compute their thumbprints through b.jwk.
  var ec = { kty: "EC", crv: "P-256", x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0" };
  check("dpop.thumbprint composes b.jwk", b.auth.dpop.thumbprint(ec) === b.jwk.thumbprint(ec));
  check("dpop refuses symmetric kty", code(function () { b.auth.dpop.thumbprint({ kty: "oct", k: "x" }); }) === "auth-dpop/refused-kty");
}

async function run() {
  testSurface();
  testRfc7638();
  testKtys();
  testHashOption();
  testErrors();
  testUnsupportedKtyPrototypeNames();
  testHashOptionPrototypeNames();
  testComposition();
}
module.exports = { run: run };
if (require.main === module) { run().then(function () { console.log("[jwk] OK — " + helpers.getChecks() + " checks passed"); }, function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }); }
