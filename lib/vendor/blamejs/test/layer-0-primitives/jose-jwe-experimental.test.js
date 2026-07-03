// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.jose.jwe.experimental — ML-KEM-1024 + XChaCha20-Poly1305 JWE.
 *
 * Codepoints follow draft-ietf-jose-pqc-kem-05; may change before
 * IANA registration. The `x-blamejs-experimental: true` header
 * marker is part of the wire contract until graduation.
 */

var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

function testRoundTrip() {
  var pair = b.crypto.generateEncryptionKeyPair();
  var jwe = b.jose.jwe.experimental.encrypt("hello world", pair.publicKey,
    { audit: false });
  check("compact has 5 segments", jwe.split(".").length === 5);
  check("first segment is base64url", /^[A-Za-z0-9_-]+$/.test(jwe.split(".")[0]));

  var pt = b.jose.jwe.experimental.decrypt(jwe, pair.privateKey, { audit: false });
  check("plaintext round-trip", pt.toString("utf8") === "hello world");
}

function testHeaderShape() {
  var pair = b.crypto.generateEncryptionKeyPair();
  var jwe = b.jose.jwe.experimental.encrypt("data", pair.publicKey,
    { typ: "JWE+pqc", contentType: "application/json", audit: false });
  var header = JSON.parse(
    Buffer.from(jwe.split(".")[0].replace(/-/g, "+").replace(/_/g, "/") + "==", "base64").toString("utf8")
  );
  check("alg = ML-KEM-1024", header.alg === "ML-KEM-1024");
  check("enc = XC20P",        header.enc === "XC20P");
  check("experimental marker", header["x-blamejs-experimental"] === true);
  check("typ honored",         header.typ === "JWE+pqc");
  check("cty honored",         header.cty === "application/json");
}

function testRefusalsOnTamper() {
  var pair = b.crypto.generateEncryptionKeyPair();
  var jwe = b.jose.jwe.experimental.encrypt("payload", pair.publicKey,
    { audit: false });
  var parts = jwe.split(".");

  // Mismatch alg by tampering header.
  var hdr = JSON.parse(
    Buffer.from(parts[0].replace(/-/g, "+").replace(/_/g, "/") + "==", "base64").toString("utf8")
  );
  hdr.alg = "RSA-OAEP";
  var tamperedHeader = Buffer.from(JSON.stringify(hdr), "utf8").toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  var tampered = [tamperedHeader, parts[1], parts[2], parts[3], parts[4]].join(".");
  var threw = false;
  try { b.jose.jwe.experimental.decrypt(tampered, pair.privateKey, { audit: false }); }
  catch (_e) { threw = true; }
  check("alg-mismatch refused", threw);

  // Missing experimental marker.
  delete hdr.alg;
  hdr.alg = "ML-KEM-1024";
  delete hdr["x-blamejs-experimental"];
  var noMarker = Buffer.from(JSON.stringify(hdr), "utf8").toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  threw = false;
  try { b.jose.jwe.experimental.decrypt([noMarker, parts[1], parts[2], parts[3], parts[4]].join("."),
    pair.privateKey, { audit: false }); } catch (_e) { threw = true; }
  check("missing experimental marker refused", threw);

  // Wrong segment count.
  threw = false;
  try { b.jose.jwe.experimental.decrypt(parts.slice(0, 4).join("."), pair.privateKey,
    { audit: false }); } catch (_e) { threw = true; }
  check("4-segment compact refused", threw);
}

function testBinaryRoundTrip() {
  // Codex P1 v0.10.10 — decrypt MUST be lossless for binary plaintext.
  // Pre-fix b.crypto.decrypt utf8-decoded the result, corrupting 0xFF
  // into the Unicode replacement character.
  var pair = b.crypto.generateEncryptionKeyPair();
  var binary = Buffer.from([0x00, 0xff, 0x80, 0x7f, 0x01, 0xfe, 0xc0, 0x3f]);
  var jwe = b.jose.jwe.experimental.encrypt(binary, pair.publicKey, { audit: false });
  var pt = b.jose.jwe.experimental.decrypt(jwe, pair.privateKey, { audit: false });
  check("binary plaintext round-trips losslessly",
    Buffer.isBuffer(pt) && pt.equals(binary));
}

function testMalformedHeaderTyped() {
  // Codex P2 v0.10.10 — malformed base64url header MUST surface as a
  // typed JoseJweExperimentalError, not a raw TypeError from
  // b.crypto.fromBase64Url.
  var pair = b.crypto.generateEncryptionKeyPair();
  var pt = b.jose.jwe.experimental.encrypt("x", pair.publicKey, { audit: false });
  // Replace header segment with non-base64url bytes.
  var parts = pt.split(".");
  parts[0] = "!@#$%^&*";
  var tampered = parts.join(".");
  var caught = null;
  try { b.jose.jwe.experimental.decrypt(tampered, pair.privateKey, { audit: false }); }
  catch (e) { caught = e; }
  check("malformed header is typed JoseJweExperimentalError",
    caught !== null && caught.name === "JoseJweExperimentalError" &&
    /header/.test(caught.message));
}

function testErrorClassExported() {
  check("error class exported",
    typeof b.jose.jwe.experimental.JoseJweExperimentalError === "function");
}

function run() {
  testRoundTrip();
  testHeaderShape();
  testRefusalsOnTamper();
  testBinaryRoundTrip();
  testMalformedHeaderTyped();
  testErrorClassExported();
}

if (require.main === module) run();
module.exports = { run: run };
