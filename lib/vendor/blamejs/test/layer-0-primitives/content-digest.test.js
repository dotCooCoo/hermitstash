// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.contentDigest (RFC 9530 Digest Fields).
 * The oracle is RFC 9530 Appendix D: the body {"hello": "world"} has the
 * published SHA-256 / SHA-512 Content-Digest values reproduced here, so a
 * wrong hash, encoding, or byte handling would diverge from the RFC.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

// RFC 9530 Appendix D — body and its published digests.
var BODY = '{"hello": "world"}';
var SHA256 = "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:";
var SHA512 = "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:";
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

function testSurface() {
  check("b.contentDigest.create is a function", typeof b.contentDigest.create === "function");
  check("b.contentDigest.verify is a function", typeof b.contentDigest.verify === "function");
  check("b.contentDigest.ACTIVE_ALGORITHMS lists sha-256 + sha-512", b.contentDigest.ACTIVE_ALGORITHMS.indexOf("sha-256") !== -1 && b.contentDigest.ACTIVE_ALGORITHMS.indexOf("sha-512") !== -1);
  var threw = null; try { b.contentDigest.verify("sha-256=abc", BODY); } catch (e) { threw = e; }
  check("b.contentDigest.ContentDigestError is the thrown typed error", typeof b.contentDigest.ContentDigestError === "function" && threw instanceof b.contentDigest.ContentDigestError);
}

function testCreateRealVector() {
  check("create: SHA-256 matches RFC 9530 Appendix D", b.contentDigest.create(BODY) === SHA256);
  check("create: SHA-512 matches RFC 9530 Appendix D", b.contentDigest.create(BODY, { algorithms: ["sha-512"] }) === SHA512);
  check("create: multi-algorithm dictionary", b.contentDigest.create(BODY, { algorithms: ["sha-256", "sha-512"] }) === SHA256 + ", " + SHA512);
}

function testVerifyRealVector() {
  var out = b.contentDigest.verify(SHA256, BODY);
  check("verify: real RFC SHA-256 Content-Digest verifies", out.ok && out.verified.join() === "sha-256");
  check("verify: real RFC SHA-512 Content-Digest verifies", b.contentDigest.verify(SHA512, BODY).ok === true);
  check("verify: both digests in one field verify", b.contentDigest.verify(SHA256 + ", " + SHA512, BODY).verified.length === 2);
  check("verify: required algorithm present passes", b.contentDigest.verify(SHA256, BODY, { required: ["sha-256"] }).ok === true);
  // A Buffer body round-trips with the string body.
  check("verify: Buffer body verifies against the same digest", b.contentDigest.verify(SHA256, Buffer.from(BODY, "utf8")).ok === true);
}

function testRefusals() {
  // Tampered body fails.
  check("verify: tampered body refused", code(function () { b.contentDigest.verify(SHA256, '{"hello": "WORLD"}'); }) === "content-digest/mismatch");
  // A flipped digest byte fails.
  check("verify: wrong digest refused", code(function () { b.contentDigest.verify("sha-256=:" + "A".repeat(43) + "=:", BODY); }) === "content-digest/mismatch");
  // A legacy-only digest (md5) is not trusted.
  check("verify: legacy-only (md5) digest refused", code(function () { b.contentDigest.verify("md5=:rL0Y20zC+Fzt72VPzMSk2A==:", BODY); }) === "content-digest/no-modern-digest");
  // Required algorithm absent.
  check("verify: missing required algorithm refused", code(function () { b.contentDigest.verify(SHA256, BODY, { required: ["sha-512"] }); }) === "content-digest/missing-algorithm");
  // Malformed byte-sequence value.
  check("verify: non-byte-sequence value refused", code(function () { b.contentDigest.verify("sha-256=abc", BODY); }) === "content-digest/bad-field");
  // Non-canonical / garbage-suffixed base64 (Node's lax decoder would
  // otherwise accept these) is refused.
  var good = SHA256.slice("sha-256=:".length, -1);
  check("verify: stray characters in byte sequence refused", code(function () { b.contentDigest.verify("sha-256=:" + good.slice(0, -2) + "!!:", BODY); }) === "content-digest/bad-field");
  check("verify: non-canonical base64 padding refused", code(function () { b.contentDigest.verify("sha-256=:" + good + "==:", BODY); }) === "content-digest/bad-field");
  // create refuses insecure algorithms.
  check("create: insecure algorithm refused", code(function () { b.contentDigest.create(BODY, { algorithms: ["md5"] }); }) === "content-digest/insecure-algorithm");
  check("create: unknown algorithm refused", code(function () { b.contentDigest.create(BODY, { algorithms: ["sha3-256"] }); }) === "content-digest/unsupported-algorithm");
}

function testLegacyIgnoredWhenModernPresent() {
  // A field mixing a legacy algorithm with a valid modern one verifies on
  // the modern entry and ignores the legacy one.
  var mixed = "md5=:rL0Y20zC+Fzt72VPzMSk2A==:, " + SHA256;
  var out = b.contentDigest.verify(mixed, BODY);
  check("verify: legacy entry ignored when a modern digest is present + matches", out.ok && out.verified.join() === "sha-256");
}

async function run() {
  testSurface();
  testCreateRealVector();
  testVerifyRealVector();
  testRefusals();
  testLegacyIgnoredWhenModernPresent();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[content-digest] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
