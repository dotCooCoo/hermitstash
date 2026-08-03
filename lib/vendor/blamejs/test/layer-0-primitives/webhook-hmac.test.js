// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// b.webhookHmac — inbound verification of the timestamped-HMAC webhook scheme
// (t=<ts>,v1=<hmac>) used by Stripe, Tailscale, etc.

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
var nodeCrypto = require("node:crypto");

var SECRET = "whsec_test_secret_value_0123456789";
var BODY = JSON.stringify({ event: "ping", id: 42, nested: { k: "v" } });

function _sig(ts, body, secret, alg) {
  return nodeCrypto.createHmac(alg || "sha256", secret).update(ts + "." + body).digest("hex");
}
function _now() { return Math.floor(Date.now() / 1000); }
function _header(ts, body, secret) { return "t=" + ts + ",v1=" + _sig(ts, body, secret); }
function _threw(fn) { try { fn(); return null; } catch (e) { return e; } }

function testValidRoundtrip() {
  var ts = _now();
  var r = b.webhookHmac.verify({ header: _header(ts, BODY, SECRET), rawBody: BODY, secret: SECRET });
  check("valid signature verifies",              r.valid === true);
  check("returns the parsed timestamp (number)", r.timestamp === ts);
}

function testTamperedBodyRefused() {
  var ts = _now();
  var hdr = _header(ts, BODY, SECRET);
  var e = _threw(function () { b.webhookHmac.verify({ header: hdr, rawBody: BODY + "x", secret: SECRET }); });
  check("a tampered body is refused",             e && e.code === "webhook-hmac/bad-signature");
}

function testWrongSecretRefused() {
  var ts = _now();
  var e = _threw(function () { b.webhookHmac.verify({ header: _header(ts, BODY, SECRET), rawBody: BODY, secret: "other-secret" }); });
  check("a wrong secret is refused",              e && e.code === "webhook-hmac/bad-signature");
}

function testReplayWindow() {
  var body = BODY;
  var oldTs = _now() - 999;
  var e1 = _threw(function () { b.webhookHmac.verify({ header: _header(oldTs, body, SECRET), rawBody: body, secret: SECRET }); });
  check("a timestamp past tolerance is refused (replay)", e1 && e1.code === "webhook-hmac/timestamp-skew");
  var futureTs = _now() + 999;
  var e2 = _threw(function () { b.webhookHmac.verify({ header: _header(futureTs, body, SECRET), rawBody: body, secret: SECRET }); });
  check("a far-future timestamp is refused",      e2 && e2.code === "webhook-hmac/timestamp-skew");
  // A tight custom tolerance refuses a slightly-old but otherwise-valid signature.
  var nearOld = _now() - 120;
  var e3 = _threw(function () { b.webhookHmac.verify({ header: _header(nearOld, body, SECRET), rawBody: body, secret: SECRET, toleranceSec: 30 }); });
  check("a tighter toleranceSec refuses an older ts", e3 && e3.code === "webhook-hmac/timestamp-skew");
  // The same signature verifies under a looser tolerance.
  var r = b.webhookHmac.verify({ header: _header(nearOld, body, SECRET), rawBody: body, secret: SECRET, toleranceSec: 600 });
  check("a looser toleranceSec accepts the same ts", r.valid === true);
}

function testKeyRotationMultiSignature() {
  var ts = _now();
  // A rotated secret presents two v1 signatures; only the second is valid.
  var hdr = "t=" + ts + ",v1=" + "deadbeef".repeat(8) + ",v1=" + _sig(ts, BODY, SECRET);
  var r = b.webhookHmac.verify({ header: hdr, rawBody: BODY, secret: SECRET });
  check("a rotated (multi-v1) header verifies if ANY v1 matches", r.valid === true);
  // Order-independent: valid signature first.
  var hdr2 = "t=" + ts + ",v1=" + _sig(ts, BODY, SECRET) + ",v1=" + "cafe".repeat(16);
  check("multi-v1 verifies regardless of order", b.webhookHmac.verify({ header: hdr2, rawBody: BODY, secret: SECRET }).valid === true);
  // ALL wrong → refused.
  var hdrBad = "t=" + ts + ",v1=" + "0".repeat(64) + ",v1=" + "1".repeat(64);
  var e = _threw(function () { b.webhookHmac.verify({ header: hdrBad, rawBody: BODY, secret: SECRET }); });
  check("multi-v1 with no matching signature is refused", e && e.code === "webhook-hmac/bad-signature");
}

function testUnknownVersionsIgnored() {
  var ts = _now();
  // Unknown v0=/v2= schemes are ignored; the good v1 still verifies.
  var hdr = "t=" + ts + ",v0=" + "aa".repeat(20) + ",v2=" + "bb".repeat(20) + ",v1=" + _sig(ts, BODY, SECRET);
  check("unrecognized signature versions are ignored", b.webhookHmac.verify({ header: hdr, rawBody: BODY, secret: SECRET }).valid === true);
  // A header item with no '=' is skipped; a valid v1 still verifies.
  var withJunk = "t=" + ts + ",junk-no-equals,v1=" + _sig(ts, BODY, SECRET);
  check("header items without '=' are skipped (a valid v1 still verifies)",
    b.webhookHmac.verify({ header: withJunk, rawBody: BODY, secret: SECRET }).valid === true);
}

function testMalformedHeaderRefused() {
  var ts = _now();
  var noTs = _threw(function () { b.webhookHmac.verify({ header: "v1=" + _sig(ts, BODY, SECRET), rawBody: BODY, secret: SECRET }); });
  check("a header with no t= is refused",         noTs && noTs.code === "webhook-hmac/missing-timestamp");
  var noSig = _threw(function () { b.webhookHmac.verify({ header: "t=" + ts, rawBody: BODY, secret: SECRET }); });
  check("a header with no v1= is refused",         noSig && noSig.code === "webhook-hmac/missing-signature");
  var badTs = _threw(function () { b.webhookHmac.verify({ header: "t=not-a-number,v1=" + "0".repeat(64), rawBody: BODY, secret: SECRET }); });
  check("a non-integer timestamp is refused",      badTs && badTs.code === "webhook-hmac/bad-timestamp");
  var floatTs = _threw(function () { b.webhookHmac.verify({ header: "t=12.5,v1=" + "0".repeat(64), rawBody: BODY, secret: SECRET }); });
  check("a fractional timestamp is refused",       floatTs && floatTs.code === "webhook-hmac/bad-timestamp");
}

function testBufferInputs() {
  var ts = _now();
  var bodyBuf = Buffer.from(BODY, "utf8");
  var secretBuf = Buffer.from(SECRET, "utf8");
  var hdr = "t=" + ts + ",v1=" + nodeCrypto.createHmac("sha256", secretBuf).update(ts + "." + BODY).digest("hex");
  check("a Buffer rawBody + Buffer secret verify", b.webhookHmac.verify({ header: hdr, rawBody: bodyBuf, secret: secretBuf }).valid === true);
  // A non-UTF8 body (bytes an invalid-UTF8 JSON layer would corrupt) verifies byte-exact.
  var rawBytes = Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0xff, 0x7d]); // {"x":\xff}
  var hdr2 = "t=" + ts + ",v1=" + nodeCrypto.createHmac("sha256", secretBuf).update(Buffer.concat([Buffer.from(ts + ".", "utf8"), rawBytes])).digest("hex");
  check("a non-UTF8 raw body verifies byte-exact", b.webhookHmac.verify({ header: hdr2, rawBody: rawBytes, secret: secretBuf }).valid === true);
}

function testConfigurableFieldsAndProfiles() {
  var ts = _now();
  // Custom field names (a Slack-ish "ts"/"sig" single header).
  var hdr = "ts=" + ts + ",sig=" + _sig(ts, BODY, SECRET);
  check("custom tsField/sigField verify",         b.webhookHmac.verify({ header: hdr, rawBody: BODY, secret: SECRET, tsField: "ts", sigField: "sig" }).valid === true);
  // Profiles resolve to the Stripe defaults.
  check("profile 'stripe' verifies",              b.webhookHmac.verify({ header: _header(ts, BODY, SECRET), rawBody: BODY, secret: SECRET, profile: "stripe" }).valid === true);
  check("profile 'tailscale' verifies",           b.webhookHmac.verify({ header: _header(ts, BODY, SECRET), rawBody: BODY, secret: SECRET, profile: "tailscale" }).valid === true);
  var badProf = _threw(function () { b.webhookHmac.verify({ header: _header(ts, BODY, SECRET), rawBody: BODY, secret: SECRET, profile: "nope" }); });
  check("an unknown profile is refused",           badProf && badProf.code === "webhook-hmac/bad-profile");
}

function testAlgorithms() {
  var ts = _now();
  var hdr512 = "t=" + ts + ",v1=" + _sig(ts, BODY, SECRET, "sha512");
  check("alg hmac-sha512 verifies",               b.webhookHmac.verify({ header: hdr512, rawBody: BODY, secret: SECRET, alg: "hmac-sha512" }).valid === true);
  // sha512 digest presented to the default sha256 verifier → no match.
  var e = _threw(function () { b.webhookHmac.verify({ header: hdr512, rawBody: BODY, secret: SECRET }); });
  check("a sha512 digest is refused under sha256", e && e.code === "webhook-hmac/bad-signature");
  var badAlg = _threw(function () { b.webhookHmac.verify({ header: _header(ts, BODY, SECRET), rawBody: BODY, secret: SECRET, alg: "hmac-sha1" }); });
  check("a weak/unsupported alg is refused",       badAlg && badAlg.code === "webhook-hmac/bad-alg");
}

function testConfigTimeValidation() {
  var ts = _now();
  var hdr = _header(ts, BODY, SECRET);
  check("non-object opts throw",                   _threw(function () { b.webhookHmac.verify(null); }) !== null);
  check("an unknown opt key is refused",           _threw(function () { b.webhookHmac.verify({ header: hdr, rawBody: BODY, secret: SECRET, bogus: 1 }); }) !== null);
  check("a missing/empty secret is refused",       _threw(function () { b.webhookHmac.verify({ header: hdr, rawBody: BODY, secret: "" }); }).code === "webhook-hmac/bad-secret");
  check("a missing header is refused",             _threw(function () { b.webhookHmac.verify({ header: "", rawBody: BODY, secret: SECRET }); }).code === "webhook-hmac/bad-header");
  check("a non-Buffer/string rawBody is refused",  _threw(function () { b.webhookHmac.verify({ header: hdr, rawBody: 12345, secret: SECRET }); }).code === "webhook-hmac/bad-body");
  check("a bad toleranceSec is refused",           _threw(function () { b.webhookHmac.verify({ header: hdr, rawBody: BODY, secret: SECRET, toleranceSec: -5 }); }).code === "webhook-hmac/bad-tolerance");
}

function testErrorClass() {
  var e = _threw(function () { b.webhookHmac.verify({ header: "t=1,v1=" + "0".repeat(64), rawBody: BODY, secret: SECRET }); });
  check("errors are WebhookHmacError instances",  e instanceof b.webhookHmac.WebhookHmacError);
  check("verification errors are permanent",      e && e.permanent === true);
}

function run() {
  testValidRoundtrip();
  testTamperedBodyRefused();
  testWrongSecretRefused();
  testReplayWindow();
  testKeyRotationMultiSignature();
  testUnknownVersionsIgnored();
  testMalformedHeaderRefused();
  testBufferInputs();
  testConfigurableFieldsAndProfiles();
  testAlgorithms();
  testConfigTimeValidation();
  testErrorClass();
}

if (require.main === module) {
  try { run(); }
  catch (e) { console.error(e); process.exit(1); }
}
module.exports = { run: run };
