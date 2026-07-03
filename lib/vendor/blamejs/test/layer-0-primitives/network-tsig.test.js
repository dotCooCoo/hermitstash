// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.network.dns.tsig (RFC 8945).
 * Oracle: dnspython 2.8.0 — reference TSIG-signed DNS messages. The signed
 * wire + MAC for a fixed key / message / time are frozen below; `sign`
 * must reproduce them byte-for-byte and `verify` must accept them.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
var tsig = b.network.dns.tsig;
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
function hex(s) { return Buffer.from(s, "hex"); }

// dnspython keyring secret = base64("0123456789abcdef0123456789abcdef").
var SECRET = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
var KEY = "test.key.";

// Vector 1 — HMAC-SHA256, fudge 300, time_signed 1779813293.
var V1 = {
  unsigned: hex("123401000001000000000000076578616d706c6503636f6d0000010001"),
  signed:   hex("123401000001000000000001076578616d706c6503636f6d00000100010474657374036b65790000fa00ff00000000003d0b686d61632d7368613235360000006a15cbad012c0020f8edb5dfdb6717c4bf6a3e50d9883be981ec862458101432ff7fe9348b127dcd123400000000"),
  mac:      "f8edb5dfdb6717c4bf6a3e50d9883be981ec862458101432ff7fe9348b127dcd",
  time: 1779813293, fudge: 300, alg: "hmac-sha256",
};
// Vector 2 — HMAC-SHA512, fudge 600, time_signed 1779813320.
var V2 = {
  unsigned: hex("abcd01000001000000000000046d61696c076578616d706c65036f726700000f0001"),
  signed:   hex("abcd01000001000000000001046d61696c076578616d706c65036f726700000f00010474657374036b65790000fa00ff00000000005d0b686d61632d7368613531320000006a15cbc8025800402c9b1ce5273ed4cf11067dcb8994606e8a5ea09fa5337eda6e6907e3bba08956375853771bf52567875dc3771acd67cf31ad2c6985914fd92b5b1440a1ee3c68abcd00000000"),
  mac:      "2c9b1ce5273ed4cf11067dcb8994606e8a5ea09fa5337eda6e6907e3bba08956375853771bf52567875dc3771acd67cf31ad2c6985914fd92b5b1440a1ee3c68",
  time: 1779813320, fudge: 600, alg: "hmac-sha512",
};

function testSurface() {
  check("tsig.sign is a function", typeof tsig.sign === "function");
  check("tsig.verify is a function", typeof tsig.verify === "function");
  check("tsig.ERROR has BADSIG/BADKEY/BADTIME", tsig.ERROR.BADSIG === 16 && tsig.ERROR.BADKEY === 17 && tsig.ERROR.BADTIME === 18);
  check("tsig.TsigError is a class", typeof tsig.TsigError === "function");
}

function testSignMatchesDnspython() {
  var s1 = tsig.sign(V1.unsigned, { keyName: KEY, secret: SECRET, algorithm: "hmac-sha256", fudge: V1.fudge, time: V1.time });
  check("sign SHA-256 MAC matches dnspython", s1.mac.toString("hex") === V1.mac);
  check("sign SHA-256 wire matches dnspython byte-for-byte", s1.wire.equals(V1.signed));

  var s2 = tsig.sign(V2.unsigned, { keyName: KEY, secret: SECRET, algorithm: "hmac-sha512", fudge: V2.fudge, time: V2.time });
  check("sign SHA-512 MAC matches dnspython", s2.mac.toString("hex") === V2.mac);
  check("sign SHA-512 wire matches dnspython byte-for-byte", s2.wire.equals(V2.signed));
}

function testVerifyAcceptsDnspython() {
  var r1 = tsig.verify(V1.signed, { keys: { "test.key.": { secret: SECRET } }, now: V1.time });
  check("verify SHA-256 dnspython message is valid", r1.valid && r1.macValid && r1.timeValid);
  check("verify reports keyName + algorithm + timeSigned", r1.keyName === "test.key." && r1.algorithm === "hmac-sha256" && r1.timeSigned === V1.time);

  var r2 = tsig.verify(V2.signed, { keys: { "test.key.": { secret: SECRET } }, now: V2.time });
  check("verify SHA-512 dnspython message is valid", r2.valid && r2.macValid);

  // Single-key form.
  var r1b = tsig.verify(V1.signed, { keyName: "test.key.", secret: SECRET, now: V1.time });
  check("verify single-key form works", r1b.valid);
}

function testVerifyRejects() {
  // Wrong secret → MAC mismatch (BADSIG), never throws.
  var bad = tsig.verify(V1.signed, { keys: { "test.key.": { secret: Buffer.alloc(32, 9) } }, now: V1.time });
  check("wrong secret → !valid + BADSIG", !bad.valid && !bad.macValid && bad.error === tsig.ERROR.BADSIG);

  // Outside the fudge window → BADTIME.
  var late = tsig.verify(V1.signed, { keys: { "test.key.": { secret: SECRET } }, now: V1.time + 100000 });
  check("time outside fudge → !valid + BADTIME", !late.valid && late.macValid && !late.timeValid && late.error === tsig.ERROR.BADTIME);

  // Unknown key → BADKEY.
  var nokey = tsig.verify(V1.signed, { keys: { "other.key.": { secret: SECRET } }, now: V1.time });
  check("unknown key → !valid + BADKEY", !nokey.valid && nokey.error === tsig.ERROR.BADKEY);

  // Tampered message body → MAC mismatch.
  var tampered = Buffer.from(V1.signed); tampered[2] ^= 0x20;   // flip a bit in the question/flags region
  var tr = tsig.verify(tampered, { keys: { "test.key.": { secret: SECRET } }, now: V1.time });
  check("tampered message → !valid", !tr.valid);
}

function testRoundTripAndPolicy() {
  // sign → verify round-trip with a fresh time.
  var signed = tsig.sign(V1.unsigned, { keyName: KEY, secret: SECRET, time: 1700000000, fudge: 300 });
  var rt = tsig.verify(signed.wire, { keys: { "test.key.": { secret: SECRET } }, now: 1700000000 });
  check("sign→verify round-trip is valid", rt.valid);

  // Default algorithm is HMAC-SHA256.
  check("default algorithm is hmac-sha256", tsig.verify(signed.wire, { keys: { "test.key.": { secret: SECRET } }, now: 1700000000 }).algorithm === "hmac-sha256");

  // Broken algorithms refused unless allowLegacy.
  check("hmac-md5 refused by default", code(function () { tsig.sign(V1.unsigned, { keyName: KEY, secret: SECRET, algorithm: "hmac-md5" }); }) === "tsig/legacy-algorithm");
  check("hmac-sha1 permitted under allowLegacy", typeof tsig.sign(V1.unsigned, { keyName: KEY, secret: SECRET, algorithm: "hmac-sha1", allowLegacy: true }).mac === "object");
  check("unknown algorithm refused", code(function () { tsig.sign(V1.unsigned, { keyName: KEY, secret: SECRET, algorithm: "hmac-foo" }); }) === "tsig/bad-algorithm");

  // Missing keyName / non-Buffer message refused.
  check("missing keyName refused", code(function () { tsig.sign(V1.unsigned, { secret: SECRET }); }) === "tsig/bad-opt");
  check("non-Buffer message refused", code(function () { tsig.sign("not a buffer", { keyName: KEY, secret: SECRET }); }) === "tsig/bad-message");
}

// dnspython vector with an UPPERCASE key name "Test.Key." — proves the MAC
// digest downcases names (DNS names are case-insensitive) and the wire
// preserves the sender's case.
var UC = {
  signed: hex("123401000001000000000001076578616d706c6503636f6d00000100010454657374034b65790000fa00ff00000000003d0b686d61632d7368613235360000006a15d3d9012c00202d9c8c40b15f04407fc096200b1403a6535ee57a37580b636690b7e8146a0642123400000000"),
  mac: "2d9c8c40b15f04407fc096200b1403a6535ee57a37580b636690b7e8146a0642",
  time: 1779815385,
};

function testCaseInsensitive() {
  // Verify a message whose TSIG key name is "Test.Key." against a key map
  // keyed lower-case — must match (case-insensitive) and the downcased
  // digest must validate against dnspython's MAC.
  var r = tsig.verify(UC.signed, { keys: { "test.key.": { secret: SECRET } }, now: UC.time });
  check("case-insensitive key match + downcased digest verifies", r.valid && r.macValid);

  // Signing with a mixed-case key name reproduces dnspython's MAC byte-exact
  // (proves the digest downcases, not the wire).
  var s = tsig.sign(V1.unsigned, { keyName: "Test.Key.", secret: SECRET, time: UC.time, fudge: 300 });
  check("sign mixed-case key matches dnspython MAC", s.mac.toString("hex") === UC.mac);
  check("sign preserves the key-name case on the wire", s.wire.includes(Buffer.from("Test", "ascii")));
}

function testOriginalIdRoundTrip() {
  // RFC 8945 §5.3.2 — the verifier restores the Original ID (carried in the
  // TSIG RDATA) into the message header before computing the digest, so a
  // signed message survives an on-wire ID rewrite by a forwarder. sign() must
  // therefore digest the SAME Original-ID form; otherwise any signature whose
  // originalId differs from the message's current header ID fails its own
  // verify. The default (originalId == message ID) path is covered above; this
  // pins the advertised non-default originalId opt — sign must produce a
  // signature its own verify accepts.
  var onwire = V1.unsigned.readUInt16BE(0);                 // 0x1234
  var altId = (onwire ^ 0xffff) & 0xffff;                   // a distinct Original ID
  var signed = tsig.sign(V1.unsigned, { keyName: KEY, secret: SECRET, time: V1.time, fudge: 300, originalId: altId });
  var rt = tsig.verify(signed.wire, { keys: { "test.key.": { secret: SECRET } }, now: V1.time });
  check("sign with a non-default originalId → verifies under its own verify", rt.valid && rt.macValid);

  // It genuinely survives an on-wire ID rewrite: flip the header ID on the
  // wire (as a forwarder would); verify restores originalId and still passes.
  var rewired = Buffer.from(signed.wire);
  rewired.writeUInt16BE((altId ^ 0x5555) & 0xffff, 0);
  var rt2 = tsig.verify(rewired, { keys: { "test.key.": { secret: SECRET } }, now: V1.time });
  check("non-default originalId survives an on-wire ID rewrite", rt2.valid && rt2.macValid);
}

function testRrHeaderTamper() {
  // RFC 8945 §4.2 — TSIG RR CLASS must be ANY and TTL must be 0. These
  // bytes are outside the MAC, so they must be validated explicitly.
  var tc = Buffer.from(V1.signed);
  var idx = tc.indexOf(Buffer.from("00fa00ff", "hex"));   // TSIG type (250) + CLASS ANY (255)
  tc[idx + 3] = 0x01;                                      // CLASS ANY -> IN
  check("tampered TSIG CLASS is rejected", code(function () { tsig.verify(tc, { keys: { "test.key.": { secret: SECRET } }, now: V1.time }); }) === "tsig/bad-rr");

  var tt = Buffer.from(V1.signed);
  tt[idx + 7] = 0x01;                                      // a TTL byte -> non-zero
  check("tampered TSIG TTL is rejected", code(function () { tsig.verify(tt, { keys: { "test.key.": { secret: SECRET } }, now: V1.time }); }) === "tsig/bad-rr");
}

async function run() {
  testSurface();
  testSignMatchesDnspython();
  testVerifyAcceptsDnspython();
  testVerifyRejects();
  testCaseInsensitive();
  testRrHeaderTamper();
  testRoundTripAndPolicy();
  testOriginalIdRoundTrip();
}
module.exports = { run: run };
if (require.main === module) { run().then(function () { console.log("[network-tsig] OK — " + helpers.getChecks() + " checks passed"); }, function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }); }
