"use strict";
/**
 * Layer 0 — b.base32 (RFC 4648).
 * Oracle: the RFC 4648 §10 test vectors for both the standard Base32
 * alphabet and the extended-hex alphabet.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

// RFC 4648 §10 — standard Base32.
var STD = [["", ""], ["f", "MY======"], ["fo", "MZXQ===="], ["foo", "MZXW6==="],
  ["foob", "MZXW6YQ="], ["fooba", "MZXW6YTB"], ["foobar", "MZXW6YTBOI======"]];
// RFC 4648 §10 — Base32 extended hex.
var HEX = [["", ""], ["f", "CO======"], ["fo", "CPNG===="], ["foo", "CPNMU==="],
  ["foob", "CPNMUOG="], ["fooba", "CPNMUOJ1"], ["foobar", "CPNMUOJ1E8======"]];

function testSurface() {
  check("b.base32.encode is a function", typeof b.base32.encode === "function");
  check("b.base32.decode is a function", typeof b.base32.decode === "function");
  check("b.base32.Base32Error is a class", typeof b.base32.Base32Error === "function");
}

function testVectors() {
  var ep = 0, dp = 0;
  STD.forEach(function (t) {
    if (b.base32.encode(Buffer.from(t[0])) === t[1]) ep++; else check("std encode " + JSON.stringify(t[0]), false);
    if (b.base32.decode(t[1]).toString() === t[0]) dp++; else check("std decode " + t[1], false);
  });
  check("RFC 4648 standard: all encode vectors", ep === STD.length);
  check("RFC 4648 standard: all decode vectors", dp === STD.length);
  var hep = 0, hdp = 0;
  HEX.forEach(function (t) {
    if (b.base32.encode(Buffer.from(t[0]), { variant: "rfc4648-hex" }) === t[1]) hep++; else check("hex encode " + JSON.stringify(t[0]), false);
    if (b.base32.decode(t[1], { variant: "rfc4648-hex" }).toString() === t[0]) hdp++; else check("hex decode " + t[1], false);
  });
  check("RFC 4648 hex: all encode vectors", hep === HEX.length);
  check("RFC 4648 hex: all decode vectors", hdp === HEX.length);
}

function testOptions() {
  check("padding:false omits =", b.base32.encode(Buffer.from("f"), { padding: false }) === "MY");
  check("round-trip random 20 bytes", (function () {
    var buf = require("crypto").randomBytes(20);
    return b.base32.decode(b.base32.encode(buf)).equals(buf);
  })());
  // loose decode: lower-case, spaces, dashes, missing padding.
  check("loose decodes lower-case + separators", b.base32.decode("mzxw 6ytb-oi", { loose: true }).toString() === "foobar");
  check("strict rejects lower-case", code(function () { b.base32.decode("mzxw6ytb"); }) === "base32/bad-char");
  check("strict rejects bad char", code(function () { b.base32.decode("MZXW60TB"); }) === "base32/bad-char");
  check("bad variant throws", code(function () { b.base32.encode(Buffer.from("x"), { variant: "nope" }); }) === "base32/bad-variant");
  check("non-buffer encode throws", code(function () { b.base32.encode("not a buffer"); }) === "base32/bad-input");
  check("non-string decode throws", code(function () { b.base32.decode(123); }) === "base32/bad-input");
  // Embedded / non-trailing padding is malformed and must be rejected
  // (not silently truncated at the first "=").
  check("rejects embedded padding then data", code(function () { b.base32.decode("MZXW=6YTB"); }) === "base32/bad-char");
  check("rejects padding then data (loose)", code(function () { b.base32.decode("mz=xw", { loose: true }); }) === "base32/bad-char");
  check("accepts valid trailing padding", b.base32.decode("MZXW6YQ=").toString() === "foob");
}

function testTotpComposition() {
  // The TOTP secret produced by generateSecret must decode through b.base32.
  var secret = b.auth.totp.generateSecret();
  check("totp secret decodes via b.base32 (loose)", b.base32.decode(secret, { loose: true }).length > 0);
  // The TOTP secret is unpadded standard Base32 → re-encoding the decoded
  // bytes (unpadded) reproduces the secret exactly.
  check("totp secret round-trips through b.base32", b.base32.encode(b.base32.decode(secret, { loose: true }), { padding: false }) === secret);
}

async function run() {
  testSurface();
  testVectors();
  testOptions();
  testTotpComposition();
}
module.exports = { run: run };
if (require.main === module) { run().then(function () { console.log("[base32] OK — " + helpers.getChecks() + " checks passed"); }, function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }); }
