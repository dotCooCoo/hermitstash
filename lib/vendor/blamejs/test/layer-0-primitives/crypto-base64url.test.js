"use strict";
/**
 * b.crypto.toBase64Url + b.crypto.fromBase64Url — RFC 4648 §5
 * base64url encode/decode routed through Node's built-in encoding.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("toBase64Url is fn",   typeof b.crypto.toBase64Url === "function");
  check("fromBase64Url is fn", typeof b.crypto.fromBase64Url === "function");
}

function testRoundTripBuffer() {
  var buf = Buffer.from([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
  var enc = b.crypto.toBase64Url(buf);
  check("encode produces base64url shape (no padding)",
    typeof enc === "string" && enc.indexOf("=") === -1 && enc.indexOf("+") === -1 && enc.indexOf("/") === -1);
  var dec = b.crypto.fromBase64Url(enc);
  check("decode round-trips to original bytes",
    Buffer.isBuffer(dec) && dec.equals(buf));
}

function testEncodeAcceptsString() {
  var enc = b.crypto.toBase64Url("hello");
  check("encode from string produces aGVsbG8", enc === "aGVsbG8");
}

function testEncodeAcceptsUint8Array() {
  var u8 = new Uint8Array([0x66, 0x6f, 0x6f]);
  var enc = b.crypto.toBase64Url(u8);
  check("encode from Uint8Array produces Zm9v", enc === "Zm9v");
}

function testEncodeRefusesBadShape() {
  var threw = null;
  try { b.crypto.toBase64Url(123); } catch (e) { threw = e; }
  check("encode refuses number input", threw && threw.message.indexOf("must be Buffer") !== -1);
}

function testDecodeRefusesBadShape() {
  var threw = null;
  try { b.crypto.fromBase64Url(123); } catch (e) { threw = e; }
  check("decode refuses non-string input", threw && threw.message.indexOf("must be a string") !== -1);
}

function testNoTrailingPadding() {
  // base64url MUST strip the `=` padding (RFC 4648 §5). The Node
  // built-in "base64url" encoding does this; the test verifies it
  // for a payload that base64 would normally pad.
  // 4 bytes → 6 base64 chars + 2 padding `=` in standard b64;
  // base64url drops the padding.
  var enc = b.crypto.toBase64Url(Buffer.from([0xff, 0xff, 0xff, 0xff]));
  check("4-byte payload yields no trailing =", enc.indexOf("=") === -1);
}

function testRoundTripWithUrlSafeChars() {
  // Bytes that produce `+` and `/` in standard base64 must become
  // `-` and `_` in base64url.
  var buf = Buffer.from([0xfb, 0xff, 0xbf]);  // → "+/+/" pattern in std b64
  var enc = b.crypto.toBase64Url(buf);
  check("base64url uses '-' instead of '+'", enc.indexOf("+") === -1);
  check("base64url uses '_' instead of '/'", enc.indexOf("/") === -1);
  var dec = b.crypto.fromBase64Url(enc);
  check("round-trip preserves bytes", dec.equals(buf));
}

function run() {
  testSurface();
  testRoundTripBuffer();
  testEncodeAcceptsString();
  testEncodeAcceptsUint8Array();
  testEncodeRefusesBadShape();
  testDecodeRefusesBadShape();
  testNoTrailingPadding();
  testRoundTripWithUrlSafeChars();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[crypto-base64url] OK"); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}
