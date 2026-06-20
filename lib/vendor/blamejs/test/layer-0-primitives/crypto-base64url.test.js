"use strict";
/**
 * b.crypto.toBase64Url + b.crypto.fromBase64Url — RFC 4648 §5
 * base64url encode/decode routed through Node's built-in encoding.
 * Also covers b.crypto.importPublicJwk — JWK → public KeyObject import —
 * and b.crypto.makeBase64UrlDecoder — typed-error binding around the strict
 * fromBase64Url decoder.
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

function testImportPublicJwk() {
  check("importPublicJwk is fn", typeof b.crypto.importPublicJwk === "function");

  // A valid Ed25519 public JWK (RFC 8037 §A.1 example) imports to a KeyObject.
  var jwk = { kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" };
  var key = b.crypto.importPublicJwk(jwk, { errorClass: TypeError, code: "x", messagePrefix: "p: " });
  check("importPublicJwk returns a public KeyObject", key && key.type === "public");

  // A malformed JWK (missing x) throws the bound class with interpolated message.
  function KeyErr(code, message) { this.code = code; this.message = message; }
  var threw = null;
  try {
    b.crypto.importPublicJwk({ kty: "OKP", crv: "Ed25519" },
      { errorClass: KeyErr, code: "bad/key", messagePrefix: "import failed: " });
  } catch (e) { threw = e; }
  check("importPublicJwk wraps a bad JWK in the bound error class",
    threw instanceof KeyErr && threw.code === "bad/key" &&
    threw.message.indexOf("import failed: ") === 0);

  // Without errorClass, the raw Node error propagates unchanged.
  var rawThrew = null;
  try { b.crypto.importPublicJwk({ kty: "OKP", crv: "Ed25519" }); }
  catch (e) { rawThrew = e; }
  check("importPublicJwk without errorClass rethrows raw",
    rawThrew !== null && !(rawThrew instanceof KeyErr));
}

function testMakeBase64UrlDecoder() {
  check("makeBase64UrlDecoder is fn", typeof b.crypto.makeBase64UrlDecoder === "function");
  function DErr(code, message) { this.code = code; this.message = message; }

  // With typeMessage: valid decodes; non-string → typeMessage; malformed → badMessage.
  var decode = b.crypto.makeBase64UrlDecoder({
    errorClass: DErr, code: "x/bad", typeMessage: "must be a string", badMessage: "not valid base64url",
  });
  check("makeBase64UrlDecoder decodes valid base64url",
    Buffer.isBuffer(decode("aGVsbG8")) && decode("aGVsbG8").toString() === "hello");
  var t1 = null; try { decode(123); } catch (e) { t1 = e; }
  check("makeBase64UrlDecoder non-string throws typeMessage",
    t1 instanceof DErr && t1.code === "x/bad" && t1.message === "must be a string");
  var t2 = null; try { decode("!!!not-base64!!!"); } catch (e) { t2 = e; }
  check("makeBase64UrlDecoder malformed throws badMessage",
    t2 instanceof DErr && t2.code === "x/bad" && t2.message === "not valid base64url");

  // Without typeMessage: a non-string falls into the decode-failure path (badMessage).
  var decode2 = b.crypto.makeBase64UrlDecoder({ errorClass: DErr, code: "y/bad", badMessage: "bad" });
  var t3 = null; try { decode2(123); } catch (e) { t3 = e; }
  check("makeBase64UrlDecoder without typeMessage: non-string → badMessage",
    t3 instanceof DErr && t3.message === "bad");

  // config-time validation.
  function r(fn) { try { fn(); return false; } catch (e) { return e instanceof TypeError; } }
  check("makeBase64UrlDecoder rejects missing errorClass",
    r(function () { b.crypto.makeBase64UrlDecoder({ code: "x", badMessage: "y" }); }));
  check("makeBase64UrlDecoder rejects missing badMessage",
    r(function () { b.crypto.makeBase64UrlDecoder({ errorClass: DErr, code: "x" }); }));
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
  testImportPublicJwk();
  testMakeBase64UrlDecoder();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[crypto-base64url] OK"); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}
