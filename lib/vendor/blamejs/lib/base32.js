"use strict";
/**
 * @module b.base32
 * @nav    Data
 * @title  Base32
 *
 * @intro
 *   Encode and decode <a href="https://www.rfc-editor.org/rfc/rfc4648">RFC
 *   4648</a> Base32 — the case-insensitive, digit-light alphabet used for
 *   TOTP / 2FA secrets, DNSSEC NSEC3 hashes, and human-transcribable
 *   identifiers. Both RFC 4648 variants are supported: the standard
 *   alphabet (<code>variant: "rfc4648"</code>, default) and the
 *   extended-hex alphabet (<code>variant: "rfc4648-hex"</code>, which sorts
 *   in the same order as the underlying bytes).
 *
 *   <code>encode</code> pads to an 8-character boundary with
 *   <code>=</code> by default (pass <code>padding: false</code> for the
 *   bare form TOTP key URIs use). <code>decode</code> is strict by default
 *   — it rejects any character outside the alphabet — but
 *   <code>loose: true</code> accepts the real-world shapes humans produce:
 *   lower-case input, embedded spaces and dashes, and missing padding.
 *
 * @card
 *   RFC 4648 Base32 encode / decode (standard + extended-hex alphabets,
 *   padded or bare, strict or lenient) — the codec behind TOTP secrets and
 *   transcribable identifiers.
 */

var { defineClass } = require("./framework-error");

var Base32Error = defineClass("Base32Error", { alwaysPermanent: true });

var ALPHABETS = {
  "rfc4648": "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
  "rfc4648-hex": "0123456789ABCDEFGHIJKLMNOPQRSTUV",
};
// Reverse lookups per variant: char-code → 5-bit value.
var LOOKUPS = {};
Object.keys(ALPHABETS).forEach(function (v) {
  var map = {};
  for (var i = 0; i < ALPHABETS[v].length; i++) map[ALPHABETS[v].charAt(i)] = i;
  LOOKUPS[v] = map;
});

var GROUP = 8;                                              // Base32 emits 8 chars per 5 input bytes (RFC 4648 §6)
var BITS = 5;                                               // 5 bits per Base32 symbol

function _alphabet(variant) {
  var a = ALPHABETS[variant || "rfc4648"];
  if (!a) throw new Base32Error("base32/bad-variant", "base32: variant must be 'rfc4648' or 'rfc4648-hex'");
  return a;
}

/**
 * @primitive  b.base32.encode
 * @signature  b.base32.encode(input, opts?)
 * @since      0.12.65
 * @status     stable
 * @related    b.base32.decode
 *
 * Encode a Buffer (or Uint8Array) to an RFC 4648 Base32 string. Output is
 * padded to an 8-character boundary with <code>=</code> unless
 * <code>padding: false</code>. The empty input encodes to the empty string.
 *
 * @opts
 *   variant:   "rfc4648" | "rfc4648-hex",   // default: "rfc4648"
 *   padding:   boolean,                      // default: true
 *
 * @example
 *   b.base32.encode(Buffer.from("foobar"));
 *   // → "MFRGGZDFMZTWQ===="
 */
function encode(input, opts) {
  opts = opts || {};
  var buf;
  if (Buffer.isBuffer(input)) buf = input;
  else if (input instanceof Uint8Array) buf = Buffer.from(input);
  else throw new Base32Error("base32/bad-input", "base32.encode: input must be a Buffer or Uint8Array");
  var alphabet = _alphabet(opts.variant);
  var pad = opts.padding !== false;

  var out = "";
  var value = 0, bits = 0;
  for (var i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i];                          // shift in one input byte
    bits += 8;                                              // eight bits per input byte
    while (bits >= BITS) {
      out += alphabet.charAt((value >>> (bits - BITS)) & 31);   // low 5 bits mask (2^5 - 1)
      bits -= BITS;
    }
  }
  if (bits > 0) out += alphabet.charAt((value << (BITS - bits)) & 31);   // final partial group, low 5 bits
  if (pad) while (out.length % GROUP !== 0) out += "=";
  return out;
}

/**
 * @primitive  b.base32.decode
 * @signature  b.base32.decode(str, opts?)
 * @since      0.12.65
 * @status     stable
 * @related    b.base32.encode
 *
 * Decode an RFC 4648 Base32 string to a Buffer. Strict by default: any
 * character outside the variant's alphabet (other than trailing
 * <code>=</code> padding) throws <code>Base32Error</code>. With
 * <code>loose: true</code> the decoder up-cases the input and ignores
 * embedded spaces and dashes (and missing padding) — the shapes TOTP keys
 * and hand-typed codes take.
 *
 * @opts
 *   variant:   "rfc4648" | "rfc4648-hex",   // default: "rfc4648"
 *   loose:     boolean,                      // default: false
 *
 * @example
 *   b.base32.decode("MFRGGZDFMZTWQ====").toString();
 *   // → "foobar"
 */
function decode(str, opts) {
  opts = opts || {};
  if (typeof str !== "string") throw new Base32Error("base32/bad-input", "base32.decode: input must be a string");
  _alphabet(opts.variant);
  var lookup = LOOKUPS[opts.variant || "rfc4648"];
  var loose = opts.loose === true;

  var bytes = [];
  var value = 0, bits = 0;
  var inPad = false;   // once "=" padding starts, only more "=" may follow
  for (var i = 0; i < str.length; i++) {
    var ch = str.charAt(i);
    if (ch === "=") { inPad = true; continue; }             // trailing padding
    if (loose && (ch === " " || ch === "-")) continue;      // ignore separators
    // A data character after padding is malformed in either mode — the "="
    // run must be trailing (rejects "M=Y======" / "MZXW=6YTB").
    if (inPad) throw new Base32Error("base32/bad-char", "base32.decode: data character '" + ch + "' after padding at index " + i);
    if (loose) ch = ch.toUpperCase();
    var idx = lookup[ch];
    if (idx === undefined) throw new Base32Error("base32/bad-char", "base32.decode: invalid Base32 character '" + str.charAt(i) + "' at index " + i);
    value = (value << BITS) | idx;
    bits += BITS;
    if (bits >= 8) {                                        // emit a full output byte
      bytes.push((value >>> (bits - 8)) & 0xff);            // eight-bit output byte mask
      bits -= 8;                                            // consumed eight bits
    }
  }
  return Buffer.from(bytes);
}

module.exports = {
  encode:      encode,
  decode:      decode,
  ALPHABETS:   ALPHABETS,
  Base32Error: Base32Error,
};
