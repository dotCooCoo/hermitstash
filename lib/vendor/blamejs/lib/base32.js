// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
  var dataCount = 0;   // count of data symbols (excludes padding + skipped separators)
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
    dataCount += 1;
    if (bits >= 8) {                                        // emit a full output byte
      bytes.push((value >>> (bits - 8)) & 0xff);            // eight-bit output byte mask
      bits -= 8;                                            // consumed eight bits
    }
  }
  // A group of 5 input bytes encodes to 8 symbols; the only valid partial-group
  // symbol counts are 2, 4, 5, 7 (for 1, 2, 3, 4 trailing bytes). A count of
  // 1/3/6 (mod 8) cannot represent any whole-byte input, so the OLD decoder
  // silently returned a truncated/garbage buffer — refuse it.
  var rem = dataCount % GROUP;
  if (rem === 1 || rem === 3 || rem === 6) {
    throw new Base32Error("base32/bad-length",
      "base32.decode: " + dataCount + " data symbol(s) is not a valid Base32 length " +
      "(a partial group is 2, 4, 5 or 7 symbols)");
  }
  // Non-canonical trailing bits (RFC 4648 §3.5): a conforming encoder zeroes the
  // final symbol's unused low bits. Non-zero leftover bits mean two distinct
  // strings decode to the same bytes — decoder malleability. Refuse it so every
  // byte sequence has exactly one Base32 form (matters where the string is a
  // key / secret / dedup handle, e.g. TOTP, identifiers).
  if (bits > 0 && (value & ((1 << bits) - 1)) !== 0) {
    throw new Base32Error("base32/non-canonical",
      "base32.decode: non-canonical encoding — the final symbol's unused low bits must be zero");
  }
  return Buffer.from(bytes);
}

module.exports = {
  encode:      encode,
  decode:      decode,
  ALPHABETS:   ALPHABETS,
  Base32Error: Base32Error,
};
