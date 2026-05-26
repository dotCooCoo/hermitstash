"use strict";
/**
 * @module b.cbor
 * @nav    Tools
 * @title  CBOR codec
 *
 * @intro
 *   A bounded, deterministic CBOR codec (RFC 8949). CBOR is the binary
 *   serialization underneath COSE (RFC 9052), CWT, SCITT, and WebAuthn
 *   attestation — a foundational substrate the framework needs in-tree
 *   to build signed-statement primitives without a third-party parser.
 *   Like every parser the framework ships, it is bounded by default:
 *   a binary decoder is attack surface, so the defaults refuse the
 *   shapes a hostile encoder uses to exhaust memory or stack.
 *
 *   <strong>Decoder defences</strong> (all on by default):
 *   - <code>maxDepth</code> — nesting cap (refuses stack exhaustion).
 *   - <code>maxBytes</code> — total input cap; a declared string /
 *     array / map length that exceeds the remaining bytes is refused
 *     before any allocation (no length-prefix memory bomb).
 *   - <strong>Indefinite-length items refused</strong> (major-type
 *     additional-info 31) — they are a streaming-complexity / DoS
 *     vector and are forbidden by deterministic encoding (§4.2.1).
 *   - <strong>Reserved additional-info (28–30) refused.</strong>
 *   - <strong>Tags refused unless allowlisted</strong>
 *     (<code>allowedTags</code>) — a tag triggers semantic
 *     reprocessing; an un-vetted tag is a confused-deputy vector.
 *   - <strong>Duplicate map keys refused</strong> (§5.6 — ambiguous).
 *   - <strong>Trailing bytes refused</strong> — the buffer must be
 *     exactly one CBOR data item.
 *
 *   <strong>Encoder</strong> emits Deterministically Encoded CBOR
 *   (§4.2): shortest-form integer / length heads, definite lengths,
 *   map keys sorted by their encoded bytes (bytewise lexicographic),
 *   no indefinite-length items. Two semantically equal values encode
 *   to byte-identical output — the property COSE signatures and SCITT
 *   receipts depend on.
 *
 *   <code>decode(buf, { requireDeterministic: true })</code> additionally
 *   asserts the input was itself deterministically encoded (it decodes,
 *   re-encodes, and refuses on any byte difference) — use it on the
 *   verify side of a signature where a non-canonical re-encoding would
 *   otherwise be a malleability vector.
 *
 *   Maps decode to a <code>Map</code> (CBOR map keys may be integers,
 *   not just strings — COSE header labels are integers); encode accepts
 *   a <code>Map</code> or a plain object (string keys). Tagged items
 *   are produced / consumed via <code>b.cbor.Tag</code>.
 *
 * @card
 *   Bounded, deterministic in-tree CBOR codec (RFC 8949 §4.2) —
 *   depth / size caps, indefinite-length + tag + duplicate-key
 *   refusal. The substrate under COSE / CWT / SCITT.
 */

var C = require("./constants");
var { defineClass } = require("./framework-error");

var CborError = defineClass("CborError", { alwaysPermanent: true });

var DEFAULT_MAX_DEPTH = 64;                                                            // allow:raw-byte-literal — nesting depth, not a size
var ABSOLUTE_MAX_DEPTH = 256;                                                          // allow:raw-byte-literal — nesting depth ceiling, not a size
var DEFAULT_MAX_BYTES = C.BYTES.mib(16);
var ABSOLUTE_MAX_BYTES = C.BYTES.mib(64);

// CBOR / IEEE-754 wire constants (not byte sizes — protocol values).
var CBOR_AI_1BYTE = 24;            // allow:raw-byte-literal — RFC 8949 §3 additional-info boundary (inline vs 1-byte argument)
var BYTES_64BIT = 8;               // allow:raw-byte-literal — width of a CBOR uint64 / float64 argument, not a cap
var FLOAT16_MANT_DIV = 1024;       // allow:raw-byte-literal — IEEE 754 half-precision mantissa scale (2^10), not a size

/**
 * @primitive b.cbor.Tag
 * @signature b.cbor.Tag(tag, value)
 * @since     0.12.32
 * @status    stable
 * @related   b.cbor.encode, b.cbor.decode
 *
 * A tagged CBOR item (major type 6) — <code>tag</code> is the
 * non-negative integer tag number, <code>value</code> the tagged
 * content. <code>encode</code> accepts a <code>Tag</code>;
 * <code>decode</code> returns one when the tag number is in
 * <code>allowedTags</code>. Construct with or without <code>new</code>.
 *
 * @example
 *   var dt = new b.cbor.Tag(0, "2026-05-24T00:00:00Z");   // RFC 8949 §3.4.1
 *   var bytes = b.cbor.encode(dt);
 *   var back = b.cbor.decode(bytes, { allowedTags: [0] });
 *   // → b.cbor.Tag { tag: 0, value: "2026-05-24T00:00:00Z" }
 */
function Tag(tag, value) {
  if (!(this instanceof Tag)) return new Tag(tag, value);
  if (typeof tag !== "number" || !Number.isInteger(tag) || tag < 0) {
    throw new CborError("cbor/bad-tag", "cbor.Tag: tag must be a non-negative integer");
  }
  this.tag = tag;
  this.value = value;
}

function _capInt(v, dflt, absolute) {
  if (v == null) return dflt;
  if (typeof v !== "number" || !isFinite(v) || v < 1) return dflt;
  var n = Math.floor(v);
  return n > absolute ? absolute : n;
}

// ---- encoder (deterministic, RFC 8949 §4.2) ----

// Preferred float serialization (RFC 8949 §4.2.1): the shortest of
// float16 / float32 / float64 that round-trips the value exactly. COSE
// + SCITT depend on this — emitting float64 for a value representable
// in float16 is non-canonical and trips requireDeterministic.
function _encodeFloat(value) {
  if (Number.isNaN(value)) return Buffer.from([0xf9, 0x7e, 0x00]);                      // allow:raw-byte-literal — canonical half NaN (RFC 8949 §4.2.1)
  if (value === Infinity) return Buffer.from([0xf9, 0x7c, 0x00]);                       // allow:raw-byte-literal — half +Inf
  if (value === -Infinity) return Buffer.from([0xf9, 0xfc, 0x00]);                      // allow:raw-byte-literal — half -Inf
  var half = _doubleToHalfBits(value);
  if (half >= 0) { var hb = Buffer.alloc(3); hb[0] = 0xf9; hb.writeUInt16BE(half, 1); return hb; }
  var f4 = Buffer.alloc(5); f4[0] = 0xfa; f4.writeFloatBE(value, 1);
  if (f4.readFloatBE(1) === value) return f4;                                          // exactly representable in float32
  var f8 = Buffer.alloc(9); f8[0] = 0xfb; f8.writeDoubleBE(value, 1); return f8;
}

// Returns the 16-bit half-precision representation of a FINITE double
// if it is exactly representable, else -1. Goes via float32: a value
// not exact in float32 cannot be exact in float16; then the float32
// exponent must fit the half range and the low 13 mantissa bits must
// be zero (half has a 10-bit mantissa vs float32's 23).
function _doubleToHalfBits(value) {
  var fbuf = Buffer.alloc(4);
  fbuf.writeFloatBE(value, 0);
  if (fbuf.readFloatBE(0) !== value) return -1;                                        // not exact in float32 → not in float16
  var f = fbuf.readUInt32BE(0);
  var sign = (f >>> 16) & 0x8000;
  var exp = (f >>> 23) & 0xff;
  var mant = f & 0x7fffff;
  var unbiased = exp - 127 + 15;
  if (unbiased >= 0x1f) return -1;                                                      // overflow half's exponent range
  if (unbiased <= 0) {
    // subnormal half (or zero / underflow).
    if (unbiased < -10) return -1;                                                      // too small for a half subnormal
    var fullMant = mant | 0x800000;                                                     // restore implicit leading 1
    var shift = 14 - unbiased;
    if (fullMant & ((1 << shift) - 1)) return -1;                                       // would drop set bits → inexact
    return sign | (fullMant >>> shift);
  }
  if (mant & 0x1fff) return -1;                                                         // low 13 bits set → not exact in half
  return sign | (unbiased << 10) | (mant >>> 13);
}

function _head(major, argument) {
  // argument is a non-negative integer (Number or BigInt). Emit the
  // shortest form: inline (<24), 1/2/4/8 byte. major is 0..7.
  var mt = major << 5;
  var big = (typeof argument === "bigint") ? argument : BigInt(argument);
  if (big < 24n) return Buffer.from([mt | Number(big)]);
  if (big < 256n) return Buffer.from([mt | 24, Number(big)]);
  if (big < 65536n) {
    var b2 = Buffer.alloc(3); b2[0] = mt | 25; b2.writeUInt16BE(Number(big), 1); return b2;
  }
  if (big < 4294967296n) {
    var b4 = Buffer.alloc(5); b4[0] = mt | 26; b4.writeUInt32BE(Number(big), 1); return b4;
  }
  if (big < 18446744073709551616n) {
    var b8 = Buffer.alloc(9); b8[0] = mt | 27; b8.writeBigUInt64BE(big, 1); return b8;
  }
  throw new CborError("cbor/int-overflow", "cbor.encode: integer exceeds 64-bit CBOR range");
}

function _encodeValue(value, opts) {
  if (value === null) return Buffer.from([0xf6]);                                       // allow:raw-byte-literal — CBOR null simple value
  if (value === undefined) return Buffer.from([0xf7]);                                  // allow:raw-byte-literal — CBOR undefined simple value
  if (value === true) return Buffer.from([0xf5]);                                       // allow:raw-byte-literal — CBOR true simple value
  if (value === false) return Buffer.from([0xf4]);                                      // allow:raw-byte-literal — CBOR false simple value

  if (typeof value === "number") {
    // Exact integers within the safe range encode as CBOR integers;
    // an integer-VALUED number beyond 2^53 (e.g. 1e300) has lost
    // integer precision and is a float — encode it as a float (use a
    // bigint for exact 64-bit CBOR integers).
    if (Number.isInteger(value) && Math.abs(value) <= Number.MAX_SAFE_INTEGER) {
      return value >= 0 ? _head(0, value) : _head(1, -1 - value);
    }
    if (!isFinite(value) && !opts.allowNonFinite) {
      throw new CborError("cbor/non-finite", "cbor.encode: NaN / Infinity refused (set allowNonFinite to emit them)");
    }
    return _encodeFloat(value);
  }
  if (typeof value === "bigint") {
    return value >= 0n ? _head(0, value) : _head(1, -1n - value);
  }
  if (typeof value === "string") {
    var u = Buffer.from(value, "utf8");
    return Buffer.concat([_head(3, u.length), u]);
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    var bs = Buffer.isBuffer(value) ? value : Buffer.from(value);
    return Buffer.concat([_head(2, bs.length), bs]);
  }
  if (Array.isArray(value)) {
    var parts = [_head(4, value.length)];
    for (var i = 0; i < value.length; i++) parts.push(_encodeValue(value[i], opts));
    return Buffer.concat(parts);
  }
  if (value instanceof Tag) {
    return Buffer.concat([_head(6, value.tag), _encodeValue(value.value, opts)]);
  }
  if (value instanceof Map || (typeof value === "object")) {
    return _encodeMap(value, opts);
  }
  throw new CborError("cbor/unencodable",
    "cbor.encode: value of type " + (typeof value) + " is not CBOR-encodable");
}

function _encodeMap(value, opts) {
  // Build [encodedKey, encodedValue] pairs, then sort by encoded-key
  // bytes (bytewise lexicographic) per §4.2.1 so the output is
  // deterministic regardless of insertion order.
  var entries = [];
  if (value instanceof Map) {
    value.forEach(function (v, k) { entries.push([_encodeValue(k, opts), _encodeValue(v, opts)]); });
  } else {
    var keys = Object.keys(value);
    for (var i = 0; i < keys.length; i++) {
      entries.push([_encodeValue(keys[i], opts), _encodeValue(value[keys[i]], opts)]);
    }
  }
  entries.sort(function (a, b) { return Buffer.compare(a[0], b[0]); });
  // Reject duplicate keys (equal encoded-key bytes) — ambiguous + a
  // canonical-form violation.
  for (var j = 1; j < entries.length; j++) {
    if (Buffer.compare(entries[j - 1][0], entries[j][0]) === 0) {
      throw new CborError("cbor/duplicate-key", "cbor.encode: duplicate map key");
    }
  }
  var out = [_head(5, entries.length)];
  for (var k = 0; k < entries.length; k++) { out.push(entries[k][0]); out.push(entries[k][1]); }
  return Buffer.concat(out);
}

/**
 * @primitive b.cbor.encode
 * @signature b.cbor.encode(value, opts?)
 * @since     0.12.32
 * @status    stable
 * @related   b.cbor.decode, b.cbor.Tag
 *
 * Encode a JavaScript value to Deterministically Encoded CBOR
 * (RFC 8949 §4.2): shortest-form integer / length heads, definite
 * lengths, map keys sorted by their encoded bytes, no indefinite-
 * length items. Two semantically-equal values produce byte-identical
 * output. Accepts numbers (integers + float64), bigint (64-bit
 * range), strings, <code>Buffer</code> / <code>Uint8Array</code>,
 * arrays, <code>Map</code> or plain objects, <code>b.cbor.Tag</code>,
 * and <code>true</code> / <code>false</code> / <code>null</code> /
 * <code>undefined</code>.
 *
 * @opts
 *   {
 *     allowNonFinite?: boolean,   // default false — NaN / Infinity refused
 *   }
 *
 * @example
 *   b.cbor.encode({ b: 2, a: 1 }).toString("hex");   // → "a2616101616202" (keys sorted)
 */
function encode(value, opts) {
  opts = opts || {};
  return _encodeValue(value, opts);
}

// ---- decoder (bounded) ----

/**
 * @primitive b.cbor.decode
 * @signature b.cbor.decode(buffer, opts?)
 * @since     0.12.32
 * @status    stable
 * @related   b.cbor.encode, b.cbor.Tag
 *
 * Decode one CBOR data item from a buffer, bounded by default. Maps
 * decode to a <code>Map</code> (CBOR keys may be integers); byte
 * strings to <code>Buffer</code>. Refuses indefinite-length items,
 * reserved additional-info (28–30), tags not in
 * <code>allowedTags</code>, duplicate map keys, and trailing bytes.
 *
 * @opts
 *   {
 *     maxDepth?:             number,    // default 64, ceiling 256 — nesting cap
 *     maxBytes?:             number,    // default 16 MiB, ceiling 64 MiB
 *     allowedTags?:          number[],  // default [] — tag numbers permitted
 *     requireDeterministic?: boolean,   // default false — assert canonical encoding
 *   }
 *
 * @example
 *   var m = b.cbor.decode(bytes, { allowedTags: [0], requireDeterministic: true });
 */
function decode(buffer, opts) {
  opts = opts || {};
  if (!Buffer.isBuffer(buffer) && !(buffer instanceof Uint8Array)) {
    throw new CborError("cbor/bad-input", "cbor.decode: input must be a Buffer / Uint8Array");
  }
  var buf = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
  var maxBytes = _capInt(opts.maxBytes, DEFAULT_MAX_BYTES, ABSOLUTE_MAX_BYTES);
  if (buf.length > maxBytes) {
    throw new CborError("cbor/too-large",
      "cbor.decode: input " + buf.length + " bytes exceeds maxBytes " + maxBytes);
  }
  var maxDepth = _capInt(opts.maxDepth, DEFAULT_MAX_DEPTH, ABSOLUTE_MAX_DEPTH);
  var allowedTags = Array.isArray(opts.allowedTags) ? opts.allowedTags : [];

  var state = { buf: buf, pos: 0, maxDepth: maxDepth, allowedTags: allowedTags };
  var value = _decodeItem(state, 0);
  if (state.pos !== buf.length) {
    throw new CborError("cbor/trailing-bytes",
      "cbor.decode: " + (buf.length - state.pos) + " trailing byte(s) after the data item");
  }

  if (opts.requireDeterministic === true) {
    // Round-trip: a deterministically-encoded input re-encodes to the
    // identical bytes. Any difference is a non-canonical encoding
    // (long-form head, unsorted keys, indefinite length) — a
    // malleability vector on a signature-verify path.
    var reencoded = _encodeValue(value, {});
    if (Buffer.compare(reencoded, buf) !== 0) {
      throw new CborError("cbor/not-deterministic",
        "cbor.decode: input is not deterministically encoded (requireDeterministic)");
    }
  }
  return value;
}

function _need(state, n) {
  if (state.pos + n > state.buf.length) {
    throw new CborError("cbor/truncated", "cbor.decode: unexpected end of input");
  }
}

function _readArgument(state, ai) {
  // ai is the low-5-bits additional info. Returns the argument as a
  // Number (or BigInt for 8-byte values beyond Number range).
  if (ai < CBOR_AI_1BYTE) return ai;
  if (ai === CBOR_AI_1BYTE) { _need(state, 1); var v1 = state.buf[state.pos]; state.pos += 1; return v1; }
  if (ai === 25) { _need(state, 2); var v2 = state.buf.readUInt16BE(state.pos); state.pos += 2; return v2; }
  if (ai === 26) { _need(state, 4); var v4 = state.buf.readUInt32BE(state.pos); state.pos += 4; return v4; }
  if (ai === 27) {
    _need(state, BYTES_64BIT);
    var big = state.buf.readBigUInt64BE(state.pos); state.pos += BYTES_64BIT;
    return big <= 9007199254740991n ? Number(big) : big;                               // safe-int → Number, else BigInt
  }
  if (ai === 31) {
    throw new CborError("cbor/indefinite-refused",
      "cbor.decode: indefinite-length items are refused (deterministic-encoding violation)");
  }
  throw new CborError("cbor/reserved-ai",
    "cbor.decode: reserved additional-information value " + ai + " (28-30) refused");
}

function _lenOf(arg) {
  // A length / count must be a Number within array bounds — a BigInt
  // length means a >2^53 declared size, which exceeds maxBytes anyway.
  if (typeof arg === "bigint") {
    throw new CborError("cbor/length-too-large", "cbor.decode: declared length exceeds addressable range");
  }
  return arg;
}

function _decodeItem(state, depth) {
  if (depth > state.maxDepth) {
    throw new CborError("cbor/max-depth", "cbor.decode: nesting exceeds maxDepth " + state.maxDepth);
  }
  _need(state, 1);
  var ib = state.buf[state.pos]; state.pos += 1;
  var major = ib >> 5;
  var ai = ib & 0x1f;

  switch (major) {
    case 0: return _readArgument(state, ai);                                            // unsigned int
    case 1: {                                                                           // negative int
      var n = _readArgument(state, ai);
      return (typeof n === "bigint") ? (-1n - n) : (-1 - n);
    }
    case 2: {                                                                           // byte string
      var blen = _lenOf(_readArgument(state, ai));
      _need(state, blen);
      var bytes = buf_slice(state, blen);
      return bytes;
    }
    case 3: {                                                                           // text string
      var slen = _lenOf(_readArgument(state, ai));
      _need(state, slen);
      var sb = buf_slice(state, slen);
      // CBOR text strings are defined as valid UTF-8 (RFC 8949 §3.1).
      // Buffer.toString("utf8") silently substitutes U+FFFD for
      // malformed bytes — that changes data and can slip an invalid
      // payload past a canonicalization / signature check. Decode
      // fatally so malformed UTF-8 is refused.
      try {
        return new TextDecoder("utf-8", { fatal: true }).decode(sb);
      } catch (_e) {
        throw new CborError("cbor/invalid-utf8",
          "cbor.decode: text string is not valid UTF-8 (RFC 8949 §3.1)");
      }
    }
    case 4: {                                                                           // array
      var alen = _lenOf(_readArgument(state, ai));
      var arr = [];
      for (var i = 0; i < alen; i++) arr.push(_decodeItem(state, depth + 1));
      return arr;
    }
    case 5: {                                                                           // map
      var mlen = _lenOf(_readArgument(state, ai));
      var m = new Map();
      var seen = [];
      for (var j = 0; j < mlen; j++) {
        var keyStart = state.pos;
        var key = _decodeItem(state, depth + 1);
        var keyBytes = state.buf.slice(keyStart, state.pos);
        for (var s = 0; s < seen.length; s++) {
          if (Buffer.compare(seen[s], keyBytes) === 0) {
            throw new CborError("cbor/duplicate-key", "cbor.decode: duplicate map key (RFC 8949 §5.6)");
          }
        }
        seen.push(keyBytes);
        var val = _decodeItem(state, depth + 1);
        m.set(key, val);
      }
      return m;
    }
    case 6: {                                                                           // tag
      var tag = _lenOf(_readArgument(state, ai));
      if (state.allowedTags.indexOf(tag) === -1) {
        throw new CborError("cbor/tag-refused",
          "cbor.decode: tag " + tag + " refused (add it to allowedTags to permit)");
      }
      return new Tag(tag, _decodeItem(state, depth + 1));
    }
    default: return _decodeSimpleOrFloat(state, ai);                                     // major 7
  }
}

function buf_slice(state, n) {
  var out = state.buf.slice(state.pos, state.pos + n);
  state.pos += n;
  // Copy so the returned buffer doesn't pin the (larger) input buffer.
  return Buffer.from(out);
}

function _decodeSimpleOrFloat(state, ai) {
  if (ai === 20) return false;
  if (ai === 21) return true;
  if (ai === 22) return null;
  if (ai === 23) return undefined;
  if (ai === 25) { _need(state, 2); var h = _readFloat16(state); return h; }
  if (ai === 26) { _need(state, 4); var f = state.buf.readFloatBE(state.pos); state.pos += 4; return f; }
  if (ai === 27) { _need(state, BYTES_64BIT); var d = state.buf.readDoubleBE(state.pos); state.pos += BYTES_64BIT; return d; }
  if (ai === 31) {
    throw new CborError("cbor/indefinite-refused", "cbor.decode: indefinite-length break refused");
  }
  throw new CborError("cbor/bad-simple",
    "cbor.decode: unsupported simple value " + ai + " (only false/true/null/undefined + float16/32/64)");
}

function _readFloat16(state) {
  // IEEE 754 half-precision → Number (RFC 8949 Appendix D).
  var half = state.buf.readUInt16BE(state.pos); state.pos += 2;
  var exp = (half >> 10) & 0x1f;
  var mant = half & 0x3ff;
  var sign = (half & 0x8000) ? -1 : 1;
  if (exp === 0) return sign * Math.pow(2, -14) * (mant / FLOAT16_MANT_DIV);
  if (exp === 31) return mant ? NaN : sign * Infinity;
  return sign * Math.pow(2, exp - 25) * (FLOAT16_MANT_DIV + mant);
}

module.exports = {
  encode:    encode,
  decode:    decode,
  Tag:       Tag,
  CborError: CborError,
};
