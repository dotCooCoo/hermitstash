"use strict";
/**
 * asn1-der — minimal ASN.1 DER walker for the framework's narrow
 * cryptographic uses (OCSP response parsing, CT SCT extension parsing).
 *
 * The standard library does NOT ship an ASN.1 parser; we add a focused
 * one rather than vendoring asn1.js (40+ KiB of JS for a small subset
 * of features). The parser is presence-only: it reads tag + length +
 * value and walks SEQUENCE / SET / context-specific structures. It
 * does NOT decode arbitrary types — callers cherry-pick OIDs / INTEGER
 * / OCTET STRING / BIT STRING / GeneralizedTime / UTCTime via the
 * helpers below.
 *
 * Shape:
 *
 *   var node = readNode(buf);
 *   // → { tag, tagClass, constructed, length, value, valueStart, totalLength }
 *
 *   var children = readSequence(buf);   // returns array of nodes
 *   var oidStr   = readOid(buf, node);
 *   var int      = readUnsignedInt(buf, node);
 *   var bytes    = readOctetString(buf, node);
 *
 * Errors throw `Asn1Error` with a `code` (`asn1/short` / `asn1/bad-length`
 * / `asn1/oid-malformed` / etc.) so callers can route on a stable shape.
 */

var { defineClass } = require("./framework-error");

var Asn1Error = defineClass("Asn1Error", { alwaysPermanent: true });

// ASN.1 tag classes per ITU-T X.690 §8.1.2.
var TAG_CLASS = Object.freeze({
  UNIVERSAL:        0,                                                          // allow:raw-byte-literal — ASN.1 tag class
  APPLICATION:      1,                                                          // allow:raw-byte-literal — ASN.1 tag class
  CONTEXT_SPECIFIC: 2,                                                          // allow:raw-byte-literal — ASN.1 tag class
  PRIVATE:          3,                                                          // allow:raw-byte-literal — ASN.1 tag class
});

// Universal tag numbers used by the framework.
var TAG = Object.freeze({
  BOOLEAN:          0x01,
  INTEGER:          0x02,
  BIT_STRING:       0x03,
  OCTET_STRING:     0x04,
  NULL:             0x05,
  OID:              0x06,
  ENUMERATED:       0x0a,
  UTF8_STRING:      0x0c,
  PRINTABLE_STRING: 0x13,
  IA5_STRING:       0x16,
  UTC_TIME:         0x17,
  GENERALIZED_TIME: 0x18,
  SEQUENCE:         0x10,
  SET:              0x11,
});

// Read a TLV (tag + length + value) starting at offset. Returns:
//   { tag, tagClass, constructed, length, value, valueStart, totalLength }
// where:
//   tag         — numeric tag (universal-class numbers are 0x01..0x1e;
//                 context-specific [N] tags surface as N with tagClass=2)
//   constructed — true for SEQUENCE / SET / explicit tags; false for primitive
//   value       — Buffer slice covering the value bytes
//   totalLength — number of bytes consumed (header + value)
function readNode(buf, offset) {
  offset = offset || 0;
  if (offset >= buf.length) {
    throw new Asn1Error("asn1/short", "buffer ended at offset " + offset);
  }

  var b0 = buf[offset];
  var tagClass   = (b0 >> 6) & 0x03;                                            // allow:raw-byte-literal — tag-class extraction
  var constructed = (b0 & 0x20) !== 0;                                          // allow:raw-byte-literal — constructed bit
  var tag         = b0 & 0x1f;                                                  // allow:raw-byte-literal — short-form tag

  var headerLen = 1;
  if (tag === 0x1f) {
    // High-tag-number form (multi-byte tag). Walk continuation octets
    // (each top bit set means another follows).
    tag = 0;
    while (true) {
      if (offset + headerLen >= buf.length) {
        throw new Asn1Error("asn1/short", "tag continuation truncated");
      }
      var byte = buf[offset + headerLen];
      headerLen += 1;
      tag = (tag << 7) | (byte & 0x7f);                                         // allow:raw-byte-literal — base-128 tag bits
      if ((byte & 0x80) === 0) break;                                           // allow:raw-byte-literal — continuation bit
    }
  }

  if (offset + headerLen >= buf.length) {
    throw new Asn1Error("asn1/short", "length-byte missing");
  }
  var lenByte = buf[offset + headerLen];
  headerLen += 1;
  var length;
  if ((lenByte & 0x80) === 0) {
    // Short form — length is the byte itself.
    length = lenByte;
  } else {
    // Long form — bottom 7 bits = number of length octets.
    var lenOctets = lenByte & 0x7f;
    if (lenOctets === 0) {
      // Indefinite length — only valid in BER, not DER. Refuse.
      throw new Asn1Error("asn1/indefinite-length",
        "indefinite-length form is not allowed in DER");
    }
    if (lenOctets > 4) {                                                        // allow:raw-byte-literal — DER length cap (>4 GiB)
      throw new Asn1Error("asn1/bad-length",
        "length octets " + lenOctets + " exceeds 4 — refusing >4 GiB structure");
    }
    if (offset + headerLen + lenOctets > buf.length) {
      throw new Asn1Error("asn1/short", "length octets truncated");
    }
    length = 0;
    for (var i = 0; i < lenOctets; i += 1) {
      length = (length * 256) + buf[offset + headerLen + i];                    // allow:raw-byte-literal — base-256 length bytes
    }
    headerLen += lenOctets;
  }

  var valueStart = offset + headerLen;
  if (valueStart + length > buf.length) {
    throw new Asn1Error("asn1/short",
      "value extends past buffer: needs " + length + " bytes at " + valueStart);
  }
  return {
    tag:         tag,
    tagClass:    tagClass,
    constructed: constructed,
    length:      length,
    value:       buf.slice(valueStart, valueStart + length),
    raw:         buf.slice(offset, offset + headerLen + length),
    valueStart:  valueStart,
    totalLength: headerLen + length,
  };
}

function readSequence(buf) {
  // Walk the children of a SEQUENCE / SET. The buffer passed in IS
  // the value of an outer node (already past the header).
  var out = [];
  var offset = 0;
  while (offset < buf.length) {
    var node = readNode(buf, offset);
    out.push(node);
    offset += node.totalLength;
  }
  return out;
}

// Decode an OBJECT IDENTIFIER (ITU-T X.690 §8.19) into dotted-decimal.
function readOid(node) {
  if (node.tag !== TAG.OID || node.tagClass !== TAG_CLASS.UNIVERSAL) {
    throw new Asn1Error("asn1/wrong-tag",
      "expected OID (tag 0x06), got " + node.tag);
  }
  var bytes = node.value;
  if (bytes.length === 0) {
    throw new Asn1Error("asn1/oid-empty", "OID value is empty");
  }
  // First two arcs are encoded as `40*X + Y`.
  var first = Math.floor(bytes[0] / 40);                                        // allow:raw-byte-literal — OID encoding constant
  var second = bytes[0] % 40;                                                   // allow:raw-byte-literal — OID encoding constant
  // Per X.690, when first byte >= 80 the first arc is 2 and second is byte-80.
  if (first > 2) { first = 2; second = bytes[0] - 80; }                         // allow:raw-byte-literal — OID encoding constant
  var arcs = [String(first), String(second)];

  var i = 1;
  while (i < bytes.length) {
    var arc = 0;
    var j = i;
    while (j < bytes.length) {
      var b = bytes[j];
      arc = (arc * 128) + (b & 0x7f);                                           // allow:raw-byte-literal — base-128 OID arc
      j += 1;
      if ((b & 0x80) === 0) break;                                              // allow:raw-byte-literal — continuation bit
    }
    if (j === i) {
      throw new Asn1Error("asn1/oid-malformed", "OID arc never terminated");
    }
    arcs.push(String(arc));
    i = j;
  }
  return arcs.join(".");
}

function readOctetString(node) {
  if (node.tag !== TAG.OCTET_STRING || node.tagClass !== TAG_CLASS.UNIVERSAL) {
    throw new Asn1Error("asn1/wrong-tag",
      "expected OCTET STRING (tag 0x04), got " + node.tag);
  }
  return node.value;
}

function readUnsignedInt(node) {
  if (node.tag !== TAG.INTEGER && node.tag !== TAG.ENUMERATED) {
    throw new Asn1Error("asn1/wrong-tag",
      "expected INTEGER/ENUMERATED, got " + node.tag);
  }
  // DER INTEGER may have a leading 0x00 byte to disambiguate from
  // negative values when the high bit is set; strip it for unsigned
  // interpretation.
  var bytes = node.value;
  if (bytes.length === 0) {
    throw new Asn1Error("asn1/int-empty", "INTEGER value is empty");
  }
  if (bytes.length > 8) {                                                       // allow:raw-byte-literal — JS safe-int byte cap
    // Caller wanted an unsigned int — for big serials they want the raw
    // bytes instead. Surface as hex string so caller decides.
    return { hex: bytes.toString("hex") };
  }
  var n = 0;
  var start = (bytes[0] === 0 && bytes.length > 1) ? 1 : 0;                     // allow:raw-byte-literal — DER zero-pad
  for (var k = start; k < bytes.length; k += 1) {
    n = (n * 256) + bytes[k];                                                   // allow:raw-byte-literal — base-256 byte
  }
  return n;
}

function readBitString(node) {
  if (node.tag !== TAG.BIT_STRING || node.tagClass !== TAG_CLASS.UNIVERSAL) {
    throw new Asn1Error("asn1/wrong-tag",
      "expected BIT STRING (tag 0x03), got " + node.tag);
  }
  // BIT STRING value: first byte is "unused bits in last byte" count;
  // remaining bytes are the bit content. For signature blobs we want
  // just the bytes — the unused count is always 0 for full-byte sigs.
  if (node.value.length === 0) {
    throw new Asn1Error("asn1/bit-string-empty", "BIT STRING is empty");
  }
  var unused = node.value[0];
  if (unused !== 0) {
    throw new Asn1Error("asn1/bit-string-unused-bits",
      "BIT STRING with unused bits is unsupported (got " + unused + ")");
  }
  return node.value.slice(1);
}

// Read a context-specific [N] EXPLICIT-tagged child. Returns the
// inner node (the tag inside the explicit wrapper).
function unwrapExplicit(node, expectedTag) {
  if (node.tagClass !== TAG_CLASS.CONTEXT_SPECIFIC || node.tag !== expectedTag) {
    throw new Asn1Error("asn1/wrong-tag",
      "expected context-specific [" + expectedTag + "], got class=" +
      node.tagClass + " tag=" + node.tag);
  }
  return readNode(node.value, 0);
}

// ---- DER writers (minimal — just the shapes the framework needs) ----
//
// Encoders for the small ASN.1 set the framework currently constructs:
// SEQUENCE / OCTET STRING / OID / INTEGER / NULL / context-specific
// [N] EXPLICIT. Fewer than 100 lines because we only emit the DER that
// crosses the wire (OCSP requests today; future TLSA encoding tomorrow).
// All length fields use the standard X.690 short / long-form encoding.

function _encodeLength(n) {
  if (n < 128) return Buffer.from([n]);                                          // allow:raw-byte-literal — X.690 short-form length boundary
  // Long-form: first byte is 0x80 | numLengthOctets, then the length
  // big-endian.
  var bytes = [];
  while (n > 0) {
    bytes.unshift(n & 0xff);                                                     // allow:raw-byte-literal — base-256 length encoding mask
    n = n >>> 8;                                                                 // allow:raw-byte-literal — base-256 length encoding shift
  }
  return Buffer.concat([Buffer.from([0x80 | bytes.length]), Buffer.from(bytes)]);
}

function writeNode(tagByte, value) {
  return Buffer.concat([Buffer.from([tagByte]), _encodeLength(value.length), value]);
}

function writeSequence(children) {
  // children: Array<Buffer> of already-encoded child nodes.
  return writeNode(TAG.SEQUENCE | 0x20, Buffer.concat(children));                // allow:raw-byte-literal — DER constructed bit
}

function writeOctetString(value) {
  return writeNode(TAG.OCTET_STRING, value);
}

function writeNull() {
  return writeNode(TAG.NULL, Buffer.alloc(0));
}

function writeInteger(buf) {
  // INTEGER values are big-endian. If high bit of leading byte is set
  // and the value is positive (cert serials always are here), prepend
  // 0x00 to disambiguate from a negative two's complement.
  if (buf.length === 0) return writeNode(TAG.INTEGER, Buffer.from([0]));
  if (buf[0] & 0x80) {                                                           // allow:raw-byte-literal — sign-bit disambiguation
    return writeNode(TAG.INTEGER, Buffer.concat([Buffer.from([0]), buf]));
  }
  return writeNode(TAG.INTEGER, buf);
}

function writeOid(dotted) {
  // Encode dotted-decimal OID per X.690 §8.19.
  var parts = String(dotted).split(".").map(function (s) { return parseInt(s, 10); });
  if (parts.length < 2) {
    throw new Asn1Error("asn1/oid-too-short", "OID needs at least 2 arcs");
  }
  var bytes = [parts[0] * 40 + parts[1]];                                        // allow:raw-byte-literal — OID first-arc encoding
  for (var i = 2; i < parts.length; i += 1) {
    var arc = parts[i];
    if (arc === 0) { bytes.push(0); continue; }
    var stack = [];
    while (arc > 0) {
      stack.unshift(arc & 0x7f);                                                 // allow:raw-byte-literal — base-128 mask
      arc = arc >>> 7;                                                           // allow:raw-byte-literal — base-128 shift
    }
    for (var j = 0; j < stack.length - 1; j += 1) stack[j] |= 0x80;              // allow:raw-byte-literal — continuation bit
    for (var k = 0; k < stack.length; k += 1) bytes.push(stack[k]);
  }
  return writeNode(TAG.OID, Buffer.from(bytes));
}

function writeContextExplicit(tagNumber, child) {
  // [N] EXPLICIT — context-specific class (0xA0 | tag) + constructed.
  var tagByte = 0xa0 | (tagNumber & 0x1f);                                       // allow:raw-byte-literal — context-specific constructed mask
  return writeNode(tagByte, child);
}

// Find a child node of a SEQUENCE / SET by predicate. Returns null if
// no child matches.
function findChild(children, predicate) {
  for (var i = 0; i < children.length; i += 1) {
    if (predicate(children[i])) return children[i];
  }
  return null;
}

module.exports = {
  TAG_CLASS:           TAG_CLASS,
  TAG:                 TAG,
  readNode:            readNode,
  readSequence:        readSequence,
  readOid:             readOid,
  readOctetString:     readOctetString,
  readUnsignedInt:     readUnsignedInt,
  readBitString:       readBitString,
  unwrapExplicit:      unwrapExplicit,
  findChild:           findChild,
  writeNode:           writeNode,
  writeSequence:       writeSequence,
  writeOctetString:    writeOctetString,
  writeInteger:        writeInteger,
  writeNull:           writeNull,
  writeOid:            writeOid,
  writeContextExplicit: writeContextExplicit,
  Asn1Error:           Asn1Error,
};
