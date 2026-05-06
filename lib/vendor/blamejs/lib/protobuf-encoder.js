"use strict";
/**
 * protobuf-encoder — minimal proto3 wire-format encoder.
 *
 * Write-only — there is no decoder. The framework emits OTLP gRPC log
 * records (a fixed schema) and never reads protobuf back. A decoder
 * would double the surface area + maintenance burden for no use case
 * the framework owns end-to-end.
 *
 * Wire format reference:
 *   https://protobuf.dev/programming-guides/encoding/
 *
 * Wire types used:
 *   0  varint    — uint32 / uint64 / int32 / int64 / bool / enum
 *   1  64-bit    — fixed64 / sfixed64 / double
 *   2  length-delimited — string / bytes / embedded message / packed repeated
 *   5  32-bit    — fixed32 / sfixed32 / float
 *
 * Each field on the wire:
 *   tag = (fieldNumber << 3) | wireType   (encoded as varint)
 *   value (per wire type)
 *
 * Operators reach for this primitive when constructing a protobuf
 * message body for an external service that accepts proto over HTTP
 * (gRPC, AWS sigv4-protobuf, GCP protobuf APIs, etc.). All buffer
 * concatenation is deferred — every encoder function returns a Buffer
 * the caller can splice in any order.
 */

var C = require("./constants");

var WIRE_VARINT  = 0;
var WIRE_64BIT   = 1;
var WIRE_LDELIM  = 2;
// Varint base — each byte carries 7 payload bits + 1 continuation bit.
var VARINT_BASE = 128;
// Wire-format byte counts for fixed-size fields.
var FIXED64_BYTES = C.BYTES.bytes(8);
// WIRE_32BIT (5) is unused — fixed32 / sfixed32 / float aren't on the
// OTel logs schema. Reserved here as documentation; un-comment + add
// helpers when a future caller (metrics histograms?) needs them.
// var WIRE_32BIT = 5;

function _writeVarint(value) {
  // proto3 varints are unsigned for the integer types we use here;
  // negative int32/int64 would need 10-byte two's-complement encoding,
  // but OTel log severity numbers / unix nanos are all non-negative.
  if (typeof value === "number") {
    if (value < 0) {
      throw new Error("protobuf-encoder: negative varint not supported (got " + value + ")");
    }
    if (!Number.isFinite(value)) {
      throw new Error("protobuf-encoder: non-finite varint (got " + value + ")");
    }
  } else if (typeof value === "bigint") {
    if (value < 0n) {
      throw new Error("protobuf-encoder: negative varint not supported (got " + value + ")");
    }
  } else {
    throw new Error("protobuf-encoder: varint must be number or bigint, got " + typeof value);
  }
  var bytes = [];
  if (typeof value === "bigint") {
    var v = value;
    do {
      var lower = Number(v & 0x7fn);
      v = v >> 7n;
      if (v !== 0n) lower |= 0x80;
      bytes.push(lower);
    } while (v !== 0n);
  } else {
    // Number path — JS numbers safely hold integers up to 2^53.
    var n = value;
    do {
      var byte = n & 0x7f;
      n = Math.floor(n / VARINT_BASE);
      if (n > 0) byte |= 0x80;
      bytes.push(byte);
    } while (n > 0);
  }
  return Buffer.from(bytes);
}

function _tag(fieldNumber, wireType) {
  return _writeVarint((fieldNumber << 3) | wireType);
}

function uint32(fieldNumber, value) {
  if (value === 0) return Buffer.alloc(0);  // proto3 default — skip
  return Buffer.concat([_tag(fieldNumber, WIRE_VARINT), _writeVarint(value)]);
}

function uint64(fieldNumber, value) {
  if (value === 0 || value === 0n) return Buffer.alloc(0);
  return Buffer.concat([_tag(fieldNumber, WIRE_VARINT), _writeVarint(value)]);
}

function bool(fieldNumber, value) {
  if (!value) return Buffer.alloc(0);  // proto3 default
  return Buffer.concat([_tag(fieldNumber, WIRE_VARINT), Buffer.from([1])]);
}

function fixed64(fieldNumber, value) {
  // For OTel: time_unix_nano fields are fixed64. Accept BigInt or
  // Number; encode as little-endian 8 bytes.
  var buf = Buffer.alloc(FIXED64_BYTES);
  if (typeof value === "bigint") {
    buf.writeBigUInt64LE(value, 0);
  } else {
    if (value < 0 || !Number.isFinite(value)) {
      throw new Error("protobuf-encoder: fixed64 must be non-negative finite (got " + value + ")");
    }
    // Number path — split into low/high 32-bit halves.
    var low  = value % 0x100000000;
    var high = Math.floor(value / 0x100000000);
    buf.writeUInt32LE(low,  0);
    buf.writeUInt32LE(high, 4);
  }
  return Buffer.concat([_tag(fieldNumber, WIRE_64BIT), buf]);
}

function double(fieldNumber, value) {
  if (value === 0) return Buffer.alloc(0);  // proto3 default
  var buf = Buffer.alloc(FIXED64_BYTES);
  buf.writeDoubleLE(value, 0);
  return Buffer.concat([_tag(fieldNumber, WIRE_64BIT), buf]);
}

function string(fieldNumber, value) {
  if (value === "" || value == null) return Buffer.alloc(0);
  var bodyBuf = Buffer.from(String(value), "utf8");
  return Buffer.concat([
    _tag(fieldNumber, WIRE_LDELIM),
    _writeVarint(bodyBuf.length),
    bodyBuf,
  ]);
}

function bytes(fieldNumber, value) {
  if (!value || value.length === 0) return Buffer.alloc(0);
  var buf = Buffer.isBuffer(value) ? value : Buffer.from(value);
  return Buffer.concat([
    _tag(fieldNumber, WIRE_LDELIM),
    _writeVarint(buf.length),
    buf,
  ]);
}

function embeddedMessage(fieldNumber, bodyBuf) {
  // bodyBuf is the already-encoded inner message body (a Buffer).
  // Caller can pass an empty buffer to encode an empty message;
  // proto3 default-skips messages whose every field is at default,
  // but we allow the caller to choose: we always emit the tag +
  // length-delimited body, which lets the operator force-include an
  // empty Resource{} when needed.
  return Buffer.concat([
    _tag(fieldNumber, WIRE_LDELIM),
    _writeVarint(bodyBuf.length),
    bodyBuf,
  ]);
}

// Repeated unpacked: each entry encoded with its own tag+value. This
// is the proto3 default for non-scalar repeated fields (messages,
// strings) — packed encoding only applies to scalar varint/fixed
// types. The caller passes an array and per-entry encoder.
function repeatedMessage(fieldNumber, items, perItemBodyEncoder) {
  if (!items || items.length === 0) return Buffer.alloc(0);
  var pieces = new Array(items.length);
  for (var i = 0; i < items.length; i++) {
    var inner = perItemBodyEncoder(items[i]);
    pieces[i] = embeddedMessage(fieldNumber, inner);
  }
  return Buffer.concat(pieces);
}

module.exports = {
  uint32:           uint32,
  uint64:           uint64,
  bool:             bool,
  fixed64:          fixed64,
  double:           double,
  string:           string,
  bytes:            bytes,
  embeddedMessage:  embeddedMessage,
  repeatedMessage:  repeatedMessage,
  // Exposed for tests — verify varint encoding directly.
  _writeVarint:     _writeVarint,
  _tag:             _tag,
};
