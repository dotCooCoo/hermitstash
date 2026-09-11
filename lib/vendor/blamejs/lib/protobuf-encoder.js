// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var C = require("./constants");

var WIRE_VARINT  = 0;
var WIRE_64BIT   = 1;
var WIRE_LDELIM  = 2;
var VARINT_BASE = 128;
var FIXED64_BYTES = C.BYTES.bytes(8);

function _writeVarint(value) {
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
  if (fieldNumber < 1 || fieldNumber > 268435455) {
    throw new RangeError("protobuf: field number " + fieldNumber +
      " out of range (1..2^28-1)");
  }
  return _writeVarint((fieldNumber << 3) | wireType);
}

function uint32(fieldNumber, value) {
  if (value === 0) return Buffer.alloc(0);
  return Buffer.concat([_tag(fieldNumber, WIRE_VARINT), _writeVarint(value)]);
}

function uint64(fieldNumber, value) {
  if (value === 0 || value === 0n) return Buffer.alloc(0);
  return Buffer.concat([_tag(fieldNumber, WIRE_VARINT), _writeVarint(value)]);
}

function int64(fieldNumber, value) {
  if (value === 0 || value === 0n) return Buffer.alloc(0);
  var bi;
  if (typeof value === "bigint") {
    bi = value;
  } else if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isInteger(value)) {
      throw new Error("protobuf-encoder: int64 must be finite integer (got " + value + ")");
    }
    bi = BigInt(value);
  } else {
    throw new Error("protobuf-encoder: int64 must be number or bigint, got " + typeof value);
  }
  if (bi < -(1n << 63n) || bi > (1n << 63n) - 1n) {
    throw new Error("protobuf-encoder: int64 out of range (got " + bi.toString() + ")");
  }
  if (bi < 0n) bi = bi + (1n << 64n);
  return Buffer.concat([_tag(fieldNumber, WIRE_VARINT), _writeVarint(bi)]);
}

function sint64(fieldNumber, value) {
  if (value === 0 || value === 0n) return Buffer.alloc(0);
  var bi;
  if (typeof value === "bigint") bi = value;
  else if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isInteger(value)) {
      throw new Error("protobuf-encoder: sint64 must be finite integer (got " + value + ")");
    }
    bi = BigInt(value);
  } else {
    throw new Error("protobuf-encoder: sint64 must be number or bigint, got " + typeof value);
  }
  if (bi < -(1n << 63n) || bi > (1n << 63n) - 1n) {
    throw new Error("protobuf-encoder: sint64 out of range (got " + bi.toString() + ")");
  }
  var zz = (bi << 1n) ^ (bi >> 63n);
  if (zz < 0n) zz = zz + (1n << 64n);
  return Buffer.concat([_tag(fieldNumber, WIRE_VARINT), _writeVarint(zz)]);
}

function bool(fieldNumber, value) {
  if (!value) return Buffer.alloc(0);
  return Buffer.concat([_tag(fieldNumber, WIRE_VARINT), Buffer.from([1])]);
}

function fixed64(fieldNumber, value) {
  var buf = Buffer.alloc(FIXED64_BYTES);
  var bi;
  if (typeof value === "bigint") {
    bi = value;
  } else if (typeof value === "string") {
    if (value.length === 0) {
      throw new Error("protobuf-encoder: fixed64 string must be non-empty unsigned digit-only");
    }
    for (var ci = 0; ci < value.length; ci += 1) {
      var cc = value.charCodeAt(ci);
      if (cc < 0x30 || cc > 0x39) {
        throw new Error("protobuf-encoder: fixed64 string must be unsigned digit-only (got " + JSON.stringify(value) + ")");
      }
    }
    bi = BigInt(value);
  } else if (typeof value === "number") {
    if (value < 0 || !Number.isFinite(value)) {
      throw new Error("protobuf-encoder: fixed64 must be non-negative finite (got " + value + ")");
    }
    if (value > Number.MAX_SAFE_INTEGER) {
      throw new Error("protobuf-encoder: fixed64 Number above MAX_SAFE_INTEGER loses precision; pass a BigInt or digit-string (got " + value + ")");
    }
    bi = BigInt(value);
  } else {
    throw new Error("protobuf-encoder: fixed64 must be bigint, number, or digit-string (got " + typeof value + ")");
  }
  if (bi < 0n || bi > (1n << 64n) - 1n) {
    throw new Error("protobuf-encoder: fixed64 out of uint64 range (got " + bi.toString() + ")");
  }
  buf.writeBigUInt64LE(bi, 0);
  return Buffer.concat([_tag(fieldNumber, WIRE_64BIT), buf]);
}

function double(fieldNumber, value) {
  if (value === 0) return Buffer.alloc(0);
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
  return Buffer.concat([
    _tag(fieldNumber, WIRE_LDELIM),
    _writeVarint(bodyBuf.length),
    bodyBuf,
  ]);
}

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
  int64:            int64,
  sint64:           sint64,
  bool:             bool,
  fixed64:          fixed64,
  double:           double,
  string:           string,
  bytes:            bytes,
  embeddedMessage:  embeddedMessage,
  repeatedMessage:  repeatedMessage,
  _writeVarint:     _writeVarint,
  _tag:             _tag,
};
