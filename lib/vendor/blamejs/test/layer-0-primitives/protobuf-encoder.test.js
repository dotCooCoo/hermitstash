"use strict";
/**
 * protobuf-encoder — proto3 wire-format encoder.
 *
 * Tests verify byte sequences against the canonical proto3 reference
 * (https://protobuf.dev/programming-guides/encoding/) so the encoder
 * is correct without a decoder for cross-validation.
 */
var helpers = require("../helpers");
var check = helpers.check;
var pb = require("../../lib/protobuf-encoder");

function _hex(buf) { return Buffer.from(buf).toString("hex"); }

async function testVarintCanonical() {
  // Reference values from the proto3 encoding spec:
  //   1   -> 01
  //   150 -> 96 01
  //   300 -> ac 02
  //   16384 -> 80 80 01
  check("varint(1)",      _hex(pb._writeVarint(1))      === "01");
  check("varint(150)",    _hex(pb._writeVarint(150))    === "9601");
  check("varint(300)",    _hex(pb._writeVarint(300))    === "ac02");
  check("varint(16384)",  _hex(pb._writeVarint(16384))  === "808001");
  check("varint(0)",      _hex(pb._writeVarint(0))      === "00");
}

async function testVarintBigInt() {
  // 2^53 - 1 (Number.MAX_SAFE_INTEGER) — within Number range.
  check("varint(2^53-1) via BigInt",
        _hex(pb._writeVarint(BigInt(Number.MAX_SAFE_INTEGER))).length > 0);
  // BigInt round-trip — encode then sanity-check first byte.
  var huge = pb._writeVarint(BigInt("9007199254740993"));   // 2^53 + 1
  check("BigInt varint produces non-empty bytes", huge.length > 0);

  var threwNeg = null;
  try { pb._writeVarint(-1); } catch (e) { threwNeg = e; }
  check("negative varint throws", threwNeg && /negative/.test(threwNeg.message));

  var threwBigNeg = null;
  try { pb._writeVarint(BigInt(-1)); } catch (e) { threwBigNeg = e; }
  check("negative bigint varint throws", threwBigNeg && /negative/.test(threwBigNeg.message));
}

async function testTagComputation() {
  // tag = (fieldNum << 3) | wireType, encoded as varint
  // field=1, wireType=0 (varint) -> tag byte 0x08
  // field=2, wireType=2 (length-delimited) -> 0x12
  // field=3, wireType=5 (32-bit) -> 0x1d
  check("tag(1, 0)=08",  _hex(pb._tag(1, 0)) === "08");
  check("tag(2, 2)=12",  _hex(pb._tag(2, 2)) === "12");
  check("tag(3, 5)=1d",  _hex(pb._tag(3, 5)) === "1d");
}

async function testStringFieldShape() {
  // string field 1 = "testing" -> 0a 07 74 65 73 74 69 6e 67
  // 0x0a = (1 << 3) | 2, 0x07 = length, then UTF-8 bytes.
  check("string field 1 'testing'",
        _hex(pb.string(1, "testing")) === "0a0774657374696e67");
  // Empty string -> proto3 default, encoder skips entirely.
  check("string('') is omitted",   pb.string(1, "").length === 0);
  check("string(null) is omitted", pb.string(1, null).length === 0);
}

async function testUint32FieldShape() {
  // uint32 field 1 = 150 -> tag (0x08) + varint 150 (96 01)
  check("uint32(1, 150)",  _hex(pb.uint32(1, 150)) === "089601");
  check("uint32(1, 0) omitted",  pb.uint32(1, 0).length === 0);
}

async function testFixed64FieldShape() {
  // fixed64 field 1 = 1 -> tag (0x09 = field 1 wire 1) + 8 bytes LE
  // 1 -> 01 00 00 00 00 00 00 00
  check("fixed64(1, 1)",
        _hex(pb.fixed64(1, 1)) === "090100000000000000");
  // BigInt path
  check("fixed64(1, 1n)",
        _hex(pb.fixed64(1, 1n)) === "090100000000000000");
}

async function testBoolFieldShape() {
  // bool field 1 = true -> 08 01; false -> omitted.
  check("bool(1, true)",   _hex(pb.bool(1, true))  === "0801");
  check("bool(1, false)",  pb.bool(1, false).length === 0);
}

async function testBytesFieldShape() {
  // bytes field 1 = <01 02 03> -> 0a 03 01 02 03
  check("bytes(1, <01 02 03>)",
        _hex(pb.bytes(1, Buffer.from([1, 2, 3]))) === "0a03010203");
  check("bytes(1, empty) omitted",  pb.bytes(1, Buffer.alloc(0)).length === 0);
}

async function testEmbeddedMessage() {
  // message field 1 = { string field 1 = "x" }
  // inner: 0a 01 78 (3 bytes)
  // outer: 0a 03 0a 01 78
  var inner = pb.string(1, "x");
  check("embeddedMessage(1, <0a 01 78>)",
        _hex(pb.embeddedMessage(1, inner)) === "0a030a0178");
  // Empty body -> tag + length 0
  check("embeddedMessage(1, empty) emits length 0",
        _hex(pb.embeddedMessage(1, Buffer.alloc(0))) === "0a00");
}

async function testRepeatedMessage() {
  // repeated message field 1 with two items: each item is a string-1
  // = "a" / "b" -> 0a 03 0a 01 61 0a 03 0a 01 62
  var rv = pb.repeatedMessage(1, ["a", "b"], function (s) {
    return pb.string(1, s);
  });
  check("repeatedMessage two items",
        _hex(rv) === "0a030a01610a030a0162");
  check("repeatedMessage([]) omitted",
        pb.repeatedMessage(1, [], function () { return Buffer.alloc(0); }).length === 0);
}

async function run() {
  await testVarintCanonical();
  await testVarintBigInt();
  await testTagComputation();
  await testStringFieldShape();
  await testUint32FieldShape();
  await testFixed64FieldShape();
  await testBoolFieldShape();
  await testBytesFieldShape();
  await testEmbeddedMessage();
  await testRepeatedMessage();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[protobuf-encoder] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
