"use strict";
/**
 * b._internal asn1-der walker — minimal DER parser used by the OCSP
 * + (future) CT SCT verifiers. Covers the shapes the framework reads:
 * SEQUENCE / OID / OCTET STRING / INTEGER / BIT STRING / context-
 * specific [N] EXPLICIT.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var asn1    = require("../../lib/asn1-der");

function testReadNodeShortFormLength() {
  // SEQUENCE { INTEGER 5 } — tag 0x30, len 0x03, content 0x02 0x01 0x05.
  var buf = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x05]);
  var node = asn1.readNode(buf);
  check("readNode: SEQUENCE tag",
        node.tag === asn1.TAG.SEQUENCE && node.constructed);
  check("readNode: length",   node.length === 3);
  check("readNode: totalLength includes 2-byte header",
        node.totalLength === 5);
}

function testReadOid() {
  // OID 1.2.840.113549.1.1.11 — sha256WithRSAEncryption.
  var buf = Buffer.from([
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
  ]);
  var node = asn1.readNode(buf);
  var oid = asn1.readOid(node);
  check("readOid decodes sha256WithRSAEncryption",
        oid === "1.2.840.113549.1.1.11");
}

function testReadSequence() {
  // SEQUENCE { INTEGER 1, INTEGER 2 }
  var buf = Buffer.from([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
  var top = asn1.readNode(buf);
  var children = asn1.readSequence(top.value);
  check("readSequence: 2 children",
        children.length === 2 &&
        asn1.readUnsignedInt(children[0]) === 1 &&
        asn1.readUnsignedInt(children[1]) === 2);
}

function testReadOctetString() {
  // OCTET STRING [0xab, 0xcd]
  var buf = Buffer.from([0x04, 0x02, 0xab, 0xcd]);
  var node = asn1.readNode(buf);
  var oct = asn1.readOctetString(node);
  check("readOctetString",
        Buffer.compare(oct, Buffer.from([0xab, 0xcd])) === 0);
}

function testReadBitString() {
  // BIT STRING { 0 unused bits, then 0xab 0xcd }
  var buf = Buffer.from([0x03, 0x03, 0x00, 0xab, 0xcd]);
  var node = asn1.readNode(buf);
  var bits = asn1.readBitString(node);
  check("readBitString strips unused-bits byte",
        Buffer.compare(bits, Buffer.from([0xab, 0xcd])) === 0);
}

function testIndefiniteLengthRefused() {
  // 0x30 0x80 (indefinite-length form) — DER forbids.
  var buf = Buffer.from([0x30, 0x80, 0x00, 0x00]);
  var threw = null;
  try { asn1.readNode(buf); } catch (e) { threw = e; }
  check("indefinite-length form throws asn1/indefinite-length",
        threw && /indefinite-length/.test(threw.code || threw.message || ""));
}

function testTruncatedRefused() {
  // 0x30 0x05 ... but only 2 content bytes follow.
  var buf = Buffer.from([0x30, 0x05, 0x02, 0x01]);
  var threw = null;
  try { asn1.readNode(buf); } catch (e) { threw = e; }
  check("truncated value throws asn1/short",
        threw && /short/.test(threw.code || threw.message || ""));
}

function testUnwrapExplicit() {
  // [0] EXPLICIT INTEGER 7  →  tag 0xa0, len 3, then INTEGER 7.
  var buf = Buffer.from([0xa0, 0x03, 0x02, 0x01, 0x07]);
  var outer = asn1.readNode(buf);
  var inner = asn1.unwrapExplicit(outer, 0);
  check("unwrapExplicit unwraps [0] context tag",
        inner.tag === asn1.TAG.INTEGER &&
        asn1.readUnsignedInt(inner) === 7);
}

async function run() {
  testReadNodeShortFormLength();
  testReadOid();
  testReadSequence();
  testReadOctetString();
  testReadBitString();
  testIndefiniteLengthRefused();
  testTruncatedRefused();
  testUnwrapExplicit();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
