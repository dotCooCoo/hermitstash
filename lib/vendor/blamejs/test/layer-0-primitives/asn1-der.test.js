// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b._internal asn1-der walker — minimal DER parser used by the OCSP
 * + (future) CT SCT verifiers. Covers the shapes the framework reads:
 * SEQUENCE / OID / OCTET STRING / INTEGER / BIT STRING / context-
 * specific [N] EXPLICIT.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;
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

function testOidFirstSubidMultibyte() {
  // OID 2.999 — first subidentifier = 40*2 + 999 = 1079, which is 0x88 0x37
  // in base-128 (DER 06 02 88 37). A single-byte first-subid decoder reads
  // it as "2.56.55"; a single-byte encoder truncates "2.999" to one octet
  // and round-trips to "1.15".
  var der = Buffer.from([0x06, 0x02, 0x88, 0x37]);
  check("readOid: 2.999 (multi-byte first subidentifier) decodes correctly",
        asn1.readOid(asn1.readNode(der)) === "2.999");
  var enc = asn1.writeOid("2.999");
  check("writeOid: 2.999 round-trips through readOid",
        asn1.readOid(asn1.readNode(enc)) === "2.999");
  check("writeOid: 2.999 emits the canonical 06 02 88 37",
        Buffer.compare(enc, der) === 0);
}

function testOidNonMinimalRejected() {
  // 06 04 2a 80 86 48 — the third subidentifier (840) carries a leading
  // 0x80 continuation octet, which X.690 §8.19.2 forbids in DER. It would
  // otherwise alias "1.2.840".
  var der = Buffer.from([0x06, 0x04, 0x2a, 0x80, 0x86, 0x48]);
  var threw = null;
  try { asn1.readOid(asn1.readNode(der)); } catch (e) { threw = e; }
  check("readOid: non-minimal (leading 0x80) subidentifier is refused",
        threw && threw.code === "asn1/oid-non-minimal");
}

function testHighTagNumberNoOverflow() {
  // 1f ff ff ff ff 7f 00 — high-tag-number form, five 7-bit octets =
  // 0x7ffffffff = 34359738367. A `tag << 7` accumulator overflows 32-bit
  // signed int and yields a negative/wrong tag; base-128 multiplication
  // keeps it correct.
  var node = asn1.readNode(Buffer.from([0x1f, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00]));
  check("readNode: high-tag-number does not overflow to a negative tag",
        node.tag === 34359738367);
  // A genuinely oversized tag (well past 2^53) must be refused, not wrap.
  var huge = Buffer.from([0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00]);
  var threw = null;
  try { asn1.readNode(huge); } catch (e) { threw = e; }
  check("readNode: tag past MAX_SAFE_INTEGER is refused",
        threw && threw.code === "asn1/tag-too-large");
}

function testNonMinimalLongFormLengthRejected() {
  // X.690 §10.1: DER requires the MINIMUM number of length octets. A short-
  // formable length (< 128) encoded in long form is non-minimal BER, not DER.
  // 0x30 0x81 0x03 0x02 0x01 0x05 encodes length 3 in a 2-octet long form
  // where the single short-form octet 0x03 is required. The parser rejects
  // every other BER-ism (indefinite length, non-minimal OID subidentifiers,
  // non-minimal high-tag-number tags), so it must reject this one too.
  var buf = Buffer.from([0x30, 0x81, 0x03, 0x02, 0x01, 0x05]);
  var threw = null;
  try { asn1.readNode(buf); } catch (e) { threw = e; }
  check("readNode: non-minimal long-form length (0x81 0x03) is refused",
        threw && threw.code === "asn1/length-non-minimal");
}

function testLeadingZeroLengthOctetRejected() {
  // 0x82 0x00 0x7f encodes length 127 with a leading-zero length octet — a
  // strict-DER parser refuses the redundant octet (short form 0x7f is
  // required). Aliases a value to two distinct wire encodings otherwise.
  var body = Buffer.alloc(127, 0xaa);
  var buf = Buffer.concat([Buffer.from([0x04, 0x82, 0x00, 0x7f]), body]);
  var threw = null;
  try { asn1.readNode(buf); } catch (e) { threw = e; }
  check("readNode: leading-zero length octet (0x82 0x00 0x7f) is refused",
        threw && threw.code === "asn1/length-non-minimal");
}

function testMinimalLongFormLengthAccepted() {
  // Control: a genuinely long value (300 bytes) needs the 3-octet long form
  // 0x82 0x01 0x2c, which IS minimal — the strictness check must NOT reject
  // it. Guards against a fix that over-rejects legitimate long-form DER.
  var body = Buffer.alloc(300, 0xbb);
  var octet = asn1.writeOctetString(body);        // encoder emits 04 82 01 2c ...
  var node = asn1.readNode(octet);
  check("readNode: minimal long-form length (0x82 0x01 0x2c) is accepted",
        node.length === 300 && Buffer.compare(asn1.readOctetString(node), body) === 0);
  // Boundary: length 128 is the first value that REQUIRES long form (short
  // form maxes at 127); 0x81 0x80 is minimal and must be accepted.
  var body128 = Buffer.alloc(128, 0xcc);
  var octet128 = asn1.writeOctetString(body128);  // 04 81 80 ...
  check("readNode: minimal long-form at the 128-byte boundary is accepted",
        asn1.readNode(octet128).length === 128);
  // Boundary: length 127 is the last short-form value; must round-trip.
  var body127 = Buffer.alloc(127, 0xdd);
  check("readNode: short-form length 127 is accepted",
        asn1.readNode(asn1.writeOctetString(body127)).length === 127);
}

function testCmsDecodeRefusesNonMinimalLength() {
  // Consumer path: b.cms.decode routes the top-level ContentInfo through
  // readNode. A non-minimal outer SEQUENCE length must be refused as
  // cms/bad-asn1 rather than silently parsed — otherwise a BER/DER parser-
  // differential encoding of an attacker-supplied CMS is accepted.
  var inner = Buffer.concat([
    asn1.writeOid("1.2.840.113549.1.7.1"),
    asn1.writeContextExplicit(0, asn1.writeNull()),
  ]);
  // Canonical short-form outer length would be one octet; force long form.
  var nonMinimal = Buffer.concat([Buffer.from([0x30, 0x81, inner.length]), inner]);
  var threw = null;
  try { b.cms.decode(nonMinimal); } catch (e) { threw = e; }
  check("b.cms.decode: non-minimal ContentInfo length is refused (cms/bad-asn1)",
        threw && threw.code === "cms/bad-asn1");
  // Control: the DER-minimal encoding of the same ContentInfo still decodes.
  var canonical = asn1.writeNode(0x30, inner);
  check("b.cms.decode: the DER-minimal ContentInfo still decodes",
        b.cms.decode(canonical).contentType === "1.2.840.113549.1.7.1");
}

async function run() {
  testReadNodeShortFormLength();
  testReadOid();
  testOidFirstSubidMultibyte();
  testOidNonMinimalRejected();
  testHighTagNumberNoOverflow();
  testNonMinimalLongFormLengthRejected();
  testLeadingZeroLengthOctetRejected();
  testMinimalLongFormLengthAccepted();
  testCmsDecodeRefusesNonMinimalLength();
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
