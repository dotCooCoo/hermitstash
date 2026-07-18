// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.cbor bounded deterministic CBOR codec (RFC 8949).
 * Encoder validated against RFC 8949 Appendix A vectors + §4.2
 * deterministic encoding; decoder validated against the bounded
 * refusals (depth / size / indefinite-length / reserved-ai / tag /
 * duplicate-key / trailing-byte / non-canonical).
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
var cbor = b.cbor;

function _hex(buf) { return Buffer.from(buf).toString("hex"); }

function testSurface() {
  // Reference every export through the public b.cbor.* path (the
  // coverage gate matches the dotted form).
  check("b.cbor.encode exposed", typeof b.cbor.encode === "function");
  check("b.cbor.decode exposed", typeof b.cbor.decode === "function");
  check("b.cbor.Tag exposed", typeof b.cbor.Tag === "function");
  check("b.cbor.CborError exposed", typeof b.cbor.CborError === "function");
  var rt = b.cbor.decode(b.cbor.encode(new b.cbor.Tag(0, "x")), { allowedTags: [0] });
  check("b.cbor round-trips a tag via the public path", rt instanceof b.cbor.Tag && rt.value === "x");
  var err = null;
  try { b.cbor.decode(Buffer.from([0x9f, 0x01, 0xff])); } catch (e) { err = e; }
  check("b.cbor.CborError is thrown on bad input", err instanceof b.cbor.CborError);
}

function testAppendixAVectors() {
  // RFC 8949 Appendix A.
  var vectors = [
    [0, "00"], [1, "01"], [10, "0a"], [23, "17"], [24, "1818"], [100, "1864"],
    [1000, "1903e8"], [-1, "20"], [-100, "3863"], [1000000, "1a000f4240"],
    [false, "f4"], [true, "f5"], [null, "f6"],
    ["", "60"], ["a", "6161"], ["IETF", "6449455446"], ["ü", "62c3bc"],
    [[], "80"], [[1, 2, 3], "83010203"], [[1, [2, 3], [4, 5]], "8301820203820405"],
  ];
  var ok = true;
  for (var i = 0; i < vectors.length; i++) {
    var got = _hex(cbor.encode(vectors[i][0]));
    if (got !== vectors[i][1]) { ok = false; check("vector " + JSON.stringify(vectors[i][0]) + " → " + vectors[i][1] + " (got " + got + ")", false); }
  }
  check("encode: matches RFC 8949 Appendix A integer/string/array vectors", ok);
  check("encode: bytes h'01020304' → 4401020304", _hex(cbor.encode(Buffer.from([1, 2, 3, 4]))) === "4401020304");
  // Preferred float serialization (§4.2.1): shortest width that
  // round-trips. 1.5 fits float16; an integer-valued float is encoded
  // as an integer (deterministic encoding prefers the shortest form).
  check("encode: float 1.5 → f93e00 (preferred half)", _hex(cbor.encode(1.5)) === "f93e00");
  check("encode: 100000 → integer, not float", _hex(cbor.encode(100000)) === "1a000186a0");
  check("encode: 3.4 → float64 (not half/float32 representable)", _hex(cbor.encode(3.4)) === "fb400b333333333333");
  check("encode: map {1:2,3:4} (int keys) → a201020304", _hex(cbor.encode(new Map([[1, 2], [3, 4]]))) === "a201020304");
  check("encode: nested {a:1,b:[2,3]} → a26161016162820203", _hex(cbor.encode({ a: 1, b: [2, 3] })) === "a26161016162820203");
}

function testDeterministicEncoding() {
  // §4.2 — map keys sorted by encoded-key bytes regardless of order.
  check("deterministic: map key order is normalized", _hex(cbor.encode({ b: 2, a: 1 })) === _hex(cbor.encode({ a: 1, b: 2 })));
  check("deterministic: shortest-form integer head", _hex(cbor.encode(24)) === "1818" && _hex(cbor.encode(23)) === "17");
  // Duplicate key on encode (a Map can hold structurally-equal encoded keys only via distinct JS keys — guard the explicit case).
  var dup = null;
  try { cbor.encode(new Map([["a", 1]])); } catch (e) { dup = e; }
  check("deterministic: well-formed map encodes", dup === null);
}

function testRoundTrip() {
  var value = { id: 7, tags: ["x", "y"], meta: new Map([[1, "alg"], [2, Buffer.from([0xab])]]), ok: true, n: null };
  var decoded = cbor.decode(cbor.encode(value));
  check("round-trip: top-level map decodes to Map", decoded instanceof Map);
  check("round-trip: scalar + array + nested preserved",
    decoded.get("id") === 7 && decoded.get("tags")[1] === "y" && decoded.get("ok") === true && decoded.get("n") === null);
  check("round-trip: nested map int keys preserved", decoded.get("meta") instanceof Map && decoded.get("meta").get(1) === "alg");
  check("round-trip: byte string preserved", Buffer.isBuffer(decoded.get("meta").get(2)) && decoded.get("meta").get(2)[0] === 0xab);
  // negative + float + float16 decode
  check("round-trip: negative int", cbor.decode(cbor.encode(-100)) === -100);
  check("round-trip: float64", cbor.decode(cbor.encode(3.14159)) === 3.14159);
  check("decode: float16 (0xf93e00 = 1.5)", cbor.decode(Buffer.from([0xf9, 0x3e, 0x00])) === 1.5);
  // Preferred-width round-trips: each chooses the shortest exact form.
  [1.5, -2.5, 0.5, 3.4, 1e300, 5.960464477539063e-8].forEach(function (n) {
    check("preferred-float round-trip " + n, cbor.decode(cbor.encode(n)) === n);
  });
  // A canonically float16-encoded value passes requireDeterministic
  // (the preferred-serialization fix — float64 emission would falsely
  // reject it).
  check("requireDeterministic: float16-canonical input accepted", cbor.decode(cbor.encode(1.5), { requireDeterministic: true }) === 1.5);
}

function testIntegerBoundary() {
  // RFC 8949 §3 — a negative-int argument up to 2^64-1 is an integer,
  // never a float. The canonical negative integer -2^53 (major 1, 8-byte
  // argument 2^53-1) has a value ONE below the safe-Number range. Decoding
  // it as a plain Number let the deterministic encoder re-emit it as a
  // float (its integer branch is |v| <= 2^53-1), which broke round-trip
  // and falsely tripped requireDeterministic on a perfectly canonical
  // integer. It must decode to a BigInt that re-encodes byte-identically.
  var negPow53 = Buffer.from([0x3b, 0x00, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
  var decoded = cbor.decode(negPow53);
  check("decode: canonical -2^53 decodes as an exact integer (BigInt)",
    typeof decoded === "bigint" && decoded === -9007199254740992n);
  check("round-trip: -2^53 re-encodes to the integer head, not a float",
    _hex(cbor.encode(decoded)) === "3b001fffffffffffff");
  var reject = null;
  try { cbor.decode(negPow53, { requireDeterministic: true }); } catch (e) { reject = e; }
  check("requireDeterministic: canonical integer -2^53 is accepted", reject === null);
  // The neighbour -(2^53-1) = MIN_SAFE_INTEGER stays a Number and round-trips.
  var minSafe = Buffer.from([0x3b, 0x00, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe]);
  var mn = cbor.decode(minSafe);
  check("decode: MIN_SAFE_INTEGER stays a Number and round-trips",
    mn === -9007199254740991 && _hex(cbor.encode(mn)) === "3b001ffffffffffffe");
}

function testInvalidUtf8() {
  // CBOR text strings must be valid UTF-8 (§3.1) — malformed bytes are
  // refused, not silently replaced with U+FFFD.
  var bad = null;
  try { cbor.decode(Buffer.from([0x63, 0xff, 0xff, 0xff])); } catch (e) { bad = e; }   // text(3) + invalid bytes
  check("decode: invalid UTF-8 text string refused", bad && bad.code === "cbor/invalid-utf8");
  check("decode: valid multibyte UTF-8 preserved", cbor.decode(cbor.encode("héllo ☃")) === "héllo ☃");
}

function testTags() {
  var enc = cbor.encode(new cbor.Tag(42, "answer"));
  check("encode: tagged value", _hex(enc) === "d82a66616e73776572");
  var refused = null;
  try { cbor.decode(enc); } catch (e) { refused = e; }
  check("decode: tag refused unless allowlisted", refused && refused.code === "cbor/tag-refused");
  var t = cbor.decode(enc, { allowedTags: [42] });
  check("decode: allowlisted tag returns Tag", t instanceof cbor.Tag && t.tag === 42 && t.value === "answer");
}

function testBoundedRefusals() {
  var cases = [
    ["indefinite array", Buffer.from([0x9f, 0x01, 0xff]), {}, "cbor/indefinite-refused"],
    ["reserved ai-28", Buffer.from([0x1c]), {}, "cbor/reserved-ai"],
    ["duplicate map key", Buffer.from([0xa2, 0x01, 0x02, 0x01, 0x03]), {}, "cbor/duplicate-key"],
    ["trailing bytes", Buffer.from([0x01, 0x02]), {}, "cbor/trailing-bytes"],
    ["truncated head", Buffer.from([0x18]), {}, "cbor/truncated"],
    ["length bomb (no data)", Buffer.from([0x9a, 0xff, 0xff, 0xff, 0xff]), {}, "cbor/truncated"],
    ["bad simple value (major 7, ai 28)", Buffer.from([0xfc]), {}, "cbor/bad-simple"],
  ];
  var ok = true;
  for (var i = 0; i < cases.length; i++) {
    var caught = null;
    try { cbor.decode(cases[i][1], cases[i][2]); } catch (e) { caught = e; }
    if (!caught || caught.code !== cases[i][3]) { ok = false; check(cases[i][0] + " expected " + cases[i][3] + " got " + (caught && caught.code), false); }
  }
  check("decode: bounded refusals fire with the right codes", ok);

  var depth = null;
  try { cbor.decode(cbor.encode([[[[[1]]]]]), { maxDepth: 2 }); } catch (e) { depth = e; }
  check("decode: maxDepth refuses over-deep nesting", depth && depth.code === "cbor/max-depth");

  var big = null;
  try { cbor.decode(cbor.encode([1, 2, 3, 4, 5]), { maxBytes: 2 }); } catch (e) { big = e; }
  check("decode: maxBytes refuses oversize input", big && big.code === "cbor/too-large");
}

function testRequireDeterministic() {
  // Long-form encoding of 1 (0x1801) is valid CBOR but non-canonical.
  var nonCanon = null;
  try { cbor.decode(Buffer.from([0x18, 0x01]), { requireDeterministic: true }); } catch (e) { nonCanon = e; }
  check("requireDeterministic: non-canonical long-form refused", nonCanon && nonCanon.code === "cbor/not-deterministic");
  // A canonical encoding round-trips through the determinism check.
  var d = cbor.decode(cbor.encode({ a: 1, b: 2 }), { requireDeterministic: true });
  check("requireDeterministic: canonical input accepted", d.get("a") === 1 && d.get("b") === 2);
  // Lenient decode (default) accepts the long form.
  check("decode: non-canonical accepted without requireDeterministic", cbor.decode(Buffer.from([0x18, 0x01])) === 1);
}

function testInputValidation() {
  var e1 = null;
  try { cbor.decode("not a buffer"); } catch (e) { e1 = e; }
  check("decode: non-buffer input refused", e1 && e1.code === "cbor/bad-input");
  var e2 = null;
  try { cbor.encode(function () {}); } catch (e) { e2 = e; }
  check("encode: unencodable value refused", e2 && e2.code === "cbor/unencodable");
  var e3 = null;
  try { cbor.encode(NaN); } catch (e) { e3 = e; }
  check("encode: NaN refused by default", e3 && e3.code === "cbor/non-finite");
  check("encode: NaN emitted under allowNonFinite", Buffer.isBuffer(cbor.encode(NaN, { allowNonFinite: true })));
}

function run() {
  testSurface();
  testAppendixAVectors();
  testDeterministicEncoding();
  testRoundTrip();
  testIntegerBoundary();
  testInvalidUtf8();
  testTags();
  testBoundedRefusals();
  testRequireDeterministic();
  testInputValidation();
}

module.exports = { run: run };

if (require.main === module) {
  run();
  console.log("[cbor] OK — " + helpers.getChecks() + " checks passed");
}
