"use strict";
/**
 * Layer 0 — b.structuredFields full RFC 8941 codec (parse + serialize).
 * The oracle is a curated set of the official httpwg/structured-field-tests
 * conformance vectors (the same JSON the spec authors maintain): each
 * `raw` parses to the published `expected` value model, each `must_fail`
 * case is rejected, and every passing value round-trips through serialize.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
var SF = b.structuredFields;

// --- httpwg expected-value normaliser (their format → comparable JSON) ---
function b32(buf) {
  var A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", bits = 0, val = 0, out = "";
  for (var i = 0; i < buf.length; i++) { val = (val << 8) | buf[i]; bits += 8; while (bits >= 5) { out += A[(val >> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += A[(val << (5 - bits)) & 31];
  while (out.length % 8 !== 0) out += "=";
  return out;
}
function mineVal(v) {
  if (v instanceof SF.Token) return { token: v.value };
  if (v instanceof SF.ByteSequence) return { binary: b32(v.value) };
  if (v instanceof SF.Decimal) return v.value;   // compare a Decimal numerically (httpwg uses plain numbers)
  if (v instanceof SF.Date) return { date: v.value };
  if (v instanceof SF.DisplayString) return { displaystring: v.value };
  return v;
}
function mineParams(map) { var o = []; map.forEach(function (v, k) { o.push([k, mineVal(v)]); }); return o; }
function mineItem(it) { return [mineVal(it.value), mineParams(it.params)]; }
function mineMember(m) { return Array.isArray(m.items) ? [m.items.map(mineItem), mineParams(m.params)] : mineItem(m); }
function mine(out, type) {
  if (type === "item") return mineItem(out);
  if (type === "list") return out.map(mineMember);
  var o = []; out.forEach(function (m, k) { o.push([k, mineMember(m)]); }); return o;
}
function httpVal(v) {
  if (v && v.__type === "token") return { token: v.value };
  if (v && v.__type === "binary") return { binary: v.value };
  if (v && v.__type === "date") return { date: v.value };
  if (v && v.__type === "displaystring") return { displaystring: v.value };
  return v;
}
function httpParams(arr) { return arr.map(function (p) { return [p[0], httpVal(p[1])]; }); }
function httpItem(it) { return [httpVal(it[0]), httpParams(it[1])]; }
function httpMember(m) { return Array.isArray(m[0]) ? [m[0].map(httpItem), httpParams(m[1])] : httpItem(m); }
function http(exp, type) {
  if (type === "item") return httpItem(exp);
  if (type === "list") return exp.map(httpMember);
  return exp.map(function (e) { return [e[0], httpMember(e[1])]; });
}

// Curated cases from httpwg/structured-field-tests (number, string, token,
// boolean, binary, item, list, dictionary, param-list).
var CASES = [
  { name: "basic integer", raw: "42", t: "item", expected: [42, []] },
  { name: "negative integer", raw: "-42", t: "item", expected: [-42, []] },
  { name: "negative zero", raw: "-0", t: "item", expected: [0, []] },
  { name: "basic decimal", raw: "1.5", t: "item", expected: [1.5, []] },
  { name: "negative decimal", raw: "-1.5", t: "item", expected: [-1.5, []] },
  { name: "too many int digits", raw: "1111111111111111", t: "item", must_fail: true },
  { name: "trailing decimal point", raw: "1.", t: "item", must_fail: true },
  { name: "too many frac digits", raw: "1.1234", t: "item", must_fail: true },
  { name: "basic string", raw: '"foo bar"', t: "item", expected: ["foo bar", []] },
  { name: "empty string", raw: '""', t: "item", expected: ["", []] },
  { name: "escaped quote", raw: '"b\\"a"', t: "item", expected: ['b"a', []] },
  { name: "unterminated string", raw: '"foo', t: "item", must_fail: true },
  { name: "basic token", raw: "a_b-c.d3:f%00/*", t: "item", expected: [{ __type: "token", value: "a_b-c.d3:f%00/*" }, []] },
  { name: "token with capitals", raw: "fooBar", t: "item", expected: [{ __type: "token", value: "fooBar" }, []] },
  { name: "true boolean", raw: "?1", t: "item", expected: [true, []] },
  { name: "false boolean", raw: "?0", t: "item", expected: [false, []] },
  { name: "unknown boolean", raw: "?Q", t: "item", must_fail: true },
  { name: "basic binary", raw: ":aGVsbG8=:", t: "item", expected: [{ __type: "binary", value: "NBSWY3DP" }, []] },
  { name: "empty binary", raw: "::", t: "item", expected: [{ __type: "binary", value: "" }, []] },
  { name: "unpadded binary (RFC 8941 §4.2.7 synthesizes padding)", raw: ":aGVsbG8:", t: "item", expected: [{ __type: "binary", value: "NBSWY3DP" }, []] },
  { name: "padding at beginning", raw: ":=aGVsbG8=:", t: "item", must_fail: true },
  { name: "empty item", raw: "", t: "item", must_fail: true },
  { name: "leading space item", raw: " \t 1", t: "item", must_fail: true },
  { name: "trailing space item", raw: "1 \t ", t: "item", must_fail: true },
  { name: "item with param", raw: "5; foo=bar", t: "item", expected: [5, [["foo", { __type: "token", value: "bar" }]]] },
  { name: "boolean param value", raw: "1; a; b=?0", t: "item", expected: [1, [["a", true], ["b", false]]] },
  { name: "basic list", raw: "1, 42", t: "list", expected: [[1, []], [42, []]] },
  { name: "empty list", raw: "", t: "list", expected: [] },
  { name: "basic inner list", raw: "(1 2)", t: "list", expected: [[[[1, []], [2, []]], []]] },
  { name: "inner list with params", raw: "(1 2);a=1", t: "list", expected: [[[[1, []], [2, []]], [["a", 1]]]] },
  { name: "trailing comma list", raw: "1, 42, ", t: "list", must_fail: true },
  { name: "basic dictionary", raw: "a=1, b=2", t: "dictionary", expected: [["a", [1, []]], ["b", [2, []]]] },
  { name: "dictionary bare key", raw: "a=1, b, c=3", t: "dictionary", expected: [["a", [1, []]], ["b", [true, []]], ["c", [3, []]]] },
  { name: "dictionary inner-list value", raw: "a=(1 2)", t: "dictionary", expected: [["a", [[[1, []], [2, []]], []]]] },
  { name: "trailing comma dict", raw: "a=1,", t: "dictionary", must_fail: true },
  // RFC 9651 Date (§3.3.7)
  { name: "date epoch", raw: "@0", t: "item", expected: [{ __type: "date", value: 0 }, []] },
  { name: "date positive", raw: "@1659578233", t: "item", expected: [{ __type: "date", value: 1659578233 }, []] },
  { name: "date negative", raw: "@-1659578233", t: "item", expected: [{ __type: "date", value: -1659578233 }, []] },
  { name: "date decimal", raw: "@1659578233.12", t: "item", must_fail: true },
  { name: "date too large", raw: "@1000000000000000", t: "item", must_fail: true },
  { name: "date empty", raw: "@", t: "item", must_fail: true },
  { name: "date sign only", raw: "@-", t: "item", must_fail: true },
  { name: "date non-digit", raw: "@abc", t: "item", must_fail: true },
  // RFC 9651 Display String (§3.3.8)
  { name: "ascii display string", raw: '%"foo bar"', t: "item", expected: [{ __type: "displaystring", value: "foo bar" }, []] },
  { name: "non-ascii display string (lowercase escaping)", raw: '%"f%c3%bc%c3%bc"', t: "item", expected: [{ __type: "displaystring", value: "füü" }, []] },
  { name: "non-ascii display string (uppercase escaping)", raw: '%"f%C3%BC"', t: "item", must_fail: true },
  { name: "non-ascii display string (unescaped)", raw: '%"füü"', t: "item", must_fail: true },
  { name: "display string quoting", raw: '%"foo %22bar%22 \\ baz"', t: "item", expected: [{ __type: "displaystring", value: 'foo "bar" \\ baz' }, []] },
  { name: "bad display string utf-8", raw: '%"%c3%28"', t: "item", must_fail: true },
  { name: "bad display string hex", raw: '%"%g0%1w"', t: "item", must_fail: true },
  { name: "truncated display string escape", raw: '%"%"', t: "item", must_fail: true },
  { name: "unbalanced display string", raw: '%"foo', t: "item", must_fail: true },
  { name: "single-quoted display string", raw: "%'foo'", t: "item", must_fail: true },
];

function testConformance() {
  var passed = 0, failed = 0, roundtrips = 0;
  CASES.forEach(function (c) {
    if (c.must_fail) {
      var threw = false;
      try { SF.parse(c.raw, c.t); } catch (_e) { threw = true; }
      if (threw) failed++; else check("must_fail rejected: " + c.name, false);
      return;
    }
    var got;
    try { got = SF.parse(c.raw, c.t); }
    catch (_e) { check("parse ok: " + c.name, false); return; }
    var ok = JSON.stringify(mine(got, c.t)) === JSON.stringify(http(c.expected, c.t));
    if (ok) passed++; else check("value matches RFC vector: " + c.name + " (got " + JSON.stringify(mine(got, c.t)) + ")", false);
    // Round-trip: serialize → parse → serialize must be stable.
    try {
      var s1 = SF.serialize(got, c.t);
      var s2 = SF.serialize(SF.parse(s1, c.t), c.t);
      if (s1 === s2) roundtrips++; else check("round-trip stable: " + c.name + " (" + s1 + " vs " + s2 + ")", false);
    } catch (e) { check("round-trip ok: " + c.name + " — " + e.message, false); }
  });
  check("all passing vectors parse to the RFC value model (" + passed + ")", passed === CASES.filter(function (c) { return !c.must_fail; }).length);
  check("all must_fail vectors are rejected (" + failed + ")", failed === CASES.filter(function (c) { return c.must_fail; }).length);
  check("all passing vectors round-trip stably (" + roundtrips + ")", roundtrips === passed);
}

function testSerialize() {
  check("serialize: token item with param", SF.serialize({ value: new SF.Token("gzip"), params: new Map([["q", 1]]) }, "item") === "gzip;q=1");
  check("serialize: string item", SF.serialize({ value: "a b", params: new Map() }, "item") === '"a b"');
  check("serialize: byte sequence", SF.serialize({ value: new SF.ByteSequence(Buffer.from("hello")), params: new Map() }, "item") === ":aGVsbG8=:");
  check("serialize: list of inner list", SF.serialize([{ items: [{ value: 1, params: new Map() }, { value: 2, params: new Map() }], params: new Map() }], "list") === "(1 2)");
  check("serialize: dictionary from object", SF.serialize({ a: { value: 1, params: new Map() }, b: { value: true, params: new Map() } }, "dictionary") === "a=1, b");
  function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
  check("serialize: out-of-range integer refused", code(function () { SF.serialize({ value: 10000000000000000, params: new Map() }, "item"); }) === "structured-fields/serialize");
  check("serialize: invalid token refused", code(function () { SF.serialize({ value: new SF.Token("1bad"), params: new Map() }, "item"); }) === "structured-fields/serialize");
}

function testDecimalTypePreserved() {
  // A numerically-integral Decimal must NOT serialize back to an Integer.
  var parsed = SF.parse("1.0", "item");
  check("parse: '1.0' yields a Decimal (not a bare integer)", parsed.value instanceof SF.Decimal);
  check("serialize: Decimal 1.0 round-trips to '1.0', not '1'", SF.serialize(parsed, "item") === "1.0");
  check("serialize: explicit SfDecimal forces the decimal form", SF.serialize({ value: new SF.Decimal(5), params: new Map() }, "item") === "5.0");
  check("serialize: a fractional JS number still serializes as a Decimal", SF.serialize({ value: 2.5, params: new Map() }, "item") === "2.5");
  check("serialize: an integral JS number serializes as an Integer", SF.serialize({ value: 5, params: new Map() }, "item") === "5");
}

function testDisplayStringSurrogate() {
  function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
  // A lone UTF-16 surrogate is not a valid Unicode string — serialize must
  // fail rather than silently emit U+FFFD (RFC 9651 §4.1.10).
  check("serialize: lone surrogate display string refused", code(function () { SF.serialize({ value: new SF.DisplayString("a\uD800b"), params: new Map() }, "item"); }) === "structured-fields/serialize");
  // A valid astral code point (surrogate pair) serializes fine.
  check("serialize: astral code point display string ok", SF.serialize({ value: new SF.DisplayString("\u{1F600}"), params: new Map() }, "item") === '%"%f0%9f%98%80"');
}

function testTypedError() {
  function E(code, msg) { this.code = code; this.message = msg; }
  E.prototype = Object.create(Error.prototype);
  var threw = null;
  try { SF.parse("1.", "item", { ErrorClass: E }); } catch (e) { threw = e; }
  check("parse: typed ErrorClass honored", threw instanceof E && threw.code === "structured-fields/parse");
}

function testSurface() {
  // Reference the full b.structuredFields.* paths so the coverage gate
  // sees them (the suite otherwise uses the SF alias).
  check("b.structuredFields.parse parses an item", b.structuredFields.parse("42", "item").value === 42);
  check("b.structuredFields.serialize round-trips an item", b.structuredFields.serialize({ value: 42, params: new Map() }, "item") === "42");
  check("b.structuredFields.Token constructs a token", new b.structuredFields.Token("gzip").value === "gzip");
  check("b.structuredFields.ByteSequence constructs a byte sequence", Buffer.isBuffer(new b.structuredFields.ByteSequence(Buffer.from("x")).value));
  check("b.structuredFields.Decimal constructs a decimal", new b.structuredFields.Decimal(1.5).value === 1.5);
  check("b.structuredFields.Date round-trips", b.structuredFields.serialize({ value: new b.structuredFields.Date(1659578233), params: new Map() }, "item") === "@1659578233");
  check("b.structuredFields.DisplayString escapes non-ASCII", b.structuredFields.serialize({ value: new b.structuredFields.DisplayString("füü"), params: new Map() }, "item") === '%"f%c3%bc%c3%bc"');
}

async function run() {
  testSurface();
  testConformance();
  testSerialize();
  testDecimalTypePreserved();
  testDisplayStringSurrogate();
  testTypedError();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[structured-fields-codec] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
