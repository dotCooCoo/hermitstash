// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.parsers.yaml — error-path and adversarial-branch coverage.
 *
 * Companion to the happy-path yaml checks in test/00-primitives.js
 * (string/number/bool/null scalars, block+flow collections, block
 * scalars, quoted strings, and the headline security rejections). This
 * file drives the branches those tests leave uncovered: opt-shape
 * refusals, wrong-input-type rejection, the resource caps (maxBytes /
 * maxKeys / maxDepth for both block and flow nesting), the full escape-
 * error family, the flow-parse error surface, block-scalar header
 * refusals, the prototype-pollution key guard across every key-decode
 * path, and the core-schema float edges (.inf / -.inf / .nan) that the
 * smoke happy-path never exercises.
 *
 * Every assertion runs offline through the public b.parsers.yaml.parse
 * consumer path — no private internals, no live backend.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var yaml = b.parsers.yaml;

// Capture the SafeYamlError code from a synchronous parse throw. Returns
// the literal string "NO-THROW" when parse returns a value, so a missing
// rejection fails the check loudly rather than silently matching.
function _code(src, opts) {
  try {
    yaml.parse(src, opts);
    return "NO-THROW";
  } catch (e) {
    return (e && e.code) || ("PLAIN:" + (e && e.message));
  }
}

// ---- opt-shape refusals (config-time throw: yaml/bad-opt) ----

function testBadNumericOpts() {
  // maxBytes / maxDepth / maxKeys must each be a positive finite integer.
  // Infinity / NaN / negative / zero / non-integer all silently lift the
  // DoS cap they enforce, so each is rejected at the entry point.
  check("maxBytes=Infinity → bad-opt", _code("a: 1", { maxBytes: Infinity }) === "yaml/bad-opt");
  check("maxBytes=NaN → bad-opt",      _code("a: 1", { maxBytes: NaN }) === "yaml/bad-opt");
  check("maxBytes=-1 → bad-opt",       _code("a: 1", { maxBytes: -1 }) === "yaml/bad-opt");
  check("maxBytes=1.5 → bad-opt",      _code("a: 1", { maxBytes: 1.5 }) === "yaml/bad-opt");
  check("maxBytes=0 → bad-opt",        _code("a: 1", { maxBytes: 0 }) === "yaml/bad-opt");
  check("maxDepth=Infinity → bad-opt", _code("a: 1", { maxDepth: Infinity }) === "yaml/bad-opt");
  check("maxDepth=0 → bad-opt",        _code("a: 1", { maxDepth: 0 }) === "yaml/bad-opt");
  check("maxKeys=NaN → bad-opt",       _code("a: 1", { maxKeys: NaN }) === "yaml/bad-opt");
  check("maxKeys=-5 → bad-opt",        _code("a: 1", { maxKeys: -5 }) === "yaml/bad-opt");
  check("maxKeys=0 → bad-opt",         _code("a: 1", { maxKeys: 0 }) === "yaml/bad-opt");
}

// ---- wrong input type (yaml/wrong-input-type) ----

function testWrongInputType() {
  check("number input rejected",    _code(42) === "yaml/wrong-input-type");
  check("object input rejected",    _code({ a: 1 }) === "yaml/wrong-input-type");
  check("null input rejected",      _code(null) === "yaml/wrong-input-type");
  check("undefined input rejected", _code(undefined) === "yaml/wrong-input-type");
  check("array input rejected",     _code([1, 2]) === "yaml/wrong-input-type");
  check("boolean input rejected",   _code(true) === "yaml/wrong-input-type");
}

function testByteInputsParse() {
  // Buffer / Uint8Array are the accepted non-string shapes — they decode
  // as UTF-8 and parse identically to the string form.
  var fromBuf = yaml.parse(Buffer.from("a: 1\n", "utf8"));
  check("Buffer input parses",     fromBuf.a === 1);
  var fromU8 = yaml.parse(new Uint8Array([0x61, 0x3a, 0x20, 0x31]));  // "a: 1"
  check("Uint8Array input parses", fromU8.a === 1);
}

// ---- resource caps ----

function testTooLargeAndKeys() {
  // maxBytes cap on the whole input.
  check("oversize input → too-large",
        _code("a: " + "x".repeat(4000), { maxBytes: b.constants.BYTES.kib(1) }) === "yaml/too-large");
  // maxKeys cap — the 3rd mapping key trips a 2-key ceiling.
  check("maxKeys exceeded → too-many-keys",
        _code("a: 1\nb: 2\nc: 3", { maxKeys: 2 }) === "yaml/too-many-keys");
}

function testDepthCaps() {
  // Block nesting deeper than maxDepth.
  check("block nesting → too-deep",
        _code("a:\n b:\n  c:\n   d: 1", { maxDepth: 3 }) === "yaml/too-deep");
  // Flow sequence nesting deeper than maxDepth (independent recursion path).
  var deepFlow = "root: " + "[".repeat(10) + "1" + "]".repeat(10);
  check("flow-sequence nesting → too-deep",
        _code(deepFlow, { maxDepth: 3 }) === "yaml/too-deep");
  // Flow mapping nesting also caps.
  var deepMap = "root: " + "{a: ".repeat(10) + "1" + "}".repeat(10);
  check("flow-mapping nesting → too-deep",
        _code(deepMap, { maxDepth: 3 }) === "yaml/too-deep");
}

// ---- banned constructs the smoke set does not reach ----

function testBannedConstructs() {
  check("complex key '? key' → complex-key-banned",
        _code("? key\n: value") === "yaml/complex-key-banned");
  check("%TAG directive → directives-banned",
        _code("%TAG ! tag:example,2000:\n---\na: 1") === "yaml/directives-banned");
  check("'...' end-of-doc marker → multi-document",
        _code("a: 1\n...") === "yaml/multi-document");
  check("bare alias '*a' → aliases-banned",
        _code("a: *ref") === "yaml/aliases-banned");
}

// ---- prototype-pollution key guard, every decode path ----

function testPoisonedKeys() {
  // Block plain key.
  check("block 'constructor:' → poisoned-key",
        _code("constructor: 1") === "yaml/poisoned-key");
  check("block 'prototype:' → poisoned-key",
        _code("prototype: 1") === "yaml/poisoned-key");
  // Double-quoted key that decodes to a poisoned name.
  check("double-quoted '__proto__' key → poisoned-key",
        _code('"__proto__": 1') === "yaml/poisoned-key");
  // Single-quoted key.
  check("single-quoted '__proto__' key → poisoned-key",
        _code("'__proto__': 1") === "yaml/poisoned-key");
  // Flow-mapping key (no space after colon keeps it in flow style).
  check("flow-mapping '__proto__' key → poisoned-key",
        _code("root: {__proto__: 1}") === "yaml/poisoned-key");
  // Compact mapping inside a block sequence item.
  check("compact-sequence 'constructor:' key → poisoned-key",
        _code("- constructor: 1") === "yaml/poisoned-key");
  // Payloads whose whole point is to land a NAMED key ('polluted') on
  // Object.prototype if the __proto__ guard regressed — both must be
  // refused. Without these, the residual assertion below would be vacuous
  // ('polluted' is a probe key nothing else in this test ever injects).
  check("block '__proto__:' with nested key → poisoned-key",
        _code("__proto__:\n  polluted: true") === "yaml/poisoned-key");
  check("flow '__proto__:' with nested key → poisoned-key",
        _code("__proto__: {polluted: true}") === "yaml/poisoned-key");
  // None of the above may have mutated Object.prototype: the injected
  // 'polluted' key must not have reached the prototype chain (`in` walks
  // it), and the constructor + prototype stay intact.
  check("Object.prototype gained no injected key",
        !("polluted" in {}) && Object.getPrototypeOf({}) === Object.prototype);
  check("Object.prototype constructor intact", ({}).constructor === Object);
}

// ---- double-quoted escape errors (yaml/bad-escape) ----

function testEscapeErrors() {
  check("bad \\u hex → bad-escape",       _code('a: "\\uZZZZ"') === "yaml/bad-escape");
  check("short \\u → bad-escape",         _code('a: "\\u12"') === "yaml/bad-escape");
  check("bad \\U hex → bad-escape",       _code('a: "\\UZZZZZZZZ"') === "yaml/bad-escape");
  check("\\U past U+10FFFF → bad-escape", _code('a: "\\UFFFFFFFF"') === "yaml/bad-escape");
  check("unknown escape → bad-escape",    _code('a: "\\q"') === "yaml/bad-escape");
}

function testEscapesDecode() {
  // The printable accepted escape set decodes to the intended chars.
  var d = yaml.parse('a: "x\\ny\\tz\\\\w\\"q\\r\\b\\f\\/p"');
  check("escape set decodes",
        d.a === "x\ny\tz\\w\"q\r\b\f/p");
  // The \0 escape decodes to a real NUL — built via fromCharCode so no
  // raw NUL byte lands in this source file.
  var dz = yaml.parse('a: "A\\0B"');
  check("\\0 decodes to NUL", dz.a === "A" + String.fromCharCode(0) + "B");
  // \u (BMP) and \U (astral) surrogate-pair handling.
  var d2 = yaml.parse('a: "\\u0041\\U0001F600"');
  check("\\u + \\U decode", d2.a === "A\u{1F600}");
}

// ---- unterminated strings (yaml/unterminated-string) ----

function testUnterminatedStrings() {
  check("unterminated double-quoted → unterminated-string",
        _code('a: "no close') === "yaml/unterminated-string");
  check("unterminated single-quoted → unterminated-string",
        _code("a: 'no close") === "yaml/unterminated-string");
  check("unterminated quote inside flow → unterminated-string",
        _code('root: ["abc') === "yaml/unterminated-string");
}

// ---- flow-collection parse errors ----

function testFlowErrors() {
  check("flow mapping missing ':' → bad-flow",
        _code("root: {x 1}") === "yaml/bad-flow");
  check("flow sequence bad separator → bad-flow",
        _code("root: [1 2 junk") === "yaml/bad-flow");
  check("flow sequence trailing comma+EOF → unterminated-flow",
        _code("root: [1,") === "yaml/unterminated-flow");
  check("flow mapping trailing comma+EOF → unterminated-flow",
        _code("root: {a: 1,") === "yaml/unterminated-flow");
}

// ---- block-scalar header refusals (yaml/bad-block-scalar) ----

function testBlockScalarHeaderErrors() {
  check("inline '|-+' (two chomps) → bad-block-scalar",
        _code("a: |-+\n  x") === "yaml/bad-block-scalar");
  check("inline '|23' (two indent digits) → bad-block-scalar",
        _code("a: |23\n  x") === "yaml/bad-block-scalar");
  check("inline '|x' (garbage indicator) → bad-block-scalar",
        _code("a: |x\n  y") === "yaml/bad-block-scalar");
}

function testBlockScalarChomp() {
  // Exercise every chomp branch through the public path.
  var keep = yaml.parse("a: |+\n  line\n\n");
  check("keep chomp retains trailing blanks", keep.a === "line\n\n\n");
  var strip = yaml.parse("a: |-\n  line\n\n");
  check("strip chomp removes trailing newlines", strip.a === "line");
  var foldedStrip = yaml.parse("a: >-\n  one\n  two\n");
  check("folded+strip collapses and strips", foldedStrip.a === "one two");
  var explicit = yaml.parse("a: |2\n    hello\n");
  check("explicit indent indicator honored", explicit.a === "  hello\n");
}

// ---- structural refusals (expected-key / bad-indent / tab-indent) ----

function testStructuralErrors() {
  check("non-key line in mapping → expected-key",
        _code("a: 1\nplain line no colon here") === "yaml/expected-key");
  check("sequence item where key expected → expected-key",
        _code("a: 1\n- item") === "yaml/expected-key");
  check("over-indented sibling key → bad-indent",
        _code("a: 1\n  b: 2") === "yaml/bad-indent");
  check("mis-indented sequence item → bad-indent",
        _code("- a\n  - b") === "yaml/bad-indent");
  check("tab in indentation → tab-indent",
        _code("a:\n\tb: 1") === "yaml/tab-indent");
}

function testTrailingContentAfterQuoted() {
  // A quoted scalar followed by non-comment content is rejected — the
  // whole line must be the string.
  check("junk after quoted scalar → trailing-content",
        _code('a: "x" junk') === "yaml/trailing-content");
}

// ---- core-schema float edges (uncovered by the happy-path smoke) ----

function testFloatEdges() {
  check(".inf → +Infinity",  yaml.parse("a: .inf").a === Infinity);
  check("-.inf → -Infinity", yaml.parse("a: -.inf").a === -Infinity);
  check("+.inf → +Infinity", yaml.parse("a: +.inf").a === Infinity);
  check(".INF (caps) → +Infinity", yaml.parse("a: .INF").a === Infinity);
  check(".nan → NaN",        Number.isNaN(yaml.parse("a: .nan").a));
  // A huge integer that would lose precision stays a string, not a
  // silently-rounded Number.
  var huge = yaml.parse("a: 999999999999999999999999").a;
  check("precision-losing int stays string", huge === "999999999999999999999999");
  // Octal / hex base prefixes resolve to numbers.
  check("0o755 → 493", yaml.parse("a: 0o755").a === 493);
  check("0x1F → 31",   yaml.parse("a: 0x1F").a === 31);
}

// ---- empty / comment-only documents resolve to null ----

function testEmptyDocuments() {
  check("empty string → null",         yaml.parse("") === null);
  check("comment-only doc → null",     yaml.parse("# just a comment\n# more") === null);
  check("blank-only doc → null",       yaml.parse("\n\n\n") === null);
  check("key with empty value → null", yaml.parse("a:").a === null);
}

// ---- scalar type-resolution edges (octal/hex precision, plain floats) ----

function testScalarResolutionEdges() {
  // A base-prefixed integer that would lose precision as a JS Number stays a
  // string (the whole token, undamaged) rather than a silently-rounded value.
  var bigOct = "0o" + "7".repeat(20);   // 8^20 well over Number.MAX_SAFE_INTEGER
  check("precision-losing octal stays string", yaml.parse("a: " + bigOct).a === bigOct);
  var bigHex = "0x" + "F".repeat(16);   // 16^16 well over Number.MAX_SAFE_INTEGER
  check("precision-losing hex stays string", yaml.parse("a: " + bigHex).a === bigHex);
  // Safe base-prefixed values still resolve to numbers — the string fallback
  // above must not swallow legitimately-representable integers.
  check("in-range octal resolves to number", yaml.parse("a: 0o17").a === 15);
  check("in-range hex resolves to number",   yaml.parse("a: 0xff").a === 255);
  // Plain floats via FLOAT_RE — distinct from the .inf / .nan special forms
  // the existing float-edge test drives.
  check("plain float 3.14 resolves",   yaml.parse("a: 3.14").a === 3.14);
  check("exponent float 5e+22 resolves", yaml.parse("a: 5e+22").a === 5e+22);
  check("leading-dot float .5 resolves", yaml.parse("a: .5").a === 0.5);
}

// ---- root-level values (flow collection / block scalar / plain scalar) ----

function testRootLevelValues() {
  var seq = yaml.parse("[1, 2, 3]");
  check("root flow sequence parses",
        Array.isArray(seq) && seq.length === 3 && seq[0] === 1 && seq[1] === 2 && seq[2] === 3);
  var map = yaml.parse("{a: 1, b: 2}");
  check("root flow mapping parses", map.a === 1 && map.b === 2);
  check("root block scalar literal parses",
        yaml.parse("|\n  hello\n  world") === "hello\nworld\n");
  check("root plain-scalar string parses", yaml.parse("hello world") === "hello world");
  check("root plain-scalar number parses", yaml.parse("42") === 42);
}

// ---- empty value followed by a sibling key at the same indent ----

function testEmptyValueWithSibling() {
  // `a:` with the next line NOT more-indented → a's value is null, and the
  // sibling key b must still be read (the null path must not consume b).
  var doc = yaml.parse("a:\nb: 2");
  check("empty-value key resolves null", doc.a === null);
  check("sibling key after empty value survives", doc.b === 2);
}

// ---- block-mapping key guards: merge key '<<' and duplicate key ----

function testBlockMappingKeyGuards() {
  check("block merge key '<<' → merge-key-banned",
        _code("<<: 1") === "yaml/merge-key-banned");
  check("block duplicate key → duplicate-key",
        _code("a: 1\na: 2") === "yaml/duplicate-key");
  // A legitimate two-key mapping must not be mis-flagged as a duplicate.
  var ok = yaml.parse("a: 1\nb: 2");
  check("distinct block keys are not duplicate", ok.a === 1 && ok.b === 2);
}

// ---- block sequence: valid items + dash-alone nested value ----

function testBlockSequenceForms() {
  var arr = yaml.parse("- a\n- b\n- c");
  check("block sequence items preserved",
        Array.isArray(arr) && arr.length === 3 &&
        arr[0] === "a" && arr[1] === "b" && arr[2] === "c");
  // "-" alone on a line → the item value lives on the more-indented lines below.
  var nested = yaml.parse("-\n  a: 1");
  check("dash-alone item takes nested mapping",
        Array.isArray(nested) && nested.length === 1 && nested[0].a === 1);
}

// ---- flow-mapping guards + closing / quoted-key forms ----

function testFlowMappingGuardsAndForms() {
  check("flow merge key '<<' → merge-key-banned",
        _code("root: {<<: 1}") === "yaml/merge-key-banned");
  check("flow duplicate key → duplicate-key",
        _code("root: {a: 1, a: 2}") === "yaml/duplicate-key");
  check("flow mapping bad separator → bad-flow",
        _code("root: {a: 1]") === "yaml/bad-flow");
  var quoted = yaml.parse('root: {"a": 1, \'b\': 2}');
  check("flow mapping quoted keys decode", quoted.root.a === 1 && quoted.root.b === 2);
  var closed = yaml.parse("root: {a: 1, b: 2}");
  check("flow mapping closes on '}' with both values", closed.root.a === 1 && closed.root.b === 2);
}

// ---- flow-value forms: single-quoted values + nested collections ----

function testFlowValueForms() {
  var sq = yaml.parse("root: ['abc', 'def']");
  check("flow single-quoted values decode", sq.root[0] === "abc" && sq.root[1] === "def");
  var nested = yaml.parse('root: [["x"], [\'y\'], 2]');
  check("nested flow sequences with quoted members preserved",
        Array.isArray(nested.root) && nested.root.length === 3 &&
        nested.root[0][0] === "x" && nested.root[1][0] === "y" && nested.root[2] === 2);
  var nestedMap = yaml.parse("root: {outer: {inner: 5}}");
  check("nested flow mapping value preserved", nestedMap.root.outer.inner === 5);
}

// ---- trailing junk after a flow collection ----

function testTrailingContentAfterFlow() {
  check("junk after flow collection → trailing-content",
        _code("a: [1, 2] junk") === "yaml/trailing-content");
}

// ---- comment stripping + folded-scalar paragraph break ----

function testCommentAndFoldedPaths() {
  // A whitespace-preceded '#' is an end-of-line comment; the scalar survives.
  check("inline eol comment stripped, value survives",
        yaml.parse("a: value # trailing comment").a === "value");
  // A '#' NOT preceded by whitespace is ordinary scalar content, kept verbatim.
  check("hash without leading whitespace stays in scalar",
        yaml.parse("a: va#lue").a === "va#lue");
  // A comment on a block-scalar header line is tolerated; the body still parses.
  check("block-scalar header comment tolerated",
        yaml.parse("|  # header comment\n  hello") === "hello\n");
  // In a folded scalar, a blank line between paragraphs becomes a newline
  // (adjacent non-blank lines otherwise fold to a single space).
  check("folded scalar blank line becomes newline",
        yaml.parse("a: >\n  one\n\n  two\n").a === "one\ntwo\n");
}

// ---- pre-validation: doubled apostrophe inside a single-quoted string ----

function testSingleQuoteEscapeInPreValidate() {
  // The `''` escape must be masked during pre-validation (so it doesn't
  // false-trip a ban scan) and decode to a single apostrophe in the value.
  var v = yaml.parse("a: 'it''s here'");
  check("doubled apostrophe decodes and content is preserved", v.a === "it's here");
}

// ---- tag refusals (yaml/tags-banned) ----

function testTagsBanned() {
  check("bare tag '!mytag' → tags-banned",
        _code("a: !mytag value") === "yaml/tags-banned");
  check("shorthand tag '!!str' → tags-banned",
        _code("a: !!str hi") === "yaml/tags-banned");
  check("verbatim tag '!<uri>' → tags-banned",
        _code("a: !<tag:x> v") === "yaml/tags-banned");
}

function run() {
  testBadNumericOpts();
  testWrongInputType();
  testByteInputsParse();
  testTooLargeAndKeys();
  testDepthCaps();
  testBannedConstructs();
  testPoisonedKeys();
  testEscapeErrors();
  testEscapesDecode();
  testUnterminatedStrings();
  testFlowErrors();
  testBlockScalarHeaderErrors();
  testBlockScalarChomp();
  testStructuralErrors();
  testTrailingContentAfterQuoted();
  testFloatEdges();
  testEmptyDocuments();
  testScalarResolutionEdges();
  testRootLevelValues();
  testEmptyValueWithSibling();
  testBlockMappingKeyGuards();
  testBlockSequenceForms();
  testFlowMappingGuardsAndForms();
  testFlowValueForms();
  testTrailingContentAfterFlow();
  testCommentAndFoldedPaths();
  testSingleQuoteEscapeInPreValidate();
  testTagsBanned();
}

module.exports = { run: run };

// Allow direct execution: `node test/layer-0-primitives/parsers-safe-yaml.test.js`
if (require.main === module) {
  try {
    run();
    console.log("OK — parsers-safe-yaml " + helpers.getChecks() + " checks passed");
    process.exit(0);
  } catch (e) {
    console.error(helpers.formatErr(e));
    process.exit(1);
  }
}
