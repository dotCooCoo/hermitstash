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
  // None of the above may have mutated Object.prototype.
  check("Object.prototype not polluted", typeof ({}).polluted === "undefined");
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
