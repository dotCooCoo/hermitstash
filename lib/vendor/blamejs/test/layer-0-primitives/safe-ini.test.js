// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.parsers.ini — error-path, adversarial-input, and defensive-branch
 * coverage.
 *
 * Drives the INI parser (lib/parsers/safe-ini.js) through every branch a
 * happy-path smoke leaves untouched: opt-shape refusals, the resource
 * caps (maxBytes / maxSections / maxKeysPerSection / maxValueBytes),
 * wrong-input-type rejection, the comment-stripping quote-state machine,
 * section-header parsing (plain, dotted, git-style quoted subsection) and
 * its error family, the key/value separator resolution (`=` vs `:`), the
 * value-coercion surface (booleans, decimal / hex integers with range
 * guards, floats, quoted strings with the escape family), the
 * duplicate-key policy matrix, and the prototype-pollution key guard
 * across bare keys, dotted + quoted section segments.
 *
 * Every assertion runs offline through the public b.parsers.ini.parse
 * consumer path — no private internals, no live backend.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var ini = b.parsers.ini;

// Capture the IniSafeError code from a synchronous parse throw. Returns
// the literal string "NO-THROW" when parse returns a value, so a missing
// rejection fails the check loudly rather than silently matching.
function _code(src, opts) {
  try {
    ini.parse(src, opts);
    return "NO-THROW";
  } catch (e) {
    return (e && e.code) || ("PLAIN:" + (e && e.message));
  }
}

// ---- opt-shape refusals (config-time throw: ini/bad-opt) ----

function testBadNumericOpts() {
  // maxBytes / maxSections / maxKeysPerSection / maxValueBytes must each be
  // a positive finite integer. Infinity / NaN / negative / zero / non-integer
  // all silently lift the DoS cap they enforce (Infinity is truthy and
  // bypasses `|| DEFAULT_*`), so each is rejected at the entry point.
  check("maxBytes=Infinity → bad-opt",           _code("a = 1", { maxBytes: Infinity }) === "ini/bad-opt");
  check("maxBytes=NaN → bad-opt",                 _code("a = 1", { maxBytes: NaN }) === "ini/bad-opt");
  check("maxBytes=-1 → bad-opt",                  _code("a = 1", { maxBytes: -1 }) === "ini/bad-opt");
  check("maxBytes=1.5 → bad-opt",                 _code("a = 1", { maxBytes: 1.5 }) === "ini/bad-opt");
  check("maxBytes=0 → bad-opt",                   _code("a = 1", { maxBytes: 0 }) === "ini/bad-opt");
  check("maxSections=Infinity → bad-opt",         _code("a = 1", { maxSections: Infinity }) === "ini/bad-opt");
  check("maxSections=0 → bad-opt",                _code("a = 1", { maxSections: 0 }) === "ini/bad-opt");
  check("maxSections=-3 → bad-opt",               _code("a = 1", { maxSections: -3 }) === "ini/bad-opt");
  check("maxKeysPerSection=NaN → bad-opt",        _code("a = 1", { maxKeysPerSection: NaN }) === "ini/bad-opt");
  check("maxKeysPerSection=0 → bad-opt",          _code("a = 1", { maxKeysPerSection: 0 }) === "ini/bad-opt");
  check("maxValueBytes=-5 → bad-opt",             _code("a = 1", { maxValueBytes: -5 }) === "ini/bad-opt");
  check("maxValueBytes=2.5 → bad-opt",            _code("a = 1", { maxValueBytes: 2.5 }) === "ini/bad-opt");
  // A large-but-finite opt is accepted (the `!== undefined` branch applies
  // the override rather than rejecting it).
  var r = ini.parse("a = 1", {
    maxBytes:          b.constants.BYTES.mib(128),
    maxSections:       5000,
    maxKeysPerSection: 5_000_000,
    maxValueBytes:     b.constants.BYTES.mib(1),
  });
  check("oversize-but-finite opts accepted", r.a === 1);
}

function testBadOnDuplicate() {
  check("onDuplicate='merge' → bad-opt",  _code("a = 1", { onDuplicate: "merge" }) === "ini/bad-opt");
  check("onDuplicate=42 → bad-opt",       _code("a = 1", { onDuplicate: 42 }) === "ini/bad-opt");
  // The three accepted values do not throw at the opt-check.
  check("onDuplicate='throw' accepted", ini.parse("a = 1", { onDuplicate: "throw" }).a === 1);
  check("onDuplicate='first' accepted", ini.parse("a = 1", { onDuplicate: "first" }).a === 1);
  check("onDuplicate='last' accepted",  ini.parse("a = 1", { onDuplicate: "last" }).a === 1);
}

// ---- wrong input type / oversize ----

function testWrongInputType() {
  check("number input rejected",    _code(42) === "ini/bad-input");
  check("object input rejected",    _code({ a: 1 }) === "ini/bad-input");
  check("null input rejected",      _code(null) === "ini/bad-input");
  check("undefined input rejected", _code(undefined) === "ini/bad-input");
  check("array input rejected",     _code([1, 2]) === "ini/bad-input");
  check("boolean input rejected",   _code(true) === "ini/bad-input");
  check("Buffer input rejected",    _code(Buffer.from("a = 1")) === "ini/bad-input");
}

function testTooLarge() {
  // maxBytes cap on the whole input, measured in UTF-8 bytes.
  check("oversize input → too-large",
        _code("a = " + "x".repeat(4000), { maxBytes: b.constants.BYTES.kib(1) }) === "ini/too-large");
  // A multibyte value counts its encoded byte length, not char count.
  check("multibyte counts bytes → too-large",
        _code("a = " + "é".repeat(10), { maxBytes: 15 }) === "ini/too-large");
}

// ---- resource caps: sections, per-section keys, value bytes ----

function testCaps() {
  check("too-many-sections → too-many-sections",
        _code("[a]\n[b]\n[c]", { maxSections: 2 }) === "ini/too-many-sections");
  // Reopening the SAME section still counts each header toward maxSections
  // (so the cap can't be defeated by re-declaring the same block).
  check("reopened section counts toward cap",
        _code("[s]\n[s]\n[s]", { maxSections: 2 }) === "ini/too-many-sections");
  check("too-many-keys → too-many-keys",
        _code("a = 1\nb = 2\nc = 3", { maxKeysPerSection: 2 }) === "ini/too-many-keys");
  check("value-too-large → value-too-large",
        _code("a = " + "x".repeat(50), { maxValueBytes: 10 }) === "ini/value-too-large");
  // value-bytes cap measures the trimmed raw value's UTF-8 length.
  check("multibyte value → value-too-large",
        _code("a = " + "\u{1F600}".repeat(4), { maxValueBytes: 10 }) === "ini/value-too-large");
}

// ---- prototype-pollution key guard, every decode path ----

function testPoisonedKeys() {
  check("bare '__proto__' key → forbidden-key",   _code("__proto__ = 1") === "ini/forbidden-key");
  check("bare 'constructor' key → forbidden-key", _code("constructor = 1") === "ini/forbidden-key");
  check("bare 'prototype' key → forbidden-key",   _code("prototype = 1") === "ini/forbidden-key");
  // Poison as a plain section name.
  check("section '[__proto__]' → forbidden-key",  _code("[__proto__]\nx = 1") === "ini/forbidden-key");
  // Poison as a NON-first dotted section segment.
  check("section '[a.constructor]' → forbidden-key", _code("[a.constructor]\nx = 1") === "ini/forbidden-key");
  check("section '[a.prototype]' → forbidden-key",   _code("[a.prototype]\nx = 1") === "ini/forbidden-key");
  // Poison as the plain section-part of a git-style quoted subsection.
  check("section '[__proto__ \"x\"]' → forbidden-key", _code('[__proto__ "x"]\ny = 1') === "ini/forbidden-key");
  // Poison as the QUOTED subsection name (the group-2 decode path).
  check("quoted subsection '[a \"__proto__\"]' → forbidden-key", _code('[a "__proto__"]\ny = 1') === "ini/forbidden-key");
  // None of the above may have mutated Object.prototype.
  check("Object.prototype not polluted", typeof ({}).polluted === "undefined");
  check("Object.prototype constructor intact", ({}).constructor === Object);
  // A key that merely CONTAINS a poison substring (or wears quote chars) is
  // a normal key — the guard matches the exact name, not a substring.
  var okKey = ini.parse("my__proto__key = 1");
  check("non-exact poison substring is a normal key", okKey.my__proto__key === 1);
}

function testNullProtoOutput() {
  // Every parsed node is a null-prototype object (defense-in-depth: a poison
  // key could only ever land as an own property, never reach Object.prototype).
  var r = ini.parse("a = 1\n[s]\nb = 2");
  check("root is null-proto",    Object.getPrototypeOf(r) === null);
  check("section is null-proto", Object.getPrototypeOf(r.s) === null);
  // Reads still work through direct property access on the null-proto tree.
  check("null-proto value read", r.a === 1 && r.s.b === 2);
}

// ---- comment stripping (the quote-state machine) ----

function testComments() {
  // Leading ; and # comment lines are skipped entirely.
  check("leading ';' comment skipped", Object.keys(ini.parse("; a comment\nk = 1")).length === 1);
  check("leading '#' comment skipped", Object.keys(ini.parse("# a comment\nk = 1")).length === 1);
  // Inline comment after whitespace is stripped from the value.
  check("inline ';' comment stripped", ini.parse("k = val ; note").k === "val");
  check("inline '#' comment stripped", ini.parse("k = val # note").k === "val");
  // A ; or # NOT preceded by whitespace stays part of the value.
  check("';' without leading space kept", ini.parse("k = a;b").k === "a;b");
  check("'#' without leading space kept", ini.parse("k = a#b").k === "a#b");
  // A comment char inside a quoted value is preserved (in-string state).
  check("';' inside quotes preserved", ini.parse('k = "a ; b"').k === "a ; b");
  check("'#' inside quotes preserved", ini.parse('k = "a # b"').k === "a # b");
  // An escaped quote keeps the string open so a later ; is still in-string.
  check("escaped quote keeps string open", ini.parse('k = "a\\" ; still in"').k === 'a" ; still in');
  // A whole-document of only comments + blanks yields an empty object.
  check("comment-only doc → empty", Object.keys(ini.parse("; x\n# y\n\n   ")).length === 0);
}

// ---- section headers: plain, dotted, quoted subsection ----

function testSectionHeaders() {
  var s = ini.parse("[a]\nx = 1");
  check("plain section", s.a.x === 1);
  var nested = ini.parse("[a.b.c]\nz = 9");
  check("dotted section nests", nested.a.b.c.z === 9);
  // git-style quoted subsection → { parent: { child: {...} } }.
  var q = ini.parse('[core "origin"]\nurl = x');
  check("quoted subsection nests", q.core.origin.url === "x");
  // Reopening a section accumulates keys into the same object.
  var reopen = ini.parse("[s]\na = 1\n[s]\nb = 2");
  check("reopened section accumulates", reopen.s.a === 1 && reopen.s.b === 2);
  // Keys before any section header land at the root.
  var rootKeys = ini.parse("top = 1\n[s]\nx = 2");
  check("root-level keys", rootKeys.top === 1 && rootKeys.s.x === 2);
}

function testSectionHeaderErrors() {
  check("empty header '[]' → empty-section",     _code("[]\nx = 1") === "ini/empty-section");
  check("missing ']' → bad-section",             _code("[a\nx = 1") === "ini/bad-section");
  check("empty dotted segment → bad-section",    _code("[a..b]\nx = 1") === "ini/bad-section");
  check("bad section char → bad-section",        _code("[a b]\nx = 1") === "ini/bad-section");
  check("trailing junk after ']' → bad-section", _code("[a] junk\nx = 1") === "ini/bad-section");
  // A scalar already bound at a path cannot become a section.
  check("scalar then section → section-conflict", _code("foo = 1\n[foo]\nbar = 2") === "ini/section-conflict");
  // A scalar collision on a NON-leaf dotted segment.
  check("scalar then deep section → section-conflict",
        _code("[a]\nb = 1\n[a.b.c]\nx = 2") === "ini/section-conflict");
}

// ---- key / value separator resolution ----

function testKeyValueSeparators() {
  check("'=' separator", ini.parse("a = 1").a === 1);
  check("':' separator", ini.parse("a: 5").a === 5);
  // When both appear, the earlier separator wins.
  check("'=' earlier wins", ini.parse("a=b:c").a === "b:c");
  check("':' earlier wins", ini.parse("a:b=c").a === "b=c");
  // A colon inside a URL value is not a separator once '=' is seen first.
  check("url value keeps colon", ini.parse("a = http://x.y/z").a === "http://x.y/z");
}

function testKeyValueErrors() {
  check("no separator → bad-line", _code("justkey") === "ini/bad-line");
  check("empty key '= 1' → empty-key", _code("= 1") === "ini/empty-key");
  check("empty key ': 1' → empty-key", _code(": 1") === "ini/empty-key");
}

// ---- duplicate-key policy matrix ----

function testDuplicateKeyPolicy() {
  check("duplicate (default throw) → duplicate-key", _code("a = 1\na = 2") === "ini/duplicate-key");
  check("onDuplicate 'first' keeps first", ini.parse("a = 1\na = 2", { onDuplicate: "first" }).a === 1);
  check("onDuplicate 'last' keeps last",   ini.parse("a = 1\na = 2", { onDuplicate: "last" }).a === 2);
  // A duplicate across a reopened section is still caught by the default.
  check("duplicate across reopen → duplicate-key",
        _code("[s]\na = 1\n[s]\na = 2") === "ini/duplicate-key");
}

// ---- value coercion: booleans, strings, escapes ----

function testBooleanCoercion() {
  check("true", ini.parse("a = true").a === true);
  check("false", ini.parse("a = false").a === false);
  check("yes", ini.parse("a = yes").a === true);
  check("no", ini.parse("a = no").a === false);
  check("on", ini.parse("a = on").a === true);
  check("off", ini.parse("a = off").a === false);
  // Case-insensitive.
  check("ON case-insensitive", ini.parse("a = ON").a === true);
  check("Off case-insensitive", ini.parse("a = Off").a === false);
  // Quoting preserves the literal string (does NOT coerce to boolean).
  check("quoted 'true' stays string", ini.parse('a = "true"').a === "true");
}

function testStringCoercion() {
  check("double-quoted string", ini.parse('a = "hello"').a === "hello");
  check("single-quoted string", ini.parse("a = 'hello'").a === "hello");
  check("empty double-quoted string", ini.parse('a = ""').a === "");
  check("bare (unquoted) string", ini.parse("a = plain text").a === "plain text");
  check("empty value → empty string", ini.parse("a =").a === "");
  // Escape family decodes.
  check("newline + tab escapes decode", ini.parse('a = "x\\ny\\tz"').a === "x\ny\tz");
  check("carriage-return escape decodes", ini.parse('a = "x\\rz"').a === "x\rz");
  check("escaped double-quote decodes", ini.parse('k = "a\\"b"').k === 'a"b');
  check("escaped single-quote decodes", ini.parse("k = 'a\\'b'").k === "a'b");
  check("escaped backslash decodes", ini.parse('a = "x\\\\y"').a === "x\\y");
}

function testStringErrors() {
  check("unknown escape → bad-escape", _code('a = "x\\q"') === "ini/bad-escape");
  check("lone quote value → bad-quote", _code('a = "') === "ini/bad-quote");
  check("lone single quote → bad-quote", _code("a = '") === "ini/bad-quote");
}

// ---- number coercion: decimal, hex, floats, and the range guards ----

function testNumberCoercion() {
  check("decimal integer", ini.parse("a = 42").a === 42);
  check("negative integer", ini.parse("a = -17").a === -17);
  check("hex integer", ini.parse("a = 0xFF").a === 255);
  check("hex uppercase prefix", ini.parse("a = 0XfF").a === 255);
  check("float with dot", ini.parse("a = 3.14").a === 3.14);
  check("float with exponent", ini.parse("a = 2e3").a === 2000);
  check("float exp sign", ini.parse("a = 1.5E-2").a === 0.015);
}

function testNumberRangeGuards() {
  // Decimal + hex integer overflow past MAX_SAFE_INTEGER is refused (a
  // silent precision-loss coercion would ship a wrong config value).
  check("decimal overflow → value-out-of-range",
        _code("a = 99999999999999999999") === "ini/value-out-of-range");
  check("hex overflow → value-out-of-range",
        _code("a = 0xFFFFFFFFFFFFFFFFFF") === "ini/value-out-of-range");
  // A float literal that overflows the double range MUST also be refused —
  // silently coercing `1e999` to Infinity violates the parser's "never
  // silently coerce to a usable shape" contract and is inconsistent with
  // the integer guard above. (RED before the float-finiteness fix: the
  // parser returned Infinity instead of throwing.)
  check("float overflow +1e999 → value-out-of-range",
        _code("a = 1e999") === "ini/value-out-of-range");
  check("float overflow -1e999 → value-out-of-range",
        _code("a = -1e999") === "ini/value-out-of-range");
  check("float overflow 1.5e400 → value-out-of-range",
        _code("a = 1.5e400") === "ini/value-out-of-range");
  check("huge float mantissa → value-out-of-range",
        _code("a = 1" + "0".repeat(400) + ".0") === "ini/value-out-of-range");
  // A finite float near the range edge still parses (the guard rejects only
  // the non-finite overflow, not every large-but-representable value).
  check("large finite float parses", ini.parse("a = 1e308").a === 1e308);
  // Float underflow → 0 is representable and stays a finite number.
  check("float underflow → 0", ini.parse("a = 1e-999").a === 0);
}

// ---- document structure: blanks, CRLF, whitespace ----

function testDocumentStructure() {
  var t = ini.parse("# header\r\n\r\na = 1\r\nb = 2\r\n");
  check("comments + blanks + CRLF", t.a === 1 && t.b === 2);
  check("empty input → empty object", Object.keys(ini.parse("")).length === 0);
  check("whitespace-only input → empty object", Object.keys(ini.parse("   \n\t\n")).length === 0);
  // Surrounding whitespace on keys and values is trimmed.
  var trimmed = ini.parse("   spaced   =   value   ");
  check("key + value trimmed", trimmed.spaced === "value");
}

// ---- error object surface ----

function testErrorSurface() {
  try {
    ini.parse("= 1");
    check("error path threw", false);
  } catch (e) {
    check("error is IniSafeError", e instanceof ini.IniSafeError);
    check("error marks isIniSafeError", e.isIniSafeError === true);
    check("error name", e.name === "IniSafeError");
    check("error code shape", e.code === "ini/empty-key");
    check("error is permanent (alwaysPermanent)", e.permanent === true);
  }
  // The public error class is constructed code-first (code, message).
  var bare = new ini.IniSafeError("ini/custom", "a plain message");
  check("bare IniSafeError code", bare.code === "ini/custom");
  check("bare IniSafeError message verbatim", bare.message === "a plain message");
  check("bare IniSafeError name", bare.name === "IniSafeError");
}

function run() {
  testBadNumericOpts();
  testBadOnDuplicate();
  testWrongInputType();
  testTooLarge();
  testCaps();
  testPoisonedKeys();
  testNullProtoOutput();
  testComments();
  testSectionHeaders();
  testSectionHeaderErrors();
  testKeyValueSeparators();
  testKeyValueErrors();
  testDuplicateKeyPolicy();
  testBooleanCoercion();
  testStringCoercion();
  testStringErrors();
  testNumberCoercion();
  testNumberRangeGuards();
  testDocumentStructure();
  testErrorSurface();
}

module.exports = { run: run };

// Allow direct execution: `node test/layer-0-primitives/safe-ini.test.js`
if (require.main === module) {
  try {
    run();
    console.log("OK — safe-ini " + helpers.getChecks() + " checks passed");
    process.exit(0);
  } catch (e) {
    console.error(helpers.formatErr(e));
    process.exit(1);
  }
}
