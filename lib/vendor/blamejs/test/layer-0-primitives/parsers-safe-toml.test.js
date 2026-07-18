// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.parsers.toml — error-path, adversarial-input, and defensive-branch
 * coverage.
 *
 * Drives the TOML 1.0 parser (lib/parsers/safe-toml.js) through every
 * branch a happy-path smoke leaves untouched: opt-shape refusals, the
 * resource caps (maxBytes / maxDepth for arrays + inline tables /
 * maxKeys), wrong-input-type rejection, the full string-escape error
 * family, every quoted / literal / multi-line string form, the
 * date-time literal surface (offset → Date, local → ISO string, the
 * bad-datetime rejection), the numeric surface (hex/oct/bin, special
 * floats, integer-overflow, radix errors), the array / inline-table
 * parse errors, the table-header redefinition matrix (array-of-tables,
 * inline-table mutation, define-twice, value-array descent), and the
 * prototype-pollution key guard across bare / quoted / dotted paths.
 *
 * Every assertion runs offline through the public b.parsers.toml.parse
 * consumer path — no private internals, no live backend.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var toml = b.parsers.toml;

// Capture the SafeTomlError code from a synchronous parse throw. Returns
// the literal string "NO-THROW" when parse returns a value, so a missing
// rejection fails the check loudly rather than silently matching.
function _code(src, opts) {
  try {
    toml.parse(src, opts);
    return "NO-THROW";
  } catch (e) {
    return (e && e.code) || ("PLAIN:" + (e && e.message));
  }
}

// ---- opt-shape refusals (config-time throw: toml/bad-opt) ----

function testBadNumericOpts() {
  // maxBytes / maxDepth / maxKeys must each be a positive finite integer.
  // Infinity / NaN / negative / zero / non-integer all silently lift the
  // DoS cap they enforce, so each is rejected at the entry point.
  check("maxBytes=Infinity → bad-opt", _code("a = 1", { maxBytes: Infinity }) === "toml/bad-opt");
  check("maxBytes=NaN → bad-opt",      _code("a = 1", { maxBytes: NaN }) === "toml/bad-opt");
  check("maxBytes=-1 → bad-opt",       _code("a = 1", { maxBytes: -1 }) === "toml/bad-opt");
  check("maxBytes=1.5 → bad-opt",      _code("a = 1", { maxBytes: 1.5 }) === "toml/bad-opt");
  check("maxBytes=0 → bad-opt",        _code("a = 1", { maxBytes: 0 }) === "toml/bad-opt");
  check("maxDepth=Infinity → bad-opt", _code("a = 1", { maxDepth: Infinity }) === "toml/bad-opt");
  check("maxDepth=0 → bad-opt",        _code("a = 1", { maxDepth: 0 }) === "toml/bad-opt");
  check("maxDepth=-3 → bad-opt",       _code("a = 1", { maxDepth: -3 }) === "toml/bad-opt");
  check("maxKeys=NaN → bad-opt",       _code("a = 1", { maxKeys: NaN }) === "toml/bad-opt");
  check("maxKeys=-5 → bad-opt",        _code("a = 1", { maxKeys: -5 }) === "toml/bad-opt");
  check("maxKeys=0 → bad-opt",         _code("a = 1", { maxKeys: 0 }) === "toml/bad-opt");
  // A large-but-finite opt is accepted (the clamp branch, not the reject
  // branch) — proves the `!== undefined` path applies Math.min clamping
  // rather than throwing.
  var r = toml.parse("a = 1", { maxBytes: b.constants.BYTES.mib(128), maxDepth: 5000, maxKeys: 5_000_000 });
  check("oversize-but-finite opts accepted (clamped)", r.a === 1);
}

// ---- wrong input type / oversize (via safe-buffer.normalizeText) ----

function testWrongInputType() {
  check("number input rejected",    _code(42) === "toml/wrong-input-type");
  check("object input rejected",    _code({ a: 1 }) === "toml/wrong-input-type");
  check("null input rejected",      _code(null) === "toml/wrong-input-type");
  check("undefined input rejected", _code(undefined) === "toml/wrong-input-type");
  check("array input rejected",     _code([1, 2]) === "toml/wrong-input-type");
  check("boolean input rejected",   _code(true) === "toml/wrong-input-type");
}

function testByteInputsParse() {
  // Buffer / Uint8Array are the accepted non-string shapes — they decode
  // as UTF-8 and parse identically to the string form. A BOM prefix is
  // stripped by normalizeText before the parser sees it.
  var fromBuf = toml.parse(Buffer.from("a = 1\n", "utf8"));
  check("Buffer input parses",     fromBuf.a === 1);
  var fromU8 = toml.parse(new Uint8Array([0x61, 0x20, 0x3d, 0x20, 0x31]));  // "a = 1"
  check("Uint8Array input parses", fromU8.a === 1);
  var withBom = toml.parse("﻿a = 1\n");
  check("leading BOM stripped",    withBom.a === 1);
}

function testTooLargeAndKeys() {
  // maxBytes cap on the whole input (toml/too-large from normalizeText).
  check("oversize input → too-large",
        _code("a = \"" + "x".repeat(4000) + "\"", { maxBytes: b.constants.BYTES.kib(1) }) === "toml/too-large");
  // maxKeys cap — the 3rd assignment trips a 2-key ceiling (_bumpKeys).
  check("maxKeys exceeded → too-many-keys",
        _code("a = 1\nb = 2\nc = 3", { maxKeys: 2 }) === "toml/too-many-keys");
  // Inline-table members also count toward maxKeys.
  check("inline-table maxKeys → too-many-keys",
        _code("t = { a = 1, b = 2, c = 3 }", { maxKeys: 2 }) === "toml/too-many-keys");
}

// ---- depth caps: arrays, inline tables, dotted-key header paths ----

function testDepthCaps() {
  // Nested value arrays past maxDepth (the _parseArray recursion guard).
  check("array nesting → too-deep",
        _code("a = [[[[1]]]]", { maxDepth: 2 }) === "toml/too-deep");
  // Nested inline tables past maxDepth (the _parseInlineTable guard, an
  // independent recursion path).
  check("inline-table nesting → too-deep",
        _code("a = { b = { c = { d = 1 } } }", { maxDepth: 2 }) === "toml/too-deep");
  // A dotted-key table header with more segments than maxDepth (guards the
  // recursive post-parse normalize walker against stack overflow).
  check("dotted-key header depth → too-deep",
        _code("[a.b.c.d.e]", { maxDepth: 3 }) === "toml/too-deep");
  // Dotted key on a key/value line also caps.
  check("dotted key/value depth → too-deep",
        _code("a.b.c.d.e = 1", { maxDepth: 3 }) === "toml/too-deep");
}

// ---- prototype-pollution key guard, every decode path ----

function testPoisonedKeys() {
  check("bare '__proto__' key → poisoned-key",   _code("__proto__ = 1") === "toml/poisoned-key");
  check("bare 'constructor' key → poisoned-key", _code("constructor = 1") === "toml/poisoned-key");
  check("bare 'prototype' key → poisoned-key",   _code("prototype = 1") === "toml/poisoned-key");
  // Quoted keys that decode to a poisoned name.
  check("double-quoted '__proto__' → poisoned-key", _code('"__proto__" = 1') === "toml/poisoned-key");
  check("single-quoted '__proto__' → poisoned-key", _code("'__proto__' = 1") === "toml/poisoned-key");
  // Poisoned segment as a NON-first dotted-key segment.
  check("dotted 'a.__proto__' → poisoned-key",   _code("a.__proto__ = 1") === "toml/poisoned-key");
  // Poisoned segment inside a table header.
  check("table header '[a.constructor]' → poisoned-key", _code("[a.constructor]") === "toml/poisoned-key");
  // Poisoned key inside an inline table.
  check("inline '{ __proto__ = 1 }' → poisoned-key", _code("t = { __proto__ = 1 }") === "toml/poisoned-key");
  // None of the above may have mutated Object.prototype.
  check("Object.prototype not polluted", typeof ({}).polluted === "undefined");
  check("Object.prototype constructor intact", ({}).constructor === Object);
}

// ---- string escape errors (toml/bad-escape) ----

function testEscapeErrors() {
  check("bad \\u hex → bad-escape",       _code('a = "\\uZZZZ"') === "toml/bad-escape");
  check("short \\u → bad-escape",         _code('a = "\\u12"') === "toml/bad-escape");
  check("bad \\U hex → bad-escape",       _code('a = "\\UZZZZZZZZ"') === "toml/bad-escape");
  check("short \\U → bad-escape",         _code('a = "\\U0001"') === "toml/bad-escape");
  check("\\U past U+10FFFF → bad-escape", _code('a = "\\UFFFFFFFF"') === "toml/bad-escape");
  check("unknown escape → bad-escape",    _code('a = "\\q"') === "toml/bad-escape");
  // A backslash escape inside a QUOTED KEY routes through the same decoder.
  check("bad escape in quoted key → bad-escape", _code('"a\\q" = 1') === "toml/bad-escape");
}

function testEscapesDecode() {
  // The full accepted escape set decodes to the intended chars.
  var d = toml.parse('a = "x\\ny\\tz\\\\w\\"q\\r\\b\\f\\/p"');
  check("escape set decodes", d.a === "x\ny\tz\\w\"q\r\b\f/p");
  // \u (BMP) and \U (astral) code points.
  var d2 = toml.parse('a = "\\u0041\\U0001F600"');
  check("\\u + \\U decode", d2.a === "A\u{1F600}");
  // A backslash escape inside a basic quoted KEY decodes.
  var d3 = toml.parse('"a\\tb" = 1');
  check("escape in quoted key decodes", Object.keys(d3)[0] === "a\tb");
}

// ---- quoted / literal string forms + their unterminated errors ----

function testStringForms() {
  check("basic string",        toml.parse('a = "hello"').a === "hello");
  check("literal string",      toml.parse("a = 'C:\\\\path'").a === "C:\\\\path");
  check("empty basic string",  toml.parse('a = ""').a === "");
  // Literal quoted key (single-quote key segment).
  var lit = toml.parse("'literal key' = 1");
  check("literal quoted key",  lit["literal key"] === 1);
}

function testUnterminatedStrings() {
  check("unterminated basic → unterminated-string",
        _code('a = "no close') === "toml/unterminated-string");
  check("unterminated literal → unterminated-string",
        _code("a = 'no close") === "toml/unterminated-string");
  check("unterminated multi-line basic → unterminated-string",
        _code('a = """no close') === "toml/unterminated-string");
  check("unterminated multi-line literal → unterminated-string",
        _code("a = '''no close") === "toml/unterminated-string");
  // Unterminated quoted KEY (EOF before the closing quote).
  check("unterminated quoted key → bad-key",
        _code('"abc') === "toml/bad-key");
}

function testBadStringChars() {
  // A raw newline inside a single-line basic string is rejected (must use
  // triple-quote for multi-line).
  check("newline in basic string → bad-string",
        _code('a = "line1\nline2"') === "toml/bad-string");
  check("newline in literal string → bad-string",
        _code("a = 'line1\nline2'") === "toml/bad-string");
  // A raw newline inside a quoted KEY.
  check("newline in quoted key → bad-key",
        _code('"ab\ncd" = 1') === "toml/bad-key");
  // An unescaped C0 control char (here a raw NUL) in a basic string.
  check("control char in basic string → bad-string",
        _code('a = "x' + String.fromCharCode(0) + 'y"') === "toml/bad-string");
}

function testMultilineStrings() {
  // Multi-line basic with a leading newline immediately after the opener
  // (that first newline is trimmed).
  var m = toml.parse('a = """\nfirst\nsecond"""');
  check("multi-line basic trims leading newline", m.a === "first\nsecond");
  // Line-ending backslash folds the newline + leading whitespace away.
  var folded = toml.parse('a = """\\\n    one \\\n    two"""');
  check("line-ending backslash folds whitespace", folded.a === "one two");
  // A line-ending backslash followed by SEVERAL blank lines folds all of
  // them (the inner blank-line-skipping loop, not just one newline).
  var foldedBlank = toml.parse('a = """one \\\n\n\n    two"""');
  check("line-ending backslash folds multiple blank lines", foldedBlank.a === "one two");
  // Escape decoding inside multi-line basic.
  var esc = toml.parse('a = """x\\ty"""');
  check("escape inside multi-line basic", esc.a === "x\ty");
  // Multi-line literal preserves everything verbatim (no escape decoding).
  var lit = toml.parse("a = '''\nline\\ttab'''");
  check("multi-line literal verbatim", lit.a === "line\\ttab");
  // Trailing quotes fold into the string (up to two before the closing
  // triple).
  var tq = toml.parse('a = """ends with quote""""');
  check("multi-line basic trailing quote", tq.a === "ends with quote\"");
}

// ---- number surface: integers, floats, radices, special values ----

function testNumbers() {
  check("plain integer",        toml.parse("a = 42").a === 42);
  check("negative integer",     toml.parse("a = -17").a === -17);
  check("underscore integer",   toml.parse("a = 1_000_000").a === 1000000);
  check("float with dot",       toml.parse("a = 3.14").a === 3.14);
  check("float with exponent",  toml.parse("a = 1e3").a === 1000);
  check("float exp sign",       toml.parse("a = 1.5E-2").a === 0.015);
  check("hex literal",          toml.parse("a = 0xDEAD_beef").a === 0xDEADBEEF);
  check("octal literal",        toml.parse("a = 0o755").a === 493);
  check("binary literal",       toml.parse("a = 0b1010").a === 10);
}

function testSpecialFloats() {
  check("+inf → +Infinity", toml.parse("a = +inf").a === Infinity);
  check("-inf → -Infinity", toml.parse("a = -inf").a === -Infinity);
  check("bare inf",         toml.parse("a = inf").a === Infinity);
  check("+nan → NaN",       Number.isNaN(toml.parse("a = +nan").a));
  check("-nan → NaN",       Number.isNaN(toml.parse("a = -nan").a));
  check("bare nan → NaN",   Number.isNaN(toml.parse("a = nan").a));
}

function testNumberErrors() {
  // Integer overflow (decimal) — TOML mandates 64-bit but a JS Number
  // can't hold it without precision loss, so the parser refuses.
  check("decimal overflow → integer-overflow",
        _code("a = 99999999999999999999") === "toml/integer-overflow");
  // Radix overflow.
  check("hex overflow → integer-overflow",
        _code("a = 0xFFFFFFFFFFFFFFFFFF") === "toml/integer-overflow");
  // Sign on a radix literal is illegal.
  check("sign on hex → bad-number",
        _code("a = -0x1F") === "toml/bad-number");
  // Radix prefix with no digits.
  check("empty digits after 0b → bad-number",
        _code("a = 0b2") === "toml/bad-number");
  // A lone minus with a dot decodes to no number (parseFloat NaN path).
  check("'-.' → bad-number",
        _code("a = -.") === "toml/bad-number");
  // A lone sign.
  check("lone '-' → bad-number",
        _code("a = -") === "toml/bad-number");
}

// ---- date-time literal surface ----

function testDateTimes() {
  // Offset date-time → JS Date (and survives _normalize as a Date).
  var off = toml.parse("d = 1979-05-27T07:32:00Z");
  check("offset date-time → Date", off.d instanceof Date);
  check("offset date-time value", off.d.getTime() === Date.UTC(1979, 4, 27, 7, 32, 0));
  var offNum = toml.parse("d = 1979-05-27T00:32:00.999-07:00");
  check("numeric-offset date-time → Date", offNum.d instanceof Date);
  // Space separator variant.
  var offSpace = toml.parse("d = 1979-05-27 07:32:00Z");
  check("space-separated offset date-time → Date", offSpace.d instanceof Date);
  // Local date-time (no offset) stays an ISO string.
  var ldt = toml.parse("d = 1979-05-27T07:32:00");
  check("local date-time → ISO string", ldt.d === "1979-05-27T07:32:00");
  // Local date only.
  var ld = toml.parse("d = 1979-05-27");
  check("local date → string", ld.d === "1979-05-27");
  // Local time only, with fractional seconds.
  var lt = toml.parse("d = 07:32:00.5");
  check("local time → string", lt.d === "07:32:00.5");
  // Fractional seconds on a local date-time.
  var frac = toml.parse("d = 1979-05-27T00:32:00.999999");
  check("fractional local date-time", frac.d === "1979-05-27T00:32:00.999999");
}

function testBadDateTime() {
  // A syntactically date-shaped but semantically invalid offset date-time
  // (month 13) fails the new Date() validity check.
  check("invalid offset date-time → bad-datetime",
        _code("d = 1979-13-01T00:00:00Z") === "toml/bad-datetime");
}

// ---- boolean + array + inline-table happy paths + parse errors ----

function testBooleansAndArrays() {
  check("true",  toml.parse("a = true").a === true);
  check("false", toml.parse("a = false").a === false);
  var arr = toml.parse("a = [1, 2, 3]");
  check("array parses", Array.isArray(arr.a) && arr.a.length === 3 && arr.a[2] === 3);
  var empty = toml.parse("a = []");
  check("empty array", Array.isArray(empty.a) && empty.a.length === 0);
  // Whitespace, newlines, comments, and a trailing comma inside an array.
  var multi = toml.parse("a = [\n  1, # first\n  2,\n]");
  check("multiline array with comment + trailing comma", multi.a.length === 2 && multi.a[1] === 2);
  var inline = toml.parse("t = { x = 1, y = 2 }");
  check("inline table parses", inline.t.x === 1 && inline.t.y === 2);
  var emptyInline = toml.parse("t = {}");
  check("empty inline table", typeof emptyInline.t === "object" && Object.keys(emptyInline.t).length === 0);
  // Dotted key inside an inline table builds nested structure.
  var dotted = toml.parse("t = { a.b = 1 }");
  check("dotted key in inline table", dotted.t.a.b === 1);
}

function testCollectionErrors() {
  check("array bad separator → bad-array",
        _code("a = [1 2]") === "toml/bad-array");
  check("inline missing '=' → bad-inline-table",
        _code("t = { x 1 }") === "toml/bad-inline-table");
  check("inline trailing comma → bad-inline-table",
        _code("t = { x = 1,}") === "toml/bad-inline-table");
  check("inline bad separator → bad-inline-table",
        _code("t = { x = 1 y = 2 }") === "toml/bad-inline-table");
}

// ---- value-position + structural errors ----

function testValueErrors() {
  check("value EOF → expected-value",  _code("a =") === "toml/expected-value");
  check("unexpected char → expected-value", _code("a = @") === "toml/expected-value");
  check("missing '=' → bad-kv",        _code("a 1") === "toml/bad-kv");
  check("empty key '= 1' → expected-key", _code("= 1") === "toml/expected-key");
  // Trailing junk after a value (no comment, no newline).
  check("trailing junk after value → expected-newline",
        _code("a = 1 junk") === "toml/expected-newline");
}

// ---- table header parsing + the redefinition matrix ----

function testTableHeaders() {
  // A single table + a nested super-table auto-vivified by a dotted header.
  var t = toml.parse("[a]\nx = 1\n[a.b]\ny = 2");
  check("nested table headers", t.a.x === 1 && t.a.b.y === 2);
  // A dotted header whose parent does not yet exist auto-vivifies it.
  var t2 = toml.parse("[a.b.c]\nz = 3");
  check("deep auto-vivified header", t2.a.b.c.z === 3);
  // Array-of-tables.
  var aot = toml.parse("[[p]]\nn = 1\n[[p]]\nn = 2");
  check("array of tables", Array.isArray(aot.p) && aot.p.length === 2 && aot.p[1].n === 2);
  // Sub-table under an array-of-tables element (descend into the last elem).
  var aotSub = toml.parse("[[p]]\nn = 1\n[p.detail]\nk = 9");
  check("sub-table under AoT element", aotSub.p[0].detail.k === 9);
  // A comment on the header line is consumed.
  var withComment = toml.parse("[a] # a table\nx = 1");
  check("header with trailing comment", withComment.a.x === 1);
}

function testTableHeaderErrors() {
  check("missing ']' → bad-table-header",
        _code("[a\nx = 1") === "toml/bad-table-header");
  check("missing second ']' in AoT → bad-table-header",
        _code("[[a]\nx = 1") === "toml/bad-table-header");
  // Redefining an existing table.
  check("table defined twice → redefine",
        _code("[a]\n[a]") === "toml/redefine");
  // A key already bound to a scalar cannot become a table.
  check("scalar then table header → redefine",
        _code("a = 1\n[a]") === "toml/redefine");
  // A key bound to a scalar cannot become a sub-table via dotted header.
  check("scalar then dotted header → redefine",
        _code("a = 1\n[a.b]") === "toml/redefine");
  // An array-of-tables name reused as a plain table.
  check("AoT then plain table → redefine",
        _code("[[a]]\n[a]") === "toml/redefine");
  // A plain table name reused as an array-of-tables.
  check("plain table then AoT → redefine",
        _code("[a]\n[[a]]") === "toml/redefine");
  // Descending into a VALUE array (scalar last element) via a header.
  check("descend into value array → redefine",
        _code("a = [1]\n[a.b]") === "toml/redefine");
  // A table header that tries to extend an inline table.
  check("header extends inline table → inline-table-mutated",
        _code("a = { x = 1 }\n[a.b]") === "toml/inline-table-mutated");
}

// ---- key/value redefinition + dotted-key building ----

function testKeyValueRedefinition() {
  check("duplicate key → duplicate-key",
        _code("a = 1\na = 2") === "toml/duplicate-key");
  check("dotted redefine scalar as sub-table → redefine",
        _code("a = 1\na.b = 2") === "toml/redefine");
  check("dotted extend inline table → inline-table-mutated",
        _code("a = { x = 1 }\na.y = 2") === "toml/inline-table-mutated");
  // Legal dotted-key building of a nested object across two lines.
  var t = toml.parse("a.b = 1\na.c = 2");
  check("dotted keys build nested object", t.a.b === 1 && t.a.c === 2);
}

// ---- whitespace / comment / blank-line handling in the top-level loop ----

function testDocumentStructure() {
  // Leading comment line, blank lines, CRLF line endings.
  var t = toml.parse("# header comment\r\n\r\na = 1\r\nb = 2\r\n");
  check("comments + blanks + CRLF", t.a === 1 && t.b === 2);
  // A document that is only comments + whitespace yields an empty object.
  var empty = toml.parse("# just a comment\n\n   \n");
  check("comment-only document → empty object",
        typeof empty === "object" && Object.keys(empty).length === 0);
  // Empty input yields an empty object.
  check("empty input → empty object", Object.keys(toml.parse("")).length === 0);
  // Output is a plain {}-prototype object (normalize strips null-prototype).
  var proto = toml.parse("a = 1");
  check("output has Object.prototype", Object.getPrototypeOf(proto) === Object.prototype);
  // A trailing comment with no newline at EOF is tolerated.
  var trailing = toml.parse("a = 1 # trailing");
  check("trailing comment at EOF", trailing.a === 1);
}

// ---- residual CR/LF, sign, and date-boundary branch arms ----

function testResidualBranches() {
  // A line-ending backslash followed by multiple CRLF blank lines folds
  // them all (the CR arm of the inner blank-line loop).
  var foldCrlf = toml.parse('a = """one \\\r\n\r\n    two"""');
  check("CRLF multi-blank fold", foldCrlf.a === "one two");
  // A multi-line literal string whose opener is followed by a CRLF trims
  // that leading CRLF.
  var mlLitCrlf = toml.parse("a = '''\r\nverbatim'''");
  check("multi-line literal trims leading CRLF", mlLitCrlf.a === "verbatim");
  // A multi-line literal ending with extra apostrophes folds up to two of
  // them into the value.
  var litTrail = toml.parse("a = '''ends'''''");
  check("multi-line literal trailing quotes", litTrail.a === "ends''");
  // A leading '+' on a plain decimal integer.
  check("+decimal sign", toml.parse("a = +42").a === 42);
  // A bare local date immediately followed by a newline + more content
  // (the date-boundary check sees a truthy non-date char, not EOF).
  var bareDate = toml.parse("d = 1979-05-27\ne = 2");
  check("bare date then newline", bareDate.d === "1979-05-27" && bareDate.e === 2);
  // A date-shaped run trailed by a digit is NOT a date; the leading digits
  // parse as a number and the stray suffix trips the newline expectation.
  check("date-shaped run + trailing digit → expected-newline",
        _code("d = 1979-05-277") === "toml/expected-newline");
  // Trailing spaces on the final line (no closing newline) reach EOF in
  // the top-level loop after whitespace is skipped.
  var trailSpace = toml.parse("a = 1\n   ");
  check("trailing spaces at EOF", trailSpace.a === 1);
  // Multi-line basic string whose opener is followed by a CRLF trims that
  // leading CRLF (the CRLF arm of the opener strip).
  var mlBasicCrlf = toml.parse("a = \"\"\"\r\nfirst\"\"\"");
  check("multi-line basic trims leading CRLF", mlBasicCrlf.a === "first");
  // A basic string ending with a lone backslash at EOF: the escape decoder
  // runs with the cursor already at end-of-input (the _advance past-EOF
  // guard) and then rejects the dangling escape.
  check("basic string backslash at EOF → bad-escape",
        _code('a = "x\\') === "toml/bad-escape");
  check("multi-line basic backslash at EOF → bad-escape",
        _code('a = """x\\') === "toml/bad-escape");
}

// ---- error object surface ----

function testErrorSurface() {
  try {
    toml.parse("a = @");
    check("error path threw", false);
  } catch (e) {
    check("error is SafeTomlError", e instanceof toml.SafeTomlError);
    check("error marks isSafeTomlError", e.isSafeTomlError === true);
    check("error carries line/col", typeof e.line === "number" && typeof e.col === "number");
    check("error name", e.name === "SafeTomlError");
  }
  // A config-time bad-opt error carries a null line (no source position).
  try {
    toml.parse("a = 1", { maxKeys: 0 });
    check("bad-opt threw", false);
  } catch (e) {
    check("bad-opt error has null line", e.line === null && e.col === null);
  }
  // The public error class defaults its code + null-positions when
  // constructed without them (the operator-facing constructor fallback).
  var bare = new toml.SafeTomlError("plain message");
  check("bare SafeTomlError default code", bare.code === "toml/invalid");
  check("bare SafeTomlError null line/col", bare.line === null && bare.col === null);
  check("bare SafeTomlError message verbatim", bare.message === "plain message");
}

function run() {
  testBadNumericOpts();
  testWrongInputType();
  testByteInputsParse();
  testTooLargeAndKeys();
  testDepthCaps();
  testPoisonedKeys();
  testEscapeErrors();
  testEscapesDecode();
  testStringForms();
  testUnterminatedStrings();
  testBadStringChars();
  testMultilineStrings();
  testNumbers();
  testSpecialFloats();
  testNumberErrors();
  testDateTimes();
  testBadDateTime();
  testBooleansAndArrays();
  testCollectionErrors();
  testValueErrors();
  testTableHeaders();
  testTableHeaderErrors();
  testKeyValueRedefinition();
  testDocumentStructure();
  testResidualBranches();
  testErrorSurface();
}

module.exports = { run: run };

// Allow direct execution: `node test/layer-0-primitives/parsers-safe-toml.test.js`
if (require.main === module) {
  try {
    run();
    console.log("OK — parsers-safe-toml " + helpers.getChecks() + " checks passed");
    process.exit(0);
  } catch (e) {
    console.error(helpers.formatErr(e));
    process.exit(1);
  }
}
