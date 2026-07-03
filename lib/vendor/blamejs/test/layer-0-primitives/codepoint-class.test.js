// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.codepointClass — control-char predicate helpers
 * (isForbiddenControlChar / firstControlCharOffset).
 */
var helpers = require("../helpers");
var check = helpers.check;
var codepointClass = require("../../lib/codepoint-class");

function testIsForbiddenControlChar() {
  var f = codepointClass.isForbiddenControlChar;
  // NUL and other C0 controls are forbidden by default.
  check("isForbiddenControlChar: NUL forbidden", f(0x00) === true);
  check("isForbiddenControlChar: 0x01 forbidden", f(0x01) === true);
  check("isForbiddenControlChar: 0x1f forbidden", f(0x1f) === true);
  // TAB always permitted.
  check("isForbiddenControlChar: TAB permitted", f(0x09) === false);
  // DEL always forbidden, regardless of opts.
  check("isForbiddenControlChar: DEL forbidden", f(0x7f) === true);
  check("isForbiddenControlChar: DEL forbidden even with allowLf/allowCr",
        f(0x7f, { allowLf: true, allowCr: true }) === true);
  // Printable + high-bit are not control chars.
  check("isForbiddenControlChar: space ok", f(0x20) === false);
  check("isForbiddenControlChar: 'A' ok", f(0x41) === false);
  check("isForbiddenControlChar: 0xff ok", f(0xff) === false);
  // LF / CR forbidden by default, permitted only when opted in.
  check("isForbiddenControlChar: LF forbidden by default", f(0x0a) === true);
  check("isForbiddenControlChar: CR forbidden by default", f(0x0d) === true);
  check("isForbiddenControlChar: LF permitted with allowLf", f(0x0a, { allowLf: true }) === false);
  check("isForbiddenControlChar: CR still forbidden with allowLf only", f(0x0d, { allowLf: true }) === true);
  check("isForbiddenControlChar: CR permitted with allowCr", f(0x0d, { allowCr: true }) === false);
  check("isForbiddenControlChar: LF still forbidden with allowCr only", f(0x0a, { allowCr: true }) === true);
  // forbidTab — the stricter identifier / key / name contexts forbid TAB too,
  // making the predicate exactly `code < 0x20 || code === 0x7f`.
  check("isForbiddenControlChar: TAB forbidden with forbidTab", f(0x09, { forbidTab: true }) === true);
  check("isForbiddenControlChar: NUL still forbidden with forbidTab", f(0x00, { forbidTab: true }) === true);
  check("isForbiddenControlChar: DEL still forbidden with forbidTab", f(0x7f, { forbidTab: true }) === true);
  check("isForbiddenControlChar: space ok with forbidTab", f(0x20, { forbidTab: true }) === false);
  check("isForbiddenControlChar: 'A' ok with forbidTab", f(0x41, { forbidTab: true }) === false);
  // forbidTab is byte-equivalent to the open-coded `code < 0x20 || code === 0x7f`
  // across every codepoint (the routed name/key validators rely on this).
  var forbidTabParity = true;
  for (var cp = 0; cp <= 0x200; cp += 1) {
    if (f(cp, { forbidTab: true }) !== (cp < 0x20 || cp === 0x7f)) { forbidTabParity = false; break; }
  }
  check("isForbiddenControlChar: forbidTab === (code < 0x20 || code === 0x7f)", forbidTabParity);
  check("firstControlCharOffset: TAB forbidden with forbidTab → offset",
        codepointClass.firstControlCharOffset("a\tb", { forbidTab: true }) === 1);
  check("firstControlCharOffset: TAB allowed by default → -1",
        codepointClass.firstControlCharOffset("a\tb") === -1);
}

function testFirstControlCharOffset() {
  var g = codepointClass.firstControlCharOffset;
  check("firstControlCharOffset: clean string → -1", g("hello world") === -1);
  check("firstControlCharOffset: TAB ok → -1", g("a\tb\tc") === -1);
  check("firstControlCharOffset: empty → -1", g("") === -1);
  check("firstControlCharOffset: NUL at 1", g("a\x00b") === 1);
  check("firstControlCharOffset: DEL at 2", g("ab\x7fc") === 2);
  check("firstControlCharOffset: first of multiple", g("ok\x01\x02") === 2);
  check("firstControlCharOffset: LF found by default", g("a\nb") === 1);
  check("firstControlCharOffset: LF skipped with allowLf", g("a\nb", { allowLf: true }) === -1);
  check("firstControlCharOffset: CRLF skipped with allowLf+allowCr",
        g("a\r\nb", { allowLf: true, allowCr: true }) === -1);
  check("firstControlCharOffset: CR found when only allowLf", g("a\rb", { allowLf: true }) === 1);
}

// #332 — the catalog is now exported on the public b. surface so a consumer
// can build a custom free-text screen without reaching into the internal
// module path or re-rolling the bidi / control / zero-width regexes.
function testPublicSurface() {
  var b = helpers.b;
  check("b.codepointClass is on the public surface", typeof b.codepointClass === "object");
  // The detectors / classifier the issue names are reachable + functional.
  check("b.codepointClass.detectCharThreats is a function", typeof b.codepointClass.detectCharThreats === "function");
  check("b.codepointClass.assertNoCharThreats is a function", typeof b.codepointClass.assertNoCharThreats === "function");
  check("b.codepointClass.applyCharStripPolicies is a function", typeof b.codepointClass.applyCharStripPolicies === "function");
  check("b.codepointClass.scriptFor is a function", typeof b.codepointClass.scriptFor === "function");
  check("b.codepointClass.detectMixedScripts is a function", typeof b.codepointClass.detectMixedScripts === "function");
  // The compiled regexes / constants are reachable.
  check("b.codepointClass.BIDI_RE is a RegExp", b.codepointClass.BIDI_RE instanceof RegExp);
  check("b.codepointClass.C0_CTRL_RE is a RegExp", b.codepointClass.C0_CTRL_RE instanceof RegExp);
  check("b.codepointClass.ZERO_WIDTH_RE is a RegExp", b.codepointClass.ZERO_WIDTH_RE instanceof RegExp);
  check("b.codepointClass.NULL_BYTE is the NUL char", b.codepointClass.NULL_BYTE === "\x00");

  // Functional smoke: a bidi-override Trojan-source payload is detected; a
  // Cyrillic confusable mixed into a Latin label is flagged.
  var bidi = "abc" + b.codepointClass.fromCp(0x202E) + "def";
  var issues = b.codepointClass.detectCharThreats(bidi, { bidiPolicy: "reject" }, "free-text");
  check("public detectCharThreats flags a bidi override", issues.length >= 1 && issues[0].kind === "bidi-override");

  var spoof = "pa" + b.codepointClass.fromCp(0x0443) + "pal";   // Cyrillic u (U+0443)
  var scripts = b.codepointClass.detectMixedScripts(spoof);
  check("public detectMixedScripts flags a Latin/Cyrillic confusable",
        Array.isArray(scripts) && scripts.indexOf("latin") !== -1 && scripts.indexOf("cyrillic") !== -1);

  // strip policy removes the override (sanitize path).
  var cleaned = b.codepointClass.applyCharStripPolicies(bidi, { bidiPolicy: "strip" });
  check("public applyCharStripPolicies strips the override", cleaned === "abcdef");

  // The composition helpers are reachable + correct on the public surface too,
  // so a consumer building its own screen doesn't reach into the internal path.
  check("b.codepointClass.hex4", b.codepointClass.hex4(0x202E) === "\\u202E");
  check("b.codepointClass.charClass",
        b.codepointClass.charClass([0x200E, [0x202A, 0x202E]]) === "\\u200E\\u202A-\\u202E");
  check("b.codepointClass.fromCp", b.codepointClass.fromCp(0x41) === "A");
  check("b.codepointClass.escapeRegExp",
        b.codepointClass.escapeRegExp("a.b*c") === "a\\.b\\*c");
  check("b.codepointClass.isAsciiAlnum",
        b.codepointClass.isAsciiAlnum(0x5a) === true && b.codepointClass.isAsciiAlnum(0x2d) === false);
  check("b.codepointClass.isUnreserved",
        b.codepointClass.isUnreserved(0x7e) === true && b.codepointClass.isUnreserved(0x2f) === false);
  check("b.codepointClass.isForbiddenControlChar",
        b.codepointClass.isForbiddenControlChar(0x00) === true && b.codepointClass.isForbiddenControlChar(0x41) === false);
  check("b.codepointClass.firstControlCharOffset",
        b.codepointClass.firstControlCharOffset("ok\x00bad") === 2 && b.codepointClass.firstControlCharOffset("clean") === -1);
  check("b.codepointClass.decodeNumericEntities",
        b.codepointClass.decodeNumericEntities("&#106;avascript:") === "javascript:" &&
        b.codepointClass.decodeNumericEntities("&#106avascript:") === "javascript:");
  // The remaining catalog constants the issue lists are reachable.
  check("b.codepointClass.BOM_CHAR",
        typeof b.codepointClass.BOM_CHAR === "string" && b.codepointClass.BOM_CHAR.charCodeAt(0) === 0xFEFF);
}

async function run() {
  testIsForbiddenControlChar();
  testFirstControlCharOffset();
  testPublicSurface();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
