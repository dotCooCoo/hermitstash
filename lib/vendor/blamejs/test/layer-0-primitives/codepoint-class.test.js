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

async function run() {
  testIsForbiddenControlChar();
  testFirstControlCharOffset();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
