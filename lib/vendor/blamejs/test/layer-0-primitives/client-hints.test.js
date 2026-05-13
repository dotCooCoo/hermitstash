"use strict";
/**
 * b.clientHints — Sec-CH-UA-* request-header parser + Accept-CH builder.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("clientHints.parse is fn",       typeof b.clientHints.parse === "function");
  check("clientHints.acceptList is fn",  typeof b.clientHints.acceptList === "function");
  check("clientHints.isKnownHint is fn", typeof b.clientHints.isKnownHint === "function");
  check("KNOWN_HINTS is array",          Array.isArray(b.clientHints.KNOWN_HINTS));
  check("ClientHintsError is fn",        typeof b.clientHints.ClientHintsError === "function");
}

function testParseHappy() {
  var ch = b.clientHints.parse({
    "sec-ch-ua":              '"Chromium";v="124", "Not-A.Brand";v="99", "Google Chrome";v="124"',
    "sec-ch-ua-mobile":       "?0",
    "sec-ch-ua-platform":     '"Windows"',
    "sec-ch-ua-platform-version": '"15.0.0"',
    "sec-ch-ua-arch":         '"x86"',
    "sec-ch-ua-bitness":      '"64"',
    "sec-ch-ua-model":        '""',
    "sec-ch-ua-wow64":        "?0",
    "x-other":                "ignored",
  });
  check("parse: brands length 3",       Array.isArray(ch.brands) && ch.brands.length === 3);
  check("parse: first brand Chromium",  ch.brands[0].brand === "Chromium");
  check("parse: first brand version",   ch.brands[0].version === "124");
  check("parse: mobile false",          ch.mobile === false);
  check("parse: platform Windows",      ch.platform === "Windows");
  check("parse: platformVersion",       ch.platformVersion === "15.0.0");
  check("parse: arch x86",              ch.arch === "x86");
  check("parse: bitness 64",            ch.bitness === "64");
  check("parse: empty model",           ch.model === "");
  check("parse: wow64 false",           ch.wow64 === false);
  check("parse: raw map captures Sec-CH-* only",
        Object.keys(ch.raw).every(function (k) { return k.indexOf("sec-ch-") === 0; }));
  check("parse: x-other excluded from raw", ch.raw["x-other"] === undefined);
}

function testParseMobileTrue() {
  var ch = b.clientHints.parse({ "sec-ch-ua-mobile": "?1" });
  check("parse: mobile true",  ch.mobile === true);
}

function testParseMalformedBoolean() {
  var ch = b.clientHints.parse({ "sec-ch-ua-mobile": "1" });
  check("parse: malformed mobile → null", ch.mobile === null);
}

function testParseAbsentHeaders() {
  var ch = b.clientHints.parse({});
  check("parse: no headers — brands null",   ch.brands === null);
  check("parse: no headers — mobile null",   ch.mobile === null);
  check("parse: no headers — platform null", ch.platform === null);
  check("parse: no headers — raw empty",     Object.keys(ch.raw).length === 0);
}

function testParseBadInput() {
  check("parse: null returns null",  b.clientHints.parse(null) === null);
  check("parse: array returns null", b.clientHints.parse([]) === null);
  check("parse: string returns null", b.clientHints.parse("hi") === null);
}

function testParseControlByteRefusal() {
  function expectCode(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(code) !== -1);
  }
  expectCode("parse: CR/LF refused",
             function () { b.clientHints.parse({ "sec-ch-ua-platform": '"Win\r\nattack"' }); }, "client-hints/bad-header-value");
  expectCode("parse: NUL refused",
             function () { b.clientHints.parse({ "sec-ch-ua-mobile": "?1\x00" }); }, "client-hints/bad-header-value");
}

function testAcceptList() {
  check("acceptList: dedupes + canonicalizes",
        b.clientHints.acceptList(["sec-ch-ua-mobile", "Sec-CH-UA-Mobile", "Sec-CH-UA-Platform"]) ===
          "Sec-CH-UA-Mobile, Sec-CH-UA-Platform");
  check("acceptList: single",
        b.clientHints.acceptList(["Sec-CH-UA-Mobile"]) === "Sec-CH-UA-Mobile");

  function expectCode(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(code) !== -1);
  }
  expectCode("acceptList: empty array refused",
             function () { b.clientHints.acceptList([]); }, "client-hints/bad-hint-list");
  expectCode("acceptList: non-array refused",
             function () { b.clientHints.acceptList(null); }, "client-hints/bad-hint-list");
  expectCode("acceptList: unknown hint refused",
             function () { b.clientHints.acceptList(["Sec-CH-UA-Plateform"]); }, "client-hints/unknown-hint");
  expectCode("acceptList: empty string entry refused",
             function () { b.clientHints.acceptList([""]); }, "client-hints/bad-hint-name");
}

function testIsKnownHint() {
  check("isKnownHint: known canonical",
        b.clientHints.isKnownHint("Sec-CH-UA-Mobile") === true);
  check("isKnownHint: known lowercase",
        b.clientHints.isKnownHint("sec-ch-ua-platform") === true);
  check("isKnownHint: unknown",
        b.clientHints.isKnownHint("X-Custom") === false);
  check("isKnownHint: empty",
        b.clientHints.isKnownHint("") === false);
  check("isKnownHint: non-string",
        b.clientHints.isKnownHint(null) === false);
}

async function run() {
  testSurface();
  testParseHappy();
  testParseMobileTrue();
  testParseMalformedBoolean();
  testParseAbsentHeaders();
  testParseBadInput();
  testParseControlByteRefusal();
  testAcceptList();
  testIsKnownHint();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
