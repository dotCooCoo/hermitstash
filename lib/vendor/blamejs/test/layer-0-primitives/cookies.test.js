// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.cookies.parseSafe — threat-detecting inbound-cookie parser.
 *
 * Drives the advertised `{ jar, issues }` contract against clean and
 * hostile Cookie headers: duplicate names (cookie-tossing), a
 * `__proto__` key (prototype-pollution attempt), CR/LF/NUL injection,
 * oversized header / name / value, malformed pairs, and non-string
 * input.
 *
 * Run standalone: `node test/layer-0-primitives/cookies.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function testCleanHeaderParses() {
  var rv = b.cookies.parseSafe("a=1; b=two; c=three");
  check("parseSafe: clean header yields no issues", rv.issues.length === 0);
  check("parseSafe: jar carries every pair", rv.jar.a === "1" && rv.jar.b === "two" && rv.jar.c === "three");
}

function testEmptyHeader() {
  var rv = b.cookies.parseSafe("");
  check("parseSafe: empty header → empty jar, no issues",
    rv.issues.length === 0 && Object.keys(rv.jar).length === 0);
}

function testDuplicateNameCookieTossing() {
  // A parent-domain cookie shadowing the legitimate one appears twice;
  // browsers apply last-write-wins. parseSafe surfaces it as a HIGH
  // issue so the middleware can refuse (cookie-tossing class).
  var rv = b.cookies.parseSafe("session=abc; session=evil");
  check("parseSafe: duplicate-name surfaced", rv.issues.length === 1);
  check("parseSafe: duplicate-name is HIGH severity",
    rv.issues[0].kind === "duplicate-name" && rv.issues[0].severity === "high");
  check("parseSafe: duplicate-name issue names the cookie", rv.issues[0].name === "session");
  check("parseSafe: jar reflects last-write-wins (browser parity)", rv.jar.session === "evil");
}

function testProtoKeyDoesNotPollute() {
  // A hostile `__proto__` cookie name must NOT reach Object.prototype.
  // The jar is a null-prototype object so the key lands as an OWN data
  // property and the global prototype is untouched.
  var rv = b.cookies.parseSafe("a=1; __proto__=polluted; b=2");
  check("parseSafe: global Object.prototype not polluted",
    ({}).polluted === undefined && Object.prototype.polluted === undefined);
  check("parseSafe: jar has null prototype (pollution-proof)",
    Object.getPrototypeOf(rv.jar) === null);
  check("parseSafe: legitimate pairs still parse alongside the hostile key",
    rv.jar.a === "1" && rv.jar.b === "2");
  // The __proto__ value lands as an own data property, not a prototype swap.
  check("parseSafe: __proto__ captured as an own data property",
    Object.prototype.hasOwnProperty.call(rv.jar, "__proto__") && rv.jar.__proto__ === "polluted");
}

function testControlByteInjection() {
  // CR / LF / NUL smuggled through a proxy is a header-injection vector;
  // parseSafe refuses the whole header (empty jar) with a HIGH issue.
  var rv = b.cookies.parseSafe("a=1\r\nSet-Cookie: evil=1");
  check("parseSafe: control byte → header-control-byte HIGH issue",
    rv.issues.length === 1 && rv.issues[0].kind === "header-control-byte" &&
    rv.issues[0].severity === "high");
  check("parseSafe: control-byte header yields empty jar (fail-closed)",
    Object.keys(rv.jar).length === 0);
}

function testNonStringInput() {
  var rv = b.cookies.parseSafe(12345);
  check("parseSafe: non-string input → bad-input HIGH issue",
    rv.issues.length === 1 && rv.issues[0].kind === "bad-input" &&
    rv.issues[0].severity === "high");
  check("parseSafe: non-string input → empty jar", Object.keys(rv.jar).length === 0);
}

function testHeaderCap() {
  var big = "x=" + "A".repeat(200);
  var rv = b.cookies.parseSafe(big, { maxHeaderBytes: 64 });
  check("parseSafe: oversized header → header-cap HIGH issue",
    rv.issues.length === 1 && rv.issues[0].kind === "header-cap" &&
    rv.issues[0].severity === "high");
  check("parseSafe: over-cap header parses no pairs", rv.jar.x === undefined);
}

function testNameAndValueCap() {
  var rvName = b.cookies.parseSafe("thisnameistoolong=v", { maxNameBytes: 4 });
  check("parseSafe: over-long name → name-cap HIGH issue",
    rvName.issues.some(function (i) { return i.kind === "name-cap" && i.severity === "high"; }));
  check("parseSafe: over-cap name not admitted to jar", rvName.jar.thisnameistoolong === undefined);

  var rvVal = b.cookies.parseSafe("k=" + "V".repeat(50), { maxValueBytes: 8 });
  check("parseSafe: over-long value → value-cap HIGH issue",
    rvVal.issues.some(function (i) { return i.kind === "value-cap" && i.severity === "high"; }));
  check("parseSafe: over-cap value not admitted to jar", rvVal.jar.k === undefined);
}

function testMalformedAndEmptyName() {
  var rvMalformed = b.cookies.parseSafe("novalue; a=1");
  check("parseSafe: pair missing `=` → pair-malformed WARN",
    rvMalformed.issues.some(function (i) { return i.kind === "pair-malformed" && i.severity === "warn"; }));
  check("parseSafe: malformed pair skipped but valid pair still parses",
    rvMalformed.jar.a === "1");

  var rvEmpty = b.cookies.parseSafe("=orphan; b=2");
  check("parseSafe: empty name → pair-empty-name WARN",
    rvEmpty.issues.some(function (i) { return i.kind === "pair-empty-name" && i.severity === "warn"; }));
  check("parseSafe: empty-name pair skipped, valid pair parses", rvEmpty.jar.b === "2");
}

function testUrlDecodeAndQuoteStrip() {
  var rv = b.cookies.parseSafe('greeting="hello%20world"');
  check("parseSafe: double-quotes stripped + percent-decoded",
    rv.jar.greeting === "hello world" && rv.issues.length === 0);
}

function run() {
  testCleanHeaderParses();
  testEmptyHeader();
  testDuplicateNameCookieTossing();
  testProtoKeyDoesNotPollute();
  testControlByteInjection();
  testNonStringInput();
  testHeaderCap();
  testNameAndValueCap();
  testMalformedAndEmptyName();
  testUrlDecodeAndQuoteStrip();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.message); process.exit(1); }
  );
}
