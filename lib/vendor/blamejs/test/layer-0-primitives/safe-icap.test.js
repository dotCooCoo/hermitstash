// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.safeIcap — RFC 3507 ICAP response parser.
 *
 * The lib is not yet wired into the public `b` object (no index.js
 * touch for this slice), so the test requires the lib module directly.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var safeIcap = require("../../lib/safe-icap");

function testSurface() {
  check("parse is fn",              typeof safeIcap.parse === "function");
  check("compliancePosture is fn",  typeof safeIcap.compliancePosture === "function");
  check("SafeIcapError is fn",      typeof safeIcap.SafeIcapError === "function");
  check("PROFILES has strict",      !!safeIcap.PROFILES.strict);
  check("PROFILES has balanced",    !!safeIcap.PROFILES.balanced);
  check("PROFILES has permissive",  !!safeIcap.PROFILES.permissive);
  check("posture hipaa → strict",   safeIcap.compliancePosture("hipaa") === "strict");
  check("posture pci-dss → strict", safeIcap.compliancePosture("pci-dss") === "strict");
  check("posture gdpr → strict",    safeIcap.compliancePosture("gdpr") === "strict");
  check("posture soc2 → strict",    safeIcap.compliancePosture("soc2") === "strict");
  check("posture bogus → null",     safeIcap.compliancePosture("bogus") === null);
  check("NAME is icap",             safeIcap.NAME === "icap");
  check("KIND is icap-response",    safeIcap.KIND === "icap-response");
}

function testParseHappyPath204() {
  var buf = Buffer.from(
    "ICAP/1.0 204 No Content\r\n" +
    "ISTag: \"clean\"\r\n" +
    "Service: c-icap/0.5.10\r\n" +
    "\r\n", "ascii");
  var rv = safeIcap.parse(buf);
  check("204 parses cleanly",       rv.statusCode === 204);
  check("statusText preserved",     rv.statusText === "No Content");
  check("istag header lowercased",  rv.headers["istag"] === '"clean"');
  check("service header lowercased", rv.headers["service"] === "c-icap/0.5.10");
  check("encapsulated absent → null", rv.encapsulated === null);
  check("body empty",               rv.body.length === 0);
  check("threatFound is false",     rv.threatFound === false);
}

function testParseEncapsulated() {
  var body = "BODY-BYTES";
  var buf = Buffer.from(
    "ICAP/1.0 200 OK\r\n" +
    "Encapsulated: res-hdr=0, res-body=42\r\n" +
    "\r\n" + body, "ascii");
  var rv = safeIcap.parse(buf);
  check("200 parses",                rv.statusCode === 200);
  check("encapsulated parsed",       rv.encapsulated && rv.encapsulated["res-hdr"] === 0);
  check("encapsulated res-body=42",  rv.encapsulated["res-body"] === 42);
  check("body slice present",        rv.body.toString("ascii") === body);
}

function testParseInfectionFound() {
  var buf = Buffer.from(
    "ICAP/1.0 200 OK\r\n" +
    "X-Infection-Found: Type=0; Resolution=2; Threat=EICAR-Test-File\r\n" +
    "Encapsulated: res-hdr=0, res-body=0\r\n" +
    "\r\n", "ascii");
  var rv = safeIcap.parse(buf);
  check("threatFound true on X-Infection-Found",  rv.threatFound === true);
  check("threatName extracted from Threat= token", rv.threatName === "EICAR-Test-File");
}

function testParseStatus403IsThreat() {
  var buf = Buffer.from(
    "ICAP/1.0 403 Forbidden\r\n" +
    "X-Block-Reason: virus\r\n" +
    "\r\n", "ascii");
  var rv = safeIcap.parse(buf);
  check("403 → threatFound true",   rv.threatFound === true);
}

function expectThrow(label, fn, expectedCodePrefix) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, threw && typeof threw.code === "string" &&
    threw.code.indexOf(expectedCodePrefix) === 0);
}

function testRefuseBareCr() {
  // A bare-CR (CR not followed by LF) anywhere in the header region
  // is the canonical ICAP-response-injection vector.
  var buf = Buffer.from(
    "ICAP/1.0 200 OK\r\n" +
    "Bad: header\rContinued\r\n" +
    "\r\n", "ascii");
  expectThrow("refuses bare-CR",
    function () { safeIcap.parse(buf); }, "safe-icap/bare-cr-or-lf");
}

function testRefuseBareLf() {
  var buf = Buffer.from(
    "ICAP/1.0 200 OK\nBad: header\r\n\r\n", "ascii");
  expectThrow("refuses bare-LF",
    function () { safeIcap.parse(buf); }, "safe-icap/bare-cr-or-lf");
}

function testRefuseNul() {
  var bytes = Buffer.from("ICAP/1.0 200 OK\r\nHdr: bad\0byte\r\n\r\n", "binary");
  expectThrow("refuses NUL in header",
    function () { safeIcap.parse(bytes); }, "safe-icap/nul-in-header");
}

function testRefuseUnexpectedStatus() {
  // 301 is NOT in the RFC 3507 §4.3.3 allowlist — a 3xx redirect from
  // an ICAP server is a smuggling shape.
  var buf = Buffer.from("ICAP/1.0 301 Moved\r\n\r\n", "ascii");
  expectThrow("refuses 301",
    function () { safeIcap.parse(buf); }, "safe-icap/unexpected-status");
}

function testRefuseBadStatusLine() {
  var buf = Buffer.from("HTTP/1.1 200 OK\r\n\r\n", "ascii");
  expectThrow("refuses non-ICAP prefix",
    function () { safeIcap.parse(buf); }, "safe-icap/bad-status-line");
}

function testRefuseOversizeHeader() {
  // Strict profile cap: 8 KiB of headers. Build a header block that
  // never reaches the terminating CRLFCRLF within the cap.
  var pad = new Array(9000).join("A");                                                             // > 8 KiB pre-CRLFCRLF
  var buf = Buffer.from("ICAP/1.0 200 OK\r\nX: " + pad + "\r\n\r\n", "ascii");
  expectThrow("refuses oversize header",
    function () { safeIcap.parse(buf); }, "safe-icap/oversize-header");
}

function testRefuseOversizeBody() {
  var pad = Buffer.alloc(2 * 1024 * 1024, 0x41);                                                   // 2 MiB > 1 MiB strict cap
  var hdr = Buffer.from(
    "ICAP/1.0 200 OK\r\nEncapsulated: res-hdr=0, res-body=0\r\n\r\n", "ascii");
  var buf = Buffer.concat([hdr, pad]);
  expectThrow("refuses oversize body",
    function () { safeIcap.parse(buf); }, "safe-icap/oversize-body");
}

function testRefuseBadEncapsulated() {
  var buf = Buffer.from(
    "ICAP/1.0 200 OK\r\nEncapsulated: bogus-part=0\r\n\r\n", "ascii");
  expectThrow("refuses unknown Encapsulated part",
    function () { safeIcap.parse(buf); }, "safe-icap/bad-encapsulated");
  var buf2 = Buffer.from(
    "ICAP/1.0 200 OK\r\nEncapsulated: res-body=not-a-number\r\n\r\n", "ascii");
  expectThrow("refuses non-numeric Encapsulated offset",
    function () { safeIcap.parse(buf2); }, "safe-icap/bad-encapsulated");
}

function testRefuseBadInput() {
  expectThrow("refuses non-Buffer",
    function () { safeIcap.parse("not-a-buffer"); }, "safe-icap/bad-input");
}

function testRefuseBadProfile() {
  var buf = Buffer.from("ICAP/1.0 204 No Content\r\n\r\n", "ascii");
  expectThrow("refuses unknown profile",
    function () { safeIcap.parse(buf, { profile: "loose" }); }, "safe-icap/bad-profile");
}

function testProfilePostureRouting() {
  // Permissive profile allows a larger header.
  var pad = new Array(12 * 1024).join("A");                                                        // ~12 KiB > strict cap but < permissive cap
  var buf = Buffer.from("ICAP/1.0 200 OK\r\nX: " + pad + "\r\n\r\n", "ascii");
  var rv = safeIcap.parse(buf, { profile: "permissive" });
  check("permissive profile accepts 12 KiB header", rv.statusCode === 200);
  // Posture maps to strict (rejection).
  expectThrow("hipaa posture rejects 12 KiB header",
    function () { safeIcap.parse(buf, { posture: "hipaa" }); }, "safe-icap/oversize-header");
}

function testBSurface() {
  var b = require("../../");
  check("b.safeIcap.parse wired",              typeof b.safeIcap.parse === "function");
  check("b.safeIcap.compliancePosture wired",  typeof b.safeIcap.compliancePosture === "function");
  check("b.safeIcap.SafeIcapError wired",      typeof b.safeIcap.SafeIcapError === "function");
}

function run() {
  testBSurface();
  testSurface();
  testParseHappyPath204();
  testParseEncapsulated();
  testParseInfectionFound();
  testParseStatus403IsThreat();
  testRefuseBareCr();
  testRefuseBareLf();
  testRefuseNul();
  testRefuseUnexpectedStatus();
  testRefuseBadStatusLine();
  testRefuseOversizeHeader();
  testRefuseOversizeBody();
  testRefuseBadEncapsulated();
  testRefuseBadInput();
  testRefuseBadProfile();
  testProfilePostureRouting();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[safe-icap] OK"); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}
