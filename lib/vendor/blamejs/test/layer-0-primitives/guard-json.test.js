// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-json — JSON content-safety primitive (b.guardJson).
 *
 * Covers: surface; registry parity; prototype-pollution detection at
 * source level (catches __proto__ / constructor / prototype keys
 * BEFORE parse — JSON.parse silently routes __proto__ through the
 * prototype setter so post-parse Object.keys misses it); duplicate-key
 * detection; NaN / Infinity / undefined refusal; comment refusal
 * (line + block); trailing comma refusal; JSON5 syntax refusal
 * (single-quoted keys, hex literals); BOM detection; bidi / null /
 * control char detection; numeric precision-loss; depth + breadth +
 * array-length + string-length + node-count caps; top-level-key
 * allowlist; sanitize round-trip (strip pollution); gate decision
 * shapes; profile + posture vocabulary.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testGuardJsonSurface() {
  check("guardJson is an object",                    typeof b.guardJson === "object");
  check("guardJson.NAME === 'json'",                 b.guardJson.NAME === "json");
  check("guardJson.KIND === 'content'",              b.guardJson.KIND === "content");
  check("guardJson.MIME_TYPES has application/json", b.guardJson.MIME_TYPES.indexOf("application/json") !== -1);
  check("guardJson.EXTENSIONS has .json",            b.guardJson.EXTENSIONS.indexOf(".json") !== -1);
  check("guardJson.PROFILES has strict",             !!b.guardJson.PROFILES["strict"]);
  check("guardJson.PROFILES has balanced",           !!b.guardJson.PROFILES["balanced"]);
  check("guardJson.PROFILES has permissive",         !!b.guardJson.PROFILES["permissive"]);
  check("guardJson.COMPLIANCE_POSTURES has hipaa",   !!b.guardJson.COMPLIANCE_POSTURES["hipaa"]);
  check("guardJson.validate is a function",          typeof b.guardJson.validate === "function");
  check("guardJson.parse is a function",             typeof b.guardJson.parse === "function");
  check("guardJson.gate is a function",              typeof b.guardJson.gate === "function");
  check("guardJson.GuardJsonError is a function",    typeof b.guardJson.GuardJsonError === "function");
  check("frameworkError.GuardJsonError exposed",     typeof b.frameworkError.GuardJsonError === "function");
}

function testGuardJsonRegistryParity() {
  check("guardJson registered in guardAll",
        b.guardAll.list().some(function (g) { return g.name === "json"; }));
  var entry = b.guardAll.list().filter(function (g) { return g.name === "json"; })[0];
  b.guardAll.SHARED_PROFILES.forEach(function (p) {
    check("registry: json supports shared profile " + p,
          entry.profiles.indexOf(p) !== -1);
  });
  b.guardAll.SHARED_POSTURES.forEach(function (p) {
    check("registry: json supports shared posture " + p,
          entry.postures.indexOf(p) !== -1);
  });
}

function testGuardJsonPrototypePollution() {
  // Plain __proto__ at top level. After JSON.parse, this is invisible
  // to Object.keys() — the source-level scan is the only reliable
  // detection (CVE-2025-55182 React Server Functions class).
  var rv1 = b.guardJson.validate('{"__proto__":{"polluted":true}}',
                                 { profile: "strict" });
  check("source-level __proto__ detected (strict)",
        rv1.ok === false &&
        rv1.issues.some(function (i) { return i.kind === "prototype-pollution-key"; }));

  // constructor / prototype at any depth.
  var rv2 = b.guardJson.validate('{"x":{"constructor":{"y":1}}}',
                                 { profile: "strict" });
  check("nested constructor key detected",
        rv2.issues.some(function (i) { return i.kind === "prototype-pollution-key"; }));

  var rv3 = b.guardJson.validate('{"a":{"prototype":1}}',
                                 { profile: "strict" });
  check("nested prototype key detected",
        rv3.issues.some(function (i) { return i.kind === "prototype-pollution-key"; }));

  // Audit-level under permissive.
  var rv4 = b.guardJson.validate('{"__proto__":{"x":1}}',
                                 { profile: "permissive" });
  check("permissive: pollution audited (high severity, ok=false because high counts)",
        rv4.issues.some(function (i) { return i.kind === "prototype-pollution-key"; }));
}

function testGuardJsonParseStripPollution() {
  // strict throws on pollution.
  var threw = null;
  try { b.guardJson.parse('{"__proto__":{"x":1}}', { profile: "strict" }); }
  catch (e) { threw = e; }
  check("parse strict: throws on __proto__",
        threw && /prototype-pollution/.test(threw.code || threw.message || ""));

  // balanced strips and returns clean object.
  var clean = b.guardJson.parse('{"__proto__":{"x":1},"a":2,"b":3}',
                                { profile: "balanced" });
  check("parse balanced: strips __proto__",
        Object.keys(clean).length === 2 && clean.a === 2 && clean.b === 3);
  check("parse balanced: prototype not polluted via stripped __proto__",
        Object.prototype.x === undefined);
}

function testGuardJsonDuplicateKeys() {
  var rv = b.guardJson.validate('{"a":1,"a":2}', { profile: "strict" });
  check("duplicate-key detected (RFC 8259 SHOULD-unique violation)",
        rv.issues.some(function (i) { return i.kind === "duplicate-key"; }));

  var rvNested = b.guardJson.validate('{"x":{"a":1,"a":2}}', { profile: "strict" });
  check("nested duplicate-key detected",
        rvNested.issues.some(function (i) { return i.kind === "duplicate-key"; }));

  // Same key at DIFFERENT scopes — not a duplicate.
  var rvOk = b.guardJson.validate('{"x":{"a":1},"y":{"a":2}}', { profile: "strict" });
  check("same key at different scopes NOT flagged",
        !rvOk.issues.some(function (i) { return i.kind === "duplicate-key"; }));
}

function testGuardJsonNanInfinity() {
  var rv1 = b.guardJson.validate('{"x":NaN}', { profile: "strict" });
  check("NaN detected (RFC 8259 forbids)",
        rv1.issues.some(function (i) { return i.kind === "nan-infinity"; }));

  var rv2 = b.guardJson.validate('{"x":Infinity}', { profile: "strict" });
  check("Infinity detected",
        rv2.issues.some(function (i) { return i.kind === "nan-infinity"; }));

  var rv3 = b.guardJson.validate('{"x":-Infinity}', { profile: "strict" });
  check("-Infinity detected",
        rv3.issues.some(function (i) { return i.kind === "nan-infinity"; }));

  var rv4 = b.guardJson.validate('{"x":undefined}', { profile: "strict" });
  check("undefined token detected",
        rv4.issues.some(function (i) { return i.kind === "nan-infinity"; }));
}

function testGuardJsonComments() {
  var rvLine = b.guardJson.validate('// comment\n{"x":1}', { profile: "strict" });
  check("line comment detected (RFC 8259 forbids; JSON5 / JSONC accept)",
        rvLine.issues.some(function (i) { return i.kind === "comment-line"; }));

  var rvBlock = b.guardJson.validate('/* note */ {"x":1}', { profile: "strict" });
  check("block comment detected",
        rvBlock.issues.some(function (i) { return i.kind === "comment-block"; }));
}

function testGuardJsonTrailingComma() {
  var rv = b.guardJson.validate('{"x":1,}', { profile: "strict" });
  check("trailing comma detected (RFC 8259 forbids)",
        rv.issues.some(function (i) { return i.kind === "trailing-comma"; }));
}

function testGuardJsonJson5Syntax() {
  // Single-quoted key — JSON5 / JSONC only.
  var rvSq = b.guardJson.validate("{'x':1}", { profile: "strict" });
  check("single-quoted key detected (JSON5-only)",
        rvSq.issues.some(function (i) { return i.kind === "single-quoted-key"; }));

  // Hex literal.
  var rvHex = b.guardJson.validate('{"x":0xFF}', { profile: "strict" });
  check("hex literal detected (JSON5-only)",
        rvHex.issues.some(function (i) { return i.kind === "hex-literal"; }));
}

function testGuardJsonBom() {
  var bom = String.fromCharCode(0xFEFF);
  var rvLead = b.guardJson.validate(bom + '{"x":1}', { profile: "strict" });
  check("leading BOM detected",
        rvLead.issues.some(function (i) { return i.kind === "bom-leading"; }));

  var rvMid = b.guardJson.validate('{"x":' + bom + '1}', { profile: "strict" });
  check("mid-stream BOM detected",
        rvMid.issues.some(function (i) { return i.kind === "bom-mid-stream"; }));
}

function testGuardJsonDepthCap() {
  // Build deeply nested JSON exceeding strict maxDepth=8.
  var deep = "";
  for (var i = 0; i < 20; i++) deep += '{"x":';
  deep += "1";
  for (var j = 0; j < 20; j++) deep += "}";
  var rv = b.guardJson.validate(deep, { profile: "strict" });
  check("depth-cap detected",
        rv.issues.some(function (i) { return i.kind === "depth-cap" ||
                                              i.kind === "parse-failed"; }));
}

function testGuardJsonKeyCountCap() {
  var keys = [];
  for (var i = 0; i < 1000; i++) keys.push('"k' + i + '":' + i);
  var rv = b.guardJson.validate("{" + keys.join(",") + "}", { profile: "strict" });
  check("key-count cap detected (strict 256 cap)",
        rv.issues.some(function (i) { return i.kind === "key-count-cap"; }));
}

function testGuardJsonArrayLengthCap() {
  var elems = [];
  for (var i = 0; i < 5000; i++) elems.push(String(i));
  var rv = b.guardJson.validate("[" + elems.join(",") + "]", { profile: "strict" });
  check("array-length cap detected (strict 1024 cap)",
        rv.issues.some(function (i) { return i.kind === "array-length-cap"; }));
}

function testGuardJsonStringLengthCap() {
  // Strict maxStringLength = 8 KiB.
  var bigStr = '"' + "x".repeat(10000) + '"';
  var rv = b.guardJson.validate('{"k":' + bigStr + '}', { profile: "strict" });
  check("string-length cap detected",
        rv.issues.some(function (i) { return i.kind === "string-too-long"; }));
}

function testGuardJsonStringLengthByteCap() {
  // maxStringLength is a per-string BYTE cap (strict 8 KiB). A multibyte string
  // whose UTF-16 code-unit count is UNDER the cap but whose UTF-8 byte length
  // EXCEEDS it must still be refused — value.length (code units) under-enforces.
  // 4100 'é' = 4100 code units (< 8192) but 8200 UTF-8 bytes (> 8192).
  var multibyte = "é".repeat(4100);
  var rv = b.guardJson.validate('{"k":"' + multibyte + '"}', { profile: "strict" });
  check("per-string maxStringLength measured in UTF-8 bytes (multibyte not under-enforced)",
        rv.issues.some(function (i) { return i.kind === "string-too-long"; }));
}

function testGuardJsonByteCap() {
  // maxBytes is a BYTE cap — multibyte input must be measured by UTF-8
  // byte length, not UTF-16 code-unit count (.length). "é" is one code
  // unit but two bytes, so a string under the char count can still
  // exceed the byte cap.
  var inner = "é".repeat(25);
  var s     = JSON.stringify(inner);               // .length ~27, bytes ~52
  var byteLen = Buffer.byteLength(s, "utf8");
  // Cap sits between the code-unit count and the byte length so a
  // char-length check would (wrongly) pass while a byte check refuses.
  var cap = s.length + 5;
  check("byte-cap fixture: bytes exceed cap but code units do not",
        byteLen > cap && s.length <= cap);
  var rv = b.guardJson.validate(s, { maxBytes: cap });
  check("multibyte input over the byte cap is refused (too-large by bytes)",
        rv.issues.some(function (i) {
          return i.kind === "too-large" && i.ruleId === "json.too-large";
        }));

  // ASCII inputs (one byte per code unit) are unaffected — a byte-length
  // cap that exactly admits the string must still pass.
  var ascii = '"' + "x".repeat(20) + '"';           // 22 bytes, 22 code units
  var rvAscii = b.guardJson.validate(ascii, { maxBytes: 64 });
  check("ASCII input within the byte cap is not flagged too-large",
        !rvAscii.issues.some(function (i) { return i.kind === "too-large"; }));

  // Non-string input keeps the bad-input shape and now carries a ruleId.
  var rvBad = b.guardJson.validate(12345, { maxBytes: 64 });
  check("non-string input → bad-input with json.bad-input ruleId",
        rvBad.issues.some(function (i) {
          return i.kind === "bad-input" && i.ruleId === "json.bad-input";
        }));
}

function testGuardJsonNumericPrecision() {
  var rv = b.guardJson.validate('{"id":99999999999999999999}', { profile: "strict" });
  check("numeric precision-loss detected (above MAX_SAFE_INTEGER)",
        rv.issues.some(function (i) { return i.kind === "numeric-precision-loss"; }));
}

function testGuardJsonTopLevelKeyAllowlist() {
  var rv = b.guardJson.validate('{"a":1,"b":2,"unauthorized":3}', {
    profile:                      "strict",
    requireTopLevelKeyAllowlist:  true,
    topLevelKeyAllowlist:         ["a", "b"],
  });
  check("top-level-key allowlist refuses unauthorized key",
        rv.issues.some(function (i) {
          return i.kind === "top-level-key-not-allowlisted";
        }));

  var rvOk = b.guardJson.validate('{"a":1,"b":2}', {
    profile:               "strict",
    topLevelKeyAllowlist:  ["a", "b"],
  });
  check("top-level allowlist passes when keys all allowed",
        !rvOk.issues.some(function (i) {
          return i.kind === "top-level-key-not-allowlisted";
        }));
}

function testGuardJsonBidi() {
  var bidi = String.fromCharCode(0x202E);   // RLO
  var rv = b.guardJson.validate('{"x":"a' + bidi + 'b"}', { profile: "strict" });
  check("bidi override detected in JSON string value",
        rv.issues.some(function (i) { return i.kind === "bidi-override"; }));
}

function testGuardJsonNullByte() {
  var nb = String.fromCharCode(0);
  var rv = b.guardJson.validate('{"x":"a' + nb + 'b"}', { profile: "strict" });
  check("null byte detected in JSON string",
        rv.issues.some(function (i) { return i.kind === "null-byte"; }));
}

function testGuardJsonClean() {
  var rv = b.guardJson.validate('{"name":"alice","age":30,"tags":["a","b"]}',
                                { profile: "strict" });
  check("clean JSON → ok=true with no issues", rv.ok === true && rv.issues.length === 0);
}

async function testGuardJsonGate() {
  var g = b.guardJson.gate({ profile: "strict" });
  var clean = await g.check({
    contentType: "application/json",
    bytes:       Buffer.from('{"x":1}', "utf8"),
  });
  check("gate clean → action=serve",
        clean.ok === true && clean.action === "serve");

  var hostile = await g.check({
    contentType: "application/json",
    bytes:       Buffer.from('{"__proto__":{"polluted":true}}', "utf8"),
  });
  check("gate hostile pollution → action !== serve",
        hostile.action !== "serve");
}

async function testGuardJsonGateSanitizeByPolicy() {
  // The gate decides sanitize-vs-refuse from the finding's OWN policy, not a
  // global "is any policy reject?" guess that wrongly blocked sanitize for
  // unrelated findings. So the SAME __proto__ input REFUSES under
  // pollutionPolicy=reject and SANITIZES under pollutionPolicy=strip (the
  // parse drops __proto__) — independent of the other policies' reject state.
  var pollute = Buffer.from('{"__proto__":{"x":1},"keep":2}', "utf8");
  var reject = await b.guardJson.gate({ profile: "strict", pollutionPolicy: "reject" })
    .check({ bytes: pollute });
  check("pollutionPolicy=reject → refuse", reject.action === "refuse");
  var strip = await b.guardJson.gate({ profile: "strict", pollutionPolicy: "strip" })
    .check({ bytes: pollute });
  check("pollutionPolicy=strip → sanitize (__proto__ dropped per policy)",
        strip.action === "sanitize" &&
        strip.sanitized.toString("utf8").indexOf("__proto__") === -1 &&
        strip.sanitized.toString("utf8").indexOf("keep") !== -1);
}

function testGuardJsonCompliancePosture() {
  var hipaa = b.guardJson.compliancePosture("hipaa");
  check("compliancePosture('hipaa') sets reject policies",
        hipaa.pollutionPolicy === "reject" &&
        hipaa.bidiPolicy === "reject" &&
        hipaa.duplicateKeyPolicy === "reject");

  var threw = null;
  try { b.guardJson.compliancePosture("unknown"); }
  catch (e) { threw = e; }
  check("compliancePosture: unknown name throws",
        threw && /unknown/.test(threw.message));
}

function testGuardJsonBadProfile() {
  var threw = null;
  try { b.guardJson.validate('{"x":1}', { profile: "made-up" }); }
  catch (e) { threw = e; }
  check("validate: unknown profile throws",
        threw && /unknown profile/i.test(threw.message));
}

async function run() {
  testGuardJsonSurface();
  testGuardJsonRegistryParity();
  testGuardJsonPrototypePollution();
  testGuardJsonParseStripPollution();
  testGuardJsonDuplicateKeys();
  testGuardJsonNanInfinity();
  testGuardJsonComments();
  testGuardJsonTrailingComma();
  testGuardJsonJson5Syntax();
  testGuardJsonBom();
  testGuardJsonDepthCap();
  testGuardJsonKeyCountCap();
  testGuardJsonArrayLengthCap();
  testGuardJsonStringLengthCap();
  testGuardJsonStringLengthByteCap();
  testGuardJsonByteCap();
  testGuardJsonNumericPrecision();
  testGuardJsonTopLevelKeyAllowlist();
  testGuardJsonBidi();
  testGuardJsonNullByte();
  testGuardJsonClean();
  testGuardJsonCompliancePosture();
  testGuardJsonBadProfile();
  await testGuardJsonGate();
  await testGuardJsonGateSanitizeByPolicy();
}

module.exports = { run: run };
