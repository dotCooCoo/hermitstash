// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-text — general-purpose UTF-8 free-text content-safety primitive
 * (b.guardText).
 *
 * Covers: required guard-family surface (NAME / KIND / MIME_TYPES /
 * EXTENSIONS / PROFILES / COMPLIANCE_POSTURES / validate / sanitize / gate /
 * buildProfile / compliancePosture / loadRulePack / INTEGRATION_FIXTURES +
 * GuardTextError); the codepoint threat catalog (bidi override / C0 control /
 * null byte / zero-width / Unicode Tags / mixed-script confusable);
 * byte-accurate maxBytes on multibyte input; multibyte legitimate-script
 * preservation; sanitize strip + amplification cap; non-repairable confusable;
 * the gate serve→audit-only→sanitize→refuse decision chain; operator rules;
 * profile + posture composition; registration in b.guardAll.allGuards().
 *
 * Hostile codepoints are constructed via String.fromCharCode so this test
 * source stays pure ASCII (the guard-family source-purity invariant).
 *
 * Run standalone: node test/layer-0-primitives/guard-text.test.js
 * Or via smoke:   node test/smoke.js
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// Hostile codepoints, built numerically.
var RLO  = String.fromCharCode(0x202E);   // RIGHT-TO-LEFT OVERRIDE (bidi)
var LRO  = String.fromCharCode(0x202D);   // LEFT-TO-RIGHT OVERRIDE (bidi)
var NUL  = String.fromCharCode(0x00);     // null byte
var BELL = String.fromCharCode(0x07);     // C0 control
var ZWSP = String.fromCharCode(0x200B);   // ZERO WIDTH SPACE
var ZWNJ = String.fromCharCode(0x200C);   // ZERO WIDTH NON-JOINER
var TAGA = String.fromCodePoint(0xE0041); // Unicode Tags block "A" (ASCII smuggling; astral — needs fromCodePoint)
var CYR_A = String.fromCharCode(0x0430);  // Cyrillic small a (confusable with Latin a)

// ---- surface ----

function testSurface() {
  check("guardText is an object",                typeof b.guardText === "object");
  check("guardText.NAME === text",               b.guardText.NAME === "text");
  check("guardText.KIND === content",            b.guardText.KIND === "content");
  check("guardText.MIME_TYPES includes text/plain",
    b.guardText.MIME_TYPES.indexOf("text/plain") !== -1);
  check("guardText.EXTENSIONS includes .txt",
    b.guardText.EXTENSIONS.indexOf(".txt") !== -1);
  check("guardText.validate is a function",      typeof b.guardText.validate === "function");
  check("guardText.sanitize is a function",      typeof b.guardText.sanitize === "function");
  check("guardText.gate is a function",          typeof b.guardText.gate === "function");
  check("guardText.buildProfile is a function",  typeof b.guardText.buildProfile === "function");
  check("guardText.compliancePosture is a function",
    typeof b.guardText.compliancePosture === "function");
  check("guardText.loadRulePack is a function",  typeof b.guardText.loadRulePack === "function");
  check("guardText.INTEGRATION_FIXTURES is an object",
    typeof b.guardText.INTEGRATION_FIXTURES === "object");
  check("guardText.GuardTextError is a function",
    typeof b.guardText.GuardTextError === "function");
}

function testProfilesAndPostures() {
  var p = Object.keys(b.guardText.PROFILES);
  check("PROFILES has strict/balanced/permissive",
    p.indexOf("strict") !== -1 && p.indexOf("balanced") !== -1 && p.indexOf("permissive") !== -1);
  var c = Object.keys(b.guardText.COMPLIANCE_POSTURES);
  check("POSTURES has hipaa/pci-dss/gdpr/soc2",
    c.indexOf("hipaa") !== -1 && c.indexOf("pci-dss") !== -1 &&
    c.indexOf("gdpr") !== -1 && c.indexOf("soc2") !== -1);
  // buildProfile composes overlays without mutating the frozen preset.
  var prof = b.guardText.buildProfile({ baseProfile: "strict", overrides: { maxBytes: 1024 } });
  check("buildProfile overlays maxBytes",        prof.maxBytes === 1024);
  check("buildProfile keeps strict bidi reject",  prof.bidiPolicy === "reject");
  // compliancePosture resolves a known posture.
  var hipaa = b.guardText.compliancePosture("hipaa");
  check("compliancePosture hipaa bidi reject",    hipaa.bidiPolicy === "reject");
}

function testRegisteredInGuardAll() {
  var names = b.guardAll.allGuards().map(function (g) { return g.NAME; });
  check("text registered in b.guardAll.allGuards()", names.indexOf("text") !== -1);
}

function testGdprPostureMatchesBalancedTier() {
  // text is a content guard: gdpr maps to the balanced tier, whose maxBytes
  // is 4 MiB. A hand-rolled partial posture omitting maxBytes silently
  // backfills the strict 1 MiB cap from DEFAULTS — an incoherent hybrid. The
  // routed posture inherits the full balanced tier, so maxBytes is 4194304.
  var gdpr = b.guardText.COMPLIANCE_POSTURES.gdpr;
  check("gdpr posture maxBytes is balanced-tier 4 MiB", gdpr.maxBytes === 4194304);
  // Consumer-path proof: a 2 MiB input (between the strict 1 MiB and balanced
  // 4 MiB caps) validates OK under the gdpr posture. Under the strict-backfill
  // hybrid it was rejected as too-large.
  var twoMiB = "a".repeat(2 * 1024 * 1024);
  var rv = b.guardText.validate(twoMiB, { compliancePosture: "gdpr" });
  check("2 MiB text validates OK under gdpr posture", rv.ok === true);
}

// ---- validate: each threat class ----

function testValidateBenign() {
  var rv = b.guardText.validate("a perfectly ordinary review", { profile: "strict" });
  check("benign text ok",                        rv.ok === true);
  check("benign text has no issues",             rv.issues.length === 0);
}

function testValidateBidi() {
  var rv = b.guardText.validate("review " + RLO + "txt.exe", { profile: "strict" });
  check("bidi override not ok",                  rv.ok === false);
  check("bidi override kind",
    rv.issues.some(function (i) { return i.kind === "bidi-override"; }));
  // LRO is also a bidi override.
  var rv2 = b.guardText.validate("a" + LRO + "b", { profile: "strict" });
  check("LRO bidi override not ok",              rv2.ok === false);
}

function testValidateControl() {
  var rv = b.guardText.validate("log line" + BELL + "injection", { profile: "strict" });
  check("control char not ok",                   rv.ok === false);
  check("control char kind",
    rv.issues.some(function (i) { return i.kind === "control-char"; }));
}

function testValidateNullByte() {
  var rv = b.guardText.validate("name" + NUL + "truncate", { profile: "strict" });
  check("null byte not ok",                      rv.ok === false);
  check("null byte kind",
    rv.issues.some(function (i) { return i.kind === "null-byte"; }));
}

function testValidateZeroWidth() {
  var rv = b.guardText.validate("hid" + ZWSP + "den", { profile: "strict" });
  check("zero-width not ok",                      rv.ok === false);
  check("zero-width kind",
    rv.issues.some(function (i) { return i.kind === "zero-width"; }));
}

function testValidateUnicodeTags() {
  // ASCII-smuggling: an invisible Tags-block instruction (prompt injection).
  var rv = b.guardText.validate("hello" + TAGA + "world", { profile: "strict" });
  check("unicode-tags not ok",                    rv.ok === false);
  check("unicode-tags kind critical",
    rv.issues.some(function (i) {
      return i.kind === "unicode-tags" && i.severity === "critical";
    }));
}

function testValidateConfusableStrictRefuses() {
  // A Latin word with one Cyrillic letter swapped in (UTS #39 confusable).
  var rv = b.guardText.validate("p" + CYR_A + "ypal", { profile: "strict" });
  check("mixed-script confusable not ok under strict", rv.ok === false);
  check("confusable kind",
    rv.issues.some(function (i) { return i.kind === "mixed-script-confusable"; }));
}

function testValidateConfusableAuditOnlyUnderPermissive() {
  // permissive: confusablePolicy "allow" -> not even reported.
  var rv = b.guardText.validate("p" + CYR_A + "ypal", { profile: "permissive" });
  check("confusable suppressed under permissive (allow)", rv.ok === true);
}

function testValidateMaxBytesByteAccurate() {
  // "€" is 3 UTF-8 bytes; 2 of them = 6 bytes > 5. text.length would be 2.
  var rv = b.guardText.validate("€€", { profile: "strict", maxBytes: 5 });
  check("maxBytes measured in bytes not chars",  rv.ok === false);
  check("too-large kind",
    rv.issues.some(function (i) { return i.kind === "too-large"; }));
  // 1 euro = 3 bytes <= 5 passes.
  var rv2 = b.guardText.validate("€", { profile: "strict", maxBytes: 5 });
  check("single euro within byte budget ok",     rv2.ok === true);
}

function testValidateMaxBytesInfinityThrows() {
  var threw = false;
  try { b.guardText.validate("x", { profile: "strict", maxBytes: Infinity }); }
  catch (e) { threw = e && e.code === "text.bad-opt"; }
  check("maxBytes Infinity throws config-time",  threw === true);
}

function testValidateMultibyteScriptsPreservedAsBenign() {
  // Legitimate single-script multilingual text is NOT an issue — the guard
  // imposes no grammar. Each is its own script (no mixing).
  check("Han text benign",        b.guardText.validate("你好世界", { profile: "strict" }).ok === true);
  check("Arabic text benign",     b.guardText.validate("مرحبا", { profile: "strict" }).ok === true);
  check("emoji benign",           b.guardText.validate("great product 👍", { profile: "strict" }).ok === true);
}

function testValidateBufferInput() {
  var rv = b.guardText.validate(Buffer.from("plain bytes", "utf8"), { profile: "strict" });
  check("Buffer input validates",                rv.ok === true);
}

// ---- encoding validity (byte → codepoint layer) ----

function testValidateInvalidEncoding() {
  // Overlong encoding of "/" (0x2F) as C0 AF — the classic UTF-8 filter bypass;
  // a lossy toString would launder it into U+FFFD.
  var overlong = Buffer.from([0x2F, 0xC0, 0xAF, 0x2F]);
  var rv = b.guardText.validate(overlong, { profile: "strict" });
  check("overlong UTF-8 flagged invalid-encoding", rv.ok === false &&
    rv.issues.some(function (i) { return i.kind === "invalid-encoding"; }));
  // Truncated multibyte (lead byte, no continuation).
  var trunc = b.guardText.validate(Buffer.from([0x41, 0xE2, 0x82]), { profile: "strict" });
  check("truncated UTF-8 flagged",                trunc.ok === false);
  // Well-formed multibyte passes the encoding check.
  check("valid UTF-8 (euro) passes encoding",
    b.guardText.validate(Buffer.from("€10", "utf8"), { profile: "strict" }).ok === true);
  // permissive audits (does not reject) malformed encoding.
  var perm = b.guardText.validate(Buffer.from([0xC0, 0xAF]), { profile: "permissive" });
  check("permissive encoding policy is audit (warn, ok stays by that axis)",
    perm.issues.some(function (i) { return i.kind === "invalid-encoding" && i.severity === "warn"; }));
}

// ---- keyspace bounds ----

function testValidateAsciiOnly() {
  var rv = b.guardText.validate("café", { profile: "strict", asciiOnly: true });
  check("asciiOnly flags non-ASCII",             rv.ok === false &&
    rv.issues.some(function (i) { return i.kind === "non-ascii"; }));
  check("asciiOnly allows pure ASCII",
    b.guardText.validate("plain ascii", { profile: "strict", asciiOnly: true }).ok === true);
}

function testValidateMaxCodepoint() {
  var astral = "hi " + String.fromCodePoint(0x1F600);
  var rv = b.guardText.validate(astral, { profile: "strict", maxCodepoint: 0xFFFF });
  check("maxCodepoint flags astral codepoint",   rv.ok === false &&
    rv.issues.some(function (i) { return i.kind === "codepoint-out-of-range"; }));
  check("maxCodepoint allows within ceiling",
    b.guardText.validate("你好", { profile: "strict", maxCodepoint: 0xFFFF }).ok === true);
}

async function testGateRefuseInvalidEncoding() {
  var overlong = Buffer.from([0x2F, 0xC0, 0xAF]);
  var v = await b.guardText.gate({ profile: "strict" }).check({ bytes: overlong });
  check("gate refuses malformed UTF-8",          v.action === "refuse");
}

// ---- sanitize ----

function testSanitizeStripsInvisibles() {
  var clean = b.guardText.sanitize("nice" + ZWSP + "re" + ZWNJ + "view", { profile: "balanced" });
  check("sanitize strips zero-width",            clean.indexOf(ZWSP) === -1 && clean.indexOf(ZWNJ) === -1);
  check("sanitize result text intact",           clean === "nicereview");
}

function testSanitizeStripsBidiControlNullTags() {
  var dirty = "a" + RLO + "b" + BELL + "c" + NUL + "d" + TAGA + "e";
  var clean = b.guardText.sanitize(dirty, { profile: "balanced" });
  check("sanitize strips bidi",   clean.indexOf(RLO) === -1);
  check("sanitize strips control", clean.indexOf(BELL) === -1);
  check("sanitize strips null",   clean.indexOf(NUL) === -1);
  check("sanitize strips tags",   clean.indexOf(TAGA) === -1);
  check("sanitize preserves letters", clean === "abcde");
}

function testSanitizePreservesMultibyte() {
  var clean = b.guardText.sanitize("你好" + ZWSP + "世界", { profile: "balanced" });
  check("sanitize preserves Han, strips zwsp",   clean === "你好世界");
}

function testSanitizeAmplificationContract() {
  // Sanitize is shrinking by contract: stripping can only remove, never grow.
  var clean = b.guardText.sanitize("hello world", { profile: "balanced" });
  check("sanitize never grows output",           clean.length <= "hello world".length);
}

// ---- gate decision chain ----

async function testGateServe() {
  var v = await b.guardText.gate({ profile: "strict" })
    .check({ bytes: Buffer.from("ordinary text", "utf8") });
  check("gate serve on benign",                  v.action === "serve");
}

async function testGateRefuseBidiStrict() {
  var v = await b.guardText.gate({ profile: "strict" })
    .check({ bytes: Buffer.from("ok " + RLO + "danger", "utf8") });
  check("gate refuse on bidi under strict",       v.action === "refuse" && v.ok === false);
}

async function testGateSanitizeBalanced() {
  // balanced strips invisibles -> sanitize action with cleaned bytes.
  var v = await b.guardText.gate({ profile: "balanced" })
    .check({ bytes: Buffer.from("nice" + ZWSP + "review", "utf8") });
  check("gate sanitize under balanced",           v.action === "sanitize");
  check("gate sanitize returns cleaned bytes",
    Buffer.isBuffer(v.sanitized) && v.sanitized.toString("utf8") === "nicereview");
}

async function testGateAuditOnlyConfusable() {
  // balanced confusablePolicy "audit" -> warn-only -> audit-only, not refuse.
  var v = await b.guardText.gate({ profile: "balanced" })
    .check({ bytes: Buffer.from("p" + CYR_A + "ypal", "utf8") });
  check("gate audit-only on balanced confusable", v.action === "audit-only");
}

async function testGateRefuseConfusableStrict() {
  // strict confusablePolicy "reject" -> high severity, non-repairable -> refuse.
  var v = await b.guardText.gate({ profile: "strict" })
    .check({ bytes: Buffer.from("p" + CYR_A + "ypal", "utf8") });
  check("gate refuse on strict confusable",       v.action === "refuse");
}

async function testGateOperatorRule() {
  var gate = b.guardText.gate({
    profile: "permissive",
    operatorRules: [{
      id: "no-profanity", severity: "high",
      detect: function (c) { return /badword/.test(c.bytes); },
      reason: "operator profanity filter",
    }],
  });
  var v = await gate.check({ bytes: Buffer.from("this has badword in it", "utf8") });
  check("operator rule fires -> refuse",          v.action === "refuse");
  check("operator rule issue surfaced",
    v.issues.some(function (i) { return i.kind === "no-profanity"; }));
  // A throwing operator rule is skipped, never crashes the gate.
  var gate2 = b.guardText.gate({
    profile: "permissive",
    operatorRules: [{ id: "boom", detect: function () { throw new Error("rule bug"); } }],
  });
  var v2 = await gate2.check({ bytes: Buffer.from("clean text", "utf8") });
  check("throwing operator rule does not crash gate", v2.action === "serve");
}

async function run() {
  testSurface();
  testProfilesAndPostures();
  testRegisteredInGuardAll();
  testGdprPostureMatchesBalancedTier();
  testValidateBenign();
  testValidateBidi();
  testValidateControl();
  testValidateNullByte();
  testValidateZeroWidth();
  testValidateUnicodeTags();
  testValidateConfusableStrictRefuses();
  testValidateConfusableAuditOnlyUnderPermissive();
  testValidateMaxBytesByteAccurate();
  testValidateMaxBytesInfinityThrows();
  testValidateMultibyteScriptsPreservedAsBenign();
  testValidateBufferInput();
  testValidateInvalidEncoding();
  testValidateAsciiOnly();
  testValidateMaxCodepoint();
  await testGateRefuseInvalidEncoding();
  testSanitizeStripsInvisibles();
  testSanitizeStripsBidiControlNullTags();
  testSanitizePreservesMultibyte();
  testSanitizeAmplificationContract();
  await testGateServe();
  await testGateRefuseBidiStrict();
  await testGateSanitizeBalanced();
  await testGateAuditOnlyConfusable();
  await testGateRefuseConfusableStrict();
  await testGateOperatorRule();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[guard-text] OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
