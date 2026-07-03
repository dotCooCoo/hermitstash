// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Sanity tests for test/helpers/_shape-match.js. Not part of the
 * smoke test surface (lives outside the per-layer index); the file is
 * a test-time substrate, so unit-test it directly here and only
 * surface failures via the codebase-patterns detectors that compose it.
 */

var sm = require("../helpers/_shape-match");

var failed = 0;
var passed = 0;
function check(label, condition) {
  if (condition) { passed += 1; }
  else { failed += 1; console.error("FAIL: " + label); }
}

// ---- findCalls ----

function testFindCallsSimpleIdent() {
  var src = "foo(); bar(1, 2); foo();";
  var calls = sm.findCalls(src, /^foo$/);
  check("findCalls: matches 2 foo()", calls.length === 2);
  check("findCalls: chain is 'foo'", calls[0].chain === "foo");
}

function testFindCallsMemberChain() {
  var src = "audit.emit({}); audit.safeEmit({}); foo.audit.emit({});";
  var calls = sm.findCalls(src, /^audit\.emit$/);
  check("findCalls: catches audit.emit only (not safeEmit)", calls.length === 1);
  check("findCalls: chain is 'audit.emit'", calls[0].chain === "audit.emit");
}

function testFindCallsBracketAccess() {
  var src = 'obj["emit"]({}); obj.emit({});';
  var calls = sm.findCalls(src, /^obj\.emit$/);
  check("findCalls: handles bracket + dot uniformly", calls.length === 2);
}

function testFindCallsIgnoresStrings() {
  var src = 'var x = "audit.emit(payload)"; audit.emit({});';
  var calls = sm.findCalls(src, /^audit\.emit$/);
  check("findCalls: ignores call inside string literal", calls.length === 1);
}

function testFindCallsIgnoresComments() {
  var src = "// audit.emit({}); should be ignored\naudit.emit({});";
  var calls = sm.findCalls(src, /^audit\.emit$/);
  check("findCalls: ignores call inside line comment", calls.length === 1);
}

function testFindCallsIgnoresBlockComments() {
  var src = "/* audit.emit({}); ignore */ audit.emit({});";
  var calls = sm.findCalls(src, /^audit\.emit$/);
  check("findCalls: ignores call inside block comment", calls.length === 1);
}

// ---- findEnclosingTry ----

function testFindEnclosingTryHits() {
  var src = 'function f() { try { audit.emit({}); } catch (e) {} }';
  var calls = sm.findCalls(src, /^audit\.emit$/);
  var encl = sm.findEnclosingTry(src, calls[0].head.start);
  check("findEnclosingTry: finds enclosing try block", encl !== null);
  check("findEnclosingTry: bodyStart < call.start", encl.bodyStart < calls[0].head.start);
  check("findEnclosingTry: bodyEnd > call.end", encl.bodyEnd > calls[0].closeParen);
}

function testFindEnclosingTryMisses() {
  var src = 'function f() { audit.emit({}); }';
  var calls = sm.findCalls(src, /^audit\.emit$/);
  var encl = sm.findEnclosingTry(src, calls[0].head.start);
  check("findEnclosingTry: returns null when no try wraps the call", encl === null);
}

function testFindEnclosingTrySiblingTryDoesNotMatch() {
  var src = 'function f() { try {} catch (e) {} audit.emit({}); }';
  var calls = sm.findCalls(src, /^audit\.emit$/);
  var encl = sm.findEnclosingTry(src, calls[0].head.start);
  check("findEnclosingTry: sibling try block does NOT enclose", encl === null);
}

// ---- aliasesOf ----

function testAliasesOfFindsVarRebind() {
  var src = "var emit = audit.emit; var safe = audit.safeEmit; var unrelated = foo.bar;";
  var aliases = sm.aliasesOf(src, /^audit\.emit$/);
  check("aliasesOf: var emit = audit.emit; → 'emit' is alias",
        aliases["emit"] === "audit.emit");
  check("aliasesOf: doesn't include safe (different chain)",
        aliases["safe"] === undefined);
  check("aliasesOf: doesn't include unrelated",
        aliases["unrelated"] === undefined);
}

function testAliasesOfFindsConstRebind() {
  var src = "const emit = audit.emit;";
  var aliases = sm.aliasesOf(src, /^audit\.emit$/);
  check("aliasesOf: handles const",
        aliases["emit"] === "audit.emit");
}

// ---- Tokenizer edge cases ----

function testTokenizerHandlesTemplateLiteral() {
  var src = "var x = `hello ${name}` + audit.emit({});";
  var calls = sm.findCalls(src, /^audit\.emit$/);
  check("tokenizer: template literal doesn't swallow surrounding calls",
        calls.length === 1);
}

function testTokenizerHandlesRegexAfterReturn() {
  var src = "function f() { return /audit\\.emit/.test(x); } audit.emit({});";
  var calls = sm.findCalls(src, /^audit\.emit$/);
  check("tokenizer: regex literal after return doesn't trip findCalls",
        calls.length === 1);
}

function run() {
  testFindCallsSimpleIdent();
  testFindCallsMemberChain();
  testFindCallsBracketAccess();
  testFindCallsIgnoresStrings();
  testFindCallsIgnoresComments();
  testFindCallsIgnoresBlockComments();
  testFindEnclosingTryHits();
  testFindEnclosingTryMisses();
  testFindEnclosingTrySiblingTryDoesNotMatch();
  testAliasesOfFindsVarRebind();
  testAliasesOfFindsConstRebind();
  testTokenizerHandlesTemplateLiteral();
  testTokenizerHandlesRegexAfterReturn();

  if (failed > 0) {
    console.error("\n" + failed + " check(s) FAILED, " + passed + " passed");
    process.exit(1);
  }
  console.log("OK — " + passed + " checks passed");
}

if (require.main === module) run();
module.exports = { run: run };
