// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.safeSql identifier-shape primitives — the default identifier regex, the
 * length ceiling, and the typed error class, each proven through the real
 * validateIdentifier consumer path rather than by existence checks.
 *
 * DEFAULT_IDENTIFIER_RE is shown to be the shape validateIdentifier applies by
 * default (an identifier the regex rejects throws sql/bad-shape; the same
 * identifier passes once a wider opts.pattern is supplied). MAX_IDENTIFIER_LENGTH
 * is shown to be the length boundary (one char past it throws sql/too-long;
 * exactly at it passes). SafeSqlError is shown to be the class every throw
 * carries, with its stable .code and default code.
 */

var { check, b } = require("../helpers");

function _code(fn) {
  try { fn(); return "OK"; }
  catch (e) { return e && e.code; }
}

// ---- DEFAULT_IDENTIFIER_RE ----

function testDefaultIdentifierRe() {
  check("b.safeSql.DEFAULT_IDENTIFIER_RE is the advertised ASCII identifier shape",
        String(b.safeSql.DEFAULT_IDENTIFIER_RE) === "/^[A-Za-z_][A-Za-z0-9_]*$/");

  // Advertised @example values: a plain snake_case name matches, a
  // digit-leading name does not.
  check("DEFAULT_IDENTIFIER_RE matches a plain identifier",
        b.safeSql.DEFAULT_IDENTIFIER_RE.test("audit_log") === true);
  check("DEFAULT_IDENTIFIER_RE rejects a digit-leading identifier",
        b.safeSql.DEFAULT_IDENTIFIER_RE.test("1starts_with_digit") === false);

  // validateIdentifier applies DEFAULT_IDENTIFIER_RE by default: a name the
  // regex rejects throws sql/bad-shape...
  check("validateIdentifier accepts a name matching DEFAULT_IDENTIFIER_RE",
        b.safeSql.validateIdentifier("audit_log") === "audit_log");
  check("validateIdentifier refuses a name failing DEFAULT_IDENTIFIER_RE",
        _code(function () { b.safeSql.validateIdentifier("col-1"); }) === "sql/bad-shape");

  // ...and the same name passes once a wider opts.pattern overrides the
  // default shape — proving the default really was DEFAULT_IDENTIFIER_RE.
  check("a wider opts.pattern accepts the name the default shape refused",
        b.safeSql.validateIdentifier("col-1", {
          pattern: /^[A-Za-z][A-Za-z0-9_-]*$/,
        }) === "col-1");
}

// ---- MAX_IDENTIFIER_LENGTH ----

function testMaxIdentifierLength() {
  check("b.safeSql.MAX_IDENTIFIER_LENGTH is the advertised 63 (Postgres NAMEDATALEN)",
        b.safeSql.MAX_IDENTIFIER_LENGTH === 63);

  // One char past the ceiling refuses with sql/too-long; exactly at the
  // ceiling is accepted. Sizing off the constant makes a drift break the test.
  var tooLong = "a".repeat(b.safeSql.MAX_IDENTIFIER_LENGTH + 1);
  check("validateIdentifier refuses a name longer than MAX_IDENTIFIER_LENGTH",
        _code(function () { b.safeSql.validateIdentifier(tooLong); }) === "sql/too-long");

  var atMax = "a".repeat(b.safeSql.MAX_IDENTIFIER_LENGTH);
  check("validateIdentifier accepts a name exactly at MAX_IDENTIFIER_LENGTH",
        b.safeSql.validateIdentifier(atMax) === atMax);
}

// ---- SafeSqlError ----

function testSafeSqlError() {
  // Every validateIdentifier rejection carries the class with a stable .code.
  var thrown = null;
  try { b.safeSql.validateIdentifier("drop"); }
  catch (e) { thrown = e; }
  check("validateIdentifier throws a b.safeSql.SafeSqlError",
        thrown instanceof b.safeSql.SafeSqlError);
  check("SafeSqlError extends Error", thrown instanceof Error);
  check("SafeSqlError carries the .isSafeSqlError brand", thrown.isSafeSqlError === true);
  check("reserved-word rejection carries code sql/reserved-word",
        thrown.code === "sql/reserved-word");

  // Distinct rejection reasons carry distinct documented codes on the SAME
  // class — the code is the security signal HTTP middleware branches on.
  check("bad-shape rejection is a SafeSqlError with code sql/bad-shape",
        _code(function () { b.safeSql.validateIdentifier("a;b"); }) === "sql/bad-shape");
  check("non-string input is a SafeSqlError with code sql/bad-type",
        _code(function () { b.safeSql.validateIdentifier(42); }) === "sql/bad-type");

  // The constructor's documented default code when none is supplied.
  var bare = new b.safeSql.SafeSqlError("boom");
  check("SafeSqlError defaults .code to sql/invalid", bare.code === "sql/invalid");
}

// ---- normalizeForScan ----

function testNormalizeForScan() {
  // A quoted table/identifier abutting a keyword with NO whitespace gets a
  // separating space so a whitespace-anchored tokenizer sees the boundary
  // (the residency write-gate evasion this primitive was extracted to close).
  check("normalizeForScan inserts a space where a quoted token abuts a word",
        b.safeSql.normalizeForScan('INSERT INTO"t"(a) VALUES(?)') === 'INSERT INTO "t"(a) VALUES(?)');

  // A slash-star block comment wedged between two keywords collapses to a
  // single space so the token boundary survives.
  var blockComment = "UPDATE" + "/*x*/" + "t SET a = ?";
  check("normalizeForScan collapses an internal block comment to a space",
        b.safeSql.normalizeForScan(blockComment) === "UPDATE t SET a = ?");

  // A line comment collapses to a single space.
  check("normalizeForScan collapses a line comment to a space",
        b.safeSql.normalizeForScan("SELECT 1-- note") === "SELECT 1 ");

  // Quote-aware: a comment marker INSIDE a string literal is copied verbatim,
  // never treated as a comment (doubled-quote escape respected).
  var litWithMarker = "SELECT '-- not a comment' AS x";
  check("normalizeForScan leaves a comment marker inside a string literal intact",
        b.safeSql.normalizeForScan(litWithMarker) === litWithMarker);

  // Already-whitespace-delimited SQL is returned unchanged (no spurious spaces).
  var clean = 'INSERT INTO "t" (a) VALUES (?)';
  check("normalizeForScan is a no-op on already-normalized SQL",
        b.safeSql.normalizeForScan(clean) === clean);

  // A backtick-quoted (MySQL) identifier abutting a word is also separated.
  check("normalizeForScan separates a backtick-quoted identifier abutting a word",
        b.safeSql.normalizeForScan("UPDATE`t` SET a = ?") === "UPDATE `t` SET a = ?");
}

async function run() {
  testDefaultIdentifierRe();
  testMaxIdentifierLength();
  testSafeSqlError();
  testNormalizeForScan();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}
