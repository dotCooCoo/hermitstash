// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-sql — error / adversarial-branch coverage for
 * b.guardSql (the raw-SQL content-safety primitive).
 *
 * The smoke + integration suites already exercise the happy path (a
 * clean parameterized fragment serves; a stacked statement refuses).
 * This file drives the ERROR-HANDLING and ADVERSARIAL-INPUT branches
 * those never reach:
 *
 *   - opts validation throws (bad contextMode / profile / posture,
 *     non-string sanitize input);
 *   - the wrong-type validate result (bad-input, not a throw);
 *   - the UTF-8 encoding gate's every invalid-sequence branch
 *     (overlong / out-of-range lead, stray + truncated + out-of-range
 *     continuation, surrogate range, replacement-char decode);
 *   - the byte-size cap;
 *   - CVE-2025-8715 quoted-identifier hazards (newline / backslash /
 *     null / control / over-length);
 *   - the leading procedural-execution verb floor (DO / CALL / EXECUTE);
 *   - the comment / literal / stacked smuggling floor (incl. the classes
 *     that STILL refuse under `permissive`);
 *   - fragment / operator-sql / migration structural rules;
 *   - the Postgres / SQLite / MySQL OS-reach floor (refuses at EVERY
 *     profile) vs the recon / timing families (soften per profile);
 *   - sanitize's refuse-throw path and gate's serve / audit-only /
 *     refuse / fail-closed dispositions.
 *
 * Run standalone: node test/layer-0-primitives/guard-sql.test.js
 * Or via smoke:   node test/smoke.js
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var BYTES = b.constants.BYTES;

var NUL  = String.fromCharCode(0);
var LF   = String.fromCharCode(10);
var BEL  = String.fromCharCode(7);       // 0x07 C0 control
var FFFD = String.fromCharCode(0xFFFD);  // Unicode replacement char

// ---- terse assertion helpers (avoid duplicated setup blocks) ----

// validate() refuses (ok:false) AND surfaces the named issue kind.
function refusesWith(label, input, opts, kind) {
  var rv = b.guardSql.validate(input, opts);
  check(label + " -> ok:false", rv.ok === false);
  check(label + " -> kind " + kind,
        rv.issues.some(function (i) { return i.kind === kind; }));
}

// validate() passes clean (ok:true).
function passesClean(label, input, opts) {
  var rv = b.guardSql.validate(input, opts);
  check(label + " -> ok:true", rv.ok === true);
}

// validate() passes (ok:true) but surfaces a warn-level audited issue.
function auditsWith(label, input, opts, kind) {
  var rv = b.guardSql.validate(input, opts);
  check(label + " -> ok:true (audited)", rv.ok === true);
  check(label + " -> audited kind " + kind,
        rv.issues.some(function (i) { return i.kind === kind && i.action === "audit"; }));
}

// A call that must throw a GuardSqlError with a specific code.
function throwsCode(label, fn, code) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label + " throws", threw !== null);
  check(label + " code " + code, threw && threw.code === code);
}

// ---- opts validation — entry-point throws (Tier-A: bad config = throw) ----

function testBadOptsThrow() {
  throwsCode("validate: unknown contextMode",
    function () { return b.guardSql.validate("x = 1", { contextMode: "nope" }); },
    "sql.bad-opt");
  throwsCode("validate: unknown profile",
    function () { return b.guardSql.validate("x = 1", { profile: "nope" }); },
    "sql.bad-profile");
  throwsCode("validate: unknown compliancePosture",
    function () { return b.guardSql.validate("x = 1", { compliancePosture: "nope" }); },
    "sql.bad-posture");
  throwsCode("sanitize: non-string / non-Buffer input",
    function () { return b.guardSql.sanitize(42); },
    "sql.bad-input");
  throwsCode("compliancePosture: unknown posture",
    function () { return b.guardSql.compliancePosture("nope"); },
    "sql.bad-posture");
}

// ---- validate() bad input — returns a bad-input RESULT, never throws ----

function testBadInputResult() {
  var kinds = ["number", "null", "object", "undefined"];
  var inputs = [42, null, {}, undefined];
  for (var i = 0; i < inputs.length; i += 1) {
    var rv = b.guardSql.validate(inputs[i]);
    check("validate(" + kinds[i] + ") -> ok:false", rv.ok === false);
    check("validate(" + kinds[i] + ") -> bad-input",
          rv.issues.some(function (x) { return x.kind === "bad-input"; }));
  }
  // A Buffer of valid SQL is accepted (drives the Buffer decode branch).
  var bufRv = b.guardSql.validate(Buffer.from("id = ? AND active = ?", "utf8"));
  check("validate(Buffer clean) -> ok:true", bufRv.ok === true);
}

// ---- Stage 1: UTF-8 encoding gate — every invalid-sequence branch ----

function testEncodingGate() {
  // Overlong / out-of-range lead bytes (0xC0 / 0xC1 only encode overlong
  // ASCII; 0xF5.. exceeds the Unicode max code point).
  refusesWith("enc: 0xC0 overlong lead",
    Buffer.from([0x78, 0xC0, 0x80]), null, "invalid-encoding");
  refusesWith("enc: 0xC1 overlong lead",
    Buffer.from([0x78, 0xC1, 0x80]), null, "invalid-encoding");
  refusesWith("enc: 0xF5 out-of-range lead",
    Buffer.from([0x78, 0xF5, 0x80, 0x80, 0x80]), null, "invalid-encoding");
  // Stray continuation byte where a lead byte is expected.
  refusesWith("enc: stray continuation 0x80",
    Buffer.from([0x78, 0x80]), null, "invalid-encoding");
  // Truncated multibyte sequence (lead promises more bytes than present).
  refusesWith("enc: truncated 2-byte (0xE0 0xA0)",
    Buffer.from([0xE0, 0xA0]), null, "invalid-encoding");
  refusesWith("enc: truncated 4-byte (0xF0 0x90 0x80)",
    Buffer.from([0x78, 0xF0, 0x90, 0x80]), null, "invalid-encoding");
  // First continuation below the non-shortest bound (E0 requires >= 0xA0).
  refusesWith("enc: non-shortest 3-byte (0xE0 0x80 0x80)",
    Buffer.from([0xE0, 0x80, 0x80]), null, "invalid-encoding");
  // Non-shortest 4-byte (F0 requires >= 0x90).
  refusesWith("enc: non-shortest 4-byte (0xF0 0x80 0x80 0x80)",
    Buffer.from([0xF0, 0x80, 0x80, 0x80]), null, "invalid-encoding");
  // UTF-16 surrogate range encoded in UTF-8 (ED allows only 0x80..0x9F).
  refusesWith("enc: surrogate range (0xED 0xA0 0x80)",
    Buffer.from([0xED, 0xA0, 0x80]), null, "invalid-encoding");
  // A later continuation byte out of the 0x80..0xBF band.
  refusesWith("enc: bad trailing continuation (0xE0 0xA0 0x00)",
    Buffer.from([0xE0, 0xA0, 0x00]), null, "invalid-encoding");
  // Replacement-char belt-and-suspenders — a string literally carrying
  // U+FFFD means a lossy decode happened somewhere upstream.
  refusesWith("enc: decoded replacement char U+FFFD",
    "id = " + FFFD, null, "invalid-encoding");
  // A VALID multibyte sequence is NOT refused (the gate rejects only
  // malformed bytes, never legal UTF-8).
  passesClean("enc: valid multibyte accepted",
    Buffer.from("id = 1", "utf8"), { contextMode: "operator-sql" });
}

// ---- byte-size cap ----

function testOversizeCap() {
  var long = "x = 1 and y = 2 and z = 3 and w = 4";
  refusesWith("oversize: exceeds maxBytes",
    long, { maxBytes: BYTES.bytes(8) }, "oversize");
  var rv = b.guardSql.validate(long, { maxBytes: BYTES.bytes(8) });
  check("oversize: severity high",
    rv.issues.some(function (i) { return i.kind === "oversize" && i.severity === "high"; }));
}

// ---- CVE-2025-8715 quoted-identifier hygiene ----

function testIdentifierHygiene() {
  refusesWith("ident: embedded newline",
    'x = "co' + LF + 'l"', { contextMode: "operator-sql" }, "identifier-hazard");
  refusesWith("ident: leading backslash",
    'x = "\\evil"', { contextMode: "operator-sql" }, "identifier-hazard");
  refusesWith("ident: embedded null byte",
    'x = "a' + NUL + 'b"', { contextMode: "operator-sql" }, "identifier-hazard");
  refusesWith("ident: embedded C0 control byte",
    'x = "a' + BEL + 'b"', { contextMode: "operator-sql" }, "identifier-hazard");
  // 64-char identifier exceeds safeSql's 63-char (Postgres NAMEDATALEN) cap.
  var overLong = new Array(65).join("a");
  refusesWith("ident: over-length (> 63 chars)",
    'x = "' + overLong + '"', { contextMode: "operator-sql" }, "identifier-hazard");
  // A legitimately spaced / mixed-case quoted identifier is NOT a hazard.
  passesClean("ident: clean spaced quoted identifier",
    'SELECT "My Col" FROM t', { contextMode: "operator-sql" });
}

// ---- leading procedural-execution verb floor (DO / CALL / EXECUTE) ----

function testLeadingVerbFloor() {
  refusesWith("verb-floor: DO anonymous block",
    "DO $body$ BEGIN PERFORM 1; END $body$", { contextMode: "operator-sql" },
    "procedural-exec");
  refusesWith("verb-floor: CALL a routine",
    "CALL do_thing()", { contextMode: "operator-sql" }, "procedural-exec");
  refusesWith("verb-floor: EXECUTE a prepared statement",
    "EXECUTE stmt", { contextMode: "operator-sql" }, "procedural-exec");
  // Floor — refuses even under permissive.
  refusesWith("verb-floor: CALL still refuses under permissive",
    "CALL do_thing()", { contextMode: "operator-sql", profile: "permissive" },
    "procedural-exec");
}

// ---- comment / literal / stacked smuggling floor ----

function testSmugglingFloor() {
  refusesWith("stacked: second statement after ';'",
    "1; DROP TABLE users", { profile: "strict" }, "stacked-statement");
  // Stacked is an irreducible floor — refuses even under permissive.
  refusesWith("stacked: still refuses under permissive",
    "1; DROP TABLE users", { profile: "permissive" }, "stacked-statement");
  refusesWith("comment: unterminated /* block",
    "id = 1 /* open", { contextMode: "fragment" }, "unterminated-comment");
  refusesWith("comment: unterminated /* still refuses under permissive",
    "id = 1 /* open", { contextMode: "fragment", profile: "permissive" },
    "unterminated-comment");
  refusesWith("comment: MySQL executable /*! */",
    "id = 1 /*! x */", { contextMode: "fragment" }, "executable-comment");
  refusesWith("comment: executable /*! still refuses under permissive",
    "id = 1 /*! x */", { contextMode: "fragment", profile: "permissive" },
    "executable-comment");
  refusesWith("literal: unterminated string literal",
    "id = 'open", { contextMode: "fragment" }, "unterminated-literal");
  refusesWith("literal: unterminated dollar-quote",
    "id = $t$open", { contextMode: "fragment" }, "unterminated-literal");
  // Ordinary comment: strict/balanced refuse, permissive audits.
  refusesWith("comment: ordinary -- refused under strict",
    "id = ? -- note", { contextMode: "fragment", profile: "strict" }, "comment");
  auditsWith("comment: ordinary -- audited under permissive",
    "id = ? -- note", { contextMode: "fragment", profile: "permissive" }, "comment");
}

// ---- fragment-mode structural rules ----

function testFragmentMode() {
  refusesWith("fragment: statement verb refused",
    "SELECT 1", { contextMode: "fragment" }, "verb-in-fragment");
  refusesWith("fragment: embedded string literal refused",
    "name = 'alice'", { contextMode: "fragment", profile: "strict" }, "embedded-literal");
  // allowLiterals opts back in a deliberate static literal.
  passesClean("fragment: allowLiterals permits a static '...'",
    "name = 'alice'", { contextMode: "fragment", allowLiterals: true });
  refusesWith("fragment: UNION set-operation refused (exfil shape)",
    "id = 1 UNION SELECT pw FROM users", { contextMode: "fragment" },
    "setop-in-fragment");
  // String-literal smuggling: a keyword INSIDE a literal is masked and
  // never fires a detector (operator-sql so no fragment embedded-literal).
  passesClean("mask: keyword inside a literal does not fire a detector",
    "SELECT 'pg_read_file'", { contextMode: "operator-sql", profile: "strict" });
  // Intra-keyword comment collapse: LOAD/**/_FILE fuses to LOAD_FILE.
  refusesWith("mask: comment-split LOAD/**/_FILE collapses and fires",
    "SELECT LOAD/**/_FILE('/x')", { contextMode: "operator-sql", profile: "permissive" },
    "mysql-load-file");
}

// ---- operator-sql mode ----

function testOperatorSqlMode() {
  // No resolvable leading verb — surfaced as an audited no-verb (ok:true).
  auditsWith("operator-sql: no resolvable verb audited",
    "()", { contextMode: "operator-sql" }, "no-verb");
  // Set operation: strict refuses, permissive audits.
  refusesWith("operator-sql: UNION refused under strict",
    "SELECT a FROM t UNION SELECT b FROM u",
    { contextMode: "operator-sql", profile: "strict" }, "setop");
  auditsWith("operator-sql: UNION audited under permissive",
    "SELECT a FROM t UNION SELECT b FROM u",
    { contextMode: "operator-sql", profile: "permissive" }, "setop");
}

// ---- migration mode ----

function testMigrationMode() {
  // Multiple DDL statements + a read are permitted (no stacked refusal).
  passesClean("migration: multi-statement DDL permitted",
    "CREATE TABLE a(id int); ALTER TABLE a ADD c int",
    { contextMode: "migration" });
  // A verb outside the DDL / read allowlist refuses.
  refusesWith("migration: GRANT not in the DDL allowlist",
    "GRANT ALL ON t TO u", { contextMode: "migration" }, "migration-verb");
  // The OS-reach floor still applies across the whole migration script.
  refusesWith("migration: COPY ... PROGRAM floor still refuses",
    "CREATE TABLE a(id int); COPY a TO PROGRAM 'sh'",
    { contextMode: "migration" }, "copy-program");
}

// ---- OS-reach floor — refuses at EVERY profile (incl. permissive) ----

function testOsReachFloorEverywhere() {
  var opFloor = { contextMode: "operator-sql", profile: "permissive" };
  refusesWith("floor: pg_read_file",
    "SELECT pg_read_file('/etc/passwd')", opFloor, "pg-read-file");
  refusesWith("floor: SQLite load_extension",
    "SELECT load_extension('x')", opFloor, "sqlite-load-extension");
  refusesWith("floor: MySQL LOAD_FILE",
    "SELECT LOAD_FILE('/etc/passwd')", opFloor, "mysql-load-file");
  refusesWith("floor: MySQL INTO OUTFILE",
    "SELECT a INTO OUTFILE '/x' FROM t", opFloor, "into-outfile");
  refusesWith("floor: SQLite ATTACH DATABASE",
    "ATTACH DATABASE 'x' AS y", opFloor, "attach-db");
  refusesWith("floor: Postgres dblink()",
    "SELECT dblink('x', 'y')", opFloor, "dblink");
  refusesWith("floor: CREATE EXTENSION",
    "CREATE EXTENSION plpythonu", opFloor, "create-extension");
  refusesWith("floor: ALTER SYSTEM",
    "ALTER SYSTEM SET x = 1", opFloor, "alter-system");
  refusesWith("floor: MySQL sys_exec()",
    "SELECT sys_exec('id')", opFloor, "mysql-sys-exec");
}

// ---- recon / timing families soften per profile (NOT floor) ----

function testReconTimingSoftenByProfile() {
  refusesWith("recon: information_schema refused under strict",
    "SELECT * FROM information_schema.tables",
    { contextMode: "operator-sql", profile: "strict" }, "schema-recon");
  auditsWith("recon: information_schema audited under balanced",
    "SELECT * FROM information_schema.tables",
    { contextMode: "operator-sql", profile: "balanced" }, "schema-recon");
  refusesWith("timing: WAITFOR DELAY refused under strict",
    "SELECT 1 WAITFOR DELAY '0:0:5'",
    { contextMode: "operator-sql", profile: "strict" }, "time-waitfor");
  auditsWith("timing: WAITFOR DELAY audited under permissive",
    "SELECT 1 WAITFOR DELAY '0:0:5'",
    { contextMode: "operator-sql", profile: "permissive" }, "time-waitfor");
  refusesWith("timing: SLEEP() refused under strict",
    "SELECT SLEEP(5)", { contextMode: "operator-sql", profile: "strict" }, "time-sleep");
}

// ---- sanitize() — normalized output vs refuse-throw ----

function testSanitize() {
  // permissive permits a comment; sanitize returns the comment-stripped
  // normalized form (NOT a made-safe query).
  var normalized = b.guardSql.sanitize("id = ? -- note" + LF + " AND active = ?",
    { profile: "permissive" });
  check("sanitize: returns a string", typeof normalized === "string");
  check("sanitize: comment stripped from normalized form",
        normalized.indexOf("note") === -1 && normalized.indexOf("active") !== -1);
  // An OS-reach floor construct has no safe transform — sanitize throws.
  throwsCode("sanitize: throws on the OS-reach floor",
    function () { return b.guardSql.sanitize("SELECT pg_read_file('/etc/passwd')"); },
    "sql.file-access");
  throwsCode("sanitize: throws on a stacked statement",
    function () { return b.guardSql.sanitize("1; DROP TABLE users"); },
    "sql.stacked");
}

// ---- gate() decision chain: serve / audit-only / refuse / fail-closed ----

async function testGateDispositions() {
  var strict = b.guardSql.gate({ profile: "strict" });
  var serveEmpty = await strict.check({});
  check("gate: no sql -> serve", serveEmpty.action === "serve" && serveEmpty.ok === true);
  var serveNonStr = await strict.check({ sql: 123 });
  check("gate: non-string sql -> serve", serveNonStr.action === "serve");
  var serveClean = await strict.check({ sql: "id = ?", mode: "fragment" });
  check("gate: clean fragment -> serve", serveClean.action === "serve");
  var refuseStacked = await strict.check({ sql: "1; DROP TABLE users" });
  check("gate: stacked -> refuse", refuseStacked.action === "refuse" && refuseStacked.ok === false);

  // audit-only — a warn-level (recon) finding under balanced.
  var balanced = b.guardSql.gate({ profile: "balanced" });
  var auditOnly = await balanced.check({
    sql: "SELECT a FROM information_schema.tables", mode: "operator-sql" });
  check("gate: recon under balanced -> audit-only",
        auditOnly.action === "audit-only" && auditOnly.ok === true);

  // ctx.mode overrides the opts default per call.
  var refuseVerbFrag = await strict.check({ sql: "SELECT 1", mode: "fragment" });
  check("gate: ctx.mode=fragment refuses a statement verb",
        refuseVerbFrag.action === "refuse");
  var serveVerbOp = await strict.check({ sql: "SELECT 1", mode: "operator-sql" });
  check("gate: ctx.mode=operator-sql serves the same verb",
        serveVerbOp.action === "serve");

  // A bad ctx.mode makes the inner check throw -> the gate FAILS CLOSED
  // (refuse with a check-threw issue), never fails open.
  var failClosed = await strict.check({ sql: "x = 1", mode: "bogus" });
  check("gate: bad ctx.mode fails closed -> refuse",
        failClosed.action === "refuse" && failClosed.ok === false);
  check("gate: bad ctx.mode surfaces check-threw",
        failClosed.issues.some(function (i) { return i.kind === "check-threw"; }));
}

// ---- surface / postures / fixtures ----

function testSurfaceAndPostures() {
  check("surface: CONTEXT_MODES lists the three modes",
        b.guardSql.CONTEXT_MODES.length === 3 &&
        b.guardSql.CONTEXT_MODES.indexOf("fragment") !== -1 &&
        b.guardSql.CONTEXT_MODES.indexOf("operator-sql") !== -1 &&
        b.guardSql.CONTEXT_MODES.indexOf("migration") !== -1);
  check("surface: PROFILES has strict/balanced/permissive",
        !!b.guardSql.PROFILES.strict && !!b.guardSql.PROFILES.balanced &&
        !!b.guardSql.PROFILES.permissive);
  check("surface: gdpr posture sets gdprRedact",
        b.guardSql.compliancePosture("gdpr").gdprRedact === true);
  check("surface: hipaa posture maps to the strict floor",
        b.guardSql.compliancePosture("hipaa").floor === "refuse");
  // The adaptive integration fixtures round-trip through validate.
  check("fixtures: benignSql serves",
        b.guardSql.validate(b.guardSql.INTEGRATION_FIXTURES.benignSql).ok === true);
  check("fixtures: hostileSql refuses",
        b.guardSql.validate(b.guardSql.INTEGRATION_FIXTURES.hostileSql,
          { profile: "strict" }).ok === false);
}

async function run() {
  testBadOptsThrow();
  testBadInputResult();
  testEncodingGate();
  testOversizeCap();
  testIdentifierHygiene();
  testLeadingVerbFloor();
  testSmugglingFloor();
  testFragmentMode();
  testOperatorSqlMode();
  testMigrationMode();
  testOsReachFloorEverywhere();
  testReconTimingSoftenByProfile();
  testSanitize();
  await testGateDispositions();
  testSurfaceAndPostures();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[guard-sql] OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
