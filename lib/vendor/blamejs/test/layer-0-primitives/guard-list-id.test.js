"use strict";
/**
 * b.guardListId — RFC 2919 List-Id header validator.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("validate is fn",          typeof b.guardListId.validate === "function");
  check("compliancePosture is fn", typeof b.guardListId.compliancePosture === "function");
  check("PROFILES frozen",         Object.isFrozen(b.guardListId.PROFILES));
  check("NAME=listId",             b.guardListId.NAME === "listId");
  // Exercise the error class so test-coverage sees a direct reference.
  var e = new b.guardListId.GuardListIdError("guard-list-id/test", "smoke");
  check("error class code",        e.code === "guard-list-id/test");
  check("error class permanent",   e.permanent === true);
}

function testAcceptsBracketed() {
  var v = b.guardListId.validate("<newsletter.example.com>");
  check("bracketed: accept",       v.action === "accept");
  check("bracketed: listId",       v.listId === "newsletter.example.com");
  check("bracketed: no phrase",    v.phrase === "");
}

function testTwoLabelRefusedUnderStrict() {
  // PR #64 Codex P1: 2-label list-id `<list.example>` produced
  // empty label under the old heuristic split. The fix drops the
  // heuristic split and tightens FQDN enforcement (requires ≥3
  // labels for non-localhost namespace per RFC 2919 §2 + DNS reality).
  var v = b.guardListId.validate("<list.example>");
  check("2-label list-id refused under strict", v.action === "refuse");
  check("2-label reason FQDN",                  v.reason.indexOf("< 3 labels") !== -1);
}

function testAcceptsPhrasePrefixed() {
  var v = b.guardListId.validate("My Newsletter <newsletter.example.com>");
  check("phrase: accept",          v.action === "accept");
  check("phrase: parsed",          v.phrase === "My Newsletter");
  check("phrase: listId",          v.listId === "newsletter.example.com");
}

function testAcceptsBareIdentifier() {
  var v = b.guardListId.validate("newsletter.example.com");
  check("bare: accept",            v.action === "accept");
  check("bare: phrase null",       v.phrase === null);
}

function testAcceptsMultiLevelLabel() {
  var v = b.guardListId.validate("<announce.team.example.com>");
  check("multi-level: accept",     v.action === "accept");
  check("multi-level: listId",     v.listId === "announce.team.example.com");
}

function testRefusesBareHost() {
  var v = b.guardListId.validate("<localhost>");
  check("bare-host refuse",        v.action === "refuse");
  check("bare-host reason",        v.reason.indexOf("missing '.'") !== -1);
}

function testRefusesCrlfInjection() {
  var v = b.guardListId.validate("<newsletter.example.com>\r\nBcc: evil@x.com");
  check("CRLF refuse",             v.action === "refuse");
  check("CRLF reason",             v.reason.indexOf("CRLF") !== -1);
}

function testRefusesControlChar() {
  var v = b.guardListId.validate("<newsletter" + String.fromCharCode(0) + ".example.com>");
  check("NUL refuse",              v.action === "refuse");
}

function testRefusesPhraseWithAngleBrackets() {
  // Smuggling — phrase carries a second `<` that the parser would
  // otherwise treat as the identifier opening.
  var v = b.guardListId.validate("evil<smuggle.com> <newsletter.example.com>");
  check("smuggle phrase refuse",   v.action === "refuse");
}

function testRefusesTrailingContent() {
  var v = b.guardListId.validate("<newsletter.example.com> trailing");
  check("trailing refuse",         v.action === "refuse");
}

function testRefusesMalformedBrackets() {
  var v = b.guardListId.validate("<newsletter.example.com");        // no closing
  check("no-close refuse",         v.action === "refuse");

  var v2 = b.guardListId.validate("<<newsletter.example.com>>");    // nested
  check("nested refuse",           v2.action === "refuse");
}

function testRefusesOversize() {
  var huge = "a".repeat(300) + ".example.com";
  var v = b.guardListId.validate("<" + huge + ">");
  check("oversize refuse",         v.action === "refuse");
  check("oversize reason",         v.reason.indexOf("cap=") !== -1);
}

function testRefusesNonAtomChars() {
  // RFC 5322 dot-atom-text disallows space, /, etc.
  var v = b.guardListId.validate("<my list.example.com>");
  check("space-in-label refuse",   v.action === "refuse");

  var v2 = b.guardListId.validate("<my/list.example.com>");
  check("slash-in-label refuse",   v2.action === "refuse");
}

function testRefusesEmptyLabel() {
  var v = b.guardListId.validate("<.example.com>");        // leading dot
  check("leading-dot refuse",      v.action === "refuse");

  var v2 = b.guardListId.validate("<my..list.example.com>");  // double dot
  check("double-dot refuse",       v2.action === "refuse");
}

function testRefusesEmptyValue() {
  var v = b.guardListId.validate("");
  check("empty value refuse",      v.action === "refuse");

  var v2 = b.guardListId.validate("<>");
  check("empty brackets refuse",   v2.action === "refuse");
}

function testRefusesNonString() {
  var threw = null;
  try { b.guardListId.validate(123); }
  catch (e) { threw = e; }
  check("non-string refused",      threw && threw.code === "guard-list-id/bad-input");
}

function testLocalhostRequiresRandomUnderStrict() {
  // Localhost without random → refused under strict.
  var v = b.guardListId.validate("<my-list.localhost>");
  check("localhost no-random refuse", v.action === "refuse");
  check("localhost reason 32-hex",     v.reason.indexOf("32-hex") !== -1);

  // Localhost with 32-hex → accepted.
  var withRandom = "list-" + "a".repeat(32) + ".localhost";
  var v2 = b.guardListId.validate("<" + withRandom + ">");
  check("localhost with random accept", v2.action === "accept");

  // Localhost without random under permissive → accepted.
  var v3 = b.guardListId.validate("<my-list.localhost>", { profile: "permissive" });
  check("localhost permissive accept",  v3.action === "accept");
}

function testProfileResolution() {
  // Permissive accepts bare-2-label (no FQDN req in permissive
  // is N/A — namespace must still have dot per §2 §2).
  var threw = null;
  try { b.guardListId.validate("<x>", { profile: "yolo" }); }
  catch (e) { threw = e; }
  check("bad profile refused",     threw && threw.code === "guard-list-id/bad-profile");
}

function testPostureBindsStrict() {
  // Localhost without random under HIPAA posture → refused
  // (posture overrides profile).
  var v = b.guardListId.validate("<my-list.localhost>", { posture: "hipaa", profile: "permissive" });
  check("hipaa overrides permissive", v.action === "refuse");
}

function testCompliancePosture() {
  check("hipaa → strict",     b.guardListId.compliancePosture("hipaa") === "strict");
  check("unknown → null",     b.guardListId.compliancePosture("foo") === null);
}

function run() {
  testSurface();
  testAcceptsBracketed();
  testTwoLabelRefusedUnderStrict();
  testAcceptsPhrasePrefixed();
  testAcceptsBareIdentifier();
  testAcceptsMultiLevelLabel();
  testRefusesBareHost();
  testRefusesCrlfInjection();
  testRefusesControlChar();
  testRefusesPhraseWithAngleBrackets();
  testRefusesTrailingContent();
  testRefusesMalformedBrackets();
  testRefusesOversize();
  testRefusesNonAtomChars();
  testRefusesEmptyLabel();
  testRefusesEmptyValue();
  testRefusesNonString();
  testLocalhostRequiresRandomUnderStrict();
  testProfileResolution();
  testPostureBindsStrict();
  testCompliancePosture();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}
