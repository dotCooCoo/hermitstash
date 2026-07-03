// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.guardSmtpCommand — SMTP command-line validator. Tests bare-CR /
 * bare-LF refusal (smuggling defense per CVE-2023-51764/51765/51766/
 * 2026-32178), per-verb shape checks, and caps.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _throws(label, fn, code) {
  var threw = null;
  try { fn(); }
  catch (e) { threw = e; }
  check(label, threw && threw.code === code);
}

function testSurface() {
  check("validate is fn",          typeof b.guardSmtpCommand.validate === "function");
  check("gate is fn",              typeof b.guardSmtpCommand.gate === "function");
  check("compliancePosture is fn", typeof b.guardSmtpCommand.compliancePosture === "function");
  check("PROFILES frozen",         Object.isFrozen(b.guardSmtpCommand.PROFILES));
  check("KNOWN_VERBS frozen",      Object.isFrozen(b.guardSmtpCommand.KNOWN_VERBS));
  check("GuardSmtpCommandError",   typeof b.guardSmtpCommand.GuardSmtpCommandError === "function");
  check("NAME=smtpCommand",        b.guardSmtpCommand.NAME === "smtpCommand");
  check("KIND=identifier",         b.guardSmtpCommand.KIND === "identifier");
}

function testParsesGreeting() {
  var p = b.guardSmtpCommand.validate("EHLO mail.example.com");
  check("EHLO verb",       p.verb === "EHLO");
  check("EHLO arg",        p.args[0] === "mail.example.com");
  check("EHLO no params",  Object.keys(p.params).length === 0);

  var helo = b.guardSmtpCommand.validate("HELO mail.example.com");
  check("HELO verb",       helo.verb === "HELO");

  var addrLit = b.guardSmtpCommand.validate("EHLO [192.0.2.1]");
  check("EHLO addr-literal", addrLit.args[0] === "[192.0.2.1]");

  var v6 = b.guardSmtpCommand.validate("EHLO [IPv6:2001:db8::1]");
  check("EHLO IPv6 addr-literal", v6.args[0] === "[IPv6:2001:db8::1]");
}

function testParsesMailFrom() {
  var p = b.guardSmtpCommand.validate("MAIL FROM:<alice@example.com>");
  check("MAIL verb",         p.verb === "MAIL");
  check("MAIL path",         p.args[0] === "<alice@example.com>");

  var withExt = b.guardSmtpCommand.validate("MAIL FROM:<a@b.com> SIZE=12345 BODY=8BITMIME");
  check("MAIL ext params",   withExt.params.SIZE === "12345");
  check("MAIL ext flag",     withExt.params.BODY === "8BITMIME");

  // Bounce sender — empty path is valid for MAIL FROM
  var bounce = b.guardSmtpCommand.validate("MAIL FROM:<>");
  check("MAIL empty path (bounce)", bounce.args[0] === "<>");
}

function testParsesRcptTo() {
  var p = b.guardSmtpCommand.validate("RCPT TO:<bob@example.com>");
  check("RCPT verb",         p.verb === "RCPT");
  check("RCPT path",         p.args[0] === "<bob@example.com>");

  // Empty forward-path refused
  _throws("RCPT TO:<> refused", function () {
    b.guardSmtpCommand.validate("RCPT TO:<>");
  }, "guard-smtp-command/empty-path");
}

function testRefusesBareCr() {
  _throws("bare CR refused",
    function () { b.guardSmtpCommand.validate("EHLO mail\rmalicious"); },
    "guard-smtp-command/bare-cr");
}

function testRefusesBareLf() {
  _throws("bare LF refused",
    function () { b.guardSmtpCommand.validate("EHLO mail\nmalicious"); },
    "guard-smtp-command/bare-lf");
}

function testPermissiveAcceptsBareLf() {
  // PR #58 Codex P2: permissive profile documents allowBareLf=true
  // but the control-char loop was rejecting 0x0a regardless. Verify
  // the documented legacy-Sendmail compat path actually accepts LF.
  // The line still needs valid SMTP shape after the LF.
  var line = "MAIL FROM:<a@b.com>";
  var parsed = b.guardSmtpCommand.validate(line, { profile: "permissive" });
  check("permissive accepts MAIL FROM (sanity)", parsed.verb === "MAIL");
  // With bare LF embedded — should now NOT throw under permissive.
  var withLf = b.guardSmtpCommand.validate("MAIL FROM:<a@b.com>\nlegacy", { profile: "permissive" });
  check("permissive accepts bare LF in line (Codex P2 fix)", withLf.verb === "MAIL");
  // Strict still rejects.
  var threw = null;
  try { b.guardSmtpCommand.validate("MAIL FROM:<a@b.com>\nlegacy"); }
  catch (e) { threw = e; }
  check("strict still rejects bare LF", threw && threw.code === "guard-smtp-command/bare-lf");
}

function testRefusesNul() {
  _throws("NUL refused",
    function () { b.guardSmtpCommand.validate("EHLO mail" + String.fromCharCode(0) + "x"); },
    "guard-smtp-command/nul");
}

function testRefusesC0Control() {
  _throws("C0 0x01 refused",
    function () { b.guardSmtpCommand.validate("EHLO mail" + String.fromCharCode(1)); },
    "guard-smtp-command/control-char");
}

function testRefusesDel() {
  _throws("DEL refused",
    function () { b.guardSmtpCommand.validate("EHLO mail" + String.fromCharCode(0x7f)); },
    "guard-smtp-command/control-char");
}

function testRefusesNonAsciiUnderStrict() {
  _throws("non-ASCII refused under strict",
    function () { b.guardSmtpCommand.validate("EHLO mαil.example.com"); },
    "guard-smtp-command/non-ascii");

  // Balanced accepts SMTPUTF8 (RFC 6531) for mailbox local-part in
  // MAIL FROM — EHLO hostnames still want the A-label form, so the
  // realistic SMTPUTF8 surface is the mailbox path.
  var p = b.guardSmtpCommand.validate("MAIL FROM:<αlice@example.com>", { profile: "balanced" });
  check("SMTPUTF8 mailbox accepted under balanced", p.verb === "MAIL");
}

function testRefusesOversizeLine() {
  // Pad past strict cap of 512.
  var pad = "x".repeat(600);
  _throws("oversize line refused",
    function () { b.guardSmtpCommand.validate("MAIL FROM:<" + pad + "@example.com>"); },
    "guard-smtp-command/oversize-line");
}

function testRefusesUnknownVerb() {
  _throws("unknown verb refused",
    function () { b.guardSmtpCommand.validate("BOGUS arg"); },
    "guard-smtp-command/unknown-verb");
}

function testRefusesZeroArgVerbWithArgs() {
  _throws("DATA with args refused",
    function () { b.guardSmtpCommand.validate("DATA extra"); },
    "guard-smtp-command/unexpected-args");
  _throws("STARTTLS with args refused (CVE-2021-38371 / -33515 class)",
    function () { b.guardSmtpCommand.validate("STARTTLS extra"); },
    "guard-smtp-command/unexpected-args");
}

function testZeroArgVerbsAccepted() {
  check("DATA accepted",     b.guardSmtpCommand.validate("DATA").verb === "DATA");
  check("RSET accepted",     b.guardSmtpCommand.validate("RSET").verb === "RSET");
  check("QUIT accepted",     b.guardSmtpCommand.validate("QUIT").verb === "QUIT");
  check("STARTTLS accepted", b.guardSmtpCommand.validate("STARTTLS").verb === "STARTTLS");
}

function testBdat() {
  var p = b.guardSmtpCommand.validate("BDAT 1024");
  check("BDAT chunk size",    p.args[0] === "1024");
  check("BDAT not LAST",      !p.params.LAST);
  var last = b.guardSmtpCommand.validate("BDAT 512 LAST");
  check("BDAT LAST",          last.params.LAST === true);
  _throws("BDAT bad chunk-size",
    function () { b.guardSmtpCommand.validate("BDAT not-a-number"); },
    "guard-smtp-command/bad-shape");
}

function testAuth() {
  var p = b.guardSmtpCommand.validate("AUTH PLAIN");
  check("AUTH mech",          p.args[0] === "PLAIN");

  var withIr = b.guardSmtpCommand.validate("AUTH PLAIN AGFsaWNlAHB3ZA==");
  check("AUTH initial-response", withIr.params.initialResponse === "AGFsaWNlAHB3ZA==");
}

function testVrfyExpn() {
  var v = b.guardSmtpCommand.validate("VRFY alice@example.com");
  check("VRFY mailbox", v.args[0] === "alice@example.com");
  var e = b.guardSmtpCommand.validate("EXPN admins");
  check("EXPN list",    e.args[0] === "admins");
}

function testRefusesEhloWithoutArg() {
  _throws("EHLO without arg refused",
    function () { b.guardSmtpCommand.validate("EHLO"); },
    "guard-smtp-command/bad-shape");
}

function testRefusesMailWithoutFrom() {
  _throws("MAIL without FROM: refused",
    function () { b.guardSmtpCommand.validate("MAIL TO:<x@y.com>"); },
    "guard-smtp-command/bad-shape");
}

function testGateServe() {
  var gate = b.guardSmtpCommand.gate({ profile: "strict" });
  return gate.check({ identifier: "EHLO mail.example.com" }).then(function (r) {
    check("gate serves valid command", r.ok === true && r.action === "serve");
  });
}

function testGateRefuseSmuggling() {
  var gate = b.guardSmtpCommand.gate({ profile: "strict" });
  return gate.check({ identifier: "MAIL FROM:<a@b.com>\r\n.\r\nMAIL FROM:<evil@x.com>" }).then(function (r) {
    check("gate refuses CRLF smuggling", r.ok === false && r.action === "refuse");
    check("gate issue.kind=bare-cr",      r.issues[0].kind === "bare-cr");
  });
}

function testCompliancePosture() {
  check("hipaa → strict",     b.guardSmtpCommand.compliancePosture("hipaa") === "strict");
  check("pci-dss → strict",   b.guardSmtpCommand.compliancePosture("pci-dss") === "strict");
  check("gdpr → strict",      b.guardSmtpCommand.compliancePosture("gdpr") === "strict");
  check("soc2 → strict",      b.guardSmtpCommand.compliancePosture("soc2") === "strict");
  check("unknown → null",     b.guardSmtpCommand.compliancePosture("hipa-typo") === null);
}

function testPostureBindsStrict() {
  // Under hipaa posture, non-ASCII refused even though caller asked balanced
  // (posture overrides profile).
  _throws("hipaa posture pins strict (no SMTPUTF8)",
    function () { b.guardSmtpCommand.validate("EHLO mαil.example.com", { posture: "hipaa" }); },
    "guard-smtp-command/non-ascii");
}

function testRegisteredInGuardAll() {
  var all = b.guardAll.allGuards();
  var found = all.some(function (g) { return g && g.NAME === "smtpCommand"; });
  check("registered in guardAll", found);
}

async function run() {
  testSurface();
  testParsesGreeting();
  testParsesMailFrom();
  testParsesRcptTo();
  testRefusesBareCr();
  testRefusesBareLf();
  testPermissiveAcceptsBareLf();
  testRefusesNul();
  testRefusesC0Control();
  testRefusesDel();
  testRefusesNonAsciiUnderStrict();
  testRefusesOversizeLine();
  testRefusesUnknownVerb();
  testRefusesZeroArgVerbWithArgs();
  testZeroArgVerbsAccepted();
  testBdat();
  testAuth();
  testVrfyExpn();
  testRefusesEhloWithoutArg();
  testRefusesMailWithoutFrom();
  await testGateServe();
  await testGateRefuseSmuggling();
  testCompliancePosture();
  testPostureBindsStrict();
  testRegisteredInGuardAll();
}

module.exports = { run: run };

if (require.main === module) run().catch(function (e) {
  process.stderr.write("FAIL: " + (e && e.stack || e) + "\n");
  process.exit(1);
});
