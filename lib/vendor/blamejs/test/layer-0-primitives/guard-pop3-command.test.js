"use strict";

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

function testSurface() {
  check("namespace",            typeof b.guardPop3Command === "object");
  check("validate fn",          typeof b.guardPop3Command.validate === "function");
  check("compliancePosture fn", typeof b.guardPop3Command.compliancePosture === "function");
  check("PROFILES",             typeof b.guardPop3Command.PROFILES === "object");
  check("error class",          typeof b.guardPop3Command.GuardPop3CommandError === "function");
  // Verify the error class is what validate throws
  var threw = null;
  try { b.guardPop3Command.validate(""); } catch (e) { threw = e; }
  check("validate refusal is GuardPop3CommandError",
    threw instanceof b.guardPop3Command.GuardPop3CommandError);
}

function testHappyPath() {
  var u = b.guardPop3Command.validate("USER alice", { tls: true });
  check("USER: verb",   u.verb === "USER");
  check("USER: args",   u.args[0] === "alice");

  var p = b.guardPop3Command.validate("PASS secret123", { tls: true });
  check("PASS: parsed", p.verb === "PASS" && p.args[0] === "secret123");

  var retr = b.guardPop3Command.validate("RETR 42");
  check("RETR: msg num", retr.verb === "RETR" && retr.args[0] === "42");

  var top = b.guardPop3Command.validate("TOP 1 5");
  check("TOP: parsed", top.verb === "TOP" && top.args[0] === "1" && top.args[1] === "5");

  var capa = b.guardPop3Command.validate("CAPA");
  check("CAPA: zero-arg", capa.verb === "CAPA" && capa.args.length === 0);

  var list = b.guardPop3Command.validate("LIST");
  check("LIST: bare (zero arg)", list.verb === "LIST" && list.args.length === 0);

  var listWith = b.guardPop3Command.validate("LIST 3");
  check("LIST: with msg-num", listWith.verb === "LIST" && listWith.args[0] === "3");
}

function testCleartextAuthRefused() {
  var threw = null;
  try { b.guardPop3Command.validate("USER alice", { tls: false }); } catch (e) { threw = e; }
  check("USER refused over cleartext under strict",
    threw && threw.code === "guard-pop3-command/cleartext-auth");

  // Permissive allows cleartext
  var rv = b.guardPop3Command.validate("USER alice", { tls: false, profile: "permissive" });
  check("USER allowed cleartext under permissive",
    rv.verb === "USER");
}

function testAuthCleartextRefused() {
  // AUTH with no mech is a CAPA-style enumeration — must stay allowed
  // pre-TLS so clients can negotiate (RFC 5034 §4).
  var rv = b.guardPop3Command.validate("AUTH", { tls: false });
  check("AUTH (no mech) allowed pre-TLS — enumeration",
    rv.verb === "AUTH" && rv.args.length === 0);

  // AUTH PLAIN over cleartext under strict — refused identically to
  // USER/PASS per RFC 2595 §2.1 + RFC 5034 §4.
  var threw = null;
  try { b.guardPop3Command.validate("AUTH PLAIN", { tls: false }); } catch (e) { threw = e; }
  check("AUTH PLAIN refused pre-TLS under strict",
    threw && threw.code === "guard-pop3-command/cleartext-auth");

  // Permissive allows
  var rv2 = b.guardPop3Command.validate("AUTH PLAIN", { tls: false, profile: "permissive" });
  check("AUTH PLAIN allowed pre-TLS under permissive",
    rv2.verb === "AUTH" && rv2.args[0] === "PLAIN");

  // Strict + TLS up: allowed
  var rv3 = b.guardPop3Command.validate("AUTH PLAIN", { tls: true });
  check("AUTH PLAIN allowed under strict when TLS up",
    rv3.verb === "AUTH" && rv3.args[0] === "PLAIN");
}

function testApopRefusedUnderStrict() {
  var threw = null;
  try { b.guardPop3Command.validate("APOP alice abcdef1234567890"); } catch (e) { threw = e; }
  check("APOP refused under strict",
    threw && threw.code === "guard-pop3-command/apop-refused");

  // Balanced allows APOP
  var rv = b.guardPop3Command.validate("APOP alice abcdef1234567890", { profile: "balanced" });
  check("APOP allowed under balanced",
    rv.verb === "APOP" && rv.args.length === 2);
}

function testBadInputRefused() {
  function expectThrow(label, fn, codeMatch) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(codeMatch) !== -1);
  }
  expectThrow("refuses non-string", function () {
    b.guardPop3Command.validate(null);
  }, "guard-pop3-command/bad-input");
  expectThrow("refuses empty line", function () {
    b.guardPop3Command.validate("");
  }, "guard-pop3-command/empty-line");
  expectThrow("refuses unknown verb", function () {
    b.guardPop3Command.validate("FROBNICATE");
  }, "guard-pop3-command/unknown-verb");
  expectThrow("refuses args on zero-arg verb", function () {
    b.guardPop3Command.validate("STAT extra");
  }, "guard-pop3-command/unexpected-args");
  expectThrow("refuses bare-LF byte under strict", function () {
    b.guardPop3Command.validate("USER alice\nb", { tls: true });
  }, "guard-pop3-command/bad-byte");
  expectThrow("refuses missing USER name", function () {
    b.guardPop3Command.validate("USER", { tls: true });
  }, "guard-pop3-command/missing-username");
  expectThrow("refuses missing PASS arg", function () {
    b.guardPop3Command.validate("PASS", { tls: true });
  }, "guard-pop3-command/missing-password");
  expectThrow("refuses non-decimal msg num", function () {
    b.guardPop3Command.validate("RETR abc");
  }, "guard-pop3-command/bad-msg-number");
  expectThrow("refuses 0 as msg num", function () {
    b.guardPop3Command.validate("RETR 0");
  }, "guard-pop3-command/bad-msg-number");
  expectThrow("refuses TOP without line-count", function () {
    b.guardPop3Command.validate("TOP 1");
  }, "guard-pop3-command/bad-top");
  expectThrow("refuses TOP with negative line-count", function () {
    b.guardPop3Command.validate("TOP 1 -1");
  }, "guard-pop3-command/bad-top");
  expectThrow("refuses oversize line under strict", function () {
    var pad = "x"; while (pad.length < 300) pad += "x";
    b.guardPop3Command.validate("USER " + pad);
  }, "guard-pop3-command/line-too-long");
}

function testCompliancePosture() {
  check("posture: hipaa → strict",   b.guardPop3Command.compliancePosture("hipaa") === "strict");
  check("posture: pci-dss → strict", b.guardPop3Command.compliancePosture("pci-dss") === "strict");
  check("posture: gdpr → strict",    b.guardPop3Command.compliancePosture("gdpr") === "strict");
  check("posture: soc2 → strict",    b.guardPop3Command.compliancePosture("soc2") === "strict");
  check("posture: unknown → null",   b.guardPop3Command.compliancePosture("nope") === null);
}

function testByteCapMultibyte() {
  // maxLineBytes / maxUsernameBytes / maxPasswordBytes are BYTE caps.
  var mb = String.fromCharCode(0x4e2d); // one 3-byte UTF-8 char
  var t1 = null;
  try { b.guardPop3Command.validate(mb.repeat(100), { profile: "strict", tls: true }); } catch (e) { t1 = e; }
  check("pop3 byte-cap: oversize multibyte line refused as line-too-long",
    t1 && t1.code === "guard-pop3-command/line-too-long");
  var t2 = null;
  try { b.guardPop3Command.validate("USER " + mb.repeat(40), { profile: "strict", tls: true }); } catch (e) { t2 = e; }
  check("pop3 byte-cap: oversize multibyte USER name refused",
    t2 && t2.code === "guard-pop3-command/username-too-long");
  var t3 = null;
  try { b.guardPop3Command.validate("PASS " + mb.repeat(40), { profile: "strict", tls: true }); } catch (e) { t3 = e; }
  check("pop3 byte-cap: oversize multibyte PASS argument refused",
    t3 && t3.code === "guard-pop3-command/password-too-long");
}

function run() {
  testByteCapMultibyte();
  testSurface();
  testHappyPath();
  testCleartextAuthRefused();
  testAuthCleartextRefused();
  testApopRefusedUnderStrict();
  testBadInputRefused();
  testCompliancePosture();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[guard-pop3-command] OK"); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}
