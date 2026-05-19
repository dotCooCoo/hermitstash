"use strict";

var helpers = require("../helpers");
var check = helpers.check;
var guardManageSieveCommand = require("../../lib/guard-managesieve-command");

function testSurface() {
  check("namespace",            typeof guardManageSieveCommand === "object");
  check("validate fn",          typeof guardManageSieveCommand.validate === "function");
  check("compliancePosture fn", typeof guardManageSieveCommand.compliancePosture === "function");
  check("PROFILES",             typeof guardManageSieveCommand.PROFILES === "object");
  check("PROFILES.strict",      typeof guardManageSieveCommand.PROFILES.strict === "object");
  check("PROFILES.balanced",    typeof guardManageSieveCommand.PROFILES.balanced === "object");
  check("PROFILES.permissive",  typeof guardManageSieveCommand.PROFILES.permissive === "object");
  check("error class",          typeof guardManageSieveCommand.GuardManageSieveCommandError === "function");

  // Verify the error class is what validate throws.
  var threw = null;
  try { guardManageSieveCommand.validate(""); } catch (e) { threw = e; }
  check("validate refusal is GuardManageSieveCommandError",
    threw instanceof guardManageSieveCommand.GuardManageSieveCommandError);
}

function testHappyPath() {
  var cap = guardManageSieveCommand.validate("CAPABILITY", { tls: true });
  check("CAPABILITY: zero-arg",
    cap.verb === "CAPABILITY" && cap.args.length === 0);

  var lo = guardManageSieveCommand.validate("LOGOUT", { tls: true });
  check("LOGOUT: zero-arg",
    lo.verb === "LOGOUT" && lo.args.length === 0);

  var st = guardManageSieveCommand.validate("STARTTLS", { tls: false });
  check("STARTTLS: zero-arg",
    st.verb === "STARTTLS" && st.args.length === 0);

  var ls = guardManageSieveCommand.validate("LISTSCRIPTS", { tls: true });
  check("LISTSCRIPTS: zero-arg",
    ls.verb === "LISTSCRIPTS");

  var noop1 = guardManageSieveCommand.validate("NOOP", { tls: true });
  check("NOOP: bare",
    noop1.verb === "NOOP" && noop1.args.length === 0);

  var noop2 = guardManageSieveCommand.validate('NOOP "tag-1"', { tls: true });
  check("NOOP: with echo tag",
    noop2.verb === "NOOP" && noop2.args[0] === "tag-1");

  var hs = guardManageSieveCommand.validate('HAVESPACE "myscript" 1024', { tls: true });
  check("HAVESPACE: parsed",
    hs.verb === "HAVESPACE" && hs.args[0] === "myscript" && hs.args[1] === 1024);

  var put = guardManageSieveCommand.validate('PUTSCRIPT "myscript" {52}', { tls: true });
  check("PUTSCRIPT: sync literal parsed",
    put.verb === "PUTSCRIPT" && put.args[0] === "myscript" &&
    put.literalBytes === 52 && put.literalPlus === false);

  var putPlus = guardManageSieveCommand.validate('PUTSCRIPT "x" {1024+}', { tls: true });
  check("PUTSCRIPT: LITERAL+ parsed",
    putPlus.literalBytes === 1024 && putPlus.literalPlus === true);

  var setActive = guardManageSieveCommand.validate('SETACTIVE "myscript"', { tls: true });
  check("SETACTIVE: parsed",
    setActive.verb === "SETACTIVE" && setActive.args[0] === "myscript");

  // RFC 5804 §2.8 — empty string deactivates all scripts.
  var setActiveEmpty = guardManageSieveCommand.validate('SETACTIVE ""', { tls: true });
  check("SETACTIVE: empty-string allowed (deactivates all per RFC 5804 §2.8)",
    setActiveEmpty.verb === "SETACTIVE" && setActiveEmpty.args[0] === "");

  var del = guardManageSieveCommand.validate('DELETESCRIPT "myscript"', { tls: true });
  check("DELETESCRIPT: parsed",
    del.verb === "DELETESCRIPT" && del.args[0] === "myscript");

  var ren = guardManageSieveCommand.validate('RENAMESCRIPT "old" "new"', { tls: true });
  check("RENAMESCRIPT: parsed",
    ren.verb === "RENAMESCRIPT" && ren.args[0] === "old" && ren.args[1] === "new");

  var getS = guardManageSieveCommand.validate('GETSCRIPT "myscript"', { tls: true });
  check("GETSCRIPT: parsed",
    getS.verb === "GETSCRIPT" && getS.args[0] === "myscript");

  var auth = guardManageSieveCommand.validate('AUTHENTICATE "PLAIN"', { tls: true });
  check("AUTHENTICATE PLAIN: parsed under TLS",
    auth.verb === "AUTHENTICATE" && auth.args[0] === "PLAIN");

  var authIR = guardManageSieveCommand.validate('AUTHENTICATE "PLAIN" {16+}', { tls: true });
  check("AUTHENTICATE PLAIN with initial-response literal: parsed",
    authIR.verb === "AUTHENTICATE" && authIR.args[0] === "PLAIN" &&
    authIR.literalBytes === 16 && authIR.literalPlus === true);
}

function testCleartextAuthRefused() {
  // RFC 4954 §4 + RFC 5804 §1.1 — AUTHENTICATE PLAIN over cleartext
  // under strict is refused.
  var threw = null;
  try {
    guardManageSieveCommand.validate('AUTHENTICATE "PLAIN"', { tls: false });
  } catch (e) { threw = e; }
  check("AUTHENTICATE PLAIN refused over cleartext under strict",
    threw && threw.code === "guard-managesieve-command/cleartext-auth");

  // LOGIN also refused.
  var threw2 = null;
  try {
    guardManageSieveCommand.validate('AUTHENTICATE "LOGIN"', { tls: false });
  } catch (e) { threw2 = e; }
  check("AUTHENTICATE LOGIN refused over cleartext under strict",
    threw2 && threw2.code === "guard-managesieve-command/cleartext-auth");

  // SCRAM-SHA-256 under strict still refused (defense-in-depth — even
  // mechanism-protected exchanges run under TLS to defeat active-MITM
  // downgrade attacks).
  var threw3 = null;
  try {
    guardManageSieveCommand.validate('AUTHENTICATE "SCRAM-SHA-256"', { tls: false });
  } catch (e) { threw3 = e; }
  check("AUTHENTICATE SCRAM-SHA-256 refused over cleartext under strict",
    threw3 && threw3.code === "guard-managesieve-command/cleartext-auth");

  // EXTERNAL exempt — credential is the TLS client cert, not a
  // password (and clients legitimately negotiate EXTERNAL after a TLS
  // session has come up).
  var ext = guardManageSieveCommand.validate('AUTHENTICATE "EXTERNAL"', { tls: false });
  check("AUTHENTICATE EXTERNAL allowed pre-TLS (RFC 4422 §4 channel-binding)",
    ext.verb === "AUTHENTICATE" && ext.args[0] === "EXTERNAL");

  // Permissive allows cleartext PLAIN.
  var rv = guardManageSieveCommand.validate('AUTHENTICATE "PLAIN"',
    { tls: false, profile: "permissive" });
  check("AUTHENTICATE PLAIN allowed pre-TLS under permissive",
    rv.verb === "AUTHENTICATE" && rv.args[0] === "PLAIN");
}

function testScriptNameShape() {
  function expectThrow(label, fn, codeMatch) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(codeMatch) !== -1);
  }
  // RFC 5804 §2.1 — slash refused (path-traversal blocker for
  // filesystem-backed sieveScripts stores).
  expectThrow("refuses forward-slash in script-name", function () {
    guardManageSieveCommand.validate('GETSCRIPT "foo/bar"', { tls: true });
  }, "guard-managesieve-command/bad-name-byte");
  // Backslash refused.
  expectThrow("refuses backslash in script-name", function () {
    guardManageSieveCommand.validate('GETSCRIPT "foo\\\\bar"', { tls: true });
  }, "guard-managesieve-command/bad-name-byte");

  // Empty script-name on GETSCRIPT — refused.
  expectThrow("refuses empty script-name on GETSCRIPT", function () {
    guardManageSieveCommand.validate('GETSCRIPT ""', { tls: true });
  }, "guard-managesieve-command/empty-name");

  // 513-byte script-name (RFC 5804 §2.1 caps at 512).
  expectThrow("refuses 513-byte script-name", function () {
    var pad = "x"; while (pad.length < 513) pad += "x";
    guardManageSieveCommand.validate('GETSCRIPT "' + pad + '"', { tls: true });
  }, "guard-managesieve-command/name-too-long");
}

function testLiteralShapeAndCaps() {
  function expectThrow(label, fn, codeMatch) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(codeMatch) !== -1);
  }
  // PUTSCRIPT with no literal at all.
  expectThrow("PUTSCRIPT missing literal", function () {
    guardManageSieveCommand.validate('PUTSCRIPT "myscript"', { tls: true });
  }, "guard-managesieve-command/bad-putscript");

  // Bad literal syntax.
  expectThrow("PUTSCRIPT bad literal syntax", function () {
    guardManageSieveCommand.validate('PUTSCRIPT "myscript" not-a-literal', { tls: true });
  }, "guard-managesieve-command/bad-literal");

  // Literal byte count exceeds strict 64 KiB cap.
  expectThrow("PUTSCRIPT literal exceeds strict 64 KiB cap", function () {
    guardManageSieveCommand.validate('PUTSCRIPT "myscript" {65537}', { tls: true });
  }, "guard-managesieve-command/script-too-large");

  // 64 KiB script accepted under strict (boundary).
  var ok = guardManageSieveCommand.validate('PUTSCRIPT "myscript" {65536}', { tls: true });
  check("PUTSCRIPT 64 KiB accepted under strict (boundary)",
    ok.literalBytes === 65536);

  // 64 KiB + 1 accepted under balanced.
  var balOk = guardManageSieveCommand.validate('PUTSCRIPT "myscript" {65537}',
    { tls: true, profile: "balanced" });
  check("PUTSCRIPT 64 KiB+1 accepted under balanced",
    balOk.literalBytes === 65537);

  // 1 MiB + 1 refused under permissive.
  expectThrow("PUTSCRIPT 1 MiB+1 refused under permissive", function () {
    guardManageSieveCommand.validate('PUTSCRIPT "myscript" {1048577}',
      { tls: true, profile: "permissive" });
  }, "guard-managesieve-command/script-too-large");
}

function testBadInputRefused() {
  function expectThrow(label, fn, codeMatch) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(codeMatch) !== -1);
  }
  expectThrow("refuses non-string", function () {
    guardManageSieveCommand.validate(null);
  }, "guard-managesieve-command/bad-input");
  expectThrow("refuses empty line", function () {
    guardManageSieveCommand.validate("");
  }, "guard-managesieve-command/empty-line");
  expectThrow("refuses unknown verb", function () {
    guardManageSieveCommand.validate("FROBNICATE");
  }, "guard-managesieve-command/unknown-verb");
  expectThrow("refuses args on zero-arg verb", function () {
    guardManageSieveCommand.validate("CAPABILITY extra");
  }, "guard-managesieve-command/unexpected-args");
  expectThrow("refuses bare-LF byte under strict", function () {
    guardManageSieveCommand.validate("CAPABILITY\nb", { tls: true });
  }, "guard-managesieve-command/bad-byte");
  expectThrow("refuses NUL byte", function () {
    guardManageSieveCommand.validate("CAPABILITY\x00", { tls: true });
  }, "guard-managesieve-command/bad-byte");
  expectThrow("refuses DEL byte", function () {
    guardManageSieveCommand.validate("CAPABILITY\x7F", { tls: true });
  }, "guard-managesieve-command/bad-byte");
  expectThrow("refuses C0 control byte (0x01)", function () {
    guardManageSieveCommand.validate("CAPABILITY\x01", { tls: true });
  }, "guard-managesieve-command/bad-byte");
  expectThrow("refuses missing AUTHENTICATE mechanism", function () {
    guardManageSieveCommand.validate("AUTHENTICATE", { tls: true });
  }, "guard-managesieve-command/missing-mechanism");
  expectThrow("refuses bare-token AUTHENTICATE mechanism (must be quoted)", function () {
    guardManageSieveCommand.validate("AUTHENTICATE PLAIN", { tls: true });
  }, "guard-managesieve-command/bad-mechanism");
  expectThrow("refuses unterminated quoted-string", function () {
    guardManageSieveCommand.validate('GETSCRIPT "myscript', { tls: true });
  }, "guard-managesieve-command/unterminated-string");
  expectThrow("refuses HAVESPACE with bad size", function () {
    guardManageSieveCommand.validate('HAVESPACE "x" notanumber', { tls: true });
  }, "guard-managesieve-command/bad-havespace");
  expectThrow("refuses oversize line under strict", function () {
    var pad = "x"; while (pad.length < 9000) pad += "x";
    guardManageSieveCommand.validate("NOOP " + pad, { tls: true });
  }, "guard-managesieve-command/line-too-long");
  expectThrow("refuses RENAMESCRIPT with one arg", function () {
    guardManageSieveCommand.validate('RENAMESCRIPT "only"', { tls: true });
  }, "guard-managesieve-command/bad-rename");
  expectThrow("refuses bad profile name", function () {
    guardManageSieveCommand.validate("CAPABILITY", { tls: true, profile: "loose" });
  }, "guard-managesieve-command/bad-profile");
}

function testCompliancePosture() {
  check("posture: hipaa → strict",   guardManageSieveCommand.compliancePosture("hipaa") === "strict");
  check("posture: pci-dss → strict", guardManageSieveCommand.compliancePosture("pci-dss") === "strict");
  check("posture: gdpr → strict",    guardManageSieveCommand.compliancePosture("gdpr") === "strict");
  check("posture: soc2 → strict",    guardManageSieveCommand.compliancePosture("soc2") === "strict");
  check("posture: unknown → null",   guardManageSieveCommand.compliancePosture("nope") === null);

  // Posture in opts overrides profile.
  var threw = null;
  try {
    guardManageSieveCommand.validate('AUTHENTICATE "PLAIN"',
      { tls: false, profile: "permissive", posture: "hipaa" });
  } catch (e) { threw = e; }
  check("posture override forces strict (refuses cleartext PLAIN)",
    threw && threw.code === "guard-managesieve-command/cleartext-auth");
}

function testBSurface() {
  var b = require("../../");
  check("b.guardManageSieveCommand.validate wired",            typeof b.guardManageSieveCommand.validate === "function");
  check("b.guardManageSieveCommand.compliancePosture wired",   typeof b.guardManageSieveCommand.compliancePosture === "function");
  check("b.guardManageSieveCommand.GuardManageSieveCommandError wired",
                                                               typeof b.guardManageSieveCommand.GuardManageSieveCommandError === "function");
}

function run() {
  testBSurface();
  testSurface();
  testHappyPath();
  testCleartextAuthRefused();
  testScriptNameShape();
  testLiteralShapeAndCaps();
  testBadInputRefused();
  testCompliancePosture();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[guard-managesieve-command] OK"); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}

// Use helpers to silence the unused-var warning for files that don't
// reach into `b` directly.
void helpers;
