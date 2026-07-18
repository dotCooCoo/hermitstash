// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("b.mail.sieve.run exists",       typeof b.mail.sieve.run === "function");
  check("b.mail.sieve.runScript exists", typeof b.mail.sieve.runScript === "function");
  check("b.mail.sieve.create exists",    typeof b.mail.sieve.create === "function");
}

function testImplicitKeep() {
  var rv = b.mail.sieve.runScript('# empty script\r\n', {});
  check("implicit keep when no action fires",
    rv.actions.length === 1 && rv.actions[0].kind === "keep" && rv.actions[0].implicit);
}

function testFileinto() {
  var script = 'require ["fileinto"];\r\n' +
    'if header :contains "Subject" "[bug]" { fileinto "bugs"; }\r\n';
  var rv = b.mail.sieve.runScript(script, {
    headers: [{ name: "Subject", value: "Re: [bug] crash" }],
  });
  check("fileinto fires + cancels implicit keep",
    rv.actions.length === 1 && rv.actions[0].kind === "fileinto" && rv.actions[0].folder === "bugs");
}

function testAddressDomain() {
  var script = 'if address :is :domain "From" "trusted.com" { keep; }\r\n';
  var rv1 = b.mail.sieve.runScript(script, {
    headers: [{ name: "From", value: "alice@trusted.com" }],
  });
  check("address :domain match",
    rv1.actions.length === 1 && rv1.actions[0].kind === "keep");
  var rv2 = b.mail.sieve.runScript(script, {
    headers: [{ name: "From", value: "alice@untrusted.com" }],
  });
  check("address :domain non-match → implicit keep",
    rv2.actions[0].implicit === true);
}

function testEnvelope() {
  var script = 'if envelope :is "from" "boss@example.com" { fileinto "Boss"; }\r\n';
  var rv = b.mail.sieve.runScript(script, {
    envelope: { from: "boss@example.com", to: "me@example.com" },
    headers:  [],
  });
  check("envelope test reads env.envelope",
    rv.actions[0].kind === "fileinto" && rv.actions[0].folder === "Boss");
}

function testSize() {
  var script = 'if size :over 1K { discard; }\r\n';
  var big = b.mail.sieve.runScript(script, { sizeBytes: 2048 });
  check("size :over fires on 2KB",
    big.actions[0].kind === "discard");
  var small = b.mail.sieve.runScript(script, { sizeBytes: 512 });
  check("size :over below threshold → implicit keep",
    small.actions[0].implicit === true);
}

function testWildcardMatches() {
  var script = 'if header :matches "Subject" "[bug]*" { fileinto "bugs"; }\r\n';
  var rv = b.mail.sieve.runScript('require ["fileinto"];\r\n' + script, {
    headers: [{ name: "Subject", value: "[bug] tracker #42" }],
  });
  check("`:matches` wildcard fires",
    rv.actions[0].kind === "fileinto");
}

function testAnyofAllof() {
  var script =
    'if anyof(header :is "X-Spam" "yes", header :contains "Subject" "viagra") {\r\n' +
    '  discard;\r\n' +
    '}\r\n';
  var rv = b.mail.sieve.runScript(script, {
    headers: [{ name: "Subject", value: "buy viagra now" }],
  });
  check("anyof matches second branch", rv.actions[0].kind === "discard");
}

function testRedirect() {
  var script = 'if header :is "From" "alerts@example.com" { redirect "ops@example.com"; }\r\n';
  var rv = b.mail.sieve.runScript(script, {
    headers: [{ name: "From", value: "alerts@example.com" }],
  });
  check("redirect captures address",
    rv.actions[0].kind === "redirect" && rv.actions[0].address === "ops@example.com");
}

function testStop() {
  var script =
    'if header :is "From" "ignore@x.com" { stop; }\r\n' +
    'keep;\r\n';
  var rv = b.mail.sieve.runScript(script, {
    headers: [{ name: "From", value: "ignore@x.com" }],
  });
  check("stop halts further commands → implicit keep applies (no explicit keep ran)",
    rv.stopped === true);
}

function testGasExhaustion() {
  // Wide allof to consume gas without nesting.
  var subs = []; for (var i = 0; i < 20; i++) subs.push("true");
  var script = "if allof(" + subs.join(", ") + ") { keep; }\r\n";
  var threw = null;
  try { b.mail.sieve.runScript(script, {}, { maxGas: 3 }); } catch (e) { threw = e; }
  check("gas exhaustion throws",
    threw && threw.code === "mail-sieve/gas-exhausted");
}

function testBadAst() {
  var threw = null;
  try { b.mail.sieve.run({ notAnAst: true }, {}); } catch (e) { threw = e; }
  check("non-script ast refused",
    threw && threw.code === "mail-sieve/bad-ast");
}

function testCreateHandle() {
  var sieve = b.mail.sieve.create({ maxGas: 100 });
  var rv = sieve.runScript('require ["fileinto"];\r\nfileinto "Test";\r\n', { headers: [] });
  check("handle runScript returns action",
    rv.actions[0].kind === "fileinto" && rv.actions[0].folder === "Test");
  var v = sieve.validateScript('require ["nonsense"];\nkeep;\n');
  check("handle validateScript surfaces unknown cap",
    !v.ok && v.issues[0].ruleId === "safe-sieve/unknown-capability");
}

// ---- tests / adversarial input ------------------------------------------

function testUnknownTestRefused() {
  // A test identifier the parser accepts (any id is a test) but the
  // interpreter never wired — must refuse, not silently pass/fail-open.
  var threw = null;
  try { b.mail.sieve.runScript('if bogustest "x" { keep; }', {}); }
  catch (e) { threw = e; }
  check("unknown test refused with typed error",
    threw && threw.code === "mail-sieve/unknown-test");
}

function testUnknownActionRefused() {
  var threw = null;
  try { b.mail.sieve.runScript('frobnicate;', {}); } catch (e) { threw = e; }
  check("unknown action refused with typed error",
    threw && threw.code === "mail-sieve/unknown-action");
}

function testBadCommandKind() {
  // Hand-built AST fed to the public run() entry — an unmodeled command
  // kind must throw a typed refusal, never fall through.
  var threw = null;
  try {
    b.mail.sieve.run({ kind: "script", commands: [{ kind: "weird" }] }, {});
  } catch (e) { threw = e; }
  check("unmodeled command kind refused",
    threw && threw.code === "mail-sieve/bad-command");
}

function testFileintoMissingFolder() {
  var threw = null;
  try { b.mail.sieve.runScript('require ["fileinto"];\r\nfileinto;\r\n', {}); }
  catch (e) { threw = e; }
  check("fileinto without folder refused",
    threw && threw.code === "mail-sieve/bad-fileinto");
  // Empty string-list argument is equally malformed (v.v[0] → null).
  var threw2 = null;
  try { b.mail.sieve.runScript('require ["fileinto"];\r\nfileinto [];\r\n', {}); }
  catch (e) { threw2 = e; }
  check("fileinto with empty list refused",
    threw2 && threw2.code === "mail-sieve/bad-fileinto");
}

function testRedirectMissingAddress() {
  var threw = null;
  try { b.mail.sieve.runScript('redirect;', {}); } catch (e) { threw = e; }
  check("redirect without address refused",
    threw && threw.code === "mail-sieve/bad-redirect");
}

function testNotTest() {
  var rv = b.mail.sieve.runScript('if not exists "X-Missing" { discard; }',
    { headers: [] });
  check("`not` inverts the sub-test",
    rv.actions[0].kind === "discard");
}

function testExists() {
  var present = b.mail.sieve.runScript('if exists "Subject" { discard; }',
    { headers: [{ name: "Subject", value: "hi" }] });
  check("exists fires when header present", present.actions[0].kind === "discard");
  var absent = b.mail.sieve.runScript('if exists "Subject" { discard; }',
    { headers: [] });
  check("exists false → implicit keep when header absent",
    absent.actions[0].implicit === true);
  // Header present but value null still counts as existing.
  var nullVal = b.mail.sieve.runScript('if exists "X-Flag" { discard; }',
    { headers: [{ name: "X-Flag", value: null }] });
  check("exists treats null-valued header as present",
    nullVal.actions[0].kind === "discard");
}

function testSizeUnderAndFallbacks() {
  var under = b.mail.sieve.runScript('if size :under 1K { discard; }',
    { sizeBytes: 512 });
  check("size :under fires below threshold", under.actions[0].kind === "discard");
  // Falls back to bodyBytes.length when sizeBytes absent.
  var body = b.mail.sieve.runScript('if size :over 3 { discard; }',
    { bodyBytes: Buffer.from("hello") });
  check("size falls back to bodyBytes.length", body.actions[0].kind === "discard");
  // No size info at all → 0 bytes, :under fires.
  var zero = b.mail.sieve.runScript('if size :under 10 { discard; }', {});
  check("size defaults to 0 bytes with no env info",
    zero.actions[0].kind === "discard");
}

function testAddressPartsAndExtraction() {
  // :localpart on a display-name address.
  var lp = b.mail.sieve.runScript(
    'if address :is :localpart "From" "alice" { keep; }',
    { headers: [{ name: "From", value: "Alice Smith <alice@example.com>" }] });
  check("address :localpart extracts local part before @",
    lp.actions[0].kind === "keep" && !lp.actions[0].implicit);
  // :all on a bracketed address returns the full addr-spec.
  var all = b.mail.sieve.runScript(
    'if address :is :all "From" "a@x.com" { keep; }',
    { headers: [{ name: "From", value: "A <a@x.com>" }] });
  check("address :all extracts full addr-spec from brackets",
    all.actions[0].kind === "keep" && !all.actions[0].implicit);
  // Address without an @: localpart is the whole token; domain is "".
  var noAtLocal = b.mail.sieve.runScript(
    'if address :is :localpart "From" "weird" { keep; }',
    { headers: [{ name: "From", value: "weird" }] });
  check("address :localpart of at-less token is the whole token",
    !noAtLocal.actions[0].implicit);
  var noAtDomain = b.mail.sieve.runScript(
    'if address :is :domain "From" "" { keep; }',
    { headers: [{ name: "From", value: "nodomain" }] });
  check("address :domain of at-less token is empty string",
    !noAtDomain.actions[0].implicit);
}

function testEnvelopeArrayAndBogusField() {
  // Array-valued envelope recipient list — each entry compared.
  var arr = b.mail.sieve.runScript('if envelope :is "to" "b@x.com" { keep; }',
    { envelope: { to: ["a@x.com", "b@x.com"] } });
  check("envelope matches any entry of an array value",
    arr.actions[0].kind === "keep" && !arr.actions[0].implicit);
  // Envelope field other than from/to is skipped per RFC 5228 §5.4.
  var bogus = b.mail.sieve.runScript('if envelope :is "subject" "x" { discard; }',
    { envelope: { from: "a@x.com" } });
  check("envelope ignores fields other than from/to",
    bogus.actions[0].implicit === true);
  // No envelope object at all → no match.
  var none = b.mail.sieve.runScript('if envelope :is "from" "a@x.com" { discard; }', {});
  check("envelope with no env.envelope → implicit keep",
    none.actions[0].implicit === true);
}

function testHeaderListsAndMultiValue() {
  // List of header names + list of keys.
  var lists = b.mail.sieve.runScript(
    'if header :contains ["To","Cc"] ["vip"] { discard; }',
    { headers: [{ name: "Cc", value: "vip@x.com" }] });
  check("header test spans a list of names and keys",
    lists.actions[0].kind === "discard");
  // Two headers of the same name — both values considered.
  var multi = b.mail.sieve.runScript('if header :is "Received" "b" { discard; }',
    { headers: [{ name: "Received", value: "a" }, { name: "Received", value: "b" }] });
  check("header test considers every value of a repeated header",
    multi.actions[0].kind === "discard");
}

function testComparatorDefaultCaseInsensitive() {
  // Default comparator is i;ascii-casemap → case-insensitive :is.
  var ci = b.mail.sieve.runScript('if header :is "Subject" "hello" { discard; }',
    { headers: [{ name: "Subject", value: "HELLO" }] });
  check("default comparator is case-insensitive (i;ascii-casemap)",
    ci.actions[0].kind === "discard");

  // An explicit `:comparator "i;octet"` binds the comparator name to the tag
  // (RFC 5228 §2.7.3), not into the positional stream -- so the header name and
  // keys stay aligned and the test still matches (previously the comparator
  // value was mis-read as the header name, silently disabling the test = a
  // filter bypass). i;octet is case-SENSITIVE (unlike the default
  // i;ascii-casemap): an exact-case key matches, a wrong-case key does not.
  var octet = b.mail.sieve.runScript(
    'if header :comparator "i;octet" :is "Subject" "HELLO" { discard; }',
    { headers: [{ name: "Subject", value: "HELLO" }] });
  check("explicit :comparator :is exact-case matches (no filter bypass)",
    octet.actions[0].kind === "discard");
  var octetMiss = b.mail.sieve.runScript(
    'if header :comparator "i;octet" :is "Subject" "hello" { discard; }',
    { headers: [{ name: "Subject", value: "HELLO" }] });
  check("explicit :comparator i;octet is case-sensitive (wrong case falls through to keep)",
    octetMiss.actions[0].implicit === true);
  // A `:comparator` with no following comparator-name string fails closed at parse.
  var badComp = false;
  try { b.mail.sieve.runScript('if header :comparator :is "Subject" "x" { discard; }', { headers: [] }); }
  catch (e) { badComp = /parse-error/.test(e.code || e.message); }
  check("explicit :comparator without a value is refused at parse", badComp);
  // An unsupported comparator name is refused at parse (like the
  // require ["comparator-<name>"] capability guard), not silently treated as
  // octet exact-matching -- otherwise it would bypass the capability guard.
  var badCompName = false;
  try {
    b.mail.sieve.runScript('if header :comparator "i;unicode-casemap" :is "Subject" "HELLO" { discard; }',
      { headers: [{ name: "Subject", value: "HELLO" }] });
  } catch (e) { badCompName = /unknown-capability|unimplemented-capability/.test(e.code || e.message); }
  check("explicit :comparator with an unsupported name is refused (no capability-guard bypass)", badCompName);
}

function testWildcardEscaping() {
  // `?` matches exactly one byte.
  var q = b.mail.sieve.runScript('if header :matches "Subject" "a?c" { discard; }',
    { headers: [{ name: "Subject", value: "abc" }] });
  check("`:matches` ? matches a single byte", q.actions[0].kind === "discard");
  // Regex metacharacters other than * / ? are escaped — `.` is literal.
  var dot = b.mail.sieve.runScript('if header :matches "Subject" "a.c" { discard; }',
    { headers: [{ name: "Subject", value: "axc" }] });
  check("`:matches` escapes regex metachars (`.` is literal, not wildcard)",
    dot.actions[0].implicit === true);
}

function testElsifElse() {
  var script =
    'if header :is "X" "1" { discard; }\r\n' +
    'elsif header :is "X" "2" { redirect "a@b.com"; }\r\n' +
    'else { keep; }\r\n';
  var elif = b.mail.sieve.runScript(script, { headers: [{ name: "X", value: "2" }] });
  check("elsif branch taken",
    elif.actions[0].kind === "redirect" && elif.actions[0].address === "a@b.com");
  var els = b.mail.sieve.runScript(script, { headers: [{ name: "X", value: "9" }] });
  check("else branch taken when no if/elsif matches",
    els.actions[0].kind === "keep" && !els.actions[0].implicit);
}

function testExplicitKeepAndStopSkips() {
  var k = b.mail.sieve.runScript('keep;\r\n', {});
  check("explicit keep is not marked implicit",
    k.actions.length === 1 && k.actions[0].kind === "keep" && !k.actions[0].implicit);
  // stop halts before a following action ever runs.
  var s = b.mail.sieve.runScript('stop;\r\nfileinto "X";\r\n', {});
  check("stop skips subsequent commands",
    s.stopped === true &&
    !s.actions.some(function (a) { return a.kind === "fileinto"; }));
}

function testFileintoListArg() {
  var rv = b.mail.sieve.runScript('require ["fileinto"];\r\nfileinto ["A","B"];\r\n', {});
  check("fileinto takes first element of a string-list arg",
    rv.actions[0].kind === "fileinto" && rv.actions[0].folder === "A");
}

function testGasExhaustionInCommands() {
  var threw = null;
  try { b.mail.sieve.runScript('keep;\r\nkeep;\r\nkeep;\r\n', {}, { maxGas: 2 }); }
  catch (e) { threw = e; }
  check("gas exhausts across a command sequence",
    threw && threw.code === "mail-sieve/gas-exhausted");
}

function testMaxGasOptValidation() {
  var cases = [
    ["zero", 0],
    ["negative", -1],
    ["Infinity", Infinity],
    ["NaN", NaN],
    ["string", "5"],
    ["fractional", 1.5],
    ["over-cap", b.mail.sieve.MAX_GAS_UNITS + 1],
  ];
  var allRefused = true;
  for (var i = 0; i < cases.length; i++) {
    var threw = null;
    try { b.mail.sieve.runScript('keep;', {}, { maxGas: cases[i][1] }); }
    catch (e) { threw = e; }
    if (!threw || threw.code !== "mail-sieve/bad-opt") allRefused = false;
  }
  check("run() refuses every out-of-range/ill-typed maxGas", allRefused);
}

function testParseErrorsPropagate() {
  // runScript surfaces the parser's typed refusals unchanged.
  var badSyntax = null;
  try { b.mail.sieve.runScript('if header :is', {}); } catch (e) { badSyntax = e; }
  check("runScript propagates parse-error", badSyntax && badSyntax.code === "safe-sieve/parse-error");
  var unimpl = null;
  try { b.mail.sieve.runScript('require ["vacation"];\r\nkeep;\r\n', {}); }
  catch (e) { unimpl = e; }
  check("runScript propagates unimplemented-capability refusal",
    unimpl && unimpl.code === "safe-sieve/unimplemented-capability");
}

function testCreateOptValidation() {
  var badOpts = null;
  try { b.mail.sieve.create(42); } catch (e) { badOpts = e; }
  check("create refuses non-object opts", badOpts && badOpts.code === "mail-sieve/bad-opt");
  var badGas = null;
  try { b.mail.sieve.create({ maxGas: -1 }); } catch (e) { badGas = e; }
  check("create refuses bad maxGas", badGas && badGas.code === "mail-sieve/bad-opt");
  var overCap = null;
  try { b.mail.sieve.create({ maxGas: b.mail.sieve.MAX_GAS_UNITS + 1 }); }
  catch (e) { overCap = e; }
  check("create refuses maxGas over cap", overCap && overCap.code === "mail-sieve/bad-opt");
}

function testCreateAuditEmissions() {
  var events = [];
  var sieve = b.mail.sieve.create({
    audit: { safeEmit: function (e) { events.push(e.action + "/" + e.outcome); } },
  });
  sieve.runScript('keep;\r\n', {});
  sieve.validateScript('require ["fileinto"];\r\nkeep;\r\n');
  sieve.validateScript('require ["nonsense"];\r\nkeep;\r\n');
  sieve.run(b.safeSieve.parse('keep;\r\n'), {});
  check("create handle emits run + validate(success/failure) + run audit events",
    events.length === 4 &&
    events[0] === "mail.sieve.run/success" &&
    events[1] === "mail.sieve.validate/success" &&
    events[2] === "mail.sieve.validate/failure" &&
    events[3] === "mail.sieve.run/success");
}

function testCreateAuditThrowDropSilent() {
  var sieve = b.mail.sieve.create({
    audit: { safeEmit: function () { throw new Error("audit sink exploded"); } },
  });
  var rv = sieve.runScript('keep;\r\n', {});
  check("create handle survives a throwing audit sink (drop-silent)",
    rv.actions[0].kind === "keep");
}

function run() {
  testSurface();
  testImplicitKeep();
  testFileinto();
  testAddressDomain();
  testEnvelope();
  testSize();
  testWildcardMatches();
  testAnyofAllof();
  testRedirect();
  testStop();
  testGasExhaustion();
  testBadAst();
  testCreateHandle();
  testUnknownTestRefused();
  testUnknownActionRefused();
  testBadCommandKind();
  testFileintoMissingFolder();
  testRedirectMissingAddress();
  testNotTest();
  testExists();
  testSizeUnderAndFallbacks();
  testAddressPartsAndExtraction();
  testEnvelopeArrayAndBogusField();
  testHeaderListsAndMultiValue();
  testComparatorDefaultCaseInsensitive();
  testWildcardEscaping();
  testElsifElse();
  testExplicitKeepAndStopSkips();
  testFileintoListArg();
  testGasExhaustionInCommands();
  testMaxGasOptValidation();
  testParseErrorsPropagate();
  testCreateOptValidation();
  testCreateAuditEmissions();
  testCreateAuditThrowDropSilent();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[mail-sieve] OK"); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}
