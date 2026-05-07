"use strict";
/**
 * guard-yaml — YAML content-safety primitive (b.guardYaml).
 *
 * Covers: surface; registry parity; dangerous-tag detection
 * (!!python/ / !!java. / !!ruby/ / !!perl/ / !!js/ / !!cs/ / !!system.
 * / !!eval / !!exec / !!new / !!apply); custom-tag and core-tag
 * policy; anchor/alias detection; alias-explosion detection; multi-
 * document streams; Norway-problem implicit booleans (no/yes/y/n/on/
 * off); leading-zero octals; merge-key chain; duplicate keys at same
 * indent level; bidi/null/control char detection; sanitize discipline
 * (no safe sanitization — refuse on critical/high); profile + posture
 * vocabulary.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testGuardYamlSurface() {
  check("guardYaml is an object",                    typeof b.guardYaml === "object");
  check("guardYaml.NAME === 'yaml'",                 b.guardYaml.NAME === "yaml");
  check("guardYaml.KIND === 'content'",              b.guardYaml.KIND === "content");
  check("guardYaml.MIME_TYPES has application/yaml", b.guardYaml.MIME_TYPES.indexOf("application/yaml") !== -1);
  check("guardYaml.EXTENSIONS has .yaml",            b.guardYaml.EXTENSIONS.indexOf(".yaml") !== -1);
  check("guardYaml.PROFILES has strict",             !!b.guardYaml.PROFILES["strict"]);
  check("guardYaml.PROFILES has balanced",           !!b.guardYaml.PROFILES["balanced"]);
  check("guardYaml.PROFILES has permissive",         !!b.guardYaml.PROFILES["permissive"]);
  check("guardYaml.COMPLIANCE_POSTURES has hipaa",   !!b.guardYaml.COMPLIANCE_POSTURES["hipaa"]);
  check("guardYaml.validate is a function",          typeof b.guardYaml.validate === "function");
  check("guardYaml.parse is a function",             typeof b.guardYaml.parse === "function");
  check("guardYaml.gate is a function",              typeof b.guardYaml.gate === "function");
  check("guardYaml.GuardYamlError is a function",    typeof b.guardYaml.GuardYamlError === "function");
  check("frameworkError.GuardYamlError exposed",     typeof b.frameworkError.GuardYamlError === "function");
}

function testGuardYamlRegistryParity() {
  check("guardYaml registered in guardAll",
        b.guardAll.list().some(function (g) { return g.name === "yaml"; }));
}

function testGuardYamlDangerousTags() {
  var prefixes = ["!!python/object", "!!java.util.HashMap",
                  "!!ruby/object:Class", "!!perl/", "!!js/Function",
                  "!!system.IO.File", "!!eval foo", "!!apply [1]"];
  for (var i = 0; i < prefixes.length; i++) {
    var rv = b.guardYaml.validate(prefixes[i] + "\n", { profile: "strict" });
    check("dangerous-tag detected: " + JSON.stringify(prefixes[i]),
          rv.ok === false &&
          rv.issues.some(function (issue) { return issue.kind === "dangerous-tag"; }));
  }
}

function testGuardYamlCustomTag() {
  var rv = b.guardYaml.validate("!Foo bar\n", { profile: "strict" });
  check("custom tag refused under strict",
        rv.issues.some(function (issue) { return issue.kind === "custom-tag"; }));
}

function testGuardYamlAlias() {
  var rv = b.guardYaml.validate("a: &a v\nb: *a\n", { profile: "strict" });
  check("anchors+aliases refused under strict",
        rv.issues.some(function (issue) { return issue.kind === "alias-disabled"; }));
}

function testGuardYamlAliasExplosion() {
  // Build alias-amplification > 8x anchors.
  var src = "a: &a 1\n";
  for (var i = 0; i < 20; i++) src += "b" + i + ": *a\n";
  var rv = b.guardYaml.validate(src, { profile: "balanced" });
  check("alias explosion detected (8x amplification floor)",
        rv.issues.some(function (issue) { return issue.kind === "alias-explosion"; }));
}

function testGuardYamlMultiDoc() {
  var rv = b.guardYaml.validate("---\nfoo: 1\n---\nbar: 2\n", { profile: "strict" });
  check("multi-document refused under strict",
        rv.issues.some(function (issue) { return issue.kind === "multi-document"; }));
}

function testGuardYamlNorwayProblem() {
  var inputs = ["country: NO\n", "x: yes\n", "y: y\n", "active: on\n",
                "mode: off\n", "n: no\n"];
  for (var i = 0; i < inputs.length; i++) {
    var rv = b.guardYaml.validate(inputs[i], { profile: "strict" });
    check("Norway problem detected: " + JSON.stringify(inputs[i]),
          rv.issues.some(function (issue) { return issue.kind === "norway-implicit-bool"; }));
  }

  // Quoted form NOT flagged.
  var rvQuoted = b.guardYaml.validate('country: "NO"\n', { profile: "strict" });
  check("quoted form NOT flagged",
        !rvQuoted.issues.some(function (issue) { return issue.kind === "norway-implicit-bool"; }));
}

function testGuardYamlLeadingZeroOctal() {
  var rv = b.guardYaml.validate("mode: 0777\n", { profile: "strict" });
  check("leading-zero octal detected",
        rv.issues.some(function (issue) { return issue.kind === "leading-zero-octal"; }));
}

function testGuardYamlMergeKey() {
  var rv = b.guardYaml.validate("base: &b\n  x: 1\nuser:\n  <<: *b\n  y: 2\n",
                                { profile: "strict" });
  check("merge-key with anchor reference detected",
        rv.issues.some(function (issue) { return issue.kind === "merge-key"; }));
}

function testGuardYamlDuplicateKeys() {
  var rv = b.guardYaml.validate("a: 1\na: 2\n", { profile: "strict" });
  check("duplicate-key detected at same indent",
        rv.issues.some(function (issue) { return issue.kind === "duplicate-key"; }));

  var rvNotDup = b.guardYaml.validate("x:\n  a: 1\ny:\n  a: 2\n", { profile: "strict" });
  check("same key at different scopes NOT flagged",
        !rvNotDup.issues.some(function (issue) { return issue.kind === "duplicate-key"; }));
}

function testGuardYamlBidiNull() {
  var bidi = String.fromCharCode(0x202E);
  var rv = b.guardYaml.validate("name: a" + bidi + "b\n", { profile: "strict" });
  check("bidi override detected in YAML scalar",
        rv.issues.some(function (issue) { return issue.kind === "bidi-override"; }));

  var nb = String.fromCharCode(0);
  var rvNull = b.guardYaml.validate("name: a" + nb + "b\n", { profile: "strict" });
  check("null byte detected",
        rvNull.issues.some(function (issue) { return issue.kind === "null-byte"; }));
}

function testGuardYamlClean() {
  var rv = b.guardYaml.validate("name: alice\nage: 30\ntags:\n  - one\n  - two\n",
                                { profile: "strict" });
  check("clean YAML → ok=true with no issues",
        rv.ok === true && rv.issues.length === 0);
}

function testGuardYamlParseStrictThrows() {
  var threw = null;
  try { b.guardYaml.parse("!!python/object/new:cls\nargs: [a]\n", { profile: "strict" }); }
  catch (e) { threw = e; }
  check("parse strict: throws on dangerous tag",
        threw && /dangerous-tag/.test(threw.code || threw.message || ""));
}

async function testGuardYamlGate() {
  var g = b.guardYaml.gate({ profile: "strict" });
  var clean = await g.check({
    contentType: "application/yaml",
    bytes:       Buffer.from("name: alice\n", "utf8"),
  });
  check("gate clean → action=serve",
        clean.ok === true && clean.action === "serve");

  var hostile = await g.check({
    contentType: "application/yaml",
    bytes:       Buffer.from("!!python/object/new:cls\nargs: [a]\n", "utf8"),
  });
  check("gate dangerous tag → action !== serve",
        hostile.action !== "serve");
}

function testGuardYamlCompliancePosture() {
  var hipaa = b.guardYaml.compliancePosture("hipaa");
  check("compliancePosture('hipaa') sets reject policies",
        hipaa.tagPolicy === "reject" &&
        hipaa.aliasPolicy === "reject");
  var threw = null;
  try { b.guardYaml.compliancePosture("unknown"); }
  catch (e) { threw = e; }
  check("compliancePosture: unknown name throws",
        threw && /unknown/.test(threw.message));
}

function testGuardYamlBadProfile() {
  var threw = null;
  try { b.guardYaml.validate("a: 1\n", { profile: "made-up" }); }
  catch (e) { threw = e; }
  check("validate: unknown profile throws",
        threw && /unknown profile/i.test(threw.message));
}

async function run() {
  testGuardYamlSurface();
  testGuardYamlRegistryParity();
  testGuardYamlDangerousTags();
  testGuardYamlCustomTag();
  testGuardYamlAlias();
  testGuardYamlAliasExplosion();
  testGuardYamlMultiDoc();
  testGuardYamlNorwayProblem();
  testGuardYamlLeadingZeroOctal();
  testGuardYamlMergeKey();
  testGuardYamlDuplicateKeys();
  testGuardYamlBidiNull();
  testGuardYamlClean();
  testGuardYamlParseStrictThrows();
  testGuardYamlCompliancePosture();
  testGuardYamlBadProfile();
  await testGuardYamlGate();
}

module.exports = { run: run };
