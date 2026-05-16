"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("validate fn",          typeof b.guardMailQuery.validate === "function");
  check("validateActor fn",     typeof b.guardMailQuery.validateActor === "function");
  check("compliancePosture fn", typeof b.guardMailQuery.compliancePosture === "function");
  check("PROFILES frozen",      Object.isFrozen(b.guardMailQuery.PROFILES));
  check("NAME = mailQuery",     b.guardMailQuery.NAME === "mailQuery");
  check("KIND = mail-query",    b.guardMailQuery.KIND === "mail-query");
  check("GuardMailQueryError is fn", typeof b.guardMailQuery.GuardMailQueryError === "function");
  var e = new b.guardMailQuery.GuardMailQueryError("mail-query/test", "test");
  check("GuardMailQueryError instances carry code", e.code === "mail-query/test");
}

function expectRefused(label, fn, codeMatch) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, threw && (threw.code || "").indexOf(codeMatch) !== -1);
}

function testValid() {
  var r = b.guardMailQuery.validate({
    and: [
      { modseq: { gt: 0 } },
      { flag: { eq: "\\Seen" } },
    ],
  });
  check("valid passes", r && typeof r === "object");
}

function testRefuses() {
  expectRefused("refuses bad input",
    function () { b.guardMailQuery.validate(null); },
    "mail-query/empty");
  expectRefused("refuses non-object",
    function () { b.guardMailQuery.validate("hi"); },
    "mail-query/bad-input");
  expectRefused("refuses function in filter",
    function () { b.guardMailQuery.validate({ pred: function () {} }); },
    "mail-query/unknown-key");  // pred isn't an op/col; rejected before reaching function check
  expectRefused("refuses regex value",
    function () { b.guardMailQuery.validate({ subject: /x/ }); },
    "mail-query/regex-not-allowed");
  expectRefused("refuses cycle",
    function () {
      var a = {};
      a.and = [a];                // cycle
      b.guardMailQuery.validate(a);
    },
    "mail-query/cycle");
  expectRefused("refuses unknown column",
    function () { b.guardMailQuery.validate({ nope: { eq: 1 } }); },
    "mail-query/unknown-key");
  expectRefused("refuses __proto__ key",
    function () {
      var f = {};
      Object.defineProperty(f, "__proto__", { value: { eq: 1 }, enumerable: true, configurable: true });
      b.guardMailQuery.validate(f);
    },
    "mail-query/proto-key");
  expectRefused("refuses non-finite number",
    function () { b.guardMailQuery.validate({ modseq: { gt: Infinity } }); },
    "mail-query/bad-number");
}

function testProjection() {
  b.guardMailQuery.validate({ modseq: { gt: 0 } }, { project: ["objectid", "modseq"] });
  expectRefused("refuses bad projection column",
    function () { b.guardMailQuery.validate({ modseq: { gt: 0 } }, { project: ["secret"] }); },
    "mail-query/bad-projection-column");
}

function testActor() {
  b.guardMailQuery.validateActor({ id: "u1" });
  expectRefused("refuses missing posture field",
    function () { b.guardMailQuery.validateActor({ id: "u1" }, "hipaa"); },
    "mail-query/missing-posture-field");
  b.guardMailQuery.validateActor({ id: "u1", purposeOfUse: "TREATMENT" }, "hipaa");
  expectRefused("refuses missing actor",
    function () { b.guardMailQuery.validateActor(null); },
    "mail-query/no-actor");
  expectRefused("refuses no id",
    function () { b.guardMailQuery.validateActor({ roles: ["x"] }); },
    "mail-query/bad-actor");
}

function testCompliance() {
  check("hipaa→strict",   b.guardMailQuery.compliancePosture("hipaa") === "strict");
  check("pci→strict",     b.guardMailQuery.compliancePosture("pci-dss") === "strict");
  check("gdpr→strict",    b.guardMailQuery.compliancePosture("gdpr") === "strict");
  check("soc2→strict",    b.guardMailQuery.compliancePosture("soc2") === "strict");
  check("unknown→null",   b.guardMailQuery.compliancePosture("nope") === null);
}

async function run() {
  testSurface();
  testValid();
  testRefuses();
  testProjection();
  testActor();
  testCompliance();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
