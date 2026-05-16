"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function expectRefused(label, fn, codeMatch) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, threw && (threw.code || "").indexOf(codeMatch) !== -1);
}

function testSurface() {
  check("validate fn",        typeof b.guardPostureChain.validate === "function");
  check("NAME = postureChain", b.guardPostureChain.NAME === "postureChain");
  check("KIND = posture-chain", b.guardPostureChain.KIND === "posture-chain");
  check("GuardPostureChainError",
    typeof b.guardPostureChain.GuardPostureChainError === "function");
  var e = new b.guardPostureChain.GuardPostureChainError("posture-chain/test", "t");
  check("error carries code", e.code === "posture-chain/test");
  check("compliancePosture hipaa",   b.guardPostureChain.compliancePosture("hipaa") === "strict");
  check("compliancePosture unknown", b.guardPostureChain.compliancePosture("nope") === null);
}

function testValid() {
  b.guardPostureChain.validate({
    postureSet: ["hipaa", "pci-dss"],
    chainTrail: ["api-gateway", "mail-agent"],
    enteredAt:  [1700000000000, 1700000000100],
    hopCount:   2,
  });
  // No timestamps — also OK.
  b.guardPostureChain.validate({
    postureSet: ["soc2"],
    chainTrail: ["entry"],
  });
}

function testRefuses() {
  expectRefused("refuses non-object",
    function () { b.guardPostureChain.validate(null); },
    "posture-chain/bad-input");
  expectRefused("refuses non-array postureSet",
    function () { b.guardPostureChain.validate({ postureSet: "hipaa", chainTrail: [] }); },
    "posture-chain/bad-posture-set");
  expectRefused("refuses duplicate regime",
    function () {
      b.guardPostureChain.validate({
        postureSet: ["hipaa", "hipaa"], chainTrail: [],
      });
    }, "posture-chain/duplicate-regime");
  expectRefused("refuses duplicate hop (recursion)",
    function () {
      b.guardPostureChain.validate({
        postureSet: ["hipaa"], chainTrail: ["agent-a", "agent-a"],
      });
    }, "posture-chain/duplicate-hop");
  expectRefused("refuses non-ASCII hop name",
    function () {
      b.guardPostureChain.validate({
        postureSet: ["hipaa"], chainTrail: ["mail-agent", "café-agent"],
      });
    }, "posture-chain/non-ascii-hop");
  expectRefused("refuses non-monotonic timestamps",
    function () {
      b.guardPostureChain.validate({
        postureSet: ["hipaa"],
        chainTrail: ["a", "b"],
        enteredAt:  [1000, 500],
      });
    }, "posture-chain/non-monotonic-timestamps");
  expectRefused("refuses enteredAt length mismatch",
    function () {
      b.guardPostureChain.validate({
        postureSet: ["hipaa"],
        chainTrail: ["a", "b"],
        enteredAt:  [1000],
      });
    }, "posture-chain/entered-at-length-mismatch");
  expectRefused("refuses oversized hop trail",
    function () {
      var hops = [];
      for (var i = 0; i < 32; i += 1) hops.push("hop-" + i);
      b.guardPostureChain.validate({
        postureSet: ["hipaa"], chainTrail: hops,
      });
    }, "posture-chain/hop-limit-exceeded");
}

async function run() {
  testSurface();
  testValid();
  testRefuses();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
