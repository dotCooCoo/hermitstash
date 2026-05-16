"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function expectThrows(label, fn, codeMatch) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, threw && (threw.code || "").indexOf(codeMatch) !== -1);
}

function testSurface() {
  check("create is fn",        typeof b.agent.postureChain.create === "function");
  check("BUILTIN_REGIMES",      Array.isArray(b.agent.postureChain.BUILTIN_REGIMES));
  check("AgentPostureChainError",
    typeof b.agent.postureChain.AgentPostureChainError === "function");
  var chain = b.agent.postureChain.create({});
  check("instance.isSubset is fn",   typeof chain.isSubset === "function");
  check("instance.union is fn",       typeof chain.union === "function");
  check("instance.canDelegate is fn", typeof chain.canDelegate === "function");
  check("instance.appendHop is fn",   typeof chain.appendHop === "function");
  check("instance.validate is fn",    typeof chain.validate === "function");
  check("instance.REGIMES has 4 builtins",
    chain.REGIMES.length === 4 && chain.REGIMES.indexOf("hipaa") !== -1);
}

async function testIsSubset() {
  var chain = b.agent.postureChain.create({});
  // empty source ⊆ any target
  check("isSubset: empty source",        chain.isSubset(["hipaa"], []) === true);
  // identical sets
  check("isSubset: identical",            chain.isSubset(["hipaa"], ["hipaa"]) === true);
  // target ⊇ source
  check("isSubset: target covers source", chain.isSubset(["hipaa", "pci-dss"], ["hipaa"]) === true);
  // target missing source regime
  check("isSubset: target missing",       chain.isSubset(["pci-dss"], ["hipaa"]) === false);
  // partial overlap insufficient
  check("isSubset: partial overlap",      chain.isSubset(["hipaa", "soc2"], ["hipaa", "pci-dss"]) === false);
}

async function testUnion() {
  var chain = b.agent.postureChain.create({});
  var u = chain.union(["hipaa"], ["pci-dss"], ["hipaa", "gdpr"]);
  check("union: 3 regimes", u.length === 3);
  check("union: hipaa once", u.indexOf("hipaa") >= 0);
  check("union: pci-dss",    u.indexOf("pci-dss") >= 0);
  check("union: gdpr",       u.indexOf("gdpr") >= 0);
}

async function testCanDelegate() {
  var chain = b.agent.postureChain.create({});
  // Source → wider target: allowed (upgrade)
  check("canDelegate: source → wider target",
    chain.canDelegate(["pci-dss"], ["hipaa", "pci-dss"], "mail.fetch") === true);
  // Source → identical target: allowed
  check("canDelegate: source → identical",
    chain.canDelegate(["hipaa"], ["hipaa"], "mail.fetch") === true);
  // Source → narrower target: refused
  check("canDelegate: source → narrower (downgrade)",
    chain.canDelegate(["hipaa", "pci-dss"], ["pci-dss"], "mail.fetch") === false);
  // Source → completely different target: refused
  check("canDelegate: source → unrelated",
    chain.canDelegate(["hipaa"], ["soc2"], "mail.fetch") === false);
}

async function testAppendHop() {
  var chain = b.agent.postureChain.create({});
  var env0 = { postureSet: ["hipaa"], chainTrail: ["api-gateway"], enteredAt: [1700000000000], hopCount: 1 };
  var env1 = chain.appendHop(env0, "mail-agent");
  check("appendHop: trail extended", env1.chainTrail.length === 2);
  check("appendHop: hopCount updated", env1.hopCount === 2);
  check("appendHop: timestamps extended", env1.enteredAt.length === 2);
  check("appendHop: original env unchanged", env0.chainTrail.length === 1);
}

async function testValidateDowngradeRefused() {
  var chain = b.agent.postureChain.create({});
  var env = {
    postureSet: ["hipaa", "pci-dss"],
    chainTrail: ["api-gateway"],
    enteredAt:  [1700000000000],
    hopCount:   1,
  };
  // Target set ⊇ source: validate succeeds
  chain.validate(env, ["hipaa", "pci-dss", "gdpr"]);
  // Target missing a source regime: refused
  expectThrows("validate refuses downgrade",
    function () { chain.validate(env, ["pci-dss"]); },
    "agent-posture-chain/downgrade-refused");
}

async function testDeclareCustomRegime() {
  var chain = b.agent.postureChain.create({});
  chain.declareRegime("healthcare-tier-1");
  check("declared regime is usable", true);
  // Refuses duplicates
  expectThrows("refuses duplicate regime declare",
    function () { chain.declareRegime("hipaa"); },
    "agent-posture-chain/duplicate-regime");
}

async function testGuardRefusalAtBoundary() {
  var chain = b.agent.postureChain.create({});
  expectThrows("validate refuses bad envelope",
    function () { chain.validate({ postureSet: "hipaa", chainTrail: [] }, ["hipaa"]); },
    "posture-chain/bad-posture-set");
}

async function run() {
  testSurface();
  await testIsSubset();
  await testUnion();
  await testCanDelegate();
  await testAppendHop();
  await testValidateDowngradeRefused();
  await testDeclareCustomRegime();
  await testGuardRefusalAtBoundary();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
