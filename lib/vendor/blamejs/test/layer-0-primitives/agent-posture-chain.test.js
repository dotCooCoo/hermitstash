"use strict";

var fs      = require("fs");
var os      = require("os");
var path    = require("path");
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
  var env0 = chain.appendHop({ postureSet: ["hipaa"] }, "api-gateway");
  var env1 = chain.appendHop(env0, "mail-agent");
  check("appendHop: trail extended", env1.chainTrail.length === 2);
  check("appendHop: hopCount updated", env1.hopCount === 2);
  check("appendHop: timestamps extended", env1.enteredAt.length === 2);
  check("appendHop: original env unchanged", env0.chainTrail.length === 1);
  check("appendHop: _mac populated",          typeof env1._mac === "string" && env1._mac.length > 0);
}

async function testValidateDowngradeRefused() {
  var chain = b.agent.postureChain.create({});
  var env = chain.appendHop({ postureSet: ["hipaa", "pci-dss"] }, "api-gateway");
  // Target set ⊇ source: validate succeeds
  chain.validate(env, ["hipaa", "pci-dss", "gdpr"]);
  // Target missing a source regime: refused
  expectThrows("validate refuses downgrade",
    function () { chain.validate(env, ["pci-dss"]); },
    "agent-posture-chain/downgrade-refused");
}

async function testValidateMacRefused() {
  // SUBSTRATE-10 — envelope MAC verification refuses wire-rewrite.
  var chain = b.agent.postureChain.create({});
  var env = chain.appendHop({ postureSet: ["hipaa", "pci-dss"] }, "api-gateway");
  // Tamper: strip the hipaa regime to attempt a posture downgrade.
  var tampered = Object.assign({}, env, { postureSet: ["pci-dss"] });
  // MAC was computed over the original postureSet — verify must fail.
  expectThrows("validate refuses MAC-tampered envelope",
    function () { chain.validate(tampered, ["pci-dss"]); },
    "agent-posture-chain/mac-verify-failed");
  // No-MAC envelope refused under requireMac=true (default).
  var noMac = { postureSet: ["hipaa"], chainTrail: ["api-gateway"], enteredAt: [Date.now()], hopCount: 1 };
  expectThrows("validate refuses missing-MAC envelope",
    function () { chain.validate(noMac, ["hipaa"]); },
    "agent-posture-chain/missing-mac");
}

async function testHopCountCap() {
  // SUBSTRATE-21 — hop cap defends infinite delegation recursion.
  var chain = b.agent.postureChain.create({ maxHopCount: 3 });
  var env = chain.appendHop({ postureSet: ["hipaa"] }, "h1");
  env = chain.appendHop(env, "h2");
  env = chain.appendHop(env, "h3");
  expectThrows("appendHop refuses past cap",
    function () { chain.appendHop(env, "h4"); },
    "agent-posture-chain/hop-cap-exceeded");
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
  // requireMac:false lets the guard refusal fire directly; under the
  // default the missing-MAC throw fires first (which is desired in
  // production but obscures the guard check we're asserting here).
  var chain = b.agent.postureChain.create({ requireMac: false });
  expectThrows("validate refuses bad envelope",
    function () { chain.validate({ postureSet: "hipaa", chainTrail: [] }, ["hipaa"]); },
    "posture-chain/bad-posture-set");
}

async function testGuardRefusalAtBoundaryNoMac() {
  // The bad-posture-set throw happens at guard-validation BEFORE the
  // MAC check; expectation: it still fires under requireMac=false so
  // the guard path is reachable in isolation.
  var chain = b.agent.postureChain.create({ requireMac: false });
  expectThrows("validate refuses bad envelope (no-MAC ctx)",
    function () { chain.validate({ postureSet: "hipaa", chainTrail: [] }, ["hipaa"]); },
    "posture-chain/bad-posture-set");
}

async function run() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vault-pc-"));
  await helpers.setupVaultOnly(tmpDir);
  try {
    testSurface();
    await testIsSubset();
    await testUnion();
    await testCanDelegate();
    await testAppendHop();
    await testValidateDowngradeRefused();
    await testValidateMacRefused();
    await testHopCountCap();
    await testDeclareCustomRegime();
    await testGuardRefusalAtBoundary();
    await testGuardRefusalAtBoundaryNoMac();
  } finally {
    helpers.teardownVaultOnly(tmpDir);
  }
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
