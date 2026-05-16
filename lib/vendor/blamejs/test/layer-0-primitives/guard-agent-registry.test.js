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
  check("validate fn",          typeof b.guardAgentRegistry.validate === "function");
  check("compliancePosture fn", typeof b.guardAgentRegistry.compliancePosture === "function");
  check("NAME = agentRegistry", b.guardAgentRegistry.NAME === "agentRegistry");
  check("KIND = agent-registry", b.guardAgentRegistry.KIND === "agent-registry");
  check("PROFILES frozen",      Object.isFrozen(b.guardAgentRegistry.PROFILES));
  check("RESERVED_PREFIXES frozen", Object.isFrozen(b.guardAgentRegistry.RESERVED_PREFIXES));
  check("GuardAgentRegistryError is fn", typeof b.guardAgentRegistry.GuardAgentRegistryError === "function");
  var e = new b.guardAgentRegistry.GuardAgentRegistryError("agent-registry/test", "t");
  check("error carries code", e.code === "agent-registry/test");
  check("compliancePosture hipaa", b.guardAgentRegistry.compliancePosture("hipaa") === "strict");
  check("compliancePosture unknown", b.guardAgentRegistry.compliancePosture("nope") === null);
}

function testValid() {
  b.guardAgentRegistry.validate({ kind: "register", name: "tenant-acme.mail", agentKind: "mail" });
  b.guardAgentRegistry.validate({ kind: "lookup", name: "tenant-acme.mail" });
  b.guardAgentRegistry.validate({ kind: "unregister", name: "tenant-acme.mail" });
  b.guardAgentRegistry.validate({ kind: "list" });
}

function testRefuses() {
  expectRefused("refuses bad input",
    function () { b.guardAgentRegistry.validate(null); },
    "agent-registry/bad-input");
  expectRefused("refuses bad kind",
    function () { b.guardAgentRegistry.validate({ kind: "weird", name: "x" }); },
    "agent-registry/bad-kind");
  expectRefused("refuses empty name",
    function () { b.guardAgentRegistry.validate({ kind: "register", name: "", agentKind: "mail" }); },
    "agent-registry/bad-name");
  expectRefused("refuses path-traversal",
    function () { b.guardAgentRegistry.validate({ kind: "register", name: "a/b", agentKind: "mail" }); },
    "agent-registry/bad-name-char");
  expectRefused("refuses control char",
    function () { b.guardAgentRegistry.validate({ kind: "register", name: "a\rb", agentKind: "mail" }); },
    "agent-registry/bad-name-char");
  expectRefused("refuses non-ascii",
    function () { b.guardAgentRegistry.validate({ kind: "register", name: "ünikøde", agentKind: "mail" }); },
    "agent-registry/non-ascii");
  expectRefused("refuses ROOT reserved",
    function () { b.guardAgentRegistry.validate({ kind: "register", name: "ROOT", agentKind: "mail" }); },
    "agent-registry/reserved-name");
  expectRefused("refuses FRAMEWORK. prefix",
    function () { b.guardAgentRegistry.validate({ kind: "register", name: "FRAMEWORK.audit", agentKind: "mail" }); },
    "agent-registry/reserved-prefix");
  expectRefused("refuses ..",
    function () { b.guardAgentRegistry.validate({ kind: "register", name: "x..y", agentKind: "mail" }); },
    "agent-registry/path-traversal");
  expectRefused("refuses register without kind",
    function () { b.guardAgentRegistry.validate({ kind: "register", name: "x" }); },
    "agent-registry/no-kind");
  expectRefused("refuses bad kind shape",
    function () { b.guardAgentRegistry.validate({ kind: "register", name: "x", agentKind: "MAIL" }); },
    "agent-registry/bad-kind-shape");
  expectRefused("refuses oversized name",
    function () {
      var big = "x";
      for (var i = 0; i < 8; i += 1) big += big;
      b.guardAgentRegistry.validate({ kind: "register", name: big, agentKind: "mail" });
    },
    "agent-registry/name-too-long");
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
