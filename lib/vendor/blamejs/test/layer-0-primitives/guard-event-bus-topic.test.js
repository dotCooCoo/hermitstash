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
  check("validate fn",          typeof b.guardEventBusTopic.validate === "function");
  check("compliancePosture fn", typeof b.guardEventBusTopic.compliancePosture === "function");
  check("NAME = eventBusTopic", b.guardEventBusTopic.NAME === "eventBusTopic");
  check("KIND = event-bus-topic", b.guardEventBusTopic.KIND === "event-bus-topic");
  check("PROFILES frozen",      Object.isFrozen(b.guardEventBusTopic.PROFILES));
  check("RESERVED_PREFIXES frozen", Object.isFrozen(b.guardEventBusTopic.RESERVED_PREFIXES));
  check("GuardEventBusTopicError",
    typeof b.guardEventBusTopic.GuardEventBusTopicError === "function");
  var e = new b.guardEventBusTopic.GuardEventBusTopicError("event-bus-topic/test", "t");
  check("error carries code",   e.code === "event-bus-topic/test");
  check("compliancePosture hipaa",   b.guardEventBusTopic.compliancePosture("hipaa") === "strict");
  check("compliancePosture unknown", b.guardEventBusTopic.compliancePosture("nope") === null);
}

function testValid() {
  b.guardEventBusTopic.validate("mail.scan.malware-detected");
  b.guardEventBusTopic.validate("ai.classify.prompt-injection-detected");
  b.guardEventBusTopic.validate("mail.crypto.key-rotated");
}

function testRefuses() {
  expectRefused("refuses empty",
    function () { b.guardEventBusTopic.validate(""); },
    "event-bus-topic/bad-input");
  expectRefused("refuses non-string",
    function () { b.guardEventBusTopic.validate(42); },
    "event-bus-topic/bad-input");
  expectRefused("refuses insufficient dots",
    function () { b.guardEventBusTopic.validate("malware"); },
    "event-bus-topic/insufficient-dots");
  expectRefused("refuses framework. prefix",
    function () { b.guardEventBusTopic.validate("framework.audit.fired"); },
    "event-bus-topic/reserved-prefix");
  expectRefused("refuses path-traversal",
    function () { b.guardEventBusTopic.validate("a..b.c"); },
    "event-bus-topic/path-traversal");
  expectRefused("refuses slash",
    function () { b.guardEventBusTopic.validate("a.b/c.d"); },
    "event-bus-topic/bad-char");
  expectRefused("refuses control char",
    function () { b.guardEventBusTopic.validate("a.b.c\r"); },
    "event-bus-topic/bad-char");
  expectRefused("refuses non-ascii",
    function () { b.guardEventBusTopic.validate("mail.scan.café"); },
    "event-bus-topic/non-ascii");
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
