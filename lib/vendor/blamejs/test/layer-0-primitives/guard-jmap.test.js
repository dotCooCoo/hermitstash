"use strict";

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

function testSurface() {
  check("namespace",     typeof b.guardJmap === "object");
  check("validate fn",   typeof b.guardJmap.validate === "function");
  check("compliancePosture fn", typeof b.guardJmap.compliancePosture === "function");
  check("PROFILES",      typeof b.guardJmap.PROFILES === "object");
  check("error class",   typeof b.guardJmap.GuardJmapError === "function");
}

function testHappyPath() {
  var rv = b.guardJmap.validate({
    using:       ["urn:ietf:params:jmap:core"],
    methodCalls: [["Core/echo", { hi: 1 }, "c0"]],
  });
  check("returns using",         Array.isArray(rv.using));
  check("returns methodCalls",   Array.isArray(rv.methodCalls));
  check("createdIds normalized", rv.createdIds === null);
}

function testBadShapeRefused() {
  function expectThrow(label, fn, codeMatch) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(codeMatch) !== -1);
  }
  expectThrow("refuses non-object body",
    function () { b.guardJmap.validate("not-json"); },
    "guard-jmap/bad-json");
  expectThrow("refuses array body",
    function () { b.guardJmap.validate([]); },
    "urn:ietf:params:jmap:error:invalidArguments");
  expectThrow("refuses missing using",
    function () { b.guardJmap.validate({ methodCalls: [["x", {}, "c"]] }); },
    "urn:ietf:params:jmap:error:invalidArguments");
  expectThrow("refuses missing methodCalls",
    function () { b.guardJmap.validate({ using: [] }); },
    "urn:ietf:params:jmap:error:invalidArguments");
  expectThrow("refuses empty methodCalls",
    function () { b.guardJmap.validate({ using: [], methodCalls: [] }); },
    "urn:ietf:params:jmap:error:invalidArguments");
  expectThrow("refuses non-3-tuple call",
    function () { b.guardJmap.validate({ using: [], methodCalls: [["x", {}]] }); },
    "urn:ietf:params:jmap:error:invalidArguments");
  expectThrow("refuses non-string clientId",
    function () { b.guardJmap.validate({ using: [], methodCalls: [["x", {}, 5]] }); },
    "urn:ietf:params:jmap:error:invalidArguments");
}

function testUnknownCapabilityRefused() {
  var threw = null;
  try {
    b.guardJmap.validate({
      using:       ["urn:ietf:params:jmap:contacts"],
      methodCalls: [["Contact/get", {}, "c0"]],
    });
  } catch (e) { threw = e; }
  check("unknownCapability when not advertised",
    threw && threw.code === "urn:ietf:params:jmap:error:unknownCapability");

  var rv = b.guardJmap.validate({
    using:       ["urn:ietf:params:jmap:contacts"],
    methodCalls: [["Contact/get", {}, "c0"]],
  }, { serverCapabilities: { "urn:ietf:params:jmap:contacts": true } });
  check("unknownCapability cleared when advertised",
    rv.using.indexOf("urn:ietf:params:jmap:contacts") !== -1);
}

function testCapsTripped() {
  var threw = null;
  // Build a methodCalls with 33 entries (strict cap is 32)
  var calls = [];
  for (var i = 0; i < 33; i += 1) { calls.push(["x", {}, "c" + i]); }
  try { b.guardJmap.validate({ using: [], methodCalls: calls }); }
  catch (e) { threw = e; }
  check("maxCallsInRequest tripped",
    threw && threw.code === "urn:ietf:params:jmap:error:limit/maxCallsInRequest");

  // Oversize JSON body
  var big = "{\"using\":[],\"methodCalls\":[[\"x\",{}, \"c0\"]],\"pad\":\"" +
    "x".repeat(11000000) + "\"}";
  var threw2 = null;
  try { b.guardJmap.validate(big); } catch (e) { threw2 = e; }
  check("requestTooLarge tripped",
    threw2 && threw2.code === "urn:ietf:params:jmap:error:requestTooLarge");
}

function testBackRefDepth() {
  // Build a deeply-nested back-reference shape with 9 `resultOf` keys
  // — strict cap is 8, so this trips.
  var node = { x: 1 };
  for (var i = 0; i < 9; i += 1) {
    node = { resultOf: node };
  }
  var threw = null;
  try {
    b.guardJmap.validate({
      using:       [],
      methodCalls: [["x", node, "c0"]],
    });
  } catch (e) { threw = e; }
  check("maxBackRefDepth tripped",
    threw && threw.code === "urn:ietf:params:jmap:error:limit/maxBackRefDepth");
}

function testServerCapsNotMutated() {
  // Regression: pre-fix validate() injected `urn:ietf:params:jmap:core`
  // into the operator's `serverCapabilities` object in place; the
  // listener's shared object accumulated the boolean across requests
  // and broke the Session resource's RFC 8620 §2 capability shape.
  var caps = {
    "urn:ietf:params:jmap:mail":      { maxSizeMailboxName: 64 },
    "urn:ietf:params:jmap:submission": {},
  };
  var snapshot = JSON.stringify(caps);
  var body = '{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Mailbox/get",{"accountId":"A"},"c0"]]}';
  b.guardJmap.validate(body, { serverCapabilities: caps });
  check("guard-jmap does not mutate operator serverCapabilities",
    JSON.stringify(caps) === snapshot);
}

function testRequestSizeCapInBytesNotCodeUnits() {
  // Regression: pre-fix the size check counted UTF-16 code units;
  // post-fix counts UTF-8 bytes. Verify by passing a Buffer whose
  // byte length exceeds strict's 10 MiB cap — pre-fix this would
  // throw `<rawBody.length> bytes` (Buffer length is byte length
  // already, so both pre-fix and post-fix throw); the meaningful
  // test is the string path where UTF-16 vs UTF-8 differ.
  //
  // Construct a string that exceeds the strict 10 MiB byte cap
  // using all-emoji content; the JS string is 5 MiB UTF-16 code
  // units, the wire body is ~10 MiB UTF-8 bytes — pre-fix the
  // .length check let it pass.
  var emoji    = "😀";                                                                                // 4 UTF-8 bytes, 2 UTF-16 code units
  var fill     = emoji.repeat(2_700_000);                                                              // ~10.8 MiB UTF-8 bytes, 5.4 MiB code units
  var body = '{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["Core/echo",{"_pad":"' + fill + '"},"c0"]]}';
  var threw = null;
  try {
    b.guardJmap.validate(body);                                                                      // strict default — 10 MiB cap
  } catch (e) { threw = e; }
  check("guard-jmap size cap measured in UTF-8 bytes (not code units)",
    threw && /bytes exceeds cap/.test(threw.message));
}

function testCompliancePosture() {
  check("posture: hipaa → strict",   b.guardJmap.compliancePosture("hipaa") === "strict");
  check("posture: pci-dss → strict", b.guardJmap.compliancePosture("pci-dss") === "strict");
  check("posture: gdpr → strict",    b.guardJmap.compliancePosture("gdpr") === "strict");
  check("posture: soc2 → strict",    b.guardJmap.compliancePosture("soc2") === "strict");
  check("posture: unknown → null",   b.guardJmap.compliancePosture("nope") === null);
}

function run() {
  testSurface();
  testHappyPath();
  testBadShapeRefused();
  testUnknownCapabilityRefused();
  testCapsTripped();
  testBackRefDepth();
  testServerCapsNotMutated();
  testRequestSizeCapInBytesNotCodeUnits();
  testCompliancePosture();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[guard-jmap] OK"); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}
