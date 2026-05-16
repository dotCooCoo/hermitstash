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
  check("validate fn",          typeof b.guardEventBusPayload.validate === "function");
  check("compliancePosture fn", typeof b.guardEventBusPayload.compliancePosture === "function");
  check("NAME = eventBusPayload", b.guardEventBusPayload.NAME === "eventBusPayload");
  check("KIND = event-bus-payload", b.guardEventBusPayload.KIND === "event-bus-payload");
  check("GuardEventBusPayloadError",
    typeof b.guardEventBusPayload.GuardEventBusPayloadError === "function");
  var e = new b.guardEventBusPayload.GuardEventBusPayloadError("event-bus-payload/test", "t");
  check("error carries code",   e.code === "event-bus-payload/test");
  check("compliancePosture hipaa",   b.guardEventBusPayload.compliancePosture("hipaa") === "strict");
  check("compliancePosture unknown", b.guardEventBusPayload.compliancePosture("nope") === null);
}

function testValid() {
  b.guardEventBusPayload.validate(
    { source: "x", confidence: 0.5 },
    { source: "string", confidence: "number" }
  );
  b.guardEventBusPayload.validate(
    { count: 42, name: "x", flag: true },
    { count: "integer", name: "string", flag: "boolean" }
  );
  b.guardEventBusPayload.validate(
    { at: "2026-05-14T12:00:00Z", tags: ["a", "b"] },
    { at: "isoDateTime", tags: "array" }
  );
  // Optional field absent — allowed.
  b.guardEventBusPayload.validate(
    { source: "x" },
    { source: "string", "reason?": "string" }
  );
}

function testRefuses() {
  expectRefused("refuses non-object payload",
    function () { b.guardEventBusPayload.validate(null, {}); },
    "event-bus-payload/bad-input");
  expectRefused("refuses non-object schema",
    function () { b.guardEventBusPayload.validate({}, null); },
    "event-bus-payload/bad-schema");
  expectRefused("refuses missing required field",
    function () { b.guardEventBusPayload.validate({}, { x: "string" }); },
    "event-bus-payload/missing-field");
  expectRefused("refuses type mismatch (string ≠ number)",
    function () { b.guardEventBusPayload.validate({ x: 42 }, { x: "string" }); },
    "event-bus-payload/type-mismatch");
  expectRefused("refuses non-finite number",
    function () { b.guardEventBusPayload.validate({ x: Infinity }, { x: "number" }); },
    "event-bus-payload/type-mismatch");
  expectRefused("refuses non-integer for integer type",
    function () { b.guardEventBusPayload.validate({ x: 1.5 }, { x: "integer" }); },
    "event-bus-payload/type-mismatch");
  expectRefused("refuses malformed ISO dateTime",
    function () { b.guardEventBusPayload.validate({ at: "not a date" }, { at: "isoDateTime" }); },
    "event-bus-payload/type-mismatch");
  expectRefused("refuses unknown field",
    function () { b.guardEventBusPayload.validate({ x: "a", y: 1 }, { x: "string" }); },
    "event-bus-payload/unknown-field");
  expectRefused("refuses oversize",
    function () {
      var big = { data: "x".repeat(100000) };                                                         // allow:raw-byte-literal — test
      b.guardEventBusPayload.validate(big, { data: "string" });
    },
    "event-bus-payload/oversize");
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
