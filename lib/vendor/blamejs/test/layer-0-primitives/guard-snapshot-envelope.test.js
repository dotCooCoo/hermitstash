"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function expectRefused(label, fn, codeMatch) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, threw && (threw.code || "").indexOf(codeMatch) !== -1);
}

function _validEnv() {
  return {
    snapshotId: "snap-abc-1234",
    takenAt:    Date.now(),
    frameworkVersion: "0.9.30",
    schemaVersion:    1,
    tenantId:         null,
    orchestratorState: { agents: [], elections: [], consumers: [] },
    inFlight:          { streams: [], sagas: [], outboxJobs: [], busSubscribers: [], pendingDeliveries: [] },
  };
}

function testSurface() {
  check("validate fn",        typeof b.guardSnapshotEnvelope.validate === "function");
  check("compliancePosture",  typeof b.guardSnapshotEnvelope.compliancePosture === "function");
  check("NAME = snapshotEnvelope", b.guardSnapshotEnvelope.NAME === "snapshotEnvelope");
  check("KIND = snapshot-envelope", b.guardSnapshotEnvelope.KIND === "snapshot-envelope");
  check("PROFILES frozen",    Object.isFrozen(b.guardSnapshotEnvelope.PROFILES));
  check("GuardSnapshotEnvelopeError",
    typeof b.guardSnapshotEnvelope.GuardSnapshotEnvelopeError === "function");
  var e = new b.guardSnapshotEnvelope.GuardSnapshotEnvelopeError("snapshot-envelope/test", "t");
  check("error carries code", e.code === "snapshot-envelope/test");
  check("compliancePosture hipaa", b.guardSnapshotEnvelope.compliancePosture("hipaa") === "strict");
  check("compliancePosture unknown", b.guardSnapshotEnvelope.compliancePosture("nope") === null);
}

function testValid() {
  b.guardSnapshotEnvelope.validate(_validEnv());
}

function testRefuses() {
  expectRefused("refuses non-object",
    function () { b.guardSnapshotEnvelope.validate(null); },
    "snapshot-envelope/bad-input");
  var bad1 = _validEnv(); delete bad1.snapshotId;
  expectRefused("refuses missing snapshotId",
    function () { b.guardSnapshotEnvelope.validate(bad1); },
    "snapshot-envelope/missing-snapshot-id");
  var bad2 = _validEnv(); bad2.takenAt = -1;
  expectRefused("refuses negative takenAt",
    function () { b.guardSnapshotEnvelope.validate(bad2); },
    "snapshot-envelope/bad-taken-at");
  var bad3 = _validEnv(); bad3.schemaVersion = 0;
  expectRefused("refuses zero schemaVersion",
    function () { b.guardSnapshotEnvelope.validate(bad3); },
    "snapshot-envelope/bad-schema-version");
  var bad4 = _validEnv(); delete bad4.orchestratorState;
  expectRefused("refuses missing orchestratorState",
    function () { b.guardSnapshotEnvelope.validate(bad4); },
    "snapshot-envelope/missing-orchestrator-state");
  var bad5 = _validEnv(); delete bad5.inFlight;
  expectRefused("refuses missing inFlight",
    function () { b.guardSnapshotEnvelope.validate(bad5); },
    "snapshot-envelope/missing-in-flight");
}

function testInFlightCap() {
  var env = _validEnv();
  // Push more items than the strict profile allows.
  for (var i = 0; i < 100000; i += 1) env.inFlight.streams.push({ streamId: "s-" + i });
  expectRefused("refuses in-flight cap exceeded",
    function () { b.guardSnapshotEnvelope.validate(env); },
    "snapshot-envelope/in-flight-cap");
}

async function run() {
  testSurface();
  testValid();
  testRefuses();
  testInFlightCap();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
