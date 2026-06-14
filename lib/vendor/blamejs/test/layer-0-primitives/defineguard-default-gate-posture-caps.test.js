"use strict";
// defineGuard's default gate must resolve the profile + posture BEFORE building
// the gate, so a guard gated with { compliancePosture } honors that posture's
// forensicSnippetBytes (and the profile's maxRuntimeMs). The default gate passed
// RAW opts straight to buildGuardGate, so the posture's forensic cap was dropped
// to 0 (forensic snapshots disabled) — a regulated-posture refusal carried no
// evidence, defeating the forensic-capture the posture promises.

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  // guard-cidr is built via gateContract.defineGuard with the STANDARD default
  // gate (no bespoke spec.gate), so .gate() exercises the default-gate path.
  // Its hipaa posture sets forensicSnippetBytes = 128.
  var bad = "999.999.999.999/99";
  var g = b.guardCidr.gate({ compliancePosture: "hipaa" });
  var decision = await g.check({ identifier: bad, bytes: Buffer.from(bad, "utf8") });
  check("hipaa gate refuses a malformed CIDR", decision.action === "refuse");
  check("hipaa posture forensicSnippetBytes is applied → refusal carries a forensic snapshot",
        decision.forensicSnapshot != null);
  check("the forensic snapshot is bounded by the posture cap (<= 128 bytes)",
        decision.forensicSnapshot != null && decision.forensicSnapshot.length <= 128);

  process.stdout.write("OK — defineGuard default-gate posture-cap tests\n");
}

run().then(function () { process.exit(0); })
     .catch(function (e) { process.stderr.write((e && e.stack ? e.stack : String(e)) + "\n"); process.exit(1); });
