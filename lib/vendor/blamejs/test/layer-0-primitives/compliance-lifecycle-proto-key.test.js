// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Regression: compliance lifecycle catalogs indexed by an operator-supplied
 * string must resolve only OWN keys. A regime / posture whose value collides
 * with an Object.prototype member ("valueOf", "toString", "constructor",
 * "hasOwnProperty", ...) previously resolved to the inherited function
 * instead of falling back / throwing:
 *
 *   - b.incident.report.open({ regime: "valueOf" }) picked up
 *     Object.prototype.valueOf as the deadline table -> every dueBy became
 *     NaN -> a filing 100 days past the real 30-day final wall was recorded
 *     late: false and status().late.final stayed 0 (a missed regulatory
 *     deadline reported as met).
 *   - b.retention.complianceFloor("valueOf", ttl) returned a function
 *     instead of throwing retention/unknown-posture (the config-time typo
 *     guard silently failed open for these ~7 values).
 */
var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

var PROTO_KEYS = ["valueOf", "toString", "constructor", "hasOwnProperty",
                  "isPrototypeOf", "propertyIsEnumerable", "toLocaleString"];

async function run() {
  var HOUR = b.constants.TIME.hours(1);
  var H24 = b.constants.TIME.hours(24);
  var H72 = b.constants.TIME.hours(72);
  var D30 = b.constants.TIME.days(30);

  // ---- incident.report: proto-key regime must fall back to DEFAULT_DEADLINES ----
  for (var i = 0; i < PROTO_KEYS.length; i++) {
    var regime = PROTO_KEYS[i];
    var ir = b.incident.report.create({ audit: false });
    var rec = await ir.open({ regime: regime, detectedAt: 0 });
    check("incident regime '" + regime + "' initial is finite wall not NaN",
      rec.dueBy.initial === H24);
    check("incident regime '" + regime + "' intermediate is finite wall not NaN",
      rec.dueBy.intermediate === H72);
    check("incident regime '" + regime + "' final is finite wall not NaN",
      rec.dueBy.final === D30);
  }

  // A genuinely-late FINAL filing under a proto-key regime is flagged late.
  var lateIr = b.incident.report.create({
    audit: false,
    now:   function () { return b.constants.TIME.days(100); },   // 100d >> 30d final wall
  });
  var lateRec = await lateIr.open({ regime: "valueOf", detectedAt: 0 });
  var filed = await lateIr.recordFinal(lateRec.id, { note: "100d late" });
  check("incident: 100-days-late final is late:true (not reported as met)",
    filed.stages.final.late === true);
  check("incident: late final lateBy is the real overrun",
    filed.stages.final.lateBy === b.constants.TIME.days(100) - D30);
  check("incident: status counts the late final",
    lateIr.status().late.final === 1);

  // Control: a benign unknown regime still falls back (fallback contract intact).
  var ctlIr = b.incident.report.create({ audit: false });
  var ctlRec = await ctlIr.open({ regime: "ccpa-not-a-known-regime", detectedAt: 0 });
  check("incident: benign unknown regime falls back to 30d final",
    ctlRec.dueBy.final === D30);

  // Regression: real regimes keep their statutory walls (DORA 4h initial).
  var doraIr = b.incident.report.create({ audit: false });
  var doraRec = await doraIr.open({ regime: "dora", detectedAt: 0 });
  check("incident: dora regime keeps 4h initial wall",
    doraRec.dueBy.initial === 4 * HOUR);

  // ---- retention.complianceFloor: proto-key posture must throw, not return a fn ----
  for (var j = 0; j < PROTO_KEYS.length; j++) {
    var posture = PROTO_KEYS[j];
    var threw = false;
    var ret;
    try { ret = b.retention.complianceFloor(posture, 1000); }
    catch (e) { threw = e && e.code === "retention/unknown-posture"; }
    check("retention.complianceFloor('" + posture + "') throws unknown-posture (not a function)",
      threw === true && ret === undefined);
  }

  // Control + regression: real posture returns its floor; a plain typo throws.
  check("retention.complianceFloor('hipaa') returns 6-year floor",
    b.retention.complianceFloor("hipaa") === b.constants.TIME.days(365 * 6));
  var typoThrew = false;
  try { b.retention.complianceFloor("hipaa-typo", 1000); }
  catch (e2) { typoThrew = e2 && e2.code === "retention/unknown-posture"; }
  check("retention.complianceFloor plain typo still throws", typoThrew === true);

  // applyPosture with a proto-key posture must not inherit a function floor.
  var ap = b.retention.applyPosture("valueOf");
  check("retention.applyPosture('valueOf') floorMs is null (no inherited fn)",
    ap !== null ? ap.floorMs === null : true);
  b.retention.applyPosture("");   // reset active posture

  console.log("OK — compliance lifecycle proto-key tests");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
