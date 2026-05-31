"use strict";
/**
 * b.drRunbook — disaster-recovery runbook generator.
 */

var fs = require("fs");
var os = require("os");
var path = require("path");
var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  check("drRunbook.emit is fn",      typeof b.drRunbook.emit === "function");
  check("DrRunbookError is fn",      typeof b.drRunbook.DrRunbookError === "function");
  check("POSTURE_BLOCKS hipaa key",  !!b.drRunbook.POSTURE_BLOCKS.hipaa);
  check("POSTURE_BLOCKS dora key",   !!b.drRunbook.POSTURE_BLOCKS.dora);

  var outDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-dr-runbook-"));
  try {
    var result = await b.drRunbook.emit({
      outDir:  outDir,
      posture: "hipaa",
      rtoMs:   b.constants.TIME.hours(4),
      rpoMs:   b.constants.TIME.minutes(15),
      contacts: { incidentCommander: "alice@example.test" },
      services: [
        { name: "api-edge",  rtoMs: b.constants.TIME.minutes(15), rpoMs: b.constants.TIME.minutes(5) },
        { name: "billing",   rtoMs: b.constants.TIME.hours(1),    rpoMs: b.constants.TIME.minutes(15) },
      ],
      audit: false,
    });
    check("emit returns posture",     result.posture === "hipaa");
    check("emit returns paths array", Array.isArray(result.paths) && result.paths.length === 1);
    check("emit returns sectionCount", result.sectionCount > 0);

    var body = fs.readFileSync(result.paths[0], "utf8");
    check("runbook header includes posture",  body.indexOf("HIPAA") !== -1);
    check("runbook cites HIPAA Security Rule", body.indexOf("§164.308(a)(7)") !== -1);
    check("runbook lists Incident Commander", body.indexOf("incidentCommander") !== -1);
    check("runbook lists api-edge service",   body.indexOf("api-edge") !== -1);
    check("runbook references restore steps", body.indexOf("verifyManifestSignature") !== -1);
  } finally {
    try { fs.rmSync(outDir, { recursive: true, force: true }); }
    catch (_e) { /* best-effort */ }
  }

  // Unknown posture refused
  var threwBadPosture = null;
  try {
    await b.drRunbook.emit({
      outDir: outDir, posture: "made-up-posture", audit: false,
    });
  } catch (e) { threwBadPosture = e; }
  check("emit refuses unknown posture",
    threwBadPosture && threwBadPosture.code === "dr-runbook/unknown-posture");
}

module.exports = { run: run };
