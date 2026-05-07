"use strict";
/**
 * b.secCyber — SEC Item 1.05 8-K artifact generator.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  check("secCyber.eightKArtifact is fn", typeof b.secCyber.eightKArtifact === "function");
  check("secCyber.SecCyberError is fn",  typeof b.secCyber.SecCyberError === "function");
  check("secCyber.FINDINGS",             Array.isArray(b.secCyber.FINDINGS) && b.secCyber.FINDINGS.length === 3);

  var rv = b.secCyber.eightKArtifact({
    incidentId:                "inc-001",
    registrant:                { name: "Acme Inc.", cik: "0000123456" },
    materialityDeterminedAt:   Date.parse("2026-01-05T00:00:00Z"), // Monday
    materialityFinding:        "material",
    materialityReasoning:      "Customer-PII exfil; financial-statement impact estimated at 4% of annual revenue.",
    nature:                    "Unauthorized access to customer data subset (encrypted at rest, decrypted via stolen key material).",
    scope:                     "~2.4M customer records exposed; product systems unaffected.",
    timing:                    "Detected 2026-01-03 22:00 UTC; contained 2026-01-04 06:00 UTC.",
    impact:                    "Estimated $40-60M remediation + notification cost; immaterial to FY revenue but material to Q1 EPS.",
    audit:                     false,
  });
  check("artifact returns markdown",  typeof rv.artifact.markdown === "string" && rv.artifact.markdown.indexOf("Item 1.05") !== -1);
  check("artifact returns json",      rv.artifact.json.form === "8-K" && rv.artifact.json.item === "1.05");
  check("4 business-day deadline",    typeof rv.deadline === "number" && rv.deadline > Date.parse("2026-01-05"));
  check("deadlineBusinessDays = 4",   rv.deadlineBusinessDays === 4);

  var rvNot = b.secCyber.eightKArtifact({
    incidentId:                "inc-002",
    registrant:                { name: "Acme Inc.", cik: "0000123456" },
    materialityDeterminedAt:   Date.now(),
    materialityFinding:        "not-material",
    materialityReasoning:      "Quantitative impact below 1% of annual revenue; qualitative factors do not raise materiality.",
    audit:                     false,
  });
  check("not-material skips item-1.05 sections", rvNot.artifact.markdown.indexOf("1.05(a)") === -1);

  var rvAg = b.secCyber.eightKArtifact({
    incidentId:                "inc-003",
    registrant:                { name: "Acme Inc.", cik: "0000123456" },
    materialityDeterminedAt:   Date.now(),
    materialityFinding:        "material",
    materialityReasoning:      "Significant impact; AG-delay requested.",
    nature:                    "Active intrusion in critical infrastructure adjacent system.",
    scope:                     "Limited; investigation ongoing.",
    timing:                    "Within last 24 hours.",
    impact:                    "Material if disclosed prematurely.",
    agDelayRequested:          true,
    agDelayJustification:      "Disclosure would compromise active law-enforcement coordination on critical-infrastructure attack.",
    audit:                     false,
  });
  check("AG-delay suspends deadline", rvAg.deadline === null && rvAg.deadlineBusinessDays === null);
  check("AG-delay narrative present", rvAg.artifact.markdown.indexOf("AG-delay request") !== -1);

  // Validation
  var threw = null;
  try { b.secCyber.eightKArtifact({}); } catch (e) { threw = e; }
  check("refuses missing incidentId", threw && threw.code === "BAD_INCIDENT_ID");

  threw = null;
  try { b.secCyber.eightKArtifact({
    incidentId: "x",
    registrant: { name: "Acme", cik: "1" },
    materialityFinding: "material",
    materialityReasoning: "yes",
  }); } catch (e) { threw = e; }
  check("refuses missing nature when material", threw && threw.code === "BAD_NATURE");

  threw = null;
  try { b.secCyber.eightKArtifact({
    incidentId: "x",
    registrant: { name: "Acme", cik: "1" },
    materialityFinding: "material",
    materialityReasoning: "yes",
    nature: "n", scope: "s", timing: "t", impact: "i",
    agDelayRequested: true,
  }); } catch (e) { threw = e; }
  check("AG-delay requires justification", threw && threw.code === "BAD_AG_JUSTIFICATION");
}

module.exports = { run: run };
