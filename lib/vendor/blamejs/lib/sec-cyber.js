// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var audit = require("./audit");
var C = require("./constants");
var validateOpts = require("./validate-opts");
var numericBounds = require("./numeric-bounds");
var { defineClass } = require("./framework-error");
var SecCyberError = defineClass("SecCyberError", { alwaysPermanent: true });

var FINDINGS = ["material", "not-material", "pending"];

function _addBusinessDays(startMs, days) {
  var t = new Date(startMs);
  var added = 0;
  while (added < days) {
    t = new Date(t.getTime() + C.TIME.days(1));
    var dow = t.getUTCDay();
    if (dow !== 0 && dow !== 6) added += 1;
  }
  return t.getTime();
}

function eightKArtifact(opts) {
  if (!opts || typeof opts !== "object") {
    throw SecCyberError.factory("sec-cyber/bad-opts",
      "secCyber.eightKArtifact: opts required");
  }
  validateOpts.shape(opts, {
    incidentId: "required-string",
    registrant: function (registrant) {
      if (!registrant || typeof registrant !== "object") {
        throw SecCyberError.factory("sec-cyber/bad-registrant",
          "secCyber.eightKArtifact: registrant object required");
      }
      validateOpts.requireNonEmptyString(registrant.name,
        "secCyber.eightKArtifact: registrant.name", SecCyberError, "sec-cyber/bad-registrant-name");
      validateOpts.requireNonEmptyString(registrant.cik,
        "secCyber.eightKArtifact: registrant.cik", SecCyberError, "sec-cyber/bad-cik");
    },
    detectedAt: function (detectedAt) {
      numericBounds.requirePositiveFiniteIntIfPresent(detectedAt,
        "secCyber.eightKArtifact: detectedAt", SecCyberError, "sec-cyber/bad-detected-at");
    },
    materialityDeterminedAt: function (materialityDeterminedAt) {
      numericBounds.requirePositiveFiniteIntIfPresent(materialityDeterminedAt,
        "secCyber.eightKArtifact: materialityDeterminedAt", SecCyberError, "sec-cyber/bad-mat-at");
    },
    materialityFinding: function (v) {
      if (FINDINGS.indexOf(v) === -1) {
        throw SecCyberError.factory("sec-cyber/bad-finding",
          "secCyber.eightKArtifact: materialityFinding must be one of " + FINDINGS.join(", "));
      }
    },
    materialityReasoning: function (v) {
      validateOpts.requireNonEmptyString(v,
        "secCyber.eightKArtifact: materialityReasoning", SecCyberError, "sec-cyber/bad-reasoning");
    },
    nature: function (v, label, e, c, o) {
      if (o.materialityFinding === "material") {
        validateOpts.requireNonEmptyString(v,
          "secCyber.eightKArtifact: nature", SecCyberError, "sec-cyber/bad-nature");
      } else {
        validateOpts.optionalNonEmptyString(v, label, e, c);
      }
    },
    scope: function (v, label, e, c, o) {
      if (o.materialityFinding === "material") {
        validateOpts.requireNonEmptyString(v,
          "secCyber.eightKArtifact: scope", SecCyberError, "sec-cyber/bad-scope");
      } else {
        validateOpts.optionalNonEmptyString(v, label, e, c);
      }
    },
    timing: function (v, label, e, c, o) {
      if (o.materialityFinding === "material") {
        validateOpts.requireNonEmptyString(v,
          "secCyber.eightKArtifact: timing", SecCyberError, "sec-cyber/bad-timing");
      } else {
        validateOpts.optionalNonEmptyString(v, label, e, c);
      }
    },
    impact: function (v, label, e, c, o) {
      if (o.materialityFinding === "material") {
        validateOpts.requireNonEmptyString(v,
          "secCyber.eightKArtifact: impact", SecCyberError, "sec-cyber/bad-impact");
      } else {
        validateOpts.optionalNonEmptyString(v, label, e, c);
      }
    },
    agDelayRequested:     "optional-boolean",
    agDelayJustification: function (v, label, e, c, o) {
      if (o.agDelayRequested === true) {
        validateOpts.requireNonEmptyString(v,
          "secCyber.eightKArtifact: agDelayJustification (required when agDelayRequested=true)",
          SecCyberError, "sec-cyber/bad-ag-justification");
      } else {
        validateOpts.optionalNonEmptyString(v, label, e, c);
      }
    },
    audit:                "optional-boolean",
  }, "secCyber.eightKArtifact", SecCyberError, "sec-cyber/bad-incident-id");

  var agDelayRequested = opts.agDelayRequested === true;

  var matAt = opts.materialityDeterminedAt || Date.now();
  var deadline = agDelayRequested ? null : _addBusinessDays(matAt, 4);

  var markdown = "# Form 8-K — Item 1.05 Material Cybersecurity Incident\n\n" +
    "**Registrant:** " + opts.registrant.name + " (CIK: " + opts.registrant.cik + ")\n\n" +
    "**Incident ID:** " + opts.incidentId + "\n\n" +
    "**Materiality determination date:** " + new Date(matAt).toISOString() + "\n\n" +
    "**Materiality finding:** " + opts.materialityFinding + "\n\n" +
    "**Reasoning:**\n\n" + opts.materialityReasoning + "\n\n";

  if (opts.materialityFinding === "material") {
    markdown +=
      "## Item 1.05(a) — Material aspects\n\n" +
      "**Nature.** " + opts.nature + "\n\n" +
      "**Scope.** " + opts.scope + "\n\n" +
      "**Timing.** " + opts.timing + "\n\n" +
      "## Item 1.05(b) — Material impact\n\n" + opts.impact + "\n\n";
  }

  if (agDelayRequested) {
    markdown += "## AG-delay request (17 CFR §229.106(c)(1)(ii))\n\n" +
      "Registrant asserts that disclosure of this incident would pose a substantial " +
      "risk to national security or public safety. Pursuant to the rule, registrant " +
      "requests that the Attorney General authorize a delay of disclosure.\n\n" +
      "**Justification:** " + opts.agDelayJustification + "\n\n";
  }

  markdown += "**Filing deadline:** " +
    (deadline ? new Date(deadline).toISOString() + " (4 business days from materiality determination)" :
                "suspended pending DOJ response to AG-delay request") + "\n";

  var artifactJson = {
    form:         "8-K",
    item:         "1.05",
    incidentId:   opts.incidentId,
    registrant:   { name: opts.registrant.name, cik: opts.registrant.cik },
    detectedAt:   opts.detectedAt || null,
    materialityDeterminedAt: matAt,
    materialityFinding: opts.materialityFinding,
    materialityReasoning: opts.materialityReasoning,
    items: opts.materialityFinding === "material" ? {
      "1.05(a)": {
        nature: opts.nature, scope: opts.scope, timing: opts.timing,
      },
      "1.05(b)": { impact: opts.impact },
    } : null,
    agDelayRequested:     agDelayRequested,
    agDelayJustification: agDelayRequested ? opts.agDelayJustification : null,
    deadlineMs:           deadline,
  };

  if (opts.audit !== false) {
    audit.safeEmit({
      action:   "seccyber.eight_k_artifact",
      outcome:  "success",
      metadata: {
        incidentId:           opts.incidentId,
        registrant:           opts.registrant.name,
        cik:                  opts.registrant.cik,
        materialityFinding:   opts.materialityFinding,
        deadlineMs:           deadline,
        agDelayRequested:     agDelayRequested,
      },
    });
  }

  return {
    artifact: { markdown: markdown, json: artifactJson },
    deadline: deadline,
    deadlineBusinessDays: agDelayRequested ? null : 4,
  };
}

module.exports = {
  eightKArtifact: eightKArtifact,
  FINDINGS:       FINDINGS.slice(),
  SecCyberError:  SecCyberError,
};
