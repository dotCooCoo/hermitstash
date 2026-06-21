"use strict";
/**
 * @module b.ai.frontierModelProtocol
 * @nav    Compliance
 * @title  Frontier AI Protocol
 *
 * @intro
 *   Assess a developer's obligations under California's Transparency in
 *   Frontier Artificial Intelligence Act — SB 53, Cal. Bus. &amp; Prof. Code
 *   §22757.10 et seq., signed 2025-09-29 and effective 2026-01-01 — and build
 *   the critical-safety-incident report the law requires. SB 53 attaches
 *   obligations by two thresholds: a <em>frontier model</em> is one trained
 *   with more than 10<sup>26</sup> floating-point operations (including
 *   cumulative fine-tuning), and a <em>large frontier developer</em> is a
 *   frontier developer whose annual revenue, with affiliates, exceeded
 *   $500,000,000 in the prior calendar year. Frontier developers must report
 *   critical safety incidents; large frontier developers must additionally
 *   publish an annual frontier-AI safety framework.
 *
 *   <code>frontierModelProtocol(opts)</code> takes the model's training compute
 *   and the developer's revenue and returns which thresholds are crossed and
 *   the resulting obligations, optionally checking that a supplied safety
 *   framework carries the elements the Act expects (risk identification,
 *   mitigation, governance, cybersecurity, and alignment with a recognized
 *   standard such as the NIST AI RMF or ISO/IEC 42001).
 *   <code>frontierModelProtocol.incidentReport(opts)</code> validates a
 *   critical-incident type against the Act's four definitions and computes the
 *   notification deadline: a routine report goes to the California Office of
 *   Emergency Services within 15 days of discovery; an imminent risk of death
 *   or serious physical injury is reported to an applicable authority within 24
 *   hours.
 *
 * @card
 *   California SB 53 frontier-AI protocol (`b.ai.frontierModelProtocol`) —
 *   classify frontier-model / large-developer thresholds (10²⁶ FLOPs, $500M
 *   revenue), enumerate obligations, and build the critical-safety-incident
 *   report with the 15-day / 24-hour OES notification deadline.
 */

var C = require("./constants");
var { defineClass } = require("./framework-error");

var FrontierProtocolError = defineClass("FrontierProtocolError", { alwaysPermanent: true });

// SB 53 thresholds.
var FRONTIER_FLOP_THRESHOLD = 1e26;          // > 10^26 training FLOPs → frontier model
var LARGE_DEVELOPER_REVENUE_USD = 5e8;       // > $500,000,000 prior-year revenue → large developer
var INCIDENT_DEADLINE_MS = C.TIME.days(15);  // report to CA OES within 15 days of discovery
var IMMINENT_DEADLINE_MS = C.TIME.hours(24); // within 24 hours if imminent risk to life

// The four critical safety incident categories (Cal. Bus. & Prof. Code §22757.10).
var CRITICAL_INCIDENT_TYPES = {
  "weights-exfiltration-harm":         "Unauthorized access, modification, or exfiltration of frontier-model weights resulting in death or bodily injury",
  "catastrophic-risk-materialization": "Harm resulting from the materialization of a catastrophic risk (including loss of life or property from a dangerous capability)",
  "loss-of-control-harm":              "Loss of control of a frontier model causing death or bodily injury",
  "deceptive-control-subversion":      "A frontier model using deceptive techniques to subvert developer controls, demonstrating materially increased catastrophic risk",
};

// Elements a large frontier developer's published safety framework must address.
var REQUIRED_FRAMEWORK_ELEMENTS = ["riskIdentification", "riskMitigation", "governance", "cybersecurity", "standardsAlignment"];

function _posNum(v, label) {
  if (typeof v !== "number" || !isFinite(v) || v < 0) throw new FrontierProtocolError("frontier/bad-value", "frontierModelProtocol: " + label + " must be a non-negative finite number");
  return v;
}

/**
 * @primitive  b.ai.frontierModelProtocol
 * @signature  b.ai.frontierModelProtocol(opts)
 * @since      0.13.6
 * @status     stable
 * @compliance ca-tfaia, soc2
 * @related    b.ai.aedtBiasAudit, b.ai.disclosure.applyAll
 *
 * Determine SB 53 obligations from a model's training compute and the
 * developer's revenue. Returns <code>isFrontierModel</code> (training FLOPs
 * above 10<sup>26</sup>), <code>isLargeFrontierDeveloper</code> (a frontier
 * developer with revenue above $500M), and the resulting
 * <code>obligations</code>. When <code>framework</code> is supplied, its
 * required elements are checked and reported in <code>frameworkGaps</code>.
 * Throws <code>FrontierProtocolError</code> on malformed input.
 *
 * @opts
 *   trainingFlops:    number,   // total training FLOPs incl. fine-tuning (required)
 *   annualRevenueUsd: number,   // developer prior-year revenue with affiliates (default: 0)
 *   framework:        object,   // optional safety framework to check for required elements
 *
 * @example
 *   var p = b.ai.frontierModelProtocol({ trainingFlops: 5e26, annualRevenueUsd: 1e9 });
 *   p.isFrontierModel;           // → true
 *   p.isLargeFrontierDeveloper;  // → true
 *   p.obligations;               // → ["report-critical-safety-incidents", "publish-annual-safety-framework", ...]
 */
function frontierModelProtocol(opts) {
  opts = opts || {};
  if (typeof opts !== "object") throw new FrontierProtocolError("frontier/bad-opts", "frontierModelProtocol: opts must be an object");
  var allowed = { trainingFlops: 1, annualRevenueUsd: 1, framework: 1 };
  Object.keys(opts).forEach(function (k) { if (!allowed[k]) throw new FrontierProtocolError("frontier/bad-opts", "frontierModelProtocol: unknown option '" + k + "'"); });

  var flops = _posNum(opts.trainingFlops, "trainingFlops");
  var revenue = opts.annualRevenueUsd != null ? _posNum(opts.annualRevenueUsd, "annualRevenueUsd") : 0;

  var isFrontierModel = flops > FRONTIER_FLOP_THRESHOLD;
  var isLargeFrontierDeveloper = isFrontierModel && revenue > LARGE_DEVELOPER_REVENUE_USD;

  var obligations = [];
  if (isFrontierModel) {
    obligations.push("report-critical-safety-incidents");
    obligations.push("publish-transparency-report");
  }
  if (isLargeFrontierDeveloper) {
    obligations.push("publish-annual-safety-framework");
    obligations.push("disclose-catastrophic-risk-assessment");
  }

  var out = {
    isFrontierModel: isFrontierModel,
    isLargeFrontierDeveloper: isLargeFrontierDeveloper,
    thresholds: { frontierFlops: FRONTIER_FLOP_THRESHOLD, largeDeveloperRevenueUsd: LARGE_DEVELOPER_REVENUE_USD },
    obligations: obligations,
  };

  if (opts.framework != null) {
    if (typeof opts.framework !== "object") throw new FrontierProtocolError("frontier/bad-value", "frontierModelProtocol: framework must be an object");
    var gaps = REQUIRED_FRAMEWORK_ELEMENTS.filter(function (el) { return !opts.framework[el]; });
    out.frameworkGaps = gaps;
    out.frameworkComplete = gaps.length === 0;
  }
  return out;
}

/**
 * @primitive  b.ai.frontierModelProtocol.incidentReport
 * @signature  b.ai.frontierModelProtocol.incidentReport(opts)
 * @since      0.13.6
 * @status     stable
 * @compliance ca-tfaia, soc2
 * @related    b.ai.frontierModelProtocol, b.ai.aedtBiasAudit
 *
 * Build a critical-safety-incident report and compute its notification
 * deadline to the California Office of Emergency Services. <code>type</code>
 * must be one of the Act's four categories; <code>discoveredAt</code> is when
 * the incident was discovered. The deadline is 15 days from discovery, or 24
 * hours when <code>imminentRiskToLife</code> is set. Returns the structured
 * report with <code>dueAt</code> and <code>deadlineHours</code>. Throws
 * <code>FrontierProtocolError</code> on an unknown type or bad timestamp.
 *
 * @opts
 *   type:               string,   // one of b.ai.frontierModelProtocol.INCIDENT_TYPES (required)
 *   discoveredAt:       Date,     // discovery time (Date or epoch-ms; default: now)
 *   imminentRiskToLife: boolean,  // true → 24-hour deadline (default: false → 15 days)
 *   description:        string,   // free-text incident description (optional)
 *
 * @example
 *   var r = b.ai.frontierModelProtocol.incidentReport({
 *     type: "loss-of-control-harm", discoveredAt: new Date("2026-06-01T00:00:00Z"),
 *   });
 *   r.deadlineHours;   // → 360  (15 days)
 *   r.recipient;       // → "California Office of Emergency Services"
 */
function incidentReport(opts) {
  opts = opts || {};
  if (typeof opts !== "object") throw new FrontierProtocolError("frontier/bad-opts", "incidentReport: opts must be an object");
  if (!Object.prototype.hasOwnProperty.call(CRITICAL_INCIDENT_TYPES, opts.type)) throw new FrontierProtocolError("frontier/bad-incident-type", "incidentReport: type must be one of " + Object.keys(CRITICAL_INCIDENT_TYPES).join(", "));

  var discoveredMs;
  if (opts.discoveredAt == null) discoveredMs = Date.now();
  else if (opts.discoveredAt instanceof Date) discoveredMs = opts.discoveredAt.getTime();
  else discoveredMs = Number(opts.discoveredAt);
  if (!isFinite(discoveredMs) || discoveredMs < 0) throw new FrontierProtocolError("frontier/bad-value", "incidentReport: discoveredAt must be a Date or non-negative epoch-ms");

  var imminent = opts.imminentRiskToLife === true;
  var windowMs = imminent ? IMMINENT_DEADLINE_MS : INCIDENT_DEADLINE_MS;

  return {
    type:               opts.type,
    typeDescription:    CRITICAL_INCIDENT_TYPES[opts.type],
    description:        typeof opts.description === "string" ? opts.description : null,
    imminentRiskToLife: imminent,
    discoveredAt:       new Date(discoveredMs).toISOString(),
    dueAt:              new Date(discoveredMs + windowMs).toISOString(),
    deadlineHours:      windowMs / C.TIME.hours(1),
    // §22757.13: the routine report goes to OES within 15 days; an imminent
    // risk of death or serious physical injury is reported to an applicable
    // authority within 24 hours, which the operator selects for the incident.
    recipient:          imminent ? "An applicable authority with jurisdiction (e.g. law enforcement or a public-safety agency)" : "California Office of Emergency Services",
    citation:           "Cal. Bus. & Prof. Code §22757.13 (SB 53)",
  };
}

frontierModelProtocol.incidentReport = incidentReport;
frontierModelProtocol.INCIDENT_TYPES = Object.keys(CRITICAL_INCIDENT_TYPES);
frontierModelProtocol.REQUIRED_FRAMEWORK_ELEMENTS = REQUIRED_FRAMEWORK_ELEMENTS;
frontierModelProtocol.FrontierProtocolError = FrontierProtocolError;

module.exports = frontierModelProtocol;
