"use strict";
/**
 * b.cra.report — EU Cyber Resilience Act incident-reporting wrapper.
 *
 * The Cyber Resilience Act (Regulation (EU) 2024/2847) Article 14 §1
 * mandates that manufacturers of digital products report actively-
 * exploited vulnerabilities and severe incidents to ENISA + national
 * authorities. The framework's b.incident.report primitive provides
 * the generic 3-stage shape; this wrapper specializes it with the
 * CRA-specific reporting fields, deadlines (24h early warning / 72h
 * incident notification / 14d final report), and the ENISA single-
 * reporting-point destination.
 *
 *   var cra = b.cra.report.create({
 *     enisaEndpoint: "https://enisa-spr.europa.eu/api/incidents",
 *     httpClient:    b.httpClient,
 *     audit:         b.audit,
 *     productId:     "blamejs-1.x",
 *     manufacturer:  { name: "Acme Co", contact: "security@acme.example" },
 *   });
 *   var inc = await cra.open({
 *     detectedAt:    Date.now(),
 *     vulnerability: { cveId: "CVE-2026-99999", actively_exploited: true },
 *     impact:        { ... },
 *   });
 *   await cra.earlyWarning(inc.id, { ... });        // 24h
 *   await cra.notification(inc.id, { ... });        // 72h
 *   await cra.finalReport(inc.id, { ... });         // 14d
 *
 * The wrapper composes b.incident.report so the audit chain shape,
 * persistence hook, and status surface stay consistent across every
 * regulatory regime. Per-regime CRA semantics:
 *   - early warning may be terse ("incident detected, scope unknown")
 *   - notification carries impact + mitigation + scope
 *   - final report adds root cause + lessons learned
 *
 * Submission to ENISA is opt-in per call (operators may want to
 * batch / approve before submission); pass { submit: true } on each
 * stage call to push through the operator's b.httpClient. The
 * primitive does NOT auto-submit on stage transitions — regulators
 * uniformly require operator review before filing.
 */

var C = require("./constants");
var defineClass = require("./framework-error").defineClass;
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");

var incidentReport = lazyRequire(function () { return require("./incident-report"); });
var audit = lazyRequire(function () { return require("./audit"); });

var CraReportError = defineClass("CraReportError", { alwaysPermanent: true });

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "audit", "persist", "httpClient", "enisaEndpoint",
    "productId", "manufacturer", "now",
  ], "cra.report");

  validateOpts.requireNonEmptyString(opts.productId,
    "cra.report.create: opts.productId is required (CRA Annex VII §1 requires a stable product identifier)",
    CraReportError, "cra-report/bad-product-id");
  if (!opts.manufacturer || typeof opts.manufacturer !== "object") {
    throw new CraReportError("cra-report/bad-manufacturer",
      "cra.report.create: opts.manufacturer is required (CRA Annex VII §1 requires manufacturer name + contact)");
  }
  var productId = opts.productId;
  var manufacturer = opts.manufacturer;
  var enisaEndpoint = typeof opts.enisaEndpoint === "string" && opts.enisaEndpoint.length > 0
    ? opts.enisaEndpoint : null;
  var httpClient = opts.httpClient || null;
  var auditOn = opts.audit !== false;

  // CRA Article 14 deadlines — operators don't override these without
  // documented regulatory justification (the deadlines are statutory,
  // not operator preference).
  var ir = incidentReport().create({
    audit:    opts.audit,
    persist:  opts.persist,
    now:      opts.now,
    deadlines: {
      // initial = "early warning" per CRA Article 14 §1(a) — 24h
      initial:      C.TIME.hours(24),
      // intermediate = "incident notification" per CRA Article 14 §1(b) — 72h
      intermediate: C.TIME.hours(72),
      // final = "final report" per CRA Article 14 §1(c) — 14 days
      final:        C.TIME.days(14),
    },
  });

  function _emitAudit(action, outcome, metadata) {
    if (!auditOn) return;
    try {
      audit().safeEmit({
        action:   "cra.report." + action,
        outcome:  outcome,
        metadata: metadata || {},
      });
    } catch (_e) { /* drop-silent */ }
  }

  async function _submitToEnisa(payload) {
    if (!enisaEndpoint || !httpClient) {
      _emitAudit("submit_skipped", "warning", { reason: "no-endpoint-or-client" });
      return { submitted: false, reason: "no-endpoint-or-client" };
    }
    try {
      var res = await httpClient.request({
        url:           enisaEndpoint,
        method:        "POST",
        headers:       { "Content-Type": "application/json" },
        body:          Buffer.from(JSON.stringify(payload), "utf8"),
        responseMode:  "always-resolve",
      });
      var ok = res.statusCode >= 200 && res.statusCode < 300;                        // allow:raw-byte-literal — HTTP status range
      _emitAudit("submitted", ok ? "success" : "failure", {
        statusCode: res.statusCode, productId: productId,
      });
      return { submitted: ok, statusCode: res.statusCode };
    } catch (e) {
      _emitAudit("submit_failed", "failure", { error: (e && e.message) || String(e) });
      return { submitted: false, error: (e && e.message) || String(e) };
    }
  }

  function _craEnvelope(stage, incident, fields) {
    return {
      cra_version:   "2024/2847",
      stage:         stage,                                                            // "early-warning" / "notification" / "final"
      product:       { id: productId },
      manufacturer:  manufacturer,
      incident: {
        id:           incident.id,
        detected_at:  new Date(incident.detectedAt).toISOString(),
        scope:        incident.scope,
        summary:      incident.summary,
        impact:       incident.impact,
      },
      fields:        fields || {},
    };
  }

  async function open(spec) {
    spec = Object.assign({}, spec || {}, { regime: "cra" });
    var rec = await ir.open(spec);
    _emitAudit("opened", "success", { incidentId: rec.id, productId: productId });
    return rec;
  }

  async function earlyWarning(incidentId, fields) {
    var rec = await ir.recordInitial(incidentId, fields || {});
    var result = { record: rec, submitted: null };
    if (fields && fields.submit === true) {
      result.submitted = await _submitToEnisa(_craEnvelope("early-warning", rec, fields));
    }
    return result;
  }

  async function notification(incidentId, fields) {
    var rec = await ir.recordIntermediate(incidentId, fields || {});
    var result = { record: rec, submitted: null };
    if (fields && fields.submit === true) {
      result.submitted = await _submitToEnisa(_craEnvelope("notification", rec, fields));
    }
    return result;
  }

  async function finalReport(incidentId, fields) {
    var rec = await ir.recordFinal(incidentId, fields || {});
    var result = { record: rec, submitted: null };
    if (fields && fields.submit === true) {
      result.submitted = await _submitToEnisa(_craEnvelope("final", rec, fields));
    }
    return result;
  }

  return {
    open:           open,
    earlyWarning:   earlyWarning,
    notification:   notification,
    finalReport:    finalReport,
    // Forward incident.report observability surface
    get:            function (id) { return ir.get(id); },
    list:           function ()   { return ir.list(); },
    status:         function ()   { return ir.status(); },
    productId:      productId,
    manufacturer:   manufacturer,
  };
}

module.exports = {
  create:           create,
  CraReportError:   CraReportError,
};
