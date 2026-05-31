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
      var ok = res.statusCode >= 200 && res.statusCode < 300;                        // HTTP status range
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

/**
 * @primitive b.cra.report.conformityAssessment
 * @signature b.cra.report.conformityAssessment(opts)
 * @since     0.8.77
 *
 * EU Cyber Resilience Act (Regulation 2024/2847) — Annex VIII
 * conformity-assessment dossier scaffold. Returns the structured
 * JSON document operators submit to the notified body (Module B/C/D/H
 * route per Annex VII) or self-attest under Annex VI (default for
 * non-critical products). The framework auto-fills sections it can
 * derive from the runtime — SBOM (`sbom.cdx.json` + `sbom.vendored.cdx.json`),
 * vulnerability-handling process (CVD per RFC 9116 + SECURITY.md),
 * security-by-design defaults (cite SECURITY.md threat-model
 * section), end-of-life schedule (operator-supplied) — and leaves
 * Annex I Part II essential-cybersecurity-requirements mapping for
 * the operator to fill (it's product-specific).
 *
 * Enforcement: products placed on the EU market on/after 2027-12-11
 * require a CE marking that depends on this dossier. Notified-body
 * review takes 60-90 days for self-certifying products. Run this
 * primitive at release time + commit the output under `compliance/cra/`.
 *
 * @opts
 *   {
 *     manufacturer:    { name, address, contact },
 *     product:         { name, identifier, version, description },
 *     classification:  "default" | "important-class-I" | "important-class-II" | "critical",
 *     sbomPaths:       string[],     // paths to attached SBOMs
 *     supportEnd:      string,       // ISO date — manufacturer support cessation
 *     vulnDisclosurePolicy?: string,  // URL to /.well-known/security.txt or VDP
 *     essentialReqMapping?: object,   // operator-supplied Annex I Part II mapping
 *   }
 *
 * @example
 *   var dossier = b.cra.report.conformityAssessment({
 *     manufacturer: { name: "Acme Inc.", address: "1 St", contact: "ce@acme.example" },
 *     product:      { name: "Widget Pro", identifier: "WID-001", version: "1.0", description: "..." },
 *     classification: "default",
 *     supportEnd:    "2032-12-31",
 *   });
 */
function conformityAssessment(opts) {
  if (!opts || typeof opts !== "object") {
    throw new CraReportError("cra-report/bad-conformity-opts",
      "conformityAssessment: opts required");
  }
  if (!opts.manufacturer || typeof opts.manufacturer.name !== "string") {
    throw new CraReportError("cra-report/no-manufacturer",
      "conformityAssessment: opts.manufacturer.name required");
  }
  if (!opts.product || typeof opts.product.name !== "string") {
    throw new CraReportError("cra-report/no-product",
      "conformityAssessment: opts.product.name required");
  }
  var classification = opts.classification || "default";
  var validClasses = ["default", "important-class-I", "important-class-II", "critical"];
  if (validClasses.indexOf(classification) === -1) {
    throw new CraReportError("cra-report/bad-classification",
      "conformityAssessment: classification must be one of " + validClasses.join(", "));
  }
  return {
    "$schema":      "https://blamejs.com/schema/cra-conformity-assessment-v1.json",
    regulation:     "EU 2024/2847 (Cyber Resilience Act)",
    annex:          "Annex VIII (technical documentation)",
    generatedAt:    new Date().toISOString(),
    manufacturer:   opts.manufacturer,
    product:        opts.product,
    classification: classification,
    assessmentRoute:
      classification === "default"             ? "Module A (Annex VI — internal control)" :
      classification === "important-class-I"   ? "Module B+C (Annex VII — EU-type examination)" :
      classification === "important-class-II"  ? "Module H (Annex VII — full quality assurance)" :
                                                  "Module H + notified-body for critical (Annex VII)",
    sections: {
      annexI_part1_essentialRequirements: {
        status: "operator-supplied",
        mapping: opts.essentialReqMapping || null,
        note:    "Annex I Part I essential cybersecurity requirements — operator supplies the mapping",
      },
      annexI_part2_vulnerabilityHandling: {
        status: "framework-derived",
        sbomAttached: Array.isArray(opts.sbomPaths) ? opts.sbomPaths : ["sbom.cdx.json", "sbom.vendored.cdx.json"],
        vulnDisclosurePolicy: opts.vulnDisclosurePolicy || "https://blamejs.com/.well-known/security.txt",
        cvdProcess:           "Coordinated Vulnerability Disclosure per ISO/IEC 29147 + 30111",
        incidentReporter:     "b.cra (24h early warning + 14d intermediate + 1m final per Art 14)",
      },
      annexII_userInformation: {
        status: "operator-supplied",
        note:   "Operator emits per-product handover docs",
      },
      supportPeriod: {
        end:  opts.supportEnd || null,
        note: "Manufacturer support-cessation date triggers end-of-life obligations per Art 13(8)",
      },
    },
    declarations: {
      ceMarking:           classification === "critical" ? "requires notified body" : "self-attest eligible",
      eolNotification:     "Manufacturer commits to 60-day pre-EOL notification per Art 13(8)",
      vulnReporting:       "Active exploitation reported within 24h to ENISA per Art 14(2)",
    },
  };
}

module.exports = {
  create:                 create,
  conformityAssessment:   conformityAssessment,
  CraReportError:         CraReportError,
};
