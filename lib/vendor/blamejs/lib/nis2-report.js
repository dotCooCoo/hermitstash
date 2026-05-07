"use strict";
/**
 * b.nis2.report — NIS2 Directive incident-reporting wrapper.
 *
 * Directive (EU) 2022/2555 (NIS2) Article 23 mandates that essential
 * + important entities report significant incidents to the national
 * CSIRT or competent authority. Three-stage pattern with statutory
 * deadlines:
 *   - early warning within 24h of becoming aware (Art. 23 §4(a))
 *   - incident notification within 72h, including initial assessment
 *     of severity + impact + indicators of compromise (Art. 23 §4(b))
 *   - final report within 1 month, with detailed root cause +
 *     remediation + cross-border implications (Art. 23 §4(d))
 *
 *   var nis2 = b.nis2.report.create({
 *     audit:        b.audit,
 *     entityId:     "acme-cloud-1",
 *     entityType:   "essential",                  // "essential" | "important"
 *     sectorAnnex:  "I.6",                        // NIS2 Annex I/II row id
 *     csirtEndpoint: "https://csirt.example/api",
 *     httpClient:   b.httpClient,
 *   });
 *
 * Sector annex codes follow NIS2's two annexes:
 *   - Annex I (essential): I.1 energy / I.2 transport / I.3 banking /
 *     I.4 financial-market-infrastructures / I.5 health /
 *     I.6 drinking-water / I.7 wastewater / I.8 digital-infrastructure /
 *     I.9 ICT-service-management / I.10 public-administration /
 *     I.11 space
 *   - Annex II (important): II.1 postal / II.2 waste-management /
 *     II.3 chemicals / II.4 food / II.5 manufacturing /
 *     II.6 digital-providers / II.7 research
 */

var C = require("./constants");
var defineClass = require("./framework-error").defineClass;
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");

var incidentReport = lazyRequire(function () { return require("./incident-report"); });
var audit = lazyRequire(function () { return require("./audit"); });

var Nis2ReportError = defineClass("Nis2ReportError", { alwaysPermanent: true });

var VALID_ENTITY_TYPES = Object.freeze({ essential: 1, important: 1 });

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "audit", "persist", "httpClient", "csirtEndpoint",
    "entityId", "entityType", "sectorAnnex", "now",
  ], "nis2.report");

  validateOpts.requireNonEmptyString(opts.entityId,
    "nis2.report.create: opts.entityId is required (NIS2 registration ID)",
    Nis2ReportError, "nis2-report/bad-entity-id");
  if (!VALID_ENTITY_TYPES[opts.entityType]) {
    throw new Nis2ReportError("nis2-report/bad-entity-type",
      "nis2.report.create: opts.entityType must be 'essential' or 'important' (NIS2 Article 3 classification)");
  }
  validateOpts.requireNonEmptyString(opts.sectorAnnex,
    "nis2.report.create: opts.sectorAnnex is required (e.g. 'I.6' for drinking water, 'II.6' for digital-providers)",
    Nis2ReportError, "nis2-report/bad-sector");
  var entityId = opts.entityId;
  var entityType = opts.entityType;
  var sectorAnnex = opts.sectorAnnex;
  var csirtEndpoint = opts.csirtEndpoint || null;
  var httpClient = opts.httpClient || null;
  var auditOn = opts.audit !== false;

  var ir = incidentReport().create({
    audit:    opts.audit,
    persist:  opts.persist,
    now:      opts.now,
    deadlines: {
      initial:      C.TIME.hours(24),                                                     // NIS2 Art. 23 §4(a) — early warning
      intermediate: C.TIME.hours(72),                                                     // NIS2 Art. 23 §4(b) — incident notification
      final:        C.TIME.days(30),                                                      // NIS2 Art. 23 §4(d) — final report (1 month)
    },
  });

  function _emitAudit(action, outcome, metadata) {
    if (!auditOn) return;
    try {
      audit().safeEmit({
        action:   "nis2.report." + action,
        outcome:  outcome,
        metadata: metadata || {},
      });
    } catch (_e) { /* drop-silent */ }
  }

  async function _submitToCsirt(payload) {
    if (!csirtEndpoint || !httpClient) {
      _emitAudit("submit_skipped", "warning", { reason: "no-endpoint-or-client" });
      return { submitted: false, reason: "no-endpoint-or-client" };
    }
    try {
      var res = await httpClient.request({
        url: csirtEndpoint, method: "POST",
        headers: { "Content-Type": "application/json" },
        body: Buffer.from(JSON.stringify(payload), "utf8"),
        responseMode: "always-resolve",
      });
      var ok = res.statusCode >= 200 && res.statusCode < 300;                            // allow:raw-byte-literal — HTTP status range
      _emitAudit("submitted", ok ? "success" : "failure", { statusCode: res.statusCode });
      return { submitted: ok, statusCode: res.statusCode };
    } catch (e) {
      _emitAudit("submit_failed", "failure", { error: (e && e.message) || String(e) });
      return { submitted: false, error: (e && e.message) || String(e) };
    }
  }

  function _envelope(stage, incident, fields) {
    return {
      directive:    "(EU) 2022/2555",
      article:      "23",
      stage:        stage,                                                                // "early-warning" / "notification" / "final"
      entity:       { id: entityId, type: entityType, sector: sectorAnnex },
      incident: {
        id:          incident.id,
        detected_at: new Date(incident.detectedAt).toISOString(),
        scope:       incident.scope,
        summary:     incident.summary,
        impact:      incident.impact,
      },
      fields: fields || {},
    };
  }

  async function open(spec) {
    spec = Object.assign({}, spec || {}, { regime: "nis2" });
    var rec = await ir.open(spec);
    _emitAudit("opened", "success", { incidentId: rec.id, entityId: entityId, entityType: entityType });
    return rec;
  }

  async function earlyWarning(incidentId, fields) {
    var rec = await ir.recordInitial(incidentId, fields || {});
    var result = { record: rec, submitted: null };
    if (fields && fields.submit === true) {
      result.submitted = await _submitToCsirt(_envelope("early-warning", rec, fields));
    }
    return result;
  }
  async function notification(incidentId, fields) {
    var rec = await ir.recordIntermediate(incidentId, fields || {});
    var result = { record: rec, submitted: null };
    if (fields && fields.submit === true) {
      result.submitted = await _submitToCsirt(_envelope("notification", rec, fields));
    }
    return result;
  }
  async function finalReport(incidentId, fields) {
    var rec = await ir.recordFinal(incidentId, fields || {});
    var result = { record: rec, submitted: null };
    if (fields && fields.submit === true) {
      result.submitted = await _submitToCsirt(_envelope("final", rec, fields));
    }
    return result;
  }

  return {
    open:           open,
    earlyWarning:   earlyWarning,
    notification:   notification,
    finalReport:    finalReport,
    get:            function (id) { return ir.get(id); },
    list:           function ()   { return ir.list(); },
    status:         function ()   { return ir.status(); },
    entityId:       entityId,
    entityType:     entityType,
    sectorAnnex:    sectorAnnex,
  };
}

module.exports = {
  create:             create,
  Nis2ReportError:    Nis2ReportError,
  VALID_ENTITY_TYPES: Object.keys(VALID_ENTITY_TYPES),
};
