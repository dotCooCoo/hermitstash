// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

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
  if (!Object.prototype.hasOwnProperty.call(VALID_ENTITY_TYPES, opts.entityType)) {
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

  var ir = incidentReport().create({
    audit:    opts.audit,
    persist:  opts.persist,
    now:      opts.now,
    deadlines: {
      initial:      C.TIME.hours(24),
      intermediate: C.TIME.hours(72),
      final:        C.TIME.days(30),
    },
  });

  var _emitAudit = audit().namespaced("nis2.report", opts.audit);

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
      var ok = res.statusCode >= 200 && res.statusCode < 300;
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
      stage:        stage,
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
