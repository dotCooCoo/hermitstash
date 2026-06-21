"use strict";
/**
 * b.gdpr.ropa — GDPR Article 30 Records of Processing Activities.
 *
 * Article 30 §1 (controller) + §2 (processor) require a written
 * record of processing activities. The framework's existing audit
 * chain captures *what happened* on each request; the RoPA captures
 * *what processing the operator does in general* — purposes, data
 * categories, retention periods, recipients, transfers outside the
 * EEA, security measures.
 *
 * The primitive is a registry + exporter:
 *   - register(activity)          — add a processing-activity record
 *   - update(id, patch)           — modify an existing record
 *   - remove(id)                  — soft-delete (operator audit trail)
 *   - export({ format })          — emit RoPA as JSON / CSV / Markdown
 *
 *   var ropa = b.gdpr.ropa.create({
 *     audit:        b.audit,
 *     controller:   { name: "Acme Co", contact: "dpo@acme.example" },
 *   });
 *   ropa.register({
 *     id:                  "sales-funnel-tracking",
 *     name:                "Sales-funnel CRM tracking",
 *     purposes:            ["lead-tracking", "sales-attribution"],
 *     legalBasis:          "legitimate-interests",
 *     dataCategories:      ["contact-info", "engagement-history"],
 *     dataSubjectCategories: ["prospects", "customers"],
 *     recipients:          ["analytics-vendor", "sales-team"],
 *     thirdCountryTransfers: [{ country: "US", safeguard: "scc-2021" }],
 *     retentionPeriod:     "5 years post-relationship",
 *     securityMeasures:    ["encrypted-at-rest", "tls-13", "access-control"],
 *   });
 *   var json = ropa.export({ format: "json" });
 */

var defineClass = require("./framework-error").defineClass;
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var boundedMap = require("./bounded-map");

var audit = lazyRequire(function () { return require("./audit"); });

var GdprRopaError = defineClass("GdprRopaError", { alwaysPermanent: true });

var REQUIRED_ACTIVITY_FIELDS = Object.freeze([
  "id", "name", "purposes", "legalBasis", "dataCategories",
]);

var VALID_LEGAL_BASES = Object.freeze({
  "consent":               1,                                                            // Art 6(1)(a)
  "contract":              1,                                                            // Art 6(1)(b)
  "legal-obligation":      1,                                                            // Art 6(1)(c)
  "vital-interests":       1,                                                            // Art 6(1)(d)
  "public-task":           1,                                                            // Art 6(1)(e)
  "legitimate-interests":  1,                                                            // Art 6(1)(f)
});

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "audit", "controller", "dpo", "supervisoryAuthority", "now",
  ], "gdpr.ropa");

  if (!opts.controller || typeof opts.controller !== "object") {
    throw new GdprRopaError("gdpr-ropa/bad-controller",
      "gdpr.ropa.create: opts.controller is required (Article 30 §1(a) requires controller name + contact)");
  }
  var controller = opts.controller;
  var dpo = opts.dpo || null;
  var supervisoryAuthority = opts.supervisoryAuthority || null;
  var now = typeof opts.now === "function" ? opts.now : function () { return Date.now(); };

  var activities = new Map();

  var _emitAudit = audit().namespaced("gdpr.ropa", opts.audit);

  function _validateActivity(activity, op) {
    if (!activity || typeof activity !== "object") {
      throw new GdprRopaError("gdpr-ropa/bad-activity",
        "gdpr.ropa." + op + ": activity must be an object");
    }
    for (var i = 0; i < REQUIRED_ACTIVITY_FIELDS.length; i++) {
      var f = REQUIRED_ACTIVITY_FIELDS[i];
      if (activity[f] === undefined) {
        throw new GdprRopaError("gdpr-ropa/missing-field",
          "gdpr.ropa." + op + ": activity is missing required field '" + f + "' (per Article 30 §1)");
      }
    }
    if (typeof activity.id !== "string" || activity.id.length === 0) {
      throw new GdprRopaError("gdpr-ropa/bad-id",
        "gdpr.ropa." + op + ": activity.id must be a non-empty string");
    }
    if (!Object.prototype.hasOwnProperty.call(VALID_LEGAL_BASES, activity.legalBasis)) {
      throw new GdprRopaError("gdpr-ropa/bad-legal-basis",
        "gdpr.ropa." + op + ": activity.legalBasis must be one of " + Object.keys(VALID_LEGAL_BASES).join(", "));
    }
  }

  function register(activity) {
    _validateActivity(activity, "register");
    boundedMap.requireAbsent(activities, activity.id, function () {
      throw new GdprRopaError("gdpr-ropa/duplicate-id",
        "gdpr.ropa.register: activity '" + activity.id + "' already registered");
    });
    var rec = Object.assign({}, activity, {
      registeredAt: now(),
      lastUpdatedAt: now(),
    });
    activities.set(activity.id, rec);
    _emitAudit("registered", "success", { id: activity.id, purposes: activity.purposes });
    return rec;
  }

  function update(id, patch) {
    var existing = activities.get(id);
    if (!existing) {
      throw new GdprRopaError("gdpr-ropa/not-found",
        "gdpr.ropa.update: no activity with id '" + id + "'");
    }
    if (!patch || typeof patch !== "object") {
      throw new GdprRopaError("gdpr-ropa/bad-patch",
        "gdpr.ropa.update: patch must be an object");
    }
    var merged = Object.assign({}, existing, patch, {
      id: id,                                                                            // id is immutable on update
      registeredAt: existing.registeredAt,
      lastUpdatedAt: now(),
    });
    if (patch.legalBasis && !Object.prototype.hasOwnProperty.call(VALID_LEGAL_BASES, merged.legalBasis)) {
      throw new GdprRopaError("gdpr-ropa/bad-legal-basis",
        "gdpr.ropa.update: legalBasis must be one of " + Object.keys(VALID_LEGAL_BASES).join(", "));
    }
    activities.set(id, merged);
    _emitAudit("updated", "success", { id: id, fields: Object.keys(patch) });
    return merged;
  }

  function remove(id, info) {
    var existing = activities.get(id);
    if (!existing) {
      throw new GdprRopaError("gdpr-ropa/not-found",
        "gdpr.ropa.remove: no activity with id '" + id + "'");
    }
    activities.delete(id);
    _emitAudit("removed", "success", {
      id: id,
      reason: (info && info.reason) || null,
      actor:  (info && info.actor) || null,
    });
    return { removed: true, id: id };
  }

  function get(id) { return activities.get(id) || null; }
  function list() {
    var out = [];
    activities.forEach(function (rec) { out.push(rec); });
    return out;
  }

  // Operator-facing exporter — JSON for API integrations / SCC, CSV
  // for spreadsheet handoff to legal, Markdown for human-readable
  // operator documentation. Each shape carries the same fields per
  // Article 30 §1(a-h) / §2(a-d).
  function _exportJson() {
    return {
      controller:           controller,
      dpo:                  dpo,
      supervisoryAuthority: supervisoryAuthority,
      generatedAt:          new Date(now()).toISOString(),
      article:              "30",
      regulation:           "(EU) 2016/679 (GDPR)",
      activities:           list(),
    };
  }
  // Quote a CSV cell AND neutralize spreadsheet formula injection (CWE-1236):
  // a value beginning with = + - @ TAB or CR is evaluated as a formula by
  // Excel / Google Sheets when the export is opened, so a RoPA field like
  // "=HYPERLINK(...)" or "=cmd|..." would execute. Prefix such a value with a
  // single quote so the spreadsheet renders it as literal text; then RFC-4180
  // quote (double internal quotes).
  function _csvCell(v) {
    var s = (v === undefined || v === null) ? ""
      : (Array.isArray(v) ? JSON.stringify(v) : String(v));
    var c0 = s.charCodeAt(0);
    if (c0 === 0x3d || c0 === 0x2b || c0 === 0x2d || c0 === 0x40 || c0 === 0x09 || c0 === 0x0d) {
      s = "'" + s;
    }
    return '"' + s.replace(/"/g, '""') + '"';
  }
  function _exportCsv() {
    var headers = [
      "id", "name", "purposes", "legalBasis", "dataCategories",
      "dataSubjectCategories", "recipients", "thirdCountryTransfers",
      "retentionPeriod", "securityMeasures",
    ];
    var rows = [headers.join(",")];
    var entries = list();
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      rows.push(headers.map(function (h) { return _csvCell(e[h]); }).join(","));
    }
    return rows.join("\n");
  }
  function _exportMarkdown() {
    var entries = list();
    var md = "# GDPR Article 30 Records of Processing Activities\n\n";
    md += "Generated: " + new Date(now()).toISOString() + "\n\n";
    md += "Controller: " + (controller.name || "(unspecified)") + "\n";
    md += "Contact: " + (controller.contact || "(unspecified)") + "\n\n";
    if (dpo) md += "DPO: " + (dpo.name || "(unspecified)") + " (" + (dpo.contact || "") + ")\n\n";
    md += "## Activities (" + entries.length + ")\n\n";
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      md += "### " + (e.name || e.id) + " (`" + e.id + "`)\n\n";
      md += "- Purposes: " + (e.purposes || []).join(", ") + "\n";
      md += "- Legal basis: " + e.legalBasis + "\n";
      md += "- Data categories: " + (e.dataCategories || []).join(", ") + "\n";
      if (e.dataSubjectCategories) md += "- Data subjects: " + e.dataSubjectCategories.join(", ") + "\n";
      if (e.recipients) md += "- Recipients: " + e.recipients.join(", ") + "\n";
      if (e.retentionPeriod) md += "- Retention: " + e.retentionPeriod + "\n";
      if (e.securityMeasures) md += "- Security: " + e.securityMeasures.join(", ") + "\n";
      if (e.thirdCountryTransfers && e.thirdCountryTransfers.length > 0) {
        md += "- Third-country transfers:\n";
        for (var ti = 0; ti < e.thirdCountryTransfers.length; ti++) {
          var t = e.thirdCountryTransfers[ti];
          md += "  - " + t.country + " (safeguard: " + (t.safeguard || "n/a") + ")\n";
        }
      }
      md += "\n";
    }
    return md;
  }
  function exportRopa(eopts) {
    eopts = eopts || {};
    var format = (eopts.format || "json").toLowerCase();
    _emitAudit("exported", "success", { format: format, count: activities.size });
    if (format === "csv")      return _exportCsv();
    if (format === "markdown") return _exportMarkdown();
    if (format === "json")     return _exportJson();
    throw new GdprRopaError("gdpr-ropa/bad-format",
      "gdpr.ropa.export: format must be 'json' / 'csv' / 'markdown'");
  }

  return {
    register: register,
    update:   update,
    remove:   remove,
    get:      get,
    list:     list,
    "export": exportRopa,                                                                // explicit string-key — `export` is reserved
    VALID_LEGAL_BASES: Object.keys(VALID_LEGAL_BASES),
  };
}

module.exports = {
  create:                  create,
  GdprRopaError:           GdprRopaError,
  VALID_LEGAL_BASES:       Object.keys(VALID_LEGAL_BASES),
  REQUIRED_ACTIVITY_FIELDS: REQUIRED_ACTIVITY_FIELDS,
};
