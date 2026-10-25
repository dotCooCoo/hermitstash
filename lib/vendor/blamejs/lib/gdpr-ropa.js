// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.gdpr.ropa
 * @nav    Compliance
 * @title  GDPR RoPA
 * @slug   gdpr-ropa
 *
 * @intro
 *   The Record of Processing Activities that GDPR Article 30 requires a
 *   controller to keep and to produce on request. Activities are registered
 *   in the running application rather than maintained as a separate
 *   document, so the record describes the deployment that exists.
 *
 *   An activity is refused unless it carries an id, a name, its purposes, a
 *   legal basis and the categories of data it processes, and the legal basis
 *   has to be one of the six Article 6 bases. A record that cannot answer
 *   those questions is not one a supervisory authority will accept.
 *
 *   The register exports as JSON, CSV or Markdown, and every registration,
 *   change, removal and export is recorded in the audit chain, so the
 *   register's own history shows when the controller knew what.
 *
 * @card
 *   An Article 30 Record of Processing Activities kept by the running
 *   application, refusing an activity without a valid Article 6 legal basis
 *   and exporting as JSON, CSV or Markdown.
 */

var defineClass = require("./framework-error").defineClass;
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var boundedMap = require("./bounded-map");

var audit = lazyRequire(function () { return require("./audit"); });
var incidentReport = lazyRequire(function () { return require("./incident-report"); });

var GdprRopaError = defineClass("GdprRopaError", { alwaysPermanent: true });

var REQUIRED_ACTIVITY_FIELDS = Object.freeze([
  "id", "name", "purposes", "legalBasis", "dataCategories",
]);

var ACTIVITY_STRING_FIELDS = Object.freeze(["id", "name"]);
var ACTIVITY_LIST_FIELDS = Object.freeze(["purposes", "dataCategories"]);

function _sealActivity(record) {
  return incidentReport()._frozenCopy(record);
}

var VALID_LEGAL_BASES = Object.freeze({
  "consent":               1,
  "contract":              1,
  "legal-obligation":      1,
  "vital-interests":       1,
  "public-task":           1,
  "legitimate-interests":  1,
});

/**
 * @primitive b.gdpr.ropa.create
 * @signature b.gdpr.ropa.create(opts?)
 * @since     0.8.44
 * @status    stable
 * @compliance gdpr
 * @related   b.dsr.create, b.compliance.current
 *
 * Open a Record of Processing Activities. The returned register answers
 * `register`, `update`, `remove`, `get`, `list` and `export`, and carries
 * `VALID_LEGAL_BASES`, the six Article 6 bases it will accept.
 *
 * A `controller` that is not an object raises `gdpr-ropa/bad-controller`,
 * since the controller's identity is the first thing an Article 30 record has
 * to state.
 *
 * `register(activity)` requires `id`, `name`, `purposes`, `legalBasis` and
 * `dataCategories`: a non-object activity raises `gdpr-ropa/bad-activity`, a
 * missing or non-string id `gdpr-ropa/bad-id`, any other absent required
 * field `gdpr-ropa/missing-field`, and a `legalBasis` outside `consent`,
 * `contract`, `legal-obligation`, `vital-interests`, `public-task` and
 * `legitimate-interests` raises `gdpr-ropa/bad-legal-basis`. Registering an id
 * already present raises `gdpr-ropa/duplicate-id` rather than replacing the
 * activity.
 *
 * `update(id, patch)` merges the patch over the stored activity and then
 * applies the same required-field and legal-basis checks to the result, so a
 * patch that clears `name` or `purposes` raises `gdpr-ropa/missing-field` and
 * the stored activity is left alone. A record can only leave the register
 * carrying every Article 30 §1 field. A field that is absent raises
 * `gdpr-ropa/missing-field`; one that is present but unusable raises
 * `gdpr-ropa/bad-field`, which covers a `name` that is not a non-empty string
 * and a `purposes` or `dataCategories` that is not a non-empty array of
 * names, since a record whose `purposes` is `[]` answers the Article 30
 * question with nothing. `id` keeps `gdpr-ropa/bad-id` and `legalBasis`
 * `gdpr-ropa/bad-legal-basis`, which names the six bases.
 *
 * A stored activity is frozen, with `purposes` and `dataCategories` copied
 * and frozen too, and that frozen record is what `register`, `update`, `get`
 * and `list` answer with. So clearing the array you passed to `register`, or
 * assigning to a field of the record you got back, does not reach the
 * register: either would otherwise put an activity the validation refused
 * into the next export. `update` raises `gdpr-ropa/bad-patch`
 * for a non-object patch, and `update` and `remove` raise
 * `gdpr-ropa/not-found` for an id the register does not hold. `get` answers
 * `null` instead, since asking whether an activity is registered is an
 * ordinary question rather than an error.
 *
 * `export({ format })` renders the register as `json`, `csv` or `markdown`;
 * any other format raises `gdpr-ropa/bad-format`. `controller`, `dpo` and
 * `supervisoryAuthority` are carried into the exported document, which is
 * what makes the output something to hand to an authority rather than a list
 * of rows.
 *
 * @opts
 *   controller:           object,   // name and contact of the controller
 *   dpo:                  object,   // data protection officer's details
 *   supervisoryAuthority: object,   // the authority the controller answers to
 *   now:                  object,   // function returning epoch ms; for tests
 *   audit:                object,   // audit instance, or false to stay silent
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var ropa = b.gdpr.ropa.create({ controller: { name: "Acme GmbH" } });
 *   ropa.register({
 *     id:             "billing",
 *     name:           "Customer billing",
 *     purposes:       ["invoicing"],
 *     legalBasis:     "contract",
 *     dataCategories: ["name", "address"],
 *   });
 *   ropa.list().length;                    // → 1
 *   ropa["export"]({ format: "markdown" });
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "audit", "controller", "dpo", "supervisoryAuthority", "now",
  ], "gdpr.ropa");

  if (!opts.controller || typeof opts.controller !== "object") {
    throw new GdprRopaError("gdpr-ropa/bad-controller",
      "gdpr.ropa.create: opts.controller is required (Article 30 §1(a) requires controller name + contact)");
  }
  var controller = _sealActivity(opts.controller);
  var dpo = opts.dpo ? _sealActivity(opts.dpo) : null;
  var supervisoryAuthority = opts.supervisoryAuthority
    ? _sealActivity(opts.supervisoryAuthority) : null;
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
      if (activity[f] === undefined || activity[f] === null) {
        throw new GdprRopaError("gdpr-ropa/missing-field",
          "gdpr.ropa." + op + ": activity is missing required field '" + f + "' (per Article 30 §1)");
      }
    }
    for (var s = 0; s < ACTIVITY_STRING_FIELDS.length; s++) {
      var sf = ACTIVITY_STRING_FIELDS[s];
      if (typeof activity[sf] !== "string" || activity[sf].length === 0) {
        throw new GdprRopaError(
          sf === "id" ? "gdpr-ropa/bad-id" : "gdpr-ropa/bad-field",
          "gdpr.ropa." + op + ": activity." + sf + " must be a non-empty string");
      }
    }
    for (var l = 0; l < ACTIVITY_LIST_FIELDS.length; l++) {
      var lf = ACTIVITY_LIST_FIELDS[l];
      validateOpts.optionalNonEmptyStringArray(activity[lf],
        "gdpr.ropa." + op + ": activity." + lf,
        GdprRopaError, "gdpr-ropa/bad-field");
      if (activity[lf].length === 0) {
        throw new GdprRopaError("gdpr-ropa/bad-field",
          "gdpr.ropa." + op + ": activity." + lf + " is empty, which answers " +
          "the Article 30 §1 question with nothing");
      }
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
    var rec = _sealActivity(Object.assign({}, activity, {
      registeredAt: now(),
      lastUpdatedAt: now(),
    }));
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
      id: id,
      registeredAt: existing.registeredAt,
      lastUpdatedAt: now(),
    });
    _validateActivity(merged, "update");
    var sealed = _sealActivity(merged);
    activities.set(id, sealed);
    _emitAudit("updated", "success", { id: id, fields: Object.keys(patch) });
    return sealed;
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

  function get(id) {
    var rec = activities.get(id);
    return rec ? _sealActivity(rec) : null;
  }
  function list() {
    var out = [];
    activities.forEach(function (rec) { out.push(_sealActivity(rec)); });
    return out;
  }

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
      var cells = new Array(headers.length);
      for (var hi = 0; hi < headers.length; hi++) cells[hi] = _csvCell(e[headers[hi]]);
      rows.push(cells.join(","));
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
    "export": exportRopa,
    VALID_LEGAL_BASES: Object.keys(VALID_LEGAL_BASES),
  };
}

module.exports = {
  create:                  create,
  GdprRopaError:           GdprRopaError,
  VALID_LEGAL_BASES:       Object.keys(VALID_LEGAL_BASES),
  REQUIRED_ACTIVITY_FIELDS: REQUIRED_ACTIVITY_FIELDS,
};
