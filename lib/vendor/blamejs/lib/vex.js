"use strict";
/**
 * @module     b.vex
 * @nav        Supply Chain
 * @title      VEX — OASIS CSAF 2.1 Vulnerability Exploitability eXchange
 * @order      720
 *
 * @intro
 *   VEX (Vulnerability Exploitability eXchange) statement builder per
 *   OASIS CSAF 2.1 §4.4 (CSAF VEX profile). Operators ship a
 *   `vex.cdx.json` alongside `sbom.cdx.json` declaring per-vulnerability
 *   exploitability state for the framework's component set. Status
 *   vocabulary follows the CSAF VEX profile §4.4 restriction (a strict
 *   subset of the full CSAF 2.1 §3.2.3.13 product_status vocabulary):
 *
 *     "fixed"               — framework included the vulnerable component
 *                              previously; the cited version ships the fix
 *     "known_affected"      — framework includes and uses the vulnerable
 *                              component; remediation required
 *     "known_not_affected"  — framework does not include / does not use
 *                              the vulnerable component
 *     "under_investigation" — disclosure is being evaluated
 *
 *   Justifications (when status=known_not_affected): `component_not_present`,
 *   `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`,
 *   `vulnerable_code_cannot_be_controlled_by_adversary`,
 *   `inline_mitigations_already_exist` (CSAF 2.1 §3.2.2.7).
 *
 *   `b.vex.statement({...})` produces a single VEX vulnerability
 *   record. `b.vex.document({...})` assembles a complete CSAF 2.1
 *   document with the framework's distributor metadata + an
 *   auto-emitted `product_tree.full_product_names` resolving every
 *   `product_ids` reference used by the statements (CSAF 2.1 §3.1).
 *   `b.vex.serialize` round-trips to canonical JSON (RFC 8785 / sorted
 *   keys) for signing.
 *
 *   Why the framework ships VEX: operators consuming the framework's
 *   VEX populate their own organisational VEX without re-auditing
 *   each framework dependency. Downstream consumers (Dependency-Track,
 *   csaf-validator-service, FIRST.org CSAF) reject malformed docs;
 *   shipping a spec-conformant doc is the cost of admission.
 *
 * @card
 *   OASIS CSAF 2.1 VEX statement + document builder. Operators ship
 *   `vex.cdx.json` alongside `sbom.cdx.json` to declare per-CVE
 *   exploitability state. Framework provides VEX statements for its
 *   own denied-vendor set + audit-cleared dependencies.
 */

var canonicalJson = require("./canonical-json");
var safeJson = require("./safe-json");
var C = require("./constants");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var VexError = defineClass("VexError", { alwaysPermanent: true });

// OASIS CSAF 2.1 §3.2.1 — top-level document structure constants.
var CSAF_VERSION = "2.1";
var DOCUMENT_CATEGORY_VEX = "csaf_vex";

// CSAF VEX profile §4.4 — product_status vocabulary restricted subset.
// The full CSAF 2.1 §3.2.3.13 vocabulary includes 8 values
// (first_affected, first_fixed, last_affected, recommended, etc.); the
// VEX profile restricts to these four. Spec-conformant VEX validators
// (csaf-validator-service, FIRST.org CSAF) reject documents whose
// product_status keys are outside this subset. The framework emits
// `csaf_vex` documents, so STATUS_VALUES tracks the VEX profile.
var STATUS_VALUES = Object.freeze([
  "fixed", "known_affected", "known_not_affected", "under_investigation",
]);

// CSAF 2.1 §3.2.2.7 — justifications for known_not_affected.
var JUSTIFICATION_VALUES = Object.freeze([
  "component_not_present",
  "vulnerable_code_not_present",
  "vulnerable_code_not_in_execute_path",
  "vulnerable_code_cannot_be_controlled_by_adversary",
  "inline_mitigations_already_exist",
]);

// CSAF 2.1 §3.2.1.12.1.1 — TLP 2.0 (FIRST 2022) labels. TLP:WHITE
// was renamed CLEAR in TLP 2.0; AMBER+STRICT is the additional
// restriction tier introduced in TLP 2.0. CSAF 2.1 aligns with TLP
// 2.0 — operators emitting WHITE or omitting AMBER+STRICT get
// downstream validation failures against spec-conformant tooling.
var TLP_LABELS = Object.freeze(["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"]);

// CSAF 2.1 §3.2.1.6 — document.tracking.status enumeration.
var TRACKING_STATUS_VALUES = Object.freeze(["draft", "interim", "final"]);

// CSAF 2.1 §3.2.1.10 — references[].category enumeration. `external`
// for third-party advisory URLs (NVD, GHSA, vendor pages OTHER than
// the document publisher); `self` for the publisher's own URLs
// (advisory hosted on the publisher's domain).
var REFERENCE_CATEGORY_VALUES = Object.freeze(["external", "self"]);

// CSAF 2.1 §3.2.3.7 — notes[].category enumeration. The framework
// accepts the full enumeration; operators pick per note. Default for
// `impactStatement` shorthand stays `details` (operator-readable
// impact / mitigation summary).
var NOTE_CATEGORY_VALUES = Object.freeze([
  "description", "details", "faq", "general", "legal_disclaimer",
  "other", "summary",
]);

// CSAF 2.1 §3.2.1.12.1.1.1 — TLP 2.0 boilerplate text required when
// distribution.tlp.label is RED or AMBER+STRICT (FIRST TLP 2.0). The
// document MUST carry the canonical distribution prose so consumers
// know the redistribution constraint. Operators may override via
// opts.distributionText; the framework's defaults match FIRST TLP 2.0
// verbatim so a spec-conformant doc is the no-effort default.
var TLP_DEFAULT_TEXTS = Object.freeze({
  "CLEAR":        "TLP:CLEAR information may be distributed without restriction.",
  "GREEN":        "TLP:GREEN information may be shared with peers and partner organizations within the community, but not via publicly accessible channels.",
  "AMBER":        "TLP:AMBER information may be shared with members of the recipient's organization, and clients or customers who need to know, but only on a need-to-know basis.",
  "AMBER+STRICT": "TLP:AMBER+STRICT information is restricted to the recipient organization only; no onward sharing without explicit permission.",
  "RED":          "TLP:RED information is restricted to named individual recipients. No further sharing is permitted.",
});

/**
 * @primitive b.vex.statement
 * @signature b.vex.statement(opts)
 * @since     0.9.6
 * @status    stable
 * @related   b.vex.document, b.vex.serialize
 *
 * Build a single CSAF 2.1 VEX vulnerability record. Returns an object
 * shaped per CSAF 2.1 §3.2.3 vulnerability schema with the supplied
 * CVE ID + product status + (when applicable) justification + impact
 * statement.
 *
 * Required: a vulnerability identity — `cveId` (CSAF §3.2.3.2)
 * and/or `ids` (CSAF §3.2.3.5 — array of `{ systemName, text }`
 * non-CVE tracking identifiers for advisories without an assigned
 * CVE). A `cweId` alone is NOT a valid CSAF vulnerability identity
 * (CWE is a weakness classification, not a per-vulnerability id);
 * supply `ids` alongside `cweId` when issuing a non-CVE statement.
 * Also required: `status` (one of STATUS_VALUES — CSAF VEX profile
 * §4.4 subset), `productIds` (array of product identifiers the
 * statement applies to).
 *
 * When `status === "known_not_affected"`, `justification` is required
 * per CSAF 2.1 §3.2.3.13.
 *
 * @opts
 *   cveId:           string,    // CVE-YYYY-NNNN
 *   cweId:           string,    // CWE-NNN (emitted as cwes[0] per CSAF §3.2.3.4)
 *   cweName:         string,    // human-readable CWE name (e.g. "Cross-site Scripting"); when omitted, cwes[].name is omitted (avoids CWE-ID-as-name antipattern flagged by csaf-validator)
 *   ids:             object[],  // [{ systemName, text }] non-CVE tracking ids
 *   title:           string,    // human-readable vulnerability title
 *   status:          string,    // one of STATUS_VALUES (VEX profile subset)
 *   productIds:      string[],  // CSAF product identifiers
 *   justification:   string,    // required when status=known_not_affected
 *   impactStatement: string,    // operator-readable impact / mitigation note (shorthand for notes[{category:"details",...}])
 *   notes:           object[],  // [{ category, text, title? }] full CSAF notes channel (CSAF §3.2.3.7)
 *   references:      array,     // [string] or [{ url, summary?, category? }] — CSAF §3.2.3.10
 *   firstReleased:   string,    // ISO 8601 timestamp
 *   lastUpdated:     string,    // ISO 8601 timestamp
 *
 * @example
 *   b.vex.statement({
 *     cveId:           "CVE-2024-21505",
 *     title:           "axios SSRF",
 *     status:          "known_not_affected",
 *     productIds:      ["@blamejs/core"],
 *     justification:   "component_not_present",
 *     impactStatement: "blamejs ships zero npm runtime deps; axios is never imported.",
 *   });
 */
function statement(opts) {
  if (!opts || typeof opts !== "object" || Array.isArray(opts)) {
    throw new VexError("vex/bad-opts",
      "statement: opts must be a non-null object");
  }
  // CSAF 2.1 §3.2.3 — vulnerability identity. cveId OR ids is
  // required. CWE alone is NOT a valid identity (CWE is a weakness
  // classification, not a per-vulnerability id).
  var hasIds = Array.isArray(opts.ids) && opts.ids.length > 0;
  if (!opts.cveId && !hasIds) {
    throw new VexError("vex/missing-vuln-id",
      "statement: cveId or ids[] is required (CWE alone is not a CSAF " +
      "vulnerability identity per §3.2.3.2 / §3.2.3.5)");
  }
  if (opts.cveId !== undefined) {
    if (typeof opts.cveId !== "string" || !/^CVE-\d{4}-\d{4,}$/.test(opts.cveId)) {
      throw new VexError("vex/bad-cve-id",
        "statement: cveId must match `CVE-YYYY-NNNN` (got '" + opts.cveId + "')");
    }
  }
  if (opts.cweId !== undefined) {
    if (typeof opts.cweId !== "string" || !/^CWE-\d+$/.test(opts.cweId)) {
      throw new VexError("vex/bad-cwe-id",
        "statement: cweId must match `CWE-NNN` (got '" + opts.cweId + "')");
    }
  }
  validateOpts.optionalNonEmptyString(opts.cweName, "statement.cweName", VexError, "vex/bad-cwe-name");
  if (opts.ids !== undefined) {
    if (!Array.isArray(opts.ids)) {
      throw new VexError("vex/bad-ids",
        "statement: ids must be an array of { systemName, text }");
    }
    for (var ii = 0; ii < opts.ids.length; ii++) {
      var entry = opts.ids[ii];
      if (!entry || typeof entry !== "object" ||
          typeof entry.systemName !== "string" || entry.systemName.length === 0 ||
          typeof entry.text !== "string" || entry.text.length === 0) {
        throw new VexError("vex/bad-ids",
          "statement: ids[" + ii + "] must be { systemName: string, text: string }");
      }
    }
  }
  if (STATUS_VALUES.indexOf(opts.status) === -1) {
    throw new VexError("vex/bad-status",
      "statement: status must be one of " + STATUS_VALUES.join(" / ") +
      " (CSAF VEX profile §4.4 subset)");
  }
  if (opts.productIds === undefined || opts.productIds === null) {
    throw new VexError("vex/missing-product-ids",
      "statement: productIds is required (non-empty string array)");
  }
  validateOpts.optionalNonEmptyStringArray(opts.productIds, "statement.productIds",
    VexError, "vex/bad-product-id");
  if (opts.productIds.length === 0) {
    throw new VexError("vex/missing-product-ids",
      "statement: productIds must be a non-empty string array");
  }
  if (opts.status === "known_not_affected") {
    if (!opts.justification || JUSTIFICATION_VALUES.indexOf(opts.justification) === -1) {
      throw new VexError("vex/missing-justification",
        "statement: when status=known_not_affected, justification is " +
        "required (one of " + JUSTIFICATION_VALUES.join(" / ") + ")");
    }
  }

  // CSAF 2.1 §3.2.3.7 — notes channel. Operators supplying `notes`
  // directly get the full CSAF notes vocabulary (description,
  // details, faq, general, legal_disclaimer, other, summary). The
  // `impactStatement` shorthand stays for the common "single details
  // note" case (back-compat with v0.9.6 callers).
  var compiledNotes = null;
  if (opts.notes !== undefined) {
    if (!Array.isArray(opts.notes)) {
      throw new VexError("vex/bad-notes",
        "statement: notes must be an array of { category, text, title? }");
    }
    compiledNotes = [];
    for (var ni = 0; ni < opts.notes.length; ni++) {
      var n = opts.notes[ni];
      if (!n || typeof n !== "object" ||
          typeof n.text !== "string" || n.text.length === 0 ||
          typeof n.category !== "string" ||
          NOTE_CATEGORY_VALUES.indexOf(n.category) === -1) {
        throw new VexError("vex/bad-notes",
          "statement: notes[" + ni + "] must be { category: one of " +
          NOTE_CATEGORY_VALUES.join("/") + ", text: string, title?: string }");
      }
      var noteOut = { category: n.category, text: n.text };
      if (n.title !== undefined) {
        if (typeof n.title !== "string" || n.title.length === 0) {
          throw new VexError("vex/bad-notes",
            "statement: notes[" + ni + "].title must be a non-empty string when supplied");
        }
        noteOut.title = n.title;
      }
      compiledNotes.push(noteOut);
    }
  }

  // CSAF 2.1 §3.2.3.10 — references channel. Two operator shapes:
  //   - bare string url    → { category: "external", url, summary: url }
  //   - { url, summary?, category? } → preserved verbatim after validation
  // Operator-supplied category defaults to "external" only when the
  // caller doesn't disambiguate; legitimate "self" references (URL on
  // the publisher's own domain) require operator opt-in to avoid the
  // framework auto-classifying.
  var compiledRefs = null;
  if (opts.references !== undefined) {
    if (!Array.isArray(opts.references)) {
      throw new VexError("vex/bad-references",
        "statement: references must be an array of strings or { url, summary?, category? } objects");
    }
    compiledRefs = [];
    for (var ri = 0; ri < opts.references.length; ri++) {
      var r = opts.references[ri];
      var refUrl;
      var refSummary;
      var refCategory = "external";
      if (typeof r === "string") {
        if (r.length === 0) {
          throw new VexError("vex/bad-references",
            "statement: references[" + ri + "] empty string");
        }
        refUrl = r;
        refSummary = r;
      } else if (r && typeof r === "object" && !Array.isArray(r)) {
        if (typeof r.url !== "string" || r.url.length === 0) {
          throw new VexError("vex/bad-references",
            "statement: references[" + ri + "].url must be a non-empty string");
        }
        refUrl = r.url;
        refSummary = typeof r.summary === "string" && r.summary.length > 0 ? r.summary : refUrl;
        if (r.category !== undefined) {
          if (typeof r.category !== "string" ||
              REFERENCE_CATEGORY_VALUES.indexOf(r.category) === -1) {
            throw new VexError("vex/bad-references",
              "statement: references[" + ri + "].category must be one of " +
              REFERENCE_CATEGORY_VALUES.join(" / "));
          }
          refCategory = r.category;
        }
      } else {
        throw new VexError("vex/bad-references",
          "statement: references[" + ri + "] must be a string url or { url, summary?, category? }");
      }
      compiledRefs.push({ category: refCategory, summary: refSummary, url: refUrl });
    }
  }

  var vuln = {};
  if (opts.cveId) vuln.cve = opts.cveId;
  // CSAF 2.1 §3.2.3.4 — cwes is a LIST of { id, name }. The `name`
  // field is the human-readable weakness title (e.g. "Cross-site
  // Scripting" for CWE-79). Using the CWE-ID as the name is the
  // antipattern csaf-validator-service flags; we now omit `name`
  // when the operator hasn't supplied `cweName`. CSAF schema treats
  // `name` as optional within the cwes[] array entry.
  if (opts.cweId) {
    var cweEntry = { id: opts.cweId };
    if (opts.cweName) cweEntry.name = opts.cweName;
    vuln.cwes = [cweEntry];
  }
  if (hasIds) {
    vuln.ids = opts.ids.map(_toCsafId);
  }
  if (opts.title) vuln.title = opts.title;
  vuln.product_status = {};
  // CSAF 2.1 §3.2.3.13 — bucket productIds under the status key.
  vuln.product_status[opts.status] = opts.productIds.slice();
  if (opts.status === "known_not_affected") {
    vuln.flags = [{
      label:    opts.justification,
      product_ids: opts.productIds.slice(),
    }];
  }
  // Merge impactStatement shorthand + explicit notes[]. The shorthand
  // prepends a single `{category:"details",title:"Impact",text:...}`
  // entry to preserve v0.9.6 caller ordering; operators wanting full
  // control supply `notes` directly.
  var allNotes = [];
  if (opts.impactStatement) {
    allNotes.push({
      category: "details",
      text:     opts.impactStatement,
      title:    "Impact",
    });
  }
  if (compiledNotes) allNotes = allNotes.concat(compiledNotes);
  if (allNotes.length > 0) vuln.notes = allNotes;
  if (compiledRefs) vuln.references = compiledRefs;
  if (opts.firstReleased) vuln.first_released = opts.firstReleased;
  if (opts.lastUpdated) vuln.last_updated = opts.lastUpdated;
  return vuln;
}

// _toCsafId — converts the operator-facing camelCase ids[] entries
// (`{ systemName, text }`) to the snake_case shape CSAF 2.1 §3.2.3.5
// requires (`{ system_name, text }`). One-liner, but lifted to a
// named helper so the camelCase→snake_case conversion is grepable and
// documented in one place (no other field on the statement output
// switches case — this is the only one).
function _toCsafId(entry) {
  return { system_name: entry.systemName, text: entry.text };
}

// _collectProductIds — walks every supplied statement and harvests
// the union of product_ids referenced under product_status[*] and
// flags[].product_ids. Emitted under document.product_tree.full_product_names
// (CSAF 2.1 §3.1) so flags[].product_ids and product_status keys
// resolve against the document's own product tree — the spec
// requires every referenced product_id to be defined in the
// product_tree. Without this, Dependency-Track + csaf-validator-service
// reject the document as "unresolved product reference."
function _collectProductIds(statements, productTreeNames) {
  var seen = Object.create(null);
  var ordered = [];
  function _add(id) {
    if (typeof id !== "string" || id.length === 0) return;
    if (seen[id]) return;
    seen[id] = true;
    ordered.push(id);
  }
  for (var si = 0; si < statements.length; si++) {
    var s = statements[si] || {};
    if (s.product_status && typeof s.product_status === "object") {
      var statusKeys = Object.keys(s.product_status);
      for (var ki = 0; ki < statusKeys.length; ki++) {
        var arr = s.product_status[statusKeys[ki]];
        if (Array.isArray(arr)) {
          for (var ai = 0; ai < arr.length; ai++) _add(arr[ai]);
        }
      }
    }
    if (Array.isArray(s.flags)) {
      for (var fi = 0; fi < s.flags.length; fi++) {
        var fl = s.flags[fi];
        if (fl && Array.isArray(fl.product_ids)) {
          for (var fai = 0; fai < fl.product_ids.length; fai++) _add(fl.product_ids[fai]);
        }
      }
    }
  }
  // Operator may supply product display-names via productTreeNames
  // ({ "<productId>": "<display name>" }). When omitted, the
  // product_id doubles as the display name so the emitted
  // full_product_names entry resolves consistently.
  var fpn = [];
  for (var oi = 0; oi < ordered.length; oi++) {
    var pid = ordered[oi];
    var displayName = (productTreeNames && typeof productTreeNames[pid] === "string" &&
                       productTreeNames[pid].length > 0)
      ? productTreeNames[pid]
      : pid;
    fpn.push({ product_id: pid, name: displayName });
  }
  return fpn;
}

/**
 * @primitive b.vex.document
 * @signature b.vex.document(opts)
 * @since     0.9.6
 * @status    stable
 * @related   b.vex.statement, b.vex.serialize
 *
 * Assemble a complete CSAF 2.1 VEX document with the supplied
 * vulnerability statements + framework distributor metadata. The
 * document auto-emits `product_tree.full_product_names` resolving
 * every `product_ids` reference used by the statements (CSAF 2.1
 * §3.1) so the document is self-contained — spec-conformant VEX
 * validators (csaf-validator-service, Dependency-Track) require
 * every `product_ids` reference to resolve against the document's
 * own product_tree.
 *
 * @opts
 *   documentId:        string,            // unique per-publication id (e.g. "blamejs-vex-2026-05-12")
 *   title:              string,           // document title
 *   publisher:          { name, namespace, contactDetails? },
 *   tlp:                string,           // one of TLP_LABELS; default "CLEAR"
 *   distributionText:   string,           // overrides TLP_DEFAULT_TEXTS[tlp]; required when TLP RED or AMBER+STRICT and operator wants non-default prose
 *   lang:               string,           // BCP 47 language tag (CSAF §3.2.1.13); default "en"
 *   trackingStatus:     string,           // CSAF §3.2.1.6 tracking.status — "draft" | "interim" | "final"; default "final"
 *   productTreeNames:   object,           // optional { "<productId>": "<display name>" } — when omitted, productId doubles as display name
 *   statements:         object[],         // array of b.vex.statement output
 *   distributor:        { ... },          // optional CSAF distributor block
 *   trackingId:         string,           // CSAF tracking id (e.g. version-pinned)
 *   trackingVersion:    string,           // semver
 *   currentReleaseDate: string,           // ISO 8601 timestamp
 *   initialReleaseDate: string,           // ISO 8601 timestamp
 *
 * @example
 *   var doc = b.vex.document({
 *     documentId:         "blamejs-vex-2026-05-12",
 *     title:              "blamejs framework VEX disclosures",
 *     publisher:          { name: "blamejs", namespace: "https://blamejs.com/" },
 *     trackingId:         "blamejs-vex-2026-05-12-001",
 *     trackingVersion:    "1.0.0",
 *     currentReleaseDate: "2026-05-12T00:00:00Z",
 *     initialReleaseDate: "2026-05-12T00:00:00Z",
 *     statements:         [
 *       b.vex.statement({ cveId: "CVE-2024-21505", status: "known_not_affected", productIds: ["@blamejs/core"], justification: "component_not_present" }),
 *     ],
 *   });
 */
function document(opts) {
  if (!opts || typeof opts !== "object" || Array.isArray(opts)) {
    throw new VexError("vex/bad-opts",
      "document: opts must be a non-null object");
  }
  validateOpts.shape(opts, {
    documentId:         { rule: "required-string", code: "vex/missing-documentId",         label: "documentId" },
    title:              { rule: "required-string", code: "vex/missing-title",              label: "title" },
    trackingId:         { rule: "required-string", code: "vex/missing-trackingId",         label: "trackingId" },
    trackingVersion:    { rule: "required-string", code: "vex/missing-trackingVersion",    label: "trackingVersion" },
    currentReleaseDate: { rule: "required-string", code: "vex/missing-currentReleaseDate", label: "currentReleaseDate" },
    initialReleaseDate: { rule: "required-string", code: "vex/missing-initialReleaseDate", label: "initialReleaseDate" },
    // publisher is required; the missing/sub-field checks own their own
    // codes (vex/missing-publisher{,-name,-namespace}) the test asserts
    // on. A truthy non-plain-object (array / string) is rejected with
    // vex/bad-opts (optional-plain-object semantics) BEFORE the absent
    // check, then a null/undefined publisher throws vex/missing-publisher,
    // then name/namespace are required non-empty strings.
    publisher:          function (v, label, e, c) {
      validateOpts.optionalPlainObject(v, label, e, c);
      if (!v || typeof v !== "object") {
        throw new VexError("vex/missing-publisher",
          "document: publisher object is required ({ name, namespace })");
      }
      validateOpts.requireNonEmptyString(v.name,      "publisher.name",      VexError, "vex/missing-publisher-name");
      validateOpts.requireNonEmptyString(v.namespace, "publisher.namespace", VexError, "vex/missing-publisher-namespace");
    },
    // The body's Array.isArray check throws vex/bad-statements; the shape
    // only needs to accept the key (an array is not a plain object).
    statements:         function () {},
    tlp:                "optional-string",
    lang:               "optional-string",
    trackingStatus:     "optional-string",
    productTreeNames:   "optional-plain-object",
    distributionText:   { rule: "optional-string", code: "vex/bad-distribution-text", label: "document.distributionText" },
    // distributor is copied onto distribution as-is when truthy.
    distributor:        function () {},
  }, "document", VexError, "vex/bad-opts");
  if (!Array.isArray(opts.statements)) {
    throw new VexError("vex/bad-statements",
      "document: statements must be an array of b.vex.statement objects");
  }
  var tlp = opts.tlp || "CLEAR";
  if (TLP_LABELS.indexOf(tlp) === -1) {
    throw new VexError("vex/bad-tlp",
      "document: tlp must be one of " + TLP_LABELS.join(" / "));
  }
  // CSAF 2.1 §3.2.1.13 — document.lang is a BCP 47 (RFC 5646)
  // language tag. The spec marks it optional but downstream
  // localisation pipelines + csaf-validator-service emit a warning
  // when absent; default to "en" so framework-issued docs always
  // carry the field. Operators publishing in other languages set
  // explicitly.
  var lang = "en";
  if (opts.lang !== undefined) {
    if (typeof opts.lang !== "string" || !/^[A-Za-z]{2,3}(-[A-Za-z0-9-]+)?$/.test(opts.lang)) {
      throw new VexError("vex/bad-lang",
        "document: lang must be a BCP 47 language tag (RFC 5646; e.g. 'en' / 'en-US' / 'de-DE')");
    }
    lang = opts.lang;
  }
  // CSAF 2.1 §3.2.1.6 — document.tracking.status enumeration. Default
  // "final" matches the previously-hardcoded value; operators
  // shipping in-progress disclosures set explicitly to "draft" /
  // "interim". csaf-validator rejects values outside this enum.
  var trackingStatus = "final";
  if (opts.trackingStatus !== undefined) {
    if (typeof opts.trackingStatus !== "string" ||
        TRACKING_STATUS_VALUES.indexOf(opts.trackingStatus) === -1) {
      throw new VexError("vex/bad-tracking-status",
        "document: trackingStatus must be one of " +
        TRACKING_STATUS_VALUES.join(" / ") + " (CSAF §3.2.1.6)");
    }
    trackingStatus = opts.trackingStatus;
  }
  if (opts.productTreeNames !== undefined &&
      (typeof opts.productTreeNames !== "object" || opts.productTreeNames === null ||
       Array.isArray(opts.productTreeNames))) {
    throw new VexError("vex/bad-product-tree-names",
      "document: productTreeNames must be a { <productId>: <displayName> } object");
  }
  // distributionText is validated by the shape's optional-string rule
  // above (label "document.distributionText", code vex/bad-distribution-text).
  // FIRST TLP 2.0 + CSAF §3.2.1.12.1.1.1 — distribution.text is
  // REQUIRED when TLP label is RED or AMBER+STRICT (the
  // recipient-restricted tiers carry mandatory boilerplate prose).
  // Other tiers benefit from the prose for downstream consumers;
  // emit unconditionally with the operator-overridable default.
  var distributionText = opts.distributionText || TLP_DEFAULT_TEXTS[tlp];

  // CSAF 2.1 §3.1 — product_tree.full_product_names. Auto-derive
  // from every productId referenced in statements so flags[] +
  // product_status[] entries resolve against a real product node.
  var fullProductNames = _collectProductIds(opts.statements, opts.productTreeNames || null);

  var doc = {
    document: {
      category: DOCUMENT_CATEGORY_VEX,
      csaf_version: CSAF_VERSION,
      lang: lang,
      title: opts.title,
      tracking: {
        id: opts.trackingId,
        version: opts.trackingVersion,
        status: trackingStatus,
        initial_release_date: opts.initialReleaseDate,
        current_release_date: opts.currentReleaseDate,
        revision_history: [
          { number: opts.trackingVersion, date: opts.currentReleaseDate, summary: opts.title },
        ],
      },
      distribution: {
        tlp: { label: tlp },
        text: distributionText,
      },
      publisher: {
        name:      opts.publisher.name,
        namespace: opts.publisher.namespace,
        category:  "vendor",
      },
    },
    product_tree: {
      full_product_names: fullProductNames,
    },
    vulnerabilities: opts.statements,
  };
  if (opts.publisher.contactDetails) {
    doc.document.publisher.contact_details = opts.publisher.contactDetails;
  }
  if (opts.distributor) {
    doc.document.distribution.distributor = opts.distributor;
  }
  return doc;
}

/**
 * @primitive b.vex.serialize
 * @signature b.vex.serialize(doc)
 * @since     0.9.6
 * @status    stable
 * @related   b.vex.document, b.vex.statement
 *
 * Serialize a VEX document to canonical JSON suitable for shipping
 * as `vex.cdx.json` or signing. Sorted-keys form so byte-equality
 * is stable across regenerations (matches the framework's
 * `b.canonicalJson` discipline).
 *
 * @example
 *   var json = b.vex.serialize(doc);
 *   fs.writeFileSync("vex.cdx.json", json);
 */
function serialize(doc) {
  if (!doc || typeof doc !== "object") {
    throw new VexError("vex/bad-doc",
      "serialize: doc must be the object returned by b.vex.document()");
  }
  // Route through b.canonicalJson.stringify for the deterministic
  // sorted-key bytes, then re-parse + re-stringify with 2-space
  // indent for human-diffable output. V8 preserves object insertion
  // order so the re-stringify keeps the canonical sort. One source
  // of truth for sort/scrub behaviour across the framework (rule
  // §canonicalize).
  var canonical = canonicalJson.stringify(doc);
  // Re-indent the canonical bytes for human-diffable output. allowProto keeps
  // the canonicalizer's exact key set (this is a faithful re-format of trusted
  // framework output, not a defense boundary); the size cap bounds the parse.
  return JSON.stringify(safeJson.parse(canonical, { allowProto: true, maxBytes: C.BYTES.mib(16) }), null, 2);
}

module.exports = {
  statement:               statement,
  document:                document,
  serialize:               serialize,
  STATUS_VALUES:           STATUS_VALUES,
  JUSTIFICATION_VALUES:    JUSTIFICATION_VALUES,
  TLP_LABELS:              TLP_LABELS,
  TRACKING_STATUS_VALUES:  TRACKING_STATUS_VALUES,
  REFERENCE_CATEGORY_VALUES: REFERENCE_CATEGORY_VALUES,
  NOTE_CATEGORY_VALUES:    NOTE_CATEGORY_VALUES,
  TLP_DEFAULT_TEXTS:       TLP_DEFAULT_TEXTS,
  CSAF_VERSION:            CSAF_VERSION,
  VexError:                VexError,
};
