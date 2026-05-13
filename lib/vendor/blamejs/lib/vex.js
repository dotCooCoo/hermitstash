"use strict";
/**
 * @module     b.vex
 * @nav        Supply Chain
 * @title      VEX — OASIS CSAF 2.1 Vulnerability Exploitability eXchange
 * @order      720
 *
 * @intro
 *   VEX (Vulnerability Exploitability eXchange) statement builder per
 *   OASIS CSAF 2.1 §4.4. Operators ship a `vex.cdx.json` alongside
 *   `sbom.cdx.json` declaring per-vulnerability exploitability state
 *   for the framework's component set. Status vocabulary:
 *
 *     "not_affected"        — framework does not include / does not use
 *                              the vulnerable component
 *     "affected"            — framework includes and uses the vulnerable
 *                              component; remediation required
 *     "fixed"               — framework included the vulnerable component
 *                              previously; the cited version ships the fix
 *     "under_investigation" — disclosure is being evaluated
 *
 *   Justifications (when status=not_affected): `component_not_present`,
 *   `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`,
 *   `vulnerable_code_cannot_be_controlled_by_adversary`,
 *   `inline_mitigations_already_exist`.
 *
 *   `b.vex.statement({...})` produces a single VEX vulnerability
 *   record. `b.vex.document({...})` assembles a complete CSAF 2.1
 *   document with the framework's distributor metadata. `b.vex.serialize`
 *   round-trips to canonical JSON (RFC 8785 / sorted keys) for
 *   signing. Output is operator-shippable alongside SBOM.
 *
 *   Why the framework ships VEX: the exceptd 2026-05-12 gap analysis
 *   surfaced VEX-CSAF-v2.1 as a 49-gap framework-control gap. The
 *   framework-side closure is "vendor-supplied VEX statements for
 *   every disclosed CVE the framework has been audited against."
 *   Operators consume the framework's VEX to populate their own
 *   organisational VEX without re-auditing each framework dependency.
 *
 * @card
 *   OASIS CSAF 2.1 VEX statement + document builder. Operators ship
 *   `vex.cdx.json` alongside `sbom.cdx.json` to declare per-CVE
 *   exploitability state. Framework provides VEX statements for its
 *   own denied-vendor set + audit-cleared dependencies.
 */

var canonicalJson = require("./canonical-json");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var VexError = defineClass("VexError", { alwaysPermanent: true });

// OASIS CSAF 2.1 §3.2.1 — top-level document structure constants.
var CSAF_VERSION = "2.1";
var DOCUMENT_CATEGORY_VEX = "csaf_vex";

// CSAF 2.1 §3.2.2.10 product_status vocabulary (relevant subset for VEX).
var STATUS_VALUES = Object.freeze([
  "first_affected", "first_fixed", "fixed", "known_affected",
  "known_not_affected", "last_affected", "recommended",
  "under_investigation",
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
 * Also required: `status` (one of STATUS_VALUES), `productIds`
 * (array of product identifiers the statement applies to).
 *
 * When `status === "known_not_affected"`, `justification` is required
 * per CSAF 2.1 §3.2.3.13.
 *
 * @opts
 *   cveId:        string,    // CVE-YYYY-NNNN
 *   cweId:        string,    // CWE-NNN (emitted as cwes[0] per CSAF §3.2.3.4)
 *   ids:          object[],  // [{ systemName, text }] non-CVE tracking ids
 *   title:        string,    // human-readable vulnerability title
 *   status:       string,    // one of STATUS_VALUES
 *   productIds:   string[],  // CSAF product identifiers
 *   justification: string,   // required when status=known_not_affected
 *   impactStatement: string, // operator-readable impact / mitigation note
 *   references:   string[],  // URIs to advisories / vendor pages
 *   firstReleased: string,   // ISO 8601 timestamp
 *   lastUpdated:  string,    // ISO 8601 timestamp
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
      "statement: status must be one of " + STATUS_VALUES.join(" / "));
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

  var vuln = {};
  if (opts.cveId) vuln.cve = opts.cveId;
  // CSAF 2.1 §3.2.3.4 — cwes is a LIST of { id, name }, not a
  // singleton field. The previous shape (`cwe: {...}`) failed
  // validation against spec-conformant CSAF tooling.
  if (opts.cweId) vuln.cwes = [{ id: opts.cweId, name: opts.cweId }];
  if (hasIds) {
    vuln.ids = opts.ids.map(function (entry) {
      return { system_name: entry.systemName, text: entry.text };
    });
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
  if (opts.impactStatement) {
    vuln.notes = [{
      category: "details",
      text:     opts.impactStatement,
      title:    "Impact",
    }];
  }
  if (Array.isArray(opts.references) && opts.references.length > 0) {
    vuln.references = opts.references.map(function (url) {
      return { summary: "Advisory reference", url: url, category: "external" };
    });
  }
  if (opts.firstReleased) vuln.first_released = opts.firstReleased;
  if (opts.lastUpdated) vuln.last_updated = opts.lastUpdated;
  return vuln;
}

/**
 * @primitive b.vex.document
 * @signature b.vex.document(opts)
 * @since     0.9.6
 * @status    stable
 * @related   b.vex.statement, b.vex.serialize
 *
 * Assemble a complete CSAF 2.1 VEX document with the supplied
 * vulnerability statements + framework distributor metadata.
 *
 * @opts
 *   documentId:        string,            // unique per-publication id (e.g. "blamejs-vex-2026-05-12")
 *   title:              string,           // document title
 *   publisher:          { name, namespace, contactDetails? },
 *   tlp:                string,           // one of TLP_LABELS; default "CLEAR"
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
  validateOpts.requireNonEmptyString(opts.documentId,  "documentId",  VexError, "vex/missing-documentId");
  validateOpts.requireNonEmptyString(opts.title,       "title",       VexError, "vex/missing-title");
  validateOpts.requireNonEmptyString(opts.trackingId,  "trackingId",  VexError, "vex/missing-trackingId");
  validateOpts.requireNonEmptyString(opts.trackingVersion, "trackingVersion", VexError, "vex/missing-trackingVersion");
  validateOpts.requireNonEmptyString(opts.currentReleaseDate, "currentReleaseDate", VexError, "vex/missing-currentReleaseDate");
  validateOpts.requireNonEmptyString(opts.initialReleaseDate, "initialReleaseDate", VexError, "vex/missing-initialReleaseDate");
  if (!opts.publisher || typeof opts.publisher !== "object") {
    throw new VexError("vex/missing-publisher",
      "document: publisher object is required ({ name, namespace })");
  }
  validateOpts.requireNonEmptyString(opts.publisher.name,      "publisher.name",      VexError, "vex/missing-publisher-name");
  validateOpts.requireNonEmptyString(opts.publisher.namespace, "publisher.namespace", VexError, "vex/missing-publisher-namespace");
  if (!Array.isArray(opts.statements)) {
    throw new VexError("vex/bad-statements",
      "document: statements must be an array of b.vex.statement objects");
  }
  var tlp = opts.tlp || "CLEAR";
  if (TLP_LABELS.indexOf(tlp) === -1) {
    throw new VexError("vex/bad-tlp",
      "document: tlp must be one of " + TLP_LABELS.join(" / "));
  }
  var doc = {
    document: {
      category: DOCUMENT_CATEGORY_VEX,
      csaf_version: CSAF_VERSION,
      title: opts.title,
      tracking: {
        id: opts.trackingId,
        version: opts.trackingVersion,
        status: "final",
        initial_release_date: opts.initialReleaseDate,
        current_release_date: opts.currentReleaseDate,
        revision_history: [
          { number: opts.trackingVersion, date: opts.currentReleaseDate, summary: opts.title },
        ],
      },
      distribution: {
        tlp: { label: tlp },
      },
      publisher: {
        name:      opts.publisher.name,
        namespace: opts.publisher.namespace,
        category:  "vendor",
      },
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
  return JSON.stringify(JSON.parse(canonical), null, 2);   // allow:bare-json-parse — canonical is canonicalJson.stringify output, not operator input
}

module.exports = {
  statement:            statement,
  document:             document,
  serialize:            serialize,
  STATUS_VALUES:        STATUS_VALUES,
  JUSTIFICATION_VALUES: JUSTIFICATION_VALUES,
  TLP_LABELS:           TLP_LABELS,
  CSAF_VERSION:         CSAF_VERSION,
  VexError:             VexError,
};
