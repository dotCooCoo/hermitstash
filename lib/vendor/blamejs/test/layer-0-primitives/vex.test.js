// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.vex — OASIS CSAF 2.1 VEX statement / document builder.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("vex.statement is fn",      typeof b.vex.statement === "function");
  check("vex.document is fn",       typeof b.vex.document === "function");
  check("vex.serialize is fn",      typeof b.vex.serialize === "function");
  check("STATUS_VALUES is array",   Array.isArray(b.vex.STATUS_VALUES));
  check("JUSTIFICATION_VALUES is array", Array.isArray(b.vex.JUSTIFICATION_VALUES));
  check("TLP_LABELS is array",      Array.isArray(b.vex.TLP_LABELS));
  check("TRACKING_STATUS_VALUES is array",      Array.isArray(b.vex.TRACKING_STATUS_VALUES));
  check("REFERENCE_CATEGORY_VALUES is array",   Array.isArray(b.vex.REFERENCE_CATEGORY_VALUES));
  check("NOTE_CATEGORY_VALUES is array",        Array.isArray(b.vex.NOTE_CATEGORY_VALUES));
  check("TLP_DEFAULT_TEXTS is object",          b.vex.TLP_DEFAULT_TEXTS && typeof b.vex.TLP_DEFAULT_TEXTS === "object");
  check("CSAF_VERSION is 2.1",      b.vex.CSAF_VERSION === "2.1");
  check("VexError is constructor",  typeof b.vex.VexError === "function");
  var err = new b.vex.VexError("vex/test", "test message");
  check("VexError carries code",    err.code === "vex/test");
  // TLP 2.0 (FIRST 2022) labels per CSAF 2.1 §3.2.1.12.1.1.
  check("TLP_LABELS = TLP 2.0",
        b.vex.TLP_LABELS.indexOf("CLEAR") !== -1 &&
        b.vex.TLP_LABELS.indexOf("GREEN") !== -1 &&
        b.vex.TLP_LABELS.indexOf("AMBER") !== -1 &&
        b.vex.TLP_LABELS.indexOf("AMBER+STRICT") !== -1 &&
        b.vex.TLP_LABELS.indexOf("RED") !== -1);
  check("TLP_LABELS excludes WHITE (TLP 1.0 legacy)",
        b.vex.TLP_LABELS.indexOf("WHITE") === -1);
}

function testStatementShape() {
  var s = b.vex.statement({
    cveId:           "CVE-2024-21505",
    title:           "axios SSRF",
    status:          "known_not_affected",
    productIds:      ["@blamejs/core"],
    justification:   "component_not_present",
    impactStatement: "Zero runtime deps; axios never imported.",
  });
  check("statement: cve set",                s.cve === "CVE-2024-21505");
  check("statement: title set",              s.title === "axios SSRF");
  check("statement: product_status keyed by status",
        Array.isArray(s.product_status.known_not_affected) &&
        s.product_status.known_not_affected[0] === "@blamejs/core");
  check("statement: justification flag emitted",
        Array.isArray(s.flags) && s.flags[0].label === "component_not_present");
  check("statement: impactStatement → notes[].text",
        Array.isArray(s.notes) && s.notes[0].text.indexOf("Zero runtime deps") !== -1);
}

function testStatementWithReferences() {
  // Operator string-shorthand: category defaults to "external", summary
  // defaults to the url itself (per CSAF §3.2.3.10 / §3.2.1.10 — no
  // hardcoded `"Advisory reference"` summary; the URL itself carries
  // the semantic identity).
  var s = b.vex.statement({
    cveId:        "CVE-2025-12345",
    status:       "fixed",
    productIds:   ["@blamejs/core@0.9.0"],
    references:   ["https://example.org/advisory/2025-12345"],
    firstReleased: "2026-05-12T00:00:00Z",
    lastUpdated:   "2026-05-12T00:00:00Z",
  });
  check("statement: references mapped to CSAF external refs (string shorthand)",
        Array.isArray(s.references) &&
        s.references[0].url === "https://example.org/advisory/2025-12345" &&
        s.references[0].category === "external" &&
        s.references[0].summary === "https://example.org/advisory/2025-12345");
  check("statement: timestamps preserved",
        s.first_released === "2026-05-12T00:00:00Z" &&
        s.last_updated === "2026-05-12T00:00:00Z");

  // Operator object-shape — category=self for publisher's own URLs;
  // operator-supplied summary preserved (CSAF §3.2.1.10 — `self` for
  // vendor URLs, `external` for third-party advisories).
  var s2 = b.vex.statement({
    cveId:      "CVE-2025-12346",
    status:     "fixed",
    productIds: ["@blamejs/core@0.9.0"],
    references: [
      { url: "https://blamejs.com/security/CVE-2025-12346", summary: "Vendor advisory", category: "self" },
      { url: "https://nvd.nist.gov/vuln/detail/CVE-2025-12346" },
    ],
  });
  check("statement: references[].category=self honored",
        s2.references[0].category === "self" &&
        s2.references[0].summary === "Vendor advisory");
  check("statement: references object-shape defaults category=external",
        s2.references[1].category === "external" &&
        s2.references[1].summary === "https://nvd.nist.gov/vuln/detail/CVE-2025-12346");

  // Bad reference shapes refused.
  function expectCode(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(code) !== -1);
  }
  expectCode("statement: references must be an array",
             function () {
               b.vex.statement({ cveId: "CVE-2024-0001", status: "fixed", productIds: ["x"], references: "not-an-array" });
             }, "vex/bad-references");
  expectCode("statement: references[].category outside enum refused",
             function () {
               b.vex.statement({ cveId: "CVE-2024-0001", status: "fixed", productIds: ["x"], references: [{ url: "https://x", category: "weird" }] });
             }, "vex/bad-references");
}

function testStatementRefusals() {
  function expectCode(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(code) !== -1);
  }
  expectCode("statement: missing opts",
             function () { b.vex.statement(); }, "vex/bad-opts");
  expectCode("statement: missing cve+ids (cweId alone insufficient)",
             function () { b.vex.statement({ cweId: "CWE-79", status: "fixed", productIds: ["x"] }); }, "vex/missing-vuln-id");
  expectCode("statement: missing cve+ids (no identity at all)",
             function () { b.vex.statement({ status: "fixed", productIds: ["x"] }); }, "vex/missing-vuln-id");
  expectCode("statement: bad cve id shape",
             function () { b.vex.statement({ cveId: "not-a-cve", status: "fixed", productIds: ["x"] }); }, "vex/bad-cve-id");
  expectCode("statement: bad cwe id shape",
             function () { b.vex.statement({ cveId: "CVE-2024-0001", cweId: "not-a-cwe", status: "fixed", productIds: ["x"] }); }, "vex/bad-cwe-id");
  expectCode("statement: bad ids[] entry shape",
             function () { b.vex.statement({ ids: [{ systemName: "GHSA" }], status: "fixed", productIds: ["x"] }); }, "vex/bad-ids");
  expectCode("statement: unknown status",
             function () { b.vex.statement({ cveId: "CVE-2024-0001", status: "exploded", productIds: ["x"] }); }, "vex/bad-status");
  expectCode("statement: missing productIds",
             function () { b.vex.statement({ cveId: "CVE-2024-0001", status: "fixed" }); }, "vex/missing-product-ids");
  expectCode("statement: empty productIds array",
             function () { b.vex.statement({ cveId: "CVE-2024-0001", status: "fixed", productIds: [] }); }, "vex/missing-product-ids");
  expectCode("statement: known_not_affected requires justification",
             function () { b.vex.statement({ cveId: "CVE-2024-0001", status: "known_not_affected", productIds: ["x"] }); }, "vex/missing-justification");
  expectCode("statement: bad justification token",
             function () { b.vex.statement({ cveId: "CVE-2024-0001", status: "known_not_affected", productIds: ["x"], justification: "not-real" }); }, "vex/missing-justification");
}

function testCsafCweAndIdsShape() {
  // CSAF 2.1 §3.2.3.4 — cwes is a LIST. Without `cweName`, the name
  // field is omitted (csaf-validator-service flags CWE-ID-as-name as
  // an antipattern).
  var s = b.vex.statement({
    cveId:      "CVE-2025-99999",
    cweId:      "CWE-79",
    status:     "fixed",
    productIds: ["@blamejs/core@0.9.5"],
  });
  check("statement: cwes is array (CSAF §3.2.3.4)",
        Array.isArray(s.cwes) && s.cwes.length === 1 && s.cwes[0].id === "CWE-79");
  check("statement: cwes[].name omitted when cweName not supplied",
        s.cwes[0].name === undefined);
  check("statement: no legacy cwe singleton field",
        s.cwe === undefined);

  // With cweName, name is emitted.
  var sNamed = b.vex.statement({
    cveId:      "CVE-2025-99998",
    cweId:      "CWE-79",
    cweName:    "Cross-site Scripting",
    status:     "fixed",
    productIds: ["@blamejs/core@0.9.5"],
  });
  check("statement: cwes[].name emitted when cweName supplied",
        sNamed.cwes[0].name === "Cross-site Scripting");

  // CSAF 2.1 §3.2.3.5 — non-CVE tracking via ids[]. Helper converts
  // operator camelCase to CSAF snake_case (system_name).
  var s2 = b.vex.statement({
    ids: [{ systemName: "GHSA", text: "GHSA-xxxx-yyyy-zzzz" }],
    cweId:      "CWE-79",
    status:     "fixed",
    productIds: ["@blamejs/core@0.9.5"],
  });
  check("statement: ids[] emitted with snake_case system_name",
        Array.isArray(s2.ids) && s2.ids[0].system_name === "GHSA" &&
        s2.ids[0].text === "GHSA-xxxx-yyyy-zzzz");
  check("statement: cveId optional when ids[] supplied",
        s2.cve === undefined);
}

function testStatusVocabularyIsCsafVexSubset() {
  // CSAF VEX profile §4.4 — restricted to these four values. The
  // previous shipped vocabulary leaked first_affected / first_fixed /
  // last_affected / recommended from the full CSAF 2.1 §3.2.3.13
  // product_status set, which csaf-validator-service rejects when the
  // document category is csaf_vex.
  check("STATUS_VALUES is CSAF VEX profile §4.4 subset",
        b.vex.STATUS_VALUES.length === 4);
  ["fixed", "known_affected", "known_not_affected", "under_investigation"].forEach(function (v) {
    check("STATUS_VALUES includes '" + v + "'",
          b.vex.STATUS_VALUES.indexOf(v) !== -1);
  });
  ["first_affected", "first_fixed", "last_affected", "recommended", "affected", "not_affected"].forEach(function (v) {
    check("STATUS_VALUES excludes non-VEX-profile '" + v + "'",
          b.vex.STATUS_VALUES.indexOf(v) === -1);
  });

  // Status outside the VEX subset is refused.
  var threw = null;
  try {
    b.vex.statement({ cveId: "CVE-2024-0001", status: "first_affected", productIds: ["x"] });
  } catch (e) { threw = e; }
  check("statement: status outside VEX subset refused",
        threw && (threw.code || "").indexOf("vex/bad-status") !== -1);
}

function testTlpAmberStrict() {
  var stmt = b.vex.statement({
    cveId:      "CVE-2024-21505",
    status:     "fixed",
    productIds: ["@blamejs/core"],
  });
  var doc = b.vex.document({
    documentId:         "blamejs-vex-amber-strict",
    title:              "AMBER+STRICT test",
    publisher:          { name: "blamejs", namespace: "https://blamejs.com/" },
    trackingId:         "blamejs-vex-amber-strict",
    trackingVersion:    "1.0.0",
    currentReleaseDate: "2026-05-12T00:00:00Z",
    initialReleaseDate: "2026-05-12T00:00:00Z",
    statements:         [stmt],
    tlp:                "AMBER+STRICT",
  });
  check("document: TLP 2.0 AMBER+STRICT accepted",
        doc.document.distribution.tlp.label === "AMBER+STRICT");

  // TLP 1.0 WHITE no longer accepted (renamed CLEAR in TLP 2.0).
  var threw = null;
  try {
    b.vex.document({
      documentId:         "x", title: "x",
      publisher:          { name: "x", namespace: "x" },
      trackingId:         "x", trackingVersion: "1.0.0",
      currentReleaseDate: "2026", initialReleaseDate: "2026",
      statements:         [stmt], tlp: "WHITE",
    });
  } catch (e) { threw = e; }
  check("document: TLP 1.0 WHITE refused",
        threw && (threw.code || "").indexOf("vex/bad-tlp") !== -1);
}

function testDocumentShape() {
  var stmt = b.vex.statement({
    cveId:         "CVE-2024-21505",
    status:        "known_not_affected",
    productIds:    ["@blamejs/core"],
    justification: "component_not_present",
  });
  var doc = b.vex.document({
    documentId:         "blamejs-vex-2026-05-12-001",
    title:              "blamejs framework VEX",
    publisher:          { name: "blamejs", namespace: "https://blamejs.com/" },
    trackingId:         "blamejs-vex-2026-05-12-001",
    trackingVersion:    "1.0.0",
    currentReleaseDate: "2026-05-12T00:00:00Z",
    initialReleaseDate: "2026-05-12T00:00:00Z",
    statements:         [stmt],
  });
  check("document: csaf_version 2.1",
        doc.document.csaf_version === "2.1");
  check("document: category csaf_vex",
        doc.document.category === "csaf_vex");
  check("document: publisher vendor",
        doc.document.publisher.category === "vendor" &&
        doc.document.publisher.name === "blamejs");
  check("document: tracking populated",
        doc.document.tracking.id === "blamejs-vex-2026-05-12-001" &&
        doc.document.tracking.version === "1.0.0" &&
        doc.document.tracking.status === "final");
  check("document: tlp default CLEAR",
        doc.document.distribution.tlp.label === "CLEAR");
  check("document: vulnerabilities array",
        Array.isArray(doc.vulnerabilities) && doc.vulnerabilities.length === 1);
}

function testDocumentRefusals() {
  function expectCode(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(code) !== -1);
  }
  expectCode("document: missing publisher",
             function () { b.vex.document({ documentId: "x", title: "x", trackingId: "x", trackingVersion: "1.0.0", currentReleaseDate: "2026", initialReleaseDate: "2026", statements: [] }); },
             "vex/missing-publisher");
  expectCode("document: bad TLP",
             function () { b.vex.document({ documentId: "x", title: "x", publisher: { name: "x", namespace: "x" }, trackingId: "x", trackingVersion: "1.0.0", currentReleaseDate: "2026", initialReleaseDate: "2026", statements: [], tlp: "PURPLE" }); },
             "vex/bad-tlp");
}

function testDocumentLang() {
  // CSAF 2.1 §3.2.1.13 — document.lang BCP 47 default "en".
  var stmt = b.vex.statement({
    cveId:      "CVE-2024-21505",
    status:     "fixed",
    productIds: ["@blamejs/core"],
  });
  var doc = b.vex.document({
    documentId:         "blamejs-vex-lang",
    title:              "lang default",
    publisher:          { name: "blamejs", namespace: "https://blamejs.com/" },
    trackingId:         "blamejs-vex-lang",
    trackingVersion:    "1.0.0",
    currentReleaseDate: "2026-05-12T00:00:00Z",
    initialReleaseDate: "2026-05-12T00:00:00Z",
    statements:         [stmt],
  });
  check("document: lang default 'en'", doc.document.lang === "en");

  var docDe = b.vex.document({
    documentId:         "blamejs-vex-lang-de",
    title:              "lang override",
    publisher:          { name: "blamejs", namespace: "https://blamejs.com/" },
    trackingId:         "blamejs-vex-lang-de",
    trackingVersion:    "1.0.0",
    currentReleaseDate: "2026-05-12T00:00:00Z",
    initialReleaseDate: "2026-05-12T00:00:00Z",
    statements:         [stmt],
    lang:               "de-DE",
  });
  check("document: lang BCP 47 override accepted", docDe.document.lang === "de-DE");

  var threw = null;
  try {
    b.vex.document({
      documentId: "x", title: "x",
      publisher:  { name: "x", namespace: "x" },
      trackingId: "x", trackingVersion: "1.0.0",
      currentReleaseDate: "2026", initialReleaseDate: "2026",
      statements: [stmt], lang: "not a bcp47 tag",
    });
  } catch (e) { threw = e; }
  check("document: invalid lang refused",
        threw && (threw.code || "").indexOf("vex/bad-lang") !== -1);
}

function testDocumentTrackingStatus() {
  // CSAF 2.1 §3.2.1.6 — tracking.status enum.
  var stmt = b.vex.statement({
    cveId:      "CVE-2024-21505",
    status:     "fixed",
    productIds: ["@blamejs/core"],
  });
  var doc = b.vex.document({
    documentId:         "blamejs-vex-ts",
    title:              "tracking-status default",
    publisher:          { name: "blamejs", namespace: "https://blamejs.com/" },
    trackingId:         "blamejs-vex-ts",
    trackingVersion:    "1.0.0",
    currentReleaseDate: "2026-05-12T00:00:00Z",
    initialReleaseDate: "2026-05-12T00:00:00Z",
    statements:         [stmt],
  });
  check("document: tracking.status default 'final'",
        doc.document.tracking.status === "final");

  var docDraft = b.vex.document({
    documentId:         "blamejs-vex-ts-draft",
    title:              "tracking-status draft",
    publisher:          { name: "blamejs", namespace: "https://blamejs.com/" },
    trackingId:         "blamejs-vex-ts-draft",
    trackingVersion:    "0.0.1",
    currentReleaseDate: "2026-05-12T00:00:00Z",
    initialReleaseDate: "2026-05-12T00:00:00Z",
    statements:         [stmt],
    trackingStatus:     "draft",
  });
  check("document: tracking.status 'draft' accepted",
        docDraft.document.tracking.status === "draft");

  var threw = null;
  try {
    b.vex.document({
      documentId: "x", title: "x",
      publisher:  { name: "x", namespace: "x" },
      trackingId: "x", trackingVersion: "1.0.0",
      currentReleaseDate: "2026", initialReleaseDate: "2026",
      statements: [stmt], trackingStatus: "published",
    });
  } catch (e) { threw = e; }
  check("document: trackingStatus outside enum refused",
        threw && (threw.code || "").indexOf("vex/bad-tracking-status") !== -1);
}

function testDocumentProductTree() {
  // CSAF 2.1 §3.1 — product_tree.full_product_names auto-derived from
  // every product_ids reference in statements.
  var s1 = b.vex.statement({
    cveId:         "CVE-2024-21505",
    status:        "known_not_affected",
    productIds:    ["@blamejs/core", "@blamejs/core@0.9.0"],
    justification: "component_not_present",
  });
  var s2 = b.vex.statement({
    cveId:      "CVE-2025-11111",
    status:     "fixed",
    productIds: ["@blamejs/core@0.9.42"],
  });
  var doc = b.vex.document({
    documentId:         "blamejs-vex-pt",
    title:              "product_tree harvest",
    publisher:          { name: "blamejs", namespace: "https://blamejs.com/" },
    trackingId:         "blamejs-vex-pt",
    trackingVersion:    "1.0.0",
    currentReleaseDate: "2026-05-12T00:00:00Z",
    initialReleaseDate: "2026-05-12T00:00:00Z",
    statements:         [s1, s2],
    productTreeNames:   { "@blamejs/core": "blamejs framework" },
  });
  check("document: product_tree present",
        doc.product_tree && Array.isArray(doc.product_tree.full_product_names));
  check("document: product_tree harvests union of product_ids",
        doc.product_tree.full_product_names.length === 3);
  var byId = {};
  doc.product_tree.full_product_names.forEach(function (e) { byId[e.product_id] = e.name; });
  check("document: productTreeNames override applied",
        byId["@blamejs/core"] === "blamejs framework");
  check("document: missing productTreeNames defaults display name to product_id",
        byId["@blamejs/core@0.9.0"] === "@blamejs/core@0.9.0");
  check("document: statements still under vulnerabilities[]",
        Array.isArray(doc.vulnerabilities) && doc.vulnerabilities.length === 2);
}

function testDocumentDistributionText() {
  // FIRST TLP 2.0 + CSAF §3.2.1.12.1.1.1 — distribution.text REQUIRED
  // for RED / AMBER+STRICT; framework emits default boilerplate so
  // operators don't ship malformed docs.
  var stmt = b.vex.statement({
    cveId:      "CVE-2024-21505",
    status:     "fixed",
    productIds: ["@blamejs/core"],
  });
  var docClear = b.vex.document({
    documentId:         "blamejs-vex-dt-clear",
    title:              "TLP CLEAR default text",
    publisher:          { name: "blamejs", namespace: "https://blamejs.com/" },
    trackingId:         "blamejs-vex-dt-clear",
    trackingVersion:    "1.0.0",
    currentReleaseDate: "2026-05-12T00:00:00Z",
    initialReleaseDate: "2026-05-12T00:00:00Z",
    statements:         [stmt],
  });
  check("document: TLP:CLEAR carries default distribution.text",
        typeof docClear.document.distribution.text === "string" &&
        docClear.document.distribution.text.indexOf("CLEAR") !== -1);

  var docStrict = b.vex.document({
    documentId:         "blamejs-vex-dt-strict",
    title:              "TLP AMBER+STRICT default text",
    publisher:          { name: "blamejs", namespace: "https://blamejs.com/" },
    trackingId:         "blamejs-vex-dt-strict",
    trackingVersion:    "1.0.0",
    currentReleaseDate: "2026-05-12T00:00:00Z",
    initialReleaseDate: "2026-05-12T00:00:00Z",
    statements:         [stmt],
    tlp:                "AMBER+STRICT",
  });
  check("document: TLP:AMBER+STRICT carries default distribution.text",
        typeof docStrict.document.distribution.text === "string" &&
        docStrict.document.distribution.text.indexOf("AMBER+STRICT") !== -1);

  var docCustom = b.vex.document({
    documentId:         "blamejs-vex-dt-custom",
    title:              "operator distributionText override",
    publisher:          { name: "blamejs", namespace: "https://blamejs.com/" },
    trackingId:         "blamejs-vex-dt-custom",
    trackingVersion:    "1.0.0",
    currentReleaseDate: "2026-05-12T00:00:00Z",
    initialReleaseDate: "2026-05-12T00:00:00Z",
    statements:         [stmt],
    tlp:                "AMBER",
    distributionText:   "Internal redistribution only — engineering@example.com on file.",
  });
  check("document: operator distributionText preserved",
        docCustom.document.distribution.text.indexOf("Internal redistribution") === 0);
}

function testStatementNotes() {
  // CSAF 2.1 §3.2.3.7 — notes[] full enumeration accepted.
  var s = b.vex.statement({
    cveId:      "CVE-2024-21505",
    status:     "fixed",
    productIds: ["@blamejs/core"],
    notes: [
      { category: "legal_disclaimer", text: "No warranty extends to downstream consumers." },
      { category: "summary",          text: "Issue resolved in v0.9.46." },
    ],
  });
  check("statement: notes[] preserves operator entries",
        Array.isArray(s.notes) && s.notes.length === 2 &&
        s.notes[0].category === "legal_disclaimer" &&
        s.notes[1].category === "summary");

  // impactStatement shorthand prepends a single details note.
  var s2 = b.vex.statement({
    cveId:      "CVE-2024-21506",
    status:     "fixed",
    productIds: ["@blamejs/core"],
    impactStatement: "Patch landed in v0.9.46.",
    notes: [
      { category: "summary", text: "See release notes." },
    ],
  });
  check("statement: impactStatement + notes[] merge with impact first",
        s2.notes.length === 2 &&
        s2.notes[0].category === "details" &&
        s2.notes[0].title === "Impact" &&
        s2.notes[1].category === "summary");

  // Invalid category refused.
  var threw = null;
  try {
    b.vex.statement({
      cveId: "CVE-2024-21505", status: "fixed", productIds: ["x"],
      notes: [{ category: "weird", text: "x" }],
    });
  } catch (e) { threw = e; }
  check("statement: notes[].category outside enum refused",
        threw && (threw.code || "").indexOf("vex/bad-notes") !== -1);
}

function testSerialize() {
  var stmt = b.vex.statement({
    cveId:         "CVE-2024-21505",
    status:        "known_not_affected",
    productIds:    ["@blamejs/core"],
    justification: "component_not_present",
  });
  var doc = b.vex.document({
    documentId:         "blamejs-vex-2026-05-12-001",
    title:              "blamejs framework VEX",
    publisher:          { name: "blamejs", namespace: "https://blamejs.com/" },
    trackingId:         "blamejs-vex-2026-05-12-001",
    trackingVersion:    "1.0.0",
    currentReleaseDate: "2026-05-12T00:00:00Z",
    initialReleaseDate: "2026-05-12T00:00:00Z",
    statements:         [stmt],
  });
  var json = b.vex.serialize(doc);
  check("serialize: returns JSON string",
        typeof json === "string" && json.charAt(0) === "{");
  // Canonical sort — keys must be alphabetical at every level so the
  // serialization is byte-stable.
  var idx1 = json.indexOf("\"category\"");
  var idx2 = json.indexOf("\"csaf_version\"");
  check("serialize: keys sorted (category before csaf_version)",
        idx1 !== -1 && idx2 !== -1 && idx1 < idx2);

  // Two serializations of the same document must produce identical bytes.
  var json2 = b.vex.serialize(doc);
  check("serialize: deterministic",
        json === json2);

  // Non-doc refused.
  var threw = null;
  try { b.vex.serialize(null); } catch (e) { threw = e; }
  check("serialize: null doc refused",
        threw && (threw.code || "").indexOf("vex/bad-doc") !== -1);
}

function testSerializeRoundTripsAgainstSchemaShape() {
  // Lightweight csaf-validator-shaped checks — every CSAF 2.1
  // top-level required field is present after serialize. csaf-validator
  // would surface as schema-fail when any of these are absent. The
  // checks below cover CSAF §3.1 (product_tree), §3.2.1.6 (tracking),
  // §3.2.1.12.1.1 (distribution.tlp + text), §3.2.1.13 (lang),
  // §3.2.3.13 (product_status keyed by VEX-profile status).
  var stmt = b.vex.statement({
    cveId:         "CVE-2024-21505",
    status:        "known_not_affected",
    productIds:    ["@blamejs/core"],
    justification: "component_not_present",
  });
  var doc = b.vex.document({
    documentId:         "blamejs-vex-schema",
    title:              "schema-shape round trip",
    publisher:          { name: "blamejs", namespace: "https://blamejs.com/" },
    trackingId:         "blamejs-vex-schema",
    trackingVersion:    "1.0.0",
    currentReleaseDate: "2026-05-12T00:00:00Z",
    initialReleaseDate: "2026-05-12T00:00:00Z",
    statements:         [stmt],
  });
  var json = b.vex.serialize(doc);
  var parsed = JSON.parse(json);

  // csaf-validator-shape: required keys at document level.
  ["category", "csaf_version", "lang", "title", "tracking", "distribution", "publisher"]
    .forEach(function (k) {
      check("schema: document." + k + " present", parsed.document[k] !== undefined);
    });
  ["id", "version", "status", "initial_release_date", "current_release_date", "revision_history"]
    .forEach(function (k) {
      check("schema: document.tracking." + k + " present",
            parsed.document.tracking[k] !== undefined);
    });
  check("schema: document.tracking.status within enum",
        ["draft", "interim", "final"].indexOf(parsed.document.tracking.status) !== -1);
  check("schema: document.distribution.tlp.label within TLP 2.0 enum",
        ["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"]
          .indexOf(parsed.document.distribution.tlp.label) !== -1);
  check("schema: document.distribution.text present",
        typeof parsed.document.distribution.text === "string" &&
        parsed.document.distribution.text.length > 0);
  check("schema: product_tree.full_product_names resolves flags product_ids",
        Array.isArray(parsed.product_tree.full_product_names) &&
        parsed.product_tree.full_product_names.length === 1 &&
        parsed.product_tree.full_product_names[0].product_id === "@blamejs/core");
  // VEX-profile product_status restriction.
  var vstatusKeys = Object.keys(parsed.vulnerabilities[0].product_status);
  check("schema: product_status keys within VEX profile §4.4 enum",
        vstatusKeys.every(function (k) {
          return ["fixed", "known_affected", "known_not_affected", "under_investigation"].indexOf(k) !== -1;
        }));
}

function testComplianceVexPosture() {
  // v0.9.6 posture additions — sanity-check one of the audit-derived
  // entries lands in the KNOWN_POSTURES catalog with its cascade.
  check("vex-csaf-2.1 in KNOWN_POSTURES",
        b.compliance.KNOWN_POSTURES.indexOf("vex-csaf-2.1") !== -1);
  check("cyclonedx-v1.6 in KNOWN_POSTURES",
        b.compliance.KNOWN_POSTURES.indexOf("cyclonedx-v1.6") !== -1);
  check("spdx-v3.0 in KNOWN_POSTURES",
        b.compliance.KNOWN_POSTURES.indexOf("spdx-v3.0") !== -1);
  check("nist-800-218-ssdf in KNOWN_POSTURES",
        b.compliance.KNOWN_POSTURES.indexOf("nist-800-218-ssdf") !== -1);
  check("owasp-llm-top-10-2025 in KNOWN_POSTURES",
        b.compliance.KNOWN_POSTURES.indexOf("owasp-llm-top-10-2025") !== -1);
}

async function run() {
  testSurface();
  testStatementShape();
  testStatementWithReferences();
  testStatementRefusals();
  testCsafCweAndIdsShape();
  testStatusVocabularyIsCsafVexSubset();
  testTlpAmberStrict();
  testDocumentShape();
  testDocumentRefusals();
  testDocumentLang();
  testDocumentTrackingStatus();
  testDocumentProductTree();
  testDocumentDistributionText();
  testStatementNotes();
  testSerialize();
  testSerializeRoundTripsAgainstSchemaShape();
  testComplianceVexPosture();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
