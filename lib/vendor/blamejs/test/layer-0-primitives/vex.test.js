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
  var s = b.vex.statement({
    cweId:        undefined,
    cveId:        "CVE-2025-12345",
    status:       "fixed",
    productIds:   ["@blamejs/core@0.9.0"],
    references:   ["https://example.org/advisory/2025-12345"],
    firstReleased: "2026-05-12T00:00:00Z",
    lastUpdated:   "2026-05-12T00:00:00Z",
  });
  check("statement: references mapped to CSAF external refs",
        Array.isArray(s.references) &&
        s.references[0].url === "https://example.org/advisory/2025-12345" &&
        s.references[0].category === "external");
  check("statement: timestamps preserved",
        s.first_released === "2026-05-12T00:00:00Z" &&
        s.last_updated === "2026-05-12T00:00:00Z");
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
  // CSAF 2.1 §3.2.3.4 — cwes is a LIST.
  var s = b.vex.statement({
    cveId:      "CVE-2025-99999",
    cweId:      "CWE-79",
    status:     "fixed",
    productIds: ["@blamejs/core@0.9.5"],
  });
  check("statement: cwes is array (CSAF §3.2.3.4)",
        Array.isArray(s.cwes) && s.cwes.length === 1 && s.cwes[0].id === "CWE-79");
  check("statement: no legacy cwe singleton field",
        s.cwe === undefined);

  // CSAF 2.1 §3.2.3.5 — non-CVE tracking via ids[].
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
  testTlpAmberStrict();
  testDocumentShape();
  testDocumentRefusals();
  testSerialize();
  testComplianceVexPosture();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
