"use strict";
/**
 * guard-pdf — PDF identifier-safety primitive (b.guardPdf).
 *
 * Validates PDF inputs without vendoring a full parser. Operators
 * bring their own PDF library (pdf-lib, pdfjs-dist, vendored mupdf)
 * and feed structural metadata to the guard for policy enforcement.
 * KIND="metadata" — consumes `ctx.metadata` shape: `{ bytes?,
 * hasJavaScript?, hasOpenAction?, hasEmbeddedFiles?, hasLaunchAction?,
 * isEncrypted?, pageCount?, embeddedFileCount? }`.
 *
 * Threat catalog:
 *   - Magic-byte missing or wrong — `%PDF-` header check.
 *   - JavaScript action — `/JS` / `/JavaScript` annotation triggers
 *     RCE in vulnerable readers (CVE class — Adobe / Foxit / nitro).
 *   - OpenAction trigger — `/OpenAction` runs on document open;
 *     when paired with JavaScript or LaunchAction it's a drive-by.
 *   - LaunchAction — `/Launch` action invokes external program;
 *     refused at every profile.
 *   - Embedded files — `/EmbeddedFile` may carry executable payloads.
 *   - Encrypted PDF refuse — many AV / sandbox tools can't scan;
 *     operators may want to refuse encrypted PDFs.
 *   - Oversized — bytes / page count / embedded-file count.
 *   - Polyglot — buffer carries non-PDF magic-byte signatures
 *     (operator-supplied via `polyglotDetected: true`).
 *
 *   var rv = b.guardPdf.validate(metadata, { profile: "strict" });
 *   var g  = b.guardPdf.gate({ profile: "strict" });
 */

var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var { GuardPdfError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardPdfError.factory;

// PDF magic bytes — `%PDF-` (5 bytes).
var PDF_MAGIC = [0x25, 0x50, 0x44, 0x46, 0x2D];

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    magicPolicy:              "reject",
    javascriptPolicy:          "reject",
    openActionPolicy:          "reject",
    launchActionPolicy:        "reject",
    embeddedFilePolicy:        "reject",
    encryptedPolicy:           "reject",
    polyglotPolicy:            "reject",
    pageCountPolicy:           "reject",
    embeddedFileCountPolicy:   "reject",
    maxPageCount:              500,                                              // allow:raw-byte-literal — page-count ceiling
    maxEmbeddedFileCount:      0,                                                // allow:raw-byte-literal — strict refuses any embedded file
    maxBytes:                  C.BYTES.mib(64),
    maxRuntimeMs:              C.TIME.seconds(5),
  },
  "balanced": {
    magicPolicy:              "reject",
    javascriptPolicy:          "reject",                                         // RCE class — refused at every profile
    openActionPolicy:          "audit",
    launchActionPolicy:        "reject",                                         // RCE class — refused at every profile
    embeddedFilePolicy:        "audit",
    encryptedPolicy:           "audit",
    polyglotPolicy:            "reject",                                         // polyglot refused at every profile
    pageCountPolicy:           "audit",
    embeddedFileCountPolicy:   "audit",
    maxPageCount:              5000,                                             // allow:raw-byte-literal — page-count ceiling
    maxEmbeddedFileCount:      10,                                               // allow:raw-byte-literal — embedded file ceiling
    maxBytes:                  C.BYTES.mib(128),
    maxRuntimeMs:              C.TIME.seconds(5),
  },
  "permissive": {
    magicPolicy:              "audit",
    javascriptPolicy:          "reject",                                          // RCE class — refused at every profile
    openActionPolicy:          "audit",
    launchActionPolicy:        "reject",                                          // RCE class — refused at every profile
    embeddedFilePolicy:        "audit",
    encryptedPolicy:           "allow",
    polyglotPolicy:            "reject",                                          // polyglot refused at every profile
    pageCountPolicy:           "audit",
    embeddedFileCountPolicy:   "audit",
    maxPageCount:              50000,                                            // allow:raw-byte-literal — page-count ceiling
    maxEmbeddedFileCount:      100,                                              // allow:raw-byte-literal — embedded file ceiling
    maxBytes:                  C.BYTES.mib(512),
    maxRuntimeMs:              C.TIME.seconds(5),
  },
});

var DEFAULTS = Object.freeze(Object.assign({}, PROFILES["strict"], {
  mode: "enforce",
}));

var COMPLIANCE_POSTURES = Object.freeze({
  "hipaa":   Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(512),
  }),
  "pci-dss": Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(512),
  }),
  "gdpr":    Object.assign({}, PROFILES["balanced"], {
    forensicSnippetBytes: C.BYTES.bytes(256),
  }),
  "soc2":    Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(1024),
  }),
});

function _resolveOpts(opts) {
  return gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardPdfError,
    errCodePrefix:      "pdf",
  });
}

function _hasPdfMagic(buf) {
  if (!buf || typeof buf.length !== "number" || buf.length < PDF_MAGIC.length) {
    return false;
  }
  for (var i = 0; i < PDF_MAGIC.length; i += 1) {
    if (buf[i] !== PDF_MAGIC[i]) return false;
  }
  return true;
}

function _detectIssues(metadata, opts) {
  var issues = [];
  if (!metadata || typeof metadata !== "object") {
    return [{ kind: "bad-input", severity: "high",
              ruleId: "pdf.bad-input",
              snippet: "pdf metadata is not an object" }];
  }

  var bytes = metadata.bytes;
  if (bytes && typeof bytes.length === "number" && bytes.length > opts.maxBytes) {
    return [{ kind: "pdf-cap", severity: "high",
              ruleId: "pdf.pdf-cap",
              snippet: "pdf bytes exceed maxBytes " + opts.maxBytes }];
  }

  // Magic check.
  if (bytes && opts.magicPolicy !== "allow" && !_hasPdfMagic(bytes)) {
    issues.push({
      kind: "magic-missing",
      severity: opts.magicPolicy === "reject" ? "high" : "warn",
      ruleId: "pdf.magic-missing",
      snippet: "buffer does not start with `%PDF-` magic bytes",
    });
  }

  // Polyglot — operator-supplied flag.
  if (metadata.polyglotDetected === true && opts.polyglotPolicy !== "allow") {
    issues.push({
      kind: "polyglot", severity: "critical",
      ruleId: "pdf.polyglot",
      snippet: "operator metadata flags this PDF as polyglot — refused " +
               "(buffer carries non-PDF magic-byte signatures)",
    });
  }

  // JavaScript action — RCE class.
  if (metadata.hasJavaScript === true && opts.javascriptPolicy !== "allow") {
    issues.push({
      kind: "javascript-action", severity: "critical",
      ruleId: "pdf.javascript-action",
      snippet: "PDF carries `/JS` / `/JavaScript` action — RCE class " +
               "in vulnerable readers (Adobe / Foxit / nitro CVEs)",
    });
  }

  // LaunchAction — universally refused.
  if (metadata.hasLaunchAction === true &&
      opts.launchActionPolicy !== "allow") {
    issues.push({
      kind: "launch-action", severity: "critical",
      ruleId: "pdf.launch-action",
      snippet: "PDF carries `/Launch` action — invokes external program",
    });
  }

  // OpenAction — runs on document open.
  if (metadata.hasOpenAction === true &&
      opts.openActionPolicy !== "allow") {
    issues.push({
      kind: "open-action",
      severity: opts.openActionPolicy === "reject" ? "high" : "warn",
      ruleId: "pdf.open-action",
      snippet: "PDF carries `/OpenAction` — runs on document open " +
               "(drive-by class when paired with JavaScript / Launch)",
    });
  }

  // Embedded files.
  if (metadata.hasEmbeddedFiles === true &&
      opts.embeddedFilePolicy !== "allow") {
    issues.push({
      kind: "embedded-file",
      severity: opts.embeddedFilePolicy === "reject" ? "high" : "warn",
      ruleId: "pdf.embedded-file",
      snippet: "PDF carries embedded files — may smuggle executable " +
               "payloads",
    });
  }
  if (typeof metadata.embeddedFileCount === "number" &&
      opts.embeddedFileCountPolicy !== "allow" &&
      metadata.embeddedFileCount > opts.maxEmbeddedFileCount) {
    issues.push({
      kind: "embedded-file-count",
      severity: opts.embeddedFileCountPolicy === "reject" ? "high" : "warn",
      ruleId: "pdf.embedded-file-count",
      snippet: "embedded-file count " + metadata.embeddedFileCount +
               " exceeds maxEmbeddedFileCount " + opts.maxEmbeddedFileCount,
    });
  }

  // Encrypted.
  if (metadata.isEncrypted === true && opts.encryptedPolicy !== "allow") {
    issues.push({
      kind: "encrypted",
      severity: opts.encryptedPolicy === "reject" ? "high" : "warn",
      ruleId: "pdf.encrypted",
      snippet: "PDF is encrypted — many AV / sandbox tools can't scan " +
               "encrypted documents",
    });
  }

  // Page count.
  if (typeof metadata.pageCount === "number" &&
      opts.pageCountPolicy !== "allow" &&
      metadata.pageCount > opts.maxPageCount) {
    issues.push({
      kind: "page-count",
      severity: opts.pageCountPolicy === "reject" ? "high" : "warn",
      ruleId: "pdf.page-count",
      snippet: "page count " + metadata.pageCount + " exceeds " +
               "maxPageCount " + opts.maxPageCount,
    });
  }

  return issues;
}

function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes", "maxPageCount"],
    "guardPdf.validate", GuardPdfError, "pdf.bad-opt");
  // maxEmbeddedFileCount allows 0 (strict refuses all embedded files);
  // skip the positive-finite check.
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

function sanitize(input, opts) {
  opts = _resolveOpts(opts);
  if (!input || typeof input !== "object") {
    throw _err("pdf.bad-input", "sanitize requires metadata object");
  }
  var issues = _detectIssues(input, opts);
  for (var i = 0; i < issues.length; i += 1) {
    if (issues[i].severity === "critical" || issues[i].severity === "high") {
      throw _err(issues[i].ruleId || "pdf.refused",
        "guardPdf.sanitize: " + issues[i].snippet);
    }
  }
  return input;
}

function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardPdf:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var meta = ctx && (ctx.metadata || ctx.pdfMetadata);
      if (!meta) return { ok: true, action: "serve" };
      var rv = validate(meta, opts);
      if (rv.issues.length === 0) return { ok: true, action: "serve" };
      var hasCritical = rv.issues.some(function (i) {
        return i.severity === "critical";
      });
      var hasHigh = rv.issues.some(function (i) {
        return i.severity === "high";
      });
      if (!hasCritical && !hasHigh) {
        return { ok: true, action: "audit-only", issues: rv.issues };
      }
      return { ok: false, action: "refuse", issues: rv.issues };
    });
}

var buildProfile = gateContract.makeProfileBuilder(PROFILES);

function compliancePosture(name) {
  return gateContract.lookupCompliancePosture(name, COMPLIANCE_POSTURES,
    _err, "pdf");
}

var _pdfRulePacks = gateContract.makeRulePackLoader(GuardPdfError, "pdf");
var loadRulePack = _pdfRulePacks.load;

// Operator helper: confirm bytes carry the PDF magic header.
function inspectMagic(bytes) {
  return _hasPdfMagic(bytes);
}

module.exports = {
  // ---- guard-* family registry exports ----
  NAME:                "pdf",
  KIND:                "metadata",
  INTEGRATION_FIXTURES: Object.freeze({
    kind:              "metadata",
    benignBytes:       Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x37]), // %PDF-1.7
    hostileBytes:      Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x37]),
    benignMetadata: {
      bytes: Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x37]),
      hasJavaScript: false, hasOpenAction: false, hasLaunchAction: false,
      hasEmbeddedFiles: false, isEncrypted: false, pageCount: 1,
    },
    hostileMetadata: {
      bytes: Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x37]),
      // Hostile: JavaScript action — universal refuse (RCE class).
      hasJavaScript: true,
    },
  }),
  // ---- primitive surface ----
  validate:            validate,
  sanitize:            sanitize,
  gate:                gate,
  inspectMagic:        inspectMagic,
  buildProfile:        buildProfile,
  compliancePosture:   compliancePosture,
  loadRulePack:        loadRulePack,
  PROFILES:            PROFILES,
  DEFAULTS:            DEFAULTS,
  COMPLIANCE_POSTURES: COMPLIANCE_POSTURES,
  GuardPdfError:       GuardPdfError,
};
