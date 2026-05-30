"use strict";
/**
 * @module b.guardPdf
 * @nav    Guards
 * @title  Guard Pdf
 *
 * @intro
 *   PDF content-safety guard — refuses RCE-class PDF features without
 *   vendoring a parser. Operators bring their own PDF library
 *   (pdf-lib, pdfjs-dist, vendored mupdf) and feed structural metadata
 *   to the guard. `KIND="metadata"` — consumes `ctx.metadata` shape
 *   `{ bytes?, hasJavaScript?, hasOpenAction?, hasEmbeddedFiles?,
 *   hasLaunchAction?, isEncrypted?, pageCount?, embeddedFileCount?,
 *   polyglotDetected? }`.
 *
 *   JavaScript exec refusal: `/JS` and `/JavaScript` annotations
 *   trigger RCE in vulnerable readers (the Adobe / Foxit / nitro CVE
 *   class). `metadata.hasJavaScript === true` is refused under every
 *   profile (`javascriptPolicy: "reject"` in strict / balanced /
 *   permissive). The framework refuses to negotiate on this — there
 *   is no audit-only path for executable JavaScript inside a PDF.
 *
 *   Embedded files refusal: `/EmbeddedFile` entries may smuggle
 *   executable payloads inside an otherwise-benign-looking PDF.
 *   `strict` refuses any embedded file (`maxEmbeddedFileCount: 0`);
 *   `balanced` audits up to 10; `permissive` audits up to 100.
 *
 *   OpenAction refusal: `/OpenAction` runs on document open. Standalone
 *   it's a navigation hint; paired with JavaScript or LaunchAction it's
 *   a drive-by trigger. `strict` refuses; `balanced` / `permissive`
 *   audit. JavaScript / LaunchAction are refused independently so the
 *   pairing can't slip through.
 *
 *   GoTo / Launch refusal: `/Launch` actions invoke an external
 *   program (the historical "open this .exe attached to the PDF"
 *   class). Refused under every profile (`launchActionPolicy:
 *   "reject"`). The framework keeps the exec surface closed.
 *
 *   Stream / object caps: `maxPageCount` (strict 500, balanced 5 000,
 *   permissive 50 000), `maxBytes` (strict 64 MiB, balanced 128 MiB,
 *   permissive 512 MiB), `maxEmbeddedFileCount` (strict 0, balanced
 *   10, permissive 100). Operator-supplied — the operator's parser
 *   reports the structural counts; the guard refuses on excess.
 *
 *   Magic-byte check: `%PDF-` header (5 bytes `25 50 44 46 2D`).
 *   Missing magic flagged under `strict` / `balanced` (the operator
 *   may be feeding non-PDF bytes through the wrong gate).
 *
 *   Polyglot rejection: when the operator's parser flags the buffer
 *   as polyglot (`polyglotDetected: true`), the guard refuses under
 *   every profile (`polyglotPolicy: "reject"`).
 *
 *   Encrypted-PDF posture: many AV / sandbox tools can't scan
 *   encrypted documents. `strict` refuses; `balanced` audits;
 *   `permissive` allows.
 *
 *   Operator-feeds-metadata pattern: the gate trusts the metadata
 *   object the operator's parser reports. The framework's no-deps
 *   stance argues against shipping a vendored PDF parser; the
 *   operator's parser is the ground truth and the guard enforces the
 *   policy boundary.
 *
 *   Profiles `strict` / `balanced` / `permissive` and compliance
 *   postures `hipaa` / `pci-dss` / `gdpr` / `soc2` overlay on the
 *   profile baseline.
 *
 * @card
 *   PDF content-safety guard — refuses RCE-class PDF features without vendoring a parser.
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

/**
 * @primitive  b.guardPdf.validate
 * @signature  b.guardPdf.validate(input, opts)
 * @since      0.7.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardPdf.sanitize, b.guardPdf.gate, b.guardPdf.inspectMagic
 *
 * Inspect a PDF metadata bag `{ bytes?, hasJavaScript?, hasOpenAction?,
 * hasLaunchAction?, hasEmbeddedFiles?, isEncrypted?, pageCount?,
 * embeddedFileCount?, polyglotDetected? }` and return `{ ok, issues }`.
 * Detected: `magic-missing` (no `%PDF-` header), `polyglot` (operator-
 * flagged), `javascript-action` (RCE class — universally refused),
 * `launch-action` (universally refused), `open-action` (drive-by
 * class), `embedded-file` / `embedded-file-count`, `encrypted`,
 * `page-count`, `pdf-cap`. Pure inspection — never mutates input or
 * throws on hostile metadata.
 *
 * @opts
 *   profile:           "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   magicPolicy:             "reject"|"audit"|"allow",
 *   javascriptPolicy:        "reject"|"audit"|"allow",   // strict refused — RCE class
 *   openActionPolicy:        "reject"|"audit"|"allow",
 *   launchActionPolicy:      "reject"|"audit"|"allow",   // strict refused — RCE class
 *   embeddedFilePolicy:      "reject"|"audit"|"allow",
 *   encryptedPolicy:         "reject"|"audit"|"allow",
 *   polyglotPolicy:          "reject"|"audit"|"allow",
 *   pageCountPolicy:         "reject"|"audit"|"allow",
 *   embeddedFileCountPolicy: "reject"|"audit"|"allow",
 *   maxPageCount:            number,    // strict 500, balanced 5000, permissive 50000
 *   maxEmbeddedFileCount:    number,    // strict 0, balanced 10, permissive 100
 *   maxBytes:                number,    // strict 64 MiB, balanced 128 MiB, permissive 512 MiB
 *
 * @example
 *   var rv = b.guardPdf.validate({
 *     bytes: Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x37]),
 *     hasJavaScript: true, pageCount: 1,
 *   }, { profile: "strict" });
 *   rv.ok;                                               // → false
 *   rv.issues[0].kind;                                   // → "javascript-action"
 *   rv.issues[0].severity;                               // → "critical"
 *
 *   // LaunchAction — universally refused.
 *   var launch = b.guardPdf.validate({
 *     bytes: Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x37]),
 *     hasLaunchAction: true,
 *   }, { profile: "permissive" });
 *   launch.issues.some(function (i) { return i.kind === "launch-action"; });
 *   //                                                   → true
 */
function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes", "maxPageCount"],
    "guardPdf.validate", GuardPdfError, "pdf.bad-opt");
  // maxEmbeddedFileCount allows 0 (strict refuses all embedded files);
  // skip the positive-finite check.
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

/**
 * @primitive b.guardPdf.sanitize
 * @signature b.guardPdf.sanitize(input, opts)
 * @since     0.7.13
 * @status    stable
 * @related   b.guardPdf.validate, b.guardPdf.gate
 *
 * Best-effort metadata pass-through. PDF byte sanitization
 * (stripping JavaScript actions, embedded files, OpenActions) is
 * the operator parser's responsibility — the guard cannot rewrite
 * the byte stream without a vendored PDF library. `sanitize`
 * validates the metadata against the active profile and re-throws
 * `GuardPdfError` when any issue is `critical` or `high`. Returns
 * the input unchanged when every issue is `warn` or below.
 *
 * @opts
 *   profile:           "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *
 * @example
 *   try {
 *     b.guardPdf.sanitize({
 *       bytes: Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2D]),
 *       hasJavaScript: true,
 *     }, { profile: "strict" });
 *   } catch (e) {
 *     e.code;                                            // → "pdf.javascript-action"
 *   }
 */
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

/**
 * @primitive  b.guardPdf.gate
 * @signature  b.guardPdf.gate(opts)
 * @since      0.7.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardPdf.validate, b.guardPdf.sanitize, b.fileUpload, b.staticServe
 *
 * Build a `b.gateContract` gate suitable for `b.fileUpload({ contentSafety:
 * { "application/pdf": gate } })` or `b.staticServe`. Operators pass
 * `ctx.metadata` (the parser's structural report) plus the original
 * `bytes`. Action chain: `serve` (no issues) → `audit-only`
 * (warn-only) → `refuse` (any critical / high). No `sanitize` action
 * — PDF byte streams can't be rewritten without a vendored parser.
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   name:       string,
 *   ...:        any validate opt
 *
 * @example
 *   var pdfGate = b.guardPdf.gate({ profile: "strict" });
 *
 *   var verdict = await pdfGate.check({
 *     metadata: {
 *       bytes: Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x37]),
 *       hasJavaScript: true, pageCount: 1,
 *     },
 *   });
 *   verdict.action;                                      // → "refuse"
 *   verdict.issues[0].kind;                              // → "javascript-action"
 */
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

/**
 * @primitive b.guardPdf.buildProfile
 * @signature b.guardPdf.buildProfile(opts)
 * @since     0.7.13
 * @status    stable
 * @related   b.guardPdf.compliancePosture, b.guardPdf.gate
 *
 * Resolve a named profile against the guard's PROFILES catalog and
 * return the merged options bag. Throws
 * `GuardPdfError("pdf.bad-profile")` on unknown name.
 *
 * @opts
 *   profile: "strict"|"balanced"|"permissive",
 *
 * @example
 *   var resolved = b.guardPdf.buildProfile({ profile: "strict" });
 *   resolved.javascriptPolicy;                           // → "reject"
 *   resolved.maxPageCount;                               // → 500
 */
var buildProfile = gateContract.makeProfileBuilder(PROFILES);

/**
 * @primitive  b.guardPdf.compliancePosture
 * @signature  b.guardPdf.compliancePosture(name)
 * @since      0.7.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardPdf.gate, b.guardPdf.buildProfile
 *
 * Return the option overlay for a named compliance posture
 * (`"hipaa"` / `"pci-dss"` / `"gdpr"` / `"soc2"`). Throws
 * `GuardPdfError("pdf.bad-posture")` on unknown name.
 *
 * @example
 *   var posture = b.guardPdf.compliancePosture("hipaa");
 *   posture.javascriptPolicy;                            // → "reject"
 *   posture.forensicSnippetBytes;                        // → 512
 */
function compliancePosture(name) {
  return gateContract.lookupCompliancePosture(name, COMPLIANCE_POSTURES,
    _err, "pdf");
}

var _pdfRulePacks = gateContract.makeRulePackLoader(GuardPdfError, "pdf");
/**
 * @primitive b.guardPdf.loadRulePack
 * @signature b.guardPdf.loadRulePack(pack)
 * @since     0.7.13
 * @status    stable
 * @related   b.guardPdf.gate
 *
 * Register an operator-supplied rule pack with the guard-pdf
 * registry. Throws `GuardPdfError("pdf.bad-opt")` when `pack` is
 * missing or `pack.id` is not a non-empty string.
 *
 * @example
 *   var pack = b.guardPdf.loadRulePack({
 *     id: "kb-2026-pdf",
 *     extraMaxPageCount: 200,
 *   });
 *   pack.id;                                             // → "kb-2026-pdf"
 */
var loadRulePack = _pdfRulePacks.load;

/**
 * @primitive b.guardPdf.inspectMagic
 * @signature b.guardPdf.inspectMagic(bytes)
 * @since     0.7.13
 * @status    stable
 * @related   b.guardPdf.validate, b.guardPdf.gate
 *
 * Return `true` when `bytes` starts with the PDF magic header
 * (`%PDF-`, the 5 bytes `25 50 44 46 2D`); `false` otherwise. Pure
 * inspection — never mutates input or throws.
 *
 * @example
 *   var pdfBytes = Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x37]);
 *   b.guardPdf.inspectMagic(pdfBytes);                   // → true
 *
 *   b.guardPdf.inspectMagic(Buffer.from([0x00, 0x01, 0x02]));
 *   //                                                   → false
 */
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
