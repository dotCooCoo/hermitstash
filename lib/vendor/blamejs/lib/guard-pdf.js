// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
var safeBuffer = require("./safe-buffer");
var gateContract = require("./gate-contract");
var C = require("./constants");
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
    maxPageCount:              500,                                              // page-count ceiling
    maxEmbeddedFileCount:      0,                                                // strict refuses any embedded file
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
    maxPageCount:              5000,                                             // page-count ceiling
    maxEmbeddedFileCount:      10,                                               // embedded file ceiling
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
    maxPageCount:              50000,                                            // page-count ceiling
    maxEmbeddedFileCount:      100,                                              // embedded file ceiling
    maxBytes:                  C.BYTES.mib(512),
    maxRuntimeMs:              C.TIME.seconds(5),
  },
});

var DEFAULTS = gateContract.strictDefaults(PROFILES);

var COMPLIANCE_POSTURES = gateContract.compliancePostures(PROFILES, { base: 512 });

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

  // Measure the byte cap only for measurable values. A hostile bag whose
  // `bytes` is a plain Array or array-like object carries a numeric `.length`
  // but is NOT a byte-carrier — measuring it would throw, breaking validate's
  // documented never-throw-on-hostile-metadata contract; byteLengthOfIfMeasurable
  // returns null for those, so the cap is skipped (magic detection reads only
  // the leading bytes, O(1)-bounded regardless of the reported size) instead of
  // crashing the caller.
  var bytes = metadata.bytes;
  var byteCount = safeBuffer.byteLengthOfIfMeasurable(bytes);
  if (byteCount !== null && byteCount > opts.maxBytes) {
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
// validate is assembled by gateContract.defineGuard from `detect`
// (_detectIssues) below — `validate(input, opts) = aggregateIssues(detect(
// input, resolveOpts(opts)))`, with the maxBytes / maxPageCount caps
// declared via `intOpts`. maxEmbeddedFileCount allows 0 (strict refuses all
// embedded files) so it is NOT an intOpt — the positive-finite check would
// reject the strict default. The @primitive block above documents the
// resulting public ABI.

/**
 * @primitive b.guardPdf.sanitize
 * @signature b.guardPdf.sanitize(input, opts)
 * @since     0.7.13
 * @status    stable
 * @related   b.guardPdf.validate, b.guardPdf.gate
 *
 * Disarm-by-refusal. PDF active content (`/JavaScript`, `/Launch`,
 * `/OpenAction`, embedded files) and encryption live in a
 * cross-referenced object graph; excising them safely needs a vendored
 * PDF parser, which the framework does not ship (a parser per format is
 * a supply-chain hop, and a fragile in-house excision on a security
 * primitive is worse than an honest refusal). So `sanitize` forces every
 * active-content / exfil / encryption policy to `reject` and re-throws
 * `GuardPdfError` on any finding — it never hands back a PDF that still
 * carries JavaScript, a launch/open action, embedded files, or
 * encryption. A PDF with none of these passes through unchanged
 * (genuinely nothing to strip). Operators needing a repaired file run a
 * vendored disarm tool (e.g. `qpdf --decrypt` plus removing
 * `/OpenAction` / `/Names` / `/JavaScript`).
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
  var resolved = module.exports.resolveOpts(opts);
  // Force the active-content / exfil / encryption policies to reject, then
  // refuse anything the validate chain flags. The object graph can't be
  // edited without a parser, so disarm collapses to "refuse if not already
  // inert" — never a silent passthrough of a live action. Every active-content
  // policy is pinned to "reject" here so an operator-supplied permissive opt
  // (javascriptPolicy / launchActionPolicy / polyglotPolicy: "allow" | "audit")
  // cannot make disarm hand back a live PDF — the RCE / polyglot classes the
  // guard "refuses to negotiate" on must be pinned exactly as the exfil /
  // encryption ones are, or the override is only half-applied.
  var strict = Object.assign({}, resolved, {
    magicPolicy:             "reject",
    javascriptPolicy:        "reject",
    launchActionPolicy:      "reject",
    openActionPolicy:        "reject",
    embeddedFilePolicy:      "reject",
    embeddedFileCountPolicy: "reject",
    encryptedPolicy:         "reject",
    polyglotPolicy:          "reject",
  });
  var issues = _detectIssues(input, strict);
  gateContract.throwOnRefusalSeverity(issues,
    { errorClass: GuardPdfError, codePrefix: "pdf" });
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
 * (warn-only) → `refuse` (any critical / high). The gate does not
 * rewrite bytes; `b.guardPdf.sanitize(bag)` is disarm-by-refusal (it
 * refuses any PDF still carrying active content / embedded files /
 * encryption rather than silently passing it through).
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
  opts = gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardPdfError,
    errCodePrefix:      "pdf",
  });
  return gateContract.buildGuardGate(
    opts.name || "guardPdf:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var meta = ctx && (ctx.metadata || ctx.pdfMetadata);
      if (!meta) return { ok: true, action: "serve" };
      var rv = module.exports.validate(meta, opts);
      return gateContract.severityDisposition(rv.issues);
    });
}

// buildProfile / compliancePosture / loadRulePack are assembled by
// gateContract.defineGuard below (makeProfileBuilder(PROFILES) /
// lookupCompliancePosture(_, COMPLIANCE_POSTURES) / makeRulePackLoader).
// Their wiki sections render from the single-sourced @abiTemplate blocks
// in gate-contract.js, instantiated per guard by the page generator.

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

// ---- adaptive integration-test fixtures (consumed by layer-5 host harness) ----
var INTEGRATION_FIXTURES = Object.freeze({
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
});

// Assembled from the gate-contract guard factory: error class, registry
// exports (NAME / KIND / INTEGRATION_FIXTURES), buildProfile /
// compliancePosture / loadRulePack wiring, plus the per-guard inspection
// surface. validate + sanitize are generated from `detect` (_detectIssues)
// and `sanitizeTransform` (_sanitizeTransform) with the positive-finite-int
// caps declared via `intOpts` (maxEmbeddedFileCount is excluded — strict
// defaults it to 0). The pdf extra (inspectMagic) passes through verbatim.
// KIND="metadata" is a custom kind, so the bespoke `gate`
// (operator-feeds-metadata ctx.metadata reader) is REQUIRED and carries the
// JavaScript / launch-action / embedded-file chain unchanged.
module.exports = gateContract.defineGuard({
  name:        "pdf",
  kind:        "metadata",
  errorClass:  GuardPdfError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  integrationFixtures: INTEGRATION_FIXTURES,
  // detect reads a structured `{ bytes, hasJavaScript, ... }` metadata report,
  // not text. The generated validate's default "raw" input contract hands the
  // bag straight to detect (which owns its own bad-input).
  detect:            _detectIssues,
  sanitize:          sanitize,
  intOpts:           ["maxBytes", "maxPageCount"],
  gate:        gate,
  extra: {
    inspectMagic: inspectMagic,
  },
});
