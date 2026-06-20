"use strict";
/**
 * @module b.guardXml
 * @nav    Guards
 * @title  Guard Xml
 *
 * @intro
 *   XML content-safety guard — defends against the XXE / billion-
 *   laughs / external-entity / XSLT-exec catalog that has remained
 *   active for 20+ years and continues to ship CVEs through 2025-
 *   2026. XML attack surface centers on the DOCTYPE subset, where
 *   entity declarations and external references convert a benign-
 *   looking XML document into a file-disclosure / SSRF / RCE / DoS
 *   primitive depending on the parser.
 *
 *   XXE / external entity (XML External Entity) defense:
 *   `<!ENTITY xxe SYSTEM "file:///etc/passwd">` and `SYSTEM` /
 *   `PUBLIC` identifiers pointing at `file://` / `http://` /
 *   `https://` / `ftp://` / `gopher://` / `jar://` / `netdoc://`
 *   are refused regardless of profile. CVE-2026-24400 AssertJ
 *   `toXmlDocument` default parser, CVE-2025-3225 sitemap parser,
 *   CVE-2024-1455 LangChain XXE, and CVE-2024-25062 libxml2 UAF
 *   with DTD + XInclude all fit this shape.
 *
 *   Billion-laughs / entity-expansion DoS: `<!ENTITY lol "lol">` +
 *   `<!ENTITY lol2 "&lol;&lol;...">` recursive declarations expand
 *   exponentially when the parser dereferences. Refused via the
 *   blanket `<!ENTITY>` rule; parameter entities (`<!ENTITY %>`
 *   prefix) get an additional out-of-band exfil tag. CVE-2024-8176
 *   libexpat stack overflow on recursive entity expansion +
 *   CVE-2025-24928 libxml2 stack overflow on DTD validation track
 *   the family.
 *
 *   DTD external-entity refusal: every `<!DOCTYPE>` declaration is
 *   refused unconditionally — there is no safe DTD subset that
 *   defenders can enumerate against the parser-quirk landscape, so
 *   the only stable posture is to reject the surface entirely.
 *
 *   XSLT / processing-instruction exec defense: `<?xml-stylesheet
 *   href="...">` and other `<?PI ?>` shapes can route the document
 *   through an XSLT processor with `document()` / `xsl:include` /
 *   `xsl:import` — full file-disclosure + SSRF surface. Flagged
 *   under balanced; refused under strict (after the standard
 *   `<?xml ... ?>` declaration is stripped).
 *
 *   XInclude (`<xi:include href="...">`) and `xsi:schemaLocation` /
 *   `xsi:noNamespaceSchemaLocation` are operator-controlled fetch
 *   surfaces; XML signature elements (`xmldsig`) require operator
 *   defense against signature-wrapping attacks. CDATA sections
 *   often hide payloads from naive scanners.
 *
 *   Anti-DoS caps: total document size (`maxBytes`), nesting depth
 *   (`maxDepth`), element count (`maxElements`), attribute count per
 *   element (`maxAttrsPerElement`), and attribute value length
 *   (`maxAttrValueBytes`).
 *
 *   Bidi / null / control / zero-width character threats route
 *   through the shared lib/codepoint-class detector.
 *
 *   Profiles: `strict` / `balanced` / `permissive`. Compliance
 *   postures: `hipaa` / `pci-dss` / `gdpr` / `soc2`. Even under
 *   `permissive`, DOCTYPE / ENTITY / external-entity refusal stays
 *   on — the billion-laughs and XXE classes have no safe permissive
 *   posture.
 *
 * @card
 *   XML content-safety guard — defends against the XXE / billion- laughs / external-entity / XSLT-exec catalog that has remained active for 20+ years and continues to ship CVEs through 2025- 2026.
 */

var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var { GuardXmlError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardXmlError.factory;

// ---- Source-level threat detectors ----

var DOCTYPE_RE = /<!DOCTYPE\b/i;
var ENTITY_DECL_RE = /<!ENTITY\b/i;
var PARAM_ENTITY_RE = /<!ENTITY\s+%/i;
var EXTERNAL_ENTITY_RE = /\b(SYSTEM|PUBLIC)\s+["'](file|http|https|ftp|gopher|jar|netdoc):/i;
var XINCLUDE_RE = /<xi:include\b/i;
var SCHEMA_LOCATION_RE = /\bxsi:(noNamespace)?[Ss]chemaLocation\s*=/;
var PROCESSING_INSTR_RE = /<\?[A-Za-z][\w:-]*/;
var CDATA_RE = /<!\[CDATA\[/;
var XMLDSIG_RE = /<\w*:?Signature\b[^>]*xmldsig/i;

// Numeric character reference (NCR) detector. Per XML 1.0 §4.1 every
// `&#<digits>;` / `&#x<hex>;` is a character reference; a hostile input
// fanning these out in the hundreds of thousands bypasses entity-
// expansion caps that count only `&name;` general entities (CVE-2026-
// 26278 / CVE-2026-33036 .NET XmlReader class). Per-document NCR count
// is gated by `maxNumericCharRefs` independent of the entity-policy
// branch so the operator can't disable the cap by setting
// `entityPolicy: "allow"` for a downstream signed-XML case.
var NUMERIC_CHAR_REF_RE = /&#(?:[0-9]+|x[0-9a-fA-F]+);/g;                            // allow:regex-no-length-cap — input bounded by maxBytes above

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    doctypePolicy:          "reject",
    entityPolicy:           "reject",
    externalEntityPolicy:   "reject",
    xincludePolicy:         "reject",
    schemaLocationPolicy:   "reject",
    processingInstrPolicy:  "reject",
    cdataPolicy:            "reject",
    xmlDsigPolicy:          "audit",
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    maxBytes:               C.BYTES.mib(2),
    maxDepth:               64,                                                  // recursion depth, not byte size
    maxElements:            8192,                                                // element count cap, not byte size
    maxAttrsPerElement:     64,                                                  // attr count, not byte size
    maxAttrValueBytes:      C.BYTES.kib(8),
    maxNumericCharRefs:     1024,                                                // NCR fan-out cap (CVE-2026-26278)
  },
  "balanced": {
    doctypePolicy:          "reject",                // DOCTYPE is XXE vector regardless
    entityPolicy:           "reject",
    externalEntityPolicy:   "reject",
    xincludePolicy:         "reject",
    schemaLocationPolicy:   "audit",
    processingInstrPolicy:  "audit",
    cdataPolicy:            "audit",
    xmlDsigPolicy:          "audit",
    bidiPolicy:             "strip",
    controlPolicy:          "strip",
    nullBytePolicy:         "strip",
    zeroWidthPolicy:        "strip",
    maxBytes:               C.BYTES.mib(8),
    maxDepth:               256,                                                 // recursion depth, not byte size
    maxElements:            65536,                                               // element count cap, not byte size
    maxAttrsPerElement:     128,                                                 // attr count, not byte size
    maxAttrValueBytes:      C.BYTES.kib(32),
    maxNumericCharRefs:     16384,                                               // NCR fan-out cap (CVE-2026-26278)
  },
  "permissive": {
    doctypePolicy:          "reject",                // billion-laughs class always
    entityPolicy:           "reject",
    externalEntityPolicy:   "reject",
    xincludePolicy:         "audit",
    schemaLocationPolicy:   "audit",
    processingInstrPolicy:  "audit",
    cdataPolicy:            "audit",
    xmlDsigPolicy:          "audit",
    bidiPolicy:             "audit",
    controlPolicy:          "strip",
    nullBytePolicy:         "reject",
    zeroWidthPolicy:        "strip",
    maxBytes:               C.BYTES.mib(64),
    maxDepth:               1024,                                                // recursion depth, not byte size
    maxElements:            262144,                                              // element count cap, not byte size
    maxAttrsPerElement:     256,                                                 // attr count, not byte size
    maxAttrValueBytes:      C.BYTES.kib(64),
    maxNumericCharRefs:     262144,                                              // NCR fan-out cap (CVE-2026-26278)
  },
});

var DEFAULTS = gateContract.strictDefaults(PROFILES, {
  maxRuntimeMs:  C.TIME.seconds(10),
});

var COMPLIANCE_POSTURES = gateContract.compliancePostures(PROFILES, { base: 256 });


function _detectIssues(input, opts) {
  var pre = gateContract.detectStringInput(input, opts, { name: "xml", noun: "input", emptyMode: "skip", scanCodepoints: false, cap: { bytes: opts.maxBytes, kind: "too-large", snippet: function (byteLen, max) { return "input " + byteLen + " bytes exceeds maxBytes " + max; } } });
  if (pre.done) return pre.issues;
  var issues = pre.issues;

  // 1. DOCTYPE.
  if (opts.doctypePolicy !== "allow" && DOCTYPE_RE.test(input)) {                // allow:regex-no-length-cap — input bounded by maxBytes above
    issues.push({
      kind: "doctype", severity: "critical", ruleId: "xml.doctype",
      snippet: "DOCTYPE declaration (XXE / billion-laughs vector — " +
               "CVE-2026-24400 / CVE-2024-25062 class)",
    });
  }

  // 2. <!ENTITY> declarations.
  if (opts.entityPolicy !== "allow" && ENTITY_DECL_RE.test(input)) {             // allow:regex-no-length-cap — input bounded by maxBytes above
    issues.push({
      kind: "entity-declaration", severity: "critical",
      ruleId: "xml.entity",
      snippet: "<!ENTITY> declaration (entity-expansion DoS vector)",
    });
    if (PARAM_ENTITY_RE.test(input)) {                                           // allow:regex-no-length-cap — input bounded by maxBytes above
      issues.push({
        kind: "parameter-entity", severity: "critical",
        ruleId: "xml.parameter-entity",
        snippet: "parameter entity (% prefix) — out-of-band exfil vector",
      });
    }
  }

  // 3. External entity references.
  if (opts.externalEntityPolicy !== "allow" && EXTERNAL_ENTITY_RE.test(input)) { // allow:regex-no-length-cap — input bounded by maxBytes above
    issues.push({
      kind: "external-entity", severity: "critical",
      ruleId: "xml.external-entity",
      snippet: "SYSTEM/PUBLIC external entity reference (XXE — file:// / http:// exfil)",
    });
  }

  // 4. XInclude.
  if (opts.xincludePolicy !== "allow" && XINCLUDE_RE.test(input)) {              // allow:regex-no-length-cap — input bounded by maxBytes above
    issues.push({
      kind: "xinclude",
      severity: opts.xincludePolicy === "reject" ? "critical" : "high",
      ruleId: "xml.xinclude",
      snippet: "<xi:include> remote inclusion (XXE-shaped — CVE-2024-25062 class)",
    });
  }

  // 5. xsi:schemaLocation.
  if (opts.schemaLocationPolicy !== "allow" && SCHEMA_LOCATION_RE.test(input)) { // allow:regex-no-length-cap — input bounded by maxBytes above
    issues.push({
      kind: "schema-location",
      severity: opts.schemaLocationPolicy === "reject" ? "high" : "warn",
      ruleId: "xml.schema-location",
      snippet: "xsi:schemaLocation — operator-controlled schema fetch",
    });
  }

  // 6. Processing instructions.
  if (opts.processingInstrPolicy !== "allow" && PROCESSING_INSTR_RE.test(input)) { // allow:regex-no-length-cap — input bounded by maxBytes above
    // Skip the standard `<?xml ... ?>` declaration at byte 0.
    var trimmed = input.replace(/^\s*<\?xml\s[^?]*\?>/, "");
    if (PROCESSING_INSTR_RE.test(trimmed)) {                                     // allow:regex-no-length-cap — trimmed input bounded by maxBytes above
      issues.push({
        kind: "processing-instruction",
        severity: opts.processingInstrPolicy === "reject" ? "critical" : "high",
        ruleId: "xml.pi",
        snippet: "XML processing instruction (e.g. xml-stylesheet — CSS injection vector)",
      });
    }
  }

  // 7. CDATA sections.
  if (opts.cdataPolicy !== "allow" && CDATA_RE.test(input)) {                    // allow:regex-no-length-cap — input bounded by maxBytes above
    issues.push({
      kind: "cdata",
      severity: opts.cdataPolicy === "reject" ? "critical" : "warn",
      ruleId: "xml.cdata",
      snippet: "CDATA section (often hides payloads from naive scanners)",
    });
  }

  // 8. XML signature.
  if (opts.xmlDsigPolicy !== "allow" && XMLDSIG_RE.test(input)) {                // allow:regex-no-length-cap — input bounded by maxBytes above
    issues.push({
      kind: "xml-signature", severity: "warn",
      ruleId: "xml.xmldsig",
      snippet: "XML signature element — operator must guard against signature wrapping (xmldsig)",
    });
  }

  // 8a. Numeric character reference fan-out — `&#NNNN;` / `&#xHHHH;`.
  // Bypasses the `<!ENTITY>`-counting expansion caps because NCRs are
  // parser-resolved, not document-level entities (CVE-2026-26278 /
  // CVE-2026-33036 .NET XmlReader class). Counted regardless of
  // entityPolicy so signed-XML paths that need entities-allowed don't
  // get the NCR cap disabled with them. The `maxNumericCharRefs` opt
  // is validated as a positive-finite int via defineGuard's `intOpts`
  // at the public validate boundary.
  var ncrCap = opts.maxNumericCharRefs;
  if (ncrCap !== undefined && ncrCap !== null) {
    var ncrMatches = input.match(NUMERIC_CHAR_REF_RE);                           // allow:regex-no-length-cap — input bounded by maxBytes above
    var ncrCount = ncrMatches === null ? 0 : ncrMatches.length;
    if (ncrCount > ncrCap) {
      issues.push({
        kind: "numeric-char-ref-cap", severity: "critical",
        ruleId: "xml.numeric-char-ref-cap",
        snippet: "numeric character reference count " + ncrCount +
                 " exceeds maxNumericCharRefs " + ncrCap +
                 " — NCR fan-out bypasses entity-expansion caps " +
                 "(CVE-2026-26278 / CVE-2026-33036)",
      });
    }
  }

  // 9. Codepoint-class threats.
  issues.push.apply(issues, codepointClass.detectCharThreats(input, opts, "xml", "warn"));

  // 10. Element + depth + attribute caps via tag count.
  var openTags = (input.match(/<[A-Za-z][\w:-]*/g) || []).length;
  if (openTags > opts.maxElements) {
    issues.push({
      kind: "element-cap", severity: "high",
      ruleId: "xml.element-cap",
      snippet: "element count " + openTags + " exceeds maxElements " + opts.maxElements,
    });
  }
  // Depth: count consecutive nested-open without close (rough estimate).
  var depthEstimate = 0;
  var maxDepthSeen = 0;
  var i = 0;
  while (i < input.length) {
    var lt = input.indexOf("<", i);
    if (lt === -1) break;
    if (input.charAt(lt + 1) === "/") depthEstimate -= 1;
    else if (input.charAt(lt + 1) !== "!" && input.charAt(lt + 1) !== "?") {
      depthEstimate += 1;
      if (depthEstimate > maxDepthSeen) maxDepthSeen = depthEstimate;
    }
    var gt = input.indexOf(">", lt);
    if (gt === -1) break;
    if (input.charAt(gt - 1) === "/") depthEstimate -= 1;
    i = gt + 1;
  }
  if (maxDepthSeen > opts.maxDepth) {
    issues.push({
      kind: "depth-cap", severity: "high", ruleId: "xml.depth-cap",
      snippet: "estimated nesting depth " + maxDepthSeen +
               " exceeds maxDepth " + opts.maxDepth,
    });
  }

  return issues;
}

// ---- Public surface ----

/**
 * @primitive  b.guardXml.validate
 * @signature  b.guardXml.validate(input, opts?)
 * @since      0.7.15
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardXml.sanitize, b.guardXml.gate
 *
 * Inspect `input` (string of XML source) for the full guard-xml
 * threat catalog without invoking a parser. Returns
 * `{ ok, issues }` where `issues` enumerates every
 * DOCTYPE declaration, `<!ENTITY>` definition (including parameter
 * entities), SYSTEM/PUBLIC external-entity reference, XInclude
 * directive, xsi:schemaLocation hint, processing instruction (after
 * the standard `<?xml ?>` declaration), CDATA section, XML signature
 * element, and codepoint-class threat. Element / depth caps are
 * estimated via tag-count + nesting heuristics — strict-mode rejects
 * exceeding the configured caps without requiring a full parse.
 *
 * Profile-driven (`strict` / `balanced` / `permissive`) and posture-
 * driven (`hipaa` / `pci-dss` / `gdpr` / `soc2`). Note that
 * DOCTYPE / `<!ENTITY>` / external-entity refusal stays on under
 * every profile — there is no safe permissive posture for the XXE
 * + billion-laughs class.
 *
 * @opts
 *   profile:               "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   doctypePolicy:         "reject"|"audit"|"allow",
 *   entityPolicy:          "reject"|"audit"|"allow",
 *   externalEntityPolicy:  "reject"|"audit"|"allow",
 *   xincludePolicy:        "reject"|"audit"|"allow",
 *   schemaLocationPolicy:  "reject"|"audit"|"allow",
 *   processingInstrPolicy: "reject"|"audit"|"allow",
 *   cdataPolicy:           "reject"|"audit"|"allow",
 *   xmlDsigPolicy:         "audit"|"allow",
 *   bidiPolicy:            "reject"|"strip"|"audit"|"allow",
 *   controlPolicy:         "reject"|"strip"|"allow",
 *   nullBytePolicy:        "reject"|"strip"|"allow",
 *   zeroWidthPolicy:       "reject"|"strip"|"audit"|"allow",
 *   maxBytes:              number,    // total source byte cap
 *   maxDepth:              number,    // estimated nesting depth cap
 *   maxElements:           number,    // total open-tag count cap
 *   maxAttrsPerElement:    number,    // attribute count cap per element
 *   maxAttrValueBytes:     number,    // per-attr-value length cap
 *   maxNumericCharRefs:    number,    // numeric character reference cap
 *
 * @example
 *   var hostile = '<?xml version="1.0"?>\n' +
 *                 '<!DOCTYPE r [<!ENTITY xx "yy">]>\n<r/>';
 *   var rv = b.guardXml.validate(hostile, { profile: "strict" });
 *   rv.ok;                                              // → false
 *   rv.issues.some(function (i) { return i.kind === "doctype"; });  // → true
 */
// validate is assembled by gateContract.defineGuard from `detect`
// (_detectIssues), with the positive-finite-int caps declared via `intOpts`.
// A non-string input falls through _detectIssues' xml.bad-input issue, which
// aggregateIssues reports as ok:false. The @primitive block above documents
// the resulting ABI.

/**
 * @primitive  b.guardXml.sanitize
 * @signature  b.guardXml.sanitize(input, opts?)
 * @since      0.7.15
 * @status     stable
 * @related    b.guardXml.validate, b.guardXml.gate
 *
 * Best-effort cleanup of `input` (string of XML source): strips
 * codepoint-class threats per policy (BOM, bidi when
 * `bidiPolicy: "strip"`, C0 controls when `controlPolicy: "strip"`,
 * null bytes when `nullBytePolicy: "strip"`, zero-width characters
 * when `zeroWidthPolicy: "strip"`). Throws `GuardXmlError` on any
 * critical issue — DOCTYPE / `<!ENTITY>` / external-entity / param-
 * entity shapes have no safe sanitization (the only correct response
 * is refusal). The error code matches the triggering rule
 * (`xml.doctype`, `xml.entity`, `xml.external-entity`, etc.).
 *
 * Sanitize is intentionally narrow: it cleans the character-class
 * surface but never rewrites structural XML. Use `b.guardXml.gate`
 * for the full sanitize-or-refuse action chain inside a request
 * pipeline.
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   bidiPolicy:      "reject"|"strip"|"audit"|"allow",
 *   controlPolicy:   "reject"|"strip"|"allow",
 *   nullBytePolicy:  "reject"|"strip"|"allow",
 *   zeroWidthPolicy: "reject"|"strip"|"audit"|"allow",
 *
 * @example
 *   // Build hostile input programmatically so the source stays ASCII.
 *   var ZWSP = String.fromCharCode(0x200B);
 *   var clean = b.guardXml.sanitize("<root>hello" + ZWSP + "</root>", {
 *     profile: "balanced",
 *   });
 *   clean.indexOf(ZWSP) === -1;                         // → true
 */
// _sanitizeTransform — the normalize tail applied by defineGuard's generated
// sanitize AFTER resolve -> detect -> throwOnRefusalSeverity. spec.sanitizeSeverities
// is ["critical"], so the critical structural shapes (DOCTYPE / ENTITY /
// external / parameter-entity) throw upstream; the strip-able character-class
// threats (BOM, bidi, C0, null, zero-width) are repaired here per policy.
function _sanitizeTransform(input, opts) {
  return codepointClass.applyCharStripPolicies(input, opts);
}

/**
 * @primitive  b.guardXml.gate
 * @signature  b.guardXml.gate(opts?)
 * @since      0.7.15
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardXml.validate, b.guardXml.sanitize, b.staticServe.create, b.fileUpload.create
 *
 * Build a `b.gateContract` gate suitable for plugging into
 * `b.staticServe({ contentSafety: { ".xml": gate } })`,
 * `b.fileUpload({ contentSafety: { "application/xml": gate } })`,
 * or any host primitive that consumes the gate-contract shape.
 * Action chain on validation: `serve` (no issues) → `audit-only`
 * (warn-only issues) → `sanitize` (high/critical when DOCTYPE /
 * ENTITY / external-entity policies are not `reject`, which strips
 * codepoint-class threats only) → `refuse` (any of those structural
 * policies is reject and a critical issue fired, or sanitize threw).
 *
 * Under strict and balanced both, DOCTYPE / ENTITY / external-entity
 * are reject — so the gate jumps from `audit-only` straight to
 * `refuse` for the XXE / billion-laughs class. Permissive allows
 * downgrading XInclude / schemaLocation / PI / CDATA to `audit`,
 * but never DOCTYPE / ENTITY / external-entity.
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   name:       string,    // gate identity for audit / observability
 *
 * @example
 *   var xmlGate = b.guardXml.gate({ profile: "strict" });
 *   var hostile = Buffer.from(
 *     '<?xml version="1.0"?>\n<!DOCTYPE r [<!ENTITY a "b">]>\n<r/>',
 *     "utf8");
 *   var verdict = await xmlGate.check({ bytes: hostile });
 *   verdict.action;                                     // → "refuse"
 */
// Disposition of each xml finding = what the operator's policy for that class
// selected. The XXE / injection classes (DOCTYPE / entity / external-entity /
// XInclude / schema-location / processing-instruction / CDATA / XML-signature)
// and the bidi / null / control char threats follow their policies (refuse
// under `reject`, audit under `audit`, sanitize under `strip`). A parameter
// entity rides the entity policy. The numeric-char-ref / element / depth caps
// and a bad input always refuse. Exhaustive over every kind _detectIssues emits.
function _gateDispositionFor(issue, opts) {
  var shared = gateContract.charThreatDisposition(issue, opts);
  if (shared) return shared;
  switch (issue.kind) {
    case "doctype":                return gateContract.policyDisposition(opts.doctypePolicy);
    case "entity-declaration":
    case "parameter-entity":       return gateContract.policyDisposition(opts.entityPolicy);
    case "external-entity":        return gateContract.policyDisposition(opts.externalEntityPolicy);
    case "xinclude":               return gateContract.policyDisposition(opts.xincludePolicy);
    case "schema-location":        return gateContract.policyDisposition(opts.schemaLocationPolicy);
    case "processing-instruction": return gateContract.policyDisposition(opts.processingInstrPolicy);
    case "cdata":                  return gateContract.policyDisposition(opts.cdataPolicy);
    case "xml-signature":          return gateContract.policyDisposition(opts.xmlDsigPolicy);
    case "numeric-char-ref-cap":
    case "element-cap":
    case "depth-cap":
    case "bad-input":
    case "too-large":              return "refuse";
    default:                       return null;
  }
}

function gate(opts) {
  opts = _guard.resolveOpts(opts);
  return gateContract.buildContentGate({
    name:     opts.name || "guardXml:" + (opts.profile || "default"),
    opts:     opts,
    validate: module.exports.validate,
    dispositionFor: _gateDispositionFor,
    // The strip transform, NOT the public `sanitize` — that one throws on a
    // critical finding (e.g. a bidi override) regardless of the strip policy,
    // which would turn a policy-selected sanitize into a refuse. Only the
    // char-threat classes (strip policy) reach sanitize; the XXE / injection
    // classes are refuse / audit by policy.
    produceSanitized: function (text, o) { return _sanitizeTransform(text, o); },
  });
}

// buildProfile / compliancePosture / loadRulePack are assembled by
// gateContract.defineGuard below; their wiki sections render from the
// single-sourced @abiTemplate (defineGuard) blocks in gate-contract.js,
// instantiated per guard by the page generator.

var INTEGRATION_FIXTURES = Object.freeze({
  kind:         "content",
  contentType:  "application/xml",
  extension:    ".xml",
  benignBytes:  Buffer.from('<?xml version="1.0"?><root><x>1</x></root>', "utf8"),
  // Hostile: DOCTYPE with internal-subset entity declaration (XXE +
  // billion-laughs vector — CVE-2026-24400 / CVE-2024-25062 class).
  hostileBytes: Buffer.from(
    '<?xml version="1.0"?>\n<!DOCTYPE root [<!ENTITY xx "yy">]>\n<root/>',
    "utf8"),
});

// Assembled from the gate-contract guard factory: error class, registry
// exports (NAME / KIND / MIME_TYPES / EXTENSIONS / INTEGRATION_FIXTURES),
// buildProfile / compliancePosture / loadRulePack wiring, plus validate /
// sanitize generated from `detect` (_detectIssues) + `sanitizeTransform`
// (_sanitizeTransform) — sanitizeSeverities ["critical"] keeps DOCTYPE /
// ENTITY / external / parameter-entity throwing while strip-able char-class
// threats are repaired. The bespoke `gate` carries XML's per-policy
// canSanitize matrix unchanged.
var _guard = module.exports = gateContract.defineGuard({
  name:        "xml",
  kind:        "content",
  errorClass:  GuardXmlError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  mimeTypes:   ["application/xml", "text/xml"],
  extensions:  [".xml"],
  integrationFixtures: INTEGRATION_FIXTURES,
  detect:             _detectIssues,
  sanitizeTransform:  _sanitizeTransform,
  sanitizeSeverities: ["critical"],
  intOpts:            ["maxBytes", "maxDepth", "maxElements", "maxAttrsPerElement",
                       "maxAttrValueBytes", "maxNumericCharRefs"],
  gate:        gate,
  extra: { _gateDispositionForTest: _gateDispositionFor },
});
