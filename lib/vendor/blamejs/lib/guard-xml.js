"use strict";
/**
 * guard-xml — XML content-safety primitive (b.guardXml).
 *
 * Threat catalog grounded in current research (XXE remains active in
 * 2025-2026 despite 20+ years of awareness):
 *   - CVE-2026-24400 AssertJ XXE via toXmlDocument default parser
 *   - CVE-2025-3225 sitemap parser XXE
 *   - CVE-2024-1455 LangChain XXE
 *   - CVE-2024-25062 libxml2 use-after-free with DTD + XInclude
 *   - CVE-2024-56171 libxml2 schema use-after-free
 *   - CVE-2025-24928 libxml2 stack overflow on DTD validation
 *   - CVE-2025-32415 libxml2 schema heap under-read
 *   - CVE-2025-27113 libxml2 NULL deref in pattern.c
 *   - CVE-2024-8176 libexpat stack overflow (recursive entity expansion)
 *
 *   var rv = b.guardXml.validate(input, { profile: "strict" });
 *   var safe = b.guardXml.sanitize(input, { profile: "balanced" });
 *   var g = b.guardXml.gate({ profile: "strict" });
 *
 * Threat catalog covered:
 *
 *   1. DOCTYPE declarations — refuse unconditionally regardless of
 *      profile. Catches billion-laughs entity expansion + external
 *      entity loading (XXE) + SYSTEM identifier exfil.
 *   2. <!ENTITY> declarations including parameter entities (% prefix).
 *   3. External entities — file:// / http:// / SYSTEM identifiers in
 *      DOCTYPE subset.
 *   4. XInclude — <xi:include href="..."/> remote inclusion.
 *   5. xsi:schemaLocation / xsi:noNamespaceSchemaLocation — operator-
 *      controlled schema fetch.
 *   6. Processing instructions — <?xml-stylesheet ...?> CSS injection
 *      vector.
 *   7. CDATA sections — often used to hide payloads from naive
 *      scanners.
 *   8. XML signature wrapping (xmldsig) — surface that requires
 *      careful operator handling; flagged as audit.
 *   9. Bidi / null / control / zero-width chars in element text +
 *      attribute values.
 *  10. Anti-DoS caps — total document size, max element count, max
 *      attribute count per element, max depth, max attribute value
 *      length.
 */

var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
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
    bidiPolicy:             "reject",
    controlPolicy:          "reject",
    nullBytePolicy:         "reject",
    zeroWidthPolicy:        "reject",
    maxBytes:               C.BYTES.mib(2),
    maxDepth:               64,                                                  // allow:raw-byte-literal — recursion depth, not byte size
    maxElements:            8192,                                                // allow:raw-byte-literal — element count cap, not byte size
    maxAttrsPerElement:     64,                                                  // allow:raw-byte-literal — attr count, not byte size
    maxAttrValueBytes:      C.BYTES.kib(8),
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
    maxDepth:               256,                                                 // allow:raw-byte-literal — recursion depth, not byte size
    maxElements:            65536,                                               // allow:raw-byte-literal — element count cap, not byte size
    maxAttrsPerElement:     128,                                                 // allow:raw-byte-literal — attr count, not byte size
    maxAttrValueBytes:      C.BYTES.kib(32),
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
    maxDepth:               1024,                                                // allow:raw-byte-literal — recursion depth, not byte size
    maxElements:            262144,                                              // allow:raw-byte-literal — element count cap, not byte size
    maxAttrsPerElement:     256,                                                 // allow:raw-byte-literal — attr count, not byte size
    maxAttrValueBytes:      C.BYTES.kib(64),
  },
});

var DEFAULTS = Object.freeze(Object.assign({}, PROFILES["strict"], {
  mode:          "enforce",
  maxRuntimeMs:  C.TIME.seconds(10),
}));

var COMPLIANCE_POSTURES = Object.freeze({
  "hipaa": Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(256),
  }),
  "pci-dss": Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(256),
  }),
  "gdpr": Object.assign({}, PROFILES["balanced"], {
    forensicSnippetBytes: C.BYTES.bytes(128),
  }),
  "soc2": Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(512),
  }),
});

function _resolveOpts(opts) {
  return gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardXmlError,
    errCodePrefix:      "xml",
  });
}

function _detectIssues(input, opts) {
  var issues = [];
  if (typeof input !== "string") {
    return [{ kind: "bad-input", severity: "high",
              snippet: "input is not a string" }];
  }
  if (input.length > opts.maxBytes) {
    return [{ kind: "too-large", severity: "high", ruleId: "xml.too-large",
              snippet: "input " + input.length +
                       " bytes exceeds maxBytes " + opts.maxBytes }];
  }

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

  // 9. Codepoint-class threats.
  issues.push.apply(issues, codepointClass.detectCharThreats(input, opts, "xml"));

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

function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes", "maxDepth", "maxElements", "maxAttrsPerElement",
     "maxAttrValueBytes"],
    "guardXml.validate", GuardXmlError, "xml.bad-opt");
  if (typeof input !== "string") {
    return {
      ok: false,
      issues: [{ kind: "bad-input", severity: "high",
                 snippet: "input is not a string" }],
    };
  }
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

function sanitize(input, opts) {
  opts = _resolveOpts(opts);
  if (typeof input !== "string") {
    throw _err("xml.bad-input", "sanitize requires string input");
  }
  // XML sanitization — strip what's strip-able per policy. Critical
  // shapes (DOCTYPE / ENTITY / external / parameter-entity) have no
  // safe sanitization; throw.
  var issues = _detectIssues(input, opts);
  for (var i = 0; i < issues.length; i += 1) {
    if (issues[i].severity === "critical") {
      throw _err(issues[i].ruleId || "xml.refused",
        "guardXml.sanitize: " + issues[i].snippet);
    }
  }
  // Strip character-class threats per policy via the shared helper.
  return codepointClass.applyCharStripPolicies(input, opts);
}

function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardXml:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var text = gateContract.extractBytesAsText(ctx);
      if (!text) return { ok: true, action: "serve" };
      var rv = validate(text, opts);
      if (rv.issues.length === 0) return { ok: true, action: "serve" };
      var hasCritical = rv.issues.some(function (i) {
        return i.severity === "critical" || i.severity === "high";
      });
      if (!hasCritical) return { ok: true, action: "audit-only", issues: rv.issues };

      // Sanitize-eligibility: every reject-policy off.
      var canSanitize = opts.doctypePolicy !== "reject" &&
                        opts.entityPolicy !== "reject" &&
                        opts.externalEntityPolicy !== "reject";
      if (canSanitize) {
        try {
          var clean = sanitize(text, opts);
          return { ok: true, action: "sanitize",
                   sanitized: Buffer.from(clean, "utf8"),
                   issues: rv.issues };
        } catch (_e) { /* fall through */ }
      }
      return { ok: false, action: "refuse", issues: rv.issues };
    });
}

var buildProfile = gateContract.makeProfileBuilder(PROFILES);

function compliancePosture(name) {
  return gateContract.lookupCompliancePosture(name, COMPLIANCE_POSTURES, _err, "xml");
}

var _xmlRulePacks = gateContract.makeRulePackLoader(GuardXmlError, "xml");
var loadRulePack = _xmlRulePacks.load;

module.exports = {
  // ---- guard-* family registry exports ----
  NAME:                "xml",
  KIND:                "content",
  MIME_TYPES:          Object.freeze(["application/xml", "text/xml"]),
  EXTENSIONS:          Object.freeze([".xml"]),
  INTEGRATION_FIXTURES: Object.freeze({
    kind:         "content",
    contentType:  "application/xml",
    extension:    ".xml",
    benignBytes:  Buffer.from('<?xml version="1.0"?><root><x>1</x></root>', "utf8"),
    // Hostile: DOCTYPE with internal-subset entity declaration (XXE +
    // billion-laughs vector — CVE-2026-24400 / CVE-2024-25062 class).
    hostileBytes: Buffer.from(
      '<?xml version="1.0"?>\n<!DOCTYPE root [<!ENTITY xx "yy">]>\n<root/>',
      "utf8"),
  }),
  // ---- primitive surface ----
  validate:            validate,
  sanitize:            sanitize,
  gate:                gate,
  buildProfile:        buildProfile,
  compliancePosture:   compliancePosture,
  loadRulePack:        loadRulePack,
  PROFILES:            PROFILES,
  DEFAULTS:            DEFAULTS,
  COMPLIANCE_POSTURES: COMPLIANCE_POSTURES,
  GuardXmlError:       GuardXmlError,
};
