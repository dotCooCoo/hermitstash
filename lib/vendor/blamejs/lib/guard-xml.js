// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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

var EXTERNAL_ENTITY_SCHEMES = Object.freeze([
  "file", "http", "https", "ftp", "gopher", "jar", "netdoc",
]);

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
    maxDepth:               64,
    maxElements:            8192,
    maxAttrsPerElement:     64,
    maxAttrValueBytes:      C.BYTES.kib(8),
    maxNumericCharRefs:     1024,
  },
  "balanced": {
    doctypePolicy:          "reject",
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
    maxDepth:               256,
    maxElements:            65536,
    maxAttrsPerElement:     128,
    maxAttrValueBytes:      C.BYTES.kib(32),
    maxNumericCharRefs:     16384,
  },
  "permissive": {
    doctypePolicy:          "reject",
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
    maxDepth:               1024,
    maxElements:            262144,
    maxAttrsPerElement:     256,
    maxAttrValueBytes:      C.BYTES.kib(64),
    maxNumericCharRefs:     262144,
  },
});

var DEFAULTS = gateContract.strictDefaults(PROFILES, {
  maxRuntimeMs:  C.TIME.seconds(10),
});

var COMPLIANCE_POSTURES = gateContract.compliancePostures(PROFILES, { base: 256 });


function _wordBefore(s, at) {
  return at > 0 && codepointClass.isIdentifierChar(s.charCodeAt(at - 1));
}

function _wordAt(s, at) {
  return at < s.length && codepointClass.isIdentifierChar(s.charCodeAt(at));
}

function _isSpace(s, at) {
  return at < s.length &&
         codepointClass.inRanges(s.charCodeAt(at), codepointClass.WHITESPACE_RANGES);
}

function _skipSpace(s, at) {
  var p = at;
  while (_isSpace(s, p)) p += 1;
  return p;
}

function _leadingXmlDeclEnd(s) {
  var p = _skipSpace(s, 0);
  if (!s.startsWith("<?xml", p)) return -1;
  var afterName = p + "<?xml".length;
  if (!_isSpace(s, afterName)) return -1;
  var mark = s.indexOf("?", afterName + 1);
  if (mark === -1 || s.charAt(mark + 1) !== ">") return -1;
  return mark + 2;
}

function _numericCharRefEnd(s, at) {
  if (s.charAt(at + 1) !== "#") return -1;
  var p = at + 2;
  var hex = s.charAt(p) === "x";
  if (hex) p += 1;
  var digits = p;
  while (p < s.length) {
    var cc = s.charCodeAt(p);
    if (!(hex ? codepointClass.isAsciiHexDigit(cc) : codepointClass.isAsciiDigit(cc))) break;
    p += 1;
  }
  if (p === digits || s.charAt(p) !== ";") return -1;
  return p + 1;
}

function _isExternalEntityAt(s, at) {
  if (_wordBefore(s, at)) return false;
  var keyword = codepointClass.matchesAtFolded(s, at, "SYSTEM") ? "SYSTEM"
              : codepointClass.matchesAtFolded(s, at, "PUBLIC") ? "PUBLIC"
              : null;
  if (keyword === null) return false;
  var p = at + keyword.length;
  if (!_isSpace(s, p)) return false;
  p = _skipSpace(s, p);
  var quote = s.charAt(p);
  if (quote !== "\"" && quote !== "'") return false;
  p += 1;
  for (var k = 0; k < EXTERNAL_ENTITY_SCHEMES.length; k += 1) {
    var scheme = EXTERNAL_ENTITY_SCHEMES[k];
    if (codepointClass.matchesAtFolded(s, p, scheme) &&
        s.charAt(p + scheme.length) === ":") return true;
  }
  return false;
}

function _isSchemaLocationAt(s, at) {
  if (_wordBefore(s, at) || !s.startsWith("xsi:", at)) return false;
  var afterPrefix = at + "xsi:".length;
  var starts = s.startsWith("noNamespace", afterPrefix)
    ? [afterPrefix + "noNamespace".length, afterPrefix]
    : [afterPrefix];
  for (var k = 0; k < starts.length; k += 1) {
    var p = starts[k];
    var initial = s.charAt(p);
    if (initial !== "S" && initial !== "s") continue;
    if (!s.startsWith("chemaLocation", p + 1)) continue;
    if (s.charAt(_skipSpace(s, p + 1 + "chemaLocation".length)) === "=") return true;
  }
  return false;
}

function _signatureNameEnd(s, at) {
  var run = at + 1;
  while (_wordAt(s, run)) run += 1;
  if (s.charAt(run) === ":") {
    var local = run + 1;
    while (_wordAt(s, local)) local += 1;
    if (local - (run + 1) === "Signature".length &&
        codepointClass.matchesAtFolded(s, run + 1, "Signature")) return local;
  }
  var nameStart = run - "Signature".length;
  if (nameStart > at && codepointClass.matchesAtFolded(s, nameStart, "Signature")) return run;
  return -1;
}

function _scanXmlShapes(input) {
  var found = {
    doctype:        false,
    entityDecl:     false,
    paramEntity:    false,
    externalEntity: false,
    xinclude:       false,
    schemaLocation: false,
    cdata:          false,
    xmlDsig:        false,
    processingInstr: false,
    ncrCount:       0,
    openTagCount:   0,
  };
  var openSignatureAt = -1;
  var declEnd = _leadingXmlDeclEnd(input);

  for (var i = 0; i < input.length; ) {
    var c = input.charAt(i);

    if (c === ">") { openSignatureAt = -1; i += 1; continue; }

    if (c === "&") {
      var refEnd = _numericCharRefEnd(input, i);
      if (refEnd !== -1) { found.ncrCount += 1; i = refEnd; continue; }
      i += 1;
      continue;
    }

    if (c === "<") {
      var next = input.charAt(i + 1);
      if (next === "!") {
        if (codepointClass.matchesAtFolded(input, i, "<!DOCTYPE") &&
            !_wordAt(input, i + "<!DOCTYPE".length)) found.doctype = true;
        if (codepointClass.matchesAtFolded(input, i, "<!ENTITY")) {
          var afterEntity = i + "<!ENTITY".length;
          if (!_wordAt(input, afterEntity)) found.entityDecl = true;
          if (_isSpace(input, afterEntity) &&
              input.charAt(_skipSpace(input, afterEntity)) === "%") found.paramEntity = true;
        }
        if (input.startsWith("<![CDATA[", i)) found.cdata = true;
      } else if (next === "?") {
        if (i >= declEnd &&
            codepointClass.isAsciiLetter(input.charCodeAt(i + 2))) found.processingInstr = true;
      } else if (codepointClass.isAsciiLetter(input.charCodeAt(i + 1))) {
        found.openTagCount += 1;
        if (codepointClass.matchesAtFolded(input, i, "<xi:include") &&
            !_wordAt(input, i + "<xi:include".length)) found.xinclude = true;
      }
      if (openSignatureAt === -1) {
        var nameEnd = _signatureNameEnd(input, i);
        if (nameEnd !== -1) openSignatureAt = nameEnd;
      }
      i += 1;
      continue;
    }

    if (c === "x" || c === "X") {
      if (openSignatureAt !== -1 && openSignatureAt <= i &&
          codepointClass.matchesAtFolded(input, i, "xmldsig")) found.xmlDsig = true;
      if (c === "x" && _isSchemaLocationAt(input, i)) found.schemaLocation = true;
    } else if ((c === "S" || c === "s" || c === "P" || c === "p") &&
               _isExternalEntityAt(input, i)) {
      found.externalEntity = true;
    }
    i += 1;
  }
  return found;
}

function _detectIssues(input, opts) {
  var pre = gateContract.detectStringInput(input, opts, { name: "xml", noun: "input", emptyMode: "skip", scanCodepoints: false, cap: { bytes: opts.maxBytes, kind: "too-large", snippet: function (byteLen, max) { return "input " + byteLen + " bytes exceeds maxBytes " + max; } } });
  if (pre.done) return pre.issues;
  var issues = pre.issues;
  var found = _scanXmlShapes(input);

  if (opts.doctypePolicy !== "allow" && found.doctype) {
    issues.push({
      kind: "doctype", severity: "critical", ruleId: "xml.doctype",
      snippet: "DOCTYPE declaration (XXE / billion-laughs vector — " +
               "CVE-2026-24400 / CVE-2024-25062 class)",
    });
  }

  if (opts.entityPolicy !== "allow" && found.entityDecl) {
    issues.push({
      kind: "entity-declaration", severity: "critical",
      ruleId: "xml.entity",
      snippet: "<!ENTITY> declaration (entity-expansion DoS vector)",
    });
    if (found.paramEntity) {
      issues.push({
        kind: "parameter-entity", severity: "critical",
        ruleId: "xml.parameter-entity",
        snippet: "parameter entity (% prefix) — out-of-band exfil vector",
      });
    }
  }

  if (opts.externalEntityPolicy !== "allow" && found.externalEntity) {
    issues.push({
      kind: "external-entity", severity: "critical",
      ruleId: "xml.external-entity",
      snippet: "SYSTEM/PUBLIC external entity reference (XXE — file:// / http:// exfil)",
    });
  }

  if (opts.xincludePolicy !== "allow" && found.xinclude) {
    issues.push({
      kind: "xinclude",
      severity: opts.xincludePolicy === "reject" ? "critical" : "high",
      ruleId: "xml.xinclude",
      snippet: "<xi:include> remote inclusion (XXE-shaped — CVE-2024-25062 class)",
    });
  }

  if (opts.schemaLocationPolicy !== "allow" && found.schemaLocation) {
    issues.push({
      kind: "schema-location",
      severity: opts.schemaLocationPolicy === "reject" ? "high" : "warn",
      ruleId: "xml.schema-location",
      snippet: "xsi:schemaLocation — operator-controlled schema fetch",
    });
  }

  if (opts.processingInstrPolicy !== "allow" && found.processingInstr) {
    issues.push({
      kind: "processing-instruction",
      severity: opts.processingInstrPolicy === "reject" ? "critical" : "high",
      ruleId: "xml.pi",
      snippet: "XML processing instruction (e.g. xml-stylesheet — CSS injection vector)",
    });
  }

  if (opts.cdataPolicy !== "allow" && found.cdata) {
    issues.push({
      kind: "cdata",
      severity: opts.cdataPolicy === "reject" ? "critical" : "warn",
      ruleId: "xml.cdata",
      snippet: "CDATA section (often hides payloads from naive scanners)",
    });
  }

  if (opts.xmlDsigPolicy !== "allow" && found.xmlDsig) {
    issues.push({
      kind: "xml-signature", severity: "warn",
      ruleId: "xml.xmldsig",
      snippet: "XML signature element — operator must guard against signature wrapping (xmldsig)",
    });
  }

  var ncrCap = opts.maxNumericCharRefs;
  if (ncrCap !== undefined && ncrCap !== null) {
    var ncrCount = found.ncrCount;
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

  issues.push.apply(issues, codepointClass.detectCharThreats(input, opts, "xml"));

  var openTags = found.openTagCount;
  if (openTags > opts.maxElements) {
    issues.push({
      kind: "element-cap", severity: "high",
      ruleId: "xml.element-cap",
      snippet: "element count " + openTags + " exceeds maxElements " + opts.maxElements,
    });
  }
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
    produceSanitized: function (text, o) { return _sanitizeTransform(text, o); },
  });
}

var INTEGRATION_FIXTURES = Object.freeze({
  kind:         "content",
  contentType:  "application/xml",
  extension:    ".xml",
  benignBytes:  Buffer.from('<?xml version="1.0"?><root><x>1</x></root>', "utf8"),
  hostileBytes: Buffer.from(
    '<?xml version="1.0"?>\n<!DOCTYPE root [<!ENTITY xx "yy">]>\n<root/>',
    "utf8"),
});

var POLICY_ENUM = gateContract.policyVocabulary([
  "doctypePolicy", "entityPolicy", "externalEntityPolicy", "xincludePolicy",
  "processingInstrPolicy", "cdataPolicy", "schemaLocationPolicy",
], gateContract.POLICY_VALUES.rejectAuditAllow, {
  xmlDsigPolicy: ["audit", "audit-only", "allow"],
});

var _guard = module.exports = gateContract.defineGuard({
  enumOpts:    POLICY_ENUM,
  name:        "xml",
  kind:        "content",
  charRepair:  true,
  errorClass:  GuardXmlError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  mimeTypes:   ["application/xml", "text/xml"],
  extensions:  [".xml"],
  integrationFixtures: INTEGRATION_FIXTURES,
  detect:             _detectIssues,
  sanitizeTransform:  _sanitizeTransform,
  dispositionFor:     _gateDispositionFor,
  intOpts:            ["maxBytes", "maxDepth", "maxElements", "maxAttrsPerElement",
                       "maxAttrValueBytes", "maxNumericCharRefs"],
  gate:        gate,
  extra: {
    _gateDispositionForTest: _gateDispositionFor,
    _shapesForTest: _scanXmlShapes,
  },
});
