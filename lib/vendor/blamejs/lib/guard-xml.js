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

var _err = GuardXmlError.factory;

// ---- Source-level threat detectors ----

// The threat catalog is read by ONE left-to-right walk over the source
// (`_scanXmlShapes`) rather than a pattern per threat. A document that is one
// long run of a prefix every pattern is interested in — `"<!"` repeated a
// million times — costs a full scan per pattern otherwise, and the caps that
// bound this input are byte caps, so the attacker picks the multiplier.
//
// The external-entity scheme list, kept as data because it is the one part of
// the catalog that grows: a URI scheme the XML parser will dereference.
var EXTERNAL_ENTITY_SCHEMES = Object.freeze([
  "file", "http", "https", "ftp", "gopher", "jar", "netdoc",
]);

// Numeric character references — `&#<digits>;` / `&#x<hex>;`. Per XML 1.0 §4.1
// every one is a character reference; a hostile input fanning these out in the
// hundreds of thousands bypasses entity-expansion caps that count only
// `&name;` general entities (CVE-2026-26278 / CVE-2026-33036 .NET XmlReader
// class). Per-document NCR count is gated by `maxNumericCharRefs` independent
// of the entity-policy branch so the operator can't disable the cap by setting
// `entityPolicy: "allow"` for a downstream signed-XML case.

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


// Is the character before `at` one an identifier runs through? The screens
// below are word-anchored: `SYSTEM` inside `MYSYSTEM` is not a keyword.
function _wordBefore(s, at) {
  return at > 0 && codepointClass.isIdentifierChar(s.charCodeAt(at - 1));
}

// ...and the mirror: does a word END at `at`? A keyword that runs into another
// identifier character is a longer word, so `<!ENTITYX` is not `<!ENTITY`.
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

// End of the standard `<?xml ... ?>` declaration when the document opens with
// one, else -1. Only this leading declaration is exempt from the
// processing-instruction screen; a second one anywhere later is a directive.
function _leadingXmlDeclEnd(s) {
  var p = _skipSpace(s, 0);
  if (!s.startsWith("<?xml", p)) return -1;
  var afterName = p + "<?xml".length;
  if (!_isSpace(s, afterName)) return -1;
  var mark = s.indexOf("?", afterName + 1);
  if (mark === -1 || s.charAt(mark + 1) !== ">") return -1;
  return mark + 2;
}

// End of the numeric character reference starting at `at` (the `&`), else -1.
// `&#<decimal>;` or `&#x<hex>;` — the `x` is lower case only, as XML 1.0 §4.1
// writes it, so `&#X41;` is not one.
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

// A SYSTEM / PUBLIC external-entity reference at `at`: the keyword, whitespace,
// a quote, and a scheme the parser would dereference.
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

// `xsi:schemaLocation=` / `xsi:noNamespaceSchemaLocation=`, spelled exactly:
// the attribute name is case-sensitive apart from the schemaLocation initial,
// which both spellings in the wild use differently.
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

// Where a `<...Signature` element name ends, given the `<` at `at`, in the
// order the tag may be spelled: a namespace prefix and a colon, or a bare name
// whose tail is `Signature`. -1 when this is not one.
function _signatureNameEnd(s, at) {
  var run = at + 1;
  while (_wordAt(s, run)) run += 1;
  // `<ds:Signature` — the prefix is consumed whole, so the local name has to
  // BE the word, not merely end with it.
  if (s.charAt(run) === ":") {
    var local = run + 1;
    while (_wordAt(s, local)) local += 1;
    if (local - (run + 1) === "Signature".length &&
        codepointClass.matchesAtFolded(s, run + 1, "Signature")) return local;
  }
  // `<Signature` / `<xSignature` — any prefix of word characters, then the
  // name, which has to run to the end of the word.
  var nameStart = run - "Signature".length;
  if (nameStart > at && codepointClass.matchesAtFolded(s, nameStart, "Signature")) return run;
  return -1;
}

// One left-to-right pass over the source producing every source-level shape
// the threat catalog asks about. Reading each of them separately means a
// document made entirely of one shared prefix is walked once per screen.
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
    // The standard `<?xml ... ?>` declaration a document opens with is not a
    // directive, so only a processing instruction at or after where it ends
    // counts as one.
    processingInstr: false,
    ncrCount:       0,
    openTagCount:   0,
  };
  // The `xmldsig` marker has to reach the Signature element's own tag, so a
  // `>` ends the window the marker may appear in.
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

  // 1. DOCTYPE.
  if (opts.doctypePolicy !== "allow" && found.doctype) {
    issues.push({
      kind: "doctype", severity: "critical", ruleId: "xml.doctype",
      snippet: "DOCTYPE declaration (XXE / billion-laughs vector — " +
               "CVE-2026-24400 / CVE-2024-25062 class)",
    });
  }

  // 2. <!ENTITY> declarations.
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

  // 3. External entity references.
  if (opts.externalEntityPolicy !== "allow" && found.externalEntity) {
    issues.push({
      kind: "external-entity", severity: "critical",
      ruleId: "xml.external-entity",
      snippet: "SYSTEM/PUBLIC external entity reference (XXE — file:// / http:// exfil)",
    });
  }

  // 4. XInclude.
  if (opts.xincludePolicy !== "allow" && found.xinclude) {
    issues.push({
      kind: "xinclude",
      severity: opts.xincludePolicy === "reject" ? "critical" : "high",
      ruleId: "xml.xinclude",
      snippet: "<xi:include> remote inclusion (XXE-shaped — CVE-2024-25062 class)",
    });
  }

  // 5. xsi:schemaLocation.
  if (opts.schemaLocationPolicy !== "allow" && found.schemaLocation) {
    issues.push({
      kind: "schema-location",
      severity: opts.schemaLocationPolicy === "reject" ? "high" : "warn",
      ruleId: "xml.schema-location",
      snippet: "xsi:schemaLocation — operator-controlled schema fetch",
    });
  }

  // 6. Processing instructions.
  if (opts.processingInstrPolicy !== "allow" && found.processingInstr) {
    issues.push({
      kind: "processing-instruction",
      severity: opts.processingInstrPolicy === "reject" ? "critical" : "high",
      ruleId: "xml.pi",
      snippet: "XML processing instruction (e.g. xml-stylesheet — CSS injection vector)",
    });
  }

  // 7. CDATA sections.
  if (opts.cdataPolicy !== "allow" && found.cdata) {
    issues.push({
      kind: "cdata",
      severity: opts.cdataPolicy === "reject" ? "critical" : "warn",
      ruleId: "xml.cdata",
      snippet: "CDATA section (often hides payloads from naive scanners)",
    });
  }

  // 8. XML signature.
  if (opts.xmlDsigPolicy !== "allow" && found.xmlDsig) {
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

  // 9. Codepoint-class threats.
  issues.push.apply(issues, codepointClass.detectCharThreats(input, opts, "xml", "warn"));

  // 10. Element + depth + attribute caps via tag count.
  var openTags = found.openTagCount;
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
  extra: {
    _gateDispositionForTest: _gateDispositionFor,
    // The source-shape scan, exposed so the test can compare it against the
    // patterns it replaced rather than only through a whole-document verdict.
    _shapesForTest: _scanXmlShapes,
  },
});
