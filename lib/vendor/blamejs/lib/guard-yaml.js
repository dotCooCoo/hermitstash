// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.guardYaml
 * @nav    Guards
 * @title  Guard Yaml
 *
 * @intro
 *   YAML content-safety guard — defends against the type-coercion,
 *   deserialization, and DoS catalog operators face when accepting
 *   YAML sourced from user input. All detection runs at the SOURCE
 *   level: the operator's downstream parser may be PyYAML, SnakeYAML,
 *   js-yaml, libyaml, or another implementation, and the guard
 *   refuses hostile inputs before any parser sees them.
 *
 *   Tag-injection RCE defense: language-specific deserialization tag
 *   prefixes (`!!python/` / `!!java.` / `!!ruby/` / `!!perl/` /
 *   `!!js/` / `!!cs/` / `!!net/` / `!!system.`) plus the `!!apply` /
 *   `!!new` / `!!eval` / `!!exec` family are refused regardless of
 *   profile under strict. CVE coverage: CVE-2026-24009 Docling/PyYAML
 *   unsafe load, CVE-2025-68664 LangChain deserialization, CVE-2022-
 *   1471 SnakeYAML constructor RCE, CVE-2020-1747 / CVE-2020-14343
 *   PyYAML FullLoader, CVE-2017-18342 python/object/apply.
 *
 *   YAML 1.1 vs 1.2 type-coercion attacks: PyYAML and libyaml still
 *   default to YAML 1.1 in 2026, which treats unquoted `no` / `yes`
 *   / `y` / `n` / `on` / `off` as booleans (the "Norway problem" —
 *   country code "NO" parses as false), and `0777`-shaped numerics
 *   parse as octal. These shapes are flagged at the source so
 *   operators can refuse silently coerced values.
 *
 *   Anchor-bomb (billion laughs) detection: `&anchor` declares,
 *   `*alias` references, recursive aliasing amplifies a small input
 *   into GiB on parse. Caps via `maxAnchors` + `maxAliasDepth` +
 *   `maxNodes`, plus an explicit alias-amplification ratio
 *   (aliases / anchors >= 8 fires `alias-explosion`) catches the
 *   exponential expansion shape independent of absolute counts.
 *   CVE-2026-27807 MarkUs / CVE-2025-61301 / CVE-2025-61303 ("Laughter
 *   in the Wild" — 14 libraries / 10 languages) exemplify the family.
 *
 *   Custom-tag exec surface: local `!Foo` and global `!!Bar` user
 *   tags suggest a non-safe parser is downstream even when the tag
 *   isn't on the language-specific deserialization denylist. Flagged
 *   per profile.
 *
 *   Merge-key chain DoS: `<<: *anchor` invokes the YAML 1.1 merge-
 *   key spec; chains of merge keys against deeply nested anchors are
 *   an additional anchor-chain expansion vector.
 *
 *   Multi-document streams: operators expecting a single doc silently
 *   receive only the first one and ignore the rest — hostile content
 *   in subsequent docs slips past validation that ran on the first.
 *   The guard refuses `multiDocPolicy === "reject"` and caps via
 *   `maxDocuments`.
 *
 *   Duplicate-key smuggling, BOM placement, and bidi / null / control
 *   / zero-width character threats route through the same shared
 *   detector backing the guard-json / guard-csv families.
 *
 *   Profiles: `strict` / `balanced` / `permissive`. Compliance
 *   postures: `hipaa` / `pci-dss` / `gdpr` / `soc2`. Operators select
 *   via `{ profile: "strict" }` or `{ compliancePosture: "hipaa" }`;
 *   postures overlay on top of the profile baseline.
 *
 * @card
 *   YAML content-safety guard — defends against the type-coercion, deserialization, and DoS catalog operators face when accepting YAML sourced from user input.
 */

var codepointClass = require("./codepoint-class");
var yamlLex = require("./yaml-lex");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var safeYamlLazy = lazyRequire(function () { return require("./parsers/safe-yaml"); });
var { GuardYamlError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardYamlError.factory;

var DANGEROUS_TAG_PREFIXES = Object.freeze([
  "!!python/", "!!java.", "!!ruby/", "!!perl/", "!!js/", "!!cs/",
  "!!net/", "!!system.", "!!eval", "!!exec", "!!new", "!!apply",
]);

var SAFE_CORE_TAGS = Object.freeze([
  "!!str", "!!int", "!!float", "!!bool", "!!null",
  "!!seq", "!!map", "!!set", "!!omap", "!!pairs",
  "!!binary", "!!timestamp", "!!merge",
]);

var NORWAY_TOKENS = ["no", "yes", "y", "n", "on", "off"];

var _isAsciiDigit = codepointClass.isAsciiDigit;
var _isWordChar = codepointClass.isIdentifierChar;

function _isNameStart(cc) { return codepointClass.isAsciiLetter(cc) || cc === 0x5F; }
function _isNameChar(cc) { return _isWordChar(cc) || cc === 0x2D; }
function _isSpace(cc) {
  return codepointClass.inRanges(cc, codepointClass.WHITESPACE_RANGES);
}

function _collectSigilNames(text, sigil) {
  var out = [];
  for (var i = 0; i < text.length; i += 1) {
    if (text.charAt(i) !== sigil) continue;
    if (!_isNameStart(text.charCodeAt(i + 1))) continue;
    var end = i + 2;
    while (end < text.length && _isNameChar(text.charCodeAt(end))) end += 1;
    out.push(text.slice(i, end));
    i = end - 1;
  }
  return out;
}

function _firstNorwayToken(text) {
  for (var i = 0; i < text.length; i += 1) {
    if (text.charAt(i) !== ":") continue;
    var j = i + 1;
    while (j < text.length && _isSpace(text.charCodeAt(j))) j += 1;
    for (var t = 0; t < NORWAY_TOKENS.length; t += 1) {
      var token = NORWAY_TOKENS[t];
      var slice = text.slice(j, j + token.length);
      if (slice.length !== token.length) continue;
      if (!codepointClass.containsFolded(slice, token)) continue;
      var after = text.charCodeAt(j + token.length);
      if (!isNaN(after) && _isWordChar(after)) continue;
      return { index: i, token: slice };
    }
  }
  return null;
}

function _hasLeadingZeroOctal(text) {
  for (var i = 0; i < text.length; i += 1) {
    if (text.charAt(i) !== ":") continue;
    var j = i + 1;
    while (j < text.length && _isSpace(text.charCodeAt(j))) j += 1;
    if (text.charCodeAt(j) !== 0x30) continue;
    var end = j + 1;
    while (end < text.length && _isAsciiDigit(text.charCodeAt(end))) end += 1;
    if (end === j + 1) continue;
    var after = text.charCodeAt(end);
    if (isNaN(after) || !_isWordChar(after)) return true;
  }
  return false;
}

function _hasMergeKeyAlias(text, nodeStarts) {
  return codepointClass.hasPairWhere(text, "<", "<", function (i) {
    if (nodeStarts && !nodeStarts[i]) return false;
    var j = i + 2;
    while (j < text.length && _isSpace(text.charCodeAt(j))) j += 1;
    if (text.charAt(j) !== ":") return false;
    j += 1;
    while (j < text.length && _isSpace(text.charCodeAt(j))) j += 1;
    return text.charAt(j) === "*";
  });
}

var PROFILES = Object.freeze({
  "strict": {
    tagPolicy:              "reject",
    aliasPolicy:            "reject",
    multiDocPolicy:         "reject",
    norwayPolicy:           "reject",
    leadingZeroPolicy:      "reject",
    duplicateKeyPolicy:     "reject",
    mergeKeyPolicy:         "reject",
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    safeCoreTagsAllowed:    false,
    maxBytes:               C.BYTES.mib(2),
    maxDepth:               8,
    maxAnchors:             16,
    maxAliasDepth:          1,
    maxDocuments:           1,
    maxNodes:               1024,
    maxScalarLength:        C.BYTES.kib(8),
  },
  "balanced": {
    tagPolicy:              "audit",
    aliasPolicy:            "audit",
    multiDocPolicy:         "audit",
    norwayPolicy:           "audit",
    leadingZeroPolicy:      "audit",
    duplicateKeyPolicy:     "audit",
    mergeKeyPolicy:         "audit",
    bidiPolicy:             "strip",
    controlPolicy:          "strip",
    nullBytePolicy:         "strip",
    zeroWidthPolicy:        "strip",
    safeCoreTagsAllowed:    true,
    maxBytes:               C.BYTES.mib(8),
    maxDepth:               32,
    maxAnchors:             64,
    maxAliasDepth:          3,
    maxDocuments:           16,
    maxNodes:               16384,
    maxScalarLength:        C.BYTES.kib(64),
  },
  "permissive": {
    tagPolicy:              "audit",
    aliasPolicy:            "audit",
    multiDocPolicy:         "audit",
    norwayPolicy:           "audit",
    leadingZeroPolicy:      "audit",
    duplicateKeyPolicy:     "audit",
    mergeKeyPolicy:         "audit",
    bidiPolicy:             "audit",
    controlPolicy:          "strip",
    nullBytePolicy:         "reject",
    zeroWidthPolicy:        "strip",
    safeCoreTagsAllowed:    true,
    maxBytes:               C.BYTES.mib(64),
    maxDepth:               64,
    maxAnchors:             1024,
    maxAliasDepth:          8,
    maxDocuments:           256,
    maxNodes:               65536,
    maxScalarLength:        C.BYTES.kib(256),
  },
});

var DEFAULTS = gateContract.strictDefaults(PROFILES, {
  maxRuntimeMs: C.TIME.seconds(10),
});

var COMPLIANCE_POSTURES = gateContract.compliancePostures(PROFILES, { base: 256 });

var POLICY_ENUM = gateContract.policyVocabulary([
  "tagPolicy", "aliasPolicy", "multiDocPolicy", "norwayPolicy",
  "leadingZeroPolicy", "duplicateKeyPolicy", "mergeKeyPolicy",
], ["reject", "audit", "allow"]);

var RESOLVER_ENUMS = Object.freeze(Object.assign({},
  gateContract.charPolicyEnums(DEFAULTS, { canRepair: true }), POLICY_ENUM));

var INT_OPTS = ["maxBytes", "maxDepth", "maxAnchors", "maxAliasDepth",
                "maxDocuments", "maxNodes", "maxScalarLength"];

function _countDocumentSeparators(text) {
  var n = 0;
  for (var at = 0; at + 3 < text.length; at += 1) {
    if (at > 0 && text.charCodeAt(at - 1) !== 0x0A) continue;
    if (text.slice(at, at + 3) !== "---") continue;
    if (!_isSpace(text.charCodeAt(at + 3))) continue;
    n += 1;
  }
  return n;
}

function _isDangerousTag(tag) {
  for (var i = 0; i < DANGEROUS_TAG_PREFIXES.length; i += 1) {
    if (tag.indexOf(DANGEROUS_TAG_PREFIXES[i]) === 0) return true;
  }
  return false;
}

function _isSafeCoreTag(tag) {
  return SAFE_CORE_TAGS.indexOf(tag) !== -1;
}

var TAG_TAIL = codepointClass.ASCII_ALNUM + "_./:-";

function _scanTags(text) {
  var matches = [];
  var tags = [];
  for (var i = 0; i < text.length; i += 1) {
    if (text.charAt(i) !== "!") continue;
    var nameAt = text.charAt(i + 1) === "!" ? i + 2 : i + 1;
    if (!codepointClass.isAsciiLetter(text.charCodeAt(nameAt))) continue;
    var end = nameAt + 1;
    while (end < text.length && TAG_TAIL.indexOf(text.charAt(end)) !== -1) end += 1;
    tags.push({ tag: text.slice(i, end), location: i === 0 ? 0 : i - 1 });
    i = end - 1;
  }
  for (var t = 0; t < tags.length; t += 1) {
    var tag = tags[t].tag;
    var kind;
    if (_isDangerousTag(tag)) kind = "dangerous";
    else if (_isSafeCoreTag(tag)) kind = "safe-core";
    else kind = "custom";
    matches.push({ tag: tag, location: tags[t].location, kind: kind });
  }
  return matches;
}

function _detectIssues(input, opts) {
  var pre = gateContract.detectStringInput(input, opts, { name: "yaml", noun: "input", emptyMode: "skip", scanCodepoints: false, cap: { bytes: opts.maxBytes, kind: "too-large", snippet: function (byteLen, max) { return "input " + byteLen + " bytes exceeds maxBytes " + max; } } });
  if (pre.done) return pre.issues;
  var issues = pre.issues;

  var lexed = yamlLex.lexLines(input);
  var masked = lexed.masked;

  var tagHits = _scanTags(masked);
  for (var ti = 0; ti < tagHits.length; ti += 1) {
    var t = tagHits[ti];
    if (t.kind === "dangerous") {
      issues.push({
        kind: "dangerous-tag", severity: "critical",
        ruleId: "yaml.dangerous-tag",
        location: t.location,
        snippet: "deserialization-tag injection " + JSON.stringify(t.tag) +
                 " (CVE-2026-24009 / CVE-2022-1471 class)",
      });
    } else if (t.kind === "custom") {
      if (opts.tagPolicy === "reject" ||
          (opts.tagPolicy === "audit" && !opts.safeCoreTagsAllowed)) {
        issues.push({
          kind: "custom-tag",
          severity: opts.tagPolicy === "reject" ? "critical" : "high",
          ruleId: "yaml.custom-tag",
          location: t.location,
          snippet: "custom tag " + JSON.stringify(t.tag) +
                   " (suggests non-safe parser downstream)",
        });
      }
    } else if (t.kind === "safe-core") {
      if (opts.tagPolicy === "reject" || !opts.safeCoreTagsAllowed) {
        issues.push({
          kind: "core-tag",
          severity: opts.tagPolicy === "reject" ? "high" : "warn",
          ruleId: "yaml.core-tag",
          location: t.location,
          snippet: "YAML 1.2 core tag " + JSON.stringify(t.tag),
        });
      }
    }
  }

  var anchors = _collectSigilNames(masked, "&");
  var aliases = _collectSigilNames(masked, "*");
  if (anchors.length > opts.maxAnchors) {
    issues.push({
      kind: "anchor-cap", severity: "high",
      ruleId: "yaml.anchor-cap",
      snippet: "anchor declarations " + anchors.length +
               " exceeds maxAnchors " + opts.maxAnchors,
    });
  }
  if ((anchors.length > 0 || aliases.length > 0) && opts.aliasPolicy === "reject") {
    issues.push({
      kind: "alias-disabled", severity: "critical",
      ruleId: "yaml.alias",
      snippet: "anchors/aliases refused under strict (billion-laughs vector — " +
               "CVE-2026-27807 MarkUs class)",
    });
  }
  var ampRatio = aliases.length / Math.max(anchors.length, 1);
  if (anchors.length >= 1 && ampRatio >= 8) {
    issues.push({
      kind: "alias-explosion", severity: "critical",
      ruleId: "yaml.alias-explosion",
      snippet: "alias-reference count " + aliases.length +
               " amplifies " + ampRatio.toFixed(1) +
               "x against " + anchors.length + " anchor(s) (billion-laughs shape)",
    });
  }

  var docs = _countDocumentSeparators(input);
  if (docs > 0 && opts.multiDocPolicy !== "allow") {
    if (opts.multiDocPolicy === "reject" ||
        (docs + 1) > opts.maxDocuments) {
      issues.push({
        kind: "multi-document",
        severity: opts.multiDocPolicy === "reject" ? "critical" : "high",
        ruleId: "yaml.multi-document",
        snippet: "multi-document stream (" + (docs + 1) +
                 " docs) — first-doc-wins silently masks the rest",
      });
    }
  }

  if (opts.norwayPolicy !== "allow") {
    var norway = _firstNorwayToken(input);
    if (norway) {
      issues.push({
        kind: "norway-implicit-bool",
        severity: opts.norwayPolicy === "reject" ? "critical" : "warn",
        ruleId: "yaml.norway",
        location: norway.index,
        snippet: "implicit YAML 1.1 boolean " + JSON.stringify(norway.token) +
                 " (Norway problem — country code 'NO' parses as false; " +
                 "quote scalars to disambiguate)",
      });
    }
  }

  if (opts.leadingZeroPolicy !== "allow") {
    if (_hasLeadingZeroOctal(input)) {
      issues.push({
        kind: "leading-zero-octal",
        severity: opts.leadingZeroPolicy === "reject" ? "high" : "warn",
        ruleId: "yaml.leading-zero",
        snippet: "leading-zero numeric (parses as octal in YAML 1.1)",
      });
    }
  }

  if (opts.mergeKeyPolicy !== "allow" &&
      _hasMergeKeyAlias(input, lexed.nodeStarts)) {
    issues.push({
      kind: "merge-key",
      severity: opts.mergeKeyPolicy === "reject" ? "high" : "warn",
      ruleId: "yaml.merge-key",
      snippet: "merge-key with anchor reference (anchor-chain DoS vector)",
    });
  }

  issues.push.apply(issues, codepointClass.detectCharThreats(input, opts, "yaml"));

  if (opts.duplicateKeyPolicy !== "allow") {
    var dups = _detectDuplicateKeysYaml(input);
    for (var di = 0; di < dups.length; di += 1) {
      issues.push({
        kind: "duplicate-key",
        severity: opts.duplicateKeyPolicy === "reject" ? "critical" : "warn",
        ruleId: "yaml.duplicate-key",
        snippet: "duplicate key " + JSON.stringify(dups[di]) +
                 " (YAML 1.2 SHOULD-unique; parsers silently last-wins)",
      });
    }
  }

  try {
    safeYamlLazy().parse(input, {
      maxBytes:  opts.maxBytes,
      maxDepth:  opts.maxDepth,
      maxKeys:   opts.maxNodes,
    });
  } catch (e) {
    issues.push({
      kind: "parse-failed", severity: "critical", ruleId: "yaml.parse",
      snippet: "YAML parse failed: " + (e && e.message),
    });
  }

  return issues;
}

function _mappingEntryAt(line, masked) {
  var indent = 0;
  while (indent < line.length && _isSpace(line.charCodeAt(indent))) indent += 1;
  if (indent === line.length) return null;
  for (var i = indent; i < line.length; i += 1) {
    if (line.charAt(i) !== ":") continue;
    if (masked !== undefined && masked.charAt(i) !== ":") continue;
    var after = line.charCodeAt(i + 1);
    if (i + 1 < line.length && !_isSpace(after)) continue;
    if (i === indent) return null;
    return { indent: indent, key: line.slice(indent, i) };
  }
  return null;
}

function _indentOfLine(line) {
  var i = 0;
  while (i < line.length && _isSpace(line.charCodeAt(i))) i += 1;
  return i;
}

function _sequenceDashIndent(line) {
  var i = 0;
  while (i < line.length && _isSpace(line.charCodeAt(i))) i += 1;
  if (i >= line.length || line.charAt(i) !== "-") return -1;
  if (i + 1 < line.length && !_isSpace(line.charCodeAt(i + 1))) return -1;
  return i;
}

function _isCommentLine(line) {
  var i = 0;
  while (i < line.length && _isSpace(line.charCodeAt(i))) i += 1;
  return i < line.length && line.charAt(i) === "#";
}

var _splitLines = codepointClass.splitLines;

function _detectDuplicateKeysYaml(text) {
  var dups = Object.create(null);
  var lines = _splitLines(text);
  var maskedLines = _splitLines(yamlLex.maskNonStructural(text));
  var indentScopes = Object.create(null);
  var itemStack = [];
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    if (line.length === 0 || _isCommentLine(line)) continue;
    var dashAt = _sequenceDashIndent(line);
    var lineIndent = dashAt >= 0 ? dashAt : _indentOfLine(line);
    while (itemStack.length &&
           itemStack[itemStack.length - 1].dash >= lineIndent) itemStack.pop();
    if (dashAt >= 0) {
      Object.keys(indentScopes).forEach(function (k) {
        if (Number(k) > dashAt) delete indentScopes[k];
      });
      itemStack.push({ dash: dashAt, keyIndent: -1 });
    }
    var entry = _mappingEntryAt(line, maskedLines[i]);
    if (!entry) continue;
    var indent = entry.indent;
    var key = entry.key.trim();
    if (key.charAt(0) === "[" || key.charAt(0) === "{") continue;
    var dash = key.charAt(0) === "-" &&
               (key.length === 1 || _isSpace(key.charCodeAt(1)));
    var scopeAt = indent;
    if (dash) {
      var after = 1;
      while (after < key.length && _isSpace(key.charCodeAt(after))) after += 1;
      key = key.slice(after).trim();
      if (!key || key.charAt(0) === "-" || key.charAt(0) === "[" ||
          key.charAt(0) === "{") continue;
      scopeAt = indent + after;
    }
    var item = itemStack.length ? itemStack[itemStack.length - 1] : null;
    if (item && scopeAt > item.dash) {
      if (item.keyIndent === -1 || scopeAt < item.keyIndent) item.keyIndent = scopeAt;
      if (scopeAt <= item.keyIndent) scopeAt = item.dash + 0.5;
    }
    if (!indentScopes[scopeAt]) indentScopes[scopeAt] = Object.create(null);
    if (indentScopes[scopeAt][key]) dups[key] = true;
    else indentScopes[scopeAt][key] = true;
    Object.keys(indentScopes).forEach(function (k) {
      if (Number(k) > scopeAt) delete indentScopes[k];
    });
  }
  return Object.keys(dups);
}

/**
 * @primitive  b.guardYaml.validate
 * @signature  b.guardYaml.validate(input, opts?)
 * @since      0.7.14
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardYaml.parse, b.guardYaml.gate
 *
 * Inspect `input` (string of YAML source) for the full guard-yaml
 * threat catalog without committing to a parsed value. Returns
 * `{ ok, issues }` where `issues` is the aggregated
 * detector output — every dangerous-tag prefix, custom-tag use,
 * anchor / alias amplification, multi-document split, Norway-
 * problem implicit boolean, leading-zero octal, merge-key chain,
 * duplicate-key smuggle, codepoint-class threat, and parse failure
 * is reported with `kind` / `severity` / `ruleId` / `snippet`.
 * Profile-driven (`strict` / `balanced` / `permissive`) and posture-
 * driven (`hipaa` / `pci-dss` / `gdpr` / `soc2`).
 *
 * Detection runs at the source level so the operator's downstream
 * parser (PyYAML / SnakeYAML / js-yaml / libyaml) need not be
 * consulted to identify hostile shapes. A final pass tries the safe-
 * yaml parser and surfaces parse failure as a critical issue.
 *
 * @opts
 *   profile:             "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   tagPolicy:           "reject"|"audit"|"allow",
 *   aliasPolicy:         "reject"|"audit"|"allow",
 *   multiDocPolicy:      "reject"|"audit"|"allow",
 *   norwayPolicy:        "reject"|"audit"|"allow",
 *   leadingZeroPolicy:   "reject"|"audit"|"allow",
 *   duplicateKeyPolicy:  "reject"|"audit"|"allow",
 *   mergeKeyPolicy:      "reject"|"audit"|"allow",
 *   bidiPolicy:          "reject"|"strip"|"audit"|"allow",
 *   controlPolicy:       "reject"|"strip"|"allow",
 *   nullBytePolicy:      "reject"|"strip"|"allow",
 *   zeroWidthPolicy:     "reject"|"strip"|"audit"|"allow",
 *   safeCoreTagsAllowed: boolean,
 *   maxBytes:            number,    // total source byte cap
 *   maxDepth:            number,    // recursion depth cap
 *   maxAnchors:          number,    // anchor declaration cap
 *   maxAliasDepth:       number,    // alias-chain depth cap
 *   maxDocuments:        number,    // multi-document doc count cap
 *   maxNodes:            number,    // total node count cap
 *   maxScalarLength:     number,    // per-scalar length cap
 *
 * @example
 *   var rv = b.guardYaml.validate("!!python/object/new:cls\nargs: [x]\n", {
 *     profile: "strict",
 *   });
 *   rv.ok;                                              // → false
 *   rv.issues.some(function (i) { return i.kind === "dangerous-tag"; });  // → true
 */

/**
 * @primitive  b.guardYaml.parse
 * @signature  b.guardYaml.parse(input, opts?)
 * @since      0.7.14
 * @status     stable
 * @related    b.guardYaml.validate, b.guardYaml.gate
 *
 * Parse `input` (string of YAML source) into a JavaScript value
 * after the guard-yaml threat catalog clears. Runs the full
 * validate-shape detector, throws `GuardYamlError` on the first
 * critical issue (dangerous tag, alias-explosion, multi-document
 * under reject, parse failure, etc.), then routes through the safe-
 * yaml parser with the configured `maxBytes` / `maxDepth` /
 * `maxNodes` caps.
 *
 * The throw-on-critical pre-flight is what distinguishes guarded
 * parse from a raw yaml-library `load()`: the operator's downstream
 * code never sees deserialization-tag instantiation, billion-laughs
 * expansion, or duplicate-key smuggling because the source is
 * refused before the parser runs.
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   tagPolicy:    "reject"|"audit"|"allow",
 *   aliasPolicy:  "reject"|"audit"|"allow",
 *   maxBytes:     number, maxDepth: number, maxNodes: number,
 *
 * @example
 *   var safe = b.guardYaml.parse("name: alice\nage: 30\n", {
 *     profile: "strict",
 *   });
 *   safe.name;                                          // → "alice"
 *   safe.age;                                           // → 30
 */
function parse(input, opts) {
  opts = gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardYamlError,
    errCodePrefix:      "yaml",
    intOpts:            INT_OPTS,
    nonNegativeOpts:    gateContract.capKeysOf(DEFAULTS),
    enumOpts:           RESOLVER_ENUMS,
  });
  if (typeof input !== "string") {
    throw _err("yaml/bad-input", "parse requires string input");
  }
  var issues = _detectIssues(input, opts);
  gateContract.throwOnRefusalSeverity(issues,
    { errorClass: GuardYamlError, codePrefix: "yaml", severities: ["critical"], op: "parse" });
  return safeYamlLazy().parse(input, {
    maxBytes:  opts.maxBytes,
    maxDepth:  opts.maxDepth,
    maxKeys:   opts.maxNodes,
  });
}

var INTEGRATION_FIXTURES = Object.freeze({
  kind:         "content",
  contentType:  "application/yaml",
  extension:    ".yaml",
  benignBytes:  Buffer.from('name: alice\nage: 30\n', "utf8"),
  hostileBytes: Buffer.from("!!python/object/new:cls\nargs: [\"x\"]\nmode: 0777\n", "utf8"),
});

function _gateDispositionFor(issue, opts) {
  var shared = gateContract.charThreatDisposition(issue, opts);
  if (shared) return shared;
  switch (issue.kind) {
    case "core-tag":
    case "custom-tag":
    case "dangerous-tag":        return gateContract.policyDisposition(opts.tagPolicy);
    case "alias-disabled":       return gateContract.policyDisposition(opts.aliasPolicy);
    case "duplicate-key":        return gateContract.policyDisposition(opts.duplicateKeyPolicy);
    case "leading-zero-octal":   return gateContract.policyDisposition(opts.leadingZeroPolicy);
    case "merge-key":            return gateContract.policyDisposition(opts.mergeKeyPolicy);
    case "multi-document":       return gateContract.policyDisposition(opts.multiDocPolicy);
    case "norway-implicit-bool": return gateContract.policyDisposition(opts.norwayPolicy);
    default:                     return null;
  }
}

function _sanitizeTransform(input, opts) {
  return codepointClass.scrubCharThreats(input, opts, _err, "yaml");
}

/**
 * @primitive  b.guardYaml.gate
 * @signature  b.guardYaml.gate(opts?)
 * @since      0.7.14
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardYaml.validate, b.guardYaml.parse, b.staticServe.create, b.fileUpload.create
 *
 * Build a `b.gateContract` gate for plugging into
 * `b.staticServe({ contentSafety: { ".yaml": gate } })`,
 * `b.fileUpload({ contentSafety: { "application/yaml": gate } })`,
 * or any host primitive that consumes the gate-contract shape.
 *
 * The action comes from the POLICY the active profile declares for each
 * finding, not from the finding's severity: a character class set to `strip`
 * is repaired and returned as `sanitize`, one set to `audit` reports
 * `audit-only`, and one set to `reject` refuses. Findings that carry no policy
 * and admit no repair — an alias explosion, a blown anchor cap, an oversized
 * document, one that does not parse — fall back to the conservative severity
 * answer and refuse.
 *
 * Only character-level repair is offered. Stripping an invisible or control
 * character is a text edit needing no re-emit; the tag, alias and
 * multi-document shapes have no faithful round-trip, so they refuse through
 * their own policies rather than being rewritten.
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   name:       string,    // gate identity for audit / observability
 *
 * @example
 *   var yamlGate = b.guardYaml.gate({ profile: "balanced" });
 *   var d = await yamlGate.check({ bytes: Buffer.from("key: value\n") });
 *   d.action;                                            // → "serve"
 */
function gate(opts) {
  opts = gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardYamlError,
    errCodePrefix:      "yaml",
    intOpts:            INT_OPTS,
    nonNegativeOpts:    gateContract.capKeysOf(DEFAULTS),
    enumOpts:           RESOLVER_ENUMS,
  });
  return gateContract.buildContentGate({
    name:     opts.name || "guardYaml:" + (opts.profile || "default"),
    opts:     opts,
    validate: module.exports.validate,
    dispositionFor:   _gateDispositionFor,
    produceSanitized: _sanitizeTransform,
  });
}

module.exports = gateContract.defineGuard({
  enumOpts:    POLICY_ENUM,
  name:        "yaml",
  kind:        "content",
  charRepair:  true,
  errorClass:  GuardYamlError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  mimeTypes:   ["application/yaml", "application/x-yaml", "text/yaml", "text/x-yaml"],
  extensions:  [".yml", ".yaml"],
  integrationFixtures: INTEGRATION_FIXTURES,
  detect:      _detectIssues,
  intOpts:     INT_OPTS,
  gate:              gate,
  dispositionFor:    _gateDispositionFor,
  sanitizeTransform: _sanitizeTransform,
  extra: {
    parse:                  parse,
    DANGEROUS_TAG_PREFIXES: DANGEROUS_TAG_PREFIXES,
    SAFE_CORE_TAGS:         SAFE_CORE_TAGS,
  },
});
