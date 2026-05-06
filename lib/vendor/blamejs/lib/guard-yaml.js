"use strict";
/**
 * guard-yaml — YAML content-safety primitive (b.guardYaml).
 *
 * Threat catalog grounded in current research (multiple 2025-2026
 * deserialization + DoS CVEs in popular YAML libraries):
 *   - CVE-2026-24009 Docling / PyYAML unsafe load → RCE
 *   - CVE-2026-27807 MarkUs YAML alias billion-laughs DoS
 *   - CVE-2025-68664 LangChain deserialization → RCE
 *   - CVE-2025-61301 / CVE-2025-61303 YAML library DoS family
 *     ("Laughter in the Wild" study across 14 libraries / 10 languages)
 *   - CVE-2022-1471 SnakeYAML constructor RCE
 *   - CVE-2020-1747 / CVE-2020-14343 PyYAML FullLoader RCE chain
 *   - CVE-2017-18342 PyYAML python/object/apply RCE
 *
 *   var rv = b.guardYaml.validate(input, { profile: "strict" });
 *   var safe = b.guardYaml.parse(input, { profile: "strict" });
 *   var g = b.guardYaml.gate({ profile: "strict" });
 *
 * Threat catalog covered (all source-level — operator's downstream
 * parser may be pyyaml/snakeyaml/js-yaml; the guard refuses hostile
 * sources before any parser sees them):
 *
 *   1. Tag-injection RCE — language-specific deserialization tags
 *      with prefixes !!python/ / !!java. / !!ruby/ / !!perl/ / !!js/
 *      / !!cs/ / !!net/ / !!system. and the !!apply / !!new family.
 *      Refused regardless of profile under strict.
 *
 *   2. Anchor / alias recursion (billion laughs) — &anchor declares,
 *      *alias references. Recursive aliasing amplifies a small input
 *      into GiB on parse. Caps via maxAnchors + maxAliasDepth + total
 *      node count.
 *
 *   3. Multi-document streams — operators expecting a single doc
 *      silently get the first one and ignore the rest, which can mask
 *      hostile content.
 *
 *   4. Norway problem — YAML 1.1 (still default in pyyaml + libyaml
 *      in 2026) treats unquoted no/yes/y/n/on/off as booleans. Country
 *      code "NO" → false.
 *
 *   5. Leading-zero octals — 0777 parses as octal 511 in YAML 1.1.
 *
 *   6. Duplicate keys — YAML 1.2 SHOULD-unique; parsers silently
 *      last-wins, same threat shape as JSON duplicate-key smuggling.
 *
 *   7. Local + custom user tags — even when not language-specific,
 *      surface that suggests a non-safe parser is downstream.
 *
 *   8. Merge-key chain depth (<<: *anchor) — anchor-chain DoS.
 *
 *   9. Bidi / null / control / zero-width chars in scalar values.
 *
 *  10. Anti-DoS caps — total document size, total node count, max
 *      anchors, max alias depth, max document count, max scalar
 *      length, max depth.
 */

var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var safeYamlLazy = lazyRequire(function () { return require("./parsers/safe-yaml"); });
var { GuardYamlError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardYamlError.factory;

// ---- Source-level threat detectors ----

// Dangerous tag prefixes — language-specific deserialization triggers.
var DANGEROUS_TAG_PREFIXES = Object.freeze([
  "!!python/", "!!java.", "!!ruby/", "!!perl/", "!!js/", "!!cs/",
  "!!net/", "!!system.", "!!eval", "!!exec", "!!new", "!!apply",
]);

// YAML 1.2 core tag allowlist — when allowing tags at all, only these
// are permitted under balanced.
var SAFE_CORE_TAGS = Object.freeze([
  "!!str", "!!int", "!!float", "!!bool", "!!null",
  "!!seq", "!!map", "!!set", "!!omap", "!!pairs",
  "!!binary", "!!timestamp", "!!merge",
]);

// Anchor declaration — &name. Alias reference — *name.
var ANCHOR_DECL_RE = /(^|\s|:|-)(&[A-Za-z_][A-Za-z0-9_-]*)/g;
var ALIAS_REF_RE   = /(^|\s|:|-|\[|\{|,)(\*[A-Za-z_][A-Za-z0-9_-]*)/g;

// Norway problem — unquoted YAML 1.1 boolean-shaped tokens at scalar
// position. true/false ARE valid YAML 1.2 booleans so we don't flag
// them; only the no/yes/y/n/on/off quirks fire.
var NORWAY_BOOL_QUIRK_RE = /:\s*(no|yes|y|n|on|off)\b/gi;

// Leading-zero octals — 0777 etc. at scalar position.
var LEADING_ZERO_OCTAL_RE = /:\s*0\d+\b/g;

// Merge keys — <<: *anchor chain.
var MERGE_KEY_RE = /<<\s*:\s*\*/;

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    tagPolicy:              "reject",
    aliasPolicy:            "reject",
    multiDocPolicy:         "reject",
    norwayPolicy:           "reject",
    leadingZeroPolicy:      "reject",
    duplicateKeyPolicy:     "reject",
    mergeKeyPolicy:         "reject",
    bidiPolicy:             "reject",
    controlPolicy:          "reject",
    nullBytePolicy:         "reject",
    zeroWidthPolicy:        "reject",
    safeCoreTagsAllowed:    false,
    maxBytes:               C.BYTES.mib(2),
    maxDepth:               8,                                                   // allow:raw-byte-literal — recursion depth, not byte size
    maxAnchors:             16,                                                  // allow:raw-byte-literal — anchor count cap, not byte size
    maxAliasDepth:          1,                                                   // allow:raw-byte-literal — alias chain cap, not byte size
    maxDocuments:           1,                                                   // allow:raw-byte-literal — doc count cap, not byte size
    maxNodes:               1024,                                                // allow:raw-byte-literal — node count cap, not byte size
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
    maxDepth:               32,                                                  // allow:raw-byte-literal — recursion depth, not byte size
    maxAnchors:             64,                                                  // allow:raw-byte-literal — anchor count cap, not byte size
    maxAliasDepth:          3,                                                   // allow:raw-byte-literal — alias chain cap, not byte size
    maxDocuments:           16,                                                  // allow:raw-byte-literal — doc count cap, not byte size
    maxNodes:               16384,                                               // allow:raw-byte-literal — node count cap, not byte size
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
    maxDepth:               64,                                                  // allow:raw-byte-literal — recursion depth, not byte size
    maxAnchors:             1024,                                                // allow:raw-byte-literal — anchor count cap, not byte size
    maxAliasDepth:          8,                                                   // allow:raw-byte-literal — alias chain cap, not byte size
    maxDocuments:           256,                                                 // allow:raw-byte-literal — doc count cap, not byte size
    maxNodes:               65536,                                               // allow:raw-byte-literal — node count cap, not byte size
    maxScalarLength:        C.BYTES.kib(256),
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

// ---- Helpers ----

function _resolveOpts(opts) {
  return gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardYamlError,
    errCodePrefix:      "yaml",
  });
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

// _scanTags — find every tag-prefix occurrence in the source.
function _scanTags(text) {
  var matches = [];
  var iter = text.matchAll(/(^|\s)(![A-Za-z][\w./:-]*|!![A-Za-z][\w./:-]*)/g);
  var m;
  for (m of iter) {
    var tag = m[2];
    var kind;
    if (_isDangerousTag(tag)) kind = "dangerous";
    else if (_isSafeCoreTag(tag)) kind = "safe-core";
    else kind = "custom";
    matches.push({ tag: tag, location: m.index, kind: kind });
  }
  return matches;
}

function _detectIssues(input, opts) {
  var issues = [];
  if (typeof input !== "string") {
    return [{ kind: "bad-input", severity: "high",
              snippet: "input is not a string" }];
  }
  if (input.length > opts.maxBytes) {
    return [{ kind: "too-large", severity: "high", ruleId: "yaml.too-large",
              snippet: "input " + input.length +
                       " bytes exceeds maxBytes " + opts.maxBytes }];
  }

  // 1. Tag-injection scan.
  var tagHits = _scanTags(input);
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

  // 2. Anchor / alias recursion scan.
  var anchors = [];
  var aIter = input.matchAll(ANCHOR_DECL_RE);
  var aM;
  for (aM of aIter) anchors.push(aM[2]);
  var aliases = [];
  var alIter = input.matchAll(ALIAS_REF_RE);
  var alM;
  for (alM of alIter) aliases.push(alM[2]);
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
  // alias-amplification ratio: aliases / anchors. Billion-laughs shape
  // is ratio >= 8. Independent of maxAnchors absolute cap (which is
  // about overall load); ratio is about exponential expansion shape.
  var ampRatio = aliases.length / Math.max(anchors.length, 1);
  if (anchors.length >= 1 && ampRatio >= 8) {                                    // allow:raw-byte-literal — multiplier ratio, not byte size
    issues.push({
      kind: "alias-explosion", severity: "critical",
      ruleId: "yaml.alias-explosion",
      snippet: "alias-reference count " + aliases.length +
               " amplifies " + ampRatio.toFixed(1) +
               "x against " + anchors.length + " anchor(s) (billion-laughs shape)",
    });
  }

  // 3. Multi-document.
  var docs = (input.match(/(^|\n)---\s/g) || []).length;
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

  // 4. Norway-problem implicit booleans.
  if (opts.norwayPolicy !== "allow") {
    var norwayIter = input.matchAll(NORWAY_BOOL_QUIRK_RE);
    var norwayM;
    var seen = false;
    for (norwayM of norwayIter) {
      if (!seen) {
        issues.push({
          kind: "norway-implicit-bool",
          severity: opts.norwayPolicy === "reject" ? "critical" : "warn",
          ruleId: "yaml.norway",
          location: norwayM.index,
          snippet: "implicit YAML 1.1 boolean " + JSON.stringify(norwayM[1]) +
                   " (Norway problem — country code 'NO' parses as false; " +
                   "quote scalars to disambiguate)",
        });
        seen = true;
      }
    }
  }

  // 5. Leading-zero octals.
  if (opts.leadingZeroPolicy !== "allow") {
    if (LEADING_ZERO_OCTAL_RE.test(input)) {                                     // allow:regex-no-length-cap — input bounded by maxBytes above
      issues.push({
        kind: "leading-zero-octal",
        severity: opts.leadingZeroPolicy === "reject" ? "high" : "warn",
        ruleId: "yaml.leading-zero",
        snippet: "leading-zero numeric (parses as octal in YAML 1.1)",
      });
    }
  }

  // 6. Merge-key chain depth.
  if (opts.mergeKeyPolicy !== "allow" && MERGE_KEY_RE.test(input)) {             // allow:regex-no-length-cap — input bounded by maxBytes above
    issues.push({
      kind: "merge-key",
      severity: opts.mergeKeyPolicy === "reject" ? "high" : "warn",
      ruleId: "yaml.merge-key",
      snippet: "merge-key with anchor reference (anchor-chain DoS vector)",
    });
  }

  // 7. Codepoint-class threats.
  issues.push.apply(issues, codepointClass.detectCharThreats(input, opts, "yaml"));

  // 8. Duplicate keys via per-indent block-mapping scan. Done BEFORE
  // parse because some parsers refuse-on-duplicate, and we want the
  // duplicate-key issue surfaced regardless of parser strictness.
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

  // 9. Try parse via b.parsers.yaml.
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

function _detectDuplicateKeysYaml(text) {
  var dups = Object.create(null);
  var lines = text.split(/\r?\n/);
  var indentScopes = Object.create(null);
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    if (line.length === 0 || /^\s*#/.test(line)) continue;
    var indentMatch = line.match(/^(\s*)([^\s].*?):(\s|$)/);
    if (!indentMatch) continue;
    var indent = indentMatch[1].length;
    var key = indentMatch[2].trim();
    if (key.charAt(0) === "-" || key.charAt(0) === "[" || key.charAt(0) === "{") continue;
    if (!indentScopes[indent]) indentScopes[indent] = Object.create(null);
    if (indentScopes[indent][key]) dups[key] = true;
    else indentScopes[indent][key] = true;
    Object.keys(indentScopes).forEach(function (k) {
      if (Number(k) > indent) delete indentScopes[k];
    });
  }
  return Object.keys(dups);
}

// ---- Public surface ----

function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes", "maxDepth", "maxAnchors", "maxAliasDepth",
     "maxDocuments", "maxNodes", "maxScalarLength"],
    "guardYaml.validate", GuardYamlError, "yaml.bad-opt");
  if (typeof input !== "string") {
    return {
      ok: false,
      issues: [{ kind: "bad-input", severity: "high",
                 snippet: "input is not a string" }],
    };
  }
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

function parse(input, opts) {
  opts = _resolveOpts(opts);
  if (typeof input !== "string") {
    throw _err("yaml.bad-input", "parse requires string input");
  }
  var issues = _detectIssues(input, opts);
  for (var i = 0; i < issues.length; i += 1) {
    if (issues[i].severity === "critical") {
      throw _err(issues[i].ruleId || "yaml.refused",
        "guardYaml.parse: " + issues[i].snippet);
    }
  }
  return safeYamlLazy().parse(input, {
    maxBytes:  opts.maxBytes,
    maxDepth:  opts.maxDepth,
    maxKeys:   opts.maxNodes,
  });
}

function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardYaml:" + (opts.profile || "default"),
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
      return { ok: false, action: "refuse", issues: rv.issues };
    });
}

var buildProfile = gateContract.makeProfileBuilder(PROFILES);

function compliancePosture(name) {
  return gateContract.lookupCompliancePosture(name, COMPLIANCE_POSTURES, _err, "yaml");
}

var _yamlRulePacks = gateContract.makeRulePackLoader(GuardYamlError, "yaml");
var loadRulePack = _yamlRulePacks.load;

module.exports = {
  // ---- guard-* family registry exports ----
  NAME:                "yaml",
  KIND:                "content",
  MIME_TYPES:          Object.freeze([
    "application/yaml", "application/x-yaml", "text/yaml", "text/x-yaml",
  ]),
  EXTENSIONS:          Object.freeze([".yml", ".yaml"]),
  INTEGRATION_FIXTURES: Object.freeze({
    kind:         "content",
    contentType:  "application/yaml",
    extension:    ".yaml",
    benignBytes:  Buffer.from('name: alice\nage: 30\n', "utf8"),
    // Hostile: deserialization-tag injection (CVE-2026-24009 PyYAML
    // class). Parser-runtime would attempt to instantiate the named
    // language-specific class.
    hostileBytes: Buffer.from("!!python/object/new:cls\nargs: [\"x\"]\n", "utf8"),
  }),
  // ---- primitive surface ----
  validate:            validate,
  parse:               parse,
  gate:                gate,
  buildProfile:        buildProfile,
  compliancePosture:   compliancePosture,
  loadRulePack:        loadRulePack,
  PROFILES:            PROFILES,
  DEFAULTS:            DEFAULTS,
  COMPLIANCE_POSTURES: COMPLIANCE_POSTURES,
  DANGEROUS_TAG_PREFIXES: DANGEROUS_TAG_PREFIXES,
  SAFE_CORE_TAGS:      SAFE_CORE_TAGS,
  GuardYamlError:      GuardYamlError,
};
