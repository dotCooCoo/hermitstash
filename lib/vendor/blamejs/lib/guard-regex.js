"use strict";
/**
 * guard-regex — Regex pattern identifier-safety primitive
 * (b.guardRegex).
 *
 * Validates user-supplied regex pattern strings for catastrophic-
 * backtracking (ReDoS) shapes BEFORE compilation. KIND="identifier" —
 * consumes ctx.identifier (or ctx.pattern).
 *
 * Threat catalog:
 *   - Nested quantifiers — `(a+)+`, `(a*)+`, `(.+)+`. The classic
 *     ReDoS shape. CVE-2024-21538 (cross-spawn) and CVE-2022-25929
 *     (chartjs-adapter-luxon) are recent prominent examples.
 *   - Quantifier-after-grouped-quantifier — `(a|b)+\w*` style strings.
 *   - Alternation overlap with quantifier — `(\d|\d{2})*`.
 *   - Bounded quantifiers with very large counts — operator-tunable
 *     via maxBoundedRepeat.
 *   - Excessive pattern length — defense against parser DoS.
 *   - Lookbehind / lookahead with quantifiers inside.
 *   - BIDI / null / control / zero-width universal refuse.
 *
 *   var rv = b.guardRegex.validate("(a+)+b", { profile: "strict" });
 *   var g  = b.guardRegex.gate({ profile: "strict" });
 */

var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var { GuardRegexError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardRegexError.factory;

// Nested-quantifier detector: `(group)+`-style followed by another
// quantifier or repetition that operates on the grouped match.
var NESTED_QUANT_RE = /\([^()]*[*+?][^()]*\)\s*[*+?{]/;

// Alternation-with-quantifier — `(a|b|...)+`, `(a|b)*`.
var ALTERNATION_QUANT_RE = /\([^()]*\|[^()]*\)\s*[*+]/;

// Bounded repetition — captures the upper bound when present.
var BOUNDED_REPEAT_RE = /\{(\d+)(?:,(\d*))?\}/g;

// Lookaround with internal quantifier — `(?=.*+)`, `(?!a*)`.
var LOOKAROUND_QUANT_RE = /\(\?[=!<][^()]*[*+]/;

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    bidiPolicy:               "reject",
    controlPolicy:             "reject",
    nullBytePolicy:            "reject",
    zeroWidthPolicy:           "reject",
    nestedQuantPolicy:         "reject",
    alternationQuantPolicy:    "reject",
    boundedRepeatPolicy:       "reject",
    lookaroundQuantPolicy:     "reject",
    maxBoundedRepeat:          100,                                              // allow:raw-byte-literal — bounded repeat ceiling
    maxPatternBytes:           C.BYTES.kib(1),
    maxBytes:                  C.BYTES.kib(1),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
  "balanced": {
    bidiPolicy:               "reject",
    controlPolicy:             "reject",
    nullBytePolicy:            "reject",
    zeroWidthPolicy:           "reject",
    nestedQuantPolicy:         "reject",
    alternationQuantPolicy:    "audit",
    boundedRepeatPolicy:       "audit",
    lookaroundQuantPolicy:     "audit",
    maxBoundedRepeat:          1000,                                             // allow:raw-byte-literal — bounded repeat ceiling
    maxPatternBytes:           C.BYTES.kib(2),
    maxBytes:                  C.BYTES.kib(2),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
  "permissive": {
    bidiPolicy:               "reject",                                          // BIDI refused at every profile
    controlPolicy:             "reject",                                          // controls refused at every profile
    nullBytePolicy:            "reject",                                          // null refused at every profile
    zeroWidthPolicy:           "reject",                                          // zero-width refused at every profile
    nestedQuantPolicy:         "reject",                                          // canonical ReDoS class refused at every profile
    alternationQuantPolicy:    "allow",
    boundedRepeatPolicy:       "audit",
    lookaroundQuantPolicy:     "audit",
    maxBoundedRepeat:          10000,                                            // allow:raw-byte-literal — bounded repeat ceiling
    maxPatternBytes:           C.BYTES.kib(8),
    maxBytes:                  C.BYTES.kib(8),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
});

var DEFAULTS = Object.freeze(Object.assign({}, PROFILES["strict"], {
  mode: "enforce",
}));

var COMPLIANCE_POSTURES = Object.freeze({
  "hipaa":   Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(256),
  }),
  "pci-dss": Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(256),
  }),
  "gdpr":    Object.assign({}, PROFILES["balanced"], {
    forensicSnippetBytes: C.BYTES.bytes(128),
  }),
  "soc2":    Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(512),
  }),
});

function _resolveOpts(opts) {
  return gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardRegexError,
    errCodePrefix:      "regex",
  });
}

function _detectIssues(input, opts) {
  var issues = [];
  if (typeof input !== "string") {
    return [{ kind: "bad-input", severity: "high",
              ruleId: "regex.bad-input",
              snippet: "regex pattern is not a string" }];
  }
  if (input.length === 0) {
    return [{ kind: "empty", severity: "high",
              ruleId: "regex.empty",
              snippet: "regex pattern is empty" }];
  }
  if (Buffer.byteLength(input, "utf8") > opts.maxPatternBytes) {
    return [{ kind: "pattern-cap", severity: "high",
              ruleId: "regex.pattern-cap",
              snippet: "regex pattern exceeds maxPatternBytes " +
                       opts.maxPatternBytes }];
  }

  var charThreats = codepointClass.detectCharThreats(input, opts, "regex");
  for (var ci = 0; ci < charThreats.length; ci += 1) issues.push(charThreats[ci]);

  if (opts.nestedQuantPolicy !== "allow" && NESTED_QUANT_RE.test(input)) {       // allow:regex-no-length-cap — input bounded by maxPatternBytes
    issues.push({
      kind: "nested-quantifier", severity: "critical",
      ruleId: "regex.nested-quantifier",
      snippet: "pattern contains nested-quantifier shape (e.g. " +
               "`(a+)+`) — canonical ReDoS catastrophic-backtracking " +
               "class (CVE-2024-21538 cross-spawn / CVE-2022-25929)",
    });
  }

  if (opts.alternationQuantPolicy !== "allow" &&
      ALTERNATION_QUANT_RE.test(input)) {                                        // allow:regex-no-length-cap — input bounded by maxPatternBytes
    issues.push({
      kind: "alternation-quantifier",
      severity: opts.alternationQuantPolicy === "reject" ? "high" : "warn",
      ruleId: "regex.alternation-quantifier",
      snippet: "pattern contains alternation-with-quantifier shape " +
               "(e.g. `(a|b)+`) — alternation overlap may amplify " +
               "search paths",
    });
  }

  if (opts.lookaroundQuantPolicy !== "allow" &&
      LOOKAROUND_QUANT_RE.test(input)) {                                         // allow:regex-no-length-cap — input bounded by maxPatternBytes
    issues.push({
      kind: "lookaround-quantifier",
      severity: opts.lookaroundQuantPolicy === "reject" ? "high" : "warn",
      ruleId: "regex.lookaround-quantifier",
      snippet: "pattern contains quantifier inside lookaround " +
               "(`(?=.*+)`) — catastrophic in some engines",
    });
  }

  if (opts.boundedRepeatPolicy !== "allow") {
    BOUNDED_REPEAT_RE.lastIndex = 0;
    var match;
    while ((match = BOUNDED_REPEAT_RE.exec(input)) !== null) {                   // allow:regex-no-length-cap — input bounded by maxPatternBytes
      var lower = parseInt(match[1], 10);                                        // allow:raw-byte-literal — base-10 radix
      var upper = match[2] === undefined ? lower :
                  match[2] === "" ? Infinity : parseInt(match[2], 10);           // allow:raw-byte-literal — base-10 radix
      var ceiling = (upper === Infinity || upper > lower) ? upper : lower;
      if (ceiling > opts.maxBoundedRepeat) {
        issues.push({
          kind: "bounded-repeat-cap",
          severity: opts.boundedRepeatPolicy === "reject" ? "high" : "warn",
          ruleId: "regex.bounded-repeat-cap",
          snippet: "bounded-repeat `" + match[0] + "` upper bound " +
                   (ceiling === Infinity ? "unbounded" : ceiling) +
                   " exceeds maxBoundedRepeat " + opts.maxBoundedRepeat,
        });
        break;
      }
    }
  }

  return issues;
}

function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes", "maxPatternBytes", "maxBoundedRepeat"],
    "guardRegex.validate", GuardRegexError, "regex.bad-opt");
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

function sanitize(input, opts) {
  opts = _resolveOpts(opts);
  if (typeof input !== "string") {
    throw _err("regex.bad-input", "sanitize requires string input");
  }
  var issues = _detectIssues(input, opts);
  for (var i = 0; i < issues.length; i += 1) {
    if (issues[i].severity === "critical" || issues[i].severity === "high") {
      throw _err(issues[i].ruleId || "regex.refused",
        "guardRegex.sanitize: " + issues[i].snippet);
    }
  }
  return input;
}

function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardRegex:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var pattern = ctx && (ctx.identifier || ctx.pattern);
      if (pattern === undefined || pattern === null) {
        return { ok: true, action: "serve" };
      }
      var rv = validate(pattern, opts);
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
    _err, "regex");
}

var _regexRulePacks = gateContract.makeRulePackLoader(GuardRegexError, "regex");
var loadRulePack = _regexRulePacks.load;

module.exports = {
  // ---- guard-* family registry exports ----
  NAME:                "regex",
  KIND:                "identifier",
  INTEGRATION_FIXTURES: Object.freeze({
    kind:              "identifier",
    benignBytes:       Buffer.from("^[a-z]+$", "utf8"),
    hostileBytes:      Buffer.from("(a+)+b", "utf8"),
    benignIdentifier:  "^[a-z]+$",
    hostileIdentifier: "(a+)+b",
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
  GuardRegexError:     GuardRegexError,
};
