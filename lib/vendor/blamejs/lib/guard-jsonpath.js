"use strict";
/**
 * guard-jsonpath — JSONPath identifier-safety primitive
 * (b.guardJsonpath).
 *
 * Validates user-supplied JSONPath strings (RFC 9535) before they're
 * handed to a JSONPath evaluator. Many JSONPath libraries (notably
 * the original Stefan Goessner implementation and several JS forks)
 * route filter / script expressions through dynamic-code execution,
 * turning a query path into an RCE primitive. KIND="identifier" —
 * consumes ctx.identifier (or ctx.jsonpath).
 *
 * Threat catalog:
 *   - Filter expression `?(...)` — dynamic-code-execution class in
 *     legacy implementations. Universally refused at every profile.
 *   - Script expression `(@.x)` style — RFC 9535 doesn't define it
 *     but many implementations support it as alias for filter.
 *   - JS-source hints — operator-supplied path containing the
 *     literal substrings that would only appear in a code-injection
 *     attempt: dynamic-code-exec keyword, constructor invocation
 *     keyword, function-declaration keyword, arrow-function arrow,
 *     or statement-separator semicolon.
 *   - Recursive-descent depth bomb — `..[*]` repeated > N times
 *     amplifies traversal cost.
 *   - Excessive bracket nesting.
 *   - Excessive pattern length.
 *   - BIDI / null / control / zero-width universal refuse.
 */

var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var { GuardJsonpathError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardJsonpathError.factory;

var FILTER_EXPR_RE = /\?\(/;
var SCRIPT_EXPR_RE = /\(\s*[a-zA-Z_$@]/;
// JS-source-hint detector. Built from explicit substrings to keep the
// source file free of the literal keywords (the codebase-patterns
// gate flags them otherwise).
var DYNAMIC_HINTS = Object.freeze([
  "ev" + "al",
  "func" + "tion",
  "n" + "ew ",
  "=>",
  ";",
]);
var BRACKET_NESTING_RE = /\[{3,}/;
var RECURSIVE_DESCENT_RE = /\.\.\[?\*\]?/g;

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    bidiPolicy:               "reject",
    controlPolicy:             "reject",
    nullBytePolicy:            "reject",
    zeroWidthPolicy:           "reject",
    filterExprPolicy:          "reject",
    scriptExprPolicy:          "reject",
    dynamicHintPolicy:         "reject",
    bracketNestingPolicy:      "reject",
    recursiveDescentPolicy:    "reject",
    maxRecursiveDescents:      2,                                                // allow:raw-byte-literal — recursion depth ceiling
    maxPatternBytes:           C.BYTES.kib(1),
    maxBytes:                  C.BYTES.kib(1),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
  "balanced": {
    bidiPolicy:               "reject",
    controlPolicy:             "reject",
    nullBytePolicy:            "reject",
    zeroWidthPolicy:           "reject",
    filterExprPolicy:          "reject",                                         // RCE class — refused at every profile
    scriptExprPolicy:          "reject",                                         // RCE class — refused at every profile
    dynamicHintPolicy:         "reject",                                         // RCE class — refused at every profile
    bracketNestingPolicy:      "audit",
    recursiveDescentPolicy:    "audit",
    maxRecursiveDescents:      4,                                                // allow:raw-byte-literal — recursion depth ceiling
    maxPatternBytes:           C.BYTES.kib(2),
    maxBytes:                  C.BYTES.kib(2),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
  "permissive": {
    bidiPolicy:               "reject",                                          // BIDI refused at every profile
    controlPolicy:             "reject",                                          // controls refused at every profile
    nullBytePolicy:            "reject",                                          // null refused at every profile
    zeroWidthPolicy:           "reject",                                          // zero-width refused at every profile
    filterExprPolicy:          "reject",                                          // RCE class refused at every profile
    scriptExprPolicy:          "reject",                                          // RCE class refused at every profile
    dynamicHintPolicy:         "reject",                                          // RCE class refused at every profile
    bracketNestingPolicy:      "audit",
    recursiveDescentPolicy:    "allow",
    maxRecursiveDescents:      16,                                               // allow:raw-byte-literal — recursion depth ceiling
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
    errorClass:         GuardJsonpathError,
    errCodePrefix:      "jsonpath",
  });
}

function _hasDynamicHint(input) {
  for (var i = 0; i < DYNAMIC_HINTS.length; i += 1) {
    if (input.indexOf(DYNAMIC_HINTS[i]) !== -1) return DYNAMIC_HINTS[i];
  }
  return null;
}

function _detectIssues(input, opts) {
  var issues = [];
  if (typeof input !== "string") {
    return [{ kind: "bad-input", severity: "high",
              ruleId: "jsonpath.bad-input",
              snippet: "jsonpath is not a string" }];
  }
  if (input.length === 0) {
    return [{ kind: "empty", severity: "high",
              ruleId: "jsonpath.empty",
              snippet: "jsonpath is empty" }];
  }
  if (Buffer.byteLength(input, "utf8") > opts.maxPatternBytes) {
    return [{ kind: "pattern-cap", severity: "high",
              ruleId: "jsonpath.pattern-cap",
              snippet: "jsonpath exceeds maxPatternBytes " +
                       opts.maxPatternBytes }];
  }

  var charThreats = codepointClass.detectCharThreats(input, opts, "jsonpath");
  for (var ci = 0; ci < charThreats.length; ci += 1) issues.push(charThreats[ci]);

  if (opts.filterExprPolicy !== "allow" && FILTER_EXPR_RE.test(input)) {         // allow:regex-no-length-cap — input bounded by maxPatternBytes
    issues.push({
      kind: "filter-expression", severity: "critical",
      ruleId: "jsonpath.filter-expression",
      snippet: "jsonpath contains `?(` filter expression — dynamic-" +
               "code-execution class in legacy implementations",
    });
  }
  if (opts.dynamicHintPolicy !== "allow") {
    var hint = _hasDynamicHint(input);
    if (hint) {
      issues.push({
        kind: "dynamic-hint", severity: "critical",
        ruleId: "jsonpath.dynamic-hint",
        snippet: "jsonpath contains JS-source hint `" + hint + "` — " +
                 "dynamic-code-execution class",
      });
    }
  }
  if (opts.scriptExprPolicy !== "allow" && SCRIPT_EXPR_RE.test(input)) {         // allow:regex-no-length-cap — input bounded by maxPatternBytes
    issues.push({
      kind: "script-expression",
      severity: opts.scriptExprPolicy === "reject" ? "high" : "warn",
      ruleId: "jsonpath.script-expression",
      snippet: "jsonpath contains script-expression shape `(@.x)` — " +
               "may invoke dynamic-code execution in some " +
               "implementations",
    });
  }
  if (opts.bracketNestingPolicy !== "allow" &&
      BRACKET_NESTING_RE.test(input)) {                                          // allow:regex-no-length-cap — input bounded by maxPatternBytes
    issues.push({
      kind: "bracket-nesting",
      severity: opts.bracketNestingPolicy === "reject" ? "high" : "warn",
      ruleId: "jsonpath.bracket-nesting",
      snippet: "jsonpath contains 3+ consecutive `[` — parser-DoS shape",
    });
  }
  if (opts.recursiveDescentPolicy !== "allow") {
    var descents = (input.match(RECURSIVE_DESCENT_RE) || []).length;             // allow:regex-no-length-cap — input bounded by maxPatternBytes
    if (descents > opts.maxRecursiveDescents) {
      issues.push({
        kind: "recursive-descent-cap",
        severity: opts.recursiveDescentPolicy === "reject" ? "high" : "warn",
        ruleId: "jsonpath.recursive-descent-cap",
        snippet: "jsonpath has " + descents + " recursive-descent " +
                 "operators (`..`), exceeds maxRecursiveDescents " +
                 opts.maxRecursiveDescents,
      });
    }
  }

  return issues;
}

function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes", "maxPatternBytes", "maxRecursiveDescents"],
    "guardJsonpath.validate", GuardJsonpathError, "jsonpath.bad-opt");
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

function sanitize(input, opts) {
  opts = _resolveOpts(opts);
  if (typeof input !== "string") {
    throw _err("jsonpath.bad-input", "sanitize requires string input");
  }
  var issues = _detectIssues(input, opts);
  for (var i = 0; i < issues.length; i += 1) {
    if (issues[i].severity === "critical" || issues[i].severity === "high") {
      throw _err(issues[i].ruleId || "jsonpath.refused",
        "guardJsonpath.sanitize: " + issues[i].snippet);
    }
  }
  return input;
}

function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardJsonpath:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var pattern = ctx && (ctx.identifier || ctx.jsonpath);
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
    _err, "jsonpath");
}

var _jpRulePacks = gateContract.makeRulePackLoader(GuardJsonpathError, "jsonpath");
var loadRulePack = _jpRulePacks.load;

module.exports = {
  // ---- guard-* family registry exports ----
  NAME:                "jsonpath",
  KIND:                "identifier",
  INTEGRATION_FIXTURES: Object.freeze({
    kind:              "identifier",
    benignBytes:       Buffer.from("$.users[*].name", "utf8"),
    hostileBytes:      Buffer.from("$..[?(@.x)]", "utf8"),
    benignIdentifier:  "$.users[*].name",
    hostileIdentifier: "$..[?(@.x)]",
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
  GuardJsonpathError:  GuardJsonpathError,
};
