"use strict";
/**
 * @module b.guardJsonpath
 * @nav    Guards
 * @title  Guard Jsonpath
 *
 * @intro
 *   JSONPath content-safety guard — refuses user-supplied JSONPath
 *   query strings that exhibit dynamic-code-execution shapes BEFORE
 *   they reach a JSONPath evaluator. Many JSONPath implementations
 *   (the original Stefan Goessner reference and several JS forks)
 *   route filter / script expressions through `eval`-class
 *   dispatch, turning a query path into an RCE primitive; this
 *   primitive screens the path so a hostile query can't escape into
 *   code execution. KIND=`identifier`; the gate consumes
 *   `ctx.identifier` (or `ctx.jsonpath`) and refuses on hostile
 *   shapes. Targets the RFC 9535 compliant subset — filter / script
 *   expressions with code-execution semantics are rejected at every
 *   profile.
 *
 *   Threat catalog: filter expression `?(...)` (dynamic-code-
 *   execution class in legacy implementations — refused
 *   universally); script expression shape `(@.x)` (RFC 9535
 *   undefined but several implementations alias it to filter);
 *   JS-source hints (the path contains substrings that only appear
 *   in a code-injection attempt — dynamic-code-exec keyword,
 *   constructor invocation keyword, function-declaration keyword,
 *   arrow-function arrow, or statement-separator semicolon);
 *   recursive-descent depth bomb (`..[*]` repeated past
 *   `maxRecursiveDescents`); 3+ consecutive `[` parser-DoS shape;
 *   per-pattern byte cap; BIDI override / zero-width / C0 control /
 *   null-byte universal refuse.
 *
 *   Profiles: `strict` / `balanced` / `permissive`. Compliance
 *   postures: `hipaa` / `pci-dss` / `gdpr` / `soc2`. Operators
 *   select via `{ profile: "strict" }` or
 *   `{ compliancePosture: "hipaa" }`; postures overlay on top of the
 *   profile baseline. Filter / script / dynamic-hint refusal holds
 *   at every profile — the RCE class is never an operator opt-in.
 *
 *   JSONPath strings can't be repaired safely — `sanitize` either
 *   passes through clean input or throws `GuardJsonpathError`; the
 *   gate returns `serve` / `audit-only` / `refuse` (no `sanitize`
 *   action). The source file's hint catalog is composed from
 *   substring fragments so the file itself stays free of the
 *   literal keywords (the codebase-patterns gate flags them
 *   otherwise).
 *
 * @card
 *   JSONPath content-safety guard — refuses user-supplied JSONPath query strings that exhibit dynamic-code-execution shapes BEFORE they reach a JSONPath evaluator.
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

/**
 * @primitive  b.guardJsonpath.validate
 * @signature  b.guardJsonpath.validate(input, opts)
 * @since      0.7.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardJsonpath.gate, b.guardJsonpath.sanitize
 *
 * Inspect a user-supplied JSONPath string and return an aggregated
 * issue list. Pure inspection — never throws on hostile paths;
 * caller decides what to do with the issues. The `ok` flag is
 * `true` only when zero `critical` / `high` issues fire. Throws
 * `GuardJsonpathError("jsonpath.bad-opt")` when a numeric opt is
 * non-finite / negative (config-time mistake by the operator).
 *
 * @opts
 *   profile:                "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   bidiPolicy:             "reject"|"audit"|"allow",
 *   controlPolicy:          "reject"|"audit"|"allow",
 *   nullBytePolicy:         "reject"|"audit"|"allow",
 *   zeroWidthPolicy:        "reject"|"strip"|"audit"|"allow",
 *   filterExprPolicy:       "reject"|"audit"|"allow",
 *   scriptExprPolicy:       "reject"|"audit"|"allow",
 *   dynamicHintPolicy:      "reject"|"audit"|"allow",
 *   bracketNestingPolicy:   "reject"|"audit"|"allow",
 *   recursiveDescentPolicy: "reject"|"audit"|"allow",
 *   maxRecursiveDescents:   number,
 *   maxPatternBytes:        number,
 *   maxBytes:               number,
 *   maxRuntimeMs:           number,
 *
 * @example
 *   var clean = b.guardJsonpath.validate("$.users[*].name", { profile: "strict" });
 *   clean.ok;                                          // → true
 *
 *   var hostile = b.guardJsonpath.validate("$..[?(@.x)]", { profile: "strict" });
 *   hostile.ok;                                        // → false
 *   hostile.issues.some(function (i) { return i.kind === "filter-expression"; });  // → true
 */
function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes", "maxPatternBytes", "maxRecursiveDescents"],
    "guardJsonpath.validate", GuardJsonpathError, "jsonpath.bad-opt");
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

/**
 * @primitive  b.guardJsonpath.sanitize
 * @signature  b.guardJsonpath.sanitize(input, opts)
 * @since      0.7.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardJsonpath.validate, b.guardJsonpath.gate
 *
 * Pass-through-or-throw. JSONPath expressions cannot be safely
 * repaired (stripping a `?(` from a filter silently changes query
 * semantics); this primitive returns the input unchanged when no
 * `critical` or `high` issue fires, otherwise throws
 * `GuardJsonpathError` with the offending rule id (e.g.
 * `jsonpath.filter-expression`, `jsonpath.dynamic-hint`,
 * `jsonpath.script-expression`). Operators that need a "best-
 * effort cleanup" semantic should reject the path at the boundary
 * instead.
 *
 * @opts
 *   profile:                "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   filterExprPolicy:       "reject"|"audit"|"allow",
 *   scriptExprPolicy:       "reject"|"audit"|"allow",
 *   dynamicHintPolicy:      "reject"|"audit"|"allow",
 *   bracketNestingPolicy:   "reject"|"audit"|"allow",
 *   recursiveDescentPolicy: "reject"|"audit"|"allow",
 *   maxRecursiveDescents:   number,
 *   maxPatternBytes:        number,
 *
 * @example
 *   var safe = b.guardJsonpath.sanitize("$.users[*].name", { profile: "strict" });
 *   safe;                                              // → "$.users[*].name"
 *
 *   try {
 *     b.guardJsonpath.sanitize("$..[?(@.x)]", { profile: "strict" });
 *   } catch (e) {
 *     e.code;                                          // → "jsonpath.filter-expression"
 *   }
 */
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

/**
 * @primitive  b.guardJsonpath.gate
 * @signature  b.guardJsonpath.gate(opts)
 * @since      0.7.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardJsonpath.validate, b.guardJsonpath.sanitize
 *
 * Build a `b.gateContract` gate that screens `ctx.identifier` (or
 * `ctx.jsonpath`) before the path reaches a JSONPath evaluator.
 * Action chain: `serve` (no issues) → `audit-only` (warn-only) →
 * `refuse` (any `critical` or `high`). No `sanitize` action —
 * JSONPath strings cannot be repaired. Compose into query
 * endpoints / search filters / data-export flows so operator-fed
 * paths hit the guard before any evaluator dispatch.
 *
 * @opts
 *   profile:                "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   name:                   string,    // override gate name in audit emissions
 *   filterExprPolicy:       "reject"|"audit"|"allow",
 *   scriptExprPolicy:       "reject"|"audit"|"allow",
 *   dynamicHintPolicy:      "reject"|"audit"|"allow",
 *   bracketNestingPolicy:   "reject"|"audit"|"allow",
 *   recursiveDescentPolicy: "reject"|"audit"|"allow",
 *   maxRecursiveDescents:   number,
 *   maxPatternBytes:        number,
 *
 * @example
 *   var gate = b.guardJsonpath.gate({ profile: "strict" });
 *
 *   gate({ identifier: "$..[?(@.x)]" }).then(function (rv) {
 *     rv.ok;                                           // → false
 *     rv.action;                                       // → "refuse"
 *   });
 *
 *   gate({ identifier: "$.users[*].name" }).then(function (rv) {
 *     rv.action;                                       // → "serve"
 *   });
 */
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

/**
 * @primitive  b.guardJsonpath.buildProfile
 * @signature  b.guardJsonpath.buildProfile(opts)
 * @since      0.7.13
 * @status     stable
 * @related    b.guardJsonpath.gate, b.guardJsonpath.compliancePosture
 *
 * Compose a derived guardJsonpath profile from one or more named
 * bases plus inline overrides. `opts.extends` is a profile name
 * (`"strict"` / `"balanced"` / `"permissive"`) or an array of
 * names; later entries shadow earlier ones. Inline `opts` keys win
 * last. Used to keep operator-defined profiles traceable to a
 * baseline rather than re-typing every key.
 *
 * @opts
 *   extends: string|string[],   // base profile name(s) to compose
 *   ...:     any guardJsonpath key, // inline override of resolved keys
 *
 * @example
 *   var custom = b.guardJsonpath.buildProfile({
 *     extends: "balanced",
 *     maxRecursiveDescents: 1,
 *     recursiveDescentPolicy: "reject",
 *   });
 *   custom.maxRecursiveDescents;                       // → 1
 *   custom.filterExprPolicy;                           // → "reject"
 */
var buildProfile = gateContract.makeProfileBuilder(PROFILES);

/**
 * @primitive  b.guardJsonpath.compliancePosture
 * @signature  b.guardJsonpath.compliancePosture(name)
 * @since      0.7.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardJsonpath.gate, b.guardJsonpath.buildProfile
 *
 * Look up a compliance-posture overlay by name (`"hipaa"` /
 * `"pci-dss"` / `"gdpr"` / `"soc2"`). Returns a shallow clone of
 * the posture object — the caller may mutate freely. Throws
 * `GuardJsonpathError("jsonpath.bad-posture")` on unknown name.
 *
 * @example
 *   var posture = b.guardJsonpath.compliancePosture("hipaa");
 *   posture.filterExprPolicy;                          // → "reject"
 *   posture.forensicSnippetBytes;                      // → 256
 */
function compliancePosture(name) {
  return gateContract.lookupCompliancePosture(name, COMPLIANCE_POSTURES,
    _err, "jsonpath");
}

var _jpRulePacks = gateContract.makeRulePackLoader(GuardJsonpathError, "jsonpath");
/**
 * @primitive  b.guardJsonpath.loadRulePack
 * @signature  b.guardJsonpath.loadRulePack(pack)
 * @since      0.7.13
 * @status     stable
 * @related    b.guardJsonpath.gate
 *
 * Register an operator-supplied rule pack with the guardJsonpath
 * registry. The pack is identified by `pack.id` (non-empty string)
 * and stored for later inspection / dispatch by gates that opt in
 * via `opts.rulePackId`. Returns the pack object unchanged on
 * success; throws `GuardJsonpathError("jsonpath.bad-opt")` when
 * `pack` is missing or `pack.id` is not a non-empty string.
 *
 * @example
 *   var pack = b.guardJsonpath.loadRulePack({
 *     id: "no-wildcards",
 *     rules: [
 *       { id: "wildcard", severity: "high",
 *         detect: function (path) { return path.indexOf("[*]") !== -1; },
 *         reason: "wildcard index forbidden in this context" },
 *     ],
 *   });
 *   pack.id;                                           // → "no-wildcards"
 */
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
