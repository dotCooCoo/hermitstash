"use strict";
/**
 * @module b.guardRegex
 * @nav    Guards
 * @title  Guard Regex
 *
 * @intro
 *   Regex-pattern content-safety guard — refuses user-supplied
 *   pattern strings that exhibit catastrophic-backtracking (ReDoS)
 *   shapes BEFORE the framework compiles them with `new RegExp(...)`.
 *   Operator-untrusted patterns flow into search filters, allow-lists,
 *   route matchers, and form validators; this primitive screens them
 *   so a hostile input can't pin a CPU at 100% inside the regex
 *   engine. KIND=`identifier`; the gate consumes `ctx.identifier`
 *   (or `ctx.pattern`) and refuses on hostile shapes. Composes with
 *   framework parsers (`b.safeJson` / `b.safeBuffer` / route helpers)
 *   so any operator-fed pattern hits the guard first.
 *
 *   Threat catalog: nested quantifiers (`(a+)+`, `(a*)+`, `(.+)+` —
 *   the canonical ReDoS class, e.g. CVE-2024-21538 cross-spawn and
 *   CVE-2022-25929 chartjs-adapter-luxon); alternation-with-
 *   quantifier (`(a|b)+`, `(\d|\d{2})*`) where alternation overlap
 *   amplifies search paths; quantifier-inside-lookaround
 *   (`(?=.*+)`, `(?!a*)`) — catastrophic in some engines; bounded
 *   repetition with a large upper bound (gated by
 *   `maxBoundedRepeat`); per-pattern byte cap to defend against
 *   parser-stage DoS; BIDI override / zero-width / C0 control /
 *   null-byte universal refuse.
 *
 *   Profiles: `strict` / `balanced` / `permissive`. Compliance
 *   postures: `hipaa` / `pci-dss` / `gdpr` / `soc2`. Operators
 *   select via `{ profile: "strict" }` or
 *   `{ compliancePosture: "hipaa" }`; postures overlay on top of the
 *   profile baseline. Nested-quantifier rejection holds at every
 *   profile — the catastrophic class is never an operator opt-in.
 *
 *   Pattern strings can't be repaired safely — `sanitize` either
 *   passes through clean input or throws `GuardRegexError`; the
 *   gate returns `serve` / `audit-only` / `refuse` (no `sanitize`
 *   action). Detector regexes themselves are length-bounded by
 *   `maxPatternBytes` so the screener can't be DoS'd by its own
 *   inputs.
 *
 * @card
 *   Regex-pattern content-safety guard — refuses user-supplied pattern strings that exhibit catastrophic-backtracking (ReDoS) shapes BEFORE the framework compiles them with `new RegExp(...)`.
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

// Nested extglob detector — picomatch `*(...)` / `+(...)` / `?(...)` /
// `@(...)` / `!(...)` containing another extglob inside (CVE-2026-33671
// nested-extglob catastrophic-backtracking class). Two extglob heads in
// the same pattern with no closing paren between them indicates nesting.
// The consecutive-star detector (CVE-2026-26996) walks the input by
// char so doesn't need a regex literal.
var EXTGLOB_HEAD_RE = /[*+?@!]\(/g;                                                  // allow:regex-no-length-cap — input bounded by maxPatternBytes

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
    consecutiveStarPolicy:    "reject",
    nestedExtglobPolicy:      "reject",
    inputKind:                "regex",                                            // CVE-2026-26996 + CVE-2026-33671 detectors apply only when inputKind=="glob"
    maxBoundedRepeat:          100,                                              // allow:raw-byte-literal — bounded repeat ceiling
    maxConsecutiveStars:        2,                                                // allow:raw-byte-literal — `**` recursive glob permitted; >=3 refused
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
    consecutiveStarPolicy:    "reject",                                          // CVE-2026-26996 refused at every profile
    nestedExtglobPolicy:      "reject",                                          // CVE-2026-33671 refused at every profile
    maxBoundedRepeat:          1000,                                             // allow:raw-byte-literal — bounded repeat ceiling
    maxConsecutiveStars:        2,                                                // allow:raw-byte-literal — `**` recursive glob permitted; >=3 refused
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
    consecutiveStarPolicy:    "reject",                                          // CVE-2026-26996 refused at every profile
    nestedExtglobPolicy:      "reject",                                          // CVE-2026-33671 refused at every profile
    maxBoundedRepeat:          10000,                                            // allow:raw-byte-literal — bounded repeat ceiling
    maxConsecutiveStars:        2,                                                // allow:raw-byte-literal — `**` recursive glob permitted; >=3 refused
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

  _detectConsecutiveStar(input, opts, issues);
  _detectNestedExtglob(input, opts, issues);

  return issues;
}

// Consecutive-star wildcard cap (CVE-2026-26996). Operator-supplied
// glob fragments compile to minimatch / picomatch / RegExp; a long run
// of `*` against a non-matching literal walks O(4^N). Three-or-more
// consecutive `*` is the canonical bad shape; `**` (recursive glob)
// stays permitted, gated by the profile's `maxConsecutiveStars`.
function _detectConsecutiveStar(input, opts, issues) {
  if (opts.consecutiveStarPolicy === "allow") return;
  // CVE-2026-26996 is a minimatch glob-shape backtracking class —
  // `***+literal` walks O(4^N) when minimatch translates the run to a
  // backtracking-heavy regex. Native ECMAScript regex syntax cannot
  // produce three consecutive `*` quantifiers (it's a SyntaxError),
  // so applying this detector to `inputKind: "regex"` strings only
  // produces false positives on legitimate regex shapes like
  // `a*(b)*` where `*(` is quantifier+group, not extglob.
  if (opts.inputKind !== "glob") return;
  var starRun = 0;
  var starRunMax = 0;
  for (var si = 0; si < input.length; si += 1) {
    if (input.charAt(si) === "*") {
      starRun += 1;
      if (starRun > starRunMax) starRunMax = starRun;
    } else {
      starRun = 0;
    }
  }
  var starCeiling = opts.maxConsecutiveStars === undefined ?
                    2 : opts.maxConsecutiveStars;                                // allow:raw-byte-literal — `**` glob ceiling
  if (starRunMax > starCeiling) {
    issues.push({
      kind: "consecutive-star",
      severity: opts.consecutiveStarPolicy === "reject" ? "critical" : "high",
      ruleId: "regex.consecutive-star",
      snippet: "pattern has " + starRunMax + " consecutive `*` " +
               "wildcards (cap " + starCeiling + ") — O(4^N) " +
               "backtracking on non-matching literal (CVE-2026-26996)",
    });
  }
}

// Nested-extglob detector (CVE-2026-33671). picomatch `*(...)` /
// `+(...)` / `?(...)` / `@(...)` / `!(...)` containing another
// extglob inside compiles to catastrophic-backtracking regex.
function _detectNestedExtglob(input, opts, issues) {
  if (opts.nestedExtglobPolicy === "allow") return;
  // CVE-2026-33671 is picomatch-specific: the extglob heads `*(`/
  // `+(`/`?(`/`@(`/`!(` collide with valid ECMAScript regex shapes
  // (quantifier + capturing group). Restricting this detector to
  // `inputKind: "glob"` avoids false-positive refusal of regex
  // patterns like `a*(b+(c))` where the heads are quantifier
  // groupings, not extglob.
  if (opts.inputKind !== "glob") return;
  // Collect extglob head positions via match() — read-only scan.
  var heads = [];
  var allHeads = input.match(EXTGLOB_HEAD_RE);                                   // allow:regex-no-length-cap — input bounded by maxPatternBytes
  if (allHeads === null || allHeads.length < 2) return;
  // Locate each head index manually (match returns substrings, not idx).
  var scanFrom = 0;
  for (var hh = 0; hh < allHeads.length; hh += 1) {
    var ch0 = allHeads[hh].charAt(0);
    var idx = scanFrom;
    while (idx < input.length - 1) {
      var c0 = input.charAt(idx);
      var c1 = input.charAt(idx + 1);
      if (c1 === "(" && c0 === ch0) break;
      idx += 1;
    }
    heads.push(idx);
    scanFrom = idx + 1;
    if (heads.length > 1024) break;                                              // allow:raw-byte-literal — head-count safety cap
  }
  var nested = false;
  for (var hi = 0; hi < heads.length && !nested; hi += 1) {
    var headStart = heads[hi];
    // Walk forward tracking paren depth. Inner head before close = nested.
    var pdepth = 1;
    for (var pj = headStart + 2; pj < input.length && pdepth > 0; pj += 1) {
      var ch = input.charAt(pj);
      if (ch === "(") {
        pdepth += 1;
        if (pj > 0) {
          var preVerb = input.charAt(pj - 1);
          if (preVerb === "*" || preVerb === "+" || preVerb === "?" ||
              preVerb === "@" || preVerb === "!") {
            nested = true;
            break;
          }
        }
      } else if (ch === ")") {
        pdepth -= 1;
      }
    }
  }
  if (nested) {
    issues.push({
      kind: "nested-extglob",
      severity: opts.nestedExtglobPolicy === "reject" ? "critical" : "high",
      ruleId: "regex.nested-extglob",
      snippet: "pattern contains nested extglob quantifier " +
               "(`*(...*(...))`) — catastrophic backtracking class " +
               "(CVE-2026-33671 picomatch)",
    });
  }
}

/**
 * @primitive  b.guardRegex.validate
 * @signature  b.guardRegex.validate(input, opts)
 * @since      0.7.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardRegex.gate, b.guardRegex.sanitize
 *
 * Inspect a user-supplied regex pattern string and return an
 * aggregated issue list. Pure inspection — never throws on hostile
 * patterns; caller decides what to do with the issues. The `ok`
 * flag is `true` only when zero `critical` / `high` issues fire.
 * Throws `GuardRegexError("regex.bad-opt")` when a numeric opt is
 * non-finite / negative (config-time mistake by the operator).
 *
 * @opts
 *   profile:                "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   bidiPolicy:             "reject"|"audit"|"allow",
 *   controlPolicy:          "reject"|"audit"|"allow",
 *   nullBytePolicy:         "reject"|"audit"|"allow",
 *   zeroWidthPolicy:        "reject"|"strip"|"audit"|"allow",
 *   nestedQuantPolicy:      "reject"|"audit"|"allow",
 *   alternationQuantPolicy: "reject"|"audit"|"allow",
 *   boundedRepeatPolicy:    "reject"|"audit"|"allow",
 *   lookaroundQuantPolicy:  "reject"|"audit"|"allow",
 *   consecutiveStarPolicy:  "reject"|"audit"|"allow",
 *   nestedExtglobPolicy:    "reject"|"audit"|"allow",
 *   inputKind:              "regex"|"glob",
 *   maxBoundedRepeat:       number,
 *   maxConsecutiveStars:    number,
 *   maxPatternBytes:        number,
 *   maxBytes:               number,
 *   maxRuntimeMs:           number,
 *
 * @example
 *   var clean = b.guardRegex.validate("^[a-z]+$", { profile: "strict" });
 *   clean.ok;                                          // → true
 *
 *   var hostile = b.guardRegex.validate("(a+)+b", { profile: "strict" });
 *   hostile.ok;                                        // → false
 *   hostile.issues.some(function (i) { return i.kind === "nested-quantifier"; });  // → true
 */
function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes", "maxPatternBytes", "maxBoundedRepeat", "maxConsecutiveStars"],
    "guardRegex.validate", GuardRegexError, "regex.bad-opt");
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

/**
 * @primitive  b.guardRegex.sanitize
 * @signature  b.guardRegex.sanitize(input, opts)
 * @since      0.7.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardRegex.validate, b.guardRegex.gate
 *
 * Pass-through-or-throw. Regex patterns cannot be safely repaired
 * (stripping a `+` from a quantifier silently changes match
 * semantics); this primitive returns the input unchanged when no
 * `critical` or `high` issue fires, otherwise throws
 * `GuardRegexError` with the offending rule id (e.g.
 * `regex.nested-quantifier`, `regex.lookaround-quantifier`,
 * `regex.bounded-repeat-cap`). Operators that need a "best-effort
 * cleanup" semantic should reject the input at the boundary
 * instead.
 *
 * @opts
 *   profile:                "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   nestedQuantPolicy:      "reject"|"audit"|"allow",
 *   alternationQuantPolicy: "reject"|"audit"|"allow",
 *   boundedRepeatPolicy:    "reject"|"audit"|"allow",
 *   lookaroundQuantPolicy:  "reject"|"audit"|"allow",
 *   consecutiveStarPolicy:  "reject"|"audit"|"allow",
 *   nestedExtglobPolicy:    "reject"|"audit"|"allow",
 *   inputKind:              "regex"|"glob",
 *   maxBoundedRepeat:       number,
 *   maxConsecutiveStars:    number,
 *   maxPatternBytes:        number,
 *
 * @example
 *   var safe = b.guardRegex.sanitize("^[a-z]+$", { profile: "strict" });
 *   safe;                                              // → "^[a-z]+$"
 *
 *   try {
 *     b.guardRegex.sanitize("(a+)+b", { profile: "strict" });
 *   } catch (e) {
 *     e.code;                                          // → "regex.nested-quantifier"
 *   }
 */
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

/**
 * @primitive  b.guardRegex.gate
 * @signature  b.guardRegex.gate(opts)
 * @since      0.7.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardRegex.validate, b.guardRegex.sanitize
 *
 * Build a `b.gateContract` gate that screens `ctx.identifier` (or
 * `ctx.pattern`) before any compilation step. Action chain:
 * `serve` (no issues) → `audit-only` (warn-only) → `refuse` (any
 * `critical` or `high`). No `sanitize` action — pattern strings
 * cannot be repaired. Compose into framework parsers / form
 * validators / route matchers so operator-fed patterns hit the
 * guard before reaching `new RegExp()`.
 *
 * @opts
 *   profile:                "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   name:                   string,    // override gate name in audit emissions
 *   nestedQuantPolicy:      "reject"|"audit"|"allow",
 *   alternationQuantPolicy: "reject"|"audit"|"allow",
 *   boundedRepeatPolicy:    "reject"|"audit"|"allow",
 *   lookaroundQuantPolicy:  "reject"|"audit"|"allow",
 *   consecutiveStarPolicy:  "reject"|"audit"|"allow",
 *   nestedExtglobPolicy:    "reject"|"audit"|"allow",
 *   inputKind:              "regex"|"glob",
 *   maxBoundedRepeat:       number,
 *   maxConsecutiveStars:    number,
 *   maxPatternBytes:        number,
 *
 * @example
 *   var gate = b.guardRegex.gate({ profile: "strict" });
 *
 *   gate({ identifier: "(a+)+b" }).then(function (rv) {
 *     rv.ok;                                           // → false
 *     rv.action;                                       // → "refuse"
 *   });
 *
 *   gate({ identifier: "^[a-z]+$" }).then(function (rv) {
 *     rv.action;                                       // → "serve"
 *   });
 */
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

/**
 * @primitive  b.guardRegex.buildProfile
 * @signature  b.guardRegex.buildProfile(opts)
 * @since      0.7.13
 * @status     stable
 * @related    b.guardRegex.gate, b.guardRegex.compliancePosture
 *
 * Compose a derived guardRegex profile from one or more named
 * bases plus inline overrides. `opts.extends` is a profile name
 * (`"strict"` / `"balanced"` / `"permissive"`) or an array of
 * names; later entries shadow earlier ones. Inline `opts` keys win
 * last. Used to keep operator-defined profiles traceable to a
 * baseline rather than re-typing every key.
 *
 * @opts
 *   extends: string|string[],   // base profile name(s) to compose
 *   ...:     any guardRegex key, // inline override of resolved keys
 *
 * @example
 *   var custom = b.guardRegex.buildProfile({
 *     extends: "balanced",
 *     maxBoundedRepeat: 50,
 *     boundedRepeatPolicy: "reject",
 *   });
 *   custom.maxBoundedRepeat;                           // → 50
 *   custom.nestedQuantPolicy;                          // → "reject"
 */
var buildProfile = gateContract.makeProfileBuilder(PROFILES);

/**
 * @primitive  b.guardRegex.compliancePosture
 * @signature  b.guardRegex.compliancePosture(name)
 * @since      0.7.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardRegex.gate, b.guardRegex.buildProfile
 *
 * Look up a compliance-posture overlay by name (`"hipaa"` /
 * `"pci-dss"` / `"gdpr"` / `"soc2"`). Returns a shallow clone of
 * the posture object — the caller may mutate freely. Throws
 * `GuardRegexError("regex.bad-posture")` on unknown name.
 *
 * @example
 *   var posture = b.guardRegex.compliancePosture("hipaa");
 *   posture.nestedQuantPolicy;                         // → "reject"
 *   posture.forensicSnippetBytes;                      // → 256
 */
function compliancePosture(name) {
  return gateContract.lookupCompliancePosture(name, COMPLIANCE_POSTURES,
    _err, "regex");
}

var _regexRulePacks = gateContract.makeRulePackLoader(GuardRegexError, "regex");
/**
 * @primitive  b.guardRegex.loadRulePack
 * @signature  b.guardRegex.loadRulePack(pack)
 * @since      0.7.13
 * @status     stable
 * @related    b.guardRegex.gate
 *
 * Register an operator-supplied rule pack with the guardRegex
 * registry. The pack is identified by `pack.id` (non-empty string)
 * and stored for later inspection / dispatch by gates that opt in
 * via `opts.rulePackId`. Returns the pack object unchanged on
 * success; throws `GuardRegexError("regex.bad-opt")` when `pack`
 * is missing or `pack.id` is not a non-empty string.
 *
 * @example
 *   var pack = b.guardRegex.loadRulePack({
 *     id: "no-empty-alternation",
 *     rules: [
 *       { id: "empty-alt", severity: "high",
 *         detect: function (pattern) { return /\(\|/.test(pattern); },
 *         reason: "alternation with empty branch" },
 *     ],
 *   });
 *   pack.id;                                           // → "no-empty-alternation"
 */
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
