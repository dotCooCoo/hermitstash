"use strict";
/**
 * guard-shell — Shell metacharacter identifier-safety primitive
 * (b.guardShell).
 *
 * Validates user-input strings BEFORE they're handed to a
 * child-process spawn (regardless of operator's `shell:` opt). The
 * canonical defense is "use array args + shell:false", but operators
 * still receive operator-untrusted strings that flow through path-
 * arg or arg-list shapes — guardShell refuses obvious shell-injection
 * shapes before the spawn call. KIND="identifier" — consumes
 * ctx.identifier (or ctx.arg).
 *
 * Threat catalog:
 *   - POSIX shell metacharacters — `;`, `&`, `|`, `<`, `>`, `(`, `)`,
 *     `{`, `}`, `[`, `]`, `*`, `?`, `~`, `!`, `#`, `\`, single + double
 *     quotes.
 *   - Backtick command substitution.
 *   - `$(...)` command substitution and `${VAR}` parameter expansion.
 *   - Process substitution `<(...)` / `>(...)`.
 *   - cmd.exe metacharacters — `&`, `|`, `<`, `>`, `^`, `%`, `"`, `'`,
 *     `(`, `)`, `,`, `;`, `=`, ` `, tabs, newlines.
 *   - Newline / NUL injection (line splitting in scripts).
 *   - Variable expansion `$VAR`.
 *   - Operator may opt-in to `argHyphenPolicy` to refuse leading `-`
 *     arguments (defense against `-rf` / `--exec` / etc.).
 *   - BIDI / zero-width / control / null-byte universal refuse.
 *
 *   var rv = b.guardShell.validate("file with spaces.txt",
 *                                  { profile: "strict" });
 *   var g  = b.guardShell.gate({ profile: "strict" });
 */

var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var { GuardShellError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardShellError.factory;

// POSIX shell metachars (excluding whitespace which is per-policy).
var POSIX_META_RE = /[;&|<>$`\\()[\]{}*?~!#'"]/;

// cmd.exe metachars.
var CMD_META_RE = /[&|<>^%"',;=]/;

// $(...) and ${...} command/param substitution.
var DOLLAR_PAREN_RE = /\$\(/;
var DOLLAR_BRACE_RE = /\$\{/;

// $VAR parameter expansion (bare).
var DOLLAR_VAR_RE = /\$[A-Za-z_][A-Za-z0-9_]*/;

// Process substitution.
var PROCESS_SUBST_RE = /[<>]\(/;

// Newline (any).
var NEWLINE_RE = /[\r\n]/;

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    bidiPolicy:           "reject",
    controlPolicy:         "reject",
    nullBytePolicy:        "reject",
    zeroWidthPolicy:       "reject",
    posixMetaPolicy:       "reject",
    cmdMetaPolicy:         "reject",
    dollarSubstPolicy:     "reject",
    processSubstPolicy:    "reject",
    backtickPolicy:        "reject",
    newlinePolicy:         "reject",
    argHyphenPolicy:       "reject",
    maxBytes:              C.BYTES.kib(2),
    maxRuntimeMs:          C.TIME.seconds(2),
  },
  "balanced": {
    bidiPolicy:           "reject",
    controlPolicy:         "reject",
    nullBytePolicy:        "reject",
    zeroWidthPolicy:       "reject",
    posixMetaPolicy:       "audit",
    cmdMetaPolicy:         "audit",
    dollarSubstPolicy:     "reject",
    processSubstPolicy:    "reject",
    backtickPolicy:        "reject",
    newlinePolicy:         "reject",
    argHyphenPolicy:       "audit",
    maxBytes:              C.BYTES.kib(2),
    maxRuntimeMs:          C.TIME.seconds(2),
  },
  "permissive": {
    bidiPolicy:           "reject",                                              // BIDI refused at every profile
    controlPolicy:         "reject",                                              // controls refused at every profile
    nullBytePolicy:        "reject",                                              // null refused at every profile
    zeroWidthPolicy:       "reject",                                              // zero-width refused at every profile
    posixMetaPolicy:       "audit",
    cmdMetaPolicy:         "audit",
    dollarSubstPolicy:     "reject",                                              // command substitution refused at every profile
    processSubstPolicy:    "reject",                                              // process substitution refused at every profile
    backtickPolicy:        "reject",                                              // backtick substitution refused at every profile
    newlinePolicy:         "reject",                                              // newline refused at every profile
    argHyphenPolicy:       "allow",
    maxBytes:              C.BYTES.kib(8),
    maxRuntimeMs:          C.TIME.seconds(2),
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
    errorClass:         GuardShellError,
    errCodePrefix:      "shell",
  });
}

function _detectIssues(input, opts) {
  var issues = [];
  if (typeof input !== "string") {
    return [{ kind: "bad-input", severity: "high",
              ruleId: "shell.bad-input",
              snippet: "shell arg is not a string" }];
  }
  if (input.length === 0) {
    // Empty arg is not necessarily a threat (legit blank args exist).
    return [];
  }
  if (Buffer.byteLength(input, "utf8") > opts.maxBytes) {
    return [{ kind: "shell-cap", severity: "high",
              ruleId: "shell.shell-cap",
              snippet: "shell arg exceeds maxBytes " + opts.maxBytes }];
  }

  var charThreats = codepointClass.detectCharThreats(input, opts, "shell");
  for (var ci = 0; ci < charThreats.length; ci += 1) issues.push(charThreats[ci]);

  // $(...) / ${...} / backtick — universal refuse.
  if (opts.dollarSubstPolicy !== "allow" &&
      (DOLLAR_PAREN_RE.test(input) || DOLLAR_BRACE_RE.test(input))) {            // allow:regex-no-length-cap — input bounded by maxBytes
    issues.push({
      kind: "dollar-substitution", severity: "critical",
      ruleId: "shell.dollar-substitution",
      snippet: "argument contains `$(` or `${` — POSIX shell command / " +
               "parameter substitution",
    });
  }
  if (opts.backtickPolicy !== "allow" && input.indexOf("`") !== -1) {
    issues.push({
      kind: "backtick", severity: "critical",
      ruleId: "shell.backtick",
      snippet: "argument contains backtick — POSIX shell command " +
               "substitution",
    });
  }
  if (opts.processSubstPolicy !== "allow" && PROCESS_SUBST_RE.test(input)) {     // allow:regex-no-length-cap — input bounded by maxBytes
    issues.push({
      kind: "process-substitution", severity: "critical",
      ruleId: "shell.process-substitution",
      snippet: "argument contains `<(` or `>(` — Bash process " +
               "substitution",
    });
  }
  if (opts.dollarSubstPolicy !== "allow" && DOLLAR_VAR_RE.test(input)) {         // allow:regex-no-length-cap — input bounded by maxBytes
    issues.push({
      kind: "dollar-var",
      severity: opts.dollarSubstPolicy === "reject" ? "high" : "warn",
      ruleId: "shell.dollar-var",
      snippet: "argument contains `$VAR` parameter expansion",
    });
  }
  if (opts.newlinePolicy !== "allow" && NEWLINE_RE.test(input)) {                // allow:regex-no-length-cap — input bounded by maxBytes
    issues.push({
      kind: "newline", severity: "high",
      ruleId: "shell.newline",
      snippet: "argument contains CR / LF — line-splitting in shell " +
               "scripts",
    });
  }
  if (opts.posixMetaPolicy !== "allow" && POSIX_META_RE.test(input)) {           // allow:regex-no-length-cap — input bounded by maxBytes
    issues.push({
      kind: "posix-metachar",
      severity: opts.posixMetaPolicy === "reject" ? "high" : "warn",
      ruleId: "shell.posix-metachar",
      snippet: "argument contains POSIX shell metacharacter " +
               "(`;|&<>()[]{}*?~!#`'\"\\`)",
    });
  }
  if (opts.cmdMetaPolicy !== "allow" && CMD_META_RE.test(input)) {               // allow:regex-no-length-cap — input bounded by maxBytes
    issues.push({
      kind: "cmd-metachar",
      severity: opts.cmdMetaPolicy === "reject" ? "high" : "warn",
      ruleId: "shell.cmd-metachar",
      snippet: "argument contains cmd.exe metacharacter " +
               "(`&|<>^%\"',;=`)",
    });
  }
  if (opts.argHyphenPolicy !== "allow" && input.charAt(0) === "-") {
    issues.push({
      kind: "arg-hyphen-leading",
      severity: opts.argHyphenPolicy === "reject" ? "high" : "warn",
      ruleId: "shell.arg-hyphen-leading",
      snippet: "argument begins with `-` — would be parsed as an " +
               "option flag by the target binary (`-rf` / `--exec` " +
               "class)",
    });
  }

  return issues;
}

function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes"],
    "guardShell.validate", GuardShellError, "shell.bad-opt");
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

function sanitize(input, opts) {
  opts = _resolveOpts(opts);
  if (typeof input !== "string") {
    throw _err("shell.bad-input", "sanitize requires string input");
  }
  // Shell args can't be repaired — sanitize either passes through
  // valid input or throws.
  var issues = _detectIssues(input, opts);
  for (var i = 0; i < issues.length; i += 1) {
    if (issues[i].severity === "critical" || issues[i].severity === "high") {
      throw _err(issues[i].ruleId || "shell.refused",
        "guardShell.sanitize: " + issues[i].snippet);
    }
  }
  return input;
}

function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardShell:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var arg = ctx && (ctx.identifier || ctx.arg);
      if (arg === undefined || arg === null) return { ok: true, action: "serve" };
      var rv = validate(arg, opts);
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
    _err, "shell");
}

var _shellRulePacks = gateContract.makeRulePackLoader(GuardShellError, "shell");
var loadRulePack = _shellRulePacks.load;

module.exports = {
  // ---- guard-* family registry exports ----
  NAME:                "shell",
  KIND:                "identifier",
  INTEGRATION_FIXTURES: Object.freeze({
    kind:              "identifier",
    benignBytes:       Buffer.from("safe-arg-value", "utf8"),
    hostileBytes:      Buffer.from("safe; rm -rf /", "utf8"),
    benignIdentifier:  "safe-arg-value",
    // Hostile: command-injection via metacharacter chain.
    hostileIdentifier: "safe; rm -rf /",
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
  GuardShellError:     GuardShellError,
};
