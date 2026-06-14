"use strict";
/**
 * @module b.guardShell
 * @nav    Guards
 * @title  Guard Shell
 *
 * @intro
 *   Shell-argument content-safety guard — refuses user-supplied
 *   strings that carry shell-injection shapes BEFORE they reach a
 *   child-process spawn. The canonical defense is "command + literal
 *   argv array, never `shell: true`" (route through `b.processSpawn`,
 *   which holds that contract); guardShell layers the metacharacter
 *   catalog on top so even operator-untrusted strings flowing through
 *   the argv slots are screened. KIND=`identifier`; the gate consumes
 *   `ctx.identifier` (or `ctx.arg`) and refuses on hostile shapes.
 *
 *   Threat catalog: POSIX shell metacharacters
 *   (`;` `&` `|` `<` `>` `(` `)` `{` `}` `[` `]` `*` `?` `~` `!` `#`
 *   `\` and single/double quotes); backtick command substitution;
 *   `$(...)` command substitution and `${VAR}` parameter expansion;
 *   process substitution `<(...)` / `>(...)`; cmd.exe metacharacters
 *   (`&` `|` `<` `>` `^` `%` `"` `'` `(` `)` `,` `;` `=` plus
 *   whitespace + newlines); CR / LF / NUL line-splitting; bare
 *   `$VAR` parameter expansion; leading `-` arguments (`-rf` /
 *   `--exec` flag-injection class) gated by `argHyphenPolicy`; BIDI
 *   override / zero-width / C0 control / null-byte refuse at every
 *   profile.
 *
 *   Profiles: `strict` / `balanced` / `permissive`. Compliance
 *   postures: `hipaa` / `pci-dss` / `gdpr` / `soc2`. Operators select
 *   via `{ profile: "strict" }` or `{ compliancePosture: "hipaa" }`;
 *   postures overlay on top of the profile baseline.
 *
 *   Shell args cannot be repaired safely — `sanitize` either passes
 *   through clean input or throws `GuardShellError`; the gate returns
 *   `serve` / `audit-only` / `refuse` (no `sanitize` action). Pair
 *   with `b.processSpawn` so the eventual `child_process.spawn` call
 *   uses `shell: false` and the screened argv values.
 *
 * @card
 *   Shell-argument content-safety guard — refuses user-supplied strings that carry shell-injection shapes BEFORE they reach a child-process spawn.
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

/**
 * @primitive  b.guardShell.validate
 * @signature  b.guardShell.validate(input, opts)
 * @since      0.7.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardShell.gate, b.guardShell.sanitize, b.processSpawn
 *
 * Inspect a single shell-argument string and return an aggregated
 * issue list. Pure inspection — never throws on hostile input;
 * caller decides what to do with the issues. The `ok` flag is
 * `true` only when zero `critical` / `high` issues fire. Throws
 * `GuardShellError("shell.bad-opt")` when a numeric opt is
 * non-finite / negative (config-time mistake by the operator).
 *
 * @opts
 *   profile:           "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   bidiPolicy:        "reject"|"audit"|"allow",
 *   controlPolicy:     "reject"|"audit"|"allow",
 *   nullBytePolicy:    "reject"|"audit"|"allow",
 *   zeroWidthPolicy:   "reject"|"strip"|"audit"|"allow",
 *   posixMetaPolicy:   "reject"|"audit"|"allow",
 *   cmdMetaPolicy:     "reject"|"audit"|"allow",
 *   dollarSubstPolicy: "reject"|"audit"|"allow",
 *   processSubstPolicy:"reject"|"audit"|"allow",
 *   backtickPolicy:    "reject"|"audit"|"allow",
 *   newlinePolicy:     "reject"|"audit"|"allow",
 *   argHyphenPolicy:   "reject"|"audit"|"allow",
 *   maxBytes:          number,
 *   maxRuntimeMs:      number,
 *
 * @example
 *   var clean = b.guardShell.validate("safe-arg-value", { profile: "strict" });
 *   clean.ok;                                          // → true
 *
 *   var hostile = b.guardShell.validate("safe; rm -rf /", { profile: "strict" });
 *   hostile.ok;                                        // → false
 *   hostile.issues.some(function (i) { return i.kind === "posix-metachar"; });  // → true
 */
function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes"],
    "guardShell.validate", GuardShellError, "shell.bad-opt");
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

/**
 * @primitive  b.guardShell.sanitize
 * @signature  b.guardShell.sanitize(input, opts)
 * @since      0.7.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardShell.validate, b.guardShell.gate
 *
 * Pass-through-or-throw. Shell arguments cannot be safely repaired
 * (stripping a `;` inside an arg fundamentally changes operator
 * intent); this primitive returns the input unchanged when no
 * `critical` or `high` issue fires, otherwise throws
 * `GuardShellError` with the offending rule id (e.g.
 * `shell.posix-metachar`, `shell.dollar-substitution`,
 * `shell.backtick`, `shell.newline`). Operators that need a
 * "best-effort cleanup" semantic should use a different argv shape
 * (path + literal arg array) rather than trying to disarm a hostile
 * string.
 *
 * @opts
 *   profile:           "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   posixMetaPolicy:   "reject"|"audit"|"allow",
 *   cmdMetaPolicy:     "reject"|"audit"|"allow",
 *   dollarSubstPolicy: "reject"|"audit"|"allow",
 *   processSubstPolicy:"reject"|"audit"|"allow",
 *   backtickPolicy:    "reject"|"audit"|"allow",
 *   newlinePolicy:     "reject"|"audit"|"allow",
 *   argHyphenPolicy:   "reject"|"audit"|"allow",
 *   maxBytes:          number,
 *
 * @example
 *   var arg = b.guardShell.sanitize("safe-arg-value", { profile: "strict" });
 *   arg;                                               // → "safe-arg-value"
 *
 *   try {
 *     b.guardShell.sanitize("safe; rm -rf /", { profile: "strict" });
 *   } catch (e) {
 *     e.code;                                          // → "shell.posix-metachar"
 *   }
 */
function sanitize(input, opts) {
  opts = _resolveOpts(opts);
  if (typeof input !== "string") {
    throw _err("shell.bad-input", "sanitize requires string input");
  }
  // Shell args can't be repaired — sanitize either passes through
  // valid input or throws.
  var issues = _detectIssues(input, opts);
  gateContract.throwOnRefusalSeverity(issues, {
    errorClass: GuardShellError, codePrefix: "shell",
  });
  return input;
}

// The request-boundary gate is the gate-contract factory default: it reads
// `ctx.identifier` (or `ctx.arg`), runs `validate`, and maps severity to
// action — `serve` (no issue) / `audit-only` (info / warn) / `refuse` (any
// high / critical). No `sanitize` action — shell args cannot be repaired.
// Compose with `b.processSpawn` so each argv slot is gated before reaching
// the OS (the spawn primitive itself enforces `shell: false`; the gate
// enforces metacharacter cleanliness). Its wiki section renders from the
// single-sourced `@abiTemplate gate` block in gate-contract.js.

// buildProfile / compliancePosture / loadRulePack are assembled by
// gateContract.defineGuard below (makeProfileBuilder(PROFILES) /
// lookupCompliancePosture(_, COMPLIANCE_POSTURES) / makeRulePackLoader).
// Their wiki sections render from the single-sourced @abiTemplate blocks
// in gate-contract.js, instantiated per guard by the page generator.

// ---- adaptive integration-test fixtures (consumed by layer-5 host harness) ----
var INTEGRATION_FIXTURES = Object.freeze({
  kind:              "identifier",
  benignBytes:       Buffer.from("safe-arg-value", "utf8"),
  hostileBytes:      Buffer.from("safe; rm -rf /", "utf8"),
  benignIdentifier:  "safe-arg-value",
  // Hostile: command-injection via metacharacter chain.
  hostileIdentifier: "safe; rm -rf /",
});

// Assembled from the gate-contract guard factory: error class, registry
// exports (NAME / KIND / INTEGRATION_FIXTURES), buildProfile /
// compliancePosture / loadRulePack wiring, plus the per-guard inspection
// surface (validate / sanitize). The gate is the factory default chain,
// dispatched to `ctx.identifier` / `ctx.arg` via ctxFields.
module.exports = gateContract.defineGuard({
  name:        "shell",
  kind:        "identifier",
  errorClass:  GuardShellError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  integrationFixtures: INTEGRATION_FIXTURES,
  validate:    validate,
  sanitize:    sanitize,
  ctxFields:   ["identifier", "arg"],
});
