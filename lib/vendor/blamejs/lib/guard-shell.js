// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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

var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var codepointClass = require("./codepoint-class");
var C = require("./constants");
var { GuardShellError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var POSIX_META_CHARS = ";&|<>$`\\()[]{}*?~!#'\"";

var CMD_META_CHARS = "&|<>^%\"',;=";

var NEWLINE_CHARS = "\r\n";


var PROFILES = Object.freeze({
  "strict": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
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
    ...gateContract.CHAR_THREATS_REJECT_ALL,
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
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    posixMetaPolicy:       "audit",
    cmdMetaPolicy:         "audit",
    dollarSubstPolicy:     "reject",
    processSubstPolicy:    "reject",
    backtickPolicy:        "reject",
    newlinePolicy:         "reject",
    argHyphenPolicy:       "allow",
    maxBytes:              C.BYTES.kib(8),
    maxRuntimeMs:          C.TIME.seconds(2),
  },
});

var DEFAULTS = gateContract.strictDefaults(PROFILES);

var COMPLIANCE_POSTURES = gateContract.compliancePostures(PROFILES, { base: 256 });

function _hasDollarSubstitution(s) {
  for (var i = 0; i + 1 < s.length; i += 1) {
    if (s.charAt(i) !== "$") continue;
    var next = s.charAt(i + 1);
    if (next === "(" || next === "{") return true;
  }
  return false;
}

function _hasDollarVariable(s) {
  for (var i = 0; i + 1 < s.length; i += 1) {
    if (s.charAt(i) !== "$") continue;
    var cc = s.charCodeAt(i + 1);
    if (codepointClass.isAsciiLetter(cc) || cc === 0x5F) return true;
  }
  return false;
}

function _hasProcessSubstitution(s) {
  for (var i = 0; i + 1 < s.length; i += 1) {
    var c = s.charAt(i);
    if ((c === "<" || c === ">") && s.charAt(i + 1) === "(") return true;
  }
  return false;
}

function _detectIssues(input, opts) {
  var pre = gateContract.detectStringInput(input, opts, { name: "shell", noun: "shell arg", emptyMode: "ok", cap: { bytes: opts.maxBytes, snippet: "shell arg exceeds maxBytes " + opts.maxBytes } });
  if (pre.done) return pre.issues;
  var issues = pre.issues;

  if (opts.dollarSubstPolicy !== "allow" && _hasDollarSubstitution(input)) {
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
  if (opts.processSubstPolicy !== "allow" && _hasProcessSubstitution(input)) {
    issues.push({
      kind: "process-substitution", severity: "critical",
      ruleId: "shell.process-substitution",
      snippet: "argument contains `<(` or `>(` — Bash process " +
               "substitution",
    });
  }
  if (opts.dollarSubstPolicy !== "allow" && _hasDollarVariable(input)) {
    issues.push({
      kind: "dollar-var",
      severity: opts.dollarSubstPolicy === "reject" ? "high" : "warn",
      ruleId: "shell.dollar-var",
      snippet: "argument contains `$VAR` parameter expansion",
    });
  }
  if (opts.newlinePolicy !== "allow" &&
      codepointClass.indexOfAny(input, NEWLINE_CHARS) !== -1) {
    issues.push({
      kind: "newline", severity: "high",
      ruleId: "shell.newline",
      snippet: "argument contains CR / LF — line-splitting in shell " +
               "scripts",
    });
  }
  if (opts.posixMetaPolicy !== "allow" &&
      codepointClass.indexOfAny(input, POSIX_META_CHARS) !== -1) {
    issues.push({
      kind: "posix-metachar",
      severity: opts.posixMetaPolicy === "reject" ? "high" : "warn",
      ruleId: "shell.posix-metachar",
      snippet: "argument contains POSIX shell metacharacter " +
               "(`;|&<>()[]{}*?~!#`'\"\\`)",
    });
  }
  if (opts.cmdMetaPolicy !== "allow" &&
      codepointClass.indexOfAny(input, CMD_META_CHARS) !== -1) {
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
 * `GuardShellError("shell/bad-opt")` when a numeric opt is
 * non-finite / negative (config-time mistake by the operator).
 *
 * @opts
 *   profile:           "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   bidiPolicy:        "reject"|"audit"|"allow",
 *   controlPolicy:     "reject"|"audit"|"allow",
 *   nullBytePolicy:    "reject"|"audit"|"allow",
 *   zeroWidthPolicy:   "reject"|"audit"|"allow",
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
function _sanitizeTransform(input) {
  return input;
}

var INTEGRATION_FIXTURES = gateContract.identifierFixtures("safe-arg-value", "safe; rm -rf /");

var POLICY_ENUM = gateContract.policyVocabulary([
  "posixMetaPolicy", "cmdMetaPolicy", "dollarSubstPolicy", "processSubstPolicy",
  "backtickPolicy", "newlinePolicy", "argHyphenPolicy",
], gateContract.POLICY_VALUES.rejectAuditAllow);

module.exports = gateContract.defineGuard({
  enumOpts:    POLICY_ENUM,
  name:        "shell",
  kind:        "identifier",
  errorClass:  GuardShellError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  integrationFixtures: INTEGRATION_FIXTURES,
  detect:           _detectIssues,
  sanitizeTransform: _sanitizeTransform,
  intOpts:          ["maxBytes"],
  ctxFields:   ["identifier", "arg"],
});
