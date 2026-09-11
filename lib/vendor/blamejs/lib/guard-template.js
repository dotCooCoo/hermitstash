// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.guardTemplate
 * @nav    Guards
 * @title  Guard Template
 *
 * @intro
 *   Server-Side Template Injection (SSTI) content-safety guard —
 *   refuses user-supplied strings that contain template-engine
 *   syntax BEFORE they're rendered. Template-injection vulnerable
 *   surfaces escape sandboxes through engine helpers (`render`,
 *   `lookup`, `with`, `attr_filter`); the safe shape is "logic-less
 *   templates only, untrusted strings are data not code". This
 *   primitive enforces that boundary by refusing engine syntax in
 *   any operator-untrusted input. Pair with logic-less Mustache
 *   helpers, Handlebars `noEscape: false`, and Liquid's strict-
 *   variables mode so the framework's defense-in-depth holds even
 *   when an operator forgets to escape. KIND=`identifier`; the
 *   gate consumes `ctx.identifier` (or `ctx.text`) and refuses on
 *   hostile shapes.
 *
 *   Threat catalog (engine-shape detection): Jinja2 / Django / Twig
 *   / Liquid / Handlebars / Mustache / AngularJS — `{{...}}`
 *   expressions and `{%...%}` statements (CVE-2024-22195 Jinja
 *   `xml_attr_filter`, CVE-2024-26139 Bottle, CVE-2024-23348
 *   Pyrogram); ERB / Tornado — `<%...%>` and `<%=...%>`; Pug —
 *   `#{...}` interpolation and `!{...}` raw-HTML interpolation
 *   (prototype-pollution exit when the model is operator-fed);
 *   Mako / Velocity / Tornado / JS template-literal — `${...}`
 *   interpolation; Velocity directives (`#set`, `#if`, `#foreach`,
 *   `#parse`, `#include`); BIDI / null / C0 control / zero-width
 *   universal refuse.
 *
 *   Profiles: `strict` / `balanced` / `permissive`. Compliance
 *   postures: `hipaa` / `pci-dss` / `gdpr` / `soc2`. Operators
 *   select via `{ profile: "strict" }` or
 *   `{ compliancePosture: "hipaa" }`; postures overlay on top of the
 *   profile baseline. Jinja / ERB / Pug shape rejection holds at
 *   every profile — the SSTI class is never an operator opt-in.
 *
 *   Template input cannot be repaired safely (stripping `{{` from
 *   `{{name}}` produces a different document); `sanitize` either
 *   passes through clean input or throws `GuardTemplateError`; the
 *   gate returns `serve` / `audit-only` / `refuse` (no `sanitize`
 *   action). The `${...}` and Velocity-directive policies default
 *   to `audit` outside `strict` because they overlap with legitimate
 *   JS / shell substrings, so operators tune via overrides.
 *
 * @card
 *   Server-Side Template Injection (SSTI) content-safety guard — refuses user-supplied strings that contain template-engine syntax BEFORE they're rendered.
 */

var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var codepointClass = require("./codepoint-class");
var C = require("./constants");
var { GuardTemplateError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var VELOCITY_DIRECTIVES = ["set", "if", "else", "elseif", "end", "foreach",
                           "parse", "include", "stop"];

var PROFILES = Object.freeze({
  "strict": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    jinjaPolicy:               "reject",
    erbPolicy:                 "reject",
    pugPolicy:                 "reject",
    dollarBracePolicy:         "reject",
    velocityDirectivePolicy:   "reject",
    maxBytes:                  C.BYTES.kib(64),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
  "balanced": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    jinjaPolicy:               "reject",
    erbPolicy:                 "reject",
    pugPolicy:                 "reject",
    dollarBracePolicy:         "audit",
    velocityDirectivePolicy:   "reject",
    maxBytes:                  C.BYTES.kib(128),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
  "permissive": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    jinjaPolicy:               "reject",
    erbPolicy:                 "reject",
    pugPolicy:                 "reject",
    dollarBracePolicy:         "audit",
    velocityDirectivePolicy:   "audit",
    maxBytes:                  C.BYTES.kib(512),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
});

var DEFAULTS = gateContract.strictDefaults(PROFILES);

var COMPLIANCE_POSTURES = gateContract.compliancePostures(PROFILES, { base: 512 });

function _hasDelimitedRun(text, open, close) {
  var at = text.indexOf(open);
  if (at === -1) return false;
  return text.indexOf(close, at + open.length) !== -1;
}

function _hasPugInterpolation(text) {
  for (var i = 0; i + 1 < text.length; i += 1) {
    var c = text.charAt(i);
    if ((c !== "#" && c !== "!") || text.charAt(i + 1) !== "{") continue;
    if (text.indexOf("}", i + 2) !== -1) return true;
  }
  return false;
}

function _hasVelocityDirective(text) {
  for (var i = 0; i < text.length; i += 1) {
    if (text.charAt(i) !== "#") continue;
    for (var d = 0; d < VELOCITY_DIRECTIVES.length; d += 1) {
      var name = VELOCITY_DIRECTIVES[d];
      var slice = text.slice(i + 1, i + 1 + name.length);
      if (slice.length !== name.length) continue;
      if (!codepointClass.containsFolded(slice, name)) continue;
      var after = text.charCodeAt(i + 1 + name.length);
      if (isNaN(after) || !codepointClass.isIdentifierChar(after)) return true;
    }
  }
  return false;
}

function _detectIssues(input, opts) {
  var pre = gateContract.detectStringInput(input, opts, { name: "template", noun: "template input", emptyMode: "ok", cap: { bytes: opts.maxBytes, kind: "input-cap", snippet: "template input exceeds maxBytes " + opts.maxBytes } });
  if (pre.done) return pre.issues;
  var issues = pre.issues;

  if (opts.jinjaPolicy !== "allow") {
    if (_hasDelimitedRun(input, "{{", "}}")) {
      issues.push({
        kind: "jinja-expression", severity: "high",
        ruleId: "template.jinja-expression",
        snippet: "input contains `{{...}}` template-engine expression " +
                 "syntax — Jinja / Django / Twig / Liquid / Handlebars / " +
                 "AngularJS SSTI shape (CVE-2024-22195 / 26139 / 23348 " +
                 "class)",
      });
    }
    if (_hasDelimitedRun(input, "{%", "%}")) {
      issues.push({
        kind: "jinja-statement", severity: "high",
        ruleId: "template.jinja-statement",
        snippet: "input contains `{%...%}` template-engine statement " +
                 "syntax — SSTI shape",
      });
    }
  }
  if (opts.erbPolicy !== "allow" && _hasDelimitedRun(input, "<%", "%>")) {
    issues.push({
      kind: "erb-expression", severity: "high",
      ruleId: "template.erb-expression",
      snippet: "input contains `<%...%>` template-engine expression " +
               "syntax — ERB / Tornado SSTI shape",
    });
  }
  if (opts.pugPolicy !== "allow" && _hasPugInterpolation(input)) {
    issues.push({
      kind: "pug-interpolation", severity: "high",
      ruleId: "template.pug-interpolation",
      snippet: "input contains `#{...}` or `!{...}` template-engine " +
               "interpolation — Pug SSTI shape",
    });
  }
  if (opts.dollarBracePolicy !== "allow" && _hasDelimitedRun(input, "${", "}")) {
    issues.push({
      kind: "dollar-brace",
      severity: opts.dollarBracePolicy === "reject" ? "high" : "warn",
      ruleId: "template.dollar-brace",
      snippet: "input contains `${...}` interpolation — Mako / " +
               "Velocity / Tornado / JS template-literal SSTI shape",
    });
  }
  if (opts.velocityDirectivePolicy !== "allow" && _hasVelocityDirective(input)) {
    issues.push({
      kind: "velocity-directive",
      severity: opts.velocityDirectivePolicy === "reject" ? "high" : "warn",
      ruleId: "template.velocity-directive",
      snippet: "input contains Velocity directive (`#set` / `#if` / " +
               "`#foreach` / etc.) — SSTI shape",
    });
  }

  return issues;
}

/**
 * @primitive  b.guardTemplate.validate
 * @signature  b.guardTemplate.validate(input, opts)
 * @since      0.7.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardTemplate.gate, b.guardTemplate.sanitize
 *
 * Inspect a user-supplied template-rendering input and return an
 * aggregated issue list. Pure inspection — never throws on
 * hostile input; caller decides what to do with the issues. The
 * `ok` flag is `true` only when zero `critical` / `high` issues
 * fire. Throws `GuardTemplateError("template/bad-opt")` when a
 * numeric opt is non-finite / negative (config-time mistake by
 * the operator).
 *
 * @opts
 *   profile:                 "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   bidiPolicy:              "reject"|"audit"|"allow",
 *   controlPolicy:           "reject"|"audit"|"allow",
 *   nullBytePolicy:          "reject"|"audit"|"allow",
 *   zeroWidthPolicy:         "reject"|"audit"|"allow",
 *   jinjaPolicy:             "reject"|"audit"|"allow",
 *   erbPolicy:               "reject"|"audit"|"allow",
 *   pugPolicy:               "reject"|"audit"|"allow",
 *   dollarBracePolicy:       "reject"|"audit"|"allow",
 *   velocityDirectivePolicy: "reject"|"audit"|"allow",
 *   maxBytes:                number,
 *   maxRuntimeMs:            number,
 *
 * @example
 *   var clean = b.guardTemplate.validate("Hello world", { profile: "strict" });
 *   clean.ok;                                          // → true
 *
 *   var hostile = b.guardTemplate.validate("Hello {{7*7}}", { profile: "strict" });
 *   hostile.ok;                                        // → false
 *   hostile.issues.some(function (i) { return i.kind === "jinja-expression"; });  // → true
 */

/**
 * @primitive  b.guardTemplate.sanitize
 * @signature  b.guardTemplate.sanitize(input, opts)
 * @since      0.7.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardTemplate.validate, b.guardTemplate.gate
 *
 * Pass-through-or-throw. Template-input strings cannot be safely
 * repaired (stripping `{{` from `{{name}}` produces a different
 * document and silently changes operator intent); this primitive
 * returns the input unchanged when no `critical` or `high` issue
 * fires, otherwise throws `GuardTemplateError` with the offending
 * rule id (e.g. `template.jinja-expression`,
 * `template.erb-expression`, `template.pug-interpolation`,
 * `template.velocity-directive`). Operators that need a "best-
 * effort cleanup" semantic should pre-escape the input through
 * the rendering engine's own escape helper instead.
 *
 * @opts
 *   profile:                 "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   jinjaPolicy:             "reject"|"audit"|"allow",
 *   erbPolicy:               "reject"|"audit"|"allow",
 *   pugPolicy:               "reject"|"audit"|"allow",
 *   dollarBracePolicy:       "reject"|"audit"|"allow",
 *   velocityDirectivePolicy: "reject"|"audit"|"allow",
 *   maxBytes:                number,
 *
 * @example
 *   var safe = b.guardTemplate.sanitize("Hello world", { profile: "strict" });
 *   safe;                                              // → "Hello world"
 *
 *   try {
 *     b.guardTemplate.sanitize("Hello {{7*7}}", { profile: "strict" });
 *   } catch (e) {
 *     e.code;                                          // → "template.jinja-expression"
 *   }
 */
function _sanitizeTransform(input) {
  return input;
}

var INTEGRATION_FIXTURES = gateContract.identifierFixtures("Hello world", "Hello {{7*7}}");

var POLICY_ENUM = gateContract.policyVocabulary([
  "jinjaPolicy", "erbPolicy", "pugPolicy", "dollarBracePolicy",
  "velocityDirectivePolicy",
], gateContract.POLICY_VALUES.rejectAuditAllow);

module.exports = gateContract.defineGuard({
  enumOpts:    POLICY_ENUM,
  name:        "template",
  kind:        "identifier",
  errorClass:  GuardTemplateError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  integrationFixtures: INTEGRATION_FIXTURES,
  detect:           _detectIssues,
  sanitizeTransform: _sanitizeTransform,
  intOpts:          ["maxBytes"],
  ctxFields:   ["identifier", "text"],
});
