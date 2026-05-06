"use strict";
/**
 * guard-template — Template-injection identifier-safety primitive
 * (b.guardTemplate).
 *
 * Detects Server-Side Template Injection (SSTI) shapes in user-input
 * strings before they're rendered through any template engine. Refused
 * by default at every profile — operator-untrusted input rarely
 * legitimately contains template-engine syntax. KIND="identifier" —
 * consumes ctx.identifier (or ctx.text).
 *
 * Threat catalog (engine-shape detection):
 *   - Jinja2 / Django / Twig / Liquid — `{{...}}` and `{%...%}`.
 *     Recent CVEs: CVE-2024-22195 (Jinja xml_attr filter),
 *     CVE-2024-26139 (Bottle), CVE-2024-23348 (Pyrogram).
 *   - Handlebars — `{{...}}` (same shape as Jinja; flagged together).
 *   - ERB / Tornado — `<%...%>` and `<%=...%>`.
 *   - Pug — `#{...}` interpolation, `!{...}` raw-HTML interpolation.
 *   - Mako / Velocity / Tornado — `${...}` interpolation.
 *   - Velocity directive — `#set(...)`, `#if(...)`, `#foreach(...)`.
 *   - AngularJS — `{{...}}` (covered by Jinja shape; legacy).
 *   - BIDI / null / control / zero-width universal refuse.
 *
 *   var rv = b.guardTemplate.validate("Hello {{ name }}",
 *                                     { profile: "strict" });
 *   var g  = b.guardTemplate.gate({ profile: "strict" });
 */

var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var { GuardTemplateError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardTemplateError.factory;

// Engine-shape detectors.
var JINJA_EXPR_RE   = /\{\{[\s\S]*?\}\}/;
var JINJA_STMT_RE   = /\{%[\s\S]*?%\}/;
var ERB_EXPR_RE     = /<%[\s\S]*?%>/;
var PUG_INTERP_RE   = /[#!]\{[\s\S]*?\}/;
var DOLLAR_BRACE_RE = /\$\{[\s\S]*?\}/;
var VELOCITY_DIR_RE = /#(?:set|if|else|elseif|end|foreach|parse|include|stop)\b/i;

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    bidiPolicy:               "reject",
    controlPolicy:             "reject",
    nullBytePolicy:            "reject",
    zeroWidthPolicy:           "reject",
    jinjaPolicy:               "reject",
    erbPolicy:                 "reject",
    pugPolicy:                 "reject",
    dollarBracePolicy:         "reject",
    velocityDirectivePolicy:   "reject",
    maxBytes:                  C.BYTES.kib(64),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
  "balanced": {
    bidiPolicy:               "reject",
    controlPolicy:             "reject",
    nullBytePolicy:            "reject",
    zeroWidthPolicy:           "reject",
    jinjaPolicy:               "reject",                                          // SSTI class — refused at every profile
    erbPolicy:                 "reject",
    pugPolicy:                 "reject",
    dollarBracePolicy:         "audit",                                           // ${...} can also be JS template literal — audit
    velocityDirectivePolicy:   "reject",
    maxBytes:                  C.BYTES.kib(128),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
  "permissive": {
    bidiPolicy:               "reject",                                          // BIDI refused at every profile
    controlPolicy:             "reject",                                          // controls refused at every profile
    nullBytePolicy:            "reject",                                          // null refused at every profile
    zeroWidthPolicy:           "reject",                                          // zero-width refused at every profile
    jinjaPolicy:               "reject",                                          // SSTI class refused at every profile
    erbPolicy:                 "reject",                                          // SSTI class refused at every profile
    pugPolicy:                 "reject",                                          // SSTI class refused at every profile
    dollarBracePolicy:         "audit",
    velocityDirectivePolicy:   "audit",
    maxBytes:                  C.BYTES.kib(512),
    maxRuntimeMs:              C.TIME.seconds(2),
  },
});

var DEFAULTS = Object.freeze(Object.assign({}, PROFILES["strict"], {
  mode: "enforce",
}));

var COMPLIANCE_POSTURES = Object.freeze({
  "hipaa":   Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(512),
  }),
  "pci-dss": Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(512),
  }),
  "gdpr":    Object.assign({}, PROFILES["balanced"], {
    forensicSnippetBytes: C.BYTES.bytes(256),
  }),
  "soc2":    Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(1024),
  }),
});

function _resolveOpts(opts) {
  return gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardTemplateError,
    errCodePrefix:      "template",
  });
}

function _detectIssues(input, opts) {
  var issues = [];
  if (typeof input !== "string") {
    return [{ kind: "bad-input", severity: "high",
              ruleId: "template.bad-input",
              snippet: "template input is not a string" }];
  }
  if (input.length === 0) return [];
  if (Buffer.byteLength(input, "utf8") > opts.maxBytes) {
    return [{ kind: "input-cap", severity: "high",
              ruleId: "template.input-cap",
              snippet: "template input exceeds maxBytes " + opts.maxBytes }];
  }

  var charThreats = codepointClass.detectCharThreats(input, opts, "template");
  for (var ci = 0; ci < charThreats.length; ci += 1) issues.push(charThreats[ci]);

  if (opts.jinjaPolicy !== "allow") {
    if (JINJA_EXPR_RE.test(input)) {                                             // allow:regex-no-length-cap — input bounded by maxBytes
      issues.push({
        kind: "jinja-expression", severity: "high",
        ruleId: "template.jinja-expression",
        snippet: "input contains `{{...}}` template-engine expression " +
                 "syntax — Jinja / Django / Twig / Liquid / Handlebars / " +
                 "AngularJS SSTI shape (CVE-2024-22195 / 26139 / 23348 " +
                 "class)",
      });
    }
    if (JINJA_STMT_RE.test(input)) {                                             // allow:regex-no-length-cap — input bounded by maxBytes
      issues.push({
        kind: "jinja-statement", severity: "high",
        ruleId: "template.jinja-statement",
        snippet: "input contains `{%...%}` template-engine statement " +
                 "syntax — SSTI shape",
      });
    }
  }
  if (opts.erbPolicy !== "allow" && ERB_EXPR_RE.test(input)) {                   // allow:regex-no-length-cap — input bounded by maxBytes
    issues.push({
      kind: "erb-expression", severity: "high",
      ruleId: "template.erb-expression",
      snippet: "input contains `<%...%>` template-engine expression " +
               "syntax — ERB / Tornado SSTI shape",
    });
  }
  if (opts.pugPolicy !== "allow" && PUG_INTERP_RE.test(input)) {                 // allow:regex-no-length-cap — input bounded by maxBytes
    issues.push({
      kind: "pug-interpolation", severity: "high",
      ruleId: "template.pug-interpolation",
      snippet: "input contains `#{...}` or `!{...}` template-engine " +
               "interpolation — Pug SSTI shape",
    });
  }
  if (opts.dollarBracePolicy !== "allow" && DOLLAR_BRACE_RE.test(input)) {       // allow:regex-no-length-cap — input bounded by maxBytes
    issues.push({
      kind: "dollar-brace",
      severity: opts.dollarBracePolicy === "reject" ? "high" : "warn",
      ruleId: "template.dollar-brace",
      snippet: "input contains `${...}` interpolation — Mako / " +
               "Velocity / Tornado / JS template-literal SSTI shape",
    });
  }
  if (opts.velocityDirectivePolicy !== "allow" &&
      VELOCITY_DIR_RE.test(input)) {                                             // allow:regex-no-length-cap — input bounded by maxBytes
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

function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes"],
    "guardTemplate.validate", GuardTemplateError, "template.bad-opt");
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

function sanitize(input, opts) {
  opts = _resolveOpts(opts);
  if (typeof input !== "string") {
    throw _err("template.bad-input", "sanitize requires string input");
  }
  var issues = _detectIssues(input, opts);
  for (var i = 0; i < issues.length; i += 1) {
    if (issues[i].severity === "critical" || issues[i].severity === "high") {
      throw _err(issues[i].ruleId || "template.refused",
        "guardTemplate.sanitize: " + issues[i].snippet);
    }
  }
  return input;
}

function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardTemplate:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var text = ctx && (ctx.identifier || ctx.text);
      if (text === undefined || text === null) {
        return { ok: true, action: "serve" };
      }
      var rv = validate(text, opts);
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
    _err, "template");
}

var _tplRulePacks = gateContract.makeRulePackLoader(GuardTemplateError, "template");
var loadRulePack = _tplRulePacks.load;

module.exports = {
  // ---- guard-* family registry exports ----
  NAME:                "template",
  KIND:                "identifier",
  INTEGRATION_FIXTURES: Object.freeze({
    kind:              "identifier",
    benignBytes:       Buffer.from("Hello world", "utf8"),
    hostileBytes:      Buffer.from("Hello {{7*7}}", "utf8"),
    benignIdentifier:  "Hello world",
    // Hostile: Jinja-shape SSTI probe.
    hostileIdentifier: "Hello {{7*7}}",
  }),
  // ---- primitive surface ----
  validate:             validate,
  sanitize:             sanitize,
  gate:                 gate,
  buildProfile:         buildProfile,
  compliancePosture:    compliancePosture,
  loadRulePack:         loadRulePack,
  PROFILES:             PROFILES,
  DEFAULTS:             DEFAULTS,
  COMPLIANCE_POSTURES:  COMPLIANCE_POSTURES,
  GuardTemplateError:   GuardTemplateError,
};
