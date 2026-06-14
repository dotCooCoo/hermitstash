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
 * fire. Throws `GuardTemplateError("template.bad-opt")` when a
 * numeric opt is non-finite / negative (config-time mistake by
 * the operator).
 *
 * @opts
 *   profile:                 "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   bidiPolicy:              "reject"|"audit"|"allow",
 *   controlPolicy:           "reject"|"audit"|"allow",
 *   nullBytePolicy:          "reject"|"audit"|"allow",
 *   zeroWidthPolicy:         "reject"|"strip"|"audit"|"allow",
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
function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes"],
    "guardTemplate.validate", GuardTemplateError, "template.bad-opt");
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

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
function sanitize(input, opts) {
  opts = _resolveOpts(opts);
  if (typeof input !== "string") {
    throw _err("template.bad-input", "sanitize requires string input");
  }
  var issues = _detectIssues(input, opts);
  gateContract.throwOnRefusalSeverity(issues, { errorClass: GuardTemplateError, codePrefix: "template" });
  return input;
}

// gate / buildProfile / compliancePosture / loadRulePack are assembled by
// gateContract.defineGuard below. The gate is the standard
// serve -> audit-only -> refuse chain (template input cannot be repaired, so
// there is no sanitize action), dispatched to ctx.identifier || ctx.text via
// the spec's ctxFields. Its wiki section renders from the single-sourced
// @abiTemplate (defineGuard) blocks in gate-contract.js, instantiated per
// guard by the page generator.

var INTEGRATION_FIXTURES = Object.freeze({
  kind:              "identifier",
  benignBytes:       Buffer.from("Hello world", "utf8"),
  hostileBytes:      Buffer.from("Hello {{7*7}}", "utf8"),
  benignIdentifier:  "Hello world",
  // Hostile: Jinja-shape SSTI probe.
  hostileIdentifier: "Hello {{7*7}}",
});

// Assembled from the gate-contract guard factory: error class, registry
// exports (NAME / KIND / INTEGRATION_FIXTURES), the default gate, buildProfile
// / compliancePosture / loadRulePack wiring, plus the per-guard inspection
// surface (validate / sanitize) passed through verbatim. The gate is the
// factory default serve -> audit-only -> refuse chain; ctxFields names the
// ctx fields it reads (ctx.identifier, then ctx.text) so untrusted strings on
// either field reach the SSTI validator before any engine renders them.
module.exports = gateContract.defineGuard({
  name:        "template",
  kind:        "identifier",
  errorClass:  GuardTemplateError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  integrationFixtures: INTEGRATION_FIXTURES,
  validate:    validate,
  sanitize:    sanitize,
  ctxFields:   ["identifier", "text"],
});
