"use strict";
/**
 * @module b.guardMime
 * @nav    Guards
 * @title  Guard Mime
 *
 * @intro
 *   Media-type identifier-safety guard. Validates user-supplied
 *   RFC 6838 media-type strings destined for Accept-shape comparison,
 *   content-type allowlists, and dispatch routing. KIND="identifier"
 *   — the gate consumes `ctx.identifier` (or `ctx.mime`).
 *
 *   Threat catalog: shape malformation (not RFC 6838 type/subtype
 *   grammar); bad token characters (RFC 6838 §4.2 restricts type and
 *   subtype to ALPHA / DIGIT / `!#$&-^_.+` — spaces / quotes /
 *   Unicode reject); parameter injection through pass-through
 *   `text/plain; charset=...` shapes; wildcard `*‍/‍*` / `type/*`
 *   (Accept-only — refused as content-type at strict); vendor tree
 *   `application/vnd.<vendor>` and personal tree `application/prs.*`
 *   plus unregistered `x.*` flagged so operators audit the namespace;
 *   risky types refuse list (`application/x-msdownload`,
 *   `.x-msdos-program`, `.x-sh`, `.x-csh`, `application/javascript`,
 *   `text/javascript`) when handed off to a script-host;
 *   BIDI / zero-width / C0-control / null-byte universal-refuse.
 *
 *   Magic-byte verification and polyglot rejection are performed by
 *   the operator-side fixture pipeline: the gate emits the asserted
 *   identifier; downstream content guards (`b.guardSvg` / `b.guardPdf`
 *   / `b.guardImage`) compare it against `inspectMagic(buffer)` and
 *   refuse mismatches.
 *
 *   Profiles: `strict` / `balanced` / `permissive`. Compliance
 *   postures: `hipaa` / `pci-dss` / `gdpr` / `soc2`.
 *
 * @card
 *   Media-type identifier-safety guard.
 */

var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var safeBuffer = require("./safe-buffer");
var { GuardMimeError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardMimeError.factory;

// RFC 6838 type / subtype grammar. The `restricted-name` allows
// ALPHA / DIGIT first, then ALPHA / DIGIT / `!#$&-^_.+`. Length cap
// 127 octets per token.
var TOKEN_RE = /^[A-Za-z0-9][A-Za-z0-9!#$&\-^_.+]{0,126}$/;

// Parameter token (RFC 7231 §3.1.1.1): tchar set per RFC 7230.
var PARAM_TOKEN_RE = safeBuffer.RFC7230_TCHAR_RE;

// Quoted-string body (between double quotes) per RFC 7230 §3.2.6.
var QUOTED_STRING_BODY_RE = /^[\t\x20-\x7e]*$/;                                   // printable ASCII range

// Risky-type refuse list (operator-supplied scripts handed to a host).
var RISKY_TYPES = Object.freeze([
  "application/x-msdownload",
  "application/x-bat",
  "application/x-msdos-program",
  "application/x-sh",
  "application/x-csh",
  "application/x-perl",
  "application/x-python",
  "application/javascript",
  "application/x-javascript",
  "text/javascript",
  "text/x-javascript",
  "application/x-shockwave-flash",
  "application/x-msi",
]);

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    wildcardPolicy:       "reject",
    vendorTreePolicy:     "audit",
    personalTreePolicy:   "audit",
    unregisteredTreePolicy: "audit",
    riskyTypePolicy:      "reject",
    parameterPolicy:      "audit",
    maxBytes:             C.BYTES.bytes(255),
    maxRuntimeMs:         C.TIME.seconds(2),
  },
  "balanced": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    wildcardPolicy:       "audit",
    vendorTreePolicy:     "allow",
    personalTreePolicy:   "audit",
    unregisteredTreePolicy: "audit",
    riskyTypePolicy:      "audit",
    parameterPolicy:      "audit",
    maxBytes:             C.BYTES.bytes(255),
    maxRuntimeMs:         C.TIME.seconds(2),
  },
  "permissive": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    wildcardPolicy:       "allow",
    vendorTreePolicy:     "allow",
    personalTreePolicy:   "allow",
    unregisteredTreePolicy: "allow",
    riskyTypePolicy:      "audit",
    parameterPolicy:      "allow",
    maxBytes:             C.BYTES.bytes(255),
    maxRuntimeMs:         C.TIME.seconds(2),
  },
});

// ---- Parser ----

function _splitTopLevel(input) {
  // Returns { typeSubtype, params: [{name, value}], errors: [string] }.
  // Splits on `;` outside quoted-strings.
  var parts = [];
  var inQuote = false;
  var start = 0;
  for (var i = 0; i < input.length; i += 1) {
    var c = input.charAt(i);
    if (c === '"' && (i === 0 || input.charAt(i - 1) !== "\\")) inQuote = !inQuote;
    else if (!inQuote && c === ";") {
      parts.push(input.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(input.slice(start));
  parts = parts.map(function (p) { return p.trim(); });
  return parts;
}

function _detectIssues(input, opts) {
  var pre = gateContract.detectStringInput(input, opts, { name: "mime", cap: { bytes: opts.maxBytes } });
  if (pre.done) return pre.issues;
  var issues = pre.issues;

  var parts = _splitTopLevel(input);
  var typeSubtype = parts[0];
  var paramParts = parts.slice(1).filter(function (p) { return p.length > 0; });

  // Type/subtype shape.
  var slashAt = typeSubtype.indexOf("/");
  if (slashAt === -1) {
    issues.push({
      kind: "mime-shape", severity: "high",
      ruleId: "mime.mime-shape",
      snippet: "missing `/` between type and subtype",
    });
    return issues;
  }
  var type = typeSubtype.slice(0, slashAt);
  var subtype = typeSubtype.slice(slashAt + 1);

  // Wildcard policy.
  if ((type === "*" || subtype === "*") &&
      opts.wildcardPolicy !== "allow") {
    issues.push({
      kind: "wildcard",
      severity: opts.wildcardPolicy === "reject" ? "high" : "warn",
      ruleId: "mime.wildcard",
      snippet: "wildcard `" + typeSubtype + "` only valid in Accept " +
               "headers; refused as content-type at strict",
    });
  }

  // Token validation per type / subtype.
  if (type !== "*") {
    if (!TOKEN_RE.test(type)) {                                                  // allow:regex-no-length-cap — input bounded by maxBytes
      issues.push({
        kind: "type-shape", severity: "high",
        ruleId: "mime.type-shape",
        snippet: "type `" + type + "` is not a valid RFC 6838 " +
                 "restricted-name token",
      });
    }
  }
  if (subtype !== "*") {
    if (!TOKEN_RE.test(subtype)) {                                               // allow:regex-no-length-cap — input bounded by maxBytes
      issues.push({
        kind: "subtype-shape", severity: "high",
        ruleId: "mime.subtype-shape",
        snippet: "subtype `" + subtype + "` is not a valid RFC 6838 " +
                 "restricted-name token",
      });
    }
  }

  // Tree-prefix detection.
  var subtypeLower = subtype.toLowerCase();
  if (subtypeLower.indexOf("vnd.") === 0 &&
      opts.vendorTreePolicy !== "allow") {
    issues.push({
      kind: "vendor-tree",
      severity: opts.vendorTreePolicy === "reject" ? "high" : "warn",
      ruleId: "mime.vendor-tree",
      snippet: "subtype `" + subtype + "` is in the vendor tree " +
               "(`vnd.*`); audit the vendor namespace",
    });
  }
  if (subtypeLower.indexOf("prs.") === 0 &&
      opts.personalTreePolicy !== "allow") {
    issues.push({
      kind: "personal-tree",
      severity: opts.personalTreePolicy === "reject" ? "high" : "warn",
      ruleId: "mime.personal-tree",
      snippet: "subtype `" + subtype + "` is in the personal tree " +
               "(`prs.*`)",
    });
  }
  if ((subtypeLower.indexOf("x.") === 0 || subtypeLower.indexOf("x-") === 0) &&
      opts.unregisteredTreePolicy !== "allow") {
    issues.push({
      kind: "unregistered-tree",
      severity: opts.unregisteredTreePolicy === "reject" ? "high" : "warn",
      ruleId: "mime.unregistered-tree",
      snippet: "subtype `" + subtype + "` is in the unregistered tree " +
               "(`x.*` / `x-*`)",
    });
  }

  // Risky-type refuse list (use lowercased canonical compare).
  var canonical = (type + "/" + subtype).toLowerCase();
  if (RISKY_TYPES.indexOf(canonical) !== -1 &&
      opts.riskyTypePolicy !== "allow") {
    issues.push({
      kind: "risky-type",
      severity: opts.riskyTypePolicy === "reject" ? "high" : "warn",
      ruleId: "mime.risky-type",
      snippet: "media type `" + canonical + "` is on the risky-type " +
               "refuse list (executable / script-host class)",
    });
  }

  // Parameter validation (all params at once — covers injection class).
  if (paramParts.length > 0 && opts.parameterPolicy !== "allow") {
    for (var pi = 0; pi < paramParts.length; pi += 1) {
      var pp = paramParts[pi];
      var eqAt = pp.indexOf("=");
      if (eqAt === -1) {
        issues.push({
          kind: "param-shape",
          severity: opts.parameterPolicy === "reject" ? "high" : "warn",
          ruleId: "mime.param-shape",
          snippet: "parameter `" + pp + "` missing `=` value separator",
        });
        continue;
      }
      var pname = pp.slice(0, eqAt).trim();
      var pvalue = pp.slice(eqAt + 1).trim();
      if (!PARAM_TOKEN_RE.test(pname)) {                                         // allow:regex-no-length-cap — name bounded by parameter length within maxBytes
        issues.push({
          kind: "param-name",
          severity: opts.parameterPolicy === "reject" ? "high" : "warn",
          ruleId: "mime.param-name",
          snippet: "parameter name `" + pname + "` is not a valid " +
                   "RFC 7231 §3.1.1.1 tchar token",
        });
      }
      // Value: either a token or a quoted-string.
      if (pvalue.length === 0) {
        issues.push({
          kind: "param-value-empty",
          severity: opts.parameterPolicy === "reject" ? "high" : "warn",
          ruleId: "mime.param-value-empty",
          snippet: "parameter `" + pname + "` has empty value",
        });
      } else if (pvalue.charAt(0) === '"' &&
                 pvalue.charAt(pvalue.length - 1) === '"') {
        var inner = pvalue.slice(1, -1);
        if (!QUOTED_STRING_BODY_RE.test(inner)) {                                // allow:regex-no-length-cap — value bounded within maxBytes
          issues.push({
            kind: "param-value-shape",
            severity: opts.parameterPolicy === "reject" ? "high" : "warn",
            ruleId: "mime.param-value-shape",
            snippet: "parameter `" + pname + "` quoted-string contains " +
                     "non-printable bytes (RFC 7230 §3.2.6)",
          });
        }
      } else if (!PARAM_TOKEN_RE.test(pvalue)) {                                 // allow:regex-no-length-cap — value bounded within maxBytes
        issues.push({
          kind: "param-value-shape",
          severity: opts.parameterPolicy === "reject" ? "high" : "warn",
          ruleId: "mime.param-value-shape",
          snippet: "parameter `" + pname + "` value `" + pvalue + "` " +
                   "is not a valid token or quoted-string",
        });
      }
    }
  }

  return issues;
}

/**
 * @primitive  b.guardMime.validate
 * @signature  b.guardMime.validate(input, opts?)
 * @since      0.7.47
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardMime.sanitize, b.guardMime.gate
 *
 * Inspect a media-type string against the resolved profile and
 * return `{ ok, issues }`. Each issue carries `kind` / `severity`
 * (`critical` | `high` | `medium` | `low`) / `ruleId` / `snippet`.
 * Non-string input returns a single `mime.bad-input` issue rather
 * than throwing — callers that prefer an exception use
 * `b.guardMime.sanitize`.
 *
 * @opts
 *   profile:                "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   bidiPolicy:             "reject"|"strip"|"audit"|"allow",
 *   controlPolicy:          "reject"|"strip"|"allow",
 *   nullBytePolicy:         "reject"|"strip"|"allow",
 *   zeroWidthPolicy:        "reject"|"strip"|"allow",
 *   wildcardPolicy:         "reject"|"audit"|"allow",
 *   vendorTreePolicy:       "reject"|"audit"|"allow",
 *   personalTreePolicy:     "reject"|"audit"|"allow",
 *   unregisteredTreePolicy: "reject"|"audit"|"allow",
 *   riskyTypesPolicy:       "reject"|"audit"|"allow",
 *   parameterPolicy:        "reject"|"audit"|"allow",
 *   maxBytes:               number,    // default 256 (RFC-recommended cap)
 *
 * @example
 *   var rv = b.guardMime.validate("application/json", { profile: "strict" });
 *   rv.ok;                                             // → true
 *   rv.issues.length;                                  // → 0
 *
 *   var bad = b.guardMime.validate("application/x-msdownload", { profile: "strict" });
 *   bad.ok;                                            // → false
 *   bad.issues[0].ruleId;                              // → "mime.risky-type"
 */
// validate is assembled by gateContract.defineGuard from `detect`
// (_detectIssues) below — `validate(input, opts) = aggregateIssues(detect(
// input, resolveOpts(opts)))`, with the maxBytes cap declared via `intOpts`.
// The @primitive block above documents the resulting public ABI.

/**
 * @primitive  b.guardMime.sanitize
 * @signature  b.guardMime.sanitize(input, opts?)
 * @since      0.7.47
 * @status     stable
 * @related    b.guardMime.validate, b.guardMime.gate
 *
 * Lower-case the canonical type/subtype while preserving
 * parameter-value case (some parameter values are case-significant —
 * e.g. multipart `boundary` tokens). Throws `GuardMimeError` when any
 * `critical` or `high` issue fires (risky-type, parameter-injection,
 * BIDI / null-byte / control). Use `validate` to inspect issues
 * without throwing.
 *
 * @opts
 *   profile:                "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   ...:                    same shape as b.guardMime.validate opts,
 *
 * @example
 *   var safe = b.guardMime.sanitize("Application/JSON; charset=UTF-8",
 *                                   { profile: "balanced" });
 *   safe;                                              // → "application/json; charset=UTF-8"
 *
 *   try {
 *     b.guardMime.sanitize("application/javascript", { profile: "strict" });
 *   } catch (e) {
 *     e.code;                                          // → "mime.risky-type"
 *   }
 */
// _sanitizeTransform — the guard-specific normalize applied by defineGuard's
// generated sanitize AFTER resolve → detect → throw-on-refusal. Input is an
// already-validated string at this point (a non-string refuses upstream).
function _sanitizeTransform(input) {
  // Normalize: lowercase the type/subtype; preserve parameter case
  // because some parameter values are case-significant (e.g. boundary
  // tokens in multipart/form-data).
  var parts = _splitTopLevel(input);
  var canonical = parts[0].toLowerCase();
  return parts.slice(1).reduce(function (acc, p) {
    return acc + "; " + p;
  }, canonical);
}

// The request-boundary gate is the gate-contract factory default: it reads
// `ctx.identifier` (or `ctx.mime`), runs `validate`, and maps severity to
// action — `serve` (no issue) / `audit-only` (info / warn) / `refuse` (any
// high / critical). Its wiki section renders from the single-sourced
// `@abiTemplate gate` block in gate-contract.js.

// buildProfile / compliancePosture / loadRulePack are assembled by
// gateContract.defineGuard below (makeProfileBuilder(PROFILES) /
// lookupCompliancePosture(_, COMPLIANCE_POSTURES) / makeRulePackLoader).
// Their wiki sections render from the single-sourced @abiTemplate blocks
// in gate-contract.js, instantiated per guard by the page generator.

// Hostile: risky-type — refused at strict (executable script-host class).
var INTEGRATION_FIXTURES = gateContract.identifierFixtures("application/json", "application/x-msdownload");

// Assembled from the gate-contract guard factory: error class, registry
// exports (NAME / KIND / INTEGRATION_FIXTURES), buildProfile /
// compliancePosture / loadRulePack wiring, plus the per-guard inspection
// surface (validate / sanitize). The gate is the factory default chain,
// dispatched to `ctx.identifier` / `ctx.mime` via ctxFields.
module.exports = gateContract.defineGuard({
  name:        "mime",
  kind:        "identifier",
  errorClass:  GuardMimeError,
  profiles:    PROFILES,
  base:        128,
  integrationFixtures: INTEGRATION_FIXTURES,
  detect:           _detectIssues,
  sanitizeTransform: _sanitizeTransform,
  intOpts:          ["maxBytes"],
  ctxFields:   ["identifier", "mime"],
});
