// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.guardText
 * @nav    Guards
 * @title  Guard Text
 *
 * @intro
 *   General-purpose UTF-8 free-text content-safety guard — the screen for
 *   unconstrained human text (a comment, a note, a review body, a gift
 *   message, a display name) where the legitimate content is "arbitrary
 *   letters in any writing system" but the dangerous content is a hidden
 *   codepoint that renders as nothing yet changes meaning.
 *
 *   Unlike the format-specific members of the guard family (csv / html / svg /
 *   json / yaml / xml / markdown), this guard imposes NO grammar on its input.
 *   Cyrillic, Han, Arabic, emoji, combining marks — all pass. What it screens
 *   is the codepoint threat catalog shared across the family:
 *
 *     - Unicode bidi overrides (CVE-2021-42574 Trojan Source — U+202A..U+202E,
 *       U+2066..U+2069, U+200E/F, U+061C). Visible text reads one way; the
 *       logical order is reversed.
 *     - C0 control characters (minus tab / lf / cr, which are legitimate in
 *       free text) — terminal-escape and log-injection vectors.
 *     - Null bytes — truncation / C-string-boundary attacks downstream.
 *     - Zero-width / invisible formatting chars (ZWSP / ZWNJ / ZWJ / WJ / SHY /
 *       BOM) — payload-hiding and watermark channels.
 *     - Unicode Tags block (U+E0000..U+E007F) — "ASCII smuggling": an invisible
 *       copy of an ASCII instruction an LLM tokenizer reads verbatim
 *       (prompt-injection over a comment field).
 *     - Mixed-script confusables (UTS #39) — a Cyrillic letter inside an
 *       otherwise-Latin word. Audit severity by default (legitimate
 *       multilingual text mixes scripts); promoted to refuse under the strict
 *       profile and the regulated postures.
 *
 *   Three profiles ship — `strict` / `balanced` / `permissive` — plus four
 *   compliance postures (`hipaa` / `pci-dss` / `gdpr` / `soc2`). `strict`
 *   rejects bidi / control / null; `balanced` strips them and serves the
 *   cleaned text; `permissive` strips the invisibles and only audits the rest.
 *   Sanitize is a SHRINKING operation by contract — stripping invisible
 *   codepoints never grows the string; an amplification past
 *   `sanitizeAmplificationCap` (default 1.5x) is refused.
 *
 *   `b.guardText.gate(opts)` plugs into `b.fileUpload` / `b.staticServe` /
 *   `b.mail` / `b.objectStore` / `b.guardAll` like every other content guard.
 *
 *   Threat-detection regex literals are composed from the numeric codepoint
 *   tables in `b.codepointClass`. The source file never embeds the attack
 *   characters themselves (the family ASCII-purity invariant).
 *
 * @card
 *   General-purpose UTF-8 free-text guard — allows arbitrary letters in any script, screens bidi / control / null / zero-width / Unicode-Tags / confusable codepoints.
 */

var codepointClass = require("./codepoint-class");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var gateContract = require("./gate-contract");
var { GuardTextError } = require("./framework-error");

var _err = GuardTextError.factory;
var HEX_RADIX = 16;

var PROFILES = Object.freeze({
  "strict": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    tagsPolicy:        "reject",
    confusablePolicy:  "reject",
    allowedScripts:    null,
    maxBytes:          C.BYTES.mib(1),
  },
  "balanced": {
    bidiPolicy:        "strip",
    controlPolicy:     "strip",
    nullBytePolicy:    "strip",
    zeroWidthPolicy:   "strip",
    tagsPolicy:        "strip",
    confusablePolicy:  "audit",
    allowedScripts:    null,
    maxBytes:          C.BYTES.mib(4),
  },
  "permissive": {
    bidiPolicy:        "audit",
    controlPolicy:     "strip",
    nullBytePolicy:    "strip",
    zeroWidthPolicy:   "strip",
    tagsPolicy:        "strip",
    confusablePolicy:  "allow",
    allowedScripts:    null,
    maxBytes:          C.BYTES.mib(16),
    encodingPolicy:    "audit",
  },
});

var DEFAULTS = gateContract.strictDefaults(PROFILES, {
  encodingPolicy:           "reject",
  asciiOnly:                false,
  maxCodepoint:             null,
  sanitizeAmplificationCap: 1.5,
  forensicSnippetBytes:     0,
  maxRuntimeMs:             C.TIME.seconds(30),
});

var COMPLIANCE_POSTURES = gateContract.compliancePostures(PROFILES, { base: 256 });

var POLICY_ENUM = gateContract.policyVocabulary(
  ["confusablePolicy", "encodingPolicy"],
  gateContract.POLICY_VALUES.rejectAuditAllow);

var RESOLVER_ENUMS = Object.freeze(Object.assign({},
  gateContract.charPolicyEnums(DEFAULTS, { canRepair: true }), POLICY_ENUM));

var INT_OPTS = ["maxBytes"];

function _resolveOpts(opts) {
  return gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardTextError,
    errCodePrefix:      "text",
    intOpts:            INT_OPTS,
    nonNegativeOpts:    gateContract.capKeysOf(DEFAULTS),
    enumOpts:           RESOLVER_ENUMS,
  });
}

var _STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true });
function _hasLoneSurrogate(text) {
  for (var i = 0; i < text.length; i += 1) {
    var cc = text.charCodeAt(i);
    if (cc >= 0xD800 && cc <= 0xDBFF) {
      var next = text.charCodeAt(i + 1);
      if (!(next >= 0xDC00 && next <= 0xDFFF)) return true;
      i += 1;
    } else if (cc >= 0xDC00 && cc <= 0xDFFF) {
      return true;
    }
  }
  return false;
}

function _strictText(input) {
  if (Buffer.isBuffer(input)) {
    try { return { text: _STRICT_UTF8.decode(input), encodingError: null }; }
    catch (_e) {
      return { text: input.toString("utf8"),
               encodingError: "malformed UTF-8 (overlong / invalid continuation / truncated multibyte)" };
    }
  }
  if (typeof input === "string") {
    return { text: input,
             encodingError: _hasLoneSurrogate(input) ? "unpaired UTF-16 surrogate" : null };
  }
  return { text: null, encodingError: null };
}

function _firstCodepointAbove(text, max) {
  for (var i = 0; i < text.length; ) {
    var cp = text.codePointAt(i);
    if (cp > max) return { index: i, cp: cp };
    i += cp > 0xFFFF ? 2 : 1;
  }
  return null;
}

function _detectIssues(text, opts) {
  var issues = [];
  if (typeof text !== "string") return issues;

  issues.push.apply(issues, codepointClass.detectCharThreats(text, opts, "text"));


  if (opts.confusablePolicy !== "allow") {
    var scripts = codepointClass.detectMixedScripts(text, opts.allowedScripts || null);
    if (scripts) {
      issues.push({
        kind: "mixed-script-confusable",
        severity: opts.confusablePolicy === "reject" ? "high" : "warn",
        ruleId: "text.confusable",
        location: 0,
        snippet: "mixed-script text (UTS #39 confusable risk): " + scripts.join(", "),
      });
    }
  }

  if (opts.asciiOnly) {
    var na = _firstCodepointAbove(text, 0x7F);
    if (na) {
      issues.push({
        kind: "non-ascii", severity: "high", ruleId: "text.non-ascii",
        location: na.index,
        snippet: "non-ASCII codepoint U+" + na.cp.toString(HEX_RADIX) +
                 " at offset " + na.index + " (asciiOnly keyspace)",
      });
    }
  }
  if (typeof opts.maxCodepoint === "number") {
    var oor = _firstCodepointAbove(text, opts.maxCodepoint);
    if (oor) {
      issues.push({
        kind: "codepoint-out-of-range", severity: "high", ruleId: "text.codepoint-range",
        location: oor.index,
        snippet: "codepoint U+" + oor.cp.toString(HEX_RADIX) + " at offset " +
                 oor.index + " exceeds maxCodepoint U+" + opts.maxCodepoint.toString(HEX_RADIX),
      });
    }
  }

  return issues;
}

var _STRIPPABLE = Object.freeze({
  "bidi-override": true, "control-char": true, "null-byte": true,
  "zero-width": true, "unicode-tags": true,
});

function _dispositionFor(issue, opts) {
  switch (issue.kind) {
    case "bidi-override":  return opts.bidiPolicy;
    case "control-char":   return opts.controlPolicy;
    case "null-byte":      return opts.nullBytePolicy;
    case "zero-width":     return opts.zeroWidthPolicy;
    case "unicode-tags":   return opts.tagsPolicy;
    case "mixed-script-confusable":
      return opts.confusablePolicy === "reject" ? "reject" : "audit";
    case "invalid-encoding":
      return opts.encodingPolicy === "reject" ? "reject" : "audit";
    case "non-ascii":
    case "codepoint-out-of-range":
      return "reject";
    case "too-large":
    case "bad-input":
      return "reject";
    default:
      return (issue.severity === "high" || issue.severity === "critical")
        ? "reject" : "audit";
  }
}

/**
 * @primitive  b.guardText.validate
 * @signature  b.guardText.validate(input, opts?)
 * @since      0.15.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardText.sanitize, b.guardText.gate, b.guardAll.gate
 *
 * Inspect `input` (string or Buffer of UTF-8 text) and return `{ ok, issues }`.
 * Each issue carries `{ kind, severity, ruleId, location, snippet }` with
 * severity in `"warn"|"high"|"critical"`. Three validation axes: (1) ENCODING —
 * a Buffer is decoded as STRICT UTF-8, so a malformed / overlong / truncated
 * sequence is flagged `invalid-encoding` rather than silently lossily decoded
 * to U+FFFD (the overlong-encoding filter-bypass); a JS string is checked for
 * unpaired surrogates. (2) KEYSPACE — `asciiOnly` pins the allowed codepoint
 * range to US-ASCII and `maxCodepoint` sets a ceiling (distinct from the script
 * axis: the raw codepoint range, not which writing systems mix). (3) CODEPOINT
 * THREATS — Unicode bidi override (CVE-2021-42574 Trojan Source), C0 control
 * char, null byte, zero-width / invisible char, Unicode Tags block char (ASCII
 * smuggling), and mixed-script confusable. Arbitrary letters in any single
 * script are NOT issues — this guard imposes no grammar. `ok` is `false` only
 * when at least one issue is `high` or `critical`. Pure inspection — never
 * mutates input or throws (other than the `maxBytes` positive-finite-integer
 * opt check). The `maxBytes` limit is measured in UTF-8 BYTES. Passing
 * `Infinity` for `maxBytes` throws.
 *
 * @opts
 *   profile:           "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   bidiPolicy:        "reject"|"strip"|"audit"|"allow",
 *   controlPolicy:     "reject"|"strip"|"allow",
 *   nullBytePolicy:    "reject"|"strip"|"allow",
 *   zeroWidthPolicy:   "reject"|"strip"|"allow",
 *   tagsPolicy:        "reject"|"strip"|"allow",
 *   confusablePolicy:  "reject"|"audit"|"allow",
 *   encodingPolicy:    "reject"|"audit"|"allow",   // malformed UTF-8 (default reject)
 *   asciiOnly:         boolean,          // keyspace = US-ASCII only (default false)
 *   maxCodepoint:      number,           // keyspace ceiling (e.g. 0xFFFF for BMP-only)
 *   allowedScripts:    Array,            // confusable allowlist (e.g. ["latin","han"])
 *   maxBytes:          number,           // default 1 MiB, measured in UTF-8 bytes
 *
 * @example
 *   var rv = b.guardText.validate("hello world", { profile: "strict" });
 *   rv.ok;                                             // → true
 *   // Build the hostile input programmatically so the source stays ASCII.
 *   var RLO = String.fromCharCode(0x202E);
 *   var bad = b.guardText.validate("review " + RLO + "txt.exe", { profile: "strict" });
 *   bad.ok;                                            // → false
 *   bad.issues[0].kind;                                // → "bidi-override"
 */
function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes"], "guardText.validate", GuardTextError, "text/bad-opt");

  var decoded = _strictText(input);
  if (decoded.text == null) {
    return gateContract.runIssueValidator(input, opts, _detectIssues);
  }
  var encIssue = (decoded.encodingError && opts.encodingPolicy !== "allow")
    ? { kind: "invalid-encoding",
        severity: opts.encodingPolicy === "reject" ? "critical" : "warn",
        ruleId: "text.invalid-encoding", snippet: decoded.encodingError }
    : null;
  var byteLen = Buffer.byteLength(decoded.text, "utf8");
  if (byteLen > opts.maxBytes) {
    var big = [{ kind: "too-large", severity: "high", ruleId: "text.too-large",
                 snippet: "input " + byteLen + " bytes exceeds maxBytes " + opts.maxBytes }];
    if (encIssue) big.unshift(encIssue);
    return { ok: false, issues: big };
  }
  var rv = gateContract.runIssueValidator(decoded.text, opts, _detectIssues);
  if (!encIssue) return rv;
  var issues = [encIssue].concat(rv.issues);
  var ok = issues.every(function (i) { return i.severity !== "critical" && i.severity !== "high"; });
  return { ok: ok, issues: issues };
}

/**
 * @primitive  b.guardText.sanitize
 * @signature  b.guardText.sanitize(input, opts?)
 * @since      0.15.13
 * @status     stable
 * @related    b.guardText.validate, b.guardText.gate
 *
 * Best-effort cleanup of `input` (string or Buffer): strips bidi overrides
 * (when `bidiPolicy: "strip"`), C0 control chars (`controlPolicy: "strip"`),
 * null bytes (`nullBytePolicy: "strip"`), zero-width / invisible chars
 * (`zeroWidthPolicy: "strip"`), and Unicode Tags block chars (`tagsPolicy:
 * "strip"`). Legitimate letters in any script are preserved; a mixed-script
 * confusable is NEVER auto-repaired (there is no safe automated repair — the
 * gate refuses it instead). Sanitize is a SHRINKING operation by contract:
 * when the output exceeds `sanitizeAmplificationCap` (default 1.5x) the
 * function throws `GuardTextError("text/sanitize-amplified")`.
 *
 * A class set to `"reject"` throws rather than returning: `"reject"` refuses,
 * `"strip"` repairs, and `"audit"` reports through `validate` while leaving
 * the text alone. Under `strict` every class is `"reject"`, so sanitize there
 * either returns clean input or throws — it never hands back a threat.
 *
 * @opts
 *   profile:           "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   bidiPolicy:        "reject"|"strip"|"audit"|"allow",
 *   controlPolicy:     "reject"|"strip"|"allow",
 *   nullBytePolicy:    "reject"|"strip"|"allow",
 *   zeroWidthPolicy:   "reject"|"strip"|"allow",
 *   tagsPolicy:        "reject"|"strip"|"allow",
 *   sanitizeAmplificationCap: number,    // default 1.5
 *
 * @example
 *   var ZWSP = String.fromCharCode(0x200B);
 *   var clean = b.guardText.sanitize("nice" + ZWSP + "review", { profile: "balanced" });
 *   clean.indexOf(ZWSP) === -1;                        // → true
 *   clean;                                             // → "nicereview"
 */
function sanitize(input, opts) {
  opts = _resolveOpts(opts);
  var decoded = _strictText(input);
  if (decoded.text == null) {
    throw _err("text/bad-input", "sanitize requires string or Buffer input");
  }
  if (decoded.encodingError && opts.encodingPolicy === "reject") {
    throw _err("text.invalid-encoding",
      "cannot sanitize input with " + decoded.encodingError + " (not repairable)");
  }
  var text = decoded.text;
  var sanitized = codepointClass.scrubCharThreats(text, opts, _err, "text");
  var amplification = sanitized.length / Math.max(text.length, 1);
  if (amplification > opts.sanitizeAmplificationCap) {
    throw _err("text/sanitize-amplified",
      "sanitize grew output " + amplification.toFixed(2) +
      "x; cap " + opts.sanitizeAmplificationCap);
  }
  return sanitized;
}

/**
 * @primitive  b.guardText.gate
 * @signature  b.guardText.gate(opts?)
 * @since      0.15.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardText.validate, b.guardText.sanitize, b.fileUpload.create, b.staticServe.create
 *
 * Build a `b.gateContract` gate suitable for plugging into
 * `b.fileUpload({ contentSafety: { "text/plain": gate } })`,
 * `b.staticServe({ contentSafety: { ".txt": gate } })`, `b.mail`, or
 * `b.objectStore`. Action chain on inspection: `serve` (no issues) →
 * `audit-only` (warn-only issues — e.g. a mixed-script confusable under
 * `confusablePolicy: "audit"`) → `sanitize` (critical/high but no `reject`
 * policy active — strips the invisible codepoints and serves the cleaned text)
 * → `refuse` (critical/high under any `reject` policy, a confusable under
 * `confusablePolicy: "reject"`, or when sanitize fails / amplifies past cap).
 *
 * Operator extensibility: pass `operatorRules: [{ id, severity, detect:
 * fn(ctx)->boolean, reason }]` to inject custom detectors alongside the
 * built-in catalog. Rules run best-effort — a throwing detector is skipped
 * (the framework cannot crash a request because an operator rule mishandled
 * bytes).
 *
 * @opts
 *   profile:           "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   name:              string,    // gate identity for audit / observability
 *   operatorRules:     Array,     // [{ id, severity, detect: function, reason }]
 *
 * @example
 *   var textGate = b.guardText.gate({ profile: "strict" });
 *   var upload = b.fileUpload.create({ contentSafety: { "text/plain": textGate } });
 *   var RLO = String.fromCharCode(0x202E);
 *   var hostile = Buffer.from("ok " + RLO + "danger", "utf8");
 *   var verdict = await textGate.check({ bytes: hostile });
 *   verdict.action;                                    // → "refuse"
 */
function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardText:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var text = gateContract.extractBytesAsText(ctx);
      if (!text) return { ok: true, action: "serve" };
      var rawInput = (ctx && Buffer.isBuffer(ctx.bytes)) ? ctx.bytes : text;
      var rv = validate(rawInput, opts);

      var operatorIssues = [];
      if (Array.isArray(opts.operatorRules)) {
        for (var ri = 0; ri < opts.operatorRules.length; ri += 1) {
          var rule = opts.operatorRules[ri];
          try {
            if (rule.detect && rule.detect({ bytes: text, ctx: ctx })) {
              operatorIssues.push({
                kind: rule.id, severity: rule.severity || "warn",
                ruleId: rule.id, snippet: rule.reason || rule.id,
              });
            }
          } catch (_e) { /* operator rule best-effort — never crash the request */ }
        }
      }
      var allIssues = rv.issues.concat(operatorIssues);
      if (allIssues.length === 0) return { ok: true, action: "serve" };

      var dispositions = allIssues.map(function (i) { return _dispositionFor(i, opts); });
      if (dispositions.indexOf("reject") !== -1) {
        return { ok: false, action: "refuse", issues: allIssues };
      }
      if (dispositions.indexOf("strip") !== -1) {
        var stripUnrepairable = allIssues.some(function (i, idx) {
          return dispositions[idx] === "strip" && !_STRIPPABLE[i.kind];
        });
        if (stripUnrepairable) {
          return { ok: false, action: "refuse", issues: allIssues };
        }
        try {
          var clean = sanitize(text, opts);
          return {
            ok: true, action: "sanitize",
            sanitized: Buffer.from(clean, "utf8"),
            issues: allIssues,
          };
        } catch (_e) {
          return { ok: false, action: "refuse", issues: allIssues };
        }
      }
      return { ok: true, action: "audit-only", issues: allIssues };
    });
}

var INTEGRATION_FIXTURES = Object.freeze({
  kind:        "content",
  contentType: "text/plain",
  extension:   ".txt",
  benignBytes: Buffer.from("a perfectly ordinary review of the product", "utf8"),
  hostileBytes: Buffer.from("ok " + String.fromCharCode(0x202E) + "danger", "utf8"),
});

module.exports = gateContract.defineGuard({
  enumOpts:    POLICY_ENUM,
  name:        "text",
  kind:        "content",
  charRepair:  true,
  errorClass:  GuardTextError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  mimeTypes:   ["text/plain"],
  extensions:  [".txt"],
  integrationFixtures: INTEGRATION_FIXTURES,
  validate:    validate,
  sanitize:    sanitize,
  intOpts:     INT_OPTS,
  gate:        gate,
});
