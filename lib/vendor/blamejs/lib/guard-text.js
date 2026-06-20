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
var HEX_RADIX = 16;                                                 // base-16 radix, not byte size

// ---- Shared codepoint catalog (composed from lib/codepoint-class) ----
// Pre-compiled regexes pulled from the shared catalog; this guard adds no
// codepoint table of its own.
var TAG_RE        = codepointClass.TAG_RE;

// ---- Profile presets ----
// policy axis vocabulary mirrors the codepoint-class opt names so
// detectCharThreats / assertNoCharThreats / applyCharStripPolicies read them
// directly: bidiPolicy / controlPolicy / nullBytePolicy / zeroWidthPolicy /
// tagsPolicy each in "reject" | "strip" | "audit" | "allow". confusablePolicy
// ("reject" | "audit" | "allow") is text-specific — no strip, because you
// cannot repair a confusable without guessing the intended script.
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
  // Encoding/keyspace axis (byte→codepoint layer + codepoint range), distinct
  // from the bad-codepoint regexes. encodingPolicy: reject malformed UTF-8 by
  // default; asciiOnly / maxCodepoint are opt-in keyspace ceilings.
  encodingPolicy:           "reject",   // "reject" | "audit" | "allow"
  asciiOnly:                false,
  maxCodepoint:             null,
  sanitizeAmplificationCap: 1.5,
  forensicSnippetBytes:     0,
  maxRuntimeMs:             C.TIME.seconds(30),
});

var COMPLIANCE_POSTURES = gateContract.compliancePostures(PROFILES, { base: 256 });

// ---- Internal helpers ----

function _resolveOpts(opts) {
  return gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardTextError,
    errCodePrefix:      "text",
  });
}

function _firstMatch(text, re) {
  if (typeof text !== "string") return null;
  var m = text.match(re);
  if (!m) return null;
  return { index: m.index, char: m[0] };
}

// _STRICT_UTF8 — fatal-mode decoder: an overlong encoding, an invalid
// continuation byte, or a truncated multibyte sequence THROWS instead of
// lossily substituting U+FFFD. A guard that only `toString("utf8")`s its bytes
// silently launders an overlong-encoded "/" or NUL into U+FFFD, defeating a
// downstream filter (the classic UTF-8 overlong filter-bypass). Validating the
// ENCODING (the byte→codepoint layer) is distinct from the codepoint regexes.
var _STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true });
// Unpaired UTF-16 surrogate in an already-decoded JS string (malformed Unicode
// that a Buffer round-trip can't represent).
var _LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/;

// _strictText — decode `input` to a JS string AND report a malformed encoding.
// Buffer → strict UTF-8 (fatal); string → unpaired-surrogate check. Returns
// { text, encodingError } where encodingError is null for well-formed input.
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
             // allow:regex-no-length-cap — _LONE_SURROGATE_RE is a single-pass char-class
             // alternation (no quantifier, no backtracking); O(n) on any input length.
             encodingError: _LONE_SURROGATE_RE.test(input) ? "unpaired UTF-16 surrogate" : null };
  }
  return { text: null, encodingError: null };
}

// _firstCodepointAbove — first codepoint exceeding `max` (keyspace ceiling),
// iterating by codepoint so an astral char counts once. Returns { index, cp }.
function _firstCodepointAbove(text, max) {
  for (var i = 0; i < text.length; ) {
    var cp = text.codePointAt(i);
    if (cp > max) return { index: i, cp: cp };
    i += cp > 0xFFFF ? 2 : 1;
  }
  return null;
}

// _detectIssues — pure inspection; never mutates / throws. Emits at most one
// issue per class (the codepoint catalog classes + the text-specific
// confusable class). An "allow" policy suppresses the class entirely;
// everything else surfaces the issue and the gate/sanitize layer decides
// serve / strip / refuse.
function _detectIssues(text, opts) {
  var issues = [];
  if (typeof text !== "string") return issues;

  // bidi / null-byte / control / zero-width — delegate to the shared catalog
  // detector so the per-class match-and-push block lives in exactly one place.
  // Invisible chars spoof displayed text (homoglyph), so zero-width is `high`.
  issues.push.apply(issues, codepointClass.detectCharThreats(text, opts, "text", "high"));

  if (opts.tagsPolicy !== "allow") {
    // TAG_RE uses the `u` flag (astral block U+E0000..U+E007F); index is the
    // UTF-16 offset of the first tag codepoint.
    var tagMatch = text.match(TAG_RE);
    if (tagMatch) {
      issues.push({
        kind: "unicode-tags", severity: "critical", ruleId: "text.unicode-tags",
        location: tagMatch.index,
        snippet: "Unicode Tags block char (ASCII-smuggling / prompt-injection) at offset " +
                 tagMatch.index,
      });
    }
  }

  if (opts.confusablePolicy !== "allow") {
    var scripts = codepointClass.detectMixedScripts(text, opts.allowedScripts || null);
    if (scripts) {
      // Mixed-script is an audit signal by default (legitimate multilingual
      // text mixes scripts); strict / regulated postures set confusablePolicy
      // "reject", which promotes the severity below so the gate refuses.
      issues.push({
        kind: "mixed-script-confusable",
        severity: opts.confusablePolicy === "reject" ? "high" : "warn",
        ruleId: "text.confusable",
        location: 0,
        snippet: "mixed-script text (UTS #39 confusable risk): " + scripts.join(", "),
      });
    }
  }

  // Keyspace bounds — restrict the allowed codepoint range. asciiOnly pins the
  // keyspace to US-ASCII (cp <= 0x7F); maxCodepoint sets an arbitrary ceiling.
  // Distinct from the script/confusable axis: this is the raw codepoint range,
  // not which writing systems mix.
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

// _STRIPPABLE — issue kinds whose codepoints the sanitizer can physically
// remove. A confusable / too-large / operator-rule hit is NOT in this set:
// there is no safe automated repair, so its disposition can only be serve /
// audit / refuse — never sanitize.
var _STRIPPABLE = Object.freeze({
  "bidi-override": true, "control-char": true, "null-byte": true,
  "zero-width": true, "unicode-tags": true,
});

// _dispositionFor — map a fired issue to the operator's chosen disposition
// for its class, drawn from the resolved policy axis (not a generic severity
// threshold). This is what makes the profile semantics honest: under
// `permissive`, bidiPolicy "audit" means report-and-serve, while controlPolicy
// "strip" means remove-and-serve. Returns "reject" | "strip" | "audit" |
// "serve". A non-strippable class that an operator marked dangerous (a
// confusable under "reject", an oversized input, a high/critical operator
// rule) resolves to "reject" — never "strip" — so the gate refuses rather than
// serving a file it cannot actually clean.
function _dispositionFor(issue, opts) {
  switch (issue.kind) {
    case "bidi-override":  return opts.bidiPolicy;
    case "control-char":   return opts.controlPolicy;
    case "null-byte":      return opts.nullBytePolicy;
    case "zero-width":     return opts.zeroWidthPolicy;
    case "unicode-tags":   return opts.tagsPolicy;
    case "mixed-script-confusable":
      // No "strip" — a confusable cannot be repaired without guessing the
      // intended script. reject → refuse; anything else → audit-and-serve.
      return opts.confusablePolicy === "reject" ? "reject" : "audit";
    case "invalid-encoding":
      // Malformed UTF-8 is not repairable by stripping. reject → refuse;
      // audit → serve-with-note. ("allow" never produces this issue.)
      return opts.encodingPolicy === "reject" ? "reject" : "audit";
    case "non-ascii":
    case "codepoint-out-of-range":
      // A keyspace violation under an operator-set ceiling — not strippable
      // (can't drop arbitrary letters), so refuse.
      return "reject";
    case "too-large":
    case "bad-input":
      return "reject";
    default:
      // Operator rule (or any custom kind): a high/critical hit blocks; a
      // warn rides along as an audit note. Operator rules are never strippable.
      return (issue.severity === "high" || issue.severity === "critical")
        ? "reject" : "audit";
  }
}

// _stripIssues — sanitize path. Removes only the invisible / dangerous
// codepoints whose policy is "strip"; never touches legitimate letters, never
// repairs a confusable (no safe automated repair). Delegates the bidi /
// control / null / zero-width / tags strips to the shared catalog helper so
// the replace() sequence lives once.
function _stripIssues(text, opts) {
  if (typeof text !== "string") return text;
  return codepointClass.applyCharStripPolicies(text, opts);
}

// ---- Public surface ----

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
    ["maxBytes"], "guardText.validate", GuardTextError, "text.bad-opt");

  var decoded = _strictText(input);
  if (decoded.text == null) {
    return gateContract.runIssueValidator(input, opts, _detectIssues);
  }
  // Encoding-validity is the byte→codepoint layer, checked before the codepoint
  // regexes — a malformed/overlong sequence is a critical refuse-or-audit issue
  // depending on encodingPolicy (default reject).
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
 * function throws `GuardTextError("text.sanitize-amplified")`.
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
    throw _err("text.bad-input", "sanitize requires string or Buffer input");
  }
  // Malformed UTF-8 is not safely repairable by stripping codepoints; under the
  // default reject policy, refuse rather than serve a lossily-decoded string.
  if (decoded.encodingError && opts.encodingPolicy === "reject") {
    throw _err("text.invalid-encoding",
      "cannot sanitize input with " + decoded.encodingError + " (not repairable)");
  }
  var text = decoded.text;
  var byteLen = Buffer.byteLength(text, "utf8");
  if (byteLen > opts.maxBytes) {
    throw _err("text.too-large",
      "input " + byteLen + " bytes exceeds maxBytes " + opts.maxBytes);
  }
  var sanitized = _stripIssues(text, opts);
  var amplification = sanitized.length / Math.max(text.length, 1);
  if (amplification > opts.sanitizeAmplificationCap) {
    throw _err("text.sanitize-amplified",
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
      // Validate the RAW bytes when present so strict UTF-8 decoding can catch a
      // malformed / overlong sequence (extractBytesAsText already lossily
      // decoded it to a string).
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

      // Resolve the strongest disposition across every fired issue, driven by
      // the per-class policy (reject > strip > audit > serve). One "reject"
      // refuses; otherwise a "strip" sanitizes the strippable codepoints and
      // serves the cleaned text; otherwise the issues are audit-only.
      var dispositions = allIssues.map(function (i) { return _dispositionFor(i, opts); });
      if (dispositions.indexOf("reject") !== -1) {
        return { ok: false, action: "refuse", issues: allIssues };
      }
      if (dispositions.indexOf("strip") !== -1) {
        // Fail-closed invariant: every issue we're about to "sanitize away"
        // must be a codepoint class the stripper can physically remove. If a
        // future kind ever resolves to "strip" without being strippable,
        // refuse rather than serve a file we only claimed to clean.
        var stripUnrepairable = allIssues.some(function (i, idx) {
          return dispositions[idx] === "strip" && !_STRIPPABLE[i.kind];
        });
        if (stripUnrepairable) {
          return { ok: false, action: "refuse", issues: allIssues };
        }
        // Amplify-past-cap / bad-input refuses instead.
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

// ---- adaptive integration-test fixtures (consumed by layer-5 host harness) ----
var INTEGRATION_FIXTURES = Object.freeze({
  kind:        "content",
  contentType: "text/plain",
  extension:   ".txt",
  benignBytes: Buffer.from("a perfectly ordinary review of the product", "utf8"),
  // Hostile: a bidi override (U+202E RTLO) embedded mid-string — strict
  // profile refuses; CVE-2021-42574 Trojan Source. Built from a numeric
  // codepoint so this source stays pure ASCII.
  hostileBytes: Buffer.from("ok " + String.fromCharCode(0x202E) + "danger", "utf8"),
});

// Assembled from the gate-contract guard factory: error class, registry
// exports (NAME / KIND / MIME_TYPES / EXTENSIONS / INTEGRATION_FIXTURES),
// buildProfile / compliancePosture / loadRulePack wiring, plus the per-guard
// inspection surface (validate / sanitize / gate). The bespoke `gate` carries
// the text sanitize-then-refuse chain (confusables are non-repairable).
module.exports = gateContract.defineGuard({
  name:        "text",
  kind:        "content",
  errorClass:  GuardTextError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  mimeTypes:   ["text/plain"],
  extensions:  [".txt"],
  integrationFixtures: INTEGRATION_FIXTURES,
  validate:    validate,
  sanitize:    sanitize,
  gate:        gate,
});
