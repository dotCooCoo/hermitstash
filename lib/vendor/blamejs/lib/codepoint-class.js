// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.codepointClass
 * @nav    Validation
 * @title  Codepoint Class
 *
 * @intro
 *   Shared codepoint-table threat catalog and regex compiler — the Unicode
 *   bidi-override / C0-control / zero-width / null-byte / Unicode-Tags tables
 *   (plus UTS&nbsp;#39 confusable-script detection) that the
 *   <code>b.guard*</code> family composes internally, exposed on the public
 *   surface so a consumer can build a custom free-text screen without
 *   re-rolling the regexes (where the zero-width class is mistyped and the
 *   astral Unicode-Tags "ASCII smuggling" block forgotten) or coupling to an
 *   internal module path. For a ready-made unconstrained-free-text guard reach
 *   for <code>b.guardText</code>; use this catalog when you need the raw
 *   detectors, tables, or script classifier to compose your own. Detectors
 *   emit attack characters programmatically from numeric codepoint tables
 *   (never as source literals), so files that use them stay pure ASCII.
 *
 *   Threat detectors that need to match Unicode bidi overrides, C0
 * control characters, zero-width / invisible chars, etc. compose
 * regex character classes from numeric codepoint range tables here
 * instead of embedding the attack characters directly in their
 * source files. Centralizing the tables means:
 *
 *   - Source files in lib/guard-* stay pure ASCII (zero
 *     irregular-whitespace lint findings, no eslint-disable comments
 *     for this category).
 *   - Adding / removing a codepoint from the catalog is a single
 *     edit; every guard picks up the change.
 *   - The detector composes the way an attacker would compose the
 *     payload (programmatic codepoint emission, not literal typing).
 *
 * Surface:
 *
 *   hex4(cp)              -> "\\uXXXX" escape for a single codepoint
 *   charClass(ranges)     -> regex character class body for a range
 *                            table (e.g. [0x200E, [0x202A,0x202E]])
 *   fromCp(cp)            -> String.fromCharCode shorthand
 *   ranges()              -> { BIDI_RANGES, C0_CTRL_RANGES,
 *                              ZERO_WIDTH_RANGES }
 *   compiled()            -> { BIDI_RE, BIDI_RE_G, C0_CTRL_RE,
 *                              C0_CTRL_RE_G, ZERO_WIDTH_RE, ZW_RE_G,
 *                              NULL_RE_G, NULL_BYTE, BOM_CHAR }
 *
 * The compiled() exports are RegExp instances built from the
 * codepoint tables at module load. Consumers grab them once at boot.
 *
 * Codepoint tables:
 *
 *   BIDI_RANGES — Unicode bidi-override family (CVE-2021-42574
 *     Trojan Source). LRM U+200E / RLM U+200F / ALM U+061C / LRE
 *     U+202A / RLE U+202B / PDF U+202C / LRO U+202D / RLO U+202E /
 *     LRI U+2066 / RLI U+2067 / FSI U+2068 / PDI U+2069.
 *
 *   C0_CTRL_RANGES — C0 control characters minus tab (U+09) / lf
 *     (U+0A) / cr (U+0D) — those are dialect-shaped chars that
 *     parsers handle separately. Everything else (U+00, U+01-U+08,
 *     U+0B-U+0C, U+0E-U+1F) flagged as control-byte injection.
 *
 *   ZERO_WIDTH_RANGES — invisible-formatting / zero-width chars
 *     attackers use to hide payloads:
 *     SHY  U+00AD  ZWSP U+200B  ZWNJ U+200C  ZWJ  U+200D
 *     WJ   U+2060  BOM  U+FEFF
 *
 * @card
 *   The Unicode threat-codepoint catalog (bidi / control / zero-width / Tags
 *   tables + confusable-script detection) the guard family composes — exposed
 *   so you can build a custom free-text screen without re-rolling the regexes.
 */

var HEX_RADIX = 16;                                                 // base-16 radix, not byte size

/**
 * @primitive b.codepointClass.hex4
 * @signature b.codepointClass.hex4(cp)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.charClass, b.codepointClass.fromCp
 *
 * Format a codepoint as a 4-digit `\uXXXX` regex escape (zero-padded, upper
 * case) — the building block `charClass` uses to compile a range table into a
 * character-class body without embedding the attack character as a literal.
 *
 * @example
 *   b.codepointClass.hex4(0x202E);   // returns the escape "\\u202E"
 */
function hex4(cp) {
  var s = cp.toString(HEX_RADIX).toUpperCase();
  while (s.length < 4) s = "0" + s;
  return "\\u" + s;
}
/**
 * @primitive b.codepointClass.charClass
 * @signature b.codepointClass.charClass(rangeList)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.hex4, b.codepointClass.detectCharThreats
 *
 * Compile a codepoint range table — numbers and `[lo, hi]` pairs — into a regex
 * character-class body (the inner text of `[...]`), so a detector can build its
 * own class from a catalog table without typing the codepoints as literals.
 *
 * @example
 *   var body = b.codepointClass.charClass([0x200E, [0x202A, 0x202E]]);
 *   var re = new RegExp("[" + body + "]");
 */
function charClass(rangeList) {
  return rangeList.map(function (r) {
    return Array.isArray(r) ? hex4(r[0]) + "-" + hex4(r[1]) : hex4(r);
  }).join("");
}
/**
 * @primitive b.codepointClass.fromCp
 * @signature b.codepointClass.fromCp(cp)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.hex4
 *
 * `String.fromCharCode` shorthand — emit the actual character for a codepoint
 * at runtime (e.g. to build a test fixture) instead of typing the attack
 * character as a source literal.
 *
 * @example
 *   var rlo = b.codepointClass.fromCp(0x202E);   // the U+202E override char
 */
function fromCp(cp) { return String.fromCharCode(cp); }

var BIDI_RANGES       = [0x200E, 0x200F, 0x061C, [0x202A, 0x202E], [0x2066, 0x2069]];
var C0_CTRL_RANGES    = [[0x0000, 0x0008], 0x000B, 0x000C, [0x000E, 0x001F]];
var ZERO_WIDTH_RANGES = [0x00AD, [0x200B, 0x200D], 0x2060, 0xFEFF];
// TAG_RANGES — Unicode Tags block U+E0000..U+E007F. TAG U+E0001 plus
// the printable-ASCII tag map U+E0020..U+E007E carry an invisible copy
// of an ASCII instruction that renders as nothing but is read verbatim
// by an LLM tokenizer — the "ASCII smuggling" / Unicode-Tags prompt-
// injection class. Stripping the block from untrusted prompt segments
// removes the hidden instruction channel.
var TAG_RANGES        = [[0xE0000, 0xE007F]];

// allow:dynamic-regex — codepoints from BIDI_RANGES literal table
var BIDI_RE       = new RegExp("[" + charClass(BIDI_RANGES) + "]");
// allow:dynamic-regex — codepoints from BIDI_RANGES literal table
var BIDI_RE_G     = new RegExp("[" + charClass(BIDI_RANGES) + "]", "g");
// allow:dynamic-regex — codepoints from C0_CTRL_RANGES literal table
var C0_CTRL_RE    = new RegExp("[" + charClass(C0_CTRL_RANGES) + "]");
// allow:dynamic-regex — codepoints from C0_CTRL_RANGES literal table
var C0_CTRL_RE_G  = new RegExp("[" + charClass(C0_CTRL_RANGES) + "]", "g");
// allow:dynamic-regex — codepoints from ZERO_WIDTH_RANGES literal table
var ZERO_WIDTH_RE = new RegExp("[" + charClass(ZERO_WIDTH_RANGES) + "]");
// allow:dynamic-regex — codepoints from ZERO_WIDTH_RANGES literal table
var ZW_RE_G       = new RegExp("[" + charClass(ZERO_WIDTH_RANGES) + "]", "g");
// allow:dynamic-regex — single literal codepoint U+0000
var NULL_RE_G     = new RegExp(hex4(0x0000), "g");
// Unicode Tags block (U+E0000..U+E007F). The \u{...} escape keeps this
// source file pure ASCII (the codepoint-class purity invariant) while
// matching astral codepoints — hence the `u` flag. Global form for the
// strip path.
var TAG_RE        = /[\u{E0000}-\u{E007F}]/u;
var TAG_RE_G      = /[\u{E0000}-\u{E007F}]/gu;

var NULL_BYTE = fromCp(0x0000);
var BOM_CHAR  = fromCp(0xFEFF);

// Unicode script-range catalog for IDN-homograph / mixed-script
// confusable detection (UTS #39). Used by guard-domain, guard-email,
// safe-url IDN host-label classification, and any future caller that
// needs "is this label entirely one writing system?". Centralizing the
// table keeps the codepoint definitions in one place — adding a script
// is a single edit.
var SCRIPT_RANGES = {
  latin:    [[0x0041, 0x005A], [0x0061, 0x007A],
             [0x00C0, 0x024F], [0x1E00, 0x1EFF]],                                 // Unicode script ranges
  cyrillic: [[0x0400, 0x04FF], [0x0500, 0x052F]],                                 // Unicode Cyrillic + Cyrillic Supplement
  greek:    [[0x0370, 0x03FF], [0x1F00, 0x1FFF]],                                 // Unicode Greek + Greek Extended
  armenian: [[0x0530, 0x058F]],                                                   // Unicode Armenian
  cherokee: [[0x13A0, 0x13FF], [0xAB70, 0xABBF]],                                 // Unicode Cherokee + Cherokee Supplement
  han:      [[0x4E00, 0x9FFF]],                                                   // CJK Unified Ideographs
  hiragana: [[0x3040, 0x309F]],                                                   // Hiragana
  katakana: [[0x30A0, 0x30FF]],                                                   // Katakana
  hangul:   [[0xAC00, 0xD7AF]],                                                   // Hangul Syllables
  arabic:   [[0x0600, 0x06FF]],                                                   // Arabic
  hebrew:   [[0x0590, 0x05FF]],                                                   // Hebrew
};

/**
 * @primitive b.codepointClass.scriptFor
 * @signature b.codepointClass.scriptFor(cp)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.detectMixedScripts
 *
 * Return the Unicode script name for a codepoint (`"latin"`, `"cyrillic"`,
 * `"greek"`, `"han"`, ...), or `null` when the codepoint is script-neutral
 * (digits, punctuation, symbols). The classifier `detectMixedScripts` uses to
 * spot homograph / confusable mixing (UTS&nbsp;#39).
 *
 * @example
 *   b.codepointClass.scriptFor("a".charCodeAt(0));   // returns "latin"
 *   b.codepointClass.scriptFor(0x0430);              // returns "cyrillic" (the confusable a)
 */
function scriptFor(cp) {
  var keys = Object.keys(SCRIPT_RANGES);
  for (var i = 0; i < keys.length; i += 1) {
    var ranges = SCRIPT_RANGES[keys[i]];
    for (var j = 0; j < ranges.length; j += 1) {
      if (cp >= ranges[j][0] && cp <= ranges[j][1]) return keys[i];
    }
  }
  return null;
}

/**
 * @primitive b.codepointClass.detectMixedScripts
 * @signature b.codepointClass.detectMixedScripts(label, allowedScripts)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.scriptFor, b.guardText
 *
 * UTS&nbsp;#39 confusable detection: return `null` when `label` is single-script
 * (or every script it uses is in the optional `allowedScripts` allowlist), or
 * the full array of script names when it mixes scripts — the homograph attack
 * shape (a Cyrillic confusable letter inside an otherwise-Latin label). Callers
 * decide refuse / audit / strip. Pass `allowedScripts` to permit legitimate
 * mixing (an ASCII word inside a non-Latin label).
 *
 * @example
 *   b.codepointClass.detectMixedScripts("paypal");   // null (single-script)
 *   var spoof = "pa" + b.codepointClass.fromCp(0x0443) + "pal";  // Cyrillic u (U+0443)
 *   b.codepointClass.detectMixedScripts(spoof);                       // ["latin", "cyrillic"]
 *   b.codepointClass.detectMixedScripts(spoof, ["latin", "cyrillic"]); // null (allowlisted)
 */
function detectMixedScripts(label, allowedScripts) {
  if (typeof label !== "string" || label.length === 0) return null;
  var seen = {};
  for (var i = 0; i < label.length; i += 1) {
    var script = scriptFor(label.charCodeAt(i));
    if (script === null) continue;
    seen[script] = true;
  }
  var scripts = Object.keys(seen);
  if (scripts.length <= 1) return null;
  if (!allowedScripts) return scripts;
  for (var k = 0; k < scripts.length; k += 1) {
    if (allowedScripts.indexOf(scripts[k]) === -1) return scripts;
  }
  return null;
}

/**
 * @primitive b.codepointClass.detectCharThreats
 * @signature b.codepointClass.detectCharThreats(text, opts, codePrefix, zeroWidthSeverity)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.assertNoCharThreats, b.codepointClass.applyCharStripPolicies, b.guardText
 *
 * Scan `text` for the character-class threats — bidi override, null byte, C0
 * control, and (opt-in) zero-width — and return an array of issue objects
 * `{ kind, severity, ruleId, location, snippet }`, at most one per class. Each
 * class is gated by an opts policy that isn't `"allow"`; `ruleId` is prefixed
 * with `codePrefix`. The non-throwing detection pass the `b.guard*` family
 * shares instead of re-rolling the per-class match-and-push. `zeroWidthSeverity`
 * opts the zero-width scan in and stamps its severity.
 *
 * @opts
 *   bidiPolicy:      string,   // non-"allow" -> flag bidi overrides
 *   nullBytePolicy:  string,   // non-"allow" -> flag null bytes
 *   controlPolicy:   string,   // non-"allow" -> flag C0 controls
 *   zeroWidthPolicy: string,   // non-"allow" (+ zeroWidthSeverity) -> flag zero-width
 *
 * @example
 *   var issues = b.codepointClass.detectCharThreats(
 *     userText, { bidiPolicy: "reject", nullBytePolicy: "reject" }, "comment");
 *   if (issues.length) refuse(issues[0].ruleId);
 */
function detectCharThreats(text, opts, codePrefix, zeroWidthSeverity) {
  var issues = [];
  if (typeof text !== "string") return issues;
  if (opts && opts.bidiPolicy !== "allow") {
    var bidiMatch = text.match(BIDI_RE);
    if (bidiMatch) {
      issues.push({
        kind: "bidi-override", severity: "critical",
        ruleId: codePrefix + ".bidi",
        location: bidiMatch.index,
        snippet: "Unicode bidi override (CVE-2021-42574 Trojan Source)",
      });
    }
  }
  if (opts && opts.nullBytePolicy !== "allow") {
    var nullIdx = text.indexOf(NULL_BYTE);
    if (nullIdx >= 0) {
      issues.push({
        kind: "null-byte", severity: "critical",
        ruleId: codePrefix + ".null-byte",
        location: nullIdx,
        snippet: "null byte at byte " + nullIdx,
      });
    }
  }
  if (opts && opts.controlPolicy !== "allow") {
    var ctrlMatch = text.match(C0_CTRL_RE);
    if (ctrlMatch) {
      issues.push({
        kind: "control-char", severity: "high",
        ruleId: codePrefix + ".control",
        location: ctrlMatch.index,
        snippet: "C0 control char U+" + ctrlMatch[0].charCodeAt(0).toString(HEX_RADIX),
      });
    }
  }
  // Zero-width / invisible-formatting chars — the fourth Trojan-source-class
  // character threat, detected here alongside its siblings so no guard
  // hand-rolls it. OPT-IN AND severity via zeroWidthSeverity: a caller that
  // wants zero-width detection passes the context-appropriate severity
  // ("high" where an invisible char spoofs an identifier / filename / line of
  // text; "warn" where it is cosmetic), and omitting it skips the scan. Gated
  // further on a defined non-`allow` zeroWidthPolicy — flagged under `strip`
  // too (like bidi / null / control) so a zero-width-only input under `strip`
  // reaches the sanitizer and is removed rather than served unchanged.
  if (zeroWidthSeverity && opts && opts.zeroWidthPolicy &&
      opts.zeroWidthPolicy !== "allow") {
    var zwMatch = text.match(ZERO_WIDTH_RE);
    if (zwMatch) {
      issues.push({
        kind: "zero-width", severity: zeroWidthSeverity,
        ruleId: codePrefix + ".zero-width",
        location: zwMatch.index,
        snippet: "zero-width / invisible-formatting char U+" +
                 zwMatch[0].charCodeAt(0).toString(HEX_RADIX) + " at byte " + zwMatch.index,
      });
    }
  }
  return issues;
}

/**
 * @primitive b.codepointClass.assertNoCharThreats
 * @signature b.codepointClass.assertNoCharThreats(text, opts, errorFactory, codePrefix)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.detectCharThreats, b.guardText
 *
 * Throw — via `errorFactory(code, message)` — when `text` contains a character
 * class whose opts policy is `"reject"` (bidi / null byte / C0 control). The
 * throwing counterpart of `detectCharThreats`; `errorFactory` lets the caller
 * raise its own typed error and `codePrefix` namespaces the rule code. The
 * caller bounds the input length before calling (the regexes are unbounded).
 *
 * @opts
 *   bidiPolicy:     string,   // "reject" -> throw on a bidi override
 *   nullBytePolicy: string,   // "reject" -> throw on a null byte
 *   controlPolicy:  string,   // "reject" -> throw on a C0 control
 *
 * @example
 *   b.codepointClass.assertNoCharThreats(value,
 *     { bidiPolicy: "reject", nullBytePolicy: "reject" },
 *     function (code, msg) { return new TypeError(code + ": " + msg); }, "note");
 */
function assertNoCharThreats(text, opts, errorFactory, codePrefix) {
  if (typeof text !== "string") return;
  if (opts && opts.bidiPolicy === "reject" && BIDI_RE.test(text)) {           // allow:regex-no-length-cap — caller bounds length before invoking
    throw errorFactory(codePrefix + ".bidi",
      "input contains Unicode bidi override (CVE-2021-42574)");
  }
  if (opts && opts.nullBytePolicy === "reject" && text.indexOf(NULL_BYTE) !== -1) {
    throw errorFactory(codePrefix + ".null-byte",
      "input contains null byte");
  }
  if (opts && opts.controlPolicy === "reject" && C0_CTRL_RE.test(text)) {     // allow:regex-no-length-cap — caller bounds length before invoking
    throw errorFactory(codePrefix + ".control",
      "input contains C0 control character");
  }
}

/**
 * @primitive b.codepointClass.applyCharStripPolicies
 * @signature b.codepointClass.applyCharStripPolicies(text, opts)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.detectCharThreats, b.guardText
 *
 * Strip each character-class threat whose opts policy is `"strip"` and return
 * the cleaned string — the sanitize counterpart of `detectCharThreats`, shared
 * by every guard's sanitize path so none re-rolls the same sequence of
 * `replace()` calls. Removes bidi overrides, C0 controls, null bytes,
 * zero-width chars, and the Unicode-Tags block ("ASCII smuggling") per policy.
 *
 * @opts
 *   bidiPolicy:      string,   // "strip" -> remove bidi overrides
 *   controlPolicy:   string,   // "strip" -> remove C0 controls
 *   nullBytePolicy:  string,   // "strip" -> remove null bytes
 *   zeroWidthPolicy: string,   // "strip" -> remove zero-width / invisible chars
 *   tagsPolicy:      string,   // "strip" -> remove the Unicode Tags block
 *
 * @example
 *   var clean = b.codepointClass.applyCharStripPolicies(userText,
 *     { bidiPolicy: "strip", zeroWidthPolicy: "strip", tagsPolicy: "strip" });
 */
function applyCharStripPolicies(text, opts) {
  if (typeof text !== "string") return text;
  var out = text;
  if (opts && opts.bidiPolicy === "strip")      out = out.replace(BIDI_RE_G, "");
  if (opts && opts.controlPolicy === "strip")   out = out.replace(C0_CTRL_RE_G, "");
  if (opts && opts.nullBytePolicy === "strip")  out = out.replace(NULL_RE_G, "");
  if (opts && opts.zeroWidthPolicy === "strip") out = out.replace(ZW_RE_G, "");
  if (opts && opts.tagsPolicy === "strip")      out = out.replace(TAG_RE_G, "");
  return out;
}

// REGEXP_META_RE — the full ECMAScript RegExp metacharacter set
// (. * + ? ^ $ { } ( ) | [ ] \).
var REGEXP_META_RE = /[.*+?^${}()|[\]\\]/g;

/**
 * @primitive b.codepointClass.escapeRegExp
 * @signature b.codepointClass.escapeRegExp(s)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.charClass
 *
 * Escape every ECMAScript RegExp metacharacter in a string so an operator- or
 * input-supplied token matches literally when spliced into a `new RegExp(...)`
 * — a token destined for dynamic compilation cannot inject a pattern.
 *
 * @example
 *   var re = new RegExp(b.codepointClass.escapeRegExp("a.b*c"));
 *   re.test("a.b*c");   // true — the . and * are literal
 */
function escapeRegExp(s) {
  return String(s).replace(REGEXP_META_RE, "\\$&");
}

// HEX_PAIR_RE — a percent-escape's two-hex-digit value (RFC 3986 §2.1
// pct-encoded). Percent-decoders test the two characters after a `%`
// against this before parseInt with the hex radix; shared so the literal
// lives once.
var HEX_PAIR_RE = /^[0-9A-Fa-f]{2}$/;

/**
 * @primitive b.codepointClass.isAsciiAlnum
 * @signature b.codepointClass.isAsciiAlnum(cc)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.isUnreserved
 *
 * Test whether a char code is an ASCII letter or digit (`A-Z` / `a-z` / `0-9`)
 * — the alphanumeric range check that recurs across every byte-class parser
 * (URL unreserved, XML name chars, header tokens), centralized so the range
 * literals live once.
 *
 * @example
 *   b.codepointClass.isAsciiAlnum("Z".charCodeAt(0));   // true
 *   b.codepointClass.isAsciiAlnum("-".charCodeAt(0));   // false
 */
function isAsciiAlnum(cc) {
  return (cc >= 0x41 && cc <= 0x5a) ||   // A-Z
         (cc >= 0x61 && cc <= 0x7a) ||   // a-z
         (cc >= 0x30 && cc <= 0x39);     // 0-9
}

/**
 * @primitive b.codepointClass.isUnreserved
 * @signature b.codepointClass.isUnreserved(cc)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.isAsciiAlnum
 *
 * Test whether a char code is in the RFC&nbsp;3986 §2.3 unreserved set —
 * `ALPHA` / `DIGIT` / `-` / `.` / `_` / `~`. A percent-escape of an unreserved
 * character is over-encoding the URI spec says SHOULD be decoded (§6.2.2.3).
 *
 * @example
 *   b.codepointClass.isUnreserved("~".charCodeAt(0));   // true
 *   b.codepointClass.isUnreserved("/".charCodeAt(0));   // false
 */
function isUnreserved(cc) {
  return isAsciiAlnum(cc) ||
         cc === 0x2d ||   // -
         cc === 0x2e ||   // .
         cc === 0x5f ||   // _
         cc === 0x7e;     // ~
}

/**
 * @primitive b.codepointClass.isForbiddenControlChar
 * @signature b.codepointClass.isForbiddenControlChar(code, opts)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.firstControlCharOffset
 *
 * The header-injection / RFC&nbsp;5322 control-byte predicate every "refuse
 * control bytes in a header / line / value" loop shares. Returns `true` for DEL
 * (`0x7f`) and any C0 control (`< 0x20`) other than TAB (`0x09`); LF and CR are
 * refused by default but can be permitted per call (a reader that already split
 * on CRLF, or a folding grammar). Distinct from the `C0_CTRL_RE` scanning table
 * which always exempts LF/CR and never matches DEL.
 *
 * @opts
 *   forbidTab: boolean,   // also forbid TAB -> predicate is `code < 0x20 || code === 0x7f`
 *   allowLf:   boolean,   // permit LF (0x0a)
 *   allowCr:   boolean,   // permit CR (0x0d)
 *
 * @example
 *   b.codepointClass.isForbiddenControlChar(0x00);                 // true (NUL)
 *   b.codepointClass.isForbiddenControlChar(0x09, { forbidTab: true }); // true (TAB forbidden)
 */
function isForbiddenControlChar(code, opts) {
  if (code === 0x7f) return true;          // DEL
  if (code >= 0x20) return false;
  if (code === 0x09 && (!opts || !opts.forbidTab)) return false;  // TAB — permitted unless forbidTab
  if (opts) {
    if (opts.allowLf && code === 0x0a) return false;
    if (opts.allowCr && code === 0x0d) return false;
  }
  return true;
}

/**
 * @primitive b.codepointClass.firstControlCharOffset
 * @signature b.codepointClass.firstControlCharOffset(s, opts)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.isForbiddenControlChar
 *
 * Return the index of the first forbidden control char in `s` (under the same
 * `opts` as `isForbiddenControlChar`), or `-1` when none. Callers wrap it as a
 * boolean (`!== -1`), throw with the offending code (`s.charCodeAt(offset)`),
 * or derive a byte offset — replacing the open-coded control-byte scan each
 * parser previously rolled by hand.
 *
 * @opts
 *   forbidTab: boolean,   // also treat TAB as forbidden
 *   allowLf:   boolean,   // permit LF (0x0a)
 *   allowCr:   boolean,   // permit CR (0x0d)
 *
 * @example
 *   b.codepointClass.firstControlCharOffset("ok\x00bad");   // 2 (the NUL)
 *   b.codepointClass.firstControlCharOffset("clean");          // -1
 */
function firstControlCharOffset(s, opts) {
  for (var i = 0; i < s.length; i += 1) {
    if (isForbiddenControlChar(s.charCodeAt(i), opts)) return i;
  }
  return -1;
}

// Decode HTML numeric character references (hex &#x..; and decimal &#..;) just
// enough to expose a scheme hidden behind entity-encoding. The trailing
// semicolon is OPTIONAL — a browser decodes `&#106avascript:` (no semicolon)
// the same as `&#106;avascript:`, so a semicolon-required decoder lets the
// no-semicolon form bypass a scheme allowlist. Shared so guard-html / guard-svg
// / guard-markdown cannot drift on this (the bug class that shipped one buggy
// + one correct copy).
var NUMERIC_ENTITY_RE_G = /&#(?:x([0-9a-f]+)|(\d+));?/gi;
/**
 * @primitive b.codepointClass.decodeNumericEntities
 * @signature b.codepointClass.decodeNumericEntities(s)
 * @since     0.15.21
 * @status    stable
 * @related   b.codepointClass.detectCharThreats
 *
 * Decode HTML numeric character references (hex `&#x..;` and decimal `&#..;`)
 * just enough to expose a scheme hidden behind entity-encoding. The trailing
 * semicolon is OPTIONAL — a browser decodes `&#106avascript:` (no semicolon)
 * the same as `&#106;avascript:`, so a semicolon-required decoder lets the
 * no-semicolon form slip a scheme past an allowlist. Shared so the markup
 * guards cannot drift on this.
 *
 * @example
 *   b.codepointClass.decodeNumericEntities("&#106;avascript:");   // "javascript:"
 *   b.codepointClass.decodeNumericEntities("&#106avascript:");    // "javascript:" (no semicolon)
 */
function decodeNumericEntities(s) {
  return String(s == null ? "" : s).replace(NUMERIC_ENTITY_RE_G, function (m, hex, dec) {
    var cp = hex !== undefined ? parseInt(hex, 16) : parseInt(dec, 10);
    if (!isFinite(cp) || cp < 0 || cp > 0x10FFFF) return m;
    try { return String.fromCodePoint(cp); } catch (_e) { return m; }
  });
}

module.exports = {
  isForbiddenControlChar:  isForbiddenControlChar,
  firstControlCharOffset:  firstControlCharOffset,
  decodeNumericEntities:   decodeNumericEntities,
  isAsciiAlnum:      isAsciiAlnum,
  isUnreserved:      isUnreserved,
  hex4:              hex4,
  charClass:         charClass,
  fromCp:            fromCp,
  escapeRegExp:      escapeRegExp,
  HEX_PAIR_RE:       HEX_PAIR_RE,
  BIDI_RANGES:       BIDI_RANGES,
  C0_CTRL_RANGES:    C0_CTRL_RANGES,
  ZERO_WIDTH_RANGES: ZERO_WIDTH_RANGES,
  TAG_RANGES:        TAG_RANGES,
  BIDI_RE:           BIDI_RE,
  BIDI_RE_G:         BIDI_RE_G,
  C0_CTRL_RE:        C0_CTRL_RE,
  C0_CTRL_RE_G:      C0_CTRL_RE_G,
  ZERO_WIDTH_RE:     ZERO_WIDTH_RE,
  ZW_RE_G:           ZW_RE_G,
  NULL_RE_G:         NULL_RE_G,
  TAG_RE:            TAG_RE,
  TAG_RE_G:          TAG_RE_G,
  NULL_BYTE:         NULL_BYTE,
  BOM_CHAR:          BOM_CHAR,
  applyCharStripPolicies: applyCharStripPolicies,
  assertNoCharThreats:    assertNoCharThreats,
  detectCharThreats:      detectCharThreats,
  SCRIPT_RANGES:          SCRIPT_RANGES,
  scriptFor:              scriptFor,
  detectMixedScripts:     detectMixedScripts,
};
