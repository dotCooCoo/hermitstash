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
 *   like SUM / AVERAGE pass through unprefixed).
 *
 *   Unicode bidi/zero-width strip: CVE-2021-42574 Trojan Source bidi
 *   overrides (U+202A-202E, U+2066-2069) are rejected or stripped
 *   per profile; zero-width characters (ZWSP / ZWNJ / ZWJ / WJ / SHY)
 *   always strip. Leading bidi/zero-width prefixes are stripped before
 *   the formula scan so a cell beginning with U+200B`=SUM(...)` cannot
 *   slip past the start-anchor check.
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

var HEX_RADIX = 16;                                                 // allow:raw-byte-literal — base-16 radix, not byte size
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
var ZERO_WIDTH_RE = codepointClass.ZERO_WIDTH_RE;
var ZW_RE_G       = codepointClass.ZW_RE_G;
var NULL_RE_G     = codepointClass.NULL_RE_G;
var HOMOGLYPH_RE  = new RegExp("[" + _charClass(HOMOGLYPH_RANGES) + "]");      // allow:dynamic-regex — codepoints from HOMOGLYPH_RANGES literal table
var HOMOGLYPH_G   = new RegExp("[" + _charClass(HOMOGLYPH_RANGES) + "]", "g"); // allow:dynamic-regex — codepoints from HOMOGLYPH_RANGES literal table
var BOM_RE_LEAD   = new RegExp("^" + _hex4(0xFEFF));                           // allow:dynamic-regex — single literal codepoint U+FEFF
var BOM_RE_G      = new RegExp(_hex4(0xFEFF), "g");                            // allow:dynamic-regex — single literal codepoint U+FEFF

// Formula-trigger character class assembled from FORMULA_PREFIX_CPS:
//   [=+\-@\t\r\u3D...] — used inside the "<line-start or delimiter>"
//   formula-prefix scan and the dangerous-function scan.
var FORMULA_TRIGGER_CLASS = (function () {
  var parts = FORMULA_PREFIX_CPS.map(function (cp) {
    if (cp === 0x2D) return "\\-";    // hyphen literal inside char class
    if (cp === 0x5C) return "\\\\";   // backslash safety
    return _hex4(cp);
  });
  return "[" + parts.join("") + "]";
})();

// allow:dynamic-regex — class composed from FORMULA_PREFIX_CPS literal table
var FORMULA_SCAN_RE = new RegExp(
  "(^|[,;\\t|])\"?(" + FORMULA_TRIGGER_CLASS + ")"
);
// allow:dynamic-regex — class composed from FORMULA_PREFIX_CPS literal table
var DANGER_SCAN_RE = new RegExp(
  "(^|[,;\\t|])\"?" + FORMULA_TRIGGER_CLASS + "([A-Z][A-Z0-9_.]*)\\b",
  "g"
);
// allow:dynamic-regex — class composed from FORMULA_PREFIX_CPS literal table
var ALLOWLIST_FIRST_WORD_RE = new RegExp(
  "^" + FORMULA_TRIGGER_CLASS + "([A-Z]+)\\b"
);

var NULL_BYTE = codepointClass.NULL_BYTE;
var BOM_CHAR  = codepointClass.BOM_CHAR;

// FORMULA_PREFIXES — array of single-char strings; iteration cost is
// the same as a Set for n=12. _stringFromCps keeps the source ASCII.
var FORMULA_PREFIXES = Object.freeze(_stringFromCps(FORMULA_PREFIX_CPS).split(""));

// Default row count cap for serialize. 2^20 ~ 1M rows.
var DEFAULT_MAX_ROWS = 0x100000;

// Forensic-snippet sizes per compliance posture.
var FORENSIC_SNIPPET_HIPAA   = C.BYTES.bytes(256);
var FORENSIC_SNIPPET_PCI_DSS = C.BYTES.bytes(256);
var FORENSIC_SNIPPET_GDPR    = C.BYTES.bytes(128);
var FORENSIC_SNIPPET_SOC2    = C.BYTES.bytes(512);

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

var DEFAULTS = Object.freeze({
  delimiter:                 ",",
  lineEnding:                "\r\n",
  encoding:                  "utf-8",
  locale:                    "C",
  formulaInjectionPolicy:    "prefix-tab",
  formulasAllowlist:         Object.freeze(["SUM", "AVERAGE", "COUNT", "MIN", "MAX", "IF", "CONCATENATE"]),
  dangerousFunctions:        DANGEROUS_FUNCTIONS,
  bomPrefix:                 false,
  maxRows:                   DEFAULT_MAX_ROWS,
  maxCellBytes:              C.BYTES.kib(64),
  maxTotalBytes:             C.BYTES.gib(1),
  maxColumns:                0x400,
  sanitizeAmplificationCap:  1.5,
  controlCharPolicy:         "reject",
  bidiCharPolicy:            "reject",
  homoglyphPolicy:           "audit",
  nullByteHandling:          "reject",
  trailingWhitespacePolicy:  "trim",
  dialectPolicy:             "strict",
  nullSemantics:             "empty-string",
  nullMarker:                "\\N",
  preserveLeadingZeros:      false,
  preserveBooleanStrings:    false,
  preserveDateStrings:       false,
  dateFormat:                "iso8601",
  numericPrecisionPolicy:    "decimal-string-above-safe-int",
  piiPolicy:                 "preserve",
  forensicSnippetBytes:      0,
  mode:                      "enforce",
  maxRuntimeMs:              C.TIME.seconds(30),
});

var COMPLIANCE_POSTURES = Object.freeze({
  "hipaa": {
    formulaInjectionPolicy: "prefix-tab",
    bidiCharPolicy:         "reject",
    controlCharPolicy:      "reject",
    nullByteHandling:       "reject",
    piiPolicy:              "redact",
    forensicSnippetBytes:   FORENSIC_SNIPPET_HIPAA,
  },
  "pci-dss": {
    formulaInjectionPolicy: "prefix-tab",
    bidiCharPolicy:         "reject",
    controlCharPolicy:      "reject",
    nullByteHandling:       "reject",
    piiPolicy:              "redact",
    forensicSnippetBytes:   FORENSIC_SNIPPET_PCI_DSS,
  },
  "gdpr": {
    formulaInjectionPolicy: "prefix-tab",
    bidiCharPolicy:         "strip",
    controlCharPolicy:      "strip",
    piiPolicy:              "redact",
    forensicSnippetBytes:   FORENSIC_SNIPPET_GDPR,
  },
  "soc2": {
    formulaInjectionPolicy: "prefix-tab",
    bidiCharPolicy:         "reject",
    controlCharPolicy:      "reject",
    nullByteHandling:       "reject",
    forensicSnippetBytes:   FORENSIC_SNIPPET_SOC2,
  },
});

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

  if (opts.bidiCharPolicy !== "allow") {
    var bidiMatch = _firstMatch(text, BIDI_RE);
    if (bidiMatch) {
      issues.push({
        kind: "bidi-override", severity: "critical", ruleId: "csv.bidi",
        location: bidiMatch.index,
        snippet: "Unicode bidi override at byte " + bidiMatch.index +
                 " (CVE-2021-42574 Trojan Source)",
      });
    }
  }

  if (opts.controlCharPolicy !== "allow") {
    var ctrlMatch = _firstMatch(text, C0_CTRL_RE);
    if (ctrlMatch) {
      issues.push({
        kind: "control-char", severity: "high", ruleId: "csv.control",
        location: ctrlMatch.index,
        snippet: "C0 control char U+" + ctrlMatch.char.charCodeAt(0).toString(HEX_RADIX) +
                 " at byte " + ctrlMatch.index,
      });
    }
  }

  var nullIdx = text.indexOf(NULL_BYTE);
  if (nullIdx >= 0 && opts.nullByteHandling !== "allow") {
    issues.push({
      kind: "null-byte", severity: "critical", ruleId: "csv.null-byte",
      location: nullIdx, snippet: "null byte at " + nullIdx,
    });
  }

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

  var zwMatch = _firstMatch(text, ZERO_WIDTH_RE);
  if (zwMatch) {
    issues.push({
      kind: "zero-width", severity: "warn", ruleId: "csv.zero-width",
      location: zwMatch.index,
      snippet: "zero-width char U+" + zwMatch.char.charCodeAt(0).toString(HEX_RADIX) +
               " at byte " + zwMatch.index,
    });
  }

  if (opts.formulaInjectionPolicy !== "audit-only" && opts.formulaInjectionPolicy !== "allow") {
    // Strip ZWSP / RTLO / LRM / RLM / BOM at cell-start before the
    // formula scan. Without this, a cell beginning with U+200B (zero-
    // width space), U+202E (RTLO), U+200E/F (LTR/RTL marks), or U+FEFF
    // (BOM) followed by `=` slips past the start-anchor check (the `^`
    // sits before the codepoint, not after) and the formula reaches
    // the spreadsheet evaluator. Browsers + Excel + Sheets all strip
    // these silently — operator users see "=SUM(...)" rendered, the
    // file shipped a hidden bidi prefix that bypassed the scanner.
    // U+200B-200F (ZWSP / ZWNJ / ZWJ / LRM / RLM) +
    // U+202A-202E (LRE / RLE / PDF / LRO / RLO) +
    // U+2066-2069 (LRI / RLI / FSI / PDI) +
    // U+FEFF (BOM)                                                     // allow:dynamic-regex — explicit codepoints, no operator input
    var stripped = text.replace(new RegExp("^[\\u200B-\\u200F\\u202A-\\u202E\\u2066-\\u2069\\uFEFF]+"), "");
    var formulaMatch = _firstMatch(stripped, FORMULA_SCAN_RE);
    if (formulaMatch) {
      issues.push({
        kind: "formula-prefix-cell", severity: "critical",
        ruleId: "csv.formula-injection",
        location: formulaMatch.index,
        snippet: "cell beginning with formula trigger " +
                 JSON.stringify(formulaMatch.char.slice(-1)) +
                 " at byte " + formulaMatch.index +
                 (stripped.length !== text.length ? " (after stripping leading bidi/zero-width prefix)" : ""),
      });
    }
  }

  if (Array.isArray(opts.dangerousFunctions) && opts.dangerousFunctions.length > 0) {
    var dangerIter = text.matchAll(DANGER_SCAN_RE);
    var dangerMatch;
    for (dangerMatch of dangerIter) {
      var fn = dangerMatch[2].toUpperCase();
      if (opts.dangerousFunctions.indexOf(fn) !== -1) {
        issues.push({
          kind: "dangerous-function", severity: "critical",
          ruleId: "csv.dangerous-function",
          location: dangerMatch.index,
          snippet: "spreadsheet function " + JSON.stringify(fn) +
                   " is on the dangerous-function denylist (exfiltration / RCE vector)",
        });
      }
    }
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

function _stripIssues(text, opts) {
  if (typeof text !== "string") return text;
  var out = text;
  if (opts.bomPrefix !== true) out = out.replace(BOM_RE_LEAD, "");
  out = out.replace(BOM_RE_G, "");
  if (opts.bidiCharPolicy === "strip") out = out.replace(BIDI_RE_G, "");
  if (opts.controlCharPolicy === "strip") out = out.replace(C0_CTRL_RE_G, "");
  if (opts.nullByteHandling === "strip") out = out.replace(NULL_RE_G, "");
  if (opts.homoglyphPolicy === "strip") out = out.replace(HOMOGLYPH_G, "");
  out = out.replace(ZW_RE_G, "");
  if (opts.trailingWhitespacePolicy === "trim") {
    out = out.split("\n").map(function (line) {
      return line.replace(/[ \t]+$/g, "");
    }).join("\n");
  }
  return out;
}

function _resolveOpts(opts) {
  return gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardCsvError,
    errCodePrefix:      "csv",
  });
}

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
  opts = Object.assign({}, DEFAULTS, opts || {});
  var str = value == null ? "" : String(value);

  if (str.length > opts.maxCellBytes) {
    throw _err("csv.cell-too-large", "cell exceeds maxCellBytes " + opts.maxCellBytes);
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
    str = str.replace(/[ \t]+$/g, "");
  } else if (opts.trailingWhitespacePolicy === "reject" && /[ \t]+$/.test(str)) {
    throw _err("csv.trailing-whitespace", "cell has trailing whitespace");
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
      str = "\t" + str;
    } else if (policy === "prefix-quote") {
      str = "'" + str;
    } else if (policy === "wrap-with-quotes-and-prefix") {
      str = "'" + str;
    } else if (policy === "allowlist") {
      var firstWord = str.match(ALLOWLIST_FIRST_WORD_RE);
      if (firstWord && opts.formulasAllowlist.indexOf(firstWord[1]) === -1) {
        str = "'" + str;
      }
    }
  }

  return str;
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
      return validate(input, Object.assign({ schema: spec }, opts || {}));
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
 *   // Formula trigger disarmed with a leading TAB per OWASP guidance:
 *   out.indexOf("\t=WEBSERVICE") !== -1;               // → true
 *   out.indexOf("\r\n") !== -1;                        // → true
 */
function serialize(rows, opts) {
  opts = _resolveOpts(opts);
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

  var escapedRows = [];
  for (var ri = 0; ri < rows.length; ri += 1) {
    var row = rows[ri];
    var escapedRow;
    if (Array.isArray(row)) {
      escapedRow = row.map(function (v) {
        var ev = escapeCell(v, opts);
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
        var ev2 = escapeCell(row[keys[ki]], opts);
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

  var out = csv.stringify(escapedRows, {
    delimiter:    opts.delimiter,
    quote:        opts.quote || "\"",
    eol:          opts.lineEnding,
    alwaysQuote:  opts.alwaysQuote || false,
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
function validate(input, opts) {
  opts = _resolveOpts(opts);
  return gateContract.runIssueValidator(input, opts, _detectIssues);
}

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
 * `nullByteHandling: "strip"`), zero-width chars (always), and
 * trailing whitespace per `trailingWhitespacePolicy`. Refuses
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
function sanitize(input, opts) {
  opts = _resolveOpts(opts);
  var text = typeof input === "string"
    ? input
    : (Buffer.isBuffer(input) ? input.toString("utf8") : null);
  if (text == null) {
    throw _err("csv.bad-input", "sanitize requires string or Buffer input");
  }
  var sanitized = _stripIssues(text, opts);
  var amplification = sanitized.length / Math.max(text.length, 1);
  if (amplification > opts.sanitizeAmplificationCap) {
    throw _err("csv.sanitize-amplified",
      "sanitize grew output " + amplification.toFixed(2) +
      "x; cap " + opts.sanitizeAmplificationCap);
  }
  return sanitized;
}

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
 * `b.mail`, or `b.objectStore`. Action chain on validation:
 * `serve` (no issues) → `audit-only` (warn-only issues) →
 * `sanitize` (critical/high but no `reject` policy active —
 * sanitize, re-parse, re-serialize so formula mitigation lands)
 * → `refuse` (critical/high under any `reject` policy, or when
 * sanitize fails / amplifies past cap).
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
 *   // Direct invocation for an upload pipeline:
 *   var hostile = Buffer.from("name,formula\r\nalice,=cmd|x\r\n", "utf8");
 *   var verdict = await csvGate.check({ bytes: hostile });
 *   verdict.action;                                    // → "refuse"
 */
function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardCsv:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var text = gateContract.extractBytesAsText(ctx);
      if (!text) return { ok: true, action: "serve" };
      var rv = validate(text, opts);

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
          } catch (_e) { /* operator rule best-effort */ }
        }
      }
      var allIssues = rv.issues.concat(operatorIssues);

      if (allIssues.length === 0) return { ok: true, action: "serve" };
      var hasCritical = allIssues.some(function (i) {
        return i.severity === "critical" || i.severity === "high";
      });
      if (!hasCritical) {
        return { ok: true, action: "audit-only", issues: allIssues };
      }

      if (opts.formulaInjectionPolicy !== "reject" &&
          opts.bidiCharPolicy !== "reject" &&
          opts.controlCharPolicy !== "reject" &&
          opts.nullByteHandling !== "reject") {
        try {
          var clean = sanitize(text, opts);
          var hasFormulaIssue = allIssues.some(function (i) {
            return i.kind === "formula-prefix-cell" ||
                   i.kind === "dangerous-function";
          });
          if (hasFormulaIssue) {
            var parsedRows = csv.parse(clean, { header: false });
            clean = serialize(parsedRows, Object.assign({}, opts, { headers: false }));
          }
          return {
            ok: true, action: "sanitize",
            sanitized: Buffer.from(clean, "utf8"),
            issues: allIssues,
          };
        } catch (_e) { /* fall through to refuse */ }
      }

      return { ok: false, action: "refuse", issues: allIssues };
    });
}

/**
 * @primitive  b.guardCsv.buildProfile
 * @signature  b.guardCsv.buildProfile(opts)
 * @since      0.7.5
 * @status     stable
 * @related    b.guardCsv.gate, b.guardCsv.compliancePosture
 *
 * Compose a derived profile from one or more named bases plus
 * inline overrides. `opts.extends` is a profile name (`"strict"`
 * / `"balanced"` / `"permissive"` / `"email-attachment"`) or an
 * array of names; later entries shadow earlier ones. Inline
 * `opts` keys win last. Used to keep operator-defined profiles
 * traceable to a baseline rather than re-typing every key.
 *
 * @opts
 *   extends: string|string[],   // base profile name(s) to compose
 *   ...:     any guard-csv key, // inline override of resolved keys
 *
 * @example
 *   var custom = b.guardCsv.buildProfile({
 *     extends: "strict",
 *     trailingWhitespacePolicy: "preserve",
 *     bomPrefix: true,
 *   });
 *   custom.formulaInjectionPolicy;                     // → "prefix-tab"
 *   custom.bomPrefix;                                  // → true
 */
var buildProfile = gateContract.makeProfileBuilder(PROFILES);

/**
 * @primitive  b.guardCsv.compliancePosture
 * @signature  b.guardCsv.compliancePosture(name)
 * @since      0.7.5
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardCsv.gate, b.guardCsv.buildProfile
 *
 * Look up a compliance-posture overlay by name (`"hipaa"` /
 * `"pci-dss"` / `"gdpr"` / `"soc2"`). Returns a shallow clone of
 * the posture object — the caller may mutate freely. Throws
 * `GuardCsvError("csv.bad-posture")` on unknown name.
 *
 * @example
 *   var posture = b.guardCsv.compliancePosture("hipaa");
 *   posture.piiPolicy;                                 // → "redact"
 *   posture.bidiCharPolicy;                            // → "reject"
 */
function compliancePosture(name) {
  return gateContract.lookupCompliancePosture(name, COMPLIANCE_POSTURES, _err, "csv");
}

var _csvRulePacks = gateContract.makeRulePackLoader(GuardCsvError, "csv");
/**
 * @primitive  b.guardCsv.loadRulePack
 * @signature  b.guardCsv.loadRulePack(pack)
 * @since      0.7.5
 * @status     stable
 * @related    b.guardCsv.gate
 *
 * Register an operator-supplied rule pack with the guard-csv
 * registry. The pack is identified by `pack.id` (non-empty
 * string) and stored for later inspection / dispatch by gates
 * that opt in via `opts.rulePackId`. Returns the pack object
 * unchanged on success; throws `GuardCsvError("csv.bad-opt")`
 * when `pack` is missing or `pack.id` is not a non-empty string.
 *
 * @example
 *   var pack = b.guardCsv.loadRulePack({
 *     id: "pii-extra",
 *     rules: [
 *       { id: "ssn-cell", severity: "critical",
 *         detect: function (cell) { return /^\d{3}-\d{2}-\d{4}$/.test(cell); },
 *         reason: "US SSN-shaped value in CSV cell" },
 *     ],
 *   });
 *   pack.id;                                           // → "pii-extra"
 */
var loadRulePack = _csvRulePacks.load;

module.exports = {
  // ---- guard-* family registry exports (consumed by b.guardAll) ----
  NAME:                "csv",
  KIND:                "content",                                                 // content-bytes guard (consumes ctx.bytes)
  MIME_TYPES:          Object.freeze(["text/csv"]),
  EXTENSIONS:          Object.freeze([".csv"]),
  // ---- adaptive integration-test fixtures (consumed by layer-5 host harness) ----
  INTEGRATION_FIXTURES: Object.freeze({
    kind:        "content",
    contentType: "text/csv",
    extension:   ".csv",
    benignBytes: Buffer.from("name,age\r\nalice,30\r\n", "utf8"),
    // Hostile: cell starts with formula trigger `=cmd|x` — strict
    // profile prepends TAB so spreadsheets disarm at evaluation time;
    // gate's check returns refuse for any critical/high issue.
    hostileBytes: Buffer.from("name,formula\r\nalice,=cmd|x\r\n", "utf8"),
  }),
  // ---- primitive surface ----
  serialize:           serialize,
  validate:            validate,
  sanitize:            sanitize,
  escapeCell:          escapeCell,
  detect:              detect,
  schema:              schema,
  gate:                gate,
  buildProfile:        buildProfile,
  compliancePosture:   compliancePosture,
  loadRulePack:        loadRulePack,
  PROFILES:            PROFILES,
  DEFAULTS:            DEFAULTS,
  COMPLIANCE_POSTURES: COMPLIANCE_POSTURES,
  FORMULA_PREFIXES:    FORMULA_PREFIXES,
  DANGEROUS_FUNCTIONS: DANGEROUS_FUNCTIONS,
  GuardCsvError:       GuardCsvError,
};
