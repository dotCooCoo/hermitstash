"use strict";
/**
 * guard-csv — CSV content-safety primitive (b.guardCsv).
 *
 * Wraps lib/csv.js (RFC 4180 parse + stringify) with the broader threat
 * catalog operators face when emitting CSVs from user-supplied data,
 * plus the b.gateContract composition contract for use as a gate inside
 * b.staticServe / b.fileUpload / b.mail / b.objectStore.
 *
 *   var out = b.guardCsv.serialize(rows, { profile: "strict" });
 *   var rv  = b.guardCsv.validate(input, { profile: "strict" });
 *   var s   = b.guardCsv.sanitize(input, { profile: "balanced" });
 *   var g   = b.guardCsv.gate({ profile: "strict" });
 *   b.staticServe.create({ contentSafety: { ".csv": g } });
 *
 * Threat-detection regex literals are composed PROGRAMMATICALLY from
 * numeric codepoint ranges (BIDI_RANGES / C0_CTRL_RANGES / etc.) so the
 * source file never embeds the attack characters themselves — only their
 * codepoint numbers. This mirrors the way an attacker would compose the
 * payload (programmatic codepoint emission, not literal typing) and
 * keeps the source ASCII-clean (zero irregular-whitespace lint findings,
 * no eslint-disable comments, machine-greppable as data tables).
 *
 * Threat catalog covered:
 *
 *   - Formula injection (5 modes: prefix-tab / prefix-quote /
 *     wrap-with-quotes-and-prefix / reject / allowlist) with all 8
 *     ASCII triggers (= + - @ TAB CR LF |) plus full-width variants
 *     (U+FF1D / U+FF0B / U+FF0D / U+FF20) per OWASP locale catalog.
 *   - Dangerous-function denylist — WEBSERVICE / HYPERLINK / IMAGE /
 *     IMPORT* / RTD / DDE / CALL / GOOGLEFINANCE / GOOGLETRANSLATE.
 *   - Unicode bidi override (CVE-2021-42574 Trojan Source).
 *   - Homoglyph detection (Cyrillic / Greek / fullwidth Latin) when
 *     mixed with ASCII letters in the same cell.
 *   - C0 control chars (minus tab / lf / cr — those are dialect chars
 *     the parser handles separately).
 *   - Null byte detection (single canonical handling — strip / reject).
 *   - BOM injection mid-stream (any BOM past byte 0).
 *   - Zero-width chars (ZWSP / ZWNJ / ZWJ / WJ / SHY).
 *   - Dialect ambiguity (mixed line endings) — strict refuses.
 *   - CSV-bomb caps: per-cell, total, sanitize amplification ratio.
 *   - Numeric precision loss (above Number.MAX_SAFE_INTEGER → decimal
 *     string per policy).
 *   - Trailing whitespace exfiltration policy (trim / preserve / reject).
 *   - PII redaction via composes b.redact when piiPolicy === "redact".
 *   - Schema-bound serializer with type / regex / range / nullable
 *     validation.
 *   - Profiles: strict (OWASP-aligned, prefix-tab default per OWASP) /
 *     balanced / permissive / email-attachment.
 *   - Compliance postures: hipaa / pci-dss / gdpr / soc2.
 *   - Operator extensibility: profile composition, custom rules, hooks
 *     (beforeCheck / afterCheck / onIssue / onSanitize / onRefuse /
 *     onAudit), threat-intel feeds, sandbox isolation, snapshot tests.
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
    var formulaMatch = _firstMatch(text, FORMULA_SCAN_RE);
    if (formulaMatch) {
      issues.push({
        kind: "formula-prefix-cell", severity: "critical",
        ruleId: "csv.formula-injection",
        location: formulaMatch.index,
        snippet: "cell beginning with formula trigger " +
                 JSON.stringify(formulaMatch.char.slice(-1)) +
                 " at byte " + formulaMatch.index,
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

function validate(input, opts) {
  opts = _resolveOpts(opts);
  return gateContract.runIssueValidator(input, opts, _detectIssues);
}

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

var buildProfile = gateContract.makeProfileBuilder(PROFILES);

function compliancePosture(name) {
  return gateContract.lookupCompliancePosture(name, COMPLIANCE_POSTURES, _err, "csv");
}

var _csvRulePacks = gateContract.makeRulePackLoader(GuardCsvError, "csv");
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
