// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.csv
 * @featured true
 * @nav    Tools
 * @title  CSV
 *
 * @intro
 *   RFC 4180 parser + serializer with operator-friendly defaults.
 *
 *   `b.csv.parse` accepts a string, Buffer, or Uint8Array and returns
 *   either an array of row objects (header mode, default) or an array
 *   of arrays (when `header: false`). Strips a leading UTF-8 BOM,
 *   handles CRLF / LF / CR line endings, and supports doubled-quote
 *   escapes inside quoted fields.
 *
 *   `b.csv.stringify` accepts an array of objects or arrays and emits
 *   RFC 4180 output. Cells are quoted only when they contain the
 *   delimiter, the quote char, CR, or LF — unless `alwaysQuote: true`
 *   forces full quoting.
 *
 *   Anti-DoS bounds are on by default: `maxBytes` (16 MiB),
 *   `maxRows` (1,000,000), and `maxFieldBytes` (1 MiB). Each cap is
 *   validated as a positive finite integer at call time — passing
 *   `Infinity` throws, never a silent bypass.
 *
 *   SCOPE: this module is for trusted-source-only emission. It performs
 *   RFC 4180 quote/delimiter escaping but does NOT defend against the
 *   broader CSV-injection threat catalog (Excel/Sheets formula
 *   triggers, Unicode bidi overrides, dangerous-function denylist,
 *   homoglyphs, control-byte injection, BOM mid-stream, dialect
 *   ambiguity, CSV-bombs). Any path that emits or accepts user-supplied
 *   cells MUST route through `b.guardCsv` — its serialize / validate /
 *   sanitize / gate surface handles every documented threat with a
 *   single profile choice (strict / balanced / permissive /
 *   email-attachment) or compliance posture (hipaa / pci-dss / gdpr /
 *   soc2).
 *
 *   Throws `CsvError` (FrameworkError, permanent) on shape violations.
 *
 * @card
 *   RFC 4180 parser + serializer with operator-friendly defaults.
 */
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var pick = require("./pick");
var { defineClass } = require("./framework-error");

/**
 * @primitive b.csv.CsvError
 * @signature b.csv.CsvError
 * @since     0.4.0
 * @related   b.csv.parse, b.csv.stringify
 *
 * FrameworkError subclass thrown by `b.csv.parse` and
 * `b.csv.stringify` on shape violations: bad delimiter / quote,
 * unterminated quoted field, oversized input, oversized field,
 * row-length mismatch, or unsupported `eol` / `onBadRow` value.
 * `alwaysPermanent` — never retried by `b.retry`. Operators catch
 * it to distinguish CSV-shape problems from upstream IO errors.
 *
 * @example
 *   try {
 *     b.csv.parse('name,age\n"unterminated', { header: true });
 *   } catch (e) {
 *     e instanceof b.csv.CsvError;   // → true
 *     e.code;                        // → "csv/unterminated-quote"
 *   }
 */
var CsvError = defineClass("CsvError", { alwaysPermanent: true });

/**
 * @primitive b.csv.DEFAULTS_PARSE
 * @signature b.csv.DEFAULTS_PARSE
 * @since     0.4.0
 * @related   b.csv.parse, b.csv.DEFAULTS_STRINGIFY
 *
 * Frozen-by-convention defaults applied to `b.csv.parse(input, opts)`
 * before the call's own `opts` overlay. Exposed so operators can
 * introspect the active limits (`maxBytes`, `maxRows`,
 * `maxFieldBytes`) without re-deriving them from documentation.
 *
 * @example
 *   b.csv.DEFAULTS_PARSE.maxBytes;       // → 16777216  (16 MiB)
 *   b.csv.DEFAULTS_PARSE.maxRows;        // → 1000000
 *   b.csv.DEFAULTS_PARSE.maxFieldBytes;  // → 1048576   (1 MiB)
 *   b.csv.DEFAULTS_PARSE.delimiter;      // → ","
 */
var DEFAULTS_PARSE = {
  header:        true,
  delimiter:     ",",
  quote:         "\"",
  trim:          false,
  maxBytes:      C.BYTES.mib(16),
  maxRows:       1_000_000,
  maxFieldBytes: C.BYTES.mib(1),
  onBadRow:      "throw",
};

/**
 * @primitive b.csv.DEFAULTS_STRINGIFY
 * @signature b.csv.DEFAULTS_STRINGIFY
 * @since     0.4.0
 * @related   b.csv.stringify, b.csv.DEFAULTS_PARSE
 *
 * Frozen-by-convention defaults applied to `b.csv.stringify(rows, opts)`
 * before the call's own `opts` overlay. Exposed so operators can
 * introspect the active emission policy (`eol`, `delimiter`,
 * `alwaysQuote`) without re-deriving it from documentation.
 *
 * @example
 *   b.csv.DEFAULTS_STRINGIFY.header;       // → true
 *   b.csv.DEFAULTS_STRINGIFY.delimiter;    // → ","
 *   b.csv.DEFAULTS_STRINGIFY.eol;          // → "\r\n"
 *   b.csv.DEFAULTS_STRINGIFY.alwaysQuote;  // → false
 */
var DEFAULTS_STRINGIFY = {
  header:       true,
  delimiter:    ",",
  quote:        "\"",
  eol:          "\r\n",
  alwaysQuote:  false,
  columns:      null,
};

function _validateDelim(name, value) {
  if (typeof value !== "string" || value.length !== 1) {
    throw new CsvError("csv/bad-delimiter",
      name + " must be a single character, got " + JSON.stringify(value));
  }
  if (value === "\r" || value === "\n") {
    throw new CsvError("csv/bad-delimiter",
      name + " cannot be CR or LF");
  }
}

// ---- parse ----

/**
 * @primitive b.csv.parse
 * @signature b.csv.parse(input, opts?)
 * @since     0.4.0
 * @related   b.csv.stringify, b.csv.DEFAULTS_PARSE
 *
 * Parse RFC 4180 CSV text into rows. By default the first row is
 * treated as a header and each subsequent row is returned as an
 * object keyed by header name; pass `header: false` to receive
 * an array of arrays instead. Accepts a string, Buffer, or
 * Uint8Array; a leading UTF-8 BOM is stripped. CR, LF, and CRLF
 * are all accepted as row terminators. Doubled-quote sequences
 * inside a quoted field decode to a literal quote character.
 *
 * Anti-DoS caps (`maxBytes`, `maxRows`, `maxFieldBytes`) are
 * enforced as positive finite integers. Passing `Infinity` or
 * `NaN` throws `CsvError` rather than silently disabling the cap.
 *
 * @opts
 *   header:        boolean,  // first row is column names (default true)
 *   delimiter:     string,   // single byte, default ","
 *   quote:         string,   // single byte, default '"'
 *   trim:          boolean,  // strip leading/trailing whitespace per cell
 *   maxBytes:      number,   // input cap, default 16 MiB
 *   maxRows:       number,   // row-count cap, default 1,000,000
 *   maxFieldBytes: number,   // per-cell cap, default 1 MiB
 *   onBadRow:      string,   // "throw" (default) or "skip"
 *
 * @example
 *   var rows = b.csv.parse("name,age\nalice,30\nbob,25");
 *   // → [ { name: "alice", age: "30" }, { name: "bob", age: "25" } ]
 *
 *   var arrays = b.csv.parse("a,b\n1,2", { header: false });
 *   // → [ [ "a", "b" ], [ "1", "2" ] ]
 *
 *   // Doubled-quote escape inside a quoted field decodes to one quote.
 *   var quoted = b.csv.parse('msg\n"she said ""hi"""', { header: true });
 *   // → [ { msg: 'she said "hi"' } ]
 *
 *   // Tab-separated values via the delimiter opt.
 *   var tsv = b.csv.parse("a\tb\n1\t2", { delimiter: "\t" });
 *   // → [ { a: "1", b: "2" } ]
 */
function parse(input, opts) {
  opts = Object.assign({}, DEFAULTS_PARSE, opts || {});
  // maxBytes / maxRows / maxFieldBytes via shared lib/numeric-bounds —
  // Infinity / NaN bypass the corresponding caps and let a hostile
  // multi-megabyte CSV (or a single hostile row / single hostile field)
  // through unbounded.
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes", "maxRows", "maxFieldBytes"],
    "csv.parse", CsvError, "csv/bad-opt");

  var s;
  if (typeof input === "string") s = input;
  else if (Buffer.isBuffer(input)) s = input.toString("utf8");
  else if (input instanceof Uint8Array) s = Buffer.from(input).toString("utf8");
  else {
    throw new CsvError("csv/bad-input",
      "parse: input must be string, Buffer, or Uint8Array, got " + typeof input);
  }
  if (s.charCodeAt(0) === 0xFEFF) s = s.slice(1);
  if (Buffer.byteLength(s, "utf8") > opts.maxBytes) {
    throw new CsvError("csv/too-large",
      "parse: input exceeds maxBytes (" + opts.maxBytes + ")");
  }

  _validateDelim("delimiter", opts.delimiter);
  _validateDelim("quote",     opts.quote);
  if (opts.delimiter === opts.quote) {
    throw new CsvError("csv/bad-delimiter",
      "delimiter and quote must differ");
  }
  if (opts.onBadRow !== "throw" && opts.onBadRow !== "skip") {
    throw new CsvError("csv/bad-opt",
      "onBadRow must be 'throw' or 'skip'");
  }

  var len = s.length;
  var pos = 0;
  var rows = [];
  var row = [];
  var field = "";
  var inQuote = false;

  function pushField() {
    if (Buffer.byteLength(field, "utf8") > opts.maxFieldBytes) {
      throw new CsvError("csv/field-too-large",
        "field exceeds maxFieldBytes at row " + (rows.length + 1));
    }
    row.push(opts.trim ? field.trim() : field);
    field = "";
  }
  function pushRow() {
    pushField();
    rows.push(row);
    if (rows.length > opts.maxRows) {
      throw new CsvError("csv/too-many-rows",
        "row count exceeds maxRows (" + opts.maxRows + ")");
    }
    row = [];
  }

  while (pos < len) {
    var ch = s.charAt(pos);
    if (inQuote) {
      if (ch === opts.quote) {
        if (pos + 1 < len && s.charAt(pos + 1) === opts.quote) {
          field += opts.quote;
          pos += 2;
          continue;
        }
        inQuote = false;
        pos += 1;
        continue;
      }
      field += ch;
      pos += 1;
    } else {
      if (ch === opts.delimiter) {
        pushField();
        pos += 1;
      } else if (ch === "\r") {
        pushRow();
        pos += 1;
        if (pos < len && s.charAt(pos) === "\n") pos += 1;
      } else if (ch === "\n") {
        pushRow();
        pos += 1;
      } else if (ch === opts.quote && field === "") {
        inQuote = true;
        pos += 1;
      } else {
        field += ch;
        pos += 1;
      }
    }
  }
  if (inQuote) {
    throw new CsvError("csv/unterminated-quote",
      "unterminated quoted field");
  }
  if (field.length > 0 || row.length > 0) pushRow();

  if (!opts.header) return rows;
  if (rows.length === 0) return [];

  var header = rows[0];
  var out = [];
  for (var r = 1; r < rows.length; r++) {
    var rec = rows[r];
    if (rec.length !== header.length) {
      if (opts.onBadRow === "skip") continue;
      throw new CsvError("csv/row-length-mismatch",
        "row " + r + " has " + rec.length + " fields, header has " + header.length);
    }
    var obj = {};
    for (var i = 0; i < header.length; i++) {
      // A header column named __proto__ / constructor / prototype would be
      // written straight onto the row object, shadowing (constructor) or
      // dropping/re-parenting (__proto__) the inherited slot — an attacker
      // then controls a downstream `row.constructor` / type check. Refuse.
      if (pick.isPoisonedKey(header[i])) {
        throw new CsvError("csv/forbidden-header",
          "header column '" + header[i] + "' is a reserved prototype key");
      }
      obj[header[i]] = rec[i];
    }
    out.push(obj);
  }
  return out;
}

// ---- stringify ----

/**
 * @primitive b.csv.stringify
 * @signature b.csv.stringify(rows, opts?)
 * @since     0.4.0
 * @related   b.csv.parse, b.csv.DEFAULTS_STRINGIFY
 *
 * Serialize an array of rows to RFC 4180 CSV text. Rows may be
 * arrays (positional) or plain objects (keyed by header). When the
 * first row is an object, header columns default to that row's
 * `Object.keys`; pass `opts.columns` to force an explicit column
 * order or to surface keys missing from the first row. Cells are
 * quoted only when they contain the delimiter, the quote char,
 * CR, or LF — unless `alwaysQuote: true` forces full quoting.
 * `null` and `undefined` cells emit as empty strings; everything
 * else is coerced via `String()`.
 *
 * The default end-of-line is CRLF per RFC 4180; pass `eol: "\n"`
 * for plain LF output.
 *
 * @opts
 *   header:      boolean,         // emit a header row (default true)
 *   delimiter:   string,          // single byte, default ","
 *   quote:       string,          // single byte, default '"'
 *   eol:         string,          // "\r\n" (default) or "\n"
 *   alwaysQuote: boolean,         // quote every cell unconditionally
 *   columns:     Array<string>,   // explicit column order / subset
 *
 * @example
 *   var out = b.csv.stringify([
 *     { name: "alice", age: 30 },
 *     { name: "bob",   age: 25 },
 *   ]);
 *   // → "name,age\r\nalice,30\r\nbob,25"
 *
 *   // Cells containing the delimiter are quoted; embedded quotes double.
 *   var quoted = b.csv.stringify([
 *     { msg: 'she said "hi", then left' },
 *   ], { eol: "\n" });
 *   // → 'msg\n"she said ""hi"", then left"'
 *
 *   // Array-of-arrays input with an explicit column header.
 *   var cols = b.csv.stringify(
 *     [ [ "1", "2" ], [ "3", "4" ] ],
 *     { columns: [ "a", "b" ], eol: "\n" }
 *   );
 *   // → "a,b\n1,2\n3,4"
 */
function stringify(rows, opts) {
  opts = Object.assign({}, DEFAULTS_STRINGIFY, opts || {});
  if (!Array.isArray(rows)) {
    throw new CsvError("csv/bad-input",
      "stringify: rows must be an array, got " + typeof rows);
  }
  _validateDelim("delimiter", opts.delimiter);
  _validateDelim("quote",     opts.quote);
  if (opts.delimiter === opts.quote) {
    throw new CsvError("csv/bad-delimiter",
      "delimiter and quote must differ");
  }
  if (opts.eol !== "\r\n" && opts.eol !== "\n") {
    throw new CsvError("csv/bad-opt",
      "eol must be '\\r\\n' or '\\n'");
  }
  if (rows.length === 0) return "";

  var first = rows[0];
  var asObjects;
  var header;
  if (Array.isArray(first)) {
    asObjects = false;
    header = Array.isArray(opts.columns) ? opts.columns : null;
  } else if (first !== null && typeof first === "object") {
    asObjects = true;
    header = Array.isArray(opts.columns) ? opts.columns : Object.keys(first);
  } else {
    throw new CsvError("csv/bad-input",
      "stringify: rows must be arrays or plain objects");
  }

  function escapeCell(value) {
    var str = value == null ? "" : String(value);
    var needsQuote = opts.alwaysQuote ||
      str.indexOf(opts.delimiter) !== -1 ||
      str.indexOf(opts.quote) !== -1 ||
      str.indexOf("\n") !== -1 ||
      str.indexOf("\r") !== -1;
    if (needsQuote) {
      str = opts.quote + str.split(opts.quote).join(opts.quote + opts.quote) + opts.quote;
    }
    return str;
  }

  var out = [];
  if (opts.header && header) {
    out.push(header.map(escapeCell).join(opts.delimiter));
  }
  for (var i = 0; i < rows.length; i++) {
    var rec = rows[i];
    var cells;
    if (asObjects) {
      cells = header.map(function (k) { return escapeCell(rec[k]); });
    } else {
      cells = rec.map(escapeCell);
    }
    out.push(cells.join(opts.delimiter));
  }
  return out.join(opts.eol);
}

module.exports = {
  parse:               parse,
  stringify:           stringify,
  CsvError:            CsvError,
  DEFAULTS_PARSE:      DEFAULTS_PARSE,
  DEFAULTS_STRINGIFY:  DEFAULTS_STRINGIFY,
};
