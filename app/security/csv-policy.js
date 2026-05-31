/**
 * CSV policy — safe CSV generation for admin exports.
 *
 * Delegates to b.guardCsv.serialize. Formula-injection triggers
 * (=, +, -, @, |, tab, CR, LF, and the full-width homoglyph variants
 * ＝ ＋ － ＠) are neutralised with a leading apostrophe; Unicode bidi
 * overrides (CVE-2021-42574 "Trojan Source"), C0 control characters, and
 * NUL bytes are stripped; and cell / row / total size is capped against
 * CSV-amplification bombs. Output is byte-identical to the prior
 * hand-rolled escaper for ordinary data — only hostile cells are altered,
 * always in the safe direction — and an export never throws on a hostile
 * field (control/bidi/null are stripped, not rejected).
 */
var b = require("../../lib/vendor/blamejs");

// Pinned so the escaping disposition matches the prior helper: an
// apostrophe formula prefix (Excel reads the cell as literal text), LF
// line endings, preserved trailing whitespace, neutralise-don't-throw for
// control / bidi / NUL bytes, and the prior String(value) rendering for
// numbers. The amplification caps (rows / cell / total bytes) are raised to
// effectively unlimited: this serialises trusted database rows for an
// admin, not untrusted input, and the prior helper imposed no cap, so a
// large-but-legitimate export must not fail. The cell-level escaping is
// what defends the export against CSV/formula injection.
var UNLIMITED = Number.MAX_SAFE_INTEGER;
var CSV_OPTS = {
  formulaInjectionPolicy: "prefix-quote",
  lineEnding: "\n",
  controlCharPolicy: "strip",
  bidiCharPolicy: "strip",
  nullByteHandling: "strip",
  trailingWhitespacePolicy: "preserve",
  numericPrecisionPolicy: "preserve",
  maxRows: UNLIMITED,
  maxCellBytes: UNLIMITED,
  maxTotalBytes: UNLIMITED,
};

/**
 * Build a CSV string from an array of objects.
 * @param {string[]} headers - column names (trusted literals)
 * @param {object[]} rows - data rows
 * @param {function} rowMapper - (row) => [val1, val2, ...]
 */
function buildCsv(headers, rows, rowMapper) {
  // serialize emits no header line for an empty record set; render the
  // header row through the same escaper (headers as a single header-less
  // row) so the zero-row and multi-row paths escape identically.
  if (rows.length === 0) {
    return b.guardCsv.serialize([headers], Object.assign({ headers: false }, CSV_OPTS)) + "\n";
  }
  var body = b.guardCsv.serialize(rows.map(rowMapper), Object.assign({ headers: headers }, CSV_OPTS));
  return body + "\n";   // terminate the final row, matching the prior helper
}

module.exports = { buildCsv };
