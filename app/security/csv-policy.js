/**
 * CSV Policy — safe CSV generation with formula injection protection.
 * All CSV exports must use these helpers.
 */

/**
 * Escape a value for safe CSV inclusion.
 * Neutralizes formula-triggering characters (=, +, -, @, tab, carriage return).
 * Quotes values containing commas, newlines, or double-quotes.
 */
function csvSafe(val) {
  var s = String(val == null ? "" : val);
  // Prefix formula-triggering characters
  if (s.length > 0 && "=+-@\t\r".indexOf(s[0]) !== -1) s = "'" + s;
  // Quote if contains special CSV characters
  if (s.indexOf('"') !== -1 || s.indexOf(",") !== -1 || s.indexOf("\n") !== -1) {
    s = '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

/**
 * Build a CSV string from an array of objects.
 * @param {string[]} headers - Column names
 * @param {object[]} rows - Data rows
 * @param {function} rowMapper - (row) => [val1, val2, ...] mapping function
 */
function buildCsv(headers, rows, rowMapper) {
  var csv = headers.join(",") + "\n";
  for (var i = 0; i < rows.length; i++) {
    var values = rowMapper(rows[i]);
    csv += values.map(csvSafe).join(",") + "\n";
  }
  return csv;
}

module.exports = { csvSafe, buildCsv };
