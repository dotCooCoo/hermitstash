"use strict";
/**
 * b.objectStore conditional-GET Range header (shared across sigv4 / gcs / azure).
 * The documented + shipped contract is `range: [start, end]` (array) — see
 * b.archive.adapters.objectStore and b.backup. Reading .start/.end off an array
 * yielded "bytes=undefined-undefined", which every store IGNORES, silently
 * returning the FULL object instead of the requested byte range.
 */

var helpers = require("../helpers");
var check   = helpers.check;

var httpReq = require("../../lib/object-store/http-request");
var apply   = httpReq.applyConditionalGetHeaders;

function run() {
  // Array contract [start, end] → correct bytes= header (the real caller shape).
  var t1 = apply({}, { range: [0, 1023] }, "Range");
  check("array range [0,1023] → bytes=0-1023", t1.Range === "bytes=0-1023");

  // Honors the backend-specific range header name (Azure x-ms-range).
  var t2 = apply({}, { range: [100, 199] }, "x-ms-range");
  check("array range honors azure header name", t2["x-ms-range"] === "bytes=100-199");

  // { start, end } object form still accepted (compatibility).
  var t3 = apply({}, { range: { start: 5, end: 9 } }, "Range");
  check("object {start,end} compat → bytes=5-9", t3.Range === "bytes=5-9");

  // No range → no Range header at all.
  var t4 = apply({}, {}, "Range");
  check("no range → no Range header emitted", !("Range" in t4));

  // Malformed range must throw, not emit a garbage header that over-fetches.
  var threw = null;
  try { apply({}, { range: [undefined, 10] }, "Range"); } catch (e) { threw = e; }
  check("malformed range ([undefined,10]) throws, not bytes=undefined",
        threw && /range must be|INVALID_RANGE/.test((threw.message || "") + " " + (threw.code || "")));
  var threwInv = null;
  try { apply({}, { range: [10, 5] }, "Range"); } catch (e) { threwInv = e; }
  check("inverted range (end < start) throws", threwInv !== null);
  var threwNeg = null;
  try { apply({}, { range: [-1, 5] }, "Range"); } catch (e) { threwNeg = e; }
  check("negative start throws", threwNeg !== null);

  console.log("[object-store-range-header] OK — " + helpers.getChecks() + " checks passed");
}

module.exports = { run: run };
if (require.main === module) {
  try { run(); } catch (e) { console.error("FAIL: " + helpers.formatErr(e)); process.exit(1); }
}
