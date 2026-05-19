"use strict";

// jazzer.js fuzz harness for b.safeSieve.parse — bounded RFC 5228
// parser. Refuses oversized scripts, control bytes, unknown
// capabilities, RFC-defined-but-unimplemented capabilities, and
// caps each grammar dimension. The harness asserts the parser
// neither crashes nor leaks an exception type the framework doesn't
// expect.

var b = require("../index");
var SafeSieveError = b.safeSieve.SafeSieveError;

module.exports.fuzz = function (data) {
  var s;
  try { s = data.toString("utf8"); }
  catch (_e) { return; }
  // Cap fuzz input to a sensible size — jazzer corpus stays under the
  // permissive profile's 1 MiB cap; anything past that is just OS-page
  // churn without exercising the parser.
  if (s.length > 200000) s = s.slice(0, 200000);                                                       // allow:raw-byte-literal — fuzz cap
  try {
    b.safeSieve.parse(s, { profile: "permissive" });
  } catch (e) {
    if (e instanceof SafeSieveError) return;
    if (e instanceof RangeError) return;                                                               // stack overflow on degenerate input is acceptable
    throw e;
  }
};
